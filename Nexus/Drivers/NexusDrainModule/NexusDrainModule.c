/**
 * @file NexusDrainModule.c
 * @brief A module that releases everything and STILL has a caller inside it.
 *        Exists solely to execute NxcMapUnmap's DRAIN TIMEOUT -- the last unexercised teardown branch.
 *
 * ============================================================================================
 * WHY A THIRD TEST MODULE, AND WHY NEITHER EXISTING ONE COVERS THIS
 * ============================================================================================
 *
 * NxcMapUnmap has four phases: PREPARE, COMMIT, DRAIN, BARRIER.
 *
 *   NexusTestModule    every phase succeeds -- the normal path
 *   NexusZombieModule  PREPARE says yes, COMMIT fails -- the unrecoverable path
 *   this module        PREPARE and COMMIT both SUCCEED, and DRAIN still times out
 *
 * That last combination is not reachable from either existing module, and it is the one branch in
 * the teardown contract that has never run. the design notes I-01.
 *
 * ⚠ NEITHER EXISTING MODULE CAN BE EXTENDED TO COVER IT, and the reason is a detail worth stating:
 * both refuse in PREPARE while `ActiveCount != 0`. That is correct, honest behaviour for them -- and
 * it means unmap fails at PREPARE and NEVER REACHES DRAIN. A module that reaches the drain loop must
 * answer PREPARE and COMMIT truthfully in the affirmative while a caller is still inside it.
 *
 * ============================================================================================
 * WHY THAT IS HONEST AND NOT A RIGGED FAILURE
 * ============================================================================================
 *
 * PREPARE and COMMIT are about RESOURCES: can this module release what it holds, and did it.
 * `ActiveCount` is about EXECUTION: is a processor currently inside one of its entry points. Those
 * are genuinely different questions, which is exactly why the contract has a separate DRAIN phase --
 * NxcMapUnmap's own comment says "ActiveCount reaching zero says no processor is inside an ENTRY
 * POINT", not that resources are freed.
 *
 * So this module models something real: it has released everything it held (COMMIT is true, and it
 * sets NXM_FLAG_TORN_DOWN truthfully), and a call is still in flight. Nothing here fakes a verdict,
 * injects state into the host, or reports a phase it did not complete.
 *
 * ============================================================================================
 * ⚠ ONE SHOT PER BOOT. READ THIS BEFORE RUNNING IT.
 * ============================================================================================
 *
 * A drain timeout sets `Slot->Zombie`, and `NxcMapUnmap` refuses any zombie slot forever
 * (MapModule.c). So once the timeout fires, THIS INSTANCE'S EXTENT IS LEAKED UNTIL REBOOT and no
 * later unmap will reclaim it. There is no "hold, time out, release, retry" sequence -- verified by
 * reading the guard, not assumed.
 *
 * Use `release` BEFORE unmapping if you want the slot back. Once unmap has timed out, only a reboot
 * clears it.
 *
 * ============================================================================================
 * HOW TO RUN IT
 * ============================================================================================
 *
 *   PlatformCtl map <path>\NexusDrainModule.sys     -> note the module id
 *   PlatformCtl modcmd 4096                          -> HOLD: ActiveCount becomes 1
 *   PlatformCtl unmap <id>                           -> the branch under test
 *
 * Expected: unmap blocks for roughly one second (64 iterations of a nominal 1 ms, which is really
 * ~15.6 ms per the system clock tick), then:
 *
 *   result   REFUSED, DiagRefusalLine pointing at the drain-timeout return
 *   log      "[unmap] module N DRAIN TIMEOUT (ActiveCount=1) -- extent leaked deliberately"
 *   arena    unchanged by the unmap; the extent is gone until reboot
 *
 * To prove the loop WAITS rather than merely failing, `release` from a second shell while the unmap
 * is blocked: the count drops mid-loop and the unmap should then SUCCEED. That is the more
 * interesting half and it needs no thread inside this module -- the second command is the thread.
 *
 * Constraints inherited from Include/NexusModule.h: no import table, no SEH, no CRT, entry called as
 * DriverEntry(NULL, NULL).
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "../../Include/NexusModule.h"
#include "../../Include/NexusHost.h"
#include "../../Include/NexusCommand.h"

/*
 * The TYPED nt call table. A mapped module carries no import table, so every kernel call goes
 * through the host's already-resolved surface (NexusHost.h: "a module casts NtApi to NXC_NT_API*
 * after checking Magic"). NXC_NT_API_TYPED asks for the struct definition only -- this module must
 * NOT include NexusNtApiRedirect.h, because the redirects rewrite bare names into accesses on a
 * global instance that exists in NexusCore, not here.
 */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

static NXM_U32 DrainPrepare(void);
static NXM_U32 DrainCommit(void);

__declspec(dllexport) NEXUS_MODULE_DESCRIPTOR NexusModuleDescriptor =
{
	NEXUS_MODULE_MAGIC,
	NEXUS_MODULE_ABI,
	(NXM_U32)sizeof(NEXUS_MODULE_DESCRIPTOR),
	DrainPrepare,
	DrainCommit,
	0,                         /* Flags: no callbacks, no threads, not a hypervisor    */
	0,                         /* ActiveCount, maintained below                        */
	"NexusDrainModule",        /* Name, NUL-padded by the initialiser                  */
	0                          /* Host, written by NexusCore before the entry runs      */
};

__declspec(dllexport) volatile NXM_U64 NexusDrainModuleRan = 0;

/*
 * Module-owned opcodes. Must be at or above NXCMD_OP_MODULE_FIRST -- Core's dispatch enforces the
 * split so a module cannot shadow a Core opcode, which is the guard that stops a module from
 * intercepting its own unmap.
 */
#define DRAIN_OP_HOLD     (NXCMD_OP_MODULE_FIRST + 0u)
#define DRAIN_OP_RELEASE  (NXCMD_OP_MODULE_FIRST + 1u)
/*
 * ⚠ TIMED HOLD -- the opcode that makes I-01's re-check TESTABLE AT ALL.
 *
 * The plain HOLD raises ActiveCount forever, which only ever produces the TIMEOUT. Proving the drain
 * loop RE-CHECKS needs the count to fall WHILE the host is spinning, and nothing could do that: a
 * command cannot (Core retires this module's opcodes after PREPARE, before COMMIT, and serialises
 * every command anyway), and the module had no thread and no timer.
 *
 * So the module now owns a TIMER. HOLD_TIMED raises the count and arms a DPC to lower it after N
 * milliseconds. Issue it with N well under the ~1 s drain bound and the unmap must SUCCEED at ~N ms
 * instead of refusing at ~1000 -- which a loop that slept on a fixed schedule could never do.
 */
#define DRAIN_OP_HOLD_TIMED (NXCMD_OP_MODULE_FIRST + 2u)

/**
 * HOLD: raise ActiveCount and deliberately do not lower it.
 *
 * ⚠ THE IMBALANCE IS THE ENTIRE POINT, and it is why this looks wrong next to every other module. A
 * well-behaved module raises the count on entry to a handler and lowers it before returning, so the
 * count is zero whenever no call is in flight. This one leaves it raised, which is precisely the
 * state DRAIN exists to detect: a module that believes a caller is still inside it.
 *
 * ⚠ IT MUST NOT BLOCK. Commands are serialised by Core's interlocked guard, so a handler that slept
 * would block the very `unmap` this test needs to issue next -- the drain loop would never run
 * because the command channel would still be held by this call. Increment and return.
 */
/*
 * ⚠ THE TIMER AND ITS DPC LIVE IN THE MODULE'S OWN IMAGE, which is exactly what makes the teardown
 * ordering matter. Two cases, and both are safe by construction rather than by timing:
 *
 *   drain SUCCEEDS -- the DPC has already run (that is why the count fell). The host's BARRIER step
 *     is a KeIpiGenericCall, which runs above DISPATCH_LEVEL on every processor and therefore cannot
 *     complete while a DPC is still executing anywhere. The extent is not reclaimed until it does.
 *
 *   drain TIMES OUT -- the slot becomes a ZOMBIE and the extent is LEAKED, never reclaimed. A timer
 *     still queued into that memory is harmless precisely because the memory is never given back.
 *
 * The dangerous combination -- a queued DPC pointing into reclaimed memory -- cannot arise from
 * either path.
 */
static KTIMER gDrainTimer;
static KDPC   gDrainDpc;
static volatile LONG gTimerArmed = 0;

static VOID
DrainReleaseDpc(
	_In_ PKDPC Dpc,
	_In_opt_ PVOID Context,
	_In_opt_ PVOID Arg1,
	_In_opt_ PVOID Arg2
	)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Arg1);
	UNREFERENCED_PARAMETER(Arg2);

	/*
	 * ⚠ THE WHOLE POINT OF THE MODULE, IN ONE LINE. This runs at DISPATCH_LEVEL on whatever
	 * processor the timer expires on, WHILE the host may be inside its drain loop on another. If the
	 * loop genuinely re-reads ActiveCount it sees this and completes; if it hoisted the load it
	 * cannot, and will refuse at ~1 s with the count already zero -- which is the exact discrepancy
	 * the test is looking for.
	 */
	if (NexusModuleDescriptor.ActiveCount > 0)
		NexusModuleDescriptor.ActiveCount--;

	InterlockedExchange(&gTimerArmed, 0);
}

static NXH_U32
DrainHoldTimed(
	void* Command
	)
{
	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;
	NEXUS_COMMAND* CONST Cmd = (NEXUS_COMMAND*)Command;

	/*
	 * Milliseconds before the release. ⚠ ReadOffset, NOT ReadLength -- that is the field
	 * `modcmd --value X` actually plumbs (PlatformCtl CmdModCmd). Checked rather than assumed:
	 * reading the wrong field would have given a silent default-200 on every call while the CLI
	 * cheerfully reported the value it sent.
	 */
	NXH_U32 Ms = (Cmd != NULL && Cmd->ReadOffset != 0) ? (NXH_U32)Cmd->ReadOffset : 200u;
	if (Ms > 5000u)
		Ms = 5000u;   /* bounded: a long timer outlives the test and confuses the next run */

	/*
	 * ⚠ MAGIC AND ABI FIRST, THEN THE TABLE. NexusHost.h states the contract in as many words: the
	 * module casts NtApi to NXC_NT_API* only AFTER checking Magic. Skipping that would be calling
	 * through a pointer supplied by whatever happens to be at Host, which for a module is the one
	 * value it cannot validate any other way.
	 */
	if (Host == NULL || Host->Magic != NEXUS_HOST_MAGIC || Host->Abi != NEXUS_HOST_ABI ||
	    Host->NtApi == NULL)
		return NXCMD_RESULT_REFUSED;

	NXC_NT_API* CONST Nt = (NXC_NT_API*)Host->NtApi;

	if (Nt->KeInitializeTimer == NULL || Nt->KeInitializeDpc == NULL || Nt->KeSetTimer == NULL)
	{
		/* Resolution is per-name and can fail per-name; an unresolved entry is NULL, not a stub.
		 * Refusing here beats calling through it and blaming the timer for a resolver miss. */
		Host->Log("[NexusDrainModule] HOLD_TIMED unavailable -- timer APIs not resolved\n");
		return 3;
	}

	if (InterlockedCompareExchange(&gTimerArmed, 1, 0) != 0)
	{
		Host->Log("[NexusDrainModule] HOLD_TIMED refused -- a timer is already armed\n");
		return 1;
	}

	NexusModuleDescriptor.ActiveCount++;

	Nt->KeInitializeTimer(&gDrainTimer);
	Nt->KeInitializeDpc(&gDrainDpc, DrainReleaseDpc, NULL);

	LARGE_INTEGER Due;
	Due.QuadPart = -((LONGLONG)Ms * 10000LL);   /* relative, 100 ns units */
	Nt->KeSetTimer(&gDrainTimer, Due, &gDrainDpc);

	if (Host != NULL)
		Host->Log("[NexusDrainModule] HOLD_TIMED -- ActiveCount %lu, release in %lu ms. "
		          "An unmap issued now should SUCCEED at about that mark, not refuse at ~1000.\n",
		          (unsigned long)NexusModuleDescriptor.ActiveCount, (unsigned long)Ms);

	/*
	 * ⚠ NXCMD_RESULT_OK, NOT 0. The first version returned a private 0/1/2/3 code and the surface
	 * printed "7 = REFUSED" for a call that had ARMED THE TIMER AND WORKED -- the unmap went on to
	 * succeed at 298 ms. A handler's return value IS the command result; inventing a second
	 * convention for it makes a working path report failure, which is the same
	 * two-expressions-that-must-agree defect this codebase keeps finding. The specific reason lives
	 * in the log, where the other handlers put theirs.
	 */
	return NXCMD_RESULT_OK;
}

static NXH_U32
DrainHold(
	void* Command
	)
{
	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;

	UNREFERENCED_PARAMETER(Command);

	NexusModuleDescriptor.ActiveCount++;

	if (Host != NULL)
		Host->Log("[NexusDrainModule] HOLD -- ActiveCount is now %lu and will NOT be released. "
		          "The next unmap should hit the DRAIN TIMEOUT.\n",
		          (unsigned long)NexusModuleDescriptor.ActiveCount);

	return NXCMD_RESULT_OK;
}

/**
 * RELEASE: lower the count, so the slot can be torn down normally after all.
 *
 * Exists for two reasons. It lets a hold be undone without a reboot IF unmap has not yet timed out.
 * And it is how the more interesting half of the test is run: release from a second shell while an
 * unmap is blocked in the drain loop, and the unmap should then SUCCEED -- which proves the loop
 * genuinely waits and re-checks rather than failing on a fixed schedule.
 *
 * Refuses at zero rather than wrapping. An unsigned decrement below zero would report an ActiveCount
 * of 4294967295 and every subsequent drain would time out with a number nobody could explain.
 */
static NXH_U32
DrainRelease(
	void* Command
	)
{
	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;

	UNREFERENCED_PARAMETER(Command);

	if (NexusModuleDescriptor.ActiveCount == 0)
	{
		if (Host != NULL)
			Host->Log("[NexusDrainModule] RELEASE with ActiveCount already 0 -- REFUSED "
			          "(decrementing would wrap to 4294967295)\n");
		return NXCMD_RESULT_REFUSED;
	}

	NexusModuleDescriptor.ActiveCount--;

	if (Host != NULL)
		Host->Log("[NexusDrainModule] RELEASE -- ActiveCount is now %lu\n",
		          (unsigned long)NexusModuleDescriptor.ActiveCount);

	return NXCMD_RESULT_OK;
}

/**
 * Prepare: YES, and truthfully.
 *
 * ⚠ DELIBERATELY DOES NOT CHECK ActiveCount, unlike NexusTestModule and NexusZombieModule. Those are
 * right to check it -- refusing while in use is the safe, ordinary answer. But that answer means
 * unmap stops at PREPARE and the drain loop never runs, so a module that checks it can never reach
 * the branch this file exists to exercise.
 *
 * Not a lie: PREPARE asks whether teardown is POSSIBLE, and for this module it is. It holds no
 * callbacks, no threads and no resources it cannot release. The in-flight call is a separate fact,
 * and DRAIN is the phase that exists to ask about it.
 */
static NXM_U32
DrainPrepare(
	void
	)
{
	return NXM_TEARDOWN_OK;
}

/**
 * Commit: releases everything and says so, truthfully.
 *
 * NXM_FLAG_TORN_DOWN is set because teardown genuinely completed -- there was nothing to release
 * beyond the image itself. That is what makes the subsequent drain timeout meaningful: the host is
 * refusing to reclaim memory from a module that reported a clean teardown, purely because a caller
 * is still inside it. Exactly the case the phase was written for.
 */
static NXM_U32
DrainCommit(
	void
	)
{
	NexusModuleDescriptor.Flags |= NXM_FLAG_TORN_DOWN;
	return NXM_TEARDOWN_OK;
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	/* Balanced around the entry, the way a healthy module does it. The DELIBERATE imbalance lives in
	 * DrainHold and nowhere else, so a count above zero can only have come from an explicit hold. */
	NexusModuleDescriptor.ActiveCount++;

	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;
	if (Host == NULL || Host->Magic != NEXUS_HOST_MAGIC || Host->Abi != NEXUS_HOST_ABI)
	{
		NexusModuleDescriptor.ActiveCount--;
		return STATUS_INVALID_PARAMETER;
	}

	Host->Log("[NexusDrainModule] mapped and running; owner id %llu\n",
	          (unsigned long long)Host->Owner);

	/*
	 * Registering BOTH opcodes is also the first real exercise of RegisterCommand by an actual
	 * module -- it was built and, per the design notes, its registration path had never been used by one.
	 * A failure here is reported and the module still runs: it would simply be untestable, which is
	 * worth saying plainly rather than failing to map for a reason nobody could see.
	 */
	CONST NXH_U32 RcHold = Host->RegisterCommand(Host->Owner, DRAIN_OP_HOLD, DrainHold);
	CONST NXH_U32 RcRel  = Host->RegisterCommand(Host->Owner, DRAIN_OP_RELEASE, DrainRelease);
	CONST NXH_U32 RcTmd  = Host->RegisterCommand(Host->Owner, DRAIN_OP_HOLD_TIMED, DrainHoldTimed);
	Host->Log("[NexusDrainModule] RegisterCommand: hold_timed(%u)=%u\n",
	          DRAIN_OP_HOLD_TIMED, RcTmd);

	Host->Log("[NexusDrainModule] RegisterCommand: hold(%u)=%u release(%u)=%u\n",
	          DRAIN_OP_HOLD, RcHold, DRAIN_OP_RELEASE, RcRel);

	/* 0 is success for RegisterCommand (NexusHost.h). ASCII only in log strings: this reaches a
	 * cp1252 console, where a multi-byte glyph renders as mojibake. */
	if (RcHold != 0 || RcRel != 0)
		Host->Log("[NexusDrainModule] !! registration FAILED -- the drain test cannot be run\n");

	NexusDrainModuleRan = 0x4E58445241494EULL;   /* 'NXDRAIN' -- proof this code executed */

	NexusModuleDescriptor.ActiveCount--;
	return STATUS_SUCCESS;
}
