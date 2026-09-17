/**
 * @file NexusTestModule.c
 * @brief The smallest module that fully honours the mapped-module contract. Exists to TEST the
 *        runtime map path, and to be deliberately corrupted so the REFUSAL path can be tested too.
 *
 * ============================================================================================
 * WHY THIS EXISTS
 * ============================================================================================
 *
 * Everything NexusCore's runtime mapper does had, until now, never run: nothing had ever been
 * mapped, so `map` was correct by construction and unproven in practice. Worse, the
 * refuse-a-module-we-cannot-protect rule could not be demonstrated at all -- a well-formed image in
 * a 4 KB-backed arena never produces a refusal, so the branch was unreachable by design.
 *
 * This module is the vehicle for both. Built once, it is a VALID module and proves the happy path.
 * Byte-patched by tools/make_malformed_module.py it becomes an image whose section table overruns
 * SizeOfImage, which drives NxcPteProtectImage to report a refusal through a REAL code path -- no
 * diagnostic flag, no forced state, no fake failure. The only difference between the two cases is
 * the field under test.
 *
 * ============================================================================================
 * EVERY CONSTRAINT HERE IS INHERITED, NOT INVENTED -- see Include/NexusModule.h
 * ============================================================================================
 *
 *  1. NO IMPORT TABLE. This module cannot import from anything: NexusCore's mapper binds imports
 *     against ntoskrnl only, and an import table is the FF-25 signature the whole payload design
 *     removes. Everything the module needs comes through NEXUS_HOST_API instead.
 *  2. NO SEH. x64 unwinding is table-driven off the loaded-module list and a mapped image is
 *     deliberately absent from it. No __try anywhere.
 *  3. NO CRT, no globals needing construction, no floating point. Nothing runs before the entry.
 *  4. THE DESCRIPTOR MUST BE WRITABLE. Not `const`: the host writes Host into it before applying
 *     protections, and the module writes ActiveCount on every call.
 *  5. Entry is called as DriverEntry(NULL, NULL). Touching either argument is a bugcheck.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "../../Include/NexusModule.h"
#include "../../Include/NexusHost.h"

/* Forward declarations: the descriptor references these before they are defined. */
static NXM_U32 TestPrepare(void);
static NXM_U32 TestCommit(void);

/*
 * THE DESCRIPTOR. Exported under the exact name the mapper looks for, and deliberately NOT const --
 * see constraint 4. `volatile` on nothing here: the host's write to Host happens strictly before the
 * entry runs, so there is no concurrent access to guard against.
 */
__declspec(dllexport) NEXUS_MODULE_DESCRIPTOR NexusModuleDescriptor =
{
	NEXUS_MODULE_MAGIC,
	NEXUS_MODULE_ABI,
	(NXM_U32)sizeof(NEXUS_MODULE_DESCRIPTOR),
	TestPrepare,
	TestCommit,
	0,                       /* Flags: no callbacks, no threads, not a hypervisor      */
	0,                       /* ActiveCount, maintained below                          */
	"NexusTestModule",       /* Name, NUL-padded by the initialiser                    */
	0                        /* Host, written by NexusCore before the entry runs        */
};

/*
 * Proof-of-life, written by the entry and readable by anyone who can see this image. Not a
 * diagnostic flag standing in for real work -- the module genuinely has no other job, and the point
 * is to prove the MAP worked, which means proving code in this image actually executed.
 */
__declspec(dllexport) volatile NXM_U64 NexusTestModuleRan = 0;

/**
 * Prepare: stop taking new work, report whether unload is possible. Must not destroy state.
 *
 * Honest rather than trivial: it refuses while any call is still inside the module. This module
 * cannot actually have a concurrent caller today, so in practice it agrees on the first ask and
 * `unmap` completes in ONE step. Exercising the refusal deliberately is `NexusDrainModule`'s job --
 * see the note below.
 */
/*
 * ⚠⚠ THIS USED TO REFUSE THE FIRST ASK AFTER EVERY MAP, AND THAT IS REMOVED. `unmap` IS ONE STEP.
 *
 * The old behaviour was `if (++gPrepareAsks == 1) return NXM_TEARDOWN_REFUSED;` -- a per-instance
 * counter in module .data, so EVERY mapped instance refused once before agreeing:
 *
 *     unmap #1  -> NXM_TEARDOWN_REFUSED -> NXCMD_RESULT_BUSY
 *     unmap #2  -> NXM_TEARDOWN_OK      -> full six-step teardown
 *
 * It was added for a real reason: the refusal path was unreachable, because Prepare only
 * refused on `ActiveCount != 0` and this module can have no concurrent caller, so the contract's
 * central promise -- a refused unmap leaves the module mapped, running and intact -- had never once
 * executed.
 *
 * ⚠ THAT COVERAGE NOW EXISTS SOMEWHERE BETTER, WHICH IS WHY THIS CAN GO. `NexusDrainModule` exercises
 * exactly the same host-side path ON DEMAND: `modcmd 4096` raises its ActiveCount so Prepare refuses,
 * and `4098` arms the timed variant that drives the drain timeout. Opt-in is strictly better than
 * unconditional -- the BUSY path is still testable whenever it is the thing being tested, and the
 * ordinary module no longer makes every caller ask twice.
 *
 * And the cost of the old design was not theoretical. On it produced a false alarm: a
 * `MODULE_BUSY` from this deliberate refusal was read as the DRAIN-TIMEOUT branch, which zombies a
 * slot and leaks an extent, and reported as "the machine state is polluted, a reboot is needed".
 * Nothing was wrong. A test fixture whose normal behaviour is indistinguishable from a real fault is
 * a fixture that will be misread again.
 *
 * The honest `ActiveCount` refusal below STAYS. That one is a module telling the truth about itself.
 */
static NXM_U32
TestPrepare(
	void
	)
{
	if (NexusModuleDescriptor.ActiveCount != 0)
		return NXM_TEARDOWN_REFUSED;   /* still in use: stay RUNNING and intact, do not tear down */

	return NXM_TEARDOWN_OK;
}

/**
 * Commit: release everything. Nothing to release -- no callbacks, no threads, no allocations kept.
 *
 * Returning OK here is truthful precisely BECAUSE this module holds nothing. A module that allocated
 * from the arena would have to free it here, and returning OK without doing so is the unrecoverable
 * case the contract warns about.
 */
static NXM_U32
TestCommit(
	void
	)
{
	NexusModuleDescriptor.Flags |= NXM_FLAG_TORN_DOWN;
	return NXM_TEARDOWN_OK;
}

/**
 * Entry. Called by NexusCore's runtime mapper as DriverEntry(NULL, NULL).
 *
 * Exercises the HOST API deliberately, rather than just returning success: the host pointer, the
 * logging path and owner-tagged arena allocation had all been built and never used by an actual
 * module. A test module that only returns STATUS_SUCCESS would prove the mapper copies bytes and
 * nothing about whether a mapped module can DO anything.
 */
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NexusModuleDescriptor.ActiveCount++;

	/*
	 * CHECK, do not assume. NULL here means the host did not fill it in, and dereferencing zero in
	 * kernel mode is a bugcheck -- the contract says a module must refuse instead.
	 */
	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;
	if (Host == NULL || Host->Magic != NEXUS_HOST_MAGIC || Host->Abi != NEXUS_HOST_ABI)
	{
		NexusModuleDescriptor.ActiveCount--;
		return STATUS_INVALID_PARAMETER;
	}

	Host->Log("[NexusTestModule] mapped and running; owner id %llu, kernel %p +%u\n",
	          (unsigned long long)Host->Owner,
	          (PVOID)(ULONG_PTR)Host->KernelBase,
	          Host->KernelSize);

	/*
	 * Allocate through the host, owner-tagged. This is the path that made arena ownership usable at
	 * all, and it has never been driven by a real module -- so exercising it here is the point, not
	 * decoration. Freed immediately: a test module that leaks an extent would make every subsequent
	 * arena reading a lie.
	 */
	/*
	 * ⚠ 8192, NOT 4096, AND THE SIZE IS THE POINT. Chosen so the arena reading can actually
	 * distinguish a working Free from a broken one.
	 *
	 * With 4096 it could not. HostFree was a no-op, so this allocation leaked one page -- and the guard
	 * page the allocator was supposed to place behind the image is also one page. Both bugs produced
	 * ArenaUsed = 32 KB for this 28 KB module, so the number agreed with the correct answer for entirely
	 * the wrong reasons and I misread the leak as the guard.
	 *
	 * At 8192 the two diverge: a working Free leaves 32 KB (image + its guard), a broken one leaves
	 * 44 KB (image + guard + 8 KB + its guard). A test whose passing value is the same as its failing
	 * value is not a test.
	 */
	void* CONST Block = Host->Alloc(Host->Owner, 8192);
	if (Block != NULL)
	{
		Host->Log("[NexusTestModule] arena alloc OK at %p\n", Block);
		Host->Free(Host->Owner, Block);
	}
	else
	{
		Host->Log("[NexusTestModule] arena alloc FAILED\n");
	}

	NexusTestModuleRan = 0x4E58544D4F44554CULL;   /* 'NXTMODUL' -- proof this code executed */

	NexusModuleDescriptor.ActiveCount--;
	return STATUS_SUCCESS;
}
