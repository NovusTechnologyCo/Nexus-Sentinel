/**
 * @file NexusZombieModule.c
 * @brief A module that PASSES Prepare and then FAILS Commit -- the contract's unrecoverable case.
 *        Exists solely to execute the most dangerous branch in NxcMapUnmap.
 *
 * ============================================================================================
 * WHY A SECOND TEST MODULE, AND WHY IT CANNOT BE A MODE OF THE FIRST
 * ============================================================================================
 *
 * NxcMapUnmap's zombie path -- deliberately leak the extent, mark the slot permanently dead, never
 * reclaim or reuse it -- was written, reviewed, committed, and had never once run. It is the code
 * that decides to permanently surrender memory rather than risk cross-module corruption, and until
 * something exercised it the only evidence it worked was that it looked right.
 *
 * NexusTestModule cannot cover it. A failed COMMIT leaves an instance that can NEVER be torn down
 * again by design, so the behaviour is not repeatable within one mapped instance and cannot be a
 * later phase of a module whose earlier phases must keep working. Hence a separate image.
 *
 * ⚠ EVERY SUCCESSFUL MAP OF THIS MODULE PERMANENTLY COSTS ARENA SPACE UNTIL REBOOT. That is not a
 * defect in the test, it IS the behaviour under test. 16 MB against a ~32 KB footprint is roughly
 * 500 runs before exhaustion, and a reboot resets it. Map it deliberately, not in a loop.
 *
 * ============================================================================================
 * WHAT IT PROVES -- and why the lie is in COMMIT rather than PREPARE
 * ============================================================================================
 *
 * PREPARE answers OK: teardown IS possible. COMMIT then fails. That ordering is the whole point --
 * the contract calls a failed COMMIT unrecoverable precisely BECAUSE PREPARE already promised
 * otherwise, so the module is left in a state neither side can describe. A module that refused in
 * PREPARE would be the ordinary, safe case, which NexusTestModule already covers.
 *
 * This is an honest module, not a forced failure: it models one that genuinely cannot complete
 * teardown -- a real possibility for anything holding a callback Windows offers no way to
 * unregister. NXM_TEARDOWN_FAILED is a documented return value of the contract, and returning it
 * truthfully is what this module does. Nothing here fakes a verdict or injects state into the host.
 *
 * Expected observable outcome:
 *   unmap -> NXCMD_RESULT_REFUSED, DiagFlags carries NXCMD_UNMAP_COMMITTED
 *         -> "FAILED AFTER TEARDOWN BEGAN ... slot is now a zombie"
 *         -> arena stays at this module's footprint FOREVER
 *   unmap again -> refused at the Zombie check, and NOTHING is retried
 *
 * Constraints are inherited from Include/NexusModule.h exactly as in NexusTestModule: no import
 * table, no SEH, no CRT, descriptor not const, entry called as DriverEntry(NULL, NULL).
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "../../Include/NexusModule.h"
#include "../../Include/NexusHost.h"

static NXM_U32 ZombiePrepare(void);
static NXM_U32 ZombieCommit(void);

__declspec(dllexport) NEXUS_MODULE_DESCRIPTOR NexusModuleDescriptor =
{
	NEXUS_MODULE_MAGIC,
	NEXUS_MODULE_ABI,
	(NXM_U32)sizeof(NEXUS_MODULE_DESCRIPTOR),
	ZombiePrepare,
	ZombieCommit,
	0,                         /* Flags: no callbacks, no threads, not a hypervisor    */
	0,                         /* ActiveCount, maintained below                        */
	"NexusZombieModule",       /* Name, NUL-padded by the initialiser                  */
	0                          /* Host, written by NexusCore before the entry runs      */
};

__declspec(dllexport) volatile NXM_U64 NexusZombieModuleRan = 0;

/**
 * Prepare: says YES. Deliberately.
 *
 * The unrecoverable case requires PREPARE to succeed -- that promise is exactly what makes a
 * subsequent COMMIT failure unrecoverable rather than merely inconvenient.
 */
static NXM_U32
ZombiePrepare(
	void
	)
{
	if (NexusModuleDescriptor.ActiveCount != 0)
		return NXM_TEARDOWN_REFUSED;   /* still honest: never claim readiness while in use */

	return NXM_TEARDOWN_OK;
}

/**
 * Commit: cannot finish, and says so.
 *
 * NXM_TEARDOWN_FAILED is a documented return of the contract and this reports it truthfully -- the
 * module models one that genuinely cannot release what it holds. It notably does NOT set
 * NXM_FLAG_TORN_DOWN, which is correct: teardown did not complete, and claiming otherwise would be
 * the fake-success this codebase forbids.
 *
 * Everything after this point in NxcMapUnmap is the branch under test.
 */
static NXM_U32
ZombieCommit(
	void
	)
{
	return NXM_TEARDOWN_FAILED;
}

/**
 * Entry. Identical in shape to NexusTestModule's -- the module must be genuinely healthy and running
 * for its teardown failure to mean anything. A module that failed to start would test nothing.
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

	NEXUS_HOST_API* CONST Host = (NEXUS_HOST_API*)(ULONG_PTR)NexusModuleDescriptor.Host;
	if (Host == NULL || Host->Magic != NEXUS_HOST_MAGIC || Host->Abi != NEXUS_HOST_ABI)
	{
		NexusModuleDescriptor.ActiveCount--;
		return STATUS_INVALID_PARAMETER;
	}

	Host->Log("[NexusZombieModule] mapped and running; owner id %llu -- THIS MODULE WILL FAIL COMMIT\n",
	          (unsigned long long)Host->Owner);

	/*
	 * Allocate and deliberately DO NOT free, unlike NexusTestModule.
	 *
	 * This is what makes the leak measurable rather than merely claimed. A module whose COMMIT fails
	 * is one that could not release what it held, so holding something is part of modelling it
	 * honestly -- and it means the arena figure after the failed unmap is strictly larger than the
	 * image alone, proving NxcArenaFreeOwner was never called rather than called and found nothing.
	 */
	void* CONST Block = Host->Alloc(Host->Owner, 8192);
	if (Block != NULL)
		Host->Log("[NexusZombieModule] arena alloc OK at %p -- intentionally NOT freed\n", Block);

	NexusZombieModuleRan = 0x4E585A4F4D424945ULL;   /* 'NXZOMBIE' -- proof this code executed */

	NexusModuleDescriptor.ActiveCount--;
	return STATUS_SUCCESS;
}
