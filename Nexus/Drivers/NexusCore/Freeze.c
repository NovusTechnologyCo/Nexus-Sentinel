/**
 * @file Freeze.c
 * @brief Suspend/resume with a registry. The hazard analysis lives in Freeze.h -- read it first.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Freeze.h"
#include "Bp.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define FrzLog NxcLogExt

/*
 * ⚠ THE REGISTRY HOLDS A REFERENCED PEPROCESS, NOT JUST A PID, and that is a correctness
 * requirement rather than a convenience.
 *
 * The first version stored only the PID and re-resolved it in thaw with PsLookupProcessByProcessId.
 * WINDOWS REUSES PIDs. A frozen process can be terminated -- suspension does not prevent that -- and
 * a brand new process can be handed the same number before thaw runs. Thaw would then resume A
 * PROCESS WE NEVER FROZE, and if that process had been legitimately suspended by something else (a
 * debugger, say) we would have silently released it.
 *
 * Keeping the reference closes the window completely: a referenced EPROCESS cannot be freed, so the
 * pointer can never come to mean a different process. The reference is exactly what a reference is
 * for, and it is released in thaw.
 */
static UINT32     gFrozen[NXC_MAX_FROZEN];   /* 0 = empty slot; PID 0 can never be frozen anyway */
static PVOID      gFrozenObj[NXC_MAX_FROZEN];/* referenced PEPROCESS, released by thaw            */
static KSPIN_LOCK gFrozenLock;
static LONG       gFrozenInit = 0;

static void
EnsureInit(
	void
	)
{
	/* Initialised on first use rather than at DriverEntry: freeze is not on the boot path, and a
	 * spinlock this driver may never touch does not need to exist before it is asked for. */
	if (InterlockedCompareExchange(&gFrozenInit, 1, 0) == 0)
	{
		KeInitializeSpinLock(&gFrozenLock);
		for (ULONG i = 0; i < NXC_MAX_FROZEN; i++)
		{
			gFrozen[i]    = 0;
			gFrozenObj[i] = NULL;
		}
		InterlockedExchange(&gFrozenInit, 2);
		return;
	}

	/* Another thread is mid-init. Spin briefly rather than proceed on a half-built lock. */
	while (gFrozenInit != 2)
		YieldProcessor();
}

NTSTATUS
NxcFreezeProcess(
	_In_ UINT32 Pid
	)
{
	EnsureInit();

	/*
	 * ⚠ REFUSALS FIRST, BEFORE THE PROCESS IS EVEN LOOKED UP where possible. Suspending one of these
	 * does not fail -- it succeeds and hangs the machine. See Freeze.h.
	 */
	if (Pid == 0 || Pid == 4)
	{
		FrzLog("[freeze] pid %u is Idle/System -- REFUSED\n", Pid);
		return STATUS_ACCESS_DENIED;
	}

	if (Pid == (UINT32)(ULONG_PTR)PsGetCurrentProcessId())
	{
		/*
		 * The mistake that would actually get made. PsSuspendProcess suspends EVERY thread including
		 * the one running this command, which then never returns to release the command channel --
		 * a mistyped PID would cost a reboot.
		 */
		FrzLog("[freeze] pid %u is the CALLER -- REFUSED (it would never resume itself)\n", Pid);
		return STATUS_ACCESS_DENIED;
	}

	PVOID Process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process)) || Process == NULL)
		return STATUS_NOT_FOUND;

	if (PsIsSystemProcess(Process))
	{
		FrzLog("[freeze] pid %u is a SYSTEM process -- REFUSED\n", Pid);
		ObfDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	if (PsIsProtectedProcess(Process) || PsIsProtectedProcessLight(Process))
	{
		FrzLog("[freeze] pid %u is PROTECTED/PPL -- REFUSED\n", Pid);
		ObfDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	/*
	 * ⚠⚠ THE MIRROR OF `bp set`'s FROZEN REFUSAL, AND WITHOUT IT THE DEADLOCK IS ONLY REORDERED (D22).
	 *
	 * `bp set` and `bp list <pid>` refuse a frozen process because `Ps{Get,Set}ContextThread` on a
	 * non-current thread queues an APC and WAITS, and a suspended thread never delivers it. That
	 * refusal closes the order "freeze, then touch a context".
	 *
	 * It does nothing about the other order. Arm a breakpoint on a running process, THEN freeze it,
	 * and the next `bp clear` or `bp list` -- including the one a careful operator runs to tidy up --
	 * blocks forever on an APC that can never arrive. Same hang, reached backwards, and the machine
	 * looks entirely healthy throughout.
	 *
	 * So freeze refuses a process we have breakpoints in. Two refusals are what make the pair safe;
	 * one of them alone just moves the trap.
	 */
	if (NxcBpProcessHasBreakpoints(Pid))
	{
		ObfDereferenceObject(Process);
		FrzLog("[freeze] pid %u has HARDWARE BREAKPOINTS armed by us -- REFUSED. Freezing now would "
		       "make a later `bp clear` block forever on an APC a suspended thread cannot deliver. "
		       "Clear the breakpoints first.\n", Pid);
		return STATUS_INVALID_DEVICE_STATE;
	}

	/*
	 * Claim the slot BEFORE suspending. If the suspend then fails the slot is released -- whereas
	 * suspending first and failing to find a slot would leave a process stopped with no record of it,
	 * which is precisely the state this registry exists to make impossible.
	 */
	KIRQL Irql;
	ULONG Slot = NXC_MAX_FROZEN;

	KeAcquireSpinLock(&gFrozenLock, &Irql);
	for (ULONG i = 0; i < NXC_MAX_FROZEN; i++)
	{
		if (gFrozen[i] == Pid)
		{
			KeReleaseSpinLock(&gFrozenLock, Irql);
			ObfDereferenceObject(Process);
			FrzLog("[freeze] pid %u is already frozen -- REFUSED (suspends are refcounted; "
			       "nesting would need matched thaws)\n", Pid);
			return STATUS_ALREADY_COMMITTED;
		}
		if (gFrozen[i] == 0 && Slot == NXC_MAX_FROZEN)
			Slot = i;
	}
	if (Slot != NXC_MAX_FROZEN)
		gFrozen[Slot] = Pid;
	KeReleaseSpinLock(&gFrozenLock, Irql);

	if (Slot == NXC_MAX_FROZEN)
	{
		ObfDereferenceObject(Process);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	CONST NTSTATUS St = PsSuspendProcess(Process);

	if (!NT_SUCCESS(St))
	{
		/* Nothing was suspended, so release both the slot and the reference. */
		KeAcquireSpinLock(&gFrozenLock, &Irql);
		gFrozen[Slot]    = 0;
		gFrozenObj[Slot] = NULL;
		KeReleaseSpinLock(&gFrozenLock, Irql);
		ObfDereferenceObject(Process);
		FrzLog("[freeze] pid %u: PsSuspendProcess failed 0x%08X\n", Pid, St);
		return St;
	}

	/*
	 * ⚠ THE REFERENCE IS DELIBERATELY NOT RELEASED. It is what keeps the stored pointer meaning THIS
	 * process until thaw -- see the note on gFrozenObj. NxcThawProcess releases it.
	 */
	KeAcquireSpinLock(&gFrozenLock, &Irql);
	gFrozenObj[Slot] = Process;
	KeReleaseSpinLock(&gFrozenLock, Irql);

	FrzLog("[freeze] pid %u SUSPENDED (slot %u)\n", Pid, Slot);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcThawProcess(
	_In_ UINT32 Pid,
	_Out_ UINT32* OutThawed
	)
{
	*OutThawed = 0;
	EnsureInit();

	/*
	 * The registry is drained into a local FIRST, under the lock, and the resumes happen after it is
	 * released -- PsResumeProcess needs PASSIVE_LEVEL and the lock runs at DISPATCH.
	 *
	 * Slots are cleared as they are taken, so a concurrent thaw cannot resume the same process twice
	 * and drive the suspend count negative.
	 */
	UINT32 Take[NXC_MAX_FROZEN];
	PVOID  TakeObj[NXC_MAX_FROZEN];
	ULONG  n = 0;

	KIRQL Irql;
	KeAcquireSpinLock(&gFrozenLock, &Irql);
	for (ULONG i = 0; i < NXC_MAX_FROZEN; i++)
	{
		if (gFrozen[i] == 0)
			continue;
		if (Pid != 0 && gFrozen[i] != Pid)
			continue;
		Take[n]      = gFrozen[i];
		TakeObj[n]   = gFrozenObj[i];
		n++;
		gFrozen[i]    = 0;
		gFrozenObj[i] = NULL;
	}
	KeReleaseSpinLock(&gFrozenLock, Irql);

	if (n == 0)
		return STATUS_NOT_FOUND;

	UINT32 Done = 0;
	for (ULONG i = 0; i < n; i++)
	{
		/*
		 * ⚠ THE STORED POINTER IS USED, AND THE PID IS ONLY FOR THE LOG.
		 *
		 * Re-resolving with PsLookupProcessByProcessId here would be a real bug: Windows REUSES
		 * PIDs, a suspended process can still be terminated, and a new process can hold the same
		 * number by the time thaw runs. That lookup would then resume A PROCESS WE NEVER FROZE --
		 * and if something else had legitimately suspended it, we would have silently released it.
		 *
		 * The reference taken at freeze time is what makes this pointer still mean the same process.
		 */
		PVOID CONST Process = TakeObj[i];
		if (Process == NULL)
		{
			/* A slot recorded a pid with no object: only reachable if a freeze was interrupted
			 * between claiming the slot and publishing the reference. Nothing to resume, and saying
			 * so beats counting it as a success. */
			FrzLog("[freeze] pid %u had no held reference -- NOT resumed\n", Take[i]);
			continue;
		}

		CONST NTSTATUS St = PsResumeProcess(Process);

		/* Released here, matching the reference deliberately kept by NxcFreezeProcess. The process
		 * may well have exited while frozen; the reference kept its EPROCESS alive so that this
		 * resume had something valid to act on either way. */
		ObfDereferenceObject(Process);

		if (NT_SUCCESS(St))
		{
			Done++;
			FrzLog("[freeze] pid %u RESUMED\n", Take[i]);
		}
		else
		{
			FrzLog("[freeze] pid %u: PsResumeProcess failed 0x%08X -- STILL SUSPENDED\n",
			       Take[i], St);
		}
	}

	*OutThawed = Done;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcFreezeList(
	_Out_writes_(Cap) UINT32* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* OutCount
	)
{
	*OutCount = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	EnsureInit();

	KIRQL Irql;
	KeAcquireSpinLock(&gFrozenLock, &Irql);

	UINT32 n = 0;
	for (ULONG i = 0; i < NXC_MAX_FROZEN && n < Cap; i++)
	{
		if (gFrozen[i] != 0)
			Out[n++] = gFrozen[i];
	}

	KeReleaseSpinLock(&gFrozenLock, Irql);

	*OutCount = n;
	return STATUS_SUCCESS;
}
