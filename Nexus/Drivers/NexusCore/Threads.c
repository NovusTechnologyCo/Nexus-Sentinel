/**
 * @file Threads.c
 * @brief CID sweep for a process's threads. Reasoning, and the export measurements, in Threads.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Threads.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define ThrLog NxcLogExt

/*
 * The CID space is swept in steps of 4 for the same reason `procs` does it: CIDs are allocated from
 * a handle table whose entries are 4-aligned, so three quarters of the space can never hold one.
 *
 * ⚠ THE CEILING IS NOW THE SHARED CONSTANT, NOT A LOCAL COPY. This line used to read 0x40000 under a
 * comment asserting it matched Processes.c -- which said 0x80000. Two sweeps of ONE namespace that
 * disagree about its size produce a `--hidden` diff made of nothing but the difference in bounds,
 * which is exactly what the old comment said must not happen while the code did it. Taking the number
 * from Processes.h makes the claim structural instead of asserted. (see NXC_CID_CEILING.)
 */
#define NXC_TID_CEILING   NXC_CID_CEILING

NTSTATUS
NxcEnumThreads(
	_In_ UINT32 Pid,
	_Out_writes_(Cap) NXCMD_THREAD_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* SweptTo
	)
{
	*Got     = 0;
	*Total   = 0;
	*SweptTo = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	UINT32 Found = 0;
	UINT32 Wrote = 0;

	for (UINT32 Tid = 0; Tid < NXC_TID_CEILING; Tid += 4)
	{
		PETHREAD Thread = NULL;
		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &Thread)) ||
		    Thread == NULL)
		{
			continue;
		}

		/*
		 * The filter. Asking each thread who owns it is what turns a sweep of the whole CID space
		 * into "this process's threads", and it uses only exported calls -- the direct route
		 * (PsGetNextProcessThread over the PEPROCESS) is NOT exported on this build, measured.
		 */
		if ((UINT32)(ULONG_PTR)PsGetThreadProcessId(Thread) != Pid)
		{
			ObfDereferenceObject(Thread);
			continue;
		}

		Found++;

		if (Wrote < Cap)
		{
			NXCMD_THREAD_ENTRY* CONST E = &Out[Wrote];
			RtlZeroMemory(E, sizeof(*E));

			E->ThreadId  = (NXCMD_U32)(ULONG_PTR)PsGetThreadId(Thread);
			E->ProcessId = Pid;
			E->Teb       = (NXCMD_U64)(ULONG_PTR)PsGetThreadTeb(Thread);
			E->CreateTime = (NXCMD_U64)PsGetThreadCreateTime(Thread);

			/*
			 * ⚠ TERMINATING IS REPORTED, NEVER SILENTLY FILTERED. A thread that has exited but is
			 * still referenced stays in the CID table and vanishes from the usermode snapshot --
			 * which is exactly how `procs --hidden` produced 7 false positives on its first run.
			 *
			 * Dropping them here would fix the diff and lose a fact: a terminating thread IS a real
			 * thing about the process, and a caller comparing against a snapshot needs to know which
			 * side of that difference it is looking at. So it is a FLAG, and the subtraction that
			 * builds `--hidden` is what consults it.
			 */
			E->Terminating = PsIsThreadTerminating(Thread) ? 1u : 0u;

			Wrote++;
		}

		ObfDereferenceObject(Thread);
	}

	*Got     = Wrote;
	*Total   = Found;
	*SweptTo = NXC_TID_CEILING;

	ThrLog("threads: pid %u -- %u found, %u reported (swept to %u)\n",
	       Pid, Found, Wrote, NXC_TID_CEILING);

	return STATUS_SUCCESS;
}
