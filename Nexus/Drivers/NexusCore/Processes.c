/**
 * @file Processes.c
 * @brief PID-space sweep. The design reasoning lives in Processes.h -- read it first.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Processes.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define ProcLog NxcLogExt

NTSTATUS
NxcEnumProcesses(
	_Out_writes_(Cap) NXCMD_PROCESS_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* SweptTo,
	_Out_ UINT32* ElapsedUs
	)
{
	*Got       = 0;
	*Total     = 0;
	*SweptTo   = 0;
	*ElapsedUs = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	LARGE_INTEGER Freq;
	Freq.QuadPart = 0;
	CONST LARGE_INTEGER Start = KeQueryPerformanceCounter(&Freq);

	UINT32 Found = 0;
	UINT32 Wrote = 0;

	for (UINT32 Pid = 0; Pid < NXC_PID_CEILING; Pid += 4)
	{
		PVOID Process = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process)) ||
		    Process == NULL)
			continue;

		Found++;

		if (Wrote < Cap)
		{
			NXCMD_PROCESS_ENTRY* CONST E = &Out[Wrote];
			RtlZeroMemory(E, sizeof(*E));

			E->Pid        = Pid;
			E->ParentPid  = (NXCMD_U32)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(Process);
			E->SessionId  = (NXCMD_U32)PsGetProcessSessionId(Process);
			E->CreateTime = (NXCMD_U64)PsGetProcessCreateTimeQuadPart(Process);

			/*
			 * ImageFileName is a fixed 15-char array inside EPROCESS, NOT a pointer to a string, and
			 * Windows itself truncates long names into it ("gameservicelaunc"). Copied byte by byte
			 * with the terminator forced, because the source is not guaranteed NUL-terminated when
			 * the name fills the field -- a strcpy here would read past it.
			 */
			CONST CHAR* CONST Name = PsGetProcessImageFileName(Process);
			if (Name != NULL)
			{
				for (UINT32 i = 0; i < sizeof(E->Name) - 1; i++)
				{
					E->Name[i] = (NXCMD_U8)Name[i];
					if (Name[i] == '\0')
						break;
				}
				E->Name[sizeof(E->Name) - 1] = '\0';
			}

			Wrote++;
		}

		ObfDereferenceObject(Process);
	}

	CONST LARGE_INTEGER End = KeQueryPerformanceCounter(NULL);
	if (Freq.QuadPart > 0)
		*ElapsedUs = (UINT32)(((End.QuadPart - Start.QuadPart) * 1000000LL) / Freq.QuadPart);

	if (Wrote < Found && Wrote > 0)
		Out[0].Flags |= NXC_PROC_FLAG_TRUNCATED;

	*Got     = Wrote;
	*Total   = Found;
	*SweptTo = NXC_PID_CEILING;

	ProcLog("procs: %u found, %u returned, swept to %u, %u us\n",
	        Found, Wrote, NXC_PID_CEILING, *ElapsedUs);
	return STATUS_SUCCESS;
}
