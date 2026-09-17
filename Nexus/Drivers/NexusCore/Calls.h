/*
 * Calls.h -- call evidence from an inline hook. B-01 (file capture) / B-02 (object + registry).
 * The reasoning lives in Calls.c, next to the code it governs.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

NTSTATUS
NxcCallsInit(
	_In_  UINT32  Slots,
	_Out_ UINT32* OutSlots
	);

/* Called from NxcHookOnHit. Runs at the target's IRQL, in the CALLER's context -- which is exactly
 * what makes the usermode string pointers in Arg2/Arg3 dereferenceable here and nowhere else. */
void
NxcCallsRecord(
	_In_ UINT64 TargetVa,
	_In_ UINT64 ReturnAddress,
	_In_ UINT64 Arg1,
	_In_ UINT64 Arg2,
	_In_ UINT64 Arg3,
	_In_ UINT64 Arg4,
	_In_ UINT64 EntryRsp,
	_In_ UINT32 Flags
	);

NTSTATUS
NxcCallsRead(
	_Out_writes_(Cap) NXCMD_CALL_ENTRY* Out,
	_In_  UINT32  Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutDropped,
	_Out_ UINT64* OutNamed
	);

void
NxcCallsStats(
	_Out_ UINT32* OutSlots,
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutDropped,
	_Out_ UINT64* OutNamed,
	_Out_ UINT64* OutExtent
	);
