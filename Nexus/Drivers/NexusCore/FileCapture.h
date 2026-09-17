/*
 * FileCapture.h -- B-01's second half. The reasoning lives in FileCapture.c.
 *
 * The hook references a FILE_OBJECT and queues it; a system thread resolves the name, opens by path
 * and reads. Nothing expensive happens on the caller's thread.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

NTSTATUS
NxcFileCaptureInit(
	_In_  UINT32  Slots,
	_In_  UINT32  ByteBudgetKb,
	_Out_ UINT32* OutSlots
	);

/* Called from the NtSetInformationFile hook when the class is a delete disposition. Runs on the
 * caller's thread at the function ENTRY, so it does object-manager work only -- no I/O. */
void
NxcFileCaptureOnDelete(
	_In_ UINT64 Handle,
	_In_ UINT32 InfoClass
	);

/* The OTHER delete: FILE_DELETE_ON_CLOSE at create, which never reaches NtSetInformationFile at all.
 * Queues the PATH, because at the NtCreateFile entry the handle does not exist yet -- and the path is
 * live, because delete-on-close cannot have fired on a file only now being opened. */
void
NxcFileCaptureOnCreateDeleteOnClose(
	_In_reads_(NameChars) CONST UINT16* Name,
	_In_ UINT32 NameChars,
	_In_ UINT32 CreateOptions
	);

NTSTATUS
NxcFileCaptureRead(
	_Out_writes_(Cap) NXCMD_FCAP_ENTRY* Out,
	_In_  UINT32  Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT64* OutTotal
	);

/* Bytes out of the capture arena, bounded by what has actually been WRITTEN. */
NTSTATUS
NxcFileCapturePull(
	_In_  UINT64  ByteOffset,
	_In_  UINT32  Bytes,
	_Out_writes_bytes_(Bytes) void* Out,
	_Out_ UINT32* OutCopied
	);

void
NxcFileCaptureStats(
	_Out_ NXCMD_FCAP_STATS* Out
	);
