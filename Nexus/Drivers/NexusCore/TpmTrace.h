/**
 * @file TpmTrace.h
 * @brief OBSERVE TPM command traffic. Decode nothing, change nothing, answer one question.
 *
 * WHY (the design notes)
 * ------------------------------------------------------
 * The SB spoof's remaining limits -- rung C (replay the log against the REAL PCR values) and rung
 * D (TPM2_Quote) -- are accepted on one calibration: "it reads no PCRs and issues no Quote".
 * That is an assertion about one target from one investigation, and the entire decision to stop
 * work on C/D rests on it.
 *
 * A verifier cannot exercise C without TPM2_PCR_Read, nor D without TPM2_Quote. Both are TPM
 * commands with a fixed header. So the question is measurable, and this measures it.
 *
 * ⚠ STRICTLY OBSERVATIONAL, AND THE REASON IS MEASUREMENT VALIDITY.
 * This project already modifies what a verifier sees -- Tier 1 hooks GetVariable, Tier 3 rewrites
 * the TCG log, the DXE rewrites bootmgr's PCR snapshot. Those are the PRODUCT. This is the
 * INSTRUMENT, and an instrument that alters the traffic it measures cannot tell you what the
 * target does. That is the mirror-oracle failure this project has already paid for twice (the
 * `Setup` b52 byte; the C-vs-Python transform comparison). This records the request and returns 0
 * so the target's call proceeds untouched. It never rewrites a request or a response.
 *
 * WHY THE KERNEL DISPATCH AND NOT tbs.dll
 * ---------------------------------------
 * `\Driver\TPM`'s IRP_MJ_DEVICE_CONTROL is the one chokepoint every TPM command crosses --
 * usermode traffic funnelled through the TBS service AND commands issued by other kernel drivers.
 * A usermode hook on Tbsip_Submit_Command would miss the second category entirely, and the target
 * whose behaviour actually matters (per done-list item 3a) is a ~70 MB kernel driver. Hooking one
 * ring-3 export would have measured the wrong half of the problem.
 *
 * ETW was tried first and produced nothing: the `TPM` provider {1B6B0772-251B-4D42-917D-
 * FACA166BC059} is a WPP provider that emits no events in retail. A trace wrapped around a live
 * TPM2_PCR_Read yielded 1 event, id 0 -- the ETL header. measured.
 *
 * FAIL OPEN ON CAPTURE, NEVER ON THE TARGET'S CALL. Every path returns without disturbing the IRP.
 * When the command bytes cannot be safely reached the record is still written, carrying an
 * NXCMD_TPM_WHY_* code -- an empty capture with a stated cause, never a silent zero.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/**
 * Resolve \Driver\TPM's IRP_MJ_DEVICE_CONTROL dispatch -- the VA to hook with --tpm.
 * Returns 0 on failure with a NXCMD_TPM_RESOLVE_* reason. Never fatal.
 */
UINT64
NxcTpmResolveDispatch(
	_Out_ UINT32* OutWhy
	);

/** How many TPM device objects the record filter is bound to. 0 = filter OPEN (everything). */
UINT32
NxcTpmBoundDeviceCount(
	void
	);

/**
 * Reserve the ring from the ARENA (D4), owner-tagged and bounded. Idempotent: a second call with
 * the same slot count is a no-op rather than a leak.
 */
NTSTATUS
NxcTpmTraceInit(
	_In_  UINT32 Slots,
	_Out_ UINT32* OutDetail
	);

/**
 * Record one TPM device-control request. Called from NxcHookOnHit for a hook carrying
 * NXC_HOOK_FLAG_TPM, on the CALLER'S OWN THREAD -- which is the only context where the issuing
 * process id is the right answer.
 *
 * @param DeviceObject  the dispatch's arg1, unused but taken so the shape matches the target
 * @param Irp           the dispatch's arg2
 */
void
NxcTpmTraceRecord(
	_In_ UINT64 DeviceObject,
	_In_ UINT64 Irp
	);

/**
 * Drain to the caller's OutBuffer (D2). Reports what was PRODUCED, not what was requested (D3):
 * Count is what fit, Total is what exists, Dropped is what the producer could not record.
 */
NTSTATUS
NxcTpmTraceRead(
	_Out_writes_bytes_(Cap) void* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutCount,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutDropped
	);

/** Release the arena extent. Safe to call when never initialised. */
void
NxcTpmTraceTeardown(
	void
	);
