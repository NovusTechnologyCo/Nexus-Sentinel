/**
 * @file Threads.h
 * @brief Enumerate a process's threads FROM THE KERNEL, by CID sweep. Item 13's prerequisite.
 *
 * ============================================================================================
 * WHY THIS EXISTS AT ALL, AND WHY NOW
 * ============================================================================================
 *
 * v2 had NO thread surface. That was survivable until `bp set`: D19 established that a hardware
 * breakpoint "on a process" is a debug-register write on EVERY THREAD in it, because Windows keeps
 * debug registers as per-thread context and restores them across a context switch. So enumerating
 * threads is not an adjacent nicety for item 13 -- it is the thing item 13 is built on, and it was
 * found by mapping v1's ioctl surface rather than by hitting the wall an hour into coding (D20).
 *
 * ============================================================================================
 * ⚠ WHY NOT `ZwQuerySystemInformation`, WHICH IS WHAT v1 USED
 * ============================================================================================
 *
 * TIER 3 (`Nexus/Kernel/src/thread/thread.cpp`, `NexusEnumThreads`): v1 queried
 * `SystemProcessInformation` and read `NumberOfThreads` plus the trailing thread array.
 *
 * ⚠ THAT IS THE USERMODE-VISIBLE SNAPSHOT -- the same source Toolhelp reads, and precisely the
 * source anything concealed would be ABSENT FROM. v2 already treats that snapshot as a thing to
 * check against rather than to trust: `procs --hidden` is a CID-table sweep MINUS the usermode
 * snapshot, and it exists because the snapshot can lie. Enumerating threads from it would inherit
 * the blind spot the rest of this phase was built to close.
 *
 * TIER 4: sweep the CID space from the kernel, exactly as `procs` does. Independent of the snapshot,
 * which means the two can be COMPARED -- and `threads --hidden` then falls out of the same
 * subtraction that already works for processes, for free.
 *
 * ============================================================================================
 * ⚠ EVERY API HERE WAS MEASURED, NOT ASSUMED -- v1 GOT THIS WRONG TWICE
 * ============================================================================================
 *
 * Measured against this machine's ntoskrnl with `tools/ntos_exports.py`:
 *
 *   EXPORTED      PsLookupThreadByThreadId, PsGetThreadId, PsGetThreadProcessId,
 *                 PsGetThreadTeb, PsIsThreadTerminating, PsGetThreadCreateTime
 *   NOT EXPORTED  PsGetNextProcessThread
 *
 * So the obvious iteration -- walk the process's own thread list with `PsGetNextProcessThread` -- is
 * NOT AVAILABLE, and v1's plan to use it could never have run. v1 also states in a comment that
 * "PsGetThreadTeb is not exported, so we skip TEB for now"; on this build **it is exported**. Two
 * unchecked claims in one file, which is why every name above was put through the export tool
 * instead of trusted (an earlier finding).
 *
 * ⚠ AND THE ZOMBIE LESSON IS APPLIED BY CONSTRUCTION, NOT AFTER A FALSE POSITIVE. `procs --hidden`
 * reported 7 false positives on its first run because a TERMINATED-but-still-referenced process
 * stays in the CID table while vanishing from the usermode snapshot. Threads have exactly the same
 * shape, and `PsIsThreadTerminating` is the kernel-side discriminator -- checked here from the
 * start, so the same defect is not rediscovered a second time.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/* For NXC_CID_CEILING -- processes and threads are ONE namespace, so they share ONE ceiling. */
#include "Processes.h"

/**
 * Enumerate every thread belonging to @p Pid.
 *
 * ⚠ THE SWEEP IS THE POINT. Thread IDs come from the same CID space as process IDs, so this walks it
 * and asks each candidate which process owns it. That is O(ceiling) rather than O(threads), and it
 * is worth it for the same reason `procs` pays the cost: an enumeration derived from the kernel's
 * own object manager cannot be edited by a target the way a snapshot can.
 *
 * @param Pid        owning process; every thread whose `PsGetThreadProcessId` matches is reported
 * @param Got        entries written
 * @param Total      threads FOUND, which may exceed Got (D3 -- truncation must never read as
 *                   completeness)
 * @param SweptTo    the CID value the sweep reached, so a partial sweep is visible as one
 */
NTSTATUS NxcEnumThreads(
	_In_ UINT32 Pid,
	_Out_writes_(Cap) NXCMD_THREAD_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* SweptTo
	);
