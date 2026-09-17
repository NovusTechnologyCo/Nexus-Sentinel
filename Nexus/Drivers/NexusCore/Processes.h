/**
 * @file Processes.h
 * @brief Process enumeration by sweeping the PID space.
 *
 * ============================================================================================
 * WHY THIS IS A KERNEL COMMAND AT ALL
 * ============================================================================================
 *
 * Its stated job -- "pick a target" -- does not need the kernel. PlatformCtl can call
 * CreateToolhelp32Snapshot and be done, with no opcode, no ABI surface, no staging buffer and no
 * truncation story. That was very nearly the answer.
 *
 * What makes it worth a kernel command is the SUBTRACTION, exactly as with regions vs modules:
 *
 *   usermode snapshot   what the system ADMITS to  (walks ActiveProcessLinks, eventually)
 *   this sweep          what actually EXISTS       (the PspCidTable, via PsLookupProcessByProcessId)
 *
 * Those are different structures. Unlinking an EPROCESS from ActiveProcessLinks -- the oldest and
 * still most common way to hide a process -- removes it from every usermode enumeration while
 * leaving it fully resolvable by PID, because the CID table is not the list that was edited. So the
 * difference between the two enumerations is a detection, and it comes free with the sweep.
 *
 * ⚠ THIS IS A GENERAL MECHANISM, NOT A TARGET-SPECIFIC ONE. It knows nothing about any particular
 * process. It reports the EVIDENCE -- present in one enumeration, absent from the other -- and
 * leaves the verdict to whoever reads it. Same discipline as `regions --hidden`.
 *
 * ============================================================================================
 * WHY A SWEEP RATHER THAN A LIST WALK
 * ============================================================================================
 *
 * The direct alternative is walking PsActiveProcessHead. It is UNEXPORTED, so reaching it means a
 * byte-pattern scan of ntoskrnl -- an assumption that cannot be verified at runtime, which is the
 * same reason Pte.h rejected resolving MmSetPageProtection by signature. It is also the very list a
 * hidden process has been unlinked from, so it could not detect the thing this exists to detect.
 *
 * The sweep needs no unexported symbol, pins no offset, and asks the CID table directly. Its cost is
 * one hash lookup per candidate PID, at PASSIVE_LEVEL, on a diagnostic path. That cost is MEASURED
 * and logged rather than assumed -- if it turns out to matter, the number will say so.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/*
 * Sweep ceiling for the CID space. CIDs are allocated as multiples of 4, so every sweep steps by 4
 * and this covers 131072 candidates.
 *
 * ⚠⚠ ONE CONSTANT FOR PROCESSES AND THREADS, because Windows allocates BOTH from the SAME handle
 * table (PspCidTable). A pid and a tid are drawn from one numeric namespace and never collide --
 * MEASURED on this machine, 14 minutes after boot: max pid 27476 (0x6B54), max tid 27616
 * (0x6BE0), interleaved. There is no such thing as a "tid range" separate from the pid range.
 *
 * ⚠ THIS CORRECTS A REAL DEFECT. Threads.c swept to 0x40000 under a comment asserting "the ceiling
 * matches Processes.c deliberately" -- while Processes.h said 0x80000. Half the space, and the
 * comment claiming otherwise is what made it invisible: a reader checking the invariant would have
 * read the sentence and stopped. The consequence is worse than a short enumeration: `bp set` arms a
 * breakpoint on EVERY thread of a process, so a tid past the ceiling is a thread that silently does
 * not get one. "Works, except on the threads it doesn't" is precisely the failure mode D22's
 * per-thread design exists to avoid.
 *
 * ⚠ AND THE HARDWARE PASS DID NOT CATCH IT. `threads <pid>` was verified twice with exact counts;
 * both runs had every tid under 0x6BE0, so the bound was never approached. That is a test of the one
 * case where the defect is invisible -- the tidy-fixture lesson again, in a different costume.
 *
 * A CEILING IS A LIE UNLESS IT IS REPORTED. Windows will hand out ids above this on a long-lived
 * machine, so a sweep can miss one -- and a miss that looks like an absence would turn `--hidden`
 * inside out, reporting something as concealed when it was merely out of range. Every sweep returns
 * the ceiling it actually swept, and the caller prints it.
 */
#define NXC_CID_CEILING   0x80000u

/** Kept as the process-side spelling; they are the same space and must stay the same number. */
#define NXC_PID_CEILING   NXC_CID_CEILING

/** Set on entry 0 when the caller's buffer could not hold every process found. */
#define NXC_PROC_FLAG_TRUNCATED   0x00000001u

/**
 * Sweep the PID space.
 *
 * @param Got         entries written (<= Cap)
 * @param Total       processes FOUND. Separate from Got so truncation cannot read as completeness.
 * @param SweptTo     the PID ceiling actually swept -- see the warning on NXC_PID_CEILING
 * @param ElapsedUs   how long the sweep took, measured not estimated
 */
NTSTATUS NxcEnumProcesses(
	_Out_writes_(Cap) NXCMD_PROCESS_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* SweptTo,
	_Out_ UINT32* ElapsedUs
	);
