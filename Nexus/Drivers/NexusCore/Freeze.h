/**
 * @file Freeze.h
 * @brief Suspend and resume a target process, with a registry so nothing can be left wedged.
 *
 * ============================================================================================
 * WHY THIS EXISTS
 * ============================================================================================
 *
 * A dump of a running target is not a consistent snapshot. The first page read and the last page
 * read are separated by milliseconds of the target's own execution, so a structure spanning them can
 * be captured half-updated -- a pointer already advanced next to the buffer it used to point at.
 * Freezing the target removes the disagreement, and `read --atomic` is the consumer.
 *
 * SUSPEND AND RESUME ONLY. Never terminate, never inject. Those are not capture and they are not in
 * scope for this framework.
 *
 * ============================================================================================
 * ⚠ THE REAL HAZARD IS AN UNBALANCED FREEZE
 * ============================================================================================
 *
 * A suspend with no matching resume leaves a process stopped forever -- and if the tool that issued
 * it dies in between, nothing remembers to undo it. Three things guard against that:
 *
 *   1. A REGISTRY. Every freeze is recorded, so `freeze list` can show what is stopped and
 *      `thaw --all` can release everything without knowing what was frozen or by whom.
 *   2. ONE FREEZE PER PROCESS. PsSuspendProcess is REFERENCE-COUNTED: two suspends need two resumes.
 *      Allowing nesting would make the count something the caller has to track, and a caller that
 *      lost count would leave a process suspended while `thaw` reported success. A second freeze is
 *      refused instead.
 *   3. `read --atomic` DOES ITS OWN freeze/read/thaw INSIDE ONE COMMAND, so the dangerous case -- a
 *      freeze whose thaw depends on a second round trip surviving -- is exactly the one that is
 *      never left to chance.
 *
 * ============================================================================================
 * ⚠ WHAT IS REFUSED, AND WHY REFUSING IS NOT CAUTION
 * ============================================================================================
 *
 * Suspending the wrong process does not fail, it HANGS THE MACHINE, and no error is reported because
 * the call succeeded. So the refusals below are the feature:
 *
 *   PID 0 and PID 4      Idle and System. Stopping System stops the kernel's own worker threads.
 *   PsIsSystemProcess    the same class, identified by the kernel rather than by a number.
 *   protected / PPL      cannot be suspended meaningfully, and asking is not a diagnostic.
 *   OUR OWN CALLER       PsSuspendProcess suspends every thread INCLUDING the one executing this
 *                        command, which never returns to release the command channel. The machine
 *                        would need a reboot to recover a mistyped PID.
 *
 * The caller's PID is the one that would actually get typed by accident, which is why it is checked
 * explicitly rather than assumed impossible.
 */

#pragma once

#include <ntddk.h>

/** Simultaneously frozen processes. Small on purpose: freezing many at once is not a capture. */
#define NXC_MAX_FROZEN   8u

/**
 * Suspend @p Pid and record it.
 *
 * @retval STATUS_SUCCESS               frozen and recorded
 * @retval STATUS_NOT_FOUND             no such process
 * @retval STATUS_ACCESS_DENIED         refused -- system, protected, or the caller itself
 * @retval STATUS_ALREADY_COMMITTED     already frozen by us; refused rather than nested
 * @retval STATUS_INSUFFICIENT_RESOURCES  registry full
 */
NTSTATUS NxcFreezeProcess(_In_ UINT32 Pid);

/**
 * Resume @p Pid, or EVERY frozen process when @p Pid is 0.
 *
 * @param OutThawed  how many were actually resumed
 * @retval STATUS_NOT_FOUND  that PID was not frozen by us (or nothing was)
 */
NTSTATUS NxcThawProcess(_In_ UINT32 Pid, _Out_ UINT32* OutThawed);

/**
 * Which processes we currently hold frozen.
 *
 * @param Out  receives up to @p Cap PIDs
 */
NTSTATUS NxcFreezeList(_Out_writes_(Cap) UINT32* Out, _In_ UINT32 Cap, _Out_ UINT32* OutCount);
