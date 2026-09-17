/**
 * @file Bp.h
 * @brief Hardware breakpoints. STAGE 1: READ. Two views, because there are two different truths.
 *
 * ============================================================================================
 * WHY READ-ONLY FIRST, AND WHY THAT IS NOT CAUTION FOR ITS OWN SAKE
 * ============================================================================================
 *
 * Arming DR0-DR3 does nothing useful on its own. When a debug register matches, the CPU raises
 * `#DB` -> IDT vector 1 -> the trap handler -> the exception dispatcher, and with nothing
 * intercepting that, the target receives `STATUS_SINGLE_STEP` and DIES. A `bp set` built before the
 * handler exists is not a capture tool; it is a way to kill the process being studied.
 *
 * The dispatcher is now IDENTIFIED (`the design notes` D16/D17) and deliberately NOT hooked -- patching
 * the path of every exception in the system is a decision, not a step. So arming waits.
 *
 * ============================================================================================
 * ⚠ TWO VIEWS, BECAUSE A "DEBUG REGISTER" MEANS TWO DIFFERENT THINGS
 * ============================================================================================
 *
 * **PER-CPU** -- what is physically in DR0-3/DR6/DR7 on each core right now. This is the CONTENTION
 * check, and it is the same discipline `trace arm` uses before touching PT: four registers per core,
 * anything can own them (a debugger, an anti-cheat, another driver), and arming over a live
 * breakpoint steals it as silently as arming PT over Ipt.sys would have.
 *
 * **PER-THREAD** -- what is in each thread's saved CONTEXT. This is what a breakpoint actually IS on
 * Windows, and the two can legitimately disagree: a thread not currently running holds its registers
 * in its context, not in any CPU.
 *
 * ⚠ THE RESEARCH THAT MADE THIS SPLIT NECESSARY (D22, four sources, three types):
 *
 *   - Windows keeps debug registers as PER-THREAD CONTEXT. `DISPATCHER_HEADER.DebugActive` is a mask
 *     of which DRs are valid for the thread; `KeContextToKframes`/`Ke386SanitizeDr` load and sanitise
 *     them across a context switch. **So a raw `__writedr` from a driver is per-CPU and TRANSIENT**
 *     -- a breakpoint on whatever runs next on that core, not on a thread. It would have presented
 *     as "works sometimes", which is the worst way for this to be wrong.
 *   - TIER 3 (v1, `Nexus/Kernel/src/debug/`) had the right architecture -- thread CONTEXT with
 *     `CONTEXT_DEBUG_REGISTERS` -- and reached for `Zw{Get,Set}ContextThread`, which are **NOT
 *     exported**. It resolved them with `MmGetSystemRoutineAddress`, got NULL, and bailed. v1's
 *     hardware breakpoints could never have run, with `PsGetContextThread`/`PsSetContextThread`
 *     (both exported, measured) sitting one name away.
 *
 * ============================================================================================
 * ⚠⚠ AND THE ONE THAT WOULD HAVE HUNG THE MACHINE
 * ============================================================================================
 *
 * ReactOS's `ntoskrnl/ps/debug.c`: for a thread OTHER than the current one, the context routines
 * **QUEUE AN APC AND WAIT FOR IT TO COMPLETE.** Get and Set share `PspGetOrSetContextKernelRoutine`,
 * so this is true of READING a context as well as writing one.
 *
 * **A SUSPENDED THREAD CANNOT DELIVER AN APC.** So any per-thread context operation against a FROZEN
 * process blocks the caller forever -- and the obvious workflow is exactly the trap: *freeze the
 * target, inspect or set its breakpoints, thaw*. That hangs the command path. Not a crash, which is
 * worse in one way: the machine looks healthy and the command simply never returns.
 *
 * So **every per-thread operation here REFUSES a frozen process**, checked against the freeze
 * registry v2 already maintains. Set-side gets the mirror rule (`freeze` refuses a process with live
 * breakpoints), or the deadlock is merely reordered rather than prevented.
 *
 * ⚠ ONE HAZARD ACCEPTED AND WRITTEN DOWN: DR7 bit 13 is GD, "general detect", which raises `#DB`
 * before ANY `mov` touching a debug register -- including the read of DR7 that would reveal GD is
 * set. There is no way to test for it without taking the risk, and this image has no SEH. Accepted
 * because nothing on a normal Windows system sets GD (every debugger reads DRs freely) and because
 * the resulting `#DB` clears GD before its handler runs. Recorded because "essentially never" is
 * exactly the class of assumption this project has been burned by.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"
/* NXC_BPD_SLOT, for NxcBpSlotTable below. One-directional: BpDispatch.h includes only ntddk.h, so
 * this cannot form a cycle -- and sharing the type is what keeps the slot table SINGLE. */
#include "BpDispatch.h"

#define NXC_BP_MAX_CPUS  64u

/*
 * ⚠ THE PER-CPU RECORD IS THE WIRE RECORD, `NXCMD_BP_CPU`, used directly rather than filled from a
 * driver-private twin. A private struct plus a copy loop is two layouts that must agree about which
 * of Local/Global/Type/Len is which, and the copy is written once and read never again. Sharing the
 * one definition removes the possibility instead of documenting it -- the same argument that makes
 * NXC_NT_API_LIST an X-macro.
 */
typedef NXCMD_BP_CPU NXC_BP_CPU;

/**
 * Read the PHYSICAL debug registers on every logical processor.
 *
 * ⚠ SAMPLED ON THE OWNING CORE, NEVER READ FROM ANOTHER -- the rule the PT MSRs needed. Debug
 * registers are per-processor, so reading them from whichever core services the command would report
 * that core's breakpoints under all 24 numbers: a wrong answer shaped exactly like a right one.
 */
NTSTATUS NxcBpRead(
	_Out_writes_(Cap) NXC_BP_CPU* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);

/**
 * Read each of a process's threads' SAVED debug registers, from their CONTEXT.
 *
 * ⚠ REFUSES A FROZEN PROCESS with STATUS_PROCESS_IS_TERMINATING-style clarity, because
 * `PsGetContextThread` on a non-current thread queues an APC and waits, and a suspended thread never
 * delivers it. This is the deadlock D22 found; the refusal is what makes the command safe to run
 * next to `freeze` at all.
 *
 * @param OutRefusedFrozen  set when the refusal above fired, so the caller can say WHY rather than
 *                          reporting an empty list
 */
NTSTATUS NxcBpReadThreads(
	_In_ UINT32 Pid,
	_Out_writes_(Cap) NXCMD_BP_THREAD* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* OutRefusedFrozen,
	/* ⚠ HOW MANY CONTEXT READS FAILED. Without this, a thread we could not examine is
	 * indistinguishable from one with no breakpoint set -- and the display asserted the latter for
	 * all of stage 1 while reading ZERO contexts. Absent is not the same as empty. */
	_Out_ UINT32* OutReadFailed
	);

/* ================================================================================================
 * ⚠⚠ STAGE 2 -- ARMING. THE INTERLOCK IS THE FEATURE.
 * ============================================================================================= */

/**
 * Is a `#DB` handler installed on the exception dispatcher?
 *
 * ⚠ THIS IS AN HONEST REPORT OF REALITY, NOT A PLACEHOLDER. Right now nothing is hooked, so it
 * returns FALSE, and `NxcBpSet` refuses on that basis. When item 15's patch lands this becomes true
 * and arming starts working with no other change. It is NOT a stub in the forbidden sense: it does
 * not fake success, it reports a state that is currently false and gates a dangerous operation on it.
 */
BOOLEAN NxcBpHandlerInstalled(void);

/**
 * The armed-slot table, read-only, for the exception observer's classifier.
 *
 * ⚠ ONE TABLE, NOT A MIRROR. `bp set` owns it; NxcBpdClassify needs it from another file while
 * running on the system's exception path. Two copies that must agree is the defect shape this
 * project keeps paying for -- and here a stale copy would mean CLAIMING an exception against a
 * breakpoint that is no longer armed, i.e. swallowing someone else's #DB.
 */
CONST NXC_BPD_SLOT* NxcBpSlotTable(void);

/** Which PID a slot was armed for. Carried into hit records so the stack can be read afterwards --
 *  the slot table holds CR3 for attribution, but a reader needs a pid to issue a process read. */
UINT32 NxcBpSlotPid(_In_ UINT32 Slot);

/** Was this slot armed with --pt? Bounding the PT buffer costs two WRMSRs and a fence per trap, so
 *  the opt-in is per-slot rather than global, and it is cleared when the slot is released. */
void    NxcBpSlotSetPtBound(_In_ UINT32 Slot, _In_ BOOLEAN On);
BOOLEAN NxcBpSlotPtBound(_In_ UINT32 Slot);

/**
 * Bitmask of the enabled slots in `Dr[0..3]` that WE armed, matched on index AND address.
 *
 * ⚠ `bp list`'s contention check had no way to ask this and warned about stealing a breakpoint
 * from ourselves. Worse than noise: with our slot live, a genuinely foreign one would have looked
 * exactly the same, so the check was blind precisely when it was needed.
 */
UINT32 NxcBpOwnedSlotMask(_In_reads_(NXC_BPD_MAX_SLOTS) CONST UINT64* Dr);

/* ================================================================================================
 * GLOBAL ARMING. The per-thread route is measurably unavailable (D54), so this is the one that
 * works -- CE's architecture, with attribution by CR3 in the classifier.
 * ============================================================================================= */

/**
 * Arm a breakpoint with the DR7 GLOBAL bit on every core, attributed to `Pid` by CR3.
 *
 * ⚠⚠ REFUSES UNLESS CLAIMING IS ENABLED, and that is the point rather than a precaution. A global
 * DR watches a LINEAR ADDRESS on every CPU whatever address space is loaded, so an unrelated
 * process touching the same linear address traps too. If nothing claims, that process receives
 * STATUS_SINGLE_STEP and dies looking like it crashed by itself.
 *
 * ⚠ EXECUTE breakpoints are refused: they cannot be resumed without EFLAGS.RF, which needs the
 * unexported KTRAP_FRAME, so one would trap forever with nobody able to swallow it.
 */
NTSTATUS NxcBpSetGlobal(
	_In_ UINT32 Pid,
	_In_ UINT64 Address,
	_In_ UINT32 Type,
	_In_ UINT32 Len,
	_Out_ UINT32* OutSlot,
	_Out_ UINT32* OutCpus
	);

/** Disarm a global slot on every core. Registers first, then the table -- see the implementation. */
NTSTATUS NxcBpClearGlobal(_In_ UINT32 Slot);

/**
 * Arm TWO execute breakpoints as one operation -- build-plan item 14 (`bp fork`).
 *
 * ⚠ THE VALUE IS THE ROLLBACK, NOT THE SPEED. Two `NxcBpSetGlobal` calls from usermode can leave
 * site 0 armed when site 1 refuses, and that half-armed state produces hits which are true but
 * UNPAIRED -- indistinguishable, in the record, from half of a real paired capture. Here a failure
 * at site 1 disarms site 0 before returning, so "this command failed" and "nothing is armed" are the
 * same fact rather than two that have to agree.
 *
 * Both are EXECUTE (R/W=00, LEN=00) and inherit that gate: refused until KTRAP_FRAME.EFlags is
 * proven, since resuming an execute breakpoint needs EFLAGS.RF.
 *
 * ⚠ Va0 == Va1 is REFUSED. Two slots on one address is not a fork; it burns a slot and reports
 * doubled hits for a single site, which is worse than useless because it looks like data.
 */
NTSTATUS NxcBpSetFork(
	_In_ UINT32 Pid,
	_In_ UINT64 Va0,
	_In_ UINT64 Va1,
	_Out_ UINT32* OutSlot0,
	_Out_ UINT32* OutSlot1,
	_Out_ UINT32* OutCpus
	);

/**
 * Probe PsGetContextThread three ways -- the caller's own thread (direct capture), another thread
 * in the caller's process, and a thread in `CrossPid` (both via the special-kernel-APC rendezvous).
 *
 * Exists because the API refuses EVERY thread of a live usermode process here with
 * STATUS_UNSUCCESSFUL, and a failed read was indistinguishable from a read that found nothing --
 * so `bp list` reported "no thread has a breakpoint" while reading zero contexts. READS ONLY.
 */
NTSTATUS NxcBpCtxProbe(
	_In_ UINT32 CrossPid,
	_Out_ UINT64* OutSelf,
	_Out_ UINT64* OutSameProcess,
	_Out_ UINT64* OutCrossProcess,
	/* IRQL of the caller. KeInsertQueueApc is the single failure path; the caller's own state is
	 * therefore evidence, and CR8 costs no nt import. */
	_Out_ UINT64* OutIrql,
	/* Did KeInsertQueueApc accept an APC queued DIRECTLY from here, to our own thread? This is the
	 * discriminator: PsGetContextThread's only failure IS that call returning FALSE. */
	_Out_ UINT64* OutApcInsert,
	_Out_ UINT64* OutApcRan,
	/* One nibble per ContextFlags set tried (CONTROL, INTEGER, DEBUG_REGISTERS, FULL): 0 succeeded,
	 * 1 refused. The STATUS is already known; WHICH REQUESTS are refused is not. */
	_Out_ UINT64* OutFlagProbe
	);

/**
 * Arm a hardware breakpoint on EVERY thread of a process.
 *
 * ⚠⚠ REFUSES WHILE NO DISPATCHER HANDLER IS INSTALLED, AND THAT REFUSAL IS THE WHOLE POINT.
 *
 * When DR0-3 match, the CPU raises `#DB` -> IDT vector 1 -> the trap handler -> the exception
 * dispatcher. With nothing intercepting that, the target receives `STATUS_SINGLE_STEP` and **DIES**.
 * So an armed breakpoint without a handler is not a capture tool; it is a way to kill the process
 * being studied, and it would do so on the FIRST hit, in a way that looks like the target crashing
 * on its own.
 *
 * Bp.h has said that in prose since this file was created. Prose is not an interlock. This is:
 * arming is impossible, by construction, until the handler exists.
 *
 * ⚠ REFUSES A FROZEN PROCESS, for the same reason the read side does: `PsSetContextThread` on a
 * non-current thread queues an APC and WAITS, and a suspended thread never delivers it (D22).
 *
 * ⚠ COVERAGE IS A POINT-IN-TIME SNAPSHOT AND SAYS SO. A thread created after this returns has its
 * own context and none of our registers. `PsSetCreateThreadNotifyRoutine` is the route (exported,
 * measured at RVA 0x77B0C0) and until it exists the caller is told how many threads were covered
 * rather than being allowed to assume "the process".
 *
 * @param Pid       target
 * @param Address   linear address to watch
 * @param Type      DR7 R/W encoding: 0 exec, 1 write, 3 read-write
 * @param Len       DR7 LEN encoding: 0 = 1 byte, 1 = 2, 2 = 8, 3 = 4
 * @param OutSlot   the DR slot used
 * @param OutThreads threads actually armed -- point-in-time, never "the process"
 */
/**
 * @param OutDiag  WHY the arming loop lost threads, packed as four 16-bit counts:
 *                 [15:0] threads found, [31:16] skipped as terminating,
 *                 [47:32] PsLookupThreadByThreadId failed, [63:48] PsSetContextThread refused.
 *
 * ⚠ EXISTS BECAUSE "0 armed" NAMES NOTHING. The first live attempt returned a bare
 * STATUS_UNSUCCESSFUL and logged the breakdown to BpLog -- i.e. to DbgPrint, where the operator
 * cannot see it -- so usermode asserted a cause the numbers did not support. Four quite different
 * failures produce "0 armed", and the counts are the only thing that separates them.
 */
NTSTATUS NxcBpSet(
	_In_ UINT32 Pid,
	_In_ UINT64 Address,
	_In_ UINT32 Type,
	_In_ UINT32 Len,
	_Out_ UINT32* OutSlot,
	_Out_ UINT32* OutThreads,
	_Out_ UINT64* OutDiag,
	/* [31:0] first PsGetContextThread failure, [63:32] first PsSetContextThread failure.
	 * Separate from the return status, which is AMBIGUOUS -- those APIs can themselves return
	 * STATUS_UNSUCCESSFUL, indistinguishable from the generic fallback. */
	_Out_ UINT64* OutDiag2
	);

/** Disarm a slot across every thread of the process it was armed for. */
NTSTATUS NxcBpClear(
	_In_ UINT32 Slot,
	_Out_ UINT32* OutThreads
	);

/**
 * Does this process have any breakpoint armed by us?
 *
 * ⚠ THE MIRROR OF THE FROZEN REFUSAL (D22). `bp set` refuses a frozen process because the APC would
 * never be delivered; without this, `freeze` could be called AFTERWARDS and the deadlock would be
 * merely REORDERED rather than prevented -- a later `bp clear` or `bp list` would then hang. Freeze
 * consults this and refuses.
 */
BOOLEAN NxcBpProcessHasBreakpoints(_In_ UINT32 Pid);
