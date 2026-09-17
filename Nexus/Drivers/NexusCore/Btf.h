/*
 * Btf.h -- BRANCH-STEPPING (D119). IA32_DEBUGCTL[1] + EFLAGS.TF.
 *
 * The processor raises #DB after every instruction THAT CAUSES A BRANCH instead of after every
 * instruction. That is control-flow tracing of a target while modifying NOT ONE BYTE of it -- no
 * inline hook, no trampoline, no page alias. For code that checksums itself, that is the whole
 * point, and it is the one tracing surface here with no observable footprint in the target.
 *
 * ⚠⚠ BTF IS ONE-SHOT AND THAT GOVERNS THE ENTIRE DESIGN. SDM vol 3, 19.4.3:
 *
 *     "The processor clears the BTF flag when it generates a debug exception. The debugger must
 *      set the BTF flag before resuming program execution to continue single-stepping on branches."
 *
 * So every #DB clears it. Arming once would step exactly ONE branch and then silently degrade to
 * per-INSTRUCTION stepping, because EFLAGS.TF is still set -- the failure is a TRAP FLOOD, not a
 * silence, which is why it had to be known before a line was written. The only place reliably
 * between two branches of a running thread is the #DB handler that just took one, so the re-arm
 * lives in the dispatcher and nowhere else.
 *
 * ⚠ SCOPE IS EFLAGS.TF, NOT THIS MSR. DEBUGCTL is per-core, so BTF is set on every core -- but it
 * only does anything to a thread whose EFLAGS.TF is set, and only the target's is. Arming all cores
 * therefore steps nothing else. TF is set INITIALLY from usermode through SetThreadContext on a
 * handle (D1), which keeps arming out of the trap frame entirely.
 *
 * ⚠⚠ BUT TF MUST ALSO BE RE-SET ON EVERY TRAP, AND THAT WAS NOT IN THE ORIGINAL DESIGN. D119
 * reasoned that only BTF needed re-arming, because the SDM says the PROCESSOR clears BTF and says
 * nothing about clearing TF. True of the processor, false of the SYSTEM: measured on the
 * first hardware run, a 1-second window recorded EXACTLY ONE branch, and the target's own thread
 * context then reported TF CLEAR. Windows' debug-trap path clears TF in the frame before
 * dispatching, and we SWALLOW the exception, so nothing re-sets it.
 *
 * So the dispatcher writes TF back into the live trap frame through the PROVEN KTRAP_FRAME.EFlags
 * offset, behind the same shape gate the EFLAGS.RF write uses. Reading could not have found this --
 * it is why a feature that compiles is not a feature.
 *
 * ⚠ THE RECORD IS DELIBERATELY TINY. A full NXC_BPD_HIT -- registers, 256 bytes of stack, an LBR
 * ring -- is unaffordable at branch rate. A branch record is an IP, a sequence number and the core.
 * D3 still applies: the drain reports what was PRODUCED, and drops are counted, never hidden.
 */
#pragma once

#include <ntddk.h>
#include "Translate.h"   /* NxcTranslateDtbOffset -- one derivation, not a second */

/*
 * ⚠ SIZED FROM A MEASURED BURST, NOT PICKED. Bounded on purpose -- this is the memory a branch flood
 * can consume, and an unbounded ring trades a known cost for an unknown one (same reasoning as
 * NXC_LBR_MAX_SNAPSHOTS). But 8192 was too small once the ring became a real ring:
 *
 *   measured, 48-byte filter, 2 s window, continuous drain:
 *     291,483 records kept, 728 DROPPED
 *
 * The drain was keeping up 99.75% of the time; the losses were BURSTS. At the ~150K qualifying
 * branches/sec that run produced, 8192 slots is ~55 ms of headroom and a scheduling hiccup in the
 * draining thread eats that. 32768 gives ~220 ms, and unfiltered (~2.3M/sec) it is ~14 ms against
 * the old 3.5 ms.
 *
 * COST: 32768 * 24 B of records + 32768 * 8 B of commit markers = ~1 MB of non-paged static. Stated
 * because it is charged whether branch stepping is used or not.
 */
#define NXC_BTF_MAX_RECORDS 32768u

#pragma pack(push, 1)
typedef struct _NXC_BTF_REC
{
	UINT64 Rip;         /* the branch TARGET -- where control landed                     */
	UINT64 Sequence;    /* monotonic, so a gap in the drain is a visible loss            */
	UINT32 Cpu;
	UINT32 Reserved0;
} NXC_BTF_REC;
#pragma pack(pop)

/**
 * Arm branch-stepping for one address space.
 *
 * @param Pid   the target. Its CR3 is resolved HERE through the proven DTB offset, because usermode
 *              has no business holding a CR3 and a caller-supplied one would let a typo flood an
 *              arbitrary address space with #DB. The dispatcher still DECIDES on CR3 -- it runs on
 *              the exception path, where that is what the hardware gives it.
 *
 * ⚠ This sets DEBUGCTL.BTF on every core and nothing else. Until the target's EFLAGS.TF is set,
 * no trap occurs at all; that is the caller's step and it is deliberate, so an arm can never
 * start stepping something by itself.
 */
/**
 * @param FilterStart / FilterEnd  inclusive VA range; a branch whose TARGET falls outside it is
 *        NOT RECORDED. Both zero means record everything.
 *
 * ⚠ THE FILTER IS WHY THIS IS USABLE AT ALL. measured: a busy target produced ~4.6
 * MILLION branches in 2 seconds and the ring holds 8192 -- so an unfiltered trace keeps 0.2% of a
 * hot loop, and WHICH 0.2% is decided by nothing but arrival order. Filtering in the KERNEL, on the
 * trap, is the only place it helps: usermode never sees the 99.8%.
 *
 * ⚠ FILTERED IS NOT DROPPED, and they are counted separately. A dropped record is a LOSS -- the ring
 * was full and a branch that qualified was thrown away. A filtered record is the command doing what
 * it was told. Reporting them in one number would turn a working filter into an alarming loss rate.
 */
NTSTATUS NxcBtfArm(_In_ UINT32 Pid, _In_ UINT64 FilterStart, _In_ UINT64 FilterEnd,
                   _In_ BOOLEAN Kernel);

/*
 * RING 0 (D120). Kernel != FALSE clears IA32_FMASK bit 8, so the target's EFLAGS.TF survives its own
 * SYSCALL and the kernel path it entered is branch-stepped too. Opt-in, restored EXACTLY on disarm
 * from the value measured per core, and scoped by TF exactly as ring-3 stepping is: a thread whose
 * TF is clear is unaffected, so other processes' syscalls on that core are not stepped.
 *
 * ⚠ Our own #DB handler cannot self-step: an interrupt or trap gate clears TF after pushing EFLAGS
 * (SDM vol 3), so the dispatcher always runs with TF already clear.
 */
UINT64  NxcBtfFmaskSaved(_In_ UINT32 Cpu);
BOOLEAN NxcBtfKernelOn(void);

/* Branches seen and deliberately NOT recorded because they fell outside the filter. Not a loss. */
UINT64 NxcBtfFiltered(void);

/**
 * Clear DEBUGCTL.BTF on every core and stop claiming. Records already taken remain drainable --
 * disarming is not discarding, and a caller that armed, ran and disarmed still gets its trace.
 */
NTSTATUS NxcBtfDisarm(void);

/**
 * Is this the address space we are stepping? Takes an ALREADY-MASKED CR3 frame, because the
 * dispatcher has computed one by the time it asks and a second masking helper here would be a
 * second thing that has to keep agreeing with Cr3Frame forever.
 */
BOOLEAN NxcBtfIsTarget(_In_ UINT64 Cr3FrameMasked);

/**
 * Record one branch and RE-ARM BTF on this core. Called from the dispatcher on a claimed BS trap.
 *
 * ⚠ THE RE-ARM IS NOT SEPARABLE FROM THE RECORD. Splitting them invites a path that records and
 * forgets to re-arm, which does not fail loudly -- it degrades to instruction stepping and floods.
 *
 * @param TfRestored  whether the caller could write EFLAGS.TF back into the trap frame. FALSE is
 *                    counted, because without TF the trace stops dead after one branch -- which is
 *                    indistinguishable from a target that simply stopped branching unless counted.
 */
void NxcBtfOnTrap(_In_ UINT64 Rip, _In_ BOOLEAN TfRestored);

/**
 * Hand back records oldest-first and REMOVE what is handed back.
 *
 * @param Got       records written (D3: what was PRODUCED)
 * @param Total     records still held after this drain
 * @param Dropped   records the ring could not hold since arming -- a FLOOR on what was missed
 */
NTSTATUS NxcBtfDrain(
	_Out_writes_(Cap) NXC_BTF_REC* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT64* Dropped
	);

/* Stopping. While true the dispatcher CLEARS EFLAGS.TF on each claimed trap instead of
 * re-setting it -- the trap is the only thing that reliably reaches a thread under a
 * branch storm, so the storm is what ends the stepping. */
BOOLEAN NxcBtfDraining(void);

BOOLEAN NxcBtfArmed(void);
UINT32  NxcBtfPid(void);
UINT64  NxcBtfTaken(void);
UINT64  NxcBtfDropped(void);

/* Traps where EFLAGS.TF could NOT be re-set. Non-zero means the trace stopped because
 * nothing was stepping any more, which is NOT the same as the target having stopped
 * branching -- and the two would otherwise look identical. */
UINT64  NxcBtfTfFailed(void);
