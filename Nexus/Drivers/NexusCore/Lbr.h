/**
 * @file Lbr.h
 * @brief Last Branch Records. STAGE 1: READ ONLY -- no MSR is written. Full research in D23.
 *
 * ============================================================================================
 * WHAT LBR IS FOR HERE, GIVEN PT ALREADY WORKS
 * ============================================================================================
 *
 * Intel PT is verified end to end and produces thousands of executed IPs. What it does NOT produce
 * is the path BETWEEN them: TNT packets compress conditional branches to one bit each, so
 * reconstructing the walk requires decoding the target's own instructions, which requires the image
 * -- and the images this framework exists to inspect are the ones you cannot trust a disk copy of.
 *
 * LBR answers the other half. Each entry is an explicit source -> target pair, needing NO image at
 * all, plus (where enumerated) whether the branch mispredicted, how many cycles since the previous
 * entry, and the branch TYPE. Thirty-two of them, shallow and exact, against PT's deep and
 * compressed. Neither replaces the other, which is why the plan kept both.
 *
 * ============================================================================================
 * ⚠ THIS MACHINE HAS ARCHITECTURAL LBR, AND THAT IS A DIFFERENT DEVICE FROM THE LEGACY ONE
 * ============================================================================================
 *
 * Not a newer revision of the same registers -- a different register set with a different shape:
 *
 *   - Enable moved from IA32_DEBUGCTL[0] to **IA32_LBR_CTL[0]** (0x14CE). DEBUGCTL[0] does nothing.
 *   - **THERE IS NO TOS.** IA32_LBR_TOS (0x1C9) is gone. Entry 0 is ALWAYS the youngest branch, and
 *     a read walks 0..depth-1 and stops at the first FROM_IP == 0.
 *   - **THERE IS NO LBR_SELECT.** Filtering moved into IA32_LBR_CTL: bits 2:1 are the CPL filter,
 *     bit 3 is call-stack mode, bits 22:16 select branch types.
 *   - Depth comes from CPUID.1CH instead of a per-model table, and **writing IA32_LBR_DEPTH resets
 *     every entry**.
 *
 * ⚠ SO v1's `debug/lbr.cpp` IS NOT A REFERENCE FOR THIS PART, IT IS A DESCRIPTION OF THE OTHER ONE.
 * It reads TOS and indexes 0x680/0x6C0 from it; on this machine that MSR is not implemented. It also
 * picks depth from a family/model table (would say 16; measured 32), and its "CPL filter" writes
 * DEBUGCTL bits 9 and 10 -- which its OWN COMMENTS four lines earlier label *"Disable BTS in ring
 * 0/3"*. Those are BTS controls. v1's LBR filter never filtered LBR.
 *
 * ⚠ AND READING THE WRONG MSR IS NOT A FAILED PROBE. RDMSR of an unimplemented MSR raises #GP, and a
 * manually mapped image has no SEH, so it is a bugcheck. Every read below is gated on CPUID first --
 * fail-closed, never "try it and see".
 *
 * ============================================================================================
 * ⚠⚠ WHY THIS IS BUILDABLE NOW, WHEN THE PLAN SAID IT WAS BLOCKED
 * ============================================================================================
 *
 * `the design notes` and `the design notes` both deferred LBR behind item 15 -- the system-wide #DB
 * interception, the riskiest thing in the plan -- reasoning that *"reading it without a trap
 * describes our own read path"*.
 *
 * **Setting IA32_LBR_CTL.USR without .OS means ring-0 branches are never recorded at all.** The read
 * path runs at ring 0. It cannot pollute a ring it is excluded from. The objection does not survive
 * the capability existing, and the capability is enumerated in CPUID.1CH:EBX[0].
 *
 * The REAL limitation is a different one, and stating it precisely matters: **LBR has no CR3
 * filter.** PT has one; LBR does not. So with USR-only recording the ring holds the last 32
 * user-mode branches of whichever process was last scheduled on that core. LBR still wants a moment
 * -- it just does not want a #DB.
 *
 * And v2 already owns a moment: the **inline hook** (phase 5, built and hardware-verified). A stub
 * runs on the target's own thread immediately after the target's branches, so the ring at that
 * instant IS the path into the hook. Better than a #DB for this, and needs nothing new.
 *
 * Stage 1 here is honest about all of that: it reads the ring on every core and LABELS the result as
 * "whatever last ran here", because with nothing armed that is exactly what it is.
 *
 * ⚠ ONE REFINEMENT TO "OUR READ CANNOT POLLUTE THE RING", AND IT IS NOT A CONTRADICTION. The filter
 * is on the CPL at which a branch is TAKEN. Our read runs at ring 0, so every branch inside it is
 * excluded -- but `KeIpiGenericCall` DELIVERS AN INTERRUPT, and if the target core was executing
 * user code at that instant, the vector to the handler is a branch taken at ring 3 and IS recorded:
 * one entry, user FROM, kernel TO, sitting at index 0 as the youngest.
 *
 * So a read costs at most ONE entry, it is identifiable (a kernel TO with a user FROM), and it
 * displaces the oldest entry rather than the newest. Recorded here because otherwise it surfaces as
 * a confusing artifact -- "why does the newest branch always point into the kernel?" -- and gets
 * mistaken for the filter not working. This is exactly why the selftest counts kernel-sourced FROM
 * addresses and not kernel TO addresses.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/*
 * Architectural LBR MSRs. Values agreed by Linux `msr-index.h` and the SDM (D23).
 *
 * ⚠ NEVER READ ANY OF THESE WITHOUT THE CPUID GATE. See the #GP note above.
 */
#define IA32_LBR_CTL             0x000014CEu
#define IA32_LBR_DEPTH_MSR       0x000014CFu
#define IA32_LBR_INFO_0          0x00001200u
#define IA32_LBR_FROM_IP_0       0x00001500u
#define IA32_LBR_TO_IP_0         0x00001600u

/*
 * ⚠⚠ THE LAST EVENT RECORD. ARCHITECTURAL, and part of architectural LBR rather than a separate
 * feature -- so there is NO separate capability bit to probe and no separate enable to set.
 *
 * SDM Vol 4, IA-32 ARCHITECTURAL MSR table (verified in the local corpus, `grep 1DDH`):
 *     1DDH 477  IA32_LER_FROM_IP   Last Event Record Source IP Register       (R/W)
 *     1DEH 478  IA32_LER_TO_IP     Last Event Record Destination IP Register  (R/W)
 *     1E0H 480  IA32_LER_INFO      Last Event Record Info Register            (R/W)
 *
 * SDM Vol 3 20.1: the LER "records the last taken branch preceding the last exception, hardware
 * interrupt, or software interrupt", and is "subject to the same dependencies on enabling and
 * filtering" as the LBRs -- i.e. IA32_LBR_CTL.LBREn, which NxcLbrArm already sets.
 *
 * ⚠ NAMING IS THE TRAP, NOT AVAILABILITY. The same register pair is IA32_LER_FROM_IP (Intel,
 * current), MSR_LER_FROM_LIP (Intel, Core-era), LastExceptionFromIP (Intel, P6) and
 * MSR_IA32_LASTINTFROMIP in Linux -- and Intel renamed the feature from "Last EXCEPTION Record" to
 * "Last EVENT Record". Six web searches produced two WRONG answers, including a confident
 * "0x1E0 does not exist" reasoned from Linux not defining it. The manual settled it in one grep.
 * If these ever need re-checking, grep the MSR NUMBER, never the name.
 */
#define IA32_LER_FROM_IP         0x000001DDu
#define IA32_LER_TO_IP           0x000001DEu
#define IA32_LER_INFO            0x000001E0u

/* IA32_LBR_CTL fields. Bit 0 enables; the rest configure. Linux's ARCH_LBR_CTL_MASK is 0x7f000e --
 * bits 1,2,3 and 16..22 and NOT bit 0 -- which corroborates the split by construction. */
#define LBR_CTL_EN               (1ULL << 0)
#define LBR_CTL_OS               (1ULL << 1)   /* record ring 0     */
#define LBR_CTL_USR              (1ULL << 2)   /* record ring > 0   */
#define LBR_CTL_CALL_STACK       (1ULL << 3)

/* IA32_LBR_x_INFO fields, present only as CPUID.1CH:ECX enumerates them. */
#define LBR_INFO_CYC_CNT_MASK    0xFFFFULL           /* [15:0]  cycles since previous entry */
#define LBR_INFO_BR_TYPE_SHIFT   56                  /* [59:56] branch type                 */
#define LBR_INFO_BR_TYPE_MASK    0xFULL
#define LBR_INFO_CYC_VALID       (1ULL << 60)
#define LBR_INFO_MISPRED         (1ULL << 63)

#define NXC_LBR_MAX_CPUS         64u

/*
 * Snapshot ceiling. Each is ~1.6 KB, so 256 is ~400 KB of arena -- bounded on purpose: this is the
 * memory a hook on a hot function can consume before capture stops, and an unbounded ring would
 * trade a known cost for an unknown one.
 */
#define NXC_LBR_MAX_SNAPSHOTS    256u

/**
 * Read the LBR ring on every logical processor, and report the per-core capability that governs it.
 *
 * ⚠ SAMPLED ON THE OWNING CORE. LBR MSRs are per-processor, so reading them from whichever core
 * services the command would report that core's ring under all 24 numbers -- the same wrong-answer-
 * shaped-like-a-right-one the debug registers and the PT MSRs both needed guarding against.
 *
 * ⚠ WITH NOTHING ARMED THIS DESCRIBES WHATEVER LAST RAN, INCLUDING US. Stage 1 does not write
 * IA32_LBR_CTL, so on a machine where nobody else enabled LBR the ring is empty and on one where
 * somebody did it is theirs. Both are reported as found. `Enabled` says which case a core is in.
 *
 * @param Got     entries written (one per logical processor, <= Cap)
 * @param Total   logical processors that EXIST, so truncation cannot read as completeness (D3)
 */
/**
 * Did WE arm LBR on the CURRENT core? Declared here as well as in BpDispatch.h because Lbr.c itself
 * needs it in the per-core read, ABOVE the definition -- and a local forward declaration would be a
 * second place the signature has to agree.
 *
 * ⚠ NOT the same question as "is IA32_LBR_CTL.EN set". The processor clears EN entering a #DB
 * handler, and another owner can have it set without us; both cases are why this exists.
 */
BOOLEAN NxcLbrArmedHere(void);

NTSTATUS NxcLbrRead(
	_Out_writes_(Cap) NXCMD_LBR_CPU* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);

/* Branch-type filter, IA32_LBR_CTL[22:16]. Bit positions from Linux's ARCH_LBR_*_BIT (D23). */
#define LBR_CTL_JCC              (1ULL << 16)
#define LBR_CTL_NEAR_REL_JMP     (1ULL << 17)
#define LBR_CTL_NEAR_IND_JMP     (1ULL << 18)
#define LBR_CTL_NEAR_REL_CALL    (1ULL << 19)
#define LBR_CTL_NEAR_IND_CALL    (1ULL << 20)
#define LBR_CTL_NEAR_RET         (1ULL << 21)
#define LBR_CTL_OTHER_BRANCH     (1ULL << 22)

/*
 * ⚠⚠ "ANY BRANCH" MUST BE SPELLED OUT. AN EMPTY FILTER RECORDS **NOTHING**, NOT EVERYTHING.
 *
 * MEASURED ON THIS MACHINE, and it is the opposite of the intuitive reading. `lbr selftest`
 * armed with `EN | USR | OS` and no type bits, ran a kernel branch generator, and the ring came back
 * EMPTY -- while `lbr arm --calls`, which does set type bits, filled rings on all 24 cores in the
 * same run. Two observations, one conclusion: bits 22:16 are an INCLUSION list, and an empty list
 * includes nothing.
 *
 * ⚠ AND A WEB SOURCE SAID THE OPPOSITE, plausibly, by analogy from the legacy `LBR_SELECT` register
 * where zero means unfiltered. Linux settles it in code rather than prose -- `ARCH_LBR_ANY` is
 * defined as all seven bits ORed together, so the kernel that actually drives this hardware does not
 * rely on zero meaning "all" either. Reasoning by analogy from the legacy device is exactly the
 * mistake this whole file exists to avoid: architectural LBR is a DIFFERENT DEVICE.
 *
 * ⚠ THE COST OF GETTING IT WRONG IS SILENT. LBR_CTL.EN reads back set, `lbr read` reports the core
 * as armed, and every ring is empty forever. That is indistinguishable from a quiet machine.
 */
#define LBR_CTL_ANY_BRANCH  (LBR_CTL_JCC | LBR_CTL_NEAR_REL_JMP | LBR_CTL_NEAR_IND_JMP | \
                             LBR_CTL_NEAR_REL_CALL | LBR_CTL_NEAR_IND_CALL | \
                             LBR_CTL_NEAR_RET | LBR_CTL_OTHER_BRANCH)

/**
 * Arm LBR on every logical processor. STAGE 2 -- this WRITES IA32_LBR_CTL.
 *
 * ⚠ REFUSES A CONTENDED FACILITY. If LBR_CTL.EN is already set on ANY core this returns
 * STATUS_DEVICE_BUSY and writes nothing anywhere, because one ring per core means arming over
 * somebody else's is theft, not sharing. `OutContended` says how many cores were the problem.
 *
 * ⚠ REFUSES A NON-UNIFORM MACHINE FOR A CAPABILITY IT NEEDS. This is a hybrid part; if the caller
 * asks for a filter that some core type does not support, arming a subset would produce a trace
 * whose meaning depends on which core the target happened to run on. Refused as a whole.
 *
 * @param ArmFlags       NXCMD_LBR_ARM_*
 * @param OutArmed       cores actually armed
 * @param OutContended   cores whose LBR was ALREADY enabled (nonzero means nothing was armed)
 * @param OutUnsupported cores lacking architectural LBR or a requested capability
 */
NTSTATUS NxcLbrArm(
	_In_ UINT32 ArmFlags,
	_Out_ UINT32* OutArmed,
	_Out_ UINT32* OutContended,
	_Out_ UINT32* OutUnsupported
	);

/**
 * Clear LBR_CTL.EN on every logical processor.
 *
 * ⚠ CLEARS ONLY THE ENABLE, AND ONLY WHERE WE ARMED. Zeroing the whole register on a core somebody
 * else owns would destroy their configuration, and this command cannot tell whose it is from the
 * register alone -- so it disarms against the record of what NxcLbrArm actually armed.
 */
NTSTATUS NxcLbrDisarm(
	_Out_ UINT32* OutDisarmed
	);

/**
 * Clear IA32_LBR_CTL.EN on EVERY core, ignoring the ownership record.
 *
 * ⚠ THE ESCAPE HATCH FOR `lbr arm --fake-foreign`, which arms without recording ownership so the
 * contention check has a known-bad -- and is therefore unclearable by the normal disarm, by design.
 * ⚠ NEVER THE DEFAULT: on a machine where a real profiler owns LBR this steals it.
 */
NTSTATUS NxcLbrDisarmForce(_Out_ UINT32* OutDisarmed);

/* ================================================================================================
 * STAGE 3 -- SNAPSHOTS TAKEN FROM A HOOK, which is what makes a ring attributable to a target.
 * ============================================================================================= */

/**
 * Reserve the snapshot ring. PASSIVE_LEVEL, from the ARENA (D4), before any hook can fire.
 *
 * ⚠ ALLOCATED UP FRONT BECAUSE THE CONSUMER CANNOT ALLOCATE. A snapshot is taken inside a hook, on
 * the target's own thread, at whatever IRQL that function runs at -- possibly DISPATCH or above,
 * where no allocator may be called. So the capture path does nothing but RDMSR and store.
 *
 * ⚠ AND FROM THE ARENA, NOT POOL. Capture storage is arena-resident and owner-tagged by standing
 * decision: a pool allocation is tagged, enumerable, and exactly the artifact this framework spends
 * effort not leaving behind.
 *
 * @param Slots  snapshots to reserve; the capture stops when they are full, so this is the bound on
 *               what a hook on a hot function costs. Clamped to NXC_LBR_MAX_SNAPSHOTS.
 */
/**
 * Reserve the snapshot ring.
 *
 * @param Wrap  0 = FILL AND STOP (default): keep the FIRST Slots snapshots, then count drops. The
 *              cost is bounded by construction -- once full every later hit is one increment.
 *              1 = WRAP: keep the LAST Slots. For a target that does something interesting ONCE at
 *              an unknown moment (a section that decrypts, runs, re-encrypts), the branches worth
 *              having are the ones AROUND that event, and a ring filled during the first
 *              milliseconds after arming holds startup noise and refuses everything that matters.
 *              ⚠ Wrapping pays ~96 RDMSRs on the target's own thread for EVERY hit, forever.
 */
NTSTATUS NxcLbrSnapInit(_In_ UINT32 Slots, _In_ UINT32 Wrap);

/** Release the snapshot ring. PASSIVE_LEVEL, and refuses while any LBR-sampling hook is installed. */
NTSTATUS NxcLbrSnapFree(void);

/**
 * Take one snapshot of THIS core's ring. Called from the hook handler; safe at any IRQL.
 *
 * ⚠ NO LOCK, AND NONE IS POSSIBLE. This runs at the hooked function's IRQL, which may be above
 * DISPATCH, so the slot is claimed with a single InterlockedIncrement and written by its owner
 * alone. Two cores hitting the hook at once take two different slots.
 *
 * ⚠ IT STOPS RATHER THAN WRAPPING. A wrapping ring would keep paying the RDMSR cost forever and
 * would silently discard the FIRST snapshots -- and the first hits after a hook goes in are the
 * ones worth having. Filling up and stopping is both cheaper and more useful.
 *
 * @param TargetVa  the hooked function, recorded with the snapshot so a drained record says what
 *                  it was about
 */
void NxcLbrSnapTake(_In_ UINT64 TargetVa, _In_ UINT64 FrozenCtl);

/** Snapshots taken, and hits that found the ring already full. Counters, never a verdict. */
/**
 * @param OutOverwritten  snapshots REPLACED by wrapping. Distinct from dropped: a drop was never
 *                        recorded, an overwrite WAS recorded and then superseded. Without both,
 *                        "200 taken into 40 slots" cannot be read correctly.
 */
void NxcLbrSnapCounters(_Out_ UINT32* OutTaken, _Out_ UINT32* OutDropped, _Out_ UINT32* OutSlots,
                        _Out_ UINT32* OutOverwritten);

/** Copy out what has been captured. PASSIVE_LEVEL. */
NTSTATUS NxcLbrSnapDrain(
	_Out_writes_(Cap) NXCMD_LBR_SNAPSHOT* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);

/**
 * Prove -- or disprove -- the property every other decision here rests on: that recording ring 3
 * ONLY keeps our own kernel-side path out of the ring.
 *
 * ⚠ THIS EXISTS BECAUSE THE CLAIM WAS REASONING, NOT MEASUREMENT. D23 retired the plan's stated
 * reason for gating LBR behind a `#DB` handler on the strength of "USR without OS means ring-0
 * branches are not recorded". That is what the SDM says and what four sources agree on. It is still
 * a claim about THIS silicon until this silicon is asked.
 *
 * ⚠⚠ AND THE NEGATIVE RESULT NEEDS A POSITIVE CONTROL, OR IT MEANS NOTHING. "Zero kernel branches in
 * the ring" is equally consistent with the filter working and with LBR recording nothing at all. So
 * the test runs the SAME kernel branch generator twice: once armed ring-3-only, where the expected
 * count is ZERO, and once armed with ring 0 included, where it must be NONZERO. Only the pair is
 * evidence. A test that could not fail on a broken filter would be the tidy-fixture mistake again.
 *
 * Runs entirely inside one IPI broadcast so the branches and the read happen on the SAME core with
 * no chance of migration between them -- a migration would silently turn this into a test of a
 * different core's ring.
 *
 * @param OutUserOnlyKernelHits  kernel-VA entries seen while armed RING 3 ONLY. MUST be 0.
 * @param OutKernelModeHits      kernel-VA entries seen while armed with ring 0. MUST be > 0.
 * @param OutCoresTested         cores that actually ran both phases
 */
NTSTATUS NxcLbrSelfTest(
	_Out_ UINT32* OutUserOnlyKernelHits,
	_Out_ UINT32* OutKernelModeHits,
	_Out_ UINT32* OutCoresTested
	);
