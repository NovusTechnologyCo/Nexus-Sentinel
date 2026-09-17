/**
 * @file BpDispatch.h
 * @brief "Is this #DB OURS?" -- item 15's hard part, buildable and PROVABLE with nothing patched.
 *
 * ============================================================================================
 * WHY THIS EXISTS SEPARATELY FROM THE PATCH
 * ============================================================================================
 *
 * Item 15 is usually described as "hook the exception dispatcher". The hooking is the part that
 * needed a measurement (`hook --probe`: `rel32` reaches `KiDispatchException` with ~334 MB to spare,
 * on three unrelated KASLR bases) and the part that needs a DECISION, because five bytes go into the
 * path of every exception in the system.
 *
 * **The hard part is neither.** It is this function: given a `#DB`, decide whether it belongs to us.
 *
 *   - Say YES to somebody else's exception and we SWALLOW it. A debugger's breakpoint stops working;
 *     a `STATUS_SINGLE_STEP` that some other component was waiting on never arrives. That is worse
 *     than not hooking at all, and it is silent.
 *   - Say NO to our own and the target receives `STATUS_SINGLE_STEP` and DIES -- the exact failure
 *     `bp set` exists to prevent.
 *
 * Both mistakes are decisions made in a handler running on an arbitrary thread at an arbitrary IRQL,
 * where nothing can be logged safely and nothing can be retried. So the decision is **pure**: it
 * takes values, returns a verdict, touches no global state and calls nothing. That makes it provable
 * against synthetic inputs at PASSIVE_LEVEL, with no patch installed anywhere -- which is why it is
 * being built before the decision about the patch, not after.
 *
 * ============================================================================================
 * ⚠ HOW A #DB IS IDENTIFIED, AND WHY DR6 ALONE IS NOT ENOUGH
 * ============================================================================================
 *
 * DR6 says WHICH condition fired: bits 0-3 are B0..B3 (a data/exec breakpoint matched), bit 14 is BS
 * (single-step), bit 13 is BD (debug-register access with GD set). It does NOT say WHOSE.
 *
 * Windows keeps debug registers as PER-THREAD context (D22), so the same DR slot means different
 * things in different threads -- our breakpoint in thread A and a debugger's in thread B can both be
 * "B0". Slot number alone is therefore not identity, and using it as identity is how a hook starts
 * eating a debugger's breakpoints.
 *
 * ⚠ SO IDENTITY IS THE PAIR (slot, CR3), AND CR3 MUST BE MASKED. `bp set` records which process a
 * slot was armed for; the handler compares the FAULTING CR3 against that. PCID is enabled on all 24
 * logical processors here, so CR3 bits 11:0 hold a context id that is NOT part of the address --
 * comparing raw CR3 values would never match (an earlier finding).
 * Both sides are masked to the frame before comparison, in one place, by one function.
 *
 * ⚠ AND BS IS CLAIMED ONLY WHEN WE ASKED FOR IT. A single-step trap with no armed slot matching is
 * somebody else's -- a debugger stepping, or `EFLAGS.TF` set by code we are watching rather than
 * code we are driving. Claiming BS unconditionally would swallow every single-step on the machine.
 *
 * ⚠ BD IS NEVER OURS. Bit 13 means something executed a `mov` touching a debug register while
 * DR7.GD was set. We never set GD (Bp.h records why), so a BD trap is always another agent's and
 * passing it through is the only correct answer.
 */

#pragma once

#include <ntddk.h>

/* NXC_BPD_HIT and its NXC_BPD_PRESENT_* flags -- the record crosses to usermode, so it is defined
 * ONCE in the shared header rather than here and again on the other side. */
#include "../../Include/NexusCommand.h"
#include "Idt.h"   /* NXC_GPR_MAP -- the derived volatile-GPR offsets */

/* DR6 condition bits, SDM Vol 3 17.2.3. */
#define NXC_DR6_B0        (1ULL << 0)
#define NXC_DR6_B1        (1ULL << 1)
#define NXC_DR6_B2        (1ULL << 2)
#define NXC_DR6_B3        (1ULL << 3)
#define NXC_DR6_BD        (1ULL << 13)   /* debug-register access with DR7.GD -- never ours */
#define NXC_DR6_BS        (1ULL << 14)   /* single step                                     */
#define NXC_DR6_BT        (1ULL << 15)   /* task switch -- cannot occur in IA-32e           */

#define NXC_DR6_SLOT_MASK (NXC_DR6_B0 | NXC_DR6_B1 | NXC_DR6_B2 | NXC_DR6_B3)

/** What the handler should do with a #DB. */
#define NXC_BPD_PASS_THROUGH   0u   /* not ours -- let the real dispatcher have it, untouched */
#define NXC_BPD_CLAIM          1u   /* ours: record it and resume the target                  */

/** Why, so a wrong verdict can be diagnosed rather than guessed at. */
#define NXC_BPD_WHY_NOT_DB        0u   /* the vector was not 1                              */
#define NXC_BPD_WHY_NO_CONDITION  1u   /* DR6 named no condition we handle                  */
#define NXC_BPD_WHY_BD            2u   /* general-detect: never ours, we do not set GD      */
#define NXC_BPD_WHY_NO_SLOT       3u   /* the firing slot is not armed by us                */
#define NXC_BPD_WHY_FOREIGN_CR3   4u   /* our slot, but a DIFFERENT process faulted         */
#define NXC_BPD_WHY_MATCH_SLOT    5u   /* CLAIM: armed slot + matching CR3                  */
#define NXC_BPD_WHY_MATCH_STEP    6u   /* CLAIM: single-step we asked for, matching CR3     */
/*
 * CLAIM, but NOT a sighting of the target. A GLOBALLY armed slot matched in a process that is not
 * ours -- which happens by construction, because a global DR watches a LINEAR ADDRESS in every
 * address space. WE wrote that register, so we swallow the trap rather than let an innocent
 * process take a STATUS_SINGLE_STEP for a breakpoint it never asked for. Counted separately:
 * SUPPRESSING is not ATTRIBUTING.
 */
#define NXC_BPD_WHY_GLOBAL_FOREIGN 7u
/*
 * CLAIM: a BRANCH STEP from the address space armed by NxcBtfArm (D119). Carries NO SLOT --
 * OutSlot is NXC_BPD_MAX_SLOTS and the claim path must not index the slot table for it.
 */
#define NXC_BPD_WHY_MATCH_BTF      8u

/** One armed slot, as `bp set` would record it. Four per process, four per CPU. */
typedef struct _NXC_BPD_SLOT
{
	UINT64 Cr3;         /* the target's DirectoryTableBase, ALREADY MASKED to the frame */
	UINT64 Address;     /* what was armed -- reported, not used for the verdict         */
	UINT32 Armed;
	UINT32 WantStep;    /* we asked for a single-step after this one fired              */
	/*
	 * ⚠ DR7 R/W ENCODING, AND IT GATES THE CLAIM. 00 = execute, 01 = write, 11 = read/write.
	 *
	 * A DATA breakpoint traps AFTER the access, so RIP already points past the instruction and
	 * claiming is simply "return without dispatching" -- nothing needs writing to the trap frame.
	 *
	 * An EXECUTE breakpoint traps BEFORE the instruction retires. Resuming without setting
	 * EFLAGS.RF re-enters the same instruction, re-arms the same trap, and the machine spins in the
	 * exception path forever. Setting RF means writing the target's KTRAP_FRAME, whose layout is
	 * unexported and version-dependent -- exactly the pinning this project bans. So EXECUTE
	 * breakpoints are NEVER claimed until the trap frame can be DERIVED, and the type is recorded
	 * here so the claim path can enforce that rather than trust the caller not to arm one.
	 */
	UINT32 Type;
	/*
	 * ⚠ ARMED WITH THE DR7 **GLOBAL** BIT ON EVERY CORE, rather than into a thread's CONTEXT. This
	 * flips what a FOREIGN CR3 means, and the two answers are opposite:
	 *
	 *   per-thread -> slot 0 in another thread may be a DEBUGGER'S. Pass it through.
	 *   global     -> WE own DR0 machine-wide, so it is OUR trap in a process we do not watch.
	 *                 Swallow it, or that process dies for a breakpoint we set.
	 */
	UINT32 Global;
} NXC_BPD_SLOT;

/* ⚠ NXC_BPD_MAX_SLOTS now lives in NexusCommand.h, included above. It moved because usermode needs
 * it too (the per-site tally in `bp hits`), and defining it in both places is the two-expressions-
 * that-must-agree shape this file argues against elsewhere. Not redefined here on purpose. */

/* ================================================================================================
 * THE PER-HIT RECORD -- what a breakpoint actually PRODUCES.
 *
 * Counting hits proves the mechanism; it is not evidence about the target. This is the evidence:
 * one record per claimed trap, captured on the faulting thread at the moment of the trap.
 *
 * ⚠⚠ `Present` IS NOT OPTIONAL BOOKKEEPING -- IT IS WHAT KEEPS THIS HONEST. The registers a hit
 * would ideally carry live in TWO structures: KTRAP_FRAME has the volatile set and the IRET tail,
 * while R12-R15 live in KEXCEPTION_FRAME. Only fields whose offsets have been DERIVED AND PROVEN are
 * filled, and `Present` says which those were. A record that zero-filled the rest would make "we did
 * not capture R13" and "R13 was 0" render identically -- and after +0xF8 was very nearly written into
 * Dr6 on the strength of an unverified offset, guessing at a second structure's layout to make a
 * record look complete is precisely the move to refuse.
 * ============================================================================================= */

/*
 * ⚠ THE RECORD ITSELF LIVES IN NexusCommand.h, NOT HERE. It crosses to usermode, and a structure
 * defined in a kernel-only header would have to be RE-DECLARED on the other side -- two definitions
 * that must agree, which is the exact shape that has already cost this project a live patch behind
 * "nothing was patched" and a flag mask that silently dropped new flags. One definition, shared.
 */


/**
 * Read out captured hits, and the count DROPPED because the ring was full.
 *
 * ⚠ THE DROP COUNT IS RETURNED WITH THE DATA, ALWAYS. A ring that silently overwrites presents a
 * partial capture as a complete one; `Sequence` gaps and this counter are the two independent ways a
 * reader can tell. D3: report what was ACTUALLY produced.
 */
/** Reset the hit ring. Sequence is zeroed BEFORE the counters so a concurrent reader never sees a
 *  stale record under a fresh count. */
void NxcBpdHitsClear(void);

void NxcBpdHitStats(_Out_ UINT32* OutHeld, _Out_ UINT64* OutTotal, _Out_ UINT64* OutDropped);

/**
 * Copy ONE record out. Returns FALSE for a slot that is empty or still being written.
 *
 * ⚠ ONE AT A TIME BY DESIGN, NOT BY OVERSIGHT. The obvious signature -- fill a caller's array of 64 --
 * puts 5.6 KB on the stack, and MSVC answers a frame that large with a `__chkstk` call. In a payload
 * that carries NO IMPORT TABLE that is a link-time import, and the build gate rejected it. Copying
 * per record keeps the frame at one structure.
 */
BOOLEAN NxcBpdHitAt(_In_ UINT32 Index, _Out_ NXC_BPD_HIT* Out);

/**
 * Decide whether a `#DB` belongs to us. PURE: no globals, no calls, no allocation, no logging.
 *
 * ⚠ THE CALLER PASSES THE FAULTING CR3 RAW; MASKING HAPPENS HERE. One place, so a caller that
 * forgets cannot produce a verdict that is wrong in the direction of claiming.
 *
 * @param Vector    the trap vector; anything other than 1 passes through immediately
 * @param Dr6       the faulting DR6
 * @param FaultCr3  CR3 as it was when the trap fired, RAW (PCID bits still present)
 * @param Slots     what we have armed
 * @param OutWhy    NXC_BPD_WHY_* -- always written, on claim and on pass-through alike
 * @param OutSlot   which slot matched, or NXC_BPD_MAX_SLOTS when none did
 * @return NXC_BPD_CLAIM or NXC_BPD_PASS_THROUGH
 */
UINT32 NxcBpdClassify(
	_In_ UINT32 Vector,
	_In_ UINT64 Dr6,
	_In_ UINT64 FaultCr3,
	_In_reads_(NXC_BPD_MAX_SLOTS) CONST NXC_BPD_SLOT* Slots,
	_Out_ UINT32* OutWhy,
	_Out_ UINT32* OutSlot
	);

/* ================================================================================================
 * ⚠⚠ THE DISPATCHER OBSERVER -- STAGE 1: IT WATCHES. IT CLAIMS NOTHING.
 * ============================================================================================= */

/**
 * Called from the hook on `KiDispatchException`, once per DISPATCHED EXCEPTION on the whole machine.
 *
 * ⚠ MONITOR ONLY, AND THAT IS A DESIGN STAGE RATHER THAN CAUTION FOR ITS OWN SAKE. To CLAIM a `#DB`
 * this would have to return early from the dispatcher with `EFLAGS.RF` set in the target's TRAP
 * FRAME -- and `KTRAP_FRAME`'s layout is unexported and version-dependent. Pinning those offsets is
 * precisely what this project bans, and getting one wrong writes a flag into the middle of somebody
 * else's saved register state on the system exception path. So interception waits for the trap frame
 * to be DERIVED rather than assumed, and this stage proves the far riskier structural claim first:
 * that a five-byte patch on the exception path is survivable at all.
 *
 * ⚠ ARG1 IS A `PEXCEPTION_RECORD`, AND THAT IS THE ONLY REASON THIS NEEDS NO ASSEMBLY CHANGES. The
 * existing thunk already forwards the target's first two integer arguments. `EXCEPTION_RECORD` is a
 * PUBLIC, architecturally stable structure -- `ExceptionCode` at offset 0 has been there since NT --
 * so reading it pins nothing. Everything past that first qword is deliberately untouched.
 *
 * ⚠ EVERY LINE OF THIS RUNS ON THE SYSTEM'S EXCEPTION PATH. The fast reject comes first, it takes no
 * lock, it allocates nothing, it calls nothing that can page, and for the overwhelming majority of
 * exceptions -- which are not ours and never will be -- it is one load and one compare.
 */
/* Returns NON-ZERO to SWALLOW the dispatched exception -- the thunk then returns to the target's
 * caller and KiDispatchException never runs. Zero on every other path; see the four gates in the
 * implementation. */
UINT64 NxcBpdOnException(_In_ UINT64 ExceptionRecordVa, _In_ UINT64 ReturnAddress,
                         _In_ UINT64 TrapFrameVa, _In_ UINT64 ExceptionFrameVa);

/**
 * Record what the STATIC oracle (NxcIdtDeriveEflagsOffset, which decodes ntoskrnl's code) concluded.
 *
 * ⚠ THIS DOES NOT CHOOSE THE OFFSET THAT GETS WRITTEN TO. It is kept only so the two derivations can
 * be COMPARED. The static route was measured wrong once already, and in the most dangerous way: the
 * displacement it recovers is relative to a BIASED frame pointer (`TrapFrame = rbp - 0x80` at the
 * real call site), so its raw answer 0xF8 is KTRAP_FRAME.Dr6 rather than EFlags at 0x178. Keeping it
 * as a separate, clearly-labelled cross-check is what makes that visible instead of authoritative.
 */
void NxcBpdSetEflagsOffset(_In_ UINT32 Offset);

/** The live derivation: the offset in force, frames examined, frames that AGREED, and frames that
 *  DISAGREED. Any disagreement at all is disqualifying -- see NxcBpdEflagsProven. */
void NxcBpdEflagsCheck(_Out_ UINT32* OutOffset, _Out_ UINT64* OutChecked,
                       _Out_ UINT64* OutPlausible, _Out_ UINT64* OutRejected);

/** The static oracle's answer and whether it was produced at all, plus frames that yielded nothing.
 *  Reported so a DISAGREEMENT between the two methods is on screen rather than inferred. */
void NxcBpdEflagsCross(_Out_ UINT32* OutStatic, _Out_ UINT32* OutStaticValid,
                       _Out_ UINT64* OutNoMatch);

/**
 * May the derived offset be WRITTEN to? Fails closed: needs a candidate, at least
 * NXC_BPD_EFLAGS_MIN_AGREE live frames agreeing, and ZERO disagreements ever.
 *
 * ⚠ THE GATE FOR EXECUTE BREAKPOINTS. Resuming one requires setting EFLAGS.RF in the target's trap
 * frame; at a wrong offset that writes a bit into another thread's saved register state on the
 * exception path. Until this returns TRUE, execute breakpoints stay refused.
 */
BOOLEAN NxcBpdClaimEnabled(void);

BOOLEAN NxcBpdEflagsProven(_Out_opt_ UINT32* OutOffset);

/** EFLAGS.RF writes made to resume an EXECUTE breakpoint, and writes ABANDONED at the last moment
 *  because the frame failed the write-time shape check. Distinct from the claim count: they answer
 *  "how many claims needed a resume fixup" versus "how many frames were not what they claimed". */
/**
 * WHY the live derivation yielded nothing, split three ways. Mutually exclusive; they sum to the
 * total reported by NxcBpdEflagsCheck's OutNoMatch.
 *
 * ⚠ THE SPLIT EXISTS BECAUSE THE COMBINED COUNTER MISLED. Measured 07-31, it went 10% -> 20% -> 26%
 * while the page-straddle model predicted 9.77%, and no reading could say whether frames were
 * unreadable (geometry) or readable-and-rejected (a property of those frames). STRADDLED is the
 * boring one; TAIL_BAD means the faulting RIP WAS in the frame and the architectural fields after it
 * did not hold, which would be a real finding about the exception path.
 */
void NxcBpdEflagsFailBreakdown(_Out_ UINT64* OutStraddled, _Out_ UINT64* OutRipAbsent,
                               _Out_ UINT64* OutTailBad);

/** Record what the last derivation ATTEMPT returned, success or refusal. Its own log messages go to
 *  DbgPrint and are unreachable without a kernel debugger, so the status has to travel. */
void NxcBpdSetGprStatus(_In_ NTSTATUS Status, _In_ UINT32 Gate);

/** Whether a derivation was attempted at all, and what it returned. Attempted-and-refused is a
 *  different fact from never-attempted, and "not derived" cannot tell them apart. */
void NxcBpdGprStatus(_Out_ UINT32* OutTried, _Out_ UINT32* OutStatus, _Out_ UINT32* OutGate);

/** Keep the funnel VA from hook-install time: R12-R15 are derived from it, at ARM time. */
void NxcBpdSetFunnelVa(_In_ UINT64 FunnelVa);
UINT64 NxcBpdFunnelVa(void);

/** Publish the DERIVED R12-R15 offsets. A SEPARATE map from the volatile one: different structure,
 *  different anchor, different proof -- so a failure in one never silently supplies the other. */
void NxcBpdSetNvGprMap(_In_ CONST NXC_NVGPR_MAP* Map);

/** Publish the DERIVED volatile-GPR offsets so hits can carry the registers. Valid is set LAST. */
void NxcBpdSetGprMap(_In_ CONST NXC_GPR_MAP* Map);

/** The map in force, and whether it is usable at all. */
BOOLEAN NxcBpdGprMap(_Out_ NXC_GPR_MAP* Out);

void NxcBpdRfStats(_Out_ UINT64* OutWrites, _Out_ UINT64* OutRefused);

/** Execute hits that could NOT be resumed and were ESCAPED -- swallowed anyway, with this core's
 *  DR7 cleared for the slot. Non-zero means the breakpoint is self-disarming across cores; it is a
 *  SAFETY event, not a failure, and it is the alternative to killing an innocent process. */
UINT64 NxcBpdEscapes(void);

/**
 * Prove the IRET-tail matcher against SYNTHETIC frames, including ones it must REJECT.
 *
 * ⚠ THE FIXTURES ARE ADVERSARIAL BY DESIGN. The first plants a decoy qword equal to the faulting RIP
 * earlier in the frame: a matcher that stops at the first RIP-shaped value answers with the wrong
 * offset and only the four following architectural fields rule it out. The rest are a CS/SS ring
 * mismatch, EFLAGS with bit 1 clear and with bit 15 set, a kernel CS beside a user RSP, an LDT
 * selector, and a frame where the RIP appears nowhere.
 *
 * Runs the SHIPPED matcher, not a copy -- a suite that tests a reimplementation tests the
 * reimplementation. No hardware, no exceptions: callable the moment the driver is mapped.
 */
NTSTATUS NxcBpdEflagsSelfTest(_Out_ UINT32* OutRun, _Out_ UINT32* OutFailed,
                              _Out_ UINT32* OutFirstFailure);

/** Turn swallowing on or off. DEFAULT OFF -- a build with this code behaves like one without. */
void NxcBpdClaimEnable(_In_ UINT32 Enable);

/** Whether swallowing is on, how many were swallowed, and how many matched but were REFUSED
 *  (an execute breakpoint, which cannot be resumed without pinning the trap frame). */
void NxcBpdClaimState(_Out_ UINT32* OutEnabled, _Out_ UINT64* OutClaimed, _Out_ UINT64* OutRefused);

/** Traps SWALLOWED for a globally armed slot that fired in a process that is NOT our target.
 *  Suppressing is not attributing -- these are deliberately kept out of the match count. */
UINT64 NxcBpdForeignSuppressed(void);

/** How many DISTINCT callers were seen, and the first few, so the caller can be named offline. */
#define NXC_BPD_MAX_CALLERS 8u
void NxcBpdCallers(
	_Out_writes_(NXC_BPD_MAX_CALLERS) UINT64* Out,
	_Out_ UINT32* OutCount
	);

/** What the observer saw. Counters, never a verdict. */
void NxcBpdObserverCounters(
	_Out_ UINT64* OutSeen,        /* every dispatched exception that reached us      */
	_Out_ UINT64* OutDebugTraps,  /* of those, STATUS_SINGLE_STEP (#DB)              */
	_Out_ UINT64* OutBreakpoints, /* STATUS_BREAKPOINT (int3) -- adjacent, not ours  */
	_Out_ UINT64* OutRejected     /* records we refused to read (non-canonical arg1) */
	);

/**
 * WHAT ARG1 ACTUALLY WAS. Added after the first live run refused 5894 of 5894.
 *
 * ⚠ KNOWING ONLY "NOT A KERNEL POINTER" COST A BOOT AND ANSWERED ALMOST NOTHING. These buckets turn
 * the next run into an IDENTIFICATION rather than another rejection: a small integer says the
 * parameter is a count or an index, a user VA says it is a usermode pointer, zero says it is unused,
 * and a kernel pointer whose first dword parses as an NTSTATUS is the positive signal that a
 * candidate really is on the exception-record path.
 */
void NxcBpdArgShape(
	_Out_ UINT64* OutZero,
	_Out_ UINT64* OutSmall,
	_Out_ UINT64* OutUser,
	_Out_ UINT64* OutLooksLikeRecord,
	_Out_ UINT64* OutNotARecord
	);

/**
 * THE DISTINCT arg1 FIRST-DWORDS ACTUALLY SEEN, with hit counts.
 *
 * ⚠ ADDED BECAUSE THE BUCKETS ABOVE STOPPED BEING ENOUGH. The first live run on the real exception
 * dispatcher  saw 104 exceptions, of which 98 fell in "kernel pointer, something else"
 * -- their first dword had neither top bit set. That is a number with no finding attached: it
 * cannot distinguish genuinely low-severity codes from arg1 not being the record on one of the two
 * observed call paths, from a read returning something stale.
 *
 * The values themselves settle it, and they are cheap to keep. Reported as EVIDENCE (D6) -- this
 * surface names no verdict, it hands back the codes and lets usermode decide.
 *
 * OutOverflow is how many distinct codes did NOT fit. A truncated histogram that does not say it is
 * truncated is a confident partial answer, which is the failure this project keeps paying for.
 */
/**
 * What the classifier WOULD have done, while claiming nothing (stage 1 of the claim path).
 *
 * ⚠ OutWouldClaim IS A FALSIFIABLE CONTROL, NOT A STATISTIC. With no breakpoint armed it must be
 * EXACTLY ZERO -- every #DB on the machine then belongs to someone else. A non-zero value is a
 * false positive, and enabling the real claim on top of it would swallow a live exception in an
 * unrelated process. Do not wire the claim until this reads 0 against real traffic.
 */
void NxcBpdClaimStats(
	_Out_ UINT64* OutClassified,
	_Out_ UINT64* OutWouldClaim,
	_Out_ UINT64* OutNotOurs,
	_Out_ UINT32* OutLastWhy,
	_Out_ UINT32* OutLastSlot
	);

#define NXC_BPD_MAX_CODES 16u
void NxcBpdCodeHistogram(
	_Out_writes_(NXC_BPD_MAX_CODES) UINT32* OutCodes,
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutHits,
	/* First-seen sample per code. OutFirstRa = the RETURN ADDRESS, i.e. WHICH call path produced
	 * this code -- two callers and two codes invites the assumption that they pair up, and nothing
	 * recorded so far actually establishes it. OutExcAddr = the qword at record+0x10,
	 * EXCEPTION_RECORD.ExceptionAddress: a code address there means arg1 really is a record and
	 * the odd value is a genuine ExceptionCode; anything else means arg1 is not a record on that
	 * path. That is the fork the bucket counters cannot resolve. Zero = not sampled/unreadable. */
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutFirstRa,
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutExcAddr,
	_Out_ UINT32* OutCount,
	_Out_ UINT64* OutOverflow
	);

/* ================================================================================================
 * FREEZING THE LBR RING AT THE INSTANT OF A HIT
 * ============================================================================================= */

/**
 * Is ARCHITECTURAL LBR usable on this part? Cached; safe to call from the trap path.
 *
 * ⚠ CALL THIS BEFORE NxcLbrFreezeRing FROM ANY PATH THAT IS NOT ALREADY BEHIND `lbr arm`.
 * FreezeRing does an unguarded RDMSR of 0x14CE, which on a part without arch LBR is #GP -- and with
 * no SEH in a mapped image, a bugcheck rather than a failed probe.
 */
BOOLEAN NxcLbrArchAvailable(void);

/**
 * Did WE arm LBR on the CURRENT core? Not the same question as "is EN set", and on the #DB path the
 * two disagree by design -- the processor clears EN before entering a debug-exception handler.
 */
BOOLEAN NxcLbrArmedHere(void);

/**
 * DIAGNOSTIC ONLY -- suppress the next @p Count EFLAGS.RF writes so the ESCAPE branch runs.
 *
 * ⚠ The escape is the branch that handles an execute breakpoint which CANNOT be resumed, where the
 * alternative is a process spinning forever in the exception path. It has never executed: RF writes
 * stopped failing once the offset was proven. A safety path that has never run is not a verified
 * one, and this is how it gets run against a known-bad.
 *
 * A COUNTDOWN, not a mode -- it reaches zero on its own, so a wrong value cannot leave the machine
 * permanently unable to resume execute breakpoints. It suppresses a write; it never fakes one.
 */
void   NxcBpdForceRfFail(_In_ UINT32 Count);
UINT64 NxcBpdForceRfFailRemaining(void);

/*
 * ⚠ WHY "tail REJECTED" NEEDED SPLITTING. It counted EIGHT distinct checks under one name and was
 * the last unexplained number in an otherwise-verified mechanism: 2-24 per run, meaning a RIP was
 * found in the frame but the architectural IRET fields did not hold -- which for a well-formed frame
 * should be impossible. One name for eight causes is the shape that cost four boots on 07-31 and a
 * hardware run on 08-07; naming them is cheaper than reasoning about them.
 *
 * ORDERED BY POSITION IN THE CHECK SEQUENCE, so the matcher can record the FURTHEST-progressing
 * rejection simply by taking the maximum.
 */
/* ⚠ NXC_BPD_TR_* now live in NexusCommand.h, included above -- usermode names them, and the shape
 * block's size derives from NXC_BPD_TR_COUNT on BOTH sides. Defining them here too is exactly the
 * drift that zeroed the whole block. Not redefined on purpose.
 *
 * ⚠ AND THE COUNTS THE SHAPE BLOCK IS SIZED FROM MUST MATCH THIS FILE'S OWN LIMITS, or the kernel
 * writes past what usermode allocated. Asserted rather than trusted. */
NXCMD_ASSERT(bpd_callers_agree, NXC_BPD_MAX_CALLERS == NXCMD_BPD_MAX_CALLERS);
NXCMD_ASSERT(bpd_codes_agree,   NXC_BPD_MAX_CODES   == NXCMD_BPD_MAX_CODES);

/**
 * Per-reason tally of frames where the RIP was found but the tail was rejected.
 *
 * ⚠ A PILE-UP ON `_CS` IS THE SIGNATURE OF SPURIOUS MATCHES, not of malformed tails: the scan sweeps
 * ~70 offsets, so any qword that happens to equal the faulting RIP sets "RIP found" and then fails
 * at the first selector check. That also contaminates BPD_FAIL_TAIL_BAD itself -- a spurious early
 * match plus a real tail skipped for page containment reports TAIL_BAD instead of STRADDLED.
 */
void NxcBpdTailRejectBreakdown(_Out_writes_(NXC_BPD_TR_COUNT) UINT64* Out);

/**
 * The CS/SS of the FIRST frame to hit a tail rejection, and which check it was.
 *
 * A category is not a fact. "SS implausible" x20 has at least two explanations -- real ring-0 frames
 * with a NULL SS (architecturally legal at CPL 0 in long mode, and rejected by BpdPlausibleSelector's
 * `Sel == 0`), or spurious matches whose neighbouring qwords happen to look like a code selector.
 * The observed values separate them; reasoning about them does not.
 */
void NxcBpdTailRejectWitness(_Out_ UINT64* OutCs, _Out_ UINT64* OutSs, _Out_ UINT64* OutWhy);

/** Frames matched ONLY because a null SS beside a ring-0 CS is accepted. 0 here with rejections
 *  still climbing means the exemption is not being reached and the diagnosis was wrong. */
UINT64 NxcBpdTailNullSsAccepted(void);

/**
 * Clear `IA32_LBR_CTL.EN` and return the ORIGINAL value. Call this FIRST, before anything else.
 *
 * ⚠⚠ EVERY BRANCH EXECUTED BEFORE THE FREEZE DESTROYS ONE ENTRY OF THE THING WE CAME TO READ.
 * MEASURED (D36): with the freeze inside `NxcLbrSnapTake`, our own handler burned **23 of 32**
 * entries -- the indirect calls through the nt API table and their bodies -- leaving ~8 of genuine
 * caller history. That is why the first working trace reached two hops back and stopped.
 *
 * ⚠ THE THUNK IS NOT THE PROBLEM, WHICH IS WHY THIS IS IN C AND NOT IN ASSEMBLY. `push`, `sub` and
 * `movaps` are not control transfers, so the thunk's entire prologue records NOTHING; it contributes
 * exactly one entry, the `call` into C. Moving the freeze into `HookThunk.asm` would buy about one
 * additional entry over doing it here, in exchange for editing the hot path of every hook where the
 * stack arithmetic is already load-bearing. Not worth it -- and the branch accounting is the reason,
 * rather than a preference.
 *
 * ⚠ READ-MODIFY-WRITE OF BIT 0 ONLY. Another agent may own this ring with its own CPL filter, branch
 * filter or call-stack mode. Reconstructing a control word would silently reconfigure their capture,
 * so exactly one bit is touched and the caller restores the value this returns.
 *
 * @return the CTL value as found. Pass it to NxcLbrThawRing. Zero-EN means LBR was not recording.
 */
UINT64 NxcLbrFreezeRing(void);

/** Restore what NxcLbrFreezeRing returned, exactly. */
void NxcLbrThawRing(_In_ UINT64 SavedCtl);

/* EFLAGS bits the resume path must get right. */
#define NXC_EFLAGS_TF     (1ULL << 8)    /* trap flag: single-step after the next instruction */
#define NXC_EFLAGS_RF     (1ULL << 16)   /* resume flag: suppress ONE instruction breakpoint  */

/**
 * Compute what EFLAGS and DR6 must become before returning to a target whose `#DB` we CLAIMED.
 *
 * ⚠⚠ THIS IS WHERE THE CLASSIC HANG LIVES, AND IT HANGS THE WHOLE MACHINE, NOT THE TARGET.
 *
 * An EXECUTE breakpoint fires BEFORE the instruction at its address retires. Resume without setting
 * `EFLAGS.RF` and the very same instruction traps again, immediately, forever -- a `#DB` storm on
 * whatever core the target is on, at a rate no log can absorb. `RF` suppresses exactly one
 * instruction-breakpoint trap and the CPU clears it automatically afterwards, which is precisely the
 * "step past the one that fired" semantic wanted here. (Data breakpoints trap AFTER the access and
 * do not need it; setting `RF` for them is harmless, and testing which kind fired in order to skip
 * it would be a branch that can only be wrong.)
 *
 * ⚠ DR6 IS STICKY AND THE CPU NEVER CLEARS IT. Leave a condition bit set and the NEXT `#DB` -- from
 * any source, including a debugger's -- arrives carrying our stale bit, and any handler that reads
 * DR6 to decide ownership then sees a lie we wrote. The classifier already refuses to trust a stale
 * slot bit behind BD, but the correct fix is upstream: clear what we consumed.
 *
 * ⚠ AND ONLY WHAT WE CONSUMED. Zeroing DR6 wholesale would destroy a condition another agent had not
 * yet handled -- the same swallowing failure as claiming a foreign trap, arriving by a different
 * route. Only the bits named by `Consumed` are cleared. Reserved bits 11:4 read as 1 on real
 * hardware; they are preserved rather than normalised, because inventing a value for a field we do
 * not own is how a diagnostic starts disagreeing with `!dr` in a debugger.
 *
 * @param Eflags    EFLAGS as the trap frame holds it
 * @param Dr6       DR6 as the trap fired with it
 * @param Consumed  the DR6 bits this handler acted on -- typically one slot bit, or BS
 * @param OutEflags corrected EFLAGS to write back
 * @param OutDr6    corrected DR6 to write back
 */
void NxcBpdResume(
	_In_ UINT64 Eflags,
	_In_ UINT64 Dr6,
	_In_ UINT64 Consumed,
	_Out_ UINT64* OutEflags,
	_Out_ UINT64* OutDr6
	);

/**
 * Prove the classifier against synthetic inputs. PASSIVE_LEVEL, NOTHING PATCHED, no hardware touched.
 *
 * ⚠ EVERY CASE IS A KNOWN-BAD OR A KNOWN-GOOD WITH A STATED EXPECTED ANSWER, and the suite fails if
 * any case returns the other one. A classifier that only ever saw the happy path would claim
 * correctly and swallow silently, and swallowing is the failure nobody would notice.
 *
 * @param OutRan     cases executed
 * @param OutFailed  cases whose verdict disagreed with their expectation
 * @param OutFirstBad index of the first disagreement, or OutRan if none
 */
NTSTATUS NxcBpdSelfTest(
	_Out_ UINT32* OutRan,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirstBad
	);
