/**
 * @file BpDispatch.c
 * @brief The "is this #DB ours?" decision, and the suite that proves it. Reasoning in BpDispatch.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "BpDispatch.h"
#include "Btf.h"
#include "Bp.h"        /* NxcBpSlotTable -- ONE slot table, never a mirror */
/*
 * ⚠ BEFORE THE REDIRECT HEADER, DELIBERATELY. Pte.h pulls in ntddk declarations, and the redirects
 * below are `#define KeFoo (NexusNtApi.KeFoo)` -- including a header that DECLARES an nt API after
 * them rewrites the declaration itself into a struct member access. Every header that is not ours
 * belongs above line 26.
 */
#include "Pte.h"       /* NxcPteQuery -- the only residency check legal on the trap path */
#include "Lbr.h"
#include "Trace.h"   /* NxcTracePtBoundHere -- D108, the PT position at the trap */       /* IA32_LBR_* MSR numbers and LBR_CTL_EN -- see BpdCaptureLbr */
#include <intrin.h>   /* __readdr / __readcr3 / __readeflags / __writeeflags */

/*
 * ⚠ REQUIRED THE MOMENT THIS FILE CALLS ANY nt API. The payload carries NO import table; each call
 * must go through NexusNtApi. This file had none until BpdRecordHit needed the processor number, and
 * the build gate caught it immediately -- which is the argument for the gate being in the build.
 *
 * ⚠ THE ORDER IS LOAD-BEARING: the typed table, then the extern, then the redirects. The redirect
 * header is nothing but `#define KeFoo (NexusNtApi.KeFoo)`, so including it before `NexusNtApi` is
 * declared expands to a reference to an undeclared identifier at the CALL SITE -- an error that
 * points at the caller and says nothing about the missing declaration.
 */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define BpdLog NxcLogExt

/*
 * ⚠ ONE PLACE MASKS CR3, AND EVERY COMPARISON GOES THROUGH IT. PCID is enabled on all 24 logical
 * processors here, so CR3[11:0] is a context id rather than address bits, and a raw comparison could
 * never match. That defect already cost this project a wrong diagnosis once
 * (an earlier finding); a single masking function is the
 * structural answer, since two call sites that mask differently is exactly how it came back.
 */
static UINT64
Cr3Frame(
	_In_ UINT64 Cr3
	)
{
	return Cr3 & 0x000FFFFFFFFFF000ULL;
}

/* ================================================================================================
 * THE OBSERVER. Runs on the system exception path. Read the contract in BpDispatch.h first.
 * ============================================================================================= */

#define NXC_STATUS_SINGLE_STEP  0x80000004u   /* #DB -- what a debug register raises */
#define NXC_STATUS_BREAKPOINT   0x80000003u   /* int3 -- adjacent, and NOT ours       */

static volatile LONG64 gObsSeen        = 0;
static volatile LONG64 gObsDebugTraps  = 0;
static volatile LONG64 gObsBreakpoints = 0;
static volatile LONG64 gObsRejected    = 0;
/* What arg1 ACTUALLY was, so a run identifies the function instead of only rejecting it. */
static volatile LONG64 gObsArgZero        = 0;   /* 0 -- an unused parameter                */
static volatile LONG64 gObsArgSmall       = 0;   /* < 0x10000 -- a count, index or flags    */
static volatile LONG64 gObsArgUser        = 0;   /* a usermode VA                           */
static volatile LONG64 gObsLooksLikeRecord = 0;  /* kernel ptr whose first dword is NTSTATUS */
static volatile LONG64 gObsNotARecord     = 0;   /* kernel ptr that is something else        */

/* Distinct return addresses -- WHO calls the hooked function. Mapped to a name offline. */
static volatile UINT64 gObsCallers[NXC_BPD_MAX_CALLERS];
static volatile LONG   gObsCallerCount = 0;

/* Distinct arg1 first-dwords seen, with hit counts. See the note at the recording site: a bucket
 * count said 98 were "something else" and could not say which values those were. */
static volatile UINT32 gObsCodes[NXC_BPD_MAX_CODES];
static volatile LONG64 gObsCodeHits[NXC_BPD_MAX_CODES];
static volatile LONG   gObsCodeCount    = 0;
static volatile LONG64 gObsCodeOverflow = 0;
/* First-seen sample per distinct code: which caller produced it, and what sits at record+0x10
 * (EXCEPTION_RECORD.ExceptionAddress). See the recording site for why these two. */
static volatile UINT64 gObsCodeRa[NXC_BPD_MAX_CODES];
static volatile UINT64 gObsCodeAddr[NXC_BPD_MAX_CODES];

/*
 * THE CLAIM PATH, STAGE 1. The classifier now runs on live #DB traffic and records what it WOULD
 * have claimed, while claiming nothing. gBpdWouldClaim is the falsifiable control: with no
 * breakpoint armed it must be EXACTLY ZERO, because every #DB on the machine belongs to somebody
 * else. Any other value is a false positive caught before it could swallow a real exception.
 */
static volatile LONG64 gBpdClassified = 0;
static volatile LONG64 gBpdWouldClaim = 0;
static volatile LONG64 gBpdNotOurs    = 0;
static volatile UINT32 gBpdLastWhy    = 0;
static volatile UINT32 gBpdLastSlot   = 0;

/*
 * STAGE 2. gBpdClaimEnabled DEFAULTS TO ZERO and nothing in the driver sets it -- only an explicit
 * command does. A build containing the claim path therefore behaves exactly like one without it
 * until someone asks, which is the difference between shipping a capability and shipping a change.
 *
 * ⚠⚠ BUT IT IS AN **ARM-TIME** INTERLOCK, NOT A DISPATCH-TIME GATE (corrected).
 *
 * The dispatcher does NOT consult it when deciding to swallow a trap, and must not. By the time a
 * #DB reaches the claim path we have already established that WE programmed the register that
 * raised it -- and there is no state of this flag that makes handing our own trap to Windows
 * correct, because Windows kills a process for a breakpoint it did not set. Every claim decision
 * below is therefore unconditional on ownership alone; see the execute, data and BTF branches,
 * each of which says so at its site.
 *
 * What the flag still legitimately does is refuse to ARM (Btf.c does exactly this). That is the
 * right place for it: if nothing is armed, nothing traps, and "observer only" is true because
 * there is nothing to observe -- not because we declined to clean up after ourselves.
 */
static volatile LONG   gBpdClaimEnabled = 0;
static volatile LONG64 gBpdClaimed      = 0;   /* exceptions actually swallowed        */
static volatile LONG64 gBpdClaimRefused = 0;   /* matched, enabled, and still refused  */
/*
 * SUPPRESSED but NOT a sighting: a globally armed slot fired in a process that is not our target.
 * We wrote that register, so we swallow the trap rather than kill an innocent process -- but it
 * says nothing about the thing we are watching, so it must never be counted as a hit on it.
 */
static volatile LONG64 gBpdForeignSuppressed = 0;

/*
 * EFLAGS.RF writes performed to resume an EXECUTE breakpoint, and writes REFUSED at the last moment.
 * Separate from gBpdClaimed because they answer different questions: how many claims needed a resume
 * fixup, versus how many frames failed the write-time shape check and were abandoned instead.
 */
static volatile LONG64 gBpdRfWrites  = 0;
static volatile LONG64 gBpdRfRefused = 0;

/*
 * ================================================================================================
 * THE HIT RING. Fixed size, no allocation, no lock -- this is written from the exception path.
 *
 * ⚠ A CLAIMED SLOT IS RESERVED BEFORE IT IS FILLED. gBpdHitTotal is incremented FIRST and its old
 * value is the writer's index, so two processors trapping at once take different slots. The record
 * is then filled and only afterwards marked valid via its Sequence field -- a reader that sees a
 * sequence of 0 knows the slot is mid-write rather than reading half a record.
 *
 * ⚠ AND IT DROPS RATHER THAN OVERWRITES. Once the ring is full, further hits increment
 * gBpdHitDropped and are discarded. Overwriting would present the LAST 64 hits as though they were
 * all of them -- and the whole point of `bp --fork` is knowing whether BOTH fork points fired.
 * ================================================================================================
 */
/*
 * The DERIVED volatile-GPR offsets. Copied in whole under no lock: it is written once from PASSIVE
 * (an arm) and read on the trap path, and a torn read is impossible in practice because the only
 * transition is invalid -> valid with the fields written before Valid is set.
 */
static NXC_GPR_MAP     gBpdGprMap;
static NXC_NVGPR_MAP   gBpdNvGprMap;

/*
 * The FUNNEL VA, kept from hook-install time. R12-R15 are derived from the funnel (it builds
 * KEXCEPTION_FRAME), but the derivation runs at ARM time -- so the address has to survive the gap.
 * Stored where the other derivation state lives rather than re-resolved, because a second resolution
 * is a second source of truth for "which funnel".
 */
static volatile LONG64 gBpdFunnelVa = 0;

/*
 * The NTSTATUS the last derivation ATTEMPT returned. Recorded because "not derived" is four
 * different refusals and its reasons reach DbgPrint only -- unreachable on a machine with no kernel
 * debugger, which is every machine this actually runs on.
 */
static volatile LONG   gBpdGprStatus  = 0;
static volatile LONG   gBpdGprTried   = 0;
static volatile LONG   gBpdGprGate    = 0;

/* Per-reason tally for "the RIP was in the frame but the IRET tail did not hold" -- see the header. */
static volatile LONG64 gBpdTailReject[NXC_BPD_TR_COUNT];

/* The CS/SS of the FIRST frame to hit a tail rejection, so the category has a witness. */
static volatile LONG64 gBpdTrFirstSeen = 0;
static volatile LONG64 gBpdTrFirstCs   = 0;
static volatile LONG64 gBpdTrFirstSs   = 0;
static volatile LONG64 gBpdTrFirstWhy  = 0;

/* Frames accepted ONLY because a null SS beside a ring-0 CS is now allowed. */
static volatile LONG64 gBpdTailNullSs   = 0;

static NXC_BPD_HIT     gBpdHits[NXC_BPD_MAX_HITS];
static volatile LONG64 gBpdHitTotal   = 0;   /* hits offered to the ring, including dropped */
static volatile LONG64 gBpdHitDropped = 0;

/* ================================================================================================
 * KTRAP_FRAME.EFlags, DERIVED FROM LIVE TRAP FRAMES.
 *
 * ⚠⚠ WHY THIS IS NOT DONE BY DECODING CODE, AND WHAT DECODING CODE ACTUALLY PRODUCED.
 *
 * The first attempt derived the offset statically: find `test dword ptr [reg+X], 0x200` on the
 * exception path, observe that 0x200 is EFLAGS.IF, conclude X is KTRAP_FRAME.EFlags. Measured
 * against this machine's own ntoskrnl -- **10.0.26100.8972**, via `tools/ntos_eflags_offset.py` --
 * that reasoning is RIGHT ABOUT THE BIT AND WRONG ABOUT THE BASE. The site it finds is:
 *
 *     lea  r8, [rbp-80h]                     <- arg3 of KiDispatchException: THE TRAP FRAME
 *     ...
 *     test dword ptr [rbp+0F8h], 200h        <- the EFLAGS.IF test
 *
 * so the frame pointer is biased: TrapFrame = rbp - 0x80, and the field is at 0x80 + 0xF8 = +0x178.
 * The displacement alone, 0xF8, is KTRAP_FRAME.**Dr6**. Taking it at face value would have written
 * EFLAGS.RF into the saved debug-status register of a live trap frame -- silently, on every resumed
 * execute breakpoint. (The bias idiom is not rare: `lea rbp,[rsp+80h]` appears at 43 sites.)
 *
 * So the offset is derived from DATA instead, and from data this driver did not get from the frame:
 *
 *   EXCEPTION_RECORD.ExceptionAddress is the faulting RIP, and KTRAP_FRAME stores the hardware IRET
 *   frame -- Rip, SegCs, EFlags, Rsp, SegSs at an 8-byte stride, an ORDER FIXED BY THE ARCHITECTURE
 *   rather than by Windows. Find the qword in the frame equal to that RIP and the next four slots
 *   must have the shape the CPU guarantees. EFlags is the third.
 *
 * That is an INDEPENDENT oracle, not a mirror of the static one: different method, different input,
 * and it validates against the exact object that will later be written to. The two are cross-checked
 * (NxcBpdEflagsCross) precisely because agreement between independent methods is worth something and
 * agreement between an assumption and itself is not.
 *
 * ------------------------------------------------------------------------------------------------
 * PROVENANCE, AND WHY THE BUILD NUMBER IS RECORDED BUT NOT DEPENDED ON.
 *
 * Every value quoted above -- +0x178, the 0xF8/Dr6 trap, the 43 `lea rbp,[rsp+80h]` sites -- was
 * OBSERVED on **ntoskrnl 10.0.26100.8972** (the OS reports 26200.8973 / 25H2; that is an enablement
 * package over 26100 servicing, so the ntoskrnl version is the one that means anything).
 *
 * The build is written down so a future reader can tell WHERE a quoted number came from. It is NOT
 * a value this code trusts, and no constant here is pinned to it. The offset is rederived from live
 * frames every boot, anchored to the IRET frame shape -- Rip, SegCs, EFlags, Rsp, SegSs at 8-byte
 * stride -- which is fixed by the ARCHITECTURE and not by Windows. That anchor is the whole reason
 * a Windows update cannot silently move this: the thing being counted from is not Microsoft's to
 * change.
 *
 * So if this ever misbehaves after a Windows update, the question is WHICH GATE FAILED CLOSED, not
 * which constant went stale. `NXC_BPD_EFLAGS_MIN_AGREE` independent agreements are required before
 * the offset may be written at all, and a single disagreement blocks the write permanently.
 *
 * ⚠ A BUILD NUMBER IN A COMMENT ENFORCES NOTHING. It is documentation of a measurement, in exactly
 * the sense that `Idt.h` records 0x118 for R12 where the PUBLISHED KEXCEPTION_FRAME says 0x110.
 * Recording it must never become an excuse to pin the value it describes -- that is how a derived
 * offset gets reintroduced as a constant wearing a citation.
 * ============================================================================================= */

#define NXC_BPD_EFLAGS_MIN_AGREE 32u   /* independent exceptions required before it may be WRITTEN */

static volatile LONG   gBpdEflagsOffset   = 0;   /* the candidate, once a frame has produced one   */
static volatile LONG64 gBpdEflagsAttempts = 0;   /* frames that were scannable at all              */
static volatile LONG64 gBpdEflagsAgree    = 0;   /* frames whose IRET tail matched the candidate   */
static volatile LONG64 gBpdEflagsDisagree = 0;   /* ⚠ ANY non-zero here means DO NOT WRITE         */
/*
 * ⚠ ONE BUCKET FOR TWO CAUSES MISREADS AS ONE CAUSE. This was a single gBpdEflagsNoMatch, and on
 * hardware it went 10% -> 20% -> 26% while the page-straddle model predicted 9.77% -- a discrepancy
 * that could not be diagnosed because "straddled" and "scanned and rejected" were indistinguishable.
 * Split into the three states that actually occur, so the next reading ANSWERS the question:
 *
 *   STRADDLED  -- containment blocked every candidate; pure geometry, expected ~9.77%
 *   RIP ABSENT -- the frame was fully readable and the faulting RIP is NOT in it anywhere
 *   TAIL BAD   -- the RIP was found, but the four architectural fields after it were rejected
 *
 * The three are mutually exclusive and sum to the old total, so nothing is lost in the split.
 */
static volatile LONG64 gBpdEflagsStraddled = 0;
static volatile LONG64 gBpdEflagsRipAbsent = 0;
static volatile LONG64 gBpdEflagsTailBad   = 0;
static volatile LONG   gBpdEflagsStatic   = 0;   /* what the code-decoding oracle said, for the    */
static volatile LONG   gBpdEflagsStaticOk = 0;   /* cross-check only -- never used as the value    */

void
NxcBpdSetEflagsOffset(
	_In_ UINT32 Offset
	)
{
	/*
	 * ⚠ THIS RECORDS THE STATIC ORACLE'S ANSWER; IT DOES NOT SET THE OFFSET USED. Naming it "set"
	 * would invite exactly the mistake the whole comment above exists to prevent -- the static value
	 * is a CROSS-CHECK, and the derivation that gets written to is the one proven against live
	 * frames. Kept as a separate field so a disagreement is visible rather than resolved by whoever
	 * wrote last.
	 */
	InterlockedExchange(&gBpdEflagsStatic, (LONG)Offset);
	InterlockedExchange(&gBpdEflagsStaticOk, (Offset != 0) ? 1 : 0);
}

void
NxcBpdEflagsCheck(
	_Out_ UINT32* OutOffset,
	_Out_ UINT64* OutChecked,
	_Out_ UINT64* OutPlausible,
	_Out_ UINT64* OutRejected
	)
{
	*OutOffset    = (UINT32)gBpdEflagsOffset;
	*OutChecked   = (UINT64)gBpdEflagsAttempts;
	*OutPlausible = (UINT64)gBpdEflagsAgree;
	*OutRejected  = (UINT64)gBpdEflagsDisagree;
}

void
NxcBpdEflagsCross(
	_Out_ UINT32* OutStatic,
	_Out_ UINT32* OutStaticValid,
	_Out_ UINT64* OutNoMatch
	)
{
	*OutStatic      = (UINT32)gBpdEflagsStatic;
	*OutStaticValid = (UINT32)gBpdEflagsStaticOk;
	/* The total, preserved so the existing field keeps meaning what it meant. */
	*OutNoMatch     = (UINT64)gBpdEflagsStraddled + (UINT64)gBpdEflagsRipAbsent +
	                  (UINT64)gBpdEflagsTailBad;
}

/**
 * Capture one hit. Runs on the faulting thread, on the exception path, at the trap's IRQL.
 *
 * ⚠ ONLY DERIVED FIELDS ARE FILLED, and `Present` says which. The IRET tail is located by the same
 * proven matcher the resume path uses -- not read at an assumed offset -- so if this frame does not
 * match, those fields stay zero and the IRET bit stays clear rather than recording five plausible
 * numbers from the wrong place.
 */
static volatile LONG64 gBpdEscapes = 0;

/*
 * DIAGNOSTIC ONLY, AND IT IS A COUNTDOWN RATHER THAN A MODE. Set from usermode, it suppresses the
 * next N EFLAGS.RF writes so the ESCAPE branch below actually RUNS.
 *
 * ⚠ WHY IT HAS TO EXIST. `ESCAPED (unresumable)` has been 0 on every run since the branch was
 * written: it is reached only when RF cannot be written to a live trap frame, which no longer
 * happens now the offset is proven. So the branch that handles the MOST dangerous case -- an
 * execute breakpoint that cannot be resumed, where the alternative is a process spinning forever in
 * the exception path -- is the one piece of the claim path never executed. Reasoning about it is
 * exactly what this project does not accept for a check ("prove it against a KNOWN-BAD").
 *
 * ⚠ A COUNTDOWN, so a wrong value cannot leave the machine permanently unable to resume execute
 * breakpoints. It reaches zero and the path is normal again.
 *
 * ⚠ AND IT IS NEVER THE FINAL PATH. It suppresses a write; it does not fake one, and it does not
 * make the escape report success. FORCE_* flags are diagnostic-only by standing rule.
 */
static volatile LONG64 gBpdForceRfFail = 0;

void
NxcBpdForceRfFail(
	_In_ UINT32 Count
	)
{
	InterlockedExchange64(&gBpdForceRfFail, (LONG64)Count);
}

UINT64
NxcBpdForceRfFailRemaining(void)
{
	return (UINT64)gBpdForceRfFail;
}

/*
 * ================================================================================================
 * ⚠⚠ AN EXECUTE BREAKPOINT WE CANNOT RESUME MUST NOT BE PASSED THROUGH. THAT KILLS THE PROCESS.
 * ================================================================================================
 *
 * MEASURED THE HARD WAY: a global execute breakpoint on ntdll!NtDelayExecution killed a
 * batch of unrelated applications. The mechanism was a fallback chosen in the wrong direction.
 *
 * A global DR fires in EVERY address space. Resuming an execute hit needs EFLAGS.RF written into the
 * target's trap frame, and that write is refused whenever the frame straddles a page -- which the
 * live counters put at 10-25%%. The old code treated a refused write as "do not claim", and NOT
 * CLAIMING hands the #DB to KiDispatchException, which delivers STATUS_SINGLE_STEP to a process that
 * never asked for a breakpoint. It dies looking like its own crash.
 *
 * On a rarely-called target that was a handful of exits per test. On a function every sleeping
 * thread calls, roughly one hit in five was fatal.
 *
 * ⚠ THE SAFE STATES ARE "SWALLOW AND RESUME" OR "NOT ARMED". There is no safe pass-through here, so
 * this ESCAPES instead:
 *
 *   1. SWALLOW anyway. The process survives. Without RF it would re-execute the same instruction and
 *      trap again -- a hang, which is bad but recoverable, where death is not.
 *   2. CLEAR THIS CORE'S DR7 for the slot, immediately. The thread resumes on this core and does not
 *      re-trap, so step 1's hang does not happen. Each core disarms itself the first time it hits
 *      the unresumable case, so the whole machine converges without an IPI -- which cannot be issued
 *      from this IRQL anyway.
 *
 * ⚠ THE SLOT STAYS "ARMED" IN THE TABLE ON PURPOSE. DR7 is still set on cores that have not hit yet,
 * and marking it unarmed would make the classifier answer NO_SLOT for those -- pass-through, and
 * back to killing processes. The table entry is what keeps us swallowing until every core is clear.
 */
static void
BpdEscapeUnresumable(
	_In_ UINT32 Slot
	)
{
	InterlockedIncrement64(&gBpdEscapes);

	if (Slot >= NXC_BPD_MAX_SLOTS)
		return;

	/* Clear BOTH L and G for this slot on the CURRENT processor. Local write, no IPI, safe at any
	 * IRQL -- and it is the core the trapping thread is about to resume on. */
	CONST UINT64 Dr7 = __readdr(7);
	__writedr(7, Dr7 & ~((3ULL) << (Slot * 2u)));
}

/*
 * Copy the trapping thread's stack INTO the record, at the moment of the trap.
 *
 * ⚠ WHY THIS EXISTS WHEN `bp hits --stack N` ALREADY READS THE STACK. That read runs in usermode at
 * PASSIVE, long after the trap: frames have been popped and their pages reused. In the
 * run two records came back as 256 bytes of zeros for exactly that reason, and "the frame held zero"
 * and "the frame was gone before we looked" rendered identically. Both reads are kept -- a
 * DISAGREEMENT between the trap-time bytes and the PASSIVE bytes is itself evidence about how fast
 * the target recycles its stack, which neither read alone can show.
 *
 * ⚠ WHY IT IS SAFE TO WALK THE SELF-MAP HERE. The comment on NXC_BPD_HIT.Pid used to argue that
 * trap-time capture was impossible because there is no legal residency check above DISPATCH. That is
 * true of MmIsAddressValid and false of the problem: NxcPteQuery reads PAGE-TABLE pages through the
 * self-map, and those are never paged out, so the walk cannot fault at any IRQL. It also checks each
 * level's present bit before descending, so a partially-absent walk returns failure instead of
 * touching an unmapped table.
 *
 * ⚠ WHY THE SELF-MAP RESOLVES THE *TARGET'S* TABLES. The self-map reflects whatever CR3 is loaded.
 * Reaching this function at all means the classifier already matched the trap to our slot AND our
 * target's CR3 -- MATCH_SLOT is the only route to a recorded hit. So the current address space is
 * provably the target's, and the walk cannot silently return some other process's page. The self-map
 * INDEX is randomised per BOOT, not per process, which is why one derivation at DriverEntry stays
 * valid here (measured: 453 / 375 / 497 across boots -- never pinned).
 *
 * Fails CLOSED at every gate: PRESENT_STACK stays clear and StackBytes stays 0, so a reader can
 * never mistake "not captured" for "captured and empty".
 */
static void
BpdCaptureStack(
	_Inout_ NXC_BPD_HIT* H
	)
{
	/* The IRET tail is what supplies Rsp and Cs. Without it there is no stack pointer to trust. */
	if ((H->Present & NXC_BPD_PRESENT_IRET) == 0)
		return;

	/*
	 * ⚠ RING 3 ONLY. A ring-0 frame's Rsp is a kernel stack -- readable, but it is not what this
	 * capture is for, and SMAP/user-VA reasoning below would not apply to it. Every hit measured so
	 * far has been ring 3; a ring-0 one would be a finding and should not be quietly folded in here.
	 */
	if ((H->Cs & 3ull) != 3ull)
		return;

	CONST UINT64 Rsp = H->Rsp;

	/* Canonical low half only. A user Rsp outside this is not a user stack, whatever else it is. */
	if (Rsp == 0 || Rsp >= 0x0000800000000000ull)
		return;

	/*
	 * ⚠ BOUNDED TO THE PAGE Rsp SITS IN, AND THAT IS WHAT MAKES ONE PTE QUERY SUFFICIENT. Spanning
	 * into the next page would need a second query and open a second window in which that page could
	 * be trimmed. A hit near a page edge therefore captures LESS than the maximum, and StackBytes
	 * reports what was actually taken rather than what was asked for (D3).
	 */
	UINT32 Want = (UINT32)(0x1000u - (UINT32)(Rsp & 0xFFFull));
	if (Want > NXC_BPD_STACK_MAX)
		Want = NXC_BPD_STACK_MAX;
	if (Want == 0)
		return;

	NXC_PTE_INFO Info;
	if (!NT_SUCCESS(NxcPteQuery(Rsp, &Info)))
		return;

	if ((Info.Flags & NXC_PTE_VALID) == 0 || (Info.Flags & NXC_PTE_PRESENT) == 0)
		return;

	/*
	 * ⚠ AND IT MUST BE A USER PAGE. A ring-3 thread reached this address, so U/S is set on every
	 * level by construction; if it reads back clear, the walk did not land where we think it did and
	 * refusing is the only honest answer. This is the cheap cross-check on the address-space
	 * argument above -- it costs nothing and would catch the one failure that argument cannot.
	 */
	if ((Info.Flags & NXC_PTE_USER) == 0)
		return;

	/*
	 * ⚠ SMAP IS ACTIVE (CR4 bit 21, measured on this machine). Ring 0 cannot read a user page without
	 * EFLAGS.AC, so the copy runs inside a window with AC set -- and with IF CLEARED, because since
	 * Broadwell AC is NOT cleared on interrupt delivery: an interrupt taken inside this window would
	 * run its whole handler with SMAP disabled. Clearing IF makes the window non-preemptible, which
	 * is a few hundred nanoseconds for 256 bytes.
	 *
	 * The original EFLAGS is restored wholesale, so IF returns to whatever it was rather than to an
	 * assumed value -- this path runs both with interrupts enabled and disabled depending on where
	 * the trap came from, and guessing which would be wrong half the time.
	 */
	CONST UINT64 SavedFlags = __readeflags();

	__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);

	/*
	 * ⚠ VOLATILE, AND NOT ONLY FOR CORRECTNESS. A plain byte loop is exactly what MSVC recognises and
	 * rewrites into a `memcpy` call -- and the payload carries NO import table, so that rewrite fails
	 * the build gate rather than producing a subtle bug. volatile blocks the idiom recognition.
	 */
	for (UINT32 i = 0; i < Want; i++)
		H->Stack[i] = *(volatile UINT8*)(ULONG_PTR)(Rsp + (UINT64)i);

	__writeeflags(SavedFlags);

	H->StackBytes = Want;
	H->Present   |= NXC_BPD_PRESENT_STACK;
}

/*
 * Snapshot the LBR ring into the record -- the PATH to the trapping instruction (D107).
 *
 * ⚠ NO FREEZE IS NEEDED HERE, AND THAT IS THE FINDING RATHER THAN AN OMISSION. Hook.c freezes as its
 * very first act because a usermode hook stub runs at RING 3, so its own branches are precisely what
 * the USR filter records -- D36 measured 23 of 32 entries destroyed before the freeze could land.
 * This path runs at ring 0. With the default filter (USR set, OS clear) ring-0 branches are not
 * recorded at all, proven on this silicon by `lbr selftest`: 768 kernel-sourced entries when OS was
 * included, ZERO when it was not. The entire kernel trap-entry path therefore costs the ring nothing.
 *
 * ⚠ EXCEPT WHEN SOMEBODY ARMED WITH .OS, and then a freeze cannot save us either -- the trap entry
 * ran hundreds of ring-0 branches before this function existed, so the ring is already theirs. We
 * still capture, and LbrCtl carries the OS bit so the reading is honest rather than absent. Freezing
 * anyway would only protect our own short read loop, at the cost of two WRMSRs on every claimed trap.
 *
 * ⚠ AND THE ENTRIES ARE NOT SELF-DESCRIBING. `lbr arm` is machine-wide; another owner's filter
 * changes what these pairs MEAN. That is why LbrCtl is stored as evidence, not as metadata.
 */
static void
BpdCaptureLbr(
	_Inout_ NXC_BPD_HIT* H
	)
{
	/*
	 * ⚠ CPUID GATE FIRST, ALWAYS. RDMSR of 0x14CE on a part without architectural LBR is #GP, and a
	 * mapped image has no SEH -- that is a bugcheck, not a failed probe. Cached, because this runs on
	 * every claimed trap.
	 */
	if (!NxcLbrArchAvailable())
	{
		H->LbrWhy = NXC_BPD_LBRWHY_NO_ARCH;
		return;
	}

	/*
	 * ⚠⚠ THE LAST EVENT RECORD, READ FIRST -- BEFORE THE RING WALK, AND THAT ORDER IS THE POINT.
	 *
	 * LER holds the branch taken immediately before the last exception/interrupt. We are ON the
	 * fault path here, so right now it names the branch that reached the FAULTING instruction.
	 * The ring walk below costs up to ~96 RDMSRs; any interrupt taken during it would overwrite
	 * LER with its own path and we would record the timer tick instead of the fault. Three RDMSRs
	 * first closes that window.
	 *
	 * ⚠⚠ AND THE HOPE THAT THIS WOULD NAME THE FAULT'S BRANCH WAS MEASURED AND REFUTED. One trap,
	 * one record, LBR armed ANY_BRANCH:
	 *
	 *     RIP  : 0000011E4CEF0000
	 *     [ 0] 00007FFB7959F209 -> 0000011E4CEF0000  ind-call MISPRED   <- the LBR RING
	 *     LER  : 0x00007FFC65D4C407 -> 0x00007FFC65DD41B2  ret          <- unrelated
	 *
	 * LBR entry [0]'s To matches the trapped RIP EXACTLY; LER holds a frequent system path. Even
	 * here, this observer sits deep in KiDispatchException and the window from the fault is long
	 * enough for an interrupt to overwrite LER. The RING survives it and answers the question.
	 *
	 * ⚠ SO THE READS STAY, BUT THE CLAIM DOES NOT. Three RDMSRs for "the last event the CPU
	 * recorded" is cheap and occasionally its own evidence. It is NOT the branch into the fault --
	 * consumers are told to use entry [0]. Left in deliberately rather than deleted, so the next
	 * reader finds the measurement instead of re-proposing the idea.
	 *
	 * ⚠ NO EXTRA GATE. SDM Vol 3 20.1: the LER is "subject to the same dependencies on enabling and
	 * filtering" as the LBRs, and Vol 4 lists all three in the ARCHITECTURAL MSR table -- so the
	 * NxcLbrArchAvailable() check just passed is exactly the gate these need. Adding a second one
	 * would be two conditions that must agree about one fact.
	 */
	H->LerFrom = __readmsr(IA32_LER_FROM_IP);
	H->LerTo   = __readmsr(IA32_LER_TO_IP);
	H->LerInfo = __readmsr(IA32_LER_INFO);

	CONST UINT64 Ctl = __readmsr(IA32_LBR_CTL);

	/*
	 * ⚠ STORED BEFORE THE DECISION, NOT AFTER IT. When the capture fails, the raw control word is the
	 * only thing that says WHY, and a record that dropped it can only shrug. This is what the first
	 * build of this function got wrong.
	 */
	H->LbrCtl = Ctl;

	/*
	 * ⚠⚠ EN IS CLEAR HERE BY DESIGN, AND TESTING IT WAS THE BUG. The first build of this refused
	 * whenever `IA32_LBR_CTL.EN` read 0 and reported the ring as unarmed. measured: armed
	 * 0x00380005 (--calls) read back 0x00380004 at the trap, and armed 0x0038000D (--stack) read back
	 * 0x0038000C -- every bit intact EXCEPT bit 0, in both modes, on every record. The SDM says why:
	 * the processor clears the LBR enable before entering a debug-exception handler, and "this action
	 * does not clear previously stored LBR stack MSRs". That is the hardware FREEZING the ring for
	 * the handler -- the exact service we wanted -- and we read it as "nobody armed it" and walked
	 * away from a full ring.
	 *
	 * So the question is whether WE armed this core, which is what NxcLbrArmedHere answers from the
	 * record `lbr arm` wrote. A ring somebody ELSE has enabled is still worth reading, hence the
	 * second clause; only when neither holds is there genuinely nothing here.
	 */
	CONST BOOLEAN Ours = NxcLbrArmedHere();

	if (!Ours && (Ctl & LBR_CTL_EN) == 0)
	{
		H->LbrWhy = NXC_BPD_LBRWHY_DISABLED;
		return;
	}

	CONST UINT64 Depth = __readmsr(IA32_LBR_DEPTH_MSR);

	H->LbrDepth = (UINT32)(Depth & 0xFFFFFFFFull);

	UINT32 Want = H->LbrDepth;
	if (Want > NXC_BPD_LBR_MAX)
		Want = NXC_BPD_LBR_MAX;   /* truncation, and LbrDepth vs LbrCount is how a reader sees it */

	/*
	 * ⚠ NO TOS. Architectural LBR is stack-like: entry 0 is ALWAYS the youngest branch, and the walk
	 * stops at the first FROM_IP == 0 -- which is how Linux reads it, and why none of v1's TOS-based
	 * indexing survives here. A zero FROM is the end of what has been recorded, not a hole to skip.
	 */
	UINT32 n = 0;
	for (; n < Want; n++)
	{
		CONST UINT64 From = __readmsr(IA32_LBR_FROM_IP_0 + n);
		if (From == 0)
			break;

		H->Lbr[n].From = From;
		H->Lbr[n].To   = __readmsr(IA32_LBR_TO_IP_0 + n);
		H->Lbr[n].Info = __readmsr(IA32_LBR_INFO_0 + n);
	}

	H->LbrCount = n;

	/* ⚠ ZERO ENTRIES IS NOT A CAPTURE. An armed ring that recorded nothing yet says so by staying
	 * ABSENT, rather than presenting an empty list that reads like "this branch came from nowhere".
	 * But it gets its OWN reason code -- "enabled and empty" and "never enabled" need different
	 * investigations, and one word for both is what made the first build undiagnosable. */
	H->LbrWhy = (n != 0) ? NXC_BPD_LBRWHY_OK : NXC_BPD_LBRWHY_EMPTY;

	if (n != 0)
		H->Present |= NXC_BPD_PRESENT_LBR;

	/*
	 * ⚠⚠ RE-ENABLE, OR LBR DIES ON THIS CORE AFTER ITS FIRST HIT. The processor cleared EN on the way
	 * into this exception and normally the debug handler restores it -- but we SWALLOW the trap, so
	 * nobody else will. Without this the ring records exactly one trap per core and then goes silent
	 * forever, which would look like "LBR stopped working" and be blamed on anything but the swallow.
	 *
	 * ⚠ ONLY WHEN THE RING IS OURS, and written as the value we READ plus bit 0 -- never a
	 * reconstructed control word. Another owner's filter, CPL setting and call-stack mode all live in
	 * the bits we are preserving, and rebuilding them from our own assumptions is how one agent
	 * silently reconfigures another's capture.
	 *
	 * ⚠ WRITING CTL DOES NOT RESET THE RING; only writing IA32_LBR_DEPTH does (D23). So this resumes
	 * recording without discarding what is already there.
	 */
	if (Ours && (Ctl & LBR_CTL_EN) == 0)
		__writemsr(IA32_LBR_CTL, Ctl | LBR_CTL_EN);
}

static void
BpdRecordHit(
	_In_ UINT64 TrapFrameVa,
	_In_ UINT64 ExceptionFrameVa,
	_In_ UINT64 Dr6,
	_In_ UINT64 RawCr3,
	_In_ UINT32 Slot,
	_In_ UINT32 Why,
	_In_ UINT64 Address
	)
{
	/* Reserve first: the old value is this writer's index, so concurrent traps never collide. */
	CONST LONG64 Ticket = InterlockedIncrement64(&gBpdHitTotal) - 1;

	if (Ticket < 0)
		return;

	/*
	 * ⚠ IT WRAPS. IT DID NOT USED TO, AND THAT WAS A SILENT PARTIAL. Until this returned
	 * once Ticket reached the capacity, which made gBpdHits a FILL-ONCE buffer holding the first N
	 * traps for the lifetime of the arming -- while every comment and the usermode text called it a
	 * ring and said "ring full". Those two phrases describe opposite behaviours: a ring keeps the
	 * NEWEST window, fill-once keeps the OLDEST. The measured run made the cost concrete -- a write
	 * breakpoint on a thread stack filled all 64 records in 1.8 s with the target's STARTUP path and
	 * then went blind for the remaining 13 s, still reporting a full-looking result.
	 *
	 * Newest-wins is the right window for a trap recorder: the operator arms, does the thing they
	 * care about, then reads. Oldest-wins answers a question nobody asked.
	 *
	 * DROPPED still counts every displaced record, so "how much did I lose" survives the change.
	 */
	if (Ticket >= (LONG64)NXC_BPD_MAX_HITS)
		InterlockedIncrement64(&gBpdHitDropped);

	NXC_BPD_HIT* CONST H = &gBpdHits[(UINT64)Ticket % (UINT64)NXC_BPD_MAX_HITS];

	/*
	 * ⚠ INVALIDATE BEFORE OVERWRITING. Once the buffer wraps, this slot already holds a COMPLETE
	 * record that a reader may be copying right now. Zeroing Sequence first means that reader sees
	 * "not valid" rather than a record whose first half is the new trap and second half the old one.
	 * The store is volatile: under MSVC's default /volatile:ms on x64 a volatile store is a release,
	 * so it cannot sink below the field writes that follow, and x86-64 store ordering does the rest.
	 */
	*(volatile UINT64*)&H->Sequence = 0;

	H->Dr6       = Dr6;
	H->Cr3       = RawCr3;
	H->Address   = Address;
	H->Slot      = Slot;
	H->Why       = Why;
	H->Processor = KeGetCurrentProcessorNumberEx(NULL);
	H->Pid       = NxcBpSlotPid(Slot);   /* so the stack can be read afterwards, at PASSIVE */
	H->Present   = NXC_BPD_PRESENT_TRAP;

	/*
	 * ⚠ RESET, BECAUSE THE BUFFER WRAPS. This slot may still hold a previous hit's length. Present is
	 * reassigned above so a stale PRESENT_STACK cannot survive, but a stale LENGTH under a fresh flag
	 * is the kind of half-inherited record the wrap made possible. Stack[] itself is left alone -- the
	 * flag is the contract, exactly as it already is for the GPR fields.
	 */
	H->StackBytes = 0;
	H->LbrCtl     = 0;
	H->LbrDepth   = 0;
	H->LbrCount   = 0;
	H->LbrWhy     = NXC_BPD_LBRWHY_NO_ARCH;
	H->PtOffset   = 0;
	H->PtWhy      = NXC_BPD_PTWHY_NOT_ASKED;
	H->PtGen      = 0;   /* overwritten by the first gate that actually runs */
	/* ⚠ RESET FOR THE SAME REASON AS THE REST: the buffer wraps, and BpdCaptureLbr returns early on
	 * a part without architectural LBR without ever reaching the LER reads. Left alone, this slot
	 * would serve a PREVIOUS hit's Last Event Record as though it belonged to this fault. */
	H->LerFrom    = 0;
	H->LerTo      = 0;
	H->LerInfo    = 0;

	/*
	 * ⚠ THE LBR SNAPSHOT GOES FIRST, AHEAD OF EVERY OTHER CAPTURE. On the default filter our ring-0
	 * branches are excluded and order would not matter -- but if another owner armed with .OS set,
	 * every branch this function executes before the read displaces one entry of what we came for.
	 * Cheap insurance against a configuration we do not control, and it costs nothing when we do.
	 */
	BpdCaptureLbr(H);

	/*
	 * ⚠ PT IS BOUNDED ONLY WHEN THE SLOT ASKED (D108). Unlike the LBR snapshot, which is RDMSR-only
	 * and therefore unconditional, this clears IA32_RTIT_CTL.TraceEn and fences -- the SDM requires
	 * it, because the output pointer read while tracing is STALE. Two WRMSRs and a serializing fence
	 * on every claimed trap is not something to spend without being asked: one run here took 4648
	 * hits in 15 seconds.
	 */
	if (NxcBpSlotPtBound(Slot))
		H->PtWhy = NxcTracePtBoundHere(&H->PtOffset, &H->PtGen);
	else
		H->PtWhy = NXC_BPD_PTWHY_NOT_ASKED;

	if (H->PtWhy == NXC_BPD_PTWHY_OK)
		H->Present |= NXC_BPD_PRESENT_PT;

	/*
	 * ⚠ THE TAIL IS LOCATED, NOT ASSUMED -- and by the SAME function that proved the offset. Passing
	 * the faulting RIP would be circular here (we do not have it independently at this point), so the
	 * proven EFlags offset is used to recover the tail base: EFlags sits at tail + 0x10.
	 */
	UINT32 EfOffset = 0;
	if (NxcBpdEflagsProven(&EfOffset) && EfOffset >= 0x10u &&
	    TrapFrameVa >= 0xFFFF800000000000ull)
	{
		CONST UINT64 Tail = TrapFrameVa + (EfOffset - 0x10u);

		if (((Tail ^ (Tail + 0x27ull)) & ~0xFFFull) == 0 &&
		    ((Tail ^ TrapFrameVa) & ~0xFFFull) == 0)
		{
			H->Rip    = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x00ull);
			H->Cs     = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x08ull);
			H->EFlags = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x10ull);
			H->Rsp    = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x18ull);
			H->Ss     = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x20ull);
			H->Present |= NXC_BPD_PRESENT_IRET;
		}
	}

	/*
	 * ⚠ THE VOLATILE GPRs, ONLY IF THEIR OFFSETS WERE DERIVED AND CROSS-CHECKED. Same containment
	 * rule as the tail: the whole read must stay inside the page the trap frame starts in, checked
	 * against the LAST byte touched. If anything fails, the flag stays clear and the fields stay
	 * zero -- never a partially-filled register set presented as a complete one.
	 */
	if (gBpdGprMap.Valid && TrapFrameVa >= 0xFFFF800000000000ull)
	{
		CONST UINT64 First = TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_RAX];
		CONST UINT64 Last  = TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_R11] + 7ull;

		if (((First ^ Last) & ~0xFFFull) == 0 &&
		    ((First ^ TrapFrameVa) & ~0xFFFull) == 0)
		{
			H->Rax = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_RAX]);
			H->Rcx = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_RCX]);
			H->Rdx = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_RDX]);
			H->R8  = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_R8]);
			H->R9  = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_R9]);
			H->R10 = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_R10]);
			H->R11 = *(volatile UINT64*)(ULONG_PTR)(TrapFrameVa + gBpdGprMap.Offset[NXC_GPR_R11]);
			H->Present |= NXC_BPD_PRESENT_VOLGPR;
		}
	}

	/*
	 * ⚠ R12-R15, FROM A DIFFERENT STRUCTURE AND UNDER A DIFFERENT FLAG. KEXCEPTION_FRAME is arg2, a
	 * separate pointer with a separately derived map -- so a failure in one register set can never
	 * silently supply the other. Same containment rule, checked against the LAST byte touched.
	 */
	if (gBpdNvGprMap.Valid && ExceptionFrameVa >= 0xFFFF800000000000ull)
	{
		CONST UINT64 First = ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R12];
		CONST UINT64 Last  = ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R15] + 7ull;

		if (((First ^ Last) & ~0xFFFull) == 0 &&
		    ((First ^ ExceptionFrameVa) & ~0xFFFull) == 0)
		{
			H->R12 = *(volatile UINT64*)(ULONG_PTR)(ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R12]);
			H->R13 = *(volatile UINT64*)(ULONG_PTR)(ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R13]);
			H->R14 = *(volatile UINT64*)(ULONG_PTR)(ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R14]);
			H->R15 = *(volatile UINT64*)(ULONG_PTR)(ExceptionFrameVa + gBpdNvGprMap.Offset[NXC_NVGPR_R15]);
			H->Present |= NXC_BPD_PRESENT_NVGPR;
		}
	}

	/*
	 * ⚠ LAST OF THE FILLS, BECAUSE IT DEPENDS ON THEM. BpdCaptureStack needs Rsp and Cs, which only
	 * exist once the IRET tail above succeeded -- and it must run BEFORE Sequence publishes the
	 * record, or a reader could copy a hit whose stack bytes are still arriving.
	 */
	BpdCaptureStack(H);

	/*
	 * ⚠ SEQUENCE IS WRITTEN LAST, AND IT IS WHAT MAKES THE RECORD VALID. Ticket+1 so a filled record
	 * is never 0 -- a reader seeing 0 knows the slot is reserved but still being written, rather than
	 * reading a half-populated record and believing it.
	 *
	 * ⚠ IT IS ALSO THE RECORD'S GLOBAL IDENTITY, which matters now that the buffer wraps. Index no
	 * longer implies age -- after a wrap gBpdHits[0] holds a NEWER hit than gBpdHits[1] -- so the
	 * only thing that orders records is this number, and the reader uses it for exactly that.
	 * Volatile for the same release reason as the invalidating store above.
	 */
	*(volatile UINT64*)&H->Sequence = (UINT64)(Ticket + 1);
}

void
NxcBpdHitsClear(void)
{
	/*
	 * ⚠ SEQUENCE FIRST, COUNTERS SECOND. A reader treats Sequence == 0 as "reserved, not yet
	 * filled", so zeroing it before the totals means a concurrent reader sees records disappear
	 * rather than seeing a stale record under a fresh count. The reverse order would briefly present
	 * old records as new ones, which is the exact confusion this command exists to remove.
	 */
	for (UINT32 i = 0; i < NXC_BPD_MAX_HITS; i++)
		gBpdHits[i].Sequence = 0;

	InterlockedExchange64(&gBpdHitTotal, 0);
	InterlockedExchange64(&gBpdHitDropped, 0);
}

void
NxcBpdHitStats(
	_Out_ UINT32* OutHeld,
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutDropped
	)
{
	CONST LONG64 Total = gBpdHitTotal;

	*OutTotal   = (UINT64)Total;
	*OutDropped = (UINT64)gBpdHitDropped;

	LONG64 Have = Total;
	if (Have > (LONG64)NXC_BPD_MAX_HITS)
		Have = (LONG64)NXC_BPD_MAX_HITS;

	*OutHeld = (UINT32)Have;
}

BOOLEAN
NxcBpdHitAt(
	_In_ UINT32 Index,
	_Out_ NXC_BPD_HIT* Out
	)
{
	if (Index >= NXC_BPD_MAX_HITS)
		return FALSE;

	/*
	 * ⚠ SEQUENCE IS THE VALIDITY FLAG, AND IT IS READ FIRST. BpdRecordHit reserves a slot, fills it,
	 * and writes Sequence LAST -- so a zero here means the slot is reserved but still being written
	 * by another processor. Returning it anyway would hand back a record whose fields are partly
	 * stale memory and look exactly like data.
	 */
	CONST UINT64 Before = *(volatile UINT64*)&gBpdHits[Index].Sequence;

	if (Before == 0)
		return FALSE;

	*Out = gBpdHits[Index];

	/*
	 * ⚠ RE-READ AFTER THE COPY, BECAUSE THE BUFFER WRAPS NOW. Checking validity only before the copy
	 * was sufficient while records were written once and never touched again. With newest-wins, a
	 * trap on another processor can overwrite this exact slot DURING the copy, and the result would
	 * be half of one hit and half of another -- a record that is internally impossible yet carries
	 * every "present" flag. A changed sequence means the copy raced; the record is dropped rather
	 * than repaired, because there is nothing here to repair it from.
	 */
	CONST UINT64 After = *(volatile UINT64*)&gBpdHits[Index].Sequence;

	if (After != Before)
		return FALSE;

	return TRUE;
}

void
NxcBpdEflagsFailBreakdown(
	_Out_ UINT64* OutStraddled,
	_Out_ UINT64* OutRipAbsent,
	_Out_ UINT64* OutTailBad
	)
{
	*OutStraddled = (UINT64)gBpdEflagsStraddled;
	*OutRipAbsent = (UINT64)gBpdEflagsRipAbsent;
	*OutTailBad   = (UINT64)gBpdEflagsTailBad;
}

void
NxcBpdSetGprStatus(
	_In_ NTSTATUS Status,
	_In_ UINT32 Gate
	)
{
	InterlockedExchange(&gBpdGprStatus, (LONG)Status);
	InterlockedExchange(&gBpdGprGate, (LONG)Gate);
	InterlockedExchange(&gBpdGprTried, 1);
}

void
NxcBpdGprStatus(
	_Out_ UINT32* OutTried,
	_Out_ UINT32* OutStatus,
	_Out_ UINT32* OutGate
	)
{
	*OutTried  = (UINT32)gBpdGprTried;
	*OutStatus = (UINT32)gBpdGprStatus;
	*OutGate   = (UINT32)gBpdGprGate;
}

void
NxcBpdSetFunnelVa(
	_In_ UINT64 FunnelVa
	)
{
	InterlockedExchange64(&gBpdFunnelVa, (LONG64)FunnelVa);
}

UINT64
NxcBpdFunnelVa(void)
{
	return (UINT64)gBpdFunnelVa;
}

void
NxcBpdSetNvGprMap(
	_In_ CONST NXC_NVGPR_MAP* Map
	)
{
	/* Valid LAST, same as the volatile map: a concurrent trap sees the whole map or none of it. */
	NXC_NVGPR_MAP Local = *Map;
	CONST BOOLEAN WasValid = Local.Valid;
	Local.Valid = FALSE;
	gBpdNvGprMap = Local;
	gBpdNvGprMap.Valid = WasValid;
}

void
NxcBpdSetGprMap(
	_In_ CONST NXC_GPR_MAP* Map
	)
{
	/* ⚠ Valid LAST. Every offset is in place before the flag that authorises reading them, so a
	 * concurrent trap either sees the whole map or none of it. */
	NXC_GPR_MAP Local = *Map;
	CONST BOOLEAN WasValid = Local.Valid;
	Local.Valid = FALSE;
	gBpdGprMap = Local;
	gBpdGprMap.Valid = WasValid;
}

BOOLEAN
NxcBpdGprMap(
	_Out_ NXC_GPR_MAP* Out
	)
{
	*Out = gBpdGprMap;
	return gBpdGprMap.Valid;
}

void
NxcBpdRfStats(
	_Out_ UINT64* OutWrites,
	_Out_ UINT64* OutRefused
	)
{
	*OutWrites  = (UINT64)gBpdRfWrites;
	*OutRefused = (UINT64)gBpdRfRefused;
}

UINT64
NxcBpdEscapes(void)
{
	return (UINT64)gBpdEscapes;
}

BOOLEAN
NxcBpdEflagsProven(
	_Out_opt_ UINT32* OutOffset
	)
{
	CONST UINT32 Off = (UINT32)gBpdEflagsOffset;
	if (OutOffset != NULL)
		*OutOffset = Off;

	/*
	 * ⚠ FAIL CLOSED, AND A SINGLE DISAGREEMENT IS FATAL. The consumer WRITES to this displacement in
	 * another thread's saved register state. "Mostly agreed" is not a state that justifies that; if
	 * two live frames ever disagreed then one of them was not a trap frame, and which one is unknown.
	 */
	return (Off != 0 &&
	        gBpdEflagsDisagree == 0 &&
	        gBpdEflagsAgree >= (LONG64)NXC_BPD_EFLAGS_MIN_AGREE);
}

/*
 * Is this a selector Windows could plausibly have pushed? Kernel CS/SS and the two usermode
 * (compatibility and long mode) pairs, and nothing else. Checked as a SHAPE -- the upper 48 bits of
 * the pushed qword are zero -- rather than by value alone, because that is what makes a random
 * pointer fail the test.
 */
static BOOLEAN
BpdPlausibleSelector(
	_In_ UINT64 Value,
	_In_ BOOLEAN IsCode
	)
{
	if ((Value & 0xFFFFFFFFFFFF0000ull) != 0)
		return FALSE;

	CONST UINT32 Sel = (UINT32)(Value & 0xFFFFu);
	if (Sel == 0)
		return FALSE;
	if ((Sel & 0x4u) != 0)
		return FALSE;   /* LDT selector -- not something the kernel's trap path pushes */

	/* RPL 0 or 3; ring 1 and 2 are unused by Windows. */
	CONST UINT32 Rpl = Sel & 3u;
	if (Rpl == 1u || Rpl == 2u)
		return FALSE;

	UNREFERENCED_PARAMETER(IsCode);
	return TRUE;
}

/**
 * Locate KTRAP_FRAME.EFlags in ONE live frame, and fold the answer into the running agreement.
 *
 * @param TrapFrameVa  the frame ntoskrnl handed the dispatcher (arg3), canonical-kernel already.
 * @param FaultRip     EXCEPTION_RECORD.ExceptionAddress -- the anchor, from OUTSIDE the frame.
 *
 * ⚠ THE MATCH IS FIVE FIELDS, NOT ONE. KTRAP_FRAME ends with the hardware IRET frame, whose ORDER
 * AND STRIDE ARE ARCHITECTURAL: Rip, SegCs, EFlags, Rsp, SegSs, eight bytes apart. So the test is
 *
 *     [R+0x00] == the faulting RIP        (matched against a value from another argument)
 *     [R+0x08]    a plausible selector, upper 48 bits zero
 *     [R+0x10]    EFLAGS shape: bit 1 SET, bits 3/5/15 CLEAR, upper 32 bits zero
 *     [R+0x18]    a canonical, non-zero RSP
 *     [R+0x20]    a plausible selector whose RPL EQUALS CS's
 *
 * The last clause is the one that makes it hard to satisfy by accident: CS and SS are pushed by the
 * same trap and always carry the same privilege level, so a coincidental RIP-shaped qword somewhere
 * else in the frame has to be followed by four more fields that agree with each other AND with the
 * ring the exception came from.
 */
#define BPD_FAIL_NONE      0u
#define BPD_FAIL_STRADDLED 1u
#define BPD_FAIL_RIP_GONE  2u
#define BPD_FAIL_TAIL_BAD  3u

static BOOLEAN
BpdMatchIretTail(
	_In_ UINT64 TrapFrameVa,
	_In_ UINT64 FaultRip,
	_In_ BOOLEAN EnforcePageContainment,
	_Out_ UINT32* OutEflagsOffset,
	_Out_opt_ UINT32* OutFailWhy
	)
{
	/* Which of the three failure states this frame landed in -- see the counters' comment. */
	UINT32  Skipped  = 0;
	BOOLEAN RipFound = FALSE;

	/*
	 * ⚠ WHICH CHECK STOPPED IT -- because "tail REJECTED" is EIGHT causes wearing one name, and it is
	 * the last unexplained number in a mechanism that is otherwise verified end to end. Counting the
	 * FURTHEST-PROGRESSING rejection per frame rather than every rejection: the scan sweeps ~70
	 * offsets and a random qword that happens to equal FaultRip will fail at the first selector check,
	 * which says nothing about the real tail. The offset that got furthest is the one worth naming.
	 *
	 * Ordered by position in the sequence below, so "furthest" is simply the largest value.
	 */
	UINT32 Furthest = 0;

	/*
	 * ⚠ AND THE VALUES THAT CAUSED IT, because "SS implausible" is still a category, not a fact. The
	 * leading explanation for a 20/20 pile-up on SS is that a null SS is ARCHITECTURALLY LEGAL at
	 * CPL 0 in long mode, so real kernel frames push SS = 0 and BpdPlausibleSelector's `Sel == 0`
	 * rejects them. That is a hypothesis; the CS/SS actually seen turns it into a measurement, and
	 * guessing instead has already cost two hardware runs today.
	 */
	UINT64 FurthestCs = 0, FurthestSs = 0;
	/*
	 * The scan window. A KTRAP_FRAME is 0x190 bytes and the IRET tail lives near its end, but the
	 * whole plausible span is swept rather than starting at a guessed offset -- starting at 0x160
	 * "because that is where Rip is" would be the pinning this function exists to avoid.
	 */
	CONST UINT32 ScanFrom = 0x40u;
	CONST UINT32 ScanTo   = 0x188u;

	*OutEflagsOffset = 0;

	for (UINT32 R = ScanFrom; R <= ScanTo; R += 8u)
	{
		CONST UINT64 At = TrapFrameVa + R;

		/*
		 * ⚠ THE WHOLE FIVE-FIELD READ MUST STAY ON ONE PAGE, and it is checked against the LAST byte
		 * touched (+0x27), not the first. A frame that straddles a page boundary simply yields no
		 * derivation this time -- counted as NoMatch, never guessed at. Roughly one exception in ten
		 * lands that way, which costs nothing when thousands arrive a minute.
		 *
		 * ⚠ DISABLED ONLY FOR THE SELF-TEST, whose fixtures are stack buffers this driver owns and
		 * may legitimately straddle a page. Live callers always pass TRUE -- the parameter exists so
		 * the tested code and the shipped code are THE SAME FUNCTION rather than two that must agree.
		 */
		if (EnforcePageContainment &&
		    (((At ^ (At + 0x27ull)) & ~0xFFFull) != 0 ||
		     ((At ^ TrapFrameVa) & ~0xFFFull) != 0))
		{
			Skipped++;
			continue;
		}

		if (*(volatile UINT64*)(ULONG_PTR)At != FaultRip)
			continue;

		/* The RIP IS in this frame. Anything that rejects it from here on is the TAIL failing, which
		 * is a completely different finding from the RIP being absent. */
		RipFound = TRUE;

		CONST UINT64 Cs  = *(volatile UINT64*)(ULONG_PTR)(At + 0x08ull);
		CONST UINT64 Efl = *(volatile UINT64*)(ULONG_PTR)(At + 0x10ull);
		CONST UINT64 Rsp = *(volatile UINT64*)(ULONG_PTR)(At + 0x18ull);
		CONST UINT64 Ss  = *(volatile UINT64*)(ULONG_PTR)(At + 0x20ull);

		if (!BpdPlausibleSelector(Cs, TRUE))
			{ if (Furthest <= NXC_BPD_TR_CS)   { Furthest = NXC_BPD_TR_CS;   FurthestCs = Cs; FurthestSs = Ss; } continue; }
		/*
		 * ⚠⚠ A NULL SS IS LEGAL AT CPL 0 IN LONG MODE, and rejecting it threw away real frames.
		 * measured: 20 of 20 tail rejections were SS, with CS passing every time -- which
		 * cannot be spurious matches, because a spurious match is followed by RANDOM qwords and CS
		 * would fail nearly always. So these are genuine ring-0 trap frames pushing SS = 0, and
		 * BpdPlausibleSelector's `Sel == 0` was discarding them.
		 *
		 * ⚠ THE ZERO TEST STAYS FOR EVERYTHING ELSE, because it is what makes a random pointer fail:
		 * zero qwords are everywhere on a stack. The exemption is narrow -- null SS, and only beside
		 * a RING-0 CS -- and the remaining tail checks still have to hold (EFLAGS fixed bits, EFLAGS
		 * upper half, RSP canonical and kernel-side), so a run of zeros cannot walk through here.
		 *
		 * ⚠ COUNTED, so "the fix did nothing" and "the fix was never reached" stay distinguishable.
		 */
		CONST BOOLEAN SsNullAtRing0 = ((Ss == 0ull) && ((Cs & 3ull) == 0ull));

		if (!SsNullAtRing0 && !BpdPlausibleSelector(Ss, FALSE))
			{ if (Furthest <= NXC_BPD_TR_SS)   { Furthest = NXC_BPD_TR_SS;   FurthestCs = Cs; FurthestSs = Ss; } continue; }
		if ((Cs & 3ull) != (Ss & 3ull))   /* CS and SS are pushed together and always share a ring */
			{ if (Furthest <= NXC_BPD_TR_RING) { Furthest = NXC_BPD_TR_RING; FurthestCs = Cs; FurthestSs = Ss; } continue; }

		/* EFLAGS: bit 1 reads 1 always, bits 3, 5 and 15 read 0 always. Architectural, so this
		 * cannot drift with a Windows build. The field is 32 bits; the upper half is padding. */
		if ((Efl & 0xFFFFFFFF00000000ull) != 0)
			{ if (Furthest < NXC_BPD_TR_EFL_HIGH) Furthest = NXC_BPD_TR_EFL_HIGH; continue; }
		if ((Efl & 0x2ull) == 0 || (Efl & 0x8ull) != 0 ||
		    (Efl & 0x20ull) != 0 || (Efl & 0x8000ull) != 0)
			{ if (Furthest < NXC_BPD_TR_EFL_FIXED) Furthest = NXC_BPD_TR_EFL_FIXED; continue; }

		/* RSP must be a canonical address on the side of the world CS says we came from. */
		if (Rsp == 0)
			{ if (Furthest < NXC_BPD_TR_RSP_ZERO) Furthest = NXC_BPD_TR_RSP_ZERO; continue; }
		if ((Cs & 3ull) == 0)
		{
			if (Rsp < 0xFFFF800000000000ull)
				{ if (Furthest < NXC_BPD_TR_RSP_SIDE) Furthest = NXC_BPD_TR_RSP_SIDE; continue; }
		}
		else
		{
			if (Rsp >= 0x00007FFFFFFFFFFFull)
				{ if (Furthest < NXC_BPD_TR_RSP_SIDE) Furthest = NXC_BPD_TR_RSP_SIDE; continue; }
		}

		/* ⚠ A MATCH THAT ONLY THE EXEMPTION ALLOWED. Counting it separately is what turns "the null-SS
		 * fix works" from a belief into a number -- and if this stays 0 while tail rejections stay
		 * 20, the exemption is not being reached and the diagnosis was wrong. */
		if (SsNullAtRing0)
			InterlockedIncrement64(&gBpdTailNullSs);

		*OutEflagsOffset = R + 0x10u;
		if (OutFailWhy != NULL)
			*OutFailWhy = BPD_FAIL_NONE;
		return TRUE;
	}

	if (OutFailWhy != NULL)
	{
		/*
		 * ⚠ ORDER MATTERS: "the tail was found and rejected" is the most specific statement and wins.
		 * Reporting STRADDLED for a frame that was mostly readable would hide the interesting case
		 * behind the boring one -- which is precisely how the single counter misled.
		 */
		if (RipFound)
			*OutFailWhy = BPD_FAIL_TAIL_BAD;
		else if (Skipped != 0)
			*OutFailWhy = BPD_FAIL_STRADDLED;
		else
			*OutFailWhy = BPD_FAIL_RIP_GONE;
	}

	/*
	 * ⚠ LIVE CALLERS ONLY. The self-test passes EnforcePageContainment = FALSE and deliberately feeds
	 * malformed fixtures, so counting there would fill these with the very cases they exist to rule
	 * out -- a diagnostic polluted by its own test is worse than none.
	 *
	 * ⚠ AND THIS IS WHY BPD_FAIL_TAIL_BAD IS CONTAMINATED, which the ordering above admits without
	 * quantifying: a SPURIOUS early match (some qword equal to FaultRip) sets RipFound, and if the
	 * REAL tail was then skipped for page containment, the frame reports TAIL_BAD rather than
	 * STRADDLED. The per-reason split is what makes that visible -- a pile-up on the first check (CS)
	 * is the signature of spurious matches, not of malformed tails.
	 */
	if (EnforcePageContainment && RipFound && Furthest < NXC_BPD_TR_COUNT)
	{
		InterlockedIncrement64(&gBpdTailReject[Furthest]);

		/*
		 * ⚠ FIRST ONE WINS, DELIBERATELY. A last-writer field would show whatever the most recent
		 * frame happened to hold and change under you between two reads of the same run -- the
		 * "reading that does not reproduce" problem. Published once, with the selectors that caused
		 * the rejection, so the number and the explanation come from the SAME frame.
		 */
		if (InterlockedCompareExchange64(&gBpdTrFirstSeen, 1, 0) == 0)
		{
			gBpdTrFirstCs  = (LONG64)FurthestCs;
			gBpdTrFirstSs  = (LONG64)FurthestSs;
			gBpdTrFirstWhy = (LONG64)Furthest;
		}
	}

	return FALSE;
}

void
NxcBpdTailRejectBreakdown(
	_Out_writes_(NXC_BPD_TR_COUNT) UINT64* Out
	)
{
	for (UINT32 i = 0; i < NXC_BPD_TR_COUNT; i++)
		Out[i] = (UINT64)gBpdTailReject[i];
}

void
NxcBpdTailRejectWitness(
	_Out_ UINT64* OutCs,
	_Out_ UINT64* OutSs,
	_Out_ UINT64* OutWhy
	)
{
	*OutCs  = (UINT64)gBpdTrFirstCs;
	*OutSs  = (UINT64)gBpdTrFirstSs;
	*OutWhy = (UINT64)gBpdTrFirstWhy;
}

UINT64
NxcBpdTailNullSsAccepted(void)
{
	return (UINT64)gBpdTailNullSs;
}

static void
BpdDeriveEflags(
	_In_ UINT64 TrapFrameVa,
	_In_ UINT64 FaultRip
	)
{
	UINT32 Found = 0, FailWhy = BPD_FAIL_NONE;

	InterlockedIncrement64(&gBpdEflagsAttempts);

	if (BpdMatchIretTail(TrapFrameVa, FaultRip, TRUE, &Found, &FailWhy))
	{
		/* A full match. Fold it into the running agreement. */
		{
			CONST LONG   Prev  = InterlockedCompareExchange(&gBpdEflagsOffset, (LONG)Found, 0);

			if (Prev == 0 || Prev == (LONG)Found)
			{
				InterlockedIncrement64(&gBpdEflagsAgree);
			}
			else
			{
				/*
				 * ⚠ TWO LIVE FRAMES DISAGREED. One of them was not a trap frame, and nothing here
				 * can say which -- so the candidate is not "corrected", it is POISONED. NxcBpdEflagsProven
				 * refuses forever after, and execute breakpoints stay refused rather than writing a
				 * flag into a structure whose identity is in doubt.
				 */
				InterlockedIncrement64(&gBpdEflagsDisagree);
			}
		}
		return;
	}

	/*
	 * No offset in this frame satisfied all five fields. WHICH of the three ways it failed is the
	 * datum -- the single combined counter is what left a 26%-vs-9.77% discrepancy undiagnosable.
	 */
	if (FailWhy == BPD_FAIL_TAIL_BAD)
		InterlockedIncrement64(&gBpdEflagsTailBad);
	else if (FailWhy == BPD_FAIL_STRADDLED)
		InterlockedIncrement64(&gBpdEflagsStraddled);
	else
		InterlockedIncrement64(&gBpdEflagsRipAbsent);
}

/* ================================================================================================
 * THE SELF-TEST -- AND IT IS BUILT AROUND THE CASES THAT MUST FAIL.
 *
 * ⚠ A SELF-TEST ON THE TIDIEST FIXTURE TESTS THE ONE CASE WHERE THE DEFECT IS INVISIBLE. A synthetic
 * frame with the IRET tail in the right place and zeroes everywhere else would pass against a
 * matcher that checked ONLY the RIP -- which is exactly the weak matcher this must rule out. So the
 * fixtures are adversarial: the first one plants a DECOY qword equal to the faulting RIP earlier in
 * the frame, and the correct answer is only reachable by rejecting it on the four following fields.
 *
 * ⚠ AND IT RUNS THE SHIPPED FUNCTION, not a copy. BpdMatchIretTail is called by both this and the
 * live path; a self-test against a reimplementation proves the reimplementation.
 * ============================================================================================= */

#define BPD_ST_RIP 0
#define BPD_ST_CS  1
#define BPD_ST_EFL 2
#define BPD_ST_RSP 3
#define BPD_ST_SS  4

typedef struct _BPD_SELFTEST_CASE
{
	PCSTR   Name;
	UINT32  TailAt;        /* where the IRET tail is planted, or 0 for none                */
	UINT64  Decoy;         /* a qword equal to FaultRip planted at DecoyAt, 0 = none       */
	UINT32  DecoyAt;
	UINT64  Cs, Efl, Rsp, Ss;
	BOOLEAN ExpectMatch;
	UINT32  ExpectOffset;  /* meaningful only when ExpectMatch                             */
} BPD_SELFTEST_CASE;

NTSTATUS
NxcBpdEflagsSelfTest(
	_Out_ UINT32* OutRun,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirstFailure
	)
{
	CONST UINT64 Rip = 0xFFFFF80312345678ull;   /* a kernel code address, the anchor */

	/*
	 * ⚠ THE TAIL SITS AT 0x168 IN EVERY POSITIVE FIXTURE, AND THAT IS NOT A CLAIM ABOUT WINDOWS.
	 * The matcher is not told where to look -- it sweeps 0x40..0x188 -- so the fixture offset only
	 * has to be inside the window. It is set to the offset this build actually uses so that a
	 * REGRESSION in the sweep bounds shows up as a failure here rather than as silence on hardware.
	 */
	CONST BPD_SELFTEST_CASE Cases[] =
	{
		/* 1. The case that matters: a DECOY RIP earlier in the frame, with garbage after it. A
		 *    matcher that stops at the first RIP-shaped qword returns 0x88 and is WRONG. */
		{ "decoy RIP earlier in frame", 0x168, Rip, 0x78,
		  0x0010, 0x0246, 0xFFFFF80300001000ull, 0x0018, TRUE, 0x178 },

		/* 2. Ordinary kernel-mode frame. */
		{ "kernel frame", 0x168, 0, 0,
		  0x0010, 0x0246, 0xFFFFF80300001000ull, 0x0018, TRUE, 0x178 },

		/* 3. Ordinary user-mode frame -- CS/SS ring 3, RSP below the canonical split. */
		{ "user frame", 0x168, 0, 0,
		  0x0033, 0x0246, 0x000000000012F000ull, 0x002B, TRUE, 0x178 },

		/* 4. CS says ring 0, SS says ring 3. The CPU never pushes that pair. MUST REJECT. */
		{ "CS/SS ring mismatch", 0x168, 0, 0,
		  0x0010, 0x0246, 0xFFFFF80300001000ull, 0x002B, FALSE, 0 },

		/* 5. EFLAGS bit 1 clear -- architecturally impossible. MUST REJECT. */
		{ "EFLAGS bit 1 clear", 0x168, 0, 0,
		  0x0010, 0x0244, 0xFFFFF80300001000ull, 0x0018, FALSE, 0 },

		/* 6. EFLAGS bit 15 set -- architecturally impossible. MUST REJECT. */
		{ "EFLAGS bit 15 set", 0x168, 0, 0,
		  0x0010, 0x8246, 0xFFFFF80300001000ull, 0x0018, FALSE, 0 },

		/* 7. Kernel CS with a USER stack pointer. MUST REJECT. */
		{ "kernel CS, user RSP", 0x168, 0, 0,
		  0x0010, 0x0246, 0x000000000012F000ull, 0x0018, FALSE, 0 },

		/* 8. A selector with the LDT bit set -- not something the trap path pushes. MUST REJECT. */
		{ "LDT selector", 0x168, 0, 0,
		  0x0014, 0x0246, 0xFFFFF80300001000ull, 0x001C, FALSE, 0 },

		/* 9. No tail at all: the RIP appears nowhere. MUST REJECT. */
		{ "RIP absent", 0, 0, 0, 0, 0, 0, 0, FALSE, 0 },
	};

	CONST UINT32 Count = (UINT32)(sizeof(Cases) / sizeof(Cases[0]));
	UINT32 Failed = 0, First = 0xFFFFFFFFu;

	*OutRun = 0;
	*OutFailed = 0;
	*OutFirstFailure = 0xFFFFFFFFu;

	for (UINT32 i = 0; i < Count; i++)
	{
		/*
		 * ⚠ SIZED FROM THE SWEEP, NOT FROM KTRAP_FRAME. The matcher's last candidate is R = 0x188 and
		 * it reads five fields from there, so the final byte touched is 0x188 + 0x27 = 0x1AF. A
		 * 0x1A0-byte buffer -- the size of a real KTRAP_FRAME, which is the obvious choice -- is 16
		 * bytes short, and with page containment disabled for the fixtures nothing would stop the
		 * overread. It would not have crashed either; it would have read uninitialised stack and made
		 * the suite intermittent, which is worse than a failure.
		 */
		UINT64 Frame[0x200 / 8];
		RtlZeroMemory(Frame, sizeof(Frame));

		CONST BPD_SELFTEST_CASE* CONST C = &Cases[i];

		if (C->Decoy != 0)
			Frame[C->DecoyAt / 8] = C->Decoy;

		if (C->TailAt != 0)
		{
			Frame[(C->TailAt / 8) + BPD_ST_RIP] = Rip;
			Frame[(C->TailAt / 8) + BPD_ST_CS ] = C->Cs;
			Frame[(C->TailAt / 8) + BPD_ST_EFL] = C->Efl;
			Frame[(C->TailAt / 8) + BPD_ST_RSP] = C->Rsp;
			Frame[(C->TailAt / 8) + BPD_ST_SS ] = C->Ss;
		}

		UINT32 Got = 0;
		CONST BOOLEAN Matched =
			BpdMatchIretTail((UINT64)(ULONG_PTR)Frame, Rip, FALSE, &Got, NULL);

		BOOLEAN Ok;
		if (C->ExpectMatch)
			Ok = (Matched && Got == C->ExpectOffset);
		else
			Ok = !Matched;

		if (!Ok)
		{
			BpdLog("bpd selftest: case %u \"%s\" FAILED -- expected %s (0x%X), got %s (0x%X)\n",
			       i, C->Name,
			       C->ExpectMatch ? "a match" : "NO match",
			       C->ExpectMatch ? C->ExpectOffset : 0u,
			       Matched ? "a match" : "no match",
			       Got);
			Failed++;
			if (First == 0xFFFFFFFFu)
				First = i;
		}

		(*OutRun)++;
	}

	*OutFailed = Failed;
	*OutFirstFailure = First;

	if (Failed != 0)
	{
		BpdLog("bpd selftest: %u of %u cases FAILED -- the IRET-tail matcher is not sound, "
		       "and the derived offset must not be used.\n", Failed, Count);
		return STATUS_UNSUCCESSFUL;
	}

	BpdLog("bpd selftest: %u/%u OK -- the matcher accepts real tails and rejects a decoy RIP, "
	       "ring mismatches, impossible EFLAGS and mismatched stacks.\n", Count, Count);
	return STATUS_SUCCESS;
}

UINT64
NxcBpdOnException(
	_In_ UINT64 ExceptionRecordVa,
	_In_ UINT64 ReturnAddress,
	_In_ UINT64 TrapFrameVa,
	_In_ UINT64 ExceptionFrameVa
	)
{
	/*
	 * ⚠ ZERO UNLESS PROVEN OTHERWISE. Non-zero makes the thunk RETURN TO THE TARGET'S CALLER, so the
	 * dispatcher never runs and the exception is swallowed. Declared here and returned at EVERY exit
	 * so that swallowing is something this function must actively decide, never something it can
	 * fall into.
	 */
	UINT64 Claim = 0;
	InterlockedIncrement64(&gObsSeen);

	/*
	 * ⚠ WHO CALLED US -- the datum that turns "wrong again" into a NAME. Two hardware runs each
	 * established only that a candidate was NOT the function we wanted; argument VALUES say what a
	 * parameter is, while the return address says WHERE WE ARE, and an ntoskrnl RVA maps to its
	 * containing function offline with `tools/ntos_callgraph.py`.
	 *
	 * Distinct values only, capped, and recorded WITHOUT A LOCK: this runs on the trap path, so the
	 * collection is a bounded linear scan over at most eight qwords. A duplicate slipping in under a
	 * race would cost one wasted slot and nothing else, which is the right trade against taking a
	 * lock here.
	 */
	if (ReturnAddress != 0)
	{
		UINT32 Seen = 0;
		CONST LONG Count = gObsCallerCount;
		for (LONG i = 0; i < Count && i < (LONG)NXC_BPD_MAX_CALLERS; i++)
		{
			if (gObsCallers[i] == ReturnAddress) { Seen = 1; break; }
		}
		if (!Seen && Count < (LONG)NXC_BPD_MAX_CALLERS)
		{
			CONST LONG Slot = InterlockedIncrement(&gObsCallerCount) - 1;
			if (Slot >= 0 && Slot < (LONG)NXC_BPD_MAX_CALLERS)
				gObsCallers[Slot] = ReturnAddress;
		}
	}

	/*
	 * ⚠⚠ measured: THIS REFUSED **5894 OF 5894** -- arg1 is NEVER a kernel pointer at
	 * RVA 0x6C0100. The function there is on the common trap path, as D16/D17's three-vector
	 * intersection showed, but it is **NOT `KiDispatchException`** and its first argument is not an
	 * `EXCEPTION_RECORD`. D17 said so and was under-weighted: *"IT IS STILL NOT A PICK (D6)."* The
	 * shape heuristic -- 1281 bytes, 40 calls -- picked wrong, and 5894 hits in a short window is far
	 * more traffic than genuine dispatched exceptions, which corroborates it.
	 *
	 * ⚠ THE REFUSAL IS WHY THAT COST NOTHING. 5894 dereferences of a non-pointer, inside exception
	 * dispatch, at arbitrary IRQL, would not have been a crash -- it would have been a machine that
	 * stopped responding. Counting instead of trusting is what turned a wrong identification into a
	 * clean measurement.
	 *
	 * `MmIsAddressValid` is still not usable here (documented <= DISPATCH; this can be entered above
	 * it), so the test remains a compare, which cannot itself fault.
	 */
	if (ExceptionRecordVa < 0xFFFF800000000000ULL)
	{
		InterlockedIncrement64(&gObsRejected);

		/*
		 * ⚠ AND NOW IT IDENTIFIES RATHER THAN ONLY REFUSING. Knowing "arg1 is not a kernel pointer"
		 * cost a boot cycle and told us only that we were wrong. Bucketing it says WHAT we hooked:
		 * a small integer means a count or an index, a user VA means a usermode pointer, zero means
		 * an unused parameter. That is the difference between the next run confirming a candidate
		 * and merely rejecting one.
		 */
		if (ExceptionRecordVa == 0)
			InterlockedIncrement64(&gObsArgZero);
		else if (ExceptionRecordVa < 0x10000ULL)
			InterlockedIncrement64(&gObsArgSmall);
		else
			InterlockedIncrement64(&gObsArgUser);
		return Claim;
	}

	/*
	 * ⚠ A KERNEL POINTER IS NOT YET AN EXCEPTION_RECORD, and after 5894/5894 that distinction has
	 * been paid for. A real record's ExceptionCode is an NTSTATUS with the top two bits meaningful --
	 * warnings are 0x8xxxxxxx and errors 0xCxxxxxxx -- so a first dword outside that shape says the
	 * pointer is kernel memory that is something else entirely. Counted separately, so a candidate
	 * function is CONFIRMED by the data rather than assumed from its shape.
	 */

	/*
	 * ⚠ ONE LOAD, AND ONLY THE FIRST QWORD'S LOW HALF. `EXCEPTION_RECORD.ExceptionCode` is at offset
	 * 0 and has been since NT -- a public structure, so this pins nothing and cannot drift. Nothing
	 * past it is touched, because nothing past it is needed to answer the only question this stage
	 * asks: how much #DB traffic is there really?
	 */
	CONST UINT32 Code = *(volatile UINT32*)(ULONG_PTR)ExceptionRecordVa;

	/*
	 * Does it even look like an NTSTATUS? This is the test that CONFIRMS the function.
	 *
	 * ⚠⚠ THE SEVERITY TEST ALONE MISCLASSIFIED THE MACHINE'S MOST COMMON EXCEPTION. Measured
	 * on the real dispatcher: 2526 of 2539 hits carried `0x10000004`, which has neither
	 * top bit set, so `(Code & 0xC0000000)` filed every one of them under "kernel pointer,
	 * something else" -- i.e. as evidence AGAINST the identification.
	 *
	 * They are `KI_EXCEPTION_ACCESS_VIOLATION`. The kernel has an INTERNAL exception-code family
	 * `KI_EXCEPTION_INTERNAL = 0x10000000` (WRK ki.h / ReactOS): |0x01 GP_FAULT, |0x02 INVALID_OP,
	 * |0x03 INTEGER_DIVIDE_BY_ZERO, |0x04 ACCESS_VIOLATION. They are severity 0 by construction and
	 * are translated to the public 0xC00000xx codes before anything outside the kernel sees them --
	 * so a severity test is exactly the wrong instrument for kernel-side exception dispatch.
	 *
	 * Confirmed by the sampler, not by inference: record+0x10 held a real ntoskrnl code address for
	 * BOTH families, so arg1 is a genuine EXCEPTION_RECORD on both call paths.
	 */
	CONST BOOLEAN IsPublicStatus   = ((Code & 0xC0000000u) != 0);
	CONST BOOLEAN IsKiInternalCode = ((Code & 0xFFFFFF00u) == 0x10000000u);

	if (IsPublicStatus || IsKiInternalCode)
		InterlockedIncrement64(&gObsLooksLikeRecord);
	else
		InterlockedIncrement64(&gObsNotARecord);

	/*
	 * ⚠⚠ DERIVE KTRAP_FRAME.EFlags FROM THIS FRAME. Runs on EVERY exception, not just #DB, and that
	 * is the point: #DB has been 0 of 2539 observed exceptions on this machine, so deriving only
	 * there would mean the FIRST execute breakpoint runs against an offset nothing had ever
	 * confirmed. On the general path the machine's own ~2500 exceptions a minute prove it thousands
	 * of times over before anything is armed.
	 *
	 * ⚠ THE ANCHOR COMES FROM OUTSIDE THE FRAME. EXCEPTION_RECORD.ExceptionAddress is the faulting
	 * RIP, supplied by the dispatcher in a DIFFERENT argument. Matching it against a qword inside the
	 * trap frame is therefore a real correspondence between two independent sources -- unlike
	 * "the value here looks like EFLAGS", which any 1-in-16 word satisfies.
	 *
	 * ⚠ NO MmIsAddressValid, SAME-PAGE CONTAINMENT ONLY -- identical reasoning to the record reads
	 * above: that API is documented for IRQL <= DISPATCH and exceptions dispatch above it. Every read
	 * here is proven to stay inside the single 4 KB page containing the pointer ntoskrnl handed us,
	 * so if that page is mapped the whole read is mapped.
	 */
	if (TrapFrameVa >= 0xFFFF800000000000ull)
	{
		CONST UINT64 AddrAt = ExceptionRecordVa + 0x10ull;
		if (((AddrAt ^ (AddrAt + 7ull)) & ~0xFFFull) == 0 &&
		    ((AddrAt ^ ExceptionRecordVa) & ~0xFFFull) == 0)
		{
			CONST UINT64 FaultRip = *(volatile UINT64*)(ULONG_PTR)AddrAt;
			if (FaultRip != 0)
				BpdDeriveEflags(TrapFrameVa, FaultRip);
		}
	}

	/*
	 * ⚠⚠ RECORD THE ACTUAL CODES. First live run on the dispatcher  saw 104 exceptions
	 * of which 98 landed in "kernel ptr, something else" -- meaning their first dword had neither
	 * top bit set, i.e. severity 0. A bucket count cannot say WHICH values those were, so it cannot
	 * distinguish the possibilities that matter:
	 *
	 *     - arg1 is an EXCEPTION_RECORD and these are genuinely low-severity codes;
	 *     - arg1 is NOT the record on one of the two observed call paths (there are two callers:
	 *       KiExceptionDispatch+0x145 and the 26-byte sub_6AC360+0x12);
	 *     - the read is returning something stale or zero.
	 *
	 * "98 were something else" is a number without a finding attached. A histogram of the distinct
	 * values, with counts, turns it into one -- and per D6 it reports the codes as EVIDENCE and
	 * draws no conclusion here.
	 *
	 * Fixed-size, no allocation, no lock: this runs on the target's thread at the target's IRQL on
	 * the path of EVERY exception in the system. A linear scan of 16 entries is affordable there;
	 * anything that can block or allocate is not. Ties are broken by "first seen wins", and
	 * gObsCodeOverflow counts what did not fit so a full table never masquerades as a complete one.
	 */
	{
		LONG Count = gObsCodeCount;
		if (Count > (LONG)NXC_BPD_MAX_CODES)
			Count = (LONG)NXC_BPD_MAX_CODES;

		BOOLEAN Found = FALSE;
		for (LONG i = 0; i < Count; i++)
		{
			if (gObsCodes[i] == Code)
			{
				InterlockedIncrement64(&gObsCodeHits[i]);
				Found = TRUE;
				break;
			}
		}

		if (!Found)
		{
			CONST LONG Slot = InterlockedIncrement(&gObsCodeCount) - 1;
			if (Slot >= 0 && Slot < (LONG)NXC_BPD_MAX_CODES)
			{
				gObsCodes[Slot] = Code;
				InterlockedIncrement64(&gObsCodeHits[Slot]);

				/*
				 * ⚠⚠ SAMPLE ONCE PER DISTINCT CODE -- this is what turns the histogram from a
				 * tally into an identification, and it costs nothing on the hot path because it
				 * only runs the first time a value is seen.
				 *
				 * Two samples, chosen because between them they answer the actual question. The
				 * first live run showed exactly two codes: 0x80000003 (STATUS_BREAKPOINT, x8 --
				 * matching the int3 count exactly) and 0x10000004 (x22). There are also exactly
				 * two callers. The obvious story is "one caller per code", and it is UNPROVEN --
				 * nothing recorded so far ties a code to a caller.
				 *
				 *   ReturnAddress -- WHICH call path produced this code. Settles the pairing.
				 *   +0x10         -- EXCEPTION_RECORD.ExceptionAddress. If arg1 really is a
				 *                    record, this is a code address; if it is some other
				 *                    structure, it will not be. That distinguishes "an unusual
				 *                    but real ExceptionCode" from "arg1 is not a record here",
				 *                    which is the fork the bucket counters cannot resolve.
				 *
				 * ⚠⚠ NO `MmIsAddressValid` HERE -- IT IS ILLEGAL ON THIS PATH. It is documented
				 * for IRQL <= DISPATCH and an exception can be dispatched ABOVE it, exactly as the
				 * note 100 lines up already says about arg1 itself. The first draft of this sampler
				 * called it twice and the no-imports build gate caught it, which is the only reason
				 * an illegal call did not ship onto the system's exception path.
				 *
				 * So the guard stays a COMPARE, which cannot itself fault: arg1 is already known
				 * canonical-kernel from the check above, and the read is 16 bytes into the same
				 * structure. Requiring the last byte to remain in the same 4 KB PAGE means no page
				 * boundary is crossed, so if arg1 is mapped the whole read is mapped.
				 */
				gObsCodeRa[Slot] = ReturnAddress;
				CONST UINT64 AddrField = ExceptionRecordVa + 0x10ull;
				if (((AddrField ^ (AddrField + 7ull)) & ~0xFFFull) == 0 &&
				    ((AddrField ^ ExceptionRecordVa) & ~0xFFFull) == 0)
					gObsCodeAddr[Slot] = *(volatile UINT64*)(ULONG_PTR)AddrField;
			}
			else
			{
				/* Table full. Counted, never silently dropped -- a truncated histogram that
				 * does not say it is truncated is a confident partial answer. */
				InterlockedIncrement64(&gObsCodeOverflow);
			}
		}
	}

	if (Code == NXC_STATUS_SINGLE_STEP)
	{
		InterlockedIncrement64(&gObsDebugTraps);

		/*
		 * ============================================================================
		 * ⚠⚠ THE CLAIM PATH, STAGE 1: DECIDE, COUNT, CLAIM NOTHING.
		 * ============================================================================
		 *
		 * Global debug registers are the only architecture available to us -- measured
		 * PsGetContextThread refuses this caller for EVERY ContextFlags, so
		 * per-thread CONTEXT is out (D54). A global DR fires in EVERY process, so the
		 * observer must be able to tell OUR breakpoint from everyone else's and swallow
		 * only ours.
		 *
		 * A FALSE POSITIVE HERE SUPPRESSES A REAL EXCEPTION IN AN UNRELATED PROCESS.
		 * With ~2500 exceptions a minute through this hook, "mostly right" is a machine
		 * that breaks in ways nobody can trace back to here. So the classifier runs on
		 * live traffic FIRST and only counts what it WOULD have claimed.
		 *
		 * THE POSITIVE CONTROL IS EXACT: with no breakpoint armed, gBpdWouldClaim must
		 * be ZERO. Not "low" -- zero. Any other number is a false positive, measured
		 * before it could do harm, and the claim must not be enabled until it is 0.
		 *
		 * Cost is nil in the normal case: this whole block is behind a #DB test, and #DB
		 * has been 0 of 2539 observed exceptions on this machine.
		 */
		CONST UINT64 Dr6 = __readdr(6);

		/*
		 * ⚠ RAW CR3, NOT MASKED. NxcBpdClassify's contract is explicit: the caller passes
		 * it RAW and the PCID masking happens THERE, in one place, "so a caller that
		 * forgets cannot produce a verdict that is wrong in the direction of claiming."
		 * The first draft here masked it anyway and carried a comment explaining why --
		 * harmless only because masking is idempotent, but it is exactly the shape where
		 * a second copy of a rule drifts from the first. One rule, one place.
		 */
		CONST UINT64 FaultCr3 = __readcr3();

		UINT32 Why = 0, Slot = 0;
		CONST UINT32 Verdict =
			NxcBpdClassify(1u /* #DB */, Dr6, FaultCr3, NxcBpSlotTable(), &Why, &Slot);

		InterlockedIncrement64(&gBpdClassified);
		if (Verdict == NXC_BPD_CLAIM)
		{
			if (Why == NXC_BPD_WHY_GLOBAL_FOREIGN)
				InterlockedIncrement64(&gBpdForeignSuppressed);
			else
				InterlockedIncrement64(&gBpdWouldClaim);
			gBpdLastSlot = Slot;
			/* ⚠ WRITTEN ON THIS PATH TOO. It used to be set only on pass-through, so after a
			 * CLAIM the display showed the initial 0 -- which is WHY_NOT_DB, "the vector was not
			 * 1", a direct contradiction of having just claimed a #DB. An unset field rendered as
			 * a meaningful one. */
			gBpdLastWhy = Why;

			/*
			 * ⚠⚠ BRANCH STEP (D119): ITS OWN PATH, DELIBERATELY NOT THREADED THROUGH THE GATES BELOW.
			 *
			 * Those gates exist to decide whether a SLOT can be resumed past -- execute versus data,
			 * EFLAGS.RF, slot index in range. A BTF trap has no slot and needs no RF: BS is a TRAP,
			 * reported after the branch has already retired, so RIP is past it and resuming needs
			 * nothing. Routing it through gates written for a different question would mean either
			 * loosening them or indexing Slots[NXC_BPD_MAX_SLOTS].
			 *
			 * ⚠⚠ IT DOES **NOT** RESPECT gBpdClaimEnabled, AND THAT IS DELIBERATE.
			 * It used to, and the two sentences below this one said why that was wrong while the code
			 * did it anyway: passing a BTF trap through delivers STATUS_SINGLE_STEP and kills the
			 * target. NxcBtfDisarm's own drain comment has the measured proof --
			 * `run 3 : passthru delta 1  alive=FALSE  why=3 NO_SLOT  <-- died`. So `bp claim off`
			 * while branch stepping was armed killed the target at the next branch, and a BTF target
			 * takes ~2.3 MILLION traps a second, so "the next branch" is immediate.
			 *
			 * OWNERSHIP IS ALREADY ESTABLISHED before this line: NxcBtfIsTarget matched this CR3, and
			 * BpdJudge ALREADY returned NXC_BPD_CLAIM on the strength of it. The claim switch governs
			 * whether we START intercepting, never whether we clean up after silicon WE programmed --
			 * the same rule the execute branch below is unconditional for.
			 *
			 * ⚠ AND IT MUST CLAIM. Passing a BTF trap through delivers STATUS_SINGLE_STEP to the
			 * target and kills it -- and we are the reason the trap exists at all.
			 */
			if (Why == NXC_BPD_WHY_MATCH_BTF)
			{
				/*
				 * The branch TARGET is the faulting RIP -- BS is raised after the branch, so the
				 * saved RIP is where control landed. Recovered from the IRET tail through the
				 * PROVEN EFlags offset, the same way BpdRecordHit locates it, and the record is
				 * taken with a zero RIP rather than skipped if that gate is not satisfied: a
				 * branch we saw and could not place is still a branch we saw.
				 */
				UINT64  BranchRip   = 0;
				BOOLEAN TfRestored  = FALSE;
				UINT32  EfOff       = 0;
				if (NxcBpdEflagsProven(&EfOff) && EfOff >= 0x10u &&
				    TrapFrameVa >= 0xFFFF800000000000ull)
				{
					CONST UINT64 Tail = TrapFrameVa + (EfOff - 0x10u);
					if (((Tail ^ (Tail + 0x27ull)) & ~0xFFFull) == 0 &&
					    ((Tail ^ TrapFrameVa) & ~0xFFFull) == 0)
					{
						BranchRip = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x00ull);

						/*
						 * ⚠⚠ RE-SET EFLAGS.TF, AND THIS WAS NOT IN THE DESIGN -- HARDWARE SAID SO.
						 *
						 * D119 reasoned that only DEBUGCTL.BTF needed re-arming, because the SDM
						 * says the processor clears BTF on a #DB and says nothing about clearing
						 * TF. That is true of the PROCESSOR and false of the SYSTEM: measured
						 * on the first hardware run, a 1-second window recorded
						 * EXACTLY ONE branch and the target's own thread context then reported
						 * TF CLEAR. Windows' debug-trap path clears TF in the frame before
						 * dispatching, and we SWALLOW the exception, so nothing re-sets it.
						 *
						 * Reading could not have found this. It is the reason the testing rule
						 * says a feature that compiles is not a feature.
						 *
						 * ⚠ SAME GATE AS THE RF WRITE, and re-validated on THIS frame rather than
						 * trusting that the offset was proven against OTHER frames: bit 1 is
						 * always set in EFLAGS, and bits 3, 5 and 15 are always clear. A value
						 * that is not EFLAGS-shaped means this frame is not laid out like the
						 * ones that proved the offset, and the write is abandoned.
						 */
						/*
						 * ⚠⚠ RING 3 ONLY, AND LEAVING THIS OUT KILLED THE TARGET. measured.
						 *
						 * The first version re-set TF on any frame whose EFLAGS looked right. A
						 * #DB can be taken on a RING-0 frame -- `bp dispatch status` reports 13
						 * such frames kept by the EFlags derivation -- and writing TF there makes
						 * the KERNEL single-step on the IRET. Those kernel steps then arrive in
						 * states this classifier does not recognise, and a #DB we do not claim is
						 * delivered to the target as STATUS_SINGLE_STEP, which KILLS it.
						 *
						 * On a busy target: 4052 #DB classified, 4050 matched, and just
						 * **2 passed through** -- and those 2 were enough. The process died within
						 * ~100 ms every time. Two traps out of four thousand, so this would have
						 * looked like a rare flake rather than a mechanism.
						 *
						 * CS is at tail+0x08 by the architectural IRET shape -- the same shape that
						 * proved the EFlags offset, so it costs nothing extra to check. RPL 3 means
						 * the interrupted code was usermode, which is the only code BTF is meant
						 * to be stepping: the target's own ring-3 branches.
						 */
						CONST UINT64 Cs = *(volatile UINT64*)(ULONG_PTR)(Tail + 0x08ull);
						volatile UINT32* CONST Ef = (volatile UINT32*)(ULONG_PTR)(Tail + 0x10ull);
						CONST UINT32 Before = *Ef;

						if ((Cs & 3ull) != 3ull)
						{
							/*
							 * ⚠ A RING-0 FRAME IS NOT A STEPPING FRAME, so there is nothing to
							 * restore and this is NOT a TF failure. Counting it as one would make
							 * the "TF could not be re-set" number fire on the healthy path, which
							 * is the same defect as an all-clear that means nothing was examined --
							 * in reverse. The ring-3 frame's own TF is untouched and stepping
							 * continues when the thread returns to usermode.
							 */
							TfRestored = TRUE;
						}
						else if ((Before & 0x2u) != 0 && (Before & 0x8u) == 0 &&
						         (Before & 0x20u) == 0 && (Before & 0x8000u) == 0)
						{
							/*
							 * ⚠⚠ DRAINING INVERTS THIS WRITE, AND THAT IS HOW STEPPING STOPS.
							 *
							 * Clearing TF is what ends branch stepping, and usermode CANNOT DO IT
							 * under load: with the target taking ~2.3 million traps a second,
							 * SuspendThread and Thread32Next come back with nothing, because
							 * nothing in that process gets scheduled long enough to be caught.
							 * measured -- roughly one run in four then died, because
							 * TF stayed set after the kernel stopped claiming.
							 *
							 * The trap is the ONE thing that reliably reaches that thread. So
							 * while draining we still claim, and clear TF here instead of setting
							 * it. A thread cannot escape: to escape it would have to execute, and
							 * executing is what traps.
							 */
							*Ef = NxcBtfDraining() ? (Before & ~0x100u) : (Before | 0x100u);
							TfRestored = TRUE;
						}
					}
				}

				/*
				 * ⚠ THE COUNT OF FAILED RE-SETS IS CARRIED, NOT DISCARDED. Without TF the trace
				 * stops dead after one branch -- which looks exactly like a target that stopped
				 * branching. The two must not be indistinguishable.
				 */
				NxcBtfOnTrap(BranchRip, TfRestored);

				/* Our condition only -- another agent's bits in this register are not ours. */
				__writedr(6, Dr6 & ~NXC_DR6_BS);
				InterlockedIncrement64(&gBpdClaimed);
				Claim = 1;
			}
			else
			{

			/*
			 * ============================================================================
			 * ⚠⚠ STAGE 2: ACTUALLY SWALLOW IT. FOUR INDEPENDENT GATES, ALL REQUIRED.
			 * ============================================================================
			 *
			 * 1. the classifier matched an ARMED slot whose CR3 is the target's (above);
			 * 2. claiming is EXPLICITLY ENABLED -- default off, so a build that merely
			 *    contains this code changes nothing until asked;
			 * 3. the slot is a DATA breakpoint. An EXECUTE breakpoint traps BEFORE the
			 *    instruction retires, so resuming without EFLAGS.RF re-enters it forever;
			 *    setting RF means writing an unexported KTRAP_FRAME, which this project
			 *    does not pin. Refused, not "handled";
			 * 4. the slot index is in range -- a bad index here indexes the slot table on
			 *    the exception path.
			 *
			 * ⚠ DR6 IS CLEARED BECAUSE WE ARE TAKING WINDOWS' JOB. Its handler normally
			 * clears the status bits; we are preventing that handler from running, so a
			 * stale B0-B3 would make the NEXT #DB look like this one fired again. The
			 * write is our own bit only -- another agent's condition in the same register
			 * is not ours to erase.
			 */
			CONST NXC_BPD_SLOT* CONST Slots = NxcBpSlotTable();

			/*
			 * ⚠⚠ GATE 3 SPLIT IN TWO ON, BECAUSE EXECUTE IS NO LONGER UNCONDITIONALLY
			 * REFUSED -- it is refused UNLESS the trap frame's EFLAGS offset has been PROVEN.
			 *
			 * A data breakpoint traps AFTER the access, so RIP already points past it and resuming
			 * needs nothing. An EXECUTE breakpoint traps BEFORE the instruction retires, so returning
			 * without setting EFLAGS.RF re-enters the same instruction and traps again, forever.
			 *
			 * RF suppresses exactly one instruction-breakpoint match on the next resume and the CPU
			 * clears it itself, which is precisely the semantics wanted here.
			 *
			 * ⚠ THE OFFSET IS NEVER ASSUMED. NxcBpdEflagsProven fails closed: it needs a candidate
			 * derived from live frames, 32 of them agreeing, and ZERO disagreements ever. Deriving it
			 * by decoding ntoskrnl gave 0xF8 -- KTRAP_FRAME.Dr6 -- because that displacement is
			 * relative to a biased rbp, and writing RF there would corrupt the saved debug status of
			 * whatever thread trapped. See BpdMatchIretTail.
			 */
			BOOLEAN MayClaim = FALSE;
			UINT32  RfOffset = 0;

			/*
			 * ============================================================================
			 * ⚠⚠⚠ AN EXECUTE HIT IS **ALWAYS** CLAIMED. NEVER PASSED THROUGH. EVER.
			 * ============================================================================
			 *
			 * THIS BRANCH IS FIRST AND UNCONDITIONAL BECAUSE THE PREVIOUS SHAPE KILLED
			 * APPLICATIONS TWICE ON.
			 *
			 * The structure was `if (claimEnabled && slotOk) { if (data) ... else if (proven &&
			 * frameOk) { ...escape on failure... } }`. Every escape sat INSIDE the inner block, so
			 * ANY of these skipped them entirely and left MayClaim FALSE:
			 *
			 *     claiming disabled          -- e.g. `bp claim off` while a slot is still armed
			 *     the EFlags offset unproven -- poisoned, or not yet 32 frames
			 *     TrapFrameVa not canonical  -- an unexpected call path into the dispatcher
			 *
			 * and FALSE means the #DB reaches KiDispatchException, which delivers
			 * STATUS_SINGLE_STEP to a process that never asked for a breakpoint. It dies looking
			 * like its own crash. I patched two inner leaves and left the trunk, then said it was
			 * fixed; the second batch of dead applications is what that cost.
			 *
			 * ⚠ THE INVARIANT, STATED ONCE AND ENFORCED STRUCTURALLY: if WE set DR7 for this slot
			 * and it is an EXECUTE breakpoint, WE own the trap. There is no condition under which
			 * handing it to Windows is correct, because Windows will kill a process for a
			 * breakpoint it did not set. Resume it if we can, ESCAPE it if we cannot -- and escape
			 * means swallow plus disarm this core, so the target neither dies nor spins.
			 *
			 * ⚠ AND IT DELIBERATELY IGNORES gBpdClaimEnabled. That flag governs whether we START
			 * intercepting; it cannot govern whether we finish cleaning up after a register we
			 * already wrote. Turning claiming off with an execute slot armed used to be lethal.
			 */
			if (Slot < NXC_BPD_MAX_SLOTS && Slots[Slot].Type == 0u)
			{
				BOOLEAN Resumed = FALSE;

				if (NxcBpdEflagsProven(&RfOffset) &&
				    TrapFrameVa >= 0xFFFF800000000000ull)
				{
					/*
					 * ⚠ CONTAINMENT IS CHECKED AGAINST THE BYTES WE ARE ABOUT TO WRITE. Same
					 * reasoning as every other read on this path -- MmIsAddressValid is illegal above
					 * DISPATCH -- but this one MODIFIES memory, so a failed check must abandon the
					 * claim rather than continue without the write. Claiming without setting RF is
					 * the infinite trap loop this gate exists to prevent.
					 */
					CONST UINT64 At = TrapFrameVa + RfOffset;
					if (((At ^ (At + 3ull)) & ~0xFFFull) == 0 &&
					    ((At ^ TrapFrameVa) & ~0xFFFull) == 0)
					{
						volatile UINT32* CONST Eflags = (volatile UINT32*)(ULONG_PTR)At;
						CONST UINT32 Before = *Eflags;

						/*
						 * ⚠ RE-VALIDATE THE SHAPE AT THE MOMENT OF WRITING, not only when the offset
						 * was derived. The offset was proven against OTHER frames; this is THIS
						 * frame. A value here that is not EFLAGS-shaped means this frame is not laid
						 * out like the ones that proved it, and the write is abandoned.
						 */
						/*
						 * ⚠ THE DIAGNOSTIC SUPPRESSION SITS HERE, at the LAST gate, so a forced
						 * failure exercises the escape by the SAME route a real one would: every
						 * other check has already passed and only `Resumed` is left unset. Placing
						 * it earlier would test a path no real failure takes.
						 */
						BOOLEAN ForceFail = FALSE;
						for (LONG64 Cur = gBpdForceRfFail; Cur > 0; Cur = gBpdForceRfFail)
						{
							if (InterlockedCompareExchange64(&gBpdForceRfFail, Cur - 1, Cur) == Cur)
							{
								ForceFail = TRUE;
								break;
							}
						}

						if (!ForceFail &&
						    (Before & 0x2u) != 0 && (Before & 0x8u) == 0 &&
						    (Before & 0x20u) == 0 && (Before & 0x8000u) == 0)
						{
							*Eflags = Before | 0x00010000u;   /* RF */
							InterlockedIncrement64(&gBpdRfWrites);
							Resumed = TRUE;
						}
					}
				}

				/*
				 * ⚠ ONE ESCAPE, ON THE ONLY PATH THAT CAN REACH IT. Every way of failing to resume
				 * -- unproven offset, non-canonical frame, straddled page, wrong EFLAGS shape --
				 * converges here, because `Resumed` is the single thing they all fail to set. That
				 * is the structural form of the fix: the previous version had an escape per failure
				 * site and therefore missed the failures that had no site.
				 */
				if (!Resumed)
				{
					InterlockedIncrement64(&gBpdRfRefused);
					BpdEscapeUnresumable(Slot);
				}

				MayClaim = TRUE;   /* ⚠ UNCONDITIONAL. See the block comment above. */
			}
			else if (Slot < NXC_BPD_MAX_SLOTS)
			{
				/*
				 * DATA breakpoint: RIP is already past the access, so there is nothing to resume
				 * past and claiming is simply "return without dispatching".
				 *
				 * ⚠⚠ ALSO UNCONDITIONAL, AND THE COMMENT THAT USED TO DEFEND THE GATE WAS WRONG
				 *. It read: "a data hit passed through is delivered as an ordinary
				 * exception and does not kill anything." Windows reports a debug-register #DB as
				 * STATUS_SINGLE_STEP -- the SAME status as a TF step -- and this project has
				 * already MEASURED what a passed-through STATUS_SINGLE_STEP does to a target: it
				 * kills it. See the run table in NxcBtfDisarm's drain comment.
				 *
				 * The comment conflated two different questions. RESUMABILITY: data and execute
				 * genuinely differ, and only execute needs the EFLAGS.RF write -- that part was
				 * right, and it is why this branch is separate. LETHALITY: they do not differ at
				 * all, and that is the part the gate was keyed on.
				 *
				 * Ownership is the only question that matters here, and it was answered before we
				 * arrived: WE set DR7 for this slot, so the trap is ours to swallow.
				 */
				MayClaim = TRUE;
			}

			if (MayClaim)
			{
				/*
				 * ⚠ RECORDED BEFORE DR6 IS CLEARED. The record carries the raw Dr6 so a reader can
				 * re-derive which condition fired; clearing first would capture the value we just
				 * wrote rather than the one the CPU set.
				 *
				 * ⚠ AND ONLY FOR A REAL CLAIM. WHY_GLOBAL_FOREIGN reaches this block too -- our
				 * register, another process -- and suppressing that is not a sighting of the target.
				 * Recording it would put another process's RIP in the target's evidence, which is
				 * both wrong and the kind of wrong that reads as a finding.
				 */
				if (Why != NXC_BPD_WHY_GLOBAL_FOREIGN)
					BpdRecordHit(TrapFrameVa, ExceptionFrameVa, Dr6, FaultCr3, Slot, Why,
					             Slots[Slot].Address);

				__writedr(6, Dr6 & ~(1ULL << Slot));
				InterlockedIncrement64(&gBpdClaimed);
				Claim = 1;
			}
			else
			{
				/*
				 * Matched, and STILL not claimed. Since both branches above became unconditional
				 * this means exactly ONE thing: Slot >= NXC_BPD_MAX_SLOTS, i.e. the classifier
				 * named a match it could not place in the table. It no longer means "claiming was
				 * off" and no longer counts an unresumable execute breakpoint -- that case now
				 * claims and reports through BpdEscapeUnresumable instead of being passed to
				 * Windows to kill the target with.
				 */
				InterlockedIncrement64(&gBpdClaimRefused);
			}

			}   /* end of the non-BTF claim path */
		}
		else
		{
			InterlockedIncrement64(&gBpdNotOurs);
			gBpdLastWhy = Why;
		}
	}
	else if (Code == NXC_STATUS_BREAKPOINT)
		InterlockedIncrement64(&gObsBreakpoints);

	/*
	 * ⚠ NOTHING ELSE HAPPENS on the observation path -- no log write, no LBR snapshot. What this
	 * function may now do, and only through the four gates above, is SWALLOW a #DB it has matched
	 * to one of our armed data breakpoints.
	 *
	 * ⚠⚠ THE COMPILER CAUGHT THIS EXIT MISSING, AND IT WOULD HAVE BEEN THE WORST BUG OF THE DAY.
	 * C4715 "not all control paths return a value": falling off the end leaves whatever happens to
	 * be in rax, and the thunk TESTS rax to decide whether to swallow the call. A garbage value
	 * there would return early from KiDispatchException at random, on the exception path of the
	 * whole machine. Zero here is not tidiness -- it is the safe default made explicit.
	 */
	return Claim;
}

void
NxcBpdObserverCounters(
	_Out_ UINT64* OutSeen,
	_Out_ UINT64* OutDebugTraps,
	_Out_ UINT64* OutBreakpoints,
	_Out_ UINT64* OutRejected
	)
{
	*OutSeen        = (UINT64)gObsSeen;
	*OutDebugTraps  = (UINT64)gObsDebugTraps;
	*OutBreakpoints = (UINT64)gObsBreakpoints;
	*OutRejected    = (UINT64)gObsRejected;
}

void
NxcBpdCallers(
	_Out_writes_(NXC_BPD_MAX_CALLERS) UINT64* Out,
	_Out_ UINT32* OutCount
	)
{
	CONST LONG Count = gObsCallerCount;
	CONST UINT32 Use = (Count < 0) ? 0u
	                 : ((UINT32)Count > NXC_BPD_MAX_CALLERS) ? NXC_BPD_MAX_CALLERS : (UINT32)Count;

	for (UINT32 i = 0; i < NXC_BPD_MAX_CALLERS; i++)
		Out[i] = (i < Use) ? gObsCallers[i] : 0;

	*OutCount = Use;
}

void
NxcBpdArgShape(
	_Out_ UINT64* OutZero,
	_Out_ UINT64* OutSmall,
	_Out_ UINT64* OutUser,
	_Out_ UINT64* OutLooksLikeRecord,
	_Out_ UINT64* OutNotARecord
	)
{
	*OutZero            = (UINT64)gObsArgZero;
	*OutSmall           = (UINT64)gObsArgSmall;
	*OutUser            = (UINT64)gObsArgUser;
	*OutLooksLikeRecord = (UINT64)gObsLooksLikeRecord;
	*OutNotARecord      = (UINT64)gObsNotARecord;
}

void
NxcBpdCodeHistogram(
	_Out_writes_(NXC_BPD_MAX_CODES) UINT32* OutCodes,
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutHits,
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutFirstRa,
	_Out_writes_(NXC_BPD_MAX_CODES) UINT64* OutExcAddr,
	_Out_ UINT32* OutCount,
	_Out_ UINT64* OutOverflow
	)
{
	LONG Count = gObsCodeCount;
	if (Count < 0)
		Count = 0;
	if (Count > (LONG)NXC_BPD_MAX_CODES)
		Count = (LONG)NXC_BPD_MAX_CODES;

	for (LONG i = 0; i < (LONG)NXC_BPD_MAX_CODES; i++)
	{
		OutCodes[i]   = (i < Count) ? gObsCodes[i] : 0u;
		OutHits[i]    = (i < Count) ? (UINT64)gObsCodeHits[i] : 0ull;
		OutFirstRa[i] = (i < Count) ? gObsCodeRa[i] : 0ull;
		OutExcAddr[i] = (i < Count) ? gObsCodeAddr[i] : 0ull;
	}
	*OutCount    = (UINT32)Count;
	*OutOverflow = (UINT64)gObsCodeOverflow;
}

UINT32
NxcBpdClassify(
	_In_ UINT32 Vector,
	_In_ UINT64 Dr6,
	_In_ UINT64 FaultCr3,
	_In_reads_(NXC_BPD_MAX_SLOTS) CONST NXC_BPD_SLOT* Slots,
	_Out_ UINT32* OutWhy,
	_Out_ UINT32* OutSlot
	)
{
	*OutWhy  = NXC_BPD_WHY_NOT_DB;
	*OutSlot = NXC_BPD_MAX_SLOTS;

	if (Vector != 1 || Slots == NULL)
		return NXC_BPD_PASS_THROUGH;

	/*
	 * ⚠ BD FIRST, AND IT IS ALWAYS A PASS-THROUGH. Bit 13 means something executed a `mov` touching a
	 * debug register while DR7.GD was set. We never set GD -- Bp.h records why -- so a BD trap
	 * belongs to whoever did. Checked BEFORE the slot bits because DR6 is STICKY: the CPU accumulates
	 * condition bits and does not clear them, so a BD can arrive with a stale B0 still set from an
	 * earlier trap. Testing the slot bits first would claim that as ours on the strength of history.
	 */
	if (Dr6 & NXC_DR6_BD)
	{
		*OutWhy = NXC_BPD_WHY_BD;
		return NXC_BPD_PASS_THROUGH;
	}

	CONST UINT64 Fault = Cr3Frame(FaultCr3);

	/*
	 * A breakpoint slot fired. Identity is the PAIR (slot, CR3) -- never the slot alone, because
	 * debug registers are per-thread context and "B0" means different things in different threads
	 * (D22). A debugger's breakpoint in slot 0 of its own thread is also "B0".
	 */
	if (Dr6 & NXC_DR6_SLOT_MASK)
	{
		for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
		{
			if ((Dr6 & (1ULL << i)) == 0)
				continue;
			if (!Slots[i].Armed)
				continue;

			if (Cr3Frame(Slots[i].Cr3) != Fault)
			{
				/*
				 * OUR slot number, SOMEBODY ELSE'S process -- and what to do about it depends
				 * ENTIRELY on who wrote the register. These are opposite answers, and getting them
				 * the wrong way round kills processes.
				 *
				 * ⚠⚠ PER-THREAD (Global == 0): the debug registers are per-thread CONTEXT, so slot 0
				 * in another thread may belong to a debugger. This is SOMEONE ELSE'S BREAKPOINT and
				 * swallowing it would break their tooling silently. PASS IT THROUGH.
				 *
				 * ⚠⚠ GLOBAL (Global == 1): WE wrote DR0 on every core with the G bit, so EVERY B0
				 * trap on this machine is caused by OUR register. A foreign CR3 does not mean
				 * somebody else's breakpoint -- it means OUR breakpoint, hit by a process we are not
				 * watching, because a global DR matches a LINEAR ADDRESS in every address space.
				 * Passing that through delivers STATUS_SINGLE_STEP to an innocent process, which
				 * DIES for a breakpoint we set and which it never asked for.
				 *
				 * So a global slot CLAIMS the trap -- we caused it, we clean it up -- and reports
				 * GLOBAL_FOREIGN so the caller can count it as suppressed WITHOUT recording it as a
				 * sighting of the target. Suppressing is not the same as attributing.
				 *
				 * This distinction was found by reasoning about the FOREIGN_CR3 test rather than by
				 * running it: the test would have "passed" by killing unrelated processes. The
				 * classifier had inherited per-thread semantics that are correct for the
				 * architecture it was designed against and wrong for the one that actually works.
				 */
				*OutSlot = i;
				if (Slots[i].Global)
				{
					*OutWhy = NXC_BPD_WHY_GLOBAL_FOREIGN;
					return NXC_BPD_CLAIM;
				}
				*OutWhy = NXC_BPD_WHY_FOREIGN_CR3;
				return NXC_BPD_PASS_THROUGH;
			}

			*OutWhy  = NXC_BPD_WHY_MATCH_SLOT;
			*OutSlot = i;
			return NXC_BPD_CLAIM;
		}

		*OutWhy = NXC_BPD_WHY_NO_SLOT;
		return NXC_BPD_PASS_THROUGH;
	}

	/*
	 * ⚠ A SINGLE STEP IS CLAIMED ONLY WHEN WE ASKED FOR ONE, and only from the process we asked it
	 * of. `bp set` re-arms by stepping off a breakpoint, so we do generate these -- but a debugger
	 * stepping, or code setting its own EFLAGS.TF, generates them too. Claiming BS unconditionally
	 * would swallow every single-step on the machine, which would break every debugger on it.
	 */
	if (Dr6 & NXC_DR6_BS)
	{
		/*
		 * ⚠ BRANCH-STEPPING FIRST, AND IT OWNS NO SLOT (D119). BTF traps are single-steps like any
		 * other, so they arrive here -- but they are not a slot stepping off a breakpoint, they are
		 * the whole point of the arming. Tested before the slot loop because a BTF target may ALSO
		 * have a data breakpoint armed with WantStep, and matching that first would attribute a
		 * branch step to a slot and clear a DR6 bit the CPU never set.
		 *
		 * OutSlot stays NXC_BPD_MAX_SLOTS: the claim path must not index the slot table for this.
		 */
		if (NxcBtfIsTarget(Fault))
		{
			*OutWhy  = NXC_BPD_WHY_MATCH_BTF;
			*OutSlot = NXC_BPD_MAX_SLOTS;
			return NXC_BPD_CLAIM;
		}

		for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
		{
			if (!Slots[i].Armed || !Slots[i].WantStep)
				continue;
			if (Cr3Frame(Slots[i].Cr3) != Fault)
				continue;

			*OutWhy  = NXC_BPD_WHY_MATCH_STEP;
			*OutSlot = i;
			return NXC_BPD_CLAIM;
		}

		*OutWhy = NXC_BPD_WHY_NO_SLOT;
		return NXC_BPD_PASS_THROUGH;
	}

	/*
	 * ⚠⚠ BTF CATCH-ALL, AND IT IS WHAT STOPPED THE TARGET DYING. measured.
	 *
	 * With branch stepping armed, a busy target died every run. The counters said why:
	 *
	 *     #DB classified            : 3723
	 *     matched as OURS           : 3722
	 *     passed through (not ours) : 1        <-- and one is enough
	 *     last verdict              : why=1 NO_CONDITION
	 *
	 * A passed-through single-step is delivered as STATUS_SINGLE_STEP and kills the process. ONE trap
	 * in 3722 did it, which is exactly the ratio that reads as a flake rather than a mechanism.
	 *
	 * NO_CONDITION means DR6 named nothing we handle -- and DR6 is read LIVE here with __readdr(6),
	 * not taken from the frame. `bp dispatch status` reports TWO distinct callers into this
	 * dispatcher, and on one of those routes Windows' trap entry has already consumed DR6 before we
	 * see it. So DR6 is not a reliable way to recognise our own traps, and no amount of care reading
	 * it makes it one.
	 *
	 * ⚠ THE ADDRESS SPACE IS THE RELIABLE IDENTIFIER. If branch stepping is armed for this CR3 then WE
	 * are the reason EFLAGS.TF is set in it, so a #DB from it is ours by construction whatever DR6
	 * says. Claiming it costs at worst swallowing a single-step somebody else provoked in a process we
	 * have deliberately taken over; passing it through KILLS that process. Those are not comparable.
	 *
	 * ⚠ SCOPED, NOT BLANKET: only while BTF is armed, and only for the ONE address space it is armed
	 * against. Every other #DB on the machine still reaches this line and still passes through.
	 */
	if (NxcBtfIsTarget(Fault))
	{
		*OutWhy  = NXC_BPD_WHY_MATCH_BTF;
		*OutSlot = NXC_BPD_MAX_SLOTS;
		return NXC_BPD_CLAIM;
	}

	/* A #DB naming no condition we handle. BT cannot occur in IA-32e; anything else is not ours. */
	*OutWhy = NXC_BPD_WHY_NO_CONDITION;
	return NXC_BPD_PASS_THROUGH;
}

void
NxcBpdResume(
	_In_ UINT64 Eflags,
	_In_ UINT64 Dr6,
	_In_ UINT64 Consumed,
	_Out_ UINT64* OutEflags,
	_Out_ UINT64* OutDr6
	)
{
	/*
	 * RF suppresses ONE instruction-breakpoint trap and the CPU clears it for us on the next
	 * successful instruction. Without it an execute breakpoint re-fires on the same instruction
	 * forever -- a #DB storm on that core, which takes the machine, not just the target.
	 */
	*OutEflags = Eflags | NXC_EFLAGS_RF;

	/*
	 * ⚠ CLEAR ONLY WHAT WE CONSUMED. DR6 is sticky and the CPU never clears it, so leaving our bit
	 * set makes the next #DB -- from anyone -- carry a condition we already handled. Zeroing the
	 * whole register instead would destroy a condition somebody else has not handled yet, which is
	 * the swallowing failure again by a different route.
	 *
	 * Bits 11:4 read as 1 on real hardware and are left exactly as found: a field we do not own is
	 * not ours to normalise, and inventing a value is how a report starts disagreeing with `!dr`.
	 */
	*OutDr6 = Dr6 & ~Consumed;
}

/* ================================================================================================
 * THE PROOF. Synthetic inputs, PASSIVE_LEVEL, nothing patched and no hardware touched.
 * ============================================================================================= */

typedef struct _NXC_BPD_CASE
{
	CONST CHAR* Name;
	UINT32      Vector;
	UINT64      Dr6;
	UINT64      FaultCr3;
	UINT32      ArmedMask;      /* which slots are armed          */
	UINT32      StepMask;       /* which armed slots want a step  */
	UINT64      SlotCr3;        /* the CR3 every armed slot holds */
	UINT32      ExpectVerdict;
	UINT32      ExpectWhy;
} NXC_BPD_CASE;

/*
 * ⚠ TWO DIFFERENT CR3 VALUES THAT SHARE A FRAME, AND TWO THAT DIFFER ONLY IN PCID. The PCID cases
 * are the ones that matter: `OURS_PCID` has the same frame as `OURS` with a different context id, so
 * a raw comparison would REJECT a trap that is genuinely ours. That is the regression this suite
 * exists to hold, and it is a case a happy-path test would never contain.
 */
#define BPD_CR3_OURS       0x00000001AB000000ULL
#define BPD_CR3_OURS_PCID  0x00000001AB000042ULL   /* same frame, different PCID */
#define BPD_CR3_THEIRS     0x00000002CD000000ULL

static CONST NXC_BPD_CASE gCases[] =
{
	/* --- pass-through cases: every one of these is somebody else's exception --------------- */
	{ "vector 14 (#PF) is not ours",
	  14, NXC_DR6_B0, BPD_CR3_OURS, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NOT_DB },

	{ "#DB with BD set is NEVER ours (we never set GD)",
	  1, NXC_DR6_BD, BPD_CR3_OURS, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_BD },

	/* ⚠ THE STICKY-DR6 CASE. B0 is set from an earlier trap and BD is the real cause. Testing the
	 * slot bits first would claim this as ours on the strength of a stale bit. */
	{ "BD wins over a STALE slot bit (DR6 is sticky)",
	  1, NXC_DR6_BD | NXC_DR6_B0, BPD_CR3_OURS, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_BD },

	{ "a slot that is NOT armed is not ours",
	  1, NXC_DR6_B2, BPD_CR3_OURS, 0x3 /* only 0,1 armed */, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NO_SLOT },

	/* ⚠ THE ONE THAT MAKES SLOT-ALONE IDENTIFICATION WRONG: our slot number, their process. */
	{ "OUR slot number in a FOREIGN process is not ours",
	  1, NXC_DR6_B0, BPD_CR3_THEIRS, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_FOREIGN_CR3 },

	{ "a single step we did NOT ask for is not ours",
	  1, NXC_DR6_BS, BPD_CR3_OURS, 0xF, 0 /* no slot wants a step */, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NO_SLOT },

	{ "a step we asked for, in a FOREIGN process, is not ours",
	  1, NXC_DR6_BS, BPD_CR3_THEIRS, 0xF, 0xF, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NO_SLOT },

	{ "#DB naming no condition at all is not ours",
	  1, 0, BPD_CR3_OURS, 0xF, 0xF, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NO_CONDITION },

	{ "nothing armed: every #DB passes through",
	  1, NXC_DR6_B0, BPD_CR3_OURS, 0, 0, BPD_CR3_OURS,
	  NXC_BPD_PASS_THROUGH, NXC_BPD_WHY_NO_SLOT },

	/* --- claim cases ----------------------------------------------------------------------- */
	{ "armed slot 0, matching CR3 -> OURS",
	  1, NXC_DR6_B0, BPD_CR3_OURS, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_SLOT },

	{ "armed slot 3, matching CR3 -> OURS",
	  1, NXC_DR6_B3, BPD_CR3_OURS, 0x8, 0, BPD_CR3_OURS,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_SLOT },

	/* ⚠ THE PCID REGRESSION, IN BOTH DIRECTIONS. Same frame, different context id. A raw comparison
	 * rejects these, and rejecting our own trap kills the target -- the exact failure bp set exists
	 * to prevent. Two cases, because the PCID can differ on either side. */
	{ "PCID differs on the FAULTING side -> still ours",
	  1, NXC_DR6_B0, BPD_CR3_OURS_PCID, 0xF, 0, BPD_CR3_OURS,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_SLOT },

	{ "PCID differs on the STORED side -> still ours",
	  1, NXC_DR6_B0, BPD_CR3_OURS, 0xF, 0, BPD_CR3_OURS_PCID,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_SLOT },

	{ "a step we DID ask for, matching CR3 -> OURS",
	  1, NXC_DR6_BS, BPD_CR3_OURS, 0x1, 0x1, BPD_CR3_OURS,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_STEP },

	/* ⚠ BOTH a slot AND single-step set, which the CPU does produce when stepping off a breakpoint.
	 * The slot must win: it names WHICH breakpoint, and the step is how we got back to it. */
	{ "slot + BS together: the SLOT decides",
	  1, NXC_DR6_B1 | NXC_DR6_BS, BPD_CR3_OURS, 0xF, 0xF, BPD_CR3_OURS,
	  NXC_BPD_CLAIM, NXC_BPD_WHY_MATCH_SLOT },
};

NTSTATUS
NxcBpdSelfTest(
	_Out_ UINT32* OutRan,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirstBad
	)
{
	CONST UINT32 Count = (UINT32)(sizeof(gCases) / sizeof(gCases[0]));

	*OutRan      = 0;
	*OutFailed   = 0;
	*OutFirstBad = Count;

	for (UINT32 c = 0; c < Count; c++)
	{
		CONST NXC_BPD_CASE* CONST K = &gCases[c];

		NXC_BPD_SLOT Slots[NXC_BPD_MAX_SLOTS];
		RtlZeroMemory(Slots, sizeof(Slots));
		for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
		{
			Slots[i].Armed    = (K->ArmedMask >> i) & 1u;
			Slots[i].WantStep = (K->StepMask  >> i) & 1u;
			Slots[i].Cr3      = K->SlotCr3;
			Slots[i].Address  = 0x7FF000000000ULL + i;
		}

		UINT32 Why = 0xFFFFFFFFu, Slot = 0xFFFFFFFFu;
		CONST UINT32 Verdict = NxcBpdClassify(K->Vector, K->Dr6, K->FaultCr3, Slots, &Why, &Slot);

		(*OutRan)++;

		/*
		 * ⚠ THE REASON IS CHECKED, NOT ONLY THE VERDICT. A classifier that returned the right answer
		 * for the wrong reason would pass a verdict-only suite and then diverge the moment a case it
		 * was never given arrives -- which, in a handler on the system exception path, is the worst
		 * possible time to discover the reasoning was coincidental.
		 */
		if (Verdict != K->ExpectVerdict || Why != K->ExpectWhy)
		{
			if (*OutFailed == 0)
				*OutFirstBad = c;
			(*OutFailed)++;

			BpdLog("bpd: CASE %u FAILED -- %s: got verdict %u why %u, expected verdict %u why %u\n",
			       c, K->Name, Verdict, Why, K->ExpectVerdict, K->ExpectWhy);
		}
	}

	/*
	 * ---- RESUME CASES ----------------------------------------------------------------------
	 *
	 * ⚠ A WRONG ANSWER HERE HANGS THE MACHINE, NOT THE TARGET. Miss RF and an execute breakpoint
	 * re-fires on the same instruction forever, at a rate no log absorbs. Miss the DR6 clear and the
	 * next #DB from ANY source carries a stale condition we wrote.
	 *
	 * Written as a table for the same reason as the classifier: each line names the mistake it
	 * catches, so a future edit that "simplifies" one of them has to argue with a sentence.
	 */
	static CONST struct
	{
		CONST CHAR* Name;
		UINT64 Eflags, Dr6, Consumed, WantEflags, WantDr6;
	} kResume[] =
	{
		{ "RF is SET so an execute breakpoint does not re-fire forever",
		  0x00000246ULL, NXC_DR6_B0, NXC_DR6_B0,
		  0x00010246ULL, 0 },

		{ "the consumed slot bit is CLEARED (DR6 is sticky)",
		  0x00000246ULL, NXC_DR6_B1 | 0xFF0ULL, NXC_DR6_B1,
		  0x00010246ULL, 0xFF0ULL },

		/* ⚠ THE ONE THAT MATTERS MOST: another agent's condition must SURVIVE. Zeroing DR6 wholesale
		 * would swallow it, which is the claiming failure arriving by a different route. */
		{ "a condition we did NOT consume SURVIVES",
		  0x00000246ULL, NXC_DR6_B0 | NXC_DR6_B2, NXC_DR6_B0,
		  0x00010246ULL, NXC_DR6_B2 },

		/* Reserved bits 11:4 read as 1 on real hardware and are not ours to normalise. */
		{ "reserved DR6 bits 11:4 are PRESERVED, not normalised",
		  0x00000246ULL, 0x0FF0ULL | NXC_DR6_B3, NXC_DR6_B3,
		  0x00010246ULL, 0x0FF0ULL },

		/* ⚠ RF IS SET, NEVER TOGGLED. An EFLAGS that already carried it must not come back cleared. */
		{ "RF already set stays set (set, not toggled)",
		  0x00010246ULL, NXC_DR6_B0, NXC_DR6_B0,
		  0x00010246ULL, 0 },

		/* ⚠ TF IS THE TARGET'S, NOT OURS. A target single-stepping itself must keep doing so;
		 * clearing TF here would silently change the behaviour of the program under inspection. */
		{ "the target's own TF is left ALONE",
		  0x00000346ULL, NXC_DR6_BS, NXC_DR6_BS,
		  0x00010346ULL, 0 },
	};

	CONST UINT32 RCount = (UINT32)(sizeof(kResume) / sizeof(kResume[0]));
	for (UINT32 r = 0; r < RCount; r++)
	{
		UINT64 GotEflags = 0, GotDr6 = 0;
		NxcBpdResume(kResume[r].Eflags, kResume[r].Dr6, kResume[r].Consumed, &GotEflags, &GotDr6);

		(*OutRan)++;

		if (GotEflags != kResume[r].WantEflags || GotDr6 != kResume[r].WantDr6)
		{
			if (*OutFailed == 0)
				*OutFirstBad = Count + r;
			(*OutFailed)++;

			BpdLog("bpd: RESUME CASE %u FAILED -- %s: got eflags %llX dr6 %llX, "
			       "expected %llX / %llX\n",
			       r, kResume[r].Name, GotEflags, GotDr6,
			       kResume[r].WantEflags, kResume[r].WantDr6);
		}
	}

	BpdLog("bpd: selftest -- %u case(s) (%u classify, %u resume), %u failed\n",
	       *OutRan, Count, RCount, *OutFailed);
	return (*OutFailed == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

void
NxcBpdClaimEnable(
	_In_ UINT32 Enable
	)
{
	InterlockedExchange(&gBpdClaimEnabled, (LONG)(Enable ? 1 : 0));
	BpdLog(Enable ? "bp dispatch claim: ENABLED -- arming permitted; matching #DBs are SWALLOWED\n"
	              : "bp dispatch claim: disabled -- ARMING is refused. This does NOT make an "
	                "already-armed slot observer-only: traps from registers we programmed are "
	                "still claimed, because passing one through kills the target.\n");
}

BOOLEAN
NxcBpdClaimEnabled(void)
{
	/* ⚠ EXPOSED FOR THE BTF INTERLOCK (D119). Branch stepping is the one surface that MAKES a trap
	 * the target would not otherwise take, so arming it with claiming off would kill the target with
	 * a STATUS_SINGLE_STEP we caused. The refusal belongs here, where the flag is authoritative, and
	 * not in a usermode probe of a status field that means something else. */
	return (gBpdClaimEnabled != 0) ? TRUE : FALSE;
}

void
NxcBpdClaimStats(
	_Out_ UINT64* OutClassified,
	_Out_ UINT64* OutWouldClaim,
	_Out_ UINT64* OutNotOurs,
	_Out_ UINT32* OutLastWhy,
	_Out_ UINT32* OutLastSlot
	)
{
	*OutClassified = (UINT64)gBpdClassified;
	*OutWouldClaim = (UINT64)gBpdWouldClaim;
	*OutNotOurs    = (UINT64)gBpdNotOurs;
	*OutLastWhy    = gBpdLastWhy;
	*OutLastSlot   = gBpdLastSlot;
}

UINT64
NxcBpdForeignSuppressed(void)
{
	return (UINT64)gBpdForeignSuppressed;
}

void
NxcBpdClaimState(
	_Out_ UINT32* OutEnabled,
	_Out_ UINT64* OutClaimed,
	_Out_ UINT64* OutRefused
	)
{
	*OutEnabled = (UINT32)gBpdClaimEnabled;
	*OutClaimed = (UINT64)gBpdClaimed;
	*OutRefused = (UINT64)gBpdClaimRefused;
}
