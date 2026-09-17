/**
 * @file Idt.h
 * @brief The IDT as a READ-ONLY ANCHOR. Nothing here writes a gate, now or later.
 *
 * ============================================================================================
 * WHAT THIS IS FOR (build-plan item 15, decision D15)
 * ============================================================================================
 *
 * Phase 3's whole premise is trapping execution, and everything in it needs a handler on the
 * exception path. The plan called that item "idt hook <vector>" and treated intercepting the vector
 * as the hard part. It is not.
 *
 * TIER 1 (`reference material/`): Cheat Engine's `DBKKernel/interruptHook.c` rewrites the IDT gate
 *   directly -- save `wLowOffset`/`wHighOffset`/`TopOffset`, write a new one. It works, it is the
 *   classic approach, and it is the wrong one here (see below).
 *
 * TIER 2 (internet): `KiDispatchException` is on the path of every exception and calls `KdTrap`
 *   first. So a FUNCTION hook reaches the same events, and a function hook beats a gate rewrite on
 *   every axis that matters here:
 *
 *     - one patch, versus 24 per-CPU IDTs that must all agree
 *     - `hook list` / `unhook` exist; a rewritten gate has no inventory and no restore
 *     - it is not the thing PatchGuard explicitly checks
 *
 *   PatchGuard is disabled on this machine, so the last point is not what decides it. It is worth
 *   stating anyway: "safe because PatchGuard is off" is a worse position than "did not touch what
 *   PatchGuard checks", even while both work.
 *
 * TIER 3 (v1): shipped `--fork-cap`, which per the plan's own ordering note cannot have worked
 *   without a `#DB` handler of some kind. Worth reading before item 15 is finished; it does not
 *   change the choice.
 *
 * ============================================================================================
 * ⚠ AND THE ACTUAL PROBLEM, WHICH THE PLAN DID NOT LIST AT ALL
 * ============================================================================================
 *
 * MEASURED off this machine's own `ntoskrnl.exe` (`tools/ntos_exports.py`): the only matching
 * exports are `KdDebuggerEnabled`, `KdDebuggerNotPresent`, `KdEnableDebugger` and
 * `KdRefreshDebuggerNotPresent`. **`KiDispatchException` and `KdTrap` are NOT exported.**
 *
 * So the difficulty is naming the thing to hook, and this file is the answer's first half:
 *
 *     __sidt                          -> the IDT's base. A READ. Writes nothing.
 *     vector 1's gate                 -> KiDebugTrapOrFault's address, version-independent in a way
 *                                        a byte signature is not
 *     RtlLookupFunctionEntry(that)    -> its exact bounds, from .pdata, with no symbols
 *     decode forward within bounds    -> the direct call targets
 *     keep .pdata function STARTS     -> a target that is not one means the decode drifted
 *
 * ⚠ THE LAST FILTER IS WHAT MAKES THIS CHECKABLE RATHER THAN PLAUSIBLE. A `call rel32` whose
 * destination is not a function start means the scan wandered into the middle of an instruction, or
 * the bounds were wrong. Validated offline against this machine before being trusted in the kernel:
 * 17 of 17 direct call targets across four exported functions landed exactly on `.pdata` starts
 * (`tools/ntos_callgraph.py`).
 *
 * ⚠ WHAT THIS FILE DELIBERATELY DOES NOT DO: decide which target is the dispatcher. It REPORTS the
 * candidates and the evidence for each. Picking one is a judgement, D6 says surfaces report evidence
 * and never a verdict, and a wrong pick here would be a hook on a function nobody intended.
 */

#pragma once

#include <ntddk.h>

/*
 * The x64 .pdata record. Written out rather than relying on a header typedef, for the same reason
 * the IDT gate below is: the exact field order is what turns an RVA into a bounds check, and the
 * Win32 spellings of these types (DWORD64, PUNWIND_HISTORY_TABLE) are not available in the km
 * headers this driver builds against -- which is how the first attempt failed to compile.
 *
 * All three fields are RVAs from the image base RtlLookupFunctionEntry hands back, never VAs.
 */
typedef struct _NXC_RUNTIME_FUNCTION
{
	UINT32 BeginAddress;
	UINT32 EndAddress;
	UINT32 UnwindData;
} NXC_RUNTIME_FUNCTION;

/** Direct call targets we will report from one function's body. */
#define NXC_IDT_MAX_TARGETS  16u

/** One decoded call target, with the evidence for whether it is a real function. */
typedef struct _NXC_IDT_TARGET
{
	UINT64 Va;             /* where the call goes                                       */
	UINT64 FuncBegin;      /* .pdata BeginAddress covering it, as a VA; 0 if uncovered   */
	UINT64 FuncEnd;
	UINT32 CallSite;       /* offset of the transfer within the probed function         */
	UINT32 IsFunctionStart; /* Va == FuncBegin -- the check that makes this checkable    */
	UINT32 IsTailJump;     /* E9 rather than E8 -- see the note on NXC_IDT_PROBE         */
	/*
	 * ⚠ TARGET INSIDE THE PROBED FUNCTION'S OWN BOUNDS -- an ordinary internal branch, NOT a
	 * transfer to anything. The first hardware run found two of these per vector and the report
	 * labelled them "decode may have drifted", because the only distinction being drawn was
	 * function-start versus not. That reads a normal jump as a fault.
	 *
	 * Three cases, and they need three names: INTERNAL (inside our own bounds, expected),
	 * EXTERNAL and a .pdata function start (a real transfer -- the dispatcher candidates), and
	 * EXTERNAL but NOT a function start (the genuinely suspicious one the cross-check is for).
	 */
	UINT32 IsInternal;
	/*
	 * ⚠ FOUND BY THE UNALIGNED SCAN RATHER THAN THE LINEAR DECODE. Reported because the two have
	 * different confidence: the decode knows this byte began an instruction, the scan does not and
	 * relies entirely on the .pdata function-start filter to reject coincidental 0xE8/0xE9 bytes.
	 * Both are validated the same way; only one also knows the byte was an opcode boundary.
	 */
	UINT32 FoundByScan;
	UINT32 Reserved1;
} NXC_IDT_TARGET;

/** What a probe of one IDT vector found. */
typedef struct _NXC_IDT_PROBE
{
	UINT64 IdtBase;
	UINT16 IdtLimit;
	UINT16 Vector;

	/*
	 * ⚠ RSB-stuffing calls dropped by this probe (Spectre-v2 return-stack fill: a real E8 to a
	 * target < 0x40 forward). REPORTED, not silent -- a filter that removes 27 of 37 transfers and
	 * says nothing is indistinguishable from a decode that found only 10. On this build
	 * KiExceptionDispatch drops 27 and keeps 10.
	 *
	 * Occupies what was Reserved0, so the usermode ABI size is unchanged.
	 */
	UINT32 RsbFiltered;

	/*
	 * ⚠ EXTERNAL TRANSFERS TO .pdata FUNCTION STARTS, COUNTED TO THE END OF THE FUNCTION AND NOT
	 * CAPPED BY THE TARGET TABLE. This is the value the dispatcher derivation RANKS ON.
	 *
	 * `TargetCount` cannot serve: it stops at NXC_IDT_MAX_TARGETS, and that reported
	 * KiDispatchException as 15 when the real figure is 28 -- a FLOOR presented as a count. It
	 * still won, which is the dangerous part: two saturating candidates would tie at 15 and the
	 * tie-check would refuse a decidable resolution, with nothing in the output saying the scores
	 * were truncated rather than equal.
	 */
	UINT32 ExternalStarts;

	UINT64 HandlerVa;      /* the gate's target -- KiDebugTrapOrFault for vector 1 */
	UINT64 HandlerBegin;   /* its .pdata bounds                                   */
	UINT64 HandlerEnd;
	UINT32 DecodedBytes;   /* how much of the body decoded cleanly                */
	UINT32 TargetCount;

	/*
	 * ⚠ WHY THE DECODE STOPPED. Reported because "stopped before the end" on its own is not
	 * actionable, and the first hardware run of this probe produced exactly that on all three
	 * vectors -- 132 of 424 bytes, 126 of 861, 122 of 2047 -- with nothing saying why.
	 *
	 * StopReason: 0 = ran to the end of the function, 1 = the length decoder errored,
	 * 2 = the target table filled, 3 = the next byte was not resident.
	 */
	UINT32 StopReason;
	UINT32 StopOffset;
	UINT8  StopBytes[16];  /* what was actually there, so an unknown encoding can be identified */

	NXC_IDT_TARGET Targets[NXC_IDT_MAX_TARGETS];
} NXC_IDT_PROBE;

/**
 * Read one IDT vector and derive the direct call targets of its handler.
 *
 * ⚠ READ-ONLY, TOP TO BOTTOM. `__sidt` reads a register; the gate is read; `RtlLookupFunctionEntry`
 * reads .pdata; the body is decoded. Not one byte is written anywhere by this call, which is the
 * property that makes it safe to run on a live machine at all.
 *
 * @param Vector    IDT vector to read (1 = #DB, 3 = #BP, 14 = #PF). Ignored when DirectVa != 0.
 * @param DirectVa  probe THIS function instead of an IDT vector's handler.
 *
 *                  ⚠ EXISTS BECAUSE A TRAP HANDLER CHAINS. measured: vector 1's only
 *                  tail jump goes to its own function end + 24 -- `KiDebugTrapOrFault` continues in
 *                  the adjacent function, so everything it eventually transfers to is invisible from
 *                  the entry function alone. Following that hop needs a probe that takes an address,
 *                  and one primitive that probes ANY function is better than a second command that
 *                  duplicates the decode.
 *
 *                  The IDT is still the anchor: DirectVa is only ever an address this probe already
 *                  derived from a gate, never one a caller invented.
 * @param Out       everything found, including partial results when the decode stopped early
 */
NTSTATUS NxcIdtProbe(_In_ UINT32 Vector, _In_ UINT64 DirectVa, _Out_ NXC_IDT_PROBE* Out);

/**
 * Is @p Va the handler entry of ANY present IDT gate?
 *
 * ⚠⚠ EXISTS TO MAKE A BUGCHECK IMPOSSIBLE, NOT TO INFORM. `NxcHookInstall` refuses any target this
 * returns TRUE for, because an ISR entry is not a hookable function:
 *
 *   - it runs BEFORE `swapgs`, so GS still points at the USER GS base -- and the hook thunk's
 *     `KeGetCurrentProcessorNumberEx` is a GS-relative PCR read, which therefore dereferences
 *     user-controlled memory inside a trap handler;
 *   - interrupts are OFF (an interrupt gate clears IF), so anything that faults or spins there wedges
 *     that core rather than failing;
 *   - `hde64` (2009) cannot decode `swapgs`, which these prologues start with, so the stolen-byte
 *     count is untrustworthy even before the GS problem.
 *
 * Hooking the vector-1 handler bugchecked this machine with CLOCK_WATCHDOG_TIMEOUT --
 * a core stopped answering the clock, which is exactly what the above produces.
 *
 * ⚠ IT ASKS THE LIVE IDT, so it cannot be defeated by a different Windows build, a different vector,
 * or an address derived some other way. And it bans only ENTRY POINTS: a function CALLED by a
 * handler, after the prologue has run `swapgs`, is an ordinary C function and remains hookable.
 */
BOOLEAN NxcIdtIsGateHandler(_In_ UINT64 Va, _Out_opt_ UINT32* OutVector);

/**
 * Derive KTRAP_FRAME.EFlags's offset by decoding ntoskrnl's OWN code.
 *
 * ⚠ WHY A DERIVATION AND NOT A CONSTANT. Item 14 needs EXECUTE breakpoints, and resuming one
 * without setting `EFLAGS.RF` re-enters the same instruction forever. RF lives in the target's
 * KTRAP_FRAME, whose layout is unexported and moves between builds -- pinning it is what this
 * project bans, and a wrong offset writes into somebody else's saved register state on the
 * exception path.
 *
 * The kernel states the offset itself: the stack-switch wrapper on the exception path does
 * `test dword ptr [rbp+0xF8], 0x200`, and 0x200 is EFLAGS.IF, which can only be tested against the
 * saved EFLAGS. Decoding one instruction whose meaning is unambiguous is not pinning.
 *
 * @param FunnelVa  KiExceptionDispatch, itself derived from the live IDT. The wrapper is one of its
 *                  direct callees, so this walks from a fact rather than a hardcoded RVA.
 * @param OutSites  how many sites agreed. **TWO OR MORE IS THE CHECK** -- one match could be a
 *                  coincidental test against something else, and the consumer WRITES to this
 *                  displacement in a live trap frame. Returns STATUS_NOT_FOUND for a lone site and
 *                  STATUS_UNSUCCESSFUL if two sites disagree, because a contested offset is worse
 *                  than none.
 */
NTSTATUS NxcIdtDeriveEflagsOffset(
	_In_ UINT64 FunnelVa,
	_Out_ UINT32* OutOffset,
	_Out_ UINT32* OutSites
	);

/* ================================================================================================
 * THE VOLATILE GPRs IN KTRAP_FRAME -- Rax, Rcx, Rdx, R8, R9, R10, R11.
 * ============================================================================================= */

/** The seven volatile registers, in the order the trap entry stores them. */
#define NXC_GPR_RAX 0u
#define NXC_GPR_RCX 1u
#define NXC_GPR_RDX 2u
#define NXC_GPR_R8  3u
#define NXC_GPR_R9  4u
#define NXC_GPR_R10 5u
#define NXC_GPR_R11 6u
#define NXC_GPR_COUNT 7u

/* Which gate a derivation stopped at. Distinct values because three of them share one NTSTATUS. */
#define NXC_GPR_GATE_OK          0u
#define NXC_GPR_GATE_NO_BIAS     1u   /* no `lea rbp,[rsp+B]` at all                        */
#define NXC_GPR_GATE_BIAS_AMBIG  2u   /* two different biases -- nothing can be attributed  */
#define NXC_GPR_GATE_MISSING_REG 3u   /* a register was never stored: a PARTIAL map         */
#define NXC_GPR_GATE_GAP         4u   /* the run is not contiguous at 8-byte stride         */
#define NXC_GPR_GATE_NO_EFLAGS   5u   /* nothing to corroborate the bias against            */
#define NXC_GPR_GATE_EFLAGS_BAD  6u   /* bias contradicts the PROVEN offset                 */
#define NXC_GPR_GATE_UNREADABLE  7u   /* the trap entry function could not be read          */

typedef struct _NXC_GPR_MAP
{
	UINT32  Offset[NXC_GPR_COUNT];  /* KTRAP_FRAME offset of each, once PROVEN */
	UINT32  Bias;                   /* the `lea rbp,[rsp+B]` that made them readable */
	UINT32  EflagsSeen;             /* what THIS function's EFLAGS.IF test resolved to, or 0 */
	/*
	 * ⚠ WHICH GATE REFUSED. STATUS_NOT_FOUND covers THREE of them -- no bias, a register never
	 * stored, and no EFLAGS test to corroborate against -- so the status alone cannot say which,
	 * and that is the defect this whole session has been about. Written on EVERY exit, including
	 * success (NXC_GPR_GATE_OK), so a reader never has to infer it from what is absent.
	 */
	UINT32  Gate;
	/*
	 * ⚠ WHAT THE DECODER ACTUALLY LOOKED AT. Gate 1 said "no `lea rbp,[rsp+B]` in the trap entry",
	 * while the OFFLINE ntoskrnl has exactly that instruction at +0x0C of the same function. Only two
	 * things can explain that, and they are distinguishable by the bytes themselves: the live binary
	 * differs from the offline copy, or the bounds are not the function I think they are. Reported so
	 * the comparison is a reading rather than an argument.
	 */
	UINT64  Begin;
	UINT64  First[2];   /* the first 16 bytes at Begin */
	BOOLEAN Valid;                  /* every gate below passed */
} NXC_GPR_MAP;

/**
 * Derive the volatile GPR offsets by decoding the TRAP ENTRY function.
 *
 * ⚠ ANCHORED ON AN IDT GATE, WHICH IS THE STRONGEST ANCHOR THIS SUBSYSTEM HAS. The function is the
 * one containing the vector's handler address, read EXACTLY from the live IDT -- not derived, not
 * shape-matched, not a hardcoded RVA. Three earlier identifications by shape were all falsified;
 * this one cannot be, because the CPU itself is the source.
 *
 * ⚠ WHY THE ENTRY AND NOT THE FUNNEL. measured: the funnel's function contains ZERO
 * rbp-relative GPR stores -- it does not save them. The trap ENTRY does, off `rbp` biased by 0x80,
 * exactly like the EFLAGS test the offset derivation already proved.
 *
 * ⚠ FOUR GATES, ALL REQUIRED, ALL FAIL-CLOSED:
 *   1. exactly ONE `lea rbp,[rsp+B]` -- two different biases means no store can be attributed;
 *   2. all seven registers found, each by its FIRST store (rdx is stored twice: once as Rdx and
 *      again into Dr0, and first-wins plus gate 3 rejects the second);
 *   3. **the seven form a CONTIGUOUS 8-byte run in architectural order** rax,rcx,rdx,r8,r9,r10,r11.
 *      This is the structural check, the same discipline as the IRET tail: a relationship the
 *      hardware and the layout impose, not a constant anyone typed. It is what rejects a
 *      coincidental store landing among them;
 *   4. **the SAME function must re-yield the PROVEN EFlags offset** from its own
 *      `test [rbp+0F8h], ...` sites. A bias that disagrees with the one EFlags proved is REFUSED,
 *      never reconciled -- a contested bias is worse than none.
 *
 * @param Vector          the IDT vector whose handler function to decode (1 = #DB).
 * @param ProvenEflags    the offset already proven from LIVE trap frames, for gate 4. Pass 0 to skip
 *                        that gate ONLY in the self-test, never on the live path.
 */
NTSTATUS NxcIdtDeriveVolatileGprs(
	_In_ UINT32 Vector,
	_In_ UINT32 ProvenEflags,
	_Out_ NXC_GPR_MAP* Out
	);

/**
 * Prove the GPR derivation against SYNTHETIC prologues, including ones it must REJECT.
 *
 * ⚠ THE FIXTURES ARE ADVERSARIAL. A tidy prologue passes against a derivation that checks nothing;
 * these include two conflicting biases, a bias whose EFLAGS test contradicts the proven offset,
 * stores off a DIFFERENT base register, and a run with a gap in it. Runs the SHIPPED decoder.
 */
NTSTATUS NxcIdtGprSelfTest(
	_Out_ UINT32* OutRun,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirstFailure
	);


/* ================================================================================================
 * R12-R15 IN KEXCEPTION_FRAME -- a SECOND structure, with its own anchor and its own proof.
 * ============================================================================================= */

#define NXC_NVGPR_R12 0u
#define NXC_NVGPR_R13 1u
#define NXC_NVGPR_R14 2u
#define NXC_NVGPR_R15 3u
#define NXC_NVGPR_COUNT 4u

typedef struct _NXC_NVGPR_MAP
{
	UINT32  Offset[NXC_NVGPR_COUNT];  /* KEXCEPTION_FRAME offsets, once PROVEN */
	UINT32  SaveBase;                 /* the `lea rax,[rsp+B]` displacement    */
	UINT32  Gate;                     /* NXC_GPR_GATE_* -- shared vocabulary   */
	BOOLEAN Valid;
} NXC_NVGPR_MAP;

/**
 * Derive R12-R15 by decoding the FUNNEL, where KEXCEPTION_FRAME is built.
 *
 * ⚠ THE BASE IS PROVEN, NOT ASSUMED -- the whole lesson of +0xF8/Dr6. The funnel does
 * `mov rdx, rsp` to form arg2, so the ExceptionFrame IS rsp; `lea rax,[rsp+B]` then fixes the save
 * base relative to it, and the seven nonvolatiles (rbx rdi rsi r12 r13 r14 r15) follow contiguously
 * at 8-byte stride in architectural order.
 *
 * ⚠ AND IT DISAGREES WITH THE PUBLISHED KEXCEPTION_FRAME (R12 at 0x110). measured on
 * 10.0.26100.8972 it is 0x118. The measurement comes from the running kernel's own code with the
 * base established; do NOT "correct" it toward a remembered layout -- that is how a pinned offset
 * gets reintroduced wearing a citation.
 *
 * Gates, all fail-closed and sharing NXC_GPR_GATE_* so one vocabulary covers both derivations:
 *   1. exactly ONE `lea <reg>,[rsp+B]` feeding the stores;
 *   2. all four registers found, first-store-wins;
 *   3. CONTIGUOUS 8-byte run in architectural order R12,R13,R14,R15;
 *   4. the base PROVEN by `mov rdx, rsp` in the same function -- without it, refuse.
 */
NTSTATUS NxcIdtDeriveNonvolatileGprs(
	_In_ UINT64 FunnelVa,
	_Out_ NXC_NVGPR_MAP* Out
	);

/** Prove the above against synthetic funnels, including ones it must REJECT. */
NTSTATUS NxcIdtNvGprSelfTest(_Out_ UINT32* OutRun, _Out_ UINT32* OutFailed, _Out_ UINT32* OutFirst);
