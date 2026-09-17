/**
 * @file Trace.h
 * @brief Intel PT trace buffers and ToPA tables. STAGE 1: ALLOCATION ONLY -- nothing is armed.
 *
 * ============================================================================================
 * WHY PT, AND WHY BEFORE PHASE 3
 * ============================================================================================
 *
 * TIER 3 (v1): v1 implemented BTS and LBR. Intel PT was declared seven times and never built; PEBS
 *   returns STATUS_NOT_IMPLEMENTED. Per the standing rule, v1 NOT building something is evidence
 *   about v1's time and difficulty, NOT about merit -- so PT is judged on its own.
 *
 * TIER 2 (SDM Vol 3, Ch 33): PT emits compressed control-flow packets to a memory buffer described
 *   by a Table of Physical Addresses. It answers "what path did this code take" completely, where
 *   LBR answers it for the last ~32 branches only.
 *
 * measured on this machine, all 24 logical processors: PT present on EVERY core (P and
 *   E), with ToPA output AND CR3 filtering. So PT is not a maybe here; it is available everywhere.
 *
 * ⚠ AND PT NEEDS NO TRIGGER, which is what moves it ahead of Phase 3. LBR's ring describes whoever
 * last executed, so reading it without a trap describes OUR OWN read path -- it needs an exception
 * handler to be useful, and that handler is the system-wide #DB IDT hook, the riskiest item in the
 * plan. PT writes CONTINUOUSLY into its buffer, so the trace exists with nothing to trap on, and
 * CR3 filtering scopes it to one process. That takes the IDT hook off the critical path entirely.
 *
 * ============================================================================================
 * ⚠ STAGE 1 IS ALLOCATION ONLY. NOT ONE MSR IS WRITTEN.
 * ============================================================================================
 *
 * This file builds the buffers and the ToPA tables and reports them. It does not set TraceEn, does
 * not touch IA32_RTIT_*, and cannot start a trace.
 *
 * That split is deliberate, and it is the same discipline CpuProbe.h states: the allocation is
 * verifiable by inspection (are the physical addresses right, is the alignment right, did the
 * contiguous allocation actually succeed), whereas arming is not -- a wrong ToPA entry handed to
 * enabled hardware is the CPU writing to a physical address we chose. Getting the addresses proven
 * FIRST, with nothing enabled, is the only order in which a mistake is cheap.
 *
 * ⚠ AND THE PROBE ALREADY FOUND THE OTHER REASON TO WAIT: Windows ships Ipt.sys, PT has ONE set of
 * MSRs per logical processor, and `cpuprobe` reports whether TraceEn is already set. Arming without
 * checking that would silently steal another driver's trace.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/*
 * Per-CPU output region size, as a ToPA size code: region bytes = 1 << (12 + Code).
 *
 * DEFAULT IS 256 KB (code 6), not the megabytes a real trace wants, and that is a STAGE 1 choice:
 * this memory is PHYSICALLY CONTIGUOUS and comes out of the same pool everything else needs. 24
 * logical processors x 256 KB = 6 MB. At 2 MB each it would be 48 MB of contiguous allocation, which
 * can fail outright on a fragmented system -- and a failure there would look like "PT does not work"
 * rather than "the allocator said no".
 */
#define NXC_TOPA_SIZE_CODE_DEFAULT   6u        /* 1 << (12+6) = 256 KB */
#define NXC_TOPA_SIZE_CODE_MAX       15u       /* SDM: 4 bits, 4 KB .. 128 MB */

/** Per-CPU trace state. One instance per logical processor. */
typedef struct _NXC_TRACE_CPU
{
	void*  ToPaVa;        /* the ToPA table itself -- contiguous, page aligned */
	UINT64 ToPaPa;
	void*  BufferVa;      /* the output region                                */
	UINT64 BufferPa;
	UINT32 BufferSize;
	UINT32 Armed;
	/*
	 * ⚠ SAMPLED ON THE OWNING CORE, NEVER READ FROM ANOTHER. IA32_RTIT_* are per-logical-processor,
	 * so reading them from the caller's core would report the CALLER's trace state under another
	 * core's number -- a wrong answer that looks exactly like a right one.
	 *
	 * OutputOffset is the ONLY field here that distinguishes a trace that RAN from one that merely
	 * armed. Buffer addresses and the Armed flag both come from what we wrote; this comes from what
	 * the hardware did.
	 *
	 * ⚠ A POSITION WITHIN THE REGION, NOT A TOTAL. The ToPA is circular, so this returns to 0 when
	 * the region fills. Documented as a byte count once; hardware disproved it (148,848 then
	 * 25,376, having passed 262,144). Once Wrapped is set the total is unknown-but-at-least
	 * BufferSize.
	 *
	 * ⚠ THIS COMMENT USED TO END "Intel PT keeps no wrap counter, so do not invent one" AND THAT WAS
	 * WRONG -- corrected. No REGISTER counts wraps, which is what had been checked; the
	 * ToPA entry's INT bit makes the CPU announce every fill, so the count is available and is now
	 * kept in WrapPmi. Arm with NXC_TRACE_ARM_PMI and the total is BufferSize * WrapPmi +
	 * OutputOffset, exactly, with nothing invented. The instruction not to invent a number was
	 * right; the claim that the hardware could not supply one was a limit of what had been read.
	 */
	UINT64 OutputOffset;  /* IA32_RTIT_OUTPUT_MASK_PTRS[63:32]                                */
	UINT64 RtitStatus;    /* IA32_RTIT_STATUS -- Error/Stopped are why a trace silently died  */
	/*
	 * IA32_RTIT_CTL AS IT READ BACK on this core after arming (D117). Not what was requested -- what
	 * the hardware kept. This is a HYBRID part, so "which timing packets is the trace carrying" has
	 * no single answer for the machine and a decoder pointed at the wrong assumption fails in ways
	 * that look like corrupt data rather than a configuration difference.
	 */
	UINT64 RtitCtl;
	UINT32 Wrapped;       /* the region has been filled at least once                         */

	/*
	 * ⚠ WRAP GENERATION -- what makes a PT BOUND still mean something after the region wraps.
	 *
	 * `Wrapped` is a one-shot boolean detected by scanning the tail; it says "this has been full at
	 * least once" and nothing more. Two bounds taken either side of a wrap therefore compare wrongly:
	 * offset 5,000 is LATER than offset 250,000 once the writer has come round, and the offsets alone
	 * say the opposite. (Generation, Offset) is a total order and restores the comparison.
	 *
	 * Counted in SOFTWARE because the hardware does not count it: a single-entry circular ToPA region
	 * has an output pointer and no revolution counter. Incremented wherever the offset is sampled --
	 * every `trace status` and every bounded trap -- so the granularity is as fine as the sampling.
	 *
	 * ⚠ HONEST LIMIT: two full wraps BETWEEN consecutive samples undercount by one. At the measured
	 * 42 B/ms/core a 256 KB region takes ~6 s to fill, and bounded traps arrive milliseconds apart,
	 * so that needs the target idle for 12 s-plus between hits. Recorded rather than hidden.
	 */
	UINT64 LastOffset;    /* previous sample, to detect the pointer going backwards            */
	UINT32 Generation;    /* +1 each time it does                                              */

	/*
	 * ⚠ THE EXACT WRAP COUNT, FROM HARDWARE -- and the reason the sentence above ("Intel PT keeps no
	 * wrap counter, so do not invent one") is now WRONG, corrected, D111.
	 *
	 * The claim was true of the registers and false of the architecture. A ToPA ENTRY carries an INT
	 * bit: set it, and the CPU raises a performance-monitoring interrupt at the instant that region
	 * FILLS, every time it fills. Counting those is a wrap counter -- exact, not sampled, and
	 * immune to the undercount the Generation field has to admit to.
	 *
	 * So `Generation` and `WrapPmi` measure the SAME event by two mechanisms that share no code:
	 * one counts observed pointer reversals at sample time, the other counts hardware fill
	 * interrupts. They are reported side by side deliberately. WrapPmi >= Generation always, and the
	 * GAP is the undercount made visible rather than argued about
	 * (an earlier finding).
	 *
	 * Zero when PMI mode was not requested, which is why ArmFlags travels beside it -- otherwise a
	 * disabled counter and a region that never filled report the same 0.
	 */
	UINT32 WrapPmi;       /* ToPA region-full interrupts taken on this core                    */
	UINT32 ArmFlags;      /* NXC_TRACE_ARM_* actually applied to this core                     */
	UINT32 PmiWhy;        /* NXC_TRACE_PMIWHY_* -- why PMI mode is or is not live here         */
	UINT64 LvtPcSaved;    /* the LVT PC entry we displaced, restored verbatim on disarm        */
	UINT32 LvtPcValid;    /* non-zero once LvtPcSaved holds a real reading                     */
	/*
	 * ⚠ WHICH FEATURES ARE HOLDING THE LVT -- NXC_LVTPC_OWNER_*, a REFCOUNT BY BIT, not a flag.
	 * LVT PC is ONE per-core register and two features now need it delivered as NMI: PT's ToPA
	 * fill counter and the PEBS PMI CR3 filter. Restoring it when the FIRST of them disarms would
	 * leave the second one's PMIs arriving at a vector nobody claims -- an unclaimed NMI, which is
	 * a bugcheck 0x80. The entry is put back only when the last owner lets go.
	 *
	 * Took Reserved0's slot. (Was `UINT32 Reserved0`.)
	 *
	 * (!) AN EARLIER VERSION OF THIS NOTE CLAIMED THE STRUCT CROSSES TO USERMODE AND ITS SIZE MUST
	 * NOT MOVE. That was wrong -- I asserted it without checking. NxcTraceStatus COPIES field by
	 * field into a separate wire struct, so this one is driver-internal and fields may be added.
	 * Corrected rather than left, because a false constraint in a comment is obeyed for years.
	 */
	UINT32 LvtPcOwners;

	/*
	 * CONTINUOUS-DRAIN CURSOR. Total bytes handed to a caller so far, as a monotonic count across
	 * wraps -- not an offset, because an offset alone cannot tell "nothing new" from "a whole lap".
	 *
	 * ⚠ THE ToPA REGION IS CIRCULAR AND THE HARDWARE NEVER STOPS. A capture that arms, waits and
	 * dumps therefore reads whatever survived the overwriting, and at the measured ~42 B/ms/core a
	 * 256 KB region laps in about six seconds. The same shape cost the PEBS filter 96% of its
	 * matches before it became a consuming ring; PT loses it silently instead, because a circular
	 * buffer always looks full and well-formed.
	 */
	UINT64 DrainedTotal;
} NXC_TRACE_CPU;

#define NXC_LVTPC_OWNER_PT      0x1u    /* Intel PT ToPA region-full PMI    */
#define NXC_LVTPC_OWNER_PEBS    0x2u    /* PEBS per-record CR3 filter PMI   */
#define NXC_LVTPC_OWNER_SAMPLE  0x4u    /* fixed-counter sampling profiler  */

/* ---------------------------------------------------------------------------------------------
 * ARM-TIME OPTIONS. Both change what the HARDWARE does, so both are chosen at arm and recorded
 * per core -- a flag that lived only in the caller could not be reported back beside its effect.
 * ------------------------------------------------------------------------------------------- */

/**
 * ToPA STOP: halt the trace when the region fills instead of wrapping.
 *
 * ⚠ THIS IS AN INDEPENDENT ORACLE FOR "THE REGION FILLED", and that is why it exists here rather
 * than as a convenience. `Wrapped` is our own inference from scanning the region's tail for a
 * non-zero byte. STOP is the CPU's own statement: the SDM has it latch IA32_RTIT_STATUS.Stopped and
 * leave the offset at the region size. The two share no code, so agreement is evidence and
 * DISAGREEMENT names which one is broken -- Stopped set with Wrapped clear indicts the tail scan,
 * the reverse indicts the arm.
 *
 * ⚠ MUTUALLY EXCLUSIVE WITH OBSERVING A WRAP, by construction: SDM confirms tracing is disabled at
 * the fill and NO wrap occurs. So it proves the region CAN fill in a given window; it can never be
 * the mode a wrap is measured in. Two passes, not one.
 */
#define NXC_TRACE_ARM_STOP   NXCMD_TRACE_ARM_STOP

/**
 * ToPA INT: raise a PMI each time the region fills, and count them (see WrapPmi).
 *
 * ⚠ COSTS AN INTERRUPT PER FILL and displaces the local APIC's LVT Performance Counter entry. The
 * displaced value is saved per core and restored on disarm, which is the one respect in which this
 * beats both reference implementations -- see the block above NxcTracePmiArmHere in Trace.c.
 */
#define NXC_TRACE_ARM_PMI    NXCMD_TRACE_ARM_PMI

/*
 * NXC_TRACE_CPU::PmiWhy -- a REASON, never a bare failure. Absent, refused and live are three
 * different states, and one code for all three is how a diagnostic starts absorbing fixes
 * (an earlier finding).
 *
 * ⚠ ALIASES, NOT COPIES. The values live in NexusCommand.h so that both sides of the channel read
 * the same constant; see the block there for why a restatement is not acceptable here.
 */
#define NXC_TRACE_PMIWHY_NOT_REQUESTED   NXCMD_TRACE_PMIWHY_NOT_REQUESTED
#define NXC_TRACE_PMIWHY_LIVE            NXCMD_TRACE_PMIWHY_LIVE
/* ⚠ MEANING NARROWED. It once meant "this core is in xAPIC mode", which was a refusal. xAPIC is now
 * supported via a PASSIVE-time mapping of the APIC page, so this code now means the STRONGER thing:
 * xAPIC mode AND the mapping was unavailable. A core in xAPIC mode with a good mapping reports LIVE. */
#define NXC_TRACE_PMIWHY_NO_X2APIC       NXCMD_TRACE_PMIWHY_NO_X2APIC
#define NXC_TRACE_PMIWHY_NO_CALLBACK     NXCMD_TRACE_PMIWHY_NO_CALLBACK
#define NXC_TRACE_PMIWHY_LVT_READBACK    NXCMD_TRACE_PMIWHY_LVT_READBACK

/**
 * Allocate ToPA tables and output regions for every logical processor.
 *
 * ⚠ ALLOCATES PHYSICALLY CONTIGUOUS MEMORY, which can fail on a fragmented system and is NOT a bug
 * when it does. Partial success is reported rather than rolled back: knowing 18 of 24 CPUs got
 * buffers is more useful than "it failed", and freeing is a separate explicit call.
 *
 * @param SizeCode  region size code; region bytes = 1 << (12 + SizeCode)
 * @param OutOk     CPUs that got both a table and a buffer
 */
/**
 * Pin WHERE IN the PT output region execution is, RIGHT NOW, on the CURRENT core.
 *
 * ⚠ CLEARS TraceEn, FENCES, READS, RESTORES -- and every step is required. The SDM: updates to
 * OUTPUT_BASE/OUTPUT_MASK_PTRS are ASYNCHRONOUS with execution, so reading the pointer while tracing
 * returns a stale offset that looks exactly like a good one.
 *
 * ⚠ REFUSES when RTIT_CTL.OS is set: PT's CPL filter is separate from its CR3 filter, and our trap
 * path runs in the target's CR3, so a trace with ring 0 included contains OUR handler.
 *
 * @return NXC_BPD_PTWHY_*
 */
UINT32 NxcTracePtBoundHere(_Out_ UINT64* OutOffset, _Out_ UINT32* OutGeneration);

NTSTATUS NxcTraceAlloc(_In_ UINT32 SizeCode, _Out_ UINT32* OutOk);

/** Release everything NxcTraceAlloc took. Safe to call when nothing is allocated. */
void NxcTraceFree(void);

/**
 * ============================================================================================
 * STAGE 2 -- ARMING. This is the part that writes MSRs.
 * ============================================================================================
 *
 * ⚠ EVERY RULE BELOW IS A #GP IF BROKEN, AND A #GP HERE IS A BUGCHECK. There is no SEH in this
 * driver, so an MSR write that faults is not an error path -- it is the end of the machine.
 *
 *  1. TraceEn MUST be 0 before any other IA32_RTIT_* register is written. The SDM makes this an
 *     architectural requirement, not a recommendation.
 *  2. Only bits whose CAPABILITY BIT IS SET may be written. CR3 filtering and ToPA are enumerated
 *     in CPUID.(14H); MTC, CYC, PSB and PTW each have their own. Everything unconfirmed stays 0 --
 *     which is why this arms a deliberately MINIMAL configuration rather than a featureful one.
 *  3. The capability check is REPEATED AT ARM TIME on the arming core. `cpuprobe` measured it
 *     earlier, on a different call, and this is a hybrid machine -- an answer from another core is
 *     not an answer about this one.
 *  4. IA32_RTIT_STATUS must be cleared before enabling, or a stale Error/Stopped bit stops the
 *     trace immediately and silently.
 *
 * ⚠ AND CONTENTION IS RE-CHECKED AT ARM TIME. `cpuprobe` reporting PT free is a measurement from
 * the past; Ipt.sys can start between then and now. Arming over a live tracer would silently steal
 * it, so each core refuses if it finds TraceEn already set rather than trusting the earlier probe.
 */

/**
 * Arm Intel PT.
 *
 * @param Cr3Filter  when non-zero, trace ONLY execution under this CR3 -- the whole reason PT is
 *                   usable here without a trigger. Zero traces everything, which on 24 cores fills
 *                   a 256 KB buffer in well under a second and is almost never what is wanted.
 * @param OnlyCpu    arm a single logical processor, or 0xFFFFFFFF for all. Arming one first and
 *                   reading it back is the cheap way to find a bad configuration before it is
 *                   applied twenty-four times.
 * @param OutArmed   cores that armed AND read back as armed -- not cores that were written to
 */
/**
 * @param ArmFlags  NXC_TRACE_ARM_* -- ToPA STOP and/or PMI. 0 is the circular, interrupt-free mode
 *                  every trace before used, so an unchanged caller gets unchanged
 *                  behaviour.
 */
/**
 * @param Ranges       address-range filters, or NULL. Validated by the CALLER; each core still
 *                     re-derives its own CPUID range count and refuses what it cannot do.
 * @param RangeCount   how many, 0 for none.
 * @param OutRangeRefused  cores that armed the TRACE but refused the FILTERS -- a distinct outcome
 *                     from both success and failure, because such a core is tracing MORE than asked
 *                     rather than less, and a caller told only 'armed: N' would never know.
 */
/**
 *  @param Timing  TSC / MTC / CYC / PSB / PTWRITE request, or NULL for control-flow only.
 *  @param OutTimingRefused  cores that armed the TRACE but refused the TIMING request. Separate
 *         from OutRangeRefused because they are different failures with different fixes, and a
 *         single "something was refused" count is the diagnostic that absorbs every fix.
 */
NTSTATUS NxcTraceArm(_In_ UINT64 Cr3Filter, _In_ UINT32 OnlyCpu, _In_ UINT32 ArmFlags,
                     _In_opt_ CONST NXCMD_PT_RANGE* Ranges, _In_ UINT32 RangeCount,
                     _In_opt_ CONST NXCMD_PT_TIMING* Timing,
                     _Out_ UINT32* OutArmed, _Out_ UINT32* OutRangeRefused,
                     _Out_ UINT32* OutTimingRefused);

/** Clear TraceEn everywhere. Safe when nothing is armed; used on every teardown path. */
NTSTATUS NxcTraceDisarm(_Out_ UINT32* OutDisarmed);

/* ---------------------------------------------------------------------------------------------
 * NMI SAMPLING PROFILER. Shares the LVT PC and the NMI callback with the ToPA fill counter, so
 * both are registered once and released only when NEITHER consumer still wants them.
 * ------------------------------------------------------------------------------------------- */

/** @param Period retired RING-3 instructions between samples. Refused below 10,000 -- a short
 *  period is an NMI storm at retire rate, and clamping would profile at a rate nobody asked for. */
/* ---------------------------------------------------------------------------------------------
 * PEBS -- STAGE 1: ALLOCATION ONLY. NOT ONE MSR IS WRITTEN.
 *
 * ⚠⚠ THE SPLIT IS THE SAME ONE ToPA HAS, FOR THE SAME REASON, AND IT IS NOT CEREMONY.
 * IA32_DS_AREA is a POINTER THE CPU WRITES THROUGH. Hand it a wrong address with PEBS enabled and
 * the processor writes records into memory we do not own -- silent corruption with nothing pointing
 * back here. Exactly the hazard a bad ToPA entry carries, and Trace.h's answer applies unchanged:
 * the allocation is verifiable by INSPECTION (are the addresses right, is the alignment right, did
 * the allocation actually succeed) while arming is not. Getting the addresses proven FIRST, with
 * nothing enabled, is the only order in which a mistake is cheap.
 *
 * MEASURED on this machine before any of this was written (cpuprobe): PEBS present on
 * all 24 cores, record format 6, ARCH_REG set, and BASELINE set -- so ADAPTIVE PEBS is available and
 * the record layout is CHOSEN via MSR_PEBS_DATA_CFG rather than inherited.
 * ------------------------------------------------------------------------------------------- */

/** Allocate a DS management area + PEBS buffer per core. Writes NO MSR and starts nothing.
 *  @param Records  PEBS records per core; the buffer is sized from the record stride. */
NTSTATUS NxcPebsAlloc(_In_ UINT32 Records, _In_ UINT32 MaxStride, _Out_ UINT32* OutOk);

/* Bytes per record slot the last alloc actually reserved, after clamping. Report this, never
 * the value that was requested. */
UINT32 NxcPebsAllocStride(void);
void     NxcPebsFree(void);
/** Stage 2. Uses PMC0, not a fixed counter: the DS area PebsCounterReset[] array is
 *  unambiguously indexed by GENERAL-PURPOSE counter, and a wrong reset offset is a value the CPU
 *  reloads from memory we chose. It also means PEBS and the D114 profiler do not compete. */
NTSTATUS NxcPebsArm(_In_ UINT64 Cr3Filter, _In_ UINT64 Period, _In_ UINT32 Groups,
                    _In_ UINT32 LdLat, _Out_ UINT32* OutArmed);
/** ⚠ THE MSR READ-BACKS TRAVEL IN NXCMD_PEBS_CPU_STATE, NOT THROUGH ACCESSORS ON THE ARM COMMAND.
 *  MSR_PEBS_DATA_CFG alone came back 0x2 as requested while records stayed Basic-only, because the
 *  missing bit was IA32_PERFEVTSEL0.Adaptive_Record (34) -- a second register. Both are reported by
 *  `pebs status`, per core, so a P-core/E-core split cannot hide behind one number and there is one
 *  expression for the values rather than two that must agree. */
NTSTATUS NxcPebsDisarm(_Out_ UINT32* OutDisarmed);
/** Copy RAW record bytes out. Deliberately unparsed -- see the block at the end of NxcPebsDrain
 *  for why a size check written from recall would be worse than none. */
NTSTATUS NxcPebsDrain(_In_ UINT32 Cpu, _Out_writes_bytes_(Cap) void* Out, _In_ UINT32 Cap,
                      _Out_ UINT32* OutBytes, _Out_ UINT32* OutWritten);
/**
 * PMI CR3-filter outcome, as EVIDENCE rather than a verdict (D6). `Kept` is what survived in the
 * buffer for a drain; `Rejected` is what the CR3 test rewound over; `Pmis` is how many filter
 * interrupts arrived at all. Kept + Rejected <= Pmis, and a shortfall means overflows that produced
 * no judgeable record -- which is a fact worth being able to see, not one to hide.
 *
 * ⚠ ONE CALL, NOT FOUR ACCESSORS. Two of them (NxcPebsKept/NxcPebsRejected) were declared here by
 * the reverted first attempt and never defined; separate accessors also let a caller print numbers
 * sampled at different instants, which for a ratio is a wrong answer that looks plausible.
 */
void NxcPebsFilterStats(_Out_ UINT32* OutActive, _Out_ UINT64* OutKept,
                        _Out_ UINT64* OutRejected, _Out_ UINT64* OutPmis);
/** The CR3 the PMI filter compares against -- a comparison cannot be debugged from one side. */
UINT64 NxcPebsTargetCr3(void);
/** Records discarded as unattributable, and matches lost to a full keep buffer. */
void NxcPebsFilterLoss(_Out_ UINT64* OutDropped, _Out_ UINT64* OutKeepFull);

NTSTATUS NxcPebsStatus(_Out_writes_(Cap) NXCMD_PEBS_CPU_STATE* Out, _In_ UINT32 Cap,
                       _Out_ UINT32* OutGot, _Out_ UINT32* OutTotal);

/* ---------------------------------------------------------------------------------------------
 * NMI OBSERVER. Registered at driver init, never deregistered.
 *
 * ⚠ CALL NxcTraceNmiInit FROM DriverEntry. Two things depend on it: the observer can only see NMIs
 * that arrive with nothing armed if it is listening from boot -- and that is the ONLY state the
 * bugcheck 0x80s under investigation ever happened in -- and a permanent registration removes the
 * deregistration decision that caused them to be possible. That check was wrong twice.
 * ------------------------------------------------------------------------------------------- */
void   NxcTraceNmiInit(void);
void   NxcNmiObserveStats(_Out_ UINT64* OutTotal, _Out_ UINT64* OutUnclaimed,
                          _Out_ UINT32* OutCatchOn, _Out_ UINT32* OutRegistered);
UINT32 NxcNmiObserveDrain(_Out_writes_(Cap) NXCMD_NMI_OBS* Out, _In_ UINT32 Cap,
                          _Out_ UINT64* OutTotal);
/** ⚠ DIAGNOSTIC ONLY -- SUPPRESSES a real bugcheck 0x80 so the evidence can be read. Off by
 *  default, counted separately as CAUGHT, and announced by `nmi status`. Not a fix. */
void   NxcNmiSetCatch(_In_ UINT32 On);

NTSTATUS NxcSampleArm(_In_ UINT64 Cr3Filter, _In_ UINT64 Period, _Out_ UINT32* OutArmed);
NTSTATUS NxcSampleDisarm(_Out_ UINT32* OutSamples, _Out_ UINT32* OutLost);
NTSTATUS NxcSampleDrain(_Out_writes_(Cap) NXCMD_SAMPLE_ENTRY* Out, _In_ UINT32 Cap,
                        _Out_ UINT32* OutGot, _Out_ UINT32* OutTotal, _Out_ UINT32* OutLost);

/** Report per-CPU state for `PlatformCtl trace status`. */
/**
 * @param Exact  clear TraceEn and fence on each core before reading the output pointer.
 *
 * ⚠ WITHOUT IT THE BYTE COUNT IS A LOWER BOUND, not an error: the SDM says OUTPUT_MASK_PTRS updates
 * are ASYNCHRONOUS with execution, so a read taken while tracing misses whatever is still in the
 * CPU's internal packet buffer. WITH it the figure is exact and the trace is briefly STOPPED --
 * which perturbs the thing being measured, so it is opt-in rather than the default.
 */
NTSTATUS NxcTraceStatus(
	_Out_writes_(Cap) NXCMD_TRACE_CPU_STATE* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_In_ BOOLEAN Exact
	);

/**
 * Copy raw trace bytes out of one CPU's output region.
 *
 * ⚠ RAW BYTES, NO INTERPRETATION. D5: the kernel reports facts, usermode decides. A Intel PT packet
 * decoder in a manually mapped image with no SEH, running against a buffer that hardware is possibly
 * still writing, would be the most fragile code in the project for no gain -- the bytes are the same
 * bytes either side of the channel.
 *
 * TIER 1 agrees independently: Cheat Engine's ultimap2 does not decode in the kernel either. It maps
 * the ToPA buffer into the waiting usermode process and lets that side consume it.
 *
 * ⚠ THE REGION IS CIRCULAR, SO OFFSET 0 IS NOT THE START OF ANYTHING. After a wrap, byte 0 is
 * whatever the writer most recently laid down there, and it is almost certainly mid-packet. The
 * caller is expected to find a PSB and begin there -- that is precisely what PSB exists for. This
 * function does not try to be clever about it, because guessing a start point and being wrong
 * produces a decode that looks successful and is fiction.
 *
 * @param Cpu     logical processor whose region to read
 * @param Offset  byte offset within the region
 * @param Bytes   how many to copy
 * @param Out     caller's buffer (D2)
 * @param OutCopied  what was ACTUALLY copied -- a request past the end is clamped, not refused,
 *                   and the caller is told the real number (D3)
 */
/**
 * CONSUME what PT has written since the last call -- the drain a long capture needs.
 *
 * ⚠ NxcTraceDump is random-access on a CIRCULAR region and knows nothing about what the caller has
 * already seen, so arm-wait-dump silently returns only what survived being overwritten. This
 * returns the new bytes, reports how many were LOST to overrun, and how many are still PENDING.
 *
 * Call NxcTraceDrainRefresh() ONCE per sweep first: IA32_RTIT_* are per-core, so the offsets have
 * to be sampled by an IPI, and doing that per-CPU would be 24 broadcasts instead of one.
 */
NTSTATUS NxcTraceDrain(_In_ UINT32 Cpu, _Out_writes_bytes_(Cap) void* Out, _In_ UINT32 Cap,
                       _Out_ UINT32* OutBytes, _Out_ UINT64* OutLost, _Out_ UINT64* OutPending);
NTSTATUS NxcTraceDrainRefresh(void);

NTSTATUS NxcTraceDump(
	_In_ UINT32 Cpu,
	_In_ UINT64 Offset,
	_In_ UINT32 Bytes,
	_Out_writes_bytes_(Bytes) void* Out,
	_Out_ UINT32* OutCopied
	);
