/**
 * @file Trace.c
 * @brief Intel PT ToPA allocation. STAGE 1: no MSR is written. Reasoning lives in Trace.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>   /* _mm_mfence -- the SDM requires a fence after clearing TraceEn */

#include "Trace.h"
/* IA32_LBR_FROM_IP_0 / _TO_IP_0 -- the sampling profiler reads the last RING-3 branch instead of a
 * trap frame it is never handed. See the block above the sample ring for why that is sound. */
#include "Lbr.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define TrcLog NxcLogExt

/*
 * ToPA entry layout (SDM Vol 3, Table 33-4). Written out rather than referenced, because getting a
 * bit position wrong here means the CPU writes trace data to a physical address we did not intend.
 *
 *   bit  0      END    this entry's address field points at ANOTHER ToPA table, not a buffer
 *   bit  2      INT    raise PMI when this region fills
 *   bit  4      STOP   stop tracing when this region fills
 *   bits 9:6    Size   region bytes = 1 << (12 + Size)
 *   bits 63:12  the output region's PHYSICAL base
 */
#define TOPA_END          (1ULL << 0)
#define TOPA_INT          (1ULL << 2)
#define TOPA_STOP         (1ULL << 4)
#define TOPA_SIZE_SHIFT   6
#define TOPA_SIZE_MASK    (0xFULL << TOPA_SIZE_SHIFT)
#define TOPA_PA_MASK      0xFFFFFFFFFFFFF000ULL

#define NXC_MAX_TRACE_CPUS  64u

static NXC_TRACE_CPU gTrace[NXC_MAX_TRACE_CPUS];

/* Set for the duration of one `trace status --exact`; see SampleOnEachCpu. */
static volatile LONG gTraceExactSample = 0;
static UINT32        gTraceCpus = 0;

/* Defined below; NxcTraceFree must call it BEFORE releasing any buffer. */
NTSTATUS NxcTraceDisarm(_Out_ UINT32* OutDisarmed);

/* Defined below, and used by BOTH the disarm and the sample paths -- declared here because the
 * disarm comes first in this file and C4013 is an error in this project precisely so that a use
 * before declaration cannot compile into an implicit int-returning guess. */
static void TraceNoteWrap(_Inout_ NXC_TRACE_CPU* T);

/*
 * ⚠ ONE PLACE THAT ADVANCES THE GENERATION, called from every site that samples the offset. Two
 * copies of "did the pointer go backwards" is the drift this codebase keeps finding.
 */
static void
TraceNoteGeneration(
	_Inout_ NXC_TRACE_CPU* T,
	_In_ UINT64 Offset
	)
{
	if (Offset < T->LastOffset)
		T->Generation++;

	T->LastOffset = Offset;
}

/*
 * ⚠⚠ ONE PLACE THAT CLEARS THE PER-CAPTURE COUNTERS, AND THERE ARE THREE CALLERS: free, alloc, arm.
 *
 * Found on hardware. `trace status` immediately after a fresh `trace alloc` reported
 * `ARMED=no POSITION=0 FILLED=no GEN=1` -- a wrap generation on a buffer that had never been armed.
 * The 1 was earned by the PREVIOUS capture, whose final disarm caught the pointer lower than the last
 * sample had left it, and it then survived `trace free` and `trace alloc` because each of those reset
 * its own hand-written list of fields:
 *
 *   NxcTraceFree     cleared OutputOffset, RtitStatus, Wrapped   -- and not Generation/LastOffset
 *   NxcTraceAlloc    cleared Armed                               -- and not the counters at all
 *   ArmOnEachCpu     cleared the counters (fixed earlier today)  -- the only complete one
 *
 * ⚠ THREE LISTS THAT MUST AGREE IS THE SHAPE, and this file already fixed the arm-side half of the
 * same bug hours earlier -- which is exactly why a second copy of the list was the wrong repair.
 * Every field a capture writes is cleared HERE, so adding a counter later cannot leave two of the
 * three sites behind (an earlier finding,
 * An earlier finding).
 *
 * ⚠ THE LVT FIELDS ARE DELIBERATELY NOT HERE. LvtPcSaved/LvtPcValid are a RESOURCE, owned by
 * TracePmiArmHere and TracePmiDisarmHere, not a measurement. Clearing LvtPcValid from a reset would
 * discard a pending restore and leave a core's LVT PC pointing at our NMI vector permanently.
 * Counters get reset; resources get released.
 */
static void
TraceResetCounters(
	_Inout_ NXC_TRACE_CPU* T
	)
{
	T->OutputOffset = 0;
	T->RtitStatus   = 0;
	T->Wrapped      = 0;
	T->LastOffset   = 0;
	/* The drain cursor is part of a capture SESSION, not a counter: a new arm must start at zero or
	 * the first drain would report bytes from the previous trace as pending. */
	T->DrainedTotal = 0;
	T->Generation   = 0;
	T->WrapPmi      = 0;
	T->ArmFlags     = 0;
	T->PmiWhy       = 0;
}

void
NxcTraceFree(
	void
	)
{
	/*
	 * ⚠ DISARM FIRST. THIS IS NOT TIDINESS.
	 *
	 * An armed core is writing trace packets into these exact physical pages, by hardware, with no
	 * involvement from us. Freeing them while TraceEn is set hands those frames back to the
	 * allocator while the CPU keeps writing to them -- silent corruption of whatever is handed the
	 * memory next, with nothing pointing back here.
	 *
	 * Stage 1 could not have this bug because nothing was ever armed. Stage 2 introduced it, so the
	 * ordering is established in the same change.
	 */
	UINT32 Disarmed = 0;
	(void)NxcTraceDisarm(&Disarmed);
	if (Disarmed != 0)
		TrcLog("trace: free disarmed %u core(s) first -- they were writing to these pages\n",
		       Disarmed);

	for (UINT32 i = 0; i < NXC_MAX_TRACE_CPUS; i++)
	{
		/*
		 * ⚠⚠ RETIRE BEFORE DESTROY. THIS WAS free-then-NULL AND IT IS THE SAME BUG AS `NxcPebsFree`.
		 *
		 * The old order called `MmFreeContiguousMemory(gTrace[i].BufferVa)` and only afterwards
		 * stored NULL. Between those two statements the global is a NON-NULL POINTER TO FREED
		 * MEMORY, and `BufferSize` still held its old value until three lines later -- so BOTH
		 * halves of every reader's guard passed while the memory was already gone.
		 *
		 * The readers are real and take no lock: `NxcTraceDrain` and `NxcTraceDump` both test
		 * `BufferVa == NULL || BufferSize == 0` and then `RtlCopyMemory` out of `T->BufferVa` at
		 * PASSIVE. Neither consults `Armed`, so the `NxcTraceDisarm` above does not protect them,
		 * and a continuous drain loop is precisely the documented workload.
		 *
		 * ⚠ THIS FILE ALREADY ARGUED THE FIX AND APPLIED IT TO ONLY ONE OF THE TWO SIBLINGS.
		 * `NxcPebsFree` was corrected after four 0x80 bugchecks -- "the memory is
		 * released while the global still points at it" -- and `NxcTraceFree` kept the defect.
		 * of this file.
		 *
		 * Order now: snapshot the pointers, unpublish EVERY field a reader tests, fence, then free.
		 * The buffer is still released before the table for the reason below.
		 */
		void* CONST RetireBuf  = gTrace[i].BufferVa;
		void* CONST RetireToPa = gTrace[i].ToPaVa;

		gTrace[i].BufferVa     = NULL;
		gTrace[i].ToPaVa       = NULL;
		gTrace[i].ToPaPa       = 0;
		gTrace[i].BufferPa     = 0;
		gTrace[i].BufferSize   = 0;
		gTrace[i].Armed        = 0;

		/* The unpublishing stores must be visible before the memory can be handed to anyone else. */
		_mm_mfence();

		/*
		 * ⚠ FREES THE BUFFER BEFORE THE TABLE, and the order is not cosmetic: the table's entries
		 * POINT AT the buffer. If a future stage ever frees while hardware is armed, releasing the
		 * table first would leave the CPU writing through entries in reclaimed memory. Freeing the
		 * pointed-to region first at least makes that a fault rather than silent corruption.
		 */
		if (RetireBuf  != NULL) MmFreeContiguousMemory(RetireBuf);
		if (RetireToPa != NULL) MmFreeContiguousMemory(RetireToPa);
		/* ⚠ WAS THREE HAND-LISTED FIELDS AND LEFT Generation/LastOffset/WrapPmi BEHIND, so a freed
		 * capture's generation was still reported against the next allocation. See TraceResetCounters. */
		TraceResetCounters(&gTrace[i]);
	}
	gTraceCpus = 0;
}

NTSTATUS
NxcTraceAlloc(
	_In_ UINT32 SizeCode,
	_Out_ UINT32* OutOk
	)
{
	*OutOk = 0;

	if (SizeCode > NXC_TOPA_SIZE_CODE_MAX)
		return STATUS_INVALID_PARAMETER;

	/* Re-allocating over a live allocation would leak every previous buffer, so refuse rather than
	 * silently overwrite the pointers that are the only way to free them. */
	if (gTraceCpus != 0)
	{
		TrcLog("trace: already allocated for %u CPUs -- free first\n", gTraceCpus);
		return STATUS_ALREADY_COMMITTED;
	}

	CONST ULONG Cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	CONST ULONG Use  = (Cpus < NXC_MAX_TRACE_CPUS) ? Cpus : NXC_MAX_TRACE_CPUS;
	CONST SIZE_T RegionBytes = (SIZE_T)1 << (12 + SizeCode);

	PHYSICAL_ADDRESS High;
	High.QuadPart = MAXULONG64;

	UINT32 Ok = 0;
	for (ULONG i = 0; i < Use; i++)
	{
		/*
		 * ⚠ ALIGNMENT IS REQUESTED, NOT HOPED FOR. The ToPA entry stores this region's base in bits
		 * 63:12 alongside a size code, so the region must be aligned to ITS OWN SIZE -- a 256 KB
		 * region needs a 256 KB-aligned base or the low bits are unrepresentable.
		 *
		 * The first version used MmAllocateContiguousMemory, which promises only PAGE alignment, and
		 * then REFUSED whatever came back misaligned. That checked the requirement without ever
		 * asking for it: on a fragmented machine most CPUs would have been refused and the feature
		 * would have reported "0 of 24" as though memory were exhausted, when the allocator had
		 * simply never been told what was needed.
		 *
		 * BoundaryAddressMultiple names a boundary the allocation must not CROSS. An allocation of
		 * exactly RegionBytes that cannot cross a RegionBytes boundary must begin on one, which is
		 * precisely the alignment the entry format requires.
		 */
		PHYSICAL_ADDRESS Low;      Low.QuadPart      = 0;
		PHYSICAL_ADDRESS Boundary; Boundary.QuadPart = (LONGLONG)RegionBytes;

		void* CONST Buf = MmAllocateContiguousMemorySpecifyCache(RegionBytes, Low, High,
		                                                         Boundary, MmCached);
		if (Buf == NULL)
		{
			TrcLog("trace: cpu %lu -- no %llu-byte contiguous block aligned to %llu "
			       "(fragmentation, not a bug)\n",
			       i, (ULONG64)RegionBytes, (ULONG64)RegionBytes);
			continue;
		}

		CONST UINT64 BufPa = (UINT64)MmGetPhysicalAddress(Buf).QuadPart;
		if (BufPa == 0 || (BufPa & (RegionBytes - 1)) != 0)
		{
			/*
			 * ⚠ THIS SHOULD NOW BE UNREACHABLE, and it is kept precisely because of that.
			 *
			 * BoundaryAddressMultiple above asks for the alignment, so reaching here means the
			 * allocator did not honour it -- an assumption about another component's behaviour
			 * turning out false, which is the class of thing this codebase refuses to discover the
			 * hard way. Arming a misaligned region would have the CPU write outside our allocation,
			 * so it is refused rather than trusted, and the log says the request was ignored rather
			 * than merely that the address was wrong.
			 *
			 * Rounding up inside the allocation is NOT the fix: it would leave part of the region
			 * outside what we own -- the same bug wearing a repair.
			 */
			TrcLog("trace: cpu %lu -- PA 0x%llX NOT aligned to 0x%llX despite "
			       "BoundaryAddressMultiple asking for it -- REFUSED\n",
			       i, BufPa, (ULONG64)RegionBytes);
			MmFreeContiguousMemory(Buf);
			continue;
		}

		void* CONST Table = MmAllocateContiguousMemory(PAGE_SIZE, High);
		if (Table == NULL)
		{
			MmFreeContiguousMemory(Buf);
			continue;
		}

		CONST UINT64 TablePa = (UINT64)MmGetPhysicalAddress(Table).QuadPart;
		if (TablePa == 0 || (TablePa & 0xFFFULL) != 0)
		{
			MmFreeContiguousMemory(Table);
			MmFreeContiguousMemory(Buf);
			continue;
		}

		RtlZeroMemory(Table, PAGE_SIZE);
		RtlZeroMemory(Buf, RegionBytes);

		/*
		 * Two entries: the output region, then an END entry pointing back at this same table.
		 *
		 * That makes the buffer CIRCULAR -- it wraps and overwrites the oldest packets rather than
		 * stopping. Chosen over STOP because the interesting moment in a capture is almost always
		 * the most RECENT one; a buffer that stopped hours ago holds the least useful window it
		 * could. STOP and INT are both left clear, and stage 2 gets to choose them deliberately.
		 */
		UINT64* CONST E = (UINT64*)Table;
		E[0] = (BufPa & TOPA_PA_MASK) | (((UINT64)SizeCode << TOPA_SIZE_SHIFT) & TOPA_SIZE_MASK);
		E[1] = (TablePa & TOPA_PA_MASK) | TOPA_END;

		gTrace[i].ToPaVa     = Table;
		gTrace[i].ToPaPa     = TablePa;
		gTrace[i].BufferVa   = Buf;
		gTrace[i].BufferPa   = BufPa;
		gTrace[i].BufferSize = (UINT32)RegionBytes;
		gTrace[i].Armed      = 0;
		/*
		 * ⚠ A FRESH BUFFER MUST REPORT FRESH COUNTERS. Alloc used to set only Armed, so a `trace
		 * status` between alloc and arm showed the PREVIOUS capture's generation against a region that
		 * had never been traced -- observed on hardware as `ARMED=no POSITION=0 FILLED=no GEN=1`.
		 * The region itself is zeroed above for the same reason: stale evidence that looks current is
		 * worse than no evidence, and that applies to the counters as much as to the packets.
		 */
		TraceResetCounters(&gTrace[i]);
		Ok++;
	}

	gTraceCpus = Use;
	*OutOk = Ok;

	TrcLog("trace: allocated %u of %lu CPUs, %llu bytes each (STAGE 1 -- NOTHING ARMED)\n",
	       Ok, Use, (ULONG64)RegionBytes);

	/* Partial success is SUCCESS with a count, not a failure. Knowing 18 of 24 CPUs got buffers is
	 * more actionable than a single status, and freeing is a separate explicit call either way. */
	return (Ok == 0) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------------------------------
 * STAGE 2 -- arming. Read the block in Trace.h before changing anything here.
 * ------------------------------------------------------------------------------------------- */

#define IA32_RTIT_OUTPUT_BASE       0x00000560u
#define IA32_RTIT_OUTPUT_MASK_PTRS  0x00000561u
#define IA32_RTIT_CTL               0x00000570u
#define IA32_RTIT_STATUS            0x00000571u
#define IA32_RTIT_CR3_MATCH         0x00000572u

/*
 * IA32_RTIT_ADDRn_A/B -- the address-range filter pairs. n's base MSR is 0x580 + 2n, its limit
 * 0x581 + 2n, and its 4-bit role field sits in IA32_RTIT_CTL at bit 32 + 4n.
 *
 * TIER 1 (reference material): cheat-engine's ultimap2.c computes exactly this
 * (`msr_start = IA32_RTIT_ADDR0_A + 2*i`, `bit = 32 + i*4`, FilterEn `1 << bit`, TraceStop
 * `2 << bit`). TIER 2 (SDM Vol 3C, IP Filtering): ADDRn_CFG 0 = unused, 1 = FilterEn range,
 * 2 = TraceStop range; ADDRn_A is the base and ADDRn_B the limit, both inclusive.
 *
 * ⚠ ultimap2 carries the remark "FilterEn // not supported in the latest windows build". Recorded
 * because it came from the same source as the arithmetic, and NOT inherited: it is a claim about
 * someone else's machine at some other time, and this driver measures the thing directly. If
 * filtering does not take here, the read-back below will say so on the core it failed.
 */
#define IA32_RTIT_ADDR0_A           0x00000580u
#define RTIT_ADDR_MSR_A(n)          (IA32_RTIT_ADDR0_A + 2u * (n))
#define RTIT_ADDR_MSR_B(n)          (IA32_RTIT_ADDR0_A + 2u * (n) + 1u)
#define RTIT_CTL_ADDR_CFG_SHIFT(n)  (32u + 4u * (n))
#define RTIT_CTL_ADDR_CFG_MASK(n)   (0xFULL << RTIT_CTL_ADDR_CFG_SHIFT(n))

/* IA32_RTIT_CTL. Only these are ever set; every other bit needs a capability we do not check. */
#define RTIT_CTL_TRACEEN    (1ULL << 0)
#define RTIT_CTL_OS         (1ULL << 2)
#define RTIT_CTL_USER       (1ULL << 3)
#define RTIT_CTL_CR3FILTER  (1ULL << 7)
#define RTIT_CTL_TOPA       (1ULL << 8)
#define RTIT_CTL_BRANCHEN   (1ULL << 13)

/*
 * ---- TIMING AND PTWRITE (D117) --------------------------------------------------
 *
 * Control flow alone answers WHERE execution went and never WHEN or HOW LONG. These four bits are
 * what turn a PT trace into something you can put a clock against:
 *
 *   TSCEn    a TSC packet at PSB boundaries -- wall-clock anchors, coarse and cheap
 *   MTCEn    Mini Time Counter packets at a chosen divisor of the always-running crystal, so
 *            elapsed time between anchors is bounded rather than unknown
 *   CYCEn    cycle counts between packets -- the finest resolution PT offers, and the costliest
 *   PTWEn    the PTWRITE instruction emits its operand INTO the trace: a value from the program
 *            itself, inline with the control flow that produced it
 *
 * ⚠⚠ TIER 1 DISAGREES WITH ITSELF HERE, AND THE OLDER COPY IS THE DANGEROUS ONE.
 *
 * `reference material/cheat-engine-master/DBKKernel/ultimap2.h` carries an RTIT_CTL bitfield that
 * marks bits 1, 4, 5 and 12 as Reserved_0 / Reserved_1 / Reserved_2. On this part those are CYCEn,
 * PwrEvtEn, FUPonPTW and PTWEn -- four LIVE controls described as reserved. Its ultimap2.c then sets
 * `TSCEn = 0` and never touches MTC at all: Cheat Engine's PT is deliberately control-flow only.
 * Per the redevelopment rule, a reference not implementing something says nothing about its merit.
 *
 * The current copy in the same tree -- `HyperDbg/hyperdbg/dependencies/ia32-doc/out/ia32.h` -- has
 * all of them, and it is what these defines follow. Two tier-1 sources, one stale, and taking the
 * first one found would have written a "reserved" bit and taken a #GP with no SEH to catch it.
 */
#define RTIT_CTL_CYCEN      (1ULL << 1)
#define RTIT_CTL_MTCEN      (1ULL << 9)
#define RTIT_CTL_TSCEN      (1ULL << 10)
#define RTIT_CTL_PTWEN      (1ULL << 12)
#define RTIT_CTL_FUPONPTW   (1ULL << 5)

#define RTIT_CTL_MTCFREQ_SHIFT   14u
#define RTIT_CTL_CYCTHRESH_SHIFT 19u
#define RTIT_CTL_PSBFREQ_SHIFT   24u
#define RTIT_CTL_4BIT_MASK       0xFULL

/*
 * CPUID.(EAX=14H, ECX=0).EBX -- what this core is ALLOWED to be asked for.
 * CPUID.(EAX=14H, ECX=1)     -- WHICH ENCODINGS of the 4-bit fields it accepts, as BITMAPS.
 *
 * ⚠⚠ THE BITMAPS ARE THE WHOLE SAFETY ARGUMENT, AND THEY ARE WHY TIER 2 WAS NOT OPTIONAL. MTCFreq,
 * CycThresh and PSBFreq are 4-bit fields with 16 possible values, and a part implements a SUBSET.
 * Writing an unimplemented encoding is a #GP on the WRMSR -- in a manually mapped image with no SEH,
 * that is a bugcheck, not an error return. So no constant is ever written here: every value is
 * checked against the core's own bitmap first, and an unsupported request is REFUSED.
 *
 * ⚠ A web summary during this research placed the PSB-frequency bitmap in EDX. EDX is RESERVED in
 * this subleaf. Reading a reserved register returns whatever it returns and would have selected an
 * encoding on no evidence at all. Verified against the SDM's own table before a line was written.
 */
#define PT_EBX_CYC_PSB      (1u << 1)   /* configurable PSB + cycle-accurate mode */
#define PT_EBX_IP_FILTER    (1u << 2)
#define PT_EBX_MTC          (1u << 3)   /* MTC packets                            */
#define PT_EBX_PTWRITE      (1u << 4)   /* licenses PTWEn (12) and FUPonPTW (5)   */

/*
 * ---- DisTNT: TRADE BRANCH RESOLUTION FOR TRACE DURATION --------------------------------------
 *
 * TNT packets encode taken/not-taken for CONDITIONAL branches, and they are the BULK of a trace by
 * volume. Suppressing them keeps everything that carries an ADDRESS -- TIP, FUP, PSB, PIP, and the
 * calls/returns/indirect branches -- while dropping the conditional detail.
 *
 * That is a real capture trade for this project: a fixed ToPA buffer covers far more EXECUTION of a
 * long-running obfuscated target when it is not spending itself on conditional-branch bits. Control
 * flow through a packer's dispatch loop is still visible; which way each `jcc` went is not.
 *
 *   CPUID.(14H,0).EBX[8] = 1  -> writes may set IA32_RTIT_CTL[55]
 *   IA32_RTIT_CTL[55] DisTNT  -> stop generating TNT packets
 *
 * Both verified against Intel's SDM change document, not recalled: "Bit 08 in CPUID Leaf
 * 14H EBX: If 1, writes can set IA32_RTIT_CTL[55] (DisTNT), disabling TNT packet generation."
 * This part reports EBX = 0x15F, so bit 8 is SET.
 */
#define PT_EBX_TNT_DISABLE  (1u << 8)   /* licenses DisTNT (55)                   */
#define RTIT_CTL_DISTNT     (1ULL << 55)

/* IA32_RTIT_STATUS */
#define RTIT_STATUS_ERROR   (1ULL << 4)
#define RTIT_STATUS_STOPPED (1ULL << 5)

/* ---------------------------------------------------------------------------------------------
 * THE ToPA FILL INTERRUPT -- an EXACT wrap count, where the software generation is a lower bound.
 * Read the WrapPmi block in Trace.h first; the mechanism is summarised there and the ugly parts
 * are here.
 * ------------------------------------------------------------------------------------------- */

#define IA32_APIC_BASE            0x0000001Bu
#define IA32_PERF_GLOBAL_STATUS   0x0000038Eu   /* bit 55 = TraceToPAPMI                        */
#define IA32_PERF_GLOBAL_OVF_CTRL 0x00000390u   /* write 1 to bit 55 to clear it                */
/* Read-only here, purely so the NMI observer can record it: a stray BTF/LBR/BTS enable left in
 * DEBUGCTL is one of the few things that turns into an unexpected trap, and it costs one RDMSR to
 * rule in or out. Btf.c defines the same number for its own use; this is an alias, not a second
 * source of truth -- the value is architectural. */
#define IA32_DEBUGCTL             0x000001D9u
#define IA32_X2APIC_LVT_PMI       0x00000834u   /* the LVT PC entry, in x2APIC mode             */

#define APIC_BASE_X2APIC_ENABLE   (1ULL << 10)
#define PERF_GLOBAL_TOPA_PMI      (1ULL << 55)

/*
 * LVT entry layout: vector 7:0, delivery mode 10:8, mask 16. Delivery mode 100b is NMI, and in NMI
 * mode the VECTOR FIELD IS IGNORED by the hardware -- 2 is written anyway so a reader of the MSR
 * sees the architectural NMI vector rather than a stale value from whoever had the entry before.
 */
#define LVT_VECTOR_MASK           0x000000FFULL
#define LVT_DELIVERY_MASK         0x00000700ULL
#define LVT_DELIVERY_NMI          0x00000400ULL
#define LVT_MASKED                (1ULL << 16)
#define LVT_PMI_NMI_VALUE         (LVT_DELIVERY_NMI | 2ULL)

/*
 * ⚠ ONE HANDLE FOR THE WHOLE MACHINE, and it must be, because KeRegisterNmiCallback is per-SYSTEM
 * and not per-core. Registering once per armed core would install N callbacks that each run on every
 * NMI, and the count would come out multiplied by the number of cores -- a wrong answer that scales
 * with the machine, which is the worst kind to debug.
 */
static void* volatile gNmiHandle = NULL;

/* ---------------------------------------------------------------------------------------------
 * NMI SAMPLING PROFILER -- where a target executes, with NOTHING patched.
 *
 * A PMU counter is set to overflow every N retired ring-3 instructions. The overflow raises a PMI,
 * which arrives as an NMI through the same LVT PC entry the ToPA fill counter uses, and the handler
 * records WHERE the target was. No breakpoint, no hook, no page permission changed, no byte of the
 * target modified -- so there is nothing for it to notice.
 *
 * ⚠⚠ THE HARD PART WAS GETTING RIP, AND THE ANSWER CAME FROM THIS MORNING'S SELFTEST.
 *
 * KeRegisterNmiCallback's callback is `BOOLEAN(PVOID Context, BOOLEAN Handled)` -- it is handed NO
 * TRAP FRAME, so the interrupted RIP is not available to it. Finding a KTRAP_FRAME by walking the
 * NMI stack would be derivable but fragile, at NMI level, where a wrong guess has no SEH behind it.
 *
 * Instead the handler reads the LAST BRANCH from the architectural LBR. That is sound here for one
 * measured reason: `lbr selftest` proved that recording RING 3 ONLY yields ZERO
 * kernel-sourced entries (phase 1 = 0) while the instrument was demonstrably live (phase 2 = 768).
 * So the NMI handler's own ring-0 execution CANNOT enter a ring-3-filtered LBR stack, and the top
 * entry still describes the TARGET at the moment the counter overflowed.
 *
 * ⚠ WHICH IS WHY IA32_DEBUGCTL.FREEZE_LBRS_ON_PMI IS NOT USED. It exists (bit 11) precisely to keep
 * a PMI handler's branches out of the ring, and on a ring-3-filtered arch-LBR part that pollution is
 * already impossible. Using it would add a second mechanism for a property we have MEASURED rather
 * than assumed -- and arch LBR moved the enable to IA32_LBR_CTL, so DEBUGCTL semantics here are the
 * kind of thing that is right until it is not.
 *
 * ⚠ SAMPLES ARE A DISTRIBUTION, NEVER A TRACE. N instructions between samples means every sample is
 * a point, and the gaps are unobserved by construction. This answers "where does it spend time",
 * which is a different question from PT's "what path did it take" -- and the two compose: sample to
 * find the hot range, then aim `trace arm --filter` at it.
 * ------------------------------------------------------------------------------------------- */

#define IA32_FIXED_CTR0             0x00000309u
#define IA32_FIXED_CTR_CTRL         0x0000038Du
#define IA32_PERF_GLOBAL_CTRL       0x0000038Fu

/* IA32_FIXED_CTR_CTRL, counter 0: bit 0 OS, bit 1 USR, bit 3 PMI-on-overflow. */
#define FIXED_CTR0_USR              (1ULL << 1)
#define FIXED_CTR0_PMI              (1ULL << 3)
#define PERF_GLOBAL_FIXED0_EN       (1ULL << 32)
#define PERF_GLOBAL_FIXED0_OVF      (1ULL << 32)

/* The counter is 48-bit on this part; counting UP to overflow means preloading its two's
 * complement, so the reload value is derived from the period rather than pinned. */
#define FIXED_CTR_WIDTH_MASK        0x0000FFFFFFFFFFFFULL

/*
 * ⚠ THE SAME 63:12 MASK THE ARM PATH USES, AND FOR THE SAME REASON. CR4.PCIDE is set on all 24 LPs
 * here, so a live CR3 carries a context id in bits 11:0 while a DirectoryTableBase read from
 * EPROCESS does not -- an unmasked comparison could never match
 * (an earlier finding).
 *
 * BpDispatch.c has its own `Cr3Frame` and it is deliberately NOT reused here: it is static to that
 * translation unit, and its comment argues that ONE masking function is the structural answer
 * because two call sites masking differently is how the defect returned. Two files cannot share a
 * static, so what is shared instead is the MASK VALUE and the reasoning -- 63:12, exactly what the
 * SDM says the CR3 filter compares, exactly what NxcTraceArm writes into IA32_RTIT_CR3_MATCH.
 */
static UINT64
SampleCr3Frame(
	_In_ UINT64 Cr3
	)
{
	return Cr3 & 0xFFFFFFFFFFFFF000ULL;
}

typedef struct _NXC_SAMPLE
{
	UINT64 LbrFrom;    /* last ring-3 branch source -- WHERE the target was            */
	UINT64 LbrTo;      /* and where it went                                            */
	UINT64 Cr3;        /* masked frame, so a sample can be attributed to a process     */
	UINT32 Cpu;
	UINT32 Reserved0;
} NXC_SAMPLE;

#define NXC_SAMPLE_RING  4096u

static NXC_SAMPLE      gSampleRing[NXC_SAMPLE_RING];
static volatile LONG   gSampleWrite = 0;    /* monotonic; & (RING-1) indexes            */
static volatile LONG   gSampleLost  = 0;    /* overwritten before a drain -- REPORTED   */
static UINT64 volatile gSampleCr3   = 0;    /* 0 = every process                        */
static UINT64 volatile gSamplePeriod = 0;
static volatile LONG   gSampleArmed = 0;
static volatile LONG   gSampleCores = 0;   /* cores that actually armed                       */
static volatile LONG   gSampleNoLbr = 0;   /* cores refused because IA32_LBR_CTL.EN was clear */

/*
 * The xAPIC MMIO mapping of the local APIC page, or NULL in x2APIC mode (where the LVT PC is an MSR
 * and no mapping is needed). ONE mapping for the machine: every core's local APIC is at the same
 * PHYSICAL address, so there is nothing per-core to map.
 *
 * ⚠ MAPPED AT PASSIVE, OUTSIDE THE IPI BROADCAST. MmMapIoSpace is a PASSIVE-only API and the arm
 * broadcast runs at IPI_LEVEL -- that ordering constraint is the entire reason xAPIC support was
 * first written as a refusal. Doing the mapping before the broadcast and handing the cores a pointer
 * removes the obstacle rather than documenting it.
 */
static void* volatile gApicMmio     = NULL;
static UINT64 volatile gApicMmioPa  = 0;

#define APIC_MMIO_LVT_PMI  0x340u   /* byte offset of the LVT Performance Counter entry */

/*
 * ⚠⚠ THE ONLY TWO FUNCTIONS THAT TOUCH THE LVT PC, AND EVERY SITE GOES THROUGH THEM.
 *
 * There are three callers -- arm, disarm, and the NMI handler's re-unmask -- and each needs the same
 * question answered: is this core in x2APIC mode (MSR 0x834) or xAPIC mode (MMIO 0x340)? Three copies
 * of that decision is three chances for one of them to pick the other mode, which would read a live
 * register and write a dead one. The pattern has already cost this project real defects: install and
 * remove deriving a target separately left a LIVE PATCH behind a report that nothing was patched
 * (an earlier finding).
 *
 * So the mode test lives here, once, and is re-evaluated per call rather than cached -- a cached
 * answer would be a second source of truth about the same hardware fact.
 *
 * Returns 0 and ignores writes when neither route is available, which is the state a core reports as
 * PMIWHY_NO_X2APIC only if the mapping ALSO failed.
 */
static UINT64
TraceLvtPcRead(
	void
	)
{
	if ((__readmsr(IA32_APIC_BASE) & APIC_BASE_X2APIC_ENABLE) != 0)
		return __readmsr(IA32_X2APIC_LVT_PMI);

	void* CONST Mmio = gApicMmio;
	if (Mmio == NULL)
		return 0;

	return (UINT64)*(volatile UINT32*)((UINT8*)Mmio + APIC_MMIO_LVT_PMI);
}

static void
TraceLvtPcWrite(
	_In_ UINT64 Value
	)
{
	if ((__readmsr(IA32_APIC_BASE) & APIC_BASE_X2APIC_ENABLE) != 0)
	{
		__writemsr(IA32_X2APIC_LVT_PMI, Value);
		return;
	}

	void* CONST Mmio = gApicMmio;
	if (Mmio == NULL)
		return;

	/* ⚠ A SINGLE 32-BIT WRITE. The APIC's registers are 32 bits wide and a wider access to this page
	 * is undefined; the value is masked so a caller passing a 64-bit register image cannot silently
	 * write garbage into the reserved half. */
	*(volatile UINT32*)((UINT8*)Mmio + APIC_MMIO_LVT_PMI) = (UINT32)(Value & 0xFFFFFFFFull);
}

/* Is EITHER route to the LVT PC available on this core? Used to tell "no way to reach the register"
 * apart from "reached it and the write did not stick", which are different repairs. */
static BOOLEAN
TraceLvtPcReachable(
	void
	)
{
	return ((__readmsr(IA32_APIC_BASE) & APIC_BASE_X2APIC_ENABLE) != 0) || (gApicMmio != NULL);
}

/*
 * ⚠⚠ EVERY MACHINE-WIDE PMI RESOURCE RELEASED IN ONE PLACE, AND THERE ARE TWO CALLERS.
 *
 * PMI mode acquires two things that outlive a single core: the NMI callback registration and, in xAPIC
 * mode, the APIC page mapping. They are released on the disarm path AND on the failed-arm path -- two
 * sites, which is exactly the arrangement that produced a permanent handle leak in the file-capture
 * worker this same day: five closes were consolidated to one site, then a second resource was added
 * whose owner stayed outside it, and the symptom was not a handle count but a file that would not
 * delete (an earlier finding).
 *
 * The lesson recorded there was to enumerate the OWNERS rather than the exit paths. So both owners are
 * named here, once, and neither caller gets to list them itself.
 *
 * ⚠ THE ORDER IS LOAD-BEARING. The NMI handler's re-unmask reads gApicMmio; KeDeregisterNmiCallback
 * waits for in-flight callbacks to finish. Deregister first and no handler can be inside that read.
 * Unmap first and the page is torn out from under a callback at NMI level, where nothing catches a
 * fault. This is the reason the function exists rather than two tidy lines at each site.
 *
 * PASSIVE_LEVEL only -- both APIs require it.
 */
/*
 * ⚠⚠ DOES ANY CORE STILL HAVE ITS LVT PC POINTED AT NMI? Derived from HARDWARE-OWNERSHIP STATE, not
 * from a list of features -- and that distinction is the whole bug this closes.
 *
 * LvtPcValid is set by TracePmiArmHere and cleared only when the last owner restores the entry, so it
 * answers "can this core still deliver an NMI to our handler" for EVERY consumer at once: PT's ToPA
 * counter, the sampling profiler, and the PEBS CR3 filter. A new fourth consumer is covered the day
 * it is written, because it necessarily goes through the same arm path.
 *
 * ⚠ THE CHECK IT REPLACES ASKED ABOUT PT ONLY (`gTrace[i].ArmFlags & NXC_TRACE_ARM_PMI`), and I
 * ADDED PEBS AS A THIRD CONSUMER WITHOUT UPDATING IT. With the PEBS filter armed, a `sample disarm`
 * saw "PT does not want it" and released the shared plumbing -- deregistering the NMI callback while
 * PEBS still had LVT PC set to NMI and PMC0 counting. The next overflow delivered an NMI that nothing
 * on the machine claimed, which is bugcheck 0x80 by definition.
 *
 * This is the SECOND time this file has been bitten by exactly this shape
 * (an earlier finding -- "a second resource was added
 * whose owner stayed outside it"). The comment above TracePmiReleaseAll already said to enumerate the
 * OWNERS rather than the exit paths; a feature-name test is not enumerating owners, it is a list that
 * silently drops the next one added. State cannot drift; a list can.
 */
static BOOLEAN
TracePmiAnyCoreHoldsLvt(
	void
	)
{
	for (UINT32 i = 0; i < NXC_MAX_TRACE_CPUS; i++)
	{
		if (gTrace[i].LvtPcValid != 0)
			return TRUE;
	}
	return FALSE;
}

static void
TracePmiReleaseAll(
	void
	)
{
	/*
	 * ⚠⚠ FAIL CLOSED. Releasing the callback while any core can still raise a PMI as an NMI is the
	 * 0x80 generator, so the plumbing is KEPT when that is true -- a leaked registration until module
	 * unload is harmless, an unclaimed NMI bugchecks the machine. Refusing to release is the safe
	 * direction and this is the one place that has to know it.
	 */
	if (TracePmiAnyCoreHoldsLvt())
	{
		TrcLog("trace: NOT releasing the APIC mapping -- a core still has LVT PC on NMI delivery.\n");
		return;
	}

	/*
	 * ⚠⚠ THE NMI CALLBACK IS **NOT** DEREGISTERED HERE ANY MORE, AND THAT IS THE FIX, NOT AN
	 * OVERSIGHT.
	 *
	 * It is registered once at driver init and stays for the life of the module. Deregistering it
	 * was the thing that made an unclaimed NMI possible at all: every "is anyone still using this"
	 * test is a chance to be wrong, and this file has now been wrong twice -- once when the sampling
	 * profiler was added and once when I added the PEBS filter as a third consumer. A permanent
	 * registration cannot be wrong, because there is no decision left to make.
	 *
	 * The cost is one callback registration until unload. The cost of the alternative is a bugcheck.
	 *
	 * It also gives the NMI OBSERVER above something to observe with nothing armed -- which is the
	 * only state in which the crashes we are chasing actually happen.
	 */

	if (gApicMmio != NULL)
	{
		MmUnmapIoSpace(gApicMmio, 0x1000);
		gApicMmio   = NULL;
		gApicMmioPa = 0;
	}
}

/*
 * THE NMI HANDLER. Runs at NMI level: no locks, no allocation, no logging, nothing that can fault.
 *
 * ⚠ IT CLASSIFIES BEFORE IT CLAIMS, and the ORDER of the three tests is the point. This machine
 * runs other things that raise NMIs, and the #DB work already proved on hardware what happens when
 * a shared trap is claimed indiscriminately -- the fork run showed exactly one foreign
 * #DB correctly passed through against sixteen claimed. Same discipline, different vector:
 *
 *   1. is this core one WE armed, in PMI mode?   -- ours to look at at all
 *   2. does bit 55 say a ToPA region FILLED?     -- hardware's own statement of the cause
 *   3. only then claim it.
 *
 * Failing any test returns `Handled` UNCHANGED, which passes the NMI to whoever comes next exactly
 * as if we were not registered. Returning FALSE would be wrong for a different reason: it would
 * discard a preceding handler's claim.
 */
/* Defined beside gPebs, ~1000 lines below -- the array and its type are declared there and this
 * callback is above them. That ordering is why the original needed a forward-declared helper too,
 * so step A necessarily bundles the state read WITH the forward call. If A crashes, splitting
 * those two is the next cut. */
static BOOLEAN PebsDsLive(_In_ ULONG Cpu);
static BOOLEAN PebsPmiJudge(_In_ ULONG Cpu, _In_ UINT64 GlobalStatus);

/* ---------------------------------------------------------------------------------------------
 * NMI OBSERVER -- because eleven bugcheck 0x80s produced no evidence about the NMI itself.
 *
 * 0x80 means "an NMI arrived and nothing claimed it". Every dump says that and NOTHING says WHICH
 * NMI, from where, or what the PMU looked like at the time -- `!analyze` reports `GenuineIntel.sys`,
 * which is the placeholder for "attributed to the processor". Eleven crashes, no data. So the
 * driver records it instead of the dump.
 *
 * ⚠ THIS RUNS ON EVERY NMI ON THE MACHINE, INCLUDING WHEN NOTHING IS ARMED. That is the entire
 * point: the crashes that matter happened with nothing armed, which is exactly the case the old
 * callback returned from before reading anything.
 *
 * NMI-LEVEL RULES OBSERVED: no locks, no allocation, no logging, nothing that can fault. The ring
 * is a fixed static array with an interlocked write index; every value comes from an MSR read or a
 * null-checked APIC read, both of which are safe here.
 * ------------------------------------------------------------------------------------------- */
/* The record and its flags live in NexusCommand.h so the kernel that WRITES them and the usermode
 * that PRINTS them cannot drift. Aliased, not copied. */
#define NXC_NMIOBS_PT_LIVE      NXCMD_NMIOBS_PT_LIVE
#define NXC_NMIOBS_SAMPLE_LIVE  NXCMD_NMIOBS_SAMPLE_LIVE
#define NXC_NMIOBS_PEBS_LIVE    NXCMD_NMIOBS_PEBS_LIVE
#define NXC_NMIOBS_CLAIMED      NXCMD_NMIOBS_CLAIMED
#define NXC_NMIOBS_CAUGHT       NXCMD_NMIOBS_CAUGHT
#define NXC_NMI_OBS_RING        NXCMD_NMI_OBS_RING

typedef NXCMD_NMI_OBS NXC_NMI_OBS;

static NXC_NMI_OBS     gNmiObs[NXC_NMI_OBS_RING];
static volatile LONG64 gNmiObsWrite   = 0;   /* monotonic; & (RING-1) indexes */
static volatile LONG64 gNmiObsTotal   = 0;   /* every NMI seen                */
static volatile LONG64 gNmiObsUnclaim = 0;   /* nobody claimed -> a 0x80 candidate */
static volatile LONG   gNmiCatch      = 0;   /* DIAGNOSTIC opt-in; see below  */

static BOOLEAN TracePmiNmiCallbackInner(_In_opt_ void* Context, _In_ BOOLEAN Handled);

static BOOLEAN
TracePmiNmiCallback(
	_In_opt_ void*   Context,
	_In_     BOOLEAN Handled
	)
{
	CONST ULONG ObsCpu = KeGetCurrentProcessorNumberEx(NULL);

	/* Snapshot BEFORE the real handler runs -- it clears overflow bits and re-unmasks the LVT, so
	 * reading afterwards would report the state we just created rather than the one that arrived. */
	CONST UINT64 ObsStatus = __readmsr(IA32_PERF_GLOBAL_STATUS);
	CONST UINT64 ObsLvt    = TraceLvtPcRead();
	CONST UINT64 ObsDbgCtl = __readmsr(IA32_DEBUGCTL);
	CONST UINT64 ObsTsc    = __rdtsc();
	CONST UINT64 ObsCr3    = __readcr3();   /* RAW -- masking is a suspect, see NXCMD_NMI_OBS */

	UINT32 ObsFlags = 0;
	if (ObsCpu < NXC_MAX_TRACE_CPUS)
	{
		if (gTrace[ObsCpu].Armed != 0 && (gTrace[ObsCpu].ArmFlags & NXC_TRACE_ARM_PMI) != 0)
			ObsFlags |= NXC_NMIOBS_PT_LIVE;
		if (PebsDsLive(ObsCpu))
			ObsFlags |= NXC_NMIOBS_PEBS_LIVE;
	}
	if (InterlockedCompareExchange(&gSampleArmed, 1, 1) == 1)
		ObsFlags |= NXC_NMIOBS_SAMPLE_LIVE;

	InterlockedIncrement64(&gNmiObsTotal);

	BOOLEAN Result = TracePmiNmiCallbackInner(Context, Handled);
	if (Result)
		ObsFlags |= NXC_NMIOBS_CLAIMED;

	/*
	 * ⚠⚠ DIAGNOSTIC CATCH -- OFF BY DEFAULT, AND IT IS NOT A FIX.
	 *
	 * With it on, an NMI nobody claimed is claimed HERE so the machine survives and the record below
	 * can actually be read. That SUPPRESSES a real bugcheck 0x80, which is exactly the kind of
	 * fake-success this project bans -- so it is opt-in, it is counted separately as CAUGHT rather
	 * than folded into anything, and `nmi status` leads with a warning whenever it is enabled. It
	 * exists because a bugcheck destroys the evidence about itself: eleven of them taught us nothing
	 * about the NMI, and the only way to read the state is to still be running.
	 */
	if (!Result)
	{
		InterlockedIncrement64(&gNmiObsUnclaim);
		if (InterlockedCompareExchange(&gNmiCatch, 1, 1) == 1)
		{
			ObsFlags |= NXC_NMIOBS_CAUGHT;
			Result = TRUE;
		}
	}

	{
		CONST LONG64 Slot = InterlockedIncrement64(&gNmiObsWrite) - 1;
		NXC_NMI_OBS* CONST R = &gNmiObs[(ULONG)(Slot & (LONG64)(NXC_NMI_OBS_RING - 1u))];
		R->Tsc          = ObsTsc;
		R->GlobalStatus = ObsStatus;
		R->LvtPc        = ObsLvt;
		R->DebugCtl     = ObsDbgCtl;
		R->Cr3          = ObsCr3;
		R->Cpu          = (UINT32)ObsCpu;
		R->Flags        = ObsFlags;
	}

	return Result;
}

static BOOLEAN
TracePmiNmiCallbackInner(
	_In_opt_ void*   Context,
	_In_     BOOLEAN Handled
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return Handled;

	/*
	 * ⚠ TWO INDEPENDENT CONSUMERS, SO THE GATE IS AN **OR**. This read `PT armed with PMI on this
	 * core`, which was right while the ToPA fill counter was the only cause -- and would have
	 * rejected EVERY sampling NMI on a machine where PT was not armed at all, i.e. the normal case
	 * for a profiling run. Caught while adding the second consumer rather than on hardware.
	 */
	CONST BOOLEAN PtPmiLive  = (gTrace[Cpu].Armed != 0) &&
	                           ((gTrace[Cpu].ArmFlags & NXC_TRACE_ARM_PMI) != 0);
	CONST BOOLEAN SampleLive = (InterlockedCompareExchange(&gSampleArmed, 1, 1) == 1);

	/*
	 * ⚠⚠ BISECT STEP A. HALF OF THE SUSPECT DIFF, ON ITS OWN.
	 *
	 * Four bugcheck 0x80s came from restoring the PEBS PMI filter, and the only restored code that
	 * runs with nothing armed is TWO independent additions to this callback:
	 *
	 *   A  this read of per-CPU PEBS state added to the early-out condition   <-- THIS BUILD
	 *   B  a PebsPmiJudge() call inserted before the return-Handled path      <-- NOT in this build
	 *
	 * Testing them together is what made four crashes uninformative. A alone is decisive: crash and
	 * it is this; survive and it is B. No kernel debugger, no new APIs, no dump parsing -- the build
	 * identity IS the experiment.
	 *
	 * Deliberately inlined rather than calling a helper defined ~1000 lines below, so this step tests
	 * ⚠ gPebs and its type are declared ~1000 lines BELOW this callback, so the read cannot be
	 * inlined here -- which is exactly why the original needed a forward-declared helper. Step A
	 * therefore necessarily bundles the STATE READ with the FORWARD CALL. If A crashes, splitting
	 * those two (by relocating the declaration) is the next cut.
	 */
	CONST BOOLEAN PebsLive = PebsDsLive((ULONG)Cpu);

	if (!PtPmiLive && !SampleLive && !PebsLive)
		return Handled;

	CONST UINT64 GStatus = __readmsr(IA32_PERF_GLOBAL_STATUS);

	/*
	 * ⚠ TWO CAUSES SHARE THIS ONE INTERRUPT, AND THEY ARE CLASSIFIED SEPARATELY. LVT PC is a single
	 * per-core register, so the ToPA fill counter and the sampling profiler necessarily arrive
	 * through the same NMI. IA32_PERF_GLOBAL_STATUS says which -- bit 55 for a ToPA region fill,
	 * bit 32 for fixed counter 0 overflowing. Both can be set in one delivery, so both are tested;
	 * an `else` here would silently drop whichever lost the race.
	 */
	if ((GStatus & PERF_GLOBAL_FIXED0_OVF) != 0 && InterlockedCompareExchange(&gSampleArmed, 1, 1) == 1)
	{
		/*
		 * The LBR top entry is the last RING-3 branch. Our own ring-0 path cannot be in it -- see
		 * the block above SampleArm; that is measured, not assumed.
		 */
		CONST UINT64 Cr3Now = SampleCr3Frame(__readcr3());
		CONST UINT64 Want   = gSampleCr3;

		if (Want == 0 || Want == Cr3Now)
		{
			CONST LONG Slot = InterlockedIncrement(&gSampleWrite) - 1;
			NXC_SAMPLE* CONST S = &gSampleRing[(ULONG)Slot & (NXC_SAMPLE_RING - 1u)];
			S->LbrFrom   = __readmsr(IA32_LBR_FROM_IP_0);
			S->LbrTo     = __readmsr(IA32_LBR_TO_IP_0);
			S->Cr3       = Cr3Now;
			S->Cpu       = (UINT32)Cpu;
			S->Reserved0 = 0;

			/* ⚠ THE RING OVERWRITES, AND SAYS SO. A profile that silently dropped samples would
			 * understate exactly the hot code it exists to find. */
			if ((ULONG)Slot >= NXC_SAMPLE_RING)
				InterlockedIncrement(&gSampleLost);
		}

		/* Reload for the next N events, then clear the overflow. Order matters: clearing first
		 * would leave a window where the counter is at 0 and free-running. */
		__writemsr(IA32_FIXED_CTR0, (0ULL - gSamplePeriod) & FIXED_CTR_WIDTH_MASK);
		__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_FIXED0_OVF);

		CONST UINT64 LvtS = TraceLvtPcRead();
		if ((LvtS & LVT_MASKED) != 0)
			TraceLvtPcWrite(LvtS & ~LVT_MASKED);

		if ((GStatus & PERF_GLOBAL_TOPA_PMI) == 0)
			return TRUE;
	}

	/*
	 * PEBS PMI CR3 FILTERING. Third cause sharing this one interrupt, classified by its own
	 * GLOBAL_STATUS bit (PMC0 overflow) exactly as the two above are -- and tested rather than
	 * `else`d for the same reason: a PMC0 overflow and a ToPA fill can arrive in one delivery.
	 */
	if (PebsPmiJudge((ULONG)Cpu, GStatus))
	{
		if ((GStatus & PERF_GLOBAL_TOPA_PMI) == 0)
			return TRUE;
	}

	if ((GStatus & PERF_GLOBAL_TOPA_PMI) == 0)
		return Handled;

	gTrace[Cpu].WrapPmi++;

	/* Clear the cause. Leaving it set means the next PMI on this core cannot be distinguished from
	 * this one, and a level-sensitive re-assert would loop. */
	__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_TOPA_PMI);

	/*
	 * ⚠ RE-UNMASK. THE HARDWARE MASKS THIS ENTRY WHEN IT DELIVERS, so without this line exactly ONE
	 * fill is ever counted and every wrap after the first is silently lost -- a counter that reads 1
	 * forever and looks like a buffer that wrapped once. Both reference implementations do this and
	 * neither explains why; the SDM's LVT description is where it comes from.
	 */
	CONST UINT64 Lvt = TraceLvtPcRead();
	if ((Lvt & LVT_MASKED) != 0)
		TraceLvtPcWrite(Lvt & ~LVT_MASKED);

	return TRUE;
}

/*
 * Point this core's LVT PC at the NMI vector, saving what was there. Runs at IPI_LEVEL inside the
 * arm broadcast, on the core it configures -- the LVT is per-LOCAL-APIC, so it cannot be done from
 * the calling core any more than the RTIT MSRs can.
 *
 * ⚠ WORKS IN BOTH APIC MODES, AND THE FIRST VERSION DID NOT. It began as "x2APIC only" with xAPIC
 * refused, on the reasoning that reaching an MMIO LVT means mapping physical memory from inside an
 * IPI callback at IPI_LEVEL -- MmMapIoSpace being PASSIVE-only, on a project that has frozen this
 * host twice pointing that API at the wrong thing
 * (an earlier finding).
 *
 * Every clause of that was true and the conclusion was still wrong. The obstacle was WHERE the
 * mapping happened, not whether it could: NxcTraceArm runs at PASSIVE, maps the one page there, and
 * hands the cores a pointer. What remained was a refusal that named a limit instead of removing it,
 * which is precisely what an earlier finding is about -- and the
 * safety rule it invoked says never MmMapIoSpace on system RAM, while the local APIC page is a
 * device register page and exactly what that API exists for.
 */
static UINT32
TracePmiArmHere(
	_Inout_ NXC_TRACE_CPU* T,
	_In_    UINT32         Owner        /* NXC_LVTPC_OWNER_* -- who is claiming the entry */
	)
{
	if (!TraceLvtPcReachable())
		return NXC_TRACE_PMIWHY_NO_X2APIC;   /* xAPIC AND the mapping failed -- see PmiWhy */

	/*
	 * ⚠ ALREADY OURS -- TAKE A REFERENCE, DO NOT SAVE AGAIN. Saving here a second time would
	 * capture the FIRST owner's NMI value as "what was here before", and the eventual restore would
	 * put NMI delivery back permanently with nothing claiming it. See NXC_LVTPC_OWNER_* in Trace.h.
	 */
	if (T->LvtPcValid != 0)
	{
		T->LvtPcOwners |= Owner;
		return NXC_TRACE_PMIWHY_LIVE;
	}

	T->LvtPcSaved  = TraceLvtPcRead();
	T->LvtPcValid  = 1;
	T->LvtPcOwners = Owner;

	TraceLvtPcWrite(LVT_PMI_NMI_VALUE);

	/*
	 * ⚠ READ BACK, for the same reason the RTIT arm does: a write that did not take would surface
	 * much later as "the wrap counter is 0", with nothing pointing here. Check the two fields that
	 * matter rather than the whole register -- the vector field is ignored in NMI mode and hardware
	 * is free to report it as anything.
	 */
	CONST UINT64 Got = TraceLvtPcRead();
	if ((Got & LVT_DELIVERY_MASK) != LVT_DELIVERY_NMI || (Got & LVT_MASKED) != 0)
	{
		TraceLvtPcWrite(T->LvtPcSaved);
		T->LvtPcValid  = 0;
		T->LvtPcOwners = 0;
		return NXC_TRACE_PMIWHY_LVT_READBACK;
	}

	/* A bit 55 left set by anything earlier would make the first NMI look like our fill. */
	__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_TOPA_PMI);
	return NXC_TRACE_PMIWHY_LIVE;
}

/* Put back exactly what was displaced. The counterpart to the block above, and the reason this
 * approach is reversible where the reference implementations' is not. */
static void
TracePmiDisarmHere(
	_Inout_ NXC_TRACE_CPU* T,
	_In_    UINT32         Owner        /* NXC_LVTPC_OWNER_* -- who is letting go */
	)
{
	if (T->LvtPcValid == 0)
		return;

	/*
	 * ⚠ THE LAST OWNER RESTORES, NOT THE FIRST ONE OUT. Dropping this reference while the other
	 * feature is still generating PMIs would point LVT PC back at its original vector with our
	 * NMI-delivered interrupts still arriving -- unclaimed, which is a bugcheck 0x80. The three
	 * 0x80s this file already carries were a different cause, and that is exactly why this one is
	 * worth closing before it can be confused with them.
	 */
	T->LvtPcOwners &= ~Owner;
	if (T->LvtPcOwners != 0)
		return;

	/* ⚠ NOT GATED ON THE APIC MODE HERE. The helper re-derives it, so a core that somehow armed via
	 * one route cannot be restored via the other -- and a mode check duplicated at this site would be
	 * the second source of truth the helper exists to prevent. */
	TraceLvtPcWrite(T->LvtPcSaved);
	__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_TOPA_PMI);

	T->LvtPcValid = 0;
}

/*
 * PASSIVE-LEVEL PREPARATION FOR ANY NMI-DELIVERED PMI. Returns non-zero when a core may safely
 * point its LVT PC at NMI delivery; 0 means it must not.
 *
 * ⚠ BOTH STEPS ARE PASSIVE-ONLY AND MUST HAPPEN BEFORE THE IPI BROADCAST. MmMapIoSpace and
 * KeRegisterNmiCallback cannot run at IPI_LEVEL, which is where every ArmOnEachCpu executes. And
 * "before" is not stylistic: the first PMI can arrive microseconds after the counter is enabled, so
 * registering afterwards arms a core whose interrupt has nowhere to go -- an NMI nothing on this
 * machine claims, which is a bugcheck 0x80.
 *
 * ⚠ SHARED, NOT COPIED. This was inline in NxcTraceArm while PT was the only caller. The PEBS CR3
 * filter needs the identical two steps, and two copies of a resource acquisition that must agree is
 * the shape this codebase keeps finding broken
 * (an earlier finding). The callback registration is
 * idempotent by the gNmiHandle guard, so N features calling this still install exactly one.
 */
static UINT32
TracePmiPrepare(void)
{
	/*
	 * ⚠ THE xAPIC MAPPING, HERE AND NOWHERE ELSE, BECAUSE HERE IS PASSIVE.
	 *
	 * In x2APIC mode the LVT PC is MSR 0x834 and none of this runs. In xAPIC mode it is a register
	 * in the local APIC's MMIO page, and mapping that page is a PASSIVE-only operation -- which is
	 * why the first version of this code REFUSED xAPIC rather than supporting it. The refusal was
	 * about where the mapping could happen, not whether it could.
	 *
	 * The physical address comes from IA32_APIC_BASE[51:12] -- the CPU stating where its own local
	 * APIC lives. It is not a caller-supplied address and cannot be aimed elsewhere, which is the
	 * property that separates this from the arbitrary physical mapping that froze this host twice.
	 * One page, MmNonCached, released in NxcTraceDisarm.
	 */
	if (gApicMmio == NULL &&
	    (__readmsr(IA32_APIC_BASE) & APIC_BASE_X2APIC_ENABLE) == 0)
	{
		PHYSICAL_ADDRESS ApicPa;
		ApicPa.QuadPart = (LONGLONG)(__readmsr(IA32_APIC_BASE) & 0x000FFFFFFFFFF000ULL);

		if (ApicPa.QuadPart != 0)
		{
			gApicMmioPa = (UINT64)ApicPa.QuadPart;
			gApicMmio   = MmMapIoSpace(ApicPa, 0x1000, MmNonCached);
			TrcLog("trace: xAPIC mode -- mapped the local APIC page at PA 0x%llX -> %p\n",
			       (ULONG64)ApicPa.QuadPart, gApicMmio);
		}
		else
		{
			TrcLog("trace: xAPIC mode and IA32_APIC_BASE reports no base -- PMI unavailable\n");
		}
	}

	/* ⚠ ONCE, GUARDED. A second registration without an intervening deregister would stack a second
	 * callback and double every count. Normally already done by NxcTraceNmiInit at driver init;
	 * this stays as the fallback so an arm still works if init could not register. */
	if (gNmiHandle == NULL)
		gNmiHandle = KeRegisterNmiCallback((PVOID)TracePmiNmiCallback, NULL);

	return (gNmiHandle != NULL) ? 1u : 0u;
}

/*
 * REGISTER THE NMI CALLBACK FOR THE LIFE OF THE DRIVER. Called from DriverEntry.
 *
 * ⚠ WHY AT INIT RATHER THAN AT ARM. Two reasons, and the second is why it is worth a boot.
 *
 * 1. It removes the deregistration decision entirely, and that decision is what produced bugcheck
 *    0x80 here: the callback was released while a core still had LVT PC pointed at NMI. The check
 *    guarding it was wrong twice -- once when the sampling profiler became a second consumer, once
 *    when I made the PEBS filter a third. There is nothing left to get wrong.
 *
 * 2. It lets the NMI OBSERVER see NMIs THAT ARRIVE WITH NOTHING ARMED -- which is precisely the
 *    state every crash under investigation occurred in, and precisely the state the old per-arm
 *    registration could not observe. Eleven bugchecks produced no evidence about the NMI itself
 *    because nothing of ours was listening when it happened.
 *
 * Failure is non-fatal and reported: without it PMI arming still registers on demand, and the
 * observer simply sees nothing rather than lying about it.
 */
void
NxcTraceNmiInit(
	void
	)
{
	if (gNmiHandle != NULL)
		return;

	gNmiHandle = KeRegisterNmiCallback((PVOID)TracePmiNmiCallback, NULL);
	if (gNmiHandle == NULL)
		TrcLog("trace: KeRegisterNmiCallback FAILED at init -- NMI observation is unavailable this "
		       "boot, and `nmi status` will report zero because nothing is listening, NOT because "
		       "no NMI arrived.\n");
	else
		TrcLog("trace: NMI observer registered for the life of the driver.\n");
}

/* Read the observer. EVIDENCE, never a verdict (D6): counts plus the raw MSR values seen. */
void
NxcNmiObserveStats(
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutUnclaimed,
	_Out_ UINT32* OutCatchOn,
	_Out_ UINT32* OutRegistered
	)
{
	*OutTotal      = (UINT64)gNmiObsTotal;
	*OutUnclaimed  = (UINT64)gNmiObsUnclaim;
	*OutCatchOn    = (InterlockedCompareExchange(&gNmiCatch, 1, 1) == 1) ? 1u : 0u;
	*OutRegistered = (gNmiHandle != NULL) ? 1u : 0u;
}

/* Copy the ring out, oldest first. Returns how many records exist. */
UINT32
NxcNmiObserveDrain(
	_Out_writes_(Cap) NXC_NMI_OBS* Out,
	_In_  UINT32      Cap,
	_Out_ UINT64*     OutTotal
	)
{
	*OutTotal = (UINT64)gNmiObsTotal;
	if (Out == NULL || Cap == 0)
		return 0;

	CONST LONG64 Written = gNmiObsWrite;
	CONST UINT32 Have    = (Written >= (LONG64)NXC_NMI_OBS_RING)
	                       ? NXC_NMI_OBS_RING : (UINT32)Written;
	CONST UINT32 Give    = (Have < Cap) ? Have : Cap;

	/* Oldest first: start at Written-Have and walk forward. */
	for (UINT32 i = 0; i < Give; i++)
	{
		CONST LONG64 Idx = Written - (LONG64)Have + (LONG64)i;
		Out[i] = gNmiObs[(ULONG)(Idx & (LONG64)(NXC_NMI_OBS_RING - 1u))];
	}
	return Give;
}

/* DIAGNOSTIC ONLY. See the block in the callback -- this SUPPRESSES a real bugcheck. */
void
NxcNmiSetCatch(
	_In_ UINT32 On
	)
{
	InterlockedExchange(&gNmiCatch, (On != 0) ? 1 : 0);
	TrcLog("trace: NMI diagnostic catch %s\n", (On != 0) ? "ENABLED -- 0x80 is being SUPPRESSED" : "disabled");
}

/* Per-core sampling arm/disarm, run inside an IPI broadcast on the core it configures. The PMU
 * counters are per-logical-processor exactly like the RTIT MSRs. */
static ULONG_PTR
SampleArmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	CONST UINT32 Enable = (UINT32)Context;

	if (Enable == 0)
	{
		/* ⚠ STOP COUNTING BEFORE UNMASKING ANYTHING ELSE. Leaving the counter enabled while the
		 * handler stops recording would keep taking NMIs nothing consumes. */
		__writemsr(IA32_PERF_GLOBAL_CTRL,
		           __readmsr(IA32_PERF_GLOBAL_CTRL) & ~PERF_GLOBAL_FIXED0_EN);
		__writemsr(IA32_FIXED_CTR_CTRL,
		           __readmsr(IA32_FIXED_CTR_CTRL) & ~0xFULL);
		__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_FIXED0_OVF);

		/*
		 * ⚠ A GUARD, NOT A MODULO. This was `gTrace[KeGetCurrentProcessorNumberEx(NULL) %
		 * NXC_MAX_TRACE_CPUS]` -- the only modulo of its kind in this file, while the arm branch
		 * below and every other per-CPU IPI handler (`ArmOnEachCpu`, `DisarmOnEachCpu`,
		 * `PebsArmOnEachCpu`) all use `>= NXC_MAX_TRACE_CPUS -> return 0`.
		 *
		 * Unreachable on this machine (24 LPs, and 24 % 64 == 24), so it has never misfired. It is
		 * corrected anyway because of WHAT it would do above 64 LPs: wrap into ANOTHER core's slot
		 * and release that core's LVT PC ownership, while `TraceLvtPcWrite` restores the saved
		 * value onto the LOCAL apic. That leaves one core's LVT pointing at NMI delivery with its
		 * ownership already cleared -- the exact unclaimed-NMI shape that produced the 0x80 hunt.
		 * A silent wrap is the same class as the flag mask that silently dropped new flags.
		 */
		CONST ULONG DCpu = KeGetCurrentProcessorNumberEx(NULL);
		if (DCpu >= NXC_MAX_TRACE_CPUS)
			return 0;

		TracePmiDisarmHere(&gTrace[DCpu], NXC_LVTPC_OWNER_SAMPLE);
		return 0;
	}

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return 0;

	/*
	 * ⚠⚠ LBR MUST ALREADY BE ENABLED ON THIS CORE, AND THIS CHECK EXISTS BECAUSE ITS ABSENCE
	 * PRODUCED A PERFECT SILENT PARTIAL ON HARDWARE.
	 *
	 * The handler reports WHERE the target was by reading IA32_LBR_FROM_IP_0. With IA32_LBR_CTL.EN
	 * clear that MSR reads 0 -- so the first run took 197,814 samples, reported every one of them
	 * as taken (which was TRUE, the counter really did overflow that many times), and every single
	 * address was NULL. The histogram printed "0 distinct pages in 4096 samples" and nothing said
	 * why. A count that is honest about itself while the payload is empty is exactly the shape this
	 * codebase keeps finding.
	 *
	 * ⚠ REFUSED, NOT AUTO-ARMED. Arming LBR here would fight `lbr arm`'s own state -- two owners of
	 * one per-core facility, where whichever disarmed last would silently stop the other. The caller
	 * is told what to run instead.
	 */
	if ((__readmsr(IA32_LBR_CTL) & LBR_CTL_EN) == 0)
	{
		InterlockedIncrement(&gSampleNoLbr);
		return 0;
	}

	if (TracePmiArmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_SAMPLE) != NXC_TRACE_PMIWHY_LIVE)
		return 0;   /* no route to the LVT PC on this core -- it simply does not sample */

	InterlockedIncrement(&gSampleCores);

	/*
	 * USR only, OS deliberately clear. Two reasons, and the second is the load-bearing one:
	 * the target's own execution is what a profile is for, and counting ring 0 would include the
	 * NMI handler this very counter triggers -- a feedback loop that samples itself.
	 */
	__writemsr(IA32_PERF_GLOBAL_CTRL,
	           __readmsr(IA32_PERF_GLOBAL_CTRL) & ~PERF_GLOBAL_FIXED0_EN);
	__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_FIXED0_OVF);
	__writemsr(IA32_FIXED_CTR0, (0ULL - gSamplePeriod) & FIXED_CTR_WIDTH_MASK);
	__writemsr(IA32_FIXED_CTR_CTRL,
	           (__readmsr(IA32_FIXED_CTR_CTRL) & ~0xFULL) | FIXED_CTR0_USR | FIXED_CTR0_PMI);
	__writemsr(IA32_PERF_GLOBAL_CTRL,
	           __readmsr(IA32_PERF_GLOBAL_CTRL) | PERF_GLOBAL_FIXED0_EN);
	return 0;
}

typedef struct _NXC_ARM_CTX
{
	UINT64          Cr3Filter;
	UINT32          OnlyCpu;
	UINT32          ArmFlags;
	/* Address-range filters, already validated by the caller. RangeCount is what the CALLER asked
	 * for; each core still refuses what ITS OWN CPUID says it cannot do -- see ArmOnEachCpu. */
	CONST NXCMD_PT_RANGE* Ranges;
	UINT32          RangeCount;
	volatile LONG   RangeRefused;   /* cores that took the trace but NOT the filters */
	/* Whether the NMI callback is registered. Without it a ToPA INT would raise an NMI that nothing
	 * on this machine claims, so INT is never set when this is 0 -- see the single expression that
	 * ties them together in ArmOnEachCpu. */
	UINT32          NmiOk;

	/*
	 * Timing + PTWRITE request (D117). Each is what the CALLER asked for; every core checks its OWN
	 * CPUID and refuses what it cannot do, exactly like RangeCount above.
	 *
	 * ⚠ 0xFF means "not requested". The 4-bit encodings have 0 as a MEANINGFUL VALUE -- MTCFreq 0 is
	 * a real divisor, CycThresh 0 is a real threshold -- so 0 cannot double as the unset sentinel.
	 * That exact mistake cost a hardware run on `trace alloc 0` earlier today: a valid value serving
	 * as "unset" silently substituted a default and reported the caller's own argument back at them.
	 * See an earlier finding.
	 */
	UINT32          WantTsc;        /* 0 or 1                                  */
	UINT32          MtcFreq;        /* 4-bit encoding, or 0xFF for not wanted  */
	UINT32          CycThresh;      /* 4-bit encoding, or 0xFF for not wanted  */
	UINT32          PsbFreq;        /* 4-bit encoding, or 0xFF for not wanted  */
	UINT32          WantPtw;        /* 0 or 1                                  */
	UINT32          WantFupOnPtw;   /* 0 or 1 -- pair a PTWRITE payload with its IP */
	/* 0 or 1 -- suppress TNT packets (RTIT_CTL.DisTNT). Trades conditional-branch detail for how
	 * much EXECUTION a fixed buffer can cover. Gated on CPUID.(14H,0).EBX[8], fail-closed. */
	UINT32          WantDisTnt;
	/* Which RINGS the trace records. Ring 0 is opt-in because it is self-polluting -- this
	 * driver's own code lands in the trace -- and because without an IP range filter it traces
	 * the whole kernel. CR3 filtering cannot scope kernel code: the kernel is mapped in every
	 * address space. */
	UINT32          WantUser;
	UINT32          WantOs;
	volatile LONG   TimingRefused;  /* cores that took the trace but NOT the timing request */

	volatile LONG   Armed;
	volatile LONG   Refused;
} NXC_ARM_CTX;

static NXC_ARM_CTX* volatile gArmCtx = NULL;

/**
 * Give back the LVT PC reference this core took, on any path that FAILS AFTER taking it.
 *
 * ⚠⚠ WITHOUT THIS, A REFUSED CORE HOLDS LVT PC ON NMI DELIVERY FOR THE LIFE OF THE DRIVER.
 *
 * `ArmOnEachCpu` claims the shared LVT PC early (`TracePmiArmHere`, OWNER_PT) but only sets
 * `gTrace[Cpu].Armed = 1` at the very END, after every capability and read-back check has passed.
 * `DisarmOnEachCpu` short-circuits on `if (Armed == 0) return 0;` -- deliberately, so it never
 * disturbs a foreign tracer. Those two facts combine badly: a core that claimed the LVT and then
 * failed a later check has `LvtPcValid = 1`, `LvtPcOwners = OWNER_PT`, `Armed = 0`, and NOTHING
 * can ever release it.
 *
 * The consequences run straight down the ownership plumbing this file exists to protect:
 *   - `TracePmiAnyCoreHoldsLvt()` stays TRUE, so `TracePmiReleaseAll` refuses to unmap the xAPIC
 *     page forever;
 *   - `LvtPcSaved` is never restored, so that core's LVT PC points at NMI delivery permanently --
 *     and any later PMU overflow there from ANY source is an NMI we decline. That is 0x80;
 *   - a later PEBS or Sample arm on the same core sees `LvtPcValid != 0`, takes the reference-only
 *     path, and when IT disarms, OWNER_PT is still set so the restore is skipped again.
 *
 * ⚠ THE LIKELY TRIGGER IS THE HYBRID PART, not an exotic failure: the timing-capability check
 * below reads CPUID.(14H,1) bitmaps that differ between P and E cores, so one timing request can
 * be accepted on P-cores and refused on E-cores -- leaking the reference on every E-core at once.
 *
 * Gated on LIVE because that is the only return value that actually took a reference.
 * of this file.
 */
static void
ArmReleaseLvtOnFailure(
	_In_ ULONG  Cpu,
	_In_ UINT32 PmiWhy
	)
{
	if (PmiWhy == NXC_TRACE_PMIWHY_LIVE && Cpu < NXC_MAX_TRACE_CPUS)
		TracePmiDisarmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PT);
}

static ULONG_PTR
ArmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	NXC_ARM_CTX* CONST Ctx = gArmCtx;
	if (Ctx == NULL)
		return 0;

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Ctx->OnlyCpu != 0xFFFFFFFFu && Cpu != Ctx->OnlyCpu)
		return 0;
	if (Cpu >= NXC_MAX_TRACE_CPUS || gTrace[Cpu].ToPaPa == 0)
		return 0;

	/*
	 * ⚠ CAPABILITY RE-CHECK ON THIS CORE. cpuprobe measured this earlier and on whatever core it
	 * happened to run -- this machine is hybrid, so that is not an answer about this one.
	 */
	int R[4];
	__cpuid(R, 0);
	if ((ULONG)R[0] < 0x14)
	{
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}
	__cpuidex(R, 7, 0);
	if ((R[1] & (1 << 25)) == 0)                 /* Intel PT present */
	{
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}
	__cpuidex(R, 0x14, 0);
	CONST BOOLEAN HasCr3Filter = (R[1] & (1 << 0)) != 0;
	CONST BOOLEAN HasToPa      = (R[2] & (1 << 0)) != 0;
	if (!HasToPa)
	{
		/* Without ToPA the only output form is a single contiguous region, which this stage did
		 * not allocate for. Refusing beats arming a mode the buffers were not built for. */
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	/*
	 * ⚠ CONTENTION, RE-CHECKED HERE rather than trusted from the probe. Ipt.sys can have started
	 * since. Arming over a live tracer would silently steal it -- and the theft would look like a
	 * corrupt trace to whoever owned it.
	 */
	if (__readmsr(IA32_RTIT_CTL) & RTIT_CTL_TRACEEN)
	{
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	/* 1. TraceEn to 0 first. Every other RTIT write below depends on it. */
	__writemsr(IA32_RTIT_CTL, 0);

	/* 2. A stale Error or Stopped bit stops the trace the instant it starts, silently. */
	__writemsr(IA32_RTIT_STATUS, 0);

	/*
	 * 2b. THE ToPA ENTRY'S OPTION BITS. Alloc deliberately left STOP and INT clear and said "stage 2
	 *     gets to choose them deliberately"; this is that choice, and it belongs here because both
	 *     are per-ARM decisions rather than properties of the allocation.
	 *
	 * ⚠ INT IS TIED TO THE LVT BEING LIVE BY ONE EXPRESSION, and that coupling is the whole safety
	 * argument. Setting INT while nothing catches the interrupt means the CPU raises an NMI on every
	 * region fill that no handler on this machine claims. The two facts therefore cannot be set
	 * separately: `Opt` gets TOPA_INT if and only if TracePmiArmHere returned LIVE on this very core.
	 * Two statements that must agree is the shape this codebase keeps finding broken
	 * (an earlier finding).
	 */
	UINT64* CONST Entry = (UINT64*)gTrace[Cpu].ToPaVa;
	if (Entry == NULL)
	{
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	UINT32 PmiWhy = NXC_TRACE_PMIWHY_NOT_REQUESTED;
	if ((Ctx->ArmFlags & NXC_TRACE_ARM_PMI) != 0)
		PmiWhy = (Ctx->NmiOk != 0) ? TracePmiArmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PT)
		                           : NXC_TRACE_PMIWHY_NO_CALLBACK;

	UINT64 Opt = 0;
	if ((Ctx->ArmFlags & NXC_TRACE_ARM_STOP) != 0)
		Opt |= TOPA_STOP;
	if (PmiWhy == NXC_TRACE_PMIWHY_LIVE)
		Opt |= TOPA_INT;

	Entry[0] = (Entry[0] & ~(TOPA_STOP | TOPA_INT)) | Opt;

	/*
	 * ⚠ WHAT WAS APPLIED, NOT WHAT WAS ASKED (D3). A core that could not take PMI mode still gets a
	 * perfectly good trace, so the arm is not refused over a counter -- but ArmFlags must then NOT
	 * claim PMI, or a WrapPmi of 0 would be indistinguishable from a region that never filled. The
	 * reason code carries the difference.
	 */
	/*
	 * ⚠ RESET AND CLASSIFY *BEFORE* TraceEn IS SET, NOT AFTER.
	 *
	 * These used to be written at the bottom of the function, after step 5 enabled tracing. At the
	 * measured 1.9 GB/s a 4 KB region fills in about two microseconds, so a ToPA fill interrupt can
	 * arrive between "tracing is on" and "ArmFlags says PMI is live" -- and the NMI handler checks
	 * exactly those fields to decide whether the interrupt is ours. It would have passed the first
	 * fill or two through as somebody else's rather than counting them.
	 *
	 * Passing through is the SAFE direction, so this was an undercount and never a wrong claim. It is
	 * still an undercount in the one counter whose entire purpose is being exact.
	 */
	TraceResetCounters(&gTrace[Cpu]);
	gTrace[Cpu].ArmFlags = (UINT32)((Opt & TOPA_STOP) ? NXC_TRACE_ARM_STOP : 0u)
	                     | (UINT32)((Opt & TOPA_INT)  ? NXC_TRACE_ARM_PMI  : 0u);
	gTrace[Cpu].PmiWhy   = PmiWhy;

	/* 3. Output. OUTPUT_MASK_PTRS = 0 means "ToPA entry 0, offset 0" -- a fresh trace from the
	 *    top of the table, which is exactly what we want and needs no bit arithmetic. */
	__writemsr(IA32_RTIT_OUTPUT_BASE, gTrace[Cpu].ToPaPa);
	__writemsr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);

	/*
	 * 4. CR3 filter.
	 *
	 * ⚠ THE COMPARISON IS ON BITS 63:12, NOT 63:5. This comment previously said 63:5, which is the
	 * PAE-paging rule; x64 Windows runs IA-32e paging, where the SDM is explicit:
	 *
	 *   "CR3 matches IA32_RTIT_CR3_MATCH if the two registers are identical for bits 63:12, or
	 *    63:5 when in PAE paging mode; the lower 5 bits of CR3 and IA32_RTIT_CR3_MATCH are ignored."
	 * -- SDM Vol 3C, Filtering by CR3. Confirmed against two independent copies.
	 *
	 * ⚠ SO THE PCID DOES NOT PARTICIPATE, and that is the answer to the question this machine
	 * raises. CR4.PCIDE is set on all 24 LPs here, so a live CR3 carries a context id in bits 11:0
	 * while the DirectoryTableBase we read out of EPROCESS does not. Under a 63:5 compare that
	 * mismatch would silently filter out the entire target -- armed, running, tracing nothing. Under
	 * the real 63:12 compare both sides' low bits are discarded and the frames match.
	 *
	 * The mask is therefore 11:0, matching what the hardware compares rather than merely what it
	 * refuses. Clearing only 4:0 (enough to avoid the #GP on reserved bits) would leave bits 11:5 in
	 * a field the CPU ignores here but does NOT ignore under PAE -- a value that is right for the
	 * wrong reason. Masking to the compared width makes the register say what it means.
	 *
	 * TIER 1 (reference material): Cheat Engine's ultimap2.c writes the RAW CR3 and catches the #GP,
	 * falling back to `& 0xFFFFFFFFFFFFF000` -- the same 63:12 value, arrived at by exception rather
	 * than by reading the rule. There is no SEH in this driver, so the fallback path does not exist
	 * for us and the mask has to be right the first time.
	 */
	/*
	 * ---- RING SELECTION (D120) --------------------------------------------------------------
	 *
	 * ⚠ THIS WAS `| RTIT_CTL_USER` UNCONDITIONALLY -- PT COULD NOT TRACE RING 0 AT ALL.
	 * `RTIT_CTL_OS` was defined and referenced by a guard, and NOTHING EVER SET IT.
	 *
	 * The requirement is explicit: the target's usermode modules are the near-term
	 * focus, but it also loads a KERNEL DRIVER -- 70 MB, and reportedly where the interesting
	 * behaviour lives. Tracing that needs ring 0, so a usermode-only tracer is not sufficient for
	 * the actual target of this project.
	 *
	 * ⚠ RING 0 IS SELF-POLLUTING BY CONSTRUCTION, which is why it is OPT-IN. With .OS set, this
	 * driver's own code -- the arm path, the PMI handler, every interrupt that lands mid-capture --
	 * is in the trace alongside the target. Same reasoning `lbr arm --kernel` already carries.
	 *
	 * ⚠ AND CR3 FILTERING DOES NOT SCOPE KERNEL CODE. The kernel is mapped into every address
	 * space, so a CR3 filter cannot isolate one driver. The tool for ring-0 scoping is the IP RANGE
	 * filter -- `--filter <driver_base>-<driver_end>` -- which is verified working. Ring 0 without
	 * a range filter traces the WHOLE kernel and fills a ToPA buffer in milliseconds.
	 *
	 * At least one ring must be selected; a trace with neither .OS nor .USER records nothing while
	 * reporting success, which is the silent-partial shape.
	 */
	UINT64 Ctl = RTIT_CTL_TOPA | RTIT_CTL_BRANCHEN;
	if (Ctx->WantUser) Ctl |= RTIT_CTL_USER;
	if (Ctx->WantOs)   Ctl |= RTIT_CTL_OS;
	if ((Ctl & (RTIT_CTL_USER | RTIT_CTL_OS)) == 0)
		Ctl |= RTIT_CTL_USER;   /* caller asked for neither -- default to the historic behaviour */

	/*
	 * 4b. ADDRESS-RANGE FILTERS.
	 *
	 * ⚠ THE RANGE COUNT IS RE-DERIVED ON THIS CORE, not taken from the caller and not from whatever
	 * cpuprobe saw earlier. This CPU is hybrid: CPUID.(14H,1):EAX[2:0] is a PER-CORE answer, and a
	 * count trusted from another core would write an ADDRn pair this core does not implement -- a
	 * #GP on a WRMSR, with no SEH in a manually mapped image to catch it.
	 *
	 * A core that cannot take every requested range takes NONE of them and reports the refusal. Half
	 * a filter is not a smaller filter -- it traces a different thing while looking like it worked.
	 */
	if (Ctx->RangeCount != 0)
	{
		int RR[4];
		__cpuidex(RR, 0x14, 0);
		CONST UINT32 PtSubLeaves = (UINT32)RR[0];
		CONST BOOLEAN HasIpFilter = (RR[1] & (1 << 2)) != 0;

		UINT32 CoreRanges = 0;
		if (PtSubLeaves >= 1)
		{
			__cpuidex(RR, 0x14, 1);
			CoreRanges = (UINT32)(RR[0] & 0x7);
		}

		if (!HasIpFilter || CoreRanges < Ctx->RangeCount)
		{
			InterlockedIncrement(&Ctx->RangeRefused);
		}
		else
		{
			for (UINT32 r = 0; r < Ctx->RangeCount; r++)
			{
				__writemsr(RTIT_ADDR_MSR_A(r), Ctx->Ranges[r].Start);
				__writemsr(RTIT_ADDR_MSR_B(r), Ctx->Ranges[r].End);
				Ctl = (Ctl & ~RTIT_CTL_ADDR_CFG_MASK(r))
				    | (((UINT64)Ctx->Ranges[r].Cfg & 0xFULL) << RTIT_CTL_ADDR_CFG_SHIFT(r));
			}
		}
	}

	/*
	 * 4c. TIMING PACKETS AND PTWRITE (D117).
	 *
	 * ⚠ ALL-OR-NOTHING, PER CORE, AND FAIL-CLOSED. If ANY part of the timing request cannot be
	 * honoured on this core, the core takes NONE of it and records the refusal. The alternative --
	 * arming whatever happens to be supported -- produces a trace that is missing exactly the packets
	 * the analysis was going to rely on, and reports success. That is the silent-partial shape, and
	 * on a hybrid part it would differ BETWEEN CORES in the same capture.
	 *
	 * ⚠ EVERY 4-BIT ENCODING IS CHECKED AGAINST THIS CORE'S OWN BITMAP BEFORE IT IS WRITTEN. An
	 * unimplemented encoding is a #GP on the WRMSR, and there is no SEH here to turn that into a
	 * failure return -- it is a bugcheck. The bitmaps are the only thing standing between a caller's
	 * number and that.
	 */
	CONST BOOLEAN WantsTiming = (Ctx->WantTsc != 0) || (Ctx->MtcFreq != 0xFFu) ||
	                            (Ctx->CycThresh != 0xFFu) || (Ctx->PsbFreq != 0xFFu) ||
	                            (Ctx->WantPtw != 0) || (Ctx->WantFupOnPtw != 0) ||
	                            (Ctx->WantDisTnt != 0);   /* shares the CPUID probe and the gate */
	if (WantsTiming)
	{
		int TR[4];
		__cpuidex(TR, 0x14, 0);
		CONST UINT32  PtSub      = (UINT32)TR[0];
		CONST UINT32  Ebx0       = (UINT32)TR[1];
		CONST BOOLEAN CanCycPsb  = (Ebx0 & PT_EBX_CYC_PSB) != 0;
		CONST BOOLEAN CanMtc     = (Ebx0 & PT_EBX_MTC) != 0;
		CONST BOOLEAN CanPtw     = (Ebx0 & PT_EBX_PTWRITE) != 0;

		UINT32 MtcMap = 0, CycMap = 0, PsbMap = 0;
		if (PtSub >= 1)
		{
			__cpuidex(TR, 0x14, 1);
			MtcMap = ((UINT32)TR[0] >> 16) & 0xFFFFu;   /* EAX[31:16] */
			CycMap =  (UINT32)TR[1]        & 0xFFFFu;   /* EBX[15:0]  */
			PsbMap = ((UINT32)TR[1] >> 16) & 0xFFFFu;   /* EBX[31:16] -- NOT EDX, which is reserved */
		}

		/* One expression per request: "asked for" AND "this core allows it" AND, for the encoded
		 * fields, "this exact encoding is in the core's bitmap". Anything else refuses. */
		CONST BOOLEAN MtcOk = (Ctx->MtcFreq == 0xFFu) ||
		                      (CanMtc && Ctx->MtcFreq < 16u &&
		                       (MtcMap & (1u << Ctx->MtcFreq)) != 0);
		CONST BOOLEAN CycOk = (Ctx->CycThresh == 0xFFu) ||
		                      (CanCycPsb && Ctx->CycThresh < 16u &&
		                       (CycMap & (1u << Ctx->CycThresh)) != 0);
		CONST BOOLEAN PsbOk = (Ctx->PsbFreq == 0xFFu) ||
		                      (CanCycPsb && Ctx->PsbFreq < 16u &&
		                       (PsbMap & (1u << Ctx->PsbFreq)) != 0);
		CONST BOOLEAN PtwOk = (Ctx->WantPtw == 0 && Ctx->WantFupOnPtw == 0) || CanPtw;
		/* DisTNT joins the same all-or-nothing gate. A core that cannot suppress TNT would produce
		 * a trace far shorter in EXECUTION covered than its siblings for the same buffer -- on a
		 * hybrid part that is a per-core difference inside one capture, which is the shape this
		 * gate exists to prevent. */
		CONST BOOLEAN CanDisTnt = (Ebx0 & PT_EBX_TNT_DISABLE) != 0;
		CONST BOOLEAN TntOk     = (Ctx->WantDisTnt == 0) || CanDisTnt;

		if (!MtcOk || !CycOk || !PsbOk || !PtwOk || !TntOk)
		{
			/*
			 * ⚠ REFUSE THE WHOLE ARM ON THIS CORE, not just the timing. The first version counted
			 * the refusal and armed anyway -- which made this path DISAGREE WITH THE READ-BACK PATH
			 * below, where the identical condition (the timing bits did not stick) tears the trace
			 * down and returns. Two paths for one condition with two different outcomes is a defect
			 * regardless of which one is right.
			 *
			 * Fail-closed is the one that is right here. An unfiltered trace is MORE data than asked
			 * for and obvious; a trace with no timing packets is exactly what was asked for minus
			 * the ability to answer 'when', and it decodes perfectly while being silently unable to.
			 * The caller asked for a timeline; a core that cannot give one should not pretend.
			 */
			ArmReleaseLvtOnFailure(Cpu, PmiWhy);   /* refusal 1 of 4 -- see the helper */
			InterlockedIncrement(&Ctx->TimingRefused);
			InterlockedIncrement(&Ctx->Refused);
			return 0;
		}
		else
		{
			/* TSCEn has no capability gate in CPUID.(14H,0).EBX -- it is available wherever PT is,
			 * which is why it is not checked and the others are. Stated because an unchecked write
			 * beside four checked ones otherwise reads as an oversight. */
			if (Ctx->WantTsc)      Ctl |= RTIT_CTL_TSCEN;
			if (Ctx->MtcFreq != 0xFFu)
				Ctl |= RTIT_CTL_MTCEN |
				       (((UINT64)Ctx->MtcFreq & RTIT_CTL_4BIT_MASK) << RTIT_CTL_MTCFREQ_SHIFT);
			if (Ctx->CycThresh != 0xFFu)
				Ctl |= RTIT_CTL_CYCEN |
				       (((UINT64)Ctx->CycThresh & RTIT_CTL_4BIT_MASK) << RTIT_CTL_CYCTHRESH_SHIFT);
			if (Ctx->PsbFreq != 0xFFu)
				Ctl |= (((UINT64)Ctx->PsbFreq & RTIT_CTL_4BIT_MASK) << RTIT_CTL_PSBFREQ_SHIFT);
			if (Ctx->WantPtw)      Ctl |= RTIT_CTL_PTWEN;
			if (Ctx->WantFupOnPtw) Ctl |= RTIT_CTL_FUPONPTW;
			if (Ctx->WantDisTnt)   Ctl |= RTIT_CTL_DISTNT;
		}
	}

	if (Ctx->Cr3Filter != 0 && HasCr3Filter)
	{
		__writemsr(IA32_RTIT_CR3_MATCH, Ctx->Cr3Filter & 0xFFFFFFFFFFFFF000ULL);
		Ctl |= RTIT_CTL_CR3FILTER;
	}
	else if (Ctx->Cr3Filter != 0)
	{
		/* Asked to scope to one process on a core that cannot. Tracing EVERYTHING instead would
		 * fill the buffer in milliseconds and answer a different question, so refuse. */
		ArmReleaseLvtOnFailure(Cpu, PmiWhy);   /* refusal 2 of 4 -- see the helper */
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	/* 5. Arm. USER only, OS deliberately clear: kernel-mode tracing multiplies the volume and the
	 *    target's own execution is what this is for. */
	__writemsr(IA32_RTIT_CTL, Ctl | RTIT_CTL_TRACEEN);

	/*
	 * 6. READ BACK. A write that silently did not take is the failure mode that would otherwise be
	 *    discovered as "the buffer is empty" much later, with nothing pointing here.
	 */
	CONST UINT64 Got    = __readmsr(IA32_RTIT_CTL);
	CONST UINT64 Status = __readmsr(IA32_RTIT_STATUS);

	if ((Got & RTIT_CTL_TRACEEN) == 0 || (Status & (RTIT_STATUS_ERROR | RTIT_STATUS_STOPPED)))
	{
		__writemsr(IA32_RTIT_CTL, 0);
		/* ⚠ Clearing RTIT_CTL does NOT release the LVT: the trace control MSR and the LVT PC entry
		 * are independent, and only the disarm helper decrements LvtPcOwners. Refusal 3 of 4. */
		ArmReleaseLvtOnFailure(Cpu, PmiWhy);
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	/*
	 * ⚠ AND THE READ-BACK COMPARES WHAT WAS ASKED FOR, NOT MERELY THAT TRACING IS ON.
	 *
	 * Checking TRACEEN alone would have passed a core that accepted the write and dropped every
	 * timing bit -- tracing happily, silently missing the packets the capture exists to produce.
	 * That is exactly what PEBS did twice today: MSR_PEBS_DATA_CFG read back precisely as requested
	 * while the records carried none of it, because the verification covered one register and the
	 * defect was in another. Here the comparison is against the value that was WRITTEN, so it cannot
	 * be satisfied by a partial success.
	 *
	 * The whole request is dropped and the refusal counted -- a core running with half the timing
	 * bits produces a trace that decodes without complaint and is missing the timeline.
	 */
	/*
	 * ⚠ DisTNT WAS MISSING FROM THIS MASK WHILE THE ARM ABOVE SETS IT. Every other capability-gated
	 * bit written into `Ctl` is verified here; bit 55 was not, because it was added later
	 *  and this list was not extended with it. A core that accepted every timing bit
	 * EXCEPT DisTNT would therefore satisfy the comparison and report success while TNT packets
	 * kept flowing -- the exact silent partial the paragraph above says this check prevents, and
	 * the same shape as a flag mask that silently drops the flag added last.
	 *
	 * Masking with `Ctl` keeps the not-requested case correct: bit 55 is only set in Ctl when
	 * WantDisTnt AND the capability check both held, so WantedBits stays clear otherwise.
	 * of this file.
	 */
	CONST UINT64 WantedBits = Ctl & (RTIT_CTL_TSCEN | RTIT_CTL_MTCEN | RTIT_CTL_CYCEN |
	                                 RTIT_CTL_PTWEN | RTIT_CTL_FUPONPTW | RTIT_CTL_DISTNT |
	                                 (RTIT_CTL_4BIT_MASK << RTIT_CTL_MTCFREQ_SHIFT) |
	                                 (RTIT_CTL_4BIT_MASK << RTIT_CTL_CYCTHRESH_SHIFT) |
	                                 (RTIT_CTL_4BIT_MASK << RTIT_CTL_PSBFREQ_SHIFT));
	if (WantedBits != 0 && (Got & WantedBits) != WantedBits)
	{
		__writemsr(IA32_RTIT_CTL, 0);
		ArmReleaseLvtOnFailure(Cpu, PmiWhy);   /* refusal 4 of 4 -- see the helper */
		InterlockedIncrement(&Ctx->TimingRefused);
		InterlockedIncrement(&Ctx->Refused);
		return 0;
	}

	/* The RTIT_CTL this core actually ended up with. Reported per core, because on a hybrid part
	 * "which timing packets am I getting" is not one answer for the machine. */
	gTrace[Cpu].RtitCtl = Got;

	/*
	 * ⚠ EVERYTHING ELSE WAS ALREADY CLEARED BY TraceResetCounters IN STEP 2b, before TraceEn. Only the
	 * read-back status belongs here, because step 6 is where it is read.
	 *
	 * The counters were once reset at THIS point, and that was two separate bugs. The first: the reset
	 * list here was hand-written and the lists in free/alloc were different, so a freed capture's
	 * generation reached a fresh allocation -- observed as `ARMED=no POSITION=0 FILLED=no GEN=1`. The
	 * second: resetting after TraceEn left a window in which a fill interrupt could arrive before
	 * ArmFlags told the NMI handler the core was ours.
	 */
	gTrace[Cpu].RtitStatus = Status;

	gTrace[Cpu].Armed = 1;
	InterlockedIncrement(&Ctx->Armed);
	return 0;
}

static ULONG_PTR
DisarmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return 0;

	/*
	 * ⚠ ONLY CLEAR WHAT WE ARMED. A core we never touched may be running someone else's trace, and
	 * clearing TraceEn there would stop it with no indication to its owner.
	 */
	if (gTrace[Cpu].Armed == 0)
		return 0;

	__writemsr(IA32_RTIT_CTL, 0);

	/*
	 * ⚠ SAMPLE THE FINAL COUNT HERE, AND AFTER CLEARING TraceEn. This is the LAST moment the number
	 * exists: once Armed drops to 0 the status path stops sampling this core, so a capture that was
	 * armed, ran, and disarmed without anyone calling `trace status` in between would otherwise
	 * report zero bytes -- indistinguishable from a trace that never wrote.
	 *
	 * After TraceEn clears, the SDM has the CPU flush its internal packet buffer to memory, so the
	 * offset read here counts everything the trace produced. Read before the clear and the tail is
	 * missing.
	 */
	gTrace[Cpu].OutputOffset = __readmsr(IA32_RTIT_OUTPUT_MASK_PTRS) >> 32;
	gTrace[Cpu].RtitStatus   = __readmsr(IA32_RTIT_STATUS);
	TraceNoteWrap(&gTrace[Cpu]);
	TraceNoteGeneration(&gTrace[Cpu], gTrace[Cpu].OutputOffset);

	/*
	 * ⚠ TEAR THE PMI DOWN WHILE THIS CORE STILL CLAIMS IT, i.e. BEFORE Armed drops to 0. The NMI
	 * callback passes an NMI through untouched when Armed is 0, so clearing the flag first would
	 * leave a window where a fill interrupt we caused arrives and nobody claims it.
	 *
	 * TraceEn is already clear two lines up, so no further fill can be generated -- but the ToPA INT
	 * bit is cleared anyway rather than left for the next arm to overwrite. A table entry that asks
	 * for an interrupt while no handler is registered is a state worth not existing, even briefly.
	 */
	UINT64* CONST DEntry = (UINT64*)gTrace[Cpu].ToPaVa;
	if (DEntry != NULL)
		DEntry[0] &= ~(TOPA_STOP | TOPA_INT);

	TracePmiDisarmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PT);
	gTrace[Cpu].ArmFlags = 0;

	gTrace[Cpu].Armed = 0;

	NXC_ARM_CTX* CONST Ctx = gArmCtx;
	if (Ctx != NULL)
		InterlockedIncrement(&Ctx->Armed);
	return 0;
}

NTSTATUS
NxcTraceArm(
	_In_ UINT64 Cr3Filter,
	_In_ UINT32 OnlyCpu,
	_In_ UINT32 ArmFlags,
	_In_opt_ CONST NXCMD_PT_RANGE* Ranges,
	_In_ UINT32 RangeCount,
	_In_opt_ CONST NXCMD_PT_TIMING* Timing,
	_Out_ UINT32* OutArmed,
	_Out_ UINT32* OutRangeRefused,
	_Out_ UINT32* OutTimingRefused
	)
{
	*OutArmed = 0;
	*OutRangeRefused = 0;
	*OutTimingRefused = 0;

	if (gTraceCpus == 0)
	{
		TrcLog("trace: nothing allocated -- `trace alloc` first\n");
		return STATUS_INVALID_DEVICE_STATE;
	}

	/*
	 * ⚠ ZERO THE REGIONS BEFORE ARMING, AT PASSIVE, FOR TWO SEPARATE REASONS.
	 *
	 * The first is the wrap detector. It concludes "this region was filled" from a non-zero byte near
	 * its end, which is only sound if the region STARTED empty. Re-arming over a buffer a previous
	 * run had already wrapped would report a wrap the instant the new trace began -- true of the
	 * memory, false of the trace, and indistinguishable from the real thing.
	 *
	 * The second matters more and outlives this function: a partially filled buffer still holds the
	 * PREVIOUS run's packets past the write position. Anything that decodes it later would read those
	 * as this run's data. Stale evidence that looks current is worse than no evidence, so the region
	 * is cleared rather than merely tracked.
	 *
	 * Done HERE and not in ArmOnEachCpu because that runs at IPI_LEVEL inside a broadcast, with every
	 * core waiting. 24 x 256 KB of zeroing there would stall the whole machine for the duration; here
	 * it is ordinary work on one thread.
	 */
	for (UINT32 i = 0; i < gTraceCpus; i++)
	{
		if (OnlyCpu != 0xFFFFFFFFu && i != OnlyCpu)
			continue;
		if (gTrace[i].BufferVa != NULL && gTrace[i].BufferSize != 0)
			RtlZeroMemory(gTrace[i].BufferVa, gTrace[i].BufferSize);
	}

	/*
	 * ⚠ REGISTER THE NMI CALLBACK HERE, AT PASSIVE, BEFORE THE BROADCAST -- both halves of that
	 * sentence are requirements. KeRegisterNmiCallback is a PASSIVE_LEVEL API and the broadcast runs
	 * at IPI_LEVEL, so it cannot be done from inside ArmOnEachCpu. And it must be BEFORE, because the
	 * first region fill can happen microseconds after TraceEn is set: registering afterwards would
	 * arm a core whose fill interrupt has nowhere to go.
	 *
	 * ⚠ ONCE, GUARDED. A second arm without an intervening disarm would otherwise stack a second
	 * callback and double every count.
	 */
	UINT32 NmiOk = 0;
	if ((ArmFlags & NXC_TRACE_ARM_PMI) != 0)
	{
		NmiOk = TracePmiPrepare();
		if (NmiOk == 0)
			TrcLog("trace: PMI requested but KeRegisterNmiCallback failed -- arming WITHOUT the\n"
			       "       exact wrap counter. The trace itself is unaffected.\n");
	}

	NXC_ARM_CTX Ctx;
	Ctx.Cr3Filter = Cr3Filter;
	Ctx.OnlyCpu   = OnlyCpu;
	Ctx.ArmFlags  = ArmFlags;
	Ctx.NmiOk     = NmiOk;
	Ctx.Ranges       = Ranges;
	Ctx.RangeCount   = (Ranges != NULL) ? RangeCount : 0;
	Ctx.RangeRefused = 0;

	/* Absent timing request == every field UNSET, written in one place rather than relying on the
	 * caller having zeroed a struct we then reinterpret. 0 is a VALID encoding in three of these
	 * fields, so a zeroed struct and "no timing wanted" are not the same thing. */
	Ctx.WantTsc       = (Timing != NULL) ? Timing->WantTsc      : 0u;
	Ctx.MtcFreq       = (Timing != NULL) ? Timing->MtcFreq      : NXCMD_PT_TIMING_UNSET;
	Ctx.CycThresh     = (Timing != NULL) ? Timing->CycThresh    : NXCMD_PT_TIMING_UNSET;
	Ctx.PsbFreq       = (Timing != NULL) ? Timing->PsbFreq      : NXCMD_PT_TIMING_UNSET;
	Ctx.WantPtw       = (Timing != NULL) ? Timing->WantPtw      : 0u;
	Ctx.WantFupOnPtw  = (Timing != NULL) ? Timing->WantFupOnPtw : 0u;
	Ctx.WantDisTnt    = (Timing != NULL) ? Timing->WantDisTnt   : 0u;
	Ctx.WantUser      = (Timing != NULL) ? Timing->WantUser     : 1u;
	Ctx.WantOs        = (Timing != NULL) ? Timing->WantOs       : 0u;
	Ctx.TimingRefused = 0;

	Ctx.Armed     = 0;
	Ctx.Refused   = 0;

	gArmCtx = &Ctx;
	(void)KeIpiGenericCall(ArmOnEachCpu, 0);
	gArmCtx = NULL;

	*OutArmed = (UINT32)Ctx.Armed;
	*OutRangeRefused = (UINT32)Ctx.RangeRefused;
	*OutTimingRefused = (UINT32)Ctx.TimingRefused;

	/*
	 * ⚠ IF NOTHING ARMED, GIVE THE CALLBACK BACK. Leaving it registered after a failed arm means an
	 * NMI handler with no cores to serve, living until the module unloads -- and it would still be
	 * there to be double-counted by the guard above on the next attempt.
	 */
	if (Ctx.Armed == 0)
		TracePmiReleaseAll();

	TrcLog("trace: ARMED %ld core(s), %ld refused (cr3 filter 0x%llX, cpu %s, flags 0x%X)\n",
	       Ctx.Armed, Ctx.Refused, Cr3Filter,
	       (OnlyCpu == 0xFFFFFFFFu) ? "all" : "one", ArmFlags);

	return (Ctx.Armed == 0) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------------------------------
 * PEBS STAGE 1 -- ALLOCATION ONLY. Read the block in Trace.h before changing anything here.
 * ------------------------------------------------------------------------------------------- */

/*
 * The DS management area, exactly as the SDM lays it out in 64-bit mode.
 *
 * TIER 1 (reference material): cheat-engine's ultimap.h carries this same struct as
 * DS_AREA_MANAGEMENT64 and uses it for BTS. Taking the LAYOUT from a source that has run it beats
 * transcribing offsets from a table, and it agrees with the SDM field for field.
 *
 * ⚠ THE CPU WRITES PEBS_IndexBaseAddress. Everything else here is ours to set; that one field is
 * hardware's cursor into the buffer, which is how a drain knows how many records exist.
 */
typedef struct _NXC_DS_AREA
{
	UINT64 BtsBufferBase;
	UINT64 BtsIndex;
	UINT64 BtsAbsoluteMax;
	UINT64 BtsInterruptThreshold;
	UINT64 PebsBufferBase;
	UINT64 PebsIndex;              /* <-- the CPU advances this */
	UINT64 PebsAbsoluteMax;
	UINT64 PebsInterruptThreshold;
	UINT64 PebsCounterReset[4];
	UINT64 Reserved;
} NXC_DS_AREA;

/*
 * Record stride REQUESTED: the Basic group plus the GPR group. Adaptive PEBS is available here
 * (BASELINE measured set on all 24 cores), so this is a CHOICE -- memory-info and XMM groups are
 * deliberately not requested, because a record carries what it is asked for and a smaller record
 * samples faster and parses simpler.
 *
 * ⚠ AND IT IS A REQUEST, NEVER AN ASSUMPTION. Every PEBS record states its OWN size in its first
 * field. The drain compares that against this stride and walks at the RECORD'S step on a mismatch
 * rather than the requested one -- the same rule the command channel learned twice,
 * applied to a struct the HARDWARE defines rather than one we do. It caught this constant being
 * wrong on the very first run where the GPR group actually arrived.
 *
 * ⚠ 176, NOT 160, AND THE CORRECTION IS A MEASUREMENT RATHER THAN A READING OF THE MANUAL. The GPR
 * group is 144 bytes, not 16 x 8: it carries RFLAGS and RIP as well as the general-purpose
 * registers. Two hardware runs bracket it -- 32-byte records with the group off, 176 with it on.
 * That undercount SIZED A BUFFER THE CPU WRITES THROUGH; see the allocation below.
 *
 * ⚠ THE NUMBERS THEMSELVES LIVE IN NexusCommand.h so the kernel that SIZES the buffer and the
 * usermode that CHECKS the drain cannot drift apart. This is an alias, not a second copy.
 */
#define NXC_PEBS_BASIC_BYTES   NXCMD_PEBS_BASIC_BYTES
#define NXC_PEBS_GPR_BYTES     NXCMD_PEBS_GPR_BYTES
#define NXC_PEBS_STRIDE        NXCMD_PEBS_STRIDE

typedef struct _NXC_PEBS_CPU
{
	/*
	 * ⚠ DOES THIS CORE HAVE LIVE PEBS HARDWARE OF OURS? Set after the arm has programmed every MSR,
	 * cleared after the disarm has stopped them -- so it tracks the SILICON, not the intent.
	 *
	 * The PMI judge tests this rather than the global `gPebsArmed`, because the global is the
	 * arm/disarm interlock and is cleared BEFORE the IPI that stops the counters. A PMI in that
	 * window is ours and must be claimed; keying on the global declined it and reopened bugcheck
	 * 0x80. See the block in PebsPmiJudge.
	 */
	UINT32       Armed;
	NXC_DS_AREA* DsArea;
	void*        Buffer;
	UINT64       DsAreaPa;
	UINT64       BufferPa;
	UINT32       BufferBytes;
	UINT32       Records;
	/* The stride ARM selected, from NxcPebsStrideFor(gPebsDataCfg). Not a constant any more: it
	 * depends on which groups were requested, and the buffer wall is placed from it. Reported to
	 * usermode so `pebs status` shows what was actually programmed rather than the default. */
	UINT32       Stride;
	/* Bytes per record slot the BUFFER was built for. Arm refuses any group set needing more --
	 * the CPU writes these records and cannot be asked to fit. */
	UINT32       AllocStride;
	/*
	 * KEPT RECORDS, copied out of the DS buffer by the PMI judge.
	 *
	 * measured and this is why it exists: the CPU writes PEBS records FAR faster than
	 * PMIs are delivered, so the in-place rewind only ever reached the newest record and every
	 * other record stayed in the buffer UNJUDGED. A drain of cpu0 held 372 records of which only
	 * 27.4% were the target's, including 32 KERNEL IPs from a USR-only counter. The buffer was
	 * being delivered as "filtered" and was nothing of the kind.
	 *
	 * So attribution happens once, in the PMI, for the ONE record CR3 can speak for -- and that
	 * record is copied HERE. Everything else is discarded, because a record whose address space we
	 * cannot name is not a record we may hand back.
	 */
	void*        KeepBuf;
	/*
	 * ⚠⚠ A CONSUMING RING, NOT A FILL-ONCE BUFFER -- and the difference is whether a long capture
	 * can miss its target.
	 *
	 * The first version had a single KeepWrite that only reset at ARM. So the buffer filled, and
	 * from that moment EVERY further match was lost -- draining did not free a single slot.
	 * Measured: 43.2% of sampled records belonged to the target and only 4.2% were stored. For a
	 * real capture that is the worst possible shape: you get the opening of the trace and silently
	 * miss everything after it, with the interesting behaviour usually being the part you missed.
	 *
	 * Monotonic indices, same as the BTF ring: the judge appends at Write % Max, the drain consumes
	 * [Read, Write) and advances Read. Records are lost ONLY if the writer laps the reader, which is
	 * a real backlog and is counted as one -- never the silent permanent stall the old shape had.
	 */
	UINT64       KeepWrite;     /* monotonic; & wrapped by KeepMax */
	UINT64       KeepRead;      /* monotonic; advanced by the drain */
	UINT32       KeepMax;       /* capacity in records              */
} NXC_PEBS_CPU;

static NXC_PEBS_CPU gPebs[NXC_MAX_TRACE_CPUS];
static UINT32       gPebsCpus = 0;

/* ---------------------------------------------------------------------------------------------
 * PEBS STAGE 2 -- arming. Read the block in Trace.h first.
 * ------------------------------------------------------------------------------------------- */

#define IA32_DS_AREA                0x00000600u
#define IA32_PEBS_ENABLE            0x000003F1u
#define MSR_PEBS_DATA_CFG           0x000003F2u
#define IA32_PERFEVTSEL0            0x00000186u
#define IA32_PMC0                   0x000000C1u

/*
 * ⚠ PMC0, NOT A FIXED COUNTER, AND THAT IS A DELIBERATE NARROWING.
 *
 * The sampling profiler (D114) uses fixed counter 0 because it only needs an overflow. PEBS needs a
 * RESET VALUE the CPU reloads after each record, and the DS area's `PebsCounterReset[]` array is
 * unambiguously indexed by GENERAL-PURPOSE counter. Where the reset for a FIXED counter lives varies
 * by layout revision, and a wrong offset there is a value the CPU reloads from memory we chose --
 * exactly the class of mistake stage 1 exists to keep cheap. PMC0 has one documented answer.
 *
 * ⚠ AND IT MEANS PEBS AND THE PROFILER DO NOT COMPETE. They use different counters, so both can be
 * armed at once, which matters because they answer different questions about the same target.
 */
#define PERFEVTSEL_INST_RETIRED_P   0x000000C0ull   /* event 0xC0, umask 0x00 */

/*
 * ---- LOAD-LATENCY SAMPLING, WHICH IS WHAT ACTUALLY FILLS THE MEMINFO GROUP -------------------
 *
 * Arming `--mem` on INST_RETIRED produced a 208-byte record with the MemInfo group present and its
 * DATA SOURCE and LATENCY fields ZERO on every core of both types (measured). The data
 * linear address appeared only on E-cores. A generic instruction-retired event has no memory
 * semantics to report, so most of the group has nothing to say.
 *
 * MEM_TRANS_RETIRED.LOAD_LATENCY is the event that does: it samples LOADS whose latency EXCEEDS a
 * threshold, and the threshold lives in its own MSR.
 *
 *   event 0xCD, umask 0x01                       -- verified against Intel's event lists / libpfm4
 *   MSR_PEBS_LD_LAT_THRESHOLD = 0x3F6            -- verified against Linux `msr-index.h`
 *
 * ⚠ THE THRESHOLD IS A FILTER, NOT A SETTING. Only loads SLOWER than it are recorded. Set it high
 * and the buffer stays empty and looks broken; set it at 0 and the hardware may refuse or record
 * nothing useful. Linux's own tooling uses small values (ldlat=3 upward), so the default here is
 * deliberately low -- we want most loads, not just pathological ones.
 *
 * ⚠ AND DO NOT ASSUME IT BEHAVES THE SAME ON BOTH CORE TYPES. This is a hybrid part and the
 * MemInfo group ALREADY proved asymmetric: the data linear address was populated on 6 of 6 E-cores
 * and 0 of 3 P-cores for INST_RETIRED. Whether P-cores populate it for a real memory event is a
 * QUESTION TO MEASURE, not a fact to design around. That is why the event is SELECTABLE rather
 * than hardcoded -- the old event stays available so the two can be compared on the same machine.
 */
#define PERFEVTSEL_MEM_TRANS_LOAD_LAT 0x000001CDull  /* event 0xCD, umask 0x01 */
#define MSR_PEBS_LD_LAT_THRESHOLD     0x000003F6u
#define PERFEVTSEL_USR              (1ull << 16)
/* ⚠ PEBS WAS RING-3 ONLY TOO, and for the same reason PT was: this bit was ORed in
 * unconditionally and there was no OS counterpart. A kernel driver's register state at a
 * sampled instruction is exactly what PEBS is for. Opt-in, same as PT -- with .OS set the
 * counter also samples this driver's own execution. */
#define PERFEVTSEL_OS               (1ull << 17)
#define PERFEVTSEL_EN               (1ull << 22)
#define PEBS_ENABLE_PMC0            (1ull << 0)
#define PEBS_DATA_CFG_GPR           (1ull << 1)     /* Basic group is implicit; this adds the GPRs */

/*
 * ---- THE OTHER TWO GROUPS THE HARDWARE OFFERS (D119) --------------------------------------------
 *
 * MSR_PEBS_DATA_CFG selects what a record CONTAINS. Until now only the GPR group was ever asked
 * for, which answers "where was the program and what was in its registers". Two more groups answer
 * questions nothing else in this framework can:
 *
 *   MEM_INFO  the DATA LINEAR ADDRESS the sampled instruction touched, its data source, and the
 *             LATENCY in core cycles. That is a memory-access capture surface: not "what code ran"
 *             but "what memory it reached and how long it waited". For an introspection framework
 *             this is the difference between seeing a decryption routine execute and seeing WHICH
 *             BUFFER it read.
 *
 *   LBR       the branch history captured ATOMICALLY WITH THE SAMPLE. `lbr read` already exposes
 *             the ring, but reading it separately is a second trip that the target can run through;
 *             in the record it is the call path AS OF that instruction, by construction.
 *
 * ⚠ THE GROUPS APPEAR IN A FIXED ORDER AND EARLIER ONES SHIFT LATER ONES. The order is
 * Basic, MemInfo, GPR, XMM, LBR -- so enabling MemInfo MOVES the GPR group. Nothing may assume the
 * GPRs are at +0x20 any more; the parser derives every offset from the record's own format bitmap.
 * That bitmap is the low bits of qword0 and uses the SAME numbering as these DATA_CFG bits, which
 * is what makes deriving it possible rather than guesswork.
 *
 * ⚠ AND THE GROUP SIZES ARE MEASURED, NOT RECALLED. The record states its own size in qword0
 * bits 63:48, so enabling one group at a time makes the hardware report that group's size as the
 * delta. That is how the GPR group was found to be 144 bytes and not the "obviously 16 x 8" = 128
 * that was assumed and wrong. No size here is written from memory.
 */
#define PEBS_DATA_CFG_MEM           (1ull << 0)     /* data linear address, source, latency        */
#define PEBS_DATA_CFG_XMM           (1ull << 2)     /* not requested -- see the note above         */
#define PEBS_DATA_CFG_LBR           (1ull << 3)     /* branch history, atomic with the sample      */
#define PEBS_DATA_CFG_LBR_ENTRIES_SHIFT 24u         /* bits 31:24 = how many LBR entries to store  */

/*
 * ⚠ ADAPTIVE_RECORD -- THE SECOND ENABLE, AND ITS ABSENCE COST A HARDWARE RUN.
 *
 * MSR_PEBS_DATA_CFG read back 0x2 on all 24 cores -- the GPR bit was WRITTEN, ACCEPTED and RETAINED
 * -- and the records still arrived 32 bytes, Basic group alone. DATA_CFG was never the problem.
 * IA32_PERF_CAPABILITIES.PEBS_BASELINE[14] gates a PAIR of things, not one: the DATA_CFG MSR *and*
 * the per-counter adaptive-record enables. DATA_CFG says WHAT a record should contain; this bit says
 * to build an ADAPTIVE record at all. Without it the counter emits the basic record and DATA_CFG is
 * a correctly-stored value nothing consults -- which is why reading it back proved nothing.
 *
 * Bit 34 for a general-purpose counter (IA32_PERFEVTSELx.Adaptive_Record); bit 32 of
 * IA32_FIXED_CTR_CTRL for fixed counter 0, which we do not use here (see the PMC0 note above).
 *
 * 4-tier,: `reference material/` has NOTHING -- Cheat Engine's ultimap and dbvm carry the
 * Nehalem-era DS layout and predate adaptive PEBS entirely, and ia32-doc stops at bit 31 of this
 * register. Found at tier 2 (Intel SDM via the KVM adaptive-PEBS series; Linux calls it
 * ICL_EVENTSEL_ADAPTIVE (1ULL << 34) / ICL_FIXED_0_ADAPTIVE (1ULL << 32)). v1 never built PEBS.
 *
 * ⚠ BIT 34 IS ABOVE 32. Any accidental 32-bit truncation on the way to WRMSR drops it silently and
 * leaves exactly the symptom it was added to fix, so it is READ BACK like the other three.
 */
#define PERFEVTSEL_ADAPTIVE         (1ull << 34)
#define PERF_GLOBAL_PMC0_EN         (1ull << 0)
#define PERF_GLOBAL_PMC0_OVF        (1ull << 0)

/*
 * ⚠⚠ BIT 62 -- `OvfBuf`, THE DS-SAVE-AREA BUFFER OVERFLOW. THIS BIT IS THE BUGCHECK 0x80.
 *
 * measured, and it is the first direct observation in twelve crashes. With the PMI
 * filter armed, the NMI observer recorded 24 NMIs -- one per core -- every one of them with
 * GLOBAL_STATUS = 0x4000000000000000 and every one CLAIMED BY NOBODY:
 *
 *     CPU 21  GLOBAL_STATUS 0x4000000000000000  LVT_PC 0x00010402  PEBS  CAUGHT(would-be-0x80)
 *
 * Only the diagnostic catch kept the machine alive to see it.
 *
 * WHY NOBODY CLAIMED IT. PEBS raises its PMI through this bit, NOT through PMC0's overflow bit --
 * the counter overflow is what triggers the RECORD, and the DS buffer crossing its threshold is
 * what triggers the INTERRUPT. PebsPmiJudge tested only PERF_GLOBAL_PMC0_OVF (bit 0) and returned
 * FALSE for anything else. Bit 55 (ToPA) was clear so PT did not claim it; bit 32 (fixed counter)
 * was clear so the profiler did not claim it. An NMI our own code caused, that our own handler then
 * declined -- which is bugcheck 0x80 by definition.
 *
 * It also explains why `pebs status` read "0 kept, 0 rejected": the judge early-returned before ever
 * looking at a record, so the filter never filtered ANYTHING while generating an NMI per record.
 * A feature that did nothing and crashed the machine doing it.
 */
#define PERF_GLOBAL_OVF_BUFFER      (1ull << 62)

/* Everything PEBS is allowed to be the cause of. Named once so the TEST and the CLEAR cannot
 * disagree -- they are the two halves of claiming an interrupt, and a bit tested but not cleared
 * re-asserts forever while a bit cleared but not tested is claimed silently. */
#define PERF_GLOBAL_PEBS_CAUSES     (PERF_GLOBAL_PMC0_OVF | PERF_GLOBAL_OVF_BUFFER)

static UINT64 volatile gPebsPeriod = 0;

/*
 * PMI-FILTER STATE. All EVIDENCE, never a verdict (D6): what the CR3 test kept, what it rewound,
 * and how many PMIs arrived that produced no judgeable record.
 */
static UINT32 volatile gPebsPmiFilter = 0;   /* opt-in; 0 = no NMI source is programmed at all */
static LONG64 volatile gPebsKept      = 0;
static LONG64 volatile gPebsRejected  = 0;
static LONG64 volatile gPebsPmiCount  = 0;
static LONG64 volatile gPebsDropped   = 0;   /* written by the CPU, never attributable  */
static LONG64 volatile gPebsKeepFull  = 0;   /* wanted but the keep buffer was full     */

static BOOLEAN
PebsDsLive(
	_In_ ULONG Cpu
	)
{
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return FALSE;
	return (gPebs[Cpu].DsArea != NULL) ? TRUE : FALSE;
}
static UINT64 volatile gPebsCr3    = 0;

/*
 * What the caller asked a record to CONTAIN (D119). The GPR group is always requested -- it is the
 * reason PEBS is here -- and these add to it. Stored rather than recomputed so the read-back the
 * arm path reports is comparable against what was actually asked for.
 */
static UINT64 volatile gPebsDataCfg = PEBS_DATA_CFG_GPR;

/*
 * Load-latency threshold in core cycles, or 0 for "do not use the load-latency event at all".
 * Non-zero switches PERFEVTSEL0 from INST_RETIRED to MEM_TRANS_RETIRED.LOAD_LATENCY and programs
 * MSR_PEBS_LD_LAT_THRESHOLD. Kept as state rather than recomputed so the arm read-back can report
 * what was actually programmed on each core.
 */
static UINT32 volatile gPebsLdLat = 0;

/* LBR entries ACTUALLY programmed after clamping to what the buffer was sized for. 0 = the LBR
 * group was not requested. Reported so a clamp cannot happen silently. */
static UINT32 volatile gPebsLbrEntries = 0;

/* Which rings PEBS counts. Default matches the historic behaviour: ring 3 only. */
static UINT32 volatile gPebsWantUsr = 1;
static UINT32 volatile gPebsWantOs  = 0;

/* Bytes per record slot the last `pebs alloc` actually RESERVED, after clamping. Returned to the
 * caller so it can report what was produced rather than what it asked for. */
static UINT32 volatile gPebsAllocStride = 0;

UINT32 NxcPebsAllocStride(void) { return gPebsAllocStride; }

/*
 * The record size implied by a DATA_CFG value. ONE function, so the buffer wall, the reported
 * stride and the drain all derive the number from the same place rather than three copies agreeing
 * by luck -- which is precisely how 160 survived in four places.
 *
 * Basic is unconditional. The rest are added only if their bit is set, in the architectural group
 * order, and each size is the one VERIFIED against Linux `struct pebs_*`.
 */
static UINT32
NxcPebsStrideFor(
	_In_ UINT64 DataCfg
	)
{
	UINT32 Bytes = NXCMD_PEBS_BASIC_BYTES;
	if (DataCfg & PEBS_DATA_CFG_MEM) Bytes += NXCMD_PEBS_MEM_BYTES;
	if (DataCfg & PEBS_DATA_CFG_GPR) Bytes += NXCMD_PEBS_GPR_BYTES;
	if (DataCfg & PEBS_DATA_CFG_XMM) Bytes += NXCMD_PEBS_XMM_BYTES;
	if (DataCfg & PEBS_DATA_CFG_LBR)
	{
		/* ⚠ DECODE THE STORED VALUE AS entries-1, MATCHING HOW IT WAS ENCODED. The +1 here and
		 * the -1 in NXCMD_PEBS_LBR_CFG are the same fact stated twice, in the two places that
		 * must agree; getting one without the other sizes the wall for the wrong record. */
		CONST UINT32 Entries = (UINT32)(((DataCfg >> 24) & 0xFFu) + 1u);
		Bytes += NXCMD_PEBS_LBR_BYTES(Entries);
	}
	return Bytes;
}
static volatile LONG   gPebsArmed  = 0;
static volatile LONG   gPebsCores  = 0;
/*
 * Per-core read-backs of the TWO registers that between them decide a record's contents. Per core,
 * not one global, so a partial effect across P and E cores cannot hide behind a single number --
 * this is a hybrid part and the capability probes are already per-core-type for the same reason.
 *
 * ⚠ BOTH ARE NEEDED TO NAME A FAILURE. DATA_CFG alone read back 0x2 and was still consistent with a
 * record that carried no GPRs, because the group selection and the adaptive-record enable are
 * different registers. One value could not distinguish "asked for the wrong thing" from "asked
 * correctly and never switched the feature on".
 */
static UINT64          gPebsDataCfgReadback[NXC_MAX_TRACE_CPUS];
static UINT64          gPebsEvtSelReadback[NXC_MAX_TRACE_CPUS];
static UINT64          gPebsLdLatReadback[NXC_MAX_TRACE_CPUS];

/* ---------------------------------------------------------------------------------------------
 * PEBS CR3 FILTERING, FOR REAL -- judged in the PMI, one record at a time.
 *
 * ⚠ PEBS HAS NO CR3 FILTER IN HARDWARE. PT has one; PEBS does not, and no amount of MSR
 * programming invents one. `pebs arm --pid` therefore RESOLVED a CR3 and then applied nothing, and
 * `pebs status` said so in as many words. This is the closing of that gap.
 *
 * THE MECHANISM. A PEBS record is written at retirement and carries no address-space identity, but
 * the CORE still holds it: CR3 at the moment the PMI is delivered is the address space the sampled
 * instruction retired in. The NMI follows the record by a few hundred cycles -- far inside a
 * scheduling quantum -- so reading CR3 in the handler identifies the record's owner.
 *
 * ⚠ THE THRESHOLD TRICK IS WHAT MAKES IT PER-RECORD RATHER THAN PER-BATCH. Setting
 * PebsInterruptThreshold to Base + ONE stride does NOT mean "one record then stop": the CPU keeps
 * appending and PebsIndex keeps climbing, and every subsequent write is also >= the threshold. So
 * the PMI fires after EVERY record while records accumulate normally. One record, one judgement.
 *
 * ⚠ REJECTION IS A REWIND, NOT A COPY. A rejected record is discarded by moving the CPU's own
 * cursor back over it, so the next record overwrites it in place. No second buffer, no memcpy in an
 * NMI, and the drain sees a dense array of kept records -- it needs no filter-awareness at all.
 *
 * WHAT THIS COSTS, STATED PLAINLY: one NMI per sample instead of one per buffer-full. That is why
 * the period floor is raised hard in filter mode (NxcPebsArm) -- at the unfiltered floor of 10000
 * this would be an NMI every 10000 instructions on every core at once.
 *
 * ⚠⚠ AND THE HISTORY, BECAUSE IT COST FOUR BUGCHECKS. The first version of this filter produced
 * four 0x80 NMI_HARDWARE_FAILUREs and was reverted wholesale, with a note saying PEBS scoping must
 * never introduce an NMI source again. That note named the wrong culprit. A bisect (A / B1 / B)
 * put the fault in the DEREFERENCE of DsArea inside this judge, and reading NxcPebsFree explained
 * why: it freed the buffers and only then NULLed the globals, publishing a pointer to freed memory
 * for the window in between. A stale pointer is invisible to a null check and fatal to a
 * dereference -- exactly the B1-survives / B-dies split the bisect drew. The free path now retires
 * before it destroys, and step B2 ran this same dereference clean across 40 rapid alloc/free pairs.
 * The NMI source was the AMPLIFIER (more NMIs, more chances to hit the window), never the cause.
 * ------------------------------------------------------------------------------------------- */
static BOOLEAN
PebsPmiJudge(
	_In_ ULONG  Cpu,
	_In_ UINT64 GlobalStatus
	)
{
	/*
	 * ⚠⚠ TEST **BOTH** CAUSES. Testing only PMC0's overflow bit is what produced bugcheck 0x80.
	 *
	 * PEBS raises its PMI through GLOBAL_STATUS bit 62 (OvfBuf, the DS buffer crossing its
	 * threshold), NOT through bit 0. Bit 0 says a counter overflowed -- which is what triggers the
	 * RECORD; bit 62 is what triggers the INTERRUPT. This tested bit 0 alone and returned FALSE for
	 * everything else, so an NMI WE caused went unclaimed by PT (bit 55 clear), unclaimed by the
	 * profiler (bit 32 clear) and unclaimed by us. That is 0x80, by definition.
	 *
	 * MEASURED: 24 NMIs, one per core, all GLOBAL_STATUS 0x4000000000000000, all
	 * CAUGHT(would-be-0x80). See PERF_GLOBAL_OVF_BUFFER.
	 */
	if ((GlobalStatus & PERF_GLOBAL_PEBS_CAUSES) == 0)
		return FALSE;
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return FALSE;
	/*
	 * ⚠⚠ THIS WAS `if (gPebsPmiFilter == 0) return FALSE;` AND IT WAS A FOURTH ROUTE TO 0x80.
	 *
	 * Its comment said "not our NMI source -- somebody else's counter", and the ARM PATH IN THIS
	 * SAME FILE FALSIFIES THAT. In unfiltered mode `NxcPebsArm` deliberately programs
	 * `PebsInterruptThreshold = Base + Span - Stride` -- "UNFILTERED: one PMI when the buffer is
	 * nearly full, purely so a wrap can be counted". So unfiltered PEBS ARMS A PMI, and this line
	 * then declined to claim the very interrupt we asked for, without clearing GLOBAL_STATUS.
	 *
	 * The delivery route is the one this file already documents: `trace arm --pmi` or `sample arm`
	 * points LVT PC at NMI delivery, and unfiltered PEBS never calls `TracePmiArmHere` -- it
	 * silently rides on whatever routing is already there. Overflow then arrives as an NMI that PT
	 * declines (bit 55 clear), the profiler declines (bit 32 clear), and this declined too.
	 * Unclaimed NMI is 0x80 by definition -- the same sentence the comment block above already
	 * wrote about bit 62, one path short of covering it.
	 *
	 * ⚠ THE RIGHT TEST IS "DID WE ARM PEBS ON THIS CORE", NOT "DID WE ASK FOR A FILTER". The filter
	 * decides whether records get JUDGED; it says nothing about who owns the interrupt. Ownership
	 * is what claiming an NMI is about, so it is what is asked here.
	 *
	 * The unfiltered path now falls through to the SAME reload/clear/unmask tail as the filtered
	 * one and only skips the record-judging block, so the two cannot drift apart the way a
	 * copied-out tail would. of this file.
	 */
	/*
	 * ⚠⚠ PER-CORE, NOT THE GLOBAL `gPebsArmed`. THE GLOBAL WAS WRONG AND IT REOPENED 0x80.
	 *
	 * `NxcPebsDisarm` does `InterlockedCompareExchange(&gPebsArmed, 0, 1)` FIRST and only then
	 * broadcasts `PebsArmOnEachCpu(0)` to stop the counters. So between those two statements every
	 * core still has PMC0 enabled and a live PEBS threshold, while the global already reads 0 -- and
	 * a PMI arriving in that window was declined here WITHOUT clearing GLOBAL_STATUS. An NMI we
	 * caused and refused to claim is bugcheck 0x80, which is the exact defect this gate was added to
	 * close, reintroduced through the flag it was keyed on.
	 *
	 * The file already documents the rule and I did not follow it: `gPebsPmiFilter` is cleared only
	 * AFTER the broadcast returns, precisely because "the judge reads it to decide whether an
	 * arriving PMI is ours at all. Clearing it first would strand both." `gPebsArmed` has the
	 * opposite lifetime -- it is the arm/disarm interlock, and it has to fall first so a second
	 * disarm is refused.
	 *
	 * `gPebs[Cpu].Armed` is published after this core's MSRs are programmed and retired only after
	 * they are stopped, so it tracks the HARDWARE rather than the intent. Found by an adversarial
	 * review of this fix, aimed at the change deliberately.
	 */
	if (gPebs[Cpu].Armed == 0 || gPebs[Cpu].DsArea == NULL)
		return FALSE;      /* this core has no live PEBS of ours -- genuinely somebody else's */

	/*
	 * ⚠ SNAPSHOT THE POINTER ONCE. Re-reading the global after the null test would reintroduce the
	 * retire race in miniature -- a pointer that passes the check and is freed before the
	 * dereference. This is the bug that produced the four 0x80s; see the block above.
	 */
	NXC_DS_AREA* CONST Ds = gPebs[Cpu].DsArea;
	if (Ds == NULL || gPebs[Cpu].Buffer == NULL)
		return FALSE;

	InterlockedIncrement64(&gPebsPmiCount);

	/*
	 * ⚠ ONLY THE JUDGING IS FILTER-GATED. Unfiltered PEBS still OWNS this interrupt and must still
	 * clear it, reload the counter and re-unmask LVT PC -- it simply has no CR3 test to apply and
	 * leaves the records in the DS buffer for the drain to collect. Everything below the closing
	 * brace is therefore shared by both modes.
	 */
	if (gPebsPmiFilter != 0)
	{
		CONST UINT64 Stride = (UINT64)gPebs[Cpu].Stride;
		CONST UINT64 Base   = Ds->PebsBufferBase;
		CONST UINT64 Idx    = Ds->PebsIndex;

		/* No complete record to judge. Reached when the counter overflowed without PEBS assisting --
		 * still ours to re-arm, so this falls through to the reload rather than returning. */
		if (Stride != 0 && Idx >= Base + Stride && Idx <= Ds->PebsAbsoluteMax)
		{
			CONST UINT64 Cr3Now = SampleCr3Frame(__readcr3());
			CONST UINT64 Want   = gPebsCr3;

			/*
			 * ⚠⚠ ONLY THE NEWEST RECORD IS ATTRIBUTABLE, AND THE REST ARE DISCARDED.
			 *
			 * CR3 read here speaks for the instruction that was just sampled -- the newest record,
			 * at Idx - Stride. It says NOTHING about records written earlier in this same window,
			 * and there are usually several: measured, the CPU writes records far faster
			 * than PMIs arrive. The first version rewound the newest record and left the others in
			 * the buffer, which then went out of the drain AS THOUGH FILTERED -- 372 records of
			 * which 27.4% were the target's, including 32 KERNEL IPs from a USR-only counter.
			 *
			 * A record whose address space we cannot name is not a record we may hand back. So the
			 * one we CAN name is copied out, everything else is counted as dropped, and the buffer
			 * is reset. Fewer samples, every one of them attributable -- which is the only version
			 * of this that is honest.
			 */
			CONST UINT64 InWindow = (Idx - Base) / Stride;      /* >= 1 */
			if (InWindow > 1)
				InterlockedAdd64(&gPebsDropped, (LONG64)(InWindow - 1));

			if (Want != 0 && Cr3Now != Want)
			{
				InterlockedIncrement64(&gPebsRejected);
			}
			else
			{
				/* Copy the attributable record into the keep buffer. Fixed size, no lock, no
				 * allocation -- everything an NMI is allowed to do. */
				void* CONST Keep = gPebs[Cpu].KeepBuf;
				CONST UINT32 KMax = gPebs[Cpu].KeepMax;
				CONST UINT64 KW   = gPebs[Cpu].KeepWrite;
				CONST UINT64 KR   = gPebs[Cpu].KeepRead;

				/* Full means the DRAIN has fallen behind, not that capture is over. One slot frees
				 * the moment usermode reads one. */
				if (Keep != NULL && KMax != 0 && (KW - KR) < (UINT64)KMax)
				{
					CONST UINT8* CONST Src = (CONST UINT8*)(ULONG_PTR)(Idx - Stride);
					UINT8* CONST Dst = (UINT8*)Keep + ((SIZE_T)(KW % (UINT64)KMax) * (SIZE_T)Stride);
					for (UINT64 b = 0; b < Stride; b++)
						Dst[b] = Src[b];

					/* ⚠ THE INDEX MOVES LAST. A drain running on another core must never see a slot
					 * counted before its bytes are there -- same rule as the BTF ring's commit. */
					_mm_sfence();
					gPebs[Cpu].KeepWrite = KW + 1;
					InterlockedIncrement64(&gPebsKept);
				}
				else
				{
					/* A match we could not store because the reader is behind. A real loss, and it
					 * must never be folded into "rejected" -- opposite meanings. */
					InterlockedIncrement64(&gPebsKeepFull);
				}
			}

			/* Reset the cursor: nothing left in the DS buffer is attributable. */
			Ds->PebsIndex = Base;
		}
	}

	/*
	 * Reload the counter, then clear the overflow. That order, not the reverse: clearing first
	 * leaves a window in which the counter sits at 0 and free-runs. Same argument as the sampling
	 * profiler's reload above -- and PEBS's own auto-reload does not cover an overflow that
	 * produced no record.
	 */
	/*
	 * ⚠ CLEAR EVERY BIT WE TESTED, NOT JUST BIT 0. A cause that is tested but never cleared
	 * re-asserts immediately and the PMI arrives again the instant we return -- an interrupt storm
	 * rather than a bugcheck, which is the failure mode that replaces 0x80 if only half of this is
	 * fixed. PERF_GLOBAL_PEBS_CAUSES names the same set as the test above so the two cannot drift.
	 */
	__writemsr(IA32_PMC0, (0ULL - gPebsPeriod) & 0x0000FFFFFFFFFFFFULL);
	__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_PEBS_CAUSES);

	/* ⚠ RE-UNMASK. The hardware masks LVT PC as it delivers, so without this exactly ONE record is
	 * ever judged and the filter silently stops filtering -- which reads as "the filter does
	 * nothing", the same symptom it was built to remove. */
	{
		CONST UINT64 Lvt = TraceLvtPcRead();
		if ((Lvt & LVT_MASKED) != 0)
			TraceLvtPcWrite(Lvt & ~LVT_MASKED);
	}

	return TRUE;
}

static ULONG_PTR
PebsArmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	CONST UINT32 Enable = (UINT32)Context;
	CONST ULONG  Cpu    = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS)
		return 0;

	if (Enable == 0)
	{
		/*
		 * ⚠ THE ORDER HERE IS THE WHOLE SAFETY ARGUMENT, and it is the mirror of NxcTraceFree's.
		 * Stop the counter, stop PEBS, and only THEN drop IA32_DS_AREA. Clearing DS_AREA first would
		 * leave a core with PEBS enabled and no valid buffer pointer.
		 */
		__writemsr(IA32_PERF_GLOBAL_CTRL,
		           __readmsr(IA32_PERF_GLOBAL_CTRL) & ~PERF_GLOBAL_PMC0_EN);
		__writemsr(IA32_PERFEVTSEL0, 0);
		__writemsr(IA32_PEBS_ENABLE, 0);
		__writemsr(IA32_DS_AREA, 0);
		/* ⚠ BOTH CAUSES, for the same reason the judge clears both: a bit 62 (DS buffer overflow)
		 * left set here survives the disarm as a latched cause with nobody left watching for it. */
		__writemsr(IA32_PERF_GLOBAL_OVF_CTRL, PERF_GLOBAL_PEBS_CAUSES);

		/* ⚠ THE LVT GOES BACK LAST, AFTER THE COUNTER IS ALREADY STOPPED. Restoring it first would
		 * leave a live PMC0 whose overflow arrives at the original vector while we still believe we
		 * own the delivery. Same argument as the DS_AREA ordering directly above. */
		TracePmiDisarmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PEBS);

		/*
		 * ⚠ RETIRED LAST, AFTER THE COUNTER IS STOPPED -- the mirror of the arm. While this is still
		 * set the judge will CLAIM an arriving PEBS PMI, which is exactly right: until the writes
		 * above land, this core can still generate one.
		 */
		gPebs[Cpu].Armed = 0;
		return 0;
	}

	if (gPebs[Cpu].DsArea == NULL || gPebs[Cpu].Buffer == NULL)
		return 0;

	/* Counter disabled while every other register is set up. Enabling first would start counting
	 * against a DS area the CPU has not been told about yet. */
	__writemsr(IA32_PERF_GLOBAL_CTRL,
	           __readmsr(IA32_PERF_GLOBAL_CTRL) & ~PERF_GLOBAL_PMC0_EN);
	__writemsr(IA32_PERFEVTSEL0, 0);
	__writemsr(IA32_PEBS_ENABLE, 0);

	/* The index is ours to reset; the CPU advances it from here. */
	gPebs[Cpu].DsArea->PebsIndex          = gPebs[Cpu].DsArea->PebsBufferBase;
	gPebs[Cpu].DsArea->PebsCounterReset[0] = (0ULL - gPebsPeriod) & 0x0000FFFFFFFFFFFFULL;

	/*
	 * ⚠⚠ RE-PLACE THE WALL FOR THE STRIDE WE ACTUALLY SELECTED.
	 *
	 * Alloc sized everything for NXCMD_PEBS_STRIDE_MAX because it could not know what arm would
	 * request. Now we know. AbsoluteMax must sit at an EXACT MULTIPLE of the real record size from
	 * the base, or the last record starts inside the buffer and ends past it -- that is defence 1
	 * from the alloc comment, and it is the defence that was already wrong once at 160-vs-176.
	 *
	 * This can only ever move the wall DOWN from the worst case, never up, so the allocation stays
	 * larger than the wall by at least the slack record no matter which groups were asked for.
	 */
	{
		CONST UINT32 Stride = NxcPebsStrideFor(gPebsDataCfg);

		/*
		 * ⚠ REFUSE, DO NOT CLAMP. If the selected groups need more per record than `pebs alloc`
		 * reserved, there is nowhere safe to put them: the CPU writes these records itself and
		 * would run past the wall. Clamping would silently deliver fewer LBR entries than asked
		 * for, which is the silent-partial shape. NxcPebsArm has already failed the whole arm.
		 */
		if (Stride > gPebs[Cpu].AllocStride)
			return 0;
		CONST UINT64 Base   = gPebs[Cpu].DsArea->PebsBufferBase;
		CONST UINT64 Span   = (UINT64)gPebs[Cpu].Records * Stride;

		gPebs[Cpu].DsArea->PebsAbsoluteMax        = Base + Span;
		gPebs[Cpu].BufferBytes                    = (UINT32)Span;
		gPebs[Cpu].Stride                         = Stride;

		/*
		 * ⚠⚠ THE THRESHOLD IS WHAT DECIDES PER-RECORD VERSUS PER-BUFFER, and the filtering mode is
		 * the only difference between these two lines.
		 *
		 * UNFILTERED: one PMI when the buffer is nearly full, purely so a wrap can be counted.
		 *
		 * FILTERED: Base + ONE stride. That does NOT stop collection after one record -- the CPU
		 * keeps appending and PebsIndex keeps climbing, so every later write is also >= the
		 * threshold and every record gets its own PMI. One record, one CR3 judgement, which is the
		 * whole reason the filter is exact rather than batch-granular.
		 */
		gPebs[Cpu].DsArea->PebsInterruptThreshold =
			(gPebsPmiFilter != 0) ? (Base + Stride) : (Base + Span - Stride);
	}

	__writemsr(IA32_DS_AREA, (UINT64)(ULONG_PTR)gPebs[Cpu].DsArea);
	__writemsr(MSR_PEBS_DATA_CFG, gPebsDataCfg);
	__writemsr(IA32_PMC0, (0ULL - gPebsPeriod) & 0x0000FFFFFFFFFFFFULL);
	__writemsr(IA32_PEBS_ENABLE, PEBS_ENABLE_PMC0);

	/* USR only, OS clear -- same reasoning as the profiler: the target's execution is the subject,
	 * and counting ring 0 would include the machinery doing the counting.
	 *
	 * ADAPTIVE is what makes MSR_PEBS_DATA_CFG mean anything; see the define. */
	/*
	 * ⚠ THE THRESHOLD MSR IS WRITTEN BEFORE THE EVENT THAT CONSULTS IT, and cleared when the event
	 * is not in use. A stale threshold left behind from a previous arm would silently filter a
	 * later run -- an empty buffer with no explanation, which is the hardest kind of defect to
	 * attribute because nothing reports an error.
	 */
	if (gPebsLdLat != 0)
		__writemsr(MSR_PEBS_LD_LAT_THRESHOLD, (UINT64)gPebsLdLat);
	else
		__writemsr(MSR_PEBS_LD_LAT_THRESHOLD, 0);

	/*
	 * ⚠⚠ THE LVT IS CLAIMED BEFORE THE COUNTER IS ENABLED, AND THE FILTER IS ABANDONED IF IT CANNOT
	 * BE. Both halves matter.
	 *
	 * BEFORE, because enabling PMC0 first opens a window in which an overflow is delivered through
	 * whatever vector the LVT still holds -- someone else's handler, receiving an interrupt we
	 * caused.
	 *
	 * AND ABANDONED, because a core that cannot reach its LVT PC would otherwise run with the
	 * one-record threshold and no PMI to act on it: PebsIndex would advance and nothing would ever
	 * judge or rewind. That is not "filtering slightly worse", it is unfiltered data reported as
	 * filtered -- the silent-partial shape this file refuses everywhere else. Refuse the core.
	 */
	if (gPebsPmiFilter != 0 &&
	    TracePmiArmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PEBS) != NXC_TRACE_PMIWHY_LIVE)
	{
		__writemsr(IA32_PERFEVTSEL0, 0);
		__writemsr(IA32_PEBS_ENABLE, 0);
		__writemsr(IA32_DS_AREA, 0);
		return 0;   /* this core does not arm; gPebsCores will report the shortfall */
	}

	__writemsr(IA32_PERFEVTSEL0,
	           (gPebsLdLat != 0 ? PERFEVTSEL_MEM_TRANS_LOAD_LAT : PERFEVTSEL_INST_RETIRED_P) |
	           (gPebsWantUsr ? PERFEVTSEL_USR : 0ull) |
	           (gPebsWantOs  ? PERFEVTSEL_OS  : 0ull) |
	           PERFEVTSEL_EN | PERFEVTSEL_ADAPTIVE);
	__writemsr(IA32_PERF_GLOBAL_CTRL,
	           __readmsr(IA32_PERF_GLOBAL_CTRL) | PERF_GLOBAL_PMC0_EN);

	/*
	 * ⚠ READ BACK. A WRMSR that did not take shows up much later as "the buffer is empty", with
	 * nothing pointing here -- the same argument the RTIT arm makes for itself.
	 */
	/*
	 * ⚠ DATA_CFG IS READ BACK TOO, AND ITS ABSENCE FROM THIS CHECK WAS A REAL DEFECT.
	 *
	 * The first armed run produced records whose OWN size field read 32 -- the Basic group alone --
	 * meaning the GPR group never made it in. Two of the three MSRs written here were verified and
	 * the third was not, and the third is the one that silently did nothing. Recorded per core so a
	 * partial effect across P and E cores cannot hide behind a single number.
	 */
	/*
	 * ⚠ AND THE READ-BACK THAT WAS ADDED WAS STILL THE WRONG ONE. DATA_CFG came back 0x2 on 24/24
	 * cores, which looked like a clean verification and explained nothing, because the register that
	 * had not been written was IA32_PERFEVTSEL0's ADAPTIVE bit. A read-back only proves what it
	 * covers; adding one register to the check while a second went unchecked reproduced the original
	 * defect one register over. Both travel now, and usermode names which one is missing.
	 */
	gPebsDataCfgReadback[Cpu] = __readmsr(MSR_PEBS_DATA_CFG);
	gPebsEvtSelReadback[Cpu]  = __readmsr(IA32_PERFEVTSEL0);
	/* Third register, same argument as the other two: a threshold that did not take is invisible
	 * except as an empty buffer, with nothing pointing here. */
	gPebsLdLatReadback[Cpu]   = __readmsr(MSR_PEBS_LD_LAT_THRESHOLD);

	if (__readmsr(IA32_DS_AREA) != (UINT64)(ULONG_PTR)gPebs[Cpu].DsArea ||
	    (__readmsr(IA32_PEBS_ENABLE) & PEBS_ENABLE_PMC0) == 0)
	{
		__writemsr(IA32_PERF_GLOBAL_CTRL,
		           __readmsr(IA32_PERF_GLOBAL_CTRL) & ~PERF_GLOBAL_PMC0_EN);
		__writemsr(IA32_PERFEVTSEL0, 0);
		__writemsr(IA32_PEBS_ENABLE, 0);
		__writemsr(IA32_DS_AREA, 0);
		/* ⚠ GIVE THE LVT BACK ON THIS PATH TOO. It was claimed a few lines above and this core is
		 * now not arming; leaking the reference would hold NMI delivery for a feature that ends up
		 * with no counter behind it. */
		TracePmiDisarmHere(&gTrace[Cpu], NXC_LVTPC_OWNER_PEBS);
		return 0;
	}

	/*
	 * ⚠ PUBLISHED LAST, AFTER EVERY MSR IS PROGRAMMED. This is what the PMI judge tests to decide
	 * whether an arriving PEBS interrupt is ours, so it must not be true before the hardware that
	 * generates one is actually live. See the note on the field.
	 */
	gPebs[Cpu].Armed = 1;

	InterlockedIncrement(&gPebsCores);
	return 0;
}

NTSTATUS
NxcPebsArm(
	_In_ UINT64 Cr3Filter,
	_In_ UINT64 Period,
	_In_ UINT32 Groups,          /* NXCMD_PEBS_ARM_FLAG_* -- intent, not MSR bits */
	_In_ UINT32 LdLat,           /* 0 = INST_RETIRED; non-zero = load-latency threshold, cycles */
	_Out_ UINT32* OutArmed
	)
{
	*OutArmed = 0;

	if (gPebsCpus == 0)
		return STATUS_INVALID_DEVICE_STATE;
	if (Period < 10000ull || Period > 0x0000FFFFFFFFFFFFull)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠⚠ THE FILTERED PERIOD FLOOR, AND IT IS A REFUSAL RATHER THAN A CLAMP.
	 *
	 * Filtering costs one NMI PER RECORD instead of one per buffer-full. At the unfiltered floor of
	 * 10000 that is an NMI every 10000 retired instructions on every core simultaneously -- roughly
	 * 300k/sec/core here, each thousands of cycles deep. That is not a slow machine, it is a machine
	 * that spends its time in NMI handlers.
	 *
	 * NXCMD_PEBS_PMIFILTER_MIN_PERIOD is ~1e6, which puts the interrupt rate near 3k/sec/core: real
	 * overhead, bounded, and stated. Refused rather than clamped because a caller who asked for a
	 * 10000-instruction period and silently got 1000000 would compute rates from the number they
	 * asked for -- reporting REQUESTED instead of PRODUCED, which is the stub shape.
	 */
	if ((Groups & NXCMD_PEBS_ARM_FLAG_PMIFILTER) != 0 &&
	    Period < NXCMD_PEBS_PMIFILTER_MIN_PERIOD)
		return STATUS_INVALID_PARAMETER;
	/*
	 * ⚠ TRANSLATE INTENT TO MSR BITS HERE, AND REFUSE ANYTHING NOT UNDERSTOOD.
	 *
	 * Usermode sends NXCMD_PEBS_ARM_FLAG_*, never a raw DATA_CFG value. This register decides how
	 * many bytes the CPU writes per record into a buffer it was handed a pointer to, so an
	 * unrecognised bit here is not a cosmetic error -- it is the hardware writing a size the wall
	 * was not placed for. Unknown bits are REFUSED rather than masked off, because silently
	 * dropping part of a request is the silent-partial shape.
	 */
	if ((Groups & ~((UINT32)NXCMD_PEBS_ARM_FLAG_ALL | NXCMD_PEBS_ARM_LBR_MASK)) != 0)
		return STATUS_INVALID_PARAMETER;

	/* The entry count shares the word with the flags -- bits 15:8. See NXCMD_PEBS_ARM_LBR_*. */
	CONST UINT32 LbrEntries = NXCMD_PEBS_ARM_LBR_GET(Groups);

	if (InterlockedCompareExchange(&gPebsArmed, 1, 0) != 0)
		return STATUS_ALREADY_COMMITTED;

	{
		UINT64 Cfg = PEBS_DATA_CFG_GPR;    /* always: the registers are why PEBS is here */
		if (Groups & NXCMD_PEBS_ARM_FLAG_MEM) Cfg |= PEBS_DATA_CFG_MEM;

		/* A load-latency threshold implies the MemInfo group -- the whole reason to use that event
		 * is the fields MemInfo carries. Asking for one without the other would arm a memory event
		 * and then throw away what it measured, which is a stub by another route. */
		if (LdLat != 0) Cfg |= PEBS_DATA_CFG_MEM;

		if (Groups & NXCMD_PEBS_ARM_FLAG_XMM) Cfg |= PEBS_DATA_CFG_XMM;

		/*
		 * Ring selection. Neither bit set keeps the historic ring-3-only behaviour rather than
		 * counting nothing -- a counter with neither USR nor OS never fires, which would look like
		 * a broken feature instead of a bad request.
		 */
		{
			/*
			 * ⚠⚠ THE FIRST VERSION MADE `--kernel` MEAN "KERNEL ONLY" (found).
			 *
			 * It read `gPebsWantUsr = (WantU || !WantO)`, so asking for ring 0 CLEARED ring 3:
			 * PERFEVTSEL read back 0x4004200C0 -- OS set, USR clear -- when the documented intent,
			 * and PT's behaviour on the same flag, is that ring 0 is ADDED. Following a usermode
			 * module into its own driver needs BOTH rings in one capture; kernel-only would have
			 * silently dropped the usermode half of exactly the workflow this was built for.
			 *
			 * The flags are literal now: each bit enables its ring, and neither bit set falls back
			 * to ring 3 so that a counter is never armed with both rings off (it would simply never
			 * fire, which reads as a broken feature rather than a bad request). PlatformCtl's
			 * `--kernel` sets BOTH bits, which is what makes it additive.
			 */
			CONST UINT32 WantU = (Groups & NXCMD_PEBS_ARM_FLAG_USR) != 0;
			CONST UINT32 WantO = (Groups & NXCMD_PEBS_ARM_FLAG_OS)  != 0;
			gPebsWantUsr = (WantU || (!WantU && !WantO)) ? 1u : 0u;
			gPebsWantOs  = WantO;
		}

		if (Groups & NXCMD_PEBS_ARM_FLAG_LBR)
		{
			/*
			 * ⚠ CLAMPED TO WHAT THE BUFFER WAS SIZED FOR, NOT TO WHAT WAS ASKED.
			 *
			 * `pebs alloc` sized every record for NXCMD_PEBS_LBR_MAX_ENTRIES. A request above that
			 * would have the CPU write past the wall, so it is clamped rather than honoured --
			 * and clamping SILENTLY would be the silent-partial shape, so the clamped value is
			 * reported through LbrEntries and shows up in `pebs status`.
			 */
			UINT32 Ent = LbrEntries;
			if (Ent == 0) Ent = NXCMD_PEBS_LBR_MAX_ENTRIES;
			if (Ent > NXCMD_PEBS_LBR_MAX_ENTRIES) Ent = NXCMD_PEBS_LBR_MAX_ENTRIES;
			Cfg |= NXCMD_PEBS_LBR_CFG(Ent);      /* the -1 encoding lives inside that macro */
			gPebsLbrEntries = Ent;
		}
		else
		{
			gPebsLbrEntries = 0;
		}

		/*
		 * ⚠ CHECK THE FIT HERE, BEFORE THE IPI, SO THE DIAGNOSTIC IS THE TRUE ONE.
		 *
		 * The per-core arm also refuses an oversized record, but if every core refuses, the caller
		 * would be told "no core armed -- DS_AREA or PEBS_ENABLE did not read back". That message
		 * names two registers that were fine and sends the reader to the wrong place. The real
		 * cause is knowable right now: the buffer was reserved for a smaller record.
		 */
		{
			CONST UINT32 Need = NxcPebsStrideFor(Cfg);
			if (gPebsCpus != 0 && Need > gPebs[0].AllocStride)
			{
				InterlockedExchange(&gPebsArmed, 0);
				TrcLog("pebs: refusing arm -- %u byte record needs more than the %u reserved by "
				       "alloc. Re-run `pebs alloc` sized for these groups.\n",
				       Need, gPebs[0].AllocStride);
				return STATUS_BUFFER_TOO_SMALL;
			}
		}

		gPebsDataCfg = Cfg;
		gPebsLdLat   = LdLat;
	}

	gPebsPeriod = Period;
	gPebsCr3    = SampleCr3Frame(Cr3Filter);
	InterlockedExchange(&gPebsCores, 0);

	/*
	 * ⚠⚠ THE FILTER NEEDS A CR3 TO COMPARE AGAINST, AND WITHOUT ONE IT IS NOT A FILTER.
	 *
	 * `--pmi-filter` with no `--pid` would arm an NMI per record, judge every one of them against
	 * "match anything", and keep the lot -- all of the cost and none of the scoping, while `pebs
	 * status` announced that filtering was on. Refused instead.
	 */
	if ((Groups & NXCMD_PEBS_ARM_FLAG_PMIFILTER) != 0 && gPebsCr3 == 0)
	{
		InterlockedExchange(&gPebsArmed, 0);
		TrcLog("pebs: --pmi-filter needs a target CR3; pass --pid.\n");
		return STATUS_INVALID_PARAMETER;
	}


	/*
	 * ⚠ NO KEEP BUFFER MEANS NO FILTER. The judge copies each attributable record out of the DS
	 * buffer; without somewhere to copy it, the filter would count matches it cannot deliver and
	 * the drain would fall back to the raw DS buffer -- i.e. unfiltered data under a filtered
	 * label, which is the exact defect this whole path just had. Refuse instead.
	 */
	for (UINT32 ci = 0; ci < gPebsCpus; ci++)
	{
		if ((Groups & NXCMD_PEBS_ARM_FLAG_PMIFILTER) != 0 && gPebs[ci].KeepBuf == NULL)
		{
			InterlockedExchange(&gPebsArmed, 0);
			TrcLog("pebs: --pmi-filter refused -- cpu %u has no keep buffer. Re-run `pebs alloc` with fewer records.\n", ci);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		gPebs[ci].KeepWrite = 0;
		gPebs[ci].KeepRead  = 0;
	}
	/*
	 * ⚠ PREPARE THE NMI ROUTE BEFORE THE BROADCAST, AND DO NOT ARM THE FILTER IF IT FAILED. The
	 * per-core claim happens at IPI_LEVEL inside PebsArmOnEachCpu and cannot register a callback or
	 * map a page; both are done here, at PASSIVE. A core pointed at NMI with no callback registered
	 * is an unclaimed NMI -- bugcheck 0x80.
	 */
	gPebsPmiFilter = 0;
	if ((Groups & NXCMD_PEBS_ARM_FLAG_PMIFILTER) != 0)
	{
		if (TracePmiPrepare() == 0)
		{
			InterlockedExchange(&gPebsArmed, 0);
			TrcLog("pebs: --pmi-filter requested but the NMI callback could not be registered -- "
			       "REFUSING, rather than arming machine-wide and calling it filtered.\n");
			return STATUS_UNSUCCESSFUL;
		}
		gPebsPmiFilter = 1;
		InterlockedExchange64(&gPebsKept, 0);
		InterlockedExchange64(&gPebsRejected, 0);
		InterlockedExchange64(&gPebsPmiCount, 0);
	}

	(void)KeIpiGenericCall(PebsArmOnEachCpu, 1);

	if (gPebsCores == 0)
	{
		(void)KeIpiGenericCall(PebsArmOnEachCpu, 0);
		InterlockedExchange(&gPebsArmed, 0);
		gPebsPmiFilter = 0;   /* the disarm pass above already returned every LVT reference */
		TrcLog("pebs: no core armed -- DS_AREA or PEBS_ENABLE did not read back, or the LVT PC "
		       "was unreachable with --pmi-filter\n");
		return STATUS_UNSUCCESSFUL;
	}

	*OutArmed = (UINT32)gPebsCores;
	TrcLog("pebs: DATA_CFG read back as 0x%llX on cpu0 (2 = GPR group requested)\n",
	       gPebsDataCfgReadback[0]);
	TrcLog("pebs: ARMED on %ld core(s), period %llu, cr3 0x%llX, pmi-filter %s\n",
	       gPebsCores, Period, gPebsCr3, (gPebsPmiFilter != 0) ? "ON" : "off");
	return STATUS_SUCCESS;
}

/* PMI-filter evidence for `pebs status` (D3: what was PRODUCED). Kept + rejected is every record
 * the hardware wrote; kept alone is what survives in the buffer for the drain. */
void
NxcPebsFilterStats(
	_Out_ UINT32* OutActive,
	_Out_ UINT64* OutKept,
	_Out_ UINT64* OutRejected,
	_Out_ UINT64* OutPmis
	)
{
	*OutActive   = gPebsPmiFilter;
	*OutKept     = (UINT64)gPebsKept;
	*OutRejected = (UINT64)gPebsRejected;
	*OutPmis     = (UINT64)gPebsPmiCount;
}

/*
 * The two numbers that make the filter HONEST rather than merely quiet.
 *
 * Dropped  -- records the CPU wrote that no PMI could attribute, discarded rather than
 *             delivered. Before these were silently handed back as filtered
 *             output, which is how a drain came back 27.4% on-target with kernel IPs in it.
 * KeepFull -- records that MATCHED and were lost anyway because the keep buffer was full.
 *             A different failure from a rejection and it must never be counted as one.
 */
void
NxcPebsFilterLoss(
	_Out_ UINT64* OutDropped,
	_Out_ UINT64* OutKeepFull
	)
{
	*OutDropped  = (UINT64)gPebsDropped;
	*OutKeepFull = (UINT64)gPebsKeepFull;
}

/*
 * The CR3 the filter is actually comparing against. Reported because "0 kept, 277041 rejected" with
 * the target provably running says the COMPARISON is wrong, and a comparison cannot be debugged
 * from one side of it. This is the value as stored -- already masked by SampleCr3Frame at arm.
 */
UINT64
NxcPebsTargetCr3(
	void
	)
{
	return gPebsCr3;
}

NTSTATUS
NxcPebsDrain(
	_In_  UINT32 Cpu,
	_Out_writes_bytes_(Cap) void* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutBytes,
	_Out_ UINT32* OutWritten
	)
{
	*OutBytes   = 0;
	*OutWritten = 0;

	if (Out == NULL || Cap == 0 || Cpu >= NXC_MAX_TRACE_CPUS)
		return STATUS_INVALID_PARAMETER;
	if (gPebs[Cpu].DsArea == NULL || gPebs[Cpu].Buffer == NULL)
		return STATUS_INVALID_DEVICE_STATE;

	/*
	 * ⚠ THE CPU'S OWN CURSOR IS THE ONLY THING THAT SAYS HOW MUCH IS THERE. PebsIndex is advanced by
	 * hardware as it writes; the difference from the base is the byte count. Anything we counted
	 * ourselves would be a guess about what the processor did.
	 */
	/*
	 * WHICH BUFFER ARE WE DRAINING, and it is not always the CPU's.
	 *
	 * With the PMI CR3 filter running, the DS buffer holds records the CPU wrote and we could NOT
	 * attribute -- they are discarded on every PMI. The records that survived attribution live in
	 * the keep buffer, and that is the only thing entitled to be called filtered output.
	 *
	 * measured, before this split existed: draining the DS buffer under the filter
	 * returned 372 records of which 27.4% belonged to the target, including 32 KERNEL IPs from a
	 * USR-only counter. It was unfiltered data wearing a filtered label.
	 */
	if (gPebsPmiFilter != 0 && gPebs[Cpu].KeepBuf != NULL && gPebs[Cpu].KeepMax != 0)
	{
		CONST UINT32 Stride = (gPebs[Cpu].Stride != 0) ? gPebs[Cpu].Stride : NXC_PEBS_STRIDE;
		CONST UINT32 KMax   = gPebs[Cpu].KeepMax;
		CONST UINT64 KW     = gPebs[Cpu].KeepWrite;   /* snapshot: the judge may advance it */
		UINT64       KR     = gPebs[Cpu].KeepRead;

		CONST UINT64 Pending  = KW - KR;
		CONST UINT32 CanTake  = Cap / Stride;
		CONST UINT32 Take     = (Pending < (UINT64)CanTake) ? (UINT32)Pending : CanTake;

		/*
		 * ⚠⚠ THIS CONSUMES. That is the entire point, and its absence was a real defect: with a
		 * fill-once buffer a long capture kept the FIRST N matches and silently lost every one
		 * after, which for a real target means missing exactly the behaviour you armed for.
		 *
		 * Copied record by record because the ring wraps -- a single RtlCopyMemory would splice the
		 * wrap point into the middle of the output and hand back a record that never existed.
		 */
		for (UINT32 r = 0; r < Take; r++)
		{
			CONST UINT8* CONST Src =
				(CONST UINT8*)gPebs[Cpu].KeepBuf + ((SIZE_T)((KR + r) % (UINT64)KMax) * (SIZE_T)Stride);
			RtlCopyMemory((UINT8*)Out + ((SIZE_T)r * (SIZE_T)Stride), Src, Stride);
		}

		/* ⚠ ADVANCE ONLY BY WHAT WAS ACTUALLY COPIED. Advancing by Pending would free slots whose
		 * contents never reached the caller -- silent data loss dressed as a successful drain. */
		gPebs[Cpu].KeepRead = KR + Take;

		*OutBytes   = Take * Stride;
		*OutWritten = (UINT32)((Pending > 0xFFFFFFFFull) ? 0xFFFFFFFFul : Pending) * Stride;
		return STATUS_SUCCESS;
	}

	CONST UINT64 Base  = gPebs[Cpu].DsArea->PebsBufferBase;
	CONST UINT64 Index = gPebs[Cpu].DsArea->PebsIndex;

	if (Index < Base || (Index - Base) > gPebs[Cpu].BufferBytes)
		return STATUS_DATA_ERROR;   /* the cursor is outside its own buffer -- report, never parse */

	CONST UINT32 Written = (UINT32)(Index - Base);
	*OutWritten = Written;

	CONST UINT32 Give = (Written < Cap) ? Written : Cap;
	RtlCopyMemory(Out, gPebs[Cpu].Buffer, Give);
	*OutBytes = Give;

	/*
	 * ⚠ RAW BYTES, DELIBERATELY UNPARSED, AND THAT IS NOT LAZINESS.
	 *
	 * D115 promised the drain would compare each record's OWN size field against the requested
	 * 160-byte stride and refuse on a mismatch. Making that check requires knowing WHERE in the first
	 * qword the size lives, and that bit split is not something this session could source
	 * authoritatively. Writing it from recall would produce a check that PASSES on the wrong field --
	 * strictly worse than no check, because it would then be trusted.
	 *
	 * So the bytes go up unmodified and usermode states its assumptions and TESTS them: an IP at
	 * +0x08 that is canonical and inside the target is evidence for the Basic layout; one that is not
	 * says the layout differs, at which point the raw first qword is right there to read. The
	 * hardware names the format, exactly as the PT decoder's fail-closed stop will name the block
	 * packets.
	 */
	return STATUS_SUCCESS;
}

NTSTATUS
NxcPebsDisarm(
	_Out_ UINT32* OutDisarmed
	)
{
	*OutDisarmed = 0;
	if (InterlockedCompareExchange(&gPebsArmed, 0, 1) != 1)
		return STATUS_INVALID_DEVICE_STATE;

	(void)KeIpiGenericCall(PebsArmOnEachCpu, 0);
	*OutDisarmed = (UINT32)gPebsCores;
	InterlockedExchange(&gPebsCores, 0);

	/*
	 * ⚠ CLEAR THE FILTER FLAG ONLY AFTER THE BROADCAST HAS RETURNED. The per-core disarm reads it
	 * to decide whether it holds an LVT reference, and the judge reads it to decide whether an
	 * arriving PMI is ours at all. Clearing it first would strand both.
	 */
	gPebsPmiFilter = 0;

	/*
	 * ⚠ GIVE THE SHARED NMI PLUMBING BACK IF WE WERE THE LAST HOLDER -- AFTER the broadcast, never
	 * before, for the same reason NxcTraceDisarm documents: every core must have restored its LVT PC
	 * first, or the hardware is still asking for an interrupt whose handler just went away.
	 *
	 * Previously this path released NOTHING, so arming the filter and disarming it leaked the NMI
	 * callback until module unload. That leak was harmless on its own -- but it meant PEBS was a
	 * consumer of a shared resource that never participated in releasing it, which is precisely how
	 * the ownership check in NxcSampleDisarm came to be wrong about it.
	 *
	 * TracePmiReleaseAll refuses while any core still holds the LVT, so this is safe to call
	 * unconditionally even with PT or the profiler still armed.
	 */
	TracePmiReleaseAll();

	TrcLog("pebs: disarmed -- filter kept %lld, rejected %lld, across %lld PMI(s)\n",
	       gPebsKept, gPebsRejected, gPebsPmiCount);
	return STATUS_SUCCESS;
}

void
NxcPebsFree(
	void
	)
{
	/*
	 * ⚠ DISARM FIRST, AND THIS IS NO LONGER A NOTE ABOUT THE FUTURE -- stage 2 exists now, so a core
	 * really can be holding IA32_DS_AREA pointed at these allocations. Freeing them while PEBS is
	 * enabled hands the frames back to the allocator while the CPU is still writing records into
	 * them, which is the identical bug NxcTraceFree documents for ToPA buffers.
	 */
	if (InterlockedCompareExchange(&gPebsArmed, 1, 1) == 1)
	{
		UINT32 Off = 0;
		(void)NxcPebsDisarm(&Off);
		TrcLog("pebs: free disarmed %u core(s) first -- they were writing to these pages\n", Off);
	}

	/*
	 * ⚠ NOTHING TO DISARM YET, AND THAT IS WHY THIS IS SAFE TODAY. Stage 1 never wrote IA32_DS_AREA,
	 * so no processor holds a pointer into these allocations. The moment stage 2 exists this function
	 * MUST clear IA32_DS_AREA and IA32_PEBS_ENABLE on every core FIRST -- freeing memory the CPU is
	 * writing records into is the identical mistake NxcTraceFree documents for ToPA buffers.
	 */
	for (UINT32 i = 0; i < NXC_MAX_TRACE_CPUS; i++)
	{
		/*
		 * ⚠⚠ RETIRE THE POINTER BEFORE FREEING WHAT IT POINTS AT. THIS ORDER IS THE WHOLE POINT.
		 *
		 * This read `MmFreeContiguousMemory(p); p = NULL;` -- which leaves a window, between the free
		 * and the store, where the global is a NON-NULL POINTER TO FREED MEMORY. Anything that reads
		 * these fields without a lock sees a valid-looking pointer and dereferences it.
		 *
		 * ⚠ THE NMI CALLBACK IS EXACTLY SUCH A READER, and it cannot take a lock. That is consistent
		 * with the whole bisect: step B1, whose body checks `DsArea` but NEVER
		 * DEREFERENCES it, survived 16 commands; step B, whose body reads `DsArea->PebsBufferBase`
		 * and `->PebsIndex`, died on the first command. A stale non-NULL pointer is invisible to a
		 * null check and fatal to a dereference.
		 *
		 * Publishing order elsewhere in this file already argues the mirror of this (CR3 published
		 * before the MSR, so a trap can never find the target unset). Retirement needs the same care
		 * in reverse: unpublish first, then destroy.
		 */
		void* CONST RetireBuf  = gPebs[i].Buffer;
		void* CONST RetireDs   = gPebs[i].DsArea;
		void* CONST RetireKeep = gPebs[i].KeepBuf;

		/* A core with no buffer must never read as armed, even though the guard above means it
		 * cannot be. Unpublished with the pointers it depends on, not separately. */
		gPebs[i].Armed    = 0;
		gPebs[i].Buffer   = NULL;
		gPebs[i].DsArea   = NULL;
		gPebs[i].KeepBuf   = NULL;
		gPebs[i].KeepWrite = 0;
		gPebs[i].KeepRead  = 0;
		gPebs[i].KeepMax   = 0;
		_mm_mfence();   /* the NULLs must be visible to other cores before the memory goes away */

		if (RetireBuf  != NULL) MmFreeContiguousMemory(RetireBuf);
		if (RetireDs   != NULL) MmFreeContiguousMemory(RetireDs);
		if (RetireKeep != NULL) MmFreeContiguousMemory(RetireKeep);
		gPebs[i].DsAreaPa    = 0;
		gPebs[i].BufferPa    = 0;
		gPebs[i].BufferBytes = 0;
		gPebs[i].Records     = 0;
	}
	gPebsCpus = 0;
}

NTSTATUS
NxcPebsAlloc(
	_In_ UINT32 Records,
	_In_ UINT32 MaxStride,   /* size each record slot for THIS many bytes; 0 = the modest default */
	_Out_ UINT32* OutOk
	)
{
	*OutOk = 0;

	if (Records < 16u || Records > 65536u)
		return STATUS_INVALID_PARAMETER;

	if (gPebsCpus != 0)
		return STATUS_ALREADY_COMMITTED;

	CONST ULONG Cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	CONST ULONG Use  = (Cpus < NXC_MAX_TRACE_CPUS) ? Cpus : NXC_MAX_TRACE_CPUS;
	/*
	 * ⚠⚠ THE SLACK RECORD IS A MEMORY-SAFETY FIX, NOT A ROUNDING CONVENIENCE. FOUND.
	 *
	 * PebsAbsoluteMax is not a hard wall the CPU clips a write against -- it is a limit the CPU
	 * checks the INDEX against BEFORE writing a whole record. So if AbsoluteMax is not an exact
	 * multiple of the true record size away from the base, the last record STARTS inside the buffer
	 * and ENDS past it.
	 *
	 * That was live. NXC_PEBS_STRIDE said 160 (the GPR group was assumed to be 16 registers); the
	 * hardware wrote 176. With 1024 records the allocation was 163840 bytes, 930 records fit in
	 * 163680, and record 931 would have started at 163680 and run to 163856 -- SIXTEEN BYTES PAST
	 * OUR OWN ALLOCATION, written by the processor, into contiguous memory belonging to someone else.
	 * Only the drain arriving early kept it from happening on the run that revealed it.
	 *
	 * TWO INDEPENDENT DEFENCES, because the stride is a REQUEST and this memory is written by
	 * hardware that does not consult us:
	 *   1. AbsoluteMax is placed at an exact multiple of the stride from the base (it already was),
	 *      so with the stride correct no record can straddle it; and
	 *   2. the ALLOCATION carries one extra record beyond AbsoluteMax, so that if the stride is ever
	 *      wrong again -- a new group added to DATA_CFG, a different part, a layout revision -- the
	 *      overrun lands in memory we own instead of memory we do not.
	 *
	 * Defence 1 alone would be correct and fragile. It has already been wrong once.
	 */
	/*
	 * ⚠ SIZED FOR THE LARGEST RECORD ARM CAN SELECT, NOT THE DEFAULT ONE.
	 *
	 * `pebs alloc` runs BEFORE `pebs arm`, so at this point nobody knows yet whether MemInfo will
	 * be requested. Sizing at the 176-byte default and then letting arm enable MemInfo would have
	 * the CPU writing 208-byte records into a buffer measured for 176 -- defence 2 above would
	 * absorb exactly one of them and no more.
	 *
	 * So the allocation uses NXCMD_PEBS_STRIDE_MAX and AbsoluteMax is placed for that worst case
	 * here. NxcPebsArm RE-PLACES it at an exact multiple of the stride ACTUALLY selected, which is
	 * the only value that satisfies defence 1. A smaller stride can only move the wall DOWN.
	 */
	/*
	 * ⚠ SIZED FOR WHAT THE CALLER SAYS IT MAY ARM, NOT UNCONDITIONALLY FOR THE WORST CASE.
	 *
	 * The first version of this used NXCMD_PEBS_STRIDE_MAX always. Once the LBR group existed that
	 * was 976 bytes a record -- ~1 MB of CONTIGUOUS memory per core and ~23 MB across this machine,
	 * paid on every alloc even though most runs never ask for LBR. Sizing for the worst case is the
	 * right instinct (the CPU writes these records and must not pass the wall) but the worst case
	 * is what the CALLER MIGHT ARM, and the caller knows.
	 *
	 * So alloc is told, and arm REFUSES anything larger than what was allocated -- an explicit
	 * failure rather than a clamp, because a clamp here would silently record fewer LBR entries
	 * than were asked for.
	 */
	UINT32 Stride = (MaxStride != 0) ? MaxStride : (UINT32)NXCMD_PEBS_STRIDE_NOLBR;
	if (Stride < NXCMD_PEBS_STRIDE_NOLBR)   Stride = (UINT32)NXCMD_PEBS_STRIDE_NOLBR;
	if (Stride > NXCMD_PEBS_STRIDE_MAX)     Stride = (UINT32)NXCMD_PEBS_STRIDE_MAX;

	CONST SIZE_T UsableBytes = (SIZE_T)Records * Stride;
	CONST SIZE_T BufBytes    = UsableBytes + Stride;

	PHYSICAL_ADDRESS High; High.QuadPart = MAXULONG64;

	UINT32 Ok = 0;
	for (ULONG i = 0; i < Use; i++)
	{
		NXC_DS_AREA* CONST Ds = (NXC_DS_AREA*)MmAllocateContiguousMemory(sizeof(NXC_DS_AREA), High);
		if (Ds == NULL)
			continue;

		void* CONST Buf = MmAllocateContiguousMemory(BufBytes, High);
		if (Buf == NULL) { MmFreeContiguousMemory(Ds); continue; }

		RtlZeroMemory(Ds, sizeof(*Ds));
		/* ⚠ ZEROED BECAUSE THE CPU WILL WRITE HERE. A buffer handed to hardware carrying whatever the
		 * allocator left behind makes stale bytes indistinguishable from records on the first drain --
		 * the same argument NxcTraceArm makes for zeroing ToPA regions. */
		RtlZeroMemory(Buf, BufBytes);

		Ds->PebsBufferBase = (UINT64)(ULONG_PTR)Buf;
		Ds->PebsIndex      = (UINT64)(ULONG_PTR)Buf;
		/* UsableBytes, NOT BufBytes -- the tail record is slack the CPU is never told about. */
		Ds->PebsAbsoluteMax = (UINT64)(ULONG_PTR)Buf + UsableBytes;
		/*
		 * Threshold one record short of the end, so the PMI arrives while there is still room for the
		 * record that triggered it. Setting it AT the maximum would ask for an interrupt at the moment
		 * the buffer is already full.
		 */
		/* STRIDE_MAX here to match the worst-case placement above; NxcPebsArm re-places BOTH from
		 * the stride actually selected, and a smaller stride only moves them down. */
		Ds->PebsInterruptThreshold = (UINT64)(ULONG_PTR)Buf + UsableBytes - Stride;

		gPebs[i].DsArea      = Ds;
		gPebs[i].Buffer      = Buf;
		gPebs[i].DsAreaPa    = (UINT64)MmGetPhysicalAddress(Ds).QuadPart;
		gPebs[i].BufferPa    = (UINT64)MmGetPhysicalAddress(Buf).QuadPart;
		/* The USABLE span is reported and drained. The slack record is a safety net, never capacity --
		 * reporting it would invite someone to fill it, which is the one thing it exists to survive. */
		gPebs[i].BufferBytes = (UINT32)UsableBytes;
		gPebs[i].Records     = Records;

		/*
		 * The keep buffer. Same shape as the DS buffer so a kept record can be copied verbatim.
		 * NOT contiguous-required (the CPU never writes it, we do), but allocated the same way to
		 * keep one free path rather than two.
		 *
		 * A failure here is NOT fatal to the alloc: without it the PMI filter cannot keep anything,
		 * and NxcPebsArm refuses --pmi-filter rather than pretending. Reported, never silent.
		 */
		gPebs[i].KeepBuf   = MmAllocateContiguousMemory(BufBytes, High);
		gPebs[i].KeepWrite = 0;
		gPebs[i].KeepRead  = 0;
		gPebs[i].KeepMax   = (gPebs[i].KeepBuf != NULL) ? Records : 0;
		gPebs[i].AllocStride = Stride;   /* the wall arm must not exceed */
		Ok++;
	}

	gPebsCpus       = Use;
	gPebsAllocStride = Stride;   /* what was RESERVED, after clamping -- reported back to the caller */
	*OutOk = Ok;

	TrcLog("pebs: allocated %u of %lu CPUs, %llu bytes each (STAGE 1 -- NO MSR WRITTEN)\n",
	       Ok, Use, (ULONG64)BufBytes);

	return (Ok == 0) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}

NTSTATUS
NxcPebsStatus(
	_Out_writes_(Cap) NXCMD_PEBS_CPU_STATE* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT32* OutTotal
	)
{
	*OutGot   = 0;
	*OutTotal = gPebsCpus;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST UINT32 Give = (gPebsCpus < Cap) ? gPebsCpus : Cap;
	for (UINT32 i = 0; i < Give; i++)
	{
		Out[i].DsAreaVa     = (UINT64)(ULONG_PTR)gPebs[i].DsArea;
		Out[i].DsAreaPa     = gPebs[i].DsAreaPa;
		Out[i].BufferVa     = (gPebs[i].DsArea != NULL) ? gPebs[i].DsArea->PebsBufferBase : 0;
		Out[i].BufferPa     = gPebs[i].BufferPa;
		Out[i].BufferBytes  = gPebs[i].BufferBytes;
		Out[i].ThresholdVa  = (gPebs[i].DsArea != NULL) ? gPebs[i].DsArea->PebsInterruptThreshold : 0;
		Out[i].CpuNumber    = i;
		Out[i].Records      = gPebs[i].Records;
		/* ⚠ WHAT ARM PROGRAMMED, NOT THE COMPILE-TIME DEFAULT. This was NXC_PEBS_STRIDE, which is
		 * exactly the constant-that-was-once-a-fact shape described immediately below: true while
		 * Basic+GPR was the only possible layout, and false the moment MemInfo could be requested.
		 * Before arm there is no selected stride, so report the default that alloc sized against. */
		Out[i].RecordStride = (gPebs[i].Stride != 0) ? gPebs[i].Stride
		                                            : (UINT32)NXC_PEBS_STRIDE;
		/*
		 * ⚠ THIS WAS A LITERAL 0 WITH THE COMMENT "stage 1 cannot arm; this is not a reading, it is
		 * the design". True when written and FALSE the moment stage 2 landed -- `pebs status` would
		 * have reported "Armed: no" on 24 armed cores, which is the silent-partial shape exactly:
		 * a constant that was once a fact, left behind by the code that made it a variable.
		 */
		Out[i].Armed        = (gPebsArmed != 0 && gPebs[i].DsArea != NULL) ? 1u : 0u;

		/*
		 * The two enables, as they READ BACK on this core at arm time. Reported per core because
		 * this is a hybrid part: a feature that takes on the P cores and not the E cores is a real
		 * possible outcome, and a single number from core 0 would hide it.
		 *
		 * Zero on both when never armed -- which is honest, since nothing has been written yet.
		 */
		Out[i].DataCfgReadback = gPebsDataCfgReadback[i];
		Out[i].LdLatReadback   = gPebsLdLatReadback[i];
		Out[i].EvtSelReadback  = gPebsEvtSelReadback[i];
	}
	*OutGot = Give;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcSampleArm(
	_In_ UINT64 Cr3Filter,
	_In_ UINT64 Period,
	_Out_ UINT32* OutArmed
	)
{
	*OutArmed = 0;

	/* A period of 0 would preload the counter with 0 and overflow on the very next instruction --
	 * an NMI storm at retire rate. Refused rather than clamped: a clamp would profile at a rate
	 * nobody asked for and report success. */
	if (Period < 10000ull || Period > 0x0000FFFFFFFFFFFFull)
		return STATUS_INVALID_PARAMETER;

	if (InterlockedCompareExchange(&gSampleArmed, 1, 0) != 0)
		return STATUS_ALREADY_COMMITTED;

	gSampleCr3    = SampleCr3Frame(Cr3Filter);
	gSamplePeriod = Period;
	gSampleWrite  = 0;
	gSampleLost   = 0;

	/* ⚠ THE NMI CALLBACK IS SHARED WITH THE ToPA FILL COUNTER, so it is registered ONCE and the
	 * handle is the record of whether anything is registered -- not a per-feature flag that could
	 * disagree with it. */
	if (gNmiHandle == NULL)
		gNmiHandle = KeRegisterNmiCallback((PVOID)TracePmiNmiCallback, NULL);

	if (gNmiHandle == NULL)
	{
		InterlockedExchange(&gSampleArmed, 0);
		TrcLog("sample: KeRegisterNmiCallback failed -- nothing would catch the overflow\n");
		return STATUS_UNSUCCESSFUL;
	}

	InterlockedExchange(&gSampleCores, 0);
	InterlockedExchange(&gSampleNoLbr, 0);
	(void)KeIpiGenericCall(SampleArmOnEachCpu, 1);

	/*
	 * ⚠ NO CORE ARMED MEANS THE PROFILE WOULD BE EMPTY ADDRESSES, NOT MERELY SMALLER. Refuse the
	 * whole arm and say which cause, rather than returning success over a counter that will fire
	 * hundreds of thousands of times and record nothing.
	 */
	if (gSampleCores == 0)
	{
		(void)KeIpiGenericCall(SampleArmOnEachCpu, 0);
		InterlockedExchange(&gSampleArmed, 0);
		if (gSampleNoLbr != 0)
		{
			TrcLog("sample: REFUSED -- IA32_LBR_CTL.EN is clear on %ld core(s). The sampled address\n"
			       "        comes from the LBR, so without it every sample would carry a NULL RIP.\n"
			       "        Run `lbr arm` first.\n", gSampleNoLbr);
			return STATUS_DEVICE_NOT_READY;
		}
		return STATUS_UNSUCCESSFUL;
	}

	*OutArmed = (UINT32)gSampleCores;
	TrcLog("sample: ARMED, period %llu retired ring-3 instructions, cr3 filter 0x%llX\n",
	       Period, gSampleCr3);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcSampleDisarm(
	_Out_ UINT32* OutSamples,
	_Out_ UINT32* OutLost
	)
{
	*OutSamples = (UINT32)gSampleWrite;
	*OutLost    = (UINT32)gSampleLost;

	if (InterlockedCompareExchange(&gSampleArmed, 0, 1) != 1)
		return STATUS_INVALID_DEVICE_STATE;

	(void)KeIpiGenericCall(SampleArmOnEachCpu, 0);

	/*
	 * ⚠ THE SHARED NMI PLUMBING SERVES THREE CONSUMERS NOW -- PT, this profiler, and the PEBS CR3
	 * filter. This site used to test "is PT still using it" by name, which stopped being the right
	 * question the moment PEBS became the third. TracePmiReleaseAll now makes the decision itself
	 * from LvtPcValid, so it cannot be wrong here and cannot drift when a fourth is added.
	 */
	TracePmiReleaseAll();

	TrcLog("sample: disarmed, %u sample(s), %u lost\n", *OutSamples, *OutLost);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcSampleDrain(
	_Out_writes_(Cap) NXCMD_SAMPLE_ENTRY* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutLost
	)
{
	*OutGot   = 0;
	*OutTotal = (UINT32)gSampleWrite;
	*OutLost  = (UINT32)gSampleLost;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST UINT32 Written = (UINT32)gSampleWrite;
	CONST UINT32 Have    = (Written < NXC_SAMPLE_RING) ? Written : NXC_SAMPLE_RING;
	CONST UINT32 Give    = (Have < Cap) ? Have : Cap;

	/* Walk backwards from the write cursor so a partial drain returns the MOST RECENT samples --
	 * the same reason the PT buffer is circular. */
	for (UINT32 i = 0; i < Give; i++)
	{
		CONST UINT32 Idx = (UINT32)((Written - 1 - i) & (NXC_SAMPLE_RING - 1u));
		Out[i].LbrFrom = gSampleRing[Idx].LbrFrom;
		Out[i].LbrTo   = gSampleRing[Idx].LbrTo;
		Out[i].Cr3     = gSampleRing[Idx].Cr3;
		Out[i].Cpu     = gSampleRing[Idx].Cpu;
		Out[i].Reserved0 = 0;
	}
	*OutGot = Give;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcTraceDisarm(
	_Out_ UINT32* OutDisarmed
	)
{
	*OutDisarmed = 0;

	NXC_ARM_CTX Ctx;
	Ctx.Cr3Filter = 0;
	Ctx.OnlyCpu   = 0xFFFFFFFFu;
	Ctx.ArmFlags  = 0;
	Ctx.NmiOk     = 0;
	Ctx.Ranges       = NULL;
	Ctx.RangeCount   = 0;
	Ctx.RangeRefused = 0;
	Ctx.Armed     = 0;
	Ctx.Refused   = 0;

	gArmCtx = &Ctx;
	(void)KeIpiGenericCall(DisarmOnEachCpu, 0);
	gArmCtx = NULL;

	*OutDisarmed = (UINT32)Ctx.Armed;

	/*
	 * ⚠ AFTER THE BROADCAST, NEVER BEFORE. KeDeregisterNmiCallback waits for callbacks already
	 * running to finish, which is exactly the guarantee wanted -- but every core has to have restored
	 * its LVT PC and cleared its ToPA INT bit first. Deregistering while a core still had INT set
	 * would leave the hardware asking for an interrupt with the handler gone.
	 *
	 * Unconditional, and not gated on "did anyone ask for PMI": the handle is the record of whether
	 * there is anything to release, so a gate on the request could only disagree with it.
	 *
	 * ⚠ AND "UNCONDITIONAL" IS NOW SAFE FOR A REASON IT WAS NOT BEFORE. This call used to be able to
	 * tear the callback out from under the PEBS CR3 filter, which holds the same LVT through a
	 * different arm path -- `trace disarm` would deregister and PEBS's next PMC0 overflow became an
	 * NMI nothing claimed. TracePmiReleaseAll now refuses while ANY core still holds LVT PC, so this
	 * site can stay unconditional and still be correct.
	 */
	TracePmiReleaseAll();
	TrcLog("trace: disarmed %ld core(s)\n", Ctx.Armed);
	return STATUS_SUCCESS;
}

/*
 * Gather the two live MSRs into the per-CPU records.
 *
 * ⚠ MUST RUN ON THE CORE IT IS READING. IA32_RTIT_* are per-logical-processor, so reading them from
 * a status call on whatever core happened to service the command would report one core's trace as
 * though it were everyone's -- exactly the class of confusion the per-core cpuprobe exists to avoid.
 *
 * ⚠ AND ONLY ON A CORE WE ARMED. RDMSR of an RTIT register on a core without PT raises #GP, which
 * with no SEH is a bugcheck. Armed implies the capability was verified on that core at arm time.
 */
/**
 * Has this core's output region been filled at least once?
 *
 * ⚠ DETECTED FROM THE BUFFER, NOT FROM WATCHING THE POINTER GO BACKWARDS. A sample lower than the
 * previous one does prove a wrap -- that is how this was found, 148,848 followed by
 * 25,376 -- but its ABSENCE proves nothing. Two wraps between samples, or one that lands past where
 * it started, both look exactly like ordinary forward progress. Any check built on comparing
 * consecutive samples silently depends on how often somebody happened to look.
 *
 * The region is zeroed at allocation, so a non-zero byte near its END means the writer reached that
 * point, and it can only reach it by filling the region. That is a fact about the buffer rather than
 * about the sampling rate, and it survives however long nobody was watching.
 *
 * ⚠ ONE-WAY, NEVER CLEARED HERE. Wrapping is not undone by anything except a fresh arm, which zeroes
 * it deliberately. A flag that could flicker off would let a caller read "no wrap" from a buffer
 * that has already lost data.
 *
 * ⚠ AND *THIS DETECTOR* CANNOT COUNT -- which is a limit of the tail scan, NOT of the hardware.
 * Corrected: this comment used to end "Intel PT keeps no wrap counter, so 'how many times'
 * is not recoverable from the hardware", and that was one of SIX copies of a false claim. The ToPA
 * entry's INT bit makes the CPU announce every fill; arm with NXC_TRACE_ARM_PMI and WrapPmi holds the
 * exact count.
 *
 * So the honest report from THIS function remains at-least-BufferSize, because a boolean derived from
 * one byte near the end cannot say more than that. The number simply comes from somewhere else now.
 */
static void
TraceNoteWrap(
	_Inout_ NXC_TRACE_CPU* T
	)
{
	if (T->Wrapped != 0 || T->BufferVa == NULL || T->BufferSize < 64)
		return;

	/* The last 64 bytes. Checking only the final qword would miss a writer stopped a few bytes
	 * short of the end, and scanning the whole region would be 256 KB of reads at IPI_LEVEL. */
	CONST volatile UINT64* CONST Tail =
		(CONST volatile UINT64*)((CONST UINT8*)T->BufferVa + T->BufferSize - 64);

	for (UINT32 i = 0; i < 8; i++)
	{
		if (Tail[i] != 0)
		{
			T->Wrapped = 1;
			return;
		}
	}
}

UINT32
NxcTracePtBoundHere(
	_Out_ UINT64* OutOffset,
	_Out_ UINT32* OutGeneration
	)
{
	*OutOffset     = 0;
	*OutGeneration = 0;

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);

	if (Cpu >= NXC_MAX_TRACE_CPUS || gTrace[Cpu].Armed == 0)
		return NXC_BPD_PTWHY_NOT_ARMED;

	CONST UINT64 Ctl = __readmsr(IA32_RTIT_CTL);

	if ((Ctl & RTIT_CTL_TRACEEN) == 0)
		return NXC_BPD_PTWHY_NOT_ARMED;

	/*
	 * ⚠ REFUSE WHEN RING 0 IS BEING TRACED, rather than return a bound over a polluted trace. PT's
	 * CPL filter is SEPARATE from its CR3 filter, and our exception path runs in the TARGET's CR3 --
	 * so with .OS set the trace we are about to bound contains our own trap handling, and the bound
	 * would point at OUR code rather than the target's. Same shape as D36's inline-hook burn, and
	 * worse here because PT is high-bandwidth. Fail-closed and say which condition failed.
	 */
	if ((Ctl & RTIT_CTL_OS) != 0)
		return NXC_BPD_PTWHY_OS_TRACED;

	/*
	 * ⚠⚠ THE TOGGLE IS NOT OPTIONAL, AND THE OBVIOUS VERSION OF THIS FUNCTION IS WRONG. The SDM:
	 * updates to OUTPUT_BASE / OUTPUT_MASK_PTRS are ASYNCHRONOUS with instruction execution, so
	 * reading the pointer while tracing returns a STALE offset -- one that looks exactly like a good
	 * one. "The only way to assure that all packets generated have reached their endpoint is to clear
	 * TraceEn and follow that with a store, fence, or serializing instruction."
	 *
	 * So: clear, fence, read, restore. This is the LBR freeze with the roles reversed -- there the
	 * CPU freezes the ring for us and we only have to notice; here it will not, and we have to.
	 */
	__writemsr(IA32_RTIT_CTL, Ctl & ~RTIT_CTL_TRACEEN);
	_mm_mfence();

	*OutOffset = __readmsr(IA32_RTIT_OUTPUT_MASK_PTRS) >> 32;

	/*
	 * ⚠ THE OFFSET ALONE STOPS ORDERING CORRECTLY ONCE THE REGION WRAPS -- offset 5,000 is LATER
	 * than 250,000 after the writer comes round, and the numbers say the opposite. The generation
	 * advances here, at the same instant the offset is read, so (Generation, Offset) is a total
	 * order across wraps. Counted in software because a single-entry circular ToPA has no revolution
	 * counter in hardware.
	 */
	TraceNoteGeneration(&gTrace[Cpu], *OutOffset);
	*OutGeneration = gTrace[Cpu].Generation;

	/*
	 * ⚠⚠ RESTORE, OR PT DIES AT THE FIRST BREAKPOINT. We cleared TraceEn and we SWALLOW the trap, so
	 * no other handler runs and nobody else restores it -- exactly the failure LBR_EN had, where the
	 * ring recorded one trap per core and then went silent looking like broken hardware. Written back
	 * as the value READ, never reconstructed: the CR3 filter, CPL bits and ToPA settings all live in
	 * the bits being preserved.
	 */
	__writemsr(IA32_RTIT_CTL, Ctl);

	return NXC_BPD_PTWHY_OK;
}

static ULONG_PTR
SampleOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS || gTrace[Cpu].Armed == 0)
		return 0;

	/*
	 * ⚠ EXACT MODE: stop the trace, fence, then read. The SDM requires TraceEn cleared before the
	 * output pointer is accurate, so the default sample below is a LOWER BOUND -- whatever is still
	 * in the CPU's internal packet buffer has not landed. Labelling that was the earlier fix; this
	 * is the option that removes it, and it is OPT-IN because it PERTURBS THE THING IT MEASURES:
	 * tracing stops for the duration and resumes with a fresh PSB.
	 */
	CONST BOOLEAN Exact = (gTraceExactSample != 0);
	UINT64 SavedCtl = 0;

	if (Exact)
	{
		SavedCtl = __readmsr(IA32_RTIT_CTL);
		if (SavedCtl & RTIT_CTL_TRACEEN)
		{
			__writemsr(IA32_RTIT_CTL, SavedCtl & ~RTIT_CTL_TRACEEN);
			_mm_mfence();
		}
	}

	/*
	 * Bits 63:32 are the WRITE POSITION within the current output region -- not a total.
	 *
	 * ⚠⚠ AND THIS ONE IS A LOWER BOUND, NOT AN EXACT COUNT, because TraceEn is still SET. The SDM is
	 * explicit that the processor's updates to OUTPUT_BASE/OUTPUT_MASK_PTRS are ASYNCHRONOUS with
	 * instruction execution, so a read taken while tracing may return a STALE value -- whatever is
	 * still sitting in the CPU's internal packet buffer has not landed yet. Getting an exact figure
	 * requires clearing TraceEn and fencing, which the DISARM path does (see the note there) and
	 * which this path must NOT do: `trace status` is a read-only observation and stopping the trace
	 * to measure it would change the thing being measured.
	 *
	 * Surfaced by D108's tier 2 while researching something else. It does not invalidate the
	 * CR3-filter measurement -- both sides of that comparison were sampled the same way and the gap
	 * was ~12x, far outside any buffering lag -- but the number is APPROXIMATE and the surface said
	 * it was authoritative.
	 */
	gTrace[Cpu].OutputOffset = __readmsr(IA32_RTIT_OUTPUT_MASK_PTRS) >> 32;
	gTrace[Cpu].RtitStatus   = __readmsr(IA32_RTIT_STATUS);
	TraceNoteWrap(&gTrace[Cpu]);
	TraceNoteGeneration(&gTrace[Cpu], gTrace[Cpu].OutputOffset);

	/* ⚠ RESTORE BEFORE RETURNING. Same obligation as the trap-path bound: we stopped it, nothing
	 * else will start it, and PT would simply die on this core at the first `trace status --exact`. */
	if (Exact && (SavedCtl & RTIT_CTL_TRACEEN))
		__writemsr(IA32_RTIT_CTL, SavedCtl);

	return 0;
}

NTSTATUS
NxcTraceStatus(
	_Out_writes_(Cap) NXCMD_TRACE_CPU_STATE* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_In_ BOOLEAN Exact
	)
{
	/* ⚠ OPT-IN, because it PERTURBS WHAT IT MEASURES: exact mode stops the trace on each core long
	 * enough for the pointer to be accurate, then restarts it with a fresh PSB. The default sample
	 * is a lower bound and says so; this is the option that removes the doubt when it matters. */
	InterlockedExchange(&gTraceExactSample, Exact ? 1 : 0);

	*Got   = 0;
	*Total = gTraceCpus;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	/*
	 * Refresh the live MSRs before reporting. KeIpiGenericCall runs SampleOnEachCpu on EVERY core,
	 * at IPI_LEVEL, and the routine ignores cores it did not arm.
	 *
	 * Skipped entirely when nothing is allocated: an IPI broadcast that will do nothing on all 24
	 * cores is still a synchronised stall of all 24 cores, and `trace status` is expected to be the
	 * cheap command you run repeatedly.
	 *
	 * ⚠ VALUES PERSIST AFTER DISARM ON PURPOSE. A disarmed core stops being sampled, so it keeps the
	 * last offset it reported -- which is the FINAL byte count for that trace, and the only place the
	 * result of a completed capture survives. NxcTraceArm zeroes them when a core is armed afresh.
	 */
	if (gTraceCpus != 0)
		(void)KeIpiGenericCall(SampleOnEachCpu, 0);

	/* Never leave exact mode set: the next ordinary `trace status` must not silently stop the
	 * trace it is reporting on. */
	InterlockedExchange(&gTraceExactSample, 0);

	CONST UINT32 Use = (gTraceCpus < Cap) ? gTraceCpus : Cap;
	for (UINT32 i = 0; i < Use; i++)
	{
		Out[i].CpuNumber    = i;
		Out[i].ToPaPa       = gTrace[i].ToPaPa;
		Out[i].BufferPa     = gTrace[i].BufferPa;
		Out[i].BufferSize   = gTrace[i].BufferSize;
		Out[i].Armed        = gTrace[i].Armed;
		Out[i].OutputOffset = gTrace[i].OutputOffset;
		Out[i].RtitStatus   = gTrace[i].RtitStatus;
		Out[i].Wrapped      = gTrace[i].Wrapped;
		/* The generation was computed on every sample since stage 2 and reported to NOBODY -- it
		 * reached usermode for the first time. A value that only the kernel can see is
		 * a value nothing can check (an earlier finding). */
		Out[i].Generation   = gTrace[i].Generation;
		Out[i].WrapPmi      = gTrace[i].WrapPmi;
		Out[i].ArmFlags     = gTrace[i].ArmFlags;
		Out[i].PmiWhy       = gTrace[i].PmiWhy;
		Out[i].LvtPcSaved   = gTrace[i].LvtPcValid ? gTrace[i].LvtPcSaved : 0;
		/* IA32_RTIT_CTL as it READ BACK when this core armed -- which timing packets the trace on
		 * THIS core is actually carrying. A decoder that assumes the wrong answer fails in ways that
		 * look like corrupt data rather than a configuration difference, and this is a hybrid part. */
		Out[i].RtitCtl      = gTrace[i].RtitCtl;
	}

	*Got = Use;
	return STATUS_SUCCESS;
}

/*
 * ============================================================================================
 * CONTINUOUS PT DRAIN -- consume what the hardware has written since the last call.
 * ============================================================================================
 *
 * WHY THIS EXISTS. NxcTraceDump is a random-access read of a CIRCULAR region: it copies whatever
 * happens to be at an offset right now, with no notion of what the caller has already seen. The
 * hardware never stops writing, so a capture that arms, waits and dumps reads only what survived
 * being overwritten. At the measured ~42 B/ms/core a 256 KB region laps in about six seconds, and
 * a circular buffer that has lapped looks exactly like one that has not -- full, well-formed, and
 * missing the middle of your trace.
 *
 * That is the same defect the PEBS keep buffer had, where it cost 96% of matched records. PT hides
 * it better, which makes it worse.
 *
 * THE CURSOR IS A TOTAL, NOT AN OFFSET. (Generation * BufferSize + OutputOffset) is monotonic
 * across wraps; an offset alone cannot distinguish "nothing new" from "exactly one full lap".
 *
 * ⚠ OVERRUN IS DETECTED AND REPORTED, NEVER PAPERED OVER. If the writer has advanced more than
 * BufferSize since the last drain, the oldest bytes are already gone -- we say how many and resume
 * from the oldest surviving byte. Silently returning the survivors would hand back a trace with an
 * invisible hole, and PT packets do not announce a discontinuity.
 *
 * ⚠ THE CALLER MUST HAVE REFRESHED OutputOffset FIRST. IA32_RTIT_* are per-logical-processor, so
 * they can only be read on the owning core; NxcTraceDrainRefresh does the IPI once for the whole sweep
 * rather than once per CPU, which is why this takes no IPI of its own.
 */
NTSTATUS
NxcTraceDrain(
	_In_  UINT32 Cpu,
	_Out_writes_bytes_(Cap) void* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutBytes,
	_Out_ UINT64* OutLost,
	_Out_ UINT64* OutPending
	)
{
	*OutBytes   = 0;
	*OutLost    = 0;
	*OutPending = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;
	if (Cpu >= NXC_MAX_TRACE_CPUS || Cpu >= gTraceCpus)
		return STATUS_INVALID_PARAMETER;

	NXC_TRACE_CPU* CONST T = &gTrace[Cpu];
	if (T->BufferVa == NULL || T->BufferSize == 0)
		return STATUS_INVALID_DEVICE_STATE;

	CONST UINT64 Size     = (UINT64)T->BufferSize;
	CONST UINT64 WroteTot = ((UINT64)T->Generation * Size) + T->OutputOffset;

	/* The hardware cannot un-write. A cursor ahead of the writer means the region was re-armed or
	 * freed underneath us, and continuing would emit bytes from a previous life of the buffer. */
	if (T->DrainedTotal > WroteTot)
		T->DrainedTotal = WroteTot;

	UINT64 Pending = WroteTot - T->DrainedTotal;

	if (Pending > Size)
	{
		/* Overrun: the oldest (Pending - Size) bytes were overwritten before we read them. */
		*OutLost = Pending - Size;
		T->DrainedTotal = WroteTot - Size;
		Pending = Size;
	}
	*OutPending = Pending;

	CONST UINT32 Take = (Pending < (UINT64)Cap) ? (UINT32)Pending : Cap;
	if (Take == 0)
		return STATUS_SUCCESS;

	/*
	 * Copied in at most two spans because the region wraps. One RtlCopyMemory across the wrap point
	 * would splice the end of the buffer to bytes that come EARLIER in the trace, and the decoder
	 * would read that as valid packets -- a corrupted trace that never reports itself.
	 */
	CONST UINT32 Start = (UINT32)(T->DrainedTotal % Size);
	CONST UINT32 First = ((UINT64)Start + Take > Size) ? (UINT32)(Size - Start) : Take;

	RtlCopyMemory(Out, (CONST UINT8*)T->BufferVa + Start, First);
	if (First < Take)
		RtlCopyMemory((UINT8*)Out + First, (CONST UINT8*)T->BufferVa, Take - First);

	/* Advance by what was ACTUALLY copied. Advancing by Pending would free bytes the caller never
	 * received -- silent loss wearing the shape of a successful drain. */
	T->DrainedTotal += Take;
	*OutBytes = Take;
	return STATUS_SUCCESS;
}

/*
 * Refresh every core's OutputOffset once. Split from NxcTraceDrain so a sweep across 24 CPUs costs
 * ONE IPI broadcast instead of 24 -- at a 10 ms drain interval that is the difference between ~100
 * and ~2400 broadcasts a second, and an IPI storm would perturb the very timing PT is recording.
 */
NTSTATUS
NxcTraceDrainRefresh(
	void
	)
{
	if (gTraceCpus == 0)
		return STATUS_INVALID_DEVICE_STATE;
	(void)KeIpiGenericCall(SampleOnEachCpu, 0);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcTraceDump(
	_In_ UINT32 Cpu,
	_In_ UINT64 Offset,
	_In_ UINT32 Bytes,
	_Out_writes_bytes_(Bytes) void* Out,
	_Out_ UINT32* OutCopied
	)
{
	*OutCopied = 0;

	if (Out == NULL || Bytes == 0)
		return STATUS_INVALID_PARAMETER;

	if (Cpu >= NXC_MAX_TRACE_CPUS || Cpu >= gTraceCpus)
		return STATUS_INVALID_PARAMETER;

	NXC_TRACE_CPU* CONST T = &gTrace[Cpu];
	if (T->BufferVa == NULL || T->BufferSize == 0)
		return STATUS_INVALID_DEVICE_STATE;

	if (Offset >= T->BufferSize)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠ CLAMPED, NOT REFUSED, AND THE CALLER IS TOLD THE REAL NUMBER (D3). A dump that runs off the
	 * end of the region is an ordinary thing for a caller walking a buffer in chunks; refusing would
	 * make the last chunk a special case for no reason. Silently returning a full-length buffer with
	 * garbage past the end would be far worse -- it would decode as packets.
	 */
	CONST UINT32 Avail = T->BufferSize - (UINT32)Offset;
	CONST UINT32 Take  = (Bytes < Avail) ? Bytes : Avail;

	/*
	 * ⚠ READING A REGION THE HARDWARE MAY STILL BE WRITING. That is allowed and it is the caller's
	 * problem to understand, not something to prevent: disarming first is what makes a dump
	 * self-consistent, and `trace disarm` exists for exactly that. Reading while armed gives a
	 * torn but real picture, which for a circular buffer is often what is wanted -- and refusing
	 * would make it impossible to look at a long-running trace at all.
	 */
	RtlCopyMemory(Out, (CONST UINT8*)T->BufferVa + Offset, Take);
	*OutCopied = Take;
	return STATUS_SUCCESS;
}
