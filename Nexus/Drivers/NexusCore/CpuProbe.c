/**
 * @file CpuProbe.c
 * @brief Read-only trace-capability probe. The reasoning lives in CpuProbe.h -- read it first.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "CpuProbe.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define CpuLog NxcLogExt

#define IA32_PERF_CAPABILITIES   0x00000345u
#define IA32_RTIT_CTL            0x00000570u
#define IA32_LBR_DEPTH           0x000014CFu   /* architectural LBR only (CPUID.1CH)  */

/* IA32_PERF_CAPABILITIES fields */
#define PERFCAP_LBR_FMT_MASK     0x3FULL       /* bits 5:0; 0 = no LBR                */
#define PERFCAP_PEBS_FMT_MASK    (0xFULL << 8) /* bits 11:8                            */

/* IA32_RTIT_CTL */
#define RTIT_CTL_TRACEEN         (1ULL << 0)

/*
 * Shared across the IPI callback. The callback runs on EVERY logical processor SIMULTANEOUSLY at
 * IPI_LEVEL, so each writes only its OWN slot, indexed by KeGetCurrentProcessorNumberEx -- no lock
 * is needed and none would be legal at that IRQL anyway.
 */
static NXCMD_CPU_TRACE_CAPS* volatile gProbeOut = NULL;
static volatile LONG                  gProbeCap = 0;

static ULONG_PTR
ProbeOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (gProbeOut == NULL || (LONG)Cpu >= gProbeCap)
		return 0;

	NXCMD_CPU_TRACE_CAPS* CONST E = &gProbeOut[Cpu];
	E->CpuNumber = Cpu;
	E->Flags     = 0;
	E->CoreType  = 0;
	E->LbrDepth  = 0;
	E->PerfCaps  = 0;
	E->RtitCtl   = 0;

	int Regs[4];

	/* CPUID.0: how far the leaves go. Reading a leaf above the maximum returns the HIGHEST leaf's
	 * data on Intel, not zeroes -- so an ungated read of leaf 0x1C would silently return something
	 * plausible and wrong. */
	__cpuid(Regs, 0);
	CONST ULONG MaxLeaf = (ULONG)Regs[0];

	/* CPUID.01H:EDX.DS[21] -- Debug Store, the BTS prerequisite. */
	__cpuid(Regs, 1);
	if (Regs[3] & (1 << 21))
		E->Flags |= NXCMD_CPU_HAS_BTS;

	/* CPUID.(07H,0):EBX.INTEL_PT[25] */
	if (MaxLeaf >= 7)
	{
		__cpuidex(Regs, 7, 0);
		if (Regs[1] & (1 << 25))
			E->Flags |= NXCMD_CPU_HAS_PT;
	}

	/* CPUID.(14H,0) and (14H,1) -- PT sub-features. Only meaningful when PT is present. */
	if ((E->Flags & NXCMD_CPU_HAS_PT) && MaxLeaf >= 0x14)
	{
		__cpuidex(Regs, 0x14, 0);
		CONST ULONG PtMaxSub = (ULONG)Regs[0];
		if (Regs[1] & (1 << 0))     /* EBX[0]: CR3 filtering */
			E->Flags |= NXCMD_CPU_PT_CR3_FILTER;

		/*
		 * ⚠ EBX[2]: IP FILTERING AND TraceStop. Probed because nothing here reported it and
		 * the capability it gates is the answer to a problem we spent a day measuring.
		 *
		 * PT currently filters by CR3 only -- the WHOLE process -- which on this machine measured
		 * ~1.9 GB/s unfiltered and wrapped a 256 KB region about 7,400 times a second. IP filtering
		 * traces only chosen VA RANGES instead, so a capture can cover one unpack routine rather than
		 * everything the process does. It is the difference between a firehose and an instrument.
		 *
		 * ⚠ READ-ONLY, like everything else in this probe: CPUID only, no WRMSR. Knowing whether the
		 * silicon HAS the ranges is a separate question from using them, and this answers only the
		 * first -- which is the honest order to do it in.
		 */
		if (Regs[1] & (1 << 2))
			E->Flags |= NXCMD_CPU_PT_IP_FILTER;

		if (PtMaxSub >= 1)
		{
			__cpuidex(Regs, 0x14, 1);
			/* ECX[0]: ToPA output. ECX[1]: ToPA tables with multiple entries. */
			if (Regs[2] & (1 << 0)) E->Flags |= NXCMD_CPU_PT_TOPA;
			if (Regs[2] & (1 << 1)) E->Flags |= NXCMD_CPU_PT_MULTI_TOPA;

			/*
			 * EAX[2:0] -- the NUMBER of configurable address ranges. A count, not a flag, because
			 * "supported" does not say how many filters a capture can actually install, and a design
			 * that assumed 4 on a part with 2 would silently filter on half of what it was told.
			 */
			E->PtAddrRanges = (NXCMD_U32)(Regs[0] & 0x7u);
		}
		else
		{
			/* Leaf 14H sub-leaf 0 also carries ToPA on parts without sub-leaf 1. */
			__cpuidex(Regs, 0x14, 0);
			if (Regs[2] & (1 << 0)) E->Flags |= NXCMD_CPU_PT_TOPA;
		}
	}

	/* CPUID.1AH -- hybrid core type. THE REASON THIS PROBE IS PER-CPU. */
	if (MaxLeaf >= 0x1A)
	{
		__cpuidex(Regs, 0x1A, 0);
		CONST ULONG Type = ((ULONG)Regs[0] >> 24) & 0xFF;
		if (Type != 0)
		{
			E->CoreType = Type;
			E->Flags |= NXCMD_CPU_IS_HYBRID_CORE;
			if (Type == 0x40)                       /* 0x40 = Core (P), 0x20 = Atom (E) */
				E->Flags |= NXCMD_CPU_CORE_IS_P;
		}
	}

	/*
	 * IA32_PERF_CAPABILITIES. GATED on CPUID.01H:ECX.PDCM[15] -- an ungated RDMSR of an
	 * unimplemented MSR raises #GP, and this driver has no SEH to catch it. That would be a
	 * bugcheck, not a failed probe.
	 */
	__cpuid(Regs, 1);
	if (Regs[2] & (1 << 15))
	{
		E->PerfCaps = __readmsr(IA32_PERF_CAPABILITIES);
		if ((E->PerfCaps & PERFCAP_LBR_FMT_MASK) != 0)
			E->Flags |= NXCMD_CPU_HAS_LBR;
		if ((E->PerfCaps & PERFCAP_PEBS_FMT_MASK) != 0)
			E->Flags |= NXCMD_CPU_HAS_PEBS;
	}

	/* CPUID.1CH -- architectural LBR. Gives the depth WITHOUT a model table, which is the whole
	 * reason to prefer it: a hardcoded per-model depth is the pinned-offset mistake again. */
	if (MaxLeaf >= 0x1C)
	{
		__cpuidex(Regs, 0x1C, 0);
		CONST ULONG DepthMask = (ULONG)Regs[0] & 0xFF;   /* EAX[7:0]: supported depths /8 */
		if (DepthMask != 0)
		{
			E->Flags |= NXCMD_CPU_HAS_ARCH_LBR | NXCMD_CPU_HAS_LBR;

			/* Highest supported depth: bit n set means depth 8*(n+1) is available. */
			for (ULONG b = 8; b-- > 0; )
			{
				if (DepthMask & (1u << b))
				{
					E->LbrDepth = (b + 1) * 8;
					break;
				}
			}

			/*
			 * ⚠ THE CAPABILITY WORDS, KEPT RAW AND ALSO DECODED (D23). The depth alone says the ring
			 * exists; these say how it may be ARMED, which is the question that actually blocks
			 * building on it. Dropping them meant the probe answered "can we?" and not "how?".
			 */
			E->LbrCpuidEbx = (NXCMD_U32)Regs[1];
			E->LbrCpuidEcx = (NXCMD_U32)Regs[2];

			if (Regs[1] & (1 << 0)) E->Flags |= NXCMD_CPU_LBR_CPL_FILTER;
			if (Regs[1] & (1 << 1)) E->Flags |= NXCMD_CPU_LBR_BR_FILTER;
			if (Regs[1] & (1 << 2)) E->Flags |= NXCMD_CPU_LBR_CALL_STACK;

			/* EAX[31]: IPs are LIP (already linear) rather than an effective address needing the
			 * segment base added. On x64 flat segments the two coincide, so this is recorded rather
			 * than acted on -- an assumption made visible instead of relied on silently. */
			if ((ULONG)Regs[0] & 0x80000000u) E->Flags |= NXCMD_CPU_LBR_LIP;
		}
	}

	/*
	 * ⚠ THE LEGACY LICENCE, FAIL-CLOSED. Legacy LBR lives at 0x1C9 (TOS) and 0x680/0x6C0, and NONE of
	 * those exist on an architectural-LBR part. HAS_LBR alone was being read as permission to touch
	 * them; an RDMSR of an absent MSR is a #GP, and this image has no SEH, so that is a bugcheck.
	 *
	 * Granted ONLY when arch LBR is absent AND the format is a KNOWN legacy encoding 1..7 (Linux's
	 * LBR_FORMAT_MAX_KNOWN is 0x07). An unrecognised value reads nothing rather than guessing -- and
	 * that is what makes "what does LBR_FMT report on an arch-LBR part?" a question we never have to
	 * answer correctly to stay safe.
	 */
	{
		CONST ULONG64 Fmt = E->PerfCaps & PERFCAP_LBR_FMT_MASK;
		if ((E->Flags & NXCMD_CPU_HAS_ARCH_LBR) == 0 && Fmt >= 1 && Fmt <= 7)
			E->Flags |= NXCMD_CPU_LBR_LEGACY_OK;
	}

	/*
	 * IA32_RTIT_CTL, to see whether PT IS ALREADY IN USE. Windows ships Ipt.sys, so the facility can
	 * be owned by something else -- and PT has ONE set of MSRs per logical processor. Discovering
	 * that after arming would mean having silently stolen another driver's trace.
	 */
	if (E->Flags & NXCMD_CPU_HAS_PT)
	{
		E->RtitCtl = __readmsr(IA32_RTIT_CTL);
		if (E->RtitCtl & RTIT_CTL_TRACEEN)
			E->Flags |= NXCMD_CPU_PT_IN_USE;
	}

	return 0;
}

NTSTATUS
NxcCpuProbe(
	_Out_writes_(Cap) NXCMD_CPU_TRACE_CAPS* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST ULONG Count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	*Total = Count;

	CONST ULONG Fill = (Count < Cap) ? Count : Cap;
	for (ULONG i = 0; i < Fill; i++)
	{
		RtlZeroMemory(&Out[i], sizeof(Out[i]));
		Out[i].CpuNumber = 0xFFFFFFFFu;   /* sentinel: this slot was never written by any CPU */
	}

	gProbeOut = Out;
	gProbeCap = (LONG)Fill;

	/*
	 * KeIpiGenericCall runs the callback on EVERY logical processor at IPI_LEVEL and does not return
	 * until all of them are done -- which is exactly what a per-core-type probe needs, and why this
	 * is not a loop over KeSetSystemAffinityThread. Each CPU writes only its own slot.
	 */
	(void)KeIpiGenericCall(ProbeOnEachCpu, 0);

	gProbeOut = NULL;
	gProbeCap = 0;

	/* Count only slots a CPU actually claimed. The sentinel makes a CPU that never ran visible as a
	 * gap rather than as a plausible all-zero capability set. */
	UINT32 n = 0;
	for (ULONG i = 0; i < Fill; i++)
	{
		if (Out[i].CpuNumber != 0xFFFFFFFFu)
			n++;
	}

	*Got = n;
	CpuLog("cpuprobe: %u of %u logical processors reported\n", n, Count);
	return STATUS_SUCCESS;
}
