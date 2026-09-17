/**
 * @file Lbr.c
 * @brief Read the LBR ring on every core. STAGE 1: NO MSR IS WRITTEN. Reasoning in Lbr.h and D23.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "Lbr.h"
#include "Arena.h"
#include "Hook.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define LbrLog NxcLogExt

static NXCMD_LBR_CPU* volatile gLbrOut = NULL;
static volatile LONG           gLbrCap = 0;

/**
 * Runs on EVERY logical processor at IPI_LEVEL, each writing only its own slot.
 *
 * ⚠ THE CPUID GATE IS NOT DEFENSIVE PROGRAMMING, IT IS THE ONLY THING BETWEEN THIS AND A BUGCHECK.
 * RDMSR of an unimplemented MSR raises #GP; this image has no SEH; #GP at IPI_LEVEL inside an IPI
 * broadcast is not a recoverable situation. So CPUID is consulted ON THIS CORE -- not once by the
 * caller and assumed uniform -- because the machine is hybrid and a per-core-type capability
 * difference is exactly the thing the plan told us to measure rather than assume.
 */
static ULONG_PTR
LbrReadOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	NXCMD_LBR_CPU* CONST Out = gLbrOut;
	if (Out == NULL)
		return 0;

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= (ULONG)gLbrCap || Cpu >= NXC_LBR_MAX_CPUS)
		return 0;

	NXCMD_LBR_CPU* CONST C = &Out[Cpu];
	C->CpuNumber = Cpu;

	int Regs[4];

	/* CPUID.0 first: reading a leaf above the maximum returns the HIGHEST leaf's data on Intel
	 * rather than zeroes, so an ungated CPUID.1CH would return something plausible and wrong. */
	__cpuid(Regs, 0);
	CONST ULONG MaxLeaf = (ULONG)Regs[0];

	/* CPUID.07H:0.EDX[19] -- the architectural-LBR feature bit. Both gates, not either. */
	BOOLEAN ArchBit = FALSE;
	if (MaxLeaf >= 7)
	{
		__cpuidex(Regs, 7, 0);
		ArchBit = ((ULONG)Regs[3] & (1u << 19)) != 0;
	}

	if (!ArchBit || MaxLeaf < 0x1C)
	{
		C->Flags = NXCMD_LBR_F_UNSUPPORTED;
		return 0;
	}

	__cpuidex(Regs, 0x1C, 0);
	CONST ULONG DepthMask = (ULONG)Regs[0] & 0xFFu;
	CONST ULONG Ecx       = (ULONG)Regs[2];

	if (DepthMask == 0)
	{
		/* The feature bit said yes and the enumeration leaf says no supported depth. Contradictory,
		 * so believe the one that would make us touch hardware -- and touch none. */
		C->Flags = NXCMD_LBR_F_UNSUPPORTED;
		return 0;
	}

	C->Flags = NXCMD_LBR_F_ARCH;
	if (Ecx != 0)
		C->Flags |= NXCMD_LBR_F_HAS_INFO;

	C->Ctl = __readmsr(IA32_LBR_CTL);
	if (C->Ctl & LBR_CTL_EN)
		C->Flags |= NXCMD_LBR_F_ENABLED;

	/*
	 * ⚠ WHOSE RING IS IT -- a different question from whether EN is set, and conflating them made
	 * `lbr read` announce "ARMED BY SOMETHING ELSE" on all 24 cores immediately after WE armed them.
	 * This runs on the core being read (the whole read is per-core by IPI), so the mask index is
	 * this core's. Same record `lbr arm` wrote and `NxcLbrArmedHere` consults on the trap path -- one
	 * expression for one fact, rather than three inferences that have to agree.
	 */
	if (NxcLbrArmedHere())
		C->Flags |= NXCMD_LBR_F_OURS;

	/*
	 * ⚠ DEPTH COMES FROM THE MSR, NOT FROM CPUID. CPUID.1CH:EAX[7:0] says which depths the part
	 * SUPPORTS; IA32_LBR_DEPTH says which one the ring is CONFIGURED for right now, and only the
	 * second one tells a reader how many entries are real. Confusing "can be 32" with "is 32" would
	 * read past the configured end of the ring into whatever the higher MSRs hold.
	 */
	CONST ULONG64 DepthMsr = __readmsr(IA32_LBR_DEPTH_MSR);
	ULONG Depth = (ULONG)(DepthMsr & 0xFFFFULL);

	/*
	 * Clamp to the buffer AND to the architectural ceiling. A depth larger than the record can hold
	 * is not a reason to read more MSRs -- and reporting the clamp rather than silently obeying it
	 * is the difference between a truncated answer and a wrong one.
	 */
	if (Depth > NXCMD_LBR_MAX_ENTRIES)
		Depth = NXCMD_LBR_MAX_ENTRIES;

	C->Depth = Depth;

	/*
	 * ⚠ ENTRY 0 IS THE YOUNGEST, AND THE WALK STOPS AT THE FIRST From == 0. Architectural LBR is
	 * stack-like with no TOS, so there is no rotation to undo -- and an unfilled entry reads zero,
	 * which is how Linux finds the end of the valid region too. Reading all `Depth` entries
	 * regardless would report zeroes as branches from address 0.
	 */
	ULONG Valid = 0;
	for (ULONG i = 0; i < Depth; i++)
	{
		CONST ULONG64 From = __readmsr(IA32_LBR_FROM_IP_0 + i);
		if (From == 0)
			break;

		C->Entry[i].From = From;
		C->Entry[i].To   = __readmsr(IA32_LBR_TO_IP_0 + i);
		C->Entry[i].Info = (Ecx != 0) ? __readmsr(IA32_LBR_INFO_0 + i) : 0;
		Valid++;
	}
	C->Valid = Valid;

	return 0;
}

NTSTATUS
NxcLbrRead(
	_Out_writes_(Cap) NXCMD_LBR_CPU* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST ULONG Cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	CONST ULONG Use  = (Cpus < Cap) ? Cpus : Cap;
	*Total = (UINT32)Cpus;

	RtlZeroMemory(Out, (SIZE_T)Use * sizeof(NXCMD_LBR_CPU));

	gLbrOut = Out;
	gLbrCap = (LONG)Use;
	(void)KeIpiGenericCall(LbrReadOnEachCpu, 0);
	gLbrOut = NULL;
	gLbrCap = 0;

	UINT32 Armed = 0, Unsupported = 0, WithData = 0;
	for (ULONG i = 0; i < Use; i++)
	{
		if (Out[i].Flags & NXCMD_LBR_F_ENABLED)     Armed++;
		if (Out[i].Flags & NXCMD_LBR_F_UNSUPPORTED) Unsupported++;
		if (Out[i].Valid != 0)                      WithData++;
	}

	/*
	 * The contention line, for the same reason `trace status` prints one: LBR is ONE ring per core
	 * and anything can own it. Arming over a live LBR steals it as silently as arming PT over
	 * Ipt.sys would have.
	 */
	if (Armed != 0)
		LbrLog("lbr: LBR_CTL.EN is ALREADY SET on %u of %lu core(s) -- something else owns it\n",
		       Armed, Use);

	LbrLog("lbr: %lu core(s) read -- %u with entries, %u armed, %u without architectural LBR\n",
	       Use, WithData, Armed, Unsupported);

	*Got = (UINT32)Use;
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * STAGE 2 -- ARM. Everything below WRITES IA32_LBR_CTL.
 * ============================================================================================= */

/*
 * WHICH CORES WE ARMED. Not "did we arm" as a single bool -- per core, because disarm must clear
 * only what we set. A core whose LBR someone else owns must come out of a disarm untouched, and the
 * register alone cannot say whose it is.
 */
static volatile LONG gLbrArmedMask[NXC_LBR_MAX_CPUS];

/* Set only by `lbr disarm --force` -- see the note in the disarm callback. */
static volatile LONG gLbrDisarmForce = 0;

/* Shared with the IPI callbacks. Written before the broadcast, read inside it. */
static volatile LONG  gArmFlags     = 0;
static volatile LONG  gArmProbeOnly = 0;
static volatile LONG  gArmContended = 0;
static volatile LONG  gArmUnsupported = 0;
static volatile LONG  gArmDone      = 0;

/**
 * Decide, on THIS core, whether it can satisfy the request -- and optionally do it.
 *
 * ⚠ TWO PASSES OVER ONE FUNCTION, and the probe pass is not politeness. A hybrid machine can differ
 * per core type, so arming core by core as we discover capability would leave a machine half armed
 * with no way back to a defined state. The first broadcast decides; only if every core says yes does
 * the second one write. `gArmProbeOnly` selects which.
 */
static ULONG_PTR
LbrArmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_LBR_MAX_CPUS)
		return 0;

	CONST ULONG Want = (ULONG)gArmFlags;

	int Regs[4];
	__cpuid(Regs, 0);
	CONST ULONG MaxLeaf = (ULONG)Regs[0];

	BOOLEAN ArchBit = FALSE;
	if (MaxLeaf >= 7)
	{
		__cpuidex(Regs, 7, 0);
		ArchBit = ((ULONG)Regs[3] & (1u << 19)) != 0;
	}
	if (!ArchBit || MaxLeaf < 0x1C)
	{
		InterlockedIncrement(&gArmUnsupported);
		return 0;
	}

	__cpuidex(Regs, 0x1C, 0);
	CONST ULONG DepthMask = (ULONG)Regs[0] & 0xFFu;
	CONST ULONG Ebx       = (ULONG)Regs[1];

	if (DepthMask == 0)
	{
		InterlockedIncrement(&gArmUnsupported);
		return 0;
	}

	/*
	 * ⚠ EVERY CAPABILITY IS CHECKED BEFORE THE BIT THAT NEEDS IT IS SET. Setting IA32_LBR_CTL[2:1]
	 * on a part that does not support CPL filtering, or [22:16] without branch filtering, or [3]
	 * without call-stack mode, is a #GP on the WRMSR -- and this image has no SEH.
	 *
	 * CPL filtering is required unconditionally, not only for the default: user-only recording is
	 * what keeps our own read path out of the ring, so a part without it cannot deliver the property
	 * this whole surface is built on. Refusing is more useful than silently recording everything.
	 */
	if ((Ebx & (1u << 0)) == 0)                                        /* CPL filtering  */
	{
		InterlockedIncrement(&gArmUnsupported);
		return 0;
	}
	/*
	 * ⚠ BRANCH FILTERING IS NEEDED FOR *EVERY* ARM, NOT ONLY FOR --calls. An empty IA32_LBR_CTL[22:16]
	 * records NOTHING (measured), so the unfiltered case has to write all seven type bits
	 * explicitly -- which needs the same capability. This check used to be gated on CALLS_ONLY, and
	 * that is precisely how the default path came to arm a facility that could never record.
	 *
	 * A part WITHOUT the capability is a different situation: it cannot be told which types to keep,
	 * so 22:16 stays zero and the part's own unfiltered behaviour applies. That is reported rather
	 * than refused, because refusing would make LBR unavailable on hardware where it does work.
	 */
	if ((Ebx & (1u << 1)) == 0 && (Want & NXCMD_LBR_ARM_CALLS_ONLY))
	{
		InterlockedIncrement(&gArmUnsupported);
		return 0;
	}
	if ((Want & NXCMD_LBR_ARM_CALL_STACK) && (Ebx & (1u << 2)) == 0)   /* call stack     */
	{
		InterlockedIncrement(&gArmUnsupported);
		return 0;
	}

	CONST ULONG64 Ctl = __readmsr(IA32_LBR_CTL);
	if (Ctl & LBR_CTL_EN)
	{
		InterlockedIncrement(&gArmContended);
		return 0;
	}

	if (gArmProbeOnly)
		return 0;

	/* ---- the write pass ---- */

	/*
	 * Deepest supported depth THIS core enumerates. Derived, never passed in: writing a value the
	 * part does not support is a #GP, so the only safe source for it is the part itself.
	 */
	ULONG Depth = 0;
	for (ULONG b = 8; b-- > 0; )
	{
		if (DepthMask & (1u << b))
		{
			Depth = (b + 1) * 8;
			break;
		}
	}

	/*
	 * ⚠ ORDER MATTERS: EN CLEAR, THEN DEPTH, THEN CONFIGURE-AND-ENABLE. Writing IA32_LBR_DEPTH
	 * resets every entry, so doing it after enabling would arm a ring and immediately empty it --
	 * a surface that looks armed and silently loses the first branches it was armed to catch.
	 */
	__writemsr(IA32_LBR_CTL, 0);
	__writemsr(IA32_LBR_DEPTH_MSR, Depth);

	ULONG64 New = LBR_CTL_EN;

	/*
	 * USR without OS is the default and the point. KERNEL is opt-in and additive rather than
	 * exclusive: recording ring 0 does not stop recording ring 3, it just means our own path is in
	 * there too.
	 */
	New |= LBR_CTL_USR;
	if (Want & NXCMD_LBR_ARM_KERNEL)
		New |= LBR_CTL_OS;

	/*
	 * ⚠ THE TYPE FILTER IS ALWAYS WRITTEN WHEN THE PART SUPPORTS IT, because an empty 22:16 records
	 * NOTHING. Leaving it zero for the unfiltered case armed a facility that reported EN set, showed
	 * as armed in `lbr read`, and captured nothing forever -- caught by `lbr selftest`'s positive
	 * control on the first hardware run, and by nothing else, because the harness only ever exercised
	 * --calls.
	 */
	if (Ebx & (1u << 1))
	{
		New |= (Want & NXCMD_LBR_ARM_CALLS_ONLY)
		     ? (LBR_CTL_NEAR_REL_CALL | LBR_CTL_NEAR_IND_CALL | LBR_CTL_NEAR_RET)
		     : LBR_CTL_ANY_BRANCH;
	}

	if (Want & NXCMD_LBR_ARM_CALL_STACK)
		New |= LBR_CTL_CALL_STACK;

	__writemsr(IA32_LBR_CTL, New);

	/*
	 * ⚠ THE DIAGNOSTIC SKIPS ONLY THIS LINE, which is the whole point: the MSRs are written exactly
	 * as a real arming writes them, and only the RECORD of ownership is withheld. That is what a
	 * foreign owner looks like to `lbr read`, and anything less faithful would test the checker
	 * against a case it will never meet.
	 */
	if ((Want & NXCMD_LBR_ARM_FAKE_FOREIGN) == 0)
		InterlockedExchange(&gLbrArmedMask[Cpu], 1);
	InterlockedIncrement(&gArmDone);
	return 0;
}

NTSTATUS
NxcLbrArm(
	_In_ UINT32 ArmFlags,
	_Out_ UINT32* OutArmed,
	_Out_ UINT32* OutContended,
	_Out_ UINT32* OutUnsupported
	)
{
	*OutArmed       = 0;
	*OutContended   = 0;
	*OutUnsupported = 0;

	/*
	 * ⚠ CALL-STACK MODE AND A CALLS-ONLY FILTER ARE NOT INDEPENDENT. Call-stack mode maintains a
	 * call/return stack in the ring, which only means anything if calls and returns are the branches
	 * being recorded. Accepting the combination without the filter would produce a "call stack"
	 * diluted by conditional jumps -- well-formed and misleading, which is the class of output this
	 * project treats as worse than an error.
	 */
	if ((ArmFlags & NXCMD_LBR_ARM_CALL_STACK) && !(ArmFlags & NXCMD_LBR_ARM_CALLS_ONLY))
	{
		LbrLog("lbr: call-stack mode requires the calls-only filter -- refusing the combination\n");
		return STATUS_INVALID_PARAMETER_MIX;
	}

	gArmFlags       = (LONG)ArmFlags;
	gArmContended   = 0;
	gArmUnsupported = 0;
	gArmDone        = 0;

	/* PASS 1 -- decide. Writes nothing. */
	gArmProbeOnly = 1;
	(void)KeIpiGenericCall(LbrArmOnEachCpu, 0);

	CONST UINT32 Contended   = (UINT32)gArmContended;
	CONST UINT32 Unsupported = (UINT32)gArmUnsupported;

	*OutContended   = Contended;
	*OutUnsupported = Unsupported;

	if (Contended != 0)
	{
		gArmProbeOnly = 0;
		LbrLog("lbr: REFUSING to arm -- LBR_CTL.EN is already set on %u core(s)\n", Contended);
		return STATUS_DEVICE_BUSY;
	}
	if (Unsupported != 0)
	{
		gArmProbeOnly = 0;
		LbrLog("lbr: REFUSING to arm -- %u core(s) cannot satisfy the request\n", Unsupported);
		return STATUS_NOT_SUPPORTED;
	}

	/* PASS 2 -- write, now that every core has agreed. */
	gArmContended   = 0;
	gArmUnsupported = 0;
	gArmProbeOnly   = 0;
	(void)KeIpiGenericCall(LbrArmOnEachCpu, 0);
	CONST UINT32 Armed = (UINT32)gArmDone;

	*OutArmed = Armed;

	/*
	 * ⚠ D3 APPLIED TO A WRITE. Pass 1 agreeing does not prove pass 2 wrote: the two broadcasts are
	 * separate, and a core could have gone offline between them. Report what the SECOND pass
	 * actually did, never what the first predicted.
	 */
	LbrLog("lbr: armed %u core(s), flags 0x%X (%s)\n", Armed, ArmFlags,
	       (ArmFlags & NXCMD_LBR_ARM_KERNEL) ? "ring 0 AND ring 3 -- self-polluting"
	                                         : "ring 3 only -- our own path is excluded");
	return (Armed != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static volatile LONG gDisarmDone = 0;

static ULONG_PTR
LbrDisarmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_LBR_MAX_CPUS)
		return 0;

	/*
	 * Only what WE armed. A core we never touched keeps whatever its owner configured.
	 *
	 * ⚠ EXCEPT UNDER gLbrDisarmForce, which exists BECAUSE of `lbr arm --fake-foreign`. That
	 * diagnostic deliberately arms the MSRs without recording ownership, to give the contention check
	 * a known-bad -- and the ownership rule then makes the state unclearable by design, leaving LBR
	 * enabled on every core until reboot. A diagnostic that cannot be undone is a trap for whoever
	 * runs it next, so `lbr disarm --force` clears EN regardless of the record.
	 *
	 * ⚠ IT IS NOT THE DEFAULT AND MUST NOT BECOME ONE: forcing a disarm on a machine where a REAL
	 * profiler owns LBR steals it, which is the exact theft the ownership rule prevents.
	 */
	if (InterlockedExchange(&gLbrArmedMask[Cpu], 0) == 0 && gLbrDisarmForce == 0)
		return 0;

	__writemsr(IA32_LBR_CTL, 0);
	InterlockedIncrement(&gDisarmDone);
	return 0;
}

/*
 * ⚠ ONE BODY, TWO ENTRY POINTS. The ONLY difference is whether the ownership record is honoured, and
 * writing that logic twice is exactly how install and remove drifted apart on 07-30.
 */
static NTSTATUS
LbrDisarmInternal(
	_In_ BOOLEAN Force,
	_Out_ UINT32* OutDisarmed
	)
{
	InterlockedExchange(&gLbrDisarmForce, Force ? 1 : 0);
	*OutDisarmed = 0;

	gDisarmDone = 0;
	(void)KeIpiGenericCall(LbrDisarmOnEachCpu, 0);

	/* Never leave it set for the next caller -- a sticky force would silently steal a real
	 * profiler's ring on the following ordinary disarm. */
	InterlockedExchange(&gLbrDisarmForce, 0);

	*OutDisarmed = (UINT32)gDisarmDone;
	LbrLog("lbr: disarmed %u core(s)%s\n", *OutDisarmed, Force ? " (FORCED)" : "");
	return STATUS_SUCCESS;
}

NTSTATUS
NxcLbrDisarm(
	_Out_ UINT32* OutDisarmed
	)
{
	return LbrDisarmInternal(FALSE, OutDisarmed);
}

NTSTATUS
NxcLbrDisarmForce(
	_Out_ UINT32* OutDisarmed
	)
{
	LbrLog("lbr: FORCED disarm -- clearing EN regardless of the ownership record\n");
	return LbrDisarmInternal(TRUE, OutDisarmed);
}

/* ================================================================================================
 * STAGE 3 -- SNAPSHOTS FROM A HOOK. The only reading that is attributable to a target.
 * ============================================================================================= */

static NXCMD_LBR_SNAPSHOT* volatile gSnap      = NULL;
static volatile LONG                gSnapSlots = 0;
static volatile LONG                gSnapNext  = 0;   /* claimed slots, may exceed gSnapSlots */
static volatile LONG                gSnapTaken = 0;   /* slots actually written               */
static volatile LONG                gSnapDrop  = 0;   /* hits that found the ring full        */
static ULONG                        gSnapExtent = 0;
/*
 * ⚠⚠ WRAP MODE -- KEEP THE LAST N SNAPSHOTS INSTEAD OF THE FIRST N. OPT-IN, and the default stays
 * fill-and-stop because the two answer different questions and neither is generally right.
 *
 * Fill-and-stop keeps what happened immediately after the hook went in. That is correct when the
 * question is "what does this function do when called", and it is why it was built that way.
 *
 * It is exactly WRONG for a target that does something interesting once, at an unknown moment --
 * a section that decrypts, runs and re-encrypts. There the branches worth having are the ones
 * AROUND that event, and a ring that filled during the first milliseconds after arming holds
 * startup noise and then refuses everything that matters. Measured on this project's own motivating
 * target: the gsl.dll protected core is transient, and a usermode trap installed hundreds of ms
 * later got 0 hits on the hottest instruction in the VM.
 *
 * ⚠ THE COST IS REAL AND IS WHY THIS IS NOT THE DEFAULT. A snapshot is up to 3 RDMSRs per entry
 * (~96 for a depth-32 ring) on the TARGET'S OWN THREAD at its own IRQL. Fill-and-stop bounds that
 * cost by construction: once full, every later hit is one interlocked increment. Wrapping pays the
 * full price on every hit for as long as the hook is installed.
 */
static volatile LONG                gSnapWrap  = 0;
/* Snapshots overwritten by wrapping. NOT the same as a drop -- a drop was never recorded, this WAS
 * recorded and then replaced by something newer. Reported separately (D3) so "200 taken, 40 slots"
 * cannot be read as if 200 survived. */
static volatile LONG                gSnapOver  = 0;

NTSTATUS
NxcLbrSnapInit(
	_In_ UINT32 Slots,
	_In_ UINT32 Wrap
	)
{
	if (gSnap != NULL)
		return STATUS_ALREADY_COMMITTED;

	if (Slots == 0)
		return STATUS_INVALID_PARAMETER;
	if (Slots > NXC_LBR_MAX_SNAPSHOTS)
		Slots = NXC_LBR_MAX_SNAPSHOTS;

	ULONG Extent = 0;
	void* CONST Mem = NxcArenaAlloc((ULONG)((SIZE_T)Slots * sizeof(NXCMD_LBR_SNAPSHOT)), &Extent);
	if (Mem == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	/* The arena zeroes on allocation, so Valid == 0 everywhere means "never written" by default. */
	gSnapExtent = Extent;
	gSnapNext   = 0;
	gSnapTaken  = 0;
	gSnapDrop   = 0;
	gSnapOver   = 0;
	gSnapWrap   = (Wrap != 0) ? 1 : 0;
	gSnapSlots  = (LONG)Slots;

	/*
	 * ⚠ THE POINTER IS PUBLISHED LAST, AND THAT ORDER IS THE SYNCHRONISATION. NxcLbrSnapTake reads
	 * gSnap first and does nothing if it is NULL, so every field it depends on is already set by the
	 * time a non-NULL pointer is visible. Publishing the pointer first would leave a window where a
	 * hook fires against a slot count of zero.
	 */
	InterlockedExchangePointer((void* volatile*)&gSnap, Mem);

	LbrLog("lbr: snapshot ring ready -- %u slot(s), %u bytes, arena extent %u\n",
	       Slots, (ULONG)((SIZE_T)Slots * sizeof(NXCMD_LBR_SNAPSHOT)), Extent);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcLbrSnapFree(void)
{
	if (gSnap == NULL)
		return STATUS_NOT_FOUND;

	/*
	 * ⚠ REFUSES WHILE AN LBR-SAMPLING HOOK IS STILL IN. Freeing the ring under a live hook leaves
	 * the capture path storing into released arena memory -- the same shape as the use-after-free
	 * the hook's own teardown rules exist to prevent. Unhook first.
	 */
	if (NxcHookLbrSamplerCount() != 0)
	{
		LbrLog("lbr: REFUSING to free the snapshot ring -- an LBR-sampling hook is still installed\n");
		return STATUS_DEVICE_BUSY;
	}

	/*
	 * Unpublish BEFORE freeing, mirroring init's order, so no hit can be in flight against it.
	 *
	 * ⚠ SNAPSHOT THE BASE FIRST, because the free now takes the ADDRESS and the line below is about
	 * to destroy the only copy of it.
	 */
	void* CONST RetireBase = (void*)gSnap;

	InterlockedExchangePointer((void* volatile*)&gSnap, NULL);
	gSnapSlots = 0;

	/*
	 * ⚠ FREED BY BASE, NOT BY THE STORED EXTENT ID. An extent id is a position in an array that
	 * SHIFTS under both split and coalesce, so an id held across any other arena mutation names a
	 * different extent by the time it is used -- and this one was held from init to free, which is
	 * arbitrarily long. See the note on ArenaFreeByBase. `gSnapExtent` is kept for the log line only.
	 */
	if (RetireBase != NULL)
		(void)NxcArenaFreeFor(NXC_OWNER_HOST, RetireBase);
	gSnapExtent = 0;

	LbrLog("lbr: snapshot ring released\n");
	return STATUS_SUCCESS;
}

BOOLEAN
NxcLbrArmedHere(void)
{
	/*
	 * ⚠ DID **WE** ARM THIS CORE -- which is a different question from "is EN set right now", and on
	 * the #DB path the two disagree BY DESIGN. The processor clears IA32_LBR_CTL.EN before entering a
	 * debug-exception handler (SDM: it "does not clear previously stored LBR stack MSRs"), so at a
	 * trap EN reads 0 on a ring that is armed, full, and deliberately frozen for us.
	 *
	 * Testing EN there answers the wrong question and throws away the capture. This is the record
	 * `lbr arm` wrote, so it is the same fact rather than a second one that has to agree with it.
	 */
	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);

	if (Cpu >= NXC_LBR_MAX_CPUS)
		return FALSE;

	return (gLbrArmedMask[Cpu] != 0);
}

BOOLEAN
NxcLbrArchAvailable(void)
{
	/*
	 * ⚠ CACHED, BECAUSE THE CALLER IS THE TRAP PATH. BpdRecordHit runs on every claimed #DB -- 965 of
	 * them in 15 seconds on the data-breakpoint run -- and CPUID is a serialising instruction that
	 * would be paid every time for an answer that cannot change while the machine is running.
	 *
	 * ⚠ AND IT EXISTS BECAUSE NxcLbrFreezeRing DOES NOT GATE ITS OWN RDMSR. That is safe from Hook.c,
	 * which is only reached after `lbr arm` has already established support, but the trap path has no
	 * such guarantee: RDMSR of an unimplemented MSR raises #GP, and a manually mapped image has no
	 * SEH, so on a part without architectural LBR that is a BUGCHECK rather than a failed probe.
	 * Fail-closed, never "try it and see" -- the same rule the rest of this file is built on.
	 *
	 * -1 = not yet determined, 0 = absent, 1 = present. Racing callers compute the same value.
	 */
	static volatile LONG Cached = -1;

	CONST LONG Known = Cached;
	if (Known >= 0)
		return (Known != 0);

	int Regs[4] = { 0, 0, 0, 0 };
	LONG Answer = 0;

	__cpuidex(Regs, 0, 0);
	if ((ULONG)Regs[0] >= 0x1Cu)
	{
		/* CPUID.07H:0.EDX[19] says architectural LBR exists at all... */
		__cpuidex(Regs, 7, 0);
		if (((ULONG)Regs[3] & (1u << 19)) != 0)
		{
			/* ...and a non-zero CPUID.1CH.EAX[7:0] says a depth is actually supported. Both, because
			 * the feature bit without a usable depth is not something to write MSRs against. */
			__cpuidex(Regs, 0x1C, 0);
			if (((ULONG)Regs[0] & 0xFFu) != 0)
				Answer = 1;
		}
	}

	InterlockedExchange(&Cached, Answer);
	return (Answer != 0);
}

UINT64
NxcLbrFreezeRing(void)
{
	CONST ULONG64 Ctl = __readmsr(IA32_LBR_CTL);

	/*
	 * ⚠ ONE BIT, AND NO BRANCH. `rdmsr`/`wrmsr` are not control transfers, so freezing costs the
	 * ring NOTHING -- which is the entire point of doing it before anything else. Clearing only
	 * bit 0 preserves any filter, CPL setting or call-stack mode another owner configured.
	 *
	 * ⚠⚠ THIS FUNCTION SHIPPED ONCE WITH AN EMPTY BODY, AND THE BRACES ARE WHY IT IS NOT WRITTEN
	 * WITHOUT THEM. A cleanup edit deleted the `__writemsr` line from HERE instead of from
	 * NxcLbrSnapTake -- the same text appeared in both, and the earlier occurrence matched. What was
	 * left compiled CLEANLY, because a braceless `if` silently adopted the following `return Ctl;`
	 * as its body: the freeze became a no-op, AND a clear EN bit fell off the end of a
	 * value-returning function. One live run was spent measuring a fix that was never in the binary.
	 */
	if (Ctl & LBR_CTL_EN)
	{
		__writemsr(IA32_LBR_CTL, Ctl & ~LBR_CTL_EN);
	}

	return Ctl;
}

void
NxcLbrThawRing(
	_In_ UINT64 SavedCtl
	)
{
	/* Restored EXACTLY as found. Never a reconstructed word -- see the note in BpDispatch.h. */
	if (SavedCtl & LBR_CTL_EN)
		__writemsr(IA32_LBR_CTL, SavedCtl);
}

void
NxcLbrSnapTake(
	_In_ UINT64 TargetVa,
	_In_ UINT64 FrozenCtl
	)
{
	NXCMD_LBR_SNAPSHOT* CONST Ring = gSnap;
	if (Ring == NULL)
		return;

	CONST LONG Slots = gSnapSlots;
	if (Slots <= 0)
		return;

	/*
	 * ⚠ CLAIM THE SLOT WITH ONE ATOMIC, BECAUSE NO LOCK IS LEGAL HERE. This runs at the hooked
	 * function's IRQL, which may be above DISPATCH. InterlockedIncrement returns the NEW value, so
	 * the claimed index is one less -- and a claim past the end is counted as a drop and abandoned
	 * rather than wrapped. Wrapping would keep paying the RDMSR cost forever and would discard the
	 * FIRST snapshots, which for a newly installed hook are the ones worth having.
	 */
	CONST LONG Claimed = InterlockedIncrement(&gSnapNext) - 1;
	LONG Index = Claimed;
	if (Claimed >= Slots)
	{
		if (gSnapWrap == 0)
		{
			InterlockedIncrement(&gSnapDrop);
			return;
		}
		/*
		 * ⚠ WRAP: the ring keeps the LAST Slots snapshots. The modulo is on the CLAIMED ticket, so
		 * two threads never compute the same index for different tickets and no lock is needed --
		 * the same property the fill-and-stop path relies on.
		 *
		 * ⚠ THE OVERWRITE IS COUNTED, NOT SILENT. A reader seeing 40 slots and 200 taken must be
		 * able to tell that 160 were REPLACED rather than never recorded; those are different
		 * facts about the target and only this counter separates them.
		 */
		Index = Claimed % Slots;
		InterlockedIncrement(&gSnapOver);
	}

	NXCMD_LBR_SNAPSHOT* CONST S = &Ring[Index];

	/*
	 * ⚠ WHY WRITING HERE CANNOT FAULT, stated rather than assumed, because this runs at the hooked
	 * function's IRQL and a fault above APC_LEVEL is a bugcheck rather than a page-in.
	 *
	 * The arena is ONE contiguous EfiRuntimeServicesCode region reserved by the DXE at boot. Windows
	 * maps firmware runtime-services memory permanently and never trims it, so an arena address is
	 * resident for the life of the boot -- which is the property that makes the arena, and not pool,
	 * the only correct home for a buffer written from this context. (It is also why moving this ring
	 * to ExAllocatePool2 would be a latent bugcheck rather than a style change, even with
	 * POOL_FLAG_NON_PAGED, since that would reintroduce the tagged, enumerable artefact D4 exists to
	 * avoid.)
	 */
	S->TargetVa  = TargetVa;
	S->Timestamp = __rdtsc();
	S->ProcessId = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();
	S->ThreadId  = (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId();
	S->CpuNumber = (NXCMD_U32)KeGetCurrentProcessorNumberEx(NULL);

	/*
	 * ⚠⚠ THE LAST EVENT RECORD -- three RDMSRs, and the only reading LBR cannot produce.
	 *
	 * LBR keeps recording THROUGH exception dispatch, so an observer reading the ring inside a
	 * handler finds the dispatch path has already overwritten the interesting entries. LER holds
	 * the branch taken immediately BEFORE the last exception, hardware interrupt or software
	 * interrupt, and is not disturbed by the dispatch that follows.
	 *
	 * ⚠ SAFE WITHOUT A NEW CAPABILITY GATE, and that is a fact from the manual rather than an
	 * assumption. SDM Vol 3 20.1: the LER is "comprised of three MSRs (IA32_LER_FROM_IP,
	 * IA32_LER_TO_IP, IA32_LER_INFO), and is subject to the SAME DEPENDENCIES ON ENABLING AND
	 * FILTERING" as the LBRs. Vol 4 lists all three in the ARCHITECTURAL MSR table. So they exist
	 * exactly where architectural LBR exists -- which NxcLbrArm already required and cpuprobe
	 * already measures per core type. This code only runs from a snapshot, which only happens on a
	 * hook installed after a successful arm, so the enable is a precondition rather than a hope.
	 *
	 * ⚠ AND THE FREEZE ALREADY COVERS THEM. IA32_PERF_GLOBAL_STATUS.LBR_FRZ suspends LER recording
	 * along with the LBRs (Vol 3 20.1), so the freeze this function already performs before reading
	 * the ring protects these three MSRs too -- no separate window, and nothing to get wrong.
	 *
	 * ⚠ THE VALUES CAN LEGITIMATELY BE ZERO. The MSRs reset to zero and are written only when an
	 * event actually occurs; a thread that has taken no exception since reset carries zeros. That
	 * is a real answer, reported as-is, and usermode renders it as "no event" rather than as a
	 * branch from address zero.
	 */
	S->LerFrom = __readmsr(IA32_LER_FROM_IP);
	S->LerTo   = __readmsr(IA32_LER_TO_IP);
	S->LerInfo = __readmsr(IA32_LER_INFO);

	/*
	 * ⚠ THE DEPTH IS READ FROM THE MSR, NOT CACHED FROM ARM TIME. A cached depth would be wrong the
	 * moment anything re-armed LBR at a different one, and reading past the configured end walks
	 * into MSRs that are not part of the ring.
	 *
	 * ⚠ AND THE GATE IS LBR_CTL, NOT CPUID. CPUID cannot change; whether LBR is ENABLED can, and if
	 * it is not, every FROM reads zero and the snapshot would be an empty record claiming to be a
	 * capture. Nothing is stored in that case, so an empty slot means "not reached" and never
	 * "reached and found nothing".
	 */
	/*
	 * ⚠ THE RING IS ALREADY FROZEN. `NxcHookOnHit` calls NxcLbrFreezeRing as its FIRST action, before
	 * the nt API calls whose branches used to consume 23 of 32 entries (D36). `FrozenCtl` is the
	 * value as found at the instant of the hit -- so a clear EN bit means LBR genuinely was not
	 * recording, not that we turned it off.
	 */
	CONST ULONG64 Ctl = FrozenCtl;
	if ((Ctl & LBR_CTL_EN) == 0)
	{
		S->Valid = 0;
		InterlockedIncrement(&gSnapTaken);
		return;
	}

	/*
	 * ⚠⚠ STOP RECORDING BEFORE READING. THIS READ LOOP IS ITSELF A BRANCH SOURCE.
	 *
	 * measured: with LBR armed `--kernel` (ring 0 included), every snapshot came back as
	 * 32 IDENTICAL entries -- one 10-byte forward branch repeated until it filled the ring. That
	 * branch was THE LOOP BELOW. Reading 32 entries takes ~32 iterations, each a conditional branch
	 * recorded at ring 0, so the reader overwrote the ring faster than it could copy it. The capture
	 * destroyed exactly the thing it was capturing.
	 *
	 * ⚠ AND THE RING-3-ONLY DEFAULT HID IT. With `.USR` set and `.OS` clear, ring-0 branches are not
	 * recorded at all (D23), so this loop was invisible and the snapshot path looked correct through
	 * every earlier test. It only appeared when `--kernel` made kernel branches the SUBJECT -- which
	 * is precisely the configuration needed to trace kernel control flow.
	 *
	 * `NxcLbrSelfTest` never had the bug because it clears LBR_CTL before counting. The snapshot path
	 * simply never got the same treatment, and nothing compared them.
	 *
	 * ⚠ RESTORED EXACTLY AS FOUND, not to a value we think is right: another agent may own this ring,
	 * and writing back a reconstructed CTL would silently reconfigure their capture.
	 */
	__writemsr(IA32_LBR_CTL, Ctl & ~LBR_CTL_EN);

	ULONG Depth = (ULONG)(__readmsr(IA32_LBR_DEPTH_MSR) & 0xFFFFULL);
	if (Depth > NXCMD_LBR_MAX_ENTRIES)
		Depth = NXCMD_LBR_MAX_ENTRIES;

	ULONG Valid = 0;
	for (ULONG i = 0; i < Depth; i++)
	{
		CONST ULONG64 From = __readmsr(IA32_LBR_FROM_IP_0 + i);
		if (From == 0)
			break;
		S->Entry[i].From = From;
		S->Entry[i].To   = __readmsr(IA32_LBR_TO_IP_0 + i);
		S->Entry[i].Info = __readmsr(IA32_LBR_INFO_0 + i);
		Valid++;
	}

	/*
	 * Valid is published LAST so a drain that races the write sees either 0 (not yet a capture) or
	 * a count whose entries are already stored. The slot was claimed exclusively, so no other writer
	 * can be in it -- this orders against the READER only.
	 */
	S->Valid = Valid;
	InterlockedIncrement(&gSnapTaken);
}

void
NxcLbrSnapCounters(
	_Out_ UINT32* OutTaken,
	_Out_ UINT32* OutDropped,
	_Out_ UINT32* OutSlots,
	_Out_ UINT32* OutOverwritten
	)
{
	*OutTaken       = (UINT32)gSnapTaken;
	*OutDropped     = (UINT32)gSnapDrop;
	*OutSlots       = (UINT32)gSnapSlots;
	*OutOverwritten = (UINT32)gSnapOver;
}

NTSTATUS
NxcLbrSnapDrain(
	_Out_writes_(Cap) NXCMD_LBR_SNAPSHOT* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	NXCMD_LBR_SNAPSHOT* CONST Ring = gSnap;
	if (Ring == NULL)
		return STATUS_NOT_FOUND;

	CONST UINT32 Taken = (UINT32)gSnapTaken;
	CONST UINT32 Slots = (UINT32)gSnapSlots;
	CONST UINT32 Have  = (Taken < Slots) ? Taken : Slots;

	*Total = Have;

	CONST UINT32 Copy = (Have < Cap) ? Have : Cap;
	for (UINT32 i = 0; i < Copy; i++)
		Out[i] = Ring[i];

	*Got = Copy;

	/*
	 * ⚠ DRAIN DOES NOT RESET. Re-reading must give the same answer, because a caller whose buffer
	 * was too small has to be able to ask again -- and a drain that consumed would make truncation
	 * indistinguishable from data loss. `lbr snap free` then `init` is the explicit way to start
	 * over, which is a decision rather than a side effect of looking.
	 */
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * SELFTEST -- can the ring-3-only claim be DISPROVED on this silicon?
 * ============================================================================================= */

static volatile LONG gStUserOnlyKernelHits = 0;
static volatile LONG gStKernelModeHits     = 0;
static volatile LONG gStCores              = 0;
static volatile LONG gStSink               = 0;

/*
 * Kernel branches, on purpose and hard to optimise away. `volatile` on the sink forces the stores,
 * and the three functions are separate so the ring fills with DISTINCT source addresses rather than
 * one loop's backedge repeated -- a ring holding 32 copies of one address would pass a "did we
 * record anything" check while proving much less.
 */
#pragma optimize("", off)
static void BranchLeafA(void) { gStSink += 1; }
static void BranchLeafB(void) { gStSink += 2; }
static void BranchLeafC(void) { gStSink += 3; }

static void
BranchGenerator(void)
{
	for (int i = 0; i < 24; i++)
	{
		if (i & 1) BranchLeafA(); else BranchLeafB();
		if (i % 3 == 0) BranchLeafC();
	}
}
#pragma optimize("", on)

/**
 * Count entries whose FROM address is a KERNEL VA, on this core, right now.
 *
 * ⚠ THE TEST IS ON THE SOURCE ADDRESS, NOT THE TARGET. A user-mode branch INTO the kernel (a syscall
 * or a fault) legitimately has a kernel TO with a user FROM, and counting those would report the
 * filter as broken every time the target made a system call. What the filter promises is that a
 * branch TAKEN at ring 0 is not recorded -- so FROM is the field that tests the promise.
 */
static ULONG
CountKernelSourced(
	_In_ ULONG Depth
	)
{
	ULONG Hits = 0;
	for (ULONG i = 0; i < Depth && i < NXCMD_LBR_MAX_ENTRIES; i++)
	{
		CONST ULONG64 From = __readmsr(IA32_LBR_FROM_IP_0 + i);
		if (From == 0)
			break;
		/* Canonical kernel half of the x64 address space. */
		if (From >= 0xFFFF800000000000ULL)
			Hits++;
	}
	return Hits;
}

static ULONG_PTR
LbrSelfTestOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	int Regs[4];
	__cpuid(Regs, 0);
	if ((ULONG)Regs[0] < 0x1C)
		return 0;

	__cpuidex(Regs, 7, 0);
	if (((ULONG)Regs[3] & (1u << 19)) == 0)
		return 0;

	__cpuidex(Regs, 0x1C, 0);
	CONST ULONG DepthMask = (ULONG)Regs[0] & 0xFFu;
	CONST ULONG Ebx       = (ULONG)Regs[1];
	if (DepthMask == 0 || (Ebx & (1u << 0)) == 0)   /* need CPL filtering to test CPL filtering */
		return 0;

	/* Do not disturb a facility somebody else owns, even to test it. */
	if (__readmsr(IA32_LBR_CTL) & LBR_CTL_EN)
		return 0;

	ULONG Depth = 0;
	for (ULONG b = 8; b-- > 0; )
	{
		if (DepthMask & (1u << b)) { Depth = (b + 1) * 8; break; }
	}

	/*
	 * ⚠ THE TYPE FILTER IS PART OF "ARMED", AND LEAVING IT OUT IS WHAT BROKE THE FIRST RUN. An empty
	 * IA32_LBR_CTL[22:16] records NOTHING, so the original selftest armed with EN|USR|OS, generated
	 * kernel branches, and counted zero -- and reported the INSTRUMENT as broken, which it was.
	 *
	 * That is the positive control earning its place on its first outing: without phase 2, phase 1's
	 * zero would have been read as "the CPL filter works" when the real cause was that nothing was
	 * being recorded at all. Exactly the false conclusion the two-phase design exists to prevent.
	 */
	CONST ULONG64 Types = (Ebx & (1u << 1)) ? LBR_CTL_ANY_BRANCH : 0ULL;

	/*
	 * ---- PHASE 1: ring 3 ONLY. The kernel branches below must NOT appear. ----
	 *
	 * Depth is rewritten each phase because writing IA32_LBR_DEPTH resets every entry -- which is
	 * exactly the clean slate each phase needs, so the reset is used deliberately rather than worked
	 * around with a separate clear.
	 */
	__writemsr(IA32_LBR_CTL, 0);
	__writemsr(IA32_LBR_DEPTH_MSR, Depth);
	__writemsr(IA32_LBR_CTL, LBR_CTL_EN | LBR_CTL_USR | Types);

	BranchGenerator();

	__writemsr(IA32_LBR_CTL, 0);          /* stop before reading, so the read cannot add entries */
	CONST ULONG UserOnlyHits = CountKernelSourced(Depth);

	/*
	 * ---- PHASE 2: the POSITIVE CONTROL. Same generator, ring 0 now included. ----
	 *
	 * Without this, phase 1's zero is worthless: it would be produced just as readily by an LBR that
	 * is not recording at all, by a depth of zero, or by a generator the optimiser deleted. Phase 2
	 * failing is therefore a HARDER failure than phase 1 failing -- it means the instrument is
	 * broken, not the claim.
	 */
	__writemsr(IA32_LBR_DEPTH_MSR, Depth);
	__writemsr(IA32_LBR_CTL, LBR_CTL_EN | LBR_CTL_USR | LBR_CTL_OS | Types);

	BranchGenerator();

	__writemsr(IA32_LBR_CTL, 0);
	CONST ULONG KernelModeHits = CountKernelSourced(Depth);

	/* Leave the facility exactly as found: untouched and disabled. */
	__writemsr(IA32_LBR_DEPTH_MSR, Depth);
	__writemsr(IA32_LBR_CTL, 0);

	InterlockedAdd(&gStUserOnlyKernelHits, (LONG)UserOnlyHits);
	InterlockedAdd(&gStKernelModeHits, (LONG)KernelModeHits);
	InterlockedIncrement(&gStCores);
	return 0;
}

NTSTATUS
NxcLbrSelfTest(
	_Out_ UINT32* OutUserOnlyKernelHits,
	_Out_ UINT32* OutKernelModeHits,
	_Out_ UINT32* OutCoresTested
	)
{
	*OutUserOnlyKernelHits = 0;
	*OutKernelModeHits     = 0;
	*OutCoresTested        = 0;

	gStUserOnlyKernelHits = 0;
	gStKernelModeHits     = 0;
	gStCores              = 0;

	(void)KeIpiGenericCall(LbrSelfTestOnEachCpu, 0);

	*OutUserOnlyKernelHits = (UINT32)gStUserOnlyKernelHits;
	*OutKernelModeHits     = (UINT32)gStKernelModeHits;
	*OutCoresTested        = (UINT32)gStCores;

	LbrLog("lbr selftest: %u core(s) -- ring3-only kernel hits %u (must be 0), "
	       "ring0-included kernel hits %u (must be > 0)\n",
	       *OutCoresTested, *OutUserOnlyKernelHits, *OutKernelModeHits);
	return STATUS_SUCCESS;
}
