/**
 * @file NexusCore.c
 * @brief NexusCore -- STAGE 1. Proves the EFI->kernel manual-map path, and nothing else yet.
 *
 * WHAT THIS IS FOR (v2 rebuild). NexusCore is the kernel half of the security
 * introspection framework. v1's NexusCore held this same role -- "manually mapped by NexusBootDxe
 * at boot time", providing on-demand mapping of further drivers, talking over hooked SetVariable,
 * deliberately absent from PsLoadedModuleList with no device objects. v2 rebuilds it clean rather
 * than porting (v1 is REFERENCE, never a source to port from).
 *
 * STAGE 1 SCOPE IS DELIBERATELY ALMOST-EMPTY. The thing under test is the HANDOFF, not the driver.
 * So this file does exactly one useful thing: it proves, capability by capability, which parts of
 * the kernel environment our foothold actually hands us, and reports that through a shared block
 * that can be read WITHOUT a kernel debugger. Functionality lands on top once the path is trusted.
 *
 * ============================================================================================
 * MANUAL-MAP CONSTRAINTS -- every one of these is a real crash if ignored
 * ============================================================================================
 *
 *  1. The security pragmas MUST precede every include. They disable /GS stack cookies and runtime
 *     checks for this translation unit. A mapped driver has no CRT init, so the cookie machinery
 *     those checks call into was never set up.
 *
 *  2. NEVER call __security_init_cookie() here. It is the loader's job and it is not valid in this
 *     context. Where a cookie IS present in the image, THE MAPPER initialises it (see the GS
 *     handling in the EFI-side mapper) -- not the driver. Learned from BlackAlien's testdriver,
 *     which states this explicitly.
 *
 *  3. DriverEntry is called as DriverEntry(NULL, NULL). There is no DriverObject and no
 *     RegistryPath: umap notes mapped drivers "must be designed to function without a real driver
 *     object". Anything needing one (IoCreateDevice, DriverUnload, dispatch tables) is off limits
 *     until we deliberately manufacture a driver object later. Touching the NULL is a bugcheck.
 *
 *  4. Imports may ONLY come from ntoskrnl.exe. The mapper resolves one module's exports; an import
 *     from hal.dll or anywhere else fails to bind and the first call jumps to garbage. Keep this
 *     file's API surface inside nt.
 *
 *  5. No global constructors, no C++ runtime, no floating point. Nothing runs before DriverEntry.
 *
 * ============================================================================================
 * IMPROVEMENT over the reference implementations (the point is the best solution, not a port)
 * ============================================================================================
 *
 * RedLotus (reference material/BlackAlien) hands the mapper's data to the driver through a
 * fixed-size zeroed array, `UCHAR mapper_data[MAPPER_DATA_SIZE]`, at a known symbol. Two problems:
 * a multi-KB zeroed array at a predictable location is itself a signature, and finding it requires
 * either a hardcoded RVA or that exact symbol layout.
 *
 * Instead the driver EXPORTS a single pointer-sized slot. The mapper resolves it from the driver's
 * own export directory (by hash, like it does for nt) and writes one QWORD. That is ~4 KB less
 * distinctive image content, pins no offset, and means the layout can change freely without
 * touching the mapper.
 */

/* MUST be first: kill security checks before anything can pull in a cookie reference. */
#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>
/*
 * Needed for va_start/va_end. ntddk.h does NOT provide them, and without this the linker fails
 * with LNK2019 on both. Safe in a manually-mapped driver: on MSVC these are compiler INTRINSICS,
 * not CRT calls, so including this pulls in no runtime we do not have.
 */
#include <stdarg.h>

#include "../../Include/NexusCoreBoot.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "Arena.h"
#include "MapModule.h"
#include "Capture.h"
#include "LogRing.h"
#include "TpmCrb.h"
#include "Pte.h"
/* For NxcTraceNmiInit only -- the NMI observer is registered from DriverEntry so it can see NMIs
 * that arrive with nothing armed, which is the state every bugcheck 0x80 so far occurred in. */
#include "Trace.h"

/*
 * The one slot the mapper patches, exported so it is resolvable by export hash with no hardcoded
 * RVA. `volatile` because the mapper writes it from a different execution context entirely (UEFI,
 * before the kernel is running) and the compiler must not cache or reorder around that write.
 *
 * Initialised to NULL so that a NON-mapped load -- someone sc-creating this as a normal service --
 * is detected and refused rather than dereferencing a wild value. RedLotus does the same check via
 * MmIsAddressValid; a NULL initialiser plus validation is strictly cheaper and equally safe.
 */
__declspec(dllexport) volatile NEXUS_CORE_BOOT_BLOCK* NexusCoreBootSlot = NULL;

/*
 * THE nt CALL TABLE. Exported so the EFI mapper finds it by name from our own export directory --
 * same mechanism as NexusCoreBootSlot, no hardcoded RVA.
 *
 * Filled by the mapper BEFORE DriverEntry runs. Every nt call in this driver goes through it, so the
 * payload emits NO import table and therefore no FF 25 thunks for the published manual-map scan to
 * match (see the long rationale in NexusNtApi.h).
 *
 * Magic is pre-set so the mapper can confirm it resolved OUR table before writing pointers into it.
 */
__declspec(dllexport) volatile NXC_NT_API NexusNtApi = { NXC_NT_API_MAGIC };

/* Every nt name below this line routes through the table above. */
#include "../../Include/NexusNtApiRedirect.h"

#define NXC_LOG_PREFIX "[NexusCore] "

/*
 * Non-static logging entry for the other translation units (Arena.c, MapModule.c). ONE logging
 * path for the whole driver keeps the nt import surface in a single auditable place -- the
 * mapper scrubs import NAMES from mapped images, but the IAT shape still reflects what we use.
 */
void NxcLogExt(_In_z_ PCSTR Format, ...);

/* Command.c. Published into the boot block at the very end of DriverEntry -- see the note there. */
NTSTATUS NxcCommandHandler(_Inout_ void* CommandRaw);

/**
 * Report through DbgPrint. Kept as the ONLY variadic logging path so the import surface stays
 * minimal and auditable -- every nt import in this file is visible in one place.
 */
static VOID
NxcLog(
	_In_z_ PCSTR Format,
	...
	)
{
	va_list Args;
	va_start(Args, Format);
	vDbgPrintExWithPrefix(NXC_LOG_PREFIX, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, Args);
	va_end(Args);
}

void
NxcLogExt(
	_In_z_ PCSTR Format,
	...
	)
{
	va_list Args;
	va_start(Args, Format);
	vDbgPrintExWithPrefix(NXC_LOG_PREFIX, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, Args);
	va_end(Args);
}

/**
 * Probe the kernel environment one capability at a time and return a NXC_CAP_* bitmask.
 *
 * WHY PROBE AT ALL, rather than assume: the whole reason the full-API foothold was chosen over the
 * earliest-possible hook is that NexusCore will eventually need pool, threads and device objects.
 * That choice is a PREDICTION about what the foothold provides. This function turns it into a
 * measurement, and a partial result localises the problem -- e.g. pool working but IRQL wrong says
 * the foothold fires somewhere unexpected, which a single pass/fail bit could never tell us.
 *
 * Ordered cheapest-and-safest first, so that if one wedges the machine, the block still shows how
 * far we got on the next boot.
 */
static NXC_U32
NxcProbeCapabilities(
	VOID
	)
{
	NXC_U32 Caps = 0;

	/* 1. DbgPrint. If this binds, import resolution against ntoskrnl worked at all. */
	NxcLog("stage 1 entry -- probing kernel environment\n");
	Caps |= NXC_CAP_DBGPRINT;

	/* 2. IRQL. Decides what the rest of this function is even allowed to attempt. */
	CONST KIRQL Irql = KeGetCurrentIrql();
	if (Irql == PASSIVE_LEVEL)
		Caps |= NXC_CAP_IRQL_PASSIVE;
	NxcLog("IRQL = %u (%s)\n", (NXC_U32)Irql,
	       Irql == PASSIVE_LEVEL ? "PASSIVE -- pool and waits are legal" : "ELEVATED");

	/* 3. Rtl* string helpers -- a second, independent import to confirm binding is general. */
	UNICODE_STRING Probe;
	RtlInitUnicodeString(&Probe, L"NexusCore");
	if (Probe.Length == 9 * sizeof(WCHAR) && Probe.Buffer != NULL)
	{
		Caps |= NXC_CAP_RTL_STRING;
		NxcLog("RtlInitUnicodeString OK (%wZ)\n", &Probe);
	}

	/*
	 * 4. Pool. The single most important capability for NexusCore's real work, and the one the
	 *    earliest-hook option would NOT have given us -- so this is the check that validates the
	 *    architectural choice rather than just the code.
	 *
	 *    Only attempted at PASSIVE_LEVEL: POOL_FLAG_NON_PAGED is legal at DISPATCH_LEVEL but this
	 *    is stage 1 and a wrong assumption here bugchecks instead of reporting.
	 */
	if (Irql <= DISPATCH_LEVEL)
	{
		PVOID Block = ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096, 'CxN');
		if (Block != NULL)
		{
			RtlZeroMemory(Block, 4096);
			ExFreePoolWithTag(Block, 'CxN');
			Caps |= NXC_CAP_POOL;
			NxcLog("ExAllocatePool2 + ExFreePoolWithTag OK\n");
		}
		else
		{
			NxcLog("ExAllocatePool2 FAILED -- pool not usable at this foothold\n");
		}
	}

	/*
	 * 5. A real wait. Proves we are on a thread that can block, which is what any future worker
	 *    thread in NexusCore depends on. Illegal above PASSIVE_LEVEL, hence the guard.
	 */
	if (Irql == PASSIVE_LEVEL)
	{
		/*
		 * ⚠ ZERO INTERVAL, NOT 1 ms. measured -- this one line was 86% of DriverEntry.
		 *
		 * It used to pass -10000 (a relative 1 ms). A RELATIVE delay does not expire after the stated
		 * interval; it expires on the next system clock tick, and Windows' default interval is
		 * ~15.6 ms. So "wait 1 ms" actually waited until the next tick boundary -- anywhere from ~1 ms
		 * to ~15.6 ms depending purely on where in the tick period we happened to land.
		 *
		 * That is what produced the entry-duration mystery: 1817 / 2427 / 10964 / 2084 / 13080 /
		 * 2871 / 2140 us across seven boots. I twice explained it as core-frequency variation. The
		 * per-phase measurement disproved that outright -- the caps probe measured 2230.7 us of a
		 * 2584.6 us entry (86.3%) on a FAST boot, while all real work totalled ~346 us, and
		 * APERF/MPERF showed the core in TURBO at 147% the whole time. Nothing was throttled; we were
		 * asleep.
		 *
		 * A zero interval yields the remainder of the time slice instead of arming a timer, so there
		 * is no tick to round up to.
		 *
		 * ⚠ THIS IS A DELIBERATE WEAKENING, stated plainly: it proves KeDelayExecutionThread is
		 * CALLABLE and returns success here, which requires PASSIVE_LEVEL. It no longer proves the
		 * thread was actually parked in a wait state and resumed. That is an acceptable trade -- the
		 * IRQL probe above already establishes PASSIVE, the scheduler demonstrably works (we are
		 * running on a boot driver's init thread in a live kernel), and the alternative was paying up
		 * to 15 ms of every boot, forever, to re-prove it.
		 */
		LARGE_INTEGER Delay;
		Delay.QuadPart = 0;
		if (NT_SUCCESS(KeDelayExecutionThread(KernelMode, FALSE, &Delay)))
		{
			Caps |= NXC_CAP_DELAY;
			NxcLog("KeDelayExecutionThread OK -- callable at this IRQL (zero interval, no tick wait)\n");
		}
	}

	return Caps;
}

/**
 * Entry point. Called by the EFI-planted kernel-side mapper as DriverEntry(NULL, NULL).
 *
 * Returns STATUS_SUCCESS on a good handoff. On a refusal it returns a failure status AND records
 * why in the block, because the mapper's return value alone is not visible anywhere by the time
 * anyone looks -- the block is the only durable record of what happened this boot.
 */
_Use_decl_annotations_
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
	)
{
	/*
	 * Both are NULL under a manual map, by design. Do NOT dereference them, and do not treat NULL
	 * as an error -- it is the expected case here (constraint 3 above).
	 */
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	volatile NEXUS_CORE_BOOT_BLOCK* Block = NexusCoreBootSlot;

	/*
	 * Refuse a non-mapped load. If someone service-starts this .sys, the slot is still NULL and
	 * there is nothing to report through -- bail before touching anything.
	 */
	if (Block == NULL)
	{
		NxcLog("no boot block -- not loaded by the Nexus mapper, refusing\n");
		return STATUS_NOT_SUPPORTED;
	}

	/*
	 * Validate the block BEFORE trusting any field in it, magic first. A stale DXE paired with a
	 * newer driver is the realistic failure, and it presents as plausible-looking garbage where
	 * pointers should be. Fail closed: refusing boots the machine clean, a wild write does not.
	 */
	if (Block->Magic != NEXUS_CORE_BOOT_MAGIC)
	{
		NxcLog("bad block magic %016llX -- refusing\n", (NXC_U64)Block->Magic);
		Block->Status = NXC_STATUS_BAD_MAGIC;
		return STATUS_INVALID_PARAMETER;
	}
	if (Block->Abi != NEXUS_CORE_BOOT_ABI ||
	    Block->InputSize != (NXC_U32)sizeof(NEXUS_CORE_BOOT_BLOCK))
	{
		NxcLog("ABI mismatch: mapper says abi=%u size=%u, driver built for abi=%u size=%u\n",
		       (NXC_U32)Block->Abi, (NXC_U32)Block->InputSize,
		       (NXC_U32)NEXUS_CORE_BOOT_ABI, (NXC_U32)sizeof(NEXUS_CORE_BOOT_BLOCK));
		Block->Status = NXC_STATUS_ABI_MISMATCH;
		return STATUS_REVISION_MISMATCH;
	}

	/*
	 * Stamp arrival immediately. EntryTsc is what distinguishes "ran this boot" from "block left
	 * over from a previous boot" -- without it, a mapper that silently stopped running looks
	 * identical to one that worked, which is exactly the class of blind check that has already
	 * cost this project real time.
	 */
	//
	// ⚠ NO SEH IN THIS DRIVER. NOT a style choice -- it CANNOT work here.
	//
	// x64 unwinding is table-driven: the kernel resolves a faulting RIP to an image's .pdata through
	// the LOADED-MODULE LIST, and a manually mapped image is deliberately absent from it. Registering
	// a dynamic function table would fix that, but measured:
	//
	//     ntoskrnl.exe exports RtlLookupFunctionEntry, RtlUnwind, RtlUnwindEx, RtlVirtualUnwind,
	//     RtlVirtualUnwind2, _local_unwind -- everything needed to WALK unwind data, and NOTHING
	//     to REGISTER a table. RtlAddGrowableFunctionTable / RtlDeleteGrowableFunctionTable are
	//     exported by ntdll.dll ONLY. They are usermode APIs.
	//
	// v1's mapper_cmd_driver.c:81 names RtlAddGrowableFunctionTable as the fix, so v1's mapped
	// drivers almost certainly had non-functional SEH too -- worth remembering when judging why v1
	// was unstable.
	//
	// So: no __try/__except anywhere in this driver or any module it maps. Use APIs that RETURN
	// status instead of raising (MmCopyVirtualMemory over ProbeForRead, for one) -- see the constraint
	// documented in Include/NexusModule.h.
	//
	CONST NXC_U64 EntryStartTsc = __rdtsc();

	//
	// ============================================================================================
	// REAL TIMEBASE + CORE-CLOCK SAMPLE (ABI 8). Taken at the very top, alongside the TSC.
	// ============================================================================================
	//
	// EntryDurationUs read 1817 / 2427 / 10964 / 2084 / 13080 us across five boots doing near-identical
	// work -- two clusters ~6x apart. I attributed that to core-frequency variation, but an invariant
	// TSC measures TIME at a fixed rate, so "the work grew" and "the clock dropped" produce exactly the
	// same TSC delta. The inference was unfalsifiable with the data being collected.
	//
	// APERF/MPERF is the instrument that separates them. MPERF advances at the fixed TSC rate; APERF
	// advances in proportion to ACTUAL core frequency, so APERF/MPERF over the interval IS the average
	// core-frequency ratio. Combined with a QPC-based elapsed time (known frequency, no assumed
	// constant), the two hypotheses become distinguishable from one boot's data.
	//
	// ⚠ CPUID GATE IS MANDATORY, NOT DEFENSIVE. APERF/MPERF exist only when
	// CPUID.06H:ECX.APERFMPERF[bit 0] is set. Reading a missing MSR raises #GP, and this driver has NO
	// SEH -- so an unguarded __readmsr on a CPU without the capability is a bugcheck, not a zero.
	//
	int CpuidRegs[4] = { 0, 0, 0, 0 };
	__cpuid(CpuidRegs, 6);
	CONST BOOLEAN HaveAperf = (CpuidRegs[2] & 1) ? TRUE : FALSE;

	CONST NXC_U64 StartAperf = HaveAperf ? __readmsr(0xE8) : 0;   /* IA32_APERF */
	CONST NXC_U64 StartMperf = HaveAperf ? __readmsr(0xE7) : 0;   /* IA32_MPERF */

	LARGE_INTEGER QpcFreq;
	QpcFreq.QuadPart = 0;
	CONST LARGE_INTEGER StartQpc = KeQueryPerformanceCounter(&QpcFreq);
	Block->QpcFrequency = (NXC_U64)QpcFreq.QuadPart;

	//
	// ============================================================================================
	// MEASURED PLATFORM PROTECTION STATE (ABI 13). Read from HARDWARE, never asked of Windows.
	// ============================================================================================
	//
	// Everything this framework does assumes VBS/HVCI are OFF. That was verified once, by hand, from
	// usermode -- and Microsoft is pushing VBS-on-by-default, so a Windows update or a Core Isolation
	// toggle can flip it with no announcement. The failure mode would be a bugcheck or a mapper that
	// silently stopped working, with nothing pointing at the cause.
	//
	// ⚠ CR4 AND CPUID, NOT WMI OR THE REGISTRY. Those are architectural state; the WMI/registry
	// answers are data structures a compromised or instrumented system can simply edit. For a
	// framework whose whole purpose is inspecting hostile code, asking the possibly-compromised
	// system whether it is protected is the wrong oracle.
	//
	// Neither read can fault: CR4 is always readable in kernel mode, and leaf 0x40000000 is only
	// queried after CPUID.01H:ECX[31] reports a hypervisor is present -- on bare metal that bit is
	// clear and the leaf is not architecturally defined, so querying it blind would return garbage
	// from whatever the highest supported leaf happens to alias to.
	//
	Block->EntryCr4 = (NXC_U64)__readcr4();

	int HvRegs[4] = { 0, 0, 0, 0 };
	__cpuid(HvRegs, 1);
	if ((HvRegs[2] & (1 << 31)) != 0)          /* CPUID.01H:ECX[31] -- hypervisor present */
	{
		__cpuid(HvRegs, 0x40000000);

		/*
		 * EBX, ECX, EDX are 12 raw bytes of vendor string -- contiguous in HvRegs[1..3]. Not a C
		 * string: no NUL, and "Microsoft Hv" is exactly 12 characters.
		 *
		 * Copied BYTE BY BYTE rather than with RtlCopyMemory because Block is volatile-qualified
		 * (C4090). That qualifier is load-bearing -- the mapper and the reader both look at this
		 * memory -- and passing it through memcpy launders the volatile away, which is precisely
		 * what it exists to prevent. A 12-byte loop costs nothing here.
		 */
		CONST UCHAR* CONST VendorBytes = (CONST UCHAR*)&HvRegs[1];
		for (ULONG i = 0; i < sizeof(Block->HvVendor); i++)
			Block->HvVendor[i] = VendorBytes[i];
	}
	/* else: left all-zero by the mapper's zero-init, which IS the answer -- no hypervisor. */

	Block->EntryTsc = EntryStartTsc;
	Block->EntryIrql = (NXC_U32)KeGetCurrentIrql();
	Block->Status = NXC_STATUS_ENTERED;

	NxcLog("mapped at %p (%u bytes), original entry %p\n",
	       (PVOID)(ULONG_PTR)Block->MappedImageBase,
	       (NXC_U32)Block->MappedImageSize,
	       (PVOID)(ULONG_PTR)Block->OriginalEntry);

	/*
	 * Timed because it CONTAINS THE ONLY BLOCKING WAIT in the whole entry -- a relative 1 ms
	 * KeDelayExecutionThread, which expires on the next system clock tick (~15.6 ms by default). Two
	 * boots proved the arena NX pass is stable to 0.75% while the total moved 2797 -> 2083 us, so the
	 * variance is not CPU work; a wait whose length depends on tick phase is the obvious remaining
	 * candidate and this is what confirms or clears it.
	 */
	CONST NXC_U64 CapsStartTsc = __rdtsc();
	CONST NXC_U32 Caps = NxcProbeCapabilities();
	Block->CapsProbeTsc = (NXC_U32)(__rdtsc() - CapsStartTsc);
	Block->Capabilities = Caps;

	//
	// Bind the arena allocator to the region the DXE reserved at boot (ABI 2). NexusCore cannot
	// allocate this kind of memory itself -- gBS is gone, and ExAllocatePool2 would reintroduce the
	// pool-tagged, enumerable allocation the arena exists to avoid.
	//
	// NON-FATAL on failure. A 16 MB contiguous reservation is not guaranteed on every firmware, and
	// everything NexusCore does today works without it; only the runtime `map` command needs it.
	// Reporting it here means "no arena" is legible instead of `map` failing later for an
	// unexplained reason.
	//
	/*
	 * Gates the arena NX pass further down. It must be the ALLOCATOR'S verdict, not merely
	 * "ArenaBase is non-zero": NxcArenaInit is what validates the region, so if it refused, the
	 * base/size pair is not something we have agreed is an arena and we must not walk 16 MB of page
	 * tables on its say-so. The protect would fail closed anyway -- the survey pass refuses a range
	 * containing a non-present page without touching anything -- but an implausible ArenaSize would
	 * still cost that walk on the BOOT PATH before refusing.
	 */
	BOOLEAN ArenaReady = FALSE;

	/*
	 * ⚠⚠ THE NMI OBSERVER IS REGISTERED BEFORE THE ARENA, UNCONDITIONALLY, AND THAT IS THE POINT.
	 *
	 * It used to live inside the arena-success branch below, so a boot where the firmware could not
	 * hand us a 16 MB contiguous reservation -- or where NxcArenaInit refused the one it did -- got
	 * NO observer at all. Those are exactly the boots most likely to be doing something unusual, and
	 * therefore most likely to produce the unclaimed NMI this observer exists to catch. The comment
	 * on the call said "REGISTERED FROM BOOT AND NEVER RELEASED" while the code said "registered
	 * only if the arena came up", and the comment was the intent.
	 *
	 * It has no arena dependency: storage is static and the call only registers a callback, so it
	 * cannot fail for resources in a way that needs unwinding. Non-fatal by design.
	 *
	 * -- the code and its own load-bearing comment had
	 * been out of sync since the observer was added.
	 */
	NxcTraceNmiInit();

	CONST NXC_U64 ArenaInitStartTsc = __rdtsc();

	if (Block->ArenaBase != 0 && Block->ArenaSize != 0)
	{
		CONST NTSTATUS ArenaStatus = NxcArenaInit((void*)(ULONG_PTR)Block->ArenaBase,
		                                          Block->ArenaSize);
		if (NT_SUCCESS(ArenaStatus))
		{
			ArenaReady = TRUE;
			Block->ArenaUsed = NxcArenaUsed();
			/* Hand the mapper ntoskrnl's location (ABI 3) so it can bind further drivers' imports. */
			NxcMapInit((void*)(ULONG_PTR)Block->KernelBase, Block->KernelSize);
			NxcLog("arena ready at %p: %u MB, largest allocatable %u MB\n",
			       (PVOID)(ULONG_PTR)Block->ArenaBase,
			       Block->ArenaSize / (1024 * 1024),
			       NxcArenaLargestFree() / (1024 * 1024));

			/*
			 * Capture AFTER the arena, because a pristine copy is allocated out of it.
			 *
			 * Deliberately NOT fatal, and the return is deliberately ignored here: capture is an
			 * added capability, and a foothold that refuses to finish booting because an optional
			 * subsystem could not start is strictly worse than one without it. If
			 * PsSetLoadImageNotifyRoutine is not yet available this early -- which v1 observed --
			 * the command path re-attempts registration, so this is recoverable without a reboot.
			 */
			(void)NxcCaptureInit();

			/*
			 * The event ring. Its storage is STATIC, so this only resets the cursor -- it cannot
			 * fail for resources and there is nothing to unwind. Started here so the very first
			 * command is already recorded rather than the ring beginning mid-session.
			 */
			(void)NxcLogRingInit();

			//
			// ⚠ G1: START SERVICING THE RAM CRB. measured: with the ACPI TPM2 table at
			// revision 5, tpm.sys accepts the platform and writes TPM_CRB_CTRL_REQ.cmdReady asking
			// the TPM to leave Idle -- then polls, times out, and logs "non-recoverable error in
			// the TPM hardware". Nothing was answering, because a RAM CRB has no doorbell and the
			// DXE stops executing at ExitBootServices.
			//
			// (!) NON-FATAL BY DESIGN. It returns NOT_FOUND when the DXE published no TPM regions
			// this boot, which is a legitimate state -- transport init is non-fatal too. A TPM we
			// cannot service must not stop the rest of the driver from loading.
			//
			(void)NxcTpmCrbStart();

			/*
			 * ⚠ THE NMI OBSERVER, REGISTERED FROM BOOT AND NEVER RELEASED.
			 *
			 * Eleven bugcheck 0x80s ("an NMI arrived and nothing claimed it") produced no evidence
			 * about the NMI itself, because our callback was only registered while tracing was
			 * ARMED -- and every one of those crashes happened with nothing armed. Nothing of ours
			 * was listening at the moment that mattered.
			 *
			 * Registering here fixes both halves: the observer records every NMI with the raw MSR
			 * state at delivery, and a permanent registration removes the deregistration decision
			 * that made an unclaimed NMI possible in the first place (that check was wrong twice --
			 * once for the sampling profiler, once when the PEBS filter became a third consumer).
			 *
			 * Storage is static and the call only registers a callback, so like the ring above it
			 * cannot fail for resources in a way that needs unwinding. Non-fatal by design.
			 *
			 * ⚠ MOVED OUT OF THIS BRANCH -- see below. It used to sit HERE, inside
			 * `if (NT_SUCCESS(ArenaStatus))`, which made "registered from boot" conditional on the
			 * firmware having handed us a usable 16 MB reservation.
			 */
		}
		else
		{
			NxcLog("arena init REFUSED 0x%08X -- runtime map unavailable\n", ArenaStatus);
		}
	}
	else
	{
		NxcLog("no arena reserved by the DXE -- runtime map unavailable\n");
	}

	//
	// ============================================================================================
	// MEASURE THE PAGE PROTECTIONS WE ACTUALLY GOT (ABI 5). READ-ONLY -- nothing is changed here.
	// ============================================================================================
	//
	// Task 7 says our mapped images are RWX with no per-section protections. Before acting on that we
	// need the starting state, and there has been no way to see it: the arena and the image both come
	// from gBS->AllocatePages(EfiRuntimeServicesCode), and what Windows does with EFI runtime memory
	// is decided by the firmware's EFI_MEMORY_ATTRIBUTES_TABLE, not by us.
	//
	// The measurement can come back two ways and they need OPPOSITE fixes -- RWX means tighten, R-X
	// means the arena is not writable and NxcArenaAlloc has a latent bugcheck that has never fired
	// because nothing has allocated from it on hardware yet. Choosing a direction before looking is
	// the exact habit v2 exists to stop, and here it would cost a reboot cycle per wrong guess.
	//
	// Deliberately placed AFTER the arena bind so that a failure in here cannot cost us the arena,
	// and BEFORE the duration stamp so the cost of the walk is included in what we report.
	//
	Block->ArenaInitTsc = (NXC_U32)(__rdtsc() - ArenaInitStartTsc);

	CONST NXC_U64 PteInitStartTsc = __rdtsc();
	CONST NTSTATUS PteInitStatus = NxcPteInit();
	Block->PteInitTsc = (NXC_U32)(__rdtsc() - PteInitStartTsc);

	if (NT_SUCCESS(PteInitStatus))
	{
		Block->PteSelfMapBase = NxcPteSelfMapBase();

		/*
		 * Declare what we are allowed to reprotect, BEFORE the first protect call. Until this runs
		 * every range is refused, which is the correct default -- a forgotten call is loud rather
		 * than an unguarded window. Both extents come from the block the DXE filled, so they are the
		 * memory the mapper actually reserved for us and nothing else.
		 */
		NxcPteSetOwnedRanges(Block->MappedImageBase, Block->MappedImageSize,
		                     Block->ArenaBase, Block->ArenaSize);

		/*
		 * ⚠⚠ THE INHERITED STATE IS CAPTURED HERE AND NOWHERE ELSE, BECAUSE HERE IS THE ONLY PLACE
		 * IT IS STILL TRUE (I-04, ABI 16).
		 *
		 * Nothing has reprotected anything yet -- NxcPteSetOwnedRanges ran just above and every
		 * protect call is still ahead. So these three PTEs are exactly what WINDOWS gave us, which is
		 * the only evidence that answers "does Windows enforce the firmware's MAT?".
		 *
		 * The image query below already read this value and then had it OVERWRITTEN after
		 * NxcPteProtectImage, so what reached usermode described our own protection pass. Stored to
		 * its own field now: two different facts had been sharing one name, and the one that got lost
		 * was the one no other field could reconstruct.
		 *
		 * ⚠ THE ENTRY PAGE IS THE DEPENDENCY, not the image base. The MAT covers them as separate
		 * descriptors and we protect them differently later (header R--, code R-X); only the page
		 * holding the entry point has to be EXECUTABLE for this machine to boot at all. It is taken
		 * from the address of this very function -- the code that must be callable naming the page
		 * that must be executable, with no RVA arithmetic to get wrong.
		 */
		NXC_PTE_INFO Inherited;
		Block->InheritedImagePte = 0;
		Block->InheritedArenaPte = 0;
		Block->InheritedEntryPte = 0;
		Block->InheritedPteValid = 0;

		if (NT_SUCCESS(NxcPteQuery(Block->MappedImageBase, &Inherited)))
		{
			Block->InheritedImagePte = Inherited.Flags;
			Block->InheritedPteValid |= 0x1u;
		}
		if (Block->ArenaBase != 0 && NT_SUCCESS(NxcPteQuery(Block->ArenaBase, &Inherited)))
		{
			Block->InheritedArenaPte = Inherited.Flags;
			Block->InheritedPteValid |= 0x2u;
		}
		if (NT_SUCCESS(NxcPteQuery((UINT64)(ULONG_PTR)&DriverEntry, &Inherited)))
		{
			Block->InheritedEntryPte = Inherited.Flags;
			Block->InheritedPteValid |= 0x4u;
		}

		NXC_PTE_INFO Info;
		if (NT_SUCCESS(NxcPteQuery(Block->MappedImageBase, &Info)))
		{
			Block->ImagePteFlags = Info.Flags;
			NxcLog("image  @%p: entry %016llX level %u -> %s%s%s\n",
			       (PVOID)(ULONG_PTR)Block->MappedImageBase, Info.Value, Info.Level,
			       (Info.Flags & NXC_PTE_WRITABLE) ? "W" : "-",
			       (Info.Flags & NXC_PTE_EXECUTE)  ? "X" : "-",
			       (Info.Flags & (NXC_PTE_LARGE_2M | NXC_PTE_LARGE_1G)) ? " LARGE PAGE" : "");
		}

		if (Block->ArenaBase != 0)
		{
			if (NT_SUCCESS(NxcPteQuery(Block->ArenaBase, &Info)))
			{
				Block->ArenaPteFlags = Info.Flags;
				NxcLog("arena  @%p: entry %016llX level %u -> %s%s%s\n",
				       (PVOID)(ULONG_PTR)Block->ArenaBase, Info.Value, Info.Level,
				       (Info.Flags & NXC_PTE_WRITABLE) ? "W" : "-",
				       (Info.Flags & NXC_PTE_EXECUTE)  ? "X" : "-",
				       (Info.Flags & (NXC_PTE_LARGE_2M | NXC_PTE_LARGE_1G)) ? " LARGE PAGE" : "");

				/*
				 * Say it out loud if the arena cannot be written. This is the case that would
				 * otherwise be discovered as an unexplained crash on the first runtime map, which is
				 * the most expensive way we have of learning anything.
				 */
				if ((Info.Flags & NXC_PTE_WRITABLE) == 0)
					NxcLog("*** ARENA IS NOT WRITABLE -- runtime map would fault on its first write\n");
			}

			//
			// ====================================================================================
			// THE ARENA IS NX BY DEFAULT. Executability is granted per section, per module, or not
			// at all.
			// ====================================================================================
			//
			// measured: the arena came back RWX. Writable is correct and was the thing
			// worth confirming -- it means the allocator has no latent fault. Executable is not. It
			// is 16 MB of executable memory belonging to no module, which is precisely the shape the
			// per-section work just finished removing from the image; leaving it here would mean we
			// cleaned the 36 KB and left the 16 MB next to it.
			//
			// W IS DELIBERATELY KEPT. The allocator writes extent headers and poisons freed blocks;
			// clearing W here would bugcheck it on the first allocation. Only X is ours to remove --
			// nothing executes from free arena space by definition, and a module's own code sections
			// get X back from NxcPteProtectImage at map time.
			//
			// ⚠ THIS IS WHY MODULE PROTECTION FAILURE IS NOW FATAL IN MapModule. Before this, a
			// failed protect left a module RWX -- a hardening gap, and it still ran. With an NX
			// arena, a section that does not get its protections applied does not get its X bit
			// either, so the module's entry call is a guaranteed fault. Refusing to run it is not a
			// policy choice any more, it is the only non-crashing option. The two changes are one
			// change and must not be separated.
			//
			// COST: 4096 pages x 3 passes (survey/commit/verify). It lands in EntryDurationUs, which
			// PlatformCtl flags above 50 ms, so a regression here is visible rather than assumed.
			//
			// BroadcastFlush = FALSE: boot path, BSP only. Same reasoning as the image below.
			//
			/*
			 * Timed on its own. This pass is 4096 pages x 3 (survey/commit/verify) and is by far the
			 * largest single cost in DriverEntry, so it is the prime suspect for the 6x swing in the
			 * reported entry duration. Measuring only the TOTAL cannot say whether the variable part is
			 * here or somewhere else -- which is the same "one number, many causes" problem that cost a
			 * boot on the mapper's refusal status.
			 */
			CONST NXC_U64 ArenaNxStartTsc = __rdtsc();

			CONST NTSTATUS ArenaNxStatus = ArenaReady
				? NxcPteProtectRange(Block->ArenaBase, Block->ArenaSize, TRUE, FALSE, FALSE)
				: STATUS_DEVICE_NOT_READY;

			Block->ArenaNxTsc = (NXC_U32)(__rdtsc() - ArenaNxStartTsc);

			if (!ArenaReady)
				NxcLog("arena: allocator refused this region -- NOT applying NX to it\n");
			else if (NT_SUCCESS(ArenaNxStatus))
			{
				NxcLog("arena: %u MB set RW- (NX by default; X is granted per module section)\n",
				       Block->ArenaSize / (1024 * 1024));
			}
			else
			{
				/*
				 * Almost certainly a large page somewhere in the 16 MB -- NxcPteProtectRange refuses
				 * the whole range rather than converting part of it. Worth saying loudly, because the
				 * SAME refusal will hit every module mapped into this arena, and MapModule now treats
				 * that as fatal. So this line predicts "map will refuse everything" one boot early,
				 * instead of leaving it to be discovered as an unexplained map failure later.
				 */
				NxcLog("*** ARENA NX REFUSED 0x%08X -- arena stays executable, and per-module\n"
				       "    protection will fail the same way. `map` will REFUSE modules.\n",
				       ArenaNxStatus);
			}

			/* Re-measure so the reported flags describe the state we LEFT, not the one we found. */
			if (NT_SUCCESS(NxcPteQuery(Block->ArenaBase, &Info)))
				Block->ArenaPteFlags = Info.Flags;
		}

		//
		// ========================================================================================
		// AND NOW FIX IT: give every section the protections its own header asks for.
		// ========================================================================================
		//
		// This is task 7 proper. The mapper copies sections to their RVAs and stops, so .text, .rdata
		// and .data all inherit one flat protection -- and "a large executable region belonging to no
		// module" is a documented scan target, quite apart from being wrong.
		//
		// The correct values were never a judgement call: IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE
		// are already in the section table. We simply never applied them. Confirmed present in this
		// payload -- section alignment 0x1000 with each of the 7 sections on its own page, and the
		// mapper copies headers (MapNexusCore.c:411), so the table is readable from the mapped image.
		//
		// SAFE TO DO ON OURSELVES WHILE RUNNING. We clear W on .text, which we never write, and set NX
		// on data, which we never execute. NxcPteProtectRange surveys before it commits and refuses
		// outright on a large page, so the one dangerous outcome -- silently changing protections on
		// two megabytes of neighbouring firmware memory, including the runtime code that services the
		// GetVariable transport this whole project reports through -- cannot happen.
		//
		// The BOOT BLOCK is deliberately NOT covered: it lives on its own page past SizeOfImage
		// (MapNexusCore.c NXC_BLOCK_OFFSET), outside every section, so it stays writable and the lines
		// below can still be recorded.
		//
		UINT32 Applied = 0;
		UINT32 Refused = 0;
		/*
		 * BroadcastFlush = FALSE. Only the BSP is executing on the boot-driver init path, so no other
		 * processor can hold a stale translation for these VAs -- see the long note at the shootdown
		 * in Pte.c. The runtime map path passes TRUE, and must.
		 */
		CONST NXC_U64 ImgProtStartTsc = __rdtsc();
		CONST NTSTATUS ImgProtStatus = NxcPteProtectImage(Block->MappedImageBase,
		                                                 Block->MappedImageSize,
		                                                 FALSE, &Applied, &Refused);
		Block->ImageProtectTsc = (NXC_U32)(__rdtsc() - ImgProtStartTsc);

		if (NT_SUCCESS(ImgProtStatus))
		{
			Block->ProtectApplied = Applied;
			Block->ProtectRefused = Refused;
			NxcLog("per-section protections: %u applied, %u refused\n", Applied, Refused);

			/*
			 * Re-measure so the reported image flags describe the state we LEFT, not the one we found.
			 *
			 * ⚠ MappedImageBase is the HEADER page, not .text -- RVA 0 is where the PE headers live.
			 * So this field reports whether NxcPteProtectImage's header pass worked, and it is the only
			 * durable record of that: the header range is deliberately excluded from Applied/Refused so
			 * those keep matching the section count. R-- here means the header pass succeeded.
			 */
			if (NT_SUCCESS(NxcPteQuery(Block->MappedImageBase, &Info)))
				Block->ImagePteFlags = Info.Flags;
		}
	}
	else
	{
		/* Left at 0, which the report renders as "could not look" rather than "all bits clear". */
		NxcLog("pte: self-map derivation failed -- protections not measured this boot\n");
	}

	/*
	 * Recorded on BOTH paths. On success it is a sanity figure; on failure it is the only thing that
	 * separates a broken address calculation from a broken assumption, and the first attempt at this
	 * cost a reboot precisely because "NOT DERIVED" carried no such discriminator.
	 */
	Block->PteProbeDiag = NxcPteProbeDiag();

	/*
	 * Record how long we spent on the boot-driver init path. KeQueryPerformanceCounter would be more
	 * honest than a TSC delta, but it is another nt import for a diagnostic -- and the TSC frequency
	 * only has to be stable enough to notice a REGRESSION (tens of microseconds vs milliseconds),
	 * not to be accurate. Assumes ~3 GHz; the number is a magnitude, not a measurement.
	 */
	Block->EntryDurationUs = (NXC_U32)((__rdtsc() - EntryStartTsc) / 3000ULL);

	/*
	 * THE HONEST FIGURES (ABI 8). EntryDurationUs above is kept only so the two can be COMPARED across
	 * the same boot -- if the QPC figure is stable while the TSC-derived one swings, that is the answer
	 * stated in data rather than argued.
	 *
	 * QPC first: its frequency is reported by the API, so elapsed time carries no assumed constant.
	 */
	CONST LARGE_INTEGER EndQpc = KeQueryPerformanceCounter(NULL);
	Block->EntryQpcTicks = (NXC_U64)(EndQpc.QuadPart - StartQpc.QuadPart);

	/*
	 * Then the core-clock ratio for the interval. Integer maths only -- no floating point in a mapped
	 * driver -- and MPERF is checked non-zero because a zero delta would be a divide fault, which in
	 * kernel mode with no SEH is a bugcheck rather than a NaN.
	 *
	 * ~100 => the core ran at base frequency for this interval.
	 * ~20  => it ran at a fifth of base, so identical work costs 5x the wall time and 5x the TSC ticks.
	 * 0    => the CPU does not advertise APERF/MPERF and we deliberately did not read the MSRs.
	 */
	if (HaveAperf)
	{
		CONST NXC_U64 DeltaAperf = __readmsr(0xE8) - StartAperf;
		CONST NXC_U64 DeltaMperf = __readmsr(0xE7) - StartMperf;
		if (DeltaMperf != 0)
			Block->AperfMperfPct = (NXC_U32)((DeltaAperf * 100ULL) / DeltaMperf);
	}

	NxcLog("entry timing: %llu qpc ticks @ %llu Hz, core at %u%% of base, arena NX %u tsc\n",
	       (NXC_U64)Block->EntryQpcTicks, (NXC_U64)Block->QpcFrequency,
	       Block->AperfMperfPct, Block->ArenaNxTsc);

	//
	// ============================================================================================
	// OPEN THE COMMAND CHANNEL (ABI 7). LAST, and that ordering is the point.
	// ============================================================================================
	//
	// The DXE's SetVariable hook calls this pointer the moment it is non-zero, and SetVariable is
	// called by Windows constantly -- so publishing it earlier would expose a handler that can map
	// modules into an arena whose protections had not been applied yet, on a driver whose own
	// self-checks had not finished. Every field the handler depends on (arena bound, NX applied,
	// mapper initialised with ntoskrnl's base) is set above this line.
	//
	// Written even if the arena failed: the handler answers NXCMD_RESULT_NO_ARENA for itself, which
	// is a legible refusal, whereas a null pointer here would make the channel look dead and send
	// the next investigation after the DXE instead of the reservation.
	//
	Block->CommandHandler = (NXC_U64)(ULONG_PTR)&NxcCommandHandler;

	Block->Status = NXC_STATUS_OK;

	NxcLog("stage 1 COMPLETE -- capabilities 0x%08X%s\n", Caps,
	       (Caps & NXC_CAP_POOL) ? " (pool available: foothold is good enough for real work)"
	                             : " (NO POOL: foothold is too early for NexusCore's real needs)");

	//
	// ============================================================================================
	// PROXY TO THE HIJACKED DRIVER'S ORIGINAL ENTRY. THIS IS NOT OPTIONAL.
	// ============================================================================================
	//
	// When the autonomous trigger is armed, we are running as a BOOT-START DRIVER'S DriverEntry --
	// the mapper redirected its EntryPoint field to us. That driver still has to load. If we return
	// without calling it, or return a failure status, a boot-start driver fails to initialise, which
	// can fail the boot outright.
	//
	// So: call the original with the arguments we were handed, and return ITS status verbatim. Our
	// own success or failure must not influence the result the kernel sees -- we are a passenger on
	// this call, not the owner of it.
	//
	// Note DriverObject is a REAL object here (not NULL as in the runtime-hook path), which is what
	// lifts the no-driver-object constraint for future work: IoCreateDevice and dispatch tables
	// become legal once we are on this path.
	//
	if (Block->OriginalEntry != 0)
	{
		typedef NTSTATUS (*NXC_DRIVER_INIT)(PDRIVER_OBJECT, PUNICODE_STRING);
		CONST NXC_DRIVER_INIT Original = (NXC_DRIVER_INIT)(ULONG_PTR)Block->OriginalEntry;

		//
		// ============================================================================================
		// VALIDATE BEFORE CALLING. This was a bare `!= 0` check followed by an indirect call.
		// ============================================================================================
		//
		//  This is the single most dangerous operation in the driver -- an
		// indirect call to an address read out of a shared structure -- and it was the least validated
		// thing in a file that checks everything else twice. Magic first, then ABI, then InputSize;
		// IRQL re-checked in Command.c even though the DXE already gated on CR8, on the stated grounds
		// that "the gate lives in another binary that ships separately, and 'the other side checks' is
		// how a missing check survives". That argument applies here exactly and was not applied.
		//
		// The block is ours and its magic and ABI are verified, which catches a STALE DXE. It does not
		// catch a DXE that writes a wrong pointer at the right offset -- and the consequence is not a
		// wrong result, it is an indirect call to garbage in kernel mode at boot-driver init: an
		// immediate bugcheck with no diagnostic. Worse, Status was stamped NXC_STATUS_OK a few lines
		// above, so the only surviving evidence would say the driver was healthy.
		//
		// Two cheap checks. Canonical kernel half rules out zero-extended, usermode and truncated
		// values; MmIsAddressValid rules out an unmapped one. Neither proves it is the RIGHT entry
		// point -- nothing here can, since the hijacked driver is an arbitrary boot driver we cannot
		// bound -- but together they turn "call whatever is in the field" into "call something that is
		// at least a mapped kernel address".
		//
		// ⚠ REFUSING IS ALSO BAD, and is chosen as the lesser harm. A boot-start driver that does not
		// initialise may fail the boot; that is the risk the proxy exists to avoid. But it fails
		// VISIBLY, with a flag in the block and a status the kernel can act on, whereas calling a bad
		// pointer fails invisibly and takes the machine with it.
		//
		if ((ULONG_PTR)Original < 0xFFFF800000000000ULL ||
		    !MmIsAddressValid((PVOID)Original))
		{
			NxcLog("*** REFUSING to proxy: OriginalEntry %p is not a mapped kernel address\n",
			       (PVOID)Original);
			Block->BootFlags |= NXC_BOOTFLAG_PROXY_REFUSED;
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		NxcLog("proxying to hijacked driver's original entry %p\n", (PVOID)Original);
		CONST NTSTATUS OriginalStatus = Original(DriverObject, RegistryPath);

		Block->BootFlags |= NXC_BOOTFLAG_PROXIED;
		NxcLog("original entry returned 0x%08X -- passing it through\n", OriginalStatus);
		return OriginalStatus;
	}

	/*
	 * No original entry: we were called from the runtime-hook fallback path, where there is no
	 * hijacked driver to proxy to and DriverObject is NULL.
	 */
	return STATUS_SUCCESS;
}
