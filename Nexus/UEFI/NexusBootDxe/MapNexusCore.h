/**
 * @file MapNexusCore.h
 * @brief Map the embedded NexusCore.sys into kernel-resident memory, from UEFI, before the kernel runs.
 *
 * ============================================================================================
 * WHY THIS SHAPE -- and why it is simpler than every public reference
 * ============================================================================================
 *
 * The public mappers (umap, RedLotus/BlackAlien, nullmap) all need a KERNEL-SIDE stage: they plant
 * a small mapper that runs with kernel APIs and calls ExAllocatePool2 to get memory for the real
 * payload. That costs them a second component to hide, and puts the mapped image in NonPaged pool
 * -- which nullmap's own README admits "can be dumped so easily".
 *
 * We do not need any of that, because of one fact about where our hook sits: by the time
 * HookedOslFwpKernelSetupPhase1 runs, winload has ALREADY MAPPED ntoskrnl.exe at its final address.
 * The existing PatchNtoskrnl proves it -- it resolves nt exports there today
 * (GetProcedureAddress(ImageBase, .., "ExAllocatePool2")). So import resolution needs no kernel API
 * at all, and the ENTIRE map completes before the kernel executes a single instruction.
 *
 * Consequences, all of them wins:
 *   - no kernel-side mapper stub to conceal
 *   - no ExAllocatePool2, so nothing in NonPaged pool and nothing with a pool tag to enumerate
 *   - the image lives in EfiRuntimeServicesCode, which reads as firmware-reserved memory
 *   - one component instead of two
 *
 * v1 reached the same conclusion (NexusBootDxe.c:27 -- "In the winload hook: patches ntoskrnl
 * (DSE/PG), maps NexusCore.sys"), so this is our own proven architecture, rebuilt clean.
 *
 * ============================================================================================
 * TWO PHASES, because of a hard constraint on allocation
 * ============================================================================================
 *
 * Winload has two contexts and memory CANNOT be allocated in the protected-mode one -- the reason
 * EfiGuard keeps its 8 KB status buffer statically allocated (see the note atop PatchNtoskrnl.c).
 * The winload hook runs in that context. So the work splits:
 *
 *   PHASE 1  NexusCoreReserve()   at DXE entry, EFI services available.
 *            Allocate EfiRuntimeServicesCode, VERIFY THE SHA-256, copy headers + sections.
 *            Nothing here depends on the kernel.
 *
 *   PHASE 2  NexusCoreBind()      from the winload hook, ntoskrnl mapped, no allocation possible.
 *            Relocate, resolve nt imports, seed the GS cookie, fill the boot block, hand back the
 *            entry address. Pure computation over memory phase 1 already owns.
 *
 * ⚠ THE IMAGE MOVES ONE MORE TIME. EfiRuntimeServicesCode is relocated at SetVirtualAddressMap,
 * exactly as our own DXE is under scope 4c. So relocations must be applied AGAIN there, for the
 * ConvertPointer delta -- and relocations must never be applied twice for the same delta, which is
 * the trap 4c already documents ("relocating a LoadImage'd image applies the delta twice, equally
 * fatal"). NexusCoreRelocateForVirtual() is that step, and it must run exactly once.
 */

#pragma once

#include <Uefi.h>
#include "NexusPe.h"

/**
 * PHASE 1 -- reserve and stage. Call from the DXE entry point, where gBS is usable.
 *
 * Verifies the embedded payload's SHA-256 before touching anything, so a truncated or stale embed
 * fails here with a reason rather than becoming an early-boot hang later.
 *
 * @retval EFI_SUCCESS            staged; NexusCoreBind may run later
 * @retval EFI_CRC_ERROR          payload digest mismatch -- refuses to stage
 * @retval EFI_OUT_OF_RESOURCES   could not reserve runtime pages
 */
EFI_STATUS
EFIAPI
NexusCoreReserve(
	VOID
	);

/**
 * PHASE 2 -- bind to the kernel. Call from HookedOslFwpKernelSetupPhase1, AFTER ntoskrnl is mapped.
 *
 * Does no allocation, so it is safe in winload's protected-mode context.
 *
 * @param NtKernelBase     ntoskrnl.exe image base, as the winload hook already has it
 * @param NtKernelHeaders  its NT headers
 * @param OutEntry         receives the mapped DriverEntry address, or NULL on failure
 *
 * @retval EFI_SUCCESS       bound; *OutEntry is callable once the kernel is up
 * @retval EFI_NOT_READY     phase 1 never ran or refused
 * @retval EFI_NOT_FOUND     an import could not be resolved against ntoskrnl
 */
EFI_STATUS
EFIAPI
NexusCoreBind(
	IN UINT8* NtKernelBase,
	IN PEFI_IMAGE_NT_HEADERS NtKernelHeaders,
	OUT VOID** OutEntry
	);

/**
 * PHASE 3 -- re-relocate for the virtual address. Call ONCE from the SetVirtualAddressMap event,
 * alongside the DXE's own 4c self-relocation.
 *
 * Idempotent by an internal one-shot flag: calling twice would apply the delta twice and is fatal.
 */
VOID
EFIAPI
NexusCoreRelocateForVirtual(
	VOID
	);

/**
 * Address of the mapped image's boot block, for diagnostics. NULL until phase 1 succeeds.
 * The block is how stage 1 reports what happened WITHOUT a kernel debugger.
 */
VOID*
EFIAPI
NexusCoreGetBootBlock(
	VOID
	);

/**
 * Record one NXC_BOOTFLAG_* phase bit in the boot block.
 *
 * The DXE's boot phases are spread across MapNexusCore, PatchWinload and NexusBootDxe, and only
 * MapNexusCore owns the block pointer. Without this, "which phase did we reach" is unanswerable after
 * the fact -- the boot-console Print() calls are the only record and they scroll away.
 *
 * Added after a status read showed reserve had run and bind had not, with no way to tell
 * whether the winload patch was refused, never attempted, or applied-but-never-fired. Those have
 * different suspects, and guessing between them produced a confidently wrong answer.
 *
 * NULL-safe: some phases run before the block is addressable, and a diagnostic must never fault.
 */
VOID
EFIAPI
NexusCoreSetBootFlag(
	IN UINT32 Flag
	);

/**
 * Record the source line of a boot-phase refusal, so "which phase failed" gains a "why".
 *
 * The phase trail says winload was not patched. It cannot say whether the version was unreadable, the
 * build was below the floor, .text was missing, or the signature did not match -- four refusals with
 * four different responses, every one of them reported only by a Print() that scrolls away. That gap
 * is what left the arming failure undiagnosed.
 *
 * FIRST WRITER WINS: refusals cascade, and the first is the cause while the rest are consequences.
 */
VOID
EFIAPI
NexusCoreSetRefusalLine(
	IN UINT32 Line
	);

/**
 * Record WHY the kernel patch (PatchNtoskrnl and its two workers) gave up. Packed the same way.
 *
 * ⚠ A SEPARATE SLOT FROM NexusCoreSetRefusalLine, DELIBERATELY. Do not "simplify" these into one.
 * That field is first-writer-wins and the kernel patch runs BEFORE phase-2 bind, yet its failure is
 * non-fatal (bind proceeds -- the manual map needs no kernel patch). Sharing the slot would let an
 * advisory failure permanently occupy it and mask the bind refusal that actually stopped the load.
 *
 * Pairs with NXC_BOOTFLAG_KERNEL_PATCH_EVALUATED / _PATCHED: the flags say WHETHER, this says WHERE.
 * The expected real-world trigger is signature rot after a Windows kernel update.
 */
VOID
EFIAPI
NexusCoreSetKernelPatchLine(
	IN UINT32 Line
	);

/**
 * Publish g_PgContext's RVA, so `PlatformCtl pgdefuse verify` can read the pointer and decide for
 * itself whether the defusal took. See NEXUS_CORE_BOOT_BLOCK::PgContextRva (ABI 20).
 *
 * (!) CALLED ON EVERY BOOT THE LOCATOR RUNS, control boots included -- the defusal is skipped
 * there, but the RVA is published anyway, because the boot where PatchGuard is deliberately alive
 * is exactly the one you want to point a verifier at.
 */
VOID
EFIAPI
NexusCoreSetPgContextRva(
	IN UINT32 Rva
	);

/**
 * Record the Windows kernel build the PatchGuard signatures were matched against (ABI 13).
 *
 * Pairs with NexusCoreSetKernelPatchLine: that says WHERE a patch gave up, this says against WHICH
 * kernel it was aimed. Signature rot after a Windows update is the realistic failure here, and
 * diagnosing it needs both halves.
 *
 * ⚠ THE REVISION IS THE HALF THAT MOVES. ntoskrnl is 10.0.26100.8894 while Windows calls itself
 * build 26200 / 25H2; the build is stable for years, the revision changes every Patch Tuesday and
 * rewrites the bytes the signatures scan for.
 */
/**
 * Record WHICH DXE is running: our own PE TimeDateStamp (ABI 15).
 *
 * ⚠ PayloadIdent does not cover this. It hashes the embedded NexusCore.sys, so a DXE-only change --
 * the DSE removal, for instance -- leaves it byte-identical and the deploy
 * unverifiable. Compare against the file with tools/pe_timestamp.py.
 */
VOID
EFIAPI
NexusCoreSetDxeIdent(
	IN UINT32 Ident
	);

/**
 * ABI 17 -- publish the software-TPM regions so ring 0 can find them.
 *
 * Region A is the RAM CRB transport the ACPI TPM2 table advertises; region B is the canonical
 * state, deliberately not ACPI-described. Nothing else carries these across ExitBootServices.
 *
 * This is also what lets `readphys` into them: EfiACPIMemoryNVS is absent from Windows' system
 * RAM map, so the guard refuses both regions until it knows their published extents.
 *
 * @param Epoch  fresh per boot, 0 never valid. Anything caching one of these addresses must
 *               re-check the epoch and rediscover on a mismatch -- an address from a previous
 *               boot may point at readable memory that is now something else entirely.
 */
VOID
EFIAPI
NexusCoreSetTpmRegions(
	IN UINT64 TransportBase,
	IN UINT32 TransportSize,
	IN UINT64 StateBase,
	IN UINT32 StateSize,
	IN UINT64 Epoch
	);

/**
 * ABI 18 -- record which TCG facilities the FIRMWARE publishes (NXC_FWTCG_* bits).
 *
 * These describe the platform, not us. Read them before concluding anything about our own
 * transport: if the firmware offered the boot loader no TPM, the CRB was never the problem.
 */
VOID
EFIAPI
NexusCoreSetFirmwareTcg(
	IN UINT32 Flags
	);

/**
 * ABI 19 -- publish the TCG2 event log extent so it can be read AFTER Windows has booted.
 *
 * (!) The entry COUNT is the measurement. At DXE exit the log holds exactly one entry, the Spec
 * ID header event we wrote. Anything beyond that came from a HashLogExtendEvent call made by
 * someone else, and before ExitBootServices that can only be the boot loader. So a count of 1
 * means the loader never called us; more than 1 means it measured through us.
 *
 * That distinction is not otherwise observable: TpmPresent and the MeasuredBoot log both sit
 * downstream of G1 and read the same whether the loader measured perfectly or never called.
 *
 * @param Base  event log physical base, or 0 if TCG2 was not installed this boot
 * @param Size  event log size in bytes, or 0
 */
VOID
EFIAPI
NexusCoreSetTpmEventLog(
	IN UINT64 Base,
	IN UINT32 Size
	);

VOID
EFIAPI
NexusCoreSetKernelBuild(
	IN UINT32 BuildNumber,
	IN UINT32 Revision
	);

/**
 * PHASE 4 -- the armed one-shot. Call from the hooked GetVariable/SetVariable runtime services.
 *
 * WHY THIS EXISTS AT ALL: v1 reached NexusCore through a hooked SetVariable, but needed a Windows
 * SCHEDULED TASK to poke it. That task is a persistent, trivially-discoverable artifact -- a
 * Task Scheduler entry plus a usermode binary that must exist on disk -- which undoes much of what
 * scope 4c and the ESP path rename bought. Unacceptable for the same reason we stopped being named
 * in the TCG log.
 *
 * We do not need a trigger, because Windows already calls these hooks on its own: the Tier 1 SB
 * spoof is validated precisely by GetVariable being called many times per boot. So the vehicle
 * fires automatically, every boot, with ZERO artifacts. The "manual trigger" was never a property
 * of SetVariable -- it came from waiting on one specific variable write only usermode would make.
 *
 * Gated on two things, both necessary:
 *   - ARMED only after SetVirtualAddressMap. Before that we are not in kernel virtual address space
 *     and v1 proved calling kernel code earlier crashes ("NexusCore auto-init CANNOT happen here at
 *     ExitBootServices ... would crash").
 *   - PASSIVE_LEVEL only. On x64 IRQL *is* CR8, so this is one instruction and needs no kernel API.
 *     Windows may call runtime services at raised IRQL, so this is a real gate, not a formality --
 *     and NexusCore's probes (pool, blocking wait) are illegal above PASSIVE.
 *
 * Safe to call on every hooked call: it is a one-shot and returns immediately once fired.
 */
VOID
EFIAPI
NexusCoreTryLaunch(
	VOID
	);

/**
 * ARM THE ENTRY HIJACK -- the autonomous trigger. Call from the winload hook (phase 2) with the
 * loader entry of an early boot driver.
 *
 * WHY THIS REPLACES THE ONE-SHOT AS THE PRIMARY TRIGGER:
 *
 * Phase 4 fires on the first PASSIVE_LEVEL call to our hooked runtime services, and MEASUREMENT
 * showed Windows makes NO such call after boot -- calls-while-armed was 1 on every boot, and that
 * one call was PlatformCtl's own. The many GetVariable calls that validate the Tier 1 SB spoof all
 * happen BEFORE SetVirtualAddressMap, so they cannot arm anything. The launch was therefore waiting
 * on a human, indefinitely.
 *
 * That is fatal for HW spoofing, and for a reason of correctness rather than convenience: the window
 * [kernel start .. our patches live] is a window in which the REAL hardware IDs are readable, and
 * anything that sampled during it keeps the true value. v1's inline NDIS/SMBIOS hooks prove a real
 * share of that surface needs kernel APIs, so it cannot all move into the winload hook to dodge the
 * problem.
 *
 * MECHANISM -- data-only, which is the whole point. We overwrite the EntryPoint FIELD in a boot
 * driver's KLDR_DATA_TABLE_ENTRY. That is loader DATA, not code:
 *   - no byte of any driver's .text changes, so PatchGuard's image-integrity checks see nothing
 *   - no byte signature of a third-party driver to go stale next patch Tuesday
 *   - the kernel calls us through its own normal driver-init path, at PASSIVE_LEVEL with pool,
 *     threads and a REAL DriverObject -- which lifts the no-driver-object constraint entirely
 *
 * This is umap's technique (it hijacks acpiex.sys, entry running 2nd in load order after WDF) and
 * RedLotus's proxy pattern, and v1 already carried the KLDR_DATA_TABLE_ENTRY/boot-module lookup
 * scaffolding for it.
 *
 * ⚠ WE MUST PROXY FAITHFULLY. The hijacked driver still has to load: NexusCore calls the original
 * entry and returns ITS status. Returning failure would fail a boot-start driver, which can fail the
 * boot. The original entry is handed over in the boot block's OriginalEntry field.
 *
 * ⚠ ARMING ONLY RECORDS. The field is not written until phase 3, because the value to write is
 * NexusCore's FINAL virtual address, which is not known until SetVirtualAddressMap has run. The
 * address OF the field is captured here and stays valid -- it is kernel loader data, not an EFI
 * runtime region, so ConvertPointer does not move it.
 *
 * @param TargetEntryPointField  &KldrEntry->EntryPoint of the chosen boot driver
 * @param TargetOriginalEntry    its current value, preserved for the proxy call
 *
 * @retval EFI_SUCCESS       armed; phase 3 will redirect it
 * @retval EFI_NOT_READY     bind has not run, so there is no entry to redirect to
 */
EFI_STATUS
EFIAPI
NexusCoreArmEntryHijack(
	IN VOID** TargetEntryPointField,
	IN VOID* TargetOriginalEntry
	);

/**
 * Diagnostic counters, so a gate that never opens is DISTINGUISHABLE from a driver that failed.
 * Without this, "nothing happened" has two indistinguishable causes -- exactly the blind-signal
 * problem that has already cost this project real time.
 *
 * @param OutCalls        times a hooked runtime service ran while armed
 * @param OutRejectedIrql times the CR8 gate rejected the call
 */
VOID
EFIAPI
NexusCoreGetLaunchStats(
	OUT UINT32* OutCalls,
	OUT UINT32* OutRejectedIrql
	);
