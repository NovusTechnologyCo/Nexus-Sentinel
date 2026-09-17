/**
 * @file NexusTcg2.h
 * @brief `EFI_TCG2_PROTOCOL` — the interface the boot loader looks for and does not find.
 *
 * ⚠ THIS IS THE MEASURED BLOCKER, not a guess. `PlatformCtl status` reports, from the ABI-18 boot
 * block field:
 *
 *     firmware TCG   : TCG2 absent    TCG1.2 absent    final-events absent
 *
 * With Intel PTT disabled the platform offers the boot loader no TPM at all, so Windows has
 * produced no MeasuredBoot log since and enters the OS with no measured-boot state.
 * That is why `tpm.sys` binds our ACPI device, reports `CM_PROB_NONE`, starts its service — and
 * never writes a single byte to the CRB. Four reboots were spent on the CRB before the evidence
 * pointed here.
 *
 * ⚠ AND THIS PATH AVOIDS G1 ENTIRELY. G1 — the open gate — exists because a RAM CRB has no
 * hardware doorbell AFTER ExitBootServices. TCG2 is a BOOT-SERVICES-TIME protocol: the loader
 * calls a function pointer, we run, we return. No CRB, no doorbell, no signalling problem. G1 is
 * not solved by this; it is simply not on this path.
 *
 * ⚠ WHAT IS STILL UNPROVEN. That the firmware offers nothing is measured. That supplying TCG2 is
 * SUFFICIENT to make Windows initialise a TPM is NOT — it is the hypothesis this exists to test.
 * Do not read "we implemented TCG2" as "Windows will now have a TPM".
 */

#ifndef NEXUS_TCG2_H
#define NEXUS_TCG2_H

#include <Uefi.h>

/**
 * Build the PCR bank and event log, then install `EFI_TCG2_PROTOCOL` on a new handle.
 *
 * ⚠ MUST be called while boot services are live and allocation is still legal — alongside
 * `NexusCoreReserve()` and the transport init, not from the ExitBootServices callback. The event
 * log is allocated `EfiACPIMemoryNVS` because the OS reads it after we are gone.
 *
 * ⚠ REFUSES TO INSTALL IF THE FIRMWARE ALREADY PUBLISHES TCG2. Two TCG2 protocols would mean two
 * PCR banks disagreeing about the same PCRs, and a log that cannot replay. If the platform ever
 * gains a real TPM again — PTT re-enabled, say — this stands down rather than competing.
 *
 * @retval EFI_SUCCESS          protocol installed
 * @retval EFI_ALREADY_STARTED  firmware already publishes TCG2; nothing was installed
 * @retval other                allocation or InstallProtocolInterface failure, reported verbatim
 */
EFI_STATUS
NexusTcg2Install(
	IN EFI_PHYSICAL_ADDRESS StateBase,
	IN UINT32               StateSize
	);

/**
 * Whether this boot installed the protocol, and how much of the log has been used.
 *
 * @param OutLogBase   event log physical base, 0 if not installed
 * @param OutLogUsed   bytes written so far
 * @param OutEvents    entries written, including the Spec ID header event
 */
VOID
NexusTcg2GetState(
	OUT UINT64* OutLogBase,
	OUT UINT32* OutLogUsed,
	OUT UINT32* OutEvents
	);

/**
 * Capacity of the event log in bytes, whether or not anything has been written to it.
 *
 * Distinct from the `OutLogUsed` of NexusTcg2GetState(): the boot block publishes the EXTENT so
 * the OS side can map and parse the whole log, and a "used" figure captured at DXE exit would be
 * stale the moment the boot loader wrote its first entry.
 */
UINT32
NexusTcg2LogSize(
	VOID
	);

#endif // NEXUS_TCG2_H
