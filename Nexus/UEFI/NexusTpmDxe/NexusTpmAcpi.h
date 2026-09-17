/**
 * @file NexusTpmAcpi.h
 * @brief Phase 1.3 -- publish the ACPI TPM2 table so the RAM CRB transport is discoverable.
 *
 * `the design notes` section 3.1, 3.4. See NexusTpmAcpi.c for the TCG ACPI 1.5 Table 7
 * transcription and for why Start Method 7 is the measurement choice in this phase.
 */

#pragma once

#include <Uefi.h>

/**
 * Build and install the TPM2 table for the transport at LocalityBase.
 *
 * MUST be called after NexusTpmTransportInit() and while boot services are live.
 *
 * @param LocalityBase  the CRB LOCALITY base (region A). The table advertises the CONTROL AREA,
 *                      which is this + 0x40 -- TCG ACPI 1.5 requires the published address to be
 *                      that of the TPM_CRB_CTRL_REQ_0 register, not the locality base.
 *
 * @retval EFI_SUCCESS      table installed; a known-answer self-check result is printed
 * @retval EFI_NOT_READY    LocalityBase is 0 -- the transport did not allocate
 * @retval EFI_UNSUPPORTED  firmware exposes no EFI_ACPI_TABLE_PROTOCOL; nothing was published
 * @retval other            InstallAcpiTable failed; the status is reported verbatim
 */
EFI_STATUS
NexusTpmAcpiPublish(
	IN EFI_PHYSICAL_ADDRESS LocalityBase
	);

/**
 * The control-area address advertised this boot, or 0 if nothing was published.
 */
EFI_PHYSICAL_ADDRESS
NexusTpmAcpiPublishedControlArea(
	VOID
	);

/**
 * Publish an SSDT declaring an MSFT0101 ACPI device whose _CRS covers the transport locality.
 *
 * Phase 1.3 MEASURED that the TPM2 table alone does not bind tpm.sys -- Windows accepted the
 * table and still reported TpmPresent False, because no ACPI device node exists. This supplies
 * one. Call AFTER NexusTpmAcpiPublish().
 *
 * @param LocalityBase  region A base. MUST be below 4 GB; Memory32Fixed cannot describe more,
 *                      and the call fails honestly rather than truncating the address.
 *
 * @retval EFI_SUCCESS      SSDT installed
 * @retval EFI_NOT_READY    LocalityBase is 0
 * @retval EFI_UNSUPPORTED  no EFI_ACPI_TABLE_PROTOCOL, or the region is above 4 GB
 */
EFI_STATUS
NexusTpmSsdtPublish(
	IN EFI_PHYSICAL_ADDRESS LocalityBase
	);

/**
 * Report which TCG facilities the FIRMWARE publishes (EFI_TCG2_PROTOCOL, the 1.2 protocol, and
 * the TCG2 final-events table). Pure measurement -- publishes nothing and changes nothing.
 *
 * Exists because tpm.sys wrote nothing to the CRB even after the INTF_ID register was made
 * coherent, and Windows produced no MeasuredBoot log this boot. Those logs come from the boot
 * loader, so their absence points upstream of the ACPI table entirely.
 */
UINT32
NexusTpmProbeFirmwareTcg(
	VOID
	);
