/**
 * @file NexusTpmTransport.h
 * @brief Phase 1.2 -- RAM CRB transport (region A) and canonical state (region B) allocation.
 *
 * `the design notes` section 3.3, 3.4. See NexusTpmTransport.c for the Phase-1 packaging
 * decision that puts this inside NexusBootDxe rather than a separate NexusTpmDxe.efi.
 */

#pragma once

#include <Uefi.h>

/**
 * Allocate both NVS regions and leave them in the ExitBootServices handoff state.
 *
 * MUST be called while allocation is still legal -- alongside NexusCoreReserve() and
 * InitTcgLogSanitizer(), not from the ExitBootServices callback.
 *
 * @param OutTransport  region A physical base. This is the CRB LOCALITY base. The ACPI TPM2
 *                      table publishes the CONTROL AREA, which is this + 0x40.
 * @param OutState      region B physical base (canonical state; NOT ACPI-described).
 * @param OutEpoch      the boot epoch both regions carry. Any address recovered from saved driver
 *                      state must be rejected unless its epoch matches this one.
 *
 * @retval EFI_SUCCESS          both regions allocated and initialised
 * @retval EFI_ALREADY_STARTED  already initialised this boot; the outputs are the existing regions
 * @retval other                allocation or CRC failure; region A is freed if region B fails
 */
EFI_STATUS
NexusTpmTransportInit(
	OUT EFI_PHYSICAL_ADDRESS* OutTransport,
	OUT EFI_PHYSICAL_ADDRESS* OutState,
	OUT UINT64*               OutEpoch
	);

/**
 * Byte sizes of regions A and B. Single source of truth for the page counts.
 */
UINT32 NexusTpmTransportSizeA(VOID);
UINT32 NexusTpmTransportSizeB(VOID);
