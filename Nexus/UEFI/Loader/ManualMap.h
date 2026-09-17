/**
 * @file ManualMap.h
 * @brief Scope item 4c -- load the runtime DXE WITHOUT gBS->LoadImage, so the firmware never records it.
 *
 * WHY (the design notes). `gBS->LoadImage` does two things we do not want,
 * beyond actually loading the image:
 *
 *   1. It MEASURES the image into the TCG event log -- an EV_EFI_RUNTIME_SERVICES_DRIVER record in
 *      PCR[2] carrying our DEVICE PATH IN PLAINTEXT. Tier 3 erases that record afterwards, but
 *      erasing is strictly worse than never producing it: erasure has to work, every boot, and it
 *      cannot help if the sanitizer is ever bypassed.
 *   2. It installs EFI_LOADED_IMAGE_PROTOCOL on a firmware-created handle, which puts us in the
 *      UEFI LOADED-IMAGE LIST. `LocateHandleBuffer(ByProtocol, LoadedImage)` enumerates every loaded
 *      image with its path, and Tier 3 does not touch that list at all. This is the surface 4c
 *      closes that nothing else does.
 *
 * MEASURED BEFOREHAND, so this is not speculative: the OTHER candidate surface -- our hooked
 * gRT->GetVariable/SetVariable pointers -- turned out NOT to distinguish us. On the final memory map
 * all six gRT entries, ours and the firmware's, share one EfiRuntimeServicesCode region. So the
 * loaded-image list and the PCR[2] record ARE what identify us, and they are exactly what this
 * removes.
 *
 * ⚠ WHAT WE TAKE ON BY SKIPPING LoadImage. The firmware relocates registered runtime images at
 * SetVirtualAddressMap. A manually-mapped image is not registered, so the DXE must relocate ITSELF
 * (see Include/PeRelocate.h). Get that wrong and the first runtime GetVariable call after Windows
 * switches to virtual addressing jumps into an address that no longer exists. That is the fragile
 * part of 4c and it will not show up in a host test.
 *
 * We also synthesise the things LoadImage would have provided:
 *   - a handle, created by installing a protocol on NULL;
 *   - an EFI_LOADED_IMAGE_PROTOCOL with our real device path, because Tier 3's CollectSelfPaths
 *     identifies our images through it. Without this, self-identification returns zero, the
 *     transform fails closed, and the working spoof silently switches itself off.
 *
 * Note the synthetic protocol does NOT put us back in the loaded-image list in the incriminating
 * sense: the list is enumerated by protocol, so we ARE findable by a UEFI-time walker -- but the
 * firmware's own image registry, the PCR[2] measurement, and the SetVirtualAddressMap registration
 * are all absent. Closing the protocol route as well would break Tier 3, which is a worse trade.
 */

#pragma once

#include <Uefi.h>

/**
 * Map a PE runtime driver from the ESP into EfiRuntimeServicesCode memory and start it, without
 * ever calling gBS->LoadImage.
 *
 * @param FilePath   ESP path, e.g. L"\\EFI\\OEM\\PlatformRuntimeDxe.efi"
 * @param OutHandle  receives the synthesised image handle
 *
 * On failure nothing is left installed and any allocation is released, so the caller can fall back
 * to gBS->LoadImage. That fallback matters: a machine that will not boot is worse than one whose
 * DXE is measured.
 */
EFI_STATUS
EFIAPI
ManualMapRuntimeDriver(
	IN CHAR16* FilePath,
	OUT EFI_HANDLE* OutHandle
	);
