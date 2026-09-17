/**
 * @file Tpm2PeHash.h
 * @brief Authenticode PE/COFF image hash — the digest a TCG2 provider must produce for
 *        `HashLogExtendEvent(PE_COFF_IMAGE, ...)`.
 *
 * ⚠ THIS EXISTS BECAUSE NOT HAVING IT BROKE THE BOOT. measured, not theorised.
 *
 * `NexusTcg2.c` originally refused `PE_COFF_IMAGE` with `EFI_UNSUPPORTED`, documented at the time
 * as an honest refusal: PFP section hashing is a real algorithm and a wrong digest would produce a
 * PCR no verifier could reproduce. That reasoning was correct and the consequence was catastrophic.
 *
 * The moment `EFI_TCG2_PROTOCOL` is advertised, the platform's measured-boot path measures EVERY
 * image before loading it, and treats a measurement failure as an authentication failure:
 *
 *     [LOADER] Booting Boot0005: Windows Boot Manager
 *     [LOADER] LoadImage failed: 8000000000000003 (Unsupported)
 *     ... every boot option in turn ...
 *     Failed to boot anything. This is super bad!
 *
 * `0x8000000000000003` is `EFI_UNSUPPORTED` — our own return value, handed back through
 * `LoadImage`. EDK2's `DxeTpm2MeasureBootLib` confirms the mechanism exactly:
 *
 *     Status = Tcg2Protocol->HashLogExtendEvent (Tcg2Protocol, PE_COFF_IMAGE, ...);
 *     if (Status == EFI_VOLUME_FULL) {
 *       // Just return EFI_SUCCESS in order not to block the image load.
 *       Status = EFI_SUCCESS;
 *     }
 *     ...
 *     return Status;
 *
 * ⚠ ONLY `EFI_VOLUME_FULL` IS FORGIVEN. Every other error propagates and stops the image loading.
 * So advertising TCG2 makes PE/COFF measurement **mandatory, not optional** — a refusal is a
 * bricked boot chain.
 *
 * ---------------------------------------------------------------------------------------------
 * THE ALGORITHM
 * ---------------------------------------------------------------------------------------------
 *
 * PFP §3.3.3.1 does not define it; it defers to the *Microsoft Windows Authenticode Portable
 * Executable Signature Format*. The 16 steps, as EDK2 numbers them:
 *
 *    3-4.  hash from the image base up to the OptionalHeader `CheckSum` field
 *    5.    SKIP `CheckSum` (4 bytes) — it changes without the content changing
 *    6.    if there is no Certificate data directory: hash on to `SizeOfHeaders` and go to 10
 *    7.    otherwise hash on to the start of the Certificate directory ENTRY
 *    8.    SKIP that entry (8 bytes) — a signature must not be part of what it signs
 *    9.    hash from after it to `SizeOfHeaders`
 *    10.   SUM_OF_BYTES_HASHED = SizeOfHeaders
 *    11-12 build a table of section headers and SORT it by `PointerToRawData`
 *    13-15 hash each section's `SizeOfRawData` bytes, adding each to SUM
 *    16.   if the image is larger than SUM, hash the remainder, EXCLUDING the certificate table
 *
 * ⚠ THE BUFFER IS FILE LAYOUT, NOT LOADED LAYOUT. Sections are located at
 * `ImageAddress + PointerToRawData`, not at their `VirtualAddress`. EDK2's own TCG2 provider does
 * exactly this, and using VirtualAddress would produce a digest that is wrong in a way nothing
 * detects — it would simply never match anyone else's measurement of the same file.
 *
 * ⚠ THE SORT MATTERS. Sections are hashed in `PointerToRawData` order, which is not necessarily
 * the order they appear in the section table. Skipping the sort yields a digest that is right for
 * most images and wrong for some — the worst possible failure distribution.
 *
 * ---------------------------------------------------------------------------------------------
 * DEPENDENCY-FREE, like the rest of the TPM core, so it is host-testable against an oracle.
 * ---------------------------------------------------------------------------------------------
 */

#ifndef NEXUS_TPM2_PEHASH_H
#define NEXUS_TPM2_PEHASH_H

#include <Uefi.h>
#include "Tpm2Core.h"

/**
 * Compute the Authenticode SHA-256 digest of a PE/COFF image.
 *
 * ⚠ EVERY FIELD READ FROM THE IMAGE IS BOUNDS-CHECKED AGAINST `Size` BEFORE USE. The buffer comes
 * from whatever is being loaded, which at this point in boot has not been validated by anything.
 * A malformed header must produce FALSE, never a read outside the buffer.
 *
 * @param Image   the image bytes, in FILE layout
 * @param Size    bytes available
 * @param Digest  receives 32 bytes on success; untouched on failure
 *
 * @retval TRUE   digest computed
 * @retval FALSE  not a PE/COFF image we can parse — the caller MUST still not block the load
 */
BOOLEAN
Tpm2HashPeImage(
	IN  CONST UINT8* Image,
	IN  UINT64       Size,
	OUT UINT8        Digest[TPM2_SHA256_DIGEST_SIZE]
	);

#endif // NEXUS_TPM2_PEHASH_H
