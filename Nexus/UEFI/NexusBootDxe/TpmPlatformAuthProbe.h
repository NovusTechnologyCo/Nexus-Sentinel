/**
 * @file TpmPlatformAuthProbe.h
 * @brief Ask, at DXE time, whether platformAuth is still the empty buffer.
 *
 * Read TpmPlatformAuthProbe.c for why this question decides the entire TPM approach. In short:
 * the EK certificate NV indices are not write-locked, so rewriting the certificate is possible if
 * the platform hierarchy can be authorised -- and unlike intercepting reads (tried in v1, failed;
 * only EPT ever worked) changing the DATA has no ring-0 bypass.
 */

#ifndef NEXUS_TPM_PLATFORM_AUTH_PROBE_H
#define NEXUS_TPM_PLATFORM_AUTH_PROBE_H

#include <Uefi.h>

/**
 * Run the INERT trial-session probe and print the verdict to the boot console.
 *
 * @param OutRc  the TPM response code: 0 = platformAuth usable here, 0x0A2 = TPM_RC_BAD_AUTH
 *               (already randomised), 0xFFFFFFFF = transport failure, which is NOT an answer.
 *
 * Creates nothing and writes nothing. A refusal returns TPM_RC_BAD_AUTH, which is DA-exempt and
 * therefore costs no dictionary-attack try.
 */
EFI_STATUS
NexusTpmPlatformAuthProbe(
	OUT UINT32* OutRc
	);

#endif
