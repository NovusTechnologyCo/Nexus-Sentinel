/**
 * @file Tpm2Entropy.h
 * @brief RDRAND as the platform entropy source. See the .c for the shortfall this does NOT fix.
 */

#pragma once

#include <Uefi.h>

/**
 * Fill Out with Bytes bytes of hardware entropy.
 *
 * Matches TPM2_ENTROPY_FN so it can be handed straight to Tpm2SetEntropySource().
 *
 * @return TRUE only on a COMPLETE fill. On failure the buffer is zeroed rather than left
 *         part-written, because a partly-filled random buffer is a predictable one and a caller
 *         that ignores the return would otherwise find plausible-looking bytes.
 */
BOOLEAN Tpm2RdrandEntropy(OUT UINT8* Out, IN UINT32 Bytes);
