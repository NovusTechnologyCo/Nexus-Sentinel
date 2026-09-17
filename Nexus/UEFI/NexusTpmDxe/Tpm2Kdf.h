/**
 * @file Tpm2Kdf.h
 * @brief KDFa -- SP800-108 counter mode with HMAC, as TPM 2.0 Part 1 §8.4.10.2 defines it.
 *
 * WHY IT MATTERS HERE. Part 1 §8.4.9: *"a Primary Key is derived from a seed value, not the RNG
 * directly ... Generation of a Primary Key from a seed is based on use of an approved key
 * derivation function."* That is the mechanism that makes an SRK survive a reboot, and its absence
 * is what Windows is reporting as event 519, "The TPM has been cleared. Reason: SRK has changed".
 *
 * KDFa is also used almost everywhere else a key is needed: session keys, the XOR obfuscation
 * parameter, credential protection, symmetric keys for duplication. Part 1: *"With the exception
 * of ECDH, KDFa() is used in all cases where a KDF is required."* So this is not a one-purpose
 * helper -- it is the derivation primitive the rest of the TPM is built on.
 */

#pragma once

#include "Tpm2Hash.h"

/**
 * KDFa(hashAlg, key, label, contextU, contextV, bits).
 *
 * The inner loop, Part 1 Equation 6:
 *
 *     K(i) = HMAC(key, [i]2 || Label || 0x00 || contextU || contextV || [L]2)
 *
 * with `[i]2` a 32-bit big-endian counter starting at 1, and `[L]2` the 32-bit bit count. Blocks
 * are concatenated until they cover the request, then truncated -- which discards the *most
 * recently added* bits, not the earliest.
 *
 * ⚠ THE ZERO OCTET AFTER THE LABEL IS PART OF THE CONSTRUCTION, not a string terminator that
 * happens to be there. Part 1: *"If Label is not present, a zero octet is added. If Label is
 * present and the last octet is not zero, a zero octet is added."* Passing a NUL-terminated string
 * and hashing its terminator satisfies that exactly, and a caller who trims the NUL to be tidy
 * silently changes every key this function produces.
 *
 * ⚠ WHEN `Bits` IS NOT A MULTIPLE OF 8, THE HIGH BITS OF THE FIRST OCTET ARE CLEARED AND THE
 * VALUE IS NOT SHIFTED. Part 1 §8.4.10.2, with a worked example: a 521-bit ECC private key comes
 * back in 66 octets with the top 7 bits of octet zero clear. Shifting instead of masking gives a
 * different value that still looks plausible.
 *
 * @param Label     NUL-terminated. NULL means no label, and a single zero octet is emitted.
 * @param Out       receives exactly (Bits + 7) / 8 octets.
 * @return FALSE on a bad algorithm, a zero bit count, or a request larger than Out can be.
 */
BOOLEAN Tpm2KdfA(
	IN  UINT16       HashAlg,
	IN  CONST UINT8* Key,
	IN  UINT32       KeyLen,
	IN  CONST CHAR8* Label,
	IN  CONST UINT8* ContextU,
	IN  UINT32       ContextULen,
	IN  CONST UINT8* ContextV,
	IN  UINT32       ContextVLen,
	IN  UINT32       Bits,
	OUT UINT8*       Out
	);

//
// The largest KDFa output this build will ask for. RSA-2048 generation draws two 1024-bit
// candidate primes' worth of deterministic bytes at a time, and the DRBG below refills in blocks
// rather than one enormous call.
//
#define TPM2_KDF_MAX_BYTES          512

/**
 * A deterministic byte stream keyed by a seed -- the thing that makes a primary key reproducible.
 *
 * ⚠ THIS IS NOT AN SP800-90A DRBG AND DOES NOT CLAIM TO BE. It is KDFa called repeatedly with an
 * incrementing counter in contextV, which gives a stream that is deterministic in (seed, label,
 * context) and unpredictable without the seed. Part 1 requires primary keys to come from *an
 * approved KDF* applied to a seed, which this is; it does not require them to come from a DRBG,
 * which this is not. `TPM_PT_MODES` still correctly does not claim FIPS.
 */
typedef struct _TPM2_KDF_STREAM {
	UINT16 HashAlg;
	UINT8  Seed[TPM2_MAX_DIGEST_SIZE];
	UINT32 SeedLen;
	CONST CHAR8* Label;
	UINT8  Context[64];
	UINT32 ContextLen;
	UINT32 Counter;                    /* blocks emitted so far */
	UINT8  Block[TPM2_MAX_DIGEST_SIZE];
	UINT32 BlockUsed;                  /* bytes of Block already handed out */
	UINT32 BlockLen;
} TPM2_KDF_STREAM;

/** Start a stream. Copies the seed and context so the caller may free or reuse theirs. */
BOOLEAN Tpm2KdfStreamInit(
	OUT TPM2_KDF_STREAM* S,
	IN  UINT16           HashAlg,
	IN  CONST UINT8*     Seed,
	IN  UINT32           SeedLen,
	IN  CONST CHAR8*     Label,
	IN  CONST UINT8*     Context,
	IN  UINT32           ContextLen
	);

/**
 * Draw the next bytes.
 *
 * ⚠ SHAPED LIKE TPM2_RAND_FN ON PURPOSE, so it can be handed straight to
 * `Tpm2RsaGenerateKey` in place of the entropy source. That substitution is the whole point: the
 * same generator produces a random key from RDRAND and a REPRODUCIBLE key from a seed, with no
 * second code path to keep in step.
 */
BOOLEAN Tpm2KdfStreamBytes(IN OUT TPM2_KDF_STREAM* S, OUT UINT8* Out, IN UINT32 Bytes);
