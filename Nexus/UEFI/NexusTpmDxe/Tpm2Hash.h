/**
 * @file Tpm2Hash.h
 * @brief Crypto-agile hashing and HMAC for the TPM. No EDK2 library dependencies.
 *
 * WHY. `the design notes` §6.2 commits to a full per-spec TPM. Almost everything above
 * PCR_Extend is built on two primitives the project did not have: a hash selected AT RUNTIME by
 * TPM algorithm ID, and HMAC over that hash. Sessions, KDFa/KDFe, policy digests, HMAC
 * authorisation and the DRBG all bottom out here.
 *
 * ⚠ THIS IS REQUIRED UNDER BOTH BRANCHES OF THE §6.2 DECISION. The TCG reference implementation
 * does not supply hashing -- it takes it from a crypto backend, and we are the backend either way.
 * So this is not work that a later port would throw away.
 *
 * ⚠ DISPATCH BY ALGORITHM ID IS THE POINT, not a convenience. A TPM is handed a TPMI_ALG_HASH on
 * the wire and must answer for whichever one it advertised. Hard-coding SHA-256 and widening later
 * would mean rewriting every caller; the dispatch is cheap now and impossible to retrofit cleanly.
 *
 * ⚠ AN UNSUPPORTED ALGORITHM RETURNS FALSE. It does not fall back to SHA-256. A TPM that answers a
 * SHA-384 request with a SHA-256 digest has produced a value the caller will treat as SHA-384 --
 * which is worse than an error, because nothing downstream can detect it.
 *
 * Same dependency-free contract as Sha256.h / Sha512.h: no AllocatePool, no CopyMem, no DebugLib,
 * caller-supplied buffers only. The whole file compiles as a host program, which is how HMAC gets
 * checked against Python's `hmac` module before it is ever asked to authorise anything.
 *
 * ⚠ SHA-256 STILL LIVES IN NexusBootDxe/. It is load-bearing for the Secure Boot log sanitizer and
 * moving it would edit working SB-critical code for tidiness. Included across the directory
 * boundary instead, deliberately, and noted so the asymmetry reads as a decision rather than an
 * oversight.
 */

#pragma once

#include <Uefi.h>
#include "../NexusBootDxe/Sha256.h"
#include "Sha512.h"

//
// TPM_ALG_ID values, TPM 2.0 Library Part 2 Table 9. SHA-1 is deliberately absent: PTP does not
// require it of a new implementation, and adding a broken hash to a fresh TPM to support nothing
// would be a liability rather than a feature.
//
// (!) TPM2_ALG_SHA256 IS DEFINED HERE **UNGUARDED**, AND Tpm2Core.h ALSO DEFINES IT.
//
// That is deliberate. C permits an identical macro redefinition silently and makes a
// CONFLICTING one a hard error -- so leaving both unguarded means the compiler enforces that
// the two agree, in every translation unit that includes both. An #ifndef guard would do the
// opposite: it would hide a disagreement and let one header quietly win.
//
// The alternative -- including Tpm2Core.h from here -- would make the crypto layer depend on
// the TPM core, which is backwards: this file is what the core is built ON.
//
#define TPM2_ALG_SHA256             0x000B
#define TPM2_ALG_SHA384             0x000C
#define TPM2_ALG_SHA512             0x000D

#define TPM2_MAX_DIGEST_SIZE        64      // SHA-512
#define TPM2_MAX_BLOCK_SIZE         128     // SHA-384 / SHA-512 block

typedef struct _TPM2_HASH_CONTEXT {
	UINT16 Alg;                    // 0 = uninitialised; never assume, always check
	union {
		SHA256_CONTEXT S256;
		SHA512_CONTEXT S512;
	} U;
} TPM2_HASH_CONTEXT;

/**
 * Digest size in bytes for an algorithm, or 0 if we do not implement it.
 *
 * ⚠ 0 MEANS STOP. Callers sizing a buffer from this must treat 0 as a refusal, not as "use a
 * default" -- that is the difference between rejecting a command and overflowing a digest buffer.
 */
UINT16 Tpm2HashSize(IN UINT16 Alg);

/** Compression block size in bytes -- HMAC needs it, and it is NOT the digest size. */
UINT16 Tpm2HashBlockSize(IN UINT16 Alg);

BOOLEAN Tpm2HashInit(OUT TPM2_HASH_CONTEXT* Ctx, IN UINT16 Alg);
VOID    Tpm2HashUpdate(IN OUT TPM2_HASH_CONTEXT* Ctx, IN CONST VOID* Data, IN UINTN Length);

/** Writes Tpm2HashSize(Alg) bytes. FALSE if the context was never successfully initialised. */
BOOLEAN Tpm2HashFinal(IN OUT TPM2_HASH_CONTEXT* Ctx, OUT UINT8* Digest);

/** One-shot. FALSE (and nothing written) for an unsupported algorithm. */
BOOLEAN Tpm2Hash(IN UINT16 Alg, IN CONST VOID* Data, IN UINTN Length, OUT UINT8* Digest);

//
// ---------------------------------------------------------------------------------------------
// HMAC -- FIPS 198-1
// ---------------------------------------------------------------------------------------------
//

typedef struct _TPM2_HMAC_CONTEXT {
	UINT16            Alg;
	TPM2_HASH_CONTEXT Inner;
	UINT8             OuterKey[TPM2_MAX_BLOCK_SIZE];   // K0 ^ opad, kept for the outer pass
} TPM2_HMAC_CONTEXT;

/**
 * Begin an HMAC.
 *
 * ⚠ A KEY LONGER THAN THE BLOCK IS HASHED FIRST, per FIPS 198-1 §4 step 2 -- not truncated. The
 * two produce different MACs, and truncating is the more natural-looking mistake.
 *
 * ⚠ A KEY SHORTER THAN THE BLOCK IS ZERO-PADDED, not repeated. Also §4.
 */
BOOLEAN Tpm2HmacInit(OUT TPM2_HMAC_CONTEXT* Ctx, IN UINT16 Alg,
                     IN CONST UINT8* Key, IN UINTN KeyLen);
VOID    Tpm2HmacUpdate(IN OUT TPM2_HMAC_CONTEXT* Ctx, IN CONST VOID* Data, IN UINTN Length);
BOOLEAN Tpm2HmacFinal(IN OUT TPM2_HMAC_CONTEXT* Ctx, OUT UINT8* Mac);

BOOLEAN Tpm2Hmac(IN UINT16 Alg, IN CONST UINT8* Key, IN UINTN KeyLen,
                 IN CONST VOID* Data, IN UINTN Length, OUT UINT8* Mac);
