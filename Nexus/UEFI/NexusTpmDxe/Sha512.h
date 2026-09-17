/**
 * @file Sha512.h
 * @brief Self-contained SHA-512 and SHA-384 (FIPS 180-4). No EDK2 library dependencies.
 *
 * WHY THIS EXISTS. `the design notes` §6.2 commits to a full per-spec TPM, and PTP's
 * mandatory algorithm profile requires SHA-384. We had SHA-256 and nothing else. Whichever way the
 * port-or-scratch decision goes, the hash primitives are ours to supply: the TCG reference
 * implementation takes hashing from its crypto backend, and we are the backend.
 *
 * ⚠ SAME DEPENDENCY-FREE CONTRACT AS Sha256.h, AND FOR THE SAME REASON. No AllocatePool, no
 * CopyMem, no DebugLib -- only caller-supplied buffers. That is what lets this exact .c file
 * compile as a host program and be checked against `hashlib` before it is ever asked to run during
 * boot. A hash bug found at boot is a bricked machine; found on the host it is a failed assert.
 *
 * ⚠ SHA-384 IS SHA-512 WITH A DIFFERENT IV AND A TRUNCATED OUTPUT. It is NOT a truncation of a
 * SHA-512 digest -- the initial state differs, so the whole computation differs. Sharing the
 * compression function is correct; sharing the IV would produce a wrong answer that still looks
 * like a hash.
 *
 * ⚠ MESSAGE LENGTH IS TRACKED IN 64 BITS, NOT 128. FIPS 180-4 gives SHA-512 a 128-bit length
 * field; the high half is written as zero here, which is exact for any message below 2^64 bits
 * (2 exabytes). Stated rather than hidden: a caller hashing more than that would get a wrong
 * digest, and no caller in this project can.
 */

#pragma once

#include <Uefi.h>

#define SHA512_DIGEST_SIZE   64
#define SHA384_DIGEST_SIZE   48
#define SHA512_BLOCK_SIZE    128

typedef struct _SHA512_CONTEXT {
	UINT64 State[8];              // H0..H7
	UINT64 BitLength;             // total message length in BITS (see the 64-bit note above)
	UINT8  Block[SHA512_BLOCK_SIZE];
	UINTN  BlockLength;           // bytes currently buffered in Block
} SHA512_CONTEXT;

/* SHA-512 */
VOID Sha512Init(OUT SHA512_CONTEXT* Context);
VOID Sha512Update(IN OUT SHA512_CONTEXT* Context, IN CONST VOID* Data, IN UINTN Length);
VOID Sha512Final(IN OUT SHA512_CONTEXT* Context, OUT UINT8 Digest[SHA512_DIGEST_SIZE]);
VOID Sha512(IN CONST VOID* Data, IN UINTN Length, OUT UINT8 Digest[SHA512_DIGEST_SIZE]);

/*
 * SHA-384. Different IV, same compression function, first 48 bytes of the final state.
 * Update() is shared -- the context is identical in shape and only the initial State differs.
 */
VOID Sha384Init(OUT SHA512_CONTEXT* Context);
VOID Sha384Final(IN OUT SHA512_CONTEXT* Context, OUT UINT8 Digest[SHA384_DIGEST_SIZE]);
VOID Sha384(IN CONST VOID* Data, IN UINTN Length, OUT UINT8 Digest[SHA384_DIGEST_SIZE]);
