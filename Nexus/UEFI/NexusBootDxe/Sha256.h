/**
 * @file Sha256.h
 * @brief Self-contained SHA-256 (FIPS 180-4). No EDK2 library dependencies.
 *
 * WHY THIS EXISTS RATHER THAN BaseCryptLib:
 * Tier 3 of the Secure Boot spoof rewrites TCG log events and must recompute their SHA-256
 * digests, because the design notes is explicit that edited content with stale digests
 * (fidelity level B1) is WORSE than not spoofing at all -- a self-inconsistent log is a stronger
 * signal than an honest one.
 *
 * EDK2's usual answer is BaseCryptLib, which pulls OpensslLib. Those two were 54 MB of the 110 MB
 * of dead weight deleted from SDK/EDK2/Lib, and neither was ever linked. Dragging
 * them back for ONE hash function would undo that slim and add an enormous amount of code to a
 * boot-critical image. This file is roughly 3 KB of object code and has no dependencies at all.
 *
 * DELIBERATELY DEPENDENCY-FREE, and that is a testability decision as much as a size one: it uses
 * no AllocatePool, no CopyMem, no DebugLib, and operates only on caller-supplied buffers. That
 * means the exact same .c file compiles as a host program, so the implementation can be validated
 * against FIPS test vectors AND against real firmware-produced digests from the committed WBCL
 * baselines before it is ever asked to run during boot. A hash bug found at boot time is a bricked
 * machine; found on the host it is a failed assert.
 */

#pragma once

#include <Uefi.h>

#define SHA256_DIGEST_SIZE   32
#define SHA256_BLOCK_SIZE    64

typedef struct _SHA256_CONTEXT {
	UINT32 State[8];              // H0..H7
	UINT64 BitLength;             // total message length in BITS
	UINT8  Block[SHA256_BLOCK_SIZE];
	UINTN  BlockLength;           // bytes currently buffered in Block
} SHA256_CONTEXT;

VOID
Sha256Init(
	OUT SHA256_CONTEXT* Context
	);

VOID
Sha256Update(
	IN OUT SHA256_CONTEXT* Context,
	IN CONST VOID* Data,
	IN UINTN Length
	);

VOID
Sha256Final(
	IN OUT SHA256_CONTEXT* Context,
	OUT UINT8 Digest[SHA256_DIGEST_SIZE]
	);

//
// One-shot convenience wrapper. This is what the log sanitizer uses: every digest it recomputes
// is over a single contiguous buffer.
//
VOID
Sha256(
	IN CONST VOID* Data,
	IN UINTN Length,
	OUT UINT8 Digest[SHA256_DIGEST_SIZE]
	);
