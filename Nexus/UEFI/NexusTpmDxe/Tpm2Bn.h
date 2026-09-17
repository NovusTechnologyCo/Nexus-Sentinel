/**
 * @file Tpm2Bn.h
 * @brief Big-integer arithmetic, sized for RSA-2048.
 *
 * WHY THIS EXISTS AT ALL. The measured demand is `TPM2_CreatePrimary` with an RSA-2048 template,
 * twice per boot. Every other piece of that command -- session parsing, TPMT_PUBLIC, the object
 * Name, KDFa, the seeds -- is small and sits on primitives this project already has and already
 * tests against hashlib. The whole of the remaining difficulty is arithmetic on numbers far wider
 * than a register, and this file is that arithmetic.
 *
 * DECIDED, by the user: written rather than ported. "I would like to do as much of our
 * own code as possible over porting someone elses code." Recorded in the design notes.2,
 * which this file closes.
 *
 * ⚠ 32-BIT LIMBS WITH 64-BIT INTERMEDIATES, DELIBERATELY. A 64-bit limb needs the high half of a
 * 64x64 product, which means an intrinsic (`_umul128`) or a 128-bit type, and neither exists in
 * all three environments this code compiles for -- EDK2, the WDK, and the host harness. A 32-bit
 * limb multiplies into a plain UINT64 that every C compiler has. The cost is roughly a factor of
 * two in throughput, and the benefit is that ONE implementation is tested on the host and shipped
 * to the kernel.
 *
 * ⚠ NOTHING HERE ALLOCATES. Every value is a fixed-size struct, so the arithmetic is usable at
 * DISPATCH_LEVEL and inside a DXE with no allocator. The cost is 548 bytes per TPM2_BN, so the
 * number of live temporaries is counted rather than assumed -- see the note on ModExp.
 *
 * ⚠ THIS IS NOT CONSTANT TIME, AND IT MUST NOT BE USED AS IF IT WERE. Comparisons return early,
 * division branches on bits, and ModExp's square-and-multiply is data-dependent. That is
 * acceptable for what this TPM does -- generating primary keys from a seed we control, on a
 * machine the attacker already owns -- and would NOT be acceptable for, say, signing with a key
 * an attacker can ask about repeatedly. When a signing path lands, it needs a constant-time
 * ladder and this comment needs revisiting.
 */

#pragma once

#include "Tpm2Core.h"

//
// 4352 bits. RSA-2048 needs 1024-bit primes, a 2048-bit modulus, and 4096-bit products; the
// remaining 256 bits are headroom so an intermediate cannot silently overflow a temporary.
//
#define TPM2_BN_LIMB_BITS   32
#define TPM2_BN_MAX_BITS    4352
#define TPM2_BN_MAX_LIMBS   (TPM2_BN_MAX_BITS / TPM2_BN_LIMB_BITS)   /* 136 */

/**
 * A non-negative integer.
 *
 * ⚠ `Used` IS THE INVARIANT EVERY OPERATION MAINTAINS: the number of significant limbs, with
 * Limb[Used-1] non-zero, and Used == 0 meaning the value is exactly zero. Limbs at or above Used
 * are not read and are not guaranteed to be zero. Code that walks Limb[] directly rather than
 * through these functions is the way that invariant gets broken.
 */
typedef struct _TPM2_BN {
	UINT32 Used;
	UINT32 Limb[TPM2_BN_MAX_LIMBS];       /* little-endian: Limb[0] is least significant */
} TPM2_BN;

//
// ------------------------------------------------------------------------------------------
// Construction and inspection
// ------------------------------------------------------------------------------------------
//

VOID    Tpm2BnZero(OUT TPM2_BN* A);
VOID    Tpm2BnCopy(OUT TPM2_BN* D, IN CONST TPM2_BN* S);
VOID    Tpm2BnSetWord(OUT TPM2_BN* A, IN UINT32 V);

/**
 * Load a big-endian byte string, the way every TPM structure carries an integer.
 *
 * @return FALSE if the value does not fit, in which case A is left zero rather than truncated.
 */
BOOLEAN Tpm2BnFromBytes(OUT TPM2_BN* A, IN CONST UINT8* B, IN UINT32 Len);

/**
 * Store big-endian into exactly Len bytes, zero-padded on the left.
 *
 * @return FALSE if the value needs more than Len bytes. Nothing is written in that case: a
 *         truncated modulus is a wrong key, not a smaller one.
 */
BOOLEAN Tpm2BnToBytes(IN CONST TPM2_BN* A, OUT UINT8* B, IN UINT32 Len);

BOOLEAN Tpm2BnIsZero(IN CONST TPM2_BN* A);
BOOLEAN Tpm2BnIsOdd(IN CONST TPM2_BN* A);
UINT32  Tpm2BnBits(IN CONST TPM2_BN* A);                       /* 0 for zero */
BOOLEAN Tpm2BnTestBit(IN CONST TPM2_BN* A, IN UINT32 Bit);

/** @return -1 if A < B, 0 if equal, 1 if A > B. */
INT32   Tpm2BnCmp(IN CONST TPM2_BN* A, IN CONST TPM2_BN* B);

//
// ------------------------------------------------------------------------------------------
// Arithmetic. Every one of these returns FALSE on overflow rather than wrapping, and leaves the
// result zero. A silently wrapped modulus is a wrong key that looks like a key.
// ------------------------------------------------------------------------------------------
//

BOOLEAN Tpm2BnAdd(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* B);

/** R = A - B. @return FALSE if B > A: this type has no negative values. */
BOOLEAN Tpm2BnSub(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* B);

BOOLEAN Tpm2BnMul(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* B);
BOOLEAN Tpm2BnShiftLeft(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN UINT32 N);
VOID    Tpm2BnShiftRight(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN UINT32 N);

/**
 * Q = A / M, Rem = A mod M. Either output may be NULL.
 *
 * ⚠ BINARY LONG DIVISION, NOT KNUTH ALGORITHM D, AND THAT IS A CHOICE. Algorithm D is O(limbs^2)
 * where this is O(bits x limbs) -- roughly thirty times slower on a 2048-bit modulus. It is used
 * here anyway because division is NOT on the hot path: ModExp reduces with Montgomery
 * multiplication and calls this only twice during setup. Paying thirty times almost nothing to
 * avoid the subtle quotient-estimate correction step in Algorithm D is the right trade, and if a
 * future path makes division hot this is the function to replace.
 *
 * @return FALSE if M is zero.
 */
BOOLEAN Tpm2BnDivMod(OUT TPM2_BN* Q, OUT TPM2_BN* Rem, IN CONST TPM2_BN* A, IN CONST TPM2_BN* M);

/** A mod m for a single-word m. Used by the small-prime sieve, where it is the hot path. */
UINT32  Tpm2BnModWord(IN CONST TPM2_BN* A, IN UINT32 M);

/**
 * R = A^E mod M, by Montgomery multiplication.
 *
 * ⚠ M MUST BE ODD. Montgomery reduction needs the inverse of M modulo 2^32, which exists only for
 * odd M. FALSE is returned for even M rather than a wrong answer. Every modulus this TPM
 * exponentiates against -- an RSA modulus, or a prime under Miller-Rabin -- is odd.
 *
 * ⚠ STACK: this holds five TPM2_BN temporaries, about 2.7 KB. That is comfortable at
 * PASSIVE_LEVEL and inside a DXE, and it is why key generation does NOT run in the servicer's
 * DPC -- which has a smaller budget and a 200 ms deadline it would blow by orders of magnitude.
 */
BOOLEAN Tpm2BnModExp(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* E, IN CONST TPM2_BN* M);

BOOLEAN Tpm2BnGcd(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* B);

/**
 * R = A^-1 mod M.
 *
 * @return FALSE when the inverse does not exist, i.e. gcd(A, M) != 1. That is not an error
 *         condition during key generation -- it is the answer that rejects a candidate.
 */
BOOLEAN Tpm2BnModInv(OUT TPM2_BN* R, IN CONST TPM2_BN* A, IN CONST TPM2_BN* M);
