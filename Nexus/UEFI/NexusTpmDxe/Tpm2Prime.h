/**
 * @file Tpm2Prime.h
 * @brief Primality testing and RSA key generation, on Tpm2Bn.
 *
 * WHY IT IS NEEDED. The measured demand is `TPM2_CreatePrimary` with an RSA-2048 template, sent
 * twice per boot by Windows -- once on TPM_RH_OWNER for the SRK and once on TPM_RH_ENDORSEMENT
 * for the EK. Both templates were captured byte-exact from this machine and are recorded in
 * the design notes; both ask for RSA 2048 with the default exponent.
 *
 * ⚠ A PRIMARY KEY MUST BE A DETERMINISTIC FUNCTION OF (SEED, TEMPLATE), AND THIS FILE DOES NOT
 * PROVIDE THAT YET. Part 1 requires that re-deriving a primary key from the same seed and template
 * gives the same key, which is what makes an SRK survive a reboot. Here the candidate primes come
 * from an injected random source, so two calls give two different keys.
 *
 * That is a real gap and it has an observable consequence we are already watching: Windows logs
 * event 519, "The TPM has been cleared. Reason: SRK has changed". Closing it needs a DRBG keyed by
 * the primary seed -- KDFa over HMAC, which is written and tested -- and that is the next piece,
 * not this one. Stated here rather than discovered later.
 *
 * ⚠ NOT CONSTANT TIME. Inherited from Tpm2Bn and true of everything here as well: the sieve
 * branches on divisibility, Miller-Rabin branches on the witness result, and generation loops
 * until it finds a prime. Acceptable for deriving keys from a seed we control on a machine the
 * attacker already owns; NOT acceptable for anything an attacker can time repeatedly.
 */

#pragma once

#include "Tpm2Bn.h"

/**
 * A source of random bytes.
 *
 * ⚠ DECLARED HERE RATHER THAN TAKEN FROM Tpm2Dispatch.h, DELIBERATELY. This layer sits below the
 * dispatcher and must not include it -- the dependency would run the wrong way and would drag the
 * command set into a file that only does arithmetic. The shape is identical to TPM2_ENTROPY_FN by
 * design, so one function satisfies both.
 */
typedef BOOLEAN (*TPM2_RAND_FN)(OUT UINT8* Out, IN UINT32 Bytes);

/**
 * An RSA key pair, private included.
 *
 * ⚠ 2.7 KB. Too large for the stack in a DPC and too large to pass by value. Callers allocate it
 * and pass a pointer; key generation runs at PASSIVE_LEVEL where the budget exists.
 */
typedef struct _TPM2_RSA_KEY {
	TPM2_BN N;          /* modulus, Bits wide          */
	TPM2_BN E;          /* public exponent             */
	TPM2_BN D;          /* private exponent            */
	TPM2_BN P;          /* first prime                 */
	TPM2_BN Q;          /* second prime                */
	UINT32  Bits;       /* modulus size, e.g. 2048     */
} TPM2_RSA_KEY;

//
// FIPS 186-4 B.3.1: for a 2048-bit modulus the probabilistic test needs at least 4 Miller-Rabin
// rounds when e >= 2^16. More is cheap here because generation is not on any hot path, and the
// cost of a wrong answer is a key that silently fails to work.
//
#define TPM2_MR_ROUNDS_DEFAULT      10

/**
 * Trial division by every odd prime below 1024.
 *
 * @return TRUE if a small factor was found, i.e. the value is definitely COMPOSITE. FALSE means
 *         only that no small factor exists, which is not primality.
 */
BOOLEAN Tpm2BnHasSmallFactor(IN CONST TPM2_BN* A);

/**
 * Miller-Rabin, with the sieve applied first.
 *
 * ⚠ PROBABILISTIC, AND FIXED-BASE WHEN NO RANDOM SOURCE IS GIVEN. With `Rand` NULL the witnesses
 * are the first `Rounds` odd primes, which makes the result deterministic and reproducible -- what
 * a test suite needs. That choice is sound for candidates WE generated at random and is NOT sound
 * for a value an adversary chose, because composites can be built to pass any fixed base set.
 * Callers validating externally supplied numbers must pass a real source.
 *
 * @return TRUE if the value is probably prime.
 */
BOOLEAN Tpm2BnIsPrime(IN CONST TPM2_BN* A, IN UINT32 Rounds, IN TPM2_RAND_FN Rand);

/**
 * A random prime of exactly `Bits` bits with gcd(P - 1, E) = 1.
 *
 * ⚠ THE TOP TWO BITS ARE SET, WHICH IS NOT COSMETIC. With both set, P and Q are each at least
 * 2^(Bits-1) * sqrt(2), so their product is guaranteed to be exactly 2*Bits bits. Setting only the
 * top bit lets P*Q come out one bit short, and a 2047-bit "RSA-2048" modulus is rejected by
 * everything downstream.
 *
 * ⚠ gcd(P - 1, E) = 1 IS REQUIRED, NOT PREFERRED. Without it the private exponent does not exist
 * and the key is unusable, which is discovered much later and looks like something else.
 *
 * @return FALSE if no prime was found within the attempt budget, or on any arithmetic failure.
 */
BOOLEAN Tpm2BnGeneratePrime(OUT TPM2_BN* P, IN UINT32 Bits, IN CONST TPM2_BN* E,
                            IN TPM2_RAND_FN Rand);

/**
 * An RSA key pair with a `Bits`-bit modulus.
 *
 * ⚠ P AND Q ARE FORCED APART. FIPS 186-4 requires |P - Q| > 2^(Bits/2 - 100); primes that are too
 * close make the modulus trivially factorable by Fermat's method, which needs only a few
 * iterations when they are near sqrt(N). A pair that fails the check is discarded rather than
 * adjusted.
 *
 * ⚠ D IS COMPUTED MODULO lcm(P-1, Q-1), NOT (P-1)(Q-1). Both satisfy the RSA identity; lcm gives
 * the smaller exponent and is what Part 1 and every modern implementation use. A verifier that
 * recomputes D will get the lcm form.
 *
 * @param Exponent  the public exponent, e.g. 65537. Zero means the default 65537, which is how
 *                  the TPM templates on this machine encode it.
 */
BOOLEAN Tpm2RsaGenerateKey(OUT TPM2_RSA_KEY* Key, IN UINT32 Bits, IN UINT32 Exponent,
                           IN TPM2_RAND_FN Rand);

/**
 * R = M^E mod N, the public operation. Present so a caller can round-trip a generated key without
 * reaching into the struct.
 */
BOOLEAN Tpm2RsaPublic(OUT TPM2_BN* R, IN CONST TPM2_BN* M, IN CONST TPM2_RSA_KEY* Key);

/**
 * R = C^D mod N, the private operation.
 *
 * ⚠ PLAIN EXPONENTIATION, NOT CRT. The Chinese Remainder form is roughly four times faster and is
 * what a production TPM uses, but it is also where fault attacks land: a single corrupted half
 * leaks the factorisation. Plain modexp first, correct and simple; CRT is an optimisation to make
 * deliberately, with the fault check that has to come with it.
 */
BOOLEAN Tpm2RsaPrivate(OUT TPM2_BN* R, IN CONST TPM2_BN* C, IN CONST TPM2_RSA_KEY* Key);
