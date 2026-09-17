/**
 * @file Tpm2Prime.c
 * @brief Primality and RSA key generation. See Tpm2Prime.h for the gaps this does NOT close.
 *
 * ⚠ TESTED AGAINST THREE INDEPENDENT ORACLES, because a primality test that is wrong is wrong
 * silently -- it hands back a composite and everything downstream accepts it:
 *
 *   sympy.isprime      Baillie-PSW, a DIFFERENT ALGORITHM from Miller-Rabin, not just a different
 *                      implementation of the same one
 *   RFC 3526           published 1536- and 2048-bit MODP primes, IETF constants that owe nothing
 *                      to any code
 *   Carmichael numbers composites that pass the Fermat test for every base coprime to them. A
 *                      Fermat test mistaken for Miller-Rabin passes them; Miller-Rabin does not
 */

#include "Tpm2Prime.h"

//
// Every odd prime below 1024.
//
// ⚠ 2 IS ABSENT ON PURPOSE. Candidates are forced odd before the sieve runs, so testing 2 would
// be a wasted division on every candidate forever.
//
// The trade is lopsided in the sieve's favour: 171 single-word remainders cost almost nothing
// against the ~2 million limb operations of ONE Miller-Rabin round, and they reject about 84% of
// odd candidates before any of that starts.
//
STATIC CONST UINT32 mSmallPrimes[] = {
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
	101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
	197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
	311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
	431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
	557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
	661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
	809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
	937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021,
};

#define SMALL_PRIME_COUNT   (sizeof(mSmallPrimes) / sizeof(mSmallPrimes[0]))

BOOLEAN
Tpm2BnHasSmallFactor(
	IN CONST TPM2_BN* A
	)
{
	UINT32 i;

	if (A == NULL || A->Used == 0)
		return TRUE;                        /* zero: not prime, and not worth a special case */

	for (i = 0; i < SMALL_PRIME_COUNT; i++)
	{
		//
		// A small prime is not divisible by itself for this purpose -- the caller is asking
		// "does this have a factor SMALLER than itself", and 3 % 3 == 0 would say yes about 3.
		//
		if (A->Used == 1 && A->Limb[0] == mSmallPrimes[i])
			return FALSE;
		if (Tpm2BnModWord(A, mSmallPrimes[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

/*
 * One Miller-Rabin witness round.
 *
 * With N - 1 = 2^S * D and D odd, a prime N forces either A^D == 1, or A^(2^r * D) == N-1 for some
 * r in [0, S). Anything else is a proof of compositeness -- Miller-Rabin never says "composite"
 * about a prime, only "probably prime" about a composite.
 */
STATIC
BOOLEAN
MillerRabinRound(
	IN CONST TPM2_BN* N,
	IN CONST TPM2_BN* Nm1,
	IN CONST TPM2_BN* D,
	IN UINT32         S,
	IN CONST TPM2_BN* A
	)
{
	TPM2_BN X;
	UINT32 r;

	if (!Tpm2BnModExp(&X, A, D, N))
		return FALSE;

	if (Tpm2BnCmp(&X, Nm1) == 0)
		return TRUE;
	if (X.Used == 1 && X.Limb[0] == 1)
		return TRUE;

	for (r = 1; r < S; r++)
	{
		//
		// Squaring modulo N. ModExp with exponent 2 is the honest way to say this without a
		// separate squaring routine, and squaring is not on the hot path -- S is small.
		//
		TPM2_BN Two;
		Tpm2BnSetWord(&Two, 2);
		if (!Tpm2BnModExp(&X, &X, &Two, N))
			return FALSE;
		if (Tpm2BnCmp(&X, Nm1) == 0)
			return TRUE;
		//
		// ⚠ HITTING 1 BEFORE N-1 IS A PROOF OF COMPOSITENESS, not a reason to keep looking. It
		// means a non-trivial square root of 1 exists modulo N, which cannot happen for a prime.
		// Continuing the loop here is a classic bug that turns the test into Fermat's.
		//
		if (X.Used == 1 && X.Limb[0] == 1)
			return FALSE;
	}
	return FALSE;
}

BOOLEAN
Tpm2BnIsPrime(
	IN CONST TPM2_BN* A,
	IN UINT32         Rounds,
	IN TPM2_RAND_FN   Rand
	)
{
	TPM2_BN Nm1;
	TPM2_BN D;
	TPM2_BN Base;
	TPM2_BN One;
	UINT32 S = 0;
	UINT32 i;

	if (A == NULL || A->Used == 0)
		return FALSE;
	if (!Tpm2BnIsOdd(A))
		return (BOOLEAN)(A->Used == 1 && A->Limb[0] == 2);
	if (A->Used == 1 && A->Limb[0] < 4)
		return (BOOLEAN)(A->Limb[0] == 3);      /* 1 is not prime, 3 is */

	if (Tpm2BnHasSmallFactor(A))
	{
		//
		// The sieve says composite -- unless A IS one of the small primes, which
		// Tpm2BnHasSmallFactor already answers FALSE for. So this really is composite.
		//
		return FALSE;
	}
	//
	// A survivor that is itself small is prime: the sieve covers every prime below 1024, so
	// nothing under 1024^2 can survive with a factor left unfound.
	//
	if (A->Used == 1 && A->Limb[0] < 1024u * 1024u)
		return TRUE;

	Tpm2BnSetWord(&One, 1);
	if (!Tpm2BnSub(&Nm1, A, &One))
		return FALSE;

	//
	// N - 1 = 2^S * D, D odd.
	//
	Tpm2BnCopy(&D, &Nm1);
	while (!Tpm2BnIsOdd(&D) && !Tpm2BnIsZero(&D))
	{
		Tpm2BnShiftRight(&D, &D, 1);
		S++;
	}
	if (S == 0)
		return FALSE;                           /* N - 1 odd means N even; already handled */

	if (Rounds == 0)
		Rounds = TPM2_MR_ROUNDS_DEFAULT;

	for (i = 0; i < Rounds; i++)
	{
		if (Rand != NULL)
		{
			//
			// A random witness in [2, N-2]. Drawn as a full-width value and reduced, which
			// biases toward small values by a negligible amount and needs no rejection loop.
			//
			UINT8 Buf[TPM2_BN_MAX_LIMBS * 4];
			UINT32 Bytes = (Tpm2BnBits(A) + 7) / 8;

			if (Bytes > sizeof(Buf))
				return FALSE;
			if (!Rand(Buf, Bytes))
				return FALSE;
			if (!Tpm2BnFromBytes(&Base, Buf, Bytes))
				return FALSE;
			if (!Tpm2BnDivMod(NULL, &Base, &Base, &Nm1))
				return FALSE;
			if (Base.Used == 0 || (Base.Used == 1 && Base.Limb[0] == 1))
				Tpm2BnSetWord(&Base, 2);
		}
		else
		{
			//
			// ⚠ FIXED WITNESSES, AND THE HEADER SAYS WHAT THAT IS AND IS NOT GOOD FOR. The first
			// Rounds odd primes: deterministic, reproducible, sound for candidates we generated
			// ourselves, unsound for a value an adversary chose.
			//
			if (i >= SMALL_PRIME_COUNT)
				break;
			Tpm2BnSetWord(&Base, mSmallPrimes[i]);
		}

		if (Tpm2BnCmp(&Base, &Nm1) >= 0)
			continue;
		if (!MillerRabinRound(A, &Nm1, &D, S, &Base))
			return FALSE;
	}
	return TRUE;
}

BOOLEAN
Tpm2BnGeneratePrime(
	OUT TPM2_BN*       P,
	IN  UINT32         Bits,
	IN  CONST TPM2_BN* E,
	IN  TPM2_RAND_FN   Rand
	)
{
	UINT8 Buf[TPM2_BN_MAX_LIMBS * 4];
	UINT32 Bytes = (Bits + 7) / 8;
	UINT32 Attempt;
	TPM2_BN One;
	TPM2_BN Pm1;
	TPM2_BN G;

	if (P == NULL || Rand == NULL || Bits < 128 || Bytes > sizeof(Buf))
		return FALSE;

	Tpm2BnSetWord(&One, 1);

	//
	// The budget is generous rather than tight. Prime density near 2^1024 is about 1 in 710 odd
	// numbers, the sieve rejects ~84% of those cheaply, so a few thousand candidates is a very
	// comfortable margin -- and an unbounded loop in firmware is not something to ship.
	//
	for (Attempt = 0; Attempt < 100000u; Attempt++)
	{
		UINT32 i;

		if (!Rand(Buf, Bytes))
			return FALSE;

		//
		// ⚠ TOP TWO BITS SET, AND THE LOW BIT. The two high bits guarantee P >= 2^(Bits-1)*sqrt(2)
		// so that P*Q is exactly 2*Bits wide; the low bit makes it odd, which every later step
		// assumes.
		//
		Buf[0] |= 0xC0;
		Buf[Bytes - 1] |= 0x01;

		if (!Tpm2BnFromBytes(P, Buf, Bytes))
			return FALSE;

		//
		// Walk upward in steps of 2 rather than redrawing. Redrawing costs entropy and a fresh
		// sieve for no gain: consecutive odd candidates are just as good, and the walk is bounded
		// so it cannot drift into the next bit-length.
		//
		for (i = 0; i < 4096u; i++)
		{
			if (Tpm2BnBits(P) != Bits)
				break;                          /* walked out of range: redraw */

			if (!Tpm2BnHasSmallFactor(P) && Tpm2BnIsPrime(P, TPM2_MR_ROUNDS_DEFAULT, NULL))
			{
				//
				// gcd(P - 1, E) must be 1 or the private exponent does not exist.
				//
				if (E == NULL)
					return TRUE;
				if (!Tpm2BnSub(&Pm1, P, &One))
					return FALSE;
				if (!Tpm2BnGcd(&G, &Pm1, E))
					return FALSE;
				if (G.Used == 1 && G.Limb[0] == 1)
					return TRUE;
			}

			{
				TPM2_BN Two;
				Tpm2BnSetWord(&Two, 2);
				if (!Tpm2BnAdd(P, P, &Two))
					return FALSE;
			}
		}
	}
	return FALSE;
}

BOOLEAN
Tpm2RsaGenerateKey(
	OUT TPM2_RSA_KEY* Key,
	IN  UINT32        Bits,
	IN  UINT32        Exponent,
	IN  TPM2_RAND_FN  Rand
	)
{
	TPM2_BN One;
	TPM2_BN Pm1;
	TPM2_BN Qm1;
	TPM2_BN Diff;
	TPM2_BN Limit;
	TPM2_BN Gcd;
	TPM2_BN Lcm;
	UINT32 Half = Bits / 2;
	UINT32 Tries;

	if (Key == NULL || Rand == NULL || Bits < 256 || (Bits & 1))
		return FALSE;

	Tpm2BnSetWord(&One, 1);
	Tpm2BnSetWord(&Key->E, Exponent ? Exponent : 65537u);
	Key->Bits = Bits;

	//
	// |P - Q| must exceed 2^(Bits/2 - 100). Fermat factoring walks outward from sqrt(N) and finds
	// the factors in a handful of steps when they are close, so this is not a formality.
	//
	Tpm2BnSetWord(&Limit, 1);
	if (!Tpm2BnShiftLeft(&Limit, &Limit, Half - 100))
		return FALSE;

	if (!Tpm2BnGeneratePrime(&Key->P, Half, &Key->E, Rand))
		return FALSE;

	for (Tries = 0; Tries < 64u; Tries++)
	{
		if (!Tpm2BnGeneratePrime(&Key->Q, Half, &Key->E, Rand))
			return FALSE;

		if (Tpm2BnCmp(&Key->P, &Key->Q) == 0)
			continue;
		if (Tpm2BnCmp(&Key->P, &Key->Q) > 0)
		{
			if (!Tpm2BnSub(&Diff, &Key->P, &Key->Q))
				return FALSE;
		}
		else if (!Tpm2BnSub(&Diff, &Key->Q, &Key->P))
		{
			return FALSE;
		}
		if (Tpm2BnCmp(&Diff, &Limit) > 0)
			break;
	}
	if (Tries >= 64u)
		return FALSE;

	if (!Tpm2BnMul(&Key->N, &Key->P, &Key->Q))
		return FALSE;
	//
	// The two high bits in each prime should make this exact. Checked rather than assumed: a
	// modulus one bit short is an "RSA-2048" key that every verifier rejects, and it would be
	// found much later and blamed on something else.
	//
	if (Tpm2BnBits(&Key->N) != Bits)
		return FALSE;

	if (!Tpm2BnSub(&Pm1, &Key->P, &One))
		return FALSE;
	if (!Tpm2BnSub(&Qm1, &Key->Q, &One))
		return FALSE;

	//
	// D = E^-1 mod lcm(P-1, Q-1), and lcm(a,b) = a / gcd(a,b) * b -- divided FIRST so the
	// intermediate never exceeds the width of the product.
	//
	if (!Tpm2BnGcd(&Gcd, &Pm1, &Qm1))
		return FALSE;
	if (!Tpm2BnDivMod(&Lcm, NULL, &Pm1, &Gcd))
		return FALSE;
	if (!Tpm2BnMul(&Lcm, &Lcm, &Qm1))
		return FALSE;

	if (!Tpm2BnModInv(&Key->D, &Key->E, &Lcm))
		return FALSE;

	return TRUE;
}

BOOLEAN
Tpm2RsaPublic(
	OUT TPM2_BN*            R,
	IN  CONST TPM2_BN*      M,
	IN  CONST TPM2_RSA_KEY* Key
	)
{
	if (R == NULL || M == NULL || Key == NULL)
		return FALSE;
	return Tpm2BnModExp(R, M, &Key->E, &Key->N);
}

BOOLEAN
Tpm2RsaPrivate(
	OUT TPM2_BN*            R,
	IN  CONST TPM2_BN*      C,
	IN  CONST TPM2_RSA_KEY* Key
	)
{
	if (R == NULL || C == NULL || Key == NULL)
		return FALSE;
	return Tpm2BnModExp(R, C, &Key->D, &Key->N);
}
