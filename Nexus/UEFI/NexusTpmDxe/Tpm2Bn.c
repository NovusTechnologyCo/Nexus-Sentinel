/**
 * @file Tpm2Bn.c
 * @brief Big-integer arithmetic. See Tpm2Bn.h for why it is written rather than ported.
 *
 * ⚠ EVERY FUNCTION HERE IS TESTED AGAINST PYTHON'S ARBITRARY-PRECISION INTEGERS, on random
 * vectors and on the edges that hand-written tests miss -- zero, one, powers of two, values one
 * limb apart, operands aliased to the result. Python is a genuine independent oracle: it shares
 * no code, no author and no assumptions with this file. That is the only reason to trust a
 * from-scratch bignum, and it is why the tests were written alongside rather than afterwards.
 */

#include "Tpm2Bn.h"

//
// ------------------------------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------------------------------
//

/*
 * Re-establish the invariant: Used is the count of significant limbs, and Limb[Used-1] != 0.
 *
 * ⚠ CALLED AT THE END OF EVERY OPERATION THAT CAN PRODUCE LEADING ZEROS. Without it, a value can
 * compare unequal to itself -- 0x0001 with Used=2 and 0x0001 with Used=1 are the same number and
 * would differ on a limb-count comparison.
 */
STATIC
VOID
Trim(
	IN OUT TPM2_BN* A
	)
{
	while (A->Used > 0 && A->Limb[A->Used - 1] == 0)
		A->Used--;
}

VOID
Tpm2BnZero(
	OUT TPM2_BN* A
	)
{
	UINT32 i;

	if (A == NULL)
		return;
	for (i = 0; i < TPM2_BN_MAX_LIMBS; i++)
		A->Limb[i] = 0;
	A->Used = 0;
}

VOID
Tpm2BnCopy(
	OUT TPM2_BN*       D,
	IN  CONST TPM2_BN* S
	)
{
	UINT32 i;

	if (D == NULL || S == NULL)
		return;
	//
	// The whole array, not just Used limbs. Copying only the significant part would leave the
	// destination's old high limbs in place -- harmless while every reader respects Used, and a
	// silent corruption the first time one does not.
	//
	for (i = 0; i < TPM2_BN_MAX_LIMBS; i++)
		D->Limb[i] = S->Limb[i];
	D->Used = S->Used;
}

VOID
Tpm2BnSetWord(
	OUT TPM2_BN* A,
	IN  UINT32   V
	)
{
	Tpm2BnZero(A);
	if (A == NULL)
		return;
	if (V != 0)
	{
		A->Limb[0] = V;
		A->Used = 1;
	}
}

BOOLEAN
Tpm2BnFromBytes(
	OUT TPM2_BN*      A,
	IN  CONST UINT8*  B,
	IN  UINT32        Len
	)
{
	UINT32 i;

	if (A == NULL)
		return FALSE;
	Tpm2BnZero(A);
	if (Len == 0)
		return TRUE;
	if (B == NULL)
		return FALSE;

	//
	// Leading zeros do not count against the size limit: a 2048-bit value padded to 4096 bytes is
	// still a 2048-bit value, and TPM structures pad routinely.
	//
	while (Len > 0 && *B == 0)
	{
		B++;
		Len--;
	}
	if (Len == 0)
		return TRUE;
	if (Len > TPM2_BN_MAX_LIMBS * 4)
		return FALSE;

	for (i = 0; i < Len; i++)
	{
		UINT32 Byte = B[Len - 1 - i];
		A->Limb[i / 4] |= Byte << ((i % 4) * 8);
	}
	A->Used = (Len + 3) / 4;
	Trim(A);
	return TRUE;
}

BOOLEAN
Tpm2BnToBytes(
	IN  CONST TPM2_BN* A,
	OUT UINT8*         B,
	IN  UINT32         Len
	)
{
	UINT32 Need;
	UINT32 i;

	if (A == NULL || B == NULL)
		return FALSE;

	Need = (Tpm2BnBits(A) + 7) / 8;
	//
	// ⚠ REFUSE RATHER THAN TRUNCATE. A modulus short of its top byte is not a smaller modulus, it
	// is a different and wrong one, and it would be accepted by everything downstream.
	//
	if (Need > Len)
		return FALSE;

	for (i = 0; i < Len; i++)
		B[i] = 0;
	for (i = 0; i < Need; i++)
	{
		UINT32 Limb = A->Limb[i / 4];
		B[Len - 1 - i] = (UINT8)(Limb >> ((i % 4) * 8));
	}
	return TRUE;
}

BOOLEAN
Tpm2BnIsZero(
	IN CONST TPM2_BN* A
	)
{
	return (BOOLEAN)(A == NULL || A->Used == 0);
}

BOOLEAN
Tpm2BnIsOdd(
	IN CONST TPM2_BN* A
	)
{
	return (BOOLEAN)(A != NULL && A->Used > 0 && (A->Limb[0] & 1u) != 0);
}

UINT32
Tpm2BnBits(
	IN CONST TPM2_BN* A
	)
{
	UINT32 Top;
	UINT32 n;

	if (A == NULL || A->Used == 0)
		return 0;
	Top = A->Limb[A->Used - 1];
	n = 0;
	while (Top != 0)
	{
		Top >>= 1;
		n++;
	}
	return (A->Used - 1) * TPM2_BN_LIMB_BITS + n;
}

BOOLEAN
Tpm2BnTestBit(
	IN CONST TPM2_BN* A,
	IN UINT32         Bit
	)
{
	UINT32 Limb = Bit / TPM2_BN_LIMB_BITS;

	if (A == NULL || Limb >= A->Used)
		return FALSE;
	return (BOOLEAN)((A->Limb[Limb] >> (Bit % TPM2_BN_LIMB_BITS)) & 1u);
}

INT32
Tpm2BnCmp(
	IN CONST TPM2_BN* A,
	IN CONST TPM2_BN* B
	)
{
	UINT32 i;

	if (A->Used != B->Used)
		return (A->Used > B->Used) ? 1 : -1;
	//
	// Most significant first, and the loop counts DOWN through i+1 so it can reach index 0
	// without an unsigned counter wrapping below zero.
	//
	for (i = A->Used; i > 0; i--)
	{
		if (A->Limb[i - 1] != B->Limb[i - 1])
			return (A->Limb[i - 1] > B->Limb[i - 1]) ? 1 : -1;
	}
	return 0;
}

//
// ------------------------------------------------------------------------------------------
// Addition, subtraction, shifts
// ------------------------------------------------------------------------------------------
//

BOOLEAN
Tpm2BnAdd(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* B
	)
{
	UINT32 n;
	UINT32 i;
	UINT64 Carry = 0;
	TPM2_BN T;

	if (R == NULL || A == NULL || B == NULL)
		return FALSE;

	//
	// ⚠ ACCUMULATE INTO A TEMPORARY, NOT INTO R. Callers alias -- Tpm2BnAdd(&x, &x, &y) is
	// natural and correct-looking -- and writing R->Limb[i] while still reading A->Limb[i+1]
	// would corrupt the operand mid-loop.
	//
	Tpm2BnZero(&T);
	n = (A->Used > B->Used) ? A->Used : B->Used;
	for (i = 0; i < n; i++)
	{
		UINT64 Sum = Carry;
		Sum += (i < A->Used) ? A->Limb[i] : 0;
		Sum += (i < B->Used) ? B->Limb[i] : 0;
		T.Limb[i] = (UINT32)Sum;
		Carry = Sum >> 32;
	}
	if (Carry != 0)
	{
		if (n >= TPM2_BN_MAX_LIMBS)
		{
			Tpm2BnZero(R);
			return FALSE;
		}
		T.Limb[n] = (UINT32)Carry;
		n++;
	}
	T.Used = n;
	Trim(&T);
	Tpm2BnCopy(R, &T);
	return TRUE;
}

BOOLEAN
Tpm2BnSub(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* B
	)
{
	UINT32 i;
	UINT64 Borrow = 0;
	TPM2_BN T;

	if (R == NULL || A == NULL || B == NULL)
		return FALSE;
	//
	// This type has no sign. A caller that wanted a negative result has a bug, and returning a
	// wrapped positive value would hide it.
	//
	if (Tpm2BnCmp(A, B) < 0)
	{
		Tpm2BnZero(R);
		return FALSE;
	}

	Tpm2BnZero(&T);
	for (i = 0; i < A->Used; i++)
	{
		UINT64 Bv = (i < B->Used) ? B->Limb[i] : 0;
		UINT64 Diff = (UINT64)A->Limb[i] - Bv - Borrow;
		T.Limb[i] = (UINT32)Diff;
		Borrow = (Diff >> 63) & 1u;     /* the sign bit of the 64-bit two's-complement result */
	}
	T.Used = A->Used;
	Trim(&T);
	Tpm2BnCopy(R, &T);
	return TRUE;
}

BOOLEAN
Tpm2BnShiftLeft(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  UINT32         N
	)
{
	UINT32 Limbs = N / TPM2_BN_LIMB_BITS;
	UINT32 Bits  = N % TPM2_BN_LIMB_BITS;
	UINT32 i;
	TPM2_BN T;

	if (R == NULL || A == NULL)
		return FALSE;
	if (A->Used == 0)
	{
		Tpm2BnZero(R);
		return TRUE;
	}
	if (A->Used + Limbs + 1 > TPM2_BN_MAX_LIMBS)
	{
		Tpm2BnZero(R);
		return FALSE;
	}

	Tpm2BnZero(&T);
	for (i = A->Used; i > 0; i--)
	{
		UINT32 Src = A->Limb[i - 1];
		//
		// ⚠ A 32-BIT SHIFT BY 32 IS UNDEFINED IN C, so the carry-in half is guarded rather than
		// written as `Src >> (32 - Bits)`. This is the classic shift bug and it only shows up
		// when N happens to be a multiple of the limb width.
		//
		T.Limb[i - 1 + Limbs] |= (Bits != 0) ? (Src << Bits) : Src;
		if (Bits != 0)
			T.Limb[i + Limbs] |= (UINT32)(Src >> (TPM2_BN_LIMB_BITS - Bits));
	}
	T.Used = A->Used + Limbs + 1;
	Trim(&T);
	Tpm2BnCopy(R, &T);
	return TRUE;
}

VOID
Tpm2BnShiftRight(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  UINT32         N
	)
{
	UINT32 Limbs = N / TPM2_BN_LIMB_BITS;
	UINT32 Bits  = N % TPM2_BN_LIMB_BITS;
	UINT32 i;
	TPM2_BN T;

	if (R == NULL || A == NULL)
		return;
	Tpm2BnZero(&T);
	if (Limbs >= A->Used)
	{
		Tpm2BnCopy(R, &T);
		return;
	}

	for (i = 0; i + Limbs < A->Used; i++)
	{
		UINT32 Src = A->Limb[i + Limbs];
		UINT32 V = (Bits != 0) ? (Src >> Bits) : Src;
		if (Bits != 0 && i + Limbs + 1 < A->Used)
			V |= A->Limb[i + Limbs + 1] << (TPM2_BN_LIMB_BITS - Bits);
		T.Limb[i] = V;
	}
	T.Used = A->Used - Limbs;
	Trim(&T);
	Tpm2BnCopy(R, &T);
}

//
// ------------------------------------------------------------------------------------------
// Multiplication and division
// ------------------------------------------------------------------------------------------
//

BOOLEAN
Tpm2BnMul(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* B
	)
{
	UINT32 i;
	UINT32 j;
	TPM2_BN T;

	if (R == NULL || A == NULL || B == NULL)
		return FALSE;
	if (A->Used == 0 || B->Used == 0)
	{
		Tpm2BnZero(R);
		return TRUE;
	}
	if (A->Used + B->Used > TPM2_BN_MAX_LIMBS)
	{
		Tpm2BnZero(R);
		return FALSE;
	}

	Tpm2BnZero(&T);
	for (i = 0; i < A->Used; i++)
	{
		UINT64 Carry = 0;
		UINT64 Av = A->Limb[i];

		if (Av == 0)
			continue;
		for (j = 0; j < B->Used; j++)
		{
			//
			// The whole reason for 32-bit limbs: this product and both addends fit a UINT64 with
			// no overflow and no compiler intrinsic. (2^32-1)^2 + 2*(2^32-1) < 2^64.
			//
			UINT64 Acc = Av * (UINT64)B->Limb[j] + T.Limb[i + j] + Carry;
			T.Limb[i + j] = (UINT32)Acc;
			Carry = Acc >> 32;
		}
		T.Limb[i + B->Used] = (UINT32)Carry;
	}
	T.Used = A->Used + B->Used;
	Trim(&T);
	Tpm2BnCopy(R, &T);
	return TRUE;
}

BOOLEAN
Tpm2BnDivMod(
	OUT TPM2_BN*       Q,
	OUT TPM2_BN*       Rem,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* M
	)
{
	TPM2_BN Quo;
	TPM2_BN Cur;
	UINT32 Bits;
	UINT32 i;

	if (A == NULL || M == NULL || M->Used == 0)
		return FALSE;

	Tpm2BnZero(&Quo);
	Tpm2BnZero(&Cur);

	if (Tpm2BnCmp(A, M) < 0)
	{
		//
		// The common case in a modular reduction, and worth taking early: it avoids thousands of
		// iterations to conclude the quotient is zero.
		//
		if (Q != NULL)
			Tpm2BnCopy(Q, &Quo);
		if (Rem != NULL)
			Tpm2BnCopy(Rem, A);
		return TRUE;
	}

	//
	// Schoolbook binary long division: walk the dividend from the top bit down, shifting each bit
	// into a running remainder and subtracting the divisor when it fits.
	//
	Bits = Tpm2BnBits(A);
	for (i = Bits; i > 0; i--)
	{
		UINT32 Bit = i - 1;

		if (!Tpm2BnShiftLeft(&Cur, &Cur, 1))
			return FALSE;
		if (Tpm2BnTestBit(A, Bit))
		{
			if (Cur.Used == 0)
				Cur.Used = 1;
			Cur.Limb[0] |= 1u;
		}
		if (Tpm2BnCmp(&Cur, M) >= 0)
		{
			if (!Tpm2BnSub(&Cur, &Cur, M))
				return FALSE;
			Quo.Limb[Bit / TPM2_BN_LIMB_BITS] |= 1u << (Bit % TPM2_BN_LIMB_BITS);
			if (Quo.Used < Bit / TPM2_BN_LIMB_BITS + 1)
				Quo.Used = Bit / TPM2_BN_LIMB_BITS + 1;
		}
	}

	Trim(&Quo);
	Trim(&Cur);
	if (Q != NULL)
		Tpm2BnCopy(Q, &Quo);
	if (Rem != NULL)
		Tpm2BnCopy(Rem, &Cur);
	return TRUE;
}

UINT32
Tpm2BnModWord(
	IN CONST TPM2_BN* A,
	IN UINT32         M
	)
{
	UINT64 Rem = 0;
	UINT32 i;

	if (A == NULL || M == 0)
		return 0;
	//
	// Most significant limb first: Rem is always < M, so (Rem << 32) + limb fits a UINT64 for any
	// M that fits a UINT32.
	//
	for (i = A->Used; i > 0; i--)
		Rem = ((Rem << 32) | A->Limb[i - 1]) % M;
	return (UINT32)Rem;
}

//
// ------------------------------------------------------------------------------------------
// Montgomery modular exponentiation
// ------------------------------------------------------------------------------------------
//

/*
 * -M^-1 mod 2^32, by Newton iteration.
 *
 * Each step doubles the number of correct low bits: starting correct modulo 2, five steps reach
 * modulo 2^32. Requires M odd, which the caller has already checked.
 */
STATIC
UINT32
MontInvWord(
	IN UINT32 M0
	)
{
	UINT32 x = 1;
	UINT32 i;

	for (i = 0; i < 5; i++)
		x = x * (2u - M0 * x);
	return (UINT32)(0u - x);
}

/*
 * T = A * B * R^-1 mod M, where R = 2^(32*k) and k is the limb count of M.
 *
 * ⚠ THE CARRY OUT OF THE HIGH HALF IS PART OF THE VALUE. The intermediate can reach 2*M*R, which
 * needs one bit more than 2k limbs, so Acc[2k] is a real limb and dropping it -- the classic
 * Montgomery bug -- produces answers that are right most of the time.
 */
STATIC
BOOLEAN
MontMul(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* B,
	IN  CONST TPM2_BN* M,
	IN  UINT32         MInv
	)
{
	UINT32 k = M->Used;
	UINT32 Acc[2 * TPM2_BN_MAX_LIMBS + 1];
	UINT32 i;
	UINT32 j;
	TPM2_BN T;

	if (2 * k + 1 > (UINT32)(2 * TPM2_BN_MAX_LIMBS + 1))
		return FALSE;
	for (i = 0; i < 2 * k + 1; i++)
		Acc[i] = 0;

	for (i = 0; i < k; i++)
	{
		UINT64 Carry = 0;
		UINT64 Av = (i < A->Used) ? A->Limb[i] : 0;
		UINT32 m;

		/* Acc += A[i] * B */
		for (j = 0; j < k; j++)
		{
			UINT64 Bv = (j < B->Used) ? B->Limb[j] : 0;
			UINT64 Sum = Av * Bv + Acc[i + j] + Carry;
			Acc[i + j] = (UINT32)Sum;
			Carry = Sum >> 32;
		}
		for (j = i + k; Carry != 0 && j < 2 * k + 1; j++)
		{
			UINT64 Sum = Acc[j] + Carry;
			Acc[j] = (UINT32)Sum;
			Carry = Sum >> 32;
		}

		/* Acc += (Acc[i] * MInv mod 2^32) * M, which clears limb i */
		m = (UINT32)(Acc[i] * MInv);
		Carry = 0;
		for (j = 0; j < k; j++)
		{
			UINT64 Sum = (UINT64)m * M->Limb[j] + Acc[i + j] + Carry;
			Acc[i + j] = (UINT32)Sum;
			Carry = Sum >> 32;
		}
		for (j = i + k; Carry != 0 && j < 2 * k + 1; j++)
		{
			UINT64 Sum = Acc[j] + Carry;
			Acc[j] = (UINT32)Sum;
			Carry = Sum >> 32;
		}
	}

	/* The result is Acc >> 32k, which is < 2M, so at most one conditional subtraction. */
	Tpm2BnZero(&T);
	for (i = 0; i <= k; i++)
		T.Limb[i] = Acc[k + i];
	T.Used = k + 1;
	Trim(&T);

	if (Tpm2BnCmp(&T, M) >= 0)
	{
		if (!Tpm2BnSub(&T, &T, M))
			return FALSE;
	}
	Tpm2BnCopy(R, &T);
	return TRUE;
}

BOOLEAN
Tpm2BnModExp(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* E,
	IN  CONST TPM2_BN* M
	)
{
	TPM2_BN Base;
	TPM2_BN Acc;
	TPM2_BN RR;
	TPM2_BN Tmp;
	UINT32 MInv;
	UINT32 k;
	UINT32 Bits;
	UINT32 i;

	if (R == NULL || A == NULL || E == NULL || M == NULL)
		return FALSE;
	if (M->Used == 0)
		return FALSE;
	//
	// ⚠ ODD ONLY. Montgomery needs M invertible modulo 2^32. Refusing is correct rather than
	// limiting: every modulus this TPM exponentiates against is an RSA modulus or an odd prime
	// candidate.
	//
	if (!Tpm2BnIsOdd(M))
		return FALSE;

	/* x mod 1 is 0 for every x, and the Montgomery setup below would divide by a 1-limb R. */
	if (M->Used == 1 && M->Limb[0] == 1)
	{
		Tpm2BnZero(R);
		return TRUE;
	}

	k = M->Used;
	MInv = MontInvWord(M->Limb[0]);

	/*
	 * RR = R^2 mod M, computed as 2^(64k) mod M. This is the only division on the path, and it
	 * happens once per exponentiation rather than once per multiply -- which is the entire reason
	 * for using Montgomery form at all.
	 */
	Tpm2BnSetWord(&Tmp, 1);
	if (!Tpm2BnShiftLeft(&Tmp, &Tmp, 2 * k * TPM2_BN_LIMB_BITS))
		return FALSE;
	if (!Tpm2BnDivMod(NULL, &RR, &Tmp, M))
		return FALSE;

	/* Base = A * R mod M, via MontMul(A mod M, R^2). */
	if (!Tpm2BnDivMod(NULL, &Tmp, A, M))
		return FALSE;
	if (!MontMul(&Base, &Tmp, &RR, M, MInv))
		return FALSE;

	/* Acc = 1 * R mod M = R mod M, via MontMul(1, R^2). */
	Tpm2BnSetWord(&Tmp, 1);
	if (!MontMul(&Acc, &Tmp, &RR, M, MInv))
		return FALSE;

	Bits = Tpm2BnBits(E);
	for (i = Bits; i > 0; i--)
	{
		if (!MontMul(&Acc, &Acc, &Acc, M, MInv))
			return FALSE;
		if (Tpm2BnTestBit(E, i - 1))
		{
			if (!MontMul(&Acc, &Acc, &Base, M, MInv))
				return FALSE;
		}
	}

	/* Leave Montgomery form: MontMul(Acc, 1) = Acc * R^-1 mod M. */
	Tpm2BnSetWord(&Tmp, 1);
	if (!MontMul(R, &Acc, &Tmp, M, MInv))
		return FALSE;
	return TRUE;
}

//
// ------------------------------------------------------------------------------------------
// GCD and modular inverse
// ------------------------------------------------------------------------------------------
//

BOOLEAN
Tpm2BnGcd(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* B
	)
{
	TPM2_BN x;
	TPM2_BN y;
	TPM2_BN t;

	if (R == NULL || A == NULL || B == NULL)
		return FALSE;

	Tpm2BnCopy(&x, A);
	Tpm2BnCopy(&y, B);

	//
	// Euclid by remainder. Division is O(bits x limbs) here, but gcd runs once per candidate
	// during key generation rather than inside the exponentiation loop.
	//
	while (!Tpm2BnIsZero(&y))
	{
		if (!Tpm2BnDivMod(NULL, &t, &x, &y))
			return FALSE;
		Tpm2BnCopy(&x, &y);
		Tpm2BnCopy(&y, &t);
	}
	Tpm2BnCopy(R, &x);
	return TRUE;
}

BOOLEAN
Tpm2BnModInv(
	OUT TPM2_BN*       R,
	IN  CONST TPM2_BN* A,
	IN  CONST TPM2_BN* M
	)
{
	//
	// ⚠ SIX TEMPORARIES, NOT SEVEN, AND THE COUNT IS LOAD-BEARING. A TPM2_BN is 548 octets, so a
	// seventh put this frame over 4 KB and MSVC answered it with a `__chkstk` call -- a REAL IMPORT
	// in a payload that carries no import table, and the build gate rejected the driver. The same
	// thing has now happened three times in this tree (BpDispatch.h, Command.c, here), and the fix
	// is always the frame rather than the gate.
	//
	// It only appeared when TPM2_CreatePrimary gave this function its first caller: the linker had
	// been discarding the whole object until then.
	//
	// The seventh (`u`) was redundant. `q` is dead the moment its product is taken, so the product
	// goes there. Both Tpm2BnMul and Tpm2BnDivMod accumulate into their own locals and copy to the
	// output last, so output-aliases-input is safe in both -- checked by reading them, not assumed,
	// and the line below this already relied on it for DivMod.
	//
	TPM2_BN r0;
	TPM2_BN r1;
	TPM2_BN s0;
	TPM2_BN s1;
	TPM2_BN q;
	TPM2_BN t;

	if (R == NULL || A == NULL || M == NULL || M->Used == 0)
		return FALSE;

	//
	// Extended Euclid, kept entirely in non-negative values.
	//
	// ⚠ THE SIGN IS HANDLED BY WORKING MODULO M RATHER THAN BY A SIGN BIT. The textbook algorithm
	// alternates the sign of the cofactor; this type has no negatives, so each step computes
	// s = s0 - q*s1 as (s0 + M - (q*s1 mod M)) mod M. Every intermediate stays in [0, M).
	//
	if (!Tpm2BnDivMod(NULL, &r0, A, M))
		return FALSE;
	if (Tpm2BnIsZero(&r0))
		return FALSE;                       /* gcd(0, M) = M != 1 */

	Tpm2BnCopy(&r1, &r0);
	Tpm2BnCopy(&r0, M);
	Tpm2BnSetWord(&s0, 0);
	Tpm2BnSetWord(&s1, 1);

	while (!Tpm2BnIsZero(&r1))
	{
		if (!Tpm2BnDivMod(&q, &t, &r0, &r1))
			return FALSE;
		Tpm2BnCopy(&r0, &r1);
		Tpm2BnCopy(&r1, &t);

		/* q = (q * s1) mod M -- q's quotient value is dead here, so the product reuses it */
		if (!Tpm2BnMul(&q, &q, &s1))
			return FALSE;
		if (!Tpm2BnDivMod(NULL, &q, &q, M))
			return FALSE;

		/* t = (s0 - q) mod M, computed as (s0 + M - q) so nothing goes negative */
		if (!Tpm2BnAdd(&t, &s0, M))
			return FALSE;
		if (!Tpm2BnSub(&t, &t, &q))
			return FALSE;
		if (!Tpm2BnDivMod(NULL, &t, &t, M))
			return FALSE;

		Tpm2BnCopy(&s0, &s1);
		Tpm2BnCopy(&s1, &t);
	}

	//
	// r0 is now gcd(A, M). An inverse exists only when it is 1, and saying so is the answer that
	// rejects an RSA candidate rather than an error that aborts generation.
	//
	if (!(r0.Used == 1 && r0.Limb[0] == 1))
	{
		Tpm2BnZero(R);
		return FALSE;
	}
	Tpm2BnCopy(R, &s0);
	return TRUE;
}
