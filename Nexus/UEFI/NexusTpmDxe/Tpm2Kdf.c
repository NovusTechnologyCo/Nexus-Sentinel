/**
 * @file Tpm2Kdf.c
 * @brief KDFa and the deterministic stream built on it. See Tpm2Kdf.h for why they exist.
 *
 * ⚠ TESTED TWO WAYS, BECAUSE ONE OF THEM SHARES MY READING OF THE SPECIFICATION.
 *
 *   The single-block case reduces to ONE HMAC, and Python's `hmac` module computes it. That half
 *   is genuinely independent: Python's HMAC is not ours and was not written from this text.
 *
 *   The multi-block framing -- counter placement, the zero octet, truncation direction, MSO
 *   masking -- is checked against a Python KDFa written separately from the same Part 1 clause.
 *   That is a second IMPLEMENTATION, not a second SOURCE, and if I misread the clause both agree
 *   and both are wrong. Said plainly rather than left to look stronger than it is.
 */

#include "Tpm2Kdf.h"

STATIC
VOID
WriteBe32(
	OUT UINT8* P,
	IN  UINT32 V
	)
{
	P[0] = (UINT8)(V >> 24);
	P[1] = (UINT8)(V >> 16);
	P[2] = (UINT8)(V >> 8);
	P[3] = (UINT8)(V);
}

STATIC
UINT32
LabelLen(
	IN CONST CHAR8* Label
	)
{
	UINT32 n = 0;

	if (Label == NULL)
		return 0;
	while (Label[n] != '\0')
		n++;
	return n;
}

BOOLEAN
Tpm2KdfA(
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
	)
{
	UINT16 DigestLen = Tpm2HashSize(HashAlg);
	UINT32 Need = (Bits + 7) / 8;
	UINT32 Done = 0;
	UINT32 Counter = 0;
	UINT32 i;
	UINT8  Be[4];
	UINT8  Zero = 0;
	UINT8  Digest[TPM2_MAX_DIGEST_SIZE];

	if (Out == NULL || DigestLen == 0 || Bits == 0)
		return FALSE;
	if (Need > TPM2_KDF_MAX_BYTES)
		return FALSE;

	while (Done < Need)
	{
		TPM2_HMAC_CONTEXT Ctx;
		UINT32 Take;

		//
		// ⚠ THE COUNTER STARTS AT 1, NOT 0. Part 1 Equation 6: "[i]2 is a 32-bit counter that
		// starts at 1 and increments on each iteration." Starting at zero produces a stream that
		// looks perfectly random and matches nothing.
		//
		Counter++;

		if (!Tpm2HmacInit(&Ctx, HashAlg, Key, KeyLen))
			return FALSE;

		WriteBe32(Be, Counter);
		Tpm2HmacUpdate(&Ctx, Be, 4);

		//
		// Label, then the separating zero octet. Part 1: "If Label is not present, a zero octet
		// is added. If Label is present and the last octet is not zero, a zero octet is added."
		// Hashing the C terminator satisfies both halves of that rule at once.
		//
		if (Label != NULL)
			Tpm2HmacUpdate(&Ctx, Label, LabelLen(Label));
		Tpm2HmacUpdate(&Ctx, &Zero, 1);

		//
		// Context is contextU || contextV, Part 1 Equation 8 -- one field, delivered in two
		// pieces, with nothing between them.
		//
		if (ContextU != NULL && ContextULen != 0)
			Tpm2HmacUpdate(&Ctx, ContextU, ContextULen);
		if (ContextV != NULL && ContextVLen != 0)
			Tpm2HmacUpdate(&Ctx, ContextV, ContextVLen);

		WriteBe32(Be, Bits);
		Tpm2HmacUpdate(&Ctx, Be, 4);

		if (!Tpm2HmacFinal(&Ctx, Digest))
			return FALSE;

		//
		// ⚠ TRUNCATION DISCARDS THE MOST RECENTLY PRODUCED BITS, which falls out of filling
		// forward and stopping: the LAST block is the one clipped. Keeping the tail instead
		// would be a different function that is just as self-consistent.
		//
		Take = DigestLen;
		if (Take > Need - Done)
			Take = Need - Done;
		for (i = 0; i < Take; i++)
			Out[Done + i] = Digest[i];
		Done += Take;
	}

	//
	// ⚠ MASK THE MOST SIGNIFICANT OCTET, DO NOT SHIFT. Part 1 §8.4.10.2, with its own worked
	// example: a 521-bit value occupies 66 octets with the top 7 bits of octet zero CLEAR.
	//
	// The shifted version was written here deliberately and SURVIVED the whole suite, because the
	// only test was the spec's own 521-bit example -- where the MSO keeps a single bit, so masking
	// and shifting agree whenever that octet's top and bottom bits match. They did. The 517-bit
	// case in the test harness exists solely to keep five bits alive, where the two cannot
	// coincide, and it kills the injury on sight.
	//
	if ((Bits & 7u) != 0)
		Out[0] &= (UINT8)((1u << (Bits & 7u)) - 1u);

	return TRUE;
}

BOOLEAN
Tpm2KdfStreamInit(
	OUT TPM2_KDF_STREAM* S,
	IN  UINT16           HashAlg,
	IN  CONST UINT8*     Seed,
	IN  UINT32           SeedLen,
	IN  CONST CHAR8*     Label,
	IN  CONST UINT8*     Context,
	IN  UINT32           ContextLen
	)
{
	UINT32 i;

	if (S == NULL || Seed == NULL || Tpm2HashSize(HashAlg) == 0)
		return FALSE;
	if (SeedLen == 0 || SeedLen > sizeof(S->Seed))
		return FALSE;
	if (ContextLen > sizeof(S->Context))
		return FALSE;

	for (i = 0; i < sizeof(S->Seed); i++)
		S->Seed[i] = (i < SeedLen) ? Seed[i] : 0;
	for (i = 0; i < sizeof(S->Context); i++)
		S->Context[i] = (i < ContextLen && Context != NULL) ? Context[i] : 0;

	S->HashAlg    = HashAlg;
	S->SeedLen    = SeedLen;
	S->Label      = Label;
	S->ContextLen = ContextLen;
	S->Counter    = 0;
	S->BlockLen   = 0;
	S->BlockUsed  = 0;
	return TRUE;
}

BOOLEAN
Tpm2KdfStreamBytes(
	IN OUT TPM2_KDF_STREAM* S,
	OUT    UINT8*           Out,
	IN     UINT32           Bytes
	)
{
	UINT32 Done = 0;

	if (S == NULL || Out == NULL)
		return FALSE;

	while (Done < Bytes)
	{
		if (S->BlockUsed >= S->BlockLen)
		{
			//
			// Refill. The block index goes into contextV, so each block is a distinct KDFa call
			// rather than a longer one -- which keeps the stream position explicit and lets a
			// caller of any size be served without a maximum.
			//
			UINT8 Idx[4];
			UINT16 DigestLen = Tpm2HashSize(S->HashAlg);

			S->Counter++;
			WriteBe32(Idx, S->Counter);

			if (!Tpm2KdfA(S->HashAlg, S->Seed, S->SeedLen, S->Label,
			              S->Context, S->ContextLen, Idx, 4,
			              (UINT32)DigestLen * 8u, S->Block))
				return FALSE;

			S->BlockLen  = DigestLen;
			S->BlockUsed = 0;
		}

		Out[Done++] = S->Block[S->BlockUsed++];
	}
	return TRUE;
}
