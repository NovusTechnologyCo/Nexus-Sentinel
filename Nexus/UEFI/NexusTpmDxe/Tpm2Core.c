/**
 * @file Tpm2Core.c
 * @brief TPM 2.0 core -- wire format and the PCR bank. Read Tpm2Core.h first; the reasoning and
 *        every spec citation live there.
 *
 * ⚠ DEPENDENCY-FREE. No AllocatePool, no CopyMem, no DebugLib, no EDK2 library calls at all --
 * only caller-supplied buffers. That is what lets this exact file compile as a host program and be
 * checked against an independent oracle before it runs during boot. Do not "tidy" a CopyMem in.
 */

#include "Tpm2Core.h"

//
// ---------------------------------------------------------------------------------------------
// BIG-ENDIAN ACCESSORS
//
// Written byte-wise rather than with a cast-and-swap. Two reasons, and the second is the one that
// matters: a wire buffer has NO ALIGNMENT GUARANTEE, and on some targets an unaligned UINT32 load
// faults rather than merely being slow. Byte-wise is correct everywhere and the compiler collapses
// it to a movbe or bswap anyway.
// ---------------------------------------------------------------------------------------------
//

UINT16
Tpm2ReadBe16(
	IN CONST UINT8* P
	)
{
	return (UINT16)(((UINT16)P[0] << 8) | (UINT16)P[1]);
}

UINT32
Tpm2ReadBe32(
	IN CONST UINT8* P
	)
{
	return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) |
	       ((UINT32)P[2] <<  8) | ((UINT32)P[3]);
}

VOID
Tpm2WriteBe16(
	OUT UINT8*  P,
	IN  UINT16  V
	)
{
	P[0] = (UINT8)(V >> 8);
	P[1] = (UINT8)(V);
}

VOID
Tpm2WriteBe32(
	OUT UINT8*  P,
	IN  UINT32  V
	)
{
	P[0] = (UINT8)(V >> 24);
	P[1] = (UINT8)(V >> 16);
	P[2] = (UINT8)(V >>  8);
	P[3] = (UINT8)(V);
}

VOID
Tpm2WriteBe64(
	OUT UINT8*  P,
	IN  UINT64  V
	)
{
	//
	// TPM 2.0 has plenty of 64-bit wire fields -- Clock, Time, NV counters -- and every one of
	// them is big-endian like the rest. Written out rather than looped so it reads the same way
	// as its 16- and 32-bit neighbours.
	//
	P[0] = (UINT8)(V >> 56);
	P[1] = (UINT8)(V >> 48);
	P[2] = (UINT8)(V >> 40);
	P[3] = (UINT8)(V >> 32);
	P[4] = (UINT8)(V >> 24);
	P[5] = (UINT8)(V >> 16);
	P[6] = (UINT8)(V >>  8);
	P[7] = (UINT8)(V);
}

//
// ---------------------------------------------------------------------------------------------
// THE PCR BANK
// ---------------------------------------------------------------------------------------------
//

VOID
Tpm2PcrStartupClear(
	OUT TPM2_PCR_BANK* Bank,
	IN  UINT8          LocalityIndicator
	)
{
	UINT32 i;
	UINT32 j;

	if (Bank == NULL)
		return;

	for (i = 0; i < TPM2_PCR_COUNT; i++)
	{
		//
		// PTP 1.07 Table 15, "PCR Initial and Reset Values", TPM2_Startup(CLEAR) with no S-HCRTM
		// sequence:
		//
		//     PCR 0      Locality Indicator
		//     PCR 1-15   0
		//     PCR 16     0
		//     PCR 17     -1
		//     PCR 18-19  -1
		//     PCR 20-22  -1
		//     PCR 23     0
		//
		// where -1 is "the same size, in bytes, of the digest for the supported Hash Algorithm ID
		// with all bits set to the value of 1".
		//
		UINT8 Fill = 0x00;

		if (i >= 17 && i <= 22)
			Fill = 0xFF;

		for (j = 0; j < TPM2_SHA256_DIGEST_SIZE; j++)
			Bank->Pcr[i][j] = Fill;

		//
		// ⚠ PCR[0] IS THE LOCALITY INDICATOR, NOT ZERO. It is written into the LAST byte of the
		// digest-sized field, which is where a big-endian integer of that width puts a small value.
		//
		// For locality 0 this produces an all-zero PCR[0] -- identical to the wrong answer. That is
		// precisely why it is spelled out: the rule is encoded because it is the rule, not because
		// this configuration can currently tell the difference. A locality-0-only implementation
		// that later gains localities would otherwise carry a silent bug from here.
		//
		if (i == 0)
			Bank->Pcr[0][TPM2_SHA256_DIGEST_SIZE - 1] = LocalityIndicator;
	}

	Bank->UpdateCounter = 0;
	Bank->Started       = TRUE;
}

UINT32
Tpm2PcrExtend(
	IN OUT TPM2_PCR_BANK* Bank,
	IN     UINT32         PcrIndex,
	IN     CONST UINT8    Digest[TPM2_SHA256_DIGEST_SIZE]
	)
{
	SHA256_CONTEXT Ctx;
	UINT8          New[TPM2_SHA256_DIGEST_SIZE];
	UINT32         i;

	if (Bank == NULL || Digest == NULL)
		return TPM2_RC_VALUE;

	//
	// Refuse rather than quietly extending a bank that was never initialised. Part 3: until
	// TPM2_Startup has run the TPM accepts nothing else, and answering TPM_RC_INITIALIZE is what a
	// real TPM does. Zeroed PCRs that look plausible would be worse than an error.
	//
	if (!Bank->Started)
		return TPM2_RC_INITIALIZE;

	if (PcrIndex >= TPM2_PCR_COUNT)
		return TPM2_RC_VALUE;

	//
	// Part 1, equation (14):  PCR_new = H(PCR_old || digest)
	//
	// The concatenation order is load-bearing and is the easiest thing in this file to get
	// backwards. Old value first, then the incoming digest.
	//
	Sha256Init(&Ctx);
	Sha256Update(&Ctx, Bank->Pcr[PcrIndex], TPM2_SHA256_DIGEST_SIZE);
	Sha256Update(&Ctx, Digest, TPM2_SHA256_DIGEST_SIZE);
	Sha256Final(&Ctx, New);

	for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
		Bank->Pcr[PcrIndex][i] = New[i];

	//
	// Part 1 §17: the update counter increments on TPM2_PCR_Extend. A reader compares it across two
	// TPM2_PCR_Read calls to notice that PCRs moved underneath it.
	//
	Bank->UpdateCounter++;

	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2PcrRead(
	IN  CONST TPM2_PCR_BANK* Bank,
	IN  UINT32               PcrIndex,
	OUT UINT8                Out[TPM2_SHA256_DIGEST_SIZE]
	)
{
	UINT32 i;

	if (Bank == NULL || Out == NULL)
		return TPM2_RC_VALUE;
	if (!Bank->Started)
		return TPM2_RC_INITIALIZE;
	if (PcrIndex >= TPM2_PCR_COUNT)
		return TPM2_RC_VALUE;

	for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
		Out[i] = Bank->Pcr[PcrIndex][i];

	return TPM2_RC_SUCCESS;
}

//
// ---------------------------------------------------------------------------------------------
// COMMAND / RESPONSE HEADERS
// ---------------------------------------------------------------------------------------------
//

UINT32
Tpm2ParseCommandHeader(
	IN  CONST UINT8* Buffer,
	IN  UINT32       Length,
	OUT UINT16*      OutTag,
	OUT UINT32*      OutSize,
	OUT UINT32*      OutCode
	)
{
	UINT16 Tag;
	UINT32 Size;

	if (OutTag != NULL)  *OutTag = 0;
	if (OutSize != NULL) *OutSize = 0;
	if (OutCode != NULL) *OutCode = 0;

	if (Buffer == NULL || Length < TPM2_HEADER_SIZE)
		return TPM2_RC_COMMAND_SIZE;

	Tag  = Tpm2ReadBe16(Buffer);
	Size = Tpm2ReadBe32(Buffer + 2);

	//
	// ⚠ THE DECLARED SIZE IS CHECKED AGAINST WHAT WE ACTUALLY HAVE, in both directions.
	//
	// A commandSize LARGER than the buffer is the classic overread: every subsequent parameter
	// parse would walk off the end. A commandSize SMALLER is not merely untidy either -- it means
	// trailing bytes exist that the command does not account for, and a TPM that ignores them
	// accepts two different byte strings as the same command.
	//
	if (Size != Length)
		return TPM2_RC_COMMAND_SIZE;

	if (Tag != TPM2_ST_NO_SESSIONS && Tag != TPM2_ST_SESSIONS)
		return TPM2_RC_BAD_TAG;

	if (OutTag != NULL)  *OutTag = Tag;
	if (OutSize != NULL) *OutSize = Size;
	if (OutCode != NULL) *OutCode = Tpm2ReadBe32(Buffer + 6);

	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2WriteResponseHeader(
	OUT UINT8*  Buffer,
	IN  UINT16  Tag,
	IN  UINT32  ResponseSize,
	IN  UINT32  ResponseCode
	)
{
	if (Buffer == NULL)
		return 0;

	//
	// ⚠ ENFORCED HERE RATHER THAN TRUSTED TO THE CALLER. Part 2, on TPM_ST_NO_SESSIONS: "If the
	// responseCode from the TPM is not TPM_RC_SUCCESS, then the response tag shall have this
	// value." An error response carrying TPM_ST_SESSIONS is malformed, and the caller that just
	// hit an error path is the caller least likely to remember.
	//
	if (ResponseCode != TPM2_RC_SUCCESS)
		Tag = TPM2_ST_NO_SESSIONS;

	Tpm2WriteBe16(Buffer, Tag);
	Tpm2WriteBe32(Buffer + 2, ResponseSize);
	Tpm2WriteBe32(Buffer + 6, ResponseCode);

	return TPM2_HEADER_SIZE;
}
