/**
 * @file Tpm2Nv.c
 * @brief NV indices. See Tpm2Nv.h for why this exists and what measured it.
 *
 * ⚠ THE ORACLE FOR THIS FILE IS HARDWARE'S OWN ANSWER. The captured `TPM2_NV_ReadPublic` response
 * for `0x01C00002` carries a public area AND the Name computed over it, so the Name rule can be
 * checked without trusting my reading of Part 2 — and it was, before this file was written.
 */

#include "Tpm2Nv.h"

STATIC TPM2_NV_INDEX mIndices[TPM2_MAX_NV_INDICES];

STATIC
VOID
PutBe16(
	OUT UINT8* P,
	IN  UINT16 V
	)
{
	P[0] = (UINT8)(V >> 8);
	P[1] = (UINT8)V;
}

STATIC
VOID
PutBe32(
	OUT UINT8* P,
	IN  UINT32 V
	)
{
	P[0] = (UINT8)(V >> 24);
	P[1] = (UINT8)(V >> 16);
	P[2] = (UINT8)(V >> 8);
	P[3] = (UINT8)V;
}

#define ROOM(n)                                       \
	do {                                              \
		if (p + (n) > OutLen)                         \
			return TPM2_RC_SIZE;                      \
	} while (0)

UINT32
Tpm2NvPublicMarshal(
	IN  CONST TPM2_NV_PUBLIC* Pub,
	OUT UINT8*                Out,
	IN  UINT32                OutLen,
	OUT UINT32*               Written
	)
{
	UINT32 p = 0;
	UINT32 i;

	if (Pub == NULL || Out == NULL)
		return TPM2_RC_FAILURE;
	if (Pub->AuthPolicyLen > sizeof(Pub->AuthPolicy))
		return TPM2_RC_SIZE;

	//
	// Part 2 Table 251, in order. Everything is fixed-width except authPolicy, which is a TPM2B.
	//
	ROOM(4); PutBe32(Out + p, Pub->NvIndex);    p += 4;
	ROOM(2); PutBe16(Out + p, Pub->NameAlg);    p += 2;
	ROOM(4); PutBe32(Out + p, Pub->Attributes); p += 4;

	ROOM(2); PutBe16(Out + p, Pub->AuthPolicyLen); p += 2;
	ROOM(Pub->AuthPolicyLen);
	for (i = 0; i < Pub->AuthPolicyLen; i++)
		Out[p + i] = Pub->AuthPolicy[i];
	p += Pub->AuthPolicyLen;

	//
	// ⚠ dataSize IS THE SIZE THE INDEX WAS DEFINED AT, not how much has been written. TPMA_NV_WRITTEN
	// is the bit that says whether anything has. Emitting the written count here would make an
	// unwritten index look like a zero-length one, and a partly-written index look smaller than it is.
	//
	ROOM(2); PutBe16(Out + p, Pub->DataSize); p += 2;

	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

#undef ROOM

//
// The largest marshalled TPMS_NV_PUBLIC: 4 + 2 + 4 + 2 + policy + 2.
//
#define TPM2_NV_PUBLIC_MAX_BYTES  (14 + TPM2_MAX_DIGEST_SIZE)

BOOLEAN
Tpm2NvName(
	IN  CONST TPM2_NV_PUBLIC* Pub,
	OUT UINT8*                Name,
	OUT UINT16*               NameLen
	)
{
	UINT8  Buf[TPM2_NV_PUBLIC_MAX_BYTES];
	UINT32 Len = 0;
	UINT16 DigestLen;

	if (Pub == NULL || Name == NULL)
		return FALSE;

	DigestLen = Tpm2HashSize(Pub->NameAlg);
	if (DigestLen == 0)
		return FALSE;

	if (Tpm2NvPublicMarshal(Pub, Buf, sizeof(Buf), &Len) != TPM2_RC_SUCCESS)
		return FALSE;

	//
	// ⚠ THE ALGORITHM ID IS PART OF THE NAME, exactly as for an object. Hardware's EK index uses
	// SHA-384, so its Name is 50 octets rather than 34 -- which is the case that would break any
	// code that assumed a Name is digest-sized plus two and hardcoded 32 for the digest.
	//
	PutBe16(Name, Pub->NameAlg);
	if (!Tpm2Hash(Pub->NameAlg, Buf, Len, Name + 2))
		return FALSE;

	if (NameLen != NULL)
		*NameLen = (UINT16)(2 + DigestLen);
	return TRUE;
}

VOID
Tpm2NvReset(
	VOID
	)
{
	UINT32 i;
	UINT32 j;

	//
	// Zeroed rather than marked free, on the same rule as the object stores. NV content is not
	// always a public certificate -- an index can hold a sealed secret -- and a "free" slot holding
	// the last one is a leak with no command behind it.
	//
	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
		for (j = 0; j < sizeof(mIndices[i]); j++)
			((UINT8*)&mIndices[i])[j] = 0;
}

UINT32
Tpm2NvCount(
	VOID
	)
{
	UINT32 i;
	UINT32 n = 0;

	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
		if (mIndices[i].Defined)
			n++;
	return n;
}

CONST TPM2_NV_INDEX*
Tpm2NvFind(
	IN UINT32 NvIndex
	)
{
	UINT32 i;

	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
		if (mIndices[i].Defined && mIndices[i].Public.NvIndex == NvIndex)
			return &mIndices[i];
	return NULL;
}

UINT32
Tpm2NvEnumerate(
	IN  UINT32  First,
	IN  UINT32  Max,
	OUT UINT32* Handles
	)
{
	UINT32 n = 0;
	UINT32 i;
	UINT32 j;

	if (Handles == NULL || Max == 0)
		return 0;
	if ((First >> 24) != (TPM2_NV_INDEX_FIRST >> 24))
		return 0;

	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
	{
		UINT32 H;

		if (!mIndices[i].Defined || mIndices[i].Public.NvIndex < First)
			continue;
		if (n >= Max)
			break;

		//
		// ⚠ INSERTED IN ORDER. Same rule, same reason, as the object enumeration: `property` is a
		// STARTING handle, paging needs an increasing sequence, and slots are in definition order.
		// The object version of this passed every test until one existed where the two orders could
		// not coincide, so this one is sorted from the start rather than after an injury.
		//
		H = mIndices[i].Public.NvIndex;
		for (j = n; j > 0 && Handles[j - 1] > H; j--)
			Handles[j] = Handles[j - 1];
		Handles[j] = H;
		n++;
	}
	return n;
}

UINT32
Tpm2NvDefine(
	IN CONST TPM2_NV_PUBLIC* Pub
	)
{
	TPM2_NV_INDEX* Slot = NULL;
	UINT32 i;

	if (Pub == NULL)
		return TPM2_RC_FAILURE;

	if (Pub->NvIndex < TPM2_NV_INDEX_FIRST || Pub->NvIndex > TPM2_NV_INDEX_LAST)
		return TPM2_RC_VALUE;
	if (Tpm2HashSize(Pub->NameAlg) == 0)
		return TPM2_RC_HASH_FMT1;
	if (Pub->AuthPolicyLen > sizeof(Pub->AuthPolicy))
		return TPM2_RC_SIZE;
	if (Pub->DataSize == 0 || Pub->DataSize > TPM2_MAX_NV_DATA)
		return TPM2_RC_SIZE;

	if (Tpm2NvFind(Pub->NvIndex) != NULL)
		return TPM2_RC_NV_DEFINED;

	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
		if (!mIndices[i].Defined)
		{
			Slot = &mIndices[i];
			break;
		}
	if (Slot == NULL)
		return TPM2_RC_NV_SPACE;

	for (i = 0; i < sizeof(*Slot); i++)
		((UINT8*)Slot)[i] = 0;

	Slot->Public = *Pub;
	//
	// ⚠ WRITTEN IS CLEARED HERE NO MATTER WHAT THE CALLER PASSED. Part 2 Table 249 makes it a
	// status bit the TPM maintains, not an attribute a definer chooses. A caller that could assert
	// it would be able to make the TPM claim content it does not hold -- which for index
	// 0x01C00002 means claiming an EK certificate that is not there.
	//
	Slot->Public.Attributes &= ~(UINT32)TPM2_NVA_WRITTEN;
	Slot->Written = 0;
	Slot->Defined = TRUE;
	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2NvWrite(
	IN UINT32       NvIndex,
	IN CONST UINT8* Data,
	IN UINT16       Len
	)
{
	TPM2_NV_INDEX* Slot = NULL;
	UINT32 i;

	if (Data == NULL && Len != 0)
		return TPM2_RC_FAILURE;

	for (i = 0; i < TPM2_MAX_NV_INDICES; i++)
		if (mIndices[i].Defined && mIndices[i].Public.NvIndex == NvIndex)
		{
			Slot = &mIndices[i];
			break;
		}
	if (Slot == NULL)
		return TPM2_RC_H(TPM2_RC_HANDLE, 1);

	//
	// ⚠ THE WRITE MUST FIT THE SIZE THE INDEX WAS DEFINED AT. Part 2 gives TPM_RC_NV_RANGE for a
	// write outside it, and growing the index instead would make dataSize a lie told by the public
	// area -- which is the one part of an NV index that needs no authorization to read.
	//
	if (Len > Slot->Public.DataSize)
		return TPM2_RC_NV_RANGE;

	for (i = 0; i < Len; i++)
		Slot->Data[i] = Data[i];
	Slot->Written = Len;
	Slot->Public.Attributes |= TPM2_NVA_WRITTEN;
	return TPM2_RC_SUCCESS;
}
