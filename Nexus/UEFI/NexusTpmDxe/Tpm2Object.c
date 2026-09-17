/**
 * @file Tpm2Object.c
 * @brief TPMT_PUBLIC marshalling, object Names, and primary-key derivation. See Tpm2Object.h.
 *
 * ⚠ THE TEST VECTORS ARE THE REAL TEMPLATES WINDOWS SENDS ON THIS MACHINE, captured byte-exact
 * from the CRB. That is a stronger oracle than anything written from the specification, because
 * it was produced by code that is not ours and that had no idea we were watching.
 */

#include "Tpm2Object.h"

STATIC
UINT16
Be16(
	IN CONST UINT8* P
	)
{
	return (UINT16)(((UINT16)P[0] << 8) | P[1]);
}

STATIC
UINT32
Be32(
	IN CONST UINT8* P
	)
{
	return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | P[3];
}

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

UINT32
Tpm2PublicExponent(
	IN CONST TPM2_PUBLIC* Pub
	)
{
	if (Pub == NULL || Pub->Exponent == 0)
		return 65537u;
	return Pub->Exponent;
}

/*
 * (!) EVERY READ IS BOUNDS-CHECKED AGAINST THE OCTETS ACTUALLY PRESENT, and running out is
 * TPM_RC_INSUFFICIENT rather than TPM_RC_SIZE. Hardware taught us that distinction on 90 command
 * codes: running out of octets while unmarshalling is INSUFFICIENT; a DECLARED size disagreeing
 * with what arrived is SIZE, and that check belongs to the caller who read the declaration.
 */
#define NEED(n)                                       \
	do {                                              \
		if (p + (n) > InLen)                          \
			return TPM2_RC_INSUFFICIENT;              \
	} while (0)

UINT32
Tpm2PublicUnmarshal(
	IN  CONST UINT8*  In,
	IN  UINT32        InLen,
	OUT TPM2_PUBLIC*  Pub,
	OUT UINT32*       Used
	)
{
	UINT32 p = 0;
	UINT32 i;

	if (In == NULL || Pub == NULL)
		return TPM2_RC_FAILURE;

	for (i = 0; i < sizeof(*Pub); i++)
		((UINT8*)Pub)[i] = 0;

	NEED(2); Pub->Type    = Be16(In + p); p += 2;
	NEED(2); Pub->NameAlg = Be16(In + p); p += 2;

	//
	// ⚠ TYPE IS CHECKED BEFORE ANYTHING TYPE-SPECIFIC IS READ. Part 2 Table 225 assigns
	// TPM_RC_TYPE to an unsupported public type, and parsing an ECC parameter block as though it
	// were RSA would produce a confident wrong answer instead of a refusal.
	//
	if (Pub->Type != TPM2_ALG_RSA)
		return TPM2_RC_TYPE;

	//
	// The Name is computed with nameAlg, so a hash we cannot compute makes the object unnameable.
	// Part 2 Table 77 gives TPM_RC_HASH for a TPMI_ALG_HASH we do not implement.
	//
	if (Tpm2HashSize(Pub->NameAlg) == 0)
		return TPM2_RC_HASH_FMT1;

	NEED(4); Pub->ObjectAttributes = Be32(In + p); p += 4;

	NEED(2); Pub->AuthPolicyLen = Be16(In + p); p += 2;
	if (Pub->AuthPolicyLen > sizeof(Pub->AuthPolicy))
		return TPM2_RC_SIZE;
	NEED(Pub->AuthPolicyLen);
	for (i = 0; i < Pub->AuthPolicyLen; i++)
		Pub->AuthPolicy[i] = In[p + i];
	p += Pub->AuthPolicyLen;

	//
	// TPMT_SYM_DEF_OBJECT+: the algorithm alone when it is TPM_ALG_NULL, otherwise keyBits and
	// mode follow. Reading the two extra fields unconditionally is the classic way to desynchronise
	// a parser by four octets and then blame the field after it.
	//
	NEED(2); Pub->SymAlg = Be16(In + p); p += 2;
	if (Pub->SymAlg != TPM2_ALG_NULL_ID)
	{
		if (Pub->SymAlg != TPM2_ALG_AES)
			return TPM2_RC_SYMMETRIC;
		NEED(2); Pub->SymKeyBits = Be16(In + p); p += 2;
		NEED(2); Pub->SymMode    = Be16(In + p); p += 2;
	}

	//
	// TPMT_RSA_SCHEME+. Both captured templates are restricted decryption keys, and Part 2
	// Table 228 requires TPM_ALG_NULL for exactly that case. A scheme with parameters would need
	// its own union; refusing is honest and the refusal names the field.
	//
	NEED(2); Pub->Scheme = Be16(In + p); p += 2;
	if (Pub->Scheme != TPM2_ALG_NULL_ID)
		return TPM2_RC_SCHEME;

	NEED(2); Pub->KeyBits  = Be16(In + p); p += 2;
	NEED(4); Pub->Exponent = Be32(In + p); p += 4;

	//
	// Part 2 Table 228: the exponent is "an odd number greater than 2", with zero meaning the
	// default. An even exponent, or 1, has no inverse mod lcm(p-1,q-1) and would produce a key
	// that cannot decrypt what it encrypts.
	//
	if (Pub->Exponent != 0 && (Pub->Exponent <= 2 || (Pub->Exponent & 1u) == 0))
		return TPM2_RC_VALUE;

	NEED(2); Pub->UniqueLen = Be16(In + p); p += 2;
	if (Pub->UniqueLen > sizeof(Pub->Unique))
		return TPM2_RC_SIZE;
	NEED(Pub->UniqueLen);
	for (i = 0; i < Pub->UniqueLen; i++)
		Pub->Unique[i] = In[p + i];
	p += Pub->UniqueLen;

	if (Used != NULL)
		*Used = p;
	return TPM2_RC_SUCCESS;
}

#undef NEED

#define ROOM(n)                                       \
	do {                                              \
		if (p + (n) > OutLen)                         \
			return TPM2_RC_SIZE;                      \
	} while (0)

UINT32
Tpm2PublicMarshal(
	IN  CONST TPM2_PUBLIC* Pub,
	OUT UINT8*             Out,
	IN  UINT32             OutLen,
	OUT UINT32*            Written
	)
{
	UINT32 p = 0;
	UINT32 i;

	if (Pub == NULL || Out == NULL)
		return TPM2_RC_FAILURE;
	if (Pub->AuthPolicyLen > sizeof(Pub->AuthPolicy) || Pub->UniqueLen > sizeof(Pub->Unique))
		return TPM2_RC_SIZE;

	ROOM(2); PutBe16(Out + p, Pub->Type);    p += 2;
	ROOM(2); PutBe16(Out + p, Pub->NameAlg); p += 2;
	ROOM(4); PutBe32(Out + p, Pub->ObjectAttributes); p += 4;

	ROOM(2); PutBe16(Out + p, Pub->AuthPolicyLen); p += 2;
	ROOM(Pub->AuthPolicyLen);
	for (i = 0; i < Pub->AuthPolicyLen; i++)
		Out[p + i] = Pub->AuthPolicy[i];
	p += Pub->AuthPolicyLen;

	ROOM(2); PutBe16(Out + p, Pub->SymAlg); p += 2;
	if (Pub->SymAlg != TPM2_ALG_NULL_ID)
	{
		ROOM(2); PutBe16(Out + p, Pub->SymKeyBits); p += 2;
		ROOM(2); PutBe16(Out + p, Pub->SymMode);    p += 2;
	}

	ROOM(2); PutBe16(Out + p, Pub->Scheme);   p += 2;
	ROOM(2); PutBe16(Out + p, Pub->KeyBits);  p += 2;
	//
	// ⚠ THE EXPONENT GOES OUT EXACTLY AS IT CAME IN, zero included. See Tpm2Object.h: substituting
	// 65537 here would change the object's Name and break every handle referring to it.
	//
	ROOM(4); PutBe32(Out + p, Pub->Exponent); p += 4;

	ROOM(2); PutBe16(Out + p, Pub->UniqueLen); p += 2;
	ROOM(Pub->UniqueLen);
	for (i = 0; i < Pub->UniqueLen; i++)
		Out[p + i] = Pub->Unique[i];
	p += Pub->UniqueLen;

	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

#undef ROOM

//
// The largest marshalled TPMT_PUBLIC this build can produce.
//
// (!) THE FIXED PART IS 26 OCTETS, AND I FIRST WROTE 24. type 2, nameAlg 2, objectAttributes 4,
// authPolicy size 2, symmetric 6 (alg + keyBits + mode), scheme 2, keyBits 2, exponent 4, unique
// size 2. Two short is not a crash -- Tpm2PublicMarshal's ROOM() check would answer TPM_RC_SIZE --
// but it would refuse a legal maximum-size public area and the failure would look like a bad
// template rather than a bad constant. Counted field by field here so the next reader can check it.
//
#define TPM2_PUBLIC_FIXED_BYTES  26
#define TPM2_PUBLIC_MAX_BYTES    (26 + TPM2_MAX_DIGEST_SIZE + TPM2_MAX_RSA_KEY_BYTES)

BOOLEAN
Tpm2ObjectName(
	IN  CONST TPM2_PUBLIC* Pub,
	OUT UINT8*             Name,
	OUT UINT16*            NameLen
	)
{
	UINT8  Buf[TPM2_PUBLIC_MAX_BYTES];
	UINT32 Len = 0;
	UINT16 DigestLen;

	if (Pub == NULL || Name == NULL)
		return FALSE;

	DigestLen = Tpm2HashSize(Pub->NameAlg);
	if (DigestLen == 0)
		return FALSE;

	if (Tpm2PublicMarshal(Pub, Buf, sizeof(Buf), &Len) != TPM2_RC_SUCCESS)
		return FALSE;

	//
	// ⚠ nameAlg IS PART OF THE NAME. Part 1 §16: Name = nameAlg || H(TPMT_PUBLIC), with the
	// algorithm as a big-endian TPM_ALG_ID. A bare digest is not a Name.
	//
	PutBe16(Name, Pub->NameAlg);
	if (!Tpm2Hash(Pub->NameAlg, Buf, Len, Name + 2))
		return FALSE;

	if (NameLen != NULL)
		*NameLen = (UINT16)(2 + DigestLen);
	return TRUE;
}

/*
 * (!) A FILE-STATIC STREAM, BECAUSE TPM2_RAND_FN CARRIES NO CONTEXT.
 *
 * The same shape as `mEntropy` in Tpm2Dispatch.c, and safe for the same reason: the CRB handshake
 * serialises commands, so exactly one command is in flight at a time and there is no second caller
 * to interleave with. Said out loud rather than assumed, because if this code is ever reached from
 * two threads the failure is a silently wrong key rather than a crash.
 */
STATIC TPM2_KDF_STREAM* mPrimaryStream = NULL;

STATIC
BOOLEAN
PrimaryRand(
	OUT UINT8* Out,
	IN  UINT32 Bytes
	)
{
	if (mPrimaryStream == NULL)
		return FALSE;
	return Tpm2KdfStreamBytes(mPrimaryStream, Out, Bytes);
}

UINT32
Tpm2CreatePrimaryRsa(
	IN  CONST UINT8*       Seed,
	IN  UINT32             SeedLen,
	IN  CONST TPM2_PUBLIC* Templ,
	IN  CONST UINT8*       Personal,
	IN  UINT32             PersonalLen,
	OUT TPM2_RSA_KEY*      Key,
	OUT TPM2_PUBLIC*       OutPub
	)
{
	UINT8            Buf[TPM2_PUBLIC_MAX_BYTES];
	UINT8            TemplateHash[TPM2_MAX_DIGEST_SIZE];
	TPM2_KDF_STREAM  Stream;
	UINT32           Len = 0;
	UINT32           Rc;
	UINT16           DigestLen;
	UINT32           i;
	UINT32           Bytes;
	BOOLEAN          Ok;

	if (Seed == NULL || Templ == NULL || Key == NULL || OutPub == NULL)
		return TPM2_RC_FAILURE;
	//
	// ⚠ NO SEED, NO KEY. A primary key with a fabricated seed would be a key nobody can reproduce,
	// which is the precise failure this file exists to remove. Refusing is the only honest answer.
	//
	if (SeedLen == 0)
		return TPM2_RC_FAILURE;

	if (Templ->Type != TPM2_ALG_RSA)
		return TPM2_RC_TYPE;

	DigestLen = Tpm2HashSize(Templ->NameAlg);
	if (DigestLen == 0)
		return TPM2_RC_HASH_FMT1;

	//
	// Part 2 Table 228: keyBits is a TPMI_RSA_KEY_BITS. We generate 1024 through 4096 in multiples
	// of 256; anything else gets TPM_RC_KEY_SIZE rather than a key of the wrong length.
	//
	if (Templ->KeyBits < 1024 || Templ->KeyBits > (TPM2_MAX_RSA_KEY_BYTES * 8) ||
	    (Templ->KeyBits & 0xFFu) != 0)
		return TPM2_RC_KEY_SIZE;

	//
	// ⚠ THE TEMPLATE IS HASHED AS RECEIVED. Part 1 §24.6.3 asks for "the hash of the input
	// template"; both captured templates carry 256 zero octets in `unique`, and those octets are
	// part of what arrived. Stripping them first would be just as defensible and would produce
	// different keys, so the choice is written down instead of being implied by the code.
	//
	Rc = Tpm2PublicMarshal(Templ, Buf, sizeof(Buf), &Len);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	//
	// ⚠ PERSONALIZATION DATA IS HASHED WITH THE TEMPLATE, NOT BESIDE IT. Part 3 24.1 requires
	// the same (inPublic, inSensitive.data, seed) to give the same object, and streaming the data
	// into this hash satisfies that without capping its length at whatever the KDF context holds.
	// When the data is empty -- the case both captured commands send -- this is bit-for-bit the
	// plain template hash, so nothing that worked before changes.
	//
	{
		TPM2_HASH_CONTEXT Hc;

		if (!Tpm2HashInit(&Hc, Templ->NameAlg))
			return TPM2_RC_FAILURE;
		Tpm2HashUpdate(&Hc, Buf, Len);
		if (Personal != NULL && PersonalLen != 0)
			Tpm2HashUpdate(&Hc, Personal, PersonalLen);
		if (!Tpm2HashFinal(&Hc, TemplateHash))
			return TPM2_RC_FAILURE;
	}

	//
	// The three inputs Part 1 §24.6.3 names: the primary seed as the KDF key, the template hash as
	// context, and a use string as the label. The construction is ours by the clause's own leave --
	// "Choice of the entropy generation for Primary Objects is a vendor option" -- and Tpm2Object.h
	// records it rather than leaving it to be recovered from this code.
	//
	if (!Tpm2KdfStreamInit(&Stream, Templ->NameAlg, Seed, SeedLen,
	                       "PRIMARY OBJECT CREATION", TemplateHash, DigestLen))
		return TPM2_RC_FAILURE;

	mPrimaryStream = &Stream;
	Ok = Tpm2RsaGenerateKey(Key, Templ->KeyBits, Tpm2PublicExponent(Templ), PrimaryRand);
	mPrimaryStream = NULL;

	if (!Ok)
		return TPM2_RC_FAILURE;

	//
	// The public area we return is the template with `unique` replaced by the modulus. Everything
	// else -- attributes, policy, parameters, and the exponent field exactly as it arrived --
	// carries through untouched, because the caller's Name must be computable from it.
	//
	for (i = 0; i < sizeof(*OutPub); i++)
		((UINT8*)OutPub)[i] = ((CONST UINT8*)Templ)[i];

	Bytes = (UINT32)Templ->KeyBits / 8u;
	if (Bytes > sizeof(OutPub->Unique))
		return TPM2_RC_KEY_SIZE;

	//
	// ⚠ FIXED-WIDTH, LEADING ZEROS INCLUDED. Tpm2BnToBytes writes the modulus right-aligned in
	// exactly `Bytes` octets. A TPM2B whose length varied with the value would change the object's
	// Name for one key in 256, and the bug would look like a rare, unreproducible handle failure.
	//
	if (!Tpm2BnToBytes(&Key->N, OutPub->Unique, Bytes))
		return TPM2_RC_FAILURE;
	OutPub->UniqueLen = (UINT16)Bytes;

	return TPM2_RC_SUCCESS;
}

/* ============================================================================================
 * Creation data, creation hash, and the creation ticket.
 * ============================================================================================ */

UINT32
Tpm2CreationDataForPrimary(
	OUT TPM2_CREATION_DATA* Data,
	IN  UINT32              Hierarchy,
	IN  UINT8               Locality
	)
{
	UINT32 i;

	if (Data == NULL)
		return TPM2_RC_FAILURE;

	if (Hierarchy != TPM2_RH_OWNER && Hierarchy != TPM2_RH_ENDORSEMENT &&
	    Hierarchy != TPM2_RH_PLATFORM && Hierarchy != TPM2_RH_NULL_HIERARCHY)
		return TPM2_RC_VALUE;

	for (i = 0; i < sizeof(*Data); i++)
		((UINT8*)Data)[i] = 0;

	Data->Locality = Locality;

	//
	// ⚠ A PRIMARY OBJECT HAS NO PARENT KEY, AND PART 2 TABLE 261 SAYS EXACTLY WHAT TO WRITE:
	// parentNameAlg is TPM_ALG_NULL, and then "the size will be 4 and parentName will be the
	// hierarchy handle". A digest here would be a creation blob no verifier could reproduce, and
	// TPM2_CertifyCreation would fail later with nothing to point at.
	//
	Data->ParentNameAlg = TPM2_ALG_NULL_ID;
	Data->ParentNameLen = 4;
	PutBe32(Data->ParentName, Hierarchy);

	//
	// The Qualified Name of a primary object's parent is the same four octets. Part 1 §26.6: a
	// Primary Key "has no ancestor keys (its parent's Qualified Name is the hierarchy handle that
	// was used in CreatePrimary)".
	//
	Data->ParentQualifiedNameLen = 4;
	PutBe32(Data->ParentQualifiedName, Hierarchy);

	return TPM2_RC_SUCCESS;
}

#define ROOM(n)                                       \
	do {                                              \
		if (p + (n) > OutLen)                         \
			return TPM2_RC_SIZE;                      \
	} while (0)

UINT32
Tpm2CreationDataMarshal(
	IN  CONST TPM2_CREATION_DATA* Data,
	OUT UINT8*                    Out,
	IN  UINT32                    OutLen,
	OUT UINT32*                   Written
	)
{
	UINT32 p = 0;
	UINT32 i;

	if (Data == NULL || Out == NULL)
		return TPM2_RC_FAILURE;
	if (Data->PcrSelectLen > sizeof(Data->PcrSelect) ||
	    Data->PcrDigestLen > sizeof(Data->PcrDigest) ||
	    Data->ParentNameLen > sizeof(Data->ParentName) ||
	    Data->ParentQualifiedNameLen > sizeof(Data->ParentQualifiedName) ||
	    Data->OutsideInfoLen > sizeof(Data->OutsideInfo))
		return TPM2_RC_SIZE;

	//
	// Part 2 Table 261, in order. pcrSelect is a whole TPML_PCR_SELECTION and carries its own
	// count, so it goes out as the octets the caller supplied and gets NO length prefix -- unlike
	// every TPM2B that follows it. Getting that wrong shifts the entire rest of the structure by
	// two octets and produces a creationHash that matches nothing.
	//
	ROOM(Data->PcrSelectLen);
	for (i = 0; i < Data->PcrSelectLen; i++)
		Out[p + i] = Data->PcrSelect[i];
	p += Data->PcrSelectLen;

	ROOM(2); PutBe16(Out + p, Data->PcrDigestLen); p += 2;
	ROOM(Data->PcrDigestLen);
	for (i = 0; i < Data->PcrDigestLen; i++)
		Out[p + i] = Data->PcrDigest[i];
	p += Data->PcrDigestLen;

	ROOM(1); Out[p++] = Data->Locality;

	ROOM(2); PutBe16(Out + p, Data->ParentNameAlg); p += 2;

	ROOM(2); PutBe16(Out + p, Data->ParentNameLen); p += 2;
	ROOM(Data->ParentNameLen);
	for (i = 0; i < Data->ParentNameLen; i++)
		Out[p + i] = Data->ParentName[i];
	p += Data->ParentNameLen;

	ROOM(2); PutBe16(Out + p, Data->ParentQualifiedNameLen); p += 2;
	ROOM(Data->ParentQualifiedNameLen);
	for (i = 0; i < Data->ParentQualifiedNameLen; i++)
		Out[p + i] = Data->ParentQualifiedName[i];
	p += Data->ParentQualifiedNameLen;

	ROOM(2); PutBe16(Out + p, Data->OutsideInfoLen); p += 2;
	ROOM(Data->OutsideInfoLen);
	for (i = 0; i < Data->OutsideInfoLen; i++)
		Out[p + i] = Data->OutsideInfo[i];
	p += Data->OutsideInfoLen;

	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

//
// The largest marshalled TPMS_CREATION_DATA: every variable field at its maximum.
//
#define TPM2_CREATION_MAX_BYTES                                                      \
	(TPM2_MAX_PCR_SELECT_BYTES + 2 + TPM2_MAX_DIGEST_SIZE + 1 + 2 +                  \
	 2 + (2 + TPM2_MAX_DIGEST_SIZE) + 2 + (2 + TPM2_MAX_DIGEST_SIZE) +               \
	 2 + TPM2_MAX_OUTSIDE_INFO)

UINT32
Tpm2CreationHash(
	IN  CONST TPM2_CREATION_DATA* Data,
	IN  UINT16                    HashAlg,
	OUT UINT8*                    Digest,
	OUT UINT16*                   DigestLen
	)
{
	UINT8  Buf[TPM2_CREATION_MAX_BYTES];
	UINT32 Len = 0;
	UINT32 Rc;
	UINT16 Size;

	if (Data == NULL || Digest == NULL)
		return TPM2_RC_FAILURE;

	Size = Tpm2HashSize(HashAlg);
	if (Size == 0)
		return TPM2_RC_HASH_FMT1;

	Rc = Tpm2CreationDataMarshal(Data, Buf, sizeof(Buf), &Len);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	if (!Tpm2Hash(HashAlg, Buf, Len, Digest))
		return TPM2_RC_FAILURE;

	if (DigestLen != NULL)
		*DigestLen = Size;
	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2CreationTicket(
	IN  CONST UINT8* Proof,
	IN  UINT32       ProofLen,
	IN  UINT16       HashAlg,
	IN  UINT32       Hierarchy,
	IN  CONST UINT8* Name,
	IN  UINT16       NameLen,
	IN  CONST UINT8* CreationHash,
	IN  UINT16       CreationHashLen,
	OUT UINT8*       Out,
	IN  UINT32       OutLen,
	OUT UINT32*      Written
	)
{
	TPM2_HMAC_CONTEXT Ctx;
	UINT8  Digest[TPM2_MAX_DIGEST_SIZE];
	UINT8  Tag[2];
	UINT16 Size;
	UINT32 p = 0;
	UINT32 i;

	if (Out == NULL || Name == NULL || CreationHash == NULL)
		return TPM2_RC_FAILURE;

	//
	// ⚠ NO PROOF, NO TICKET. A ticket HMACed under a fabricated or empty key would validate
	// against nothing, and would be indistinguishable from a real one right up until
	// TPM2_CertifyCreation was asked to prove something with it.
	//
	if (Proof == NULL || ProofLen == 0)
		return TPM2_RC_FAILURE;

	Size = Tpm2HashSize(HashAlg);
	if (Size == 0)
		return TPM2_RC_HASH_FMT1;

	//
	// digest = HMAC(proof, TPM_ST_CREATION || name || creationHash). See Tpm2Object.h for why the
	// message is ours to choose and why this is the choice.
	//
	if (!Tpm2HmacInit(&Ctx, HashAlg, Proof, ProofLen))
		return TPM2_RC_FAILURE;
	// Masked before the cast, for the same reason as Tpm2Session.c: (UINT8)0x8021 is right and
	// still earns MSVC's C4310, because a constant really is being truncated.
	Tag[0] = (UINT8)((TPM2_ST_CREATION >> 8) & 0xFFu);
	Tag[1] = (UINT8)(TPM2_ST_CREATION & 0xFFu);
	Tpm2HmacUpdate(&Ctx, Tag, 2);
	Tpm2HmacUpdate(&Ctx, Name, NameLen);
	Tpm2HmacUpdate(&Ctx, CreationHash, CreationHashLen);
	if (!Tpm2HmacFinal(&Ctx, Digest))
		return TPM2_RC_FAILURE;

	//
	// TPMT_TK_CREATION: tag, hierarchy, then the digest as a TPM2B.
	//
	if (p + 2 > OutLen) return TPM2_RC_SIZE;
	PutBe16(Out + p, TPM2_ST_CREATION); p += 2;
	if (p + 4 > OutLen) return TPM2_RC_SIZE;
	PutBe32(Out + p, Hierarchy); p += 4;
	if (p + 2 > OutLen) return TPM2_RC_SIZE;
	PutBe16(Out + p, Size); p += 2;
	if (p + Size > OutLen) return TPM2_RC_SIZE;
	for (i = 0; i < Size; i++)
		Out[p + i] = Digest[i];
	p += Size;

	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

#undef ROOM

UINT32
Tpm2HierarchyProof(
	IN  CONST UINT8* Seed,
	IN  UINT32       SeedLen,
	IN  UINT16       HashAlg,
	IN  UINT32       Hierarchy,
	OUT UINT8*       Proof,
	OUT UINT16*      ProofLen
	)
{
	UINT8  Ctx[4];
	UINT16 Size;

	if (Seed == NULL || Proof == NULL || SeedLen == 0)
		return TPM2_RC_FAILURE;

	Size = Tpm2HashSize(HashAlg);
	if (Size == 0)
		return TPM2_RC_HASH_FMT1;

	//
	// The hierarchy handle is the context, so the four hierarchies get four different proofs from
	// four different seeds -- and would still get four different proofs if they ever shared one.
	//
	PutBe32(Ctx, Hierarchy);

	if (!Tpm2KdfA(HashAlg, Seed, SeedLen, "HIERARCHY PROOF",
	              Ctx, 4, NULL, 0, (UINT32)Size * 8u, Proof))
		return TPM2_RC_FAILURE;

	if (ProofLen != NULL)
		*ProofLen = Size;
	return TPM2_RC_SUCCESS;
}
