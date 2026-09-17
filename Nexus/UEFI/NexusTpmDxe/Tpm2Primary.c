/**
 * @file Tpm2Primary.c
 * @brief `TPM2_CreatePrimary`, the transient object store, and the seed interface.
 *
 * ⚠ EVERY OFFSET HERE IS CHECKED AGAINST THE 343- AND 375-OCTET COMMANDS WINDOWS ACTUALLY SENDS.
 * The parameter area is `inSensitive`, `inPublic`, `outsideInfo`, `creationPCR` — four TPM2Bs and
 * a list, in that order, with no padding and no alignment. Getting one length prefix wrong shifts
 * everything after it and produces a confident wrong answer, which is why the parser stops at the
 * first field that does not fit rather than carrying on.
 */

#include "Tpm2Primary.h"

STATIC TPM2_SEED_FN mSeed = NULL;

//
// (!) THE OBJECT STORE IS FILE-STATIC, like mEntropy and mTime in the dispatcher, and safe for the
// same reason: the CRB handshake serialises commands, so exactly one is in flight at a time.
//
// It is also large -- a TPM2_RSA_KEY is about 2.7 KB and a TPM2_PUBLIC about 600 -- so three slots
// is roughly 10 KB of BSS in both the DXE and the kernel driver. That is the price of holding real
// keys rather than pretending to, and it is stated here so nobody has to measure it to find out.
//
STATIC TPM2_OBJECT_SLOT mObjects[TPM2_MAX_LOADED_OBJECTS];

//
// (!) A SECOND ARRAY, NOT A FLAG ON THE FIRST, and the reason is the capacity properties. The TPM
// advertises HR_LOADED_AVAIL and HR_TRANSIENT_AVAIL separately from HR_PERSISTENT_AVAIL, and a
// shared array would make persisting an object silently consume a transient slot -- so a caller
// that read those properties, persisted two keys and then loaded a third would be refused for a
// reason no property it can read would explain.
//
STATIC TPM2_OBJECT_SLOT mPersistent[TPM2_MAX_PERSISTENT_OBJECTS];

VOID
Tpm2SetSeedSource(
	IN TPM2_SEED_FN Fn
	)
{
	mSeed = Fn;
}

BOOLEAN
Tpm2HaveSeedSource(
	VOID
	)
{
	return (mSeed != NULL);
}

VOID
Tpm2ObjectStoreReset(
	VOID
	)
{
	UINT32 i;
	UINT32 j;

	//
	// ⚠ ZEROED, NOT JUST MARKED FREE. These slots hold RSA private keys. Leaving P and Q in memory
	// after a TPM Reset would mean a key the caller believes was destroyed is still sitting in the
	// driver's BSS, findable by anything that can read it.
	//
	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
		for (j = 0; j < sizeof(mObjects[i]); j++)
			((UINT8*)&mObjects[i])[j] = 0;
}

UINT32
Tpm2ObjectStoreLoaded(
	VOID
	)
{
	UINT32 i;
	UINT32 n = 0;

	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
		if (mObjects[i].Loaded)
			n++;
	return n;
}

CONST TPM2_OBJECT_SLOT*
Tpm2ObjectFind(
	IN UINT32 Handle
	)
{
	UINT32 i;

	//
	// ⚠ BOTH STORES, because a handle names an object and the caller does not have to tell us
	// which kind it is. TPM2_ReadPublic on 0x81000001 and on 0x80000000 are the same question
	// about two different objects, and a lookup that only saw transient ones would answer
	// TPM_RC_HANDLE for a persistent object that is sitting right there.
	//
	// The ranges cannot collide -- transient is 0x80xxxxxx, persistent 0x81xxxxxx -- so searching
	// both in turn cannot return the wrong one.
	//
	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
		if (mObjects[i].Loaded && mObjects[i].Handle == Handle)
			return &mObjects[i];
	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		if (mPersistent[i].Loaded && mPersistent[i].Handle == Handle)
			return &mPersistent[i];
	return NULL;
}

STATIC
TPM2_OBJECT_SLOT*
AllocSlot(
	VOID
	)
{
	UINT32 i;

	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
		if (!mObjects[i].Loaded)
			return &mObjects[i];
	return NULL;
}

/*
 * The PCR digest for a TPML_PCR_SELECTION, and the selection echoed back for creationData.
 *
 * (!) THE SELECTION IS COPIED VERBATIM, NOT REBUILT. Part 3 puts the caller's `creationPCR` into
 * `creationData.pcrSelect`, and a verifier recomputing the creationHash uses the octets that were
 * sent. Normalising them -- dropping an empty bank, say -- would give a hash nobody else computes.
 */
STATIC
UINT32
PcrSelectionDigest(
	IN  CONST TPM2_PCR_BANK* Bank,
	IN  CONST UINT8*         In,
	IN  UINT32               InLen,
	IN  UINT16               HashAlg,
	OUT TPM2_CREATION_DATA*  Data,
	OUT UINT32*              Used
	)
{
	UINT32 p = 0;
	UINT32 Count;
	UINT32 b;
	UINT32 Selected = 0;
	TPM2_HASH_CONTEXT Hc;
	UINT8 Digest[TPM2_MAX_DIGEST_SIZE];

	if (InLen < 4)
		return TPM2_RC_INSUFFICIENT;
	Count = Tpm2ReadBe32(In);

	//
	// Part 2 Table 108: HASH_COUNT bounds the list. We implement one bank, so more than one
	// selection cannot be satisfied -- and saying TPM_RC_VALUE beats silently digesting the first.
	//
	if (Count > 1)
		return TPM2_RC_VALUE;

	if (!Tpm2HashInit(&Hc, HashAlg))
		return TPM2_RC_HASH_FMT1;

	p = 4;
	for (b = 0; b < Count; b++)
	{
		UINT16 Alg;
		UINT8  SelSize;
		UINT32 Bit;

		if (p + 3 > InLen)
			return TPM2_RC_INSUFFICIENT;
		Alg     = Tpm2ReadBe16(In + p); p += 2;
		SelSize = In[p]; p += 1;

		//
		// Part 2: sizeofSelect is between PCR_SELECT_MIN and PCR_SELECT_MAX. We publish 24 PCRs,
		// so 3 octets, and TPM_PT_PCR_SELECT_MIN already says so in TPM_CAP_TPM_PROPERTIES.
		//
		if (SelSize != (TPM2_PCR_COUNT + 7) / 8)
			return TPM2_RC_VALUE;
		if (p + SelSize > InLen)
			return TPM2_RC_INSUFFICIENT;

		//
		// A bank we do not have cannot select anything. Part 3 lets the TPM return a selection
		// with nothing set rather than refusing, but a caller asking for SHA-1 PCRs is asking for
		// something we cannot supply, so this refuses instead of returning a digest over nothing.
		//
		if (Alg != TPM2_ALG_SHA256)
			return TPM2_RC_VALUE;

		for (Bit = 0; Bit < TPM2_PCR_COUNT; Bit++)
		{
			if ((In[p + (Bit / 8)] & (1u << (Bit % 8))) == 0)
				continue;
			{
				UINT8 Pcr[TPM2_SHA256_DIGEST_SIZE];
				UINT32 Rc = Tpm2PcrRead(Bank, Bit, Pcr);

				if (Rc != TPM2_RC_SUCCESS)
					return Rc;
				//
				// Part 1 §17.9: the digest is over the concatenation of the selected PCR, in
				// increasing index order, with no separators.
				//
				Tpm2HashUpdate(&Hc, Pcr, TPM2_SHA256_DIGEST_SIZE);
				Selected++;
			}
		}
		p += SelSize;
	}

	if (p > sizeof(Data->PcrSelect))
		return TPM2_RC_SIZE;
	for (b = 0; b < p; b++)
		Data->PcrSelect[b] = In[b];
	Data->PcrSelectLen = (UINT16)p;

	//
	// ⚠ AN EMPTY SELECTION GIVES A ZERO-LENGTH DIGEST, NOT A DIGEST OF NOTHING. Part 2 Table 261:
	// "pcrDigest.size shall be zero if the pcrSelect list is empty." Emitting H("") instead would
	// be a 32-octet field where a verifier expects none, and every creationHash would differ.
	//
	if (Selected == 0)
	{
		Data->PcrDigestLen = 0;
	}
	else
	{
		if (!Tpm2HashFinal(&Hc, Digest))
			return TPM2_RC_FAILURE;
		Data->PcrDigestLen = Tpm2HashSize(HashAlg);
		for (b = 0; b < Data->PcrDigestLen; b++)
			Data->PcrDigest[b] = Digest[b];
	}

	if (Used != NULL)
		*Used = p;
	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2DoCreatePrimary(
	IN     CONST TPM2_PCR_BANK* Bank,
	IN     CONST UINT8*         In,
	IN     UINT32               Size,
	OUT    UINT8*               Out,
	IN     UINT32               OutSize,
	OUT    UINT32*              Written
	)
{
	TPM2_SESSION_AREA  Sessions;
	TPM2_PUBLIC        Templ;
	TPM2_CREATION_DATA Data;
	TPM2_OBJECT_SLOT*  Slot;
	UINT8  Seed[TPM2_PRIMARY_SEED_BYTES];
	UINT8  Proof[TPM2_MAX_DIGEST_SIZE];
	UINT8  CreationDigest[TPM2_MAX_DIGEST_SIZE];
	UINT8  UserAuth[TPM2_MAX_DIGEST_SIZE];
	UINT8  Personal[TPM2_MAX_DIGEST_SIZE];
	UINT16 ProofLen = 0;
	UINT16 CreationDigestLen = 0;
	UINT16 UserAuthLen = 0;
	UINT16 PersonalLen = 0;
	UINT32 Hierarchy;
	UINT32 p;
	UINT32 Used = 0;
	UINT32 Rc;
	UINT32 i;
	UINT32 SensSize;
	UINT32 PubSize;
	UINT32 w;

	if (Written != NULL)
		*Written = 0;
	if (In == NULL || Out == NULL)
		return TPM2_RC_FAILURE;

	//
	// ⚠ THIS COMMAND REQUIRES AUTHORIZATION, so TPM_ST_NO_SESSIONS is not a short form -- it is a
	// missing authorization. Part 3 clause 5.5 gives TPM_RC_AUTH_MISSING, which tells the caller
	// what to add rather than making it guess from a size error.
	//
	if (Tpm2ReadBe16(In) != TPM2_ST_SESSIONS)
		return TPM2_RC_AUTH_MISSING;

	//
	// Handle area: one handle, primaryHandle.
	//
	p = TPM2_HEADER_SIZE;
	if (Size < p + 4)
		return TPM2_RC_INSUFFICIENT;
	Hierarchy = Tpm2ReadBe32(In + p); p += 4;

	//
	// Part 3 Table 191: TPMI_RH_HIERARCHY, so OWNER, ENDORSEMENT, PLATFORM or NULL. Part 2 gives
	// TPM_RC_VALUE for a TPMI_RH_HIERARCHY that is none of them, numbered with the handle.
	//
	if (Hierarchy != TPM2_RH_OWNER && Hierarchy != TPM2_RH_ENDORSEMENT &&
	    Hierarchy != TPM2_RH_PLATFORM && Hierarchy != TPM2_RH_NULL_HIERARCHY)
		return TPM2_RC_H(TPM2_RC_VALUE, 1);

	Rc = Tpm2SessionParse(In + p, Size - p, &Sessions, &Used);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;
	p += Used;

	//
	// Part 3 Table 191 marks exactly one handle with "@", so exactly one authorization is expected.
	//
	if (Sessions.Count != 1)
		return TPM2_RC_AUTHSIZE;

	//
	// ⚠ THE HIERARCHY'S authValue IS EMPTY, AND THAT IS A MEASURED FACT ABOUT THIS TPM, not an
	// assumption about TPMs in general. Nothing has ever set an owner, endorsement or platform
	// authorization here, so the correct stored value is the empty string -- and Part 1's
	// trailing-zero rule is what makes Windows' twenty zero octets match it.
	//
	// When TPM2_HierarchyChangeAuth exists, this reads the stored value instead. It is a lookup
	// that currently has one answer, not a check that has been skipped.
	//
	Rc = Tpm2SessionAuthorize(&Sessions.S[0], 0, NULL, 0);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	// ------------------------------------------------------------------ parameters

	//
	// inSensitive: TPM2B_SENSITIVE_CREATE { userAuth: TPM2B_AUTH, data: TPM2B_SENSITIVE_DATA }.
	//
	if (Size < p + 2)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
	SensSize = Tpm2ReadBe16(In + p); p += 2;
	if (Size < p + SensSize)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
	if (SensSize != 0)
	{
		UINT32 q = p;
		UINT32 End = p + SensSize;

		if (q + 2 > End)
			return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
		UserAuthLen = Tpm2ReadBe16(In + q); q += 2;
		if (UserAuthLen > sizeof(UserAuth))
			return TPM2_RC_P(TPM2_RC_SIZE, 1);
		if (q + UserAuthLen > End)
			return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
		for (i = 0; i < UserAuthLen; i++)
			UserAuth[i] = In[q + i];
		q += UserAuthLen;

		if (q + 2 > End)
			return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
		PersonalLen = Tpm2ReadBe16(In + q); q += 2;
		if (PersonalLen > sizeof(Personal))
			return TPM2_RC_P(TPM2_RC_SIZE, 1);
		if (q + PersonalLen > End)
			return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
		for (i = 0; i < PersonalLen; i++)
			Personal[i] = In[q + i];
		q += PersonalLen;

		//
		// The declared size must be exactly consumed. Anything left over means the caller and the
		// TPM disagree about the structure, and continuing would read the template from the middle
		// of the sensitive area.
		//
		if (q != End)
			return TPM2_RC_P(TPM2_RC_SIZE, 1);
	}
	p += SensSize;

	//
	// inPublic: TPM2B_PUBLIC. Part 2 Table 236: the declared size must equal what the TPMT_PUBLIC
	// actually consumed, and TPM_RC_SIZE is the code for the mismatch.
	//
	if (Size < p + 2)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 2);
	PubSize = Tpm2ReadBe16(In + p); p += 2;
	if (Size < p + PubSize)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 2);

	Rc = Tpm2PublicUnmarshal(In + p, PubSize, &Templ, &Used);
	if (Rc != TPM2_RC_SUCCESS)
		return TPM2_RC_P(Rc, 2);
	if (Used != PubSize)
		return TPM2_RC_P(TPM2_RC_SIZE, 2);
	p += PubSize;

	//
	// ⚠ sensitiveDataOrigin AND data MUST AGREE. Part 3 clause 12.1: when sensitiveDataOrigin is
	// SET the TPM generates the sensitive data, so `data` has to be empty; when it is CLEAR the
	// caller supplies it. Accepting both at once would silently ignore one of them.
	//
	if ((Templ.ObjectAttributes & TPM2_OBJ_SENSITIVE_DATA_ORIGIN) != 0)
	{
		if (PersonalLen != 0)
			return TPM2_RC_P(TPM2_RC_ATTRIBUTES, 1);
	}
	else
	{
		if (PersonalLen == 0)
			return TPM2_RC_P(TPM2_RC_ATTRIBUTES, 1);
	}

	//
	// outsideInfo: TPM2B_DATA, copied into creationData untouched.
	//
	Rc = Tpm2CreationDataForPrimary(&Data, Hierarchy, TPM2_LOCALITY_ZERO);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	if (Size < p + 2)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 3);
	Data.OutsideInfoLen = Tpm2ReadBe16(In + p); p += 2;
	if (Data.OutsideInfoLen > sizeof(Data.OutsideInfo))
		return TPM2_RC_P(TPM2_RC_SIZE, 3);
	if (Size < p + Data.OutsideInfoLen)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 3);
	for (i = 0; i < Data.OutsideInfoLen; i++)
		Data.OutsideInfo[i] = In[p + i];
	p += Data.OutsideInfoLen;

	//
	// creationPCR: TPML_PCR_SELECTION.
	//
	Rc = PcrSelectionDigest(Bank, In + p, Size - p, Templ.NameAlg, &Data, &Used);
	if (Rc != TPM2_RC_SUCCESS)
		return TPM2_RC_P(Rc, 4);
	p += Used;

	//
	// ⚠ THE COMMAND MUST END HERE. Trailing octets mean the caller sent something this TPM did not
	// account for, and answering SUCCESS would tell it we understood a field we never read.
	//
	if (p != Size)
		return TPM2_RC_P(TPM2_RC_SIZE, 4);

	// ------------------------------------------------------------------ the key

	//
	// ⚠ NO SEED SOURCE, NO KEY. Refusing is the only honest answer: a key from a fabricated seed
	// would succeed here and then change on the next boot, which is the exact failure -- Windows
	// event 519, "the TPM has been cleared, reason: SRK has changed" -- this whole layer exists to
	// remove. A silent success would be worse than the refusal, because it would look fixed.
	//
	if (mSeed == NULL || !mSeed(Hierarchy, Seed, sizeof(Seed)))
		return TPM2_RC_FAILURE;

	Slot = AllocSlot();
	if (Slot == NULL)
		return TPM2_RC_OBJECT_MEMORY;

	Rc = Tpm2CreatePrimaryRsa(Seed, sizeof(Seed), &Templ,
	                          (PersonalLen != 0) ? Personal : NULL, PersonalLen,
	                          &Slot->Key, &Slot->Public);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	if (!Tpm2ObjectName(&Slot->Public, Slot->Name, &Slot->NameLen))
		return TPM2_RC_FAILURE;

	//
	// Part 1 §24.7.3: the object's authValue is copied from inSensitive.userAuth.
	//
	Slot->AuthLen = UserAuthLen;
	for (i = 0; i < UserAuthLen; i++)
		Slot->Auth[i] = UserAuth[i];
	Slot->Hierarchy = Hierarchy;
	Slot->Handle = TPM2_TRANSIENT_FIRST + (UINT32)(Slot - mObjects);

	Rc = Tpm2CreationHash(&Data, Templ.NameAlg, CreationDigest, &CreationDigestLen);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	Rc = Tpm2HierarchyProof(Seed, sizeof(Seed), Templ.NameAlg, Hierarchy, Proof, &ProofLen);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	// ------------------------------------------------------------------ the response

	p = TPM2_HEADER_SIZE;

	//
	// Handle area comes BEFORE parameterSize. Part 1 §18.3: in a response with sessions, the
	// handles are followed by a UINT32 parameterSize and then the parameters. Putting the size
	// first is the natural-looking mistake and desynchronises every parameter after it.
	//
	if (OutSize < p + 4)
		return TPM2_RC_SIZE;
	Tpm2WriteBe32(Out + p, Slot->Handle); p += 4;

	if (OutSize < p + 4)
		return TPM2_RC_SIZE;
	{
		UINT32 ParamStart = p + 4;
		UINT32 q = ParamStart;

		//
		// outPublic: TPM2B_PUBLIC.
		//
		if (OutSize < q + 2)
			return TPM2_RC_SIZE;
		Rc = Tpm2PublicMarshal(&Slot->Public, Out + q + 2, OutSize - (q + 2), &w);
		if (Rc != TPM2_RC_SUCCESS)
			return Rc;
		Tpm2WriteBe16(Out + q, (UINT16)w);
		q += 2 + w;

		//
		// creationData: TPM2B_CREATION_DATA.
		//
		if (OutSize < q + 2)
			return TPM2_RC_SIZE;
		Rc = Tpm2CreationDataMarshal(&Data, Out + q + 2, OutSize - (q + 2), &w);
		if (Rc != TPM2_RC_SUCCESS)
			return Rc;
		Tpm2WriteBe16(Out + q, (UINT16)w);
		q += 2 + w;

		//
		// creationHash: TPM2B_DIGEST.
		//
		if (OutSize < q + 2 + CreationDigestLen)
			return TPM2_RC_SIZE;
		Tpm2WriteBe16(Out + q, CreationDigestLen); q += 2;
		for (i = 0; i < CreationDigestLen; i++)
			Out[q + i] = CreationDigest[i];
		q += CreationDigestLen;

		//
		// creationTicket: TPMT_TK_CREATION.
		//
		Rc = Tpm2CreationTicket(Proof, ProofLen, Templ.NameAlg, Hierarchy,
		                        Slot->Name, Slot->NameLen,
		                        CreationDigest, CreationDigestLen,
		                        Out + q, OutSize - q, &w);
		if (Rc != TPM2_RC_SUCCESS)
			return Rc;
		q += w;

		//
		// name: TPM2B_NAME.
		//
		if (OutSize < q + 2 + Slot->NameLen)
			return TPM2_RC_SIZE;
		Tpm2WriteBe16(Out + q, Slot->NameLen); q += 2;
		for (i = 0; i < Slot->NameLen; i++)
			Out[q + i] = Slot->Name[i];
		q += Slot->NameLen;

		Tpm2WriteBe32(Out + p, (UINT32)(q - ParamStart));   /* parameterSize */
		p = q;
	}

	//
	// The response authorization area, one acknowledgement per command session.
	//
	Rc = Tpm2SessionWriteResponse(&Sessions, Out + p, OutSize - p, &w);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;
	p += w;

	//
	// ⚠ THE SLOT IS MARKED LOADED ONLY NOW, after every step that could still fail. A slot marked
	// loaded before a size failure would leak a handle to an object the caller was never told
	// about, and three of those exhaust the store permanently.
	//
	Slot->Loaded = TRUE;

	Tpm2WriteResponseHeader(Out, TPM2_ST_SESSIONS, p, TPM2_RC_SUCCESS);
	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

BOOLEAN
Tpm2ObjectFlush(
	IN UINT32 Handle
	)
{
	UINT32 i;
	UINT32 j;

	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
	{
		if (!mObjects[i].Loaded || mObjects[i].Handle != Handle)
			continue;

		//
		// ⚠ ZEROED, NOT MARKED FREE, for the same reason Tpm2ObjectStoreReset zeroes: the slot
		// holds an RSA private key. A "free" slot still containing P and Q is a key the caller
		// believes was destroyed, sitting in the driver's BSS for anything that can read it.
		//
		for (j = 0; j < sizeof(mObjects[i]); j++)
			((UINT8*)&mObjects[i])[j] = 0;
		return TRUE;
	}
	return FALSE;
}

//
// TPM_HT, Part 2 clause 7.2 -- the handle type in bits 31:24.
//
#define TPM2_HT_HMAC_SESSION        0x02u
#define TPM2_HT_POLICY_SESSION      0x03u
#define TPM2_HT_PERSISTENT          0x81u
#define TPM2_HT_TRANSIENT_TYPE      0x80u

UINT32
Tpm2DoFlushContext(
	IN UINT32 FlushHandle
	)
{
	//
	// TPMI_DH_CONTEXT, Part 2 Table 57: HMAC sessions, policy sessions, and transient objects,
	// with TPM_RC_VALUE for anything else.
	//
	// ⚠ EVERY CODE HERE IS NUMBERED AS A PARAMETER, NOT A HANDLE. Part 3 §28.4.1 states it
	// outright -- "flushHandle is a parameter and not a handle" -- and gives the reason: a handle
	// in the handle area would be validated as present before the command ran, which would make it
	// impossible to flush a SAVED session context. Hardware confirms it from the other direction:
	// its TPMA_CC for this command is 0x00000165, with cHandles = 0.
	//
	switch (FlushHandle >> 24)
	{
	case TPM2_HT_TRANSIENT_TYPE:
		return Tpm2ObjectFlush(FlushHandle) ? TPM2_RC_SUCCESS
		                                    : TPM2_RC_P(TPM2_RC_HANDLE, 1);

	case TPM2_HT_HMAC_SESSION:
	case TPM2_HT_POLICY_SESSION:
		//
		// ⚠ NO SESSIONS EXIST YET, SO NONE CAN BE FLUSHED -- and TPM_RC_HANDLE is exactly what
		// Part 3 asks for: "if the handle does not reference a loaded or active session, then the
		// TPM shall return TPM_RC_HANDLE". This is the correct answer to the state we are in, not
		// a placeholder. When TPM2_StartAuthSession lands, the lookup goes here and the refusal
		// narrows on its own.
		//
		// (Part 3 also notes that flushing a session ignores the handle's upper byte, so
		// 0x20000000 flushes 0x03000000. That rule is about FINDING a saved context, and there are
		// none to find until context save exists.)
		//
		return TPM2_RC_P(TPM2_RC_HANDLE, 1);

	default:
		//
		// A persistent handle lands here deliberately. Part 3 §28.4.1: "This command may not be
		// used to remove a persistent object from the TPM. Use TPM2_EvictControl()." Flushing one
		// silently would destroy an object the caller expects to survive a reboot.
		//
		return TPM2_RC_P(TPM2_RC_VALUE, 1);
	}
}

UINT32
Tpm2ObjectStoreResidue(
	VOID
	)
{
	UINT32 i;
	UINT32 j;
	UINT32 n = 0;

	//
	// ⚠ EVERY OCTET OF A FREE SLOT, NOT JUST THE KEY. A slot that is not loaded should be entirely
	// zero -- handle, hierarchy, public area, Name and authValue included. Counting only the key
	// would miss a flush that zeroed the obvious field and left the object's Name and auth behind.
	//
	for (i = 0; i < TPM2_MAX_LOADED_OBJECTS; i++)
	{
		if (mObjects[i].Loaded)
			continue;
		for (j = 0; j < sizeof(mObjects[i]); j++)
			if (((CONST UINT8*)&mObjects[i])[j] != 0)
				n++;
	}
	return n;
}

/* ============================================================================================
 * The PERSISTENT object store, and TPM2_EvictControl.
 * ============================================================================================ */


UINT32
Tpm2PersistentCount(
	VOID
	)
{
	UINT32 i;
	UINT32 n = 0;

	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		if (mPersistent[i].Loaded)
			n++;
	return n;
}

VOID
Tpm2PersistentReset(
	VOID
	)
{
	UINT32 i;
	UINT32 j;

	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		for (j = 0; j < sizeof(mPersistent[i]); j++)
			((UINT8*)&mPersistent[i])[j] = 0;
}

UINT32
Tpm2PersistentResidue(
	VOID
	)
{
	UINT32 i;
	UINT32 j;
	UINT32 n = 0;

	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
	{
		if (mPersistent[i].Loaded)
			continue;
		for (j = 0; j < sizeof(mPersistent[i]); j++)
			if (((CONST UINT8*)&mPersistent[i])[j] != 0)
				n++;
	}
	return n;
}

BOOLEAN
Tpm2ObjectQualifiedName(
	IN  CONST TPM2_OBJECT_SLOT* Slot,
	OUT UINT8*                  Qn,
	OUT UINT16*                 QnLen
	)
{
	TPM2_HASH_CONTEXT Hc;
	UINT8  Parent[4];
	UINT16 DigestLen;

	if (Slot == NULL || Qn == NULL)
		return FALSE;

	DigestLen = Tpm2HashSize(Slot->Public.NameAlg);
	if (DigestLen == 0)
		return FALSE;

	//
	// ⚠ THE PARENT'S QUALIFIED NAME IS FOUR OCTETS OF HANDLE, NOT A DIGEST. Part 1 §23.5: "Both
	// the Name and Qualified Name for a Primary Seed are the handle of the Primary Seed. This makes
	// the QN of a Primary Object equal to QN = H_nameAlg(hierarchy handle || Primary Object Name)."
	// Hashing a 34-octet placeholder here instead would produce a QN that is self-consistent, that
	// nothing else in the world computes, and that only shows up when something tries to verify an
	// ancestry.
	//
	Parent[0] = (UINT8)(Slot->Hierarchy >> 24);
	Parent[1] = (UINT8)(Slot->Hierarchy >> 16);
	Parent[2] = (UINT8)(Slot->Hierarchy >> 8);
	Parent[3] = (UINT8)(Slot->Hierarchy);

	if (!Tpm2HashInit(&Hc, Slot->Public.NameAlg))
		return FALSE;
	Tpm2HashUpdate(&Hc, Parent, 4);
	//
	// The object's WHOLE Name, algorithm prefix included -- it is hashed as the TPM2B's buffer,
	// which is what `nameAlg || digest` already is.
	//
	Tpm2HashUpdate(&Hc, Slot->Name, Slot->NameLen);

	Tpm2WriteBe16(Qn, Slot->Public.NameAlg);
	if (!Tpm2HashFinal(&Hc, Qn + 2))
		return FALSE;

	if (QnLen != NULL)
		*QnLen = (UINT16)(2 + DigestLen);
	return TRUE;
}

UINT32
Tpm2DoEvictControl(
	IN     CONST UINT8* In,
	IN     UINT32       Size,
	OUT    UINT8*       Out,
	IN     UINT32       OutSize,
	OUT    UINT32*      Written
	)
{
	TPM2_SESSION_AREA  Sessions;
	CONST TPM2_OBJECT_SLOT* Src;
	TPM2_OBJECT_SLOT*  Dst;
	UINT32 Auth;
	UINT32 ObjectHandle;
	UINT32 PersistentHandle;
	UINT32 OwnerLimit;
	UINT32 p;
	UINT32 Used = 0;
	UINT32 Rc;
	UINT32 i;
	UINT32 w;

	if (Written != NULL)
		*Written = 0;
	if (In == NULL || Out == NULL)
		return TPM2_RC_FAILURE;

	//
	// Part 3 Table 230: tag is TPM_ST_SESSIONS, because @auth requires an authorization.
	//
	if (Tpm2ReadBe16(In) != TPM2_ST_SESSIONS)
		return TPM2_RC_AUTH_MISSING;

	//
	// TWO command handles -- which is what hardware's TPMA_CC 0x04400120 declares with cHandles=2,
	// and the reason this command cannot be parsed like FlushContext.
	//
	p = TPM2_HEADER_SIZE;
	if (Size < p + 8)
		return TPM2_RC_INSUFFICIENT;
	Auth         = Tpm2ReadBe32(In + p); p += 4;
	ObjectHandle = Tpm2ReadBe32(In + p); p += 4;

	//
	// TPMI_RH_PROVISION: owner or platform only.
	//
	if (Auth != TPM2_RH_OWNER && Auth != TPM2_RH_PLATFORM)
		return TPM2_RC_H(TPM2_RC_VALUE, 1);

	Rc = Tpm2SessionParse(In + p, Size - p, &Sessions, &Used);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;
	p += Used;
	if (Sessions.Count != 1)
		return TPM2_RC_AUTHSIZE;

	//
	// The hierarchy authValue is empty; see the same note in Tpm2DoCreatePrimary.
	//
	Rc = Tpm2SessionAuthorize(&Sessions.S[0], 0, NULL, 0);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	if (Size < p + 4)
		return TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
	PersistentHandle = Tpm2ReadBe32(In + p); p += 4;

	//
	// ⚠ THE COMMAND MUST END HERE, same rule as CreatePrimary: trailing octets mean the caller
	// sent a field we never read, and SUCCESS would claim we understood it.
	//
	if (p != Size)
		return TPM2_RC_P(TPM2_RC_SIZE, 1);

	//
	// Part 3 rule 3: the persistent range is split by who authorised. Owner gets the bottom half,
	// platform the whole space. This is what keeps the OEM's indices clear of the owner's.
	//
	OwnerLimit = (Auth == TPM2_RH_PLATFORM) ? TPM2_PERSISTENT_LAST : TPM2_PERSISTENT_OWNER_LAST;

	/* ---------------------------------------------------------------- evict an existing one */
	if (ObjectHandle >= TPM2_PERSISTENT_FIRST && ObjectHandle <= TPM2_PERSISTENT_LAST)
	{
		//
		// Part 3 rule 8: objectHandle must be in the range `auth` is allowed to touch.
		//
		if (ObjectHandle > OwnerLimit)
			return TPM2_RC_H(TPM2_RC_RANGE, 2);
		//
		// Part 3 rule 9: "If objectHandle is not the same value as persistentHandle, return
		// TPM_RC_HANDLE." Evicting is not a move -- the two fields name the same object twice, and
		// a caller that disagrees with itself is not making a request the TPM can interpret.
		//
		if (ObjectHandle != PersistentHandle)
			return TPM2_RC_H(TPM2_RC_HANDLE, 2);

		for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		{
			UINT32 j;

			if (!mPersistent[i].Loaded || mPersistent[i].Handle != ObjectHandle)
				continue;
			//
			// Zeroed, not marked free: it holds an RSA private key. Same rule as the transient
			// store, and Part 3 is explicit that the object does NOT come back as a transient one
			// -- "this would prevent the immediate revocation of an object".
			//
			for (j = 0; j < sizeof(mPersistent[i]); j++)
				((UINT8*)&mPersistent[i])[j] = 0;
			goto respond;
		}
		return TPM2_RC_H(TPM2_RC_HANDLE, 2);
	}

	/* ---------------------------------------------------------------- persist a transient one */
	if (ObjectHandle < TPM2_TRANSIENT_FIRST || ObjectHandle >= TPM2_PERSISTENT_FIRST)
		return TPM2_RC_H(TPM2_RC_VALUE, 2);

	Src = Tpm2ObjectFind(ObjectHandle);
	if (Src == NULL)
		return TPM2_RC_H(TPM2_RC_HANDLE, 2);

	//
	// Part 3 rule 2: owner auth covers the STORAGE and ENDORSEMENT hierarchies; platform auth
	// covers only the platform hierarchy.
	//
	// ⚠ THIS IS WHY WINDOWS CAN PERSIST THE EK WITH OWNER AUTH. Both EvictControl commands
	// measured this boot carry authHandle 0x40000001 -- one for the SRK at 0x81000001 and one for
	// the EK at 0x81010001 -- and rule 2 is what makes the second one legal.
	//
	if (Auth == TPM2_RH_PLATFORM)
	{
		if (Src->Hierarchy != TPM2_RH_PLATFORM)
			return TPM2_RC_HIERARCHY;
	}
	else
	{
		if (Src->Hierarchy != TPM2_RH_OWNER && Src->Hierarchy != TPM2_RH_ENDORSEMENT)
			return TPM2_RC_HIERARCHY;
	}

	if (PersistentHandle < TPM2_PERSISTENT_FIRST || PersistentHandle > OwnerLimit)
		return TPM2_RC_P(TPM2_RC_RANGE, 1);

	//
	// Part 3 rule 4. NV_DEFINED is RC_VER1 and carries no field number, which is right: the
	// request is well formed, the destination is simply taken.
	//
	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		if (mPersistent[i].Loaded && mPersistent[i].Handle == PersistentHandle)
			return TPM2_RC_NV_DEFINED;

	//
	// ⚠ stClear OBJECTS CANNOT BE PERSISTED. Part 3 rule 1.2: an object with stClear SET does not
	// survive a TPM Reset, and persisting it would promise durability the object's own attributes
	// deny. Neither captured template sets it, so this refuses nothing Windows sends -- it refuses
	// what a different caller might.
	//
	if ((Src->Public.ObjectAttributes & TPM2_OBJ_ST_CLEAR) != 0)
		return TPM2_RC_ATTRIBUTES;

	Dst = NULL;
	for (i = 0; i < TPM2_MAX_PERSISTENT_OBJECTS; i++)
		if (!mPersistent[i].Loaded)
		{
			Dst = &mPersistent[i];
			break;
		}
	//
	// Part 3 rule 5. Also RC_VER1: the TPM is full, which is not a complaint about any field.
	//
	if (Dst == NULL)
		return TPM2_RC_NV_SPACE;

	//
	// ⚠ A COPY, AND THE TRANSIENT OBJECT SURVIVES IT. Part 3 rule 7: "the object referenced by
	// objectHandle will not be flushed and both objectHandle and persistentHandle may be used to
	// access the object." Windows depends on this -- it persists, then flushes the transient handle
	// separately, and a TPM that consumed the object would leave it flushing something already gone.
	//
	for (i = 0; i < sizeof(*Dst); i++)
		((UINT8*)Dst)[i] = ((CONST UINT8*)Src)[i];
	Dst->Handle = PersistentHandle;
	Dst->Loaded = TRUE;

respond:
	//
	// (!) parameterSize IS PRESENT AND ZERO, NOT ABSENT. Part 1 §18.3: a response with sessions
	// carries a UINT32 parameterSize before the parameters, and "no parameters" means the field
	// says zero rather than the field going away. Omitting it would shift the session area by four
	// octets and tpm.sys would read the acknowledgement out of nothing.
	//
	p = TPM2_HEADER_SIZE;
	if (OutSize < p + 4)
		return TPM2_RC_SIZE;
	Tpm2WriteBe32(Out + p, 0);
	p += 4;

	//
	// The response carries no parameters -- but it DOES carry the session acknowledgement, because
	// the command was tagged SESSIONS.
	//
	Rc = Tpm2SessionWriteResponse(&Sessions, Out + p, OutSize - p, &w);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;
	p += w;

	Tpm2WriteResponseHeader(Out, TPM2_ST_SESSIONS, p, TPM2_RC_SUCCESS);
	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2ObjectEnumerate(
	IN  UINT32  First,
	IN  UINT32  Max,
	OUT UINT32* Handles
	)
{
	CONST UINT32 Type = First >> 24;
	CONST TPM2_OBJECT_SLOT* Store;
	UINT32 Slots;
	UINT32 n = 0;
	UINT32 i;
	UINT32 j;

	if (Handles == NULL || Max == 0)
		return 0;

	//
	// The high octet picks the store. Anything else -- NV, sessions, permanent handles, PCRs --
	// is a range we genuinely hold nothing in, and an empty list is the true answer rather than
	// an unimplemented one.
	//
	if (Type == (TPM2_TRANSIENT_FIRST >> 24))
	{
		Store = mObjects;
		Slots = TPM2_MAX_LOADED_OBJECTS;
	}
	else if (Type == (TPM2_PERSISTENT_FIRST >> 24))
	{
		Store = mPersistent;
		Slots = TPM2_MAX_PERSISTENT_OBJECTS;
	}
	else
	{
		return 0;
	}

	for (i = 0; i < Slots; i++)
	{
		UINT32 H;

		if (!Store[i].Loaded || Store[i].Handle < First)
			continue;
		if (n >= Max)
			break;

		//
		// ⚠ INSERTED IN ORDER, because `property` is a STARTING handle and paging through a list
		// only works if the order is stable and increasing. Slots are in allocation order, so a
		// caller that asked for everything from 0x81000002 onward could otherwise be handed
		// 0x81000001. An insertion sort over at most seven entries is not worth avoiding.
		//
		H = Store[i].Handle;
		for (j = n; j > 0 && Handles[j - 1] > H; j--)
			Handles[j] = Handles[j - 1];
		Handles[j] = H;
		n++;
	}
	return n;
}
