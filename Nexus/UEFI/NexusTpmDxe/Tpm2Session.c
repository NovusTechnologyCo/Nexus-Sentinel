/**
 * @file Tpm2Session.c
 * @brief The command authorization area, and password authorization. See Tpm2Session.h.
 *
 * ⚠ THE VECTOR IS THE 29-OCTET AUTHORIZATION WINDOWS ACTUALLY SENDS, captured with both
 * TPM2_CreatePrimary calls: TPM_RS_PW, empty nonce, zero attributes, and twenty zero octets of
 * authValue that Part 1's trailing-zero rule turns into the empty authorisation.
 */

#include "Tpm2Session.h"

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

UINT16
Tpm2AuthTrim(
	IN CONST UINT8* Auth,
	IN UINT16       Len
	)
{
	if (Auth == NULL)
		return 0;
	while (Len > 0 && Auth[Len - 1] == 0)
		Len--;
	return Len;
}

BOOLEAN
Tpm2AuthEqual(
	IN CONST UINT8* A, IN UINT16 ALen,
	IN CONST UINT8* B, IN UINT16 BLen
	)
{
	UINT16 i;

	//
	// ⚠ BOTH SIDES ARE TRIMMED, NOT JUST THE CALLER'S. Part 1 §16.4: "The TPM truncates any octets
	// of zero on either of the two values before they are compared." Trimming one side would mean
	// an entity whose stored authValue ends in a zero octet rejects the very password that set it,
	// and the bug would be invisible for every authValue that happens not to end in zero.
	//
	ALen = Tpm2AuthTrim(A, ALen);
	BLen = Tpm2AuthTrim(B, BLen);

	if (ALen != BLen)
		return FALSE;
	for (i = 0; i < ALen; i++)
		if (A[i] != B[i])
			return FALSE;
	return TRUE;
}

UINT32
Tpm2SessionParse(
	IN  CONST UINT8*        In,
	IN  UINT32              InLen,
	OUT TPM2_SESSION_AREA*  Area,
	OUT UINT32*             Used
	)
{
	UINT32 Size;
	UINT32 p;
	UINT32 End;
	UINT32 i;

	if (In == NULL || Area == NULL)
		return TPM2_RC_FAILURE;

	for (i = 0; i < sizeof(*Area); i++)
		((UINT8*)Area)[i] = 0;

	if (InLen < 4)
		return TPM2_RC_INSUFFICIENT;
	Size = Be32(In);

	//
	// ⚠ THE DECLARED SIZE IS CHECKED AGAINST WHAT ARRIVED BEFORE IT IS TRUSTED. Part 2 gives
	// TPM_RC_AUTHSIZE for an authorizationSize out of range, and this is the one place in the
	// command where a declaration is being checked rather than octets being consumed -- so it is
	// AUTHSIZE here and INSUFFICIENT everywhere else, which is the distinction hardware taught us.
	//
	if (Size < 9 || Size > InLen - 4)
		return TPM2_RC_AUTHSIZE;

	Area->AreaSize = Size;
	p = 4;
	End = 4 + Size;

	while (p < End)
	{
		TPM2_AUTH_SESSION* S;
		UINT32 Num;

		if (Area->Count >= TPM2_MAX_SESSIONS)
			return TPM2_RC_AUTHSIZE;

		S = &Area->S[Area->Count];
		Num = Area->Count + 1;              /* one-based, for the response code */

		//
		// Each session: handle, nonce, attributes, hmac. Every read is bounded by End rather than
		// by InLen, so a session that claims to run past the declared area is caught here and not
		// by whatever field happens to follow it.
		//
		if (p + 4 > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		S->Handle = Be32(In + p); p += 4;

		if (p + 2 > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		S->NonceLen = Be16(In + p); p += 2;
		if (S->NonceLen > sizeof(S->Nonce))
			return TPM2_RC_S(TPM2_RC_SIZE, Num);
		if (p + S->NonceLen > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		for (i = 0; i < S->NonceLen; i++)
			S->Nonce[i] = In[p + i];
		p += S->NonceLen;

		if (p + 1 > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		S->Attributes = In[p]; p += 1;

		if (p + 2 > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		S->AuthLen = Be16(In + p); p += 2;
		if (S->AuthLen > sizeof(S->Auth))
			return TPM2_RC_S(TPM2_RC_SIZE, Num);
		if (p + S->AuthLen > End)
			return TPM2_RC_S(TPM2_RC_INSUFFICIENT, Num);
		for (i = 0; i < S->AuthLen; i++)
			S->Auth[i] = In[p + i];
		p += S->AuthLen;

		Area->Count++;
	}

	//
	// (!) THE AREA MUST END EXACTLY. p can only exceed End if a length field walked past it, and
	// every such case is caught above -- but the equality is asserted rather than assumed, because
	// "close enough" here means the first parameter is read from the middle of a session.
	//
	if (p != End)
		return TPM2_RC_AUTHSIZE;
	if (Area->Count == 0)
		return TPM2_RC_AUTHSIZE;

	if (Used != NULL)
		*Used = End;
	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2SessionAuthorize(
	IN CONST TPM2_AUTH_SESSION* Session,
	IN UINT32                   Index,
	IN CONST UINT8*             AuthValue,
	IN UINT16                   AuthValueLen
	)
{
	UINT32 Num = Index + 1;

	if (Session == NULL)
		return TPM2_RC_FAILURE;

	//
	// ⚠ ONLY TPM_RS_PW IS ACCEPTED, AND THE REFUSAL IS HONEST. HMAC and policy sessions need
	// TPM2_StartAuthSession, session contexts, rolling nonces and a full HMAC computation, none of
	// which exist yet. Accepting the handle and skipping the check would be an authorisation that
	// always succeeds -- the worst possible stub in the worst possible place.
	//
	if (Session->Handle != TPM2_RS_PW)
		return TPM2_RC_S(TPM2_RC_HANDLE, Num);

	//
	// Part 1 Table 20: nonceCaller is "required to be an Empty Buffer" for a password.
	//
	if (Session->NonceLen != 0)
		return TPM2_RC_S(TPM2_RC_VALUE, Num);

	//
	// Part 1 §16.4: "sessionAttributes.continueSession is ignored" for a password, and Table 20
	// says only continueSession may be SET. Anything else is a caller error rather than something
	// to tolerate silently.
	//
	// (!) MASKED TO ONE OCTET BEFORE THE CAST. `(UINT8)~TPM2_SESSION_CONTINUE` gives the right
	// answer and earns MSVC's C4310 "cast truncates constant value", because ~ promotes to int
	// first and 0xFFFFFFFE really is being truncated. The warning is correct even though the
	// result is not, and a firmware build with warnings in it is a build nobody reads.
	if ((Session->Attributes & (UINT8)(0xFFu & ~(UINT32)TPM2_SESSION_CONTINUE)) != 0)
		return TPM2_RC_S(TPM2_RC_VALUE, Num);

	if (!Tpm2AuthEqual(Session->Auth, Session->AuthLen, AuthValue, AuthValueLen))
		return TPM2_RC_S(TPM2_RC_AUTH_FAIL, Num);

	return TPM2_RC_SUCCESS;
}

UINT32
Tpm2SessionWriteResponse(
	IN  CONST TPM2_SESSION_AREA* Area,
	OUT UINT8*                   Out,
	IN  UINT32                   OutLen,
	OUT UINT32*                  Written
	)
{
	UINT32 p = 0;
	UINT32 i;

	if (Area == NULL || Out == NULL)
		return TPM2_RC_FAILURE;

	//
	// Part 1 Table 21, one acknowledgement per command session, in order: an empty nonceTPM, the
	// command's flags with continueSession SET, and an empty hmac. Five octets each.
	//
	for (i = 0; i < Area->Count; i++)
	{
		if (p + 5 > OutLen)
			return TPM2_RC_SIZE;

		Out[p++] = 0; Out[p++] = 0;                 /* nonceTPM: zero-length            */
		//
		// ⚠ "COPY OF THE FLAGS FROM THE COMMAND, continueSession WILL BE SET" -- Part 1 Table 21,
		// and both halves matter. Echoing the flags unchanged would clear continueSession whenever
		// the caller did; hard-coding 0x01 would drop any other flag the caller set.
		//
		Out[p++] = (UINT8)(Area->S[i].Attributes | TPM2_SESSION_CONTINUE);
		Out[p++] = 0; Out[p++] = 0;                 /* hmac: zero-length                */
	}

	if (Written != NULL)
		*Written = p;
	return TPM2_RC_SUCCESS;
}
