/**
 * @file Tpm2Hash.c
 * @brief Crypto-agile hash dispatch and HMAC (FIPS 198-1). See Tpm2Hash.h for why.
 *
 * ⚠ EVERY ENTRY POINT REFUSES AN ALGORITHM IT DOES NOT IMPLEMENT, and none of them falls back.
 * The temptation in a dispatch like this is a `default:` that does something reasonable; here the
 * only reasonable thing is to fail, because a caller that asked for SHA-384 will label whatever
 * comes back as SHA-384.
 */

#include "Tpm2Hash.h"

UINT16
Tpm2HashSize(
	IN UINT16 Alg
	)
{
	switch (Alg)
	{
	case TPM2_ALG_SHA256: return SHA256_DIGEST_SIZE;
	case TPM2_ALG_SHA384: return SHA384_DIGEST_SIZE;
	case TPM2_ALG_SHA512: return SHA512_DIGEST_SIZE;
	default:              return 0;
	}
}

UINT16
Tpm2HashBlockSize(
	IN UINT16 Alg
	)
{
	switch (Alg)
	{
	case TPM2_ALG_SHA256: return SHA256_BLOCK_SIZE;    /* 64  */
	case TPM2_ALG_SHA384: return SHA512_BLOCK_SIZE;    /* 128 -- SHA-384 uses the SHA-512 block */
	case TPM2_ALG_SHA512: return SHA512_BLOCK_SIZE;    /* 128 */
	default:              return 0;
	}
}

BOOLEAN
Tpm2HashInit(
	OUT TPM2_HASH_CONTEXT* Ctx,
	IN  UINT16             Alg
	)
{
	if (Ctx == NULL)
		return FALSE;

	Ctx->Alg = 0;         /* until proven otherwise, so a failed init cannot be Updated into */

	switch (Alg)
	{
	case TPM2_ALG_SHA256: Sha256Init(&Ctx->U.S256); break;
	case TPM2_ALG_SHA384: Sha384Init(&Ctx->U.S512); break;
	case TPM2_ALG_SHA512: Sha512Init(&Ctx->U.S512); break;
	default:              return FALSE;
	}

	Ctx->Alg = Alg;
	return TRUE;
}

VOID
Tpm2HashUpdate(
	IN OUT TPM2_HASH_CONTEXT* Ctx,
	IN     CONST VOID*        Data,
	IN     UINTN              Length
	)
{
	if (Ctx == NULL)
		return;

	switch (Ctx->Alg)
	{
	case TPM2_ALG_SHA256: Sha256Update(&Ctx->U.S256, Data, Length); break;
	case TPM2_ALG_SHA384:
	case TPM2_ALG_SHA512: Sha512Update(&Ctx->U.S512, Data, Length); break;
	default:              break;      /* uninitialised or unsupported: nothing to update */
	}
}

BOOLEAN
Tpm2HashFinal(
	IN OUT TPM2_HASH_CONTEXT* Ctx,
	OUT    UINT8*             Digest
	)
{
	if (Ctx == NULL || Digest == NULL)
		return FALSE;

	switch (Ctx->Alg)
	{
	case TPM2_ALG_SHA256: Sha256Final(&Ctx->U.S256, Digest); return TRUE;
	case TPM2_ALG_SHA384: Sha384Final(&Ctx->U.S512, Digest); return TRUE;
	case TPM2_ALG_SHA512: Sha512Final(&Ctx->U.S512, Digest); return TRUE;
	default:              return FALSE;
	}
}

BOOLEAN
Tpm2Hash(
	IN  UINT16      Alg,
	IN  CONST VOID* Data,
	IN  UINTN       Length,
	OUT UINT8*      Digest
	)
{
	TPM2_HASH_CONTEXT Ctx;

	if (!Tpm2HashInit(&Ctx, Alg))
		return FALSE;
	Tpm2HashUpdate(&Ctx, Data, Length);
	return Tpm2HashFinal(&Ctx, Digest);
}

//
// ---------------------------------------------------------------------------------------------
// HMAC -- FIPS 198-1
//
//     MAC = H( (K0 ^ opad) || H( (K0 ^ ipad) || text ) )
//
// where K0 is the key hashed down if it is longer than the block, then zero-padded up to the
// block. Both of those are step 2 of §4, and both are easy to get subtly wrong in a way that
// still produces a stable-looking MAC.
// ---------------------------------------------------------------------------------------------
//

#define HMAC_IPAD  0x36
#define HMAC_OPAD  0x5C

BOOLEAN
Tpm2HmacInit(
	OUT TPM2_HMAC_CONTEXT* Ctx,
	IN  UINT16             Alg,
	IN  CONST UINT8*       Key,
	IN  UINTN              KeyLen
	)
{
	UINT8        K0[TPM2_MAX_BLOCK_SIZE];
	UINT8        Pad[TPM2_MAX_BLOCK_SIZE];
	CONST UINT16 Block = Tpm2HashBlockSize(Alg);
	UINT16       i;

	if (Ctx == NULL || Block == 0 || (Key == NULL && KeyLen != 0))
		return FALSE;

	Ctx->Alg = 0;

	for (i = 0; i < Block; i++)
		K0[i] = 0;

	if (KeyLen > (UINTN)Block)
	{
		//
		// ⚠ HASHED, NOT TRUNCATED (FIPS 198-1 §4 step 2). Truncation is the intuitive reading and
		// produces a completely different MAC that still verifies against itself -- so it would
		// pass any self-consistent test and fail against every other implementation.
		//
		if (!Tpm2Hash(Alg, Key, KeyLen, K0))
			return FALSE;
	}
	else
	{
		for (i = 0; i < (UINT16)KeyLen; i++)
			K0[i] = Key[i];
		/* the remainder stays zero -- zero-PADDED, not key-repeated */
	}

	/* inner: H( (K0 ^ ipad) || text ) -- started here, fed by Update */
	for (i = 0; i < Block; i++)
		Pad[i] = (UINT8)(K0[i] ^ HMAC_IPAD);
	if (!Tpm2HashInit(&Ctx->Inner, Alg))
		return FALSE;
	Tpm2HashUpdate(&Ctx->Inner, Pad, Block);

	/* outer key kept for Final; the outer hash cannot start until the inner digest exists */
	for (i = 0; i < Block; i++)
		Ctx->OuterKey[i] = (UINT8)(K0[i] ^ HMAC_OPAD);

	Ctx->Alg = Alg;
	return TRUE;
}

VOID
Tpm2HmacUpdate(
	IN OUT TPM2_HMAC_CONTEXT* Ctx,
	IN     CONST VOID*        Data,
	IN     UINTN              Length
	)
{
	if (Ctx == NULL || Ctx->Alg == 0)
		return;
	Tpm2HashUpdate(&Ctx->Inner, Data, Length);
}

BOOLEAN
Tpm2HmacFinal(
	IN OUT TPM2_HMAC_CONTEXT* Ctx,
	OUT    UINT8*             Mac
	)
{
	UINT8             InnerDigest[TPM2_MAX_DIGEST_SIZE];
	TPM2_HASH_CONTEXT Outer;
	CONST UINT16      Block = (Ctx != NULL) ? Tpm2HashBlockSize(Ctx->Alg) : 0;
	CONST UINT16      Size  = (Ctx != NULL) ? Tpm2HashSize(Ctx->Alg) : 0;

	if (Ctx == NULL || Mac == NULL || Block == 0 || Size == 0)
		return FALSE;

	if (!Tpm2HashFinal(&Ctx->Inner, InnerDigest))
		return FALSE;

	if (!Tpm2HashInit(&Outer, Ctx->Alg))
		return FALSE;
	Tpm2HashUpdate(&Outer, Ctx->OuterKey, Block);
	Tpm2HashUpdate(&Outer, InnerDigest, Size);
	return Tpm2HashFinal(&Outer, Mac);
}

BOOLEAN
Tpm2Hmac(
	IN  UINT16      Alg,
	IN  CONST UINT8* Key,
	IN  UINTN       KeyLen,
	IN  CONST VOID* Data,
	IN  UINTN       Length,
	OUT UINT8*      Mac
	)
{
	TPM2_HMAC_CONTEXT Ctx;

	if (!Tpm2HmacInit(&Ctx, Alg, Key, KeyLen))
		return FALSE;
	Tpm2HmacUpdate(&Ctx, Data, Length);
	return Tpm2HmacFinal(&Ctx, Mac);
}
