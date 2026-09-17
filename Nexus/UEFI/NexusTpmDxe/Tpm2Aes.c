/**
 * @file Tpm2Aes.c
 *
 * AES (FIPS-197) and CFB mode (NIST SP 800-38A). See Tpm2Aes.h for why a TPM that had no demand
 * for a symmetric cipher now has one.
 *
 * (!) THE S-BOX IN THIS FILE WAS COMPUTED, NOT TYPED. FIPS-197 defines it as the multiplicative
 * inverse in GF(2^8) followed by an affine transform, and a generator produced these 256 octets
 * from that definition, asserting three published facts before emitting anything: row 0 matches
 * Figure 7, S(0x53) = 0xED matches the worked example, and the table is a bijection. A
 * hand-transcribed S-box is one of the classic sources of an AES that encrypts happily and agrees
 * with nobody, and the test suite recomputes the whole table from the definition anyway.
 *
 * (!) THIS IS NOT A CONSTANT-TIME IMPLEMENTATION, and saying so is part of the contract. It is
 * byte-oriented over a 256-octet S-box, so it has the cache-timing exposure every table-driven
 * AES has. The design notes already state that the object cache this protects is NOT
 * a security boundary -- the seeds sit in region B in plain RAM for the whole boot regardless.
 * This raises the floor. Claiming more would be the dishonest part.
 */

#include "Tpm2Aes.h"

//
// FIPS-197 Figure 7. Computed from the definition by the generator described above.
//
STATIC CONST UINT8 mSbox[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

//
// FIPS-197 Figure 11: the round constants, powers of x in GF(2^8).
//
STATIC CONST UINT8 mRcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, };

CONST UINT8* Tpm2AesSbox(VOID)
{
	return mSbox;
}

/**
 * Multiply by x in GF(2^8) modulo the AES reduction polynomial, FIPS-197 section 4.2.1.
 *
 * (!) THE REDUCTION IS UNCONDITIONAL IN FORM, CONDITIONAL IN EFFECT. Writing it as a branch on
 * the high bit is the same arithmetic, but a mask keeps one shape for both cases; 0x1B is the
 * low octet of the polynomial x^8 + x^4 + x^3 + x + 1.
 */
STATIC UINT8 XTime(IN UINT8 A)
{
	return (UINT8)(((A << 1) & 0xFF) ^ (((A >> 7) & 1) * 0x1B));
}

STATIC VOID SubBytes(IN OUT UINT8 S[16])
{
	UINT32 i;
	for (i = 0; i < 16; i++)
		S[i] = mSbox[S[i]];
}

/**
 * FIPS-197 section 5.1.2. The state is column-major: S[r + 4c] is row r, column c, so row r shifts
 * left by r BYTES OF STRIDE FOUR, not by r positions in the array.
 *
 * (!) THIS IS THE STEP THAT SILENTLY "WORKS" WHEN IT IS WRONG. A ShiftRows that rotates the array
 * rather than the rows still produces a bijective, avalanche-looking cipher that round-trips
 * against its own inverse. Only an external vector catches it, which is what the suite uses.
 */
STATIC VOID ShiftRows(IN OUT UINT8 S[16])
{
	UINT8 t;

	/* row 1: left by 1 */
	t = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = t;

	/* row 2: left by 2 */
	t = S[2];  S[2]  = S[10]; S[10] = t;
	t = S[6];  S[6]  = S[14]; S[14] = t;

	/* row 3: left by 3, which is right by 1 */
	t = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = t;
}

/**
 * FIPS-197 section 5.1.3: each column is multiplied by the fixed polynomial
 * {03}x^3 + {01}x^2 + {01}x + {02} in GF(2^8).
 */
STATIC VOID MixColumns(IN OUT UINT8 S[16])
{
	UINT32 c;

	for (c = 0; c < 4; c++)
	{
		UINT8* p = S + 4 * c;
		UINT8  a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
		UINT8  x  = (UINT8)(a0 ^ a1 ^ a2 ^ a3);

		p[0] ^= (UINT8)(x ^ XTime((UINT8)(a0 ^ a1)));
		p[1] ^= (UINT8)(x ^ XTime((UINT8)(a1 ^ a2)));
		p[2] ^= (UINT8)(x ^ XTime((UINT8)(a2 ^ a3)));
		p[3] ^= (UINT8)(x ^ XTime((UINT8)(a3 ^ a0)));
	}
}

STATIC VOID AddRoundKey(IN OUT UINT8 S[16], IN CONST UINT32* Rk)
{
	UINT32 c;

	for (c = 0; c < 4; c++)
	{
		UINT32 w = Rk[c];

		//
		// (!) BIG-ENDIAN BY CONSTRUCTION, NOT BY HOST LUCK. The key schedule stores each word as
		// an integer whose most significant octet is the FIRST octet of the key, so unpacking has
		// to shift rather than alias. A memcpy over a UINT32 would produce a cipher that agrees
		// with itself on this machine and with nothing on a big-endian one.
		//
		S[4 * c + 0] ^= (UINT8)(w >> 24);
		S[4 * c + 1] ^= (UINT8)(w >> 16);
		S[4 * c + 2] ^= (UINT8)(w >> 8);
		S[4 * c + 3] ^= (UINT8)(w);
	}
}

STATIC UINT32 SubWord(IN UINT32 W)
{
	return ((UINT32)mSbox[(W >> 24) & 0xFF] << 24)
	     | ((UINT32)mSbox[(W >> 16) & 0xFF] << 16)
	     | ((UINT32)mSbox[(W >> 8)  & 0xFF] << 8)
	     | ((UINT32)mSbox[(W)       & 0xFF]);
}

STATIC UINT32 RotWord(IN UINT32 W)
{
	return (W << 8) | (W >> 24);
}

BOOLEAN
Tpm2AesSetKey(
	OUT TPM2_AES_KEY* Key,
	IN  CONST UINT8*  KeyBytes,
	IN  UINT32        KeyBits
	)
{
	UINT32 Nk;
	UINT32 Nr;
	UINT32 i;
	UINT32 Total;

	if (Key == NULL)
		return FALSE;

	Key->Valid  = FALSE;
	Key->Rounds = 0;

	if (KeyBytes == NULL)
		return FALSE;

	//
	// FIPS-197 Figure 4. Nk words of key, Nr rounds. Three legal pairs and no others -- see the
	// header on why an unsupported length is refused rather than rounded to one that fits.
	//
	switch (KeyBits)
	{
	case 128: Nk = 4; Nr = 10; break;
	case 192: Nk = 6; Nr = 12; break;
	case 256: Nk = 8; Nr = 14; break;
	default:  return FALSE;
	}

	for (i = 0; i < Nk; i++)
		Key->RoundKey[i] = ((UINT32)KeyBytes[4 * i]     << 24)
		                 | ((UINT32)KeyBytes[4 * i + 1] << 16)
		                 | ((UINT32)KeyBytes[4 * i + 2] << 8)
		                 | ((UINT32)KeyBytes[4 * i + 3]);

	Total = 4 * (Nr + 1);
	for (i = Nk; i < Total; i++)
	{
		UINT32 T = Key->RoundKey[i - 1];

		if ((i % Nk) == 0)
		{
			T = SubWord(RotWord(T)) ^ ((UINT32)mRcon[(i / Nk) - 1] << 24);
		}
		//
		// (!) THE 256-BIT-ONLY EXTRA SubWord, AND IT IS THE ONE EVERY AES GETS WRONG FIRST.
		// FIPS-197 section 5.2: "for Nk = 8 and i-4 a multiple of Nk", an additional SubWord is
		// applied. A schedule that omits it produces a perfectly functional cipher that is not
		// AES-256, and every AES-128 and AES-192 vector still passes -- so the suite pins all
		// three key lengths rather than assuming one generalises.
		//
		else if (Nk > 6 && (i % Nk) == 4)
		{
			T = SubWord(T);
		}

		Key->RoundKey[i] = Key->RoundKey[i - Nk] ^ T;
	}

	Key->Rounds = Nr;
	Key->Valid  = TRUE;
	return TRUE;
}

VOID
Tpm2AesEncryptBlock(
	IN  CONST TPM2_AES_KEY* Key,
	IN  CONST UINT8         In[TPM2_AES_BLOCK_SIZE],
	OUT UINT8               Out[TPM2_AES_BLOCK_SIZE]
	)
{
	UINT8  S[16];
	UINT32 Round;
	UINT32 i;

	if (Key == NULL || !Key->Valid || In == NULL || Out == NULL)
		return;

	for (i = 0; i < 16; i++)
		S[i] = In[i];

	//
	// FIPS-197 section 5.1. The LAST round has no MixColumns -- without that asymmetry decryption
	// could not be expressed as the inverse rounds in reverse order.
	//
	AddRoundKey(S, &Key->RoundKey[0]);
	for (Round = 1; Round < Key->Rounds; Round++)
	{
		SubBytes(S);
		ShiftRows(S);
		MixColumns(S);
		AddRoundKey(S, &Key->RoundKey[4 * Round]);
	}
	SubBytes(S);
	ShiftRows(S);
	AddRoundKey(S, &Key->RoundKey[4 * Key->Rounds]);

	for (i = 0; i < 16; i++)
		Out[i] = S[i];
}

/**
 * CFB, both directions. SP 800-38A section 6.3 with s = b = 128.
 *
 * (!) ONE ROUTINE, ONE FLAG, BECAUSE THE TWO DIRECTIONS DIFFER IN EXACTLY ONE PLACE: what goes
 * into the feedback register. Encrypt feeds back what it just produced; decrypt feeds back what
 * it just consumed. Writing them as two functions invites the bodies to drift apart, and the
 * difference is a single assignment.
 */
STATIC BOOLEAN CfbCrypt(
	IN     CONST TPM2_AES_KEY* Key,
	IN OUT UINT8               Iv[TPM2_AES_BLOCK_SIZE],
	IN     CONST UINT8*        In,
	IN     UINT32              Len,
	OUT    UINT8*              Out,
	IN     BOOLEAN             Encrypting
	)
{
	UINT8  Stream[TPM2_AES_BLOCK_SIZE];
	UINT32 Done = 0;

	if (Key == NULL || !Key->Valid || Iv == NULL)
		return FALSE;
	if (Len != 0 && (In == NULL || Out == NULL))
		return FALSE;

	while (Done < Len)
	{
		UINT32 n = Len - Done;
		UINT32 i;

		if (n > TPM2_AES_BLOCK_SIZE)
			n = TPM2_AES_BLOCK_SIZE;

		Tpm2AesEncryptBlock(Key, Iv, Stream);

		for (i = 0; i < n; i++)
		{
			UINT8 c = (UINT8)(In[Done + i] ^ Stream[i]);

			//
			// The feedback octet is the CIPHERTEXT in both directions: `c` when encrypting, the
			// input when decrypting. Captured BEFORE the store, because Out may alias In.
			//
			Iv[i] = Encrypting ? c : In[Done + i];
			Out[Done + i] = c;
		}

		//
		// (!) A SHORT CHUNK ENDS THE STREAM, AND THE HEADER'S CONTRACT SAYS SO BECAUSE A TEST MADE
		// IT SAY SO. When n < 16 only the first n octets of the feedback register are replaced,
		// because only n octets of ciphertext exist to replace them with. CFB128 needs a WHOLE
		// block of feedback to continue, so there is nothing honest to carry into a next call --
		// the caller must not make one. Chunks of 16/32/16/36 chain exactly; 7/9/16/68 do not.
		//
		// Manufacturing the missing octets -- by re-encrypting, or by keeping the stale tail --
		// would produce a stream that looks plausible and matches no other CFB implementation.
		//
		Done += n;
	}

	return TRUE;
}

BOOLEAN
Tpm2AesCfbEncrypt(
	IN     CONST TPM2_AES_KEY* Key,
	IN OUT UINT8               Iv[TPM2_AES_BLOCK_SIZE],
	IN     CONST UINT8*        In,
	IN     UINT32              Len,
	OUT    UINT8*              Out
	)
{
	return CfbCrypt(Key, Iv, In, Len, Out, TRUE);
}

BOOLEAN
Tpm2AesCfbDecrypt(
	IN     CONST TPM2_AES_KEY* Key,
	IN OUT UINT8               Iv[TPM2_AES_BLOCK_SIZE],
	IN     CONST UINT8*        In,
	IN     UINT32              Len,
	OUT    UINT8*              Out
	)
{
	return CfbCrypt(Key, Iv, In, Len, Out, FALSE);
}
