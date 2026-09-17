/**
 * @file Sha512.c
 * @brief SHA-512 / SHA-384, FIPS 180-4 §6.4 and §6.5. Dependency-free by contract (see Sha512.h).
 *
 * The structure mirrors Sha256.c deliberately: same buffering discipline, same big-endian I/O
 * helpers written byte-wise, same absence of library calls. Differences from SHA-256 are exactly
 * the ones FIPS specifies -- 64-bit words, 80 rounds, different rotation amounts, a 128-bit length
 * field -- and nothing else.
 *
 * ⚠ EVERY CONSTANT HERE IS A SILENT-FAILURE SURFACE. A single wrong digit in K[] or in an IV
 * produces a hash that is well-formed, deterministic, and wrong, and no amount of reading catches
 * it reliably. That is why the host check against `hashlib` is not optional garnish: it is the
 * only thing standing between a typo and a PCR nobody can reproduce.
 */

#include "Sha512.h"

//
// FIPS 180-4 §4.2.3: first 64 bits of the fractional parts of the cube roots of the first 80
// primes.
//
STATIC CONST UINT64 K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

//
// (!) THE _64 SUFFIXES ARE NOT DECORATION. Sha256.c defines BSIG0/BSIG1/SSIG0/SSIG1/CH/MAJ with
// the SAME NAMES and 32-bit semantics. Separate translation units in the firmware build, so the
// collision is invisible there -- but the host validation compiles both .c files into ONE unit,
// and a macro-redefinition warning in the harness is exactly the kind of noise that hides a real
// warning later. Distinct names cost nothing and remove the hazard entirely.
//
#define ROTR64(x, n)  (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x, n)   ((x) >> (n))

#define CH64(x, y, z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ64(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* FIPS 180-4 §4.1.3 -- note the rotation amounts differ from SHA-256 throughout. */
#define BSIG0_64(x)      (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define BSIG1_64(x)      (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SSIG0_64(x)      (ROTR64(x,  1) ^ ROTR64(x,  8) ^ SHR64(x, 7))
#define SSIG1_64(x)      (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6))

/*
 * Big-endian load/store, written byte-wise on purpose: no unaligned 64-bit access, and no
 * dependence on the host's endianness. The same reasoning as Tpm2Core.c's wire-format accessors.
 */
STATIC
UINT64
BeRead64(
	IN CONST UINT8* P
	)
{
	return ((UINT64)P[0] << 56) | ((UINT64)P[1] << 48) | ((UINT64)P[2] << 40) |
	       ((UINT64)P[3] << 32) | ((UINT64)P[4] << 24) | ((UINT64)P[5] << 16) |
	       ((UINT64)P[6] <<  8) | ((UINT64)P[7]);
}

STATIC
VOID
BeWrite64(
	OUT UINT8*  P,
	IN  UINT64  V
	)
{
	P[0] = (UINT8)(V >> 56); P[1] = (UINT8)(V >> 48);
	P[2] = (UINT8)(V >> 40); P[3] = (UINT8)(V >> 32);
	P[4] = (UINT8)(V >> 24); P[5] = (UINT8)(V >> 16);
	P[6] = (UINT8)(V >>  8); P[7] = (UINT8)(V);
}

STATIC
VOID
Sha512Compress(
	IN OUT UINT64      State[8],
	IN     CONST UINT8 Block[SHA512_BLOCK_SIZE]
	)
{
	UINT64 W[80];
	UINT64 a, b, c, d, e, f, g, h;
	UINT32 t;

	for (t = 0; t < 16; t++)
		W[t] = BeRead64(Block + t * 8);
	for (t = 16; t < 80; t++)
		W[t] = SSIG1_64(W[t - 2]) + W[t - 7] + SSIG0_64(W[t - 15]) + W[t - 16];

	a = State[0]; b = State[1]; c = State[2]; d = State[3];
	e = State[4]; f = State[5]; g = State[6]; h = State[7];

	for (t = 0; t < 80; t++)
	{
		CONST UINT64 T1 = h + BSIG1_64(e) + CH64(e, f, g) + K[t] + W[t];
		CONST UINT64 T2 = BSIG0_64(a) + MAJ64(a, b, c);
		h = g; g = f; f = e;
		e = d + T1;
		d = c; c = b; b = a;
		a = T1 + T2;
	}

	State[0] += a; State[1] += b; State[2] += c; State[3] += d;
	State[4] += e; State[5] += f; State[6] += g; State[7] += h;
}

VOID
Sha512Init(
	OUT SHA512_CONTEXT* Context
	)
{
	UINT32 i;

	if (Context == NULL)
		return;

	/* FIPS 180-4 §5.3.5 -- fractional parts of the square roots of the first 8 primes. */
	Context->State[0] = 0x6a09e667f3bcc908ULL;
	Context->State[1] = 0xbb67ae8584caa73bULL;
	Context->State[2] = 0x3c6ef372fe94f82bULL;
	Context->State[3] = 0xa54ff53a5f1d36f1ULL;
	Context->State[4] = 0x510e527fade682d1ULL;
	Context->State[5] = 0x9b05688c2b3e6c1fULL;
	Context->State[6] = 0x1f83d9abfb41bd6bULL;
	Context->State[7] = 0x5be0cd19137e2179ULL;

	Context->BitLength  = 0;
	Context->BlockLength = 0;
	for (i = 0; i < SHA512_BLOCK_SIZE; i++)
		Context->Block[i] = 0;
}

VOID
Sha384Init(
	OUT SHA512_CONTEXT* Context
	)
{
	UINT32 i;

	if (Context == NULL)
		return;

	/*
	 * FIPS 180-4 §5.3.4 -- fractional parts of the square roots of the 9th through 16th primes.
	 * ⚠ A DIFFERENT IV, not a truncation. SHA-384 of a message is NOT the first 48 bytes of its
	 * SHA-512; sharing this table with Sha512Init would be a wrong answer shaped like a right one.
	 */
	Context->State[0] = 0xcbbb9d5dc1059ed8ULL;
	Context->State[1] = 0x629a292a367cd507ULL;
	Context->State[2] = 0x9159015a3070dd17ULL;
	Context->State[3] = 0x152fecd8f70e5939ULL;
	Context->State[4] = 0x67332667ffc00b31ULL;
	Context->State[5] = 0x8eb44a8768581511ULL;
	Context->State[6] = 0xdb0c2e0d64f98fa7ULL;
	Context->State[7] = 0x47b5481dbefa4fa4ULL;

	Context->BitLength  = 0;
	Context->BlockLength = 0;
	for (i = 0; i < SHA512_BLOCK_SIZE; i++)
		Context->Block[i] = 0;
}

VOID
Sha512Update(
	IN OUT SHA512_CONTEXT* Context,
	IN     CONST VOID*     Data,
	IN     UINTN           Length
	)
{
	CONST UINT8* P = (CONST UINT8*)Data;
	UINTN        i;

	if (Context == NULL || (Data == NULL && Length != 0))
		return;

	for (i = 0; i < Length; i++)
	{
		Context->Block[Context->BlockLength++] = P[i];
		if (Context->BlockLength == SHA512_BLOCK_SIZE)
		{
			Sha512Compress(Context->State, Context->Block);
			Context->BitLength += SHA512_BLOCK_SIZE * 8;
			Context->BlockLength = 0;
		}
	}
}

/*
 * Shared finalisation. Pads, appends the 128-bit length, and writes `Words` state words out.
 * SHA-512 asks for 8, SHA-384 for 6 -- which is where the 64- and 48-byte digests come from.
 */
STATIC
VOID
Sha512FinalCommon(
	IN OUT SHA512_CONTEXT* Context,
	OUT    UINT8*          Digest,
	IN     UINT32          Words
	)
{
	UINTN  i = Context->BlockLength;
	UINT64 TotalBits;
	UINT32 w;

	TotalBits = Context->BitLength + (UINT64)Context->BlockLength * 8;

	/* FIPS 180-4 §5.1.2: a single 1 bit, then zeros, leaving 16 bytes for the length. */
	Context->Block[i++] = 0x80;
	if (i > SHA512_BLOCK_SIZE - 16)
	{
		while (i < SHA512_BLOCK_SIZE)
			Context->Block[i++] = 0;
		Sha512Compress(Context->State, Context->Block);
		i = 0;
	}
	while (i < SHA512_BLOCK_SIZE - 16)
		Context->Block[i++] = 0;

	/*
	 * The length is 128 bits big-endian. The high 64 are always zero here -- see the header: exact
	 * for any message below 2^64 bits, and this project has no caller that can exceed it.
	 */
	BeWrite64(Context->Block + SHA512_BLOCK_SIZE - 16, 0);
	BeWrite64(Context->Block + SHA512_BLOCK_SIZE -  8, TotalBits);
	Sha512Compress(Context->State, Context->Block);

	for (w = 0; w < Words; w++)
		BeWrite64(Digest + w * 8, Context->State[w]);
}

VOID
Sha512Final(
	IN OUT SHA512_CONTEXT* Context,
	OUT    UINT8           Digest[SHA512_DIGEST_SIZE]
	)
{
	if (Context == NULL || Digest == NULL)
		return;
	Sha512FinalCommon(Context, Digest, 8);
}

VOID
Sha384Final(
	IN OUT SHA512_CONTEXT* Context,
	OUT    UINT8           Digest[SHA384_DIGEST_SIZE]
	)
{
	if (Context == NULL || Digest == NULL)
		return;
	Sha512FinalCommon(Context, Digest, 6);       /* 6 * 8 = 48 bytes */
}

VOID
Sha512(
	IN  CONST VOID* Data,
	IN  UINTN       Length,
	OUT UINT8       Digest[SHA512_DIGEST_SIZE]
	)
{
	SHA512_CONTEXT Ctx;
	Sha512Init(&Ctx);
	Sha512Update(&Ctx, Data, Length);
	Sha512Final(&Ctx, Digest);
}

VOID
Sha384(
	IN  CONST VOID* Data,
	IN  UINTN       Length,
	OUT UINT8       Digest[SHA384_DIGEST_SIZE]
	)
{
	SHA512_CONTEXT Ctx;
	Sha384Init(&Ctx);
	Sha512Update(&Ctx, Data, Length);
	Sha384Final(&Ctx, Digest);
}
