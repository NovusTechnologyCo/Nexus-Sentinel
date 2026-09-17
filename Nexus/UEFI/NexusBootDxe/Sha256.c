/**
 * @file Sha256.c
 * @brief SHA-256 (FIPS 180-4 section 6.2). See Sha256.h for why this is hand-rolled.
 *
 * Straight textbook implementation, chosen over anything clever on purpose: this runs during boot
 * where a wrong digest produces a self-incriminating TCG log and a subtle bug is unobservable
 * until something rejects the machine. Readability against the spec beats speed -- the total work
 * is a few hundred KB of hashing, once, per boot.
 *
 * No EDK2 dependencies (see the header). Byte order is handled explicitly rather than by cast,
 * so the code does not silently depend on host endianness if it is ever reused off x64.
 */

#include "Sha256.h"

//
// FIPS 180-4 section 4.2.2 -- first 32 bits of the fractional parts of the cube roots of the
// first 64 primes.
//
STATIC CONST UINT32 mSha256K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR32(x, n)    ((x) >> (n))

#define CH(x, y, z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)       (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)       (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)       (ROTR32(x,  7) ^ ROTR32(x, 18) ^ SHR32(x,  3))
#define SSIG1(x)       (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR32(x, 10))

/**
 * Process exactly one 64-byte block. FIPS 180-4 section 6.2.2.
 */
STATIC
VOID
Sha256Transform(
	IN OUT SHA256_CONTEXT* Context,
	IN CONST UINT8* Block
	)
{
	UINT32 W[64];
	UINTN i;

	//
	// Step 1: prepare the message schedule. W[0..15] are the block's big-endian words; assembled
	// byte-by-byte rather than cast so endianness is explicit.
	//
	for (i = 0; i < 16; i++)
	{
		W[i] = ((UINT32)Block[i * 4 + 0] << 24) |
			   ((UINT32)Block[i * 4 + 1] << 16) |
			   ((UINT32)Block[i * 4 + 2] <<  8) |
			   ((UINT32)Block[i * 4 + 3]);
	}
	for (i = 16; i < 64; i++)
		W[i] = SSIG1(W[i - 2]) + W[i - 7] + SSIG0(W[i - 15]) + W[i - 16];

	//
	// Step 2: initialise the working variables from the current hash value.
	//
	UINT32 a = Context->State[0];
	UINT32 b = Context->State[1];
	UINT32 c = Context->State[2];
	UINT32 d = Context->State[3];
	UINT32 e = Context->State[4];
	UINT32 f = Context->State[5];
	UINT32 g = Context->State[6];
	UINT32 h = Context->State[7];

	//
	// Step 3: the 64 rounds.
	//
	for (i = 0; i < 64; i++)
	{
		CONST UINT32 T1 = h + BSIG1(e) + CH(e, f, g) + mSha256K[i] + W[i];
		CONST UINT32 T2 = BSIG0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	//
	// Step 4: compute the intermediate hash value.
	//
	Context->State[0] += a;
	Context->State[1] += b;
	Context->State[2] += c;
	Context->State[3] += d;
	Context->State[4] += e;
	Context->State[5] += f;
	Context->State[6] += g;
	Context->State[7] += h;
}

VOID
Sha256Init(
	OUT SHA256_CONTEXT* Context
	)
{
	if (Context == NULL)
		return;

	//
	// FIPS 180-4 section 5.3.3 -- first 32 bits of the fractional parts of the square roots of the
	// first eight primes.
	//
	Context->State[0] = 0x6a09e667;
	Context->State[1] = 0xbb67ae85;
	Context->State[2] = 0x3c6ef372;
	Context->State[3] = 0xa54ff53a;
	Context->State[4] = 0x510e527f;
	Context->State[5] = 0x9b05688c;
	Context->State[6] = 0x1f83d9ab;
	Context->State[7] = 0x5be0cd19;
	Context->BitLength = 0;
	Context->BlockLength = 0;
}

VOID
Sha256Update(
	IN OUT SHA256_CONTEXT* Context,
	IN CONST VOID* Data,
	IN UINTN Length
	)
{
	if (Context == NULL || (Data == NULL && Length != 0))
		return;

	CONST UINT8* In = (CONST UINT8*)Data;
	for (UINTN i = 0; i < Length; i++)
	{
		Context->Block[Context->BlockLength++] = In[i];
		if (Context->BlockLength == SHA256_BLOCK_SIZE)
		{
			Sha256Transform(Context, Context->Block);
			Context->BitLength += SHA256_BLOCK_SIZE * 8;
			Context->BlockLength = 0;
		}
	}
}

VOID
Sha256Final(
	IN OUT SHA256_CONTEXT* Context,
	OUT UINT8 Digest[SHA256_DIGEST_SIZE]
	)
{
	if (Context == NULL || Digest == NULL)
		return;

	//
	// Account for the still-buffered bytes BEFORE padding, or the length field is wrong.
	//
	Context->BitLength += (UINT64)Context->BlockLength * 8;

	UINTN i = Context->BlockLength;

	//
	// FIPS 180-4 section 5.1.1: append 0x80, then zeros, so the length lands in the final 8 bytes
	// of a block. If there is no room for the 8-byte length, finish this block and pad a new one.
	//
	Context->Block[i++] = 0x80;
	if (i > 56)
	{
		while (i < SHA256_BLOCK_SIZE)
			Context->Block[i++] = 0x00;
		Sha256Transform(Context, Context->Block);
		i = 0;
	}
	while (i < 56)
		Context->Block[i++] = 0x00;

	//
	// 64-bit big-endian bit length.
	//
	for (UINTN b = 0; b < 8; b++)
		Context->Block[56 + b] = (UINT8)(Context->BitLength >> (56 - 8 * b));
	Sha256Transform(Context, Context->Block);

	//
	// Emit H0..H7 big-endian.
	//
	for (UINTN w = 0; w < 8; w++)
	{
		Digest[w * 4 + 0] = (UINT8)(Context->State[w] >> 24);
		Digest[w * 4 + 1] = (UINT8)(Context->State[w] >> 16);
		Digest[w * 4 + 2] = (UINT8)(Context->State[w] >>  8);
		Digest[w * 4 + 3] = (UINT8)(Context->State[w]);
	}
}

VOID
Sha256(
	IN CONST VOID* Data,
	IN UINTN Length,
	OUT UINT8 Digest[SHA256_DIGEST_SIZE]
	)
{
	SHA256_CONTEXT Context;
	Sha256Init(&Context);
	Sha256Update(&Context, Data, Length);
	Sha256Final(&Context, Digest);
}
