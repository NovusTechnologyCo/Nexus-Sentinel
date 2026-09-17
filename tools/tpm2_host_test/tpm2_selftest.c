/**
 * @file tpm2_selftest.c
 * @brief Host harness for Tpm2Core.c. Prints machine-readable results for an external oracle.
 *
 * ⚠ THIS PROGRAM ASSERTS NOTHING ABOUT CORRECTNESS. It runs the real firmware code and prints
 * what came out; `tools/check_tpm2_core.py` decides whether that is right, using Python's hashlib
 * as an INDEPENDENT implementation of SHA-256.
 *
 * That split is the whole point. A test that computes its expected value with the same code it is
 * testing agrees with itself and proves nothing -- the exact failure that let a broken
 * an early ACPI dump script look like a passing validation earlier in this phase. The oracle has to
 * come from somewhere else.
 */

#include <stdio.h>
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Core.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2EventLog.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2PeHash.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Hash.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Dispatch.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Bn.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Prime.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Kdf.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Object.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Session.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Primary.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Nv.h"
#include "../../Nexus/UEFI/NexusTpmDxe/Tpm2Aes.h"
#include <stdlib.h>

static void PrintDigest(const char* Key, const UINT8* D)
{
	int i;
	printf("%s=", Key);
	for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
		printf("%02x", D[i]);
	printf("\n");
}

/* PrintDigest is hard-wired to 32 bytes; SHA-384 and SHA-512 need their own lengths. */
/*
 * A DETERMINISTIC "entropy" source, for tests only.
 *
 * (!) IT IS DELIBERATELY NOT RANDOM, and that is safe only because it exists solely inside this
 * harness. It proves the response is SHAPED correctly -- size prefix, length, clamping. It
 * would be a catastrophe as a fallback inside the dispatcher, which is exactly why the
 * dispatcher refuses instead of carrying one.
 */
static BOOLEAN TestEntropy(UINT8* Out, UINT32 Bytes)
{
	UINT32 i;
	for (i = 0; i < Bytes; i++)
		Out[i] = (UINT8)(0x5A + i);
	return TRUE;
}

/*
 * A FIXED clock, for tests only. 0x0123456789 milliseconds is arbitrary but distinctive: a
 * response accidentally left zeroed would still pass a test that expected zero.
 */
static BOOLEAN TestClock(UINT64* Out)
{
	*Out = 0x0123456789ull;
	return TRUE;
}

/*
 * A deterministic generator for test operands.
 *
 * (!) NOT RANDOM AND NOT MEANT TO BE. The point is that the same vectors run on every machine
 * and in every build, so a failure is reproducible. xorshift64* with a fixed seed gives a wide
 * spread of bit patterns, which is what exercises carry chains -- values that are almost all
 * ones, almost all zeros, and everything between.
 */
static UINT64 gBnRand = 0x9E3779B97F4A7C15ull;

static UINT32 BnRand32(void)
{
	gBnRand ^= gBnRand >> 12;
	gBnRand ^= gBnRand << 25;
	gBnRand ^= gBnRand >> 27;
	return (UINT32)((gBnRand * 0x2545F4914F6CDD1Dull) >> 32);
}

/* A value of exactly Bytes bytes, top bit set so the size is what was asked for. */
static void BnRandom(TPM2_BN* A, UINT32 Bytes)
{
	UINT8 B[560];
	UINT32 i;

	for (i = 0; i < Bytes && i < sizeof(B); i++)
		B[i] = (UINT8)BnRand32();
	if (Bytes > 0)
		B[0] |= 0x80;
	Tpm2BnFromBytes(A, B, Bytes);
}

/* Bare lowercase hex, or "0". Python reads these back with int(x, 16). */
static void BnHex(const TPM2_BN* A)
{
	UINT8 B[560];
	UINT32 n = (Tpm2BnBits(A) + 7) / 8;
	UINT32 i;

	if (n == 0)
	{
		printf("0");
		return;
	}
	Tpm2BnToBytes(A, B, n);
	for (i = 0; i < n; i++)
		printf("%02x", B[i]);
}

/*
 * One line: "<key>.<i>=<a> <b> <r>" -- THE INPUTS BESIDE THE ANSWER.
 *
 * (!) That is the whole point of the format. Python never reproduces the C generator, so a
 * drift between the two cannot silently make the tests compare different vectors and pass.
 */
static void BnEmit(const char* Key, UINT32 Index,
                   const TPM2_BN* A, const TPM2_BN* B, const TPM2_BN* R)
{
	printf("%s.%u=", Key, Index);
	BnHex(A);
	printf(" ");
	BnHex(B);
	printf(" ");
	BnHex(R);
	printf("\n");
}
/*
 * A DETERMINISTIC source for key generation, tests only.
 *
 * (!) THE KEY MUST BE REPRODUCIBLE OR THE TEST CANNOT PIN IT. Real generation takes real
 * entropy; here the same seed must give the same primes on every machine and every run, so a
 * failure can be reproduced rather than merely reported. It is the same xorshift the bignum
 * vectors use, reseeded so the two do not share a stream.
 */
static UINT64 gPrimeRand = 0xD1B54A32D192ED03ull;

static BOOLEAN TestPrimeRand(UINT8* Out, UINT32 Bytes)
{
	UINT32 i;
	for (i = 0; i < Bytes; i++)
	{
		gPrimeRand ^= gPrimeRand >> 12;
		gPrimeRand ^= gPrimeRand << 25;
		gPrimeRand ^= gPrimeRand >> 27;
		Out[i] = (UINT8)((gPrimeRand * 0x2545F4914F6CDD1Dull) >> 33);
	}
	return TRUE;
}

/* One value as "<key>=<hex>", for places where the input/answer triple makes no sense. */
static void BnHexKey(const char* Key, const TPM2_BN* A)
{
	printf("%s=", Key);
	BnHex(A);
	printf("\n");
}

/*
 * A KDF stream, presented as a TPM2_RAND_FN.
 *
 * (!) THIS ADAPTER IS THE WHOLE DESIGN IN THREE LINES. Tpm2RsaGenerateKey takes a source of
 * bytes and does not care where they come from -- so RDRAND gives a random key and a seeded
 * KDF stream gives a REPRODUCIBLE one, through the same generator, with no second code path to
 * keep in step with the first.
 */
static TPM2_KDF_STREAM* gKdfStream = NULL;

static BOOLEAN KdfStreamRand(UINT8* Out, UINT32 Bytes)
{
	if (gKdfStream == NULL)
		return FALSE;
	return Tpm2KdfStreamBytes(gKdfStream, Out, Bytes);
}

/* Big-endian writers, so the templates above read as the Part 2 tables do. */
static void PutBe16At(UINT8* B, UINT32* p, unsigned v)
{
	B[*p] = (UINT8)(v >> 8); B[*p + 1] = (UINT8)v; *p += 2;
}

static void PutBe32At(UINT8* B, UINT32* p, unsigned v)
{
	B[*p] = (UINT8)(v >> 24); B[*p + 1] = (UINT8)(v >> 16);
	B[*p + 2] = (UINT8)(v >> 8); B[*p + 3] = (UINT8)v; *p += 4;
}

/*
 * A deterministic seed source for the tests.
 *
 * (!) A REAL TPM KEEPS THESE IN NV AND NEVER LETS THEM OUT. This one is a constant per
 * hierarchy, which is exactly what the platform provider has to be: the SAME seed for the
 * SAME hierarchy across reboots. If it were random the SRK would change every boot, which is
 * the failure -- Windows event 519 -- the whole layer exists to remove.
 */
static BOOLEAN TestSeed(UINT32 Hierarchy, UINT8* Seed, UINT32 Len)
{
	UINT32 i;
	if (Len == 0) return FALSE;
	for (i = 0; i < Len; i++)
		Seed[i] = (UINT8)((Hierarchy >> ((i % 4) * 8)) ^ (0x5A + i));
	return TRUE;
}

static void PutBe16Raw(UINT8* B, UINT32 p, unsigned v)
{
	B[p] = (UINT8)(v >> 8); B[p + 1] = (UINT8)v;
}

static void PutBe32Raw(UINT8* B, UINT32 p, unsigned v)
{
	B[p] = (UINT8)(v >> 24); B[p + 1] = (UINT8)(v >> 16);
	B[p + 2] = (UINT8)(v >> 8); B[p + 3] = (UINT8)v;
}

static void PrintHexN(const char* Key, const UINT8* D, unsigned N)
{
	unsigned i;
	printf("%s=", Key);
	for (i = 0; i < N; i++)
		printf("%02x", D[i]);
	printf("\n");
}

static void PrintBank(const char* Prefix, const TPM2_PCR_BANK* Bank)
{
	UINT32 i;
	char key[64];
	for (i = 0; i < TPM2_PCR_COUNT; i++) {
		snprintf(key, sizeof(key), "%s.pcr%02u", Prefix, i);
		PrintDigest(key, Bank->Pcr[i]);
	}
	printf("%s.counter=%u\n", Prefix, Bank->UpdateCounter);
	printf("%s.started=%u\n", Prefix, (unsigned)Bank->Started);
}

/*
 * With a file argument, hash that PE and print the digest -- nothing else. Lets the oracle run
 * the REAL firmware hasher over REAL images (our own signed DXE, bootmgfw, ...) and compare
 * against an Authenticode implementation written separately in Python.
 */
static int HashPeFile(const char* Path)
{
	FILE*  f = fopen(Path, "rb");
	UINT8* Buf;
	long   Len;
	UINT8  Digest[TPM2_SHA256_DIGEST_SIZE];
	int    i;

	if (f == NULL) { printf("pe.error=open\n"); return 1; }
	fseek(f, 0, SEEK_END); Len = ftell(f); fseek(f, 0, SEEK_SET);
	if (Len <= 0) { fclose(f); printf("pe.error=size\n"); return 1; }

	Buf = (UINT8*)malloc((size_t)Len);
	if (Buf == NULL) { fclose(f); printf("pe.error=alloc\n"); return 1; }
	if (fread(Buf, 1, (size_t)Len, f) != (size_t)Len) {
		fclose(f); free(Buf); printf("pe.error=read\n"); return 1;
	}
	fclose(f);

	printf("pe.size=%ld\n", Len);
	if (Tpm2HashPeImage(Buf, (UINT64)Len, Digest)) {
		printf("pe.ok=1\npe.digest=");
		for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++) printf("%02x", Digest[i]);
		printf("\n");
	} else {
		printf("pe.ok=0\n");
	}
	free(Buf);


	return 0;
}

int main(int argc, char** argv)
{
	if (argc > 1)
		return HashPeFile(argv[1]);

	TPM2_PCR_BANK Bank;
	UINT8  Digest[TPM2_SHA256_DIGEST_SIZE];
	UINT8  Out[TPM2_SHA256_DIGEST_SIZE];
	UINT8  Hdr[TPM2_HEADER_SIZE + 8];
	UINT16 Tag;
	UINT32 Size, Code, Rc, i;

	/* ---- extend BEFORE startup must be refused, not silently accepted ---- */
	for (i = 0; i < sizeof(Bank); i++)
		((UINT8*)&Bank)[i] = 0;
	for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
		Digest[i] = 0xAA;
	printf("rc.extend_before_startup=%u\n", Tpm2PcrExtend(&Bank, 0, Digest));
	printf("rc.read_before_startup=%u\n",   Tpm2PcrRead(&Bank, 0, Out));

	/* ---- Startup(CLEAR) at locality 0 ---- */
	Tpm2PcrStartupClear(&Bank, 0);
	PrintBank("startup_loc0", &Bank);

	/* ---- Startup(CLEAR) at locality 3: PCR[0] must carry the locality indicator ---- */
	{
		TPM2_PCR_BANK L3;
		Tpm2PcrStartupClear(&L3, 3);
		PrintDigest("startup_loc3.pcr00", L3.Pcr[0]);
	}

	/* ---- one extend of PCR 0 with 0xAA.. ---- */
	printf("rc.extend1=%u\n", Tpm2PcrExtend(&Bank, 0, Digest));
	PrintDigest("extend1.pcr00", Bank.Pcr[0]);
	printf("extend1.counter=%u\n", Bank.UpdateCounter);

	/* ---- a second extend of the same PCR with 0xBB.., to prove ORDER matters ---- */
	for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
		Digest[i] = 0xBB;
	printf("rc.extend2=%u\n", Tpm2PcrExtend(&Bank, 0, Digest));
	PrintDigest("extend2.pcr00", Bank.Pcr[0]);
	printf("extend2.counter=%u\n", Bank.UpdateCounter);

	/* ---- extend PCR 17, which starts at -1 rather than 0 ---- */
	printf("rc.extend17=%u\n", Tpm2PcrExtend(&Bank, 17, Digest));
	PrintDigest("extend17.pcr17", Bank.Pcr[17]);

	/* ---- an untouched PCR must not have moved ---- */
	PrintDigest("untouched.pcr05", Bank.Pcr[5]);

	/* ---- range checks ---- */
	printf("rc.extend_oob=%u\n", Tpm2PcrExtend(&Bank, TPM2_PCR_COUNT, Digest));
	printf("rc.read_oob=%u\n",   Tpm2PcrRead(&Bank, TPM2_PCR_COUNT, Out));

	/* ---- read returns what extend produced ---- */
	Rc = Tpm2PcrRead(&Bank, 0, Out);
	printf("rc.read0=%u\n", Rc);
	PrintDigest("read.pcr00", Out);

	/* ---- header parsing ---- */
	Tpm2WriteBe16(Hdr, TPM2_ST_NO_SESSIONS);
	Tpm2WriteBe32(Hdr + 2, TPM2_HEADER_SIZE);
	Tpm2WriteBe32(Hdr + 6, TPM2_CC_STARTUP);
	printf("rc.hdr_ok=%u\n", Tpm2ParseCommandHeader(Hdr, TPM2_HEADER_SIZE, &Tag, &Size, &Code));
	printf("hdr.tag=0x%04x\n", Tag);
	printf("hdr.size=%u\n", Size);
	printf("hdr.code=0x%08x\n", Code);

	/* short buffer */
	printf("rc.hdr_short=%u\n", Tpm2ParseCommandHeader(Hdr, TPM2_HEADER_SIZE - 1, &Tag, &Size, &Code));

	/* declared size disagrees with what we actually have, both directions */
	Tpm2WriteBe32(Hdr + 2, TPM2_HEADER_SIZE + 4);
	printf("rc.hdr_size_over=%u\n", Tpm2ParseCommandHeader(Hdr, TPM2_HEADER_SIZE, &Tag, &Size, &Code));
	Tpm2WriteBe32(Hdr + 2, TPM2_HEADER_SIZE);
	printf("rc.hdr_size_under=%u\n", Tpm2ParseCommandHeader(Hdr, TPM2_HEADER_SIZE + 4, &Tag, &Size, &Code));

	/* bad tag */
	Tpm2WriteBe16(Hdr, 0x1234);
	Tpm2WriteBe32(Hdr + 2, TPM2_HEADER_SIZE);
	printf("rc.hdr_badtag=%u\n", Tpm2ParseCommandHeader(Hdr, TPM2_HEADER_SIZE, &Tag, &Size, &Code));

	/* ---- response header: an error MUST be forced to NO_SESSIONS ---- */
	Tpm2WriteResponseHeader(Hdr, TPM2_ST_SESSIONS, TPM2_HEADER_SIZE, TPM2_RC_SUCCESS);
	printf("rsp.ok_tag=0x%04x\n", Tpm2ReadBe16(Hdr));
	Tpm2WriteResponseHeader(Hdr, TPM2_ST_SESSIONS, TPM2_HEADER_SIZE, TPM2_RC_FAILURE);
	printf("rsp.err_tag=0x%04x\n", Tpm2ReadBe16(Hdr));
	printf("rsp.err_code=0x%08x\n", Tpm2ReadBe32(Hdr + 6));

	/* ---- big-endian accessors round-trip ---- */
	Tpm2WriteBe32(Hdr, 0x01020304u);
	printf("be.bytes=%02x%02x%02x%02x\n", Hdr[0], Hdr[1], Hdr[2], Hdr[3]);
	printf("be.read=0x%08x\n", Tpm2ReadBe32(Hdr));

	/* ---- constants, so the oracle can check them against the spec ---- */
	printf("const.rc_bad_tag=0x%03x\n", TPM2_RC_BAD_TAG);
	printf("const.rc_initialize=0x%03x\n", TPM2_RC_INITIALIZE);
	printf("const.rc_command_code=0x%03x\n", TPM2_RC_COMMAND_CODE);
	printf("const.cc_startup=0x%08x\n", TPM2_CC_STARTUP);
	printf("const.cc_pcr_extend=0x%08x\n", TPM2_CC_PCR_EXTEND);
	printf("const.st_no_sessions=0x%04x\n", TPM2_ST_NO_SESSIONS);
	printf("const.alg_sha256=0x%04x\n", TPM2_ALG_SHA256);


	/* ------------------------------------------------------------------ event log ---- */
	{
		static UINT8   LogBuf[4096];
		TPM2_EVENT_LOG Log;
		TPM2_PCR_BANK  LB;
		UINT8          Meas[64];
		UINT32         k;

		Tpm2PcrStartupClear(&LB, 0);
		/*
		 * (!) POISON THE BUFFER FIRST, or this test cannot fail.
		 *
		 * LogBuf is static, so it starts zeroed and a tail-zero check on it would pass whether or
		 * not Init zeroes anything. AllocatePages does NOT zero -- on hardware the log came back
		 * holding 13,863 bytes of firmware leftovers -- so the poison IS the real condition.
		 */
		for (k = 0; k < sizeof(LogBuf); k++) LogBuf[k] = (UINT8)(0xA5 ^ (k & 0xFF));

		printf("log.init=%u\n", (unsigned)Tpm2EventLogInit(&Log, LogBuf, sizeof(LogBuf)));
		printf("log.after_init_used=%u\n", Log.Used);
		printf("log.after_init_count=%u\n", Log.Count);
		{
			/* every byte past the header entry must be zero, not poison */
			unsigned NonZero = 0;
			for (k = Log.Used; k < sizeof(LogBuf); k++)
				if (LogBuf[k] != 0) NonZero++;
			printf("log.tailzero=%u\n", NonZero == 0 ? 1u : 0u);
			printf("log.tailnonzero=%u\n", NonZero);
		}

		/* three measurements into different PCRs, with distinct data and event blobs */
		for (k = 0; k < sizeof(Meas); k++) Meas[k] = (UINT8)k;
		printf("log.rc1=%u\n", Tpm2EventLogExtend(&Log, &LB, 0, 0x80000003,
		       Meas, 64, (CONST UINT8*)"boot-app", 8, NULL));

		for (k = 0; k < sizeof(Meas); k++) Meas[k] = (UINT8)(0xF0 ^ k);
		printf("log.rc2=%u\n", Tpm2EventLogExtend(&Log, &LB, 7, 0x800000E0,
		       Meas, 32, (CONST UINT8*)"authority", 9, NULL));

		/* a zero-length measurement is legal and hashes the empty string */
		printf("log.rc3=%u\n", Tpm2EventLogExtend(&Log, &LB, 0, 0x00000004,
		       NULL, 0, NULL, 0, NULL));

		printf("log.used=%u\n", Log.Used);
		printf("log.count=%u\n", Log.Count);
		printf("log.last=%u\n", Log.LastEntryOffset);
		printf("log.truncated=%u\n", (unsigned)Log.Truncated);

		/* the whole log, so the oracle can parse and REPLAY it */
		printf("log.bytes=");
		for (k = 0; k < Log.Used; k++) printf("%02x", LogBuf[k]);
		printf("\n");

		/* and the resulting PCRs, so replay can be compared against them */
		PrintDigest("log.pcr00", LB.Pcr[0]);
		PrintDigest("log.pcr07", LB.Pcr[7]);

		/* a buffer too small even for the header must refuse rather than half-write */
		{
			TPM2_EVENT_LOG Tiny;
			static UINT8 TinyBuf[8];
			printf("log.tiny_init=%u\n", (unsigned)Tpm2EventLogInit(&Tiny, TinyBuf, sizeof(TinyBuf)));
			printf("log.tiny_used=%u\n", Tiny.Used);
			printf("log.tiny_trunc=%u\n", (unsigned)Tiny.Truncated);
		}

		/* a log that fills up must still EXTEND, and must say it truncated */
		{
			TPM2_EVENT_LOG Small;
			static UINT8   SmallBuf[80];
			TPM2_PCR_BANK  SB;
			UINT8          Before[TPM2_SHA256_DIGEST_SIZE];
			Tpm2PcrStartupClear(&SB, 0);
			Tpm2EventLogInit(&Small, SmallBuf, sizeof(SmallBuf));
			Tpm2PcrRead(&SB, 1, Before);
			printf("log.full_rc=%u\n", Tpm2EventLogExtend(&Small, &SB, 1, 4,
			       (CONST UINT8*)"x", 1, NULL, 0, NULL));
			printf("log.full_trunc=%u\n", (unsigned)Small.Truncated);
			PrintDigest("log.full_pcr01", SB.Pcr[1]);
		}
	}

	/* ------------------------------------------------- PE hash: malformed input ---- */
	{
		static UINT8 Junk[512];
		UINT8 D[TPM2_SHA256_DIGEST_SIZE];
		UINT32 k;
		for (k = 0; k < sizeof(Junk); k++) Junk[k] = (UINT8)k;

		/* not an MZ at all */
		printf("pe.junk=%u\n", (unsigned)Tpm2HashPeImage(Junk, sizeof(Junk), D));

		/* MZ but e_lfanew points past the end -- the classic overread */
		Junk[0] = 0x4D; Junk[1] = 0x5A;
		Junk[0x3C] = 0xFF; Junk[0x3D] = 0xFF; Junk[0x3E] = 0xFF; Junk[0x3F] = 0x7F;
		printf("pe.badlfanew=%u\n", (unsigned)Tpm2HashPeImage(Junk, sizeof(Junk), D));

		/* truncated below even the DOS header */
		printf("pe.tiny=%u\n", (unsigned)Tpm2HashPeImage(Junk, 4, D));
		printf("pe.null=%u\n", (unsigned)Tpm2HashPeImage(NULL, 100, D));
	}


	/* --------------------------------------- SHA-384 / SHA-512 and HMAC ---------- */
	{
		static UINT8 Big[1000];
		static UINT8 LongKey[200];
		CONST UINT8* Fox = (CONST UINT8*)"The quick brown fox jumps over the lazy dog";
		CONST UINTN  FoxLen = 43;
		UINT8  D[TPM2_MAX_DIGEST_SIZE];
		UINT8  D2[TPM2_MAX_DIGEST_SIZE];
		UINT32 k;

		for (k = 0; k < sizeof(Big); k++)     Big[k]     = (UINT8)('a' + (k % 26));
		for (k = 0; k < sizeof(LongKey); k++) LongKey[k] = (UINT8)(k * 7 + 3);

		Sha512("", 0, D);            PrintHexN("c.sha512_empty", D, 64);
		Sha384("", 0, D);            PrintHexN("c.sha384_empty", D, 48);
		Sha512("abc", 3, D);         PrintHexN("c.sha512_abc", D, 64);
		Sha384("abc", 3, D);         PrintHexN("c.sha384_abc", D, 48);
		Sha512(Big, sizeof(Big), D); PrintHexN("c.sha512_big", D, 64);
		Sha384(Big, sizeof(Big), D); PrintHexN("c.sha384_big", D, 48);

		/* streaming in awkward chunks must equal the one-shot */
		{
			SHA512_CONTEXT Sc;
			Sha512Init(&Sc);
			for (k = 0; k < sizeof(Big); k += 7)
				Sha512Update(&Sc, Big + k, (sizeof(Big) - k) < 7 ? (sizeof(Big) - k) : 7);
			Sha512Final(&Sc, D2);
			Sha512(Big, sizeof(Big), D);
			printf("c.sha512_stream=%u\n", (unsigned)(memcmp(D, D2, 64) == 0));
		}

		printf("c.size256=%u\nc.size384=%u\nc.size512=%u\nc.sizebad=%u\n",
		       Tpm2HashSize(TPM2_ALG_SHA256), Tpm2HashSize(TPM2_ALG_SHA384),
		       Tpm2HashSize(TPM2_ALG_SHA512), Tpm2HashSize(0x0004));
		printf("c.blk384=%u\n", Tpm2HashBlockSize(TPM2_ALG_SHA384));

		Tpm2Hash(TPM2_ALG_SHA384, Fox, FoxLen, D); PrintHexN("c.agile384", D, 48);
		printf("c.agilebad=%u\n", (unsigned)Tpm2Hash(0x0004, Fox, FoxLen, D));
		printf("c.hmacbad=%u\n",  (unsigned)Tpm2Hmac(0x0004, (CONST UINT8*)"k", 1, Fox, FoxLen, D));

		Tpm2Hmac(TPM2_ALG_SHA256, (CONST UINT8*)"key", 3, Fox, FoxLen, D);
		PrintHexN("c.hmac256_short", D, 32);
		Tpm2Hmac(TPM2_ALG_SHA384, (CONST UINT8*)"key", 3, Fox, FoxLen, D);
		PrintHexN("c.hmac384_short", D, 48);
		Tpm2Hmac(TPM2_ALG_SHA512, (CONST UINT8*)"key", 3, Fox, FoxLen, D);
		PrintHexN("c.hmac512_short", D, 64);

		/* key longer than the block: FIPS 198-1 says HASH it, not truncate */
		Tpm2Hmac(TPM2_ALG_SHA256, LongKey, sizeof(LongKey), Fox, FoxLen, D);
		PrintHexN("c.hmac256_long", D, 32);
		Tpm2Hmac(TPM2_ALG_SHA384, LongKey, sizeof(LongKey), Fox, FoxLen, D);
		PrintHexN("c.hmac384_long", D, 48);
		Tpm2Hmac(TPM2_ALG_SHA512, LongKey, sizeof(LongKey), Fox, FoxLen, D);
		PrintHexN("c.hmac512_long", D, 64);

		{
			TPM2_HMAC_CONTEXT Hc;
			Tpm2HmacInit(&Hc, TPM2_ALG_SHA384, (CONST UINT8*)"key", 3);
			for (k = 0; k < FoxLen; k += 5)
				Tpm2HmacUpdate(&Hc, Fox + k, (FoxLen - k) < 5 ? (FoxLen - k) : 5);
			Tpm2HmacFinal(&Hc, D2);
			Tpm2Hmac(TPM2_ALG_SHA384, (CONST UINT8*)"key", 3, Fox, FoxLen, D);
			printf("c.hmac_stream=%u\n", (unsigned)(memcmp(D, D2, 48) == 0));
		}
	}

	/* ------------------------------------------------ the command dispatcher ------ */
	{
		TPM2_PCR_BANK      DBank;
		TPM2_DISPATCH_INFO DInfo;
		UINT8  DCmd[64];
		UINT8  DOut[512];
		UINT32 DN;
		unsigned HdrOk = 1;

		/* every response must declare its own length; a header that disagrees with the byte
		 * count desynchronises a CRB peer rather than merely returning a wrong answer. */
#define DHDR(b, tag, sz, cc) do {                                   \
			Tpm2WriteBe16((b), (tag));                                    \
			Tpm2WriteBe32((b) + 2, (sz));                                 \
			Tpm2WriteBe32((b) + 6, (cc));                                 \
		} while (0)
#define DRUN(inlen) do {                                            \
			DN = Tpm2Dispatch(&DBank, DCmd, (inlen), DOut, sizeof(DOut), &DInfo);  \
			if (DN >= TPM2_HEADER_SIZE && Tpm2ReadBe32(DOut + 2) != DN) HdrOk = 0; \
		} while (0)

		Tpm2PcrStartupClear(&DBank, 0);

		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 12, TPM2_CC_STARTUP);
		Tpm2WriteBe16(DCmd + 10, TPM2_SU_CLEAR);
		DRUN(12);  printf("d.startup_clear=%03X\n", DInfo.ResponseCode);

		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 12, TPM2_CC_STARTUP);
		Tpm2WriteBe16(DCmd + 10, TPM2_SU_STATE);
		DRUN(12);  printf("d.startup_state=%03X\n", DInfo.ResponseCode);

		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 11, TPM2_CC_SELF_TEST); DCmd[10] = 0;
		DRUN(11);  printf("d.selftest=%03X\n", DInfo.ResponseCode);

		/* TPM2_Quote (0x158, Part 2 v185) -- genuinely unimplemented, and a refusal test needs a
		 * command that STAYS refused. This was GetRandom until GetRandom was implemented and the
		 * test went stale; it then carried 0x15D, which is TPM2_Sign, because the command table
		 * this project was working from had 34 of 46 entries wrong. */
		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 10, 0x00000158u);
		DRUN(10);  printf("d.unimpl=%03X\n", DInfo.ResponseCode);

		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 200, TPM2_CC_STARTUP);
		DRUN(12);  printf("d.truncated=%03X\n", DInfo.ResponseCode);

		DN = Tpm2Dispatch(&DBank, NULL, 0, DOut, sizeof(DOut), &DInfo);
		printf("d.nullin=%03X\n", DInfo.ResponseCode);
		if (DN >= TPM2_HEADER_SIZE && Tpm2ReadBe32(DOut + 2) != DN) HdrOk = 0;

		{
			UINT8 Tiny[4];
			DHDR(DCmd, TPM2_ST_NO_SESSIONS, 11, TPM2_CC_SELF_TEST); DCmd[10] = 0;
			printf("d.tinyout=%u\n",
			       Tpm2Dispatch(&DBank, DCmd, 11, Tiny, sizeof(Tiny), &DInfo));
		}

		/* the whole PT_FIXED run, 0x100..0x10C -- decoded, not spot-checked */
		DHDR(DCmd, TPM2_ST_NO_SESSIONS, 22, TPM2_CC_GET_CAPABILITY);
		Tpm2WriteBe32(DCmd + 10, 0x00000006);   /* TPM_CAP_TPM_PROPERTIES */
		Tpm2WriteBe32(DCmd + 14, 0x00000100);   /* TPM_PT_FIXED           */
		/*
		 * (!) 42, NOT 13, AND THE NUMBER COMES FROM THE MACHINE. The CRB trace recorded Windows
		 * asking for exactly 42 properties starting at PT_FIXED. The old check requested 13 and
		 * passed while 0x10E through 0x129 were entirely absent -- it verified a PREFIX and called
		 * it a run.
		 */
		Tpm2WriteBe32(DCmd + 18, 42);
		DRUN(22);
		{
			UINT32 Cnt = Tpm2ReadBe32(DOut + TPM2_HEADER_SIZE + 5);
			UINT32 Base = TPM2_HEADER_SIZE + 9;
			unsigned Contig = 1;
			UINT32 k;
			/*
			 * (!) 41, NOT 42, AND THE MISSING ONE IS THE SPEC'S OWN. Part 2 lists PT_FIXED + 21
			 * (0x115) as "reserved" -- there is no property there, so a real TPM answering 42
			 * requests returns 41. An earlier version of this test asserted a contiguous 42 and
			 * failed correct code, which is the worse kind of test failure.
			 */
			{
				UINT32 Expect = 0x00000100u;
				for (k = 0; k < Cnt; k++)
				{
					if (Expect == 0x00000115u) Expect++;      /* reserved: skip */
					if (Tpm2ReadBe32(DOut + Base + k * 8) != Expect) Contig = 0;
					Expect++;
				}
			}
			if (Cnt != 41) Contig = 0;
			printf("d.cap_contiguous=%u\n", Contig);
			printf("d.cap_family=%08x\n", Tpm2ReadBe32(DOut + Base + 0 * 8 + 4));
			printf("d.cap_revision=%u\n",  Tpm2ReadBe32(DOut + Base + 2 * 8 + 4));
			{
				UINT32 M = Tpm2ReadBe32(DOut + Base + 5 * 8 + 4);
				printf("d.cap_manuf=%c%c%c%c\n", (char)(M >> 24), (char)(M >> 16),
				       (char)(M >> 8), (char)M);
			}
		}

		printf("d.hdr_ok=%u\n", HdrOk);
#undef DHDR
#undef DRUN
	}

	/* TPM2_GetTestResult -- added on MEASURED demand: the CRB trace caught Windows asking */
	/* for it and us answering COMMAND_CODE, which is what produced "failure mode".        */
	{
		TPM2_PCR_BANK      GBank;
		TPM2_DISPATCH_INFO GInfo;
		UINT8  GCmd[16];
		UINT8  GOut[64];
		UINT32 GN;

		Tpm2PcrStartupClear(&GBank, 0);
		Tpm2WriteBe16(GCmd, TPM2_ST_NO_SESSIONS);
		Tpm2WriteBe32(GCmd + 2, 10);
		Tpm2WriteBe32(GCmd + 6, 0x0000017C);
		GN = Tpm2Dispatch(&GBank, GCmd, 10, GOut, sizeof(GOut), &GInfo);
		printf("d.testresult=%03X\n", GInfo.ResponseCode);
		printf("d.testresult_len=%u\n", GN);
		printf("d.testresult_hdr=%u\n",
		       (unsigned)(GN >= TPM2_HEADER_SIZE ? Tpm2ReadBe32(GOut + 2) : 0));
		/* outData empty, then testResult == TPM_RC_SUCCESS */
		printf("d.testresult_outdata=%u\n", (unsigned)Tpm2ReadBe16(GOut + 10));
		printf("d.testresult_value=%u\n", Tpm2ReadBe32(GOut + 12));
	}

	/* TPM_CAP_COMMANDS / ALGS / PCRS, and the cross-check between them ------------ */
	{
		TPM2_PCR_BANK      CBank;
		TPM2_DISPATCH_INFO CInfo;
		UINT8  CCmd[32];
		UINT8  COut[512];
		UINT32 CN, CCnt, CBase, k;
		UINT32 CmdCount = 0;
		UINT32 TotalCommandsProp = 0;
		unsigned Ascending = 1;

		Tpm2PcrStartupClear(&CBank, 0);

#define CAPREQ(cap, prop, cnt) do {                                    \
			Tpm2WriteBe16(CCmd, TPM2_ST_NO_SESSIONS);                        \
			Tpm2WriteBe32(CCmd + 2, 22);                                     \
			Tpm2WriteBe32(CCmd + 6, TPM2_CC_GET_CAPABILITY);                 \
			Tpm2WriteBe32(CCmd + 10, (cap));                                 \
			Tpm2WriteBe32(CCmd + 14, (prop));                                \
			Tpm2WriteBe32(CCmd + 18, (cnt));                                 \
			CN = Tpm2Dispatch(&CBank, CCmd, 22, COut, sizeof(COut), &CInfo); \
			CCnt = Tpm2ReadBe32(COut + TPM2_HEADER_SIZE + 5);                \
			CBase = TPM2_HEADER_SIZE + 9;                                    \
		} while (0)

		/*
		 * TPM_CAP_COMMANDS returns TPML_CCA -- TPMA_CC values, not bare command codes.
		 *
		 * (!) THE ASCENDING CHECK MUST COMPARE THE INDEX, NOT THE WHOLE VALUE. Attributes
		 * live in the high bits, so a command carrying cHandles sorts above one without it
		 * regardless of code -- and comparing whole values would pass on an accident.
		 */
		CAPREQ(0x00000002u, 0, 16);
		CmdCount = CCnt;
		printf("d.cap_cmd_count=%u\n", CCnt);
		for (k = 1; k < CCnt; k++)
			if ((Tpm2ReadBe32(COut + CBase + k * 4) & 0xFFFFu) <=
			    (Tpm2ReadBe32(COut + CBase + (k - 1) * 4) & 0xFFFFu)) Ascending = 0;
		printf("d.cap_cmd_ascending=%u\n", Ascending);
		printf("d.cap_cmd_first=%08x\n", Tpm2ReadBe32(COut + CBase));

		/*
		 * The ATTRIBUTES, which are the whole reason this is a TPMA_CC. Counted rather than
		 * compared one by one, so a regression to bare codes shows as ZERO rather than as a
		 * subtly different number.
		 */
		{
			UINT32 AnyAttrs = 0;
			UINT32 Handles = 0;
			for (k = 0; k < CCnt; k++)
			{
				UINT32 V = Tpm2ReadBe32(COut + CBase + k * 4);
				if (V & 0xFFFF0000u) AnyAttrs++;
				Handles += (V >> 25) & 7u;
			}
			printf("d.cap_cmd_attrs=%u\n", AnyAttrs);
			printf("d.cap_cmd_handles=%u\n", Handles);
		}

		/* TPM_CAP_ALGS: the hashes we implement */
		CAPREQ(0x00000000u, 0, 16);
		printf("d.cap_alg_count=%u\n", CCnt);
		printf("d.cap_alg_first=%04x\n", (unsigned)Tpm2ReadBe16(COut + CBase));

		/* TPM_CAP_PCRS: one SHA-256 bank, 24 PCRs allocated */
		CAPREQ(0x00000005u, 0, 16);
		printf("d.cap_pcr_banks=%u\n", CCnt);
		printf("d.cap_pcr_alg=%04x\n", (unsigned)Tpm2ReadBe16(COut + CBase));
		printf("d.cap_pcr_select=%u\n", (unsigned)COut[CBase + 2]);
		printf("d.cap_pcr_bits=%02x%02x%02x\n",
		       COut[CBase + 3], COut[CBase + 4], COut[CBase + 5]);

		/*
		 * (!) THE CROSS-CHECK. TPM_PT_TOTAL_COMMANDS and the length of the TPM_CAP_COMMANDS list
		 * are two answers to the same question, and they shipped disagreeing: the property said 4
		 * while the list was empty. Both were individually defensible; only comparing them catches
		 * it, and Windows compared them before any test here did.
		 */
		CAPREQ(0x00000006u, 0x00000129u, 1);   /* TPM_PT_TOTAL_COMMANDS */
		TotalCommandsProp = Tpm2ReadBe32(COut + CBase + 4);
		printf("d.total_commands_prop=%u\n", TotalCommandsProp);
		printf("d.commands_agree=%u\n",
		       (unsigned)(TotalCommandsProp == CmdCount));
#undef CAPREQ
	}

	/* TPM2_GetRandom: the REFUSAL matters more than the success -------------------- */
	{
		TPM2_PCR_BANK      RBank;
		TPM2_DISPATCH_INFO RInfo;
		UINT8  RCmd[16];
		UINT8  ROut[128];
		UINT32 RN;

		Tpm2PcrStartupClear(&RBank, 0);
		Tpm2WriteBe16(RCmd, TPM2_ST_NO_SESSIONS);
		Tpm2WriteBe32(RCmd + 2, 12);
		Tpm2WriteBe32(RCmd + 6, 0x0000017Bu);
		Tpm2WriteBe16(RCmd + 10, 16);

		/* no source installed: must FAIL, not fabricate */
		Tpm2SetEntropySource(NULL);
		RN = Tpm2Dispatch(&RBank, RCmd, 12, ROut, sizeof(ROut), &RInfo);
		printf("d.rand_norsrc=%03X\n", RInfo.ResponseCode);

		/* with a source: response is size-prefixed and the right length */
		Tpm2SetEntropySource(TestEntropy);
		RN = Tpm2Dispatch(&RBank, RCmd, 12, ROut, sizeof(ROut), &RInfo);
		printf("d.rand_rc=%03X\n", RInfo.ResponseCode);
		printf("d.rand_len=%u\n", RN);
		printf("d.rand_size=%u\n", (unsigned)Tpm2ReadBe16(ROut + 10));

		/* asking for more than the largest digest yields the maximum, not a refusal */
		Tpm2WriteBe16(RCmd + 10, 200);
		RN = Tpm2Dispatch(&RBank, RCmd, 12, ROut, sizeof(ROut), &RInfo);
		printf("d.rand_clamp=%u\n", (unsigned)Tpm2ReadBe16(ROut + 10));
		Tpm2SetEntropySource(NULL);
	}

	/* Handle-area validation: the DISTINCTIONS are the point ----------------------- */
	{
		TPM2_PCR_BANK      HBank;
		TPM2_DISPATCH_INFO HInfo;
		UINT8  HCmd[32];
		UINT8  HOut[128];

		Tpm2PcrStartupClear(&HBank, 0);

		/* TPM2_ReadPublic on a PERSISTENT handle: no such object -> TPM_RC_HANDLE + handle 1 */
		Tpm2WriteBe16(HCmd, TPM2_ST_NO_SESSIONS);
		Tpm2WriteBe32(HCmd + 2, 14);
		Tpm2WriteBe32(HCmd + 6, 0x00000173u);
		Tpm2WriteBe32(HCmd + 10, 0x81000001u);
		Tpm2Dispatch(&HBank, HCmd, 14, HOut, sizeof(HOut), &HInfo);
		printf("d.rdpub_persist=%03X\n", HInfo.ResponseCode);

		/* a TRANSIENT handle is a WARNING instead: it could be loaded, a missing
		 * persistent object could not */
		Tpm2WriteBe32(HCmd + 10, 0x80000000u);
		Tpm2Dispatch(&HBank, HCmd, 14, HOut, sizeof(HOut), &HInfo);
		printf("d.rdpub_transient=%03X\n", HInfo.ResponseCode);

		/* not an object handle at all -> a TYPE error, not a missing object */
		Tpm2WriteBe32(HCmd + 10, 0x40000001u);
		Tpm2Dispatch(&HBank, HCmd, 14, HOut, sizeof(HOut), &HInfo);
		printf("d.rdpub_bad=%03X\n", HInfo.ResponseCode);

		/* TPM2_NV_ReadPublic on the EK template index Windows actually asks for */
		Tpm2WriteBe32(HCmd + 6, 0x00000169u);
		Tpm2WriteBe32(HCmd + 10, 0x01C00004u);
		Tpm2Dispatch(&HBank, HCmd, 14, HOut, sizeof(HOut), &HInfo);
		printf("d.nvpub_index=%03X\n", HInfo.ResponseCode);

		/* outside the NV range -> a type error */
		Tpm2WriteBe32(HCmd + 10, 0x81000001u);
		Tpm2Dispatch(&HBank, HCmd, 14, HOut, sizeof(HOut), &HInfo);
		printf("d.nvpub_bad=%03X\n", HInfo.ResponseCode);

		/* a short command is a size error before any handle is looked at */
		Tpm2WriteBe32(HCmd + 2, 10);
		Tpm2Dispatch(&HBank, HCmd, 10, HOut, sizeof(HOut), &HInfo);
		printf("d.nvpub_short=%03X\n", HInfo.ResponseCode);
	}

	/* TPM2_ReadClock: refuses without a clock, and is shaped right with one -------- */
	{
		TPM2_PCR_BANK      CBank;
		TPM2_DISPATCH_INFO CInfo;
		UINT8  CCmd[16];
		UINT8  COut[128];
		UINT32 CN;

		Tpm2PcrStartupClear(&CBank, 0);
		Tpm2WriteBe16(CCmd, TPM2_ST_NO_SESSIONS);
		Tpm2WriteBe32(CCmd + 2, 10);
		Tpm2WriteBe32(CCmd + 6, 0x00000181u);

		Tpm2SetTimeSource(NULL);
		Tpm2Dispatch(&CBank, CCmd, 10, COut, sizeof(COut), &CInfo);
		printf("d.clock_nosrc=%03X\n", CInfo.ResponseCode);

		Tpm2SetTimeSource(TestClock);
		CN = Tpm2Dispatch(&CBank, CCmd, 10, COut, sizeof(COut), &CInfo);
		printf("d.clock_rc=%03X\n", CInfo.ResponseCode);
		printf("d.clock_len=%u\n", CN);
		printf("d.clock_time=%u\n", (unsigned)Tpm2ReadBe32(COut + 14));
		printf("d.clock_clock=%u\n", (unsigned)Tpm2ReadBe32(COut + 22));
		printf("d.clock_reset=%u\n", (unsigned)Tpm2ReadBe32(COut + 26));
		printf("d.clock_restart=%u\n", (unsigned)Tpm2ReadBe32(COut + 30));
		printf("d.clock_safe=%u\n", (unsigned)COut[34]);
		Tpm2SetTimeSource(NULL);
	}

	/* Tpm2Bn, against Python ------------------------------------------------------- */
	{
		static const UINT32 Sizes[] = { 1, 4, 5, 32, 33, 128, 129, 256 };
		TPM2_BN A, B, R, Q, M, T;
		UINT32 s;
		UINT32 n = 0;

		for (s = 0; s < sizeof(Sizes) / sizeof(Sizes[0]); s++)
		{
			UINT32 rep;
			for (rep = 0; rep < 4; rep++, n++)
			{
				BnRandom(&A, Sizes[s]);
				BnRandom(&B, Sizes[s]);

				Tpm2BnAdd(&R, &A, &B);
				BnEmit("bn.add", n, &A, &B, &R);

				/* subtraction is only defined one way round, so order the operands */
				if (Tpm2BnCmp(&A, &B) >= 0)
					Tpm2BnSub(&R, &A, &B), BnEmit("bn.sub", n, &A, &B, &R);
				else
					Tpm2BnSub(&R, &B, &A), BnEmit("bn.sub", n, &B, &A, &R);

				Tpm2BnMul(&R, &A, &B);
				BnEmit("bn.mul", n, &A, &B, &R);

				Tpm2BnDivMod(&Q, &R, &A, &B);
				BnEmit("bn.div", n, &A, &B, &Q);
				BnEmit("bn.mod", n, &A, &B, &R);

				Tpm2BnGcd(&R, &A, &B);
				BnEmit("bn.gcd", n, &A, &B, &R);

				/* shifts, at a width that is NOT a multiple of the limb size and one that is */
				Tpm2BnShiftLeft(&R, &A, 37);
				BnEmit("bn.shl37", n, &A, &A, &R);
				Tpm2BnShiftLeft(&R, &A, 64);
				BnEmit("bn.shl64", n, &A, &A, &R);
				Tpm2BnShiftRight(&R, &A, 37);
				BnEmit("bn.shr37", n, &A, &A, &R);
				Tpm2BnShiftRight(&R, &A, 64);
				BnEmit("bn.shr64", n, &A, &A, &R);

				/* modexp and modinv need an ODD modulus */
				Tpm2BnCopy(&M, &B);
				if (M.Used == 0)
					Tpm2BnSetWord(&M, 3);
				M.Limb[0] |= 1u;

				Tpm2BnSetWord(&T, 65537);
				if (Tpm2BnModExp(&R, &A, &T, &M))
					BnEmit("bn.modexp", n, &A, &M, &R);

				if (Tpm2BnModInv(&R, &A, &M))
					BnEmit("bn.modinv", n, &A, &M, &R);
				else
					printf("bn.modinv_none.%u=1\n", n);
			}
		}
		printf("bn.vectors=%u\n", n);

		/* --- edges that random vectors do not reach --------------------------------- */
		Tpm2BnZero(&A);
		Tpm2BnSetWord(&B, 1);
		printf("bn.zero_bits=%u\n", Tpm2BnBits(&A));
		printf("bn.zero_iszero=%u\n", (unsigned)Tpm2BnIsZero(&A));
		printf("bn.zero_cmp_one=%d\n", (int)Tpm2BnCmp(&A, &B));
		Tpm2BnAdd(&R, &A, &B);
		printf("bn.zero_plus_one=%u\n", R.Limb[0]);
		Tpm2BnMul(&R, &A, &B);
		printf("bn.zero_times_one=%u\n", (unsigned)Tpm2BnIsZero(&R));

		/* subtracting a larger value must REFUSE, not wrap */
		printf("bn.sub_underflow=%u\n", (unsigned)Tpm2BnSub(&R, &A, &B));
		printf("bn.sub_underflow_zeroed=%u\n", (unsigned)Tpm2BnIsZero(&R));

		/* an EVEN modulus must be refused by ModExp, not answered wrongly */
		Tpm2BnSetWord(&M, 100);
		Tpm2BnSetWord(&A, 7);
		Tpm2BnSetWord(&T, 3);
		printf("bn.modexp_even=%u\n", (unsigned)Tpm2BnModExp(&R, &A, &T, &M));

		/* x mod 1 is 0 */
		Tpm2BnSetWord(&M, 1);
		Tpm2BnModExp(&R, &A, &T, &M);
		printf("bn.modexp_mod1=%u\n", (unsigned)Tpm2BnIsZero(&R));

		/* division by zero must refuse */
		Tpm2BnZero(&M);
		Tpm2BnSetWord(&A, 5);
		printf("bn.div_by_zero=%u\n", (unsigned)Tpm2BnDivMod(&Q, &R, &A, &M));

		/* aliasing: R and A the same object must still be correct */
		BnRandom(&A, 64);
		Tpm2BnCopy(&T, &A);
		Tpm2BnAdd(&A, &A, &A);
		Tpm2BnAdd(&R, &T, &T);
		printf("bn.alias_add=%d\n", (int)Tpm2BnCmp(&A, &R));
		Tpm2BnCopy(&A, &T);
		Tpm2BnMul(&A, &A, &A);
		Tpm2BnMul(&R, &T, &T);
		printf("bn.alias_mul=%d\n", (int)Tpm2BnCmp(&A, &R));

		/* to/from bytes must round-trip, and must REFUSE a buffer that is too small */
		{
			UINT8 Buf[256];
			UINT8 Small[8];
			BnRandom(&A, 256);
			printf("bn.roundtrip_out=%u\n", (unsigned)Tpm2BnToBytes(&A, Buf, 256));
			Tpm2BnFromBytes(&B, Buf, 256);
			printf("bn.roundtrip=%d\n", (int)Tpm2BnCmp(&A, &B));
			printf("bn.tobytes_short=%u\n", (unsigned)Tpm2BnToBytes(&A, Small, 8));
			/* leading zeros must not count against the size limit */
			Tpm2BnFromBytes(&B, Buf, 256);
			printf("bn.leading_zeros=%d\n", (int)Tpm2BnCmp(&A, &B));

			/*
			 * (!) THE PADDING ITSELF, WHICH THE CHECK ABOVE CANNOT SEE. `bn.leading_zeros`
			 * compares VALUES, and Tpm2BnFromBytes ignores leading zeros -- so a ToBytes that
			 * left-justified, or that stripped the padding, would round-trip perfectly and pass.
			 *
			 * It matters because a TPM2B whose width tracked its value would change an object's
			 * Name for one key in 256. Found while injuring Tpm2Object: a variable-width modulus
			 * survived that whole suite, because a KeyBits-bit RSA modulus NEVER has a leading
			 * zero octet and the property is unobservable there. So it is tested here, on a small
			 * value in a wide buffer, where it can actually be wrong.
			 */
			{
				UINT8 Pad[16];
				Tpm2BnSetWord(&A, 0x0102u);
				printf("bn.pad_ok=%u\n", (unsigned)Tpm2BnToBytes(&A, Pad, 16));
				PrintHexN("bn.pad", Pad, 16);
			}
		}
	}

	/* ===========================================================================
	 * KNOWN-ANSWER LAYER: ask for EVERYTHING.
	 *
	 * (!) THE DEMAND TRACE NAMES ONLY WHAT ONE OS ASKED FOR ON ONE BOOT. It is the right
	 * instrument for deciding what to build NEXT and the wrong one for deciding whether what
	 * we built is CORRECT -- a command Windows never sends is untested by definition, and the
	 * first time anything else asks for it is the worst moment to find out.
	 *
	 * So this sweeps the whole TPM_CC range from Part 2 v185: 0x11F to 0x1AA, every code,
	 * implemented or not. The C side EMITS AND JUDGES NOTHING; check_tpm2_core.py knows which
	 * codes we implement (it reads the dispatcher table) and checks each answer accordingly.
	 * =========================================================================== */
	{
		TPM2_PCR_BANK      KBank;
		TPM2_DISPATCH_INFO KInfo;
		UINT8  KCmd[64];
		UINT8  KOut[512];
		UINT32 cc;
		UINT32 KN;

		for (cc = 0x0000011Fu; cc <= 0x000001AAu; cc++)
		{
			//
			// A minimal WELL-FORMED header: correct tag, correct size, nothing after it. Any
			// command needing arguments must answer TPM_RC_COMMAND_SIZE; any command we do not
			// implement must answer TPM_RC_COMMAND_CODE. Both are recognitions, and telling them
			// apart is exactly what says whether a code reached a handler.
			//
			Tpm2PcrStartupClear(&KBank, 0);
			Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
			Tpm2WriteBe32(KCmd + 2, 10);
			Tpm2WriteBe32(KCmd + 6, cc);
			KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);

			//
			// rc, bytes returned, the response TAG, and the response's OWN size field. The last
			// two are the universal invariants: every response must carry a valid tag and must
			// declare its own length correctly, whatever the command was.
			//
			printf("kat.sweep.%03X=%03X %u %04X %u\n", cc, KInfo.ResponseCode, KN,
			       (unsigned)Tpm2ReadBe16(KOut), (unsigned)Tpm2ReadBe32(KOut + 2));
		}
		printf("kat.sweep_first=11F\n");
		printf("kat.sweep_last=1AA\n");

		/* --- malformed inputs, on a spread of implemented and unimplemented codes ------ */
		{
			static const UINT32 Codes[] = {
				0x00000143u,  /* SelfTest        implemented, no arguments   */
				0x00000144u,  /* Startup         implemented, 2-byte argument */
				0x00000173u,  /* ReadPublic      implemented, 4-byte argument */
				0x0000017Au,  /* GetCapability   implemented, 12-byte argument */
				0x00000181u,  /* ReadClock       implemented, no arguments   */
				0x00000131u,  /* CreatePrimary   NOT implemented             */
				0x00000158u,  /* Quote           NOT implemented             */
				0x00000123u,  /* reserved code, in range, never assigned     */
			};
			UINT32 k;

			for (k = 0; k < sizeof(Codes) / sizeof(Codes[0]); k++)
			{
				UINT32 c = Codes[k];

				/* 1: declared size enormously larger than what was handed over */
				Tpm2PcrStartupClear(&KBank, 0);
				Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
				Tpm2WriteBe32(KCmd + 2, 0xFFFFFFFFu);
				Tpm2WriteBe32(KCmd + 6, c);
				KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);
				printf("kat.huge.%03X=%03X %u %u\n", c, KInfo.ResponseCode, KN,
				       (unsigned)Tpm2ReadBe32(KOut + 2));

				/* 2: declared size of zero */
				Tpm2WriteBe32(KCmd + 2, 0);
				KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);
				printf("kat.zerosize.%03X=%03X %u %u\n", c, KInfo.ResponseCode, KN,
				       (unsigned)Tpm2ReadBe32(KOut + 2));

				/* 3: a tag that is neither NO_SESSIONS nor SESSIONS */
				Tpm2WriteBe16(KCmd, 0x1234);
				Tpm2WriteBe32(KCmd + 2, 10);
				KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);
				printf("kat.badtag.%03X=%03X %u %u\n", c, KInfo.ResponseCode, KN,
				       (unsigned)Tpm2ReadBe32(KOut + 2));

				/* 4: a response buffer far too small to hold even a header */
				Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
				KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, 4, &KInfo);
				printf("kat.tinyout.%03X=%03X %u\n", c, KInfo.ResponseCode, KN);
			}
			printf("kat.malformed_codes=%u\n",
			       (unsigned)(sizeof(Codes) / sizeof(Codes[0])));
		}

		/* --- known answers for the commands we DO implement ---------------------------- */
		{
			UINT8 Buf[512];

			/* TPM2_Startup(CLEAR): PTP Table 15 fixes the bank the TPM comes up with. */
			Tpm2PcrStartupClear(&KBank, 0);
			Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
			Tpm2WriteBe32(KCmd + 2, 12);
			Tpm2WriteBe32(KCmd + 6, 0x00000144u);
			Tpm2WriteBe16(KCmd + 10, 0);          /* TPM_SU_CLEAR */
			KN = Tpm2Dispatch(&KBank, KCmd, 12, KOut, sizeof(KOut), &KInfo);
			printf("kat.startup_rc=%03X\n", KInfo.ResponseCode);
			printf("kat.startup_len=%u\n", KN);
			printf("kat.startup_started=%u\n", (unsigned)KBank.Started);

			/* TPM2_SelfTest(fullTest=NO) */
			Tpm2WriteBe32(KCmd + 2, 11);
			Tpm2WriteBe32(KCmd + 6, 0x00000143u);
			KCmd[10] = 0;
			KN = Tpm2Dispatch(&KBank, KCmd, 11, KOut, sizeof(KOut), &KInfo);
			printf("kat.selftest_rc=%03X\n", KInfo.ResponseCode);
			printf("kat.selftest_len=%u\n", KN);

			/* TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 1).
			 * The family indicator is SPEC-DEFINED as "2.0\0" -- a real known answer, not one
			 * of our identity choices. */
			Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
			Tpm2WriteBe32(KCmd + 2, 22);
			Tpm2WriteBe32(KCmd + 6, 0x0000017Au);
			Tpm2WriteBe32(KCmd + 10, 6);          /* TPM_CAP_TPM_PROPERTIES */
			Tpm2WriteBe32(KCmd + 14, 0x100);      /* TPM_PT_FAMILY_INDICATOR */
			Tpm2WriteBe32(KCmd + 18, 1);
			KN = Tpm2Dispatch(&KBank, KCmd, 22, KOut, sizeof(KOut), &KInfo);
			printf("kat.family_rc=%03X\n", KInfo.ResponseCode);
			printf("kat.family_more=%u\n", (unsigned)KOut[10]);
			printf("kat.family_cap=%u\n", (unsigned)Tpm2ReadBe32(KOut + 11));
			printf("kat.family_count=%u\n", (unsigned)Tpm2ReadBe32(KOut + 15));
			printf("kat.family_prop=%X\n", (unsigned)Tpm2ReadBe32(KOut + 19));
			printf("kat.family_value=%X\n", (unsigned)Tpm2ReadBe32(KOut + 23));

			/* TPM2_GetTestResult: Part 3 gives outData (TPM2B_MAX_BUFFER) then testResult
			 * (TPM_RC). A TPM that has passed its self-tests reports empty outData and
			 * TPM_RC_SUCCESS, so the whole response is fixed and is a known answer. */
			Tpm2WriteBe16(KCmd, TPM2_ST_NO_SESSIONS);
			Tpm2WriteBe32(KCmd + 2, 10);
			Tpm2WriteBe32(KCmd + 6, 0x0000017Cu);
			KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);
			printf("kat.testresult_rc=%03X\n", KInfo.ResponseCode);
			printf("kat.testresult_len=%u\n", KN);
			PrintHexN("kat.testresult_body", KOut + 10, KN > 10 ? KN - 10 : 0);

			/* TPM2_GetRandom with the deterministic test source: a true known answer. */
			Tpm2SetEntropySource(TestEntropy);
			Tpm2WriteBe32(KCmd + 2, 12);
			Tpm2WriteBe32(KCmd + 6, 0x0000017Bu);
			Tpm2WriteBe16(KCmd + 10, 8);
			KN = Tpm2Dispatch(&KBank, KCmd, 12, KOut, sizeof(KOut), &KInfo);
			printf("kat.random_len=%u\n", KN);
			printf("kat.random_size=%u\n", (unsigned)Tpm2ReadBe16(KOut + 10));
			PrintHexN("kat.random_bytes", KOut + 12, 8);
			Tpm2SetEntropySource(NULL);

			/* TPM2_ReadClock with the fixed test clock: also a true known answer. */
			Tpm2SetTimeSource(TestClock);
			Tpm2WriteBe32(KCmd + 2, 10);
			Tpm2WriteBe32(KCmd + 6, 0x00000181u);
			KN = Tpm2Dispatch(&KBank, KCmd, 10, KOut, sizeof(KOut), &KInfo);
			printf("kat.clock_len=%u\n", KN);
			PrintHexN("kat.clock_body", KOut + 10, 25);
			Tpm2SetTimeSource(NULL);

			(void)Buf;
		}
	}

	/* Tpm2Prime: primality, then a real RSA-2048 key ------------------------------- */
	{
		TPM2_BN V;
		UINT8  B[512];
		UINT32 k;

		/*
		 * Values the ORACLE decides. Python is told the number and asked whether it is prime;
		 * nothing here says which answer is expected, so the harness cannot bias the result.
		 */
		{
			static const char* Vals[] = {
				/* small, both ways */
				"02", "03", "04", "05", "09", "0b", "0f", "fb", "ff",
				/* Carmichael numbers: composites that pass FERMAT for every coprime base.
				 * 561, 1105, 1729, 2465, 2821, 6601, 8911, 62745, 162401, 314821 */
				"0231", "0451", "06c1", "09a1", "0b05", "19c9", "22cf", "f519", "027a61",
				"04cdc5",
				/*
				 * (!) THE ONES ABOVE NEVER REACH MILLER-RABIN. Every small Carmichael number is a
				 * product of small primes, so the sieve rejects it first -- which made the claim
				 * "these catch a Fermat degeneration" FALSE. Proven by injuring the inner loop and
				 * watching the suite stay green.
				 *
				 * These three are Chernick Carmichaels (6k+1)(12k+1)(18k+1) with EVERY factor above
				 * 1024, so they survive the sieve and land in Miller-Rabin:
				 *   1171 x 2341 x 3511 =  9624742921
				 *   1237 x 2473 x 3709 = 11346205609
				 *   1297 x 2593 x 3889 = 13079177569
				 * Fermat calls all three prime for every coprime base. Miller-Rabin must not.
				 */
				"023dadec09", "02a4495ba9", "030b946961",
				/* squares and products of primes near the sieve boundary */
				"0100003", "3b9aca07", "7fffffff", "80000000",
				/* a 256-bit prime and its neighbours */
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43",
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45",
			};
			for (k = 0; k < sizeof(Vals) / sizeof(Vals[0]); k++)
			{
				UINT32 n = 0;
				const char* h = Vals[k];
				while (h[2 * n] && h[2 * n + 1])
				{
					UINT32 hi = h[2 * n], lo = h[2 * n + 1];
					hi = (hi <= 0x39) ? hi - 0x30 : (hi | 0x20) - 0x57;
					lo = (lo <= 0x39) ? lo - 0x30 : (lo | 0x20) - 0x57;
					B[n] = (UINT8)((hi << 4) | lo);
					n++;
				}
				Tpm2BnFromBytes(&V, B, n);
				printf("pr.isprime.%u=%s %u\n", k, Vals[k],
				       (unsigned)Tpm2BnIsPrime(&V, 20, NULL));
			}
			printf("pr.isprime_count=%u\n",
			       (unsigned)(sizeof(Vals) / sizeof(Vals[0])));
		}

		/* the sieve on its own */
		Tpm2BnSetWord(&V, 1024u * 1024u + 1u);   /* 1048577 = 17 * 61681 */
		printf("pr.sieve_composite=%u\n", (unsigned)Tpm2BnHasSmallFactor(&V));
		Tpm2BnSetWord(&V, 1000003u);             /* prime, no factor below 1024 */
		printf("pr.sieve_prime=%u\n", (unsigned)Tpm2BnHasSmallFactor(&V));
		Tpm2BnSetWord(&V, 1021u);                /* IS a sieve entry: not its own factor */
		printf("pr.sieve_self=%u\n", (unsigned)Tpm2BnHasSmallFactor(&V));

		/* a generated 256-bit prime, handed to the oracle to judge */
		{
			TPM2_BN E, G;
			Tpm2BnSetWord(&E, 65537);
			printf("pr.gen256_ok=%u\n",
			       (unsigned)Tpm2BnGeneratePrime(&G, 256, &E, TestPrimeRand));
			printf("pr.gen256_bits=%u\n", Tpm2BnBits(&G));
			BnHexKey("pr.gen256", &G);
		}

		/* --- a real RSA-2048 key ------------------------------------------------- */
		{
			static TPM2_RSA_KEY Key;   /* 2.7 KB: static, not stack */
			TPM2_BN Msg, Enc, Dec;

			printf("pr.rsa_ok=%u\n",
			       (unsigned)Tpm2RsaGenerateKey(&Key, 2048, 65537, TestPrimeRand));
			printf("pr.rsa_bits=%u\n", Tpm2BnBits(&Key.N));
			printf("pr.rsa_pbits=%u\n", Tpm2BnBits(&Key.P));
			printf("pr.rsa_qbits=%u\n", Tpm2BnBits(&Key.Q));
			BnHexKey("pr.rsa_n", &Key.N);
			BnHexKey("pr.rsa_p", &Key.P);
			BnHexKey("pr.rsa_q", &Key.Q);
			BnHexKey("pr.rsa_d", &Key.D);
			BnHexKey("pr.rsa_e", &Key.E);

			/*
			 * (!) THE ROUND TRIP IS THE TEST THAT OWES NOTHING TO HOW THE KEY WAS MADE. Every
			 * other check re-reads the generator's own outputs; this one asserts the key WORKS.
			 */
			BnRandom(&Msg, 200);
			Tpm2BnDivMod(NULL, &Msg, &Msg, &Key.N);
			BnHexKey("pr.rsa_msg", &Msg);
			printf("pr.rsa_enc_ok=%u\n", (unsigned)Tpm2RsaPublic(&Enc, &Msg, &Key));
			printf("pr.rsa_dec_ok=%u\n", (unsigned)Tpm2RsaPrivate(&Dec, &Enc, &Key));
			printf("pr.rsa_roundtrip=%d\n", (int)Tpm2BnCmp(&Msg, &Dec));
			printf("pr.rsa_enc_differs=%d\n", (int)Tpm2BnCmp(&Msg, &Enc));
		}
	}

	/* KDFa, and the deterministic stream on top of it ------------------------------ */
	{
		static const UINT8 K[] = { 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
		                           0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
		static const UINT8 CU[] = { 0xde,0xad,0xbe,0xef };
		static const UINT8 CV[] = { 0xca,0xfe };
		UINT8 O[256];

		/*
		 * (!) THE SINGLE-BLOCK CASE IS THE ONE WITH AN INDEPENDENT ORACLE. At exactly one
		 * digest of output, KDFa collapses to a single HMAC, and Python computes that with its
		 * own hmac module -- code that is not ours and was not written from this spec text.
		 */
		printf("kdf.a1_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "IDENTITY", CU, sizeof(CU), CV, sizeof(CV), 256, O));
		PrintHexN("kdf.a1", O, 32);

		/* two blocks: exercises the counter and the concatenation */
		printf("kdf.a2_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "IDENTITY", CU, sizeof(CU), CV, sizeof(CV), 512, O));
		PrintHexN("kdf.a2", O, 64);

		/* a partial block: exercises truncation direction */
		printf("kdf.a3_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "IDENTITY", CU, sizeof(CU), CV, sizeof(CV), 400, O));
		PrintHexN("kdf.a3", O, 50);

		/* 521 bits: Part 1 gives this exact example -- 66 octets, top 7 bits of octet 0 clear */
		printf("kdf.a521_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "ECC", CU, sizeof(CU), CV, sizeof(CV), 521, O));
		PrintHexN("kdf.a521", O, 66);
		printf("kdf.a521_mso=%u\n", (unsigned)O[0]);

		/*
		 * (!) 517 BITS, BECAUSE 521 CANNOT DISTINGUISH MASK FROM SHIFT. At 521 the MSO keeps a
		 * SINGLE bit, so masking and shifting agree whenever that octet's top and bottom bits
		 * match -- a coin flip. Proven by shifting instead of masking and watching the 521 case
		 * stay green. At 517 five bits survive and the two operations cannot coincide.
		 */
		printf("kdf.a517_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "ECC", CU, sizeof(CU), CV, sizeof(CV), 517, O));
		PrintHexN("kdf.a517", O, 65);
		printf("kdf.a517_mso=%u\n", (unsigned)O[0]);

		/* no label at all: a single zero octet stands in for it */
		printf("kdf.nolabel_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       NULL, CU, sizeof(CU), CV, sizeof(CV), 256, O));
		PrintHexN("kdf.nolabel", O, 32);

		/* SHA-384, to prove the algorithm is not wired to one hash */
		printf("kdf.sha384_ok=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA384, K, sizeof(K),
		       "IDENTITY", CU, sizeof(CU), CV, sizeof(CV), 384, O));
		PrintHexN("kdf.sha384", O, 48);

		/* zero bits must refuse rather than return an empty success */
		printf("kdf.zerobits=%u\n", (unsigned)Tpm2KdfA(TPM2_ALG_SHA256, K, sizeof(K),
		       "X", CU, sizeof(CU), CV, sizeof(CV), 0, O));

		/* --- the stream, and the property that matters: REPRODUCIBILITY --------- */
		{
			TPM2_KDF_STREAM S1, S2;
			UINT8 A[100], B[100];
			UINT32 k;
			UINT32 Same = 1;

			Tpm2KdfStreamInit(&S1, TPM2_ALG_SHA256, K, sizeof(K), "SEED", CU, sizeof(CU));
			Tpm2KdfStreamBytes(&S1, A, sizeof(A));
			PrintHexN("kdf.stream", A, 64);

			/* a second stream from the same seed must produce the same bytes -- this is the
			 * whole point, and the reason event 519 exists without it */
			Tpm2KdfStreamInit(&S2, TPM2_ALG_SHA256, K, sizeof(K), "SEED", CU, sizeof(CU));
			Tpm2KdfStreamBytes(&S2, B, sizeof(B));
			for (k = 0; k < sizeof(A); k++)
				if (A[k] != B[k]) Same = 0;
			printf("kdf.stream_repeats=%u\n", Same);

			/* drawn in small pieces, the stream must be identical to one long draw */
			Tpm2KdfStreamInit(&S2, TPM2_ALG_SHA256, K, sizeof(K), "SEED", CU, sizeof(CU));
			for (k = 0; k < sizeof(B); k += 7)
				Tpm2KdfStreamBytes(&S2, B + k,
				                   (sizeof(B) - k < 7) ? (UINT32)(sizeof(B) - k) : 7u);
			Same = 1;
			for (k = 0; k < sizeof(A); k++)
				if (A[k] != B[k]) Same = 0;
			printf("kdf.stream_chunked=%u\n", Same);

			/* a different seed must give different bytes */
			{
				UINT8 K2[16];
				for (k = 0; k < 16; k++) K2[k] = 0x0c;
				Tpm2KdfStreamInit(&S2, TPM2_ALG_SHA256, K2, 16, "SEED", CU, sizeof(CU));
				Tpm2KdfStreamBytes(&S2, B, sizeof(B));
				Same = 1;
				for (k = 0; k < sizeof(A); k++)
					if (A[k] != B[k]) Same = 0;
				printf("kdf.stream_seed_matters=%u\n", Same);
			}
		}

		/* --- THE POINT: the same seed must give the same RSA key ---------------- */
		{
			static TPM2_RSA_KEY K1, K2;
			static TPM2_KDF_STREAM Sk;
			UINT32 ok1, ok2;

			Tpm2KdfStreamInit(&Sk, TPM2_ALG_SHA256, K, sizeof(K), "RSA", CU, sizeof(CU));
			gKdfStream = &Sk;
			ok1 = Tpm2RsaGenerateKey(&K1, 1024, 65537, KdfStreamRand);

			Tpm2KdfStreamInit(&Sk, TPM2_ALG_SHA256, K, sizeof(K), "RSA", CU, sizeof(CU));
			gKdfStream = &Sk;
			ok2 = Tpm2RsaGenerateKey(&K2, 1024, 65537, KdfStreamRand);

			printf("kdf.rsa_ok=%u\n", (unsigned)(ok1 && ok2));
			printf("kdf.rsa_same=%d\n", (int)Tpm2BnCmp(&K1.N, &K2.N));
			BnHexKey("kdf.rsa_n", &K1.N);
			BnHexKey("kdf.rsa_p", &K1.P);
			BnHexKey("kdf.rsa_q", &K1.Q);
			gKdfStream = NULL;
		}
	}

	/* Tpm2Object: the two templates Windows actually sends ------------------------- */
	{
		/*
		 * (!) THESE ARE THE REAL BYTES, captured from the CRB on 2026-09-08 (trace v4, 343 and
		 * 375 bytes, captured == declared). A template written from the specification would test
		 * my reading of Part 2; these test the thing Windows will actually send.
		 *
		 * SRK, TPM_RH_OWNER: RSA-2048 restricted decrypt, AES-128-CFB, attrs 0x00030472,
		 * no policy, exponent 0 (the default), unique 256 zero octets.
		 */
		/* 26 fixed octets, then the policy, then the 256-octet unique field. Sized by counting
		 * the Part 2 Table 235 fields, not by guessing: 282 and 314. */
		static UINT8 SrkT[26 + 256];
		static UINT8 EkT[26 + 32 + 256];
		static const UINT8 EkPolicy[32] = {
			0x83,0x71,0x97,0x67,0x44,0x84,0xb3,0xf8, 0x1a,0x90,0xcc,0x8d,0x46,0xa5,0xd7,0x24,
			0xfd,0x52,0xd7,0x6e,0x06,0x52,0x0b,0x64, 0xf2,0xa1,0xda,0x1b,0x33,0x14,0x69,0xaa };
		UINT32 SrkLen = 0, EkLen = 0;
		UINT32 n, q;

		n = 0;
		PutBe16At(SrkT, &n, 0x0001);            /* type    RSA        */
		PutBe16At(SrkT, &n, 0x000B);            /* nameAlg SHA-256    */
		PutBe32At(SrkT, &n, 0x00030472u);       /* objectAttributes   */
		PutBe16At(SrkT, &n, 0);                 /* authPolicy empty   */
		PutBe16At(SrkT, &n, 0x0006);            /* symmetric AES      */
		PutBe16At(SrkT, &n, 128);
		PutBe16At(SrkT, &n, 0x0043);            /* CFB                */
		PutBe16At(SrkT, &n, 0x0010);            /* scheme NULL        */
		PutBe16At(SrkT, &n, 2048);
		PutBe32At(SrkT, &n, 0);                 /* exponent = default */
		PutBe16At(SrkT, &n, 256);               /* unique: 256 zeros  */
		n += 256;
		SrkLen = n;

		n = 0;
		PutBe16At(EkT, &n, 0x0001);
		PutBe16At(EkT, &n, 0x000B);
		PutBe32At(EkT, &n, 0x000300B2u);        /* adminWithPolicy, no userWithAuth */
		PutBe16At(EkT, &n, 32);
		for (q = 0; q < 32; q++) EkT[n + q] = EkPolicy[q];
		n += 32;
		PutBe16At(EkT, &n, 0x0006);
		PutBe16At(EkT, &n, 128);
		PutBe16At(EkT, &n, 0x0043);
		PutBe16At(EkT, &n, 0x0010);
		PutBe16At(EkT, &n, 2048);
		PutBe32At(EkT, &n, 0);
		PutBe16At(EkT, &n, 256);
		n += 256;
		EkLen = n;

		printf("obj.srk_len=%u\n", (unsigned)SrkLen);
		printf("obj.ek_len=%u\n", (unsigned)EkLen);
		PrintHexN("obj.srk_bytes", SrkT, SrkLen);
		PrintHexN("obj.ek_bytes", EkT, EkLen);

		{
			TPM2_PUBLIC P1, P2;
			UINT8 Round[600];
			UINT8 Name[2 + TPM2_MAX_DIGEST_SIZE];
			UINT16 NameLen = 0;
			UINT32 used = 0, wrote = 0, k, same;

			/* --- SRK: parse, round-trip, Name --- */
			printf("obj.srk_rc=%u\n", Tpm2PublicUnmarshal(SrkT, SrkLen, &P1, &used));
			printf("obj.srk_used=%u\n", (unsigned)used);
			printf("obj.srk_type=%u\n", (unsigned)P1.Type);
			printf("obj.srk_attrs=%u\n", (unsigned)P1.ObjectAttributes);
			printf("obj.srk_keybits=%u\n", (unsigned)P1.KeyBits);
			printf("obj.srk_exp_field=%u\n", (unsigned)P1.Exponent);
			printf("obj.srk_exp_used=%u\n", (unsigned)Tpm2PublicExponent(&P1));
			printf("obj.srk_policy_len=%u\n", (unsigned)P1.AuthPolicyLen);
			printf("obj.srk_unique_len=%u\n", (unsigned)P1.UniqueLen);

			/*
			 * (!) THE ROUND TRIP IS NOT A CONVENIENCE TEST. The object Name is the hash of these
			 * exact octets, so a marshaller that normalises ANY field -- most temptingly the zero
			 * exponent -- produces a Name no other TPM would compute.
			 */
			printf("obj.srk_marshal_rc=%u\n",
			       Tpm2PublicMarshal(&P1, Round, sizeof(Round), &wrote));
			same = (wrote == SrkLen) ? 1u : 0u;
			for (k = 0; k < SrkLen && k < wrote; k++)
				if (Round[k] != SrkT[k]) same = 0;
			printf("obj.srk_roundtrip=%u\n", same);

			printf("obj.srk_name_ok=%u\n", (unsigned)Tpm2ObjectName(&P1, Name, &NameLen));
			printf("obj.srk_name_len=%u\n", (unsigned)NameLen);
			PrintHexN("obj.srk_name", Name, NameLen);

			/* --- EK: the policy must survive, and the Name must DIFFER --- */
			printf("obj.ek_rc=%u\n", Tpm2PublicUnmarshal(EkT, EkLen, &P2, &used));
			printf("obj.ek_used=%u\n", (unsigned)used);
			printf("obj.ek_attrs=%u\n", (unsigned)P2.ObjectAttributes);
			printf("obj.ek_policy_len=%u\n", (unsigned)P2.AuthPolicyLen);
			PrintHexN("obj.ek_policy", P2.AuthPolicy, P2.AuthPolicyLen);
			printf("obj.ek_marshal_rc=%u\n",
			       Tpm2PublicMarshal(&P2, Round, sizeof(Round), &wrote));
			same = (wrote == EkLen) ? 1u : 0u;
			for (k = 0; k < EkLen && k < wrote; k++)
				if (Round[k] != EkT[k]) same = 0;
			printf("obj.ek_roundtrip=%u\n", same);
			Tpm2ObjectName(&P2, Name, &NameLen);
			PrintHexN("obj.ek_name", Name, NameLen);

			/* --- refusals: each must name the right field --- */
			{
				static UINT8 Bad[600];
				TPM2_PUBLIC Px;
				UINT32 j;

				for (j = 0; j < SrkLen; j++) Bad[j] = SrkT[j];
				Bad[0] = 0x00; Bad[1] = 0x23;      /* TPM_ALG_ECC */
				printf("obj.bad_type=%u\n",
				       Tpm2PublicUnmarshal(Bad, SrkLen, &Px, &used));

				for (j = 0; j < SrkLen; j++) Bad[j] = SrkT[j];
				Bad[2] = 0x00; Bad[3] = 0x99;      /* a hash we do not implement */
				printf("obj.bad_hash=%u\n",
				       Tpm2PublicUnmarshal(Bad, SrkLen, &Px, &used));

				for (j = 0; j < SrkLen; j++) Bad[j] = SrkT[j];
				Bad[16] = 0x00; Bad[17] = 0x14;    /* scheme RSASSA, not NULL */
				printf("obj.bad_scheme=%u\n",
				       Tpm2PublicUnmarshal(Bad, SrkLen, &Px, &used));

				for (j = 0; j < SrkLen; j++) Bad[j] = SrkT[j];
				Bad[20] = 0x00; Bad[21] = 0x00;
				Bad[22] = 0x00; Bad[23] = 0x04;    /* exponent 4: even */
				printf("obj.bad_exp=%u\n",
				       Tpm2PublicUnmarshal(Bad, SrkLen, &Px, &used));

				/*
				 * (!) TRUNCATION MUST BE INSUFFICIENT, NOT SIZE. Hardware taught us that on 90
				 * command codes: running out of octets while unmarshalling is INSUFFICIENT.
				 */
				printf("obj.trunc=%u\n",
				       Tpm2PublicUnmarshal(SrkT, SrkLen - 1, &Px, &used));
				printf("obj.trunc_head=%u\n",
				       Tpm2PublicUnmarshal(SrkT, 3, &Px, &used));
				printf("obj.marshal_tight=%u\n",
				       Tpm2PublicMarshal(&P1, Round, SrkLen - 1, &wrote));
			}

			/* --- THE POINT: a primary key that is reproducible --- */
			{
				static TPM2_RSA_KEY K1, K2;
				static TPM2_PUBLIC O1, O2;
				static UINT8 Seed[32];
				UINT8 N1[2 + TPM2_MAX_DIGEST_SIZE], N2[2 + TPM2_MAX_DIGEST_SIZE];
				UINT16 L1 = 0, L2 = 0;
				UINT32 r1, r2, j;

				for (j = 0; j < 32; j++) Seed[j] = (UINT8)(0xA0 + j);

				/* 1024 bits rather than 2048 purely so the suite stays quick; the code path is
				 * identical and 2048 is exercised by the RSA tests above. */
				P1.KeyBits = 1024;
				r1 = Tpm2CreatePrimaryRsa(Seed, 32, &P1, NULL, 0, &K1, &O1);
				r2 = Tpm2CreatePrimaryRsa(Seed, 32, &P1, NULL, 0, &K2, &O2);
				printf("obj.pri_rc1=%u\n", r1);
				printf("obj.pri_rc2=%u\n", r2);
				printf("obj.pri_same_n=%d\n", (int)Tpm2BnCmp(&K1.N, &K2.N));
				printf("obj.pri_unique_len=%u\n", (unsigned)O1.UniqueLen);
				PrintHexN("obj.pri_unique", O1.Unique, O1.UniqueLen);
				BnHexKey("obj.pri_n", &K1.N);

				/* the returned public area must still name the same object twice */
				Tpm2ObjectName(&O1, N1, &L1);
				Tpm2ObjectName(&O2, N2, &L2);
				same = (L1 == L2) ? 1u : 0u;
				for (k = 0; k < L1 && k < L2; k++)
					if (N1[k] != N2[k]) same = 0;
				printf("obj.pri_name_same=%u\n", same);
				PrintHexN("obj.pri_name", N1, L1);

				/* a DIFFERENT seed must give a different key -- otherwise the seed is decorative */
				Seed[0] ^= 0xFF;
				Tpm2CreatePrimaryRsa(Seed, 32, &P1, NULL, 0, &K2, &O2);
				printf("obj.pri_seed_matters=%d\n", (int)Tpm2BnCmp(&K1.N, &K2.N));
				Seed[0] ^= 0xFF;

				/* and a different TEMPLATE must too: the EK and the SRK share a seed on a real
				 * TPM only if the hierarchy seeds are the same, and never share a KEY */
				P2.KeyBits = 1024;
				Tpm2CreatePrimaryRsa(Seed, 32, &P2, NULL, 0, &K2, &O2);
				printf("obj.pri_template_matters=%d\n", (int)Tpm2BnCmp(&K1.N, &K2.N));

				/* no seed at all must REFUSE, not invent one */
				printf("obj.pri_noseed=%u\n",
				       Tpm2CreatePrimaryRsa(Seed, 0, &P1, NULL, 0, &K2, &O2));
				P1.KeyBits = 2048;
				P2.KeyBits = 2048;
			}
		}
	}

	/* Tpm2Session: the authorization Windows actually sends ------------------------ */
	{
		/*
		 * (!) THE REAL 29-OCTET AUTHORIZATION, from both captured TPM2_CreatePrimary calls:
		 * authorizationSize 29, TPM_RS_PW, empty nonce, zero attributes, and a 20-octet
		 * authValue that is ENTIRELY ZERO.
		 *
		 * Those twenty zeros are the whole reason this file has a trailing-zero rule: Part 1
		 * makes them equal to the empty authorisation, which is what an unowned hierarchy has.
		 */
		static UINT8 Auth[4 + 29];
		TPM2_SESSION_AREA A;
		UINT32 used = 0, k, n;
		UINT8 Rsp[32];
		UINT32 wrote = 0;

		n = 0;
		PutBe32At(Auth, &n, 29);              /* authorizationSize          */
		PutBe32At(Auth, &n, 0x40000009u);     /* TPM_RS_PW                  */
		PutBe16At(Auth, &n, 0);               /* nonce: empty               */
		Auth[n++] = 0x00;                     /* sessionAttributes          */
		PutBe16At(Auth, &n, 20);              /* authValue: 20 octets ...   */
		for (k = 0; k < 20; k++) Auth[n + k] = 0;    /* ... all zero        */
		n += 20;
		printf("sess.len=%u\n", (unsigned)n);
		PrintHexN("sess.bytes", Auth, n);

		printf("sess.parse_rc=%u\n", Tpm2SessionParse(Auth, n, &A, &used));
		printf("sess.used=%u\n", (unsigned)used);
		printf("sess.count=%u\n", (unsigned)A.Count);
		printf("sess.area=%u\n", (unsigned)A.AreaSize);
		printf("sess.handle=%u\n", (unsigned)A.S[0].Handle);
		printf("sess.noncelen=%u\n", (unsigned)A.S[0].NonceLen);
		printf("sess.attrs=%u\n", (unsigned)A.S[0].Attributes);
		printf("sess.authlen=%u\n", (unsigned)A.S[0].AuthLen);

		/*
		 * (!) THE HEADLINE: twenty zero octets ARE the empty authorisation. If this trims to
		 * anything but zero, every CreatePrimary Windows sends fails to authorise.
		 */
		printf("sess.trim20=%u\n", (unsigned)Tpm2AuthTrim(A.S[0].Auth, A.S[0].AuthLen));
		printf("sess.authorize=%u\n",
		       Tpm2SessionAuthorize(&A.S[0], 0, NULL, 0));

		/* trailing-zero equality, in both directions */
		{
			static const UINT8 Pw[]   = { 'p', 'w', 0, 0, 0 };
			static const UINT8 Pw2[]  = { 'p', 'w' };
			static const UINT8 Zero[] = { 0, 0, 0 };
			static const UINT8 Lead[] = { 0, 'p', 'w' };

			printf("sess.eq_trailing=%u\n",
			       (unsigned)Tpm2AuthEqual(Pw, 5, Pw2, 2));
			/* (!) BOTH SIDES. Trimming only the caller's would make this one FALSE, and an
			 * entity whose authValue ends in zero would reject the password that set it. */
			printf("sess.eq_both=%u\n",
			       (unsigned)Tpm2AuthEqual(Pw2, 2, Pw, 5));
			printf("sess.eq_empty=%u\n",
			       (unsigned)Tpm2AuthEqual(Zero, 3, NULL, 0));
			/* leading zeros are NOT trailing zeros and must not be trimmed */
			printf("sess.eq_leading=%u\n",
			       (unsigned)Tpm2AuthEqual(Lead, 3, Pw2, 2));
			printf("sess.trim_lead=%u\n", (unsigned)Tpm2AuthTrim(Lead, 3));
		}

		/* the response acknowledgement: 5 octets, continueSession SET */
		printf("sess.rsp_rc=%u\n",
		       Tpm2SessionWriteResponse(&A, Rsp, sizeof(Rsp), &wrote));
		printf("sess.rsp_len=%u\n", (unsigned)wrote);
		PrintHexN("sess.rsp", Rsp, wrote);
		{
			/* a caller flag other than continueSession must SURVIVE, and continue must be ADDED */
			TPM2_SESSION_AREA B = A;
			B.S[0].Attributes = 0x20;         /* decrypt */
			Tpm2SessionWriteResponse(&B, Rsp, sizeof(Rsp), &wrote);
			printf("sess.rsp_attrs=%u\n", (unsigned)Rsp[2]);
			printf("sess.rsp_tight=%u\n",
			       Tpm2SessionWriteResponse(&B, Rsp, 4, &wrote));
		}

		/* --- refusals --- */
		{
			static UINT8 Bad[64];
			TPM2_SESSION_AREA C;
			UINT32 j;

			for (j = 0; j < n; j++) Bad[j] = Auth[j];

			/* authorizationSize larger than the octets present */
			PutBe32Raw(Bad, 0, 1000);
			printf("sess.big_area=%u\n", Tpm2SessionParse(Bad, n, &C, &used));
			/* and smaller than one session can possibly be */
			PutBe32Raw(Bad, 0, 4);
			printf("sess.tiny_area=%u\n", Tpm2SessionParse(Bad, n, &C, &used));
			/* a size that leaves a session half-parsed: 29 -> 20 cuts the authValue */
			PutBe32Raw(Bad, 0, 20);
			printf("sess.short_area=%u\n", Tpm2SessionParse(Bad, n, &C, &used));
			PutBe32Raw(Bad, 0, 29);

			/* fewer than 4 octets: nothing to read the size from */
			printf("sess.no_size=%u\n", Tpm2SessionParse(Bad, 3, &C, &used));

			/* an HMAC session handle must be REFUSED, not accepted and unchecked */
			Tpm2SessionParse(Auth, n, &C, &used);
			C.S[0].Handle = 0x02000000u;
			printf("sess.not_pw=%u\n", Tpm2SessionAuthorize(&C.S[0], 0, NULL, 0));

			/* a nonce on a password session is a caller error */
			Tpm2SessionParse(Auth, n, &C, &used);
			C.S[0].NonceLen = 8;
			printf("sess.pw_nonce=%u\n", Tpm2SessionAuthorize(&C.S[0], 0, NULL, 0));

			/* an attribute other than continueSession, likewise */
			Tpm2SessionParse(Auth, n, &C, &used);
			C.S[0].Attributes = 0x40;
			printf("sess.pw_attrs=%u\n", Tpm2SessionAuthorize(&C.S[0], 0, NULL, 0));

			/* the WRONG password must fail, or the check is decorative */
			{
				static const UINT8 Real[] = { 's', 'e', 'c', 'r', 'e', 't' };
				Tpm2SessionParse(Auth, n, &C, &used);
				printf("sess.wrong_pw=%u\n",
				       Tpm2SessionAuthorize(&C.S[0], 0, Real, 6));
				/* and the SECOND session numbers its error 2, not 1 */
				printf("sess.wrong_pw2=%u\n",
				       Tpm2SessionAuthorize(&C.S[0], 1, Real, 6));
			}
		}
	}

	/* Creation data, creation hash, creation ticket -------------------------------- */
	{
		TPM2_CREATION_DATA D;
		UINT8 Buf[400];
		UINT8 Dig[TPM2_MAX_DIGEST_SIZE];
		UINT8 Tk[128];
		UINT16 DigLen = 0;
		UINT32 wrote = 0, rc, k;
		static const UINT8 Proof[32] = {
			0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
			0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00 };
		static const UINT8 Name[34] = {
			0x00,0x0b,
			0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8, 0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,
			0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8, 0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,0xc0 };

		/*
		 * (!) THE CAPTURED COMMAND SENDS AN EMPTY creationPCR AND AN EMPTY outsideInfo, so this
		 * is the exact shape TPM2_CreatePrimary will produce on this machine. Part 2 Table 261:
		 * "pcrDigest.size shall be zero if the pcrSelect list is empty" -- so an empty selection
		 * gives a ZERO-LENGTH digest, not a digest of nothing.
		 */
		rc = Tpm2CreationDataForPrimary(&D, 0x40000001u, TPM2_LOCALITY_ZERO);
		printf("cre.primary_rc=%u\n", rc);
		printf("cre.parent_alg=%u\n", (unsigned)D.ParentNameAlg);
		printf("cre.parent_len=%u\n", (unsigned)D.ParentNameLen);
		PrintHexN("cre.parent_name", D.ParentName, D.ParentNameLen);
		PrintHexN("cre.parent_qn", D.ParentQualifiedName, D.ParentQualifiedNameLen);
		printf("cre.locality=%u\n", (unsigned)D.Locality);

		/* an empty TPML_PCR_SELECTION is a bare count of zero: four octets, no prefix */
		D.PcrSelectLen = 4;
		for (k = 0; k < 4; k++) D.PcrSelect[k] = 0;
		D.PcrDigestLen = 0;
		D.OutsideInfoLen = 0;

		rc = Tpm2CreationDataMarshal(&D, Buf, sizeof(Buf), &wrote);
		printf("cre.marshal_rc=%u\n", rc);
		printf("cre.marshal_len=%u\n", (unsigned)wrote);
		PrintHexN("cre.marshal", Buf, wrote);

		rc = Tpm2CreationHash(&D, TPM2_ALG_SHA256, Dig, &DigLen);
		printf("cre.hash_rc=%u\n", rc);
		printf("cre.hash_len=%u\n", (unsigned)DigLen);
		PrintHexN("cre.hash", Dig, DigLen);

		rc = Tpm2CreationTicket(Proof, 32, TPM2_ALG_SHA256, 0x40000001u,
		                        Name, 34, Dig, DigLen, Tk, sizeof(Tk), &wrote);
		printf("cre.ticket_rc=%u\n", rc);
		printf("cre.ticket_len=%u\n", (unsigned)wrote);
		PrintHexN("cre.ticket", Tk, wrote);

		/* --- refusals --- */
		/*
		 * (!) NO PROOF, NO TICKET. A ticket HMACed under an empty key would validate against
		 * nothing and look exactly like a real one until it mattered.
		 */
		printf("cre.ticket_noproof=%u\n",
		       Tpm2CreationTicket(NULL, 0, TPM2_ALG_SHA256, 0x40000001u,
		                          Name, 34, Dig, DigLen, Tk, sizeof(Tk), &wrote));
		printf("cre.ticket_tight=%u\n",
		       Tpm2CreationTicket(Proof, 32, TPM2_ALG_SHA256, 0x40000001u,
		                          Name, 34, Dig, DigLen, Tk, 8, &wrote));
		printf("cre.marshal_tight=%u\n",
		       Tpm2CreationDataMarshal(&D, Buf, 4, &wrote));
		printf("cre.bad_hierarchy=%u\n",
		       Tpm2CreationDataForPrimary(&D, 0x81000001u, TPM2_LOCALITY_ZERO));

		/*
		 * A DIFFERENT hierarchy must give a different ticket, or the hierarchy field is
		 * decorative and an endorsement ticket would validate as an owner ticket.
		 */
		{
			UINT8 Tk2[128];
			UINT32 w2 = 0, same = 1;
			Tpm2CreationTicket(Proof, 32, TPM2_ALG_SHA256, 0x4000000Bu,
			                   Name, 34, Dig, DigLen, Tk2, sizeof(Tk2), &w2);
			for (k = 0; k < w2 && k < wrote; k++)
				if (Tk[k] != Tk2[k]) same = 0;
			printf("cre.ticket_hierarchy=%u\n", same);

			/* and a different PROOF must give a different HMAC */
			{
				UINT8 P2[32];
				for (k = 0; k < 32; k++) P2[k] = Proof[k] ^ 0xFFu;
				Tpm2CreationTicket(P2, 32, TPM2_ALG_SHA256, 0x40000001u,
				                   Name, 34, Dig, DigLen, Tk2, sizeof(Tk2), &w2);
				same = 1;
				for (k = 0; k < w2 && k < wrote; k++)
					if (Tk[k] != Tk2[k]) same = 0;
				printf("cre.ticket_proof=%u\n", same);
			}
		}
	}

	/* TPM2_CreatePrimary, end to end ----------------------------------------------- */
	{
		/*
		 * (!) THE COMMAND IS ASSEMBLED FROM THE CAPTURED SHAPE: TPM_ST_SESSIONS, RH_OWNER, the
		 * 29-octet password authorization, an empty inSensitive, the real SRK template, an empty
		 * outsideInfo and an empty creationPCR. 2048 bits is what Windows asks for; the harness
		 * uses 1024 so the suite stays quick, and the template is otherwise byte-identical.
		 */
		static UINT8 Cmd[512];
		static UINT8 Rsp[2048];
		static TPM2_PCR_BANK PriBank;
		UINT32 n, k, pub, rc, wrote = 0;

		Tpm2PcrStartupClear(&PriBank, 0);
		Tpm2ObjectStoreReset();
		Tpm2SetSeedSource(TestSeed);

		n = 0;
		PutBe16At(Cmd, &n, 0x8002);            /* TPM_ST_SESSIONS            */
		PutBe32At(Cmd, &n, 0);                 /* commandSize, patched below */
		PutBe32At(Cmd, &n, 0x00000131u);       /* TPM_CC_CreatePrimary       */
		PutBe32At(Cmd, &n, 0x40000001u);       /* TPM_RH_OWNER               */
		PutBe32At(Cmd, &n, 29);                /* authorizationSize          */
		PutBe32At(Cmd, &n, 0x40000009u);       /* TPM_RS_PW                  */
		PutBe16At(Cmd, &n, 0);                 /* nonce                      */
		Cmd[n++] = 0x00;                       /* sessionAttributes          */
		PutBe16At(Cmd, &n, 20);
		for (k = 0; k < 20; k++) Cmd[n + k] = 0;
		n += 20;
		PutBe16At(Cmd, &n, 0);                 /* inSensitive: empty         */

		pub = n;
		PutBe16At(Cmd, &n, 0);                 /* inPublic size, patched     */
		PutBe16At(Cmd, &n, 0x0001);            /* RSA                        */
		PutBe16At(Cmd, &n, 0x000B);            /* SHA-256                    */
		PutBe32At(Cmd, &n, 0x00030472u);
		PutBe16At(Cmd, &n, 0);                 /* no policy                  */
		PutBe16At(Cmd, &n, 0x0006);            /* AES                        */
		PutBe16At(Cmd, &n, 128);
		PutBe16At(Cmd, &n, 0x0043);            /* CFB                        */
		PutBe16At(Cmd, &n, 0x0010);            /* scheme NULL                */
		PutBe16At(Cmd, &n, 1024);
		PutBe32At(Cmd, &n, 0);                 /* exponent: default          */
		PutBe16At(Cmd, &n, 0);                 /* unique: EMPTY              */
		PutBe16Raw(Cmd, pub, (unsigned)(n - pub - 2));

		PutBe16At(Cmd, &n, 0);                 /* outsideInfo: empty         */
		PutBe32At(Cmd, &n, 0);                 /* creationPCR: count 0       */
		PutBe32Raw(Cmd, 2, n);                 /* commandSize                */

		printf("pri.cmd_len=%u\n", (unsigned)n);
		PrintHexN("pri.cmd", Cmd, n);

		rc = Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &wrote);
		printf("pri.rc=%u\n", rc);
		printf("pri.len=%u\n", (unsigned)wrote);
		if (wrote >= 10)
		{
			printf("pri.tag=%u\n", (unsigned)((Rsp[0] << 8) | Rsp[1]));
			printf("pri.hdr_len=%u\n",
			       (unsigned)((Rsp[2] << 24) | (Rsp[3] << 16) | (Rsp[4] << 8) | Rsp[5]));
			printf("pri.hdr_rc=%u\n",
			       (unsigned)((Rsp[6] << 24) | (Rsp[7] << 16) | (Rsp[8] << 8) | Rsp[9]));
			printf("pri.handle=%u\n",
			       (unsigned)((Rsp[10] << 24) | (Rsp[11] << 16) | (Rsp[12] << 8) | Rsp[13]));
			printf("pri.paramsize=%u\n",
			       (unsigned)((Rsp[14] << 24) | (Rsp[15] << 16) | (Rsp[16] << 8) | Rsp[17]));
			PrintHexN("pri.rsp", Rsp, wrote);
		}
		printf("pri.loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());

		/*
		 * (!) THE HEADLINE. The same command twice must give the same key -- the property that
		 * makes an SRK survive a reboot. Byte-for-byte identical responses, because nothing in
		 * this command is time- or nonce-dependent.
		 */
		{
			static UINT8 Rsp2[2048];
			UINT32 w2 = 0, same = 1;
			Tpm2ObjectStoreReset();
			Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp2, sizeof(Rsp2), &w2);
			if (w2 != wrote) same = 0;
			for (k = 0; k < wrote && k < w2; k++)
				if (Rsp[k] != Rsp2[k]) same = 0;
			printf("pri.repeatable=%u\n", same);

			/* a DIFFERENT hierarchy must give a different key, or the seed split is decorative */
			PutBe32Raw(Cmd, 10, 0x4000000Bu);   /* TPM_RH_ENDORSEMENT */
			Tpm2ObjectStoreReset();
			w2 = 0;
			printf("pri.ek_rc=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp2, sizeof(Rsp2), &w2));
			same = 1;
			for (k = 0; k < wrote && k < w2; k++)
				if (Rsp[k] != Rsp2[k]) same = 0;
			printf("pri.hierarchy_matters=%u\n", same);
			PutBe32Raw(Cmd, 10, 0x40000001u);
		}

		/* --- the object store --- */
		{
			UINT32 w2 = 0, j;
			Tpm2ObjectStoreReset();
			for (j = 0; j < TPM2_MAX_LOADED_OBJECTS; j++)
				Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
			printf("pri.full_loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());
			/*
			 * (!) A FULL STORE IS A WARNING, NOT AN ERROR. RC_WARN means "try again later": the
			 * caller can flush something and retry. An RC_FMT1 failure would say the command is
			 * wrong when the only problem is that three slots are in use.
			 */
			printf("pri.full_rc=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2));
			printf("pri.full_wrote=%u\n", (unsigned)w2);
			Tpm2ObjectStoreReset();
			printf("pri.after_reset=%u\n", (unsigned)Tpm2ObjectStoreLoaded());
		}

		/* --- refusals --- */
		{
			static UINT8 Bad[512];
			UINT32 w2 = 0, j;

			Tpm2ObjectStoreReset();
			for (j = 0; j < n; j++) Bad[j] = Cmd[j];

			/* NO_SESSIONS on a command that requires authorization */
			PutBe16Raw(Bad, 0, 0x8001);
			printf("pri.no_sessions=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Bad, n, Rsp, sizeof(Rsp), &w2));
			printf("pri.no_sessions_wrote=%u\n", (unsigned)w2);
			PutBe16Raw(Bad, 0, 0x8002);

			/* a persistent handle is not a hierarchy */
			PutBe32Raw(Bad, 10, 0x81000001u);
			printf("pri.bad_hierarchy=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Bad, n, Rsp, sizeof(Rsp), &w2));
			PutBe32Raw(Bad, 10, 0x40000001u);

			/* trailing octets the TPM never accounted for */
			PutBe32Raw(Bad, 2, n + 1);
			Bad[n] = 0xEE;
			printf("pri.trailing=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Bad, n + 1, Rsp, sizeof(Rsp), &w2));
			PutBe32Raw(Bad, 2, n);

			/*
			 * (!) NO SEED SOURCE, NO KEY. A key from a fabricated seed would succeed here and
			 * change on the next boot -- event 519 again, but looking fixed.
			 */
			Tpm2SetSeedSource(NULL);
			printf("pri.no_seed=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2));
			printf("pri.have_seed=%u\n", (unsigned)Tpm2HaveSeedSource());
			Tpm2SetSeedSource(TestSeed);
			printf("pri.have_seed2=%u\n", (unsigned)Tpm2HaveSeedSource());

			/* an output buffer far too small must refuse, not overrun */
			Tpm2ObjectStoreReset();
			printf("pri.tight=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, 64, &w2));
			/*
			 * (!) AND THE SLOT MUST NOT HAVE BEEN CONSUMED. A slot marked loaded before a size
			 * failure leaks a handle to an object the caller was never told about, and three of
			 * those exhaust the store permanently.
			 */
			printf("pri.tight_loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());

			/* sensitiveDataOrigin SET with data present is a contradiction */
			Tpm2ObjectStoreReset();
		}

		/* --- TPM2_FlushContext: what the 9 OBJECT_MEMORY answers were asking for --- */
		{
			static UINT8 Fc[32];
			UINT32 w2 = 0, j, m;

			Tpm2ObjectStoreReset();

			/* fill the store, exactly as the hardware boot did */
			for (j = 0; j < TPM2_MAX_LOADED_OBJECTS; j++)
				Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
			printf("flush.filled=%u\n", (unsigned)Tpm2ObjectStoreLoaded());
			printf("flush.full_rc=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2));

			/*
			 * (!) THE WHOLE POINT, IN THREE LINES. Flush one, and a CreatePrimary that was
			 * answering OBJECT_MEMORY succeeds again. On hardware this was nine refusals in a row.
			 */
			printf("flush.residue_before=%u\n", Tpm2ObjectStoreResidue());
			printf("flush.rc=%u\n", Tpm2DoFlushContext(0x80000000u));
			/*
			 * (!) THE SLOT MUST BE ZERO NOW, BEFORE ANYTHING REUSES IT. Asked here rather than
			 * after the reuse below, because the reuse OVERWRITES the residue and hides it -- which
			 * is exactly how a flag-only flush passed this suite once already.
			 */
			printf("flush.residue=%u\n", Tpm2ObjectStoreResidue());
			printf("flush.after=%u\n", (unsigned)Tpm2ObjectStoreLoaded());
			printf("flush.reuse_rc=%u\n",
			       Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2));
			printf("flush.reuse_loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());

			/*
			 * (!) AND THE SLOT MUST BE ZEROED, NOT MARKED FREE -- it held an RSA private key.
			 * The reused slot is read back through the public interface: if the flush had only
			 * cleared a flag, the handle would still resolve to the OLD object.
			 */
			printf("flush.found_after=%u\n",
			       (unsigned)(Tpm2ObjectFind(0x80000000u) != NULL));
			Tpm2ObjectStoreReset();
			printf("flush.found_gone=%u\n",
			       (unsigned)(Tpm2ObjectFind(0x80000000u) != NULL));

			/* --- refusals, each numbered as a PARAMETER --- */
			printf("flush.absent=%u\n", Tpm2DoFlushContext(0x80000002u));
			printf("flush.hmac_sess=%u\n", Tpm2DoFlushContext(0x02000000u));
			printf("flush.policy_sess=%u\n", Tpm2DoFlushContext(0x03000000u));
			/*
			 * (!) A PERSISTENT HANDLE MUST BE REFUSED, NOT FLUSHED. Part 3 28.4.1: "This command
			 * may not be used to remove a persistent object. Use TPM2_EvictControl()." Flushing
			 * one silently would destroy an object the caller expects to survive a reboot.
			 */
			printf("flush.persistent=%u\n", Tpm2DoFlushContext(0x81000001u));
			printf("flush.permanent=%u\n", Tpm2DoFlushContext(0x40000001u));
			printf("flush.nvindex=%u\n", Tpm2DoFlushContext(0x01C00002u));

			/* --- and through the DISPATCHER, which is where the tag rule lives --- */
			Tpm2ObjectStoreReset();
			Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);

			m = 0;
			PutBe16At(Fc, &m, 0x8001);            /* TPM_ST_NO_SESSIONS */
			PutBe32At(Fc, &m, 14);
			PutBe32At(Fc, &m, 0x00000165u);
			PutBe32At(Fc, &m, 0x80000000u);       /* flushHandle: a PARAMETER */
			PrintHexN("flush.cmd", Fc, m);
			printf("flush.disp_len=%u\n",
			       (unsigned)Tpm2Dispatch(&PriBank, Fc, m, Rsp, sizeof(Rsp), NULL));
			PrintHexN("flush.disp_rsp", Rsp, 10);
			printf("flush.disp_loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());

			/*
			 * (!) A SESSION AREA IS NOT AN AUTHORISATION FAILURE HERE, IT IS A COMMAND THAT DOES
			 * NOT TAKE ONE. Part 3 28.4.1: "No sessions of any type are allowed with this command."
			 * TPM_RC_AUTH_CONTEXT says that; an auth failure would send the caller hunting for a
			 * password that was never the problem.
			 */
			PutBe16Raw(Fc, 0, 0x8002);
			printf("flush.disp_sessions=%u\n",
			       (unsigned)Tpm2Dispatch(&PriBank, Fc, m, Rsp, sizeof(Rsp), NULL));
			PrintHexN("flush.disp_sess_rsp", Rsp, 10);
			PutBe16Raw(Fc, 0, 0x8001);

			/* a short command: 10 octets with no flushHandle at all */
			PutBe32Raw(Fc, 2, 10);
			Tpm2Dispatch(&PriBank, Fc, 10, Rsp, sizeof(Rsp), NULL);
			PrintHexN("flush.disp_short_rsp", Rsp, 10);
			PutBe32Raw(Fc, 2, 14);

			Tpm2ObjectStoreReset();
		}

		/* --- TPM2_EvictControl: the whole provisioning sequence Windows performs --- */
		{
			static UINT8 Ev[80];
			static UINT8 Rp[16];
			UINT32 w2 = 0, m, k;

			Tpm2ObjectStoreReset();
			Tpm2PersistentReset();

			/*
			 * (!) THE COMMAND IS ASSEMBLED FROM THE 55 OCTETS WINDOWS ACTUALLY SENT, captured this
			 * boot: TPM_ST_SESSIONS, RH_OWNER, our transient handle, the 29-octet password
			 * authorization, and persistentHandle 0x81000001 as a PARAMETER.
			 */
			m = 0;
			PutBe16At(Ev, &m, 0x8002);
			PutBe32At(Ev, &m, 55);
			PutBe32At(Ev, &m, 0x00000120u);       /* TPM_CC_EvictControl */
			PutBe32At(Ev, &m, 0x40000001u);       /* authHandle: RH_OWNER */
			PutBe32At(Ev, &m, 0x80000000u);       /* objectHandle */
			PutBe32At(Ev, &m, 29);
			PutBe32At(Ev, &m, 0x40000009u);
			PutBe16At(Ev, &m, 0);
			Ev[m++] = 0x00;
			PutBe16At(Ev, &m, 20);
			for (k = 0; k < 20; k++) Ev[m + k] = 0;
			m += 20;
			PutBe32At(Ev, &m, 0x81000001u);       /* persistentHandle */
			printf("evict.cmd_len=%u\n", (unsigned)m);
			PrintHexN("evict.cmd", Ev, m);

			/* nothing loaded yet: the object handle names nothing */
			printf("evict.no_object=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

			/* create the SRK, then persist it -- exactly Windows order */
			Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
			printf("evict.loaded=%u\n", (unsigned)Tpm2ObjectStoreLoaded());
			printf("evict.rc=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));
			printf("evict.len=%u\n", (unsigned)w2);
			PrintHexN("evict.rsp", Rsp, w2);
			printf("evict.persisted=%u\n", (unsigned)Tpm2PersistentCount());
			/*
			 * (!) THE TRANSIENT OBJECT SURVIVES. Part 3 rule 7 -- and Windows depends on it: it
			 * persists, then flushes the transient handle separately. A TPM that consumed the
			 * object would leave it flushing something already gone.
			 */
			printf("evict.transient_kept=%u\n", (unsigned)Tpm2ObjectStoreLoaded());

			/* --- and now ReadPublic on the PERSISTENT handle must SUCCEED --- */
			{
				UINT32 q = 0;
				q = 0;
				PutBe16At(Rp, &q, 0x8001);
				PutBe32At(Rp, &q, 14);
				PutBe32At(Rp, &q, 0x00000173u);   /* TPM_CC_ReadPublic */
				PutBe32At(Rp, &q, 0x81000001u);
				PrintHexN("evict.rdpub_cmd", Rp, q);
				w2 = Tpm2Dispatch(&PriBank, Rp, q, Rsp, sizeof(Rsp), NULL);
				printf("evict.rdpub_len=%u\n", (unsigned)w2);
				PrintHexN("evict.rdpub", Rsp, w2);

				/* the transient handle names the same object and must answer identically */
				PutBe32Raw(Rp, 10, 0x80000000u);
				{
					static UINT8 R2[2048];
					UINT32 w3 = Tpm2Dispatch(&PriBank, Rp, q, R2, sizeof(R2), NULL);
					UINT32 same = (w3 == w2) ? 1u : 0u;
					for (k = 10; k < w2 && k < w3; k++)
						if (Rsp[k] != R2[k]) same = 0;
					printf("evict.same_object=%u\n", same);
				}
				PutBe32Raw(Rp, 10, 0x81000001u);
			}

			/* --- refusals --- */
			/* the destination is now occupied */
			printf("evict.taken=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

			/* owner auth may not reach the platform range */
			PutBe32Raw(Ev, m - 4, 0x81800000u);
			printf("evict.owner_range=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));
			PutBe32Raw(Ev, m - 4, 0x81000001u);

			/* the EK: endorsement hierarchy under OWNER auth is LEGAL, Part 3 rule 2 */
			Tpm2ObjectStoreReset();
			PutBe32Raw(Cmd, 10, 0x4000000Bu);   /* TPM_RH_ENDORSEMENT */
			Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
			PutBe32Raw(Cmd, 10, 0x40000001u);
			PutBe32Raw(Ev, m - 4, 0x81010001u);
			printf("evict.ek_rc=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));
			printf("evict.ek_persisted=%u\n", (unsigned)Tpm2PersistentCount());

			/* --- TPM_CAP_HANDLES enumeration, with two objects persisted --- */
			{
				UINT32 Hs[8];
				UINT32 got, z;

				got = Tpm2ObjectEnumerate(0x81000000u, 8, Hs);
				printf("enum.persist_n=%u\n", (unsigned)got);
				for (z = 0; z < got && z < 4; z++)
					printf("enum.persist_%u=%u\n", (unsigned)z, (unsigned)Hs[z]);

				/*
				 * (!) ASCENDING IS PART OF THE ANSWER. `property` is a STARTING handle so a caller
				 * can page through, and paging only works if the order is increasing. The slots are
				 * in ALLOCATION order -- 0x81010001 was persisted second here but sorts first by
				 * nothing, so an unsorted answer would hand a pager the wrong entry.
				 */
				z = 1;
				for (k = 1; k < got; k++)
					if (Hs[k] <= Hs[k - 1]) z = 0;
				printf("enum.ascending=%u\n", (unsigned)z);

				/* paging: start ABOVE the first handle and it must not be reported */
				got = Tpm2ObjectEnumerate(0x81000002u, 8, Hs);
				printf("enum.paged_n=%u\n", (unsigned)got);
				printf("enum.paged_0=%u\n", (unsigned)(got ? Hs[0] : 0));

				/* a range we hold nothing in is EMPTY, not an error */
				printf("enum.nv=%u\n", (unsigned)Tpm2ObjectEnumerate(0x01000000u, 8, Hs));
				printf("enum.transient=%u\n",
				       (unsigned)Tpm2ObjectEnumerate(0x80000000u, 8, Hs));
				/* a zero-sized output must report nothing rather than write */
				printf("enum.zero_max=%u\n",
				       (unsigned)Tpm2ObjectEnumerate(0x81000000u, 0, Hs));

				/*
				 * (!) AND NOW A CASE WHERE ALLOCATION ORDER CANNOT EQUAL ASCENDING ORDER.
				 *
				 * The sequence above persists the SRK first and the EK second, which is what Windows
				 * does -- and it puts 0x81000001 in slot 0 and 0x81010001 in slot 1, so slot order and
				 * numeric order AGREE. An enumeration that ignored sorting entirely passed every check
				 * above, and was caught only by injuring it.
				 *
				 * Persisting them the other way round puts the HIGHER handle in the LOWER slot, and
				 * the two orders cannot coincide.
				 */
				Tpm2PersistentReset();
				Tpm2ObjectStoreReset();

				PutBe32Raw(Cmd, 10, 0x4000000Bu);        /* endorsement -> the EK  */
				Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
				PutBe32Raw(Ev, 14, 0x80000000u);
				PutBe32Raw(Ev, m - 4, 0x81010001u);      /* the HIGHER handle FIRST */
				printf("enum.rev_ek=%u\n",
				       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

				Tpm2ObjectStoreReset();
				PutBe32Raw(Cmd, 10, 0x40000001u);        /* owner -> the SRK       */
				Tpm2DoCreatePrimary(&PriBank, Cmd, n, Rsp, sizeof(Rsp), &w2);
				PutBe32Raw(Ev, m - 4, 0x81000001u);      /* the LOWER handle SECOND */
				printf("enum.rev_srk=%u\n",
				       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

				got = Tpm2ObjectEnumerate(0x81000000u, 8, Hs);
				printf("enum.rev_n=%u\n", (unsigned)got);
				printf("enum.rev_0=%u\n", (unsigned)(got > 0 ? Hs[0] : 0));
				printf("enum.rev_1=%u\n", (unsigned)(got > 1 ? Hs[1] : 0));
				z = 1;
				for (k = 1; k < got; k++)
					if (Hs[k] <= Hs[k - 1]) z = 0;
				printf("enum.rev_ascending=%u\n", (unsigned)z);
			}

			/* --- eviction --- */
			/* objectHandle must EQUAL persistentHandle when evicting */
			PutBe32Raw(Ev, 14, 0x81010001u);
			PutBe32Raw(Ev, m - 4, 0x81000001u);
			printf("evict.mismatch=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

			PutBe32Raw(Ev, m - 4, 0x81010001u);
			printf("evict.evict_rc=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));
			printf("evict.after_evict=%u\n", (unsigned)Tpm2PersistentCount());
			/*
			 * (!) THE EVICTED SLOT MUST BE ZERO, asked before anything reuses it -- the same trap
			 * that let a flag-only FlushContext through this suite once.
			 */
			printf("evict.residue=%u\n", Tpm2PersistentResidue());
			/* and it is gone: evicting again finds nothing */
			printf("evict.gone=%u\n",
			       Tpm2DoEvictControl(Ev, m, Rsp, sizeof(Rsp), &w2));

			/*
			 * (!) TPM2_Startup MUST NOT REMOVE PERSISTENT OBJECTS. That is what the word means, and
			 * Part 3 28.5.1 says so outright. A Startup that cleared them would make provisioning
			 * evaporate on every TPM Reset while every other test still passed.
			 */
			printf("evict.before_startup=%u\n", (unsigned)Tpm2PersistentCount());
			Tpm2ObjectStoreReset();
			printf("evict.after_startup=%u\n", (unsigned)Tpm2PersistentCount());

			Tpm2PersistentReset();
			Tpm2ObjectStoreReset();
		}
		Tpm2ObjectStoreReset();
	}

	/* NV indices ------------------------------------------------------------------- */
	{
		TPM2_NV_PUBLIC Nv;
		UINT8  Buf[128];
		UINT8  Name[2 + TPM2_MAX_DIGEST_SIZE];
		UINT16 NameLen = 0;
		UINT32 wrote = 0, k;

		Tpm2NvReset();

		/*
		 * (!) THE ORACLE IS HARDWARE OWN ANSWER, NOT MY READING OF PART 2.
		 *
		 * Genuine Intel PTT answered TPM2_NV_ReadPublic for 0x01C00002 with a public area AND the
		 * Name computed over it. These are its exact decoded fields, so if our marshalling or our
		 * Name construction is wrong the digest cannot come out right -- and the value it has to
		 * match was produced by a TPM that is not ours.
		 *
		 * nameAlg is SHA-384, which makes the Name 50 octets rather than 34. That is the case that
		 * catches anything assuming a Name is two octets plus a 32-byte digest.
		 */
		Nv.NvIndex       = 0x01C00002u;
		Nv.NameAlg       = TPM2_ALG_SHA384;
		Nv.Attributes    = 0x62070408u;
		Nv.AuthPolicyLen = 0;
		Nv.DataSize      = 911;

		printf("nv.hw_marshal_rc=%u\n",
		       Tpm2NvPublicMarshal(&Nv, Buf, sizeof(Buf), &wrote));
		printf("nv.hw_marshal_len=%u\n", (unsigned)wrote);
		PrintHexN("nv.hw_public", Buf, wrote);
		printf("nv.hw_name_ok=%u\n", (unsigned)Tpm2NvName(&Nv, Name, &NameLen));
		printf("nv.hw_name_len=%u\n", (unsigned)NameLen);
		PrintHexN("nv.hw_name", Name, NameLen);

		/* --- the store --- */
		printf("nv.count0=%u\n", (unsigned)Tpm2NvCount());
		printf("nv.define=%u\n", Tpm2NvDefine(&Nv));
		printf("nv.count1=%u\n", (unsigned)Tpm2NvCount());
		printf("nv.found=%u\n", (unsigned)(Tpm2NvFind(0x01C00002u) != NULL));
		printf("nv.missing=%u\n", (unsigned)(Tpm2NvFind(0x01880011u) != NULL));
		/*
		 * (!) WRITTEN MUST BE CLEAR EVEN THOUGH THE CALLER ASKED FOR IT. Hardware attributes
		 * carry TPMA_NV_WRITTEN because hardware holds a certificate; we passed the same value and
		 * hold nothing. A definer that could assert WRITTEN could make the TPM claim content it
		 * does not have -- for THIS index, an EK certificate.
		 */
		{
			CONST TPM2_NV_INDEX* Ix = Tpm2NvFind(0x01C00002u);
			printf("nv.written_bit=%u\n",
			       (unsigned)((Ix->Public.Attributes >> 29) & 1u));
			printf("nv.other_attrs=%u\n",
			       (unsigned)(Ix->Public.Attributes == (0x62070408u & ~(1u << 29))));
			printf("nv.datasize=%u\n", (unsigned)Ix->Public.DataSize);
			Tpm2NvName(&Ix->Public, Name, &NameLen);
			PrintHexN("nv.name_unwritten", Name, NameLen);
			printf("nv.written_len=%u\n", (unsigned)Ix->Written);
		}
		printf("nv.redefine=%u\n", Tpm2NvDefine(&Nv));

		/* --- writing --- */
		{
			static UINT8 Blob[64];
			CONST TPM2_NV_INDEX* Ix;

			for (k = 0; k < 64; k++) Blob[k] = (UINT8)(k ^ 0x5A);
			printf("nv.write=%u\n", Tpm2NvWrite(0x01C00002u, Blob, 64));
			Ix = Tpm2NvFind(0x01C00002u);
			printf("nv.write_bit=%u\n",
			       (unsigned)((Ix->Public.Attributes >> 29) & 1u));
			printf("nv.write_len=%u\n", (unsigned)Ix->Written);
			/* dataSize still describes the INDEX, not what was written */
			printf("nv.write_datasize=%u\n", (unsigned)Ix->Public.DataSize);
			/* and the Name CHANGES, because WRITTEN is inside the area it digests */
			Tpm2NvName(&Ix->Public, Name, &NameLen);
			PrintHexN("nv.name_after_write", Name, NameLen);

			printf("nv.write_absent=%u\n", Tpm2NvWrite(0x01880011u, Blob, 8));
		}

		/* --- enumeration, ascending against definition order --- */
		{
			UINT32 Hs[8];
			UINT32 got, asc;

			/*
			 * (!) DEFINED SECOND, SORTS FIRST. 0x01880011 is defined after 0x01C00002 and is the
			 * LOWER handle, so definition order and numeric order cannot coincide -- the trap the
			 * object enumeration fell into and had to be re-tested for.
			 */
			Nv.NvIndex = 0x01880011u; Nv.DataSize = 8;
			printf("nv.def2=%u\n", Tpm2NvDefine(&Nv));
			got = Tpm2NvEnumerate(0x01000000u, 8, Hs);
			printf("nv.enum_n=%u\n", (unsigned)got);
			printf("nv.enum_0=%u\n", (unsigned)(got > 0 ? Hs[0] : 0));
			printf("nv.enum_1=%u\n", (unsigned)(got > 1 ? Hs[1] : 0));
			asc = 1;
			for (k = 1; k < got; k++)
				if (Hs[k] <= Hs[k - 1]) asc = 0;
			printf("nv.enum_ascending=%u\n", (unsigned)asc);
			printf("nv.enum_wrongtype=%u\n",
			       (unsigned)Tpm2NvEnumerate(0x81000000u, 8, Hs));
		}

		/* --- refusals --- */
		Nv.NvIndex = 0x40000001u; Nv.DataSize = 8;
		printf("nv.bad_handle=%u\n", Tpm2NvDefine(&Nv));
		Nv.NvIndex = 0x01000099u; Nv.NameAlg = 0x0099;
		printf("nv.bad_alg=%u\n", Tpm2NvDefine(&Nv));
		Nv.NameAlg = TPM2_ALG_SHA256; Nv.DataSize = 0;
		printf("nv.zero_size=%u\n", Tpm2NvDefine(&Nv));
		Nv.DataSize = TPM2_MAX_NV_DATA + 1;
		printf("nv.huge=%u\n", Tpm2NvDefine(&Nv));

		Tpm2NvReset();
		printf("nv.after_reset=%u\n", (unsigned)Tpm2NvCount());
	}

	/* --- PCR_Read / PCR_Extend / Shutdown, through the DISPATCHER ------------------- */
	/*
	 * The bank underneath has been tested since the event log landed. What had never been
	 * exercised is the WIRE: three commands that had no case in the dispatch switch at all, so
	 * every one of these vectors is new coverage rather than a second reading of Tpm2Core.
	 */
	{
		static TPM2_PCR_BANK       PBank;
		static UINT8               PC[128];
		static UINT8               PR[2048];
		static TPM2_DISPATCH_INFO  PI;
		UINT32 m, n, k;

		Tpm2PcrStartupClear(&PBank, 0);

		/* --- TPM2_Shutdown --- */
		m = 0;
		PutBe16At(PC, &m, 0x8001);
		PutBe32At(PC, &m, 12);
		PutBe32At(PC, &m, 0x00000145u);
		PutBe16At(PC, &m, 0x0000);            /* TPM_SU_CLEAR */
		n = Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.shut_clear=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.shut_clear_len=%u\n", (unsigned)(n));
		/*
		 * (!) SHUTDOWN(STATE) IS REFUSED, matching our refusal of Startup(STATE). Accepting it
		 * would promise to save state region B cannot carry across power loss, and the broken
		 * promise would surface one boot later as PCRs nobody asked to have restored.
		 */
		PutBe16Raw(PC, 10, 0x0001);           /* TPM_SU_STATE */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.shut_state=%u\n", (unsigned)(PI.ResponseCode));
		PutBe16Raw(PC, 10, 0x0002);           /* not a TPM_SU at all */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.shut_bad=%u\n", (unsigned)(PI.ResponseCode));
		PutBe32Raw(PC, 2, 13);                /* one octet too many */
		Tpm2Dispatch(&PBank, PC, 13, PR, sizeof(PR), &PI);
		printf("pcrc.shut_long=%u\n", (unsigned)(PI.ResponseCode));

		/*
		 * BuildRead(sel0, sel1, sel2) -- a PCR_Read for the SHA-256 bank over a given selection.
		 * The response is laid out at fixed offsets: counter at 10, count at 14, alg at 18,
		 * sizeofSelect at 20, the three selection octets at 21, the DIGEST COUNT at 24, and the
		 * digests from 28 on, each a two-octet size followed by 32 octets.
		 */
#define PCR_READ(s0, s1, s2)                                   \
		do {                                                       \
			m = 0;                                                 \
			PutBe16At(PC, &m, 0x8001);                             \
			PutBe32At(PC, &m, 0);                                  \
			PutBe32At(PC, &m, 0x0000017Eu);                        \
			PutBe32At(PC, &m, 1);                                  \
			PutBe16At(PC, &m, 0x000B);                             \
			PC[m++] = 3;                                           \
			PC[m++] = (UINT8)(s0);                                 \
			PC[m++] = (UINT8)(s1);                                 \
			PC[m++] = (UINT8)(s2);                                 \
			PutBe32Raw(PC, 2, m);                                  \
			n = Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);   \
		} while (0)

		/* --- one PCR, before anything has been extended --- */
		PCR_READ(0x01, 0x00, 0x00);
		printf("pcrc.read0_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.read0_len=%u\n", (unsigned)(n));
		printf("pcrc.read0_counter=%u\n", (unsigned)(Tpm2ReadBe32(PR + 10)));
		printf("pcrc.read0_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		PrintHexN("pcrc.read0_sel", PR + 18, 6);
		PrintHexN("pcrc.read0_val", PR + 30, 32);

		/* --- extend PCR 0 with a single SHA-256 digest --- */
		/*
		 * ExtendCmd builds TPM2_PCR_Extend with a password session over an empty authValue. The
		 * digest list is appended by the caller, so the same builder serves the one-entry case and
		 * the mixed-bank case below.
		 */
#define PCR_EXT_HEAD(pcr)                                      \
		do {                                                       \
			m = 0;                                                 \
			PutBe16At(PC, &m, 0x8002);                             \
			PutBe32At(PC, &m, 0);                                  \
			PutBe32At(PC, &m, 0x00000182u);                        \
			PutBe32At(PC, &m, (pcr));                              \
			PutBe32At(PC, &m, 9);                                  \
			PutBe32At(PC, &m, 0x40000009u);                        \
			PutBe16At(PC, &m, 0);                                  \
			PC[m++] = 0x00;                                        \
			PutBe16At(PC, &m, 0);                                  \
		} while (0)

		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 1);                 /* one digest */
		PutBe16At(PC, &m, 0x000B);            /* SHA-256 */
		for (k = 0; k < 32; k++) PC[m + k] = (UINT8)(k + 1);
		m += 32;
		PutBe32Raw(PC, 2, m);
		n = Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext1_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.ext1_len=%u\n", (unsigned)(n));
		PrintHexN("pcrc.ext1_resp", PR, n);
		printf("pcrc.ext1_counter=%u\n", (unsigned)(PBank.UpdateCounter));
		/*
		 * (!) THE EXTEND HAS TO BE VISIBLE THROUGH THE OTHER COMMAND. Checking PBank.Pcr[0]
		 * directly would prove only that Tpm2PcrExtend works, which was never in doubt. Reading it
		 * back through PCR_Read is what proves the two WIRE paths agree.
		 */
		PCR_READ(0x01, 0x00, 0x00);
		printf("pcrc.read1_counter=%u\n", (unsigned)(Tpm2ReadBe32(PR + 10)));
		PrintHexN("pcrc.read1_val", PR + 30, 32);

		/* --- a bank we do not have, sent FIRST --- */
		/*
		 * (!) THE SHA-1 ENTRY GOES FIRST ON PURPOSE. Part 1 lets a caller send one digest per bank
		 * it knows about, and a TPM extends the banks it implements -- so this must SUCCEED, and
		 * PCR 0 must end up exactly where a lone SHA-256 extend would have put it. Putting SHA-1
		 * second would let a wrong digest length pass unnoticed, because nothing would be parsed
		 * after it. First, the twenty octets have to be counted correctly or the SHA-256 entry
		 * behind them is misread and the PCR lands somewhere else.
		 */
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 2);                 /* two digests */
		PutBe16At(PC, &m, 0x0004);            /* SHA-1, a bank we do not implement */
		for (k = 0; k < 20; k++) PC[m + k] = 0xAA;
		m += 20;
		PutBe16At(PC, &m, 0x000B);            /* SHA-256 */
		for (k = 0; k < 32; k++) PC[m + k] = (UINT8)(k + 1);
		m += 32;
		PutBe32Raw(PC, 2, m);
		n = Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext2_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.ext2_counter=%u\n", (unsigned)(PBank.UpdateCounter));
		PCR_READ(0x01, 0x00, 0x00);
		PrintHexN("pcrc.read2_val", PR + 30, 32);

		/*
		 * (!) AN ALGORITHM WE CANNOT SIZE IS A DIFFERENT ANSWER FROM A BANK WE DO NOT HAVE. The
		 * list cannot be walked past an unknown TPMT_HA, so it is TPM_RC_HASH -- not a silent skip,
		 * which would consume the wrong number of octets and extend a PCR with whatever followed.
		 */
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 1);
		PutBe16At(PC, &m, 0x00FF);            /* no such algorithm */
		for (k = 0; k < 32; k++) PC[m + k] = 0;
		m += 32;
		PutBe32Raw(PC, 2, m);
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext_badalg=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.ext_badalg_counter=%u\n", (unsigned)(PBank.UpdateCounter));

		/* --- ALL 24 PCRs: the eight-digest cap --- */
		/*
		 * (!) THE CASE AN OBVIOUS TEST WOULD MISS. Asking for one PCR, or eight, cannot separate a
		 * correct implementation from one that echoes the requested selection back while sending
		 * fewer digests. Asking for more than eight can: TPML_DIGEST holds eight (Part 2 Table
		 * 126), so eight come back and pcrSelectionOut must name THOSE EIGHT and no others.
		 */
		PCR_READ(0xFF, 0xFF, 0xFF);
		printf("pcrc.all_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.all_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		PrintHexN("pcrc.all_sel", PR + 18, 6);
		printf("pcrc.all_len=%u\n", (unsigned)(n));

		/*
		 * (!) AND A SPARSE SELECTION, WHICH THE ALL-24 CASE STILL WOULD NOT CATCH. Nine PCRs, every
		 * other one: 0 2 4 6 8 10 12 14 16, requested as 55 55 01. Eight come back, so the answer
		 * must be 55 55 00 -- bit 16 dropped. An implementation that echoed would say 55 55 01; one
		 * that set the first eight BITS rather than the first eight SELECTED would say FF 00 00.
		 * All three are eight digests long, and only the selection tells them apart.
		 */
		PCR_READ(0x55, 0x55, 0x01);
		printf("pcrc.sparse_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		PrintHexN("pcrc.sparse_sel", PR + 18, 6);

		/*
		 * PCRs 16..23 -- exactly eight, so nothing is dropped, and 17..22 carry the all-ones reset
		 * value from PTP Table 15. A bank that zeroed everything at startup would look identical in
		 * every test above this one.
		 */
		PCR_READ(0x00, 0x00, 0xFF);
		printf("pcrc.high_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		PrintHexN("pcrc.high_sel", PR + 18, 6);
		PrintHexN("pcrc.high_16", PR + 30, 32);
		PrintHexN("pcrc.high_17", PR + 30 + 34, 32);
		PrintHexN("pcrc.high_23", PR + 30 + 34 * 7, 32);

		/*
		 * An empty selection: no digests, but Part 3 still requires the bank selector to be
		 * present in pcrSelectionOut, so the response is not empty either.
		 */
		PCR_READ(0x00, 0x00, 0x00);
		printf("pcrc.none_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.none_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		printf("pcrc.none_count=%u\n", (unsigned)(Tpm2ReadBe32(PR + 14)));
		PrintHexN("pcrc.none_sel", PR + 18, 6);
		printf("pcrc.none_len=%u\n", (unsigned)(n));

		/*
		 * A bank we do not implement is not an error either -- zero digests, and the selector for
		 * OUR bank in the answer, because that is the only bank we can report on.
		 */
		PCR_READ(0xFF, 0xFF, 0xFF);
		PutBe16Raw(PC, 14, 0x0004);           /* ask the SHA-1 bank instead */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.sha1bank_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.sha1bank_n=%u\n", (unsigned)(Tpm2ReadBe32(PR + 24)));
		PrintHexN("pcrc.sha1bank_sel", PR + 18, 6);

		/* --- refusals --- */
		PCR_READ(0xFF, 0xFF, 0xFF);
		PutBe32Raw(PC, 10, 2);                /* two selections; we implement one bank */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.two_banks=%u\n", (unsigned)(PI.ResponseCode));
		PutBe32Raw(PC, 10, 1);
		PC[16] = 2;                           /* sizeofSelect 2, not 3 */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.bad_selsize=%u\n", (unsigned)(PI.ResponseCode));
		PC[16] = 3;
		Tpm2Dispatch(&PBank, PC, m - 1, PR, sizeof(PR), &PI);
		printf("pcrc.read_short=%u\n", (unsigned)(PI.ResponseCode));
		PutBe32Raw(PC, 2, m + 1);
		PC[m] = 0x00;
		Tpm2Dispatch(&PBank, PC, m + 1, PR, sizeof(PR), &PI);
		printf("pcrc.read_long=%u\n", (unsigned)(PI.ResponseCode));

		/* a PCR index past the end of the bank, and a missing session */
		PCR_EXT_HEAD(99);
		PutBe32At(PC, &m, 0);
		PutBe32Raw(PC, 2, m);
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext_badpcr=%u\n", (unsigned)(PI.ResponseCode));
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 0);
		PutBe32Raw(PC, 2, m);
		PutBe16Raw(PC, 0, 0x8001);            /* NO_SESSIONS on a command that needs one */
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext_nosess=%u\n", (unsigned)(PI.ResponseCode));

		/*
		 * (!) A NULL BANK ANSWERS, IT DOES NOT CRASH. The dispatcher takes the bank as a pointer
		 * and every other command ignores it, so a caller that never had one is a real shape.
		 */
		PCR_READ(0x01, 0x00, 0x00);
		Tpm2Dispatch(NULL, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.read_nobank=%u\n", (unsigned)(PI.ResponseCode));
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 0);
		PutBe32Raw(PC, 2, m);
		Tpm2Dispatch(NULL, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.ext_nobank=%u\n", (unsigned)(PI.ResponseCode));

		/* --- an implemented hash with no PCR bank: consumed and DROPPED --- */
		/*
		 * (!) THIS IS THE SKIP CASE THE SHA-1 VECTOR WAS REACHING FOR AND COULD NOT REACH. Part 3
		 * splits "algorithm not implemented" (fail the call) from "PCR not implemented in that
		 * bank" (value not used), and only the second is a skip. SHA-384 is on the right side of
		 * that line for us: Tpm2Hash computes it, TPM_CAP_ALGS advertises it, and TPM_CAP_PCRS
		 * reports no bank for it.
		 *
		 * Sent FIRST, ahead of SHA-256, so its FORTY-EIGHT octets have to be counted from the
		 * algorithm ID rather than assumed. Get that wrong and the SHA-256 entry behind it is read
		 * out of the middle of a digest, and PCR 0 lands somewhere neither value predicts.
		 */
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 2);
		PutBe16At(PC, &m, 0x000C);            /* SHA-384: implemented hash, no bank */
		for (k = 0; k < 48; k++) PC[m + k] = 0xBB;
		m += 48;
		PutBe16At(PC, &m, 0x000B);            /* SHA-256 */
		for (k = 0; k < 32; k++) PC[m + k] = (UINT8)(k + 1);
		m += 32;
		PutBe32Raw(PC, 2, m);
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.mixed_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.mixed_counter=%u\n", (unsigned)(PBank.UpdateCounter));
		PCR_READ(0x01, 0x00, 0x00);
		PrintHexN("pcrc.mixed_val", PR + 30, 32);

		/* SHA-384 ALONE: accepted, counted, and nothing moves. */
		PCR_EXT_HEAD(0);
		PutBe32At(PC, &m, 1);
		PutBe16At(PC, &m, 0x000C);
		for (k = 0; k < 48; k++) PC[m + k] = 0xBB;
		m += 48;
		PutBe32Raw(PC, 2, m);
		Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);
		printf("pcrc.only384_rc=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.only384_counter=%u\n", (unsigned)(PBank.UpdateCounter));
		PCR_READ(0x01, 0x00, 0x00);
		PrintHexN("pcrc.only384_val", PR + 30, 32);

		/* --- TPM_RH_NULL: the probe Part 3 clause 22.2.1 documents --- */
		/*
		 * (!) A DISTINGUISHER WRITTEN INTO THE SPECIFICATION. "The pcrHandle parameter is allowed
		 * to reference TPM_RH_NULL. If so, the input parameters are processed but no action is
		 * taken by the TPM. This permits the caller to probe for implemented hash algorithms as an
		 * alternative to TPM2_GetCapability()." Extend nothing into nowhere and read the response
		 * code. We used to answer TPM_RC_VALUE -- the answer for an out-of-range handle, which
		 * TPM_RH_NULL is not, and which no genuine TPM gives here.
		 *
		 * The probe has to agree with TPM_CAP_ALGS or it is a distinguisher in the other
		 * direction, so all four answers below are pinned against that list.
		 */
#define PCR_PROBE(alg, dlen)                                   \
		do {                                                       \
			m = 0;                                                 \
			PutBe16At(PC, &m, 0x8002);                             \
			PutBe32At(PC, &m, 0);                                  \
			PutBe32At(PC, &m, 0x00000182u);                        \
			PutBe32At(PC, &m, 0x40000007u);   /* TPM_RH_NULL */    \
			PutBe32At(PC, &m, 9);                                  \
			PutBe32At(PC, &m, 0x40000009u);                        \
			PutBe16At(PC, &m, 0);                                  \
			PC[m++] = 0x00;                                        \
			PutBe16At(PC, &m, 0);                                  \
			PutBe32At(PC, &m, 1);                                  \
			PutBe16At(PC, &m, (alg));                              \
			for (k = 0; k < (dlen); k++) PC[m + k] = 0x11;          \
			m += (dlen);                                           \
			PutBe32Raw(PC, 2, m);                                  \
			n = Tpm2Dispatch(&PBank, PC, m, PR, sizeof(PR), &PI);   \
		} while (0)

		PCR_PROBE(0x000B, 32);                /* SHA-256: implemented, has a bank */
		printf("pcrc.probe_sha256=%u\n", (unsigned)(PI.ResponseCode));
		printf("pcrc.probe_sha256_len=%u\n", (unsigned)(n));
		PCR_PROBE(0x000C, 48);                /* SHA-384: implemented, no bank */
		printf("pcrc.probe_sha384=%u\n", (unsigned)(PI.ResponseCode));
		PCR_PROBE(0x000D, 64);                /* SHA-512: implemented, no bank */
		printf("pcrc.probe_sha512=%u\n", (unsigned)(PI.ResponseCode));
		PCR_PROBE(0x0004, 20);                /* SHA-1: NOT implemented */
		printf("pcrc.probe_sha1=%u\n", (unsigned)(PI.ResponseCode));
		PCR_PROBE(0x0012, 32);                /* SM3-256: NOT implemented */
		printf("pcrc.probe_sm3=%u\n", (unsigned)(PI.ResponseCode));
		/*
		 * (!) AND THE PROBE MUST NOT HAVE TOUCHED ANYTHING. A probe that extended PCR 0 would pass
		 * every response-code check above and quietly corrupt the log of any caller that used the
		 * documented way to enumerate hash algorithms.
		 */
		printf("pcrc.probe_counter=%u\n", (unsigned)(PBank.UpdateCounter));
		PCR_READ(0x01, 0x00, 0x00);
		PrintHexN("pcrc.probe_val", PR + 30, 32);
#undef PCR_PROBE
		#undef PCR_READ
#undef PCR_EXT_HEAD
	}

	/* --- AES (FIPS-197) and CFB (SP 800-38A) --------------------------------------- */
	/*
	 * (!) THE ONLY ALGORITHM HERE THAT NO TRACE ASKED FOR. SOFTWARE_TPM_SPEC section 5 has to
	 * cache derived primary objects on the ESP and may not put key material there in the clear,
	 * and Part 1 clause 8.4.7 names CFB for exactly that case. It is owed anyway: the SRK
	 * template we already answer declares TPM_ALG_AES / 128 / TPM_ALG_CFB.
	 */
	{
		static TPM2_AES_KEY AK;
		static UINT8 AIn[64], AOut[64], ABuf[128], AIv[16], AKey[32];
		UINT32 q;
		CONST UINT8* Sb;

		/* --- the S-box, so the suite can recompute it from the definition --- */
		Sb = Tpm2AesSbox();
		PrintHexN("aes.sbox", Sb, 256);

		/* --- FIPS-197 Appendix C: one block, all three key lengths --- */
		/*
		 * (!) THE KEY LENGTHS DO NOT GENERALISE FROM ONE ANOTHER. FIPS-197 clause 5.2 gives
		 * AES-256 an EXTRA SubWord in the key schedule that 128 and 192 do not have, so an
		 * implementation missing it passes every 128-bit and 192-bit vector ever published and
		 * fails only here. All three are pinned for that reason alone.
		 */
		for (q = 0; q < 16; q++) AIn[q] = (UINT8)(0x00 + q * 0x11);

		for (q = 0; q < 32; q++) AKey[q] = (UINT8)q;
		printf("aes.setkey128=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 128)));
		printf("aes.rounds128=%u\n", (unsigned)(AK.Rounds));
		Tpm2AesEncryptBlock(&AK, AIn, AOut);
		PrintHexN("aes.kat128", AOut, 16);

		printf("aes.setkey192=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 192)));
		printf("aes.rounds192=%u\n", (unsigned)(AK.Rounds));
		Tpm2AesEncryptBlock(&AK, AIn, AOut);
		PrintHexN("aes.kat192", AOut, 16);

		printf("aes.setkey256=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 256)));
		printf("aes.rounds256=%u\n", (unsigned)(AK.Rounds));
		Tpm2AesEncryptBlock(&AK, AIn, AOut);
		PrintHexN("aes.kat256", AOut, 16);

		/*
		 * (!) ENCRYPTING IN PLACE MUST GIVE THE SAME ANSWER. Tpm2AesEncryptBlock copies the state
		 * into a local before touching the output, and this is the vector that proves it rather
		 * than the comment claiming it.
		 */
		for (q = 0; q < 16; q++) ABuf[q] = AIn[q];
		Tpm2AesEncryptBlock(&AK, ABuf, ABuf);
		PrintHexN("aes.kat256_inplace", ABuf, 16);

		/* --- refusals --- */
		printf("aes.key64=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 64)));
		printf("aes.key64_valid=%u\n", (unsigned)(AK.Valid));
		printf("aes.key512=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 512)));
		printf("aes.key0=%u\n", (unsigned)(Tpm2AesSetKey(&AK, AKey, 0)));
		printf("aes.key_null=%u\n", (unsigned)(Tpm2AesSetKey(&AK, NULL, 128)));
		/*
		 * (!) A REFUSED SCHEDULE MUST NOT ENCRYPT. Valid is cleared by the refusal, so a caller
		 * that ignored the return gets nothing rather than a cipher under a half-built schedule.
		 * The output buffer is poisoned first, so "nothing" is visible as the poison surviving.
		 */
		for (q = 0; q < 16; q++) AOut[q] = 0xDD;
		Tpm2AesEncryptBlock(&AK, AIn, AOut);
		PrintHexN("aes.refused_no_output", AOut, 16);
		for (q = 0; q < 16; q++) AIv[q] = 0;
		printf("aes.cfb_refused=%u\n", (unsigned)(Tpm2AesCfbEncrypt(&AK, AIv, AIn, 16, AOut)));

		/* --- SP 800-38A F.3: CFB128, the four standard blocks --- */
#define AES_CFB_KAT(bits, tag)                                       \
		do {                                                                   \
			Tpm2AesSetKey(&AK, AKey, (bits));                                  \
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)q;                        \
			Tpm2AesCfbEncrypt(&AK, AIv, ABuf, 64, AOut);                       \
			PrintHexN(tag, AOut, 64);                                          \
		} while (0)

		/* the four SP 800-38A plaintext blocks, shared by every mode in that appendix */
		{
			static CONST UINT8 Pt[64] = {
				0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
				0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
				0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
				0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
			static CONST UINT8 K128[16] = {
				0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
				0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
			static CONST UINT8 K192[24] = {
				0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,
				0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b };
			static CONST UINT8 K256[32] = {
				0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
				0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };

			for (q = 0; q < 64; q++) ABuf[q] = Pt[q];
			for (q = 0; q < 16; q++) AKey[q] = K128[q];
			AES_CFB_KAT(128, "aes.cfb128");
			for (q = 0; q < 24; q++) AKey[q] = K192[q];
			AES_CFB_KAT(192, "aes.cfb192");
			for (q = 0; q < 32; q++) AKey[q] = K256[q];
			AES_CFB_KAT(256, "aes.cfb256");

			/*
			 * (!) DECRYPT IS NOT PROVED BY A ROUND TRIP. Encrypt and decrypt differ in exactly one
			 * place -- which octet enters the feedback register -- and swapping them yields a pair
			 * that round-trips perfectly against itself and matches no other AES anywhere. So the
			 * ciphertext fed in here is the PUBLISHED one, and the plaintext that must come out is
			 * the published plaintext.
			 */
			for (q = 0; q < 32; q++) AKey[q] = K256[q];
			Tpm2AesSetKey(&AK, AKey, 256);
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)q;
			Tpm2AesCfbEncrypt(&AK, AIv, ABuf, 64, AOut);
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)q;
			Tpm2AesCfbDecrypt(&AK, AIv, AOut, 64, ABuf + 64);
			PrintHexN("aes.cfb256_back", ABuf + 64, 64);
		}
#undef AES_CFB_KAT

		/* --- lengths that are NOT a multiple of the block --- */
		/*
		 * (!) EVERY PUBLISHED CFB VECTOR IS AN EXACT MULTIPLE OF SIXTEEN, SO NONE OF THEM CAN SEE
		 * A BROKEN PARTIAL BLOCK. That is the whole gap: an implementation that padded, or that
		 * advanced the IV as if a full block had passed, would pass every check above. The oracle
		 * for these is OpenSSL, through the checker, on inputs both sides can generate.
		 */
		{
			static CONST UINT32 Lens[9] = { 0, 1, 15, 16, 17, 31, 32, 33, 100 };
			static UINT8 Big[128], Enc[128], Chunk2[128];
			UINT32 li;

			for (q = 0; q < 32; q++)  AKey[q] = (UINT8)(q * 7 + 3);
			for (q = 0; q < 128; q++) Big[q] = (UINT8)(q * 37 + 11);

			for (li = 0; li < 9; li++)
			{
				UINT32 Len = Lens[li];

				Tpm2AesSetKey(&AK, AKey, 128);
				for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
				Tpm2AesCfbEncrypt(&AK, AIv, Big, Len, Enc);
				printf("aes.len%03u=", (unsigned)Len);
				for (q = 0; q < Len; q++) printf("%02x", Enc[q]);
				printf("\n");

				/*
				 * (!) AND THE IV THE CALL LEAVES BEHIND, WHICH AN EARLIER COMMENT HERE WRONGLY
				 * CALLED UNTESTABLE. It claimed OpenSSL could not be asked for it, so the chunking
				 * test would have to cover it. OpenSSL cannot report its internal register, but
				 * the CORRECT value is computable from what OpenSSL does return: after n octets,
				 * the register holds ciphertext[0..n-1] followed by the ORIGINAL IV from n on.
				 *
				 * That reasoning cost a caught injury. An injury that padded the tail of a partial
				 * block with keystream survived the whole suite, because the only test that could
				 * have seen it merely asserted two streams DIFFER -- which a wrong answer also
				 * satisfies. This prints the register so the checker can pin its exact octets.
				 */
				printf("aes.iv%03u=", (unsigned)Len);
				for (q = 0; q < 16; q++) printf("%02x", AIv[q]);
				printf("\n");
			}

			/*
			 * (!) THE CHUNKING CONTRACT, PINNED IN BOTH DIRECTIONS, BECAUSE THIS TEST CORRECTED
			 * THE HEADER RATHER THAN THE CODE. The header used to promise that any chunking
			 * reproduces a one-shot call. Chunks of 7/9/16/68 proved otherwise and the code was
			 * right: CFB128 feeds back a whole ciphertext BLOCK, so a short chunk leaves only a
			 * fragment of a feedback value and ends the stream.
			 *
			 * So ALIGNED chunks must match, and UNALIGNED chunks must NOT. Asserting only the
			 * first would let someone "fix" this later by buffering the keystream remainder and
			 * silently change a documented contract; asserting both makes that a deliberate act.
			 */
			Tpm2AesSetKey(&AK, AKey, 128);
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
			Tpm2AesCfbEncrypt(&AK, AIv, Big, 100, Enc);
			{
				static UINT8 Chunk[128];
				/* every chunk but the last is a whole number of blocks */
				static CONST UINT32 Aligned[4]   = { 16, 32, 16, 36 };
				/* and these are not, which is the case CFB128 cannot carry */
				static CONST UINT32 Unaligned[4] = {  7,  9, 16, 68 };
				UINT32 off, k2, same;

				same = 1; off = 0;
				Tpm2AesSetKey(&AK, AKey, 128);
				for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
				for (k2 = 0; k2 < 4; k2++)
				{
					Tpm2AesCfbEncrypt(&AK, AIv, Big + off, Aligned[k2], Chunk + off);
					off += Aligned[k2];
				}
				for (q = 0; q < 100; q++)
					if (Chunk[q] != Enc[q]) same = 0;
				printf("aes.chunked_aligned=%u\n", (unsigned)(same));

				same = 1; off = 0;
				Tpm2AesSetKey(&AK, AKey, 128);
				for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
				for (k2 = 0; k2 < 4; k2++)
				{
					Tpm2AesCfbEncrypt(&AK, AIv, Big + off, Unaligned[k2], Chunk + off);
					off += Unaligned[k2];
				}
				for (q = 0; q < 100; q++)
					if (Chunk[q] != Enc[q]) same = 0;
				printf("aes.chunked_unaligned=%u\n", (unsigned)(same));

				/*
				 * (!) AND THE FIRST SEVEN OCTETS STILL AGREE. The unaligned stream is not garbage
				 * from the start -- it diverges only where the first short chunk ends. Recording
				 * that keeps the failure mode honest: it is a chaining limit, not a broken cipher.
				 */
				same = 1;
				for (q = 0; q < 7; q++)
					if (Chunk[q] != Enc[q]) same = 0;
				printf("aes.chunked_prefix_ok=%u\n", (unsigned)(same));
			}

			/*
			 * (!) AND CFB IN PLACE, WHICH IS HOW AN OBJECT CACHE WILL ACTUALLY CALL IT. Out aliases
			 * In exactly. The feedback octet has to be captured BEFORE the store or the register
			 * picks up ciphertext it has already overwritten, and only an aliasing vector sees it.
			 */
			for (q = 0; q < 128; q++) Chunk2[q] = Big[q];
			Tpm2AesSetKey(&AK, AKey, 128);
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
			Tpm2AesCfbEncrypt(&AK, AIv, Chunk2, 100, Chunk2);
			{
				UINT32 same = 1;
				for (q = 0; q < 100; q++)
					if (Chunk2[q] != Enc[q]) same = 0;
		printf("aes.inplace_matches=%u\n", (unsigned)(same));
			}
			/* decrypt in place too, back to the original */
			Tpm2AesSetKey(&AK, AKey, 128);
			for (q = 0; q < 16; q++) AIv[q] = (UINT8)(q * 11 + 5);
			Tpm2AesCfbDecrypt(&AK, AIv, Chunk2, 100, Chunk2);
			{
				UINT32 same = 1;
				for (q = 0; q < 100; q++)
					if (Chunk2[q] != Big[q]) same = 0;
		printf("aes.inplace_roundtrip=%u\n", (unsigned)(same));
			}
		}
	}
	return 0;
}
