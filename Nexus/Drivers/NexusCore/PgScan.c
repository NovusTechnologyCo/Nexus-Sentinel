/**
 * @file PgScan.c
 * @brief Is a PatchGuard context resident? Read PgScan.h first -- especially the int 20h trap
 *        and the absence-of-evidence block.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "PgScan.h"
#include "Pool.h"
#include "Pte.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define PgLog NxcLogExt

/*
 * Plaintext constants from the bug-check parameter routines (Windows 11 24H2 analysis). These
 * survive the encryption that hides the rest of the context, which is what makes them usable.
 */
#define PG_CONST_A   0x5C5FC0A76E374B18ULL
#define PG_CONST_B   0x4C48B4211BBACBEBULL

/*
 * ⚠ THE FLOOR, AND WHY IT IS NOW SO LOW.
 *
 * This was 0x40000 (256 KB), chosen as a "generous lower bound" under the belief that the
 * context is about a megabyte. The real allocation measured 0x42000 -- 270336 bytes. The floor
 * cleared it by 8192 bytes. A build that allocated 1% less, or a padding choice 8 KB smaller,
 * and the scanner would have skipped the context outright and reported a confident zero, and
 * there would have been nothing in the output to suggest anything had been skipped.
 *
 * So the floor is now 64 KB, which is far below any plausible context and still excludes the
 * bulk of ordinary big pool. Cost is linear in what gets byte-scanned and the budget below
 * bounds that. This is the cheapest possible insurance against the failure that already
 * happened once, in a file whose entire purpose is to not produce a false negative.
 */
#define PG_SIZE_FLOOR       (0x10000ULL)      /* 64 KB */

/*
 * Bounded so a pathological pool cannot turn a diagnostic into a hang.
 *
 * ⚠ RAISED, AND THE OLD VALUE HAD ALREADY BITTEN. It was 4096, chosen when the floor
 * was 256 KB. Lowering the floor to 64 KB multiplied what qualifies: a real boot has 5845
 * allocations at or above it, so the snapshot silently held 70% of them and the scan reported
 * "examined 4096" -- a number that reads like completeness.
 *
 * That is the exact failure this file exists to avoid, reintroduced by a change meant to widen
 * coverage. The cap is now well clear of the measured count, and -- more importantly, because any
 * fixed cap can be exceeded again -- OutAvailable now travels with every result so the caller can
 * say WHAT FRACTION was examined instead of just how many.
 *
 * The array is uninitialised static, so it costs virtual size and no file size.
 */
#define PG_MAX_POOL_ENTRIES 16384u
#define PG_MAX_SCAN_BYTES   (64ULL * 1024ULL * 1024ULL)

/*
 * Big-pool snapshot buffer. STATIC because this runs on a diagnostic path: it is far too large
 * for a stack, and allocating it would perturb the very pool being examined.
 */
static NXCMD_POOL_ENTRY gPoolSnapshot[PG_MAX_POOL_ENTRIES];


/**
 * Is every page of [Va, Va+Size) resident, and does any page carry BOTH write and execute?
 *
 * ⚠ NxcPteQuery RATHER THAN MmIsAddressValid. The walk goes through the self-map, whose pages
 * are never paged out, so it is legal at any IRQL -- MmIsAddressValid is documented at <=
 * DISPATCH. Same reasoning as Calls.c.
 *
 * Returns FALSE if any page is absent, which is the caller's signal to SKIP rather than read.
 * Reading a non-resident pool page to hunt for PatchGuard would be a fine way to bugcheck while
 * trying to prove nothing is going to bugcheck.
 */
static BOOLEAN
PgProbeRange(
	_In_ UINT64 Va,
	_In_ UINT64 Size,
	_Out_ BOOLEAN* OutRwx
	)
{
	*OutRwx = FALSE;

	for (UINT64 Page = Va & ~(UINT64)(PAGE_SIZE - 1); Page < Va + Size; Page += PAGE_SIZE)
	{
		NXC_PTE_INFO Info;
		if (!NT_SUCCESS(NxcPteQuery(Page, &Info)))
			return FALSE;
		if ((Info.Flags & (NXC_PTE_VALID | NXC_PTE_PRESENT)) !=
			(NXC_PTE_VALID | NXC_PTE_PRESENT))
			return FALSE;

		if ((Info.Flags & NXC_PTE_WRITABLE) && (Info.Flags & NXC_PTE_EXECUTE))
			*OutRwx = TRUE;

		/*
		 * A large mapping covers the rest of its span, so stepping 4 KB through it would be
		 * 512 (or 262,144) identical queries for one answer.
		 */
		if (Info.Flags & NXC_PTE_LARGE_1G)
			Page = (Page & ~((1ULL << 30) - 1)) + (1ULL << 30) - PAGE_SIZE;
		else if (Info.Flags & NXC_PTE_LARGE_2M)
			Page = (Page & ~((1ULL << 21) - 1)) + (1ULL << 21) - PAGE_SIZE;
	}

	return TRUE;
}


/**
 * Search a resident range for either plaintext constant.
 *
 * Stepping 8 bytes, not 1: both constants are 64-bit values written as aligned QWORDs by the
 * code that stores them. A byte-granular search would be eight times the work to find the same
 * thing, and the cost matters because this runs over megabytes.
 */
static UINT32
PgFindConstants(
	_In_reads_bytes_(Size) CONST UINT64* Base,
	_In_ UINT64 Size,
	_Out_ UINT64* OutOffset
	)
{
	CONST UINT64 Count = Size / sizeof(UINT64);
	UINT32 Found = 0;

	*OutOffset = 0;

	for (UINT64 i = 0; i < Count; ++i)
	{
		CONST UINT64 V = Base[i];

		if (V == PG_CONST_A)
		{
			if (Found == 0)
				*OutOffset = i * sizeof(UINT64);
			Found |= NXC_PGSIG_CONST_A;
		}
		else if (V == PG_CONST_B)
		{
			if (Found == 0)
				*OutOffset = i * sizeof(UINT64);
			Found |= NXC_PGSIG_CONST_B;
		}

		/* Both present is as identified as this gets -- stop paying for the rest. */
		if ((Found & (NXC_PGSIG_CONST_A | NXC_PGSIG_CONST_B)) ==
			(NXC_PGSIG_CONST_A | NXC_PGSIG_CONST_B))
			break;
	}

	return Found;
}


/**
 * Find PatchGuard's in-place decryption loop near the start of an allocation.
 *
 * WHAT IT MATCHES, and why this shape rather than the bytes that were actually observed:
 *
 *     48 31 <modrm> <disp8>      REX.W xor [reg+disp8], reg
 *     48 31 <modrm> <disp8+8>
 *     48 31 <modrm> <disp8+16>   ... PG_STUB_MIN_RUN times
 *
 * The modrm byte is required to be IDENTICAL across the run but is not required to be any
 * particular value, and the displacement must advance by exactly 8. So this matches "an unrolled
 * loop xoring a buffer in qword steps" -- which is what an in-place decryptor is -- rather than
 * "the exact registers PatchGuard used on one machine on one boot". The observed stub uses rcx
 * and rdx (modrm 0x51); a build that picks rsi and rbx still matches.
 *
 * ⚠ THE SEARCH IS ANCHORED, NOT GLOBAL. Only the first PG_STUB_WINDOW bytes are examined,
 * because g_PgContext points AT the stub and the context starts within the random padding
 * window. Scanning whole megabytes for this would find xor loops in every crypto buffer and
 * compressed page in the system, and cost 30x more to do it.
 *
 * Returns the offset of the run, or 0 with a FALSE return.
 */
static BOOLEAN
PgFindStub(
	_In_reads_bytes_(Size) CONST UINT8* Base,
	_In_ UINT64 Size,
	_Out_ UINT64* OutOffset
	)
{
	*OutOffset = 0;

	UINT64 Limit = (Size < PG_STUB_WINDOW) ? Size : PG_STUB_WINDOW;
	CONST UINT64 Need = (UINT64)PG_STUB_MIN_RUN * 4u;

	if (Limit < Need)
		return FALSE;
	Limit -= Need;

	for (UINT64 i = 0; i <= Limit; ++i)
	{
		if (Base[i] != 0x48 || Base[i + 1] != 0x31)
			continue;

		CONST UINT8 Modrm = Base[i + 2];

		/*
		 * mod must be 01 (register + disp8). mod 00 has no displacement to advance, and the
		 * leading `cs: xor [rcx],rdx` of the real stub is exactly that -- which is why the run is
		 * matched from the SECOND instruction onwards and the prefix is not required at all.
		 */
		if ((Modrm & 0xC0u) != 0x40u)
			continue;

		CONST UINT8 First = Base[i + 3];
		UINT32 Run = 1;

		while (Run < PG_STUB_MIN_RUN)
		{
			CONST UINT64 At = i + (UINT64)Run * 4u;

			if (Base[At] != 0x48 || Base[At + 1] != 0x31 || Base[At + 2] != Modrm ||
				Base[At + 3] != (UINT8)(First + (UINT8)(Run * 8u)))
				break;

			Run++;
		}

		if (Run >= PG_STUB_MIN_RUN)
		{
			*OutOffset = i;
			return TRUE;
		}
	}

	return FALSE;
}


/**
 * How interesting is this combination of signatures? Higher sorts first.
 *
 * (!) A RANKING, NOT A FILTER. Every candidate is still reported; this only decides reading order.
 * The weights follow PgScan.h: a plaintext constant would identify outright, the stub is what
 * actually found the real context, and RWX was MEASURED to be a negative indicator -- so an
 * RWX-only row sorts BELOW everything else rather than above it, which is where 13 DMA buffers
 * spent two boots pretending to be findings.
 */
static UINT32
PgRank(
	_In_ UINT32 Sigs
	)
{
	UINT32 Rank = 0;

	if (Sigs & (NXC_PGSIG_CONST_A | NXC_PGSIG_CONST_B))
		Rank += 8;      /* would identify outright; has never fired */
	if (Sigs & NXC_PGSIG_STUB)
		Rank += 4;      /* the one that found the real context */
	if (Sigs & NXC_PGSIG_RWX)
		Rank += 1;      /* measured NX on PatchGuard -- sorts LAST, deliberately */

	return Rank;
}


NTSTATUS
NxcPgScan(
	_Out_writes_(Cap) NXC_PG_CANDIDATE* Out,
	_In_ UINT32 Cap,
	_In_ UINT64 MinSize,
	_Out_ UINT32* OutGot,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutScanned,
	_Out_ UINT64* OutBytes,
	_Out_ UINT32* OutSkipped,
	_Out_ UINT32* OutAvailable
	)
{
	if (Out == NULL || OutGot == NULL || OutTotal == NULL || OutScanned == NULL ||
		OutBytes == NULL || OutSkipped == NULL || OutAvailable == NULL)
		return STATUS_INVALID_PARAMETER;

	*OutGot = *OutTotal = *OutScanned = *OutSkipped = *OutAvailable = 0;
	*OutBytes = 0;

	CONST UINT64 Floor = (MinSize != 0) ? MinSize : PG_SIZE_FLOOR;

	UINT32 Got = 0, Total = 0, Scanned = 0;   /* Total: how many EXIST, not how many fit */
	CONST NTSTATUS Status = NxcPoolList(gPoolSnapshot, PG_MAX_POOL_ENTRIES,
										0 /* every tag */, Floor,
										&Got, &Total, &Scanned);
	if (!NT_SUCCESS(Status))
	{
		PgLog("pgscan: big-pool enumeration FAILED 0x%08X -- no conclusion is available\n",
		      Status);
		return Status;
	}

	/*
	 * (!) A TRUNCATED ENUMERATION MUST NOT PRODUCE A CONFIDENT ZERO. If the snapshot did not
	 * hold every allocation at or above the floor, then "nothing matched" describes the part we
	 * saw, and the caller has to be told so it can say that too.
	 */
	if (Total > Got)
	{
		PgLog("pgscan: big pool TRUNCATED -- %u of %u allocations examined. "
		      "A zero result covers only what was examined.\n", Got, Total);
	}

	UINT64 BudgetLeft = PG_MAX_SCAN_BYTES;
	UINT32 Written = 0, Candidates = 0, Skipped = 0;
	UINT64 BytesScanned = 0;

	for (UINT32 i = 0; i < Got; ++i)
	{
		CONST UINT64 Address = gPoolSnapshot[i].VirtualAddress;
		CONST UINT64 Size    = gPoolSnapshot[i].SizeInBytes;

		if (Address == 0 || Size == 0)
			continue;

		UINT32 Sigs = 0;

		/*
		 * (!) NOTHING IS SCORED FROM SIZE OR ALIGNMENT. Size serves only as the enumeration
		 * floor, and alignment says nothing: the ALLOCATION is page-aligned, and it is the
		 * CONTEXT INSIDE it that sits at a random offset -- which is what PgFindStub looks for.
		 * Both were measured, and both are recorded in PgScan.h.
		 */

		BOOLEAN Rwx = FALSE;
		if (!PgProbeRange(Address, Size, &Rwx))
		{
			/*
			 * Not fully resident. Counted and reported rather than ignored -- a scan that
			 * silently skipped the one allocation that mattered would return a clean zero.
			 */
			Skipped++;
			continue;
		}
		if (Rwx)
			Sigs |= NXC_PGSIG_RWX;

		UINT64 HitOffset = 0;

		/*
		 * The stub search is ANCHORED and runs unconditionally -- it reads at most 0x800 bytes,
		 * it is not charged against the scan budget, and it is the signature that actually finds
		 * PatchGuard. Letting a budget exhausted by earlier megabytes suppress THIS would rebuild
		 * the exact failure this file was rewritten to remove.
		 */
		UINT64 StubOffset = 0;
		if (PgFindStub((CONST UINT8*)(ULONG_PTR)Address, Size, &StubOffset))
		{
			Sigs |= NXC_PGSIG_STUB;
			HitOffset = StubOffset;
		}

		UINT64 Scan = Size;
		if (Scan > BudgetLeft)
			Scan = BudgetLeft;

		if (Scan >= sizeof(UINT64))
		{
			UINT64 ConstOffset = 0;
			CONST UINT32 Const =
				PgFindConstants((CONST UINT64*)(ULONG_PTR)Address, Scan, &ConstOffset);
			if (Const != 0)
			{
				Sigs |= Const;
				HitOffset = ConstOffset;   /* a constant outranks the stub as a locator */
			}
			BytesScanned += Scan;
			BudgetLeft   -= Scan;
		}

		/*
		 * Strong signatures only. There is no longer a weak-pair fallback: the pair it used to
		 * accept (SIZE+UNALIGNED) could not fire, and RWX -- which could and did, 13 times on one
		 * boot -- is no longer strong because PatchGuard's pages are NX.
		 */
		if ((Sigs & NXC_PGSIG_STRONG) == 0)
			continue;

		Candidates++;
		if (Written < Cap)
		{
			Out[Written].Address     = Address;
			Out[Written].SizeInBytes = Size;
			Out[Written].TagUlong    = gPoolSnapshot[i].TagUlong;
			Out[Written].Signatures  = Sigs;
			Out[Written].HitOffset   = HitOffset;
			Written++;
		}

		if (BudgetLeft == 0)
		{
			PgLog("pgscan: scan budget exhausted after %llu bytes -- allocations past this "
			      "point were shape-checked but NOT searched for constants\n", BytesScanned);
			BudgetLeft = 1;   /* stop re-logging; shape checks continue */
		}
	}

	/*
	 * Rank the reported candidates, strongest first.
	 *
	 * NOTHING IS DROPPED -- this only reorders. It exists because the first hardware run returned
	 * 12 benign RWX allocations (see PgScan.h), and on the boot that matters the one
	 * interesting entry has to be at the TOP of that list rather than somewhere inside it. A
	 * finding the reader has to hunt for is a finding they can miss.
	 *
	 * Insertion sort: Written is bounded by the caller's capacity and is a dozen in practice.
	 */
	for (UINT32 i = 1; i < Written; ++i)
	{
		CONST NXC_PG_CANDIDATE Key = Out[i];
		CONST UINT32 KeyRank = PgRank(Key.Signatures);
		UINT32 j = i;

		while (j > 0 && PgRank(Out[j - 1].Signatures) < KeyRank)
		{
			Out[j] = Out[j - 1];
			--j;
		}
		Out[j] = Key;
	}

	*OutGot     = Written;
	*OutTotal   = Candidates;
	*OutScanned   = Got;
	*OutBytes     = BytesScanned;
	*OutSkipped   = Skipped;
	*OutAvailable = Total;

	/*
	 * ⚠ THE EMPTY RESULT IS STATED, NOT IMPLIED. Pool.h reports its caveat on every empty
	 * result rather than only in documentation, "because the reader who most needs it is the
	 * one who did not open this file". Exactly the same applies here, and more so: a zero is
	 * the answer the operator WANTS, which is precisely when a caveat gets skipped over.
	 */
	if (Candidates == 0)
	{
		PgLog("pgscan: NO CANDIDATE matched (%u allocations examined, %llu bytes searched, "
		      "%u skipped as not resident).\n", Got, BytesScanned, Skipped);
		PgLog("pgscan: that means no BIG-POOL allocation carried these signatures. It is NOT "
		      "proof PatchGuard is absent, and it is worthless until this detector has been "
		      "seen to FIND a context on a boot with PG patching disabled.\n");
	}
	else
	{
		PgLog("pgscan: %u candidate(s) (%u reported), %u allocations examined, %llu bytes "
		      "searched, %u skipped.\n", Candidates, Written, Got, BytesScanned, Skipped);
	}

	return STATUS_SUCCESS;
}
