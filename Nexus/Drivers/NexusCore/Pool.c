/**
 * @file Pool.c
 * @brief Big-pool enumeration. Read Pool.h first -- especially the "only sees BIG pool" block.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Pool.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define PoolLog NxcLogExt

/* SYSTEM_INFORMATION_CLASS::SystemBigPoolInformation. 0x42 == 66. */
#define NXC_SYSTEM_BIG_POOL_INFORMATION   66

/*
 * Mirrored from the documented-but-header-absent shape.
 *
 * ⚠ VirtualAddress's BIT 0 IS A FLAG, NOT ADDRESS. The real declaration is a union of a PVOID and a
 * `ULONG_PTR NonPaged : 1` bitfield, so the low bit reports the pool type and must be masked off
 * before the pointer is used or reported. (v1's comment claimed the TOP bit; its code correctly used
 * the low one. See Pool.h.)
 */
typedef struct _NXC_BIG_POOL_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} NXC_BIG_POOL_ENTRY;

typedef struct _NXC_BIG_POOL_INFO
{
	ULONG              Count;
	NXC_BIG_POOL_ENTRY AllocatedInfo[1];   /* variable length */
} NXC_BIG_POOL_INFO;

C_ASSERT(sizeof(NXC_BIG_POOL_ENTRY) == 24);

#define NXC_POOL_FIRST_TRY   (1u * 1024u * 1024u)
#define NXC_POOL_CAP         (128u * 1024u * 1024u)
#define NXC_POOL_ATTEMPTS    8

/* ---------------------------------------------------------------------------------------------
 * Pool bait. Design and the D4 exception are in Pool.h -- read that block before changing this.
 * ------------------------------------------------------------------------------------------- */

static void*  gBait[NXC_MAX_BAIT];
static UINT32 gBaitTag[NXC_MAX_BAIT];
static UINT32 gBaitCount = 0;

UINT32
NxcPoolBaitCount(
	void
	)
{
	return gBaitCount;
}

NTSTATUS
NxcPoolBaitFree(
	_Out_ UINT32* OutFreed
	)
{
	*OutFreed = 0;

	UINT32 n = 0;
	for (UINT32 i = 0; i < NXC_MAX_BAIT; i++)
	{
		if (gBait[i] == NULL)
			continue;
		ExFreePoolWithTag(gBait[i], gBaitTag[i]);
		gBait[i]    = NULL;
		gBaitTag[i] = 0;
		n++;
	}

	gBaitCount = 0;
	*OutFreed = n;
	PoolLog("pool: freed %u bait allocations\n", n);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcPoolBait(
	_In_ UINT32 Tag,
	_In_ UINT32 Count,
	_In_ UINT32 SizeBytes,
	_Out_writes_(Cap) NXCMD_POOL_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Planted
	)
{
	*Planted = 0;

	if (Out == NULL || Cap == 0 || Tag == 0 || Count == 0)
		return STATUS_INVALID_PARAMETER;

	/*
	 * REFUSED, not silently added to. Planting a second set while one is outstanding would orphan
	 * the first -- the tracking array is the only handle on it, and this driver never unloads, so an
	 * orphan is permanent non-paged memory.
	 */
	if (gBaitCount != 0)
	{
		PoolLog("pool: %u bait blocks already planted -- free them first\n", gBaitCount);
		return STATUS_ALREADY_COMMITTED;
	}

	/*
	 * ⚠ THE FLOOR IS RAISED, NOT REFUSED. Under PAGE_SIZE the allocation is served from a subdivided
	 * pool page and never reaches SystemBigPoolInformation -- so it would be invisible to exactly
	 * the scanners it exists to attract while still consuming memory. Silently honouring a too-small
	 * request would produce bait that cannot work and no indication of why.
	 */
	UINT32 Size = SizeBytes;
	if (Size < PAGE_SIZE)
	{
		PoolLog("pool: bait size %u is below the big-pool threshold -- raised to %u\n",
		        Size, (UINT32)PAGE_SIZE);
		Size = PAGE_SIZE;
	}
	if (Size > (1u * 1024u * 1024u))
		Size = 1u * 1024u * 1024u;

	CONST UINT32 Want = (Count < NXC_MAX_BAIT) ? Count : NXC_MAX_BAIT;

	UINT32 n = 0;
	for (UINT32 i = 0; i < Want; i++)
	{
		void* CONST P = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, Tag);
		if (P == NULL)
			break;   /* partial success is normal under pressure and is reported, not rolled back */

		/*
		 * A RECOGNISABLE, NON-UNIFORM FILL. v1 filled with one repeated byte, which makes the page
		 * uniform -- and our own entropy work says a uniform page is the degenerate case every
		 * heuristic treats specially. A scanner that skips uniform pages would skip the bait.
		 *
		 * The pattern repeats the tag and the block index, so a block found later in a dump
		 * identifies itself without needing this table.
		 */
		UINT32* CONST W = (UINT32*)P;
		CONST UINT32 Words = Size / sizeof(UINT32);
		for (UINT32 k = 0; k < Words; k++)
			W[k] = Tag ^ (k * 0x9E3779B9u) ^ (i << 24);

		gBait[n]    = P;
		gBaitTag[n] = Tag;

		if (n < Cap)
		{
			Out[n].VirtualAddress = (UINT64)(ULONG_PTR)P;
			Out[n].SizeInBytes    = Size;
			Out[n].TagUlong       = Tag;
			Out[n].Flags          = NXCMD_POOL_NONPAGED;
		}
		n++;
	}

	gBaitCount = n;
	*Planted   = n;

	PoolLog("pool: planted %u of %u bait blocks, %u bytes, tag 0x%08X\n", n, Want, Size, Tag);
	return (n == 0) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}

NTSTATUS
NxcPoolList(
	_Out_writes_(Cap) NXCMD_POOL_ENTRY* Out,
	_In_ UINT32 Cap,
	_In_ UINT32 TagFilter,
	_In_ UINT64 MinSize,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* Scanned
	)
{
	*Got     = 0;
	*Total   = 0;
	*Scanned = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	/*
	 * GROW LOOP, not probe-then-allocate.
	 *
	 * The usual idiom -- call with a NULL buffer to learn the required length -- is UNRELIABLE for
	 * this information class: some Windows versions return STATUS_INFO_LENGTH_MISMATCH without
	 * writing back a length, so the caller learns nothing and a naive implementation loops forever
	 * on zero. v1 hit this. We use the returned length WHEN IT IS PRESENT and double when it is not,
	 * which is correct under both behaviours.
	 */
	PVOID    Buf     = NULL;
	SIZE_T   BufLen  = NXC_POOL_FIRST_TRY;
	NTSTATUS St      = STATUS_INFO_LENGTH_MISMATCH;

	for (int Attempt = 0; Attempt < NXC_POOL_ATTEMPTS; Attempt++)
	{
		if (BufLen > NXC_POOL_CAP)
		{
			PoolLog("pool: required buffer exceeded the %u MB cap -- refusing to keep growing\n",
			        NXC_POOL_CAP / (1024u * 1024u));
			St = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		Buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufLen, 'lPxN');
		if (Buf == NULL)
		{
			/* Out of contiguous non-paged memory for OUR buffer -- not a statement about the pool
			 * being enumerated. Reported as its own status so the two are not confused. */
			St = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		ULONG Needed = 0;
		St = ZwQuerySystemInformation(NXC_SYSTEM_BIG_POOL_INFORMATION,
		                              Buf, (ULONG)BufLen, &Needed);
		if (NT_SUCCESS(St))
			break;

		ExFreePoolWithTag(Buf, 'lPxN');
		Buf = NULL;

		if (St != STATUS_INFO_LENGTH_MISMATCH)
			break;   /* bad class, access denied -- growing will not help */

		/* Use the kernel's number when it gave one; otherwise double. Margin because the pool can
		 * grow between the query that sized it and the query that reads it. */
		BufLen = (Needed > BufLen) ? ((SIZE_T)Needed + 0x100000) : (BufLen * 2);
	}

	if (Buf == NULL || !NT_SUCCESS(St))
	{
		if (Buf != NULL)
			ExFreePoolWithTag(Buf, 'lPxN');
		return NT_SUCCESS(St) ? STATUS_UNSUCCESSFUL : St;
	}

	CONST NXC_BIG_POOL_INFO* CONST Info = (CONST NXC_BIG_POOL_INFO*)Buf;
	CONST ULONG Count = Info->Count;

	/*
	 * Trust the buffer we were given, but bound the walk by it anyway. Count comes from the kernel
	 * and should be consistent with the length -- but reading past our own allocation because a
	 * count was larger than expected is not a risk worth accepting for free.
	 */
	CONST ULONG MaxByLen = (ULONG)((BufLen - FIELD_OFFSET(NXC_BIG_POOL_INFO, AllocatedInfo))
	                               / sizeof(NXC_BIG_POOL_ENTRY));
	CONST ULONG Walk = (Count < MaxByLen) ? Count : MaxByLen;

	*Scanned = Walk;

	UINT32 Matched = 0, Wrote = 0;
	for (ULONG i = 0; i < Walk; i++)
	{
		CONST NXC_BIG_POOL_ENTRY* CONST E = &Info->AllocatedInfo[i];
		CONST ULONG_PTR Raw = (ULONG_PTR)E->VirtualAddress;

		/* ⚠ BIT 0 IS THE NONPAGED FLAG. Masking it is not tidiness -- an unmasked pointer is off by
		 * one and every address reported would be wrong. */
		CONST UINT64  Va       = (UINT64)(Raw & ~(ULONG_PTR)1);
		CONST BOOLEAN NonPaged = (Raw & 1) != 0;

		if (TagFilter != 0 && E->TagUlong != TagFilter)
			continue;
		if (MinSize != 0 && (UINT64)E->SizeInBytes < MinSize)
			continue;

		Matched++;
		if (Wrote < Cap)
		{
			Out[Wrote].VirtualAddress = Va;
			Out[Wrote].SizeInBytes    = (UINT64)E->SizeInBytes;
			Out[Wrote].TagUlong       = E->TagUlong;
			Out[Wrote].Flags          = NonPaged ? NXCMD_POOL_NONPAGED : 0u;
			Wrote++;
		}
	}

	ExFreePoolWithTag(Buf, 'lPxN');

	*Got   = Wrote;
	*Total = Matched;

	PoolLog("pool: scanned %u big-pool entries, %u matched, %u returned\n", Walk, Matched, Wrote);
	return STATUS_SUCCESS;
}
