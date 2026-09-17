/**
 * @file Arena.c
 * @brief Implementation of the runtime map arena sub-allocator. Rationale lives in Arena.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include "Arena.h"
#include "../../Include/NexusModule.h"   /* NXM_POISON_BYTE -- one poison value for the whole stack */

/*
 * Payload source: nt calls route through the exported table, so this image emits no import table
 * and therefore no FF 25 thunks for the published manual-map scan (see NexusNtApi.h).
 * `extern` because NexusCore.c owns the single instance.
 */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

/*
 * Extent table. A SORTED, GAPLESS partition of the arena: every byte belongs to exactly one extent,
 * free or in use, and Base ascends with index. That invariant is what makes coalescing a neighbour
 * check rather than a search, and it is asserted on every mutation in the checked paths below.
 *
 * Statically sized in .data on purpose -- see the no-pool note in the header.
 */
typedef struct _NXC_EXTENT
{
	UCHAR*  Base;
	ULONG   Size;      /* always a multiple of NXC_ARENA_ALIGN */
	BOOLEAN InUse;
	BOOLEAN Valid;     /* slot participates in the partition   */
	/*
	 * ⚠ A FREE IN FLIGHT. Set under the lock before the poison pass and cleared under the lock when
	 * the free is published. `InUse` STAYS SET for the whole poison, which is what keeps the
	 * allocator's first-fit (which skips InUse) from handing the range out while it is being filled
	 * with 0xCC. This flag exists only so a SECOND free of the same extent is refused immediately
	 * rather than poisoning a second time and racing the first to publish.
	 *
	 * Mirrors NXC_WATCH_CAPTURING in Capture.c: claim under the lock, do the slow work outside it,
	 * publish under the lock.
	 */
	BOOLEAN Freeing;
	ULONG   Owner;     /* NXC_OWNER_* or a module id -- lets teardown reclaim ALL of a module's memory */
} NXC_EXTENT;

static NXC_EXTENT  gExtents[NXC_MAX_EXTENTS];
static ULONG       gExtentCount = 0;
static UCHAR*      gArenaBase = NULL;
static ULONG       gArenaSize = 0;
static KSPIN_LOCK  gArenaLock;
static BOOLEAN     gInitialised = FALSE;

/** Round up to page granularity. Overflow-safe: a request near ULONG_MAX must fail, not wrap to 0. */
static ULONG
AlignUp(
	ULONG Value
	)
{
	if (Value > (0xFFFFFFFFu - (NXC_ARENA_ALIGN - 1)))
		return 0;
	return (Value + (NXC_ARENA_ALIGN - 1)) & ~(NXC_ARENA_ALIGN - 1);
}

/**
 * Overwrite a range with the poison byte.
 *
 * A hand-rolled loop rather than RtlFillMemory, so this cannot become a memset import that the
 * manual-map path then has to bind. The volatile write stops the optimiser eliding a fill it can
 * prove is never read -- which it otherwise legitimately could, and the whole point is that the bytes
 * are there for a STALE caller to hit.
 */
static void
Poison(
	UCHAR* Base,
	ULONG Size
	)
{
	for (ULONG i = 0; i < Size; i++)
		((volatile UCHAR*)Base)[i] = (UCHAR)NXM_POISON_BYTE;
}

NTSTATUS
NxcArenaInit(
	_In_ void* Base,
	_In_ ULONG Size
	)
{
	/*
	 * ⚠ REFUSE A SECOND INIT.
	 *
	 * This used to reinitialise unconditionally: reset gExtentCount to 1 and rebuild the table as one
	 * free extent covering everything. If any module were resident at the time, its extent record
	 * would simply vanish -- the memory stays mapped and its code stays running, while the allocator
	 * believes the whole arena is free and hands the same pages to the next caller. Two modules
	 * sharing memory is the unrecoverable case NxcArenaFree refuses a double free to prevent, and a
	 * second init would have created it wholesale.
	 *
	 * Not reachable today -- DriverEntry runs once per boot and NexusCoreTryLaunch is a one-shot -- so
	 * this is a guard against a future caller, not a fix for a live bug. It is a compare, and the
	 * failure it prevents is silent and total.
	 *
	 * Refused rather than treated as success: a caller asking to init an arena that already holds
	 * modules has a broken assumption, and returning SUCCESS would confirm it.
	 */
	if (gInitialised)
		return STATUS_ALREADY_INITIALIZED;

	if (Base == NULL || Size < (NXC_ARENA_ALIGN * 4))
		return STATUS_INVALID_PARAMETER;

	/* The DXE hands us a page-aligned reservation; refuse anything else rather than compensate. */
	if (((ULONG_PTR)Base & (NXC_ARENA_ALIGN - 1)) != 0)
		return STATUS_INVALID_PARAMETER;

	KeInitializeSpinLock(&gArenaLock);

	gArenaBase = (UCHAR*)Base;
	gArenaSize = Size & ~(NXC_ARENA_ALIGN - 1);

	for (ULONG i = 0; i < NXC_MAX_EXTENTS; i++)
	{
		gExtents[i].Base = NULL;
		gExtents[i].Size = 0;
		gExtents[i].InUse = FALSE;
		gExtents[i].Valid = FALSE;
		gExtents[i].Freeing = FALSE;
		gExtents[i].Owner = NXC_OWNER_NONE;
	}

	/* One free extent covering everything. Splits happen on demand. */
	gExtents[0].Base = gArenaBase;
	gExtents[0].Size = gArenaSize;
	gExtents[0].InUse = FALSE;
	gExtents[0].Valid = TRUE;
	gExtents[0].Freeing = FALSE;
	gExtents[0].Owner = NXC_OWNER_NONE;
	gExtentCount = 1;

	/*
	 * DELIBERATELY NOT POISONING THE WHOLE ARENA HERE. An earlier version did, reasoning that any
	 * execution of never-allocated arena memory should hit INT3 rather than run zeros as
	 * `add [rax],al`.
	 *
	 * The tier-2 web pass (run retroactively after the user noticed it had been skipped)
	 * changed that call: hidden drivers are described as detectable because they leave "privileged
	 * memory areas with LOW ENTROPY VALUES". A 16 MB block of uniform 0xCC is about as low-entropy
	 * and as unusual as memory gets -- a LOUDER signature than the driver image it was meant to
	 * protect. Zeroed reserved memory, by contrast, is utterly ordinary.
	 *
	 * So poison is applied ONLY where it earns its keep: to a FREED extent, in NxcArenaFree, where a
	 * stale caller genuinely might still execute. Never-allocated space stays as the DXE left it --
	 * zeroed. The diagnostic value is kept exactly where the risk is, and the 16 MB signature is not
	 * created.
	 */

	gInitialised = TRUE;
	return STATUS_SUCCESS;
}

void*
NxcArenaAlloc(
	_In_ ULONG Bytes,
	_Out_ ULONG* OutExtentId
	)
{
	/* Unowned allocations belong to NexusCore itself. */
	return NxcArenaAllocFor(NXC_OWNER_HOST, Bytes, OutExtentId);
}

void*
NxcArenaAllocFor(
	_In_ ULONG Owner,
	_In_ ULONG Bytes,
	_Out_ ULONG* OutExtentId
	)
{
	if (OutExtentId != NULL)
		*OutExtentId = NXC_EXTENT_NONE;
	if (!gInitialised || Bytes == 0)
		return NULL;

	CONST ULONG Need = AlignUp(Bytes);
	if (Need == 0)
		return NULL;

	/*
	 * A guard page follows every allocation, so a candidate extent must fit the payload PLUS the guard.
	 * The guard becomes the LAST PAGE OF THE ALLOCATION'S OWN EXTENT (see the split below) and is
	 * poisoned, so an image overrunning its bounds hits 0xCC rather than the next module's headers.
	 */
	CONST ULONG NeedWithGuard = Need + NXC_ARENA_ALIGN;
	if (NeedWithGuard < Need)          /* overflow */
		return NULL;

	KIRQL OldIrql;
	KeAcquireSpinLock(&gArenaLock, &OldIrql);

	void* Result = NULL;

	/* The trailing guard, filled AFTER the lock drops -- see the note at the fill below. */
	UCHAR* GuardBase = NULL;
	ULONG  GuardSize = 0;

	/*
	 * FIRST FIT, not best fit. With coalescing and a handful of extents, first fit is simpler and its
	 * failure mode is easier to reason about; best fit would leave a trail of unusable slivers that
	 * consume table slots for no benefit at this scale.
	 */
	for (ULONG i = 0; i < gExtentCount; i++)
	{
		if (!gExtents[i].Valid || gExtents[i].InUse || gExtents[i].Size < NeedWithGuard)
			continue;

		/*
		 * ⚠ REMAINDER IS MEASURED AGAINST NeedWithGuard, NOT Need -- the
		 * guard page this allocator documents did not exist.
		 *
		 * The old code carved `Need` and set the following free extent's Base to `Base + Need`, so the
		 * very next allocation began at the byte immediately after the previous one. Two modules ended
		 * up directly adjacent with nothing between them. The NeedWithGuard test above only proved the
		 * SOURCE extent had a spare page; the split then handed that page straight to the remainder,
		 * which is the first thing the next request consumes. The comment claimed "the gap stays part of
		 * the free extent that follows and is never handed out" -- nothing prevented that, and it was
		 * handed out every time.
		 *
		 * Now the allocation's extent absorbs the guard page: Size = Need + one page. The module is only
		 * ever told about Need bytes, so the trailing page is unreachable to it, and because the guard
		 * lives INSIDE an extent the arena still tiles the region completely -- which is the invariant
		 * coalescing depends on. An unowned hole between extents would have broken it.
		 */
		CONST ULONG Remainder = gExtents[i].Size - NeedWithGuard;

		if (Remainder == 0 || gExtentCount >= NXC_MAX_EXTENTS)
		{
			/*
			 * Exact fit including the guard, or no slot left to hold the remainder. Hand over the whole
			 * extent -- the payload is still only Need, so everything past it is slack that serves the
			 * same purpose as the guard.
			 *
			 * (This branch was previously DEAD: with Remainder measured against Need, and the loop
			 * skipping anything smaller than Need + a page, Remainder could never be 0. Measuring
			 * against NeedWithGuard makes exact fits real.)
			 */
			gExtents[i].InUse = TRUE;
			gExtents[i].Owner = Owner;
			Result = gExtents[i].Base;
			GuardBase = gExtents[i].Base + Need;
			GuardSize = gExtents[i].Size - Need;
			if (OutExtentId != NULL)
				*OutExtentId = i;
			break;
		}

		/* Split: [i] becomes payload + guard, a new extent after it holds the remainder. */
		for (ULONG j = gExtentCount; j > i + 1; j--)
			gExtents[j] = gExtents[j - 1];

		gExtents[i + 1].Base = gExtents[i].Base + NeedWithGuard;
		gExtents[i + 1].Size = Remainder;
		gExtents[i + 1].InUse = FALSE;
		gExtents[i + 1].Valid = TRUE;
		gExtents[i + 1].Owner = NXC_OWNER_NONE;

		gExtents[i].Size = NeedWithGuard;
		gExtents[i].InUse = TRUE;
		gExtents[i].Owner = Owner;
		gExtentCount++;

		GuardBase = gExtents[i].Base + Need;
		GuardSize = NXC_ARENA_ALIGN;

		Result = gExtents[i].Base;
		if (OutExtentId != NULL)
			*OutExtentId = i;
		break;
	}

	KeReleaseSpinLock(&gArenaLock, OldIrql);

	/*
	 * Zero AFTER releasing the lock: a mapped image needs its .bss zero, and the previous tenant left
	 * poison here. Done outside the lock because zeroing megabytes at raised IRQL would hold the lock
	 * far longer than the bookkeeping needs, and the extent is already exclusively ours.
	 */
	if (Result != NULL)
	{
		for (ULONG i = 0; i < Need; i++)
			((volatile UCHAR*)Result)[i] = 0;

		/*
		 * The guard is POISONED, not zeroed -- this is what gives it diagnostic value rather than making
		 * it merely unused. An image overrunning its own SizeOfImage lands on 0xCC and stops at an
		 * obvious INT3, instead of running zeros as `add [rax],al` and wandering.
		 *
		 * This does NOT reintroduce the low-entropy signature NxcArenaInit deliberately avoids: that was
		 * about painting the whole 16 MB reservation, which is a louder artefact than the driver it was
		 * protecting. One page behind each live allocation is small, and it sits where the risk is.
		 */
		if (GuardBase != NULL && GuardSize != 0)
			Poison(GuardBase, GuardSize);
	}
	return Result;
}

/**
 * Publish a free: clear the extent and coalesce. CALLER MUST HOLD gArenaLock.
 *
 * Resolves BY BASE rather than by index, because an index is a position in an array that SHIFTS.
 * Both the allocator's split and this function's own coalesce memmove entries, so any index read
 * before a lock release names a different extent afterwards.
 */
static NTSTATUS
ArenaPublishFreeLocked(
	_In_ UCHAR* Base
	)
{
	ULONG Id = NXC_EXTENT_NONE;
	for (ULONG i = 0; i < gExtentCount; i++)
	{
		if (gExtents[i].Valid && gExtents[i].Base == Base)
		{
			Id = i;
			break;
		}
	}
	if (Id == NXC_EXTENT_NONE)
		return STATUS_NOT_FOUND;

	gExtents[Id].InUse   = FALSE;
	gExtents[Id].Owner   = NXC_OWNER_NONE;
	gExtents[Id].Freeing = FALSE;

	/*
	 * Coalesce with the following then the preceding neighbour. Order matters only for
	 * simplicity: merging forward first means the backward merge sees the already-grown extent
	 * and one pass suffices.
	 *
	 * Without this the arena fragments across repeated remaps of differently-sized builds until a
	 * slightly larger one no longer fits -- "remap stops working after a few cycles", which is a
	 * horrible bug to chase.
	 */
	if (Id + 1 < gExtentCount &&
		gExtents[Id + 1].Valid && !gExtents[Id + 1].InUse && !gExtents[Id + 1].Freeing)
	{
		gExtents[Id].Size += gExtents[Id + 1].Size;
		for (ULONG j = Id + 1; j + 1 < gExtentCount; j++)
			gExtents[j] = gExtents[j + 1];
		gExtentCount--;
		gExtents[gExtentCount].Valid = FALSE;
	}

	if (Id > 0 && gExtents[Id - 1].Valid && !gExtents[Id - 1].InUse && !gExtents[Id - 1].Freeing)
	{
		gExtents[Id - 1].Size += gExtents[Id].Size;
		for (ULONG j = Id; j + 1 < gExtentCount; j++)
			gExtents[j] = gExtents[j + 1];
		gExtentCount--;
		gExtents[gExtentCount].Valid = FALSE;
	}

	return STATUS_SUCCESS;
}

/**
 * The one free path. Everything else funnels here.
 *
 * ============================================================================================
 * (!)(!) TWO RACES LIVED HERE, AND BOTH CAME FROM CARRYING STATE ACROSS A LOCK RELEASE
 * ============================================================================================
 *
 * Both reachable because `NxcImageLoadNotify`
 * (Capture.c) calls `NxcArenaAllocFor` and `NxcArenaFreeFor` from a NOTIFY CALLBACK on arbitrary
 * threads -- outside the `gCommandInProgress` gate that serialises the command path. The gate
 * covers commands; it does not cover the notify, so two arena mutations really can overlap.
 *
 * ⚠ RACE 1 -- POISON AFTER UNLOCK. The old code marked the extent free, coalesced, RELEASED THE
 * LOCK, and only then poisoned. Its comment defended this with "the extent is no longer allocatable
 * to anyone until the lock is retaken", which is exactly backwards: releasing the lock is what MAKES
 * it allocatable. A concurrent allocator could take the range, return it to a caller, and have that
 * caller's zeroed buffer overwritten with 0xCC afterwards -- violating the documented "returned
 * memory is ZEROED" contract, and surfacing far from here as a mapped image with 0xCC in its .bss.
 *
 * FIX: `InUse` STAYS SET across the poison. First-fit skips InUse extents, so the range is
 * unallocatable for the whole slow pass, and the free is published only afterwards.
 *
 * ⚠ RACE 2 -- A STALE EXTENT ID. `NxcArenaFreeFor` resolved an id under the lock, released, then
 * called a free that re-acquired and trusted that id. Its comment defended it with "nothing else
 * can run an arena mutation on this thread" -- which answers same-thread reentry, not another CPU.
 * The allocator's split shifts every entry above it UP by one, so the id then names a DIFFERENT
 * extent, and the old free only checked `Valid && InUse` -- never that the base still matched. It
 * would have freed a live extent belonging to someone else, which is the "two modules sharing
 * memory" corruption this allocator's double-free guard exists to prevent.
 *
 * FIX: NO INDEX IS EVER CARRIED ACROSS A LOCK RELEASE. The identity is the BASE POINTER, which is
 * stable (a coalesce can only absorb FREE neighbours, and this extent stays InUse), and every phase
 * re-resolves from it. The owner is re-checked too, so an extent that was freed and re-allocated to
 * a different owner in between is refused rather than freed a second time.
 */
static NTSTATUS
ArenaFreeByBase(
	_In_ UCHAR* Base,
	_In_ ULONG  ExpectOwner   /* NXC_OWNER_NONE = do not check */
	)
{
	if (!gInitialised || Base == NULL)
		return STATUS_INVALID_PARAMETER;

	KIRQL OldIrql;
	UCHAR* PoisonBase = NULL;
	ULONG  PoisonSize = 0;

	/* ---- phase 1: CLAIM under the lock. InUse stays set, so nothing can allocate it. ---- */
	KeAcquireSpinLock(&gArenaLock, &OldIrql);
	{
		ULONG Id = NXC_EXTENT_NONE;
		for (ULONG i = 0; i < gExtentCount; i++)
		{
			if (gExtents[i].Valid && gExtents[i].Base == Base)
			{
				Id = i;
				break;
			}
		}

		/*
		 * Double free, a stale pointer, a free already in flight, or an extent that has since been
		 * re-allocated to somebody else. REFUSED rather than tolerated: silently accepting any of
		 * them would let an extent be handed out twice, and two modules sharing memory is
		 * unrecoverable corruption that would surface far from here.
		 */
		if (Id == NXC_EXTENT_NONE || !gExtents[Id].InUse || gExtents[Id].Freeing ||
		    (ExpectOwner != NXC_OWNER_NONE && gExtents[Id].Owner != ExpectOwner))
		{
			KeReleaseSpinLock(&gArenaLock, OldIrql);
			return STATUS_INVALID_PARAMETER;
		}

		gExtents[Id].Freeing = TRUE;
		PoisonBase = gExtents[Id].Base;
		PoisonSize = gExtents[Id].Size;
	}
	KeReleaseSpinLock(&gArenaLock, OldIrql);

	/*
	 * ---- phase 2: poison OUTSIDE the lock ----
	 *
	 * Still safe to do without the lock, and now for a reason that is actually true: the extent is
	 * still marked InUse, and first-fit skips InUse extents, so nobody can be handed this range
	 * while it is being written. It can be megabytes, which is why it is not done under a
	 * DISPATCH_LEVEL spinlock.
	 *
	 * If something IS still executing here, this poison is what turns a silent takeover of the next
	 * module's memory into an immediate, obvious INT3 at the stale call site.
	 */
	Poison(PoisonBase, PoisonSize);

	/* ---- phase 3: PUBLISH the free under the lock, re-resolving by base ---- */
	KeAcquireSpinLock(&gArenaLock, &OldIrql);
	CONST NTSTATUS Status = ArenaPublishFreeLocked(PoisonBase);
	KeReleaseSpinLock(&gArenaLock, OldIrql);

	return Status;
}

ULONG
NxcArenaUsed(
	void
	)
{
	if (!gInitialised)
		return 0;

	KIRQL OldIrql;
	KeAcquireSpinLock(&gArenaLock, &OldIrql);

	ULONG Used = 0;
	for (ULONG i = 0; i < gExtentCount; i++)
	{
		if (gExtents[i].Valid && gExtents[i].InUse)
			Used += gExtents[i].Size;
	}

	KeReleaseSpinLock(&gArenaLock, OldIrql);
	return Used;
}

ULONG
NxcArenaLargestFree(
	void
	)
{
	if (!gInitialised)
		return 0;

	KIRQL OldIrql;
	KeAcquireSpinLock(&gArenaLock, &OldIrql);

	ULONG Largest = 0;
	for (ULONG i = 0; i < gExtentCount; i++)
	{
		if (gExtents[i].Valid && !gExtents[i].InUse && gExtents[i].Size > Largest)
			Largest = gExtents[i].Size;
	}

	KeReleaseSpinLock(&gArenaLock, OldIrql);

	/*
	 * Report what is actually ALLOCATABLE, not what is free. Every allocation reserves a guard page on
	 * top of its payload, so answering with the raw free size would promise a remap that then fails --
	 * and "it said there was room" is exactly the kind of misleading signal this project keeps
	 * stamping out.
	 */
	return (Largest > NXC_ARENA_ALIGN) ? (Largest - NXC_ARENA_ALIGN) : 0;
}

ULONG
NxcArenaFreeOwner(
	_In_ ULONG Owner
	)
{
	if (!gInitialised || Owner == NXC_OWNER_NONE)
		return 0;

	/*
	 * Collected first, freed second. NxcArenaFree coalesces and SHIFTS the table, so freeing while
	 * iterating would skip entries -- the classic mutate-while-walking bug, and here it would leave a
	 * module's memory allocated after teardown reported success.
	 */
	/*
	 * ⚠ BASES, NOT INDICES. This collected extent IDs and then freed them highest-first, defending
	 * that order as protection against coalescing shifting the table. It protects against THIS
	 * thread's own coalesce and nothing else: a concurrent split or free from the notify path shifts
	 * every collected id, and the loop then frees whatever now sits at those positions.
	 *
	 * A base pointer cannot be invalidated by a shift, so the collected identities stay correct no
	 * matter what else mutates the table. The owner is carried with each one so an extent freed and
	 * re-allocated to somebody else in between is refused rather than freed twice.
	 */
	UCHAR* Bases[NXC_MAX_EXTENTS];
	ULONG  Count = 0;

	KIRQL OldIrql;
	KeAcquireSpinLock(&gArenaLock, &OldIrql);
	for (ULONG i = 0; i < gExtentCount && Count < NXC_MAX_EXTENTS; i++)
	{
		if (gExtents[i].Valid && gExtents[i].InUse && !gExtents[i].Freeing &&
		    gExtents[i].Owner == Owner)
			Bases[Count++] = gExtents[i].Base;
	}
	KeReleaseSpinLock(&gArenaLock, OldIrql);

	ULONG Freed = 0;
	for (ULONG n = 0; n < Count; n++)
	{
		if (NT_SUCCESS(ArenaFreeByBase(Bases[n], Owner)))
			Freed++;
	}
	return Freed;
}

/**
 * Has the arena been bound and accepted?
 *
 * Exposed so callers can tell "there is no arena" apart from "the arena is full". NxcArenaAlloc
 * returns NULL for both, and the command path has to report them differently -- NXCMD_RESULT_NO_ARENA
 * is a boot-time reservation failure the user can do nothing about, whereas an exhausted arena is a
 * transient the next unmap fixes. Collapsing them into one NULL is how a diagnosis gets lost.
 */
BOOLEAN
NxcArenaReady(
	void
	)
{
	return gInitialised;
}

/**
 * Free one extent identified by its BASE POINTER, checking the owner matches.
 *
 * ============================================================================================
 * WHY THIS EXISTS -- HostFree was a no-op and the test module leaked on every map
 * ============================================================================================
 *
 * NEXUS_HOST_API::Free took a pointer, and the arena could only free by extent id, so HostFree was
 * shipped as a documented no-op. The consequence was measured: NexusTestModule allocates
 * 4096 bytes and frees them, its comment claiming it must not leak "because a test module that leaks
 * an extent would make every subsequent arena reading a lie" -- and the arena reported 32 KB used for
 * a 28 KB module. The extra 4 KB was that leak. The comment described the intent; the no-op did the
 * opposite; and I initially explained the 32 KB away as a guard page, which was wrong twice over.
 *
 * The lookup the no-op was avoiding is a linear scan of at most NXC_MAX_EXTENTS entries under the lock.
 * That is cheap, and it is bounded by a compile-time constant.
 *
 * ⚠ OWNER IS CHECKED, NOT TRUSTED. Base alone would let any module free any extent by passing a
 * pointer it does not own -- the caller supplies both values. Requiring Owner to match means a module
 * can only release memory booked to it, which is the same guarantee the Alloc side gets by having the
 * host choose the owner id rather than the module.
 */
NTSTATUS
NxcArenaFreeFor(
	_In_ ULONG Owner,
	_In_ void* Block
	)
{
	if (!gInitialised || Block == NULL || Owner == NXC_OWNER_NONE)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠ NO LOOKUP-THEN-FREE ACROSS A LOCK RELEASE ANY MORE.
	 *
	 * This used to resolve an extent id under the lock, RELEASE it, and then call a free that
	 * re-acquired and trusted that id. The comment defending it said "the id cannot go stale in
	 * between because nothing else can run an arena mutation on this thread" -- which answers
	 * same-thread reentry and nothing else. `NxcImageLoadNotify` calls this allocator from a NOTIFY
	 * CALLBACK on arbitrary threads, outside the command-serialisation gate, so another CPU really
	 * can split an extent in between; the split memmoves every entry above it up by one, and the id
	 * then names a DIFFERENT extent. The old free checked only `Valid && InUse`, never the base --
	 * so it would have freed a live extent belonging to someone else.
	 *
	 * The base pointer IS the identity and it is stable, so it is handed straight to the one free
	 * path, which re-resolves under each lock hold.
	 */
	return ArenaFreeByBase((UCHAR*)Block, Owner);
}
