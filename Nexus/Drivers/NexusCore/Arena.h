/**
 * @file Arena.h
 * @brief Sub-allocator for the boot-reserved runtime map arena.
 *
 * The DXE reserves ONE contiguous 16 MB EfiRuntimeServicesCode region at boot (ArenaBase/ArenaSize in
 * the boot block) because NexusCore cannot allocate that kind of memory itself: gBS is long gone by
 * runtime, and ExAllocatePool2 is exactly what we criticised nullmap for -- pool-tagged, enumerable,
 * "can be dumped so easily" by its own README.
 *
 * ============================================================================================
 * WHY THIS IS WHAT MAKES UNMAP/REMAP SAFE
 * ============================================================================================
 *
 * The arena never leaves our control. So:
 *   - freeing is "mark the extent free", NOT "return pages to the kernel";
 *   - a stale pointer therefore lands in OUR arena rather than in an allocation the kernel has since
 *     handed to an unrelated component -- the difference between reading wrong data and corrupting
 *     something else;
 *   - remapping a new build reuses the same memory with no allocator churn and nothing new appearing
 *     in any kernel structure.
 *
 * That last point is the actual use case: repeatedly mapping, unmapping and remapping NEW BUILDS of
 * the hypervisor without rebooting. v1 could do the mechanics and the system destabilised, because
 * it freed images with no teardown contract (see NexusModule.h). The arena removes one failure class;
 * the contract removes the bigger one. BOTH are required.
 *
 * ============================================================================================
 * DESIGN NOTES -- the deliberate choices
 * ============================================================================================
 *
 * NO POOL ANYWHERE, INCLUDING THE BOOKKEEPING. The extent table is a fixed array in NexusCore's own
 * .data. Allocating the tracking structure from pool would reintroduce precisely the artifact the
 * arena exists to avoid, which would be an easy thing to do by accident.
 *
 * COALESCING ON FREE is not optional here. The workload is map/unmap/remap of successive hypervisor
 * builds whose sizes differ, and without coalescing the arena fragments until a slightly larger build
 * no longer fits -- presenting as "remap randomly stops working after a few cycles", which is
 * miserable to diagnose.
 *
 * GUARD GAP between extents: one page, left poisoned and never allocated. An image overrunning its
 * extent hits poison instead of the neighbouring module's headers. 16 pages of waste across the whole
 * arena buys deterministic detection of a class of bug that is otherwise silent corruption.
 *
 * PROPER SPINLOCK, not a clever intrinsic one. An interlocked spin at PASSIVE_LEVEL is subtly wrong:
 * the holder can be preempted while a waiter burns a core. KeAcquireSpinLock costs two imports, and
 * since the mapper now scrubs import NAMES from the mapped image anyway, that cost is close to zero.
 * Correctness over import count.
 */

#pragma once

#include <ntddk.h>

/*
 * Extent capacity. 16 concurrent mapped modules is far beyond the real workload (the hypervisor plus
 * a handful), and the table is statically sized so it cannot itself need an allocation. Splitting a
 * free extent consumes a slot, so this is also the fragmentation ceiling.
 */
#define NXC_MAX_EXTENTS   32u

/* Page granularity: mapped PE images need section alignment, and it keeps the guard gap meaningful. */
#define NXC_ARENA_ALIGN   0x1000u

#define NXC_EXTENT_NONE   0xFFFFFFFFu

/*
 * Owner of an extent. Extents carry an owner so unmap can reclaim EVERYTHING a module took, not just
 * its image -- a module that allocates working memory and is then torn down would otherwise leak
 * those extents forever, and the arena is finite.
 *
 * NXC_OWNER_HOST is NexusCore's own bookkeeping; NXC_OWNER_NONE marks a free extent.
 */
#define NXC_OWNER_NONE    0xFFFFFFFFu
#define NXC_OWNER_HOST    0xFFFFFFFEu

/**
 * Bind the allocator to the boot-reserved region. Call once, from DriverEntry, with the values the
 * DXE published in the boot block.
 *
 * @retval STATUS_SUCCESS            ready
 * @retval STATUS_INVALID_PARAMETER  base/size unusable (e.g. the DXE reservation failed -> base 0)
 */
NTSTATUS
NxcArenaInit(
	_In_ void* Base,
	_In_ ULONG Size
	);

/**
 * Carve out a page-aligned extent.
 *
 * @param Bytes       requested size; rounded up to a page
 * @param OutExtentId ⚠ NOT A DURABLE HANDLE. See the warning below before storing this anywhere.
 *
 * ============================================================================================
 * ⚠ EXTENT IDS ARE ARRAY INDICES AND THEY MOVE.
 * ============================================================================================
 *
 * An extent id is a slot index in gExtents[], and BOTH mutating paths shift that array:
 *   - allocation SPLITS an extent and shifts every entry above it UP by one;
 *   - free COALESCES with neighbours and shifts every entry above the merge DOWN by one.
 *
 * So an id is valid only until the NEXT arena operation, from any caller. It was previously
 * documented as "the handle used to free it later", which is precisely the wrong mental model and is
 * how this became a hazard: the value looks durable, stores cleanly, and goes stale silently.
 *
 * Concretely, holding one across another map and then freeing it either hits a now-free slot (refused,
 * and the real extent leaks forever) or hits a DIFFERENT MODULE'S in-use extent and poisons a live
 * image -- the "two modules sharing memory is unrecoverable" case this allocator warns about,
 * delivered by its own id scheme.
 *
 * ⚠ TEARDOWN MUST USE NxcArenaFreeOwner, and not only for that reason. A module gets FURTHER extents
 * through NEXUS_HOST_API::Alloc, all tagged with its owner id and their extent ids discarded at the
 * call site -- so even a perfectly valid image-extent id would reclaim the image and leak every
 * allocation the module made. Owner is the only complete teardown key.
 *
 * ⚠ SO THERE IS NO ID-BASED FREE. "Free the id immediately, with no intervening arena call" is
 * not a workable rule: the mapper's failure path alone runs after header, section, relocation and
 * import work, any of which can overlap an allocation made from a notify callback on another
 * thread. A rule that holds only in one shape is a footgun with a comment on it.
 *
 * `OutExtentId` below is now DIAGNOSTIC ONLY -- it identifies an extent in a log line and must never
 * be stored to free with. Free by base and owner: NxcArenaFreeFor, or NxcArenaFreeOwner at teardown.
 * @return base address, or NULL if no free extent is large enough
 *
 * The returned memory is ZEROED, because a mapped image relies on its .bss being zero and the
 * previous tenant left poison behind.
 */
void*
NxcArenaAlloc(
	_In_ ULONG Bytes,
	_Out_ ULONG* OutExtentId
	);

/**
 * Allocate on behalf of a specific module, so teardown can reclaim it.
 *
 * WHY MODULES ALLOCATE HERE AND NOT FROM POOL: the whole reason the arena exists. A hypervisor's EPT
 * paging structures and VMCS regions in NonPaged pool are a MORE interesting find than the driver
 * image we went to such lengths to hide -- pool-tagged, enumerable, and exactly what nullmap's own
 * README calls "dumped so easily". Every reference allocates from pool (v1: ExAllocatePool2 x62;
 * BlackAlien: ExAllocatePool2 for the image itself), so this is ours to get right.
 *
 * @param Owner  module id from NxcMapModule; the extent is released by NxcArenaFreeOwner at teardown
 */
void*
NxcArenaAllocFor(
	_In_ ULONG Owner,
	_In_ ULONG Bytes,
	_Out_ ULONG* OutExtentId
	);

/**
 * Release EVERY extent belonging to one module. Called during COMMIT, after the module has quiesced.
 *
 * Returns the number of extents reclaimed -- non-zero after a module claimed it had released
 * everything is a CONTRACT VIOLATION worth logging, not a silent cleanup.
 */
ULONG
NxcArenaFreeOwner(
	_In_ ULONG Owner
	);

/**
 * Poison and release ONE extent, identified by its BASE ADDRESS and owner.
 *
 * ⚠⚠ FREE BY BASE AND OWNER. THERE IS DELIBERATELY NO `NxcArenaFree(ULONG ExtentId)`.
 *
 * An extent id is a POSITION IN AN ARRAY THAT SHIFTS -- the allocator's split memmoves entries up, the free path's
 * coalesce memmoves them down -- so an id is only meaningful while the lock that produced it is
 * still held. Every caller held one for longer: the hook stored it from install to remove, the LBR
 * ring from init to free, the mapper across the whole of image loading. Freeing a stale id either
 * hits a now-free slot (refused, real extent leaks forever) or a DIFFERENT owner's live extent,
 * which is the "two modules sharing memory is unrecoverable" case this allocator exists to prevent.
 *
 * A base address cannot go stale: a coalesce can only absorb FREE neighbours, and an in-use extent
 * is never merged away. The owner is checked too, so an extent freed and re-allocated to somebody
 * else in between is REFUSED rather than freed twice.
 *
 * ⚠ DOES NOT AND CANNOT VERIFY THAT THE MODULE IS QUIESCED. That is the teardown contract's job
 * (NexusModule.h: PREPARE, COMMIT, DRAIN, BARRIER) and the caller MUST have completed it first.
 * Calling this on a live module is the v1 bug reintroduced.
 */

/** Bytes currently allocated, for the boot block's ArenaUsed and PlatformCtl's status line. */
ULONG
NxcArenaUsed(
	void
	);

/**
 * Free one extent by its BASE POINTER, with the owner checked.
 *
 * Exists so NEXUS_HOST_API::Free can actually free. It previously could not -- the arena only freed by
 * id, a module only holds a pointer, and HostFree therefore shipped as a documented no-op. MEASURED
 * that leaked 4 KB on every map of NexusTestModule, and made the arena report 32 KB used
 * for a 28 KB module.
 *
 * ⚠ Owner is CHECKED, not trusted. The caller supplies both the pointer and the owner, so matching on
 * Base alone would let any module free any extent. Requiring the owner to match means a module can only
 * release memory booked to it -- the same guarantee the Alloc side gets from the host choosing the id.
 *
 * Returns STATUS_NOT_FOUND for a pointer that is not the base of a live extent owned by @p Owner. That
 * includes a double free, which is refused rather than tolerated for the reason NxcArenaFree gives.
 */
NTSTATUS
NxcArenaFreeFor(
	_In_ ULONG Owner,
	_In_ void* Block
	);

/** Largest single allocation still possible -- the honest answer to "will a remap fit". */
ULONG
NxcArenaLargestFree(
	void
	);

/**
 * Has the arena been bound and accepted?
 *
 * Separate from "an allocation would succeed" on purpose: NxcArenaAlloc returns NULL both when there
 * is NO arena and when the arena is merely full, and those need different answers. A failed boot-time
 * reservation is permanent for this boot; an exhausted arena is a transient the next unmap fixes.
 */
BOOLEAN
NxcArenaReady(
	void
	);
