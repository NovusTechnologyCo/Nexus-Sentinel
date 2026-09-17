/**
 * @file Pool.h
 * @brief Kernel pool enumeration -- a target's RUNTIME allocations, not its image.
 *
 * ============================================================================================
 * THE PROBLEM IT SOLVES
 * ============================================================================================
 *
 * Everything the read path reaches so far is an IMAGE: a module on disk, a module in memory, a
 * region of a process. But a driver's interesting state -- decrypted tables, resolved pointers,
 * scan results -- lives in memory it allocated at runtime, which belongs to no image and appears in
 * no module list. v1 built this to crack 64 IAT-resolver holdouts whose encrypted pointers lived in
 * pool rather than in the binary.
 *
 * ============================================================================================
 * ⚠⚠ IT ONLY SEES *BIG* POOL. THIS IS THE MOST IMPORTANT LINE IN THIS FILE.
 * ============================================================================================
 *
 * `SystemBigPoolInformation` enumerates allocations that got their own page(s) -- roughly
 * >= PAGE_SIZE. Allocations smaller than that are served from pool pages subdivided by the
 * allocator, and they DO NOT APPEAR HERE AT ALL.
 *
 * So an empty result for a tag means "no BIG allocation carries that tag". It does NOT mean the tag
 * is unused, and it does NOT mean the driver allocated nothing. Treating absence here as evidence of
 * absence is exactly the trap this project has a standing rule about, and it is easy to fall into
 * because the enumeration otherwise looks exhaustive.
 *
 * The reporting side states this on EVERY empty result rather than only in documentation, because
 * the reader who most needs it is the one who did not open this file.
 *
 * ============================================================================================
 * TIER 3 (v1) -- two hard-won details inherited, one comment NOT inherited
 * ============================================================================================
 *
 * INHERITED: the probe-with-NULL pattern is UNRELIABLE here. The usual "call with a null buffer to
 *   learn the required length" idiom does not work for this class on every Windows version -- it
 *   returns STATUS_INFO_LENGTH_MISMATCH without writing back a length. v1 hit this and worked around
 *   it by starting from a generous buffer and growing. We keep the grow loop and also USE the
 *   returned length when it is present, falling back to doubling when it is not.
 *
 * INHERITED: bit 0 of `VirtualAddress` is a NonPaged FLAG, not part of the address. It must be
 *   masked off or every reported pointer is off by one.
 *
 * ⚠ NOT INHERITED: v1's comment says "top bit indicates non-paged" while v1's CODE tests `& 1`.
 *   The code is right -- the field is a `ULONG_PTR NonPaged : 1` bitfield, which is the LOW bit --
 *   and the comment is wrong. Recorded because a reader trusting that comment would mask the wrong
 *   end of the pointer and corrupt every address on a 64-bit system.
 *
 * TIER 4 (improve): v1 started from a 16 MB NON-PAGED speculative allocation. That is a large ask on
 *   a loaded system and it can fail for reasons that have nothing to do with the query. We start at
 *   1 MB and grow, with more attempts allowed -- same destination, far less pressure, and a failure
 *   that actually means something.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/**
 * Enumerate big-pool allocations, optionally filtered.
 *
 * @param TagFilter  0 = every tag; otherwise the four-character tag as a ULONG
 * @param MinSize    0 = no minimum
 * @param Got        entries written
 * @param Total      entries that MATCHED the filter -- separate from Got so truncation cannot read
 *                   as completeness (D3)
 * @param Scanned    entries the kernel reported before filtering, so a filter that matched nothing
 *                   can be told apart from an enumeration that returned nothing
 */
/*
 * ============================================================================================
 * POOL BAIT -- plant recognizable allocations and watch what a scanner does with them
 * ============================================================================================
 *
 * A GENERAL SCANNER-CHARACTERISATION PRIMITIVE. v1's version was written for one target and
 * documented in its terms ("if it flags a tag, its violation queue fires code 50/54"). The
 * technique is not target-specific at all: plant allocations a pool scanner can see, then observe
 * whether and how it reacts. That works against any scanner, including ones nobody has looked at.
 *
 * ⚠ THE REACTION IS READ IN USERMODE, NOT HERE. Without a hypervisor there is no way to trap the
 * READ of a bait block, so the kernel cannot observe the scan itself. What it can do is plant the
 * bait and report exactly where it went; the operator correlates that against the target's
 * behaviour. Claiming to detect the scan from here would be inventing a signal we do not have.
 *
 * ============================================================================================
 * ⚠ THIS IS A DELIBERATE EXCEPTION TO CROSS-SURFACE DECISION D4
 * ============================================================================================
 *
 * D4 says capture storage comes from the ARENA and never from pool, because pool allocations are
 * tagged, enumerable, and exactly what a scanner looks for.
 *
 * Bait inverts that on purpose: BEING ENUMERABLE IS THE ENTIRE POINT. An arena allocation would not
 * appear in SystemBigPoolInformation and no scanner would ever see it, which would make the bait
 * invisible to the thing it exists to provoke. Recorded here so the exception reads as a decision
 * rather than as someone forgetting D4.
 *
 * ⚠ MINIMUM SIZE IS A HARD FLOOR, NOT A DEFAULT. An allocation under PAGE_SIZE is served from a
 * subdivided pool page and never appears in the big-pool enumeration -- so bait smaller than that is
 * invisible to precisely the scanners it is meant to attract, while still consuming memory. Requests
 * below the floor are raised to it rather than honoured.
 *
 * ⚠ BAIT OUTLIVES THE COMMAND AND THIS DRIVER NEVER UNLOADS. Every block stays allocated until
 * something frees it, so the planted set is tracked and `NxcPoolBaitFree` releases all of it. A bait
 * run with no matching free is a permanent non-paged leak.
 */

/** Simultaneously planted bait blocks. Small: bait is a probe, not a memory-pressure test. */
#define NXC_MAX_BAIT   16u

/**
 * Plant @p Count allocations of @p SizeBytes carrying @p Tag.
 *
 * @param Out      receives the planted addresses
 * @param Planted  how many were actually created -- partial success is normal under memory pressure
 *                 and is reported rather than rolled back
 */
NTSTATUS NxcPoolBait(
	_In_ UINT32 Tag,
	_In_ UINT32 Count,
	_In_ UINT32 SizeBytes,
	_Out_writes_(Cap) NXCMD_POOL_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Planted
	);

/** Release every planted bait block. Safe when nothing is planted. */
NTSTATUS NxcPoolBaitFree(_Out_ UINT32* OutFreed);

/** How many bait blocks are currently planted -- so an outstanding leak is visible. */
UINT32 NxcPoolBaitCount(void);

NTSTATUS NxcPoolList(
	_Out_writes_(Cap) NXCMD_POOL_ENTRY* Out,
	_In_ UINT32 Cap,
	_In_ UINT32 TagFilter,
	_In_ UINT64 MinSize,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* Scanned
	);
