/**
 * @file Alias.h
 * @brief A WRITABLE second mapping of pages that are mapped read-only-executable.
 *
 * ============================================================================================
 * WHY THIS EXISTS -- CET IS ACTIVE AND CR0.WP IS BANNED
 * ============================================================================================
 *
 * An inline hook has to write to a page mapped R-X. The classic move is to clear `CR0.WP` for a few
 * instructions. That is FORBIDDEN in this codebase: the window is preemptible, and it already caused
 * a `0xEF` bugcheck on this machine. CET shadow stacks are also active (CR4 bit 23), which makes
 * every trick in that family worse rather than better.
 *
 * So the write goes somewhere else entirely: a SECOND virtual address mapping the SAME physical
 * frames, created writable. The executable mapping is never modified, `CR0.WP` is never touched, and
 * CET never enters the picture -- there is no window to be preempted in, because nothing about the
 * original mapping changes.
 *
 * ============================================================================================
 * ⚠ WHY NOT THE TEXTBOOK MDL PATH -- IT RAISES, AND WE HAVE NO SEH
 * ============================================================================================
 *
 * Every hooking reference does `IoAllocateMdl` -> `MmProbeAndLockPages` ->
 * `MmMapLockedPagesSpecifyCache`, wrapped in `__try`. That wrapper is not optional and it is not
 * available to us:
 *
 *   MmProbeAndLockPages          RAISES on failure. It does not return an error, so there is no
 *                                return value to check. Without SEH that is a bugcheck.
 *   MmMapLockedPagesSpecifyCache can also raise when it cannot allocate system PTEs.
 *
 * A guard cannot fix an API that never returns on the failing path. So the design REMOVES both calls
 * rather than defending against them (decision D11):
 *
 *   1. `MmAllocateMappingAddress` reserves the VA range up front and returns NULL on failure.
 *   2. The MDL is BUILT BY HAND. Its PFN array is filled from `MmGetPhysicalAddress` on pages we
 *      already know are resident, so there is nothing to probe and nothing to lock.
 *   3. `MmMapLockedPagesWithReservedMapping` maps into the ALREADY RESERVED range, so it cannot fail
 *      for want of PTEs -- and returns NULL rather than raising if it fails at all.
 *
 * Every export used here was verified present in the real ntoskrnl before the design was settled: an
 * unresolvable name fails DriverEntry, so "probably exported" is not good enough.
 *
 * ============================================================================================
 * ⚠ WHAT THIS DELIBERATELY DOES *NOT* DO
 * ============================================================================================
 *
 * It does not install a hook, and it does not know what a hook is. It maps and unmaps. The hook is a
 * separate stage built on top once this one is proven on hardware, for the same reason Intel PT's
 * allocation was split from its arming: the mapping is verifiable in isolation (write through the
 * alias, read back through the original, do they agree) while a hook is not.
 *
 * ⚠ PAGE-GRANULAR AND CALLER-BOUNDED. The alias covers whole pages spanning the requested range. A
 * caller asking for 4 bytes gets a mapping of the page they live in, which is correct but means the
 * alias is a writable window onto MORE than was asked for. Callers must write only what they intend.
 */

#pragma once

#include <ntddk.h>

/** One live alias. Opaque to callers except that they must hand the same one back to unmap. */
typedef struct _NXC_ALIAS
{
	void*  Mdl;          /* hand-built, ours to free                      */
	void*  Reserved;     /* from MmAllocateMappingAddress                 */
	void*  WritableVa;   /* the alias -- write HERE, never to the target  */
	UINT64 TargetVa;     /* what was aliased, for the log                 */
	UINT32 Bytes;
	UINT32 Pages;
} NXC_ALIAS;

/**
 * Create a writable alias of [TargetVa, TargetVa+Bytes).
 *
 * ⚠ THE TARGET PAGES MUST ALREADY BE RESIDENT AND NON-PAGED. Nothing here locks them, because the
 * call that would lock them is the one that raises. Kernel image sections and non-paged pool qualify;
 * pageable memory does NOT, and passing it produces a PFN that may be stale by the time it is used.
 *
 * @retval STATUS_SUCCESS            Out->WritableVa is a writable mapping of the same frames
 * @retval STATUS_INVALID_PARAMETER  zero length, or a range spanning more pages than allowed
 * @retval STATUS_INSUFFICIENT_RESOURCES  reservation or mapping failed -- NOTHING was left mapped
 */
NTSTATUS NxcAliasCreate(_In_ UINT64 TargetVa, _In_ UINT32 Bytes, _Out_ NXC_ALIAS* Out);

/** Tear down an alias. Safe on a zeroed struct, so a failed create can be unwound unconditionally. */
void NxcAliasDestroy(_Inout_ NXC_ALIAS* Alias);

/**
 * PROVE the primitive against a page we own, end to end, touching nothing else.
 *
 * Writes a pattern through the ORIGINAL mapping, a different pattern through the ALIAS, then reads
 * back through the ORIGINAL. Agreement proves the two VAs really do share physical frames -- which is
 * the entire premise, and the one thing that cannot be assumed from the calls succeeding.
 *
 * @param OutDetail  0 on success, else the step that failed (1..5) so a failure names itself
 */
NTSTATUS NxcAliasSelfTest(_Out_ UINT32* OutDetail);
