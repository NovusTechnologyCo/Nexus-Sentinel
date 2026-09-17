/**
 * @file Pte.h
 * @brief Read (and eventually write) the page-table entries backing our own memory.
 *
 * ============================================================================================
 * WHY THIS EXISTS -- the four tiers,
 * ============================================================================================
 *
 * The open problem is task 7: a manually mapped image gets ONE protection for its whole extent,
 * so .text, .rdata and .data all end up with identical page permissions. A real loaded driver has
 * RX code and NX data. Ours does not, and "large executable region that belongs to no module" is a
 * documented scan target, so the mismatch is both a correctness gap and a signature.
 *
 * TIER 1 -- reference material/. ONE project has a page-protection routine:
 *   GhostMapperUM intel_driver.cpp:453 MmSetPageProtection() -- pattern-scan "PAGE" section,
 *   +12, resolve a rel32, then call it through the vulnerable driver.
 *   ⚠ IT IS NEVER CALLED. grep across the whole project finds the definition, the header
 *   declaration, and NO call sites. The one reference implementation that HAS this does not use it.
 *   Nothing else in reference material/ (nullmap, shadow, redlotus, trident, Xenos, topg, KDU)
 *   applies per-section protections to a mapped image at all.
 *
 * TIER 2 -- the web. Two independent findings, both pointing away from the API route:
 *   - M-r-J-o-h-n/Driver-Manual-Mapper states it plainly: "kernel doesn't provide any function to
 *     change page protection of kernel space memory", and solves it by mapping physical memory and
 *     "manually changing its pte write flag". Also notes RWX sections take priority over RX.
 *   - charliewolfe/Stealthy-Kernelmode-Injector does the same class of thing deliberately -- PTE
 *     manipulation and NX-bit swapping -- specifically to defeat "heuristics to detect unwanted
 *     executable pages outside signed modules".
 *   Confirmed there too: MmSetPageProtection / MmAllocateIndependentPagesEx are unexported, and
 *   their RVAs move every compile, so any use of them is a byte pattern against an internal ABI.
 *
 * TIER 3 -- v1. v1 ALREADY SOLVED THE HARD HALF and we never used it: FindPteBase()
 *   (v1's `hwid_spoof_tpm.c:3369`) derives the self-map base by probing PML4
 *   indices 256..511 and confirming the candidate PTE for ntoskrnl's base holds ntoskrnl's real
 *   PFN. No pattern, no pinned offset, self-validating. Its consumer, ScanAndSwapTpmPtes, was left
 *   a stub -- so the derivation is proven, the application never happened.
 *
 * TIER 4 -- what we do, and why it is not either of the first two.
 *
 *   REJECTED: MmSetPageProtection by signature. It is a byte pattern plus a `+12` plus a rel32
 *   resolve -- three assumptions, none of which can be VERIFIED at runtime. A pattern that matches
 *   the wrong function calls an unknown internal routine with our arguments. And the one project
 *   that ships it does not call it, which is the loudest possible review comment.
 *
 *   REJECTED: having the DXE reserve SEPARATE CODE AND DATA ARENAS so no protection change is ever
 *   needed. This was on the table and it CANNOT WORK -- not a preference, a hard technical block. A
 *   PE's sections are addressed relative to ONE image base: x64 code reaches its own .rdata/.data
 *   through RIP-relative displacements fixed at compile time. Splitting sections into two arenas
 *   changes the distance between them, and every cross-section reference in the image breaks. Base
 *   relocations cannot repair it, because a relocation applies one delta to the whole image. Keeping
 *   the distance intact means the two "arenas" are one contiguous region again -- which is where we
 *   started. Recorded so nobody re-proposes it.
 *
 *   CHOSEN: derive the self-map base, walk to the entry backing a VA, edit the entry. Reasons:
 *     - it is what the field actually does when the kernel exposes no API (tier 2, twice);
 *     - the derivation is SELF-VALIDATING. Unlike a byte pattern, a candidate base can be PROVEN
 *       correct before use, so it fails closed and loudly instead of silently addressing garbage;
 *     - it needs no unexported symbol and pins no offset;
 *     - we only ever touch entries for OUR OWN pages. PatchGuard protects specific kernel
 *       structures and kernel image sections; the PTEs backing a private allocation are not among
 *       them. Editing ntoskrnl's PTEs would be a different question and we do not.
 *
 * ============================================================================================
 * MEASURE BEFORE CHANGING -- why the first cut is READ-ONLY
 * ============================================================================================
 *
 * We do not yet know what protections our memory HAS. The arena is gBS->AllocatePages(
 * EfiRuntimeServicesCode), and Windows decides how to map EFI runtime regions from the firmware's
 * EFI_MEMORY_ATTRIBUTES_TABLE. If that table marks non-image runtime CODE as read-only-executable,
 * then our arena is not writable at runtime and the arena allocator has a latent fault that has not
 * fired yet only because nothing has allocated from it on hardware.
 *
 * That would be a bigger problem than task 7, and it is invisible to every check we currently run.
 * So this first step reads and reports the real bits; the write path is built once the data says
 * what needs changing. Guessing which direction to push the bits, on a boot path where a wrong
 * answer costs a reboot cycle to diagnose, is exactly the v1 habit v2 exists to stop.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCoreBoot.h"
/* NXCMD_KEXEC, used by NxcPteScanUnlistedExec's declaration below. The scan produces records that
 * cross the kernel/usermode wire, so the record type is the shared one rather than a private
 * duplicate that would have to be kept in step with it. */
#include "../../Include/NexusCommand.h"

/**
 * One decoded page-table entry, plus the level it was found at.
 *
 * LEVEL MATTERS MORE THAN IT LOOKS. If our image or arena is backed by a 2 MB or 1 GB large page,
 * then per-section 4 KB protection is IMPOSSIBLE without splitting that page -- the granularity of
 * protection is the granularity of the mapping. Reporting the level is therefore not a detail; it
 * decides whether task 7 is solvable at all on this machine without a page split.
 */
typedef struct _NXC_PTE_INFO
{
	UINT64  EntryVa;     /* VA of the table entry itself, via the self-map           */
	UINT64  Value;       /* raw entry                                                */
	UINT64  Pfn;         /* physical frame it points at                              */
	UINT32  Flags;       /* NXC_PTE_* decode, ready for the boot block               */
	UINT32  Level;       /* 4 = PTE (4 KB), 3 = PDE (2 MB), 2 = PDPTE (1 GB)         */
	/*
	 * ON FAILURE ONLY: which table level was absent -- 1 = PML4E, 2 = PDPTE, 3 = PDE, 4 = PTE.
	 * Zero when the query succeeded.
	 *
	 * ⚠ THIS EXISTS SO A SCAN CAN SKIP, AND WITHOUT IT A SCAN IS IMPOSSIBLE. Kernel VA space is
	 * 128 TB; at 4 KB granularity that is ~34 billion queries. Almost all of it is unmapped, and
	 * an absent entry at a given level means a FIXED span contains nothing:
	 *
	 *     PML4E absent -> skip 512 GB      PDPTE absent -> skip 1 GB
	 *     PDE   absent -> skip 2 MB        PTE   absent -> skip 4 KB
	 *
	 * A bare STATUS_NOT_FOUND cannot distinguish those, so a caller would have to step 4 KB at a
	 * time through empty space. Reporting the level turns an infeasible walk into a fast one
	 * WITHOUT changing what is read -- the descent, its PRESENT checks and its PS checks are all
	 * untouched, and nothing is written.
	 */
	UINT32  MissingLevel;
} NXC_PTE_INFO;

/**
 * Derive the page-table self-map base and prove it is correct.
 *
 * Returns STATUS_SUCCESS only when a candidate was PROVEN, never when one merely looked plausible.
 */
NTSTATUS NxcPteInit(VOID);

/** The proven self-map base, or 0 if NxcPteInit has not succeeded. */
UINT64 NxcPteSelfMapBase(VOID);

/**
 * Why the probe ended as it did: (present << 16) | readable. Meaningful whether it succeeded or
 * failed -- on failure it is the ONLY thing that separates "the address math is wrong" from "the
 * CR3 identity does not hold here", and those need different investigations.
 */
UINT32 NxcPteProbeDiag(VOID);

/**
 * Walk to the entry that actually backs @p Va, stopping at whichever level maps it.
 *
 * Returns STATUS_SUCCESS with @p Info filled, or a failure with Info->Flags = 0 if the walk hit a
 * not-present level.
 */
NTSTATUS NxcPteQuery(_In_ UINT64 Va, _Out_ NXC_PTE_INFO* Info);

/**
 * Scan kernel VA for EXECUTABLE pages belonging to no loaded module -- `modules --hidden`.
 *
 * READ ONLY. Uses NxcPteQuery's descent unchanged, and MissingLevel to skip empty spans (without
 * which 128 TB at 4 KB granularity would be ~34 billion probes).
 *
 * Caller supplies the module ranges to SUBTRACT. NexusCore's own image and arena come from the
 * ranges this module ALREADY recorded via NxcPteSetOwnedRanges -- passing them in again would be a
 * second copy of one fact. They are FLAGGED, never suppressed: a scan that hides its own footprint
 * is lying about what is mapped, and ours is the one region whose presence proves the scan works.
 *
 * Contiguous pages are coalesced into one region. Bounded by a probe ceiling, a region ceiling and
 * the caller's buffer; OutTruncated says which was hit (bit 0 = probes, bit 1 = regions), because a
 * truncated scan that looked complete would be the worst failure for a command whose finding is
 * often "nothing is there".
 *
 * @param OutWritten   regions written -- PRODUCED
 * @param OutTotal     regions found   -- EXISTS
 */
NTSTATUS
NxcPteScanUnlistedExec(
	_In_reads_(RangeCount) CONST UINT64* RangeBase,
	_In_reads_(RangeCount) CONST UINT64* RangeEnd,
	_In_ UINT32 RangeCount,
	_In_ UINT32 FirstIndex,
	_Out_writes_(Capacity) NXCMD_KEXEC* Out,
	_In_ UINT32 Capacity,
	_Out_ UINT32* OutWritten,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutTruncated,
	_Out_ UINT64* OutProbes,
	_Out_ UINT64* OutReachedVa
	);

/**
 * Declare the memory this driver is allowed to reprotect. Call once, before any protect.
 *
 * NxcPteProtectRange refuses any range not lying entirely inside our mapped image or the arena.
 * ⚠ Until this is called, BOTH extents are zero and every protect is refused -- fail-closed, so a
 * forgotten call produces loud refusals rather than an unguarded window.
 *
 *  The large-page refusal already bounded how far a range could REACH;
 * nothing bounded where it could START, and NxcPteProtectImage derives its ranges from image-supplied
 * section RVAs. A wrong base that happened to be 4 KB-mapped would have passed survey, commit and
 * verify, and logged success while rewriting another component's page tables.
 *
 * ⚠ THIS BOUND IS ALSO A POLICY, NOT ONLY A SAFETY NET -- decision D12,.
 * Writing OUR pages' PFNs into a LIVE SIGNED DRIVER'S PTEs, so a mapped module occupies that
 * driver's virtual addresses, is a real and published placement technique and this file already has
 * every primitive it needs. It was CONSIDERED AND REJECTED: it breaks MapModule's gate that a module
 * which cannot be torn down must never become resident (foreign PTEs to restore byte-exactly, a
 * cross-core TLB shootdown, and a victim driver that may execute our bytes while we are resident),
 * and it trades DOWN on protections -- that technique inherits a victim's page permissions precisely
 * because its authors have no NxcPteProtectImage. We do. See the design notes D12 for the full four.
 *
 * So do NOT widen these ranges. A future read-only consumer (`kpages`, build plan item 7.5) walks
 * OTHER modules' entries deliberately -- it uses NxcPteQuery, which does not consult this bound,
 * and that asymmetry is the design: reading a foreign entry is evidence, writing one is vandalism.
 */
void NxcPteSetOwnedRanges(
	_In_ UINT64 ImageBase,
	_In_ UINT32 ImageSize,
	_In_ UINT64 ArenaBase,
	_In_ UINT32 ArenaSize
	);

/**
 * Set W and NX across [Va, Va+Size) to exactly @p Writable / @p Executable.
 *
 * ⚠ REFUSES RATHER THAN APPROXIMATES. Every page in the range must be mapped by a real 4 KB PTE. If
 * any page is backed by a 2 MB or 1 GB entry the whole call fails with STATUS_NOT_SUPPORTED and
 * NOTHING is changed.
 *
 * That refusal is the most important line of code in this file. A large entry covers up to 512 or
 * 262144 pages, and the memory around ours is other EFI runtime allocations -- including firmware
 * runtime code that Windows calls to service GetVariable and SetVariable, which is the transport
 * this entire project reports through. "Protect our image" would silently mean "change protections
 * on two megabytes of firmware", and the failure would land somewhere else entirely, later, with no
 * connection back to here. Partial application is refused for the same reason: a range half in one
 * state is worse than a range left alone, because it is not a state anything was designed for.
 *
 * A two-pass structure enforces both -- survey every page first, and only then write.
 */
NTSTATUS NxcPteProtectRange(
	_In_ UINT64  Va,
	_In_ UINT64  Size,
	_In_ BOOLEAN Writable,
	_In_ BOOLEAN Executable,
	_In_ BOOLEAN BroadcastFlush
	);

/**
 * Apply each PE section's own characteristics to the pages backing a mapped image.
 *
 * This is task 7's actual fix: IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE already say what every
 * section wants, so the correct protections are not a judgement call -- they are data already
 * present in the image, which we had simply never applied.
 *
 * Returns the count of sections successfully protected through @p Applied, and fails only if the
 * image cannot be parsed. An individual section that cannot be protected is reported and skipped,
 * because refusing the whole image over one section would leave the other five RWX.
 *
 * ALSO PROTECTS THE HEADER PAGE (RVA 0 up to the first section) as R--, which no section covers and
 * which therefore stayed RWX in the first hardware run. It is NOT counted in @p Applied / @p Refused
 * -- those stay a section count so they keep matching NumberOfSections. Confirm it instead by
 * re-querying ImageBase after this returns: that VA is the header page.
 *
 * ⚠ @p ImageSize IS A SAFETY BOUND, not bookkeeping. Section sizes come from the IMAGE, and this
 * function is reached by MapModule with arbitrary module images. A section whose VirtualSize runs
 * past the end of the mapped extent would otherwise have its protections applied to whatever lies
 * beyond -- which in the arena is ANOTHER MODULE'S memory. MapModule's own bounds check does not
 * cover this: it validates VirtualAddress + SizeOfRawData, and skips SizeOfRawData == 0 sections
 * entirely, so a .bss-style section declaring a huge VirtualSize passes it untouched. Such a section
 * is counted as REFUSED rather than clamped -- it is malformed by definition (SizeOfImage must cover
 * every section) and this file refuses rather than approximates.
 */
NTSTATUS NxcPteProtectImage(
	_In_  UINT64  ImageBase,
	_In_  UINT32  ImageSize,
	_In_  BOOLEAN BroadcastFlush,
	_Out_ UINT32* Applied,
	_Out_ UINT32* Refused
	);
