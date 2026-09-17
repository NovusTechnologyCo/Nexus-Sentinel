/**
 * @file Translate.h
 * @brief VA -> PA translation for a TARGET process, by walking its page tables directly.
 *
 * ============================================================================================
 * WHY NOT THE THREE EASIER OPTIONS
 * ============================================================================================
 *
 * TIER 3 (v1): v1 attached to the target with KeStackAttachProcess and then called
 *   MmGetPhysicalAddress, which reads whatever CR3 is currently loaded. It works. It is also the
 *   approach cross-surface decision D1 removed from this codebase: attaching changes the calling
 *   thread's address space for the duration, so every pointer in scope silently changes meaning,
 *   and a fault or an early return between attach and detach leaves the thread in the wrong process.
 *   MmCopyVirtualMemory already gave us cross-process reads with no attach; going back to attach for
 *   ONE more capability would reintroduce the hazard the decision was made to remove.
 *
 * TIER 2 (documented API): there is none. MmGetPhysicalAddress is explicitly current-context-only,
 *   and no exported call translates a VA in a foreign process.
 *
 * REJECTED: reusing Pte.c's self-map walk. The self-map resolves the CURRENTLY LOADED CR3's tables.
 *   For a kernel VA that is fine -- the top half is shared. For a USER VA it is not: each process
 *   has its own PML4, so without attaching, the self-map answers about PlatformCtl's address space
 *   while claiming to answer about the target's. It would return a plausible, confidently wrong PA.
 *   That is the worst failure mode available here, so the self-map is not used for target VAs at all.
 *
 * CHOSEN: read the target's CR3 out of its EPROCESS, then walk PML4 -> PDPT -> PD -> PT with
 *   PHYSICAL reads. No attach, no context switch, no shared-state hazard, and it works uniformly for
 *   user and kernel VAs.
 *
 * ============================================================================================
 * ⚠ THE PAGE TABLES BEING WALKED BELONG TO THE TARGET
 * ============================================================================================
 *
 * Every table address after CR3 is read out of the target's own page tables -- memory the target can
 * write. A process that places an MMIO address in a PDPTE hands us a device register to read while
 * we believe we are reading a page table, and reading device registers is what froze this host twice.
 *
 * Every table read therefore goes through NxcPhysRead, which refuses anything that is not system
 * RAM. That gate is not defensive tidiness on this path; it is the thing standing between a hostile
 * page table and a hung machine.
 *
 * ============================================================================================
 * HOW THE EPROCESS OFFSET IS OBTAINED -- DERIVED AND PROVEN, NEVER PINNED
 * ============================================================================================
 *
 * DirectoryTableBase sits at EPROCESS+0x28 on every x64 build anyone has looked at recently. It is
 * still not hardcoded, for the reason the self-map base is not hardcoded: a pinned offset that has
 * silently moved does not fail, it reads a NEIGHBOURING FIELD and returns a confident wrong answer.
 *
 * Instead:
 *   1. Read CR3. In kernel mode that is the CURRENT process's DirectoryTableBase, by definition.
 *   2. Scan the current EPROCESS for a page-aligned QWORD equal to it. Require EXACTLY ONE match --
 *      two candidates means the scan cannot distinguish them, which is a failure, not a coin toss.
 *   3. PROVE it: walk a known VA with the derived offset and compare the result against
 *      MmGetPhysicalAddress for the same VA. Equal means the offset AND the walk are both correct.
 *
 * Step 3 is what makes this safe rather than merely clever. It is an INDEPENDENT oracle -- the
 * kernel's own translation, not a second copy of our arithmetic -- so it catches a wrong offset and
 * a wrong walk, including a shared misunderstanding of the entry format.
 */

#pragma once

#include <ntddk.h>

/* Entry flags, decoded. The raw entry is reported too; these are what a reader actually needs. */
#define NXC_XLAT_PRESENT      NXCMD_XLAT_PRESENT
#define NXC_XLAT_WRITABLE     NXCMD_XLAT_WRITABLE
#define NXC_XLAT_USER         NXCMD_XLAT_USER
#define NXC_XLAT_NX           NXCMD_XLAT_NX
#define NXC_XLAT_ACCESSED     NXCMD_XLAT_ACCESSED
#define NXC_XLAT_DIRTY        NXCMD_XLAT_DIRTY
#define NXC_XLAT_LARGE_PAGE   NXCMD_XLAT_LARGE_PAGE
#define NXC_XLAT_GLOBAL       NXCMD_XLAT_GLOBAL

/**
 * The result of one translation.
 *
 * ⚠ Effective permissions are the AND of Writable and the OR of NX across ALL FOUR LEVELS, not the
 * final entry's bits. A leaf PTE marked writable inside a read-only PDE is not writable. The
 * per-level entries are reported so that can be seen rather than assumed.
 */
typedef struct _NXC_XLAT
{
	UINT64 Cr3;              /* the target's DirectoryTableBase, as used                     */
	UINT64 PhysicalAddress;  /* the answer, including the offset within the mapping page     */
	UINT64 Entries[4];       /* raw PML4E, PDPTE, PDE, PTE -- 0 for levels not reached       */
	UINT32 Level;            /* 4 = 4 KB page, 3 = 2 MB large page, 2 = 1 GB large page      */
	UINT32 Flags;            /* NXC_XLAT_*, EFFECTIVE across the levels walked               */
	UINT32 FailedLevel;      /* 0 on success; otherwise 1..4, the level that was not present */
	/*
	 * ⚠ WHY A NOT-PRESENT ENTRY IS NOT PRESENT -- NXC_SW_*, decoded from the entry that failed.
	 *
	 * D21 asked for this by name. "Not present" collapses several completely different facts into
	 * one: a page trimmed to the standby list is ordinary paging, a page-file-backed page is
	 * ordinary paging, and a PTE of ZERO where the loader still lists a mapping is the finding this
	 * phase exists to surface. Today those all print identically, so the interesting one is
	 * invisible.
	 *
	 * ⚠ AND IT IS DECODED, NEVER FAULTED IN. v1's approach was to touch the page and let the fault
	 * handler resolve it; that PERTURBS the target -- OSR's phrasing is that it "blow[s] up the
	 * target's working set" -- and non-perturbation is a framework property here, not a preference
	 * (D21 reversing D19). The PTE already holds the answer.
	 */
	UINT32 SoftState;
} NXC_XLAT;

/*
 * Software (invalid) PTE states. Valid = bit 0, Prototype = bit 10, Transition = bit 11.
 *
 * ⚠⚠ THE ADDRESS FIELDS OF AN INVALID PTE ARE NOT ADDRESSES, AND THIS IS THE PART THAT WOULD BE GOT
 * WRONG. Windows masks not-present PTEs so that high physical-address bits are always set -- the
 * L1TF / Foreshadow mitigation, whose whole point is that a speculative walk lands outside populated
 * RAM. The mask is `nt!MiState.Hardware.InvalidPteMask` and it is NOT exported, so an invalid PTE's
 * PFN or PageFileHigh cannot be turned back into a real physical address or pagefile offset here.
 *
 * The STATE bits survive this untouched, because the mask sets high address bits and these are low
 * software bits. So v2 reports the STATE and the RAW ENTRY, and refuses to report a location -- the
 * exact line between evidence and a verdict (D6). Reporting a masked PFN as a physical address would
 * be well-formed, confident and wrong, which is this project's worst output class.
 */
#define NXC_SW_PRESENT       NXCMD_SW_PRESENT   /* not a software state -- the walk succeeded                  */
#define NXC_SW_ZERO          NXCMD_SW_ZERO   /* entry is entirely zero: NEVER committed, or torn down       */
#define NXC_SW_TRANSITION    NXCMD_SW_TRANSITION   /* bit 11: page IS still in RAM, on standby/modified           */
#define NXC_SW_PROTOTYPE     NXCMD_SW_PROTOTYPE   /* bit 10: shared/mapped -- real state lives in the proto PTE  */
/*
 * ⚠ ONE STATE, NOT TWO, AND ON PURPOSE. Pagefile-backed and demand-zero are distinguished in the
 * textbooks by whether PageFileHigh is nonzero -- a test that is WRONG here, because the L1TF
 * mitigation sets high address bits in EVERY not-present PTE, so it would report every demand-zero
 * page as pagefile-backed. Separating them needs InvalidPteMask, which is unexported. Merged and
 * named for what is actually known rather than split on a test that cannot work.
 */
#define NXC_SW_NOT_RESIDENT  NXCMD_SW_NOT_RESIDENT   /* committed, not in RAM; backing not determinable here        */

/*
 * PlatformCtl MIRRORS this struct (it cannot include ntddk), so the layout is pinned on BOTH sides.
 * The usermode copy carries the matching assert. A mirror without one is two declarations held
 * together by hope.
 */
C_ASSERT(sizeof(NXC_XLAT) == 64);
C_ASSERT(FIELD_OFFSET(NXC_XLAT, PhysicalAddress) == 8);
C_ASSERT(FIELD_OFFSET(NXC_XLAT, Entries)         == 16);
C_ASSERT(FIELD_OFFSET(NXC_XLAT, Level)           == 48);
C_ASSERT(FIELD_OFFSET(NXC_XLAT, Flags)           == 52);
C_ASSERT(FIELD_OFFSET(NXC_XLAT, FailedLevel)     == 56);

/**
 * Prove the EPROCESS DirectoryTableBase offset. Call once; safe to call again (idempotent).
 *
 * Returns STATUS_SUCCESS only when the offset was PROVEN against MmGetPhysicalAddress, never when a
 * candidate merely looked plausible.
 */
NTSTATUS NxcTranslateInit(VOID);

/** The proven EPROCESS offset of DirectoryTableBase, or 0 if NxcTranslateInit has not succeeded. */
UINT32 NxcTranslateDtbOffset(VOID);

/**
 * Translate @p Va in @p Process.
 *
 * @return STATUS_SUCCESS with Out filled; STATUS_NOT_FOUND with Out->FailedLevel set when the walk
 *         hit a non-present level (a normal, informative answer -- not an error in the caller);
 *         STATUS_INVALID_ADDRESS if a table entry pointed outside system RAM.
 */
NTSTATUS NxcTranslate(
	_In_ PVOID Process,
	_In_ UINT64 Va,
	_Out_ NXC_XLAT* Out
	);
