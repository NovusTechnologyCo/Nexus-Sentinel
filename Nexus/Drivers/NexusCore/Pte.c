/**
 * @file Pte.c
 * @brief Self-map derivation and page-table walking. See Pte.h for the four-tier rationale.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "../../Include/NexusCoreBoot.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "Pte.h"

/* The table instance lives in NexusCore.c; this TU calls nt through it like every other. */
extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define NxcLog NxcLogExt

/* x64 paging-structure bits. Named rather than inlined so the decode below reads as prose. */
#define PTE_PRESENT     0x0000000000000001ULL
#define PTE_WRITE       0x0000000000000002ULL
#define PTE_USER        0x0000000000000004ULL
#define PTE_ACCESSED    0x0000000000000020ULL
#define PTE_DIRTY       0x0000000000000040ULL
#define PTE_LARGE       0x0000000000000080ULL   /* PS -- entry maps a page, not a table */
#define PTE_GLOBAL      0x0000000000000100ULL
#define PTE_NX          0x8000000000000000ULL
#define PTE_PFN_MASK    0x000FFFFFFFFFF000ULL

/* Proven self-map base. 0 until NxcPteInit succeeds; nothing here reads it before that. */
static UINT64 gSelfMapBase = 0;

/*
 * ============================================================================================
 * THE MEMORY WE ARE ALLOWED TO REPROTECT.
 * ============================================================================================
 *
 * This file's own documentation calls the large-page refusal "the most important line of code in
 * this file", because a 2 MB entry covers neighbouring EFI runtime memory -- including the firmware
 * code that services GetVariable, the transport this whole project reports through.
 *
 * ⚠ THAT GUARD IS ONLY HALF THE PROBLEM, and the review found the other half open. It protects
 * against scope EXPANSION -- a range that turns out to cover more than intended. It does nothing
 * about a wrong BASE. A caller passing any 4 KB-mapped kernel address passes every check in
 * NxcPteProtectRange: the survey finds real level-4 PTEs, the commit rewrites them, the verify
 * confirms the new bits, and it logs success. We would have silently reprotected somebody else's
 * memory and reported it as done.
 *
 * That is not hypothetical input. NxcPteProtectImage computes each range as
 * ImageBase + Section[i].VirtualAddress, from an IMAGE-SUPPLIED section table -- the same untrusted
 * source that needed an explicit ImageSize bound after it was found unbounded. A bug in that bound,
 * or a future caller, lands here with nothing to catch it.
 *
 * So the driver declares what it owns and this file refuses everything else. Two extents cover every
 * legitimate call: our own mapped image, and the arena (module images live inside it, so their
 * sections are covered by the arena extent).
 *
 * Belt AND braces with the large-page refusal, deliberately: that one bounds how far a range can
 * reach, this one bounds where it can start. Neither implies the other.
 */
static UINT64 gOwnedImageBase = 0;
static UINT64 gOwnedImageEnd  = 0;
static UINT64 gOwnedArenaBase = 0;
static UINT64 gOwnedArenaEnd  = 0;

void
NxcPteSetOwnedRanges(
	_In_ UINT64 ImageBase,
	_In_ UINT32 ImageSize,
	_In_ UINT64 ArenaBase,
	_In_ UINT32 ArenaSize
	)
{
	gOwnedImageBase = ImageBase;
	gOwnedImageEnd  = (ImageBase != 0) ? ImageBase + ImageSize : 0;
	gOwnedArenaBase = ArenaBase;
	gOwnedArenaEnd  = (ArenaBase != 0) ? ArenaBase + ArenaSize : 0;
}

/** TRUE only if [First, LastEnd) lies ENTIRELY inside one declared extent. */
static BOOLEAN
NxcPteRangeIsOurs(
	_In_ UINT64 First,
	_In_ UINT64 LastEnd
	)
{
	if (gOwnedImageBase != 0 && First >= gOwnedImageBase && LastEnd <= gOwnedImageEnd)
		return TRUE;
	if (gOwnedArenaBase != 0 && First >= gOwnedArenaBase && LastEnd <= gOwnedArenaEnd)
		return TRUE;
	return FALSE;
}

/* Packed probe outcome for the boot block: (present << 16) | readable. */
static UINT32 gProbeDiag = 0;

/*
 * ============================================================================================
 * THE PAGE-INDEX MASK -- COMPUTED, never typed as a hex literal. Here is why.
 * ============================================================================================
 *
 * The first version of this file hardcoded 0x7FFFFFFFF. That is 35 bits. The correct width is 36:
 * a canonical x64 address is 48 bits, of which the low 12 are the page offset, leaving bits 12..47
 * as the page index.
 *
 * MEASURED CONSEQUENCE, first boot,: every kernel VA has bit 47 set, so the short mask
 * dropped it and produced a different entry address for every candidate. Real image base
 * 0xFFFFF80484E16000 -> index 0xF80484E16 correct, 0x780484E16 shipped. No candidate could satisfy
 * the CR3 identity, all 256 were rejected, and the driver reported "NOT DERIVED".
 *
 * ⚠ THE DESIGN HELD EVEN THOUGH THE ARITHMETIC DID NOT, and that is the part to keep. Because the
 * self-map base had to be PROVEN rather than assumed, a wrong address calculation could not produce
 * a confidently wrong base -- it produced no base at all, said so, and touched nothing. Had this
 * been "compute the address and edit it", the same typo would have written W/NX bits into arbitrary
 * kernel page-table entries at boot. Fail-closed derivation converted a silent memory corruptor
 * into a one-line diagnostic.
 *
 * So the mask is now DERIVED from the two constants that define it. A literal can be off by one
 * digit and still look right; (1 << (48 - 12)) - 1 cannot.
 */
#define NXC_VA_CANONICAL_BITS  48
#define NXC_PAGE_SHIFT         12
#define NXC_PT_INDEX_BITS      (NXC_VA_CANONICAL_BITS - NXC_PAGE_SHIFT)   /* 36 */
#define NXC_PT_INDEX_MASK      ((1ULL << NXC_PT_INDEX_BITS) - 1ULL)

/*
 * Cross-check against v1's independently-written spelling of the same transform
 * (v1's `hwid_spoof_tpm.c:3383`): `pteBase + ((va >> 9) & 0x7FFFFFFFF8)`.
 * That is the index scaled by 8 with the low three bits cleared, so it must equal our mask << 3.
 * Two independent derivations agreeing is worth a compile-time check; it is the cheapest possible
 * second opinion, and this file has already demonstrated it needed one.
 */
C_ASSERT((NXC_PT_INDEX_MASK << 3) == 0x7FFFFFFFF8ULL);

/**
 * Address of the PTE that maps @p Va, given a self-map base.
 *
 * THE RECURSION BELOW IS THE WHOLE TRICK and is worth stating explicitly, because it looks like
 * sleight of hand: under a self-referencing PML4 entry, the page tables are themselves visible as
 * ordinary memory starting at Base. That means "the address of the PTE for X" and "the address of
 * the PDE for X" are the SAME transform applied once and twice -- the PDE for X is the PTE for
 * (the PTE address of X), because the PTE for X lives in a page table, and that page table is
 * itself mapped by a PDE that the self-map exposes at exactly that spot.
 *
 * Writing it as one function applied 1..4 times, instead of four hand-derived shift/mask
 * expressions, removes the possibility of getting one of the four subtly wrong -- the same reason
 * NXC_NT_API_LIST is an X-macro rather than three parallel lists.
 */
static UINT64
NxcPteAddrOf(
	_In_ UINT64 Base,
	_In_ UINT64 Va
	)
{
	/* 36 bits of page index (VA bits 12..47), scaled by 8, folded onto the self-map window. */
	return Base + ((Va >> NXC_PAGE_SHIFT) & NXC_PT_INDEX_MASK) * 8ULL;
}

/**
 * Read a table entry without faulting.
 *
 * NO SEH IS AVAILABLE IN THIS DRIVER (see the constraint block in NexusCore.c), so a bad read is a
 * bugcheck, not an exception. MmIsAddressValid is the only guard we have. It is documented as racy
 * -- a page can be trimmed between the check and the read -- but the pages being probed here are
 * PAGE TABLES for resident kernel memory, which are not paged out, so the race the documentation
 * warns about does not apply to this specific use. v1's FindPteBase relied on the same property.
 */
static BOOLEAN
NxcPteReadEntry(
	_In_ UINT64 EntryVa,
	_Out_ UINT64* Value
	)
{
	*Value = 0;
	if (!MmIsAddressValid((PVOID)(ULONG_PTR)EntryVa))
		return FALSE;
	*Value = *(volatile UINT64*)(ULONG_PTR)EntryVa;
	return TRUE;
}

_Use_decl_annotations_
NTSTATUS
NxcPteInit(
	VOID
	)
{
	if (gSelfMapBase != 0)
		return STATUS_SUCCESS;

	/*
	 * THE PROOF, and why this is better than v1's version.
	 *
	 * v1 verified a candidate by looking up ntoskrnl, taking MmGetPhysicalAddress of its base, and
	 * checking the candidate PTE held that PFN. Correct, but it depends on finding a module first.
	 *
	 * The self-reference entry is a stronger and simpler witness. If index n is the self-map index,
	 * then PML4[n] is BY DEFINITION the entry pointing at the PML4 itself -- so its PFN must equal
	 * the PFN in CR3. That is a closed identity: no module lookup, no export, no second API. A
	 * candidate either satisfies it or it is not the self-map.
	 *
	 * This is the property that makes the whole approach acceptable where a byte-pattern scan was
	 * not: the answer can be CHECKED, so a wrong derivation is impossible rather than merely
	 * unlikely, and failure is a clean "no base" instead of a wild pointer.
	 */
	CONST UINT64 Cr3Pfn = __readcr3() & PTE_PFN_MASK;
	if (Cr3Pfn == 0)
	{
		NxcLog("pte: CR3 read gave no PFN -- cannot derive self-map\n");
		return STATUS_UNSUCCESSFUL;
	}

	/*
	 * Counted so a FAILURE is diagnosable from the boot block alone -- there is no debugger here and
	 * DbgPrint goes nowhere anyone can read. See PteProbeDiag in NexusCoreBoot.h: "no candidate
	 * address was even readable" and "addresses were fine but none matched CR3" are completely
	 * different bugs that would otherwise produce the identical output "NOT DERIVED".
	 */
	UINT32 Readable = 0;
	UINT32 Present  = 0;

	/* Kernel half only: the self-map has lived in indices 256..511 on every x64 Windows. */
	for (UINT32 n = 256; n < 512; n++)
	{
		CONST UINT64 Candidate = 0xFFFF000000000000ULL | ((UINT64)n << 39);

		/*
		 * Four applications of the transform land on PML4[n] -- the self-reference slot -- for any
		 * VA inside the candidate window. Feeding it the candidate base itself is the clearest
		 * spelling of "the entry that describes this window".
		 */
		CONST UINT64 SelfEntryVa = NxcPteAddrOf(Candidate,
		                           NxcPteAddrOf(Candidate,
		                           NxcPteAddrOf(Candidate,
		                           NxcPteAddrOf(Candidate, Candidate))));

		UINT64 Entry;
		if (!NxcPteReadEntry(SelfEntryVa, &Entry))
			continue;
		Readable++;
		if ((Entry & PTE_PRESENT) == 0)
			continue;
		Present++;
		if ((Entry & PTE_PFN_MASK) != Cr3Pfn)
			continue;

		gSelfMapBase = Candidate;
		gProbeDiag = (Present << 16) | (Readable & 0xFFFF);
		NxcLog("pte: self-map base %p PROVEN (pml4 index %u, cr3 pfn %llX)\n",
		       (PVOID)(ULONG_PTR)Candidate, n, Cr3Pfn >> 12);
		return STATUS_SUCCESS;
	}

	gProbeDiag = (Present << 16) | (Readable & 0xFFFF);
	NxcLog("pte: no self-map index satisfied the CR3 identity (%u readable, %u present)"
	       " -- refusing to guess\n", Readable, Present);
	return STATUS_NOT_FOUND;
}

UINT32
NxcPteProbeDiag(
	VOID
	)
{
	return gProbeDiag;
}

UINT64
NxcPteSelfMapBase(
	VOID
	)
{
	return gSelfMapBase;
}

/**
 * Decode the terminal entry into the flag set the boot block carries.
 *
 * ============================================================================================
 * ⚠ W AND X ARE THE **EFFECTIVE** PERMISSIONS, ACCUMULATED ACROSS THE WHOLE WALK.
 * ============================================================================================
 *
 *  This used to decode W and NX from the terminal entry alone, and the
 * result was reported -- through the boot block, and by PlatformCtl -- as "the page is RWX / RW- /
 * R--". That is not what a leaf entry means.
 *
 * On x86-64 the access rights for a page are the COMBINATION of every level of the walk: the page is
 * writable only if W is set in the PML4E *and* the PDPTE *and* the PDE *and* the PTE, and executable
 * only if NX is clear in ALL of them. A restrictive upper level silently overrides a permissive leaf.
 *
 * So the old reading was correct only while every upper level happened to be permissive -- which is
 * the normal Windows kernel-space pattern, and is why every measurement so far has been consistent.
 * It was true by luck of the environment, not by construction, and it was being reported under a name
 * that claimed more than it measured. Exactly the fault the MAT probe had: sample one thing, label it
 * as the whole.
 *
 * ⚠ THE SHARPER CONSEQUENCE is on the write side. NxcPteProtectRange sets W/NX on the LEAF only. If an
 * upper level were restrictive, the write would change nothing effective -- and the verify pass,
 * reading the leaf back, would confirm success. A guarantee that cannot fail is not a guarantee. With
 * effective decoding the verify now compares what the hardware will actually enforce.
 *
 * @param AccWrite  PTE_WRITE still set = W present at EVERY level walked (AND accumulator)
 * @param AccNx     PTE_NX set = NX present at SOME level walked (OR accumulator)
 */
static UINT32
NxcPteDecode(
	_In_ UINT64 Entry,
	_In_ UINT32 Level,
	_In_ UINT64 AccWrite,
	_In_ UINT64 AccNx
	)
{
	UINT32 Flags = NXC_PTE_VALID;

	if (Entry & PTE_PRESENT)  Flags |= NXC_PTE_PRESENT;
	if (Entry & PTE_USER)     Flags |= NXC_PTE_USER;
	if (Entry & PTE_DIRTY)    Flags |= NXC_PTE_DIRTY;
	if (Entry & PTE_GLOBAL)   Flags |= NXC_PTE_GLOBAL;

	/* Effective, not leaf-local. See the block above. */
	if (AccWrite & PTE_WRITE)
		Flags |= NXC_PTE_WRITABLE;

	/* Executable is the ABSENCE of NX at every level. Stated positively because that is how it reads. */
	if ((AccNx & PTE_NX) == 0)
		Flags |= NXC_PTE_EXECUTE;

	if (Level == 3) Flags |= NXC_PTE_LARGE_2M;
	if (Level == 2) Flags |= NXC_PTE_LARGE_1G;

	return Flags;
}


/*
 * Is there a PE image header on the page immediately BELOW @p RegionBase?
 *
 * ⚠ BELOW, NOT AT. A loaded image's header page is R-- and therefore not executable, so the scan
 * never sees it and the executable run begins one page later -- NexusCore reports at image base
 * + 0x1000. Looking for MZ at the region base would miss every real image.
 *
 * ⚠ THE PAGE IS PROVEN PRESENT BEFORE IT IS READ. The scan established that the REGION is mapped;
 * it established nothing about the page under it, which may be unmapped or on a different mapping
 * entirely. NxcPteQuery first, then MmIsAddressValid, then read -- reading a kernel VA on the
 * strength of a neighbouring page being present is how a scan becomes a bugcheck.
 *
 * Deliberately shallow: MZ, then e_lfanew in range, then PE\0\0. Enough to separate a mapped image
 * from a slab of executable pool, which is the only question being asked. It is EVIDENCE, not a
 * verdict -- a hand-built header would satisfy it, and saying so is the point.
 */
static BOOLEAN
NxcPteLooksLikePeImage(
	_In_ UINT64 RegionBase
	)
{
	if (RegionBase < 0x1000ull)
		return FALSE;

	CONST UINT64 HdrVa = RegionBase - 0x1000ull;

	NXC_PTE_INFO Hdr;
	if (!NT_SUCCESS(NxcPteQuery(HdrVa, &Hdr)))
		return FALSE;
	if (!MmIsAddressValid((PVOID)(ULONG_PTR)HdrVa))
		return FALSE;

	CONST UCHAR* CONST P = (CONST UCHAR*)(ULONG_PTR)HdrVa;
	if (P[0] != 'M' || P[1] != 'Z')
		return FALSE;

	/* e_lfanew is at +0x3C. Bound it inside the header page before dereferencing it. */
	UINT32 Lfanew = 0;
	RtlCopyMemory(&Lfanew, P + 0x3C, sizeof(Lfanew));
	if (Lfanew < 0x40u || Lfanew > (0x1000u - 4u))
		return FALSE;

	return (P[Lfanew] == 'P' && P[Lfanew + 1] == 'E' &&
	        P[Lfanew + 2] == 0 && P[Lfanew + 3] == 0);
}

/*
 * ================================================================================================
 * SCAN kernel VA for EXECUTABLE pages that belong to no loaded module.
 *
 * The kernel counterpart to `regions --hidden`. A driver that unlinks itself from
 * PsLoadedModuleList cannot be named, so every existing kernel command -- which all take a name --
 * is blind to it. What it cannot hide is that its code must be mapped executable.
 *
 * ⚠ READ ONLY. No PTE is written. The descent is NxcPteQuery's, unchanged, including its PRESENT
 * check before descending and its PS check before treating an entry as a table.
 *
 * ⚠ FEASIBILITY COMES ENTIRELY FROM MissingLevel. Kernel VA is 128 TB; stepping 4 KB through it is
 * ~34 billion probes. An absent entry means a fixed span is empty, so the walk skips 512 GB / 1 GB
 * / 2 MB / 4 KB accordingly. Without that this function could not exist.
 *
 * ⚠ BOUNDED THREE WAYS, because an unbounded kernel-wide walk at PASSIVE is still a long time to
 * spend inside one command: a probe ceiling, a region ceiling, and the caller's buffer. Whichever
 * is hit first stops the walk, and the caller is TOLD which -- a truncated scan that looks complete
 * would be the worst possible failure for a command whose finding is "nothing is there".
 *
 * ⚠ IT REPORTS EVIDENCE, NOT A VERDICT (D6). Executable-and-unlisted is not malicious: NexusCore
 * itself is exactly that by design. Self and arena are FLAGGED so they are recognisable, not
 * hidden -- suppressing them would be a scan that lies about its own footprint.
 * ================================================================================================
 */
_Use_decl_annotations_
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
	_Out_ UINT64* OutProbes,      /* what the walk COST -- so the ceiling is set by measurement */
	_Out_ UINT64* OutReachedVa    /* how far it got -- makes a truncated walk diagnosable       */
	)
{
	*OutWritten   = 0;
	*OutTotal     = 0;
	*OutTruncated = 0;
	*OutProbes    = 0;
	*OutReachedVa = 0;

	if (Out == NULL || Capacity == 0 || RangeBase == NULL || RangeEnd == NULL)
		return STATUS_INVALID_PARAMETER;
	if (NxcPteSelfMapBase() == 0)
		return STATUS_DEVICE_NOT_READY;

	/* Canonical kernel half. Below this is usermode and is not this command's subject. */
	CONST UINT64 KernelFirst = 0xFFFF800000000000ull;

	/*
	 * ⚠ 8 MILLION WAS TOO LOW AND THE FIRST HARDWARE RUN PROVED IT. The walk
	 * reached 0xFFFF9482CB413000 from a 0xFFFF800000000000 start -- 22.6 TB -- and stopped
	 * short of the region where drivers and our own image actually live. It reported the
	 * truncation honestly, so the scan was USELESS rather than WRONG, which is the outcome the
	 * ceiling exists to guarantee.
	 *
	 * 22.6 TB / 8M probes is ~2.8 MB per probe, i.e. almost every probe was a PDE-absent 2 MB
	 * skip through sparse space. Crossing the full 128 TB at that granularity needs ~64M, so
	 * the ceiling is 128M -- generous against the measurement rather than guessed, and still
	 * finite. Each probe is a handful of reads through the self-map.
	 */
	CONST UINT64 MaxProbes = 128ull * 1000ull * 1000ull;
	UINT64 Probes = 0;

	UINT32 Total   = 0;      /* regions FOUND, whether or not they fit the buffer */
	UINT32 Written = 0;

	UINT64 RunBase  = 0;     /* 0 = no run open */
	UINT64 RunEnd   = 0;
	UINT32 RunPages = 0;
	UINT32 RunFlags = 0;

	UINT64 Va = KernelFirst;
	for (;;)
	{
		if (Va < KernelFirst) break;          /* wrapped past the top of VA space */
		if (Probes >= MaxProbes) { *OutTruncated |= 1u; break; }

		NXC_PTE_INFO Info;
		CONST NTSTATUS St = NxcPteQuery(Va, &Info);
		Probes++;

		UINT64 Step = 0x1000ull;
		BOOLEAN Exec = FALSE;

		if (!NT_SUCCESS(St))
		{
			/* THE SKIP. An absent level means a fixed span holds nothing at all. */
			switch (Info.MissingLevel)
			{
			case 1:  Step = 1ull << 39; break;   /* no PML4E -- 512 GB empty */
			case 2:  Step = 1ull << 30; break;   /* no PDPTE  -- 1 GB empty   */
			case 3:  Step = 1ull << 21; break;   /* no PDE    -- 2 MB empty   */
			default: Step = 1ull << 12; break;   /* no PTE    -- this page    */
			}
		}
		else
		{
			if (Info.Level == 2)      Step = 1ull << 30;   /* 1 GB mapping */
			else if (Info.Level == 3) Step = 1ull << 21;   /* 2 MB mapping */
			else                      Step = 1ull << 12;

			Exec = (Info.Flags & NXC_PTE_EXECUTE) != 0;

			if (Exec)
			{
				/* Subtract every loaded module. A page inside one is accounted for. */
				for (UINT32 r = 0; r < RangeCount; r++)
				{
					if (Va >= RangeBase[r] && Va < RangeEnd[r]) { Exec = FALSE; break; }
				}
			}
		}

		if (Exec)
		{
			CONST UINT32 Add = (Info.Flags & NXC_PTE_WRITABLE) ? NXCMD_KEXEC_WRITABLE : 0u;
			CONST UINT32 Lrg = (Info.Level != 4) ? NXCMD_KEXEC_LARGE : 0u;
			/* Our own bounds come from the state this file ALREADY holds (NxcPteSetOwnedRanges),
			 * not from arguments. Passing them in would be a second copy of one fact. */
			CONST UINT32 Slf = (gOwnedImageBase != 0 && Va >= gOwnedImageBase && Va < gOwnedImageEnd)
			                   ? NXCMD_KEXEC_IS_SELF : 0u;
			CONST UINT32 Arn = (gOwnedArenaBase != 0 && Va >= gOwnedArenaBase && Va < gOwnedArenaEnd)
			                   ? NXCMD_KEXEC_IS_ARENA : 0u;

			if (RunBase != 0 && Va == RunEnd)
			{
				RunEnd    = Va + Step;      /* contiguous -- extend rather than emit */
				RunPages += 1;
				RunFlags |= (Add | Lrg | Slf | Arn);
			}
			else
			{
				/* A gap closed the previous run. Emit it, then open a new one. */
				if (RunBase != 0)
				{
					if (Total >= FirstIndex && Written < Capacity)
					{
						Out[Written].Base  = RunBase;
						Out[Written].Size  = RunEnd - RunBase;
						Out[Written].Pages = RunPages;
						Out[Written].Flags = RunFlags;
						Written++;
					}
					Total++;
				}
				RunBase  = Va;
				RunEnd   = Va + Step;
				RunPages = 1;
				/* Checked ONCE per run, at the run's base -- that is the only page a header can
				 * precede, and probing every page would cost a query per page across 128 TB. */
				RunFlags = (Add | Lrg | Slf | Arn) |
				           (NxcPteLooksLikePeImage(Va) ? NXCMD_KEXEC_PE_IMAGE : 0u);
			}

			if (Total >= 0x10000u) { *OutTruncated |= 2u; break; }   /* region ceiling */
		}
		else if (RunBase != 0)
		{
			if (Total >= FirstIndex && Written < Capacity)
			{
				Out[Written].Base  = RunBase;
				Out[Written].Size  = RunEnd - RunBase;
				Out[Written].Pages = RunPages;
				Out[Written].Flags = RunFlags;
				Written++;
			}
			Total++;
			RunBase = 0; RunEnd = 0; RunPages = 0; RunFlags = 0;
		}

		CONST UINT64 Next = Va + Step;
		if (Next <= Va) break;               /* overflow at the top of the address space */
		Va = Next;
	}

	/* A run still open at the end of the walk is a real region, not a leftover. */
	if (RunBase != 0)
	{
		if (Total >= FirstIndex && Written < Capacity)
		{
			Out[Written].Base  = RunBase;
			Out[Written].Size  = RunEnd - RunBase;
			Out[Written].Pages = RunPages;
			Out[Written].Flags = RunFlags;
			Written++;
		}
		Total++;
	}

	*OutWritten   = Written;
	*OutTotal     = Total;
	*OutProbes    = Probes;
	*OutReachedVa = Va;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NxcPteQuery(
	UINT64 Va,
	NXC_PTE_INFO* Info
	)
{
	Info->EntryVa = 0;
	Info->Value   = 0;
	Info->Pfn     = 0;
	Info->Flags   = 0;
	Info->Level   = 0;
	Info->MissingLevel = 0;

	if (gSelfMapBase == 0)
		return STATUS_DEVICE_NOT_READY;

	CONST UINT64 Base = gSelfMapBase;

	/*
	 * Descend one level at a time, CHECKING PS BEFORE DESCENDING.
	 *
	 * Order is load-bearing. If a PPE maps a 1 GB page, the address the transform would give for
	 * "the PDE" is not a page table at all -- it is data inside that 1 GB page. Reading it would
	 * return a plausible 64-bit value that decodes as a nonsense entry, and the walk would report
	 * confident garbage. Checking PS at each level is what keeps the result honest.
	 */
	/*
	 * Permission accumulators, folded in at EVERY level including the PML4E -- whose W and NX bits
	 * were previously read and discarded. AccWrite starts permissive and is ANDed down; AccNx starts
	 * clear and is ORed up. See NxcPteDecode for why the terminal entry alone is not the answer.
	 */
	UINT64 AccWrite = PTE_WRITE;
	UINT64 AccNx    = 0;

	CONST UINT64 PxeVa = NxcPteAddrOf(Base, NxcPteAddrOf(Base, NxcPteAddrOf(Base, NxcPteAddrOf(Base, Va))));
	UINT64 Entry;

	if (!NxcPteReadEntry(PxeVa, &Entry) || (Entry & PTE_PRESENT) == 0)
	{
		Info->MissingLevel = 1;   /* nothing mapped in this 512 GB */
		return STATUS_NOT_FOUND;
	}
	AccWrite &= Entry;
	AccNx    |= (Entry & PTE_NX);

	CONST UINT64 PpeVa = NxcPteAddrOf(Base, NxcPteAddrOf(Base, NxcPteAddrOf(Base, Va)));
	if (!NxcPteReadEntry(PpeVa, &Entry) || (Entry & PTE_PRESENT) == 0)
	{
		Info->MissingLevel = 2;   /* nothing mapped in this 1 GB */
		return STATUS_NOT_FOUND;
	}
	AccWrite &= Entry;
	AccNx    |= (Entry & PTE_NX);
	if (Entry & PTE_LARGE)
	{
		Info->EntryVa = PpeVa;
		Info->Value   = Entry;
		Info->Pfn     = (Entry & PTE_PFN_MASK) >> 12;
		Info->Level   = 2;
		Info->Flags   = NxcPteDecode(Entry, 2, AccWrite, AccNx);
		return STATUS_SUCCESS;
	}

	CONST UINT64 PdeVa = NxcPteAddrOf(Base, NxcPteAddrOf(Base, Va));
	if (!NxcPteReadEntry(PdeVa, &Entry) || (Entry & PTE_PRESENT) == 0)
	{
		Info->MissingLevel = 3;   /* nothing mapped in this 2 MB */
		return STATUS_NOT_FOUND;
	}
	AccWrite &= Entry;
	AccNx    |= (Entry & PTE_NX);
	if (Entry & PTE_LARGE)
	{
		Info->EntryVa = PdeVa;
		Info->Value   = Entry;
		Info->Pfn     = (Entry & PTE_PFN_MASK) >> 12;
		Info->Level   = 3;
		Info->Flags   = NxcPteDecode(Entry, 3, AccWrite, AccNx);
		return STATUS_SUCCESS;
	}

	CONST UINT64 PteVa = NxcPteAddrOf(Base, Va);
	if (!NxcPteReadEntry(PteVa, &Entry) || (Entry & PTE_PRESENT) == 0)
	{
		Info->MissingLevel = 4;   /* only this 4 KB */
		return STATUS_NOT_FOUND;
	}
	AccWrite &= Entry;
	AccNx    |= (Entry & PTE_NX);

	Info->EntryVa = PteVa;
	Info->Value   = Entry;
	Info->Pfn     = (Entry & PTE_PFN_MASK) >> 12;
	Info->Level   = 4;
	Info->Flags   = NxcPteDecode(Entry, 4, AccWrite, AccNx);
	return STATUS_SUCCESS;
}

/**
 * TLB shootdown payload. Runs on EVERY processor, at IPI_LEVEL, with all others spinning.
 *
 * Kept to nothing but INVLPG in a bounded loop. Whatever runs here stalls the entire machine for its
 * duration, so a log call or an allocation in this function would be a scheduling bug wearing the
 * costume of a diagnostic.
 */
typedef struct _NXC_TLB_RANGE
{
	UINT64 First;
	UINT64 Last;
} NXC_TLB_RANGE;

static ULONG_PTR
NxcTlbInvalidateIpi(
	_In_ ULONG_PTR Context
	)
{
	CONST NXC_TLB_RANGE* Range = (CONST NXC_TLB_RANGE*)Context;

	/*
	 * ⚠ DO NOT "OPTIMISE" THIS INTO A CR3 RELOAD. Considered and rejected by review.
	 *
	 * The obvious objection to a per-page loop is that above some tens of pages a full TLB flush is
	 * cheaper than N individual invalidations, and this can run to hundreds of pages per section
	 * while every processor spins at IPI_LEVEL. That reasoning is right in general and WRONG here.
	 *
	 * Our pages are GLOBAL -- the status read shows "global" on both the image and the arena, because
	 * Windows maps EFI runtime regions that way. A MOV to CR3 does not flush global TLB entries; that
	 * is the entire point of the G bit. Replacing this loop with a CR3 reload would therefore appear
	 * to work, cost less, and leave every processor holding a STALE WRITABLE translation for memory we
	 * just made read-only -- silent until something corrupts, which is the failure this broadcast
	 * exists to prevent.
	 *
	 * Flushing globals properly means toggling CR4.PGE, which invalidates the ENTIRE TLB on that
	 * processor -- far more disruptive than invalidating the handful of pages we actually changed, and
	 * touching a control register on every core from an IPI is a much larger thing to get wrong (this
	 * project has already been bitten once by CR0.WP/CR4.CET coupling in a runtime path).
	 *
	 * So the per-page loop is not a naive first cut, it is the correct tool for global pages. Measured
	 * cost is small in practice: protections are applied per section, so each broadcast covers one
	 * section's pages, not the whole image.
	 */
	for (UINT64 Page = Range->First; Page <= Range->Last; Page += 0x1000)
		__invlpg((PVOID)(ULONG_PTR)Page);

	return 0;
}

_Use_decl_annotations_
NTSTATUS
NxcPteProtectRange(
	UINT64  Va,
	UINT64  Size,
	BOOLEAN Writable,
	BOOLEAN Executable,
	BOOLEAN BroadcastFlush
	)
{
	if (gSelfMapBase == 0)
		return STATUS_DEVICE_NOT_READY;
	if (Size == 0)
		return STATUS_SUCCESS;

	CONST UINT64 First = Va & ~0xFFFULL;
	CONST UINT64 Last  = (Va + Size - 1) & ~0xFFFULL;

	/*
	 * OWNERSHIP CHECK, before a single entry is examined. See the extents above: the large-page
	 * refusal bounds how FAR a range reaches, this bounds where it may START, and neither implies the
	 * other. Refusing costs a log line; succeeding on someone else's PTEs is silent and permanent.
	 *
	 * Compared against the PAGE-ALIGNED range actually being modified, not the caller's arguments --
	 * First is rounded down and Last is the last page touched, so this is exactly the set of pages the
	 * commit pass would write.
	 */
	if (!NxcPteRangeIsOurs(First, Last + 0x1000ULL))
	{
		NxcLog("protect: %p +%llu is OUTSIDE our image and arena -- REFUSED\n",
		       (PVOID)(ULONG_PTR)Va, Size);
		return STATUS_ACCESS_DENIED;
	}

	/*
	 * PASS 1 -- SURVEY. Prove every page qualifies BEFORE touching a single entry.
	 *
	 * Doing this as a separate pass is the whole safety property. A single loop that checked and
	 * wrote together would leave the range half-converted the moment it met a page it could not
	 * handle, and "half of an image is RX, half is RWX" is a state nothing was designed for and
	 * nothing would report. Survey-then-commit means the only two outcomes are "all of it" and
	 * "none of it, and here is why".
	 */
	for (UINT64 Page = First; Page <= Last; Page += 0x1000)
	{
		NXC_PTE_INFO Info;
		CONST NTSTATUS Status = NxcPteQuery(Page, &Info);
		if (!NT_SUCCESS(Status))
		{
			NxcLog("protect: %p is not mapped -- refusing the whole range\n", (PVOID)(ULONG_PTR)Page);
			return Status;
		}
		if (Info.Level != 4)
		{
			NxcLog("protect: %p is on a %s page -- refusing (would change memory that is not ours)\n",
			       (PVOID)(ULONG_PTR)Page, (Info.Level == 3) ? "2 MB" : "1 GB");
			return STATUS_NOT_SUPPORTED;
		}
	}

	/*
	 * PASS 2 -- COMMIT.
	 *
	 * Read-modify-write through InterlockedCompareExchange64 rather than a plain store: only W and NX
	 * are ours to decide, and every other bit in the entry (PFN, accessed, dirty, caching, global)
	 * belongs to the memory manager. A plain store of a value computed a moment earlier would quietly
	 * roll back whatever the CPU set in between. The intrinsic needs no import, which matters here --
	 * this driver has no import table and is not getting one back for a convenience.
	 */
	/*
	 * ⚠ THE COMMIT DELIBERATELY DOES NOT RE-VALIDATE EACH PTE ADDRESS, and that is a considered
	 * choice rather than an oversight -- recorded by review so it is not "fixed" later.
	 *
	 * The survey proved every page in this range is backed by a real level-4 PTE, and the commit then
	 * dereferences the computed entry address directly, with no MmIsAddressValid. A window therefore
	 * exists in principle: if a mapping changed between the two passes, this read faults, and there is
	 * no SEH in this driver to catch it.
	 *
	 * It is not closed, for two reasons. The window is unreachable by any current path -- the ranges
	 * are our own image and arena, which are EFI runtime allocations Windows maps once and does not
	 * repartition, and the boot-path caller runs BSP-only. And MmIsAddressValid is itself documented
	 * as racy, so adding it would NARROW the window while doubling the cost of the hot loop, not close
	 * it. Buying a smaller race at a measurable price, and calling it safety, is worse than naming it.
	 *
	 * If a future caller ever protects memory it does not own the lifetime of, this needs revisiting
	 * -- and the ownership check at the top of this function is what makes "memory we own" enforceable
	 * rather than merely intended.
	 */
	UINT32 Changed = 0;
	for (UINT64 Page = First; Page <= Last; Page += 0x1000)
	{
		volatile LONG64* Entry = (volatile LONG64*)(ULONG_PTR)NxcPteAddrOf(gSelfMapBase, Page);

		for (;;)
		{
			CONST LONG64 Old = *Entry;
			LONG64 New = Old;

			if (Writable)   New |= (LONG64)PTE_WRITE;
			else            New &= ~(LONG64)PTE_WRITE;

			if (Executable) New &= ~(LONG64)PTE_NX;
			else            New |= (LONG64)PTE_NX;

			if (New == Old)
				break;
			if (_InterlockedCompareExchange64(Entry, New, Old) == Old)
			{
				Changed++;
				break;
			}
			/* Someone else touched the entry; re-read and reapply only our two bits. */
		}

		/* Local invalidation always; the cross-processor case is handled once, below. */
		__invlpg((PVOID)(ULONG_PTR)Page);
	}

	/*
	 * CROSS-PROCESSOR SHOOTDOWN -- required whenever another processor could be holding a stale
	 * translation for these VAs.
	 *
	 * The caller decides, and must, because the two call sites differ in a way this function cannot
	 * observe:
	 *
	 *   BOOT PATH (BroadcastFlush = FALSE). We run on the boot-driver init path where only the BSP
	 *   is executing. The APs have not started, hold no TLB entry for these VAs, and will populate
	 *   from page tables we have already updated. There is nothing stale to shoot down, and issuing
	 *   an IPI broadcast during early boot buys nothing for the risk.
	 *
	 *   RUNTIME PATH (BroadcastFlush = TRUE). Every processor is up and any of them may have cached
	 *   these translations. A local INVLPG then leaves other cores executing with the OLD
	 *   permissions -- writable pages we believe are read-only -- and that is not a failure that
	 *   announces itself. It is silent until something corrupts.
	 *
	 * Done ONCE for the whole range rather than per page: each KeIpiGenericCall stalls every
	 * processor, so N calls for N pages multiplies the stall by N for no benefit.
	 */
	if (BroadcastFlush)
	{
		NXC_TLB_RANGE Range;
		Range.First = First;
		Range.Last  = Last;
		KeIpiGenericCall(NxcTlbInvalidateIpi, (ULONG_PTR)&Range);
	}

	/*
	 * PASS 3 -- VERIFY. Read back and confirm the bits are what we asked for.
	 *
	 * Not paranoia. The recurring failure in this project is a check that cannot see the thing it is
	 * checking: an oracle blind to a shared bug, a leak scan on a renamed subject, a verification
	 * that matched a comment instead of an include. "The write returned" is not evidence the mapping
	 * changed. Reading the entry back through the same walk that will be used to report it is.
	 */
	for (UINT64 Page = First; Page <= Last; Page += 0x1000)
	{
		NXC_PTE_INFO Info;
		if (!NT_SUCCESS(NxcPteQuery(Page, &Info)))
			return STATUS_UNSUCCESSFUL;

		CONST BOOLEAN IsWritable   = (Info.Flags & NXC_PTE_WRITABLE) ? TRUE : FALSE;
		CONST BOOLEAN IsExecutable = (Info.Flags & NXC_PTE_EXECUTE)  ? TRUE : FALSE;

		if (IsWritable != Writable || IsExecutable != Executable)
		{
			NxcLog("protect: VERIFY FAILED at %p -- wanted %s%s, entry reads %s%s\n",
			       (PVOID)(ULONG_PTR)Page,
			       Writable ? "W" : "-", Executable ? "X" : "-",
			       IsWritable ? "W" : "-", IsExecutable ? "X" : "-");
			return STATUS_UNSUCCESSFUL;
		}
	}

	NxcLog("protect: %p +%llu -> %s%s (%u entries changed, verified)\n",
	       (PVOID)(ULONG_PTR)Va, Size,
	       Writable ? "W" : "-", Executable ? "X" : "-", Changed);
	return STATUS_SUCCESS;
}

/* Minimal PE view. Declared locally for the same reason as everything else here: no dependency on
 * a header that may not be present, and the field offsets are fixed by the format itself. */
#pragma pack(push, 1)
typedef struct { UINT16 e_magic; UINT8 pad[58]; UINT32 e_lfanew; } NXC_DOS_HEADER;
typedef struct
{
	UINT32 Signature;
	UINT16 Machine;
	UINT16 NumberOfSections;
	UINT32 TimeDateStamp;
	UINT32 PointerToSymbolTable;
	UINT32 NumberOfSymbols;
	UINT16 SizeOfOptionalHeader;
	UINT16 Characteristics;
} NXC_FILE_HEADER;
typedef struct
{
	UINT8  Name[8];
	UINT32 VirtualSize;
	UINT32 VirtualAddress;
	UINT32 SizeOfRawData;
	UINT32 PointerToRawData;
	UINT32 PointerToRelocations;
	UINT32 PointerToLinenumbers;
	UINT16 NumberOfRelocations;
	UINT16 NumberOfLinenumbers;
	UINT32 Characteristics;
} NXC_SECTION_HEADER;
#pragma pack(pop)

#define NXC_SCN_MEM_EXECUTE  0x20000000u
#define NXC_SCN_MEM_WRITE    0x80000000u

_Use_decl_annotations_
NTSTATUS
NxcPteProtectImage(
	UINT64  ImageBase,
	UINT32  ImageSize,
	BOOLEAN BroadcastFlush,
	UINT32* Applied,
	UINT32* Refused
	)
{
	*Applied = 0;
	*Refused = 0;

	if (gSelfMapBase == 0)
		return STATUS_DEVICE_NOT_READY;
	if (!MmIsAddressValid((PVOID)(ULONG_PTR)ImageBase))
		return STATUS_INVALID_ADDRESS;

	CONST NXC_DOS_HEADER* Dos = (CONST NXC_DOS_HEADER*)(ULONG_PTR)ImageBase;
	if (Dos->e_magic != 0x5A4D)
	{
		/*
		 * Headers scrubbed, or never a PE. Either way there is no section table to read, so there is
		 * no correct answer to apply -- and inventing one (say, "make it all RX") would be exactly
		 * the guess this whole exercise exists to eliminate.
		 */
		NxcLog("protect: no MZ at %p -- cannot read a section table, leaving protections alone\n",
		       (PVOID)(ULONG_PTR)ImageBase);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	CONST NXC_FILE_HEADER* File = (CONST NXC_FILE_HEADER*)(ULONG_PTR)(ImageBase + Dos->e_lfanew);
	if (File->Signature != 0x00004550)
		return STATUS_INVALID_IMAGE_FORMAT;

	CONST NXC_SECTION_HEADER* Section = (CONST NXC_SECTION_HEADER*)(ULONG_PTR)
		(ImageBase + Dos->e_lfanew + sizeof(NXC_FILE_HEADER) + File->SizeOfOptionalHeader);

	/*
	 * Lowest section RVA seen, which is where the header region ends. Tracked in the loop that has to
	 * visit every section anyway rather than read from the optional header -- see the header-page block
	 * after the loop for why that derivation is the safer of the two.
	 */
	UINT32 HeaderEnd = 0xFFFFFFFFu;

	for (UINT16 i = 0; i < File->NumberOfSections; i++)
	{
		CONST UINT32 Size = Section[i].VirtualSize ? Section[i].VirtualSize : Section[i].SizeOfRawData;
		if (Size == 0)
			continue;

		/*
		 * BOUND THE SECTION TO THE EXTENT WE ACTUALLY OWN, before it is used for anything.
		 *
		 * Section sizes are IMAGE-SUPPLIED and this runs on arbitrary module images. Beyond our
		 * extent is not unmapped memory that would fail safely -- in the arena it is the NEXT
		 * MODULE, whose pages are present, 4 KB backed, and would take the protections happily.
		 * A .bss-style section declaring an 8 MB VirtualSize would mark a neighbouring module's
		 * .text NX, and that module would fault on its next call with nothing pointing back here.
		 *
		 * MapModule does NOT catch this: it bounds VirtualAddress + SizeOfRawData, and `continue`s
		 * past SizeOfRawData == 0 sections without checking them at all -- which is exactly the
		 * shape that reaches here with an unbounded VirtualSize.
		 *
		 * Refused, not clamped. SizeOfImage covers every section by definition, so a section past it
		 * is malformed, and a malformed image is refused rather than partly honoured. With
		 * MapModule's fatal-on-refusal rule this rejects the whole module, which is the right
		 * outcome for an image that lied about its own layout.
		 */
		if ((UINT64)Section[i].VirtualAddress + Size > (UINT64)ImageSize)
		{
			(*Refused)++;
			NxcLog("protect: section %u (%.8s) rva %u +%u runs past SizeOfImage %u -- REFUSED\n",
			       i, Section[i].Name, Section[i].VirtualAddress, Size, ImageSize);
			continue;
		}

		if (Section[i].VirtualAddress < HeaderEnd)
			HeaderEnd = Section[i].VirtualAddress;

		/*
		 * The section's OWN characteristics decide. Not a policy we invent -- the linker already
		 * recorded what each section needs, and applying it is the entire fix. Note the deliberate
		 * consequence: a section marked both writable and executable stays RWX, because that is what
		 * the image asked for and silently overriding it would break the image rather than protect it.
		 */
		CONST BOOLEAN Writable   = (Section[i].Characteristics & NXC_SCN_MEM_WRITE)   ? TRUE : FALSE;
		CONST BOOLEAN Executable = (Section[i].Characteristics & NXC_SCN_MEM_EXECUTE) ? TRUE : FALSE;

		CONST NTSTATUS Status = NxcPteProtectRange(ImageBase + Section[i].VirtualAddress,
		                                           Size, Writable, Executable, BroadcastFlush);
		if (NT_SUCCESS(Status))
		{
			(*Applied)++;
		}
		else
		{
			/*
			 * Skip, do not abort. Refusing the whole image because one section sits on a large page
			 * would leave every other section RWX -- strictly worse than protecting what we can and
			 * REPORTING the count that was refused, which is why Refused is an out-parameter rather
			 * than a log line nobody reads.
			 */
			(*Refused)++;
			NxcLog("protect: section %u (%.8s) refused 0x%08X\n", i, Section[i].Name, Status);
		}
	}

	/*
	 * ============================================================================================
	 * THE HEADER PAGE -- RVA 0, belongs to no section, and was therefore never protected.
	 * ============================================================================================
	 *
	 * The loop above walks the SECTION TABLE, so it covers exactly the sections and nothing else. The
	 * PE headers sit below the first section at RVA 0 and fall through every iteration. MEASURED
	 * Second hardware boot: the image base page still read RWX with 7 of 7 sections
	 * applied, because the base page IS the header page and nothing had touched it.
	 *
	 * WHY THE RANGE IS DERIVED FROM THE SECTIONS rather than read from OptionalHeader.SizeOfHeaders:
	 * the first section's VirtualAddress is, by construction, the first SectionAlignment boundary at
	 * or after SizeOfHeaders. Using it covers the headers AND the alignment padding after them -- a
	 * gap SizeOfHeaders would have left RWX -- and it cannot overlap a section no matter what the
	 * optional header claims. It also needs no new struct offset (SizeOfHeaders lives at offset 60 of
	 * IMAGE_OPTIONAL_HEADER64, which our local NXC_FILE_HEADER does not model), and this file has
	 * already paid for one hand-derived constant -- see the page-index mask above.
	 *
	 * RO+NX stands on its own merits, independent of any stealth argument: once this function returns
	 * the headers are immutable reference data. Nothing writes them and nothing executes them, so W
	 * and X are permissions we hold for no reason. Note the section table stays READABLE -- we only
	 * clear W and set NX -- so this does not break the parse above or any later read.
	 *
	 * ⚠ DELIBERATELY NOT ZEROED, deferred rather than rejected. kdmapper and its forks zero
	 * SizeOfHeaders bytes before calling the entry point, which defeats a naive MZ/PE byte scan;
	 * RO+NX does not, the bytes stay readable. Reasons to wait: zeroing destroys the section table,
	 * unmap (task 10) is not written yet and may want it, and NxcPteProtectImage refuses an image with
	 * no MZ (see the e_magic check above) so a second call on the same image would fail. Decide it
	 * when teardown exists and its needs are known. measured: the detection vectors that
	 * actually find mapped images -- the PsLoadedModuleList walk in unKover, NMI stack walks -- never
	 * read headers, so the marginal value is small either way.
	 *
	 * NOT COUNTED in Applied/Refused: those report SECTIONS, and inflating the count with a
	 * non-section would make "7 applied" stop matching "7 sections". The durable record is the
	 * caller's re-measure of ImageBase, which reads this exact page.
	 */
	/*
	 * The >= one-page guard is not ceremony. Protection granularity is a page, so if a first section
	 * began below 0x1000 it would SHARE the header page, and "protect the headers R--" would silently
	 * strip write and execute from the start of that section instead. Every real x64 driver has
	 * SectionAlignment 0x1000 so this cannot trigger today. MapModule now REFUSES an image whose
	 * SectionAlignment is below a page (added by the same review that wrote this note, after it
	 * pointed out the gap and then only closed the header half of it), so a sub-page first section
	 * cannot reach here at all. The guard stays regardless: this function is reachable from
	 * NexusCore's own boot path too, and a check that costs one compare should not depend on a
	 * caller three files away continuing to validate its input.
	 */
	if (HeaderEnd != 0xFFFFFFFFu && HeaderEnd >= 0x1000)
	{
		CONST NTSTATUS HdrStatus = NxcPteProtectRange(ImageBase, HeaderEnd, FALSE, FALSE, BroadcastFlush);
		if (NT_SUCCESS(HdrStatus))
			NxcLog("protect: headers %p +%u -> R-- (covered by no section)\n",
			       (PVOID)(ULONG_PTR)ImageBase, HeaderEnd);
		else
			NxcLog("protect: headers refused 0x%08X -- left as mapped\n", HdrStatus);
	}
	else
	{
		NxcLog("protect: header region unbounded or under one page (first section rva %u)"
		       " -- headers left as mapped\n", HeaderEnd);
	}

	return STATUS_SUCCESS;
}
