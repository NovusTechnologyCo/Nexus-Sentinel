/**
 * @file Translate.c
 * @brief Foreign-process VA -> PA. The design reasoning lives in Translate.h -- read it first.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "Translate.h"
#include "PhysMem.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define XlatLog NxcLogExt

/* Physical frame field of a page-table entry: bits 51:12. Bits 63:52 are flags/NX, 11:0 are flags. */
#define NXC_PTE_PFN_MASK   0x000FFFFFFFFFF000ULL

/* Large-page frame masks: a 2 MB PDE ignores bits 20:12, a 1 GB PDPTE ignores bits 29:12. */
#define NXC_PDE_2MB_MASK   0x000FFFFFFFE00000ULL
#define NXC_PDPTE_1GB_MASK 0x000FFFFFC0000000ULL

#define NXC_PTE_P          0x0000000000000001ULL
#define NXC_PTE_RW         0x0000000000000002ULL
#define NXC_PTE_US         0x0000000000000004ULL
#define NXC_PTE_A          0x0000000000000020ULL
#define NXC_PTE_D          0x0000000000000040ULL
#define NXC_PTE_PS         0x0000000000000080ULL
#define NXC_PTE_G          0x0000000000000100ULL
#define NXC_PTE_NX         0x8000000000000000ULL

static UINT32  gDtbOffset = 0;
static BOOLEAN gDtbProven = FALSE;

/** Read one 8-byte page-table entry at a physical address. Gated -- see PhysMem.h. */
static NTSTATUS
ReadEntry(
	_In_ UINT64 Pa,
	_Out_ UINT64* Entry
	)
{
	*Entry = 0;

	SIZE_T Got = 0;
	CONST NTSTATUS St = NxcPhysRead(Pa, Entry, sizeof(UINT64), &Got);
	if (!NT_SUCCESS(St))
		return St;

	/* A partial read of an 8-byte entry is not a usable entry. Treat it as unreadable rather than
	 * act on half of one -- a truncated entry decodes to a valid-looking frame number. */
	if (Got != sizeof(UINT64))
		return STATUS_PARTIAL_COPY;

	return STATUS_SUCCESS;
}

/*
 * Windows software-PTE bits. Only meaningful when the Present bit is CLEAR -- with Present set,
 * bit 10 is a free-for-OS bit and bit 11 is likewise, so testing them on a valid entry reads
 * whatever the memory manager happened to leave there.
 */
#define NXC_SWPTE_PROTOTYPE   (1ULL << 10)
#define NXC_SWPTE_TRANSITION  (1ULL << 11)
#define NXC_SWPTE_PROT_MASK   (0x1FULL << 5)    /* MMPTE_SOFTWARE.Protection, bits 9:5 */

/**
 * Classify an entry whose Present bit is clear.
 *
 * ⚠ ORDER OF TESTS IS LOAD-BEARING. Transition is checked BEFORE prototype because a transition PTE
 * describes a page that is STILL IN RAM, which is a stronger and more actionable fact than "this is
 * shared" -- and the two bits are not mutually exclusive in every Windows encoding. Getting the
 * order backwards would report a recoverable in-RAM page as needing a prototype dereference.
 *
 * ⚠ NO ADDRESS IS EXTRACTED, DELIBERATELY. See the InvalidPteMask / L1TF note in Translate.h: the
 * PFN and PageFileHigh fields of an invalid PTE have been masked by the memory manager and are not
 * recoverable without an unexported global. The state is the evidence; a fabricated location would
 * not be.
 */
static UINT32
ClassifySoftwarePte(
	_In_ UINT64 Entry
	)
{
	if (Entry == 0)
		return NXC_SW_ZERO;

	if (Entry & NXC_SWPTE_TRANSITION)
		return NXC_SW_TRANSITION;

	if (Entry & NXC_SWPTE_PROTOTYPE)
		return NXC_SW_PROTOTYPE;

	/*
	 * ⚠⚠ PAGEFILE-BACKED AND DEMAND-ZERO ARE NOT SEPARABLE HERE, AND SAYING SO IS THE POINT.
	 *
	 * The textbook discriminator is whether the high bits carry a PageFileHigh offset -- a pagefile
	 * PTE has one, a demand-zero PTE does not. That test is WRONG on this machine and would have
	 * been a confident, well-formed lie: Windows' L1TF / Foreshadow mitigation SETS high
	 * physical-address bits in every not-present PTE, so `(Entry >> 32) != 0` is true of ALL of them
	 * and every demand-zero page would have been reported as pagefile-backed.
	 *
	 * (Written down because I wrote that exact test first, in the same file as a comment warning
	 * that an invalid PTE's address fields are masked. Knowing the constraint is not the same as
	 * applying it.)
	 *
	 * Undoing the mask needs `nt!MiState.Hardware.InvalidPteMask`, which is not exported. So the two
	 * states are reported as ONE, honestly named, rather than split on a test that cannot work. It
	 * is still the fact that matters: committed, not resident, and NOT the zero-PTE case that this
	 * phase is actually hunting.
	 */
	return NXC_SW_NOT_RESIDENT;
}

/**
 * The walk itself, given an explicit CR3. Split out so the proof in NxcTranslateInit can call it
 * before the DTB offset is trusted -- the proof must not depend on the thing it is proving.
 */
static NTSTATUS
WalkWithCr3(
	_In_ UINT64 Cr3,
	_In_ UINT64 Va,
	_Out_ NXC_XLAT* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));
	Out->Cr3 = Cr3;

	CONST UINT64 Base = Cr3 & NXC_PTE_PFN_MASK;
	if (Base == 0)
		return STATUS_INVALID_PARAMETER;

	CONST UINT32 Idx[4] = {
		(UINT32)((Va >> 39) & 0x1FF),   /* PML4E */
		(UINT32)((Va >> 30) & 0x1FF),   /* PDPTE */
		(UINT32)((Va >> 21) & 0x1FF),   /* PDE   */
		(UINT32)((Va >> 12) & 0x1FF),   /* PTE   */
	};

	/*
	 * Effective permissions accumulate ACROSS the levels: write requires RW at every level, execute
	 * is denied if NX is set at ANY level. Seeded permissive and narrowed as we descend, so the
	 * reported flags are what the CPU would actually enforce rather than the leaf entry's bits.
	 */
	BOOLEAN EffWrite = TRUE;
	BOOLEAN EffUser  = TRUE;
	BOOLEAN EffNx    = FALSE;

	UINT64 TableBase = Base;

	for (UINT32 Level = 0; Level < 4; Level++)
	{
		UINT64 Entry = 0;
		CONST NTSTATUS St = ReadEntry(TableBase + ((UINT64)Idx[Level] * 8), &Entry);
		if (!NT_SUCCESS(St))
		{
			Out->FailedLevel = Level + 1;
			XlatLog("xlat: VA 0x%llX -- level %u table read failed 0x%08X\n", Va, Level + 1, St);
			return (St == STATUS_INVALID_ADDRESS) ? STATUS_INVALID_ADDRESS : St;
		}

		Out->Entries[Level] = Entry;

		if ((Entry & NXC_PTE_P) == 0)
		{
			Out->FailedLevel = Level + 1;
			Out->SoftState   = ClassifySoftwarePte(Entry);
			return STATUS_NOT_FOUND;
		}

		if ((Entry & NXC_PTE_RW) == 0) EffWrite = FALSE;
		if ((Entry & NXC_PTE_US) == 0) EffUser  = FALSE;
		if ((Entry & NXC_PTE_NX) != 0) EffNx    = TRUE;

		/*
		 * PS at PDPTE (level 2) or PDE (level 3) terminates the walk at a large page. PS is RESERVED
		 * at PML4E and means something else entirely at PTE (it is PAT there), so it is only
		 * consulted at the two levels where it is defined -- testing it blindly at every level would
		 * misread a PTE with PAT set as a large page.
		 */
		if ((Level == 1 || Level == 2) && (Entry & NXC_PTE_PS) != 0)
		{
			CONST UINT64 Mask   = (Level == 1) ? NXC_PDPTE_1GB_MASK : NXC_PDE_2MB_MASK;
			CONST UINT64 Offset = (Level == 1) ? (Va & 0x3FFFFFFFULL) : (Va & 0x1FFFFFULL);

			Out->PhysicalAddress = (Entry & Mask) + Offset;
			Out->Level = Level + 1;          /* 2 = 1 GB, 3 = 2 MB -- matches NXC_PTE_INFO's scheme */
			Out->Flags = NXC_XLAT_PRESENT | NXC_XLAT_LARGE_PAGE
			           | (EffWrite ? NXC_XLAT_WRITABLE : 0u)
			           | (EffUser  ? NXC_XLAT_USER     : 0u)
			           | (EffNx    ? NXC_XLAT_NX       : 0u)
			           | ((Entry & NXC_PTE_A) ? NXC_XLAT_ACCESSED : 0u)
			           | ((Entry & NXC_PTE_D) ? NXC_XLAT_DIRTY    : 0u)
			           | ((Entry & NXC_PTE_G) ? NXC_XLAT_GLOBAL   : 0u);
			return STATUS_SUCCESS;
		}

		if (Level == 3)
		{
			Out->PhysicalAddress = (Entry & NXC_PTE_PFN_MASK) + (Va & 0xFFFULL);
			Out->Level = 4;
			Out->Flags = NXC_XLAT_PRESENT
			           | (EffWrite ? NXC_XLAT_WRITABLE : 0u)
			           | (EffUser  ? NXC_XLAT_USER     : 0u)
			           | (EffNx    ? NXC_XLAT_NX       : 0u)
			           | ((Entry & NXC_PTE_A) ? NXC_XLAT_ACCESSED : 0u)
			           | ((Entry & NXC_PTE_D) ? NXC_XLAT_DIRTY    : 0u)
			           | ((Entry & NXC_PTE_G) ? NXC_XLAT_GLOBAL   : 0u);
			return STATUS_SUCCESS;
		}

		TableBase = Entry & NXC_PTE_PFN_MASK;
	}

	/* Unreachable: level 3 always returns. Present so a future edit that breaks that is not silent. */
	Out->FailedLevel = 4;
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NxcTranslateInit(
	VOID
	)
{
	if (gDtbProven)
		return STATUS_SUCCESS;

	CONST UINT64 Cr3 = __readcr3() & NXC_PTE_PFN_MASK;
	if (Cr3 == 0)
	{
		XlatLog("xlat: CR3 reads 0 -- cannot derive the DTB offset\n");
		return STATUS_UNSUCCESSFUL;
	}

	CONST UINT8* CONST Self = (CONST UINT8*)PsGetCurrentProcess();
	if (Self == NULL)
		return STATUS_UNSUCCESSFUL;

	/*
	 * Scan for a QWORD whose FRAME matches CR3's. Range covers every x64 build's DirectoryTableBase
	 * (0x28 for many years) with generous slack, and stops well short of the far larger offsets where
	 * an unrelated pointer could coincidentally match.
	 *
	 * ⚠ BOTH SIDES ARE MASKED TO THE FRAME, and comparing the raw values would be a latent failure on
	 * this very machine. When CR4.PCIDE is set -- which modern Windows does -- CR3 carries a PROCESS
	 * CONTEXT IDENTIFIER in bits 11:0, so __readcr3() returns a value whose low bits are not part of
	 * the address at all. The stored DirectoryTableBase may or may not carry the same low bits.
	 * Comparing raw would then match nothing, the probe would report "found 0 candidates", and the
	 * whole va2pa surface would fail closed for a reason that has nothing to do with the offset being
	 * wrong. Masking both sides compares the only thing that is actually the same fact: the frame.
	 *
	 * This does not weaken the check. Uniqueness is still required, and the winner is still PROVEN
	 * against MmGetPhysicalAddress below -- masking can only make the right field findable, never
	 * make a wrong one acceptable.
	 */
	UINT32 Candidate = 0;
	UINT32 Matches   = 0;
	for (UINT32 Off = 0x08; Off <= 0x100; Off += 8)
	{
		UINT64 Value = 0;
		SIZE_T Got = 0;
		MM_COPY_ADDRESS Src;
		Src.VirtualAddress = (PVOID)(Self + Off);

		/* MmCopyMemory, not a dereference: EPROCESS is ours to read, but this driver has no SEH and
		 * a status-returning read costs nothing here. */
		if (!NT_SUCCESS(MmCopyMemory(&Value, Src, sizeof(Value), MM_COPY_MEMORY_VIRTUAL, &Got)) ||
		    Got != sizeof(Value))
			continue;

		if ((Value & NXC_PTE_PFN_MASK) == Cr3)
		{
			Matches++;
			Candidate = Off;
		}
	}

	if (Matches != 1)
	{
		/*
		 * FAIL CLOSED on zero AND on two. Two candidates means the scan cannot tell them apart, and
		 * picking one would be a coin toss whose wrong side reads a neighbouring field forever.
		 */
		XlatLog("xlat: DTB offset derivation found %u candidates (need exactly 1) -- REFUSED\n",
		        Matches);
		return STATUS_NOT_FOUND;
	}

	/*
	 * ============================================================================================
	 * PROVE IT. An INDEPENDENT oracle, not a second copy of our own arithmetic.
	 * ============================================================================================
	 *
	 * A non-paged pool page is allocated purely so there is a VA guaranteed resident, then translated
	 * two ways: by this file's walk, and by the kernel's own MmGetPhysicalAddress. Agreement proves
	 * the offset, the entry format, the index arithmetic and the large-page handling together --
	 * including a shared misunderstanding, which a check against a reference implementation of the
	 * same walk could never catch.
	 */
	PVOID CONST Probe = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'xPxN');
	if (Probe == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	CONST PHYSICAL_ADDRESS Truth = MmGetPhysicalAddress(Probe);

	NXC_XLAT Walk;
	CONST NTSTATUS WalkSt = WalkWithCr3(Cr3, (UINT64)(ULONG_PTR)Probe, &Walk);

	ExFreePoolWithTag(Probe, 'xPxN');

	if (!NT_SUCCESS(WalkSt))
	{
		XlatLog("xlat: PROOF FAILED -- walk of our own page returned 0x%08X at level %u\n",
		        WalkSt, Walk.FailedLevel);
		return WalkSt;
	}

	if ((UINT64)Truth.QuadPart != Walk.PhysicalAddress)
	{
		XlatLog("xlat: PROOF FAILED -- walk says 0x%llX, MmGetPhysicalAddress says 0x%llX "
		        "(candidate offset 0x%X)\n",
		        Walk.PhysicalAddress, (UINT64)Truth.QuadPart, Candidate);
		return STATUS_UNSUCCESSFUL;
	}

	gDtbOffset = Candidate;
	gDtbProven = TRUE;
	XlatLog("xlat: DTB offset 0x%X PROVEN (walk == MmGetPhysicalAddress at 0x%llX, level %u)\n",
	        Candidate, Walk.PhysicalAddress, Walk.Level);
	return STATUS_SUCCESS;
}

UINT32
NxcTranslateDtbOffset(
	VOID
	)
{
	/*
	 * ⚠⚠ PROVES ON DEMAND. This used to return 0 whenever nothing had happened to call
	 * NxcTranslateInit() yet -- and the ONLY caller of that is NxcTranslateProcess, deep inside a
	 * translate. So the offset was proven as a SIDE EFFECT of having previously run `read`,
	 * `va2pa` or similar, and any caller that merely ASKED for it on a fresh boot got 0.
	 *
	 * `bp set` is exactly such a caller, and it refused for that reason on a clean
	 * boot -- reported, wrongly, as "no #DB handler is installed" because both refusals shared
	 * STATUS_DEVICE_NOT_READY. Item 15 was complete and the hook was live; the message sent the
	 * reader back to finished work.
	 *
	 * An accessor whose answer depends on whether an unrelated command ran earlier is an ordering
	 * trap, not an accessor. Proving here removes the ordering entirely: it is idempotent, it is
	 * cheap after the first success (a bool test), and no caller can now read an unproven value by
	 * forgetting a call it has no reason to know about.
	 */
	if (!gDtbProven)
		(void)NxcTranslateInit();

	return gDtbProven ? gDtbOffset : 0;
}

NTSTATUS
NxcTranslate(
	_In_ PVOID Process,
	_In_ UINT64 Va,
	_Out_ NXC_XLAT* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	if (Process == NULL)
		return STATUS_INVALID_PARAMETER;

	/* Derive on first use rather than at DriverEntry: this is not on the boot path, and a failure
	 * here should surface to the caller that wanted a translation, not stall the map. */
	CONST NTSTATUS InitSt = NxcTranslateInit();
	if (!NT_SUCCESS(InitSt))
		return InitSt;

	UINT64 Cr3 = 0;
	SIZE_T Got = 0;
	MM_COPY_ADDRESS Src;
	Src.VirtualAddress = (PVOID)((CONST UINT8*)Process + gDtbOffset);

	if (!NT_SUCCESS(MmCopyMemory(&Cr3, Src, sizeof(Cr3), MM_COPY_MEMORY_VIRTUAL, &Got)) ||
	    Got != sizeof(Cr3))
	{
		XlatLog("xlat: could not read DirectoryTableBase from EPROCESS %p\n", Process);
		return STATUS_UNSUCCESSFUL;
	}

	if ((Cr3 & NXC_PTE_PFN_MASK) == 0)
	{
		/*
		 * A process whose DirectoryTableBase reads 0 has been torn down -- its address space is gone
		 * even though the EPROCESS is still referenced. Reported distinctly because "the process
		 * exited" and "the VA is not mapped" are different answers to the caller's question.
		 */
		XlatLog("xlat: EPROCESS %p has no address space (DTB 0) -- terminated?\n", Process);
		return STATUS_PROCESS_IS_TERMINATING;
	}

	return WalkWithCr3(Cr3, Va, Out);
}
