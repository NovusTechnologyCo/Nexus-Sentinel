/**
 * @file Alias.c
 * @brief Writable alias mappings. Read Alias.h first -- especially why the textbook MDL path is out.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Alias.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define AliasLog NxcLogExt

#define NXC_ALIAS_TAG      'aAxN'
#define NXC_ALIAS_MAX_PAGES 64u    /* a hook needs one or two pages; a big span is a mistake */

/*
 * ⚠ SET BY HAND because we build the MDL by hand. MDL_PAGES_LOCKED tells the mapping call that the
 * PFN array is valid and the pages will not move -- which is TRUE here only because the caller
 * contract requires resident non-paged memory. It is an assertion we are making, not one the system
 * verified for us, which is exactly why Alias.h states that contract so loudly.
 */
#define NXC_MDL_PAGES_LOCKED  0x0002

NTSTATUS
NxcAliasCreate(
	_In_ UINT64 TargetVa,
	_In_ UINT32 Bytes,
	_Out_ NXC_ALIAS* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	if (TargetVa == 0 || Bytes == 0)
		return STATUS_INVALID_PARAMETER;

	CONST ULONG Pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES((PVOID)(ULONG_PTR)TargetVa, Bytes);
	if (Pages == 0 || Pages > NXC_ALIAS_MAX_PAGES)
	{
		AliasLog("alias: %u pages requested, cap is %u -- REFUSED\n", Pages, NXC_ALIAS_MAX_PAGES);
		return STATUS_INVALID_PARAMETER;
	}

	/*
	 * MDL plus its trailing PFN array, allocated as one block. Size computed rather than taken from
	 * MmSizeOfMdl so this path needs one export fewer -- the formula is the definition of the layout,
	 * not a guess about it.
	 */
	CONST SIZE_T MdlBytes = sizeof(MDL) + ((SIZE_T)Pages * sizeof(PFN_NUMBER));
	PMDL CONST Mdl = (PMDL)ExAllocatePool2(POOL_FLAG_NON_PAGED, MdlBytes, NXC_ALIAS_TAG);
	if (Mdl == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	MmInitializeMdl(Mdl, (PVOID)(ULONG_PTR)TargetVa, Bytes);

	/*
	 * Fill the PFN array from our own translations. THIS is what replaces MmProbeAndLockPages: the
	 * pages are already resident by contract, so there is nothing to probe -- and MmGetPhysicalAddress
	 * returns a value rather than raising, which the probe does not.
	 */
	PFN_NUMBER* CONST Pfns = MmGetMdlPfnArray(Mdl);
	CONST UINT64 FirstPage = TargetVa & ~0xFFFULL;

	for (ULONG i = 0; i < Pages; i++)
	{
		CONST PHYSICAL_ADDRESS Pa =
			MmGetPhysicalAddress((PVOID)(ULONG_PTR)(FirstPage + ((UINT64)i * PAGE_SIZE)));

		if (Pa.QuadPart == 0)
		{
			/*
			 * FAIL CLOSED. A zero physical address means the page is not mapped -- the caller broke
			 * the resident/non-paged contract. Mapping a zero PFN would alias physical page 0, which
			 * is real memory belonging to something else, and the write would land there.
			 */
			AliasLog("alias: page %u of %p has no physical address -- REFUSED (not resident?)\n",
			         i, (PVOID)(ULONG_PTR)TargetVa);
			ExFreePoolWithTag(Mdl, NXC_ALIAS_TAG);
			return STATUS_INVALID_PARAMETER;
		}

		Pfns[i] = (PFN_NUMBER)(Pa.QuadPart >> PAGE_SHIFT);
	}

	Mdl->MdlFlags |= NXC_MDL_PAGES_LOCKED;

	/*
	 * Reserve the VA FIRST. This is the call that is allowed to fail, and it fails by returning NULL
	 * -- which is the whole reason the design is shaped this way.
	 */
	void* CONST Reserved =
		MmAllocateMappingAddress((SIZE_T)Pages * PAGE_SIZE + PAGE_SIZE, NXC_ALIAS_TAG);
	if (Reserved == NULL)
	{
		ExFreePoolWithTag(Mdl, NXC_ALIAS_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* Maps into the reserved range, so it cannot fail for want of PTEs. Returns NULL, never raises. */
	void* CONST Writable = MmMapLockedPagesWithReservedMapping(Reserved, NXC_ALIAS_TAG,
	                                                           Mdl, MmCached);
	if (Writable == NULL)
	{
		MmFreeMappingAddress(Reserved, NXC_ALIAS_TAG);
		ExFreePoolWithTag(Mdl, NXC_ALIAS_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/*
	 * ⚠ PROVE THE MAPPING LANDS ON THE TARGET, HERE, AT PASSIVE_LEVEL.
	 *
	 * This check exists because its absence bugchecked the machine (IRQL_NOT_LESS_OR_EQUAL,
	 * 2026-07-29). A caller assumed WritableVa mapped the PAGE and added the page offset itself; the
	 * DDI actually returns an address that ALREADY includes the MDL's ByteOffset, so the offset was
	 * applied twice and the write landed outside the mapped page. That fault happened inside a
	 * KeIpiGenericCall broadcast, where a page fault is not an error path.
	 *
	 * Both VAs name the same physical bytes by construction, so they MUST read alike. Comparing them
	 * turns every member of that failure class -- wrong frames, wrong offset, a caller's arithmetic,
	 * a future change to how the MDL is built -- into a clean refusal at PASSIVE, where a wrong
	 * answer costs a return code instead of the machine.
	 *
	 * ⚠ A page being WRITTEN CONCURRENTLY could make this disagree spuriously. That is accepted: a
	 * false refusal is recoverable and says so, and the callers here alias code, which does not
	 * change underneath them. Refusing on a disagreement we cannot explain is the correct direction
	 * to be wrong in.
	 */
	CONST ULONG Check = (Bytes < 8) ? Bytes : 8;
	for (ULONG i = 0; i < Check; i++)
	{
		CONST UINT8 ViaAlias = ((volatile CONST UINT8*)Writable)[i];
		CONST UINT8 ViaOrig  = ((volatile CONST UINT8*)(ULONG_PTR)TargetVa)[i];
		if (ViaAlias != ViaOrig)
		{
			AliasLog("alias: %p reads 0x%02X at +%u but the alias %p reads 0x%02X -- the mapping is "
			         "NOT the target. REFUSED before anything can write through it.\n",
			         (PVOID)(ULONG_PTR)TargetVa, ViaOrig, i, Writable, ViaAlias);
			MmUnmapReservedMapping(Writable, NXC_ALIAS_TAG, Mdl);
			MmFreeMappingAddress(Reserved, NXC_ALIAS_TAG);
			ExFreePoolWithTag(Mdl, NXC_ALIAS_TAG);
			return STATUS_UNSUCCESSFUL;
		}
	}

	Out->Mdl        = Mdl;
	Out->Reserved   = Reserved;
	Out->WritableVa = Writable;
	Out->TargetVa   = TargetVa;
	Out->Bytes      = Bytes;
	Out->Pages      = Pages;

	AliasLog("alias: %p +%u -> writable %p (%u pages)\n",
	         (PVOID)(ULONG_PTR)TargetVa, Bytes, Writable, Pages);
	return STATUS_SUCCESS;
}

void
NxcAliasDestroy(
	_Inout_ NXC_ALIAS* Alias
	)
{
	/*
	 * ⚠ STRICT REVERSE ORDER, and every step is guarded so a half-built alias unwinds correctly.
	 * A failed create leaves a zeroed struct, so callers can call this unconditionally rather than
	 * having to remember which steps succeeded -- which is how an unmap gets skipped.
	 */
	if (Alias->WritableVa != NULL && Alias->Reserved != NULL)
		MmUnmapReservedMapping(Alias->WritableVa, NXC_ALIAS_TAG, (PMDL)Alias->Mdl);

	if (Alias->Reserved != NULL)
		MmFreeMappingAddress(Alias->Reserved, NXC_ALIAS_TAG);

	if (Alias->Mdl != NULL)
		ExFreePoolWithTag(Alias->Mdl, NXC_ALIAS_TAG);

	RtlZeroMemory(Alias, sizeof(*Alias));
}

NTSTATUS
NxcAliasSelfTest(
	_Out_ UINT32* OutDetail
	)
{
	*OutDetail = 0;

	/*
	 * ============================================================================================
	 * The proof. Uses a page WE allocated, so a bug here damages nothing but our own scratch page.
	 * ============================================================================================
	 *
	 * The calls succeeding proves nothing on its own -- a mapping that quietly pointed at DIFFERENT
	 * frames would also "succeed". What proves the primitive is that a write through the ALIAS is
	 * visible through the ORIGINAL address. That is the entire premise an inline hook rests on.
	 */
	UINT32* CONST Page = (UINT32*)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'sAxN');
	if (Page == NULL)
	{
		*OutDetail = 1;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	CONST UINT32 Original = 0xA5A5A5A5u;
	CONST UINT32 ViaAlias = 0x5A5A5A5Au;

	Page[0] = Original;

	NXC_ALIAS Alias;
	CONST NTSTATUS St = NxcAliasCreate((UINT64)(ULONG_PTR)Page, PAGE_SIZE, &Alias);
	if (!NT_SUCCESS(St))
	{
		AliasLog("alias: SELF-TEST could not create the alias (0x%08X)\n", St);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 2;
		return St;
	}

	/* Sanity: the alias must see what the original already holds. If not, it is mapping something
	 * else entirely and the write below would corrupt an unrelated page. */
	if (((volatile UINT32*)Alias.WritableVa)[0] != Original)
	{
		AliasLog("alias: SELF-TEST alias does NOT see the original's content -- WRONG FRAMES\n");
		NxcAliasDestroy(&Alias);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 3;
		return STATUS_UNSUCCESSFUL;
	}

	((volatile UINT32*)Alias.WritableVa)[0] = ViaAlias;

	/* THE ACTUAL PROOF: read back through the ORIGINAL mapping. */
	CONST UINT32 SeenViaOriginal = ((volatile UINT32*)Page)[0];

	NxcAliasDestroy(&Alias);

	if (SeenViaOriginal != ViaAlias)
	{
		AliasLog("alias: SELF-TEST FAILED -- wrote 0x%08X via the alias, original still reads "
		         "0x%08X. The two VAs do NOT share frames.\n", ViaAlias, SeenViaOriginal);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 4;
		return STATUS_UNSUCCESSFUL;
	}

	/* And the mapping must be GONE afterwards, or every hook would leak a writable window onto
	 * executable memory -- which is worse than the hook itself. */
	if (Alias.WritableVa != NULL || Alias.Reserved != NULL || Alias.Mdl != NULL)
	{
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 5;
		return STATUS_UNSUCCESSFUL;
	}

	/*
	 * ============================================================================================
	 * PHASE 2: THE SAME PROOF, AT A DELIBERATELY UNALIGNED OFFSET.
	 * ============================================================================================
	 *
	 * ⚠ THIS PHASE EXISTS BECAUSE PHASE 1 PASSED THROUGH A BUGCHECK.
	 *
	 * ExAllocatePool2 of PAGE_SIZE returns a PAGE-ALIGNED address, so everything above ran with a
	 * page offset of ZERO. A caller that added the page offset to WritableVa -- when the DDI already
	 * includes the MDL's ByteOffset in what it returns -- computed exactly the right address anyway,
	 * because adding zero twice is adding zero once. The test exercised the single case in which the
	 * defect is invisible, and reported green while the hook path wrote 4088 bytes out of bounds at
	 * IPI_LEVEL (IRQL_NOT_LESS_OR_EQUAL).
	 *
	 * 0x2A8 is chosen for having bits set across the whole offset field: a mapping that lost or
	 * doubled it lands somewhere obviously wrong rather than somewhere plausible.
	 *
	 * The lesson generalises past this file. A self-test whose fixture is the tidiest possible input
	 * is testing the case least likely to break.
	 */
	CONST ULONG Skew = 0x2A8;
	UINT8* CONST Spot = (UINT8*)Page + Skew;

	CONST UINT8 OrigByte  = 0xC7;
	CONST UINT8 AliasByte = 0x38;
	*(volatile UINT8*)Spot = OrigByte;

	NXC_ALIAS Skewed;
	CONST NTSTATUS SSt = NxcAliasCreate((UINT64)(ULONG_PTR)Spot, sizeof(UINT32), &Skewed);
	if (!NT_SUCCESS(SSt))
	{
		AliasLog("alias: SELF-TEST could not alias an UNALIGNED target (+0x%X): 0x%08X\n", Skew, SSt);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 6;
		return SSt;
	}

	/*
	 * ⚠ WritableVa MUST NAME `Spot` ITSELF, not the page containing it. This single comparison is
	 * the whole point of the phase: if the returned address were the page base, this reads whatever
	 * is at page+0 and fails immediately -- at PASSIVE, with a detail code, instead of at IPI_LEVEL
	 * with a bugcheck.
	 */
	if (((volatile CONST UINT8*)Skewed.WritableVa)[0] != OrigByte)
	{
		AliasLog("alias: SELF-TEST unaligned alias %p does not name +0x%X -- reads 0x%02X, "
		         "expected 0x%02X. The returned VA is not what the caller is told it is.\n",
		         Skewed.WritableVa, Skew, ((volatile CONST UINT8*)Skewed.WritableVa)[0], OrigByte);
		NxcAliasDestroy(&Skewed);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 7;
		return STATUS_UNSUCCESSFUL;
	}

	((volatile UINT8*)Skewed.WritableVa)[0] = AliasByte;
	CONST UINT8 SkewSeen = *(volatile CONST UINT8*)Spot;
	NxcAliasDestroy(&Skewed);

	if (SkewSeen != AliasByte)
	{
		AliasLog("alias: SELF-TEST unaligned write did not reach +0x%X (reads 0x%02X)\n",
		         Skew, SkewSeen);
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 8;
		return STATUS_UNSUCCESSFUL;
	}

	/* Nothing outside the four aliased bytes may have moved. A doubled or dropped offset that
	 * happened to land back inside the page would otherwise pass the checks above. */
	if (((volatile CONST UINT8*)Page)[0] != (UINT8)ViaAlias)
	{
		AliasLog("alias: SELF-TEST the unaligned write DISTURBED page+0 -- the offset is wrong\n");
		ExFreePoolWithTag(Page, 'sAxN');
		*OutDetail = 9;
		return STATUS_UNSUCCESSFUL;
	}

	ExFreePoolWithTag(Page, 'sAxN');
	AliasLog("alias: SELF-TEST PASSED -- aligned AND unaligned (+0x%X); writes through the alias "
	         "were visible through the original VA and touched nothing else\n", Skew);
	return STATUS_SUCCESS;
}
