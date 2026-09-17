/**
 * @file Kpages.c
 * @brief Per-page PTE facts for a loaded kernel image, vs its own section table. Reasoning in Kpages.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Kpages.h"
#include "MapModule.h"
#include "Pte.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define KpLog NxcLogExt

/*
 * PE bits, written out rather than included. ntddk.h does not bring in the image headers, and this is
 * the same reasoning NXC_RUNTIME_FUNCTION in Idt.h records: three constants is less risk than a
 * header that drags in a different world.
 */
#define IMAGE_SCN_MEM_EXECUTE   0x20000000u
#define IMAGE_SCN_MEM_WRITE     0x80000000u
#define NXC_IMAGE_DOS_MAGIC     0x5A4Du       /* 'MZ' */
#define NXC_IMAGE_NT_MAGIC      0x00004550u   /* 'PE\0\0' */
#define NXC_IMAGE_NT_OPT_64     0x20Bu

typedef struct _NXC_SEC
{
	CHAR   Name[8];
	UINT32 VirtualSize;
	UINT32 VirtualAddress;
	UINT32 Characteristics;
} NXC_SEC;

#define NXC_MAX_SECTIONS  32u

/**
 * Read the section table out of the image AS MAPPED.
 *
 * ⚠ EVERY FIELD IS BOUNDS-CHECKED AGAINST SizeOfImage BEFORE IT IS FOLLOWED. The headers of a driver
 * we are examining precisely because it may have been tampered with are not trustworthy input: an
 * e_lfanew of 0x7FFFFFFF would walk this straight out of the image and into whatever follows. There
 * is no SEH here to catch that.
 */
static UINT32
ReadSections(
	_In_ UINT64 Base,
	_In_ UINT32 Size,
	_Out_writes_(NXC_MAX_SECTIONS) NXC_SEC* Out
	)
{
	if (Size < 0x400)
		return 0;

	CONST UINT8* CONST Img = (CONST UINT8*)(ULONG_PTR)Base;

	if (*(CONST UINT16*)Img != NXC_IMAGE_DOS_MAGIC)
		return 0;

	CONST UINT32 Lfanew = *(CONST UINT32*)(Img + 0x3C);
	/* +0x108 covers the NT signature, file header and a 64-bit optional header. */
	if (Lfanew < 0x40 || Lfanew > Size - 0x108)
		return 0;

	CONST UINT8* CONST Nt = Img + Lfanew;
	if (*(CONST UINT32*)Nt != NXC_IMAGE_NT_MAGIC)
		return 0;

	CONST UINT16 NumSections = *(CONST UINT16*)(Nt + 0x06);
	CONST UINT16 OptSize     = *(CONST UINT16*)(Nt + 0x14);
	CONST UINT16 OptMagic    = *(CONST UINT16*)(Nt + 0x18);

	if (OptMagic != NXC_IMAGE_NT_OPT_64)
		return 0;   /* PE32 here would mean the wrong image entirely */
	if (NumSections == 0 || NumSections > NXC_MAX_SECTIONS)
		return 0;

	CONST UINT64 TableOff = (UINT64)Lfanew + 0x18 + OptSize;
	if (TableOff + (UINT64)NumSections * 40u > (UINT64)Size)
		return 0;

	CONST UINT8* Sec = Img + TableOff;
	for (UINT32 i = 0; i < NumSections; i++, Sec += 40)
	{
		for (UINT32 c = 0; c < 8; c++)
			Out[i].Name[c] = (CHAR)Sec[c];
		Out[i].VirtualSize     = *(CONST UINT32*)(Sec + 0x08);
		Out[i].VirtualAddress  = *(CONST UINT32*)(Sec + 0x0C);
		Out[i].Characteristics = *(CONST UINT32*)(Sec + 0x24);
	}

	return NumSections;
}

NTSTATUS
NxcKpages(
	_In_z_ CONST CHAR* Name,
	_Out_writes_(Cap) NXCMD_KPAGE* Out,
	_In_ UINT32 Cap,
	_In_ UINT32 SkipPages,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT64* OutBase,
	_Out_ UINT32* OutSize
	)
{
	*Got     = 0;
	*Total   = 0;
	*OutBase = 0;
	*OutSize = 0;

	if (Out == NULL || Cap == 0 || Name == NULL)
		return STATUS_INVALID_PARAMETER;

	UINT64 Base = 0;
	ULONG  Size = 0;
	CONST NTSTATUS FSt = NxcFindKernelModule(Name, &Base, &Size);
	if (!NT_SUCCESS(FSt))
		return FSt;

	*OutBase = Base;
	*OutSize = (UINT32)Size;

	CONST UINT32 Pages = (UINT32)((Size + 0xFFFu) / 0x1000u);
	*Total = Pages;

	NXC_SEC Sec[NXC_MAX_SECTIONS];
	RtlZeroMemory(Sec, sizeof(Sec));
	CONST UINT32 NumSec = ReadSections(Base, (UINT32)Size, Sec);

	if (NumSec == 0)
		KpLog("kpages: %s -- section table unreadable; PTE facts still reported, expectations are "
		      "NOT (a page with no known expectation cannot produce a mismatch)\n", Name);

	UINT32 Wrote = 0;

	for (UINT32 p = SkipPages; p < Pages && Wrote < Cap; p++)
	{
		CONST UINT64 Va = Base + ((UINT64)p * 0x1000ULL);
		NXCMD_KPAGE* CONST K = &Out[Wrote];

		RtlZeroMemory(K, sizeof(*K));
		K->Va = Va;

		NXC_PTE_INFO Info;
		RtlZeroMemory(&Info, sizeof(Info));

		if (!NT_SUCCESS(NxcPteQuery(Va, &Info)) || (Info.Flags & NXC_PTE_VALID) == 0)
		{
			/*
			 * ⚠ A HOLE INSIDE SizeOfImage IS A FACT, NOT AN ERROR, and it is reported rather than
			 * skipped. Discarded-section pages legitimately vanish after boot (INIT is the obvious
			 * one), so this is usually ordinary -- but it is also what a page unmapped out from
			 * under a driver looks like, and skipping would make those two indistinguishable.
			 */
			K->Mismatch = NXCMD_KPAGE_MM_NOT_MAPPED;
			Wrote++;
			continue;
		}

		K->Pfn      = Info.Pfn;
		K->PteFlags = Info.Flags;

		/* --- what the image's own headers say this page should be --- */
		CONST UINT32 Rva = (UINT32)(Va - Base);
		for (UINT32 i = 0; i < NumSec; i++)
		{
			CONST UINT32 Lo = Sec[i].VirtualAddress;
			CONST UINT32 Hi = Sec[i].VirtualAddress + Sec[i].VirtualSize;
			if (Rva < Lo || Rva >= Hi)
				continue;

			K->Expected |= NXCMD_KPAGE_EXP_KNOWN;
			if (Sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   K->Expected |= NXCMD_KPAGE_EXP_WRITE;
			if (Sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) K->Expected |= NXCMD_KPAGE_EXP_EXECUTE;

			for (UINT32 c = 0; c < 8; c++)
				K->Section[c] = (NXCMD_U8)Sec[i].Name[c];

			/*
			 * Does the page also reach into the NEXT section? Sections are not required to be page
			 * aligned in memory, so a page can belong to two of them -- and then no single
			 * expectation is correct for it.
			 */
			if (Rva + 0x1000u > Hi)
				K->Expected |= NXCMD_KPAGE_EXP_STRADDLE;

			break;
		}

		/* --- actual vs expected --- */
		CONST BOOLEAN ActW = (K->PteFlags & NXC_PTE_WRITABLE) != 0;
		CONST BOOLEAN ActX = (K->PteFlags & NXC_PTE_EXECUTE)  != 0;
		CONST BOOLEAN Large = (K->PteFlags & (NXC_PTE_LARGE_2M | NXC_PTE_LARGE_1G)) != 0;

		if (ActW && ActX)
		{
			/*
			 * ⚠ SPLIT, NOT COMBINED. On a large page W+X is FORCED -- one protection covers 2 MB, so
			 * .text and .data share it and Windows does exactly this to ntoskrnl and hal by default.
			 * On a 4 KB page nothing forces it and the loader would not have chosen it. Reporting one
			 * number for both would put ntoskrnl at the top of every run and teach the reader that
			 * the number means nothing.
			 */
			K->Mismatch |= Large ? NXCMD_KPAGE_MM_WX_LARGE : NXCMD_KPAGE_MM_WX_4K;
		}

		if (K->PteFlags & NXC_PTE_USER)
			K->Mismatch |= NXCMD_KPAGE_MM_USER;

		/*
		 * ⚠ EXPECTATION CHECKS ARE SKIPPED FOR STRADDLING PAGES AND FOR LARGE ONES, and both
		 * exclusions are principled rather than convenient:
		 *
		 *   - a straddling page has two conflicting expectations, so any verdict is wrong for part
		 *     of it;
		 *   - a large page has ONE protection for 2 MB spanning many sections, so it cannot match a
		 *     per-section expectation even on a completely healthy image.
		 *
		 * Including either would generate mismatches from layout, which is worse than missing some:
		 * a detector whose output is mostly artefacts is a detector nobody reads.
		 */
		if ((K->Expected & NXCMD_KPAGE_EXP_KNOWN) &&
		    !(K->Expected & NXCMD_KPAGE_EXP_STRADDLE) &&
		    !Large)
		{
			CONST BOOLEAN ExpW = (K->Expected & NXCMD_KPAGE_EXP_WRITE)   != 0;
			CONST BOOLEAN ExpX = (K->Expected & NXCMD_KPAGE_EXP_EXECUTE) != 0;

			if (ActW && !ExpW) K->Mismatch |= NXCMD_KPAGE_MM_WRITE;
			if (ActX && !ExpX) K->Mismatch |= NXCMD_KPAGE_MM_EXECUTE;

			/*
			 * The reverse direction too. A .text page that is NOT executable is not what an attacker
			 * leaves behind, but it is what a FAILED or partial patch leaves behind -- and reporting
			 * only the alarming direction would make the tool blind to its own kind of mistake.
			 */
			if (!ActX && ExpX) K->Mismatch |= NXCMD_KPAGE_MM_NOT_EXEC;
		}

		Wrote++;
	}

	*Got = Wrote;

	KpLog("kpages: %s at %llX (%u bytes, %u pages) -- %u reported from index %u, %u section(s)\n",
	      Name, Base, (UINT32)Size, Pages, Wrote, SkipPages, NumSec);
	return STATUS_SUCCESS;
}
