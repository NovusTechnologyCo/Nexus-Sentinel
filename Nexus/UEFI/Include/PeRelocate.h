/**
 * @file PeRelocate.h
 * @brief Apply PE base relocations to an already-mapped image. Shared by the Loader and the DXE.
 *
 * WHY SHARED: scope item 4c manual-maps the DXE so the firmware never records it --
 * no PCR[2] measurement, no entry in the UEFI loaded-image list. That splits relocation across TWO
 * images that must agree exactly:
 *
 *   - the LOADER relocates the freshly mapped DXE from its preferred base to wherever we put it;
 *   - the DXE relocates ITSELF at SetVirtualAddressMap, because a manually-mapped image is NOT in
 *     the firmware's runtime-image list and so nobody else will.
 *
 * That second one is the fragile heart of 4c. `gBS->LoadImage` normally buys you firmware
 * relocation at SetVirtualAddressMap for free; skip LoadImage and you inherit the job. Get it wrong
 * and the first runtime GetVariable call after Windows switches to virtual addressing jumps into an
 * address that no longer exists.
 *
 * Two copies of this walk would be free to drift, and a drift between them is not a compile error --
 * it is a machine that boots until the moment it does not. Hence one header, one implementation.
 *
 * DELTAS COMPOSE: applying delta A then delta B leaves the image correct for A+B. That is what makes
 * the two-stage arrangement above valid -- the Loader's physical fixup and the DXE's virtual fixup
 * are independent applications of the same table.
 */

#pragma once

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>

/**
 * Apply every base relocation in Image's .reloc directory, shifting absolute addresses by Delta.
 *
 * @param ImageBase  start of the MAPPED image (not the raw file)
 * @param ImageSize  its size, used purely to bound the walk
 * @param Delta      value to add to each relocated address
 *
 * @retval TRUE   applied, or nothing to do (Delta == 0, or the image is relocation-free)
 * @retval FALSE  the relocation data is malformed -- caller must treat the image as unusable
 *
 * ⚠ MUST NOT ALLOCATE OR CALL BOOT SERVICES. The DXE calls this from its SetVirtualAddressMap
 * callback, after ExitBootServices, where neither is available.
 */
STATIC
BOOLEAN
ApplyPeRelocations(
	IN UINT8* ImageBase,
	IN UINTN ImageSize,
	IN INT64 Delta
	)
{
	if (ImageBase == NULL)
		return FALSE;
	if (Delta == 0)
		return TRUE;                       // already where it wants to be

	CONST EFI_IMAGE_DOS_HEADER* Dos = (CONST EFI_IMAGE_DOS_HEADER*)ImageBase;
	if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE || (UINTN)Dos->e_lfanew >= ImageSize)
		return FALSE;

	CONST EFI_IMAGE_NT_HEADERS64* Nt =
		(CONST EFI_IMAGE_NT_HEADERS64*)(ImageBase + Dos->e_lfanew);
	if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE ||
		Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return FALSE;

	CONST EFI_IMAGE_DATA_DIRECTORY* Dir =
		&Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (Dir->VirtualAddress == 0 || Dir->Size == 0)
		return TRUE;                       // no relocations: nothing to fix, not an error

	if ((UINTN)Dir->VirtualAddress >= ImageSize ||
		(UINTN)Dir->VirtualAddress + Dir->Size > ImageSize)
		return FALSE;

	UINTN Offset = 0;
	while (Offset + sizeof(EFI_IMAGE_BASE_RELOCATION) <= Dir->Size)
	{
		CONST EFI_IMAGE_BASE_RELOCATION* Block =
			(CONST EFI_IMAGE_BASE_RELOCATION*)(ImageBase + Dir->VirtualAddress + Offset);

		//
		// A zero or undersized block terminates the table. Treating it as valid would loop forever.
		//
		if (Block->SizeOfBlock < sizeof(EFI_IMAGE_BASE_RELOCATION) ||
			Offset + Block->SizeOfBlock > Dir->Size)
			break;

		CONST UINTN Count =
			(Block->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
		CONST UINT16* Entries =
			(CONST UINT16*)((CONST UINT8*)Block + sizeof(EFI_IMAGE_BASE_RELOCATION));

		for (UINTN i = 0; i < Count; i++)
		{
			CONST UINT16 Type = (UINT16)(Entries[i] >> 12);
			CONST UINTN Where = (UINTN)Block->VirtualAddress + (Entries[i] & 0x0FFF);

			//
			// EFI_IMAGE_REL_BASED_ABSOLUTE is padding and carries no fixup -- skip it silently.
			// x64 PE images produced by MSVC use DIR64 for everything else; anything other type
			// means we do not understand this image and must not guess.
			//
			if (Type == EFI_IMAGE_REL_BASED_ABSOLUTE)
				continue;
			if (Type != EFI_IMAGE_REL_BASED_DIR64)
				return FALSE;

			if (Where + sizeof(UINT64) > ImageSize)
				return FALSE;

			UINT64* Target = (UINT64*)(ImageBase + Where);
			*Target = (UINT64)((INT64)*Target + Delta);
		}

		Offset += Block->SizeOfBlock;
	}

	return TRUE;
}
