//
// NexusPe -- PE/COFF parsing for the boot DXE. See NexusPe.h for the mapped-vs-file rules.
//
// Written from the Microsoft PE/COFF specification and the x64 ABI's exception-handling
// chapter, and validated against a host prototype exercised on four ntoskrnl builds across
// two Windows releases. Replaces pe.c (EfiGuard-derived, GPLv3).
//
// Everything here is defensive on purpose. These routines parse an image that another
// component produced, and their answers are used to WRITE to kernel memory. A wrong answer
// is not a failed patch, it is a patch applied somewhere else.
//

//
// Deliberately narrow includes: NexusPe.h plus BaseLib for AsciiStrCmp, and nothing else.
// This file pulls in no Nexus state and no DXE services, which is what lets the same source
// be compiled and exercised on the host against real ntoskrnl images.
//
#include "NexusPe.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>


//
// Intel SDM vol. 4: IA32_EFER. Bit 20 is Upper Address Ignore Enable -- when set, the CPU
// ignores the upper address bits instead of faulting, so no address is "non-canonical" in
// the sense that matters here. Defined locally rather than pulled from util.h so this file
// keeps its narrow include list and no dependency on the other file being replaced.
//
#define NEXUS_MSR_EFER      ((UINT32)0xC0000080)
#define NEXUS_EFER_UAIE     ((UINT64)0x00100000)

//
// Intel SDM vol. 3: CR4.LA57 (bit 12) selects 5-level paging, i.e. 57-bit linear addresses.
//
// Implemented here rather than calling util.h's IsFiveLevelPagingEnabled(), because util.c
// is the other EfiGuard-derived file and is next to go. Depending on it would put this file
// back in the dependency it exists to remove. It is one CR4 bit defined by the SDM.
//
#define NEXUS_CR4_LA57      ((UINTN)0x00001000)

STATIC
BOOLEAN
NexusPeIsFiveLevelPaging(
	VOID
	)
{
	return (BOOLEAN)((AsmReadCr4() & NEXUS_CR4_LA57) != 0);
}


BOOLEAN
EFIAPI
NexusPeIsCanonicalForBits(
	IN UINTN Address,
	IN UINTN LinearAddressBits
	)
{
	//
	// Canonical means bits 63:SignBit are all copies of the sign bit, so an arithmetic
	// shift right by SignBit leaves either all zeroes (0) or all ones (-1). Adding 1 maps
	// those to 1 and 0, and every other value to something that is >1 once unsigned.
	//
	CONST UINTN SignBit = LinearAddressBits - 1;    // 47 for 4-level, 56 for LA57
	return (BOOLEAN)((UINTN)(((INTN)Address >> SignBit) + 1) <= 1);
}


BOOLEAN
EFIAPI
RtlIsCanonicalAddress(
	IN UINTN Address
	)
{
	//
	// (!) THE WIDTH IS A RUNTIME PROPERTY, NOT A CONSTANT.
	//
	// An earlier draft of this file hardcoded the 4-level (47-bit) test and called that the
	// safe direction. It is not: under LA57 a legitimately canonical kernel address such as
	// 0xFF00000000000000 fails a 47-bit test, so RtlpImageNtHeaderEx would reject a valid
	// image and the runtime SetVariable screen would refuse valid kernel addresses. Refusing
	// what is actually valid is a functional regression, not conservatism.
	//
	// The band that makes this matter concretely: 0xFFFF000000000000-0xFFFF7FFFFFFFFFFF is
	// canonical under LA57 and NOT under 4-level paging. A fixed width is wrong in one
	// direction or the other depending on the machine.
	//
	if ((AsmReadMsr64(NEXUS_MSR_EFER) & NEXUS_EFER_UAIE) != 0)
		return TRUE;

	return NexusPeIsCanonicalForBits(Address, NexusPeIsFiveLevelPaging() ? 57 : 48);
}


PEFI_IMAGE_NT_HEADERS
EFIAPI
RtlpImageNtHeaderEx(
	IN CONST VOID* Base,
	IN UINTN Size OPTIONAL
	)
{
	if (Base == NULL || !RtlIsCanonicalAddress((UINTN)Base))
		return NULL;

	//
	// Size is optional, and 0 means "caller vouches for the extent". Where it IS supplied,
	// every field read below is bounds-checked against it before the read, not after.
	//
	if (Size != 0 && Size < sizeof(EFI_IMAGE_DOS_HEADER))
		return NULL;

	CONST PEFI_IMAGE_DOS_HEADER DosHeader = (PEFI_IMAGE_DOS_HEADER)Base;
	if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	//
	// e_lfanew is signed in the original structure and attacker-influenced in general. A
	// negative or absurd value must not become a pointer.
	//
	CONST UINT32 NtOffset = (UINT32)DosHeader->e_lfanew;
	if (DosHeader->e_lfanew < 0 || NtOffset > 0x10000000u)
		return NULL;
	if (Size != 0 && ((UINTN)NtOffset + sizeof(EFI_IMAGE_NT_HEADERS)) > Size)
		return NULL;

	CONST PEFI_IMAGE_NT_HEADERS NtHeaders =
		(PEFI_IMAGE_NT_HEADERS)((CONST UINT8*)Base + NtOffset);
	if (!RtlIsCanonicalAddress((UINTN)NtHeaders))
		return NULL;

	if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	//
	// (!) PE32 GATE -- x64 ONLY, REJECTED AT THE DOOR.
	//
	// This is the single point where every image in the boot chain enters, so rejecting
	// 32-bit images here makes the PE32 paths UNREACHABLE rather than merely unused. That
	// distinction is load-bearing in two ways:
	//
	//   HEADER_FIELD() silently picks between OptionalHeader32 and OptionalHeader64 on
	//   IMAGE64(), so a PE32 image slipping through would misread every header field with
	//   no diagnostic at all; and
	//
	//   FindFunctionStart reads NtHeaders->OptionalHeader.DataDirectory DIRECTLY at the
	//   64-bit layout, because a mapped Windows kernel is always PE32+. On a PE32 image
	//   that lands at the wrong offset and yields a function table made of whatever was
	//   there -- which is then used to place a patch.
	//
	// An earlier draft of this file accepted both magics, which would have re-opened both.
	//
	if (!IMAGE64(NtHeaders))
		return NULL;

	return NtHeaders;
}


BOOLEAN
EFIAPI
NexusPeRvaToOffset(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN UINT32 Rva,
	OUT UINT32* Offset
	)
{
	if (NtHeaders == NULL || Offset == NULL)
		return FALSE;

	CONST PEFI_IMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);
	CONST UINT16 NumberOfSections = NtHeaders->FileHeader.NumberOfSections;

	for (UINT16 i = 0; i < NumberOfSections; ++i)
	{
		CONST PEFI_IMAGE_SECTION_HEADER Section = &Sections[i];

		//
		// (!) SPAN IS max(VirtualSize, SizeOfRawData), NOT VirtualSize ALONE.
		//
		// When a section's raw data is larger than its virtual size -- file alignment
		// padding, which is common -- an RVA inside that tail belongs to the section but
		// falls outside a VirtualSize-only test. The previous implementation used
		// VirtualSize alone and reported such an RVA as belonging to no section.
		//
		CONST UINT32 Span = Section->Misc.VirtualSize > Section->SizeOfRawData
			? Section->Misc.VirtualSize
			: Section->SizeOfRawData;

		if (Rva >= Section->VirtualAddress && Rva < Section->VirtualAddress + Span)
		{
			//
			// A section with no raw data (.bss and friends) has nothing at a file offset.
			// Saying "offset 0" for it would be a lie in the same shape as the one below.
			//
			if (Section->SizeOfRawData == 0)
				return FALSE;

			*Offset = Rva - Section->VirtualAddress + Section->PointerToRawData;
			return TRUE;
		}
	}

	//
	// (!) FAILURE IS REPORTED, NOT ENCODED AS 0.
	//
	// The previous implementation returned a bare UINT32 and used 0 for "not found". 0 is
	// also a perfectly legal file offset, so no caller could tell the two apart -- and
	// RtlpImageDirectoryEntryToDataEx duly turned "not found" into Base + 0, a pointer to
	// the DOS header, handed back as though it were the requested directory.
	//
	return FALSE;
}


VOID*
EFIAPI
RtlpImageDirectoryEntryToDataEx(
	IN CONST VOID* Base,
	IN BOOLEAN MappedAsImage,
	IN UINT16 DirectoryEntry,
	OUT UINT32* Size
	)
{
	if (Size != NULL)
		*Size = 0;

	//
	// NB: the NT loader tags data-file mappings by setting low bits of the base pointer,
	// and the previous implementation carried the LDR_IS_DATAFILE dance for it. Nothing in
	// a DXE ever produces such a pointer -- there is no NT loader here -- so that branch
	// was unreachable and is not reproduced.
	//
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(Base, 0);
	if (NtHeaders == NULL)
		return NULL;

	if (DirectoryEntry >= HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes))
		return NULL;

	CONST PEFI_IMAGE_DATA_DIRECTORY Directories = HEADER_FIELD(NtHeaders, DataDirectory);
	CONST UINT32 Rva = Directories[DirectoryEntry].VirtualAddress;
	if (Rva == 0)
		return NULL;

	//
	// Headers live at the same place in both shapes, so an RVA inside them needs no
	// translation even for a file buffer.
	//
	if (MappedAsImage || Rva < HEADER_FIELD(NtHeaders, SizeOfHeaders))
	{
		if (Size != NULL)
			*Size = Directories[DirectoryEntry].Size;
		return (UINT8*)Base + Rva;
	}

	UINT32 Offset = 0;
	if (!NexusPeRvaToOffset(NtHeaders, Rva, &Offset))
		return NULL;

	if (Size != NULL)
		*Size = Directories[DirectoryEntry].Size;
	return (UINT8*)Base + Offset;
}


VOID*
EFIAPI
GetProcedureAddress(
	IN UINTN DllBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* RoutineName
	)
{
	if (DllBase == 0 || NtHeaders == NULL || RoutineName == NULL)
		return NULL;

	if (HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes) <= EFI_IMAGE_DIRECTORY_ENTRY_EXPORT)
		return NULL;

	CONST PEFI_IMAGE_DATA_DIRECTORY Directories = HEADER_FIELD(NtHeaders, DataDirectory);
	CONST UINT32 ExportRva = Directories[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	CONST UINT32 ExportSize = Directories[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (ExportRva == 0 || ExportSize == 0)
		return NULL;

	CONST PEFI_IMAGE_EXPORT_DIRECTORY Exports =
		(PEFI_IMAGE_EXPORT_DIRECTORY)(DllBase + ExportRva);

	CONST UINT32* Functions = (CONST UINT32*)(DllBase + Exports->AddressOfFunctions);
	CONST UINT32* Names = (CONST UINT32*)(DllBase + Exports->AddressOfNames);
	CONST UINT16* Ordinals = (CONST UINT16*)(DllBase + Exports->AddressOfNameOrdinals);

	for (UINT32 i = 0; i < Exports->NumberOfNames; ++i)
	{
		CONST CHAR8* Name = (CONST CHAR8*)(DllBase + Names[i]);
		if (AsciiStrCmp(Name, RoutineName) != 0)
			continue;

		CONST UINT16 Ordinal = Ordinals[i];
		if (Ordinal >= Exports->NumberOfFunctions)
			return NULL;

		CONST UINT32 FunctionRva = Functions[Ordinal];
		if (FunctionRva == 0)
			return NULL;

		//
		// (!) FORWARDED EXPORTS ARE NOT CODE. When the "address" falls inside the export
		// directory it is really a "DLL.Symbol" string. Returning it would hand the caller
		// a pointer to text that it would then call or patch.
		//
		if (FunctionRva >= ExportRva && FunctionRva < ExportRva + ExportSize)
			return NULL;

		return (VOID*)(DllBase + FunctionRva);
	}

	return NULL;
}


//
// Linear scan rather than a binary search over the sorted name array. The export names ARE
// required to be sorted, but "required" is a property of well-formed images and this runs
// on an image we did not produce; 3,260 comparisons a handful of times at boot is not worth
// depending on that.
//


INPUT_FILETYPE
EFIAPI
GetInputFileType(
	IN CONST UINT8* ImageBase,
	IN UINTN ImageSize
	)
{
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
	if (NtHeaders == NULL)
		return Unknown;

	CONST UINT16 Subsystem = HEADER_FIELD(NtHeaders, Subsystem);

	//
	// ntoskrnl is the only NATIVE image in the boot chain.
	//
	if (Subsystem == EFI_IMAGE_SUBSYSTEM_NATIVE)
		return Ntoskrnl;

	//
	// (!) bootmgfw.efi IS AN EFI_APPLICATION (10). winload.efi IS THE WINDOWS BOOT
	// APPLICATION (16). NOT THE OTHER WAY ROUND.
	//
	// An earlier version of this file guessed that mapping instead of reproducing it, and got
	// BOTH backwards: bootmgfw came back Unknown, so HookedLoadImage never called
	// PatchBootManager and the whole chain silently did nothing -- the machine booted normally
	// with no patches and no error. Measured, on this machine:
	//
	//     bootmgfw.efi   subsystem 10 (EFI_APPLICATION)
	//     winload.efi    subsystem 16 (WINDOWS_BOOT_APPLICATION)
	//     ntoskrnl.exe   subsystem  1 (NATIVE)
	//
	// The subsystem alone is not enough either way, which is the other half of why guessing
	// failed: plenty of EFI applications are not bootmgfw, so each arm confirms with content.
	//
	if (Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION)
	{
		//
		// The BCD object GUID for {bootmgr}, which bootmgfw carries as data. Any other EFI
		// application -- a shell, another OS loader -- will not.
		//
		CONST EFI_GUID BcdBootmgrGuid =
			{ 0x9dea862c, 0x5cdd, 0x4e70, { 0xac, 0xc1, 0xf3, 0x2b, 0x34, 0x4d, 0x47, 0x95 } };

		if (ImageSize > sizeof(BcdBootmgrGuid))
		{
			CONST UINT8* CONST Limit = ImageBase + ImageSize - sizeof(BcdBootmgrGuid);
			for (CONST UINT8* Address = ImageBase; Address <= Limit; Address += sizeof(VOID*))
			{
				if (CompareMem(Address, &BcdBootmgrGuid, sizeof(BcdBootmgrGuid)) == 0)
					return BootmgfwEfi;
			}
		}

		return Unknown;     // some other EFI application is being started
	}

	if (Subsystem != EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
		return Unknown;

	//
	// Of the Windows boot applications, winload names its own XSL resource. bootmgr.efi (the
	// WIM path) and winresume/SecConfig do not, and none of them is a target, so they fall
	// through to Unknown -- identified as "not ours" rather than named and then ignored.
	//
	{
		STATIC CONST CHAR16 OsLoaderXsl[] = L"OSLOADER.XSL";
		CONST UINTN NeedleBytes = sizeof(OsLoaderXsl) - sizeof(CHAR16);   // without the NUL

		UINT32 ResourceSize = 0;
		CONST UINT8* CONST Resources = (CONST UINT8*)RtlpImageDirectoryEntryToDataEx(
			ImageBase, TRUE, EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE, &ResourceSize);
		if (Resources == NULL || ResourceSize == 0)
			return Unknown;

		if (ImageSize > NeedleBytes)
		{
			CONST UINT8* CONST Limit = ImageBase + ImageSize - NeedleBytes;
			for (CONST UINT8* Address = Resources; Address <= Limit; Address += sizeof(CHAR16))
			{
				if (CompareMem(Address, OsLoaderXsl, NeedleBytes) == 0)
					return WinloadEfi;
			}
		}
	}

	return Unknown;
}


CONST CHAR16*
EFIAPI
FileTypeToString(
	IN INPUT_FILETYPE FileType
	)
{
	switch (FileType)
	{
	case BootmgfwEfi:
		return L"bootmgr";
	case WinloadEfi:
		return L"winload";
	case Ntoskrnl:
		return L"ntoskrnl";
	default:
		return L"<unknown>";
	}
}


UINT8*
EFIAPI
FindFunctionStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST UINT8* AddressInFunction
	)
{
	//
	// Null in, null out. Callers chain this onto a search that may have failed, and this
	// lets them keep a single failure branch.
	//
	if (AddressInFunction == NULL || ImageBase == NULL || NtHeaders == NULL)
		return NULL;

	if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION)
		return NULL;

	CONST PEFI_IMAGE_DATA_DIRECTORY Directory =
		&NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (Directory->VirtualAddress == 0 || Directory->Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
		return NULL;

	if (AddressInFunction < ImageBase)
		return NULL;

	//
	// MAPPED IMAGE ASSUMPTION: the exception directory is indexed straight off the base by
	// its RVA, and the address we are looking up is converted to an RVA by subtraction.
	// Both are only true once the loader has placed the sections.
	//
	CONST PIMAGE_RUNTIME_FUNCTION_ENTRY Table =
		(PIMAGE_RUNTIME_FUNCTION_ENTRY)(ImageBase + Directory->VirtualAddress);
	CONST UINT32 Count = Directory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	CONST UINTN RelativeAddress64 = (UINTN)(AddressInFunction - ImageBase);
	if (RelativeAddress64 > MAX_UINT32)
		return NULL;
	CONST UINT32 RelativeAddress = (UINT32)RelativeAddress64;

	PIMAGE_RUNTIME_FUNCTION_ENTRY Entry = NULL;
	INT32 Low = 0;
	INT32 High = (INT32)Count - 1;
	BOOLEAN Found = FALSE;

	while (Low <= High)
	{
		CONST INT32 Middle = Low + ((High - Low) >> 1);
		Entry = &Table[Middle];

		if (RelativeAddress < Entry->BeginAddress)
			High = Middle - 1;
		else if (RelativeAddress >= Entry->EndAddress)
			Low = Middle + 1;
		else
		{
			Found = TRUE;
			break;
		}
	}

	if (!Found)
		return NULL;

	//
	// (!) A .pdata ENTRY IS NOT A FUNCTION.
	//
	// The compiler separates cold code, and each separated range gets its own entry whose
	// UNWIND_INFO carries UNW_FLAG_CHAININFO and points back at the function it belongs to.
	// Measured in ntoskrnl: 7,037 of 37,910 entries chained on 26100 (18.6%), 9,650 of
	// 35,364 on 19041 (27.3%), with one function spread over 32 ranges. Returning the
	// range start for those would name a fragment, not the function -- and the caller
	// writes a patch at whatever this returns.
	//
	UINT32 Hops = 0;

	while ((Entry->UnwindData & RUNTIME_FUNCTION_INDIRECT) != 0)
	{
		if (++Hops > UNWIND_CHAIN_LIMIT)
			return NULL;
		Entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)
			(ImageBase + (Entry->UnwindData & ~(UINT32)RUNTIME_FUNCTION_INDIRECT));
	}

	for (;;)
	{
		CONST PIMAGE_FUNCTION_UNWIND_INFO UnwindInfo =
			(PIMAGE_FUNCTION_UNWIND_INFO)(ImageBase + Entry->UnwindData);

		if ((UNWIND_INFO_FLAGS(UnwindInfo) & UNW_FLAG_CHAININFO) == 0)
			break;

		if (++Hops > UNWIND_CHAIN_LIMIT)
			return NULL;

		Entry = UNWIND_INFO_CHAINED_ENTRY(UnwindInfo);
	}

	return (UINT8*)ImageBase + Entry->BeginAddress;
}


EFI_STATUS
EFIAPI
FindResourceDataById(
	IN CONST VOID* ImageBase,
	IN BOOLEAN MappedAsImage,
	IN UINT16 TypeId,
	IN UINT16 NameId,
	IN UINT16 LanguageId OPTIONAL,
	OUT VOID** ResourceData OPTIONAL,
	OUT UINT32* ResourceSize
	)
{
	if (ImageBase == NULL || ResourceSize == NULL)
		return EFI_INVALID_PARAMETER;

	*ResourceSize = 0;
	if (ResourceData != NULL)
		*ResourceData = NULL;

	UINT32 DirectorySize = 0;
	CONST UINT8* Root = (CONST UINT8*)RtlpImageDirectoryEntryToDataEx(
		ImageBase, MappedAsImage, EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE, &DirectorySize);
	if (Root == NULL || DirectorySize == 0)
		return EFI_NOT_FOUND;

	//
	// The tree is exactly three levels here: Type -> Name -> Language, with a data entry as
	// the leaf. Offsets within it are relative to the root of the resource directory.
	//
	CONST UINT16 Ids[3] = { TypeId, NameId, LanguageId };
	CONST UINT8* Level = Root;

	for (UINTN Depth = 0; Depth < 3; ++Depth)
	{
		//
		// (!) BOUNDS-CHECK BEFORE DEREFERENCING, not after. The entry counts live INSIDE the
		// directory header, so reading them first is itself the out-of-range access this check
		// exists to prevent.
		//
		CONST UINTN LevelOffset = (UINTN)(Level - Root);
		if (LevelOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > DirectorySize)
			return EFI_VOLUME_CORRUPTED;

		CONST PIMAGE_RESOURCE_DIRECTORY Directory = (PIMAGE_RESOURCE_DIRECTORY)Level;
		CONST UINT32 Named = Directory->NumberOfNamedEntries;
		CONST UINT32 Total = Named + Directory->NumberOfIdEntries;

		//
		// (!) AND THE COUNT ITSELF IS IMAGE-SUPPLIED. Both fields are UINT16, so Total reaches
		// 131070 -- about a megabyte of entries -- and the walk below indexes the array directly.
		// Every OFFSET in this function is validated; the COUNT must be too, or a truncated or
		// malformed resource section walks off the end of it.
		//
		CONST UINTN EntriesAt = LevelOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
		if (Total > (DirectorySize - EntriesAt) / sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))
			return EFI_VOLUME_CORRUPTED;

		CONST PIMAGE_RESOURCE_DIRECTORY_ENTRY Entries =
			(PIMAGE_RESOURCE_DIRECTORY_ENTRY)(Level + sizeof(IMAGE_RESOURCE_DIRECTORY));

		CONST UINT8* Next = NULL;

		//
		// Named entries sort before ID entries, and we match IDs only, so start past them.
		//
		for (UINT32 i = Named; i < Total; ++i)
		{
			CONST PIMAGE_RESOURCE_DIRECTORY_ENTRY Entry = &Entries[i];
			if ((Entry->NameOrId & IMAGE_RESOURCE_NAME_IS_STRING) != 0)
				continue;

			//
			// A language of 0 means "first one present", which is how a single-language
			// image is handled without knowing which language that is.
			//
			if (Depth == 2 && Ids[Depth] == 0)
			{
				Next = Root + (Entry->OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY);
				break;
			}

			if ((UINT16)(Entry->NameOrId & 0xFFFF) != Ids[Depth])
				continue;

			CONST BOOLEAN IsDirectory =
				(Entry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY) != 0;
			CONST UINT32 Offset = Entry->OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY;

			//
			// The first two levels must be subdirectories and the third must not. An image
			// that says otherwise is malformed, and following it would walk a data entry as
			// though it were a directory.
			//
			if (Depth < 2 && !IsDirectory)
				return EFI_VOLUME_CORRUPTED;
			if (Depth == 2 && IsDirectory)
				return EFI_VOLUME_CORRUPTED;

			if (Offset >= DirectorySize)
				return EFI_VOLUME_CORRUPTED;

			Next = Root + Offset;
			break;
		}

		if (Next == NULL)
			return EFI_NOT_FOUND;

		Level = Next;
	}

	if ((UINTN)(Level - Root) + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > DirectorySize)
		return EFI_VOLUME_CORRUPTED;

	CONST PIMAGE_RESOURCE_DATA_ENTRY Data = (PIMAGE_RESOURCE_DATA_ENTRY)Level;
	if (Data->Size == 0)
		return EFI_NOT_FOUND;

	//
	// (!) OffsetToData IS AN RVA, EVEN IN A FILE BUFFER. Every other offset in the resource
	// tree is relative to the resource root; this one is not. Treating it like the others
	// lands somewhere inside .rsrc that merely looks like data.
	//
	if (ResourceData != NULL)
	{
		if (MappedAsImage)
		{
			//
			// (!) THE RVA AND SIZE COME FROM THE IMAGE, so the range they describe has to be
			// checked against the image before it is handed out. The caller reads Size bytes
			// there; without this, a malformed entry points the caller past the mapping.
			//
			CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, 0);
			if (NtHeaders == NULL)
				return EFI_VOLUME_CORRUPTED;

			CONST UINT32 ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
			if (Data->OffsetToData > ImageSize || Data->Size > ImageSize - Data->OffsetToData)
				return EFI_VOLUME_CORRUPTED;

			*ResourceData = (VOID*)((CONST UINT8*)ImageBase + Data->OffsetToData);
		}
		else
		{
			CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, 0);
			UINT32 FileOffset = 0;
			if (NtHeaders == NULL ||
				!NexusPeRvaToOffset(NtHeaders, Data->OffsetToData, &FileOffset))
				return EFI_VOLUME_CORRUPTED;
			*ResourceData = (VOID*)((CONST UINT8*)ImageBase + FileOffset);
		}
	}

	*ResourceSize = Data->Size;
	return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
GetPeFileVersionInfo(
	IN CONST VOID* ImageBase,
	OUT UINT16* MajorVersion OPTIONAL,
	OUT UINT16* MinorVersion OPTIONAL,
	OUT UINT16* BuildNumber OPTIONAL,
	OUT UINT16* Revision OPTIONAL,
	OUT UINT32* FileFlags OPTIONAL
	)
{
	VOID* Resource = NULL;
	UINT32 ResourceSize = 0;

	CONST EFI_STATUS Status = FindResourceDataById(
		ImageBase, TRUE, RT_VERSION, VS_VERSION_INFO, 0, &Resource, &ResourceSize);
	if (EFI_ERROR(Status))
		return Status;

	if (Resource == NULL || ResourceSize < sizeof(VS_FIXEDFILEINFO))
		return EFI_NOT_FOUND;

	//
	// A VS_VERSIONINFO opens with a length, a value length, a type, the UTF-16 key
	// "VS_VERSION_INFO", and padding to a 4-byte boundary before VS_FIXEDFILEINFO. Rather
	// than reproduce that layout field by field -- it is fiddly and the padding rules are
	// where mistakes live -- scan the block for the signature and validate what follows.
	//
	// (!) The signature is validated by StrucVersion as well. 0xFEEF04BD can occur as
	// ordinary data; a match whose StrucVersion is not 1.0 is not a VS_FIXEDFILEINFO.
	//
	CONST UINT8* Bytes = (CONST UINT8*)Resource;
	CONST UINT32 Limit = ResourceSize - (UINT32)sizeof(VS_FIXEDFILEINFO);

	for (UINT32 Offset = 0; Offset <= Limit; Offset += sizeof(UINT32))
	{
		CONST VS_FIXEDFILEINFO* Info = (CONST VS_FIXEDFILEINFO*)(Bytes + Offset);
		if (Info->Signature != VS_FFI_SIGNATURE)
			continue;
		if (Info->StrucVersion != VS_FFI_STRUCVERSION)
			continue;

		if (MajorVersion != NULL)
			*MajorVersion = (UINT16)(Info->FileVersionMS >> 16);
		if (MinorVersion != NULL)
			*MinorVersion = (UINT16)(Info->FileVersionMS & 0xFFFF);
		if (BuildNumber != NULL)
			*BuildNumber = (UINT16)(Info->FileVersionLS >> 16);
		if (Revision != NULL)
			*Revision = (UINT16)(Info->FileVersionLS & 0xFFFF);
		if (FileFlags != NULL)
			*FileFlags = Info->FileFlags & Info->FileFlagsMask;

		return EFI_SUCCESS;
	}

	return EFI_NOT_FOUND;
}


PEFI_IMAGE_SECTION_HEADER
EFIAPI
NexusPeFindSection(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* Name
	)
{
	if (NtHeaders == NULL || Name == NULL)
		return NULL;

	//
	// The needle is padded to the full field width so the comparison is a fixed eight bytes in
	// both directions. AsciiStrCmp on Section->Name would run off the end of a name that uses
	// all eight characters, because the PE format does not terminate those.
	//
	CHAR8 Needle[EFI_IMAGE_SIZEOF_SHORT_NAME];
	SetMem(Needle, sizeof(Needle), 0);
	for (UINTN i = 0; i < EFI_IMAGE_SIZEOF_SHORT_NAME && Name[i] != '\0'; ++i)
		Needle[i] = Name[i];

	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++Section)
	{
		if (CompareMem(Section->Name, Needle, EFI_IMAGE_SIZEOF_SHORT_NAME) == 0)
			return Section;
	}

	return NULL;
}
