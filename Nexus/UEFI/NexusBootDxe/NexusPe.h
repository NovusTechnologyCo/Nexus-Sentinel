#pragma once

//
// NexusPe -- PE/COFF parsing for the boot DXE.
//
// Written from the Microsoft PE/COFF specification and validated against a host prototype
// (a host-side prototype) that was exercised on four ntoskrnl builds
// spanning two Windows releases. It replaces pe.c, which was EfiGuard-derived and GPLv3.
//
// Structure layouts here are dictated by the on-disk format; the names follow the
// specification and winnt.h because call sites and every reference on the format use them.
//
// ---------------------------------------------------------------------------------------
// MAPPED IMAGES vs FILE BUFFERS -- READ THIS BEFORE CALLING ANYTHING
//
// A PE exists in two shapes and they are not interchangeable:
//
//   MAPPED   the loader has placed each section at its VirtualAddress. RVA == offset from
//            the base. This is what winload hands us for ntoskrnl, and what the kernel
//            patches operate on.
//   FILE     a raw read of the file. Section data sits at PointerToRawData, so RVA is NOT
//            the offset and must be translated through the section table.
//
// Functions that take a MappedAsImage flag handle both. FindFunctionStart does NOT -- it
// indexes the exception directory by RVA and therefore REQUIRES a mapped image. Calling it
// on a file buffer reads whatever happens to live at that file offset and returns a
// plausible-looking address, which is the worst possible failure for a routine whose answer
// gets patched into the kernel.
// ---------------------------------------------------------------------------------------
//

#include <IndustryStandard/PeImage.h>

//
// EDK2 spells these without pointer typedefs, and this codebase is x64-only.
//
typedef EFI_IMAGE_NT_HEADERS32 *PEFI_IMAGE_NT_HEADERS32;
typedef EFI_IMAGE_NT_HEADERS64 *PEFI_IMAGE_NT_HEADERS64;
typedef EFI_IMAGE_NT_HEADERS64 EFI_IMAGE_NT_HEADERS, *PEFI_IMAGE_NT_HEADERS;
typedef EFI_IMAGE_DOS_HEADER *PEFI_IMAGE_DOS_HEADER;
typedef EFI_IMAGE_FILE_HEADER *PEFI_IMAGE_FILE_HEADER;
typedef EFI_IMAGE_SECTION_HEADER *PEFI_IMAGE_SECTION_HEADER;
typedef EFI_IMAGE_DATA_DIRECTORY *PEFI_IMAGE_DATA_DIRECTORY;
typedef EFI_IMAGE_EXPORT_DIRECTORY *PEFI_IMAGE_EXPORT_DIRECTORY;

//
// Subsystem values used to tell the boot files apart.
//
#define EFI_IMAGE_SUBSYSTEM_NATIVE                      1
#define EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16

#define RT_VERSION                                      16
#define VS_VERSION_INFO                                 1
#define VS_FF_DEBUG                                     0x00000001L

#define IMAGE64(NtHeaders) \
	((NtHeaders)->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)

//
// Reach an OptionalHeader field without caring about PE32 vs PE32+. Only the few fields
// that exist in both at different offsets need this.
//
#define HEADER_FIELD(NtHeaders, Field) \
	(IMAGE64(NtHeaders) \
		? ((PEFI_IMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
		: ((PEFI_IMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

//
// The section table follows the optional header, whose size is declared rather than fixed.
//
#define IMAGE_FIRST_SECTION(NtHeaders) ((PEFI_IMAGE_SECTION_HEADER) \
	((UINTN)(NtHeaders) + \
	 OFFSET_OF(EFI_IMAGE_NT_HEADERS, OptionalHeader) + \
	 ((NtHeaders)->FileHeader.SizeOfOptionalHeader)))

//
// Which of the three boot files an image is.
//
// (!) THESE ENUMERATOR NAMES ARE THE EXISTING ONES AND MUST STAY. An earlier draft renamed
// them to InputFileTypeX while claiming the header was source-compatible; it is not a
// signature change the compiler lets you get away with quietly -- 20 call sites across
// NexusBootDxe.c, PatchBootmgr.c and PatchWinload.c refer to them by these names.
//
typedef enum _INPUT_FILETYPE
{
	Unknown,

	// EFI boot manager/loader
	BootmgfwEfi,
	WinloadEfi,

	// Kernel
	Ntoskrnl
} INPUT_FILETYPE;

//
// x64 unwind data. See the exception-handling chapter of the x64 ABI.
//
#define UNW_FLAG_NHANDLER           0x0
#define UNW_FLAG_EHANDLER           0x1
#define UNW_FLAG_UHANDLER           0x2
#define UNW_FLAG_CHAININFO          0x4

//
// Low bit of UnwindData: the entry points at a master entry rather than describing a range.
// Measured as UNUSED in every ntoskrnl examined (26100.x and 19041) -- implemented for ABI
// completeness, not because it was observed.
//
#define RUNTIME_FUNCTION_INDIRECT   0x1

//
// Refuse a cyclic or absurd unwind chain rather than spinning in a DXE with no way out.
//
#define UNWIND_CHAIN_LIMIT          32

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
	UINT32 BeginAddress;
	UINT32 EndAddress;
	UINT32 UnwindData;
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;

//
// UNWIND_INFO. Version and Flags share the first byte (3 bits then 5); FrameRegister and
// FrameOffset share the fourth. Declared as plain bytes and unpacked by hand so the layout
// does not depend on the compiler's bitfield packing.
//
typedef struct _IMAGE_FUNCTION_UNWIND_INFO
{
	UINT8 VersionAndFlags;
	UINT8 SizeOfProlog;
	UINT8 CountOfUnwindCodes;
	UINT8 FrameRegisterAndOffset;
	UINT16 UnwindCode[1];
} IMAGE_FUNCTION_UNWIND_INFO, *PIMAGE_FUNCTION_UNWIND_INFO;

#define UNWIND_INFO_VERSION(Info)   ((Info)->VersionAndFlags & 0x07)
#define UNWIND_INFO_FLAGS(Info)     (((Info)->VersionAndFlags >> 3) & 0x1F)

//
// The unwind codes are padded to an even count, and a chained entry follows them.
//
#define UNWIND_INFO_CHAINED_ENTRY(Info) \
	((PIMAGE_RUNTIME_FUNCTION_ENTRY)&(Info)->UnwindCode[((Info)->CountOfUnwindCodes + 1) & ~1])

//
// VS_FIXEDFILEINFO, as embedded in a VS_VERSIONINFO resource.
//
#define VS_FFI_SIGNATURE            0xFEEF04BDu
#define VS_FFI_STRUCVERSION         0x00010000u

typedef struct _VS_FIXEDFILEINFO
{
	UINT32 Signature;
	UINT32 StrucVersion;
	UINT32 FileVersionMS;
	UINT32 FileVersionLS;
	UINT32 ProductVersionMS;
	UINT32 ProductVersionLS;
	UINT32 FileFlagsMask;
	UINT32 FileFlags;
	UINT32 FileOS;
	UINT32 FileType;
	UINT32 FileSubtype;
	UINT32 FileDateMS;
	UINT32 FileDateLS;
} VS_FIXEDFILEINFO;

//
// Resource directory. Entries are sorted, named ones first, then ID ones.
//
typedef struct _IMAGE_RESOURCE_DIRECTORY
{
	UINT32 Characteristics;
	UINT32 TimeDateStamp;
	UINT16 MajorVersion;
	UINT16 MinorVersion;
	UINT16 NumberOfNamedEntries;
	UINT16 NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
{
	UINT32 NameOrId;        // high bit set: offset to a name string; else a 16-bit ID
	UINT32 OffsetToData;    // high bit set: offset to a subdirectory; else to a data entry
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

#define IMAGE_RESOURCE_NAME_IS_STRING       0x80000000u
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY    0x80000000u

typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
	UINT32 OffsetToData;    // an RVA, even in a file buffer
	UINT32 Size;
	UINT32 CodePage;
	UINT32 Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;


//
// Is `Address` canonical, given a linear-address width? Pure arithmetic, no CPU state, so
// both widths can be exercised on a host without an LA57 machine.
//
BOOLEAN
EFIAPI
NexusPeIsCanonicalForBits(
	IN UINTN Address,
	IN UINTN LinearAddressBits
	);

//
// Is `Address` canonical on THIS CPU?
//
// Dereferencing a non-canonical address raises #GP, and inside a UEFI runtime service that
// is unrecoverable -- the runtime SetVariable path screens kernel addresses with this.
//
// (!) The width is read from the CPU (LA57) and EFER.UAIE is honoured. A fixed 47-bit test
// is wrong on LA57 hardware, where 0xFFFF000000000000-0xFFFF7FFFFFFFFFFF is canonical --
// it would reject valid kernel addresses and valid image bases.
//
BOOLEAN
EFIAPI
RtlIsCanonicalAddress(
	IN UINTN Address
	);

//
// Validate the DOS and NT headers at `Base` and return the NT headers, or NULL.
// `Size` bounds the buffer; pass 0 for a mapped image whose extent is already trusted.
//
PEFI_IMAGE_NT_HEADERS
EFIAPI
RtlpImageNtHeaderEx(
	IN CONST VOID* Base,
	IN UINTN Size OPTIONAL
	);

//
// Which boot file this is, decided from the subsystem and the export table.
//
INPUT_FILETYPE
EFIAPI
GetInputFileType(
	IN CONST UINT8* ImageBase,
	IN UINTN ImageSize
	);

CONST CHAR16*
EFIAPI
FileTypeToString(
	IN INPUT_FILETYPE FileType
	);

//
// Address of an exported routine in a MAPPED image, or NULL.
//
// Forwarded exports return NULL: a forwarder's "address" is a string inside the export
// directory, and handing that back as code would be a pointer to text.
//
VOID*
EFIAPI
GetProcedureAddress(
	IN UINTN DllBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* RoutineName
	);

//
// Translate an RVA to a file offset through the section table.
//
// (!) Returns FALSE when the RVA lies in no section, instead of the offset 0 the previous
// implementation returned. 0 is a legitimate offset, so the old form could not be checked
// and its caller turned "not found" into a pointer to the DOS header.
//
BOOLEAN
EFIAPI
NexusPeRvaToOffset(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN UINT32 Rva,
	OUT UINT32* Offset
	);

//
// Pointer to a data directory's contents, for a mapped image or a file buffer.
//
VOID*
EFIAPI
RtlpImageDirectoryEntryToDataEx(
	IN CONST VOID* Base,
	IN BOOLEAN MappedAsImage,
	IN UINT16 DirectoryEntry,
	OUT UINT32* Size
	);

//
// Start of the function containing `AddressInFunction`, from the exception directory.
//
// (!) MAPPED IMAGES ONLY -- see the note at the top of this file.
//
// Resolves RUNTIME_FUNCTION_INDIRECT and UNW_FLAG_CHAININFO, so the answer is the PRIMARY
// entry of the function rather than the fragment that happened to contain the address.
// That matters: 18.6% of entries in ntoskrnl 26100 are chained fragments, and 27.3% in
// 19041. Returns NULL if AddressInFunction is NULL, which lets callers do
// 'FindPattern(..., &Addr); Start = FindFunctionStart(..., Addr);' with one failure branch.
//
UINT8*
EFIAPI
FindFunctionStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST UINT8* AddressInFunction
	);

//
// Locate a resource by numeric type/name/language. IDs only -- named entries are skipped.
// Pass LanguageId 0 to take the first language present.
//
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
	);

//
// File version from the image's own VS_VERSIONINFO resource.
//
// (!) MAPPED IMAGES ONLY, like the implementation it replaces. All three call sites --
// PatchBootmgr, PatchWinload, PatchNtoskrnl -- pass an image the boot manager has already
// loaded, so the signature is kept as-is rather than churning them for a generality nobody
// asked for. Use FindResourceDataById directly if a file buffer ever needs this.
//
EFI_STATUS
EFIAPI
GetPeFileVersionInfo(
	IN CONST VOID* ImageBase,
	OUT UINT16* MajorVersion OPTIONAL,
	OUT UINT16* MinorVersion OPTIONAL,
	OUT UINT16* BuildNumber OPTIONAL,
	OUT UINT16* Revision OPTIONAL,
	OUT UINT32* FileFlags OPTIONAL
	);

//
// Find a section by name.
//
// Section names are eight bytes, NOT null-terminated when the name fills the field, so a plain
// string compare against Name[] reads past it. This compares the fixed eight bytes, which is
// what the PE specification actually defines.
//
// Returns NULL when the section is absent, which every caller must treat as a refusal: section
// layout is a property of the image rather than of our code, and Microsoft has renamed and
// merged kernel sections before.
//
PEFI_IMAGE_SECTION_HEADER
EFIAPI
NexusPeFindSection(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* Name
	);
