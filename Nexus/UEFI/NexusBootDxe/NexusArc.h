#pragma once

//
// NexusArc -- the Windows boot-loader structures this driver actually reads.
// Replaces arc.h (EfiGuard-derived).
//
// ---------------------------------------------------------------------------------------
// THESE LAYOUTS ARE NOT A DESIGN CHOICE
//
// Every structure here is written by bootmgr or winload and merely READ by us. Field order
// and padding are an ABI we have to match exactly; a field declared at the wrong offset
// does not fail to compile, it reads the wrong eight bytes and the driver acts on them.
// ---------------------------------------------------------------------------------------
//
// arc.h defined 155 named types, constants and enums. TEN are referenced anywhere outside
// it -- the rest described ARC configuration trees, boot entropy sources, hardware profiles,
// ETW boot config and NUMA topology that this driver never touches. Carrying 1,534 lines to
// use five structures made every one of them look load-bearing.
//
// Only what is reachable is reproduced. If something here turns out to be needed later, the
// right move is to add that structure with its real layout -- not to restore the file.
//

#include "NexusNt.h"

//
// A BCD option as bootmgr stores it. Only the header is needed; option data follows at
// DataOffset and is walked by byte offset, not by field.
//
typedef struct _BL_BCD_OPTION
{
	UINT32 Type;
	UINT32 DataOffset;
	UINT32 DataSize;
	UINT32 ListOffset;
	UINT32 NextEntryOffset;
	UINT32 Empty;
} BL_BCD_OPTION, *PBL_BCD_OPTION;

//
// The application entry bootmgr hands to a boot application. PatchBootmgr reads Signature to
// confirm it really is one, then Flags/Guid and walks BcdData.
//
typedef struct _BL_APPLICATION_ENTRY
{
	CHAR8 Signature[8];
	UINT32 Flags;
	EFI_GUID Guid;
	UINT32 Unknown[4];
	BL_BCD_OPTION BcdData;
} BL_APPLICATION_ENTRY, *PBL_APPLICATION_ENTRY;

//
// Passed through the boot-application entry point. We never dereference it -- it is relayed
// to the original routine -- but the layout has to be right for the call to be.
//
typedef struct _BL_RETURN_ARGUMENTS
{
	UINT32 Version;
	UINT32 Status;
	UINT32 Flags;
	UINT64 DataSize;
	UINT64 DataPage;
} BL_RETURN_ARGUMENTS, *PBL_RETURN_ARGUMENTS;

//
// A loaded module, as the boot loader records it. PatchWinload walks the load-order list
// with BASE_CR() off InLoadOrderLinks and reads DllBase / SizeOfImage / EntryPoint.
//
// (!) DECLARED IN FULL EVEN THOUGH FOUR FIELDS ARE USED. This one is embedded at offset 0 of
// BLDR_DATA_TABLE_ENTRY, so every field after it shifts that structure's layout. Truncating
// it would silently move CertificatePublisher and everything below.
//
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	UINT32 ExceptionTableSize;
	VOID* GpValue;
	VOID* NonPagedDebugInfo;
	VOID* DllBase;
	VOID* EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	union
	{
		struct
		{
			UINT16 SignatureLevel : 4;
			UINT16 SignatureType : 3;
			UINT16 Frozen : 2;
			UINT16 HotPatch : 1;
			UINT16 Unused : 6;
		} s;
		UINT16 EntireField;
	} u1;
	VOID* SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	VOID* CoverageSection;
	VOID* LoadedImports;
	union
	{
		VOID* Spare;
		struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;
	} u2;

	// Windows 10 and later only. Every supported build has them -- see
	// NEXUS_MIN_SUPPORTED_BUILD -- so they are unconditional here.
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

//
// The boot loader's richer entry. The load-order list threads through the KldrEntry member
// at offset 0, which is why BASE_CR() on InLoadOrderLinks lands on either type.
//
typedef struct _BLDR_DATA_TABLE_ENTRY
{
	KLDR_DATA_TABLE_ENTRY KldrEntry;
	UNICODE_STRING CertificatePublisher;
	UNICODE_STRING CertificateIssuer;
	VOID* ImageHash;
	VOID* CertificateThumbprint;
	UINT32 ImageHashAlgorithm;
	UINT32 ThumbprintHashAlgorithm;
	UINT32 ImageHashLength;
	UINT32 CertificateThumbprintLength;
	UINT32 LoadInformation;
	UINT32 Flags;
} BLDR_DATA_TABLE_ENTRY, *PBLDR_DATA_TABLE_ENTRY;

//
// (!) DELIBERATELY TRUNCATED AFTER LoadOrderListHead.
//
// The real LOADER_PARAMETER_BLOCK continues for hundreds of bytes and its tail changes
// between Windows versions -- which is exactly why reproducing it is a liability rather than
// an asset. We read one field, at offset 0x10, and we never allocate one of these: the
// pointer always comes from winload.
//
// Stopping here is the safe direction. A field that is not declared cannot be read by
// accident; a field declared at a guessed offset can. Nothing takes sizeof() of this type,
// which is the one thing truncation would break.
//
typedef struct _LOADER_PARAMETER_BLOCK
{
	UINT32 OsMajorVersion;          // 0x00
	UINT32 OsMinorVersion;          // 0x04
	UINT32 Size;                    // 0x08
	UINT32 OsLoaderSecurityVersion; // 0x0C
	LIST_ENTRY LoadOrderListHead;   // 0x10 -- the only field this driver reads
} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;


//
// (!) THE OFFSETS ABOVE ARE AN ABI CLAIM, SO CHECK THEM AT COMPILE TIME.
//
// A comment saying "LoadOrderListHead is at 0x10" is worth nothing -- it cannot be wrong
// loudly. These declare an array of negative length if an offset moves, which turns a silent
// misread of loader memory into a build failure. Cheap, and the only part of this header
// that can actually defend the rest of it.
//
// x64 padding is what makes this necessary: insert one UINT32 anywhere above and every
// subsequent field shifts by 4 or 8 with nothing to notice.
//
typedef char nexus_arc_assert_lpb_list[(OFFSET_OF(LOADER_PARAMETER_BLOCK, LoadOrderListHead) == 0x10) ? 1 : -1];

typedef char nexus_arc_assert_kldr_links[(OFFSET_OF(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks) == 0x00) ? 1 : -1];
typedef char nexus_arc_assert_kldr_base[(OFFSET_OF(KLDR_DATA_TABLE_ENTRY, DllBase) == 0x30) ? 1 : -1];
typedef char nexus_arc_assert_kldr_entry[(OFFSET_OF(KLDR_DATA_TABLE_ENTRY, EntryPoint) == 0x38) ? 1 : -1];
typedef char nexus_arc_assert_kldr_size[(OFFSET_OF(KLDR_DATA_TABLE_ENTRY, SizeOfImage) == 0x40) ? 1 : -1];
typedef char nexus_arc_assert_kldr_basename[(OFFSET_OF(KLDR_DATA_TABLE_ENTRY, BaseDllName) == 0x58) ? 1 : -1];

// BLDR_DATA_TABLE_ENTRY must start WITH the KLDR entry, or BASE_CR() off InLoadOrderLinks
// lands on the wrong type.
typedef char nexus_arc_assert_bldr_kldr[(OFFSET_OF(BLDR_DATA_TABLE_ENTRY, KldrEntry) == 0x00) ? 1 : -1];

typedef char nexus_arc_assert_appentry_flags[(OFFSET_OF(BL_APPLICATION_ENTRY, Flags) == 0x08) ? 1 : -1];
typedef char nexus_arc_assert_appentry_guid[(OFFSET_OF(BL_APPLICATION_ENTRY, Guid) == 0x0C) ? 1 : -1];
typedef char nexus_arc_assert_appentry_bcd[(OFFSET_OF(BL_APPLICATION_ENTRY, BcdData) == 0x2C) ? 1 : -1];
