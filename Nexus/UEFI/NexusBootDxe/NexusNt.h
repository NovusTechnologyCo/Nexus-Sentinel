#pragma once

//
// NexusNt -- the handful of NT types the DXE needs, without a WDK dependency.
// Replaces ntdef.h (EfiGuard-derived).
//
// Every definition here is dictated by the NT ABI as Microsoft documents it in winnt.h and
// ntdef.h. Layouts are not a design choice: this driver reads structures the Windows loader
// wrote, so a field in the wrong place is a wrong pointer, not a style difference.
//

//
// Ignore this file entirely if the real NT headers are already in scope -- redefining these
// against winnt.h is a fight nobody wins.
//
#if !defined(_NTDEF_) && !defined(_WINNT_)

//
// DebugLib.h redefines _DEBUG without testing whether it is already defined, so pull it in
// before anything below depends on the debug macros being stable.
//
#include <Library/DebugLib.h>

//
// NT expects the architecture and debug macros that the EDK2 build expresses differently.
// x64 only -- see NEXUS_MIN_SUPPORTED_BUILD in NexusBootDxe.h and the PE32 gate in NexusPe.c.
//
#if defined(MDE_CPU_X64)
	#if !defined(_WIN64)
		#define _WIN64
	#endif
	#if !defined(_AMD64_)
		#define _AMD64_
	#endif
#endif

#if defined(EFI_DEBUG)
	#if !defined(_DEBUG)
		#define _DEBUG
	#endif
	#if !defined(DBG)
		#define DBG     1
	#endif
#endif

#if defined(MDEPKG_NDEBUG)
	#if !defined(NDEBUG)
		#define NDEBUG
	#endif
#endif

//
// A trailing array of unknown length. 1 rather than 0 because that is what the NT headers
// use and what the structures were sized against.
//
#define ANYSIZE_ARRAY               1

//
// Byte offset of a field. Deliberately the NT spelling, because the structures it is applied
// to are NT's.
//
#define FIELD_OFFSET(Type, Field)   ((INT32)(INTN)&(((Type*)0)->Field))

//
// Initialiser for a UNICODE_STRING over a literal: Length excludes the terminator,
// MaximumLength includes it. Getting that pair backwards is how a string ends up one
// character short or reading past its buffer.
//
#define RTL_CONSTANT_STRING(s) \
{ \
	(sizeof(s) - sizeof((s)[0])), \
	(sizeof(s)), \
	(s) \
}

//
// NB: ntdef.h also defined MAKELANGID, LANG_NEUTRAL, SUBLANG_NEUTRAL, LOWORD, HIWORD,
// LOBYTE and HIBYTE. None of them has a single user anywhere in the DXE. Not reproduced.
//

typedef INT32 NTSTATUS;

//
// (!) THE ANONYMOUS-STRUCT MEMBERS ARE NAMED s AND u, AND BOTH ARE LOAD-BEARING.
//
// NT declares LARGE_INTEGER with an unnamed struct plus a named one called u. EDK2 builds
// with warning 4201 (nameless struct/union) disabled but the EDK2 GCC path does not accept
// it, so both spellings are given names here and callers pick one. Renaming or dropping
// either breaks a caller with no type error -- just a different field at a different offset.
//
typedef union _LARGE_INTEGER
{
	struct
	{
		UINT32 LowPart;
		INT32 HighPart;
	} s;
	struct
	{
		UINT32 LowPart;
		INT32 HighPart;
	} u;
	INT64 QuadPart;
} LARGE_INTEGER;

//
// Counted UTF-16 string. Length and MaximumLength are in BYTES, not characters -- the most
// common way to misuse this structure is to treat them as a character count.
//
typedef struct _UNICODE_STRING
{
	UINT16 Length;
	UINT16 MaximumLength;
	CHAR16* Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

#endif // !defined(_NTDEF_) && !defined(_WINNT_)
