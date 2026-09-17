#pragma once

//
// NexusUtil -- boot-time helpers for the DXE. Replaces util.c/util.h (EfiGuard-derived).
//
// Signatures are kept identical to the ones they replace. That is not cosmetic: renaming a
// symbol here means editing every call site, and CopyWpMem alone has 24 of them.
//

#include <Protocol/LoadedImage.h>
#include <Zydis/Zydis.h>

//
// Control-register and MSR bits, per the Intel SDM. Only the ones actually used are defined;
// util.h also carried CR0_PG, CR4_CET, CR4_LA57, MSR_EFER, EFER_LMA and EFER_UAIE as public
// names with no user outside its own .c file.
//
#define CR0_WP              ((UINTN)0x00010000) // CR0.WP    -- supervisor write protect
#define NEXUS_CR0_PG        ((UINTN)0x80000000) // CR0.PG    -- paging enabled
#define NEXUS_CR4_CET       ((UINTN)0x00800000) // CR4.CET   -- control-flow enforcement
#define NEXUS_CR4_LA57      ((UINTN)0x00001000) // CR4.LA57  -- 57-bit linear addresses

//
// Waits on a timer event for N milliseconds. Requires TPL_APPLICATION.
//
EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	);

//
// Busy-stalls for N milliseconds. Safe at any TPL, unlike RtlSleep.
//
EFI_STATUS
EFIAPI
RtlStall(
	IN UINTN Milliseconds
	);

//
// Prints what a loaded image is and where it came from.
//
VOID
EFIAPI
PrintLoadedImageInfo(
	IN CONST EFI_LOADED_IMAGE* ImageInfo
	);

//
// Append to the deferred kernel-patch message buffer.
//
// (!) Do not call this directly. Use PRINT_KERNEL_PATCH_MSG(), which also sends the message
// to an attached boot debugger immediately. This buffer is only flushed to the screen at
// ExitBootServices, so anything logged solely through here is invisible until then -- and
// invisible forever if the machine does not get that far.
//
VOID
EFIAPI
AppendKernelPatchMessage(
	IN CONST CHAR16* Format,
	...
	);

//
// Flush the patch-message buffer to the console.
//
// The buffer holds a run of separately null-terminated strings rather than one string, and
// they are emitted one at a time: some platforms have a small Print() limit, and an 8 KB
// single call is silently truncated on those.
//
VOID
EFIAPI
PrintKernelPatchInfo(
	VOID
	);

//
// Clear and set CR4.CET. Assembly, necessarily -- see X64/NexusCet.asm.
//
VOID
EFIAPI
AsmDisableCet(
	VOID
	);

VOID
EFIAPI
AsmEnableCet(
	VOID
	);

//
// Drop supervisor write protection, reporting what was on so it can be put back exactly.
//
// (!) CET MUST COME DOWN WITH WP, and go back up in the opposite order. Writing to a
// read-only kernel page with CR0.WP clear is the whole point; leaving CR4.CET set while
// doing it is what turns a patch into a #CP.
//
VOID
EFIAPI
DisableWriteProtect(
	OUT BOOLEAN* WpEnabled,
	OUT BOOLEAN* CetEnabled
	);

VOID
EFIAPI
EnableWriteProtect(
	IN BOOLEAN WpEnabled,
	IN BOOLEAN CetEnabled
	);

//
// CopyMem/SetMem that drop write protection first. These are how every kernel patch in this
// driver is actually written.
//
VOID*
EFIAPI
CopyWpMem(
	OUT VOID* Destination,
	IN CONST VOID* Source,
	IN UINTN Length
	);

VOID*
EFIAPI
SetWpMem(
	OUT VOID* Destination,
	IN UINTN Length,
	IN UINT8 Value
	);

//
// TRUE when 5-level paging (57-bit linear addresses) is active.
//
BOOLEAN
EFIAPI
IsFiveLevelPagingEnabled(
	VOID
	);

//
// Case-insensitive comparison of at most Length characters.
//
INTN
EFIAPI
StrniCmp(
	IN CONST CHAR16* FirstString,
	IN CONST CHAR16* SecondString,
	IN UINTN Length
	);

//
// Case-insensitive substring search. Returns a pointer into String1, or NULL.
//
CONST CHAR16*
EFIAPI
StriStr(
	IN CONST CHAR16* String1,
	IN CONST CHAR16* String2
	);

//
// Waits for a keypress. FALSE if ESC was pressed (abort), TRUE otherwise.
//
BOOLEAN
EFIAPI
WaitForKey(
	VOID
	);

//
// Sets the foreground colour, keeping the background, optionally clearing the screen.
// Returns the previous attribute so it can be restored.
//
INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	);

//
// (!) THIS DRIVER DOES NOT SCAN FOR BYTE SIGNATURES, AND MUST NOT START.
//
// Kernel targets are located by NexusPgLocate and boot-file targets by NexusBootLocate, both
// of which identify code by what it MEANS rather than by the bytes it happens to compile to.
// A byte signature is a dependency on one build of someone else's binary; adding a pattern
// helper back here would reintroduce the technique those two modules exist to replace.
//

//
// Zydis decoder context.
//
// (!) The formatter is NOT here. util.h's version carried a ZydisFormatter and a 256-byte
// InstructionText scratch buffer, but both build configurations define
// ZYDIS_DISABLE_FORMATTER and nothing outside util.c ever read them -- so the fields, the
// custom formatter hook and its #ifndef arms were all dead. 256 bytes per context, on a
// structure that lives on the stack during kernel patching.
//
typedef struct _ZYDIS_CONTEXT
{
	ZydisDecoder Decoder;
	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

	ZyanU64 InstructionAddress;
	UINTN Length;
	UINTN Offset;
} ZYDIS_CONTEXT, *PZYDIS_CONTEXT;

//
// Initialises a decoder context for the image described by NtHeaders.
//
ZyanStatus
EFIAPI
ZydisInit(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT PZYDIS_CONTEXT Context
	);
