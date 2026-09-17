//
// NexusUtil -- boot-time helpers for the DXE. Replaces util.c (EfiGuard-derived).
//

#include "NexusBootDxe.h"
#include "NexusUtil.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
//
// (!) DevicePathLib and MemoryAllocationLib are REQUIRED, not decorative. Without the first,
// ConvertDevicePathToText is implicitly declared, MSVC assumes it returns int, and the
// returned CHAR16* is TRUNCATED TO 32 BITS on x64 -- then printed and passed to FreePool.
// The DXE build does not use /WX, so this compiled to a signed artifact with nothing worse
// than a C4013 warning scrolling past.
//
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>


EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	)
{
	EFI_EVENT TimerEvent;
	EFI_STATUS Status = gBS->CreateEvent(EVT_TIMER, TPL_APPLICATION, NULL, NULL, &TimerEvent);
	if (EFI_ERROR(Status))
		return Status;

	// SetTimer takes 100 ns units, so a millisecond is 10,000 of them.
	Status = gBS->SetTimer(TimerEvent, TimerRelative, MultU64x32(Milliseconds, 10000));
	if (!EFI_ERROR(Status))
	{
		UINTN Index;
		Status = gBS->WaitForEvent(1, &TimerEvent, &Index);
	}

	gBS->CloseEvent(TimerEvent);
	return Status;
}


EFI_STATUS
EFIAPI
RtlStall(
	IN UINTN Milliseconds
	)
{
	// gBS->Stall is specified in microseconds.
	return gBS->Stall(Milliseconds * 1000);
}


VOID
EFIAPI
PrintLoadedImageInfo(
	IN CONST EFI_LOADED_IMAGE* ImageInfo
	)
{
	if (ImageInfo == NULL)
		return;

	CHAR16* ImagePath = ConvertDevicePathToText(ImageInfo->FilePath, TRUE, TRUE);
	Print(L"    Image base:\t0x%llX\r\n", (UINTN)ImageInfo->ImageBase);
	Print(L"    Image size:\t0x%llX\r\n", (UINTN)ImageInfo->ImageSize);
	Print(L"    Image path:\t%s\r\n", ImagePath != NULL ? ImagePath : L"<none>");

	if (ImagePath != NULL)
		FreePool(ImagePath);
}


VOID
EFIAPI
AppendKernelPatchMessage(
	IN CONST CHAR16* Format,
	...
	)
{
	//
	// Room left, in CHARACTERS, keeping one for the terminator of this message. BufferSize
	// counts bytes and excludes the terminator, so the arithmetic converts once and only
	// once -- mixing the two units here is how a buffer like this gets overrun.
	//
	CONST UINTN UsedChars = gKernelPatchInfo.BufferSize / sizeof(CHAR16);
	CONST UINTN CapacityChars = ARRAY_SIZE(gKernelPatchInfo.Buffer);
	if (UsedChars + 1 >= CapacityChars)
		return;

	CONST UINTN RemainingChars = CapacityChars - UsedChars;

	VA_LIST Marker;
	VA_START(Marker, Format);
	CONST UINTN Printed = UnicodeVSPrint(&gKernelPatchInfo.Buffer[UsedChars],
										RemainingChars * sizeof(CHAR16),
										Format,
										Marker);
	VA_END(Marker);

	//
	// (!) ADVANCE PAST THE TERMINATOR, NOT ONTO IT. PrintKernelPatchInfo walks the buffer as
	// a run of separately terminated strings, so each message must keep its own NUL. Adding
	// only `Printed` would let the next message overwrite it and glue the two together.
	//
	gKernelPatchInfo.BufferSize += (Printed + 1) * sizeof(CHAR16);
}


VOID
EFIAPI
PrintKernelPatchInfo(
	VOID
	)
{
	if (gBS == NULL || gST == NULL || gST->ConOut == NULL)
		return;

	CONST UINTN TotalChars = gKernelPatchInfo.BufferSize / sizeof(CHAR16);
	UINTN Index = 0;

	//
	// One OutputString per embedded string. Some platforms have a small Print() limit and
	// silently truncate a single 8 KB call, which is exactly the output you most want when
	// something has gone wrong.
	//
	while (Index < TotalChars && Index < ARRAY_SIZE(gKernelPatchInfo.Buffer))
	{
		CHAR16* String = &gKernelPatchInfo.Buffer[Index];
		if (*String == L'\0')
		{
			Index++;
			continue;
		}

		gST->ConOut->OutputString(gST->ConOut, String);
		Index += StrLen(String) + 1;
	}
}


VOID
EFIAPI
DisableWriteProtect(
	OUT BOOLEAN* WpEnabled,
	OUT BOOLEAN* CetEnabled
	)
{
	CONST UINTN Cr0 = AsmReadCr0();
	*WpEnabled = (BOOLEAN)((Cr0 & CR0_WP) != 0);
	*CetEnabled = (BOOLEAN)((AsmReadCr4() & NEXUS_CR4_CET) != 0);

	//
	// (!) ORDER MATTERS. CET comes down FIRST, and goes back up LAST.
	//
	// Clearing CR0.WP is what lets a supervisor write land on a read-only kernel page. But
	// with CET still armed, the shadow stack is enforced across the call that does the
	// writing, and AsmDisableCet has to unwind its own return before clearing CR4.CET. Doing
	// this the other way round turns a patch into a control-protection fault.
	//
	if (*CetEnabled)
		AsmDisableCet();

	if (*WpEnabled)
		AsmWriteCr0(Cr0 & ~CR0_WP);
}


VOID
EFIAPI
EnableWriteProtect(
	IN BOOLEAN WpEnabled,
	IN BOOLEAN CetEnabled
	)
{
	if (WpEnabled)
		AsmWriteCr0(AsmReadCr0() | CR0_WP);

	if (CetEnabled)
		AsmEnableCet();
}


VOID*
EFIAPI
CopyWpMem(
	OUT VOID* Destination,
	IN CONST VOID* Source,
	IN UINTN Length
	)
{
	BOOLEAN WpEnabled, CetEnabled;
	DisableWriteProtect(&WpEnabled, &CetEnabled);

	VOID* Result = CopyMem(Destination, Source, Length);

	EnableWriteProtect(WpEnabled, CetEnabled);
	return Result;
}


VOID*
EFIAPI
SetWpMem(
	OUT VOID* Destination,
	IN UINTN Length,
	IN UINT8 Value
	)
{
	BOOLEAN WpEnabled, CetEnabled;
	DisableWriteProtect(&WpEnabled, &CetEnabled);

	VOID* Result = SetMem(Destination, Length, Value);

	EnableWriteProtect(WpEnabled, CetEnabled);
	return Result;
}


BOOLEAN
EFIAPI
IsFiveLevelPagingEnabled(
	VOID
	)
{
	return (BOOLEAN)((AsmReadCr4() & NEXUS_CR4_LA57) != 0);
}


STATIC
CHAR16
EFIAPI
NexusToUpper(
	IN CHAR16 Char
	)
{
	return (Char >= L'a' && Char <= L'z') ? (CHAR16)(Char - (L'a' - L'A')) : Char;
}


INTN
EFIAPI
StrniCmp(
	IN CONST CHAR16* FirstString,
	IN CONST CHAR16* SecondString,
	IN UINTN Length
	)
{
	if (Length == 0)
		return 0;
	if (FirstString == NULL || SecondString == NULL)
		return FirstString == SecondString ? 0 : (FirstString == NULL ? -1 : 1);

	CHAR16 A = NexusToUpper(*FirstString);
	CHAR16 B = NexusToUpper(*SecondString);

	while (A != L'\0' && A == B && Length > 1)
	{
		FirstString++;
		SecondString++;
		A = NexusToUpper(*FirstString);
		B = NexusToUpper(*SecondString);
		Length--;
	}

	return (INTN)A - (INTN)B;
}


CONST CHAR16*
EFIAPI
StriStr(
	IN CONST CHAR16* String1,
	IN CONST CHAR16* String2
	)
{
	if (String1 == NULL || String2 == NULL)
		return NULL;

	// An empty needle matches at the start, which is what StrStr does too.
	if (*String2 == L'\0')
		return String1;

	CONST UINTN NeedleLength = StrLen(String2);

	for (CONST CHAR16* Haystack = String1; *Haystack != L'\0'; Haystack++)
	{
		if (StrniCmp(Haystack, String2, NeedleLength) == 0)
			return Haystack;
	}

	return NULL;
}


BOOLEAN
EFIAPI
WaitForKey(
	VOID
	)
{
	if (gBS == NULL || gST == NULL || gST->ConIn == NULL)
		return TRUE;

	// Drain anything already buffered, so a stray keystroke from earlier does not answer
	// the prompt that has not been shown yet.
	gST->ConIn->Reset(gST->ConIn, FALSE);

	EFI_INPUT_KEY Key;
	UINTN Index;
	for (;;)
	{
		gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);

		CONST EFI_STATUS Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
		if (Status == EFI_NOT_READY)
			continue;
		if (EFI_ERROR(Status))
			return TRUE;

		return (BOOLEAN)(Key.ScanCode != SCAN_ESC);
	}
}


INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	)
{
	if (gST == NULL || gST->ConOut == NULL)
		return 0;

	CONST INT32 OriginalAttribute = gST->ConOut->Mode->Attribute;

	// Keep the background: the high nibble is the background colour, and overwriting it
	// with 0 would silently force black on a platform whose console is not.
	CONST UINTN Background = (UINTN)(OriginalAttribute & 0x70);
	gST->ConOut->SetAttribute(gST->ConOut, (TextColour & 0x0F) | Background);

	if (ClearScreen)
		gST->ConOut->ClearScreen(gST->ConOut);

	return OriginalAttribute;
}


ZyanStatus
EFIAPI
ZydisInit(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT PZYDIS_CONTEXT Context
	)
{
	//
	// NtHeaders is unused: PE32 images are refused at the door by RtlpImageNtHeaderEx, so
	// the decoder is always configured for 64-bit long mode. It stays in the signature
	// because every caller has it to hand and it documents WHICH image the context is for.
	//
	(VOID)NtHeaders;

	if (Context == NULL)
		return ZYAN_STATUS_INVALID_ARGUMENT;

	return ZydisDecoderInit(&Context->Decoder,
							ZYDIS_MACHINE_MODE_LONG_64,
							ZYDIS_STACK_WIDTH_64);
}
