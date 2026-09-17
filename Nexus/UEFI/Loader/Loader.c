#include <Uefi.h>
#include <Pi/PiDxeCis.h>

#include <Protocol/NexusBoot.h>
#include <Protocol/SimpleFileSystem.h>
#include "ManualMap.h"
#include <Guid/FileInfo.h>
#include <Protocol/LoadedImage.h>
//  <Protocol/LegacyBios.h> was included here but nothing from it was ever
// referenced. Legacy BIOS cannot occur on a UEFI-only, Windows-11-only target -- the same
// reasoning that removed the non-EFI bootmgr detection and PE32 support.
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
//
// PrintLib   -> UnicodeSPrint
// BaseMemoryLib -> CompareMem, SetMem
//
// WHY these are explicit (fixed): without them MSVC emitted C4013
// "'X' undefined; assuming extern returning int" for all three. That is NOT cosmetic
// here. CompareMem returns INTN (64-bit) and its result IS used at the device-path
// signature comparison below (`CompareMem(...) == 0`) to decide which boot target we
// matched. Assumed-int truncates that to 32 bits, so a genuinely non-zero return whose
// low 32 bits are zero would compare EQUAL and we would boot the wrong target. Low
// probability, bad failure. The SetMem/UnicodeSPrint returns are discarded, but all
// three also lost argument type-checking, which is how a bad UnicodeSPrint format
// argument would go unnoticed.
// MEASURED: 3x C4013 before, 0 warnings after, full rebuild.
//
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>


//
// Paths to the driver to try.
//
// DEPLOY LAYOUT (ESP mounts as X:, not S:):
//     X:\EFI\OEM\PlatformBootMgr.efi        <- this Loader; path set by the Boot#### entry
//     X:\EFI\OEM\PlatformRuntimeDxe.efi     <- the DXE this list finds
//
// WHY THESE NAMES. The old \EFI\NexusBoot\NexusBootDxe.efi named the project in a
// place that is READABLE FROM WINDOWS and cannot be scrubbed by the TCG-log sanitizer:
//   - UEFI measures every loaded image's DEVICE PATH IN PLAINTEXT, so the old path appeared by
//     name in PCR[4]/PCR[2] of a log Windows serves via TBS, WMI and MeasuredBoot\*.log.
//   - Worse, it is ALSO in live NVRAM: the Boot#### EFI_LOAD_OPTION carries the FilePathList,
//     which any caller of GetFirmwareEnvironmentVariableW can read. Tier 3 patches the log, but
//     the log is a RECORD of the boot -- these variables are its CONFIGURATION and are out of
//     reach. MEASURED with tools/efi_boot_entries.py.
// Hiding those variables from the GetVariable hook was considered and REJECTED as self-defeating:
// Windows writes boot variables back (bcdedit /set {fwbootmgr}, "restart to firmware", Update's
// boot repair), so the first write to persist a filtered BootOrder would drop our entry and the
// next boot would bypass Nexus entirely. Unremarkable beats invisible.
//
// `*Dxe.efi` is the EDK2 convention for a DXE driver, which is exactly what this is -- following
// the convention every vendor DXE driver follows is less anomalous than any invented name. \EFI\OEM\
// is vendor-NEUTRAL on purpose: \EFI\Dell\ would imply a known expected file set that an extra
// binary contradicts, and \EFI\Microsoft\Boot\ is serviced by Windows Update (which may overwrite
// files there, and a stray binary beside a genuine bootmgfw.efi is MORE suspicious, not less).
// \EFI\Boot\BootX64.efi is the removable-media fallback and already used by Boot0000.
//
// Pair with a COHERENT BIOS description ("Platform Boot Manager"), not a Windows-sounding one --
// a "Windows 11" entry pointing outside \EFI\Microsoft\ is itself the tell.
//
#define NEXUS_DRIVER_FILENAME			L"PlatformRuntimeDxe.efi"
#define NEXUS_DRIVER_FILENAME_LEGACY	L"NexusBootDxe.efi"
STATIC CHAR16* mDriverPaths[] = {
	//
	// Current deploy location, tried FIRST.
	//
	L"\\EFI\\OEM\\" NEXUS_DRIVER_FILENAME,

	//
	// MIGRATION FALLBACKS -- kept deliberately so a HALF-MOVED ESP still boots. Renaming the
	// directory and the file are two separate manual steps on a mounted ESP, and a Loader that
	// only accepted the final state would brick the boot between them. Covers "moved but not
	// renamed" as well as the fully-legacy layout.
	//
	L"\\EFI\\OEM\\" NEXUS_DRIVER_FILENAME_LEGACY,
	L"\\EFI\\NexusBoot\\" NEXUS_DRIVER_FILENAME_LEGACY,

	//
	// Upstream EfiGuard searched only these three. On the first v2 boot that meant the Loader
	// could not find its own DXE: status 800000000000000E (Not Found). It failed gracefully and
	// prompted -- the EfiGuard design working -- but it never loaded. Kept as a last resort.
	//
	L"\\EFI\\Boot\\" NEXUS_DRIVER_FILENAME,
	L"\\EFI\\" NEXUS_DRIVER_FILENAME,
	L"\\" NEXUS_DRIVER_FILENAME
};

STATIC EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInputEx = NULL;

//
// Whether ManualMapRuntimeDriver() succeeded, so Configure() can pass it to the driver. Not derived
// later: by the time the config is sent, the DriverHandle looks identical either way.
//
STATIC BOOLEAN mDriverWasManuallyMapped = FALSE;

//
// Defined further down, next to the boot-menu code it belongs with, but used
// earlier by ReadBootFile().
//
STATIC
EFI_HANDLE
EFIAPI
FindFileSystemByHardDrive(
	IN EFI_DEVICE_PATH_PROTOCOL* BootEntryPath
	);

STATIC
VOID
ResetTextInput(
	VOID
	)
{
	if (mTextInputEx != NULL)
		mTextInputEx->Reset(mTextInputEx, FALSE);
	else
		gST->ConIn->Reset(gST->ConIn, FALSE);
}

STATIC
UINT16
EFIAPI
WaitForKey(
	VOID
	)
{
	EFI_KEY_DATA KeyData = { 0 };
	UINTN Index = 0;
	if (mTextInputEx != NULL)
	{
		gBS->WaitForEvent(1, &mTextInputEx->WaitForKeyEx, &Index);
		mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
	}
	else
	{
		gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
		gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);
	}
	return KeyData.Key.ScanCode;
}

STATIC
UINT16
EFIAPI
WaitForKeyWithTimeout(
	IN UINTN Milliseconds
	)
{
	ResetTextInput();
	gBS->Stall(Milliseconds * 1000);

	EFI_KEY_DATA KeyData = { 0 };
	if (mTextInputEx != NULL)
		mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
	else
		gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);

	ResetTextInput();
	return KeyData.Key.ScanCode;
}

STATIC
UINT16
EFIAPI
PromptInput(
	IN CONST UINT16* AcceptedChars,
	IN UINTN NumAcceptedChars,
	IN UINT16 DefaultSelection
	)
{
	UINT16 SelectedChar;

	while (TRUE)
	{
		SelectedChar = CHAR_NULL;

		EFI_KEY_DATA KeyData = { 0 };
		UINTN Index = 0;
		if (mTextInputEx != NULL)
		{
			gBS->WaitForEvent(1, &mTextInputEx->WaitForKeyEx, &Index);
			mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
		}
		else
		{
			gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
			gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);
		}

		if (KeyData.Key.UnicodeChar == CHAR_LINEFEED || KeyData.Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
		{
			SelectedChar = DefaultSelection;
			break;
		}

		for (UINTN i = 0; i < NumAcceptedChars; ++i)
		{
			if (KeyData.Key.UnicodeChar == AcceptedChars[i])
			{
				SelectedChar = KeyData.Key.UnicodeChar;
				break;
			}
		}

		if (SelectedChar != CHAR_NULL)
			break;
	}

	Print(L"%c\r\n\r\n", SelectedChar);
	return SelectedChar;
}

STATIC
CONST CHAR16*
EFIAPI
StriStr(
	IN CONST CHAR16 *String1,
	IN CONST CHAR16 *String2
	)
{
	if (*String2 == L'\0')
		return String1;

	while (*String1 != L'\0')
	{
		CONST CHAR16* FirstMatch = String1;
		CONST CHAR16* String2Ptr = String2;
		CHAR16 String1Char = CharToUpper(*String1);
		CHAR16 String2Char = CharToUpper(*String2Ptr);

		while (String1Char == String2Char && String1Char != L'\0')
		{
			String1++;
			String2Ptr++;

			String1Char = CharToUpper(*String1);
			String2Char = CharToUpper(*String2Ptr);
		}

		if (String2Char == L'\0')
			return FirstMatch;

		if (String1Char == L'\0')
			return NULL;

		String1 = FirstMatch + 1;
	}
	return NULL;
}

// 
// Try to find a file by browsing each device
// 
STATIC
EFI_STATUS
LocateFile(
	IN CHAR16* ImagePath,
	OUT EFI_DEVICE_PATH** DevicePath
	)
{
	*DevicePath = NULL;

	UINTN NumHandles;
	EFI_HANDLE* Handles;
	EFI_STATUS Status = gBS->LocateHandleBuffer(ByProtocol,
												&gEfiSimpleFileSystemProtocolGuid,
												NULL,
												&NumHandles,
												&Handles);
	if (EFI_ERROR(Status))
		return Status;

	DEBUG((DEBUG_INFO, "[LOADER] Number of UEFI Filesystem Devices: %llu\r\n", NumHandles));

	for (UINTN i = 0; i < NumHandles; i++)
	{
		EFI_FILE_IO_INTERFACE *IoDevice;
		Status = gBS->OpenProtocol(Handles[i],
									&gEfiSimpleFileSystemProtocolGuid,
									(VOID**)&IoDevice,
									gImageHandle,
									NULL,
									EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (Status != EFI_SUCCESS)
			continue;

		EFI_FILE_HANDLE VolumeHandle;
		Status = IoDevice->OpenVolume(IoDevice, &VolumeHandle);
		if (EFI_ERROR(Status))
			continue;

		EFI_FILE_HANDLE FileHandle;
		Status = VolumeHandle->Open(VolumeHandle,
									&FileHandle,
									ImagePath,
									EFI_FILE_MODE_READ,
									EFI_FILE_READ_ONLY);
		if (!EFI_ERROR(Status))
		{
			FileHandle->Close(FileHandle);
			VolumeHandle->Close(VolumeHandle);

			//
			// L5 (fixed: FileDevicePath's result was stored without
			// being checked. It allocates, so NULL is possible, and NULL here combined with the
			// EFI_SUCCESS from Open() below produced "success with a NULL out-parameter".
			//
			*DevicePath = FileDevicePath(Handles[i], ImagePath);
			if (*DevicePath == NULL)
			{
				FreePool((VOID*)Handles);
				return EFI_OUT_OF_RESOURCES;
			}

			CHAR16 *PathString = ConvertDevicePathToText(*DevicePath, TRUE, TRUE);
			DEBUG((DEBUG_INFO, "[LOADER] Found file at %S.\r\n", PathString));
			if (PathString != NULL)
				FreePool(PathString);

			FreePool((VOID*)Handles);
			return EFI_SUCCESS;
		}
		VolumeHandle->Close(VolumeHandle);
	}

	FreePool((VOID*)Handles);

	//
	// L6 (fixed: this used to `return Status`, i.e. whatever the LAST
	// loop iteration happened to leave behind. Two ways that produced EFI_SUCCESS with
	// *DevicePath == NULL:
	//   - NumHandles == 0: the loop never runs, so Status is still the EFI_SUCCESS from
	//     LocateHandleBuffer
	//   - the found-path above returned success without validating FileDevicePath (see L5)
	// and the contract matters, because the two call sites disagree about it: the one in
	// ReadBootFile checks `EFI_ERROR(Status) || Expanded == NULL`, but the driver-load loop in
	// StartNexusBoot checks ONLY the status, then hands the pointer to gBS->LoadImage. That
	// call fails cleanly with EFI_INVALID_PARAMETER, so the symptom was a misleading
	// "LoadImage failed" instead of "driver not found" -- but the contract was still wrong.
	//
	// Reaching here means every filesystem was searched and the file was not on any of them.
	//
	return EFI_NOT_FOUND;
}

//
// Find the optimal available console output mode and set it if it's not already the current mode
//
STATIC
EFI_STATUS
EFIAPI
SetHighestAvailableTextMode(
	VOID
	)
{
	if (gST->ConOut == NULL)
		return EFI_NOT_READY;

	INT32 MaxModeNum = 0;
	UINTN Cols, Rows, MaxWeightedColsXRows = 0;
	EFI_STATUS Status = EFI_SUCCESS;

	for (INT32 ModeNum = 0; ModeNum < gST->ConOut->Mode->MaxMode; ModeNum++)
	{
		Status = gST->ConOut->QueryMode(gST->ConOut, ModeNum, &Cols, &Rows);
		if (EFI_ERROR(Status))
			continue;

		// Accept only modes where the total of (Rows * Columns) >= the previous known best.
		// Use 16:10 as an arbitrary weighting that lies in between the common 4:3 and 16:9 ratios
		CONST UINTN WeightedColsXRows = (16 * Rows) * (10 * Cols);
		if (WeightedColsXRows >= MaxWeightedColsXRows)
		{
			MaxWeightedColsXRows = WeightedColsXRows;
			MaxModeNum = ModeNum;
		}
	}

	if (gST->ConOut->Mode->Mode != MaxModeNum)
	{
		Status = gST->ConOut->SetMode(gST->ConOut, MaxModeNum);
	}

	// Clear screen and enable cursor
	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->EnableCursor(gST->ConOut, TRUE);

	return Status;
}

STATIC
EFI_STATUS
EFIAPI
StartNexusBoot(
	IN BOOLEAN InteractiveConfiguration
	)
{
	NEXUSBOOT_DRIVER_PROTOCOL* NexusBootDriverProtocol;
	EFI_DEVICE_PATH *DriverDevicePath = NULL;

	// 
	// Check if the driver is loaded 
	// 
	EFI_STATUS Status = gBS->LocateProtocol(&gNexusBootDriverProtocolGuid,
											NULL,
											(VOID**)&NexusBootDriverProtocol);
	ASSERT((!EFI_ERROR(Status) || Status == EFI_NOT_FOUND));
	if (Status == EFI_NOT_FOUND)
	{
		Print(L"[LOADER] Locating and loading driver file %S...\r\n", NEXUS_DRIVER_FILENAME);

		//
		// SCOPE ITEM 4c -- try MANUAL MAPPING first, fall back to gBS->LoadImage.
		//
		// LoadImage measures the driver into PCR[2] with its device path in PLAINTEXT, and registers
		// it in the UEFI loaded-image list that LocateHandleBuffer(ByProtocol, LoadedImage) walks.
		// Tier 3 erases the PCR[2] record afterwards but cannot touch the list, and erasing is worse
		// than never producing: it has to succeed every boot and cannot help if bypassed.
		//
		// MEASURED before building this: the other candidate surface -- our hooked gRT pointers --
		// does NOT distinguish us (all six gRT entries share one region on the final map). So the
		// loaded-image list and the PCR[2] record are what identify us, and manual mapping is what
		// removes them.
		//
		// THE FALLBACK IS NOT OPTIONAL. Manual mapping owns relocation, section layout and image
		// lifetime -- all things the firmware normally guarantees. If any of that fails we take the
		// measured-but-working path, because a machine that will not boot is worse than a DXE that
		// gets logged. Both outcomes are printed so a silent downgrade is impossible.
		//
		EFI_HANDLE DriverHandle = NULL;
		Status = EFI_NOT_FOUND;
		for (UINT32 i = 0; i < ARRAY_SIZE(mDriverPaths); ++i)
		{
			Status = ManualMapRuntimeDriver(mDriverPaths[i], &DriverHandle);
			if (!EFI_ERROR(Status))
				break;
		}
		mDriverWasManuallyMapped = !EFI_ERROR(Status);

		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER] manual map unavailable (%r); falling back to LoadImage.\r\n", Status);

			for (UINT32 i = 0; i < ARRAY_SIZE(mDriverPaths); ++i)
			{
				Status = LocateFile(mDriverPaths[i], &DriverDevicePath);
				if (!EFI_ERROR(Status))
					break;
			}
			if (EFI_ERROR(Status))
			{
				Print(L"[LOADER] Failed to find driver file %S.\r\n", NEXUS_DRIVER_FILENAME);
				goto Exit;
			}

			Status = gBS->LoadImage(FALSE, // Request is not from boot manager
									gImageHandle,
									DriverDevicePath,
									NULL,
									0,
									&DriverHandle);
			if (EFI_ERROR(Status))
			{
				Print(L"[LOADER] LoadImage failed: %llx (%r).\r\n", Status, Status);
				goto Exit;
			}

			Status = gBS->StartImage(DriverHandle, NULL, NULL);
			if (EFI_ERROR(Status))
			{
				Print(L"[LOADER] StartImage failed: %llx (%r).\r\n", Status, Status);
				goto Exit;
			}
		}
	}
	else
	{
		ASSERT_EFI_ERROR(Status);
		Print(L"[LOADER] The driver is already loaded.\r\n");
	}

	Status = gBS->LocateProtocol(&gNexusBootDriverProtocolGuid,
								NULL,
								(VOID**)&NexusBootDriverProtocol);
	if (EFI_ERROR(Status))
	{
		Print(L"[LOADER] LocateProtocol failed: %llx (%r).\r\n", Status, Status);
		goto Exit;
	}

	if (InteractiveConfiguration)
	{
		//
		// Interactive driver configuration
		//

		Print(L"Wait for a keypress to continue after each patch stage?\n"
			L"    [1] No (default)\r\n    [2] Yes (for debugging)\r\n    ");
		CONST UINT16 NoYes[] = { L'1', L'2' };
		CONST UINT16 SelectedWaitForKeyPress = PromptInput(NoYes,
														sizeof(NoYes) / sizeof(UINT16),
														L'1');

		//
		// ZERO-INIT: this was a bare `NEXUSBOOT_CONFIGURATION_DATA ConfigData;`
		// with every field assigned individually below. That is fine until someone adds a
		// field to the struct -- which just happened (DisableVbs) -- at which point the new
		// field is sent to Configure() as UNINITIALIZED STACK GARBAGE, giving a boot-to-boot
		// random value for a setting that governs whether VBS is disabled. Zero first, then
		// assign, so adding a field is fail-safe rather than fail-random.
		//
		NEXUSBOOT_CONFIGURATION_DATA ConfigData;
		SetMem(&ConfigData, sizeof(ConfigData), 0);

		ConfigData.WaitForKeyPress = (BOOLEAN)(SelectedWaitForKeyPress == L'2');

		//
		// Force VBS off, as the driver has always done. Set EXPLICITLY rather than relying on
		// the zero-init above, because 0 would mean FALSE here -- i.e. leave VBS alone -- which
		// is the opposite of the behaviour this replaced. See the note on DisableVbs in
		// Include/Protocol/NexusBoot.h for why turning it off is not a casual toggle.
		//
		ConfigData.DisableVbs = TRUE;

		//
		// Tier 1 Secure Boot spoof. Set EXPLICITLY for the same reason as DisableVbs above: the
		// zero-init would mean FALSE, silently disabling it. See the SpoofSecureBoot field docs
		// in Include/Protocol/NexusBoot.h.
		//
		ConfigData.SpoofSecureBoot = TRUE;

		//
		// Tell the driver whether it must relocate itself at SetVirtualAddressMap. Only the Loader
		// knows this -- see the field docs in Include/Protocol/NexusBoot.h.
		//
		ConfigData.ManuallyMapped = mDriverWasManuallyMapped;

		//
		// Send the configuration data to the driver
		//
		Status = NexusBootDriverProtocol->Configure(&ConfigData);

		if (EFI_ERROR(Status))
			Print(L"[LOADER] Driver Configure() returned error %llx (%r).\r\n", Status, Status);
	}

Exit:
	if (DriverDevicePath != NULL)
		FreePool(DriverDevicePath);

	return Status;
}

//
// ── BOOT-THROUGH VIA THE FIRMWARE'S OWN BootOrder / Boot#### VARIABLES ───────
//
// Replaces upstream's UefiBootManagerLib path (EfiBootManagerGetLoadOptions +
// EfiBootManagerGetLoadOptionBuffer + BmRepairAllControllers +
// BmSetMemoryTypeInformationVariable + EfiBootManagerConnectDevicePath +
// BmIsAutoCreateBootOption), which hung this Loader after the DXE
// had already loaded and hooked successfully.
//
// WHY NOT JUST FIX THE LIBRARY PATH: under VisualUefi the EDK2 boot-manager
// stack is only partially present -- several of its protocol GUIDs are
// hand-written stubs in VisualUefi.c rather than real implementations. Code that
// enumerates and repairs controllers has no reason to behave under those
// conditions, and "make the heavy abstraction work" is a worse answer than not
// needing it.
//
// WHY NOT PORT v1's FIX: v1 replaced this with a hardcoded scan for
// \EFI\Microsoft\Boot\bootmgfw.efi across every filesystem handle. That works,
// but it ignores what the firmware is actually configured to boot -- wrong on
// multi-boot machines, on non-Microsoft layouts, and on any setup where the ESP
// is not where it is assumed to be.
//
// WHAT THIS DOES INSTEAD: reads BootOrder and each Boot#### exactly as the
// firmware itself does. Those are UEFI-spec variables (UEFI 2.10 sec. 3.1.1,
// 3.1.3), available through gRT->GetVariable with no library at all. Each entry
// carries the same human-readable Description the firmware shows in its own boot
// menu -- which is also what a Nexus boot menu will display, so enumeration is
// deliberately kept separate from booting.
//
// EFI_LOAD_OPTION layout (UEFI 2.10 sec. 3.1.3):
//     UINT32                    Attributes;
//     UINT16                    FilePathListLength;   // bytes
//     CHAR16                    Description[];        // null-terminated
//     EFI_DEVICE_PATH_PROTOCOL  FilePathList[];       // FilePathListLength bytes
//     UINT8                     OptionalData[];
//
#define NEXUS_MAX_BOOT_OPTIONS 64

typedef struct _NEXUS_BOOT_OPTION {
	UINT16                    OptionNumber;   // the #### in Boot####
	UINT32                    Attributes;
	CHAR16*                   Description;    // points into Data
	EFI_DEVICE_PATH_PROTOCOL* FilePath;       // points into Data
	VOID*                     Data;           // owns the raw variable blob
} NEXUS_BOOT_OPTION;

//
// Reads one Boot#### variable and carves it into its fields.
// Data is allocated on success and owned by the caller.
//
STATIC
EFI_STATUS
EFIAPI
ReadBootOption(
	IN UINT16 OptionNumber,
	OUT NEXUS_BOOT_OPTION* Option
	)
{
	CHAR16 Name[9];
	UnicodeSPrint(Name, sizeof(Name), L"Boot%04x", OptionNumber);

	UINTN Size = 0;
	EFI_STATUS Status = gRT->GetVariable(Name, &gEfiGlobalVariableGuid, NULL, &Size, NULL);
	if (Status != EFI_BUFFER_TOO_SMALL || Size < sizeof(UINT32) + sizeof(UINT16) + sizeof(CHAR16))
		return EFI_NOT_FOUND;

	VOID* Data = AllocateZeroPool(Size);
	if (Data == NULL)
		return EFI_OUT_OF_RESOURCES;

	Status = gRT->GetVariable(Name, &gEfiGlobalVariableGuid, NULL, &Size, Data);
	if (EFI_ERROR(Status))
	{
		FreePool(Data);
		return Status;
	}

	CONST UINT32 Attributes = *(UINT32*)Data;
	CONST UINT16 FilePathListLength = *(UINT16*)((UINT8*)Data + sizeof(UINT32));
	CHAR16* Description = (CHAR16*)((UINT8*)Data + sizeof(UINT32) + sizeof(UINT16));

	//
	// Walk the description to its terminator, but never past the end of the
	// buffer. A malformed variable must not run us off the allocation.
	//
	CONST UINT8* End = (UINT8*)Data + Size;
	CHAR16* Cursor = Description;
	while ((UINT8*)(Cursor + 1) <= End && *Cursor != CHAR_NULL)
		Cursor++;
	if ((UINT8*)(Cursor + 1) > End)
	{
		FreePool(Data);
		return EFI_VOLUME_CORRUPTED;
	}

	UINT8* FilePath = (UINT8*)(Cursor + 1);
	if (FilePathListLength == 0 || FilePath + FilePathListLength > End)
	{
		FreePool(Data);
		return EFI_VOLUME_CORRUPTED;
	}

	Option->OptionNumber = OptionNumber;
	Option->Attributes = Attributes;
	Option->Description = Description;
	Option->FilePath = (EFI_DEVICE_PATH_PROTOCOL*)FilePath;
	Option->Data = Data;
	return EFI_SUCCESS;
}

//
// Enumerates boot options in BootOrder order. Kept separate from booting so a
// boot menu can present this list and let the user choose.
//
STATIC
UINTN
EFIAPI
EnumerateBootOptions(
	OUT NEXUS_BOOT_OPTION* Options,
	IN UINTN MaxOptions
	)
{
	UINTN Size = 0;
	EFI_STATUS Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid, NULL, &Size, NULL);
	if (Status != EFI_BUFFER_TOO_SMALL || Size < sizeof(UINT16))
		return 0;

	UINT16* BootOrder = (UINT16*)AllocateZeroPool(Size);
	if (BootOrder == NULL)
		return 0;

	Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid, NULL, &Size, BootOrder);
	if (EFI_ERROR(Status))
	{
		FreePool(BootOrder);
		return 0;
	}

	CONST UINTN Count = Size / sizeof(UINT16);
	UINTN Found = 0;
	for (UINTN i = 0; i < Count && Found < MaxOptions; i++)
	{
		if (!EFI_ERROR(ReadBootOption(BootOrder[i], &Options[Found])))
			Found++;
	}

	FreePool(BootOrder);
	return Found;
}

STATIC
VOID
EFIAPI
FreeBootOptions(
	IN NEXUS_BOOT_OPTION* Options,
	IN UINTN Count
	)
{
	for (UINTN i = 0; i < Count; i++)
	{
		if (Options[i].Data != NULL)
		{
			FreePool(Options[i].Data);
			Options[i].Data = NULL;
		}
	}
}

//
// Connects a single device path so gBS->LoadImage can resolve it to a handle.
//
// Walks the path: LocateDevicePath resolves as far as a handle already exists
// and hands back the unresolved remainder, then ConnectController is asked to
// produce the next node. Repeat until the whole path resolves or nothing more
// can be connected.
//
// This is the targeted equivalent of EfiBootManagerConnectDevicePath(). It
// touches only the device we are about to boot, unlike ConnectAll() which walks
// every handle in the system and does not reliably terminate under VisualUefi.
//
STATIC
VOID
EFIAPI
ConnectDevicePath(
	IN EFI_DEVICE_PATH_PROTOCOL* DevicePath
	)
{
	if (DevicePath == NULL)
		return;

	//
	// Bounded: a malformed or circular path must not spin here forever. A real
	// device path has far fewer nodes than this.
	//
	for (UINTN Guard = 0; Guard < 64; Guard++)
	{
		EFI_DEVICE_PATH_PROTOCOL* Remaining = DevicePath;
		EFI_HANDLE Handle = NULL;

		EFI_STATUS Status = gBS->LocateDevicePath(&gEfiDevicePathProtocolGuid, &Remaining, &Handle);
		if (EFI_ERROR(Status))
			return;                     // nothing on this path is connectable

		if (IsDevicePathEnd(Remaining))
			return;                     // fully resolved -- done

		Status = gBS->ConnectController(Handle, NULL, Remaining, FALSE);
		if (EFI_ERROR(Status))
			return;                     // cannot get any further
	}
}

//
// Reads a boot option's image into memory so LoadImage never has to resolve a
// device path.
//
// WHY THIS EXISTS: three attempts at making gBS->LoadImage resolve the
// Boot#### FilePath directly all failed with EFI_NOT_FOUND on every entry
// -- with ConnectDevicePath first, and with BootPolicy both FALSE
// and TRUE. Upstream never did it that way either: it called
// EfiBootManagerGetLoadOptionBuffer() to read the file and handed LoadImage a
// SourceBuffer. This is that, without the library.
//
// Resolving the path ourselves also means the failure is diagnosable: we find
// out whether the filesystem, the directory walk, or the read is what breaks,
// instead of a single opaque status from firmware.
//
STATIC
VOID*
EFIAPI
ReadBootFile(
	IN EFI_DEVICE_PATH_PROTOCOL* DevicePath,
	OUT UINTN* FileSize,
	OUT EFI_DEVICE_PATH_PROTOCOL** ResolvedPath
	)
{
	*FileSize = 0;

	//
	// Hand back the path we actually resolved, not the short form we were given.
	//
	// LoadImage uses DevicePath to populate LoadedImage->FilePath and
	// ->DeviceHandle even when SourceBuffer supplies the bytes. Passing the
	// unresolvable short form leaves the image half-initialised, and StartImage
	// then rejects the handle with EFI_INVALID_PARAMETER -- measured,
	// after the image had already loaded and been patched successfully.
	//
	*ResolvedPath = DevicePath;

	//
	// Split the path: LocateDevicePath consumes the device portion and leaves
	// Remaining pointing at the file portion.
	//
	EFI_DEVICE_PATH_PROTOCOL* Remaining = DevicePath;
	EFI_HANDLE DeviceHandle = NULL;
	EFI_STATUS Status = gBS->LocateDevicePath(&gEfiSimpleFileSystemProtocolGuid,
											  &Remaining,
											  &DeviceHandle);
	if (EFI_ERROR(Status))
	{
		//
		// SHORT-FORM DEVICE PATH. Expected, not exceptional.
		//
		// Boot#### entries routinely store a SHORT-FORM path beginning at the
		// HD() node -- e.g. HD(1,GPT,E3A23777-...)/\EFI\Microsoft\Boot\bootmgfw.efi
		// with no PciRoot()/Pci()/NVMe() prefix. That is legal (UEFI 2.10
		// sec. 3.1.2); the firmware boot manager expands it by searching handles
		// for a matching HD node.
		//
		// gBS->LocateDevicePath does EXACT PREFIX matching and performs no such
		// expansion, so it returns EFI_NOT_FOUND for every short-form entry.
		//
		// measured: this failed for ALL boot entries including
		// Boot0005 (NexusBootNoLoader), which points at the very ESP we were
		// executing from and which LocateFile() had successfully searched
		// moments earlier. Our own entry failing is what ruled out device state
		// and identified the short form as the cause -- after three wrong
		// theories (ConnectDevicePath, BootPolicy=FALSE, BootPolicy=TRUE) that
		// all assumed the device was unreachable.
		//
		// Expansion: walk the file components out of the path and let
		// LocateFile() find them by enumerating filesystem handles, which is
		// how this Loader already locates its own DXE.
		//
		CHAR16 FilePath[256];
		FilePath[0] = CHAR_NULL;

		EFI_DEVICE_PATH_PROTOCOL* Node = DevicePath;
		while (!IsDevicePathEnd(Node))
		{
			if (DevicePathType(Node) == MEDIA_DEVICE_PATH &&
				DevicePathSubType(Node) == MEDIA_FILEPATH_DP)
			{
				//
				// L4 (fixed: the StrCatS status was discarded.
				//
				// StrCatS is bounds-safe, so this was never an overflow -- but on failure the
				// SafeString contract sets Destination to an EMPTY STRING. A path split across
				// several FILEPATH nodes (which the loop below explicitly exists to handle)
				// that overflowed on a MIDDLE node would therefore be silently reset and then
				// have the REMAINING nodes appended to it -- yielding a shorter, well-formed,
				// WRONG path. That resolves to a different file rather than failing, which is
				// the worst outcome available here: we would load and patch the wrong image.
				//
				// Truncation is not recoverable, so refuse.
				//
				CONST RETURN_STATUS CatStatus = StrCatS(FilePath,
														ARRAY_SIZE(FilePath),
														((FILEPATH_DEVICE_PATH*)Node)->PathName);
				if (RETURN_ERROR(CatStatus))
				{
					Print(L"[LOADER]   file path exceeds %u chars; refusing to use a truncated path\r\n",
						(UINT32)ARRAY_SIZE(FilePath));
					return NULL;
				}
			}
			Node = NextDevicePathNode(Node);
		}

		if (FilePath[0] == CHAR_NULL)
		{
			Print(L"[LOADER]   no file component in that device path\r\n");
			return NULL;
		}

		EFI_DEVICE_PATH* Expanded = NULL;

		//
		// DUAL-BOOT CORRECTNESS: match the partition first.
		//
		// LocateFile() below returns the FIRST filesystem carrying the path. With
		// one Windows install that is always right; with two, both ESPs hold
		// \EFI\Microsoft\Boot\bootmgfw.efi and "first" silently boots whichever
		// the firmware happened to enumerate earlier.
		//
		// The HD() node in the boot entry carries the GPT partition GUID for
		// exactly this reason, so match on it and build the path from the handle
		// it identifies. Falls through to the search when the entry has no HD()
		// node or nothing matches -- correct behaviour on single-boot systems,
		// and on removable media whose signature will not be known in advance.
		//
		EFI_HANDLE Partition = FindFileSystemByHardDrive(DevicePath);
		if (Partition != NULL)
		{
			Expanded = FileDevicePath(Partition, FilePath);
			if (Expanded != NULL)
				Print(L"[LOADER]   matched partition by GPT signature\r\n");
		}

		if (Expanded == NULL)
		{
			Status = LocateFile(FilePath, &Expanded);
			if (EFI_ERROR(Status) || Expanded == NULL)
			{
				Print(L"[LOADER]   %s not found on any filesystem (%r)\r\n", FilePath, Status);
				return NULL;
			}
		}

		*ResolvedPath = Expanded;       // full path -- LoadImage needs this, not the short form
		Remaining = Expanded;
		Status = gBS->LocateDevicePath(&gEfiSimpleFileSystemProtocolGuid,
									   &Remaining,
									   &DeviceHandle);
		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER]   expanded path still unresolvable (%r)\r\n", Status);
			return NULL;
		}
	}

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* FileSystem = NULL;
	Status = gBS->OpenProtocol(DeviceHandle,
							   &gEfiSimpleFileSystemProtocolGuid,
							   (VOID**)&FileSystem,
							   gImageHandle,
							   NULL,
							   EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(Status) || FileSystem == NULL)
	{
		Print(L"[LOADER]   OpenProtocol(SimpleFileSystem) failed (%r)\r\n", Status);
		return NULL;
	}

	EFI_FILE_PROTOCOL* Root = NULL;
	Status = FileSystem->OpenVolume(FileSystem, &Root);
	if (EFI_ERROR(Status) || Root == NULL)
	{
		Print(L"[LOADER]   OpenVolume failed (%r)\r\n", Status);
		return NULL;
	}

	//
	// Walk the file portion one FILEPATH node at a time. A device path may split
	// a path across several nodes, so this cannot assume a single component.
	//
	EFI_FILE_PROTOCOL* Node = Root;
	while (!IsDevicePathEnd(Remaining))
	{
		if (DevicePathType(Remaining) == MEDIA_DEVICE_PATH &&
			DevicePathSubType(Remaining) == MEDIA_FILEPATH_DP)
		{
			CHAR16* Component = ((FILEPATH_DEVICE_PATH*)Remaining)->PathName;
			EFI_FILE_PROTOCOL* Next = NULL;
			Status = Node->Open(Node, &Next, Component, EFI_FILE_MODE_READ, 0);
			if (Node != Root)
				Node->Close(Node);
			if (EFI_ERROR(Status))
			{
				Print(L"[LOADER]   Open(%s) failed (%r)\r\n", Component, Status);
				Root->Close(Root);
				return NULL;
			}
			Node = Next;
		}
		Remaining = NextDevicePathNode(Remaining);
	}

	if (Node == Root)
	{
		Print(L"[LOADER]   device path carried no file component\r\n");
		Root->Close(Root);
		return NULL;
	}

	//
	// Size the file, then read it whole.
	//
	EFI_FILE_INFO* Info = NULL;
	UINTN InfoSize = 0;
	Status = Node->GetInfo(Node, &gEfiFileInfoGuid, &InfoSize, NULL);
	if (Status == EFI_BUFFER_TOO_SMALL)
	{
		Info = (EFI_FILE_INFO*)AllocateZeroPool(InfoSize);
		if (Info != NULL)
			Status = Node->GetInfo(Node, &gEfiFileInfoGuid, &InfoSize, Info);
	}
	if (EFI_ERROR(Status) || Info == NULL)
	{
		Print(L"[LOADER]   GetInfo failed (%r)\r\n", Status);
		if (Info != NULL)
			FreePool(Info);
		Node->Close(Node);
		Root->Close(Root);
		return NULL;
	}

	CONST UINTN Size = (UINTN)Info->FileSize;
	FreePool(Info);

	VOID* Buffer = AllocatePool(Size);
	if (Buffer == NULL)
	{
		Node->Close(Node);
		Root->Close(Root);
		return NULL;
	}

	UINTN ReadSize = Size;
	Status = Node->Read(Node, &ReadSize, Buffer);
	Node->Close(Node);
	Root->Close(Root);

	if (EFI_ERROR(Status) || ReadSize != Size)
	{
		Print(L"[LOADER]   Read failed (%r, got %llu of %llu)\r\n", Status, ReadSize, Size);
		FreePool(Buffer);
		return NULL;
	}

	*FileSize = Size;
	return Buffer;
}

//
// Does this option look like Windows? Checked against the description and the
// device path text, the same two places upstream looked.
//
STATIC
BOOLEAN
EFIAPI
BootOptionIsWindows(
	IN CONST NEXUS_BOOT_OPTION* Option
	)
{
	if (Option->Description != NULL &&
		(StriStr(Option->Description, L"Windows") != NULL ||
		 StriStr(Option->Description, L"Microsoft") != NULL))
		return TRUE;

	CHAR16* PathText = ConvertDevicePathToText(Option->FilePath, TRUE, TRUE);
	if (PathText == NULL)
		return FALSE;

	CONST BOOLEAN Match = StriStr(PathText, L"bootmgfw.efi") != NULL ||
						  StriStr(PathText, L"\\Microsoft\\") != NULL;
	FreePool(PathText);
	return Match;
}

//
// Finds the filesystem handle a boot entry actually refers to, by matching the
// HD() node rather than taking whatever comes first.
//
// WHY: LocateFile() returns the FIRST filesystem carrying a given path. With one
// Windows install that is always right. On a DUAL-BOOT machine two ESPs can both
// hold \EFI\Microsoft\Boot\bootmgfw.efi, and "first" is then a coin toss that
// silently boots the wrong OS.
//
// The HD() node in a Boot#### entry carries the partition signature (a GPT GUID,
// or an MBR signature) precisely so the firmware can tell those two apart. That
// is the field to match on.
//
// Returns NULL if the entry has no HD() node, or no connected filesystem matches
// it -- the caller then falls back to the search-by-path behaviour, which is
// still correct on single-boot systems.
//
STATIC
EFI_HANDLE
EFIAPI
FindFileSystemByHardDrive(
	IN EFI_DEVICE_PATH_PROTOCOL* BootEntryPath
	)
{
	//
	// Locate the HD() node in the boot entry.
	//
	HARDDRIVE_DEVICE_PATH* Wanted = NULL;
	for (EFI_DEVICE_PATH_PROTOCOL* Node = BootEntryPath;
		 !IsDevicePathEnd(Node);
		 Node = NextDevicePathNode(Node))
	{
		if (DevicePathType(Node) == MEDIA_DEVICE_PATH &&
			DevicePathSubType(Node) == MEDIA_HARDDRIVE_DP)
		{
			Wanted = (HARDDRIVE_DEVICE_PATH*)Node;
			break;
		}
	}
	if (Wanted == NULL)
		return NULL;                    // no partition info to match on

	UINTN HandleCount = 0;
	EFI_HANDLE* Handles = NULL;
	EFI_STATUS Status = gBS->LocateHandleBuffer(ByProtocol,
												&gEfiSimpleFileSystemProtocolGuid,
												NULL,
												&HandleCount,
												&Handles);
	if (EFI_ERROR(Status))
		return NULL;

	EFI_HANDLE Match = NULL;
	for (UINTN i = 0; i < HandleCount && Match == NULL; i++)
	{
		EFI_DEVICE_PATH_PROTOCOL* HandlePath = NULL;
		if (EFI_ERROR(gBS->HandleProtocol(Handles[i],
										  &gEfiDevicePathProtocolGuid,
										  (VOID**)&HandlePath)) || HandlePath == NULL)
			continue;

		for (EFI_DEVICE_PATH_PROTOCOL* Node = HandlePath;
			 !IsDevicePathEnd(Node);
			 Node = NextDevicePathNode(Node))
		{
			if (DevicePathType(Node) != MEDIA_DEVICE_PATH ||
				DevicePathSubType(Node) != MEDIA_HARDDRIVE_DP)
				continue;

			CONST HARDDRIVE_DEVICE_PATH* Have = (CONST HARDDRIVE_DEVICE_PATH*)Node;

			//
			// Match on the partition SIGNATURE, not the partition number.
			// Numbers are per-disk and collide across disks; the GPT GUID (or MBR
			// signature) is what actually identifies the partition.
			//
			if (Have->SignatureType == Wanted->SignatureType &&
				Have->MBRType == Wanted->MBRType &&
				CompareMem(Have->Signature, Wanted->Signature, sizeof(Wanted->Signature)) == 0)
			{
				Match = Handles[i];
				break;
			}
		}
	}

	FreePool(Handles);
	return Match;
}

//
// Boot menu.
//
// Restores the capability v1 had and upstream never did. Two things it must
// provide, learned from this session:
//   - a CLEAN BOOT that skips loading the DXE entirely. That was the user's
//     recovery path every time a bad build would not boot, and it only works if
//     the choice happens BEFORE StartNexusBoot().
//   - the ability to pick a specific entry, which is what makes dual-boot usable.
//
// Descriptions come straight from Boot####, so they read exactly as the
// firmware's own menu does.
//
// Returns the index into Options to boot, or:
//   MENU_BOOT_DEFAULT  -- normal automatic behaviour (first Windows entry)
//   MENU_BOOT_CLEAN    -- boot without loading the DXE
//   MENU_EXIT_FIRMWARE -- hand back to firmware setup
//
#define MENU_BOOT_DEFAULT   ((UINTN)-1)
#define MENU_BOOT_CLEAN     ((UINTN)-2)
#define MENU_EXIT_FIRMWARE  ((UINTN)-3)
#define MENU_TIMEOUT_SECONDS 5

//
// Reads one keystroke and returns BOTH its scan code and its character.
//
// WHY THIS EXISTS: WaitForKey() and WaitForKeyWithTimeout() return only the
// SCAN CODE, discarding UnicodeChar. That is fine for upstream, which only ever
// tested for HOME and ESC -- both scan codes.
//
// A menu needs characters too. The first version of ShowBootMenu() called
// WaitForKey(), saw scan code 0, and then called ReadKeyStroke() to fetch the
// character -- but WaitForKey() had ALREADY CONSUMED that keystroke, so the
// second read returned EFI_NOT_READY against a zeroed struct. Arrow keys worked
// (they are scan codes); Enter, C and F did nothing at all. measured.
//
// Read once, keep both halves.
//
// TimeoutMs == 0 blocks until a key arrives. Otherwise it waits that long and
// returns FALSE if nothing was pressed.
//
STATIC
BOOLEAN
EFIAPI
MenuReadKey(
	IN UINTN TimeoutMs,
	OUT EFI_INPUT_KEY* Key
	)
{
	SetMem(Key, sizeof(*Key), 0);

	if (TimeoutMs == 0)
	{
		UINTN Index = 0;
		gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
		return !EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, Key));
	}

	//
	// Poll rather than Stall-then-read, so a keypress registers immediately
	// instead of only being noticed once the whole slice has elapsed.
	//
	for (UINTN Waited = 0; Waited < TimeoutMs; Waited += 10)
	{
		if (!EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, Key)))
			return TRUE;
		gBS->Stall(10 * 1000);
	}
	return FALSE;
}

STATIC
UINTN
EFIAPI
ShowBootMenu(
	IN NEXUS_BOOT_OPTION* Options,
	IN UINTN Count
	)
{
	UINTN Selected = 0;
	UINTN Countdown = MENU_TIMEOUT_SECONDS;

	while (TRUE)
	{
		gST->ConOut->ClearScreen(gST->ConOut);
		Print(L"\r\n  NexusBoot\r\n");
		Print(L"  ---------------------------------------------\r\n\r\n");

		for (UINTN i = 0; i < Count; i++)
		{
			Print(L"   %c [%u] %s\r\n",
				  (i == Selected) ? L'>' : L' ',
				  (UINT32)(i + 1),
				  Options[i].Description);
		}

		Print(L"\r\n   %c [C] Boot clean (do not load NexusBootDxe)\r\n",
			  (Selected == Count) ? L'>' : L' ');
		Print(L"   %c [F] Exit to firmware\r\n",
			  (Selected == Count + 1) ? L'>' : L' ');

		Print(L"\r\n  ---------------------------------------------\r\n");
		if (Countdown > 0)
			Print(L"  Auto-boot in %u...  (any key to stop)\r\n", (UINT32)Countdown);
		else
			Print(L"  Up/Down to select, Enter to boot.\r\n");

		//
		// While counting down, poll in 1s slices so a keypress cancels it.
		// Once the user has interacted, block properly -- no accidental boot
		// while they are reading.
		//
		EFI_INPUT_KEY Key;
		if (Countdown > 0)
		{
			if (!MenuReadKey(1000, &Key))
			{
				Countdown--;
				if (Countdown == 0)
					return MENU_BOOT_DEFAULT;     // walked away: normal boot
				continue;
			}
			Countdown = 0;                        // user is here; stop the timer
		}
		else
		{
			if (!MenuReadKey(0, &Key))
				continue;
		}

		//
		// Scan codes and characters are mutually exclusive: a key delivers one or
		// the other, so both are checked against the SAME keystroke.
		//
		if (Key.ScanCode == SCAN_UP && Selected > 0)
			Selected--;
		else if (Key.ScanCode == SCAN_DOWN && Selected < Count + 1)
			Selected++;
		else if (Key.ScanCode == SCAN_ESC)
			return MENU_EXIT_FIRMWARE;
		else if (Key.UnicodeChar == L'c' || Key.UnicodeChar == L'C')
			return MENU_BOOT_CLEAN;
		else if (Key.UnicodeChar == L'f' || Key.UnicodeChar == L'F')
			return MENU_EXIT_FIRMWARE;
		else if (Key.UnicodeChar >= L'1' && Key.UnicodeChar < (CHAR16)(L'1' + Count))
			return (UINTN)(Key.UnicodeChar - L'1');
		else if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN || Key.UnicodeChar == CHAR_LINEFEED)
		{
			if (Selected == Count)     return MENU_BOOT_CLEAN;
			if (Selected == Count + 1) return MENU_EXIT_FIRMWARE;
			return Selected;
		}
	}
}

//
// Loads and starts ONE boot option. Shared by the automatic path and the menu's
// explicit choice so both behave identically -- same path expansion, same
// partition matching, same diagnostics.
//
STATIC
BOOLEAN
EFIAPI
BootChosenOption(
	IN NEXUS_BOOT_OPTION* Option
	)
{
	Print(L"[LOADER] Booting Boot%04x: %s\r\n", Option->OptionNumber, Option->Description);

	//
	// Connect this device path before loading from it. Cheap, and harmless when
	// the device is already connected.
	//
	ConnectDevicePath(Option->FilePath);

	UINTN FileSize = 0;
	EFI_DEVICE_PATH_PROTOCOL* ResolvedPath = NULL;
	VOID* FileBuffer = ReadBootFile(Option->FilePath, &FileSize, &ResolvedPath);
	if (FileBuffer == NULL)
		return FALSE;

	EFI_HANDLE ImageHandle = NULL;
	EFI_STATUS Status = gBS->LoadImage(TRUE,
									   gImageHandle,
									   ResolvedPath,   // resolved, NOT the short form
									   FileBuffer,
									   FileSize,
									   &ImageHandle);
	FreePool(FileBuffer);
	if (EFI_ERROR(Status))
	{
		Print(L"[LOADER] LoadImage failed: %llx (%r)\r\n", Status, Status);
		return FALSE;
	}

	//
	// Publish BootCurrent so the OS loader sees which entry it came from.
	// Non-fatal: bootmgfw reads it for diagnostics, not correctness.
	//
	gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
					 &gEfiGlobalVariableGuid,
					 EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
					 sizeof(Option->OptionNumber),
					 (VOID*)&Option->OptionNumber);

	Status = gBS->StartImage(ImageHandle, NULL, NULL);
	if (EFI_ERROR(Status))
	{
		Print(L"[LOADER] StartImage failed: %llx (%r)\r\n", Status, Status);
		return FALSE;
	}
	return TRUE;
}

//
// Boots the first viable entry in BootOrder.
//
// SkipOptionNumber is our own Boot#### (from BootCurrent) so we never boot
// ourselves recursively. RequireWindows restricts the first pass; the caller
// retries without it.
//
STATIC
BOOLEAN
EFIAPI
BootWindowsFromBootOrder(
	IN UINT16 SkipOptionNumber,
	IN BOOLEAN RequireWindows
	)
{
	NEXUS_BOOT_OPTION Options[NEXUS_MAX_BOOT_OPTIONS];
	SetMem(Options, sizeof(Options), 0);

	CONST UINTN Count = EnumerateBootOptions(Options, NEXUS_MAX_BOOT_OPTIONS);
	if (Count == 0)
	{
		Print(L"[LOADER] No boot options found in BootOrder.\r\n");
		return FALSE;
	}

	BOOLEAN Booted = FALSE;
	for (UINTN i = 0; i < Count && !Booted; i++)
	{
		if (Options[i].OptionNumber == SkipOptionNumber)
			continue;                                   // never boot ourselves
		if ((Options[i].Attributes & LOAD_OPTION_ACTIVE) == 0)
			continue;                                   // firmware has it disabled
		if (RequireWindows && !BootOptionIsWindows(&Options[i]))
			continue;

		Booted = BootChosenOption(&Options[i]);
	}

	FreeBootOptions(Options, Count);
	return Booted;
}


EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
	)
{
	//
	// NOTE: upstream called EfiBootManagerConnectAll() here.
	//
	// That walks every handle and connects every driver to every controller. It
	// is where this Loader HUNG: the DXE had already loaded and
	// installed both hooks (visible on screen), and then nothing further
	// happened. Under VisualUefi the UefiBootManagerLib stack is only partially
	// present -- several of its protocol GUIDs are hand-supplied stubs in
	// VisualUefi.c -- so a full connect-all has no reason to terminate cleanly.
	//
	// It is not needed. We boot via the firmware's own BootOrder/Boot#### entries
	// (see BootWindowsFromBootOrder), whose device paths the firmware has already
	// connected in order to enumerate them. gBS->LoadImage connects what it needs
	// on demand.
	//

	//
	// Set the highest available console mode and clear the screen
	//
	SetHighestAvailableTextMode();

	//
	// Turn off the watchdog timer
	//
	gBS->SetWatchdogTimer(0, 0, 0, NULL);

	//
	// Query the console input handle for the Simple Text Input Ex protocol
	//
	gBS->HandleProtocol(gST->ConsoleInHandle, &gEfiSimpleTextInputExProtocolGuid, (VOID **)&mTextInputEx);

	//
	// ── BOOT MENU ───────────────────────────────────────────────────────────
	//
	// Shown BEFORE the driver loads, deliberately. The clean-boot option has to
	// be able to skip StartNexusBoot() entirely -- that is the whole point of it,
	// and it was the user's recovery path throughout the v1 era whenever a build
	// would not boot. A menu placed after the load could not offer that.
	//
	NEXUS_BOOT_OPTION MenuOptions[NEXUS_MAX_BOOT_OPTIONS];
	SetMem(MenuOptions, sizeof(MenuOptions), 0);
	UINTN MenuCount = EnumerateBootOptions(MenuOptions, NEXUS_MAX_BOOT_OPTIONS);

	//
	// Drop OUR OWN entry from the menu.
	//
	// BootCurrent is the Boot#### the firmware used to start us. Leaving it in
	// the list lets the user select it, which loads Loader.efi again -- a NESTED
	// Loader that finds the DXE already present ("an instance of the driver is
	// already loaded"), draws its own menu, and leaves the user apparently back
	// where they started. measured: selecting entry 1 did exactly
	// this, and letting the nested instance time out then booted Windows, which
	// is what made it look like the selection had "done something".
	//
	// BootWindowsFromBootOrder() already skips this entry. The menu has to as
	// well, and filtering here keeps the displayed numbers matching what booting
	// actually does.
	//
	// Read BootCurrent BEFORE the menu -- the later read for the automatic path
	// happens after StartNexusBoot(), which is too late to be useful here.
	//
	{
		UINT16 SelfOption = 0xFFFF;
		UINT32 SelfAttributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
		UINTN SelfSize = sizeof(SelfOption);
		if (!EFI_ERROR(gRT->GetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
										&gEfiGlobalVariableGuid,
										&SelfAttributes,
										&SelfSize,
										&SelfOption)))
		{
			UINTN Kept = 0;
			for (UINTN i = 0; i < MenuCount; i++)
			{
				if (MenuOptions[i].OptionNumber == SelfOption)
				{
					if (MenuOptions[i].Data != NULL)
						FreePool(MenuOptions[i].Data);
					SetMem(&MenuOptions[i], sizeof(MenuOptions[i]), 0);
					continue;
				}
				if (Kept != i)
					MenuOptions[Kept] = MenuOptions[i];
				Kept++;
			}
			MenuCount = Kept;
		}
	}

	UINTN MenuChoice = MENU_BOOT_DEFAULT;
	if (MenuCount > 0)
		MenuChoice = ShowBootMenu(MenuOptions, MenuCount);

	if (MenuChoice == MENU_EXIT_FIRMWARE)
	{
		FreeBootOptions(MenuOptions, MenuCount);
		gBS->Exit(gImageHandle, EFI_SUCCESS, 0, NULL);
		return EFI_SUCCESS;
	}

	CONST BOOLEAN CleanBoot = (MenuChoice == MENU_BOOT_CLEAN);
	if (CleanBoot)
		Print(L"[LOADER] CLEAN BOOT -- NexusBootDxe will NOT be loaded.\r\n");

	//
	// Allow user to configure the driver by pressing a hotkey
	//
	CONST BOOLEAN InteractiveConfiguration = FALSE;

	//
	// Locate, load, start and configure the driver
	//
	CONST EFI_STATUS DriverStatus = CleanBoot
		? EFI_SUCCESS
		: StartNexusBoot(InteractiveConfiguration);
	if (EFI_ERROR(DriverStatus))
	{
		Print(L"\r\nERROR: driver load failed with status %llx (%r).\r\n"
			L"Press any key to continue, or press ESC to return to the firmware or shell.\r\n",
			DriverStatus, DriverStatus);
		if (WaitForKey() == SCAN_ESC)
		{
			gBS->Exit(gImageHandle, DriverStatus, 0, NULL);
			return DriverStatus;
		}
	}

	//
	// Start the "boot through" procedure to boot Windows.
	//
	// First obtain our own boot option number, since we don't want to boot ourselves again
	UINT16 CurrentBootOptionIndex;
	UINT32 Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
	UINTN Size = sizeof(CurrentBootOptionIndex);
	CONST EFI_STATUS Status = gRT->GetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
												&gEfiGlobalVariableGuid,
												&Attributes,
												&Size,
												&CurrentBootOptionIndex);
	if (EFI_ERROR(Status))
	{
		CurrentBootOptionIndex = 0xFFFF;
		Print(L"WARNING: failed to query the current boot option index variable.\r\n"
			L"This could lead to the current device being booted recursively.\r\n"
			L"If you booted from a removable device, it is recommended that you remove it now.\r\n"
			L"\r\nPress any key to continue...\r\n");
		WaitForKey();
	}

	// Query all boot options, and try each following the order set in the "BootOrder" variable, except
	// (1) Do not boot ourselves again, and
	// (2) The description or filename must indicate the boot option is some form of Windows.
	BOOLEAN BootSuccess = FALSE;

	if (MenuChoice < MenuCount)
	{
		//
		// The user picked a specific entry. Honour it and nothing else -- do not
		// silently fall through to another OS if it fails, because on a dual-boot
		// machine that would boot the one they did not choose.
		//
		BootSuccess = BootChosenOption(&MenuOptions[MenuChoice]);
		if (!BootSuccess)
		{
			Print(L"\r\nSelected entry failed to boot. Press any key to try the rest.\r\n");
			WaitForKey();
		}
	}

	FreeBootOptions(MenuOptions, MenuCount);

	//
	// CLEAN BOOT respects BootOrder exactly -- no Windows preference.
	//
	// "Clean boot" means pretend we are not here, so it must not override the
	// firmware's configured order. The Windows-first pass below is correct for
	// the BOOTKIT path (this exists to patch Windows, so it should seek out the
	// entry it is going to patch), but wrong for the escape hatch.
	//
	// The difference only shows on a multi-OS machine. With
	// BootOrder = [Nexus, Ubuntu, Windows], firmware without us boots Ubuntu,
	// while a Windows-first pass would boot Windows -- silently overriding the
	// user's choice at exactly the moment they are using the recovery path and
	// want predictable behaviour.
	//
	if (!BootSuccess && CleanBoot)
		BootSuccess = BootWindowsFromBootOrder(CurrentBootOptionIndex, FALSE);

	if (!BootSuccess)
		BootSuccess = BootWindowsFromBootOrder(CurrentBootOptionIndex, TRUE);
	if (!BootSuccess)
	{
		// No entry looked like Windows; retry without that restriction.
		BootSuccess = BootWindowsFromBootOrder(CurrentBootOptionIndex, FALSE);
	}

	if (BootSuccess)
		return EFI_SUCCESS;

	// We should never reach this unless something is seriously wrong (no boot device / partition table corrupted / catastrophic boot manager failure...)
	Print(L"Failed to boot anything. This is super bad!\r\n"
		L"Press any key to return to the firmware or shell,\r\nwhich will surely fix this and not make things worse.\r\n");
	WaitForKey();

	gBS->Exit(gImageHandle, EFI_SUCCESS, 0, NULL);

	return EFI_SUCCESS;
}
