#include "NexusBootDxe.h"
#include "NexusBootLocate.h"
#include "MapNexusCore.h"                  /* NexusCoreSetRefusalLine */
#include "../../Include/NexusCoreBoot.h"   /* NXC_DXE_REFUSAL / file ids */

#include <Library/BaseMemoryLib.h>

#include "TcgLogTransform.h"               /* snapshot record layout + GetSanitizedPcrState */

//
// ONE HOOK TARGET: bootmgfw.efi. WIM boot (bootmgr.efi) is not supported, so there is no
// second target, no per-target hook variant, and no recursive re-entry into PatchBootManager.
//
NEXUS_HOOK gImgArchHook = { 0 };


//
//  The faux-call template and its open-coded install/re-arm/restore moved to
// NexusHook.c. Three call sites each carried their own copy of the same sequence.
//



/* ============================================================================================
 * bootmgfw!BuildPcrSnapshotData -- the ONLY thing that can close rung B+.
 *
 * WHY (scope doc §3a). The firmware portion of the TCG log ends at event 53. Windows
 * Boot Manager then calls this function and appends event 54: the 0xADF01995 record, holding the
 * PCR values it just read from the REAL TPM. Our GetEventLog transform edits events in PCR 1, 4
 * and 7 -- all extended before bootmgr runs -- so that record contradicts the log we emit, on a
 * check that needs no TPM and no admin. MEASURED on boot 2750: 21 match, 3 MISMATCH.
 *
 * The transform cannot reach it: bootmgr appends to its OWN copy, after taking ours. This hook is
 * the only place the record exists while it is still writable.
 *
 * WHY THIS IS SAFE, and it is the reason this target was chosen over the obvious alternative of
 * hooking the TPM read: IDA on this exact bootmgfw shows TpmW8ApiReadPCRBank20 has EXACTLY TWO
 * cross-references, and BOTH are inside BuildPcrSnapshotData. Nothing else in the boot manager
 * reads the PCR bank through it -- not BitLocker, not an unseal decision, not a policy check. The
 * blast radius is one record. (BitLocker unseal is decided inside the TPM against the real
 * registers regardless of what any log says.)
 *
 * ⚠ STRICTLY OPTIONAL. If the target is not found --
 * a Windows update moves it, say -- we skip the patch and Tier 3 keeps working precisely as it
 * does today. A working spoof must never depend on this.
 *
 * Located by the magic as an IMMEDIATE, via NexusBootLocate. MEASURED: it occurs exactly once
 * in the whole 3 MB image, so there is nothing to disambiguate -- which is why this target was
 * always the least fragile of the three.
 *
 * The surrounding registers are deliberately NOT part of the match. Only the constant carries
 * meaning; pinning the instructions around it would add fragility without adding certainty.
 * ============================================================================================ */

//
// utl::span<uchar,-1>, passed by reference as the 4th argument. Layout confirmed from the
// disassembly: `cmp [rbx+8], rax` compares REMAINING CAPACITY against the size about to be
// written, so +0 is the write cursor and +8 is what is left.
//
typedef struct _BL_UTL_SPAN {
	UINT8*	Data;
	UINTN	Size;
} BL_UTL_SPAN;

typedef INT32 (EFIAPI *t_BuildPcrSnapshotData)(
	IN VOID* TpmContext,
	IN UINT16 AlgId,
	OUT UINT32* Written,
	IN OUT BL_UTL_SPAN* Buffer
	);

STATIC NEXUS_HOOK mBuildPcrSnapshotHook = { 0 };

STATIC
INT32
EFIAPI
HookedBuildPcrSnapshotData(
	IN VOID* TpmContext,
	IN UINT16 AlgId,
	OUT UINT32* Written,
	IN OUT BL_UTL_SPAN* Buffer
	);

STATIC
VOID
ReArmBuildPcrSnapshotHook(
	VOID
	)
{
	NexusHookRearm(&mBuildPcrSnapshotHook);
}

STATIC
INT32
EFIAPI
HookedBuildPcrSnapshotData(
	IN VOID* TpmContext,
	IN UINT16 AlgId,
	OUT UINT32* Written,
	IN OUT BL_UTL_SPAN* Buffer
	)
{

	//
	// Capture the write cursor BEFORE the call. WriteBuffer advances the span as it fills it, so
	// on return Buffer->Data points PAST the record and the only way back to its start is the
	// value we saved.
	//
	UINT8* CONST Start = (Buffer != NULL) ? Buffer->Data : NULL;
	CONST UINTN Avail = (Buffer != NULL) ? Buffer->Size : 0;

	// Remove our own bytes: calling the original through a live hook would recurse.
	NexusHookRestore(&mBuildPcrSnapshotHook);

	CONST INT32 Result = ((t_BuildPcrSnapshotData)mBuildPcrSnapshotHook.Target)(
							TpmContext, AlgId, Written, Buffer);

	ReArmBuildPcrSnapshotHook();

	//
	// Everything below is best-effort. Any refusal leaves bootmgr's genuine record exactly as it
	// built it, which is the correct outcome whenever we cannot produce a better one.
	//
	if (Result < 0 || Start == NULL || Avail < SNAPSHOT_HDR_SIZE)
		return Result;

	UINT8 Pcr[SNAPSHOT_MAX_PCRS][SHA256_DIGEST_SIZE];
	if (!GetSanitizedPcrState(Pcr))
		return Result;      // no sanitization in effect -- the true values ARE the consistent ones

	//
	// Locate our own record by its magic rather than assuming it starts at the cursor. Bounded by
	// the capacity we were handed, so a surprise layout cannot walk us off the buffer.
	//
	UINTN Limit = Avail;
	if (Limit > 0x1000)
		Limit = 0x1000;

	for (UINTN Off = 0; Off + SNAPSHOT_HDR_SIZE <= Limit; Off++)
	{
		UINT8* CONST Rec = Start + Off;
		if (*(CONST UINT32*)Rec != SNAPSHOT_MAGIC)
			continue;

		CONST UINT16 Count = *(CONST UINT16*)(Rec + 8);
		CONST UINT16 Alg   = *(CONST UINT16*)(Rec + 10);
		CONST UINT16 Size  = *(CONST UINT16*)(Rec + 12);

		if (Alg != TPM_ALG_SHA256 || Size != SHA256_DIGEST_SIZE ||
			Count == 0 || Count > SNAPSHOT_MAX_PCRS ||
			Off + SNAPSHOT_HDR_SIZE + (UINTN)Count * Size > Avail)
			return Result;      // not the layout we proved against; leave it alone

		for (UINT16 i = 0; i < Count; i++)
			CopyMem(Rec + SNAPSHOT_HDR_SIZE + (UINTN)i * Size, Pcr[i], Size);

		return Result;
	}

	return Result;
}


/**
 * Install the BuildPcrSnapshotData hook. Optional by design -- every failure path returns without
 * disturbing anything, and the caller ignores the result.
 */
STATIC
EFI_STATUS
PatchBuildPcrSnapshotData(
	IN CONST VOID* ImageBase,
	IN CONST PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	UINT8* Original = NULL;
	CONST EFI_STATUS Status = NexusBootLocateBuildPcrSnapshotData(ImageBase, NtHeaders, &Original);
	if (EFI_ERROR(Status) || Original == NULL)
	{
		Print(L"[TCG] BuildPcrSnapshotData not located (%r) -- rung B+ left open.\r\n", Status);
		return EFI_NOT_FOUND;
	}

	CONST EFI_STATUS HookStatus = NexusHookInstall(&mBuildPcrSnapshotHook, Original,
													(VOID*)&HookedBuildPcrSnapshotData);
	if (EFI_ERROR(HookStatus))
	{
		Print(L"[TCG] BuildPcrSnapshotData hook install failed (%r).\r\n", HookStatus);
		return HookStatus;
	}

	Print(L"[TCG] Hooked bootmgfw!BuildPcrSnapshotData at 0x%p.\r\n", Original);
	return EFI_SUCCESS;
}


//
// bootmgfw!ImgArchStartBootApplication hook. Patches winload.efi.
//
//  Previously this was a shared helper taking OriginalFunction and
// OriginalFunctionBytes so it could serve four thin wrappers -- {bootmgfw, bootmgr} x
// {Vista, Eight}. With only bootmgfw and only the >= 8 calling convention left, the
// indirection has nothing to select between, so the wrappers are gone and this IS the hook.
//
/*
 * ============================================================================================
 * THE BOOT-APPLICATION HOOK
 * ============================================================================================
 *
 * bootmgfw calls ImgArchStartBootApplication once for every boot application it starts, and
 * winload.efi is only one of them. The hook must therefore survive being called for something
 * else -- which is the whole reason for the re-arm below.
 */

STATIC
EFI_STATUS
EFIAPI
HookedImgArchStartBootApplication(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);


/**
 * Pack what we were handed into the boot block.
 *
 * ⚠ "NOT WINLOAD" IS NOT AN ANSWER. FileType collapses everything unrecognised into Unknown,
 * which is the reply that has explained nothing on every occasion it was needed. The PE
 * Subsystem travels with it because that is a FACT read from the image's own header at the
 * moment it was handed over -- no inference about which application it might have been.
 */
STATIC
VOID
EFIAPI
RecordForeignImage(
	IN INPUT_FILETYPE FileType,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	CONST UINT32 SubSystem = (UINT32)HEADER_FIELD(NtHeaders, Subsystem);

	NexusCoreSetBootFlag(NXC_BOOTFLAG_IMGARCH_NOT_WINLOAD |
		((((UINT32)FileType) << NXC_BOOTFLAG_IMGARCH_TYPE_SHIFT) & NXC_BOOTFLAG_IMGARCH_TYPE_MASK) |
		((SubSystem << NXC_BOOTFLAG_IMGARCH_SUBSYS_SHIFT) & NXC_BOOTFLAG_IMGARCH_SUBSYS_MASK));
}


STATIC
EFI_STATUS
EFIAPI
HookedImgArchStartBootApplication(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	)
{
	//
	// ⚠ FIRST STATEMENT, BEFORE THE RESTORE. If anything below faults or refuses, the record must
	// still show that bootmgfw DID call the function we hooked. That fact alone rules out every
	// theory in which the boot path bypasses us, and those theories are expensive to hold.
	//
	NexusCoreSetBootFlag(NXC_BOOTFLAG_IMGARCH_FIRED);

	//
	// HOW MANY TIMES. One call and several are different bugs, and without counting they are
	// indistinguishable after the fact.
	//
	STATIC UINT32 mFireCount = 0;
	if (++mFireCount > 1)
		NexusCoreSetBootFlag(NXC_BOOTFLAG_IMGARCH_MULTI);

	//
	// The hook must come out before the original is called: calling through a live hook recurses.
	// That is what makes it one-shot, and what the re-arm at the bottom exists to undo.
	//
	NexusHookRestore(&gImgArchHook);

	CONST INT32 SavedAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);

	INPUT_FILETYPE FileType = Unknown;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);

	if (NtHeaders == NULL)
	{
		// Recorded BEFORE the prompt: everything after this is console-only and gone by the time
		// Windows boots, which makes this branch and the one below indistinguishable afterwards.
		NexusCoreSetBootFlag(NXC_BOOTFLAG_IMGARCH_BAD_PE);

		Print(L"\r\n[bootmgfw hook] image at 0x%p size 0x%lx is not a valid PE.\r\n"
			L"Press any key to continue anyway, or ESC to reboot.\r\n", ImageBase, ImageSize);
		if (!WaitForKey())
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

		goto Resume;
	}

	FileType = GetInputFileType(ImageBase, (UINTN)ImageSize);
	if (FileType != WinloadEfi)
	{
		RecordForeignImage(FileType, NtHeaders);
		goto Resume;
	}

	Print(L"[ bootmgfw!ImgArchStartBootApplication ]\r\n");
	Print(L"  image      : 0x%p, 0x%lx bytes, %S\r\n", ImageBase, ImageSize,
		FileTypeToString(FileType));
	Print(L"  entry point: 0x%p\r\n",
		((UINT8*)ImageBase + HEADER_FIELD(NtHeaders, AddressOfEntryPoint)));
	Print(L"  app entry  : %a, flags 0x%lx\r\n", AppEntry->Signature, AppEntry->Flags);

	PatchWinload(ImageBase, NtHeaders);

Resume:
	//
	// Restore the console UNCONDITIONALLY, and with the whole saved attribute.
	//
	// The green above is set on every path, so a restore confined to the winload case leaves the
	// screen green for the rest of the boot on the two early exits. And the attribute must go back
	// whole: SetConsoleTextColour takes a FOREGROUND and keeps the current background, so feeding
	// it the saved background nibble yields black on black -- an invisible console, which looks
	// like a hang.
	//
	gST->ConOut->EnableCursor(gST->ConOut, FALSE);
	gST->ConOut->SetAttribute(gST->ConOut, SavedAttribute);
	if (FileType == WinloadEfi)
		gST->ConOut->ClearScreen(gST->ConOut);

	CONST EFI_STATUS CallStatus =
		((t_ImgArchStartBootApplication_Eight)gImgArchHook.Target)(
			AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments);

	//
	// ⚠⚠ NOT WINLOAD -- SO KEEP LOOKING, AND ONLY AFTER THE ORIGINAL HAS RETURNED.
	//
	// Without this the single look is spent on whichever application bootmgfw happened to start
	// first, and any boot where something precedes winload ends with the kernel unpatched and the
	// driver never mapped. Nothing about the boot METHOD differs between a working boot and a
	// failing one; what differs is how many chances we take.
	//
	// Re-arming BEFORE the call would send our own call straight back into the hook -- unbounded
	// recursion in the boot path, which is a hang with no console left to report it. For winload
	// the original never returns, so this is naturally confined to the case that needs it.
	//
	if (FileType != WinloadEfi)
		NexusHookRearm(&gImgArchHook);

	return CallStatus;
}


EFI_STATUS
EFIAPI
PatchBootManager(
	IN CONST VOID* ImageBase,
	IN UINTN ImageSize
	)
{
	if (gBootmgfwHandle == NULL)
		return EFI_NOT_STARTED;

	EFI_STATUS Status;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);

	if (NtHeaders == NULL)
	{
		Status = EFI_LOAD_ERROR;
		Print(L"\r\nPatchBootManager: bootmgfw image at 0x%p size 0x%llx is not a valid PE.\r\n",
			ImageBase, ImageSize);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_BOOTMGR, __LINE__));
		goto Finish;
	}

	UINT16 Major = 0, Minor = 0, Build = 0, Revision = 0;
	Status = GetPeFileVersionInfo(ImageBase, &Major, &Minor, &Build, &Revision, NULL);

	//
	// FAIL CLOSED ON AN UNREADABLE VERSION. A parse failure that only warned would leave the build
	// number at zero, which compares below every floor rather than above it -- so the image would
	// be treated as older than anything supported, or silently patched anyway.
	//
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchBootManager: cannot read bootmgfw version info (%r).\r\n"
			L"Refusing to patch an image whose version is unknown.\r\n", Status);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_BOOTMGR, __LINE__));
		goto Finish;
	}

	Print(L"\r\nPatching bootmgfw.efi v%u.%u.%u.%u...\r\n", Major, Minor, Build, Revision);

	if (Build < NEXUS_MIN_SUPPORTED_BUILD)
	{
		Print(L"\r\nPatchBootManager: unsupported bootmgfw build %u.\r\n"
			L"This driver targets build %u and newer only.\r\n",
			Build, (UINT32)NEXUS_MIN_SUPPORTED_BUILD);
		Status = EFI_UNSUPPORTED;
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_BOOTMGR, __LINE__));
		goto Finish;
	}

	//
	// The locator requires the boot-status constant to land in R8D and the containing function to
	// take at least three arguments, and refuses outright if more than one function qualifies.
	// That last part matters: a plain constant scan matches TWICE in this machine's bootmgfw, and
	// a first-hit-wins search would choose between a 1341-byte five-argument function and a
	// 321-byte one-argument decoy by ordering rather than by identity.
	//
	UINT8* Target = NULL;
	Status = NexusBootLocateImgArchStart(ImageBase, NtHeaders, &Target);
	if (EFI_ERROR(Status) || Target == NULL)
	{
		Print(L"\r\nPatchBootManager: could not locate ImgArchStartBootApplication (%r).\r\n",
			Status);
		Status = EFI_NOT_FOUND;
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_BOOTMGR, __LINE__));
		goto Finish;
	}

	Print(L"\r\nFound ImgArchStartBootApplication at 0x%p, detour at 0x%p.\r\n",
		(VOID*)Target, (VOID*)&HookedImgArchStartBootApplication);

	Status = NexusHookInstall(&gImgArchHook, (VOID*)Target,
							  (VOID*)&HookedImgArchStartBootApplication);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchBootManager: hook install failed (%r).\r\n", Status);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_BOOTMGR, __LINE__));
		goto Finish;
	}

	//
	// The bytes are in, and everything after this point is additive. This is therefore the honest
	// place to claim the rung, and it is what separates "returned early recording no refusal" from
	// "hook installed and bootmgfw never called it".
	//
	NexusCoreSetBootFlag(NXC_BOOTFLAG_IMGARCH_HOOKED);

	//
	// Make the boot manager's embedded PCR snapshot agree with the log the transform emits.
	//
	// ⚠ ONLY WHILE THAT TRANSFORM IS ACTUALLY RUNNING. This patch aligns the snapshot with a log
	// we rewrote. If Secure Boot is genuinely enforcing, the sanitiser stands down and the log is
	// the firmware's own -- patching the snapshot would then CREATE the disagreement this exists
	// to prevent. The two gates must stay identical.
	//
	// Result ignored on purpose: additive, and nothing downstream may depend on it.
	//
	if (gDriverConfig.SpoofSecureBoot && !SecureBootIsGenuinelyEnforcing())
		(VOID)PatchBuildPcrSnapshotData(ImageBase, NtHeaders);

Finish:
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
		if (!WaitForKey())
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	}
	else
	{
		Print(L"Successfully patched bootmgfw!ImgArchStartBootApplication.\r\n");
		RtlSleep(2000);

		if (gDriverConfig.WaitForKeyPress)
		{
			Print(L"\r\nPress any key to continue.\r\n");
			WaitForKey();
		}
	}

	//
	// SUCCESS EITHER WAY: a refusal above already asked, and the user chose to continue. Returning
	// an error here would reboot a machine whose owner just said not to.
	//
	return EFI_SUCCESS;
}
