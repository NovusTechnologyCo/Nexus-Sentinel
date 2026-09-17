#include "NexusBootDxe.h"
// For NexusCoreSetKernelPatchLine + the NXC_DXE_REFUSAL packing. Every refusal in this file records
// WHERE it gave up -- into the kernel patch's OWN slot, never the shared DxeRefusalLine (see the
// header comment on the setter for why sharing it would mask the bind failure that actually matters).
#include "MapNexusCore.h"
#include "../../Include/NexusCoreBoot.h"

#include "NexusPgLocate.h"

#include <Library/BaseMemoryLib.h>


// Global kernel patch status information.
//
// The justification for statically allocating these ~8KB is that this buffer will be accessible during both contexts of winload.efi. Winload has two
// runtime contexts: the real mode firmware context (= 1), in which EFI services are accessible, and the protected mode application context (= 0),
// which has its own GDT, IDT and paging levels and which is used to set up the NT environment and enable virtual addressing. Winload switches between
// the two with BlpArchSwitchContext() when needed. Because we cannot allocate memory in protected mode (e.g. in PatchNtoskrnl), and any memory
// allocated in real mode (e.g. in PatchWinload) will need address translation on later access, this is by far the simplest solution
// because it allows the buffer to be accessed from both contexts at all stages of driver execution.
KERNEL_PATCH_INFORMATION gKernelPatchInfo;


//
// Defuses the PatchGuard initialisation routines before control passes to the kernel.
// Everything touched here lives in INIT and .text.
//
// (!) LOCATION LIVES IN NexusPgLocate.c, NOT HERE. Targets are identified by what their code
// MEANS rather than by byte signatures -- see that header, including its note on what the
// approach is and is not demonstrated to buy.
//
// What remains here is the small part: deciding which targets are mandatory,
// and writing the patches.
//
STATIC
EFI_STATUS
EFIAPI
DisablePatchGuard(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN PEFI_IMAGE_SECTION_HEADER InitSection,
	IN PEFI_IMAGE_SECTION_HEADER TextSection,
	IN UINT16 BuildNumber
	)
{
	//
	// Sections are still taken as parameters because the caller has already validated them
	// and the g_PgContext relocation needs InitSection's address. TextSection and BuildNumber
	// are no longer read: the locator derives sections itself, and every supported build is
	// past NEXUS_MIN_SUPPORTED_BUILD, which PatchNtoskrnl() enforces before calling here.
	//
	(VOID)TextSection;
	(VOID)BuildNumber;

	PRINT_KERNEL_PATCH_MSG(L"\r\n== Locating PatchGuard routines in INIT and .text ==\r\n");

	NEXUS_PG_TARGETS Targets;
	CONST EFI_STATUS Status = NexusPgLocateTargets(ImageBase, NtHeaders, &Targets);
	if (EFI_ERROR(Status))
	{
		PRINT_KERNEL_PATCH_MSG(L"    Failed to locate the required PatchGuard routines (%r).\r\n",
			Status);
		NexusCoreSetKernelPatchLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_NTOSKRNL, __LINE__));
		return Status;
	}

	PRINT_KERNEL_PATCH_MSG(L"    KeInitAmd64SpecificState   [RVA: 0x%X]\r\n",
		(UINT32)(Targets.KeInitAmd64SpecificState - ImageBase));
	PRINT_KERNEL_PATCH_MSG(L"    CcInitializeBcbProfiler    [RVA: 0x%X]\r\n",
		(UINT32)(Targets.CcInitializeBcbProfiler - ImageBase));

	//
	// The patches. Three bytes each, except g_PgContext.
	//
	CONST UINT32 Yes = 0xC301B0;    // mov al, 1 ; ret
	CONST UINT32 No = 0xC3C033;     // xor eax, eax ; ret

	CopyWpMem(Targets.KeInitAmd64SpecificState, &No, sizeof(No));
	CopyWpMem(Targets.CcInitializeBcbProfiler, &Yes, sizeof(Yes));

	if (Targets.ExpLicenseWatchInitWorker != NULL)
	{
		CopyWpMem(Targets.ExpLicenseWatchInitWorker, &No, sizeof(No));
		PRINT_KERNEL_PATCH_MSG(L"    ExpLicenseWatchInitWorker  [RVA: 0x%X]\r\n",
			(UINT32)(Targets.ExpLicenseWatchInitWorker - ImageBase));
	}
	else
	{
		PRINT_KERNEL_PATCH_MSG(L"    ExpLicenseWatchInitWorker  NOT FOUND -- skipped.\r\n");
	}

	if (Targets.KiVerifyScopesExecute != NULL)
	{
		CopyWpMem(Targets.KiVerifyScopesExecute, &No, sizeof(No));
		PRINT_KERNEL_PATCH_MSG(L"    KiVerifyScopesExecute      [RVA: 0x%X]\r\n",
			(UINT32)(Targets.KiVerifyScopesExecute - ImageBase));
	}
	else
	{
		PRINT_KERNEL_PATCH_MSG(L"    KiVerifyScopesExecute      NOT FOUND -- skipped.\r\n");
	}

	//
	// Both callers or neither. Stubbing one of the two leaves the other reaching a bugcheck
	// path that the first no longer guards, which is worse than leaving both alone.
	//
	if (Targets.KiMcaDeferredRecoveryServiceCallers[0] != NULL &&
		Targets.KiMcaDeferredRecoveryServiceCallers[1] != NULL)
	{
		CopyWpMem(Targets.KiMcaDeferredRecoveryServiceCallers[0], &No, sizeof(No));
		CopyWpMem(Targets.KiMcaDeferredRecoveryServiceCallers[1], &No, sizeof(No));
		PRINT_KERNEL_PATCH_MSG(L"    KiMcaDeferredRecoveryService callers [RVAs: 0x%X, 0x%X]\r\n",
			(UINT32)(Targets.KiMcaDeferredRecoveryServiceCallers[0] - ImageBase),
			(UINT32)(Targets.KiMcaDeferredRecoveryServiceCallers[1] - ImageBase));
	}
	else
	{
		PRINT_KERNEL_PATCH_MSG(L"    KiMcaDeferredRecoveryService callers NOT FOUND -- skipped.\r\n");
	}

	//
	// (!) THESE TWO ARE ALTERNATIVES, NOT BOTH.
	//
	// The preferred defusal repoints g_PgContext at the discardable INIT section, so the
	// context PatchGuard later verifies is memory the kernel has already thrown away. Only if
	// that pointer could not be located AND VALIDATED do we fall back to NOPping the
	// KiSwInterrupt dispatch call, which merely stops int 20h from reaching the verifier.
	//
	// The fallback is strictly weaker, which is why it is a fallback.
	//
	if (Targets.PgContext != NULL)
	{
		CONST UINT64 NewPgContextAddress = (UINT64)(UINTN)ImageBase + InitSection->VirtualAddress;
		CopyWpMem(Targets.PgContext, &NewPgContextAddress, sizeof(NewPgContextAddress));
		NexusCoreSetPgContextRva((UINT32)(Targets.PgContext - ImageBase));
		PRINT_KERNEL_PATCH_MSG(L"    g_PgContext                [RVA: 0x%X] -> INIT\r\n",
			(UINT32)(Targets.PgContext - ImageBase));
	}
	else if (Targets.KiSwInterruptPatchSite != NULL && Targets.KiSwInterruptPatchLength > 0)
	{
		//
		// Length comes from the decode, not from sizeof() a signature array. If the encoding
		// of sti/lea/call/cli ever differs, the NOP run follows it instead of overrunning
		// into the next instruction or leaving a tail of the old one behind.
		//
		SetWpMem(Targets.KiSwInterruptPatchSite, Targets.KiSwInterruptPatchLength, 0x90);
		PRINT_KERNEL_PATCH_MSG(L"    KiSwInterrupt dispatch     [RVA: 0x%X] -> %u x nop\r\n",
			(UINT32)(Targets.KiSwInterruptPatchSite - ImageBase),
			Targets.KiSwInterruptPatchLength);
	}
	else
	{
		//
		// Not fatal. The system boots; it simply bugchecks if int 20h is ever issued from
		// kernel mode, which nothing normally does.
		//
		PRINT_KERNEL_PATCH_MSG(L"    g_PgContext and KiSwInterrupt both NOT FOUND -- skipped.\r\n");
	}

	PRINT_KERNEL_PATCH_MSG(L"\r\n");
	return EFI_SUCCESS;
}


//
// Patches ntoskrnl.exe
//
EFI_STATUS
EFIAPI
PatchNtoskrnl(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ntoskrnl.exe at 0x%llX, size 0x%llX\r\n", (UINTN)ImageBase, (UINTN)NtHeaders->OptionalHeader.SizeOfImage);

	// Print file and version info
	UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
	UINT32 FileFlags = 0;
	EFI_STATUS Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, &FileFlags);
	if (EFI_ERROR(Status))
	{
		//
		// K1 -- FAIL CLOSED (fixed. THIRD instance of this pattern,
		// after B3 (PatchBootmgr.c) and W1 (PatchWinload.c): a version-info parse failure only
		// WARNED and fell through, leaving BuildNumber == 0 and
		// gKernelPatchInfo.KernelBuildNumber == 0.
		//
		// Worse here than elsewhere, because BOTH guards lived in the `else` arm:
		//   - the supported-version floor was skipped entirely
		//   - the CHECKED-KERNEL rejection was skipped too, and that one exists because a
		//     checked build's PatchGuard and DSE init code differ enough (missing
		//     optimisations) that patching it is not merely useless but actively unsafe
		// so a parse failure meant patching an image we had explicitly decided not to patch.
		//
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: failed to obtain ntoskrnl.exe version info. Status: %llx\r\n"
			L"Refusing to patch a kernel whose version cannot be determined.\r\n", Status);
		NexusCoreSetKernelPatchLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_NTOSKRNL, __LINE__));
		return EFI_UNSUPPORTED;
	}

	PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] Patching ntoskrnl.exe v%u.%u.%u.%u...\r\n", MajorVersion, MinorVersion, BuildNumber, Revision);

	//
	// Record the version DURABLY, not just to a console that scrolls away. This is the identity of
	// the binary every signature below is matched against, and after a failure it is the first thing
	// you need.
	//
	// BOTH halves, and the REVISION is the important one: ntoskrnl here is 10.0.26100.8894 while
	// Windows reports itself as build 26200 / "25H2" (25H2 is an enablement package over 24H2's
	// branch). The BUILD is stable for years; the REVISION changes every Patch Tuesday and rewrites
	// the very bytes DisablePatchGuard scans for. Recording only the build would promise to warn
	// about signature rot and then never move when rot actually happens.
	//
	NexusCoreSetKernelBuild(BuildNumber, Revision);
	gKernelPatchInfo.KernelBuildNumber = BuildNumber;

	//
	// Supported-version floor. Single gate -- see NEXUS_MIN_SUPPORTED_BUILD in NexusBootDxe.h.
	//  Replaces `if (BuildNumber < 6001)` (Vista SP1).
	//
	if (BuildNumber < NEXUS_MIN_SUPPORTED_BUILD)
	{
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: unsupported kernel image version %u.\r\n"
			L"This build targets the Windows 11 24H2/25H2 branch (%u) and newer only.\r\n",
			BuildNumber, (UINT32)NEXUS_MIN_SUPPORTED_BUILD);
		NexusCoreSetKernelPatchLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_NTOSKRNL, __LINE__));
		return EFI_UNSUPPORTED;
	}

	if ((FileFlags & VS_FF_DEBUG) != 0)
	{
		// Do not patch checked kernels. There is too much difference in PG and DSE initialization code due to missing optimizations.
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: Checked kernels are not supported.\r\n");
		NexusCoreSetKernelPatchLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_NTOSKRNL, __LINE__));
		return EFI_UNSUPPORTED;
	}

	// Find the INIT and PAGE sections
	PEFI_IMAGE_SECTION_HEADER InitSection = NULL, TextSection = NULL, PageSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
		CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
		SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

		if (AsciiStrCmp(SectionName, "INIT") == 0)
			InitSection = Section;
		else if (AsciiStrCmp(SectionName, ".text") == 0)
			TextSection = Section;
		else if (AsciiStrCmp(SectionName, "PAGE") == 0)
			PageSection = Section;

		Section++;
	}

	//
	// N1 -- FAIL CLOSED (fixed. This was
	//     ASSERT(InitSection != NULL && TextSection != NULL && PageSection != NULL);
	// and NexusBootDxe.inf sets `-D MDEPKG_NDEBUG` for RELEASE, which makes ASSERT() a no-op.
	// So in the build we actually ship, a missing section was not caught at all -- the very
	// next statement dereferences InitSection->VirtualAddress, and the pointers are then passed
	// to DisablePatchGuard/DisableDSE which dereference them further. A section-lookup failure
	// produced a NULL DEREFERENCE DURING BOOT PATCHING rather than a diagnosable refusal.
	//
	// Not hypothetical going forward: section layout is a property of the image, not of our
	// code, and Microsoft has renamed and merged kernel sections before. An unexpected layout
	// must be refused, not dereferenced. Same fail-closed principle as B3/W1/K1, different
	// mechanism -- those were "warn and continue", this was "assert and vanish".
	//
	if (InitSection == NULL || TextSection == NULL || PageSection == NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: required section(s) not found:%S%S%S\r\n",
			InitSection == NULL ? L" INIT" : L"",
			TextSection == NULL ? L" .text" : L"",
			PageSection == NULL ? L" PAGE" : L"");
		NexusCoreSetKernelPatchLine(NXC_DXE_REFUSAL(NXC_DXE_FILE_NTOSKRNL, __LINE__));
		return EFI_NOT_FOUND;
	}

	//
	// ============================================================================================
	// THE CONTROL BOOT -- PatchGuard deliberately left alive. See NXCMD_BOOTCTL_SKIP_PG.
	// ============================================================================================
	//
	// This is the ONLY thing the one-shot skips. Everything else still runs: NexusCore is still
	// mapped, the command channel still works, and pgscan is still available -- which is the
	// entire point, because the question being answered is "does pgscan find a context when one
	// is definitely there".
	//
	// (!) SAID LOUDLY, NOT LOGGED QUIETLY. A boot that differs from every other boot in whether
	// the kernel's self-defence is running must not be something you have to go looking for. The
	// alternative is discovering it from a bugcheck three hours later and spending the evening
	// bisecting a change that was never made.
	//
	if (gDriverConfig.SkipPatchGuardDefusal)
	{
		PRINT_KERNEL_PATCH_MSG(
			L"\r\n"
			L"[PatchNtoskrnl] ******************************************************\r\n"
			L"[PatchNtoskrnl] ** CONTROL BOOT -- PATCHGUARD IS *NOT* BEING DEFUSED **\r\n"
			L"[PatchNtoskrnl] ******************************************************\r\n"
			L"[PatchNtoskrnl] This boot was armed with a ONE-SHOT flag, which has already been\r\n"
			L"[PatchNtoskrnl] consumed -- the NEXT boot defuses PatchGuard normally.\r\n"
			L"[PatchNtoskrnl] Run `PlatformCtl pgscan` EARLY. A bugcheck 0x109 later in this\r\n"
			L"[PatchNtoskrnl] boot is an expected outcome of the control, not a regression.\r\n\r\n");

		//
		// (!) STILL LOCATE, JUST DO NOT WRITE. g_PgContext's RVA is published either way, so
		// `pgdefuse verify` works on a control boot -- which is the boot you most want to point
		// it at, because it is the one where the pointer should be seen NOT to be in INIT. A
		// verifier that only functions on boots requiring no verification verifies nothing.
		//
		// It also exercises the locator on this path rather than skipping it, so a control boot
		// tests the thing that does the defusing as well as the thing that checks it.
		//
		NEXUS_PG_TARGETS Located;
		if (!EFI_ERROR(NexusPgLocateTargets(ImageBase, NtHeaders, &Located)) &&
			Located.PgContext != NULL)
		{
			CONST UINT32 Rva = (UINT32)(Located.PgContext - (CONST UINT8*)ImageBase);
			NexusCoreSetPgContextRva(Rva);
			PRINT_KERNEL_PATCH_MSG(L"    g_PgContext                [RVA: 0x%X] -> LEFT ALONE\r\n", Rva);
		}

		return EFI_SUCCESS;
	}

	// Patch INIT and .text sections to disable PatchGuard
	PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] Disabling PatchGuard... [INIT RVA: 0x%X - 0x%X]\r\n",
		InitSection->VirtualAddress, InitSection->VirtualAddress + InitSection->SizeOfRawData);
	Status = DisablePatchGuard(ImageBase,
								NtHeaders,
								InitSection,
								TextSection,
								BuildNumber);
	if (EFI_ERROR(Status))
		return Status;

	PRINT_KERNEL_PATCH_MSG(L"\r\n[PatchNtoskrnl] Successfully disabled PatchGuard.\r\n");

	//
	// ============================================================================================
	//

	return Status;
}
