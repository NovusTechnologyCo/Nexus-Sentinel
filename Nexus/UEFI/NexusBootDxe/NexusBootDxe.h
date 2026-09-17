#pragma once

#include <Uefi.h>

#include <Protocol/DriverSupportedEfiVersion.h>
#include <Protocol/NexusBoot.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Zydis/Zydis.h>
#include "NexusNt.h"
#include "NexusPe.h"
#include "NexusArc.h"
#include "NexusUtil.h"
/* PRINT_KERNEL_PATCH_MSG below expands to gNexusBootPrint, so its declaration must arrive with
 * the macro. Without this the macro compiles anywhere, calling an implicitly-declared function
 * that C assumes returns int -- which on x64 is a wrong prototype, not an error, and this build
 * has no /WX to stop it. */
#include "NexusLoaderBlock.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// ============================================================================
// SUPPORTED WINDOWS VERSION -- SINGLE SOURCE OF TRUTH
// ============================================================================
//
// This driver supports the Windows 11 24H2/25H2 servicing branch and newer. Earlier
// Windows versions and all 32-bit (IA32 / PE32) code paths are unsupported. Gate on this
// constant rather than reintroducing per-version branches.
//
// A FLOOR, NOT AN EXACT MATCH. Cumulative updates bump the revision rather than the build,
// so `>=` is forward-compatible with future servicing while still rejecting anything older.
//
// THE FLOOR IS EXPRESSED AS A FILE VERSION, AND MUST BE. 25H2 ships as an enablement
// package over 24H2: both come from the same servicing branch, so boot components keep
// 26100.xxxx FILE versions while the OS reports build 26200. Only PE file versions are
// available at boot time, so a floor set to the OS build number rejects a supported system.
//
// BOOT COMPONENTS ALSO SKEW. Within one boot, bootmgfw.efi and winload.efi can report
// different build numbers. A floor above the lowest component's version patches part of the
// chain and refuses the rest, which is worse than refusing all of it.
//
// WHY CHECK THE VERSION AT ALL, GIVEN ONE SUPPORTED LINE: because the check is what makes
// the refusal honest. The build number selects real behaviour -- most consequentially the
// boot-manager hook's calling convention -- so an unsupported build must be refused loudly
// rather than silently mispatched. A version-info parse failure that falls through leaves
// the build number at zero, which compares below every floor.
//
// FAIL CLOSED: anything below this refuses to patch and prompts the user.
//
#define NEXUS_MIN_SUPPORTED_BUILD		26100	// 24H2/25H2 servicing branch (see above)

//
// NexusBoot driver protocol handle
//
extern NEXUSBOOT_DRIVER_PROTOCOL gNexusBootDriverProtocol;

//
// Driver configuration data
//
extern NEXUSBOOT_CONFIGURATION_DATA gDriverConfig;

/**
 * Must this DXE image stay RESIDENT past ExitBootServices?
 *
 * ============================================================================================
 * ⚠ THIS IS WHAT KEEPS map / unmap / status ALIVE. Do not make it conditional casually.
 * ============================================================================================
 *
 * The DXE installs a SetVariable() runtime-service hook, and that hook is the transport for the
 * whole NEXUS_COMMAND channel. If the image is freed at ExitBootServices the hook goes with it and
 * every PlatformCtl command stops working -- silently, because the variable write still "succeeds"
 * against the real firmware service.
 *
 * Kept as a named constant rather than deleting the branches, so the requirement is STATED at
 * each site rather than being invisible -- residency is not obviously connected to the command
 * channel, and a cleanup that removed the branches would take map, unmap and every diagnostic
 * with it, with no visible link between cause and symptom.
 */
#define NEXUSBOOT_NEEDS_RUNTIME_CHANNEL  TRUE

//
// Bootmgfw.efi handle
//
extern EFI_HANDLE gBootmgfwHandle;

//
// Simple Text Input Ex protocol pointer. May be NULL
//
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL* gTextInputEx;

//
// TRUE if ExitBootServices() has been called
//
extern BOOLEAN gEfiAtRuntime;

//
// TRUE if SetVirtualAddressMap() has been called
//
extern BOOLEAN gEfiGoneVirtual;

//
// Universal template bytes for a faux call inline hook (mov [e|r]ax, <addr>, push [e|r]ax, ret)
//
#include "NexusHook.h"


//
// bootmgfw!ImgArchStartBootApplication hook to patch winload.efi.
//
// ONE PROTOTYPE, ONE CALLING CONVENTION. This function's signature changed at 10.0.16299.0;
// only the later form is supported, so there is no runtime choice of convention to get wrong.
// Do not reintroduce a second prototype selected by build number -- a version-info parse
// failure would then pick a 4-argument form for a 5-argument caller.
//
typedef
EFI_STATUS
(EFIAPI*
t_ImgArchStartBootApplication_Eight)(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);

//
// The bootmgfw!ImgArchEfiStartBootApplication hook. Target doubles as the address of the
// original, which is what the detour calls through after restoring it.
//
extern NEXUS_HOOK gImgArchHook;


//
// Patches the Windows Boot Manager (bootmgfw.efi)
//
EFI_STATUS
EFIAPI
PatchBootManager(
	IN CONST VOID* ImageBase,
	IN UINTN ImageSize
	);


//
// winload!OslFwpKernelSetupPhase1 hook
//
typedef
EFI_STATUS
(EFIAPI*
t_OslFwpKernelSetupPhase1)(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	);

//
// The winload!OslFwpKernelSetupPhase1 hook.
//
extern NEXUS_HOOK gOslFwpHook;

EFI_STATUS
EFIAPI
HookedOslFwpKernelSetupPhase1(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	);


//
// Patches winload.efi
// 
EFI_STATUS
EFIAPI
PatchWinload(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);

//
// Patches ntoskrnl.exe
// 
EFI_STATUS
EFIAPI
PatchNtoskrnl(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);


//
// The kernel patch result. This is used to hold data generated during
// HookedOslFwpKernelSetupPhase1 and PatchNtoskrnl until we can safely access
// boot services to print the output. This is done during the ExitBootServices() callback.
//
// Status holds the final patch status. If this is not EFI_SUCCESS, the buffer holds an
// error message, and the user will be prompted to reboot or continue.
// If Status is EFI_SUCCESS, the buffer holds concatenated patch information similar to what
// is printed during the patching of bootmgfw.efi/bootmgr.efi/winload.efi.
//
typedef struct _KERNEL_PATCH_INFORMATION
{
	EFI_STATUS Status;
	UINTN BufferSize;			// In bytes, excluding null terminator. This may be 0. The maximum buffer size is simply sizeof(Buffer).
	CHAR16 Buffer[8192];		// Bounded; excess output is truncated rather than growing the buffer
	// The winload version is read and enforced against NEXUS_MIN_SUPPORTED_BUILD in
	// PatchWinload.c, so it does not need to be stored here.
	UINT32 KernelBuildNumber;	// Used to determine whether an error message should be shown
	VOID* KernelBase;
} KERNEL_PATCH_INFORMATION;

extern KERNEL_PATCH_INFORMATION gKernelPatchInfo;


//
// Appends a kernel patch status info or error message to the buffer for delayed printing,
// and prints it to a boot debugger immediately if one is connected.
//
#define PRINT_KERNEL_PATCH_MSG(Fmt, ...) \
	do { \
		gNexusBootPrint(Fmt, ##__VA_ARGS__); \
		AppendKernelPatchMessage(Fmt, ##__VA_ARGS__); \
	} while (FALSE)

//
// TRUE when the firmware genuinely reports SecureBoot=1. The TCG log transform gates on this so
// it cannot "spoof" a platform that no longer needs it -- see the definition in NexusBootDxe.c.
//
BOOLEAN
SecureBootIsGenuinelyEnforcing(
	VOID
	);

#ifdef __cplusplus
}
#endif
