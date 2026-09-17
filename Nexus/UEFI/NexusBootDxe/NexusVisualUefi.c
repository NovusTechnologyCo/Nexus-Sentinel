//
// Definitions the VisualUefi (MSVC) build needs and the EDK2 build generates for itself.
// Replaces VisualUefi.c (EfiGuard-derived).
//
// (!) MSVC-ONLY BY CONSTRUCTION. Under EDK2 the build system emits these symbols, so
// compiling this file there is a duplicate-definition error. It is listed in the .vcxproj
// and deliberately NOT under [Sources] in the .inf, and the whole body is behind VISUALUEFI
// as a second line of defence.
//
#ifdef VISUALUEFI

#include <Uefi.h>
#include <Protocol/DriverSupportedEfiVersion.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/NexusBoot.h>
#include <Guid/Acpi.h>
#include <Library/DebugLib.h>


//
// EDK2's build system generates these from the .inf; VisualUefi expects them in source.
//
CONST UINT8 _gDriverUnloadImageCount = 1;
CONST UINT32 _gUefiDriverRevision = 0x210;
CONST UINT32 _gDxeRevision = 0x210;

//
// EMBEDDED IN THE BINARY as plain ASCII, so anything that reads the image off the ESP can
// see it. Was "NexusBootDxe" -- this is the one place a filename rename cannot
// reach, the file's own contents, so it is matched to the deploy name on purpose.
//
CHAR8* gEfiCallerBaseName = "PlatformRuntimeDxe";
BOOLEAN mPostEBS = FALSE;
EFI_SYSTEM_TABLE* mDebugST = NULL;


//
// Our own protocol.
//
EFI_GUID gNexusBootDriverProtocolGuid = EFI_NEXUSBOOT_DRIVER_PROTOCOL_GUID;

//
// Protocol and table GUIDs referenced by the driver.
//
EFI_GUID gEfiDriverSupportedEfiVersionProtocolGuid = EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL_GUID;
EFI_GUID gEfiSimpleTextInputExProtocolGuid = EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID;
EFI_GUID gEfiAcpi20TableGuid = EFI_ACPI_20_TABLE_GUID;

//
// TCG2, for the Tier 3 log sanitiser. Deleted on the belief that the GetEventLog
// hook was dead by measurement, then RESTORED the same day: that reasoning only proved a
// bypass path exists, and the transform was independently broken at the time, so the hook
// was never actually given a fair test. See TcgLogSanitize.h.
// Value from MdePkg Protocol/Tcg2Protocol.h.
//
EFI_GUID gEfiTcg2ProtocolGuid =
	{ 0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } };


//
// (!) LINK-TIME PLACEHOLDERS, NOT IMPLEMENTATIONS.
//
// BaseSynchronizationLib references these, so the link fails without them, but VisualUefi
// does not provide the timer plumbing they need (VisualUefi issue #25). That is survivable
// only because this driver uses interlocked operations and never a spinlock or the
// performance counter.
//
// They ASSERT and return -1 rather than returning a plausible value: if something ever does
// call one, the failure needs to be loud at the call site instead of becoming a bogus tick
// count that propagates somewhere else.
//
UINTN
EFIAPI
InternalGetSpinLockProperties(
	VOID
	)
{
	ASSERT(FALSE);
	return (UINTN)-1;
}

UINT64
EFIAPI
GetPerformanceCounter(
	VOID
	)
{
	ASSERT(FALSE);
	return (UINT64)-1;
}

UINT64
EFIAPI
GetPerformanceCounterProperties(
	OUT UINT64* StartValue OPTIONAL,
	OUT UINT64* EndValue OPTIONAL
	)
{
	ASSERT(FALSE);
	return (UINT64)-1;
}


//
// VisualUefi enters at UefiMain/UefiUnload; the driver's own entry points are named for the
// project. These forward.
//
EFI_STATUS
EFIAPI
NexusBootInitialize(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
	);

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
	)
{
	return NexusBootInitialize(ImageHandle, SystemTable);
}

EFI_STATUS
EFIAPI
NexusBootUnload(
	IN EFI_HANDLE ImageHandle
	);

EFI_STATUS
EFIAPI
UefiUnload(
	IN EFI_HANDLE ImageHandle
	)
{
	return NexusBootUnload(ImageHandle);
}

#endif // VISUALUEFI
