#include <Uefi.h>

//
// (!) THIS SDK'S EDK2 PREDATES BOTH OF THESE MACROS.
//
// Real EDK2 Base.h defines C_ASSERT and STATIC_ASSERT. The VisualUefi tree vendored here is
// EDK2 circa 2018 and defines NEITHER -- it has VERIFY_SIZE_OF and OFFSET_OF and stops there.
// Any header taken from a current EDK2 uses STATIC_ASSERT freely; IndustryStandard/Tpm2Acpi.h
// carries two of them.
//
// (!) THE COMPILER DOES NOT NAME THE MISSING MACRO. An undefined function-like macro at file
// scope parses as a declaration, so MSVC blames whatever follows -- "syntax error: missing ')'
// before 'sizeof'" for STATIC_ASSERT, and an error pointing into the OFFSET_OF expansion at an
// '&' the source never wrote for C_ASSERT. Both cost a build to identify. That is the entire
// reason this comment is long.
//
// DEFINED HERE because vshacks.h is FORCE-INCLUDED into every translation unit in the solution
// (NexusBoot.props -> ForcedIncludeFiles), so one definition covers Loader, NexusBootDxe and
// anything added later, with no per-file shim to forget.
//
// Same negative-array-size form real EDK2 uses, and deliberately the SAME NAME every time:
// repeated identical `extern` declarations of an object that is never defined are legal C, so
// many asserts coexist in one translation unit and the linker never sees them. A failing one
// asks for size -1 and breaks the build, which is the point.
//
// Both are GUARDED, so a future SDK refresh that brings the real definitions wins with no edit.
//
#ifndef C_ASSERT
#define C_ASSERT(Expression)  extern char _NexusCAssert__[(Expression) ? 1 : -1]
#endif

#ifndef STATIC_ASSERT
#define STATIC_ASSERT(Expression, Message)  extern char _NexusStaticAssert__[(Expression) ? 1 : -1]
#endif

#undef _PCD_GET_MODE_32_PcdMaximumLinkedListLength
extern UINT32 _PCD_GET_MODE_32_PcdMaximumLinkedListLength;
#undef _PCD_GET_MODE_32_PcdMaximumAsciiStringLength
extern UINT32 _PCD_GET_MODE_32_PcdMaximumAsciiStringLength;
#undef _PCD_GET_MODE_32_PcdMaximumUnicodeStringLength
extern UINT32 _PCD_GET_MODE_32_PcdMaximumUnicodeStringLength;
#undef _PCD_GET_MODE_32_PcdUefiLibMaxPrintBufferSize
extern UINT32 _PCD_GET_MODE_32_PcdUefiLibMaxPrintBufferSize;
#undef _PCD_GET_MODE_32_PcdFixedDebugPrintErrorLevel
extern UINT32 _PCD_GET_MODE_32_PcdFixedDebugPrintErrorLevel;
#undef _PCD_GET_MODE_32_PcdDebugPrintErrorLevel
extern UINT32 _PCD_GET_MODE_32_PcdDebugPrintErrorLevel;
#undef _PCD_GET_MODE_32_PcdMaximumDevicePathNodeCount
extern UINT32 _PCD_GET_MODE_32_PcdMaximumDevicePathNodeCount;
#undef _PCD_GET_MODE_32_PcdSpinLockTimeout
extern UINT32 _PCD_GET_MODE_32_PcdSpinLockTimeout;

#undef _PCD_GET_MODE_16_PcdUefiFileHandleLibPrintBufferSize
extern UINT16 _PCD_GET_MODE_16_PcdUefiFileHandleLibPrintBufferSize;

#undef _PCD_GET_MODE_BOOL_PcdVerifyNodeInList
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdVerifyNodeInList;
#undef _PCD_GET_MODE_BOOL_PcdDriverDiagnosticsDisable
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdDriverDiagnosticsDisable;
#undef _PCD_GET_MODE_BOOL_PcdComponentNameDisable
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdComponentNameDisable;
#undef _PCD_GET_MODE_BOOL_PcdComponentName2Disable
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdComponentName2Disable;
#undef _PCD_GET_MODE_BOOL_PcdUgaConsumeSupport
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdUgaConsumeSupport;
#undef _PCD_GET_MODE_BOOL_PcdDriverDiagnostics2Disable
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdDriverDiagnostics2Disable;

#undef _PCD_GET_MODE_8_PcdDebugPropertyMask
extern UINT8 _PCD_GET_MODE_8_PcdDebugPropertyMask;
#undef _PCD_GET_MODE_8_PcdDebugClearMemoryValue
extern UINT8 _PCD_GET_MODE_8_PcdDebugClearMemoryValue;

#undef _PCD_GET_MODE_BOOL_PcdShellLibAutoInitialize
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdShellLibAutoInitialize;
#undef _PCD_GET_MODE_16_PcdShellPrintBufferSize
extern UINT16 _PCD_GET_MODE_16_PcdShellPrintBufferSize;

extern CHAR8 *gEfiCallerBaseName;
extern EFI_GUID gEfiCallerIdGuid;

// UefiBootManagerLib PCDs
#undef _PCD_GET_MODE_BOOL_PcdResetOnMemoryTypeInformationChange
extern BOOLEAN _PCD_GET_MODE_BOOL_PcdResetOnMemoryTypeInformationChange;
#undef _PCD_GET_MODE_32_PcdErrorCodeSetVariable
extern UINT32 _PCD_GET_MODE_32_PcdErrorCodeSetVariable;
#undef _PCD_GET_MODE_PTR_PcdBootManagerMenuFile
extern VOID* _PCD_GET_MODE_PTR_PcdBootManagerMenuFile;
#undef _PCD_GET_MODE_32_PcdProgressCodeOsLoaderLoad
extern UINT32 _PCD_GET_MODE_32_PcdProgressCodeOsLoaderLoad;
#undef _PCD_GET_MODE_32_PcdProgressCodeOsLoaderStart
extern UINT32 _PCD_GET_MODE_32_PcdProgressCodeOsLoaderStart;
#undef _PCD_GET_MODE_PTR_PcdDriverHealthConfigureForm
extern VOID* _PCD_GET_MODE_PTR_PcdDriverHealthConfigureForm;
#undef _PCD_GET_MODE_32_PcdMaxRepairCount
extern UINT32 _PCD_GET_MODE_32_PcdMaxRepairCount;

// BasePerformanceLibNull PCD
#undef _PCD_GET_MODE_8_PcdPerformanceLibraryPropertyMask
extern UINT8 _PCD_GET_MODE_8_PcdPerformanceLibraryPropertyMask;
