## @file
# NexusBoot Package - UEFI bootkit for Nexus Sentinel
#
# Provides DSE bypass, PatchGuard bypass, manual driver mapping,
# and hypervisor bootstrap capabilities.
#
# Part of Nexus Sentinel
#
# Copyright (c) 2026, Nexus Sentinel Project
# SPDX-License-Identifier: GPL-3.0-or-later
#
##
[Defines]
  PLATFORM_NAME                  = NexusBoot
  PLATFORM_GUID                  = 27125b66-a7e4-48e1-916a-56d41e32a397
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x0001001B
  OUTPUT_DIRECTORY               = Build/NexusBoot
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  # Entry points
  UefiDriverEntryPoint           |MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiApplicationEntryPoint      |MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf

  # Core basics
  BaseLib                        |MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib                  |MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf   # or BaseMemoryLibOptDxe for X64 if perf matters
  SynchronizationLib             |MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib                         |MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  TimerLib                       |MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  IoLib                          |MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  PciLib                         |MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  PrintLib                       |MdePkg/Library/BasePrintLib/BasePrintLib.inf

  # UEFI services
  UefiLib                        |MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib       |MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib    |MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib                  |MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib            |MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  DxeServicesTableLib            |MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  DxeServicesLib                 |MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  HobLib                         |MdePkg/Library/DxeHobLib/DxeHobLib.inf
  PcdLib                         |MdePkg/Library/DxePcdLib/DxePcdLib.inf

  # Boot manager / loader support
  UefiBootManagerLib             |MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf
  SortLib                        |MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  HiiLib                         |MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  UefiHiiServicesLib             |MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  VariablePolicyHelperLib        |MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf

  # Debug & reporting
  ReportStatusCodeLib            |MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
!if $(TARGET) == RELEASE
  DebugLib                       |MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  !ifdef $(DEBUG_ON_SERIAL_PORT)
    DebugLib                     |MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  !else
    DebugLib                     |MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  !endif
!endif
  DebugPrintErrorLevelLib        |MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

  # Null / safe libs for security & compatibility
  RegisterFilterLib              |MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  StackCheckLib                  |MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
  PerformanceLib                 |MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf

[LibraryClasses.IA32, LibraryClasses.X64]
  BaseMemoryLib                  |MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf

[LibraryClasses.common.UEFI_APPLICATION]
  # Extra for applications (Loader)
  PeCoffGetEntryPointLib         |MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  FileHandleLib                  |MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf

[PcdsFixedAtBuild]
!if $(TARGET) == DEBUG
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask         |0x0F
!endif
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask |0x03
  gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange   |FALSE

[Components]
  # DXE Driver (patches boot chain)
  NexusBootDxe/NexusBootDxe.inf

  # Loader Application (user-facing boot launcher)
  Loader/Loader.inf

[BuildOptions]
  # Common flags
  *_*_*_CC_FLAGS                 = -D DISABLE_NEW_DEPRECATED_INTERFACES
  MSFT:*_*_*_CC_FLAGS            = /utf-8 /W4 /WX- /GS- /Qspectre-
  GCC:*_*_*_CC_FLAGS             = -finput-charset=UTF-8 -Wall -Wno-unused-variable -fno-stack-protector

  # Optimizations
  MSFT:RELEASE_*_*_CC_FLAGS      = /O1
  GCC:RELEASE_*_*_CC_FLAGS       = -Os

  # Linker tweaks (sane defaults, keep exception tables, etc.)
  MSFT:*_*_*_DLINK_FLAGS         = /ALIGN:0x1000 /FILEALIGN:0x1000 /SECTION:.pdata,!D /SECTION:.xdata,!D /DEBUG:FULL /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:%_PDB%
  GCC:*_*_*_DLINK_FLAGS          = -z common-page-size=0x1000
  *:*_*_X64_GENFW_FLAGS          = --keepexceptiontable --keepzeropending --keepoptionalheader