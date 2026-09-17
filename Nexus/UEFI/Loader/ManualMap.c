/**
 * @file ManualMap.c
 * @brief Scope item 4c. See ManualMap.h for WHY; this file is the mechanism.
 *
 * Deliberately conservative: every failure path frees what it allocated and returns an error so the
 * caller can fall back to gBS->LoadImage. A measured DXE is a detection problem; an unbootable
 * machine is a worse one, and this code runs before anything can report a fault.
 */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/PeImage.h>

#include "PeRelocate.h"
#include "ManualMap.h"

/**
 * Read a file from the first filesystem that has it.
 *
 * Mirrors LocateFile()'s handle enumeration in Loader.c rather than reusing it, because that
 * function returns a DEVICE PATH and closes the handle -- we need the bytes AND the device path, and
 * re-opening by device path would be a second search for a file we already found.
 */
STATIC
EFI_STATUS
ReadFileFromAnyVolume(
	IN CHAR16* Path,
	OUT VOID** Buffer,
	OUT UINTN* Size,
	OUT EFI_HANDLE* VolumeDeviceHandle
	)
{
	UINTN NumHandles = 0;
	EFI_HANDLE* Handles = NULL;

	*Buffer = NULL;
	*Size = 0;
	*VolumeDeviceHandle = NULL;

	EFI_STATUS Status = gBS->LocateHandleBuffer(ByProtocol,
												&gEfiSimpleFileSystemProtocolGuid,
												NULL, &NumHandles, &Handles);
	if (EFI_ERROR(Status))
		return Status;

	Status = EFI_NOT_FOUND;
	for (UINTN i = 0; i < NumHandles; i++)
	{
		EFI_FILE_IO_INTERFACE* Io = NULL;
		if (EFI_ERROR(gBS->OpenProtocol(Handles[i], &gEfiSimpleFileSystemProtocolGuid,
										(VOID**)&Io, gImageHandle, NULL,
										EFI_OPEN_PROTOCOL_GET_PROTOCOL)))
			continue;

		EFI_FILE_HANDLE Volume = NULL;
		if (EFI_ERROR(Io->OpenVolume(Io, &Volume)))
			continue;

		EFI_FILE_HANDLE File = NULL;
		if (EFI_ERROR(Volume->Open(Volume, &File, Path,
								   EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY)))
		{
			Volume->Close(Volume);
			continue;
		}

		//
		// File size via GetInfo. The two-call pattern is required: the first call reports the needed
		// buffer size through an error return.
		//
		UINTN InfoSize = 0;
		EFI_FILE_INFO* Info = NULL;
		Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
		if (Status == EFI_BUFFER_TOO_SMALL)
		{
			Info = (EFI_FILE_INFO*)AllocatePool(InfoSize);
			if (Info != NULL)
				Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, Info);
			else
				Status = EFI_OUT_OF_RESOURCES;
		}

		if (!EFI_ERROR(Status) && Info != NULL && Info->FileSize > 0)
		{
			CONST UINTN FileSize = (UINTN)Info->FileSize;
			VOID* Raw = AllocatePool(FileSize);
			if (Raw != NULL)
			{
				UINTN ReadSize = FileSize;
				Status = File->Read(File, &ReadSize, Raw);
				if (!EFI_ERROR(Status) && ReadSize == FileSize)
				{
					*Buffer = Raw;
					*Size = FileSize;
					*VolumeDeviceHandle = Handles[i];
				}
				else
				{
					FreePool(Raw);
					Status = EFI_DEVICE_ERROR;
				}
			}
			else
			{
				Status = EFI_OUT_OF_RESOURCES;
			}
		}

		if (Info != NULL)
			FreePool(Info);
		File->Close(File);
		Volume->Close(Volume);

		if (!EFI_ERROR(Status) && *Buffer != NULL)
			break;
	}

	FreePool((VOID*)Handles);
	return (*Buffer != NULL) ? EFI_SUCCESS : (EFI_ERROR(Status) ? Status : EFI_NOT_FOUND);
}


EFI_STATUS
EFIAPI
ManualMapRuntimeDriver(
	IN CHAR16* FilePath,
	OUT EFI_HANDLE* OutHandle
	)
{
	if (FilePath == NULL || OutHandle == NULL)
		return EFI_INVALID_PARAMETER;
	*OutHandle = NULL;

	VOID* Raw = NULL;
	UINTN RawSize = 0;
	EFI_HANDLE VolumeHandle = NULL;
	EFI_STATUS Status = ReadFileFromAnyVolume(FilePath, &Raw, &RawSize, &VolumeHandle);
	if (EFI_ERROR(Status))
		return Status;

	EFI_PHYSICAL_ADDRESS ImagePages = 0;
	UINT8* Image = NULL;
	EFI_LOADED_IMAGE_PROTOCOL* Li = NULL;
	EFI_DEVICE_PATH* Dp = NULL;

	//
	// ---- Validate the PE ------------------------------------------------------------------------
	//
	if (RawSize < sizeof(EFI_IMAGE_DOS_HEADER))
	{
		Status = EFI_LOAD_ERROR;
		goto Cleanup;
	}
	CONST EFI_IMAGE_DOS_HEADER* Dos = (CONST EFI_IMAGE_DOS_HEADER*)Raw;
	if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE ||
		(UINTN)Dos->e_lfanew + sizeof(EFI_IMAGE_NT_HEADERS64) > RawSize)
	{
		Status = EFI_LOAD_ERROR;
		goto Cleanup;
	}
	CONST EFI_IMAGE_NT_HEADERS64* Nt =
		(CONST EFI_IMAGE_NT_HEADERS64*)((CONST UINT8*)Raw + Dos->e_lfanew);
	if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE ||
		Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		Status = EFI_LOAD_ERROR;
		goto Cleanup;
	}

	CONST UINT32 SizeOfImage = Nt->OptionalHeader.SizeOfImage;
	CONST UINT32 SizeOfHeaders = Nt->OptionalHeader.SizeOfHeaders;
	if (SizeOfImage == 0 || SizeOfHeaders > RawSize)
	{
		Status = EFI_LOAD_ERROR;
		goto Cleanup;
	}

	//
	// ---- Allocate as RUNTIME code ---------------------------------------------------------------
	// EfiRuntimeServicesCode is what makes the image survive ExitBootServices. AllocatePages rather
	// than AllocatePool because the type matters and pool does not let us choose it.
	//
	CONST UINTN Pages = EFI_SIZE_TO_PAGES(SizeOfImage);
	Status = gBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode, Pages, &ImagePages);
	if (EFI_ERROR(Status))
		goto Cleanup;
	Image = (UINT8*)(UINTN)ImagePages;

	//
	// Zero first: the gap between raw and virtual section sizes is .bss, and firmware does not
	// promise fresh pages are clean.
	//
	ZeroMem(Image, Pages * EFI_PAGE_SIZE);
	CopyMem(Image, Raw, SizeOfHeaders);

	//
	// ---- Sections -------------------------------------------------------------------------------
	//
	CONST EFI_IMAGE_SECTION_HEADER* Section =
		(CONST EFI_IMAGE_SECTION_HEADER*)((CONST UINT8*)&Nt->OptionalHeader +
										  Nt->FileHeader.SizeOfOptionalHeader);
	for (UINT16 i = 0; i < Nt->FileHeader.NumberOfSections; i++)
	{
		CONST EFI_IMAGE_SECTION_HEADER* S = &Section[i];
		if ((UINTN)S->VirtualAddress + S->Misc.VirtualSize > SizeOfImage)
		{
			Status = EFI_LOAD_ERROR;
			goto Cleanup;
		}
		if (S->SizeOfRawData != 0)
		{
			if ((UINTN)S->PointerToRawData + S->SizeOfRawData > RawSize)
			{
				Status = EFI_LOAD_ERROR;
				goto Cleanup;
			}
			CopyMem(Image + S->VirtualAddress,
					(CONST UINT8*)Raw + S->PointerToRawData,
					S->SizeOfRawData);
		}
	}

	//
	// ---- Relocate to where we actually put it ---------------------------------------------------
	//
	CONST INT64 Delta = (INT64)((UINT64)(UINTN)Image - Nt->OptionalHeader.ImageBase);
	if (!ApplyPeRelocations(Image, SizeOfImage, Delta))
	{
		Status = EFI_LOAD_ERROR;
		goto Cleanup;
	}

	//
	// ---- Synthesise what LoadImage would have installed ------------------------------------------
	//
	// Tier 3's CollectSelfPaths finds our images through EFI_LOADED_IMAGE_PROTOCOL. Without this the
	// transform cannot identify itself, fails closed, and the spoof turns off -- so this is not
	// cosmetic, it is what keeps the rest of the layer working.
	//
	Dp = FileDevicePath(VolumeHandle, FilePath);
	if (Dp == NULL)
	{
		Status = EFI_OUT_OF_RESOURCES;
		goto Cleanup;
	}

	Li = (EFI_LOADED_IMAGE_PROTOCOL*)AllocateZeroPool(sizeof(EFI_LOADED_IMAGE_PROTOCOL));
	if (Li == NULL)
	{
		Status = EFI_OUT_OF_RESOURCES;
		goto Cleanup;
	}
	Li->Revision = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
	Li->ParentHandle = gImageHandle;
	Li->SystemTable = gST;
	Li->DeviceHandle = VolumeHandle;
	Li->FilePath = Dp;
	Li->ImageBase = Image;
	Li->ImageSize = SizeOfImage;
	Li->ImageCodeType = EfiRuntimeServicesCode;
	Li->ImageDataType = EfiRuntimeServicesData;
	Li->Unload = NULL;                       // manually mapped images cannot be unloaded by firmware

	//
	// Installing on a NULL handle asks the firmware to CREATE one. That handle is ours, not a
	// firmware image registration -- the image is still absent from the firmware's own image list,
	// from PCR[2], and from the SetVirtualAddressMap relocation list.
	//
	EFI_HANDLE NewHandle = NULL;
	Status = gBS->InstallProtocolInterface(&NewHandle, &gEfiLoadedImageProtocolGuid,
										   EFI_NATIVE_INTERFACE, Li);
	if (EFI_ERROR(Status))
		goto Cleanup;

	//
	// ---- Start it -------------------------------------------------------------------------------
	//
	CONST EFI_IMAGE_ENTRY_POINT Entry =
		(EFI_IMAGE_ENTRY_POINT)(VOID*)(Image + Nt->OptionalHeader.AddressOfEntryPoint);

	Print(L"[MMAP] %S mapped at 0x%p (%u KB), entry 0x%p\r\n",
		  FilePath, Image, SizeOfImage / 1024, (VOID*)Entry);

	FreePool(Raw);
	Raw = NULL;

	Status = Entry(NewHandle, gST);
	if (EFI_ERROR(Status))
	{
		//
		// The driver's own entry point refused. Leave the image mapped: it may have installed
		// protocols or hooks before failing, and tearing that down blind is more dangerous than
		// leaking a few pages this early in boot.
		//
		Print(L"[MMAP] driver entry returned %r\r\n", Status);
		gBS->UninstallProtocolInterface(NewHandle, &gEfiLoadedImageProtocolGuid, Li);
		return Status;
	}

	*OutHandle = NewHandle;
	return EFI_SUCCESS;

Cleanup:
	if (Raw != NULL)
		FreePool(Raw);
	if (Li != NULL)
		FreePool(Li);
	if (Dp != NULL)
		FreePool(Dp);
	if (ImagePages != 0)
		gBS->FreePages(ImagePages, EFI_SIZE_TO_PAGES(SizeOfImage));
	return Status;
}
