/**
 * @file TcgLogSanitize.c
 * @brief Tier 3: sanitize the TCG event log IN PLACE at the address the ACPI TPM2 table publishes.
 *
 * See TcgLogSanitize.h for WHY. This file is the C port of tools/wbcl_sanitize.py, which was
 * validated end-to-end against four real committed logs before any of this was written -- digests
 * 100%, PCR[7] matching a genuine SB-on boot, and zero identifying records. That reference is the
 * specification; where the two disagree, the reference is right and this is wrong.
 *
 * ONE DELIBERATE IMPROVEMENT over the reference. The Python identifies our images by matching a
 * PATH SUBSTRING, which is fragile (an ESP rename silently invalidates it -- that actually happened
 * on 2026-07-26) and imprecise (it could match a genuine third-party binary in the same directory).
 * Running inside the DXE we do not have to guess: we read our OWN device path from
 * EFI_LOADED_IMAGE_PROTOCOL and the Loader's from our ParentHandle. Exact, rename-proof, and
 * incapable of matching someone else's binary.
 *
 * FAIL CLOSED IS THE WHOLE DESIGN. Every mandatory edit target must be present or we emit nothing
 * and the firmware's original log flows through untouched. Scope §4: a partial sanitization is MORE
 * identifying than none -- an image event removed while its boot entry survives is a contradiction
 * no clean machine can produce, and stale digests (level B1) are a stronger signal than honesty.
 */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

#include "NexusBootDxe.h"          // gDriverConfig
#include "Sha256.h"
#include "TcgLogTransform.h"
#include "TcgLogSanitize.h"
#include "TcgAuthorityBlob.h"

//
// Defined in this module's NexusVisualUefi.c. Used to find the ACPI RSDP in the EFI configuration table.
//
extern EFI_GUID gEfiAcpi20TableGuid;


/**
 * Discover the ESP paths of OUR OWN images: this DXE, and the Loader that loaded us (our
 * ParentHandle). This is the improvement over the Python reference's hardcoded marker -- exact,
 * rename-proof, and it cannot match a third party's binary.
 *
 * A parent may legitimately not be one of ours (if this DXE were loaded straight from BDS rather
 * than by the Loader), which is why each entry is validated as a non-empty Media/FilePath rather
 * than assumed.
 */
STATIC
UINTN
CollectSelfPaths(
	OUT CHAR16 Paths[MAX_SELF_PATHS][MAX_PATH_CHARS]
	)
{
	UINTN n = 0;
	EFI_LOADED_IMAGE_PROTOCOL* Self = NULL;

	if (gBS->HandleProtocol(gImageHandle,
							&gEfiLoadedImageProtocolGuid,
							(VOID**)&Self) != EFI_SUCCESS || Self == NULL)
		return 0;

	if (Self->FilePath != NULL)
	{
		DevicePathToText((CONST UINT8*)Self->FilePath,
						 GetDevicePathSize(Self->FilePath),
						 Paths[n], MAX_PATH_CHARS);
		if (Paths[n][0] != L'\0')
			n++;
	}

	if (Self->ParentHandle != NULL && n < MAX_SELF_PATHS)
	{
		EFI_LOADED_IMAGE_PROTOCOL* Parent = NULL;
		if (gBS->HandleProtocol(Self->ParentHandle,
							   &gEfiLoadedImageProtocolGuid,
							   (VOID**)&Parent) == EFI_SUCCESS &&
			Parent != NULL && Parent->FilePath != NULL)
		{
			DevicePathToText((CONST UINT8*)Parent->FilePath,
							 GetDevicePathSize(Parent->FilePath),
							 Paths[n], MAX_PATH_CHARS);
			if (Paths[n][0] != L'\0')
				n++;
		}
	}

	return n;
}


//
// ============================================================================
// LOCATING THE LOG -- via the ACPI TPM2 table, not the TCG2 protocol
// ============================================================================
//
// See the header for why. Short version: hooking EFI_TCG2_PROTOCOL.GetEventLog was MEASURED to
// change nothing, because the TPM2 table publishes the log's PHYSICAL ADDRESS and readers take it
// straight from memory.
//

#pragma pack(push, 1)

typedef struct _ACPI_RSDP {
	CHAR8  Signature[8];        // "RSD PTR "
	UINT8  Checksum;
	CHAR8  OemId[6];
	UINT8  Revision;
	UINT32 RsdtAddress;
	UINT32 Length;
	UINT64 XsdtAddress;
	UINT8  ExtendedChecksum;
	UINT8  Reserved[3];
} ACPI_RSDP;

typedef struct _ACPI_SDT_HEADER {
	CHAR8  Signature[4];
	UINT32 Length;
	UINT8  Revision;
	UINT8  Checksum;
	CHAR8  OemId[6];
	CHAR8  OemTableId[8];
	UINT32 OemRevision;
	UINT32 CreatorId;
	UINT32 CreatorRevision;
} ACPI_SDT_HEADER;

#pragma pack(pop)

//
// TCG ACPI spec: after the 36-byte SDT header the TPM2 table carries
//   PlatformClass u16 | Reserved u16 | AddressOfControlArea u64 | StartMethod u32
//   [start-method parameters] | LAML u32 | LASA u64
// LAML/LASA sit at the very END of the table, after any start-method parameters, which is why they
// are read from (Length - 12) rather than a fixed offset. Present from revision 4.
//
#define TPM2_MIN_LENGTH_FOR_LOG   (36 + 16 + 12)


/**
 * Walk the EFI configuration table to the ACPI 2.0 RSDP, then the XSDT, and find the TPM2 table.
 * Returns NULL if absent.
 */
STATIC
CONST ACPI_SDT_HEADER*
FindTpm2Table(
	VOID
	)
{
	CONST ACPI_RSDP* Rsdp = NULL;

	if (gST == NULL || gST->ConfigurationTable == NULL)
		return NULL;

	for (UINTN i = 0; i < gST->NumberOfTableEntries; i++)
	{
		if (CompareGuid(&gST->ConfigurationTable[i].VendorGuid, &gEfiAcpi20TableGuid))
		{
			Rsdp = (CONST ACPI_RSDP*)gST->ConfigurationTable[i].VendorTable;
			break;
		}
	}
	if (Rsdp == NULL || CompareMem(Rsdp->Signature, "RSD PTR ", 8) != 0)
		return NULL;
	if (Rsdp->XsdtAddress == 0)
		return NULL;                       // 32-bit RSDT only: pre-ACPI-2.0, not this platform

	CONST ACPI_SDT_HEADER* Xsdt = (CONST ACPI_SDT_HEADER*)(UINTN)Rsdp->XsdtAddress;
	if (CompareMem(Xsdt->Signature, "XSDT", 4) != 0 || Xsdt->Length < sizeof(ACPI_SDT_HEADER))
		return NULL;

	//
	// Entries are UINT64 physical addresses. They are NOT guaranteed 8-byte aligned inside the
	// table, so they are read byte-wise rather than dereferenced as UINT64*.
	//
	CONST UINTN Count = (Xsdt->Length - sizeof(ACPI_SDT_HEADER)) / sizeof(UINT64);
	CONST UINT8* Entries = (CONST UINT8*)Xsdt + sizeof(ACPI_SDT_HEADER);
	for (UINTN i = 0; i < Count; i++)
	{
		UINT64 Address = 0;
		CopyMem(&Address, Entries + i * sizeof(UINT64), sizeof(UINT64));
		if (Address == 0)
			continue;
		CONST ACPI_SDT_HEADER* Table = (CONST ACPI_SDT_HEADER*)(UINTN)Address;
		if (CompareMem(Table->Signature, "TPM2", 4) == 0)
			return Table;
	}
	return NULL;
}


//
// Cached at DXE entry by InitTcgLogSanitizer(), consumed at ExitBootServices. Resolved EARLY
// because both operations are illegal later: ACPI physical addresses need identity mapping, and
// allocation is forbidden during EBS.
//
STATIC UINT64 mLasa = 0;
STATIC UINT32 mLaml = 0;
STATIC UINT8* mWork = NULL;
STATIC UINTN mWorkSize = 0;

//
// GetEventLog hook state. A SEPARATE buffer from mWork on purpose: the substituted log must stay
// valid until Windows has copied it, and mWork is rewritten by the ExitBootServices path. Sharing
// one buffer would let the later path scribble on a pointer Windows may still be holding.
//
STATIC EFI_TCG2_PROTOCOL* mTcg2Protocol = NULL;
STATIC EFI_TCG2_GET_EVENT_LOG mOriginalGetEventLog = NULL;
STATIC UINT8* mHookBuf = NULL;
STATIC UINTN mHookBufSize = 0;
STATIC UINT32 mHookCalls = 0;
STATIC EFI_STATUS mHookStatus = EFI_NOT_READY;
STATIC UINT32 mHookBytes = 0;


VOID
EFIAPI
GetTcgHookDiagnostics(
	OUT UINT32* CallCount,
	OUT EFI_STATUS* LastStatus,
	OUT UINT32* SubstitutedBytes
	)
{
	if (CallCount != NULL)        *CallCount = mHookCalls;
	if (LastStatus != NULL)       *LastStatus = mHookStatus;
	if (SubstitutedBytes != NULL) *SubstitutedBytes = mHookBytes;
}


/**
 * gRT-independent hook on EFI_TCG2_PROTOCOL.GetEventLog. Always calls through first and keeps the
 * firmware's status; substitutes our sanitized copy only on complete success.
 *
 * Runs in whatever context the caller is in -- bootmgfw or winload, both with boot services live and
 * identity mapping intact, since the protocol itself is firmware code. It does NOT touch ACPI, so
 * the page-table problem that hung the winload attempt does not apply here.
 */
STATIC
EFI_STATUS
EFIAPI
HookedGetEventLog(
	IN EFI_TCG2_PROTOCOL* This,
	IN EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
	OUT EFI_PHYSICAL_ADDRESS* EventLogLocation,
	OUT EFI_PHYSICAL_ADDRESS* EventLogLastEntry,
	OUT BOOLEAN* EventLogTruncated
	)
{
	CONST EFI_STATUS Status = mOriginalGetEventLog(This, EventLogFormat, EventLogLocation,
												   EventLogLastEntry, EventLogTruncated);
	mHookCalls++;

	if (!gDriverConfig.SpoofSecureBoot ||
		SecureBootIsGenuinelyEnforcing() ||	// already honest -- rewriting it would ADD a tell
		EFI_ERROR(Status) ||
		EventLogFormat != EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 ||
		EventLogLocation == NULL || *EventLogLocation == 0 ||
		mHookBuf == NULL)
	{
		mHookStatus = EFI_ERROR(Status) ? Status : EFI_UNSUPPORTED;
		return Status;
	}

	//
	// Re-sanitize on EVERY call rather than caching. The firmware appends between calls, so a cached
	// copy would be stale -- and a stale log handed to a later caller is exactly the kind of
	// self-inconsistency this tier exists to avoid.
	//
	CONST UINT8* Src = (CONST UINT8*)(UINTN)*EventLogLocation;
	CONST UINTN Extent = MeasureLogExtent(Src, mLaml != 0 ? mLaml : 0x10000);
	if (Extent == 0)
	{
		mHookStatus = EFI_VOLUME_CORRUPTED;
		return Status;
	}

	CHAR16 SelfPaths[MAX_SELF_PATHS][MAX_PATH_CHARS];
	CONST UINTN SelfCount = CollectSelfPaths(SelfPaths);
	if (SelfCount == 0)
	{
		mHookStatus = EFI_NOT_FOUND;
		return Status;
	}

	UINTN NewSize = 0;
	//
	// TRUE: the substituted log is what Windows consumes, so it gets the full treatment including
	// the authority record that makes PCR[7] match a genuine Secure-Boot-enabled boot.
	//
	mHookStatus = SanitizeTcgEventLog(Src, Extent, SelfPaths, SelfCount, TRUE,
									  mHookBuf, mHookBufSize, &NewSize);
	if (EFI_ERROR(mHookStatus))
		return Status;

	mHookBytes = (UINT32)NewSize;
	*EventLogLocation = (EFI_PHYSICAL_ADDRESS)(UINTN)mHookBuf;
	if (EventLogLastEntry != NULL)
	{
		//
		// The protocol reports the LAST ENTRY's address. Found by walking OUR copy -- scaling the
		// original offset would be wrong the moment the transform changes any record's size.
		//
		*EventLogLastEntry =
			(EFI_PHYSICAL_ADDRESS)(UINTN)(mHookBuf + FindLastRecordOffset(mHookBuf, NewSize));
	}
	return Status;
}


EFI_STATUS
EFIAPI
InitTcgLogSanitizer(
	VOID
	)
{
	CONST ACPI_SDT_HEADER* Tpm2 = FindTpm2Table();
	if (Tpm2 == NULL || Tpm2->Length < TPM2_MIN_LENGTH_FOR_LOG)
	{
		Print(L"[TCG] no usable ACPI TPM2 table; log sanitizer inactive.\r\n");
		return EFI_NOT_FOUND;
	}

	CONST UINT8* Tail = (CONST UINT8*)Tpm2 + Tpm2->Length - 12;
	CopyMem(&mLaml, Tail, sizeof(mLaml));
	CopyMem(&mLasa, Tail + 4, sizeof(mLasa));

	if (mLasa == 0 || mLaml == 0)
	{
		Print(L"[TCG] TPM2 publishes no log address; sanitizer inactive.\r\n");
		mLasa = 0;
		mLaml = 0;
		return EFI_NOT_FOUND;
	}

	//
	// Worst case output is the whole log area plus one inserted record. Reserved NOW because
	// AllocatePool cannot be called from the ExitBootServices callback.
	//
	mWorkSize = (UINTN)mLaml + TCG_AUTHORITY_BLOB_SIZE + 512;
	mWork = (UINT8*)AllocatePool(mWorkSize);
	if (mWork == NULL)
	{
		Print(L"[TCG] could not reserve %u B work buffer; sanitizer inactive.\r\n",
			  (UINT32)mWorkSize);
		mWorkSize = 0;
		return EFI_OUT_OF_RESOURCES;
	}

	//
	// Second buffer for the GetEventLog hook, and the hook itself.
	//
	// BOTH PATHS RUN, deliberately. They target different things -- the hook substitutes a pointer
	// for whoever calls the protocol, the EBS path rewrites the ACPI buffer -- and it is not yet
	// known which (if either) Windows actually consumes. Measured facts so far: TBS and MeasuredBoot
	// return byte-identical logs, so both serve ONE snapshot taken before EBS, which makes the EBS
	// path likely too late; and the protocol path was previously written off on an inference that
	// does not survive scrutiny (see the header). Running both, with per-path diagnostics, settles it
	// in one boot instead of alternating guesses.
	//
	mHookBufSize = mWorkSize;
	mHookBuf = (UINT8*)AllocatePool(mHookBufSize);
	if (mHookBuf == NULL)
	{
		Print(L"[TCG] could not reserve hook buffer; protocol path inactive.\r\n");
		mHookBufSize = 0;
	}
	else if (gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&mTcg2Protocol) == EFI_SUCCESS
			 && mTcg2Protocol != NULL)
	{
		mOriginalGetEventLog = mTcg2Protocol->GetEventLog;
		mTcg2Protocol->GetEventLog = HookedGetEventLog;
		Print(L"[TCG] hooked GetEventLog: 0x%p -> 0x%p\r\n",
			  (VOID*)mOriginalGetEventLog, (VOID*)&HookedGetEventLog);
	}
	else
	{
		mTcg2Protocol = NULL;
		Print(L"[TCG] TCG2 protocol not located; only the ACPI path is armed.\r\n");
	}

	Print(L"[TCG] log at 0x%lx (LAML %u B); sanitizer armed.\r\n", mLasa, mLaml);
	return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
PatchTcgEventLogInPlace(
	OUT UINT32* OldSize OPTIONAL,
	OUT UINT32* NewSizeOut OPTIONAL,
	OUT UINT32* Capacity OPTIONAL
	)
{
	//
	// ⚠ NO ALLOCATION AND NO ACPI LOOKUP IN HERE. This runs from the ExitBootServices callback,
	// where allocation is forbidden. Everything that needs boot services or a table walk was already
	// done by InitTcgLogSanitizer(). Printing IS safe here (the existing EBS callback prints), but
	// diagnostics still leave via OUT params so the caller owns the reporting.
	//
	if (OldSize != NULL)    *OldSize = 0;
	if (NewSizeOut != NULL) *NewSizeOut = 0;
	if (Capacity != NULL)   *Capacity = mLaml;

	if (!gDriverConfig.SpoofSecureBoot)
		return EFI_SUCCESS;
	//
	// Genuinely enforcing -> the log is already correct. Transforming it would insert a duplicate
	// authority record and desynchronise the log from the PCRs.
	//
	if (SecureBootIsGenuinelyEnforcing())
		return EFI_SUCCESS;
	if (mLasa == 0 || mWork == NULL)
		return EFI_NOT_READY;

	UINT8* Log = (UINT8*)(UINTN)mLasa;
	CONST UINTN Extent = MeasureLogExtent(Log, mLaml);
	if (OldSize != NULL)
		*OldSize = (UINT32)Extent;
	if (Extent == 0)
		return EFI_VOLUME_CORRUPTED;

	//
	// Self-discovery lives HERE, not in the transform: it needs protocols, and keeping it out of
	// the transform is what makes the transform host-testable. Refuse if we cannot identify
	// ourselves rather than sanitizing a log while recognising none of our own records -- that
	// would report success having removed nothing.
	//
	CHAR16 SelfPaths[MAX_SELF_PATHS][MAX_PATH_CHARS];
	CONST UINTN SelfCount = CollectSelfPaths(SelfPaths);
	if (SelfCount == 0)
		return EFI_NOT_FOUND;

	UINTN NewSize = 0;
	//
	// FALSE: this writes back into the fixed 64 KB ACPI log area. With the 1608-byte authority
	// record the output was 78,499 bytes against a 65,536 capacity and this path refused outright,
	// leaving the raw buffer fully dirty. Without it the transform only drops records and flips two
	// bytes, so it SHRINKS and fits -- which removes every one of our identifying records from the
	// buffer a direct-memory reader sees. That is worth more than making a buffer nobody was reading
	// claim Secure Boot was on.
	//
	CONST EFI_STATUS Status = SanitizeTcgEventLog(Log, Extent, SelfPaths, SelfCount, FALSE,
												  mWork, mWorkSize, &NewSize);
	if (EFI_ERROR(Status))
		return Status;

	if (NewSizeOut != NULL)
		*NewSizeOut = (UINT32)NewSize;

	if (NewSize > mLaml)
	{
		//
		// The log area is a fixed CAPACITY. Unlike substituting a larger buffer, an in-place patch
		// cannot grow past it -- writing beyond LAML would corrupt whatever the firmware placed
		// after the log.
		//
		return EFI_BUFFER_TOO_SMALL;
	}

	CopyMem(Log, mWork, NewSize);

	//
	// If the sanitized log is SHORTER than the original, the old tail bytes are still there and a
	// reader walking events would parse them as a bogus trailing record. Zero the difference so the
	// walk terminates exactly where the new log ends.
	//
	if (NewSize < Extent)
		ZeroMem(Log + NewSize, Extent - NewSize);

	return EFI_SUCCESS;
}
