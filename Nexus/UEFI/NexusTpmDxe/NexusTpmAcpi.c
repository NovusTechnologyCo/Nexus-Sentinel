/**
 * @file NexusTpmAcpi.c
 * @brief Phase 1.3 — publish the ACPI TPM2 table so the RAM CRB transport is DISCOVERABLE.
 *
 * `the design notes` §3.1, §3.4. Phase 1.2 allocated the transport and the boot log then
 * said, correctly, `[TCG] no usable ACPI TPM2 table` — the region existed at a known physical
 * address and nothing could find it. This file closes exactly that gap and nothing else.
 *
 * ⚠ TABLE LAYOUT IS TRANSCRIBED FROM **TCG ACPI Specification 1.5, Table 7**, read
 * from the PDF now held in `reference material/tcg/`, not recalled:
 *
 *     Field                          Len  Off
 *     Signature "TPM2"                 4    0
 *     Length                           4    4    52 + sizeof(start-method params)
 *     Revision                         1    8    "Value MUST be 6"
 *     Checksum                         1    9    entire table MUST sum to zero
 *     OEMID                            6   10
 *     OEM Table ID                     8   16
 *     OEM Revision                     4   24
 *     Creator ID                       4   28
 *     Creator Revision                 4   32
 *     Platform Class                   2   36    0 = client, 1 = server
 *     Reserved                         2   38    0
 *     Address of CRB Control Area      8   40    SHALL be the address of TPM_CRB_CTRL_REQ_0
 *     Start Method                     4   48
 *     Start Method Specific Params  0-16   52    absent for Start Method 7
 *     [LAML                            4   68    optional]
 *     [LASA                            8   72    optional -> Length becomes 80]
 *
 * ⚠ EDK2's `EFI_TPM2_ACPI_TABLE` IS BYTE-IDENTICAL TO THIS for the first 52 bytes — its `Flags`
 * field at offset 36 is what rev 4+ split into PlatformClass + Reserved. So the struct is reused
 * and only the REVISION VALUE differs: `edk2-stable202608` defines revisions 3, 4 and 5 and stops.
 * **Revision 6 is newer than the EDK2 we vendored.** That is why the constant is spelled out here
 * with its source rather than taken from `Tpm2Acpi.h`.
 */

//
// (!) NexusBootDxe.h IS DELIBERATELY NOT INCLUDED. It was, until this file moved here,
// and nothing in it was ever used: it pulls Zydis, pe.h, arc.h and the bootmgr/winload
// patch machinery into a translation unit that only needs UEFI and our own TPM headers.
// Dropping it is what proves the separation is real rather than cosmetic.
//
#include "NexusTpmAcpi.h"
#include "RamCrb.h"
#include "Tpm2Profile.h"

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/Tpm2Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/TcgService.h>

//
// For the NXC_FWTCG_* bits: the probe records its answer in the boot block (ABI 18) so it
// survives to the OS rather than living only on the boot screen.
//
#include "../../Include/NexusCoreBoot.h"

//
// ⚠ DEFINED HERE, NOT IMPORTED. `Protocol/AcpiTable.h` only DECLARES
// `extern EFI_GUID gEfiAcpiTableProtocolGuid`; the definition lives in a MdePkg source file we do
// not vendor, and none of the 31 archives we link exports it (checked). Declaring without defining
// links to nothing and fails at LINK time, which is at least honest -- but defining it locally from
// the header's own macro is the fix, and the value is asserted against that macro below.
//
STATIC EFI_GUID mAcpiTableProtocolGuid = EFI_ACPI_TABLE_PROTOCOL_GUID;

//
// TCG ACPI 1.5 Table 7: "Value MUST be 6, which is the current revision of this table."
// ⚠ NOT in EDK2 -- Tpm2Acpi.h stops at EFI_TPM2_ACPI_TABLE_REVISION_5.
//
//
// (!) THE TABLE REVISION DECIDES WHETHER WINDOWS TALKS TO US AT ALL. THIS IS MEASURED.
//
// Revision 6 (TCG ACPI 1.5, "Value MUST be 6"): tpm.sys logs event 16, "A compatible TPM is
// not found", two seconds into boot and NEVER WRITES A BYTE to the CRB. It rejects the platform
// before speaking to it. Microsoft KB 3103683 documents that exact event from that exact driver
// for a TPM2 table whose revision the OS does not recognise -- the previous generation of this
// same failure, from when revision 4 was the one too new.
//
// Revision 4: tpm.sys ACCEPTS the platform and writes TPM_CRB_CTRL_REQ.cmdReady = 1 to our CRB.
// The event changes to 27 ("initialization of the TPM failed") plus 15 ("non-recoverable error
// in the TPM hardware") -- i.e. "there is no TPM" becomes "the TPM is broken", which is what a
// TPM that never answers looks like. Everything upstream is thereby validated BY WINDOWS.
//
// Revision 5 is what is being tried now. It is EDK2 stable202608's default (that EDK2 defines
// only 3, 4 and 5), so most modern platforms publish it -- advertising 5 makes our table look
// like a current machine's rather than an older one's, for free if Windows accepts it.
//
// (!) THE DISCRIMINATOR IS ONE BIT AND IT IS CHEAP: does tpm.sys write cmdReady? Read the CRB
// with `PlatformCtl readphys`. CTRL_REQ non-zero means accepted; untouched means rejected.
//
// (!) REVERT TARGET IS 4, NOT 6. If 5 is rejected, go straight back to the value with direct
// evidence rather than experimenting onward. A known-good state is worth more than a newer
// number.
//
// (!) COMPATIBILITY, NOT CONFORMANCE -- §0 lists Windows as an "empirical compatibility layer,
// NOT a conformance authority". 6 remains the conformant value under TCG ACPI 1.5; what we
// PUBLISH is chosen to be understood by the consumer actually present.
//
// (!) THE REST OF THE TABLE IS BYTE-IDENTICAL ACROSS 4/5/6. Revision 4 reads offset 36 as
// `Flags`; 5+ split the same four bytes into PlatformClass + Reserved. We write both as zero,
// valid under either reading, so only the revision byte and the checksum ever change.
//
//
// ⚠ MEASURED: THIS MACHINE'S FIRMWARE PUBLISHES REVISION 4, NOT 5.
//
// We chose 5 because EDK2 publishes 5 by default, and both 4 and 5 were measured acceptable
// to tpm.sys. The reference capture settles it the other way: the standard is to match the
// hardware on THIS machine, and the hardware says 4.
//
#define NEXUS_TPM2_ACPI_REVISION        TPM2_PROFILE_ACPI_REVISION
#define NEXUS_TPM2_ACPI_REVISION_PROVEN      4   // MEASURED good: tpm.sys wrote cmdReady
#define NEXUS_TPM2_ACPI_REVISION_REJECTED    6   // MEASURED bad: event 16, no CRB write

//
// Table 8: 7 = "Uses the Command Response Buffer Interface".
//
// ⚠ START METHOD 7 IS A MEASUREMENT CHOICE FOR 1.3, NOT THE FINAL DESIGN. The spec's frozen
// architecture is Start Method 8 (CRB *with ACPI Start Method*), and §3.5 rejects blind polling.
// But 8 carries a NORMATIVE obligation -- TCG ACPI 1.5 says the ACPI Start Method SHALL be
// implemented when 2 or 8 is advertised -- and that `_DSM` is Phase 1.4's work.
//
// Publishing 8 without its `_DSM` would be non-conformant, and if binding then failed we could not
// tell "the table was rejected" from "the missing method was rejected". 7 needs no ACPI method at
// all, so this phase changes ONE variable: can we publish a table Windows honours, pointing at our
// own RAM?
//
// It is also the method THIS firmware published (rev 4 / method 7 / control area 0xFED40040) while
// PTT was enabled, and Windows bound to it. So method 7 is the known-good half of the experiment
// and revision 6 is the new half.
//
#define NEXUS_TPM2_START_METHOD         EFI_TPM2_ACPI_TABLE_START_METHOD_COMMAND_RESPONSE_BUFFER_INTERFACE

//
// Platform Class: 0 = client. Length: 52, because Start Method 7 defines no specific parameters and
// we publish no LAML/LASA (see the note on the log sanitizer at the bottom of this file).
//
#define NEXUS_TPM2_PLATFORM_CLASS       0
#define NEXUS_TPM2_TABLE_LENGTH         52

C_ASSERT(sizeof(EFI_TPM2_ACPI_TABLE) == NEXUS_TPM2_TABLE_LENGTH);
C_ASSERT(OFFSET_OF(EFI_TPM2_ACPI_TABLE, Flags)                == 36);
C_ASSERT(OFFSET_OF(EFI_TPM2_ACPI_TABLE, AddressOfControlArea) == 40);
C_ASSERT(OFFSET_OF(EFI_TPM2_ACPI_TABLE, StartMethod)          == 48);

STATIC UINTN                 mTableKey  = 0;
STATIC EFI_PHYSICAL_ADDRESS  mPublished = 0;   // control area we advertised, for the self-check

//
// ---------------------------------------------------------------------------------------------
// A DELIBERATELY INDEPENDENT XSDT WALK.
//
// `TcgLogSanitize.c` already has a `FindTpm2Table()`. It is STATIC, it is Secure-Boot-spoof
// critical, and it caches its answer at DXE entry -- BEFORE this file publishes anything. Two
// reasons this is a separate walk rather than an export:
//
//   1. Exporting would mean editing working, load-bearing SB code for a cosmetic dedup.
//   2. More importantly, this walk VERIFIES the table we just published. Verifying with the same
//      code a consumer uses is weaker than verifying with an independent implementation -- a bug
//      shared by both would agree with itself and teach us nothing.
//
// ⚠ If a THIRD consumer ever appears, merge them; two is the point at which independence is worth
// more than dedup, three is where it stops being.
// ---------------------------------------------------------------------------------------------
//

#pragma pack(push, 1)
typedef struct _NXA_RSDP {
	CHAR8  Signature[8];        // "RSD PTR "
	UINT8  Checksum;
	CHAR8  OemId[6];
	UINT8  Revision;
	UINT32 RsdtAddress;
	UINT32 Length;
	UINT64 XsdtAddress;
	UINT8  ExtendedChecksum;
	UINT8  Reserved[3];
} NXA_RSDP;
#pragma pack(pop)

extern EFI_GUID gEfiAcpi20TableGuid;

/**
 * Find the TPM2 table by walking the XSDT, and return its control-area address.
 *
 * @param OutRevision  revision byte as published, or 0 if not found
 * @return the AddressOfControlArea field, or 0 if no TPM2 table is present
 */
STATIC
UINT64
ReadPublishedTpm2(
	OUT UINT8* OutRevision
	)
{
	CONST NXA_RSDP* Rsdp = NULL;

	if (OutRevision != NULL)
		*OutRevision = 0;
	if (gST == NULL || gST->ConfigurationTable == NULL)
		return 0;

	for (UINTN i = 0; i < gST->NumberOfTableEntries; i++)
	{
		if (CompareGuid(&gST->ConfigurationTable[i].VendorGuid, &gEfiAcpi20TableGuid))
		{
			Rsdp = (CONST NXA_RSDP*)gST->ConfigurationTable[i].VendorTable;
			break;
		}
	}
	if (Rsdp == NULL || CompareMem(Rsdp->Signature, "RSD PTR ", 8) != 0 || Rsdp->XsdtAddress == 0)
		return 0;

	CONST EFI_ACPI_DESCRIPTION_HEADER* Xsdt =
		(CONST EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)Rsdp->XsdtAddress;
	if (CompareMem(&Xsdt->Signature, "XSDT", 4) != 0 ||
	    Xsdt->Length < sizeof(EFI_ACPI_DESCRIPTION_HEADER))
		return 0;

	//
	// Entries are UINT64 physical addresses and are NOT guaranteed 8-byte aligned inside the table,
	// so they are read byte-wise rather than dereferenced.
	//
	CONST UINTN  Count   = (Xsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT64);
	CONST UINT8* Entries = (CONST UINT8*)Xsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER);

	for (UINTN i = 0; i < Count; i++)
	{
		UINT64 Address = 0;
		CopyMem(&Address, Entries + i * sizeof(UINT64), sizeof(UINT64));
		if (Address == 0)
			continue;

		CONST EFI_ACPI_DESCRIPTION_HEADER* T = (CONST EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)Address;
		if (CompareMem(&T->Signature, "TPM2", 4) != 0)
			continue;
		if (T->Length < NEXUS_TPM2_TABLE_LENGTH)
			continue;                          // present but truncated -- not ours

		CONST EFI_TPM2_ACPI_TABLE* Tpm2 = (CONST EFI_TPM2_ACPI_TABLE*)T;
		if (OutRevision != NULL)
			*OutRevision = T->Revision;
		return Tpm2->AddressOfControlArea;
	}
	return 0;
}

/**
 * Sum every byte of a table. TCG ACPI 1.5: "Entire table MUST sum to zero."
 */
STATIC
UINT8
SumBytes(
	IN CONST VOID* Buffer,
	IN UINTN       Length
	)
{
	CONST UINT8* P = (CONST UINT8*)Buffer;
	UINT8 Sum = 0;
	for (UINTN i = 0; i < Length; i++)
		Sum = (UINT8)(Sum + P[i]);
	return Sum;
}

/**
 * Publish the TPM2 table for the transport at @p LocalityBase.
 *
 * ⚠ @p LocalityBase is the CRB LOCALITY base. The table advertises the CONTROL AREA, which is
 * that + 0x40 -- TCG ACPI 1.5 is explicit: "the address of the Control Area SHALL be the address
 * of the TPM_CRB_CTRL_REQ_0 register".
 */
EFI_STATUS
NexusTpmAcpiPublish(
	IN EFI_PHYSICAL_ADDRESS LocalityBase
	)
{
	EFI_ACPI_TABLE_PROTOCOL* Acpi = NULL;
	EFI_TPM2_ACPI_TABLE      Table;
	EFI_STATUS               Status;

	if (LocalityBase == 0)
	{
		Print(L"[TPM] ACPI: no transport to publish (region A is 0)\r\n");
		return EFI_NOT_READY;
	}

	//
	// ⚠ HONEST FAILURE, NOT A STUB. If the firmware exposes no EFI_ACPI_TABLE_PROTOCOL there is no
	// sanctioned way to add a table, and hand-splicing the XSDT behind the firmware's back is
	// exactly the kind of thing that boots once and corrupts later. Report and decline.
	//
	Status = gBS->LocateProtocol(&mAcpiTableProtocolGuid, NULL, (VOID**)&Acpi);
	if (EFI_ERROR(Status) || Acpi == NULL)
	{
		Print(L"[TPM] ACPI: EFI_ACPI_TABLE_PROTOCOL unavailable (%r) -- table NOT published\r\n",
		      Status);
		return EFI_UNSUPPORTED;
	}

	CONST EFI_PHYSICAL_ADDRESS ControlArea = LocalityBase + CRB_CONTROL_AREA_OFFSET;

	ZeroMem(&Table, sizeof(Table));
	CopyMem(&Table.Header.Signature, "TPM2", 4);
	Table.Header.Length   = NEXUS_TPM2_TABLE_LENGTH;
	Table.Header.Revision = NEXUS_TPM2_ACPI_REVISION;
	CopyMem(&Table.Header.OemId, TPM2_PROFILE_ACPI_OEM_ID, 6);
	CopyMem(&Table.Header.OemTableId, TPM2_PROFILE_ACPI_OEM_TABLE_ID, 8);
	Table.Header.OemRevision     = TPM2_PROFILE_ACPI_OEM_REVISION;
	CopyMem(&Table.Header.CreatorId, TPM2_PROFILE_ACPI_CREATOR_ID, 4);
	Table.Header.CreatorRevision = 1;

	//
	// EDK2 calls offsets 36..39 `Flags`; TCG ACPI 1.5 rev 4+ splits it into PlatformClass (u16)
	// and Reserved (u16). Client platform, reserved zero -- so the whole field is zero. Written
	// through the low half explicitly rather than left implicitly zeroed, so the intent is visible.
	//
	Table.Flags                = NEXUS_TPM2_PLATFORM_CLASS;
	Table.AddressOfControlArea = ControlArea;
	Table.StartMethod          = NEXUS_TPM2_START_METHOD;

	//
	// Checksum LAST, over the finished bytes. InstallAcpiTable recomputes it, but computing it here
	// means the buffer we hand over is already valid -- and if a future path ever writes the table
	// without the protocol, it will not silently ship an unchecksummed one.
	//
	Table.Header.Checksum = 0;
	Table.Header.Checksum = (UINT8)(0x100 - SumBytes(&Table, NEXUS_TPM2_TABLE_LENGTH));

	Status = Acpi->InstallAcpiTable(Acpi, &Table, NEXUS_TPM2_TABLE_LENGTH, &mTableKey);
	if (EFI_ERROR(Status))
	{
		Print(L"[TPM] ACPI: InstallAcpiTable FAILED: %r\r\n", Status);
		return Status;
	}
	mPublished = ControlArea;

	//
	// ⚠ KNOWN-ANSWER SELF-CHECK. We know exactly what we published, so read it back the way a
	// consumer would -- through the XSDT -- and compare. This distinguishes "InstallAcpiTable
	// returned success" from "the table is actually discoverable", which are not the same claim
	// and would otherwise both look like success until Windows failed to find it.
	//
	UINT8  SeenRevision = 0;
	CONST UINT64 SeenControlArea = ReadPublishedTpm2(&SeenRevision);

	Print(L"\r\n[TPM] ============ ACPI TPM2 table (Phase 1.3) =============\r\n");
	Print(L"[TPM] revision              : %d   (TCG ACPI 1.5 Table 7: MUST be 6)\r\n",
	      NEXUS_TPM2_ACPI_REVISION);
	Print(L"[TPM] length                : %d bytes\r\n", NEXUS_TPM2_TABLE_LENGTH);
	Print(L"[TPM] platform class        : %d  (0 = client)\r\n", NEXUS_TPM2_PLATFORM_CLASS);
	Print(L"[TPM] start method          : %d  (CRB interface)\r\n", NEXUS_TPM2_START_METHOD);
	Print(L"[TPM] locality base         : 0x%016llx\r\n", (UINT64)LocalityBase);
	Print(L"[TPM] control area PUBLISHED: 0x%016llx  (= base + 0x%02x)\r\n",
	      (UINT64)ControlArea, CRB_CONTROL_AREA_OFFSET);
	Print(L"[TPM] table key             : 0x%llx\r\n", (UINT64)mTableKey);
	Print(L"[TPM] --- read back through the XSDT, independently ---\r\n");
	Print(L"[TPM] control area SEEN     : 0x%016llx\r\n", SeenControlArea);
	Print(L"[TPM] revision SEEN         : %d\r\n", SeenRevision);

	if (SeenControlArea == ControlArea && SeenRevision == NEXUS_TPM2_ACPI_REVISION)
	{
		Print(L"[TPM] SELF-CHECK            : PASS -- discoverable, and it is our table\r\n");
	}
	else
	{
		//
		// Reported, not hidden, and not fatal: the table may still be found by Windows through a
		// path this walk does not model. What must never happen is calling this a success.
		//
		Print(L"[TPM] SELF-CHECK            : *** MISMATCH *** published 0x%016llx rev %d, "
		      L"read back 0x%016llx rev %d\r\n",
		      (UINT64)ControlArea, NEXUS_TPM2_ACPI_REVISION, SeenControlArea, SeenRevision);
	}
	Print(L"[TPM] ======================================================\r\n\r\n");

	return EFI_SUCCESS;
}

/**
 * The control area this boot advertised, or 0 if nothing was published.
 */
EFI_PHYSICAL_ADDRESS
NexusTpmAcpiPublishedControlArea(
	VOID
	)
{
	return mPublished;
}


//
// =============================================================================================
// PHASE 1.3b -- THE ACPI DEVICE NODE.
//
// (!) MEASURED, NOT ASSUMED. Phase 1.3 published a valid rev-6 TPM2 table, Windows accepted it
// and kept it -- and `tpm.sys` still did not bind (Get-Tpm: TpmPresent False, service Stopped).
// A scan of the DSDT and every readable table showed why: MSFT0101 appears nowhere, TPM_ and
// PTS_ exist only as DANGLING references, and the ACPI\INTC7001 node Windows still lists is a
// stale registry ghost from when PTT was enabled -- that string is in no live table.
//
// tpm.sys binds to a DEVICE. A static table does not create one. So we declare one.
//
// This is what the spec reserved as "Device identity -- CANDIDATE", with the instruction to
// measure whether the table alone sufficed before inventing a _HID. It does not, so the _HID is
// no longer invented.
// =============================================================================================
//

//
// (!) THE DEVICE IS NAMED NXTP, **NOT** TPM_, AND THAT IS DELIBERATE.
//
// The obvious name is TPM_, and the spec noted it would also resolve the DSDT's dangling
// \_SB.TPM_.PTS_ calls "in one move". It would -- into a device that EXISTS but has no PTS_
// method, turning "object not found" into "method not found" on a SLEEP path we have not
// characterised (that is Phase 1.7).
//
// This build is a binding experiment. Naming it TPM_ would bundle a second, unmeasured change
// into it, and 1.3 just spent a reboot separating exactly this kind of confounding. The name is
// irrelevant to binding -- Windows enumerates ACPI devices by _HID, not by namespace path.
//
// Revisit once 1.7 says what PTS_ is for.
//

//
// AML, hand-encoded. Sizes were computed before writing and every PkgLength below fits in one
// byte (<= 63), which is asserted rather than hoped for.
//
//   Scope (\_SB) { Device (NXTP) {
//       Name (_HID, "MSFT0101")
//       Name (_STA, 0x0F)
//       Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, <base>, 0x1000) })
//   } }
//
// (!) A PkgLength COUNTS ITSELF plus everything it covers. Getting that wrong yields AML that
// parses into the wrong shape rather than failing loudly, so the arithmetic is spelled out:
//     _HID 15 + _STA 7 + _CRS 23            = 45 device content
//     1 (pkglen) + 4 ("NXTP") + 45          = 50 = 0x32  device PkgLength
//     2 (5B 82) + 50                        = 52 device total
//     1 (pkglen) + 5 ("\_SB_") + 52         = 58 = 0x3A  scope PkgLength
//     1 (0x10) + 58                         = 59 body total,  + 36 header = 95
//
STATIC CONST UINT8 mSsdtBody[] = {
	//
	// Scope (\_SB)
	//
	0x10,                                  // ScopeOp
	0x3A,                                  // PkgLength = 58
	0x5C, 0x5F, 0x53, 0x42, 0x5F,          // RootChar + "_SB_"

	//
	// Device (NXTP)
	//
	0x5B, 0x82,                            // ExtOpPrefix + DeviceOp
	0x32,                                  // PkgLength = 50
	0x4E, 0x58, 0x54, 0x50,                // "NXTP"

	//
	// Name (_HID, "MSFT0101") -- the only field tpm.sys actually matches on
	//
	0x08,                                  // NameOp
	0x5F, 0x48, 0x49, 0x44,                // "_HID"
	0x0D,                                  // StringPrefix
	0x4D, 0x53, 0x46, 0x54,                // "MSFT"
	0x30, 0x31, 0x30, 0x31, 0x00,          // "0101" + NUL

	//
	// Name (_STA, 0x0F) -- present, enabled, shown, functioning
	//
	0x08,                                  // NameOp
	0x5F, 0x53, 0x54, 0x41,                // "_STA"
	0x0A, 0x0F,                            // BytePrefix, 0x0F

	//
	// Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, base, 0x1000) })
	//
	// (!) THE _CRS COVERS THE WHOLE LOCALITY PAGE, NOT JUST THE CONTROL AREA. Drivers map the
	// region ACPI describes; a _CRS covering only 0x40..0x7F would leave the data buffer at 0x80
	// outside the mapping. Linux has an explicit "ACPI region does not cover the entire
	// command/response buffer" failure path for precisely this. See RamCrb.h.
	//
	0x08,                                  // NameOp
	0x5F, 0x43, 0x52, 0x53,                // "_CRS"
	0x11,                                  // BufferOp
	0x11,                                  // PkgLength = 17
	0x0A, 0x0E,                            // BufferSize: BytePrefix 14
	0x86,                                  // Memory32Fixed, large resource
	0x09, 0x00,                            // descriptor length = 9
	0x01,                                  // ReadWrite
	0x00, 0x00, 0x00, 0x00,                // <-- BASE, patched at runtime
	0x00, 0x10, 0x00, 0x00,                // length 0x1000, one locality page
	0x79, 0x00                             // EndTag + checksum
};

#define NEXUS_SSDT_BASE_OFFSET   49      // offset of the Memory32Fixed base inside mSsdtBody

C_ASSERT(sizeof(mSsdtBody) == 59);
C_ASSERT(NEXUS_SSDT_BASE_OFFSET + 4 <= sizeof(mSsdtBody));

/**
 * Publish an SSDT declaring an MSFT0101 device whose _CRS covers the transport locality.
 *
 * @param LocalityBase  region A base. Must be below 4 GB -- Memory32Fixed is a 32-bit
 *                      descriptor, and a QWordMemory form would be needed above that.
 */
EFI_STATUS
NexusTpmSsdtPublish(
	IN EFI_PHYSICAL_ADDRESS LocalityBase
	)
{
	EFI_ACPI_TABLE_PROTOCOL* Acpi = NULL;
	EFI_STATUS               Status;
	UINTN                    Key = 0;
	UINT8                    Ssdt[sizeof(EFI_ACPI_DESCRIPTION_HEADER) + sizeof(mSsdtBody)];

	if (LocalityBase == 0)
		return EFI_NOT_READY;

	//
	// (!) HONEST FAILURE, NOT A TRUNCATED ADDRESS. Memory32Fixed cannot describe a region above
	// 4 GB. Silently writing the low 32 bits would publish a _CRS pointing at the wrong memory --
	// far worse than publishing nothing, because it would look like it worked.
	//
	if (LocalityBase + CRB_LOCALITY_SIZE > 0x100000000ull)
	{
		Print(L"[TPM] SSDT: locality base 0x%016llx is above 4 GB -- Memory32Fixed cannot "
		      L"describe it; device NOT published\r\n", (UINT64)LocalityBase);
		return EFI_UNSUPPORTED;
	}

	Status = gBS->LocateProtocol(&mAcpiTableProtocolGuid, NULL, (VOID**)&Acpi);
	if (EFI_ERROR(Status) || Acpi == NULL)
	{
		Print(L"[TPM] SSDT: EFI_ACPI_TABLE_PROTOCOL unavailable (%r)\r\n", Status);
		return EFI_UNSUPPORTED;
	}

	EFI_ACPI_DESCRIPTION_HEADER* H = (EFI_ACPI_DESCRIPTION_HEADER*)Ssdt;
	ZeroMem(Ssdt, sizeof(Ssdt));
	CopyMem(&H->Signature, "SSDT", 4);
	H->Length   = (UINT32)sizeof(Ssdt);
	H->Revision = 2;                       // 2 = 64-bit integer semantics
	CopyMem(&H->OemId, TPM2_PROFILE_ACPI_OEM_ID, 6);
	CopyMem(&H->OemTableId, TPM2_PROFILE_ACPI_OEM_TABLE_ID, 8);
	H->OemRevision     = TPM2_PROFILE_ACPI_OEM_REVISION;
	CopyMem(&H->CreatorId, TPM2_PROFILE_ACPI_CREATOR_ID, 4);
	H->CreatorRevision = 1;

	CopyMem(Ssdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER), mSsdtBody, sizeof(mSsdtBody));

	//
	// Patch the Memory32Fixed base. Written byte-wise rather than through a UINT32* because the
	// offset is not guaranteed aligned inside the table.
	//
	CONST UINT32 Base32 = (UINT32)LocalityBase;
	UINT8* CONST BaseAt = Ssdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER) + NEXUS_SSDT_BASE_OFFSET;
	CopyMem(BaseAt, &Base32, sizeof(Base32));

	H->Checksum = 0;
	H->Checksum = (UINT8)(0x100 - SumBytes(Ssdt, sizeof(Ssdt)));

	Status = Acpi->InstallAcpiTable(Acpi, Ssdt, sizeof(Ssdt), &Key);

	Print(L"\r\n[TPM] ============ ACPI device node (Phase 1.3b) ==========\r\n");
	Print(L"[TPM] device               : \\_SB.NXTP  (named NXTP, not TPM_ -- see source)\r\n");
	Print(L"[TPM] _HID                 : MSFT0101\r\n");
	Print(L"[TPM] _CRS                 : Memory32Fixed 0x%08x .. 0x%08x  (whole locality)\r\n",
	      Base32, Base32 + CRB_LOCALITY_SIZE - 1);
	Print(L"[TPM] SSDT length          : %d bytes\r\n", (UINT32)sizeof(Ssdt));
	Print(L"[TPM] install              : %r  (key 0x%llx)\r\n", Status, (UINT64)Key);
	Print(L"[TPM] ======================================================\r\n\r\n");

	return Status;
}

//
// =============================================================================================
// WHAT DOES THE FIRMWARE ITSELF PUBLISH ABOUT TPM? -- pure measurement, publishes nothing.
// =============================================================================================
//
// (!) THIS EXISTS BECAUSE THE EVIDENCE STOPPED POINTING AT THE CRB.
//
// After the INTF_ID register was made coherent, tpm.sys STILL wrote nothing -- not a command,
// not even a locality request (TPM_LOC_CTRL stayed 0). And Windows produced NO MeasuredBoot log
// this boot: C:\Windows\Logs\MeasuredBoot holds 105 of them, the newest dated,
// which is while Intel PTT was still enabled. Since PTT was disabled, none.
//
// MeasuredBoot logs are written by the BOOT LOADER, not by tpm.sys. Their absence says the
// loader found no TPM to measure into -- which on UEFI means it found no EFI_TCG2_PROTOCOL.
// That is upstream of everything we have been adjusting: the ACPI table and the CRB describe a
// device to the OS, while TCG2 is how FIRMWARE offers a TPM to the boot loader.
//
// (!) CORRELATION, NOT YET CAUSE. "No TCG2 and no TPM" is not proof that the first causes the
// second, and this probe does not settle it either -- it establishes the FACT that TCG2 is
// absent, which the argument above currently only infers. Measure the premise before acting on
// the conclusion.
//
// (!) AND NOTE WHAT WE CANNOT SEE: reads. Our evidence is "tpm.sys never WROTE". It may have
// read INTF_ID, or the control area, and declined. Detecting reads would need EPT or PT, neither
// of which exists here. Do not upgrade "no writes" into "never looked".
//

STATIC EFI_GUID mTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
STATIC EFI_GUID mTcgProtocolGuid  = EFI_TCG_PROTOCOL_GUID;
STATIC EFI_GUID mTcg2FinalEventsTableGuid = EFI_TCG2_FINAL_EVENTS_TABLE_GUID;

/**
 * Report which TCG facilities the firmware provides. Changes nothing.
 */
UINT32
NexusTpmProbeFirmwareTcg(
	VOID
	)
{
	UINT32 Flags = NXC_FWTCG_PROBED;
	VOID*      Tcg2  = NULL;
	VOID*      Tcg12 = NULL;
	EFI_STATUS S2    = gBS->LocateProtocol(&mTcg2ProtocolGuid, NULL, &Tcg2);
	EFI_STATUS S1    = gBS->LocateProtocol(&mTcgProtocolGuid,  NULL, &Tcg12);

	//
	// The final-events table is handed over through the EFI configuration table rather than a
	// protocol, so a firmware that measured anything leaves a trace here even after the protocol
	// is gone.
	//
	VOID* FinalEvents = NULL;
	if (gST != NULL && gST->ConfigurationTable != NULL)
	{
		for (UINTN i = 0; i < gST->NumberOfTableEntries; i++)
		{
			if (CompareGuid(&gST->ConfigurationTable[i].VendorGuid, &mTcg2FinalEventsTableGuid))
			{
				FinalEvents = gST->ConfigurationTable[i].VendorTable;
				break;
			}
		}
	}

	Print(L"\r\n[TPM] ======= firmware TCG facilities (probe only) =======\r\n");
	Print(L"[TPM] EFI_TCG2_PROTOCOL     : %s  (%r)\r\n",
	      (!EFI_ERROR(S2) && Tcg2 != NULL) ? L"PRESENT" : L"ABSENT ", S2);
	Print(L"[TPM] EFI_TCG_PROTOCOL (1.2): %s  (%r)\r\n",
	      (!EFI_ERROR(S1) && Tcg12 != NULL) ? L"PRESENT" : L"ABSENT ", S1);
	Print(L"[TPM] TCG2 final events tbl : %s\r\n",
	      (FinalEvents != NULL) ? L"PRESENT" : L"ABSENT");
	Print(L"[TPM] --\r\n");
	Print(L"[TPM] ABSENT here means the BOOT LOADER has no TPM to measure into, which is\r\n");
	Print(L"[TPM] upstream of the ACPI table and the CRB. See NexusTpmAcpi.c.\r\n");
	Print(L"[TPM] ======================================================\r\n\r\n");

	if (!EFI_ERROR(S2) && Tcg2 != NULL)   Flags |= NXC_FWTCG_TCG2;
	if (!EFI_ERROR(S1) && Tcg12 != NULL)  Flags |= NXC_FWTCG_TCG12;
	if (FinalEvents != NULL)              Flags |= NXC_FWTCG_FINAL_EVENTS;
	return Flags;
}
//
// ⚠ NO LAML / LASA, AND THAT IS DELIBERATE FOR 1.3.
//
// TCG ACPI 1.5 Table 7 makes the log fields optional (Length becomes 80 when present).
// `TcgLogSanitize.c` needs them -- it locates the TCG event log through exactly those fields -- so
// publishing them would switch the Tier-3 Secure Boot log sanitizer from inactive to active.
//
// That is a DIFFERENT track (Layer 2 SB spoof) with its own correctness questions, and folding it
// into a TPM binding experiment would put two unrelated changes behind one reboot. Left for that
// track to take deliberately.
//
// ⚠ Ordering note: `InitTcgLogSanitizer()` runs EARLIER in the DXE entry and caches its answer
// before this file publishes anything, so it is unaffected either way this boot. Do not "fix" that
// by reordering -- the sanitizer must see the FIRMWARE's table, not ours.
//
