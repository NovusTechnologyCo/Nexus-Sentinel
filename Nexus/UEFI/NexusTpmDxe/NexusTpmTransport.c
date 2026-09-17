/**
 * @file NexusTpmTransport.c
 * @brief Phase 1.2 — allocate and initialise the RAM CRB transport (region A) and canonical
 *        state (region B).
 *
 * `the design notes` §3.3, §3.4. Transport only: there is no TPM core behind this, and
 * Phase 2 is blocked on G1 by design.
 *
 * ⚠ PACKAGING: ONE IMAGE, AND THAT IS NOW A DECISION RATHER THAN A SHORTCUT.
 *
 * This file, and all TPM source, lives in `NexusTpmDxe/` -- but it BUILDS INTO
 * `PlatformRuntimeDxe.efi` alongside the Secure Boot spoof and the bootmgr/winload/kernel
 * patches. Earlier revisions of this comment promised a separate `NexusTpmDxe.efi` image
 * "before Phase 4". **That commitment is withdrawn** (spec rev 9.21, items 212-216).
 *
 * WHY IT WAS PROMISED: blast radius -- a TPM bug taking down the image that boots the machine.
 *
 * WHY THAT WAS WRONG: it already cannot. `Loader.c` shows its boot menu BEFORE StartNexusBoot()
 * specifically so a clean boot can skip the DXE entirely, and that path was exercised on
 * when a bad build of this very subsystem would not chain-boot Windows. The loader
 * was untouched, the menu appeared, clean boot worked. A failed experiment, not a brick.
 *
 * ⚠ THE CLEAN-BOOT MENU IS THE BLAST-RADIUS CONTROL, AND IT IS THE BETTER ONE. It covers ANY
 * DXE failure rather than only TPM ones, and costs no protocol boundary, no second signature and
 * no second manual map. A split would buy a strictly weaker version of protection we have.
 *
 * AND THE SPLIT COSTS ARE REAL WHERE ITS GAINS ARE SPECULATIVE: two artifacts per reboot cycle
 * (version skew -- the class of bug that produced the 452-vs-464 report-size mismatch the same
 * day), and a DOUBLED STEALTH SURFACE, since `ManualMap.c` exists to keep our driver out of
 * PCR[2] and the loaded-image list, and an image named like a TPM is a sharper tell than a
 * generic driver -- real TPMs are never loaded images.
 *
 * ⚠ WHAT WOULD REOPEN IT, checkable rather than a feeling: if a ported TPM core makes this
 * image large enough that manual mapping becomes unreliable -- a rising ManualMapRuntimeDriver
 * failure rate, or relocation/section counts ManualMap.c handles poorly. Not true today.
 */

//
// (!) NexusBootDxe.h IS DELIBERATELY NOT INCLUDED. It was, until this file moved here,
// and nothing in it was ever used: it pulls Zydis, pe.h, arc.h and the bootmgr/winload
// patch machinery into a translation unit that only needs UEFI and our own TPM headers.
// Dropping it is what proves the separation is real rather than cosmetic.
//
#include "NexusTpmTransport.h"
#include "RamCrb.h"
#include "TpmState.h"

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>        /* AsmReadTsc */

//
// Region A is one locality = one 4 KB page. Region B is sized for Phase 1's header plus room for
// the state a real TPM core will later need; it is not the final figure.
//
#define NEXUS_TPM_REGION_A_PAGES   1
#define NEXUS_TPM_REGION_B_PAGES   16      // 64 KB -- generous, and cheap in NVS

STATIC EFI_PHYSICAL_ADDRESS  mRegionA = 0;   // transport: the CRB locality base
STATIC EFI_PHYSICAL_ADDRESS  mRegionB = 0;   // canonical state
STATIC UINT64                mEpoch   = 0;

/**
 * A value distinct on every boot.
 *
 * ⚠ IT DOES NOT NEED TO BE SECRET, ONLY DISTINCT. Its whole job is to make a pointer from a
 * previous boot epoch detectably stale (TpmState.h). Mixing the TSC with the allocation address
 * gives that without pretending to be a random source we do not have in DXE.
 */
STATIC
UINT64
MakeBootEpoch(
	IN EFI_PHYSICAL_ADDRESS Anchor
	)
{
	CONST UINT64 Tsc = AsmReadTsc();
	UINT64 V = Tsc ^ (Anchor * 0x9E3779B97F4A7C15ull);
	V ^= V >> 33;
	V *= 0xFF51AFD7ED558CCDull;
	V ^= V >> 33;
	return V ? V : 1;      // 0 is reserved as "never valid"
}

/**
 * Lay out the CRB registers per PTP 1.07 Table 20 and the §3.4 contract.
 *
 * ⚠ THE SIZE AND ADDRESS REGISTERS ARE POPULATED, NOT ZEROED. §6.5.3.2(c.ii) says a RAM CRB
 * SHOULD zero them, and we deliberately do not: Linux `tpm_crb.c` `crb_map_io()` MAPS the buffer
 * using exactly these values, so a zero size yields a zero-length mapping. SHOULD is not SHALL,
 * and the SHALL -- treat them read-only, ignore writes -- is honoured by the servicer.
 * See the header for the full justification and the Phase 1.6 measurement that may revisit it.
 */
STATIC
VOID
InitialiseCrb(
	IN EFI_PHYSICAL_ADDRESS LocalityBase
	)
{
	NEXUS_CRB_LOCALITY* Crb = (NEXUS_CRB_LOCALITY*)(UINTN)LocalityBase;
	CONST EFI_PHYSICAL_ADDRESS BufferPhys = LocalityBase + CRB_OFF_DATA_BUFFER;

	ZeroMem(Crb, CRB_LOCALITY_SIZE);

	//
	// NORMATIVE (a): InterfaceType SHALL be 0010b -- "RAM CRB interface is active" -- in the low
	// nibble. But the WHOLE register has to be coherent, not just that nibble: see RamCrb.h, where
	// leaving the rest zero is recorded as the reason tpm.sys bound and then never wrote a byte.
	//
	Crb->IntfId = CRB_INTF_ID_VALUE;

	//
	// SHALL, and easy to miss: with CapSPICSUM = 00b in the register above, reads of these two
	// MUST return 0xFFFF. Leaving them zero would claim a checksum facility that reports 0.
	//
	Crb->DataCsumEnable = CRB_DATA_CSUM_ABSENT;
	Crb->DataCsum       = CRB_DATA_CSUM_ABSENT;

	//
	// The command and response buffers OVERLAP -- one buffer, both directions, which is what almost
	// every implementation does. Linux validates cmd_size == rsp_size in exactly that case, so the
	// two MUST be identical or it refuses the mapping.
	//
	Crb->CtrlCmdSize  = CRB_DATA_BUFFER_SIZE;
	Crb->CtrlRspSize  = CRB_DATA_BUFFER_SIZE;
	Crb->CtrlCmdLAddr = (UINT32)(BufferPhys & 0xFFFFFFFFull);
	Crb->CtrlCmdHAddr = (UINT32)(BufferPhys >> 32);
	Crb->CtrlRspAddr  = BufferPhys;

	//
	// Locality 0 only for Phase 1 (§3.4.1), stated rather than implied. Registers valid, no
	// locality currently assigned -- PTP requires that "no locality active" be reachable even in a
	// locality-0-only implementation.
	//
	Crb->LocState = CRB_LOC_STATE_TPM_REG_VALID;

	//
	// ⚠ THE HANDOFF CONTRACT (§3.2, TpmState.h): Idle, no command in flight, no pending request.
	// A stuck Start bit reads to a first post-EBS probe as a busy TPM that never answers, and would
	// be diagnosed as a signalling failure when it was really a handoff failure.
	//
	Crb->CtrlSts   = NEXUS_TPM_HANDOFF_CTRL_STS;
	Crb->CtrlStart = NEXUS_TPM_HANDOFF_CTRL_START;
	Crb->CtrlReq   = NEXUS_TPM_HANDOFF_CTRL_REQ;
}

/**
 * Fill region B's header and seal it with the two integrity checks.
 */
STATIC
EFI_STATUS
InitialiseState(
	IN EFI_PHYSICAL_ADDRESS StateBase,
	IN UINT64               StateSize,
	IN EFI_PHYSICAL_ADDRESS TransportBase,
	IN UINT64               TransportSize,
	IN UINT64               Epoch
	)
{
	NEXUS_TPM_STATE_HEADER* H = (NEXUS_TPM_STATE_HEADER*)(UINTN)StateBase;

	ZeroMem(H, (UINTN)StateSize);

	H->Magic          = NEXUS_TPM_STATE_MAGIC;
	H->Version        = NEXUS_TPM_STATE_VERSION;
	H->HeaderSize     = sizeof(NEXUS_TPM_STATE_HEADER);
	H->Epoch.Value    = Epoch;
	H->Epoch.TimestampTsc = AsmReadTsc();
	H->TransportPhys  = TransportBase;
	H->TransportSize  = TransportSize;
	H->StatePhys      = StateBase;          // self-reference: a moved copy is detectable
	H->StateSize      = StateSize;
	H->PayloadLength  = 0;                  // no TPM core yet -- Phase 2
	H->PayloadChecksum = 0;
	H->Reserved       = 0;

	//
	// HeaderCrc covers every byte above it. Computed LAST, and over exactly the bytes the reader
	// will check -- offsetof(HeaderCrc), not sizeof(header), or the CRC would cover itself.
	//
	return gBS->CalculateCrc32(H, OFFSET_OF(NEXUS_TPM_STATE_HEADER, HeaderCrc), &H->HeaderCrc);
}

/**
 * Phase 1.2 entry. Allocates both regions and leaves them in the handoff state.
 *
 * @param OutTransport  region A physical base (the LOCALITY base -- the ACPI table must publish
 *                      this + CRB_CONTROL_AREA_OFFSET, NOT this address)
 * @param OutState      region B physical base
 * @param OutEpoch      the boot epoch both regions were stamped with
 */
EFI_STATUS
NexusTpmTransportInit(
	OUT EFI_PHYSICAL_ADDRESS* OutTransport,
	OUT EFI_PHYSICAL_ADDRESS* OutState,
	OUT UINT64*               OutEpoch
	)
{
	EFI_STATUS Status;

	if (OutTransport != NULL) *OutTransport = 0;
	if (OutState != NULL)     *OutState = 0;
	if (OutEpoch != NULL)     *OutEpoch = 0;

	if (mRegionA != 0)
	{
		//
		// Already initialised this boot. Report the existing regions rather than allocating a
		// second set -- two transports would be worse than none.
		//
		if (OutTransport != NULL) *OutTransport = mRegionA;
		if (OutState != NULL)     *OutState = mRegionB;
		if (OutEpoch != NULL)     *OutEpoch = mEpoch;
		return EFI_ALREADY_STARTED;
	}

	//
	// ⚠ EfiACPIMemoryNVS with AllocateAnyPages, NOT EfiReservedMemoryType.
	//
	// UEFI 2.10/2.11 §7.2: "UEFI applications and UEFI drivers must not allocate memory of type
	// EfiReservedMemoryType." NVS is the correct type for a region the OS must PRESERVE rather than
	// reclaim, and the same clause requires runtime types to use AllocateAnyPages -- which is why
	// the physical address is not ours to choose and the ACPI table carries whatever we are given.
	//
	Status = gBS->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS,
	                            NEXUS_TPM_REGION_A_PAGES, &mRegionA);
	if (EFI_ERROR(Status))
	{
		Print(L"[TPM] transport: region A allocation failed: %r\r\n", Status);
		mRegionA = 0;
		return Status;
	}

	Status = gBS->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS,
	                            NEXUS_TPM_REGION_B_PAGES, &mRegionB);
	if (EFI_ERROR(Status))
	{
		Print(L"[TPM] transport: region B allocation failed: %r\r\n", Status);
		gBS->FreePages(mRegionA, NEXUS_TPM_REGION_A_PAGES);
		mRegionA = 0;
		mRegionB = 0;
		return Status;
	}

	mEpoch = MakeBootEpoch(mRegionA);

	InitialiseCrb(mRegionA);
	Status = InitialiseState(mRegionB, EFI_PAGES_TO_SIZE(NEXUS_TPM_REGION_B_PAGES),
	                         mRegionA, EFI_PAGES_TO_SIZE(NEXUS_TPM_REGION_A_PAGES), mEpoch);
	if (EFI_ERROR(Status))
	{
		Print(L"[TPM] transport: state header CRC failed: %r\r\n", Status);
		return Status;
	}

	//
	// ⚠ REPORT THE LOCALITY BASE **AND** THE CONTROL AREA, because confusing them is the single
	// most likely transcription error downstream. The ACPI TPM2 table publishes the CONTROL AREA;
	// the driver recovers the locality base by subtracting 0x40. Printing both makes a mistake in
	// either direction visible at boot rather than at binding.
	//
	Print(L"\r\n[TPM] ============ RAM CRB transport (Phase 1.2) ============\r\n");
	Print(L"[TPM] region A  locality base : 0x%016llx  (%u page)\r\n",
	      mRegionA, NEXUS_TPM_REGION_A_PAGES);
	Print(L"[TPM]           control area  : 0x%016llx  <- ACPI TPM2 publishes THIS\r\n",
	      mRegionA + CRB_CONTROL_AREA_OFFSET);
	Print(L"[TPM]           data buffer   : 0x%016llx  size 0x%04x\r\n",
	      mRegionA + CRB_OFF_DATA_BUFFER, CRB_DATA_BUFFER_SIZE);
	Print(L"[TPM] region B  state base    : 0x%016llx  (%u pages)\r\n",
	      mRegionB, NEXUS_TPM_REGION_B_PAGES);
	Print(L"[TPM] boot epoch              : 0x%016llx\r\n", mEpoch);
	Print(L"[TPM] InterfaceType           : 0x%x  (RAM CRB)\r\n", CRB_INTF_TYPE_RAM_CRB);
	Print(L"[TPM] handoff                 : Idle, no command in flight\r\n");
	Print(L"[TPM] ======================================================\r\n\r\n");

	if (OutTransport != NULL) *OutTransport = mRegionA;
	if (OutState != NULL)     *OutState = mRegionB;
	if (OutEpoch != NULL)     *OutEpoch = mEpoch;
	return EFI_SUCCESS;
}

/**
 * Byte sizes of the two regions, so the caller never restates a page count.
 *
 * Trivial, and deliberately so: the sizes exist in exactly one place (the PAGES defines at the
 * top of this file) and everything else asks. A second copy of a size is a second thing to get
 * wrong, and a wrong size here would widen the readphys whitelist past what we allocated.
 */
UINT32
NexusTpmTransportSizeA(
	VOID
	)
{
	return (UINT32)EFI_PAGES_TO_SIZE(NEXUS_TPM_REGION_A_PAGES);
}

UINT32
NexusTpmTransportSizeB(
	VOID
	)
{
	return (UINT32)EFI_PAGES_TO_SIZE(NEXUS_TPM_REGION_B_PAGES);
}
