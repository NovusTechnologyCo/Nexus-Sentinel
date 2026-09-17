/**
 * @file NexusTcg2.c
 * @brief `EFI_TCG2_PROTOCOL` backed by our own PCR bank and event log. Read NexusTcg2.h first.
 *
 * All seven protocol functions are implemented. Where a capability is genuinely absent it is
 * REFUSED with the specified status rather than faked — a protocol that answers plausibly and
 * does nothing is worse than one that says no, because the caller cannot tell.
 */

//
// (!) NexusBootDxe.h IS DELIBERATELY NOT INCLUDED. It was, until this file moved here,
// and nothing in it was ever used: it pulls Zydis, pe.h, arc.h and the bootmgr/winload
// patch machinery into a translation unit that only needs UEFI and our own TPM headers.
// Dropping it is what proves the separation is real rather than cosmetic.
//
#include "NexusTcg2.h"
#include "Tpm2Core.h"
#include "Tpm2Dispatch.h"
#include "Tpm2Entropy.h"
#include "Tpm2EventLog.h"
#include "TpmState.h"

//
// For CRB_DATA_BUFFER_SIZE. The protocol advertises the SAME maximum the CRB register does, so the
// two interfaces cannot promise a caller different limits for the same TPM.
//
#include "RamCrb.h"
#include "Tpm2PeHash.h"
#include "Tpm2Primary.h"

#include <Library/UefiBootServicesTableLib.h>
//
// For gRT, which the seed store needs. This file only ever wanted gBS until the seeds had to
// survive a reboot -- and they live in a UEFI variable, which is a RUNTIME service even when it is
// called during boot services.
//
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/Tcg2Protocol.h>

//
// PFP: "the 'PC Client PFP' specification defines a minimum log size of 64KB". One page more than
// that would be arbitrary; 64 KB is the number the standard names.
//
#define NEXUS_TCG2_LOG_PAGES     16          /* 64 KB */

//
// ⚠ THE VENDOR ID IS THE SAME 'INTC' THE REST OF THIS MACHINE ALREADY IMPLIES.
//
// The CRB interface register advertises VID 0x8086 for the same reason (RamCrb.h): this box ran
// Intel PTT until it was disabled, Windows still remembers TaskManufacturerId 0x494E5443 in the
// TPM service's registry key, and an identity that contradicts all of that is a louder signal
// than one that matches. "Report SPOOFED, never ABSENT" applied to the protocol layer.
//
// TCG2's ManufacturerID is the 4-character TCG vendor ID, not the 16-bit CRB VID.
//
#define NEXUS_TCG2_MANUFACTURER  SIGNATURE_32('I','N','T','C')

STATIC EFI_GUID mTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;

//
// State. One SHA-256 bank and one log, for the life of the boot.
//
STATIC TPM2_PCR_BANK   mBank;
STATIC TPM2_EVENT_LOG  mLog;
STATIC EFI_HANDLE      mHandle    = NULL;

//
// Region B -- the canonical state (the design notes.3). Zero when transport init
// did not allocate it, which is a legitimate state: transport init is non-fatal by design, and
// measurement must still work without it.
//
STATIC NEXUS_TPM_EXTEND_STATS mStats = { 0, 0, 0, 0 };

//
// The primary seeds, generated at transport init and published into region B so NexusCore
// finds them after ExitBootServices. See TpmState.h for what these are and why they must
// never reach the boot block.
//
STATIC NEXUS_TPM_SEEDS mSeeds;

/*
 * ============================================================================================
 * WHERE THE SEEDS LIVE BETWEEN BOOTS.
 * ============================================================================================
 *
 * A boot-services-only UEFI variable, written ONCE and read every boot after.
 *
 * (!) THIS IS A DELIBERATE REFINEMENT OF SPEC 5, WHICH SAYS "Location: ESP". That rule exists
 * because TPM state CHANGES AT RUNTIME -- NV writes, persistent handles, counters -- so
 * NexusCore has to own it and the DXE only reads. The seeds are not that: they are written once
 * and never modified, so the rule's reason does not reach them.
 *
 * (!) AND NVRAM IS STRICTLY SAFER HERE THAN THE ESP. Without EFI_VARIABLE_RUNTIME_ACCESS the
 * variable is unreachable through runtime services after ExitBootServices, so Windows cannot
 * read it with GetFirmwareEnvironmentVariable and neither can anything running as administrator.
 * An ESP file is readable by any admin with a drive letter. Spec 5.2 already says NVRAM is in
 * SPI flash rather than on the disk; this uses that property for confidentiality rather than
 * only for rollback resistance.
 *
 * It is NOT a security boundary against physical access or an SPI programmer. Region B already
 * holds the seeds in plain RAM for the whole boot, so this raises the floor, not the ceiling.
 *
 * (!) WRITTEN ONCE, AND THAT MATTERS FOR THE FLASH. NVRAM has finite write endurance and some
 * firmwares handle heavy variable traffic badly. This writes only when no valid variable exists,
 * so a machine that has been provisioned never writes again.
 */
#define NEXUS_TPM_SEED_VAR_NAME      L"NexusTpmSeeds"
#define NEXUS_TPM_SEED_STORE_MAGIC   0x5354455344454553ull   /* "SEEDSETS" */
#define NEXUS_TPM_SEED_STORE_VERSION 1

STATIC EFI_GUID mNexusTpmSeedGuid = {
	0x7E3A9C41, 0x5B62, 0x4D18,
	{ 0x9F, 0xA7, 0xC3, 0x64, 0x11, 0x8E, 0x2D, 0x50 }
};

/*
 * (!) THE NULL HIERARCHY SEED IS ABSENT FROM THIS STRUCT ON PURPOSE. Part 1: objects under
 * TPM_RH_NULL are usable only until the next TPM Reset, so its seed MUST be regenerated every
 * boot. Storing it would make null-hierarchy objects outlive a reset, which is the one thing
 * that hierarchy is defined not to do. Leaving it out of the structure means it cannot be stored
 * by accident later.
 */
#pragma pack(push, 1)
typedef struct _NEXUS_TPM_SEED_STORE {
	UINT64 Magic;
	UINT32 Version;
	UINT8  Storage[NEXUS_TPM_SEED_BYTES];
	UINT8  Endorsement[NEXUS_TPM_SEED_BYTES];
	UINT8  Platform[NEXUS_TPM_SEED_BYTES];
	UINT32 Crc;                 /* over every byte above; MUST be last */
} NEXUS_TPM_SEED_STORE;
#pragma pack(pop)

C_ASSERT(OFFSET_OF(NEXUS_TPM_SEED_STORE, Crc) ==
         sizeof(NEXUS_TPM_SEED_STORE) - sizeof(UINT32));

STATIC EFI_PHYSICAL_ADDRESS mStateBase = 0;
STATIC UINT32               mStateSize = 0;
STATIC BOOLEAN         mInstalled = FALSE;

//
// ---------------------------------------------------------------------------------------------
// GetCapability
// ---------------------------------------------------------------------------------------------
//

STATIC
EFI_STATUS
EFIAPI
Tcg2GetCapability(
	IN EFI_TCG2_PROTOCOL*                     This,
	IN OUT EFI_TCG2_BOOT_SERVICE_CAPABILITY*  Capability
	)
{
	//
	// ⚠ THE CALLER'S `Size` FIELD IS AN INPUT, AND IT IS LOAD-BEARING. The caller states how much
	// structure it allocated; we fill up to that and report the size actually required. A caller
	// built against an older, shorter structure must not have its stack written past.
	//
	UINT8 Requested;

	if (This == NULL || Capability == NULL)
		return EFI_INVALID_PARAMETER;

	Requested = Capability->Size;
	Capability->Size = (UINT8)sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY);

	if (Requested < sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY))
	{
		//
		// Specified behaviour: partially populate, set the required Size, return BUFFER_TOO_SMALL.
		// The one field a short caller can still act on is the structure version.
		//
		if (Requested >= OFFSET_OF(EFI_TCG2_BOOT_SERVICE_CAPABILITY, StructureVersion) +
		                 sizeof(EFI_TCG2_VERSION))
		{
			Capability->StructureVersion.Major = 1;
			Capability->StructureVersion.Minor = 1;
		}
		return EFI_BUFFER_TOO_SMALL;
	}

	Capability->StructureVersion.Major = 1;
	Capability->StructureVersion.Minor = 1;
	Capability->ProtocolVersion.Major  = 1;
	Capability->ProtocolVersion.Minor  = 1;

	//
	// One bank. Claiming SHA-1 as well would be the cheap way to look more compatible and would be
	// a lie: there is no SHA-1 implementation behind it, so any caller selecting that bank would
	// get digests we cannot produce.
	//
	Capability->HashAlgorithmBitmap = EFI_TCG2_BOOT_HASH_ALG_SHA256;
	Capability->ActivePcrBanks      = EFI_TCG2_BOOT_HASH_ALG_SHA256;
	Capability->NumberOfPCRBanks    = 1;

	//
	// Only the crypto-agile format. The log's first entry is 1.2-shaped so a 1.2 parser stops
	// cleanly, but that does not mean a 1.2 log EXISTS to hand out, and advertising one would
	// promise a GetEventLog answer we cannot give.
	//
	Capability->SupportedEventLogs = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;

	//
	// ⚠ TRUE, and this is the whole point of the experiment. The measured state is that the
	// firmware presents no TPM; this protocol IS the TPM from the loader's point of view, and it
	// answers HashLogExtendEvent for real.
	//
	Capability->TPMPresentFlag = TRUE;

	//
	// Sized from the CRB data buffer so the two interfaces cannot promise different limits for the
	// same TPM. 0x0F80 is the PTP maximum and what the CRB advertises.
	//
	Capability->MaxCommandSize  = (UINT16)CRB_DATA_BUFFER_SIZE;
	Capability->MaxResponseSize = (UINT16)CRB_DATA_BUFFER_SIZE;

	Capability->ManufacturerID = NEXUS_TCG2_MANUFACTURER;

	return EFI_SUCCESS;
}

//
// ---------------------------------------------------------------------------------------------
// GetEventLog
// ---------------------------------------------------------------------------------------------
//

STATIC
EFI_STATUS
EFIAPI
Tcg2GetEventLog(
	IN  EFI_TCG2_PROTOCOL*         This,
	IN  EFI_TCG2_EVENT_LOG_FORMAT  Format,
	OUT EFI_PHYSICAL_ADDRESS*      Location,
	OUT EFI_PHYSICAL_ADDRESS*      LastEntry,
	OUT BOOLEAN*                   Truncated
	)
{
	if (This == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// Refuse a format we do not keep. Handing back the agile log when asked for the 1.2 log would
	// be answered as though it were 1.2 and parsed into nonsense.
	//
	if (Format != EFI_TCG2_EVENT_LOG_FORMAT_TCG_2)
		return EFI_INVALID_PARAMETER;

	if (Location != NULL)
		*Location = (EFI_PHYSICAL_ADDRESS)(UINTN)mLog.Buffer;

	if (LastEntry != NULL)
	{
		//
		// ⚠ `Count` DECIDES THIS, NOT A ZERO OFFSET. The header event lives at offset 0, so an
		// offset of 0 is a perfectly ordinary answer once anything has been written; only an empty
		// log has no last entry.
		//
		*LastEntry = (mLog.Count == 0)
		             ? 0
		             : (EFI_PHYSICAL_ADDRESS)(UINTN)(mLog.Buffer + mLog.LastEntryOffset);
	}

	if (Truncated != NULL)
		*Truncated = mLog.Truncated;

	return EFI_SUCCESS;
}

/**
 * Mirror the PCR bank into region B and re-seal the header.
 *
 * ⚠ A MIRROR, DELIBERATELY, AND ONLY FOR NOW. The DXE static above is the working copy; this
 * copies it into the canonical region after every mutation. Two reasons it is not yet a pointer
 * straight into region B:
 *
 *   - region B may not exist (transport init is non-fatal), and a null bank pointer in
 *     HashLogExtendEvent would break the boot -- a failure mode this file has already produced
 *     once today.
 *   - while the DXE is the only writer the two copies are identical by construction, so the
 *     mirror is not a weaker claim, only a cheaper one.
 *
 * ⚠ WHEN THE POST-EBS SERVICER EXISTS THIS FLIPS: region B becomes authoritative and the DXE
 * static goes away. There will be no DXE running to disagree with it. Do not let the mirror
 * become the permanent arrangement by inertia.
 *
 * ⚠ CHECKSUM ORDER MATTERS. HeaderCrc covers PayloadChecksum, so the payload is summed FIRST
 * and the header sealed SECOND. Reversing it yields a header whose CRC certifies a stale
 * payload checksum -- which validates, and is wrong.
 */
/*
 * The seed provider handed to Tpm2Primary.
 *
 * (!) A HIERARCHY WE DO NOT HAVE A SEED FOR RETURNS FALSE, and TPM2_CreatePrimary then answers
 * TPM_RC_FAILURE. That is the whole contract: no seed, no key, never an invented one.
 */
STATIC
BOOLEAN
Tcg2SeedSource(
	IN  UINT32 Hierarchy,
	OUT UINT8* Seed,
	IN  UINT32 SeedLen
	)
{
	CONST UINT8* Src;

	if (Seed == NULL || SeedLen == 0 || SeedLen > NEXUS_TPM_SEED_BYTES)
		return FALSE;
	if (mSeeds.Magic != NEXUS_TPM_SEEDS_MAGIC)
		return FALSE;

	switch (Hierarchy)
	{
	case 0x40000001u: Src = mSeeds.Storage;     break;   /* TPM_RH_OWNER       */
	case 0x4000000Bu: Src = mSeeds.Endorsement; break;   /* TPM_RH_ENDORSEMENT */
	case 0x4000000Cu: Src = mSeeds.Platform;    break;   /* TPM_RH_PLATFORM    */
	case 0x40000007u: Src = mSeeds.Null;        break;   /* TPM_RH_NULL        */
	default:          return FALSE;
	}

	CopyMem(Seed, Src, SeedLen);
	return TRUE;
}

/*
 * Generate a fresh set of primary seeds.
 *
 * ⚠ FRESH EVERY BOOT, AND THAT IS THE KNOWN GAP RATHER THAN THE DESIGN. Spec §5 puts the
 * persistent copy in A/B slots on the ESP, owned by NexusCore, read by the DXE at boot. Until
 * that lands, TPM2_CreatePrimary SUCCEEDS and returns a DIFFERENT SRK on every boot -- which is
 * still exactly what Windows reports as event 519. Stated here so the next reader does not have
 * to deduce it from a log entry.
 *
 * ⚠ ALL-OR-NOTHING. A partial fill would be a seed with less entropy than it claims, and every
 * key derived from it would be weak with nothing anywhere saying so.
 */
/*
 * Read the seeds back. FALSE means "no usable stored copy", never a partial fill.
 */
STATIC
BOOLEAN
LoadSeeds(
	VOID
	)
{
	NEXUS_TPM_SEED_STORE Store;
	UINTN      Size = sizeof(Store);
	UINT32     Crc  = 0;
	EFI_STATUS Status;

	ZeroMem(&Store, sizeof(Store));
	Status = gRT->GetVariable(NEXUS_TPM_SEED_VAR_NAME, &mNexusTpmSeedGuid,
	                          NULL, &Size, &Store);

	//
	// (!) EVERY FIELD IS CHECKED BEFORE ANY SEED IS TRUSTED, and the size is checked EXACTLY
	// rather than as a minimum. A short variable would leave the tail of the struct as whatever
	// was on the stack, which is a seed with less entropy than it claims and no error anywhere.
	//
	if (EFI_ERROR(Status) || Size != sizeof(Store))
		return FALSE;
	if (Store.Magic != NEXUS_TPM_SEED_STORE_MAGIC ||
	    Store.Version != NEXUS_TPM_SEED_STORE_VERSION)
		return FALSE;

	if (EFI_ERROR(gBS->CalculateCrc32(&Store, OFFSET_OF(NEXUS_TPM_SEED_STORE, Crc), &Crc)))
		return FALSE;
	if (Crc != Store.Crc)
		return FALSE;

	ZeroMem(&mSeeds, sizeof(mSeeds));
	CopyMem(mSeeds.Storage,     Store.Storage,     NEXUS_TPM_SEED_BYTES);
	CopyMem(mSeeds.Endorsement, Store.Endorsement, NEXUS_TPM_SEED_BYTES);
	CopyMem(mSeeds.Platform,    Store.Platform,    NEXUS_TPM_SEED_BYTES);

	//
	// (!) THE NULL SEED IS GENERATED, NEVER LOADED. See the note on the store type: objects under
	// TPM_RH_NULL are defined to die at a TPM Reset, and a stored null seed would outlive one.
	//
	if (!Tpm2RdrandEntropy(mSeeds.Null, NEXUS_TPM_SEED_BYTES))
	{
		ZeroMem(&mSeeds, sizeof(mSeeds));
		return FALSE;
	}

	mSeeds.Magic = NEXUS_TPM_SEEDS_MAGIC;
	mSeeds.Flags = NEXUS_TPM_SEEDS_PERSISTED;
	ZeroMem(&Store, sizeof(Store));
	return TRUE;
}

/*
 * Write the three durable seeds. The null seed is never written.
 */
STATIC
BOOLEAN
SaveSeeds(
	VOID
	)
{
	NEXUS_TPM_SEED_STORE Store;
	EFI_STATUS Status;

	ZeroMem(&Store, sizeof(Store));
	Store.Magic   = NEXUS_TPM_SEED_STORE_MAGIC;
	Store.Version = NEXUS_TPM_SEED_STORE_VERSION;
	CopyMem(Store.Storage,     mSeeds.Storage,     NEXUS_TPM_SEED_BYTES);
	CopyMem(Store.Endorsement, mSeeds.Endorsement, NEXUS_TPM_SEED_BYTES);
	CopyMem(Store.Platform,    mSeeds.Platform,    NEXUS_TPM_SEED_BYTES);

	if (EFI_ERROR(gBS->CalculateCrc32(&Store, OFFSET_OF(NEXUS_TPM_SEED_STORE, Crc), &Store.Crc)))
		return FALSE;

	//
	// (!) NO EFI_VARIABLE_RUNTIME_ACCESS, AND THAT IS THE WHOLE POINT OF THE CHOICE. With only
	// BOOTSERVICE_ACCESS the variable cannot be read through runtime services once Windows is up,
	// so GetFirmwareEnvironmentVariable cannot reach it and neither can anything running as
	// administrator. Adding RUNTIME_ACCESS "so we can read it later" would hand the EK private key
	// to any elevated process on the machine.
	//
	Status = gRT->SetVariable(NEXUS_TPM_SEED_VAR_NAME, &mNexusTpmSeedGuid,
	                          EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
	                          sizeof(Store), &Store);

	ZeroMem(&Store, sizeof(Store));
	return (BOOLEAN)(!EFI_ERROR(Status));
}

STATIC
BOOLEAN
GenerateSeeds(
	VOID
	)
{
	ZeroMem(&mSeeds, sizeof(mSeeds));

	if (!Tpm2RdrandEntropy(mSeeds.Storage,     NEXUS_TPM_SEED_BYTES) ||
	    !Tpm2RdrandEntropy(mSeeds.Endorsement, NEXUS_TPM_SEED_BYTES) ||
	    !Tpm2RdrandEntropy(mSeeds.Platform,    NEXUS_TPM_SEED_BYTES) ||
	    !Tpm2RdrandEntropy(mSeeds.Null,        NEXUS_TPM_SEED_BYTES))
	{
		ZeroMem(&mSeeds, sizeof(mSeeds));
		return FALSE;
	}

	mSeeds.Magic = NEXUS_TPM_SEEDS_MAGIC;
	mSeeds.Flags = 0;          /* not persisted -- see the note above */
	return TRUE;
}

STATIC
VOID
SyncCanonicalState(
	VOID
	)
{
	NEXUS_TPM_STATE_HEADER* H;
	UINT8*                  Payload;

	if (mStateBase == 0 || mStateSize == 0)
		return;

	H = (NEXUS_TPM_STATE_HEADER*)(UINTN)mStateBase;

	//
	// Refuse to touch a region that is not ours. The header was written by the transport this
	// same boot, so a mismatch means something overwrote it -- and blindly re-sealing would
	// launder the damage into a structure that passes validation.
	//
	if (H->Magic != NEXUS_TPM_STATE_MAGIC || H->HeaderSize != sizeof(NEXUS_TPM_STATE_HEADER))
		return;

	if (H->HeaderSize + sizeof(TPM2_PCR_BANK) + sizeof(NEXUS_TPM_EXTEND_STATS) +
	    sizeof(NEXUS_TPM_SEEDS) > mStateSize)
		return;                       // cannot fit; leave PayloadLength at 0, honestly empty

	Payload = (UINT8*)(UINTN)mStateBase + H->HeaderSize;
	CopyMem(Payload, &mBank, sizeof(TPM2_PCR_BANK));
	CopyMem(Payload + sizeof(TPM2_PCR_BANK), &mStats, sizeof(NEXUS_TPM_EXTEND_STATS));
	//
	// (!) THE SEEDS GO INTO REGION B AND NOWHERE ELSE. This is how NexusCore receives them
	// after ExitBootServices, and the boot block is deliberately not used: it is served to
	// usermode through the hooked GetVariable status report, which would hand the EK private
	// key to any caller that asked for a status line.
	//
	CopyMem(Payload + sizeof(TPM2_PCR_BANK) + sizeof(NEXUS_TPM_EXTEND_STATS),
	        &mSeeds, sizeof(NEXUS_TPM_SEEDS));

	H->Version       = NEXUS_TPM_STATE_VERSION;
	H->PayloadLength = (UINT32)(sizeof(TPM2_PCR_BANK) + sizeof(NEXUS_TPM_EXTEND_STATS) +
	                            sizeof(NEXUS_TPM_SEEDS));

	if (EFI_ERROR(gBS->CalculateCrc32(Payload, H->PayloadLength, &H->PayloadChecksum)))
	{
		//
		// Cannot sum it -- so do not claim it. A payload advertised with a wrong checksum is worse
		// than no payload: a reader would reject the whole region rather than read a shorter one.
		//
		H->PayloadLength   = 0;
		H->PayloadChecksum = 0;
	}

	(VOID)gBS->CalculateCrc32(H, OFFSET_OF(NEXUS_TPM_STATE_HEADER, HeaderCrc), &H->HeaderCrc);
}

//
// ---------------------------------------------------------------------------------------------
// HashLogExtendEvent -- the function the boot loader actually calls to measure things
// ---------------------------------------------------------------------------------------------
//

STATIC
EFI_STATUS
EFIAPI
Tcg2HashLogExtendEvent(
	IN EFI_TCG2_PROTOCOL*    This,
	IN UINT64                Flags,
	IN EFI_PHYSICAL_ADDRESS  DataToHash,
	IN UINT64                DataToHashLen,
	IN EFI_TCG2_EVENT*       Event
	)
{
	UINT32       Rc;
	UINT32       EventDataLen;
	CONST UINT8* EventData;

	if (This == NULL || Event == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// Validate the caller's own header before trusting any length in it.
	//
	if (Event->Header.HeaderSize != sizeof(EFI_TCG2_EVENT_HEADER) ||
	    Event->Header.HeaderVersion != EFI_TCG2_EVENT_HEADER_VERSION)
		return EFI_INVALID_PARAMETER;

	if (Event->Size < sizeof(UINT32) + sizeof(EFI_TCG2_EVENT_HEADER))
		return EFI_INVALID_PARAMETER;

	if (Event->Header.PCRIndex > MAX_PCR_INDEX)
		return EFI_INVALID_PARAMETER;

	if (DataToHash == 0 && DataToHashLen != 0)
		return EFI_INVALID_PARAMETER;

	//
	// The event blob follows the header inside the caller\'s structure. Its length is whatever the
	// caller\'s declared total leaves over -- derived, never assumed.
	//
	// (!) DERIVED HERE, BEFORE ANY BRANCH CAN USE IT, and that placement is the fix for a real bug.
	// These two were assigned AFTER the PE_COFF_IMAGE block below, which reads them -- so every
	// PE/COFF measurement passed two UNINITIALISED stack values to the log writer. The visible
	// symptom was an EV_EFI_BOOT_SERVICES_APPLICATION entry logged with eventsize 0, after which
	// the log could not be parsed at all; the invisible one is that a garbage POINTER or a garbage
	// LENGTH was equally available and would have faulted or scribbled the log instead.
	//
	// The Event->Size check above is what makes this subtraction safe, so this is the earliest
	// correct point -- not merely an earlier one.
	//
	EventDataLen = Event->Size - (UINT32)(sizeof(UINT32) + sizeof(EFI_TCG2_EVENT_HEADER));
	EventData    = (CONST UINT8*)Event->Event;

	//
	// =========================================================================================
	// ⚠ THIS FUNCTION MUST NEVER RETURN A STATUS THAT BLOCKS LoadImage. IT DID ONCE.
	// =========================================================================================
	//
	// PE_COFF_IMAGE was refused with EFI_UNSUPPORTED, on the reasoning that PFP
	// section hashing is a real algorithm and a wrong digest would be worse than none. The
	// reasoning was right. The consequence was that NOTHING BOOTED:
	//
	//     [LOADER] Booting Boot0005: Windows Boot Manager
	//     [LOADER] LoadImage failed: 8000000000000003 (Unsupported)
	//     ... every boot option in turn ...
	//     Failed to boot anything. This is super bad!
	//
	// 0x8000000000000003 is EFI_UNSUPPORTED -- our own return value, handed back through
	// LoadImage. Once TCG2 is advertised the platform measures EVERY image before loading it and
	// treats a measurement failure as an authentication failure. EDK2 forgives exactly one
	// status, and it is not this one:
	//
	//     if (Status == EFI_VOLUME_FULL) {
	//       // Just return EFI_SUCCESS in order not to block the image load.
	//       Status = EFI_SUCCESS;
	//     }
	//     return Status;
	//
	// So: advertising TCG2 makes PE/COFF measurement MANDATORY. The invariant below is not a
	// nicety -- it is the difference between a machine that boots and one that does not.
	//
	if ((Flags & PE_COFF_IMAGE) != 0)
	{
		UINT8 PeDigest[TPM2_SHA256_DIGEST_SIZE];

		if (Tpm2HashPeImage((CONST UINT8*)(UINTN)DataToHash, DataToHashLen, PeDigest))
		{
			//
			// The Authenticode digest -- what every other measurement agent would compute for
			// this same file, so our PCR[4] is comparable with the rest of the world.
			//
			Rc = Tpm2EventLogExtendDigest(&mLog, &mBank,
			                              Event->Header.PCRIndex, Event->Header.EventType,
			                              PeDigest, EventData, EventDataLen);
		}
		else
		{
			//
			// ⚠ FALLBACK, AND IT IS A MEASUREMENT RATHER THAN A PRETENCE.
			//
			// The image did not parse as PE/COFF -- a header we do not understand, or one whose
			// fields contradict the buffer. Hashing the bytes we were handed still records what was
			// loaded, still extends a PCR, and still replays from the log. It is NOT the
			// Authenticode digest and will not match anyone else's measurement of the same file,
			// which is a real limitation and is why it is not the primary path.
			//
			// What it is not is a lie: something was measured, and the log says what.
			//
			Rc = Tpm2EventLogExtend(&mLog, &mBank,
			                        Event->Header.PCRIndex, Event->Header.EventType,
			                        (CONST UINT8*)(UINTN)DataToHash, (UINT32)DataToHashLen,
			                        EventData, EventDataLen, NULL);
		}

		//
		// ⚠ THE INVARIANT. Whatever went wrong above, the image loads.
		//
		// EFI_VOLUME_FULL is the ONE error the platform translates to success, and it means
		// exactly what happened if the log filled: the PCR moved, the entry did not fit. Anything
		// else would stop the boot, and a TPM that cannot be measured into is not worth a machine
		// that cannot start.
		//
		// ⚠ Rc is deliberately NOT propagated. Do not "improve" this into returning it.
		//
		(VOID)Rc;
		if (Rc == TPM2_RC_SUCCESS) mStats.LoggedExtends++;
		SyncCanonicalState();
		return mLog.Truncated ? EFI_VOLUME_FULL : EFI_SUCCESS;
	}


	if ((Flags & EFI_TCG2_EXTEND_ONLY) != 0)
	{
		//
		// Extend without logging. The digest is still computed from the data, so the PCR moves for
		// the right reason -- EXTEND_ONLY means "do not log", not "do not hash".
		//
		SHA256_CONTEXT Ctx;
		UINT8          Digest[TPM2_SHA256_DIGEST_SIZE];

		Sha256Init(&Ctx);
		if (DataToHashLen != 0)
			Sha256Update(&Ctx, (CONST VOID*)(UINTN)DataToHash, (UINTN)DataToHashLen);
		Sha256Final(&Ctx, Digest);

		Rc = Tpm2PcrExtend(&mBank, Event->Header.PCRIndex, Digest);
		if (Rc == TPM2_RC_SUCCESS) mStats.ExtendOnlyExtends++;
		SyncCanonicalState();
		return (Rc == TPM2_RC_SUCCESS) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
	}

	Rc = Tpm2EventLogExtend(&mLog, &mBank,
	                        Event->Header.PCRIndex,
	                        Event->Header.EventType,
	                        (CONST UINT8*)(UINTN)DataToHash, (UINT32)DataToHashLen,
	                        EventData, EventDataLen,
	                        NULL);
	if (Rc == TPM2_RC_SUCCESS) mStats.LoggedExtends++;
	SyncCanonicalState();

	//
	// ⚠ An extend failure here reaches the caller as EFI_DEVICE_ERROR, which for the GPT
	// measurement path is ignored (EDK2 only counts successes) -- but a future caller might
	// treat it as fatal. It is kept as a real error because, unlike the PE path above, there is
	// no platform behaviour that turns this into a boot failure today, and silently reporting
	// success for a measurement that did not happen would be the worse trade.
	//
	if (Rc != TPM2_RC_SUCCESS)
		return EFI_DEVICE_ERROR;

	//
	// ⚠ THE EXTEND HAPPENED; ONLY THE LOG ENTRY DID NOT. EFI_VOLUME_FULL is the specified way to
	// say that, and it is NOT an error the caller should retry -- retrying would extend the PCR a
	// second time for the same measurement.
	//
	if (mLog.Truncated)
		return EFI_VOLUME_FULL;

	return EFI_SUCCESS;
}

//
// ---------------------------------------------------------------------------------------------
// SubmitCommand -- raw TPM command passthrough
// ---------------------------------------------------------------------------------------------
//


STATIC
EFI_STATUS
EFIAPI
Tcg2SubmitCommand(
	IN EFI_TCG2_PROTOCOL* This,
	IN UINT32             InputSize,
	IN UINT8*             Input,
	IN UINT32             OutputSize,
	IN UINT8*             Output
	)
{
	TPM2_DISPATCH_INFO Info;
	UINT32             Written;

	if (This == NULL || Input == NULL || Output == NULL)
		return EFI_INVALID_PARAMETER;
	if (OutputSize < TPM2_HEADER_SIZE)
		return EFI_BUFFER_TOO_SMALL;

	//
	// ⚠ ONE DISPATCHER, SHARED WITH THE KERNEL-SIDE CRB SERVICER. This function used to contain
	// the command switch itself. G1 needs the same logic running after ExitBootServices, and two
	// copies of a TPM command dispatcher is how a TPM starts answering one thing to the boot
	// loader and another to the OS -- a contradiction no real TPM can produce, and exactly the
	// kind a verifier looks for.
	//
	Written = Tpm2Dispatch(&mBank, Input, InputSize, Output, OutputSize, &Info);
	if (Written == 0)
		return EFI_BUFFER_TOO_SMALL;

	//
	// Sync unconditionally rather than only for commands known to mutate the bank. It costs a
	// 776-byte copy and a CRC, and the alternative is a list that has to be kept in step with the
	// dispatcher forever -- the first command added without updating it would silently publish
	// stale canonical state.
	//
	SyncCanonicalState();

	//
	// EFI_SUCCESS even when the TPM refused: the RESPONSE carries the refusal, and that is the
	// distinction between "the TPM said no" and "the transport broke". A caller that cannot tell
	// those apart misdiagnoses every failure.
	//
	return EFI_SUCCESS;
}

//
// ---------------------------------------------------------------------------------------------
// PCR bank selection
// ---------------------------------------------------------------------------------------------
//

STATIC
EFI_STATUS
EFIAPI
Tcg2GetActivePcrBanks(
	IN  EFI_TCG2_PROTOCOL* This,
	OUT UINT32*            ActivePcrBanks
	)
{
	if (This == NULL || ActivePcrBanks == NULL)
		return EFI_INVALID_PARAMETER;

	*ActivePcrBanks = EFI_TCG2_BOOT_HASH_ALG_SHA256;
	return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
Tcg2SetActivePcrBanks(
	IN EFI_TCG2_PROTOCOL* This,
	IN UINT32             ActivePcrBanks
	)
{
	if (This == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// ⚠ ACCEPTED ONLY IF IT ASKS FOR EXACTLY WHAT WE HAVE.
	//
	// The protocol says EFI_SUCCESS means "the bitmap is already active". Accepting a request for
	// SHA-384 and then continuing to produce SHA-256 digests would give a caller a log it cannot
	// verify, with no error anywhere to explain it.
	//
	if (ActivePcrBanks != EFI_TCG2_BOOT_HASH_ALG_SHA256)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
Tcg2GetResultOfSetActivePcrBanks(
	IN  EFI_TCG2_PROTOCOL* This,
	OUT UINT32*            OperationPresent,
	OUT UINT32*            Response
	)
{
	if (This == NULL || OperationPresent == NULL || Response == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// No bank change is ever pending: a change would need a reboot to take effect, and we have
	// exactly one bank to change to.
	//
	*OperationPresent = 0;
	*Response         = 0;
	return EFI_SUCCESS;
}

STATIC EFI_TCG2_PROTOCOL mTcg2Protocol = {
	Tcg2GetCapability,
	Tcg2GetEventLog,
	Tcg2HashLogExtendEvent,
	Tcg2SubmitCommand,
	Tcg2GetActivePcrBanks,
	Tcg2SetActivePcrBanks,
	Tcg2GetResultOfSetActivePcrBanks
};

//
// ---------------------------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------------------------
//

EFI_STATUS
NexusTcg2Install(
	IN EFI_PHYSICAL_ADDRESS StateBase,
	IN UINT32               StateSize
	)
{
	EFI_STATUS            Status;
	EFI_PHYSICAL_ADDRESS  LogBase = 0;
	VOID*                 Existing = NULL;

	if (mInstalled)
		return EFI_ALREADY_STARTED;

	//
	// ⚠ STAND DOWN IF THE FIRMWARE ALREADY HAS ONE.
	//
	// Two TCG2 protocols means two PCR banks, both being extended by different callers, neither
	// matching the log the other keeps. Measured on this machine the firmware publishes none --
	// that is the entire reason this file exists -- but PTT could be re-enabled in the BIOS at any
	// time, and then the right behaviour is to get out of the way rather than compete.
	//
	Status = gBS->LocateProtocol(&mTcg2ProtocolGuid, NULL, &Existing);
	if (!EFI_ERROR(Status) && Existing != NULL)
	{
		Print(L"[TCG2] firmware already publishes EFI_TCG2_PROTOCOL -- standing down\r\n");
		return EFI_ALREADY_STARTED;
	}

	//
	// EfiACPIMemoryNVS + AllocateAnyPages, for the same reasons as the transport regions: the OS
	// must PRESERVE the log rather than reclaim it, and UEFI 2.10/2.11 §7.2 forbids a driver
	// allocating EfiReservedMemoryType and requires AllocateAnyPages for runtime types.
	//
	Status = gBS->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS,
	                            NEXUS_TCG2_LOG_PAGES, &LogBase);
	if (EFI_ERROR(Status))
	{
		Print(L"[TCG2] event log allocation FAILED: %r\r\n", Status);
		return Status;
	}

	mStateBase = StateBase;
	mStateSize = StateSize;

	//
	// Install the entropy source before any command can be dispatched (DXE: boot-time commands arrive through EFI_TCG2_PROTOCOL.SubmitCommand).
	// Without it TPM2_GetRandom answers TPM_RC_FAILURE rather than fabricating bytes.
	//
	Tpm2SetEntropySource(Tpm2RdrandEntropy);

	//
	// (!) THE SEEDS ARE GENERATED HERE AND PUBLISHED BY SyncCanonicalState. Without them
	// TPM2_CreatePrimary answers TPM_RC_FAILURE -- honestly, but it answers nothing useful,
	// and the command is advertised in TPM_CAP_COMMANDS.
	//
	// (!) A FAILURE HERE IS REPORTED AND NOT FATAL. RDRAND can be absent or wedged; the rest
	// of the TPM still works, and CreatePrimary then refuses for a reason the log names
	// rather than one anyone has to guess at.
	//
	//
	// (!) LOAD FIRST, GENERATE ONLY IF THERE IS NOTHING TO LOAD. This ordering is the whole fix
	// for Windows event 519, "The TPM has been cleared. Reason: SRK has changed": the SRK is a
	// deterministic function of the storage seed, so a seed that survives the reboot makes an SRK
	// that survives it too. Generating first and loading as a fallback would rewrite NVRAM every
	// boot and defeat both halves of that.
	//
	if (LoadSeeds())
	{
		Tpm2SetSeedSource(Tcg2SeedSource);
		Tpm2ObjectStoreReset();
		Print(L"[TCG2] primary seeds RESTORED from NVRAM\r\n");
	}
	else if (GenerateSeeds())
	{
		Tpm2SetSeedSource(Tcg2SeedSource);
		Tpm2ObjectStoreReset();
		//
		// (!) A FAILED SAVE IS REPORTED AND NOT FATAL. The TPM works for this boot either way; what
		// differs is whether the SRK survives the next one. Saying which case we are in beats a
		// silent success that looks identical and is not.
		//
		if (SaveSeeds())
		{
			mSeeds.Flags |= NEXUS_TPM_SEEDS_PERSISTED;
			Print(L"[TCG2] primary seeds GENERATED and saved to NVRAM\r\n");
		}
		else
		{
			Print(L"[TCG2] primary seeds generated but NOT SAVED;"
			      L" the SRK will change next boot\r\n");
		}
	}
	else
	{
		Print(L"[TCG2] primary seeds NOT generated (RDRAND unavailable);"
		      L" CreatePrimary will refuse\r\n");
	}

	//
	// (!) NO CLOCK IS INSTALLED HERE, DELIBERATELY. TPM2_ReadClock therefore answers
	// TPM_RC_FAILURE for the whole of the boot phase, which is correct rather than unfortunate:
	// DXE has no monotonic millisecond counter we can reach without taking a dependency the
	// dispatcher is built to avoid, and Clock feeds signed attestation structures where a
	// plausible invented value is worse than an honest refusal.
	//
	// Nothing asks for it at boot in any case -- the CRB trace shows tpm.sys sending ReadClock
	// after ExitBootServices, where NexusCore installs a real one on KeQueryPerformanceCounter.
	//

	Tpm2PcrStartupClear(&mBank, 0);

	//
	// Publish the startup state immediately, so region B describes a real TPM from the first
	// moment rather than only after something happens to be measured. PTP Table 15 initial values
	// are a MEASUREMENT -- PCR[0] carries the locality indicator, 17-22 are 0xFF -- and a reader
	// that finds an all-zero bank cannot tell "freshly started" from "never written".
	//
	SyncCanonicalState();

	if (!Tpm2EventLogInit(&mLog, (UINT8*)(UINTN)LogBase,
	                      (UINT32)EFI_PAGES_TO_SIZE(NEXUS_TCG2_LOG_PAGES)))
	{
		Print(L"[TCG2] event log init FAILED\r\n");
		gBS->FreePages(LogBase, NEXUS_TCG2_LOG_PAGES);
		return EFI_DEVICE_ERROR;
	}

	Status = gBS->InstallProtocolInterface(&mHandle, &mTcg2ProtocolGuid,
	                                       EFI_NATIVE_INTERFACE, &mTcg2Protocol);
	if (EFI_ERROR(Status))
	{
		Print(L"[TCG2] InstallProtocolInterface FAILED: %r\r\n", Status);
		gBS->FreePages(LogBase, NEXUS_TCG2_LOG_PAGES);
		return Status;
	}

	mInstalled = TRUE;

	Print(L"\r\n[TCG2] ========= EFI_TCG2_PROTOCOL installed =========\r\n");
	Print(L"[TCG2] handle             : 0x%p\r\n", mHandle);
	Print(L"[TCG2] event log          : 0x%016llx  (%u KB, NVS)\r\n",
	      (UINT64)LogBase, (UINT32)EFI_PAGES_TO_SIZE(NEXUS_TCG2_LOG_PAGES) / 1024);
	Print(L"[TCG2] header event       : %u bytes, %u entr%s\r\n",
	      mLog.Used, mLog.Count, mLog.Count == 1 ? L"y" : L"ies");
	Print(L"[TCG2] banks              : SHA-256 only\r\n");
	Print(L"[TCG2] TPMPresentFlag     : TRUE\r\n");
	Print(L"[TCG2] manufacturer       : INTC\r\n");
	Print(L"[TCG2] --\r\n");
	Print(L"[TCG2] the boot loader can now measure. Whether Windows ACTS on that is\r\n");
	Print(L"[TCG2] the open question this build exists to answer.\r\n");
	Print(L"[TCG2] ==============================================\r\n\r\n");

	return EFI_SUCCESS;
}

UINT32
NexusTcg2LogSize(
	VOID
	)
{
	//
	// (!) ZERO WHEN NOT INSTALLED, deliberately. The boot block pairs this with a base of 0, and a
	// non-zero size beside a zero base would describe a region at physical 0 -- which the readphys
	// whitelist would then have to reason about. Both zero is the single unambiguous "no log".
	//
	return mInstalled ? (UINT32)EFI_PAGES_TO_SIZE(NEXUS_TCG2_LOG_PAGES) : 0;
}

VOID
NexusTcg2GetState(
	OUT UINT64* OutLogBase,
	OUT UINT32* OutLogUsed,
	OUT UINT32* OutEvents
	)
{
	if (OutLogBase != NULL)
		*OutLogBase = mInstalled ? (UINT64)(UINTN)mLog.Buffer : 0;
	if (OutLogUsed != NULL)
		*OutLogUsed = mInstalled ? mLog.Used : 0;
	if (OutEvents != NULL)
		*OutEvents = mInstalled ? mLog.Count : 0;
}
