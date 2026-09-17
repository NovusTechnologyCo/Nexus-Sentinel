/**
 * @file TpmState.h
 * @brief Canonical TPM state (region B) and the ExitBootServices handoff contract.
 *
 * PHASE 1 ARTIFACT. `the design notes` §3.3.
 *
 * TWO DOMAINS, TWO REGIONS — and they must not be merged.
 *
 *   Region A   SHARED TRANSPORT   the CRB locality: control area + data buffer.
 *                                 ACPI-described. Host software reads and writes it freely.
 *   Region B   CANONICAL STATE    EPS, NV, hierarchies, objects, PCRs, and the internal
 *                                 register snapshot. NOT ACPI-described, so nothing looks for it.
 *
 * ⚠ THE SPLIT IS AN INTERFACE-CORRECTNESS BOUNDARY, NOT A SECURITY BOUNDARY. Ring 0 reads both
 * either way (spec §7.1). The reason they are separate is that PTP §6.5.3.2(2) observes shared
 * memory cannot enforce register semantics — software may write a read-only register or several
 * registers at what looks to us like one instant — and the remedy is an internal snapshot the host
 * cannot reach. That snapshot is unimplementable if it lives in the region the host can scribble on.
 *
 * ⚠ WHY REGION B EXISTS AT ALL, rather than the DXE just keeping state in boot-services memory:
 * it would not survive. Everything the DXE measured — bootmgr, winload — would vanish at exactly
 * the moment the OS starts asking. Both regions are EfiACPIMemoryNVS, allocated with
 * AllocateAnyPages (UEFI 2.10/2.11 §7.2 forbids a driver allocating EfiReservedMemoryType, and
 * requires AllocateAnyPages for runtime types).
 */

#ifndef NEXUS_TPM_STATE_H
#define NEXUS_TPM_STATE_H

#include <Uefi.h>
#include "RamCrb.h"
//
// (!) FOR TPM2_PCR_BANK, WHICH THE VERSION-4 SIZE ASSERT BELOW NEEDS. This header describes the
// region-B payload, and the bank is part of that payload -- so the dependency was always there,
// it was just satisfied by whoever happened to include both. An assert that depends on include
// order is an assert that disappears the first time someone reorders includes.
//
#include "Tpm2Core.h"

#define NEXUS_TPM_STATE_MAGIC        SIGNATURE_64('N','X','T','P','M','S','T','1')
#define NEXUS_TPM_STATE_VERSION      4

/*
 * ============================================================================================
 * VERSION 2 -- THE PAYLOAD IS THE PCR BANK.
 * ============================================================================================
 *
 * Version 1 defined a header and an empty payload; the transport wrote PayloadLength = 0 with
 * the note "no TPM core yet -- Phase 2". Version 2 defines the payload:
 *
 *     region B + 0                 NEXUS_TPM_STATE_HEADER
 *     region B + HeaderSize        TPM2_PCR_BANK
 *     ... + sizeof(TPM2_PCR_BANK)  NEXUS_TPM_EXTEND_STATS       (version 3)
 *     ... + sizeof(EXTEND_STATS)   NEXUS_TPM_SEEDS              (version 4)
 *
 * PayloadLength covers BOTH, and PayloadChecksum is computed over the whole payload.
 *
 * (!) PayloadLength IS THE PRESENCE FLAG, not the version. Version 2 says "if PayloadLength is
 * non-zero then the payload is a TPM2_PCR_BANK at HeaderSize" -- because the transport is
 * initialised before we know whether TCG2 will install at all. If the firmware already
 * publishes TCG2 we stand down and never write a bank, and a reader must be able to tell that
 * from a version number that was already committed.
 *
 * (!) PayloadChecksum is CRC32 over exactly PayloadLength bytes, and HeaderCrc is recomputed
 * with it -- HeaderCrc covers PayloadChecksum, so the two always move together. Both are
 * refreshed after every PCR mutation, not only at handoff: a reader that catches the region
 * mid-boot must see a self-consistent structure or a detectably broken one, never a stale
 * checksum over fresh data.
 */

/**
 * ⚠ THE BOOT-EPOCH INVARIANT (spec §3.3).
 *
 * The physical addresses of regions A and B are valid ONLY for the boot epoch in which the DXE
 * allocated them. After S4, Fast Startup, or any other firmware reinitialisation, the firmware
 * runs again and allocates FRESH regions — while a resumed kernel may still hold an address from
 * the previous epoch.
 *
 * ⚠ THE HAZARD IS A STALE POINTER THAT STILL LOOKS VALID, not stale contents. An address from the
 * last boot may point at perfectly readable memory that is now something else entirely. A checksum
 * over the wrong buffer fails; a checksum over a *plausible* wrong buffer is the nightmare.
 *
 * So the epoch is generated fresh every boot and stored in BOTH the state header and whatever
 * channel the driver uses for discovery. NexusTpmCore compares them and REDISCOVERS on mismatch.
 * It must never trust an address recovered from its own saved driver state.
 *
 * ⚠ Windows Fast Startup (hiberboot) is a hybrid S4 and is ON BY DEFAULT, so this is the common
 * case, not an edge case. Phase 1 runs cold-boot-only with it disabled — a stated limitation, and
 * gate criterion 8 closes it.
 */
typedef struct _NEXUS_TPM_BOOT_EPOCH {
	UINT64  Value;            // fresh per boot; 0 is never valid
	UINT64  TimestampTsc;     // TSC at generation -- diagnostic only, never an identity
} NEXUS_TPM_BOOT_EPOCH;

/**
 * Region B header. Everything before `Payload` is covered by `HeaderCrc`; the payload has its own
 * checksum. Two integrity checks, because they answer different questions
 * (`the design notes` §5): a payload checksum says nothing about the version or length
 * bytes that decide how the payload is READ.
 */
#pragma pack(push, 1)
typedef struct _NEXUS_TPM_STATE_HEADER {
	UINT64                Magic;            // NEXUS_TPM_STATE_MAGIC
	UINT32                Version;          // NEXUS_TPM_STATE_VERSION; refuse what we do not know
	UINT32                HeaderSize;       // sizeof(NEXUS_TPM_STATE_HEADER)
	NEXUS_TPM_BOOT_EPOCH  Epoch;            // see the invariant above
	UINT64                TransportPhys;    // region A physical base (the LOCALITY base, not +0x40)
	UINT64                TransportSize;
	UINT64                StatePhys;        // region B physical base -- self-reference, for
	                                        // detecting a copy that was moved
	UINT64                StateSize;
	UINT32                PayloadLength;
	UINT32                PayloadChecksum;
	UINT32                HeaderCrc;        // over every byte above; MUST be last in the header
	UINT32                Reserved;
} NEXUS_TPM_STATE_HEADER;
/*
 * ============================================================================================
 * VERSION 3 -- HOW THE PCRs GOT WHERE THEY ARE.
 * ============================================================================================
 *
 * (!) THE EVENT LOG IS NOT A COMPLETE HISTORY, BY DESIGN. `EFI_TCG2_EXTEND_ONLY` means "extend
 * but do not log", and Windows uses it -- measured: PCRs 11 through 14 moved with
 * nothing in our log to explain them, because Windows records those in its own WBCL instead.
 * So a replay of the log reproduces SOME PCRs and cannot reproduce others, and that is correct
 * behaviour rather than a defect.
 *
 * (!) WHICH MAKES THE COUNTS NECESSARY. Without them, "the log does not explain PCR 11" is
 * indistinguishable from "something extended PCR 11 that we do not know about". With them there
 * is an identity to check:
 *
 *     Bank.UpdateCounter == LoggedExtends + ExtendOnlyExtends
 *
 * and any drift means a fourth extend path exists that nobody has noticed. That is a much
 * stronger statement than an argument from elimination, which is what it replaces.
 */
typedef struct _NEXUS_TPM_EXTEND_STATS {
	UINT32  LoggedExtends;       // extends that also produced an event log entry
	UINT32  ExtendOnlyExtends;   // EFI_TCG2_EXTEND_ONLY -- extended, deliberately not logged
	UINT32  Reserved0;
	UINT32  Reserved1;
} NEXUS_TPM_EXTEND_STATS;

/*
 * ============================================================================================
 * VERSION 4 -- THE PRIMARY SEEDS.
 * ============================================================================================
 *
 * Part 1 §24.6.3: a primary key is derived from a hierarchy seed, and the SAME seed must give
 * the SAME key every time or the object is not reproducible. Without these, TPM2_CreatePrimary
 * has nothing to derive from and answers TPM_RC_FAILURE -- and with a FRESH set every boot it
 * succeeds while the SRK changes, which is what Windows reports as event 519.
 *
 * ⚠ THESE ARE THE SRK AND EK PRIVATE KEYS, IN EVERYTHING BUT NAME. Whoever holds the Storage
 * and Endorsement seeds can recompute both keys exactly. Stated plainly because the placement
 * has a consequence that must not be discovered later:
 *
 * ⚠ REGION B IS ORDINARY PHYSICAL MEMORY (EfiACPIMemoryNVS), so anything that can read
 * physical memory can read these -- kernel code, and this project's own `readphys`. A hardware
 * TPM keeps its seeds inside the chip and this cannot. That is the software-TPM threat model the
 * spec already states in G3, not a defect introduced here, and it is the reason a seed must never
 * be copied into the boot block: the boot block is SERVED TO USERMODE through the hooked
 * GetVariable status report, and that would hand the EK private key to any caller.
 *
 * ⚠ THE NULL HIERARCHY'S SEED IS *SUPPOSED* TO BE FRESH EVERY BOOT. Part 1: objects under
 * TPM_RH_NULL are usable only until the next TPM Reset. Regenerating it is correct behaviour for
 * that one and a bug for the other three.
 */
#define NEXUS_TPM_SEEDS_MAGIC        0x53444545534D5054ull   /* "TPMSEEDS" */
#define NEXUS_TPM_SEED_BYTES         32

/*
 * Bit 0: these seeds ARE IN DURABLE STORAGE — either loaded from it this boot, or generated and
 * successfully written to it this boot.
 *
 * ⚠ IT DELIBERATELY DOES NOT DISTINGUISH THOSE TWO, because for every consumer the useful question
 * is the same one: will the SRK be the same next boot? Both cases answer yes. The DXE console line
 * says which of the two happened, for a human reading a boot; the flag is for code, and code only
 * cares about the guarantee.
 *
 * CLEAR means the seeds are good for this boot and will not survive it — which is honest and still
 * produces a working TPM, just one whose SRK changes and whose event 519 keeps firing.
 */
#define NEXUS_TPM_SEEDS_PERSISTED    0x00000001u

typedef struct _NEXUS_TPM_SEEDS {
	UINT64  Magic;
	UINT32  Flags;
	UINT32  Reserved;
	UINT8   Storage[NEXUS_TPM_SEED_BYTES];        /* SPS -- TPM_RH_OWNER       */
	UINT8   Endorsement[NEXUS_TPM_SEED_BYTES];    /* EPS -- TPM_RH_ENDORSEMENT */
	UINT8   Platform[NEXUS_TPM_SEED_BYTES];       /* PPS -- TPM_RH_PLATFORM    */
	UINT8   Null[NEXUS_TPM_SEED_BYTES];           /* fresh every reset, by design */
} NEXUS_TPM_SEEDS;

#pragma pack(pop)

//
// HeaderCrc must be the final field before Reserved, or "everything above me" stops being a
// meaningful definition and the CRC silently covers less than it claims.
//
C_ASSERT(OFFSET_OF(NEXUS_TPM_STATE_HEADER, HeaderCrc) ==
         sizeof(NEXUS_TPM_STATE_HEADER) - 2 * sizeof(UINT32));

//
// The whole version-4 payload must fit the FIRST PAGE of region B, because the CRB trace begins
// at 0x1000 and would be overwritten. 4096 is written literally rather than pulled from the
// driver's TpmCrb.h: this header is compiled by the DXE, the driver and the host harness, and
// only one of the three can see that file. The number is the contract; the assert is here so
// growing the payload fails at compile time rather than by corrupting a ring at runtime.
//
C_ASSERT(sizeof(NEXUS_TPM_STATE_HEADER) + sizeof(TPM2_PCR_BANK) +
         sizeof(NEXUS_TPM_EXTEND_STATS) + sizeof(NEXUS_TPM_SEEDS) <= 4096);

/**
 * ⚠ "READY FOR THE FIRST POST-EBS COMMAND" — the handoff condition, spec §3.3.
 *
 * Defined as: region B validates (magic, version, header CRC, payload length in bounds, payload
 * checksum) AND the transport surface has been reconciled against it. Until both hold, the CRB
 * must present a state that makes `tpm.sys` RETRY rather than FAIL.
 *
 * ⚠ Transport can signal perfectly and still fail if the state needed to answer did not survive.
 * That is why this is part of G1 and not a detail.
 */
typedef enum _NEXUS_TPM_HANDOFF_STATE {
	NexusTpmHandoffInvalid = 0,      // nothing validated; never report ready
	NexusTpmHandoffStateOk,          // region B validated
	NexusTpmHandoffReconciled,       // transport reconciled against region B
	NexusTpmHandoffReady             // both -- and only now may a command be answered
} NEXUS_TPM_HANDOFF_STATE;

/**
 * What the DXE leaves in the CRB at ExitBootServices. Spec §3.4: these bytes are a CONTRACT, not
 * a leftover.
 *
 * ⚠ MUST present Idle with NO COMMAND IN FLIGHT. A stuck Start bit is read by a first post-EBS
 * probe as a busy TPM that never answers — indistinguishable from a hung implementation, and it
 * would be diagnosed as a signalling failure when it was really a handoff failure.
 */
#define NEXUS_TPM_HANDOFF_CTRL_STS   CRB_STS_TPM_IDLE   // idle, no error
#define NEXUS_TPM_HANDOFF_CTRL_START 0                  // explicitly NOT set
#define NEXUS_TPM_HANDOFF_CTRL_REQ   0                  // no pending request

#endif // NEXUS_TPM_STATE_H
