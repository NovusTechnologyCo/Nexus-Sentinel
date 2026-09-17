/**
 * @file Tpm2EventLog.h
 * @brief The TCG crypto-agile event log. Phase 2.
 *
 * Every measurement extended into a PCR is also RECORDED here, so a verifier can replay the log
 * and arrive at the PCR values independently. A PCR on its own says "something was measured"; the
 * log says what.
 *
 * ⚠ THE LOG AND THE PCRs MUST NOT BE ABLE TO DISAGREE. `the design notes` already made
 * this point for the Secure Boot work, and it is if anything stronger here: a log that does not
 * replay to the PCR values is a stronger signal of tampering than no log at all. So the log entry
 * and the PCR extend happen in one operation and share one digest -- see `Tpm2EventLogExtend`.
 *
 * ---------------------------------------------------------------------------------------------
 * FORMAT -- transcribed from the structures EDK2 vendors and the PFP, not recalled.
 * ---------------------------------------------------------------------------------------------
 *
 * A crypto-agile log is a 1.2-format FIRST entry announcing the format, followed by
 * TCG_PCR_EVENT2 entries. The first entry is deliberately in the OLD format so that a 1.2-only
 * parser can read it, see EV_NO_ACTION, and stop cleanly rather than misparse the rest.
 *
 *   entry 0   TCG_PCR_EVENT (1.2 layout)
 *             PCRIndex   u32   = 0
 *             EventType  u32   = EV_NO_ACTION (3)
 *             Digest     [20]  = zero
 *             EventSize  u32
 *             Event      = TCG_EfiSpecIDEventStruct:
 *                            signature[16]        "Spec ID Event03\0"
 *                            platformClass  u32   0 = client
 *                            specVersionMinor u8  0
 *                            specVersionMajor u8  2
 *                            specErrata     u8
 *                            uintnSize      u8    2 = 64-bit
 *                            numberOfAlgorithms u32
 *                            digestSizes[]        { algorithmId u16, digestSize u16 }
 *                            vendorInfoSize u8
 *
 *   entry n   TCG_PCR_EVENT2
 *             PCRIndex   u32
 *             EventType  u32
 *             Digests          TPML_DIGEST_VALUES: count u32, then per algorithm
 *                                { algorithmId u16, digest[digestSize] }
 *             EventSize  u32
 *             Event      [EventSize]
 *
 * ⚠ TPML_DIGEST_VALUES IS VARIABLE LENGTH, so entries are written BYTE-WISE. EDK2's
 * `TCG_PCR_EVENT2` struct declares `Digest` as a fixed `TPML_DIGEST_VALUES` and `Event[1]`; using
 * it directly with `sizeof` or a struct assignment produces a log whose entries are the wrong
 * length and whose fields land at the wrong offsets. The struct is a description, not a layout.
 *
 * ⚠ AND THE LOG IS LITTLE-ENDIAN, unlike TPM command traffic. The event log is a firmware data
 * structure read by the OS, not a TPM wire format -- so `Tpm2Core`'s big-endian accessors are
 * exactly the wrong tool here. Getting these two backwards produces a log that parses as garbage.
 *
 * ---------------------------------------------------------------------------------------------
 * DEPENDENCY-FREE, like Tpm2Core.c and Sha256.c, so the format can be checked on the host.
 * ---------------------------------------------------------------------------------------------
 */

#ifndef NEXUS_TPM2_EVENTLOG_H
#define NEXUS_TPM2_EVENTLOG_H

#include <Uefi.h>
#include "Tpm2Core.h"

//
// Event types used here. EDK2's UefiTcgPlatform.h has the full set; these are the ones this file
// writes or reasons about.
//
#define TPM2_EV_NO_ACTION            0x00000003
#define TPM2_EV_SEPARATOR            0x00000004

#define TPM2_SPEC_ID_SIGNATURE       "Spec ID Event03"
#define TPM2_SPEC_ID_SIGNATURE_SIZE  16

/**
 * A log under construction.
 *
 * The buffer is caller-supplied. This file never allocates -- which is what keeps it host-testable
 * and what lets the DXE put the log in `EfiACPIMemoryNVS`, where it must live so the OS can still
 * read it after ExitBootServices.
 */
typedef struct _TPM2_EVENT_LOG {
	UINT8*  Buffer;
	UINT32  Capacity;
	UINT32  Used;

	/*
	 * Offset of the last entry written, for EFI_TCG2_PROTOCOL.GetEventLog's EventLogLastEntry.
	 * ⚠ Zero is a legitimate value once the header event is written, so `Count` is what
	 * distinguishes "no entries" -- not a zero offset.
	 */
	UINT32  LastEntryOffset;
	UINT32  Count;

	/*
	 * ⚠ TRUNCATION IS RECORDED, NOT HIDDEN. GetEventLog has an EventLogTruncated output for
	 * exactly this, and a log that silently drops entries would replay to PCR values that do not
	 * match -- the self-inconsistency this whole file exists to avoid. Once set, the PCR extend
	 * still happens (the protocol requires it) but the caller is told the log is incomplete.
	 */
	BOOLEAN Truncated;
} TPM2_EVENT_LOG;

/**
 * Start a log in @p Buffer and write the Spec ID header event.
 *
 * @retval TRUE   header written
 * @retval FALSE  buffer too small even for the header -- nothing was written
 */
BOOLEAN
Tpm2EventLogInit(
	OUT TPM2_EVENT_LOG* Log,
	OUT UINT8*          Buffer,
	IN  UINT32          Capacity
	);

/**
 * Hash @p Data, extend it into @p PcrIndex, and append the matching log entry -- ONE operation,
 * because the log and the PCRs must not be able to disagree.
 *
 * ⚠ THE EXTEND HAPPENS EVEN IF THE LOG IS FULL. That is not a convenience: TCG2's
 * HashLogExtendEvent is specified as *"The extend operation will occur even if this function cannot
 * create an event log entry"*. A caller that measured something must not be able to conclude,
 * from a full log, that the measurement did not happen.
 *
 * @param Data        the bytes being measured; may be NULL only if DataLen is 0
 * @param EventData   the log's description of what was measured; may be NULL if EventDataLen is 0
 * @param OutDigest   the digest that was extended, for callers that need it; may be NULL
 *
 * @retval TPM2_RC_SUCCESS  extended, and logged
 * @retval TPM2_RC_VALUE    bad PCR index or a NULL buffer with a non-zero length
 * @retval other            whatever Tpm2PcrExtend returned
 *
 * ⚠ A SUCCESS RETURN DOES NOT MEAN THE ENTRY WAS LOGGED. Check `Log->Truncated`.
 */
UINT32
Tpm2EventLogExtend(
	IN OUT TPM2_EVENT_LOG* Log,
	IN OUT TPM2_PCR_BANK*  Bank,
	IN     UINT32          PcrIndex,
	IN     UINT32          EventType,
	IN     CONST UINT8*    Data,
	IN     UINT32          DataLen,
	IN     CONST UINT8*    EventData,
	IN     UINT32          EventDataLen,
	OUT    UINT8*          OutDigest
	);

/**
 * Append an entry for a digest that has ALREADY been computed, without hashing anything.
 *
 * ⚠ EXISTS FOR EFI_TCG2_EXTEND_ONLY AND PE/COFF MEASUREMENT, where the caller computes the digest
 * itself over a non-contiguous set of ranges. Do not use it to avoid hashing: passing a digest
 * that was not derived from what the event claims is precisely how a log stops being evidence.
 */
UINT32
Tpm2EventLogExtendDigest(
	IN OUT TPM2_EVENT_LOG* Log,
	IN OUT TPM2_PCR_BANK*  Bank,
	IN     UINT32          PcrIndex,
	IN     UINT32          EventType,
	IN     CONST UINT8     Digest[TPM2_SHA256_DIGEST_SIZE],
	IN     CONST UINT8*    EventData,
	IN     UINT32          EventDataLen
	);

#endif // NEXUS_TPM2_EVENTLOG_H
