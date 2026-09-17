/**
 * @file Tpm2Core.h
 * @brief TPM 2.0 core -- wire format and the PCR bank. Phase 2.
 *
 * `the design notes` §6. **This is the critical path now**, and that is a change from the
 * frozen plan, made on measurement (rev 9.13): the firmware publishes NO TCG facilities at all --
 * no `EFI_TCG2_PROTOCOL`, no 1.2 protocol, no final-events table -- so the boot loader was offered
 * no TPM and Windows entered the OS with no measured-boot state. That is why `tpm.sys` binds our
 * ACPI device and never writes a byte to the CRB. The CRB was never the blocker.
 *
 * ⚠ AND THE NEW ORDER IS EASIER, NOT HARDER. G1 -- the open gate -- exists because a RAM CRB has
 * no hardware doorbell AFTER ExitBootServices. `EFI_TCG2_PROTOCOL` is a BOOT-SERVICES-TIME
 * interface: the DXE answers it directly in its own code, with no CRB and no doorbell. So the
 * hardest unsolved problem in this project does not stand between us and measured boot.
 *
 * ---------------------------------------------------------------------------------------------
 * EVERY CONSTANT BELOW WAS READ FROM THE SPEC, NOT RECALLED, AND CROSS-CHECKED AGAINST EDK2.
 * ---------------------------------------------------------------------------------------------
 *
 * Sources, published by the Trusted Computing Group and not redistributed here:
 *   TPM 2.0 Library Part 1: Architecture, v185,
 *   TPM 2.0 Library Part 2: Structures,   v185,
 *   TPM 2.0 Library Part 3: Commands,     v185,
 *   TCG PC Client Platform TPM Profile,   v1.07,
 *
 * ⚠ THE CROSS-CHECK FOUND EDK2 WRONG ONCE, so it was worth doing. See TPM_RC_BAD_TAG below.
 *
 * ---------------------------------------------------------------------------------------------
 * DEPENDENCY-FREE ON PURPOSE, exactly like Sha256.c and for the same reason.
 * ---------------------------------------------------------------------------------------------
 *
 * No AllocatePool, no CopyMem, no DebugLib -- caller-supplied buffers only. That means this file
 * compiles as a HOST program, so PCR semantics can be validated against an independent oracle
 * before the code is ever asked to run during boot. A wrong Extend found at boot time is a wasted
 * reboot and a misleading PCR set; found on the host it is a failed assert.
 */

#ifndef NEXUS_TPM2_CORE_H
#define NEXUS_TPM2_CORE_H

#include <Uefi.h>
#include "../NexusBootDxe/Sha256.h"

//
// ---------------------------------------------------------------------------------------------
// WIRE FORMAT
//
// ⚠ TPM COMMANDS AND RESPONSES ARE BIG-ENDIAN. x86 is little-endian. Every multi-byte field on
// the wire must be byte-swapped, and the accessors below are the ONLY sanctioned way to touch
// them -- casting a buffer to a UINT32* and dereferencing is the single easiest way to produce a
// TPM that answers plausible nonsense.
// ---------------------------------------------------------------------------------------------
//

/**
 * Command header, Part 1 §18.2: tag, commandSize, commandCode.
 * Response header: tag, responseSize, responseCode. Same shape, 10 bytes.
 */
#define TPM2_HEADER_SIZE            10

//
// Structure tags -- Part 2 Table 21. Verified against the PDF: the table's column layout is
// mangled by text extraction, but the values are unambiguous.
//
#define TPM2_ST_RSP_COMMAND         0x00C4
#define TPM2_ST_NULL                0x8000
#define TPM2_ST_NO_SESSIONS         0x8001
#define TPM2_ST_SESSIONS            0x8002

//
// Command codes -- Part 2, "Definition of (UINT32) TPM_CC Constants". Each one below was read out
// of that table directly and matches EDK2's Tpm20.h.
//
#define TPM2_CC_SELF_TEST           0x00000143
#define TPM2_CC_STARTUP             0x00000144
#define TPM2_CC_SHUTDOWN            0x00000145
#define TPM2_CC_GET_CAPABILITY      0x0000017A
#define TPM2_CC_GET_RANDOM          0x0000017B
#define TPM2_CC_PCR_READ            0x0000017E
#define TPM2_CC_PCR_EXTEND          0x00000182

//
// Startup types -- Part 2 Table 22.
//
#define TPM2_SU_CLEAR               0x0000
#define TPM2_SU_STATE               0x0001

//
// Algorithm IDs -- Part 2. SHA-256 is the only bank this implementation has.
//
#define TPM2_ALG_SHA256             0x000B

//
// Response codes.
//
#define TPM2_RC_SUCCESS             0x000

//
// ⚠ 0x01E, **NOT** EDK2's 0x030 -- AND THE SPEC SAYS SO IN SO MANY WORDS.
//
// Part 2, under Table 21:
//
//     "the response code will be TPM_RC_BAD_TAG (0x001E), which has the same numeric value as the
//      TPM 1.2 response code for TPM_BADTAG. In a previously published version of this
//      specification, TPM_RC_BAD_TAG was incorrectly assigned a value of 0x030 instead of 30
//      (0x01e). Some implementations may return the old value instead of the new value."
//
// `edk2-stable202608` still defines `TPM_RC_BAD_TAG (0x030)` -- the value the standard itself
// calls incorrect. This is the second time a cross-check against the primary source has been worth
// the effort, and the first time EDK2 turned out to be the one that was wrong. (The first was the
// CRB data-buffer extent, where EDK2 was RIGHT and our own map was wrong -- rev 9.6.)
//
#define TPM2_RC_BAD_TAG             0x01E

#define TPM2_RC_VER1                0x100
#define TPM2_RC_INITIALIZE          (TPM2_RC_VER1 + 0x000)   /* TPM not started               */
#define TPM2_RC_FAILURE             (TPM2_RC_VER1 + 0x001)
#define TPM2_RC_COMMAND_CODE        (TPM2_RC_VER1 + 0x043)   /* command not implemented       */
#define TPM2_RC_COMMAND_SIZE        (TPM2_RC_VER1 + 0x042)

#define TPM2_RC_FMT1                0x080
#define TPM2_RC_VALUE               (TPM2_RC_FMT1 + 0x004)
#define TPM2_RC_SIZE                (TPM2_RC_FMT1 + 0x015)
#define TPM2_RC_HANDLE              (TPM2_RC_FMT1 + 0x00B)
#define TPM2_RC_INSUFFICIENT        (TPM2_RC_FMT1 + 0x01A)

//
// (!) A FORMAT-ONE CODE IS INCOMPLETE WITHOUT ITS NUMBER. Part 2 clause 6.6: bits 8-11 carry
// WHICH argument was at fault, and bit 6 says whether that number is a parameter (set) or a
// handle/session (clear). TPM_RC_HANDLE alone does not tell the caller which handle, and for a
// command with several handles that is the only useful part of the answer.
//
// N is 1-based: the first handle in the handle area is 1, not 0.
//
#define TPM2_RC_H(Rc, N)            ((Rc) | ((UINT32)(N) << 8))

//
// The same, for a PARAMETER rather than a handle: bit 6 says the number counts parameters.
//
// ⚠ MEASURED CROSS-CHECK. Real Intel PTT answers a bare header with what TBS shows as
// 0x09A. tpm.sys strips bits 8-11 AND bit 6 on the way out, so 0x1DA and 0x09A are
// indistinguishable through TBS -- but the host suite sees the full value, and the full value
// is what the specification asks for.
//
#define TPM2_RC_P(Rc, N)            ((Rc) | 0x040u | ((UINT32)(N) << 8))

//
// RC_WARN. A warning is not a failure: it tells the caller to retry or to load something first,
// which is why an unloaded TRANSIENT object is a warning while a missing PERSISTENT one is an
// error -- the transient one can be loaded, the persistent one is simply not there.
//
#define TPM2_RC_WARN                0x900
#define TPM2_RC_REFERENCE_H0        (TPM2_RC_WARN + 0x010)

//
// ---------------------------------------------------------------------------------------------
// THE PCR BANK
// ---------------------------------------------------------------------------------------------
//

#define TPM2_PCR_COUNT              24
#define TPM2_SHA256_DIGEST_SIZE     SHA256_DIGEST_SIZE

/**
 * One SHA-256 PCR bank.
 *
 * ⚠ ONE BANK, AND THAT IS A STATED LIMIT RATHER THAN AN OVERSIGHT. PTP's mandatory algorithm
 * profile is broader (§0 of the spec excludes it from the conformance claim), and a second bank is
 * additive when it is needed. Claiming banks we do not have would be the stub this project
 * forbids.
 */
typedef struct _TPM2_PCR_BANK {
	UINT8   Pcr[TPM2_PCR_COUNT][TPM2_SHA256_DIGEST_SIZE];

	/*
	 * Part 1 §17: a counter that increments on most invocations of TPM2_PCR_Extend(),
	 * TPM2_PCR_Event() and TPM2_PCR_Reset(). TPM2_PCR_Read returns it, and a reader uses it to
	 * detect that PCRs moved between two reads.
	 */
	UINT32  UpdateCounter;

	/*
	 * ⚠ TPM2_Startup HAS TO HAVE RUN. Part 3: if the TPM has not been initialized, the only
	 * command accepted is TPM2_Startup, and everything else answers TPM_RC_INITIALIZE. Tracking
	 * it is what makes that refusal HONEST rather than a silently-zeroed PCR set.
	 */
	BOOLEAN Started;
} TPM2_PCR_BANK;

/**
 * TPM2_Startup(CLEAR) initialisation, per **PTP 1.07 Table 15, "PCR Initial and Reset Values"**.
 *
 * ⚠ PCR[0] DOES NOT INITIALISE TO ZERO. Table 15 gives it the *Locality Indicator* -- "the
 * locality at which TPM2_Startup(CLEAR) is received". Every other PCR in 1..16 and 23 starts at 0,
 * and 17..22 start at -1, meaning a digest-sized field with every bit set.
 *
 * The universal assumption is that all PCRs start at zero, and for locality 0 the result happens
 * to be the same -- which is exactly what would have hidden the error here, since this
 * implementation is locality-0-only. It is encoded properly anyway: a rule that is only
 * accidentally satisfied is a rule waiting to break.
 *
 * @param LocalityIndicator  the locality at which startup is received; 0 for this implementation
 */
VOID
Tpm2PcrStartupClear(
	OUT TPM2_PCR_BANK* Bank,
	IN  UINT8          LocalityIndicator
	);

/**
 * TPM2_PCR_Extend for the SHA-256 bank.
 *
 * Part 1, equation (14), quoted exactly:
 *
 *     PCR.digest[pcrNum][alg]_new = H_alg(PCR.digest[pcrNum][alg]_old || digest)
 *
 * The old PCR value and the incoming digest are hashed TOGETHER, in that order. Not the digest
 * alone, and not the digest followed by the PCR.
 *
 * @param PcrIndex  0..23
 * @param Digest    32 bytes; the caller has already hashed whatever it is measuring
 *
 * @retval TPM2_RC_SUCCESS
 * @retval TPM2_RC_INITIALIZE  TPM2_Startup has not run
 * @retval TPM2_RC_VALUE       PcrIndex out of range
 */
UINT32
Tpm2PcrExtend(
	IN OUT TPM2_PCR_BANK* Bank,
	IN     UINT32         PcrIndex,
	IN     CONST UINT8    Digest[TPM2_SHA256_DIGEST_SIZE]
	);

/**
 * Read one PCR.
 *
 * @retval TPM2_RC_SUCCESS
 * @retval TPM2_RC_INITIALIZE  TPM2_Startup has not run
 * @retval TPM2_RC_VALUE       PcrIndex out of range
 */
UINT32
Tpm2PcrRead(
	IN  CONST TPM2_PCR_BANK* Bank,
	IN  UINT32               PcrIndex,
	OUT UINT8                Out[TPM2_SHA256_DIGEST_SIZE]
	);

//
// ---------------------------------------------------------------------------------------------
// BIG-ENDIAN ACCESSORS. The only sanctioned way to touch a wire field.
// ---------------------------------------------------------------------------------------------
//

UINT16 Tpm2ReadBe16(IN CONST UINT8* P);
UINT32 Tpm2ReadBe32(IN CONST UINT8* P);
VOID   Tpm2WriteBe16(OUT UINT8* P, IN UINT16 V);
VOID   Tpm2WriteBe32(OUT UINT8* P, IN UINT32 V);
VOID   Tpm2WriteBe64(OUT UINT8* P, IN UINT64 V);

/**
 * Parse a command header.
 *
 * @param Buffer       the raw command
 * @param Length       bytes available -- checked, never assumed
 * @param OutTag       TPM2_ST_*
 * @param OutSize      commandSize as the command declares it
 * @param OutCode      commandCode
 *
 * @retval TPM2_RC_SUCCESS
 * @retval TPM2_RC_COMMAND_SIZE  fewer than 10 bytes, or commandSize disagrees with Length
 * @retval TPM2_RC_BAD_TAG       tag is neither TPM2_ST_NO_SESSIONS nor TPM2_ST_SESSIONS
 */
UINT32
Tpm2ParseCommandHeader(
	IN  CONST UINT8* Buffer,
	IN  UINT32       Length,
	OUT UINT16*      OutTag,
	OUT UINT32*      OutSize,
	OUT UINT32*      OutCode
	);

/**
 * Write a response header. Returns TPM2_HEADER_SIZE.
 *
 * ⚠ AN ERROR RESPONSE ALWAYS USES TPM2_ST_NO_SESSIONS, whatever the command's tag was. Part 2:
 * "If the responseCode from the TPM is not TPM_RC_SUCCESS, then the response tag shall have this
 * value." This function enforces that rather than trusting the caller to remember.
 */
UINT32
Tpm2WriteResponseHeader(
	OUT UINT8*  Buffer,
	IN  UINT16  Tag,
	IN  UINT32  ResponseSize,
	IN  UINT32  ResponseCode
	);

#endif // NEXUS_TPM2_CORE_H
