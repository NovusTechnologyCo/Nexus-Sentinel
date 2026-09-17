/**
 * @file TcgLogTransform.h
 * @brief The PURE TCG-log transform: parse, edit, recompute digests, emit. No firmware dependencies.
 *
 * WHY THIS IS SPLIT OUT of TcgLogSanitize.c:
 *
 * Tier 3 has now cost three boots, and NOT ONE of them tested whether this transform is correct.
 * Every failure was about WHERE it ran -- a GetEventLog hook that may or may not be called, an ACPI
 * walk in winload where physical addresses are unmapped, an ExitBootServices call that is provably
 * too late. The transform itself has never been observed to succeed or fail.
 *
 * That is the wrong thing to keep testing on hardware. Sha256.c was validated against 161 real
 * firmware digests before it ever booted, precisely because it had no firmware dependencies. This
 * file exists so the transform gets the same treatment.
 *
 * DEPENDENCIES ARE DELIBERATELY MINIMAL: <Uefi.h> for integer types, BaseMemoryLib for
 * CopyMem/ZeroMem/CompareMem, and our own Sha256. No gBS, no gST, no protocols, no AllocatePool,
 * no Print. Everything context-dependent -- finding the ACPI TPM2 table, discovering our own device
 * paths from EFI_LOADED_IMAGE_PROTOCOL, writing back to physical memory -- stays in
 * TcgLogSanitize.c, which cannot be host-tested and does not need to be.
 *
 * In particular SELF-PATHS ARE A PARAMETER, not something this file discovers. That is what makes
 * it testable at all, and it is better design regardless: identification policy belongs to the
 * caller, mechanism belongs here.
 *
 * The specification is tools/wbcl_sanitize.py, validated end-to-end against four real committed
 * logs. Where the two disagree, the reference is right and this is wrong.
 */

#pragma once

#include <Uefi.h>
#include "Sha256.h"     /* SHA256_DIGEST_SIZE, used by the snapshot declarations below */

#define MAX_SELF_PATHS   4
#define MAX_PATH_CHARS   128

/**
 * How many bytes of a log area are actually in use, found by walking events until one fails to
 * parse. A log AREA has a fixed capacity (ACPI LAML); the CONTENT is shorter, and handing the
 * transform the whole area would walk it into uninitialised memory.
 *
 * Returns 0 if the log header itself does not parse.
 */
UINTN
EFIAPI
MeasureLogExtent(
	IN CONST UINT8* Log,
	IN UINTN Capacity
	);

/**
 * Build a sanitized copy of a WBCL/TCG2 event log in a caller-provided buffer.
 *
 * @param SrcLog     first byte of the log (the TCG_EfiSpecIdEvent header record)
 * @param SrcSize    bytes of log content (see MeasureLogExtent)
 * @param SelfPaths  ESP paths of OUR images. Records naming any of these are removed. Supplied by
 *                   the caller so this file needs no protocol access -- and so a test can pass
 *                   known values instead of whatever the running firmware happens to report.
 * @param SelfCount  number of entries in SelfPaths; 0 is rejected rather than treated as "match
 *                   nothing", because silently sanitizing nothing is the failure mode that looks
 *                   most like success.
 * @param Dst        output buffer
 * @param DstCapacity  its size; must be at least SrcSize + the inserted record + slack
 * @param DstSize    receives the sanitized length
 *
 * @param InsertAuthority  TRUE to insert the CA 2011 EV_EFI_VARIABLE_AUTHORITY record, making
 *                   PCR[7] match a genuine Secure-Boot-enabled boot. That record is 1608 bytes and
 *                   is the ONLY thing that makes this transform grow.
 *
 *                   Pass FALSE where the output must fit a FIXED-CAPACITY buffer. The ACPI log area
 *                   (LAML, 64 KB here) is such a buffer, and with the insert the output exceeded it
 *                   -- MEASURED: 78,499 > 65,536, so the in-place path refused and the raw buffer
 *                   stayed dirty. Without it the transform is size-NEGATIVE (it only drops records
 *                   and flips two bytes) and fits easily.
 *
 *                   The trade is deliberate: the substituted log Windows consumes gets the full
 *                   treatment including the authority record, while the raw ACPI buffer gets our
 *                   identifying records removed but keeps a PCR[7] that still reads Secure Boot as
 *                   off. Cleaning our traces from the raw buffer is worth more than making a buffer
 *                   nobody was reading look enabled.
 *
 * FAILS CLOSED. Every mandatory edit target must be present or nothing is written: scope §4
 * establishes that a partial sanitization is MORE identifying than none, since an image record
 * removed while its boot entry survives is a contradiction no clean machine produces.
 */
EFI_STATUS
EFIAPI
SanitizeTcgEventLog(
	IN CONST UINT8* SrcLog,
	IN UINTN SrcSize,
	IN CONST CHAR16 SelfPaths[][MAX_PATH_CHARS],
	IN UINTN SelfCount,
	IN BOOLEAN InsertAuthority,
	OUT UINT8* Dst,
	IN UINTN DstCapacity,
	OUT UINTN* DstSize
	);

//
// Windows Boot Manager's embedded PCR snapshot record. Shared with PatchBootmgr.c, which patches
// the record where bootmgr composes it -- the transform itself can never see it (scope doc §3a).
//
//   u32 magic 0xADF01995 | u16 version | u16 reserved | u16 count | u16 alg | u16 digestSize
//   u8  values[count * digestSize]
//
#define SNAPSHOT_MAGIC        0xADF01995
#define SNAPSHOT_HDR_SIZE     14
#define SNAPSHOT_MAX_PCRS     24
#define TPM_ALG_SHA256        0x000B

/**
 * The PCR state the last SUCCESSFUL sanitization finished with -- i.e. what the PCRs would read
 * at the end of the firmware log we emitted, which is exactly the moment bootmgr snapshots.
 *
 * Returns FALSE if no transform has succeeded this boot. The caller must then leave bootmgr's
 * record untouched: with no sanitization in effect the genuine values are the consistent ones.
 */
BOOLEAN
EFIAPI
GetSanitizedPcrState(
	OUT UINT8 Out[SNAPSHOT_MAX_PCRS][SHA256_DIGEST_SIZE]
	);

/**
 * Append the Media/File Path nodes of a device path as text, bounded by OutChars.
 *
 * Exported because CollectSelfPaths in TcgLogSanitize.c needs the SAME extraction the transform
 * uses for log records -- if the two differed, our own paths would be formatted one way and the
 * log's another, and nothing would ever match.
 *
 * Truncation only ever makes a comparison FAIL to match, never falsely match.
 */
VOID
EFIAPI
DevicePathToText(
	IN CONST UINT8* Dp,
	IN UINTN DpSize,
	OUT CHAR16* Out,
	IN UINTN OutChars
	);

/**
 * Byte offset of the LAST event record in a log, or 0 if none parse.
 *
 * EFI_TCG2_PROTOCOL.GetEventLog reports the last entry's ADDRESS alongside the log's, so a
 * substituted log needs its own. Computed by walking, never by scaling the original offset -- that
 * would be wrong the instant the transform changes any record's size, which is the entire point of
 * the transform.
 */
UINTN
EFIAPI
FindLastRecordOffset(
	IN CONST UINT8* Log,
	IN UINTN Size
	);
