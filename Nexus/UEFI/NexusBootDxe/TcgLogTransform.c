/**
 * @file TcgLogTransform.c
 * @brief The pure TCG-log transform. See TcgLogTransform.h for why this is separate.
 *
 * NO FIRMWARE DEPENDENCIES BY DESIGN: no gBS, no gST, no protocols, no AllocatePool, no Print.
 * That is what lets tools/tcg_transform_selftest.c compile THIS EXACT SOURCE on the host and check
 * it against tools/wbcl_sanitize.py, which is the specification. Testing a copy would be worthless
 * -- the copy gets fixed and the original is what boots.
 *
 * Three boots were spent on Tier 3 without ever establishing whether this code is correct, because
 * every failure was about WHERE it ran. This file exists so that question is answered on the host.
 */

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>

#include "Sha256.h"
#include "TcgLogTransform.h"
#include "TcgAuthorityBlob.h"

//
// TCG PC Client event types we act on. Full table in tools/tcg_log_verify_digests.py.
//
//
// Windows Boot Manager's embedded PCR snapshot (the design notes). An
// EV_NO_ACTION record carrying the PCR values the boot manager read from the TPM:
//   u32 magic | u16 version | u16 reserved | u16 count | u16 alg | u16 digestSize | values[]
// It is never extended, so its own digest is all-zero and nothing recomputes it -- which is why
// it went unnoticed until. Left alone it is a witness to the UNPATCHED state sitting
// inside the patched log, readable with no TPM and no admin.
//
#define EV_NO_ACTION                       0x00000003
// SNAPSHOT_MAGIC / SNAPSHOT_HDR_SIZE / SNAPSHOT_MAX_PCRS now live in TcgLogTransform.h, because
// PatchBootmgr.c patches the same record where bootmgr composes it and must agree on the layout.

#define EV_EFI_VARIABLE_DRIVER_CONFIG      0x80000001
#define EV_EFI_VARIABLE_BOOT               0x80000002
#define EV_EFI_BOOT_SERVICES_APPLICATION   0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER        0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER     0x80000005
#define EV_EFI_ACTION                      0x80000007
#define EV_EFI_VARIABLE_AUTHORITY          0x800000E0

//
// TPM_ALG_ID values and their digest sizes.
//
#define TPM_ALG_SHA1     0x0004
// TPM_ALG_SHA256 moved to TcgLogTransform.h -- PatchBootmgr.c validates the snapshot bank too.
#define TPM_ALG_SHA384   0x000C
#define TPM_ALG_SHA512   0x000D
#define TPM_ALG_SM3_256  0x0012

#define MAX_OUR_OPTIONS  8

//
// The EV_EFI_ACTION that immediately precedes the authority record in a genuine SB-on boot. Used as
// a POSITION ANCHOR rather than a hardcoded event index, because indices shift with every event we
// drop. Matches the reference implementation.
//
STATIC CONST CHAR8 mDmaAnchor[] = "DMA Protection Disabled";

//
// The PCR state at the END of the sanitized log, kept for the bootmgr snapshot hook.
//
// WHY THIS EXISTS: the firmware portion of the log ends at event 53; Windows Boot
// Manager then calls BuildPcrSnapshotData and appends the 0xADF01995 record as event 54,
// reporting what it read from the REAL TPM. That record is therefore a witness against our
// edits, and it is out of the transform's reach entirely (scope doc §3a).
//
// It is not out of reach of a bootmgr hook, and the values that hook needs are exactly the state
// this transform finishes with -- the log it emits covers events 1-53 and the snapshot describes
// the moment right after. Rather than recompute it anywhere else, the transform publishes what it
// already has. Recomputing in the hook would be a second implementation of the replay, and a
// second implementation is a mirror oracle.
//
STATIC UINT8 mSanitizedPcr[SNAPSHOT_MAX_PCRS][SHA256_DIGEST_SIZE];
STATIC BOOLEAN mSanitizedPcrValid = FALSE;


/**
 * Hand out the PCR state the last successful sanitization ended with.
 *
 * Returns FALSE when no transform has succeeded this boot, which the caller MUST treat as "leave
 * the genuine record alone". Writing a stale or zeroed snapshot over a real one would produce a
 * log that is worse than the one we are trying to improve.
 */
BOOLEAN
EFIAPI
GetSanitizedPcrState(
	OUT UINT8 Out[SNAPSHOT_MAX_PCRS][SHA256_DIGEST_SIZE]
	)
{
	if (Out == NULL || !mSanitizedPcrValid)
		return FALSE;
	CopyMem(Out, mSanitizedPcr, sizeof(mSanitizedPcr));
	return TRUE;
}


//
// One parsed event. Pointers are INTO the source buffer; nothing is copied.
//
typedef struct _TCG_EVENT_REF {
	UINT32 PcrIndex;
	UINT32 EventType;
	CONST UINT8* Digests;      // start of TPML_DIGEST_VALUES
	UINTN DigestsSize;
	CONST UINT8* Payload;
	UINT32 PayloadSize;
	CONST UINT8* Record;       // start of the whole record
	UINTN RecordSize;
} TCG_EVENT_REF;


/**
 * Digest size for a TPM_ALG_ID, or 0 if we do not know it.
 */
STATIC
UINTN
DigestSizeForAlg(
	IN UINT16 AlgId
	)
{
	switch (AlgId)
	{
	case TPM_ALG_SHA1:    return 20;
	case TPM_ALG_SHA256:  return 32;
	case TPM_ALG_SHA384:  return 48;
	case TPM_ALG_SHA512:  return 64;
	case TPM_ALG_SM3_256: return 32;
	default:              return 0;
	}
}



/**
 * Parse the TCG_PCR_EVENT2 at Buf+Offset. Every field is bounds-checked against Size: a malformed or
 * truncated log must make us bail, never fault, because we run before the OS exists.
 */
STATIC
BOOLEAN
ParseEvent(
	IN CONST UINT8* Buf,
	IN UINTN Size,
	IN UINTN Offset,
	OUT TCG_EVENT_REF* Ref
	)
{
	if (Buf == NULL || Ref == NULL || Offset + 12 > Size)
		return FALSE;

	CONST UINT8* p = Buf + Offset;
	CONST UINTN Remaining = Size - Offset;

	ZeroMem(Ref, sizeof(*Ref));
	Ref->Record = p;
	Ref->PcrIndex  = *(CONST UINT32*)(p + 0);
	Ref->EventType = *(CONST UINT32*)(p + 4);

	CONST UINT32 Count = *(CONST UINT32*)(p + 8);
	if (Count == 0 || Count > 8)          // 8 banks is already absurd; reject rather than trust
		return FALSE;

	UINTN Cursor = 12;
	for (UINT32 i = 0; i < Count; i++)
	{
		if (Cursor + 2 > Remaining)
			return FALSE;
		CONST UINT16 AlgId = *(CONST UINT16*)(p + Cursor);
		CONST UINTN DigestSize = DigestSizeForAlg(AlgId);
		if (DigestSize == 0)
			return FALSE;                 // unknown algorithm: cannot walk safely
		Cursor += 2 + DigestSize;
		if (Cursor > Remaining)
			return FALSE;
	}
	//
	// ⚠ Digests spans the WHOLE TPML_DIGEST_VALUES, INCLUDING its 4-byte Count -- i.e. from p+8, not
	// p+12.
	//
	// FIXED (found by tools/tcg_transform_selftest.c on its first run). This previously
	// pointed at p+12, excluding Count. EmitEvent then did CopyMem(p + 8, Digests, DigestsSize),
	// which wrote the ALGORITHM ENTRIES over the Count field: every emitted record was missing its
	// count and had every entry shifted 4 bytes early. The redigest loop then read a garbage count
	// and garbage algorithm IDs and bailed with EFI_UNSUPPORTED.
	//
	// So every record this transform emitted was malformed. All three boots would have produced a
	// corrupt log even if the placement had been right -- and none of them could have revealed it,
	// because the failures happened before the transform ever ran.
	//
	Ref->Digests = p + 8;
	Ref->DigestsSize = Cursor - 8;

	if (Cursor + 4 > Remaining)
		return FALSE;
	Ref->PayloadSize = *(CONST UINT32*)(p + Cursor);
	Cursor += 4;
	if (Ref->PayloadSize > Remaining - Cursor)
		return FALSE;
	Ref->Payload = p + Cursor;
	Cursor += Ref->PayloadSize;

	Ref->RecordSize = Cursor;
	return TRUE;
}



/**
 * Offset past the log's first record, a legacy-shaped TCG_PCR_EVENT holding TCG_EfiSpecIdEvent.
 * Layout: PCRIndex(4) EventType(4) Digest[20] EventSize(4) Event[EventSize].
 */
STATIC
BOOLEAN
SkipLogHeader(
	IN CONST UINT8* Buf,
	IN UINTN Size,
	OUT UINTN* Offset
	)
{
	if (Buf == NULL || Offset == NULL || Size < 32)
		return FALSE;
	CONST UINT32 EventSize = *(CONST UINT32*)(Buf + 28);
	if ((UINTN)EventSize > Size - 32)
		return FALSE;
	*Offset = 32 + EventSize;
	return TRUE;
}



/**
 * Split a UEFI_VARIABLE_DATA payload.
 *   VariableName EFI_GUID(16) | UnicodeNameLen u64 | VariableDataLen u64 | Name CHAR16[] | Data[]
 */
STATIC
BOOLEAN
SplitVariableData(
	IN CONST UINT8* Payload,
	IN UINTN PayloadSize,
	OUT CONST CHAR16** Name,
	OUT UINTN* NameChars,
	OUT CONST UINT8** Data,
	OUT UINTN* DataSize
	)
{
	if (Payload == NULL || PayloadSize < 32)
		return FALSE;

	CONST UINT64 NameLen = *(CONST UINT64*)(Payload + 16);
	CONST UINT64 DataLen = *(CONST UINT64*)(Payload + 24);
	if (NameLen > 512 || DataLen > PayloadSize)
		return FALSE;

	CONST UINTN NameBytes = (UINTN)NameLen * sizeof(CHAR16);
	if (32 + NameBytes > PayloadSize)
		return FALSE;
	if (32 + NameBytes + (UINTN)DataLen > PayloadSize)
		return FALSE;

	if (Name != NULL)      *Name = (CONST CHAR16*)(Payload + 32);
	if (NameChars != NULL) *NameChars = (UINTN)NameLen;
	if (Data != NULL)      *Data = Payload + 32 + NameBytes;
	if (DataSize != NULL)  *DataSize = (UINTN)DataLen;
	return TRUE;
}



/**
 * Compare a non-null-terminated CHAR16 run against a literal. Variable names in the log are NOT
 * terminated -- UnicodeNameLen delimits them -- so StrCmp cannot be used directly.
 */
STATIC
BOOLEAN
VariableNameIs(
	IN CONST CHAR16* Name,
	IN UINTN NameChars,
	IN CONST CHAR16* Literal
	)
{
	if (Name == NULL || Literal == NULL)
		return FALSE;
	UINTN i = 0;
	for (; i < NameChars; i++)
	{
		if (Literal[i] == L'\0' || Name[i] != Literal[i])
			return FALSE;
	}
	return Literal[i] == L'\0';
}



/**
 * Append the Media/FilePath (type 0x04 / subtype 0x04) nodes of a device path as text.
 * Bounded by MAX_PATH_CHARS; a path longer than that simply truncates, which only ever makes a
 * comparison fail to match, never falsely match.
 */
VOID
EFIAPI
DevicePathToText(
	IN CONST UINT8* Dp,
	IN UINTN DpSize,
	OUT CHAR16* Out,
	IN UINTN OutChars
	)
{
	UINTN o = 0;
	UINTN off = 0;

	if (Out == NULL || OutChars == 0)
		return;
	Out[0] = L'\0';
	if (Dp == NULL)
		return;

	while (off + 4 <= DpSize)
	{
		CONST UINT8 Type = Dp[off];
		CONST UINT8 SubType = Dp[off + 1];
		CONST UINT16 Len = *(CONST UINT16*)(Dp + off + 2);
		if (Len < 4 || off + Len > DpSize)
			break;
		if (Type == 0x7F)                     // END of device path
			break;
		if (Type == 0x04 && SubType == 0x04)  // MEDIA / File Path
		{
			CONST CHAR16* s = (CONST CHAR16*)(Dp + off + 4);
			CONST UINTN n = (Len - 4) / sizeof(CHAR16);
			for (UINTN i = 0; i < n && s[i] != L'\0' && o + 1 < OutChars; i++)
				Out[o++] = s[i];
		}
		off += Len;
	}
	Out[o] = L'\0';
}



/**
 * Case-insensitive "does Haystack contain Needle". ASCII-range folding only, which is all a device
 * path on an ESP uses. Case-insensitive because nothing guarantees the firmware records the same
 * case we see in our own loaded-image path.
 */
STATIC
BOOLEAN
PathContains(
	IN CONST CHAR16* Haystack,
	IN CONST CHAR16* Needle
	)
{
	if (Haystack == NULL || Needle == NULL || Needle[0] == L'\0')
		return FALSE;

	for (UINTN i = 0; Haystack[i] != L'\0'; i++)
	{
		UINTN j = 0;
		while (Needle[j] != L'\0')
		{
			CHAR16 a = Haystack[i + j];
			CHAR16 b = Needle[j];
			if (a == L'\0')
				return FALSE;
			if (a >= L'A' && a <= L'Z') a = (CHAR16)(a - L'A' + L'a');
			if (b >= L'A' && b <= L'Z') b = (CHAR16)(b - L'A' + L'a');
			if (a != b)
				break;
			j++;
		}
		if (Needle[j] == L'\0')
			return TRUE;
	}
	return FALSE;
}



/**
 * Does an image event (EV_EFI_BOOT_SERVICES_APPLICATION / _DRIVER / EV_EFI_RUNTIME_SERVICES_DRIVER)
 * refer to one of our own images?
 *
 * UEFI_IMAGE_LOAD_EVENT: ImageLocationInMemory u64 | ImageLengthInMemory u64 |
 *                        ImageLinkTimeAddress u64 | LengthOfDevicePath u64 | DevicePath[]
 */
STATIC
BOOLEAN
ImageEventIsOurs(
	IN CONST UINT8* Payload,
	IN UINTN PayloadSize,
	IN CONST CHAR16 Paths[][MAX_PATH_CHARS],
	IN UINTN PathCount
	)
{
	if (Payload == NULL || PayloadSize < 32)
		return FALSE;

	CONST UINT64 DpLen = *(CONST UINT64*)(Payload + 24);
	if (DpLen > PayloadSize - 32)
		return FALSE;

	CHAR16 Text[MAX_PATH_CHARS];
	DevicePathToText(Payload + 32, (UINTN)DpLen, Text, MAX_PATH_CHARS);
	if (Text[0] == L'\0')
		return FALSE;

	for (UINTN i = 0; i < PathCount; i++)
	{
		if (PathContains(Text, Paths[i]) || PathContains(Paths[i], Text))
			return TRUE;
	}
	return FALSE;
}



/**
 * Does an EFI_LOAD_OPTION (a Boot#### variable's data) point at one of our images?
 *   Attributes u32 | FilePathListLength u16 | Description CHAR16* (null-terminated) | FilePathList[]
 *
 * Matched on the FILE PATH, never the Description: descriptions were renamed to innocuous strings in
 * BIOS ("Windows 11 (Alt)"), so a description-based test silently finds nothing.
 */
STATIC
BOOLEAN
LoadOptionIsOurs(
	IN CONST UINT8* Data,
	IN UINTN DataSize,
	IN CONST CHAR16 Paths[][MAX_PATH_CHARS],
	IN UINTN PathCount
	)
{
	if (Data == NULL || DataSize < 8)
		return FALSE;

	CONST UINT16 FpLen = *(CONST UINT16*)(Data + 4);
	UINTN off = 6;
	while (off + 1 < DataSize && !(Data[off] == 0 && Data[off + 1] == 0))
		off += 2;
	off += 2;                                  // step past the description terminator
	if (off >= DataSize || FpLen > DataSize - off)
		return FALSE;

	CHAR16 Text[MAX_PATH_CHARS];
	DevicePathToText(Data + off, FpLen, Text, MAX_PATH_CHARS);
	if (Text[0] == L'\0')
		return FALSE;

	for (UINTN i = 0; i < PathCount; i++)
	{
		if (PathContains(Text, Paths[i]) || PathContains(Paths[i], Text))
			return TRUE;
	}
	return FALSE;
}



/**
 * Write one event into the output buffer, optionally recomputing its digests over Preimage.
 *
 * ⚠ The preimage is the CALLER's choice because the rule is PER EVENT TYPE and MEASURED, not
 * guessable: EV_EFI_VARIABLE_BOOT hashes the VariableData field ONLY, while
 * EV_EFI_VARIABLE_DRIVER_CONFIG and EV_EFI_VARIABLE_AUTHORITY hash the whole payload. Getting that
 * backwards is exactly the B1 failure. See §4 of the scope for the measurement.
 *
 * Only SHA-256 digests can be recomputed -- that is the only hash compiled into this image. A log
 * carrying any other bank must FAIL CLOSED rather than be emitted with one stale digest.
 */
/**
 * PCR extend: Pcr = SHA256(Pcr || Digest). The one operation the whole replay is built from.
 */
STATIC
VOID
ExtendPcr(
	IN OUT UINT8* Pcr,
	IN CONST UINT8* Digest
	)
{
	UINT8 Buf[2 * SHA256_DIGEST_SIZE];
	CopyMem(Buf, Pcr, SHA256_DIGEST_SIZE);
	CopyMem(Buf + SHA256_DIGEST_SIZE, Digest, SHA256_DIGEST_SIZE);
	Sha256(Buf, sizeof(Buf), Pcr);
}


/**
 * Locate the SHA-256 digest inside a TPML_DIGEST_VALUES blob.
 *
 * This is deliberately run against the digest bytes ALREADY WRITTEN TO THE OUTPUT, not against
 * the source record. Redigested events (SecureBoot, Setup, BootOrder, the inserted authority)
 * carry a different digest in the output than in the input, and replaying the input's digest
 * would produce a snapshot that disagrees with the log we actually emit -- the exact failure
 * this whole change exists to remove.
 */
STATIC
CONST UINT8*
FindSha256Digest(
	IN CONST UINT8* Digests,
	IN UINTN DigestsSize
	)
{
	if (Digests == NULL || DigestsSize < 4)
		return NULL;

	CONST UINT32 Count = *(CONST UINT32*)Digests;
	UINTN Off = 4;
	for (UINT32 i = 0; i < Count; i++)
	{
		if (Off + 2 > DigestsSize)
			return NULL;
		CONST UINT16 AlgId = *(CONST UINT16*)(Digests + Off);
		CONST UINTN Size = DigestSizeForAlg(AlgId);
		if (Size == 0 || Off + 2 + Size > DigestsSize)
			return NULL;
		if (AlgId == TPM_ALG_SHA256)
			return Digests + Off + 2;
		Off += 2 + Size;
	}
	return NULL;
}


STATIC
EFI_STATUS
EmitEvent(
	IN OUT UINT8* Out,
	IN UINTN OutCap,
	IN OUT UINTN* OutPos,
	IN UINT32 PcrIndex,
	IN UINT32 EventType,
	IN CONST UINT8* Digests,
	IN UINTN DigestsSize,
	IN CONST UINT8* Payload,
	IN UINT32 PayloadSize,
	IN BOOLEAN Redigest,
	IN CONST UINT8* Preimage,
	IN UINTN PreimageSize
	)
{
	CONST UINTN Need = 8 + DigestsSize + 4 + PayloadSize;
	if (Out == NULL || OutPos == NULL || *OutPos + Need > OutCap)
		return EFI_BUFFER_TOO_SMALL;

	UINT8* p = Out + *OutPos;
	*(UINT32*)(p + 0) = PcrIndex;
	*(UINT32*)(p + 4) = EventType;
	CopyMem(p + 8, Digests, DigestsSize);

	if (Redigest)
	{
		//
		// Walk the COPY and replace each SHA-256 digest in place. Sizes never change, so the record
		// layout is untouched.
		//
		UINT8* d = p + 8;
		CONST UINT32 Count = *(CONST UINT32*)d;
		UINTN off = 4;
		for (UINT32 i = 0; i < Count; i++)
		{
			CONST UINT16 AlgId = *(CONST UINT16*)(d + off);
			CONST UINTN Size = DigestSizeForAlg(AlgId);
			if (Size == 0)
				return EFI_UNSUPPORTED;
			if (AlgId == TPM_ALG_SHA256)
				Sha256(Preimage, PreimageSize, d + off + 2);
			else
				return EFI_UNSUPPORTED;      // cannot recompute; refuse rather than leave it stale
			off += 2 + Size;
		}
	}

	*(UINT32*)(p + 8 + DigestsSize) = PayloadSize;
	if (PayloadSize != 0)
		CopyMem(p + 8 + DigestsSize + 4, Payload, PayloadSize);

	*OutPos += Need;
	return EFI_SUCCESS;
}



/**
 * Measure how many bytes of the log area are actually in use, by walking events until one fails to
 * parse. LAML is the CAPACITY, not the content length, and the transform must be given the real
 * extent -- feeding it the whole 64 KB would make it walk into uninitialised memory.
 */
UINTN
EFIAPI
MeasureLogExtent(
	IN CONST UINT8* Log,
	IN UINTN Capacity
	)
{
	UINTN Offset = 0;
	if (!SkipLogHeader(Log, Capacity, &Offset))
		return 0;

	TCG_EVENT_REF Ref;
	while (Offset < Capacity && ParseEvent(Log, Capacity, Offset, &Ref))
		Offset += Ref.RecordSize;
	return Offset;
}



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
	)
{
	if (SrcLog == NULL || SrcSize < 64 || Dst == NULL || DstSize == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// Zero self-paths is REJECTED rather than treated as "match nothing". Sanitizing a log while
	// recognising none of our own records would remove nothing, report success, and look exactly
	// like a working spoof -- the single most dangerous outcome this code can produce.
	//
	if (SelfPaths == NULL || SelfCount == 0)
		return EFI_INVALID_PARAMETER;

	*DstSize = 0;

	UINTN HeaderEnd = 0;
	if (!SkipLogHeader(SrcLog, SrcSize, &HeaderEnd))
		return EFI_VOLUME_CORRUPTED;

	//
	// ---- PASS 1 -------------------------------------------------------------------------------
	// Find which Boot#### option numbers are ours, and confirm every mandatory target exists.
	// Two passes are required because BootOrder is measured BEFORE the Boot#### entries it names
	// (MEASURED: BootOrder at event 32, Boot0000 at 33), so a single pass cannot rewrite it.
	//
	UINT16 OurOptions[MAX_OUR_OPTIONS];
	UINTN OurOptionCount = 0;
	UINTN OurImageCount = 0;
	BOOLEAN HaveBootOrder = FALSE;
	BOOLEAN HaveSecureBoot = FALSE;
	BOOLEAN HaveSetup = FALSE;
	BOOLEAN HaveAnchor = FALSE;
	BOOLEAN HaveAuthorityAlready = FALSE;
	BOOLEAN HaveSnapshot = FALSE;
	UINT8 StartupLocality = 0;

	TCG_EVENT_REF Ref;
	for (UINTN Off = HeaderEnd; Off < SrcSize; Off += Ref.RecordSize)
	{
		if (!ParseEvent(SrcLog, SrcSize, Off, &Ref))
			break;

		switch (Ref.EventType)
		{
		case EV_EFI_BOOT_SERVICES_APPLICATION:
		case EV_EFI_BOOT_SERVICES_DRIVER:
		case EV_EFI_RUNTIME_SERVICES_DRIVER:
			if (ImageEventIsOurs(Ref.Payload, Ref.PayloadSize, SelfPaths, SelfCount))
				OurImageCount++;
			break;

		case EV_NO_ACTION:
			//
			// StartupLocality seeds PCR[0]'s LAST byte before its first extension. It is read here
			// rather than in pass 2 so the seed is provably in place before any extend -- MEASURED
			// on this platform as locality 3, and a wrong seed corrupts PCR[0] only, which reads
			// like a firmware quirk rather than a bug.
			//
			if (Ref.PayloadSize >= 17 &&
				CompareMem(Ref.Payload, "StartupLocality", 15) == 0)
			{
				StartupLocality = Ref.Payload[16];
			}
			else if (Ref.PayloadSize >= SNAPSHOT_HDR_SIZE &&
					 *(CONST UINT32*)Ref.Payload == SNAPSHOT_MAGIC)
			{
				HaveSnapshot = TRUE;
			}
			break;

		case EV_EFI_VARIABLE_BOOT:
		{
			CONST CHAR16* Name = NULL;
			UINTN NameChars = 0;
			CONST UINT8* VData = NULL;
			UINTN VSize = 0;
			if (!SplitVariableData(Ref.Payload, Ref.PayloadSize, &Name, &NameChars, &VData, &VSize))
				break;
			if (VariableNameIs(Name, NameChars, L"BootOrder"))
			{
				HaveBootOrder = TRUE;
				break;
			}
			//
			// A Boot#### entry. Parse the 4 hex digits after "Boot" to get its option number, which
			// is what BootOrder references.
			//
			if (NameChars == 8 && VariableNameIs(Name, 4, L"Boot") == FALSE)
			{
				// name starts with "Boot" only if the first four chars match; check explicitly
			}
			if (NameChars == 8 &&
				Name[0] == L'B' && Name[1] == L'o' && Name[2] == L'o' && Name[3] == L't' &&
				LoadOptionIsOurs(VData, VSize, SelfPaths, SelfCount))
			{
				UINT16 Num = 0;
				BOOLEAN Ok = TRUE;
				for (UINTN i = 4; i < 8; i++)
				{
					CHAR16 c = Name[i];
					UINT16 v;
					if (c >= L'0' && c <= L'9')      v = (UINT16)(c - L'0');
					else if (c >= L'A' && c <= L'F') v = (UINT16)(c - L'A' + 10);
					else if (c >= L'a' && c <= L'f') v = (UINT16)(c - L'a' + 10);
					else { Ok = FALSE; break; }
					Num = (UINT16)((Num << 4) | v);
				}
				if (Ok && OurOptionCount < MAX_OUR_OPTIONS)
				{
					//
					// The same Boot#### can be measured more than once when BootOrder lists it
					// twice (MEASURED on this platform), so de-duplicate.
					//
					BOOLEAN Seen = FALSE;
					for (UINTN i = 0; i < OurOptionCount; i++)
						if (OurOptions[i] == Num)
							Seen = TRUE;
					if (!Seen)
						OurOptions[OurOptionCount++] = Num;
				}
			}
			break;
		}

		case EV_EFI_VARIABLE_DRIVER_CONFIG:
		{
			CONST CHAR16* Name = NULL;
			UINTN NameChars = 0;
			CONST UINT8* VData = NULL;
			UINTN VSize = 0;
			if (!SplitVariableData(Ref.Payload, Ref.PayloadSize, &Name, &NameChars, &VData, &VSize))
				break;
			if (Ref.PcrIndex == 7 && VariableNameIs(Name, NameChars, L"SecureBoot") && VSize >= 1)
				HaveSecureBoot = TRUE;
			if (Ref.PcrIndex == 1 && VariableNameIs(Name, NameChars, L"Setup") && VSize >= 12)
				HaveSetup = TRUE;
			break;
		}

		case EV_EFI_ACTION:
			if (Ref.PcrIndex == 7 && Ref.PayloadSize >= sizeof(mDmaAnchor) - 1 &&
				CompareMem(Ref.Payload, mDmaAnchor, sizeof(mDmaAnchor) - 1) == 0)
				HaveAnchor = TRUE;
			break;

		case EV_EFI_VARIABLE_AUTHORITY:
			if (Ref.PcrIndex == 7 && Ref.PayloadSize == TCG_AUTHORITY_BLOB_SIZE)
				HaveAuthorityAlready = TRUE;
			break;

		default:
			break;
		}
	}

	//
	// FAIL CLOSED on anything missing. Each of these would leave the log self-contradictory, which
	// scope §4 establishes is worse than not touching it at all.
	//
	if (OurImageCount == 0 || OurOptionCount == 0 || !HaveBootOrder ||
		!HaveSecureBoot || !HaveSetup)
		return EFI_ABORTED;

	//
	// ⚠ THE SNAPSHOT IS **NOT** MANDATORY, and requiring it disabled Tier 3 completely.
	//
	// measured, boot 2750: an earlier revision of this function aborted when the
	// 0xADF01995 record was absent, reasoning that all four committed baselines carry exactly one.
	// Every one of those baselines is a FINAL log read from Windows. The log this transform sees
	// is not that log.
	//
	// The firmware/Windows boundary sits at event 53/54: events 1-53 are firmware measurements
	// ending with bootmgfw's own image, and event 54 -- the snapshot -- is the FIRST record
	// Windows Boot Manager writes, appended to its own copy AFTER it has taken the firmware log
	// through GetEventLog. So the record can never be present when we run, the abort fired on
	// every call, and the unmodified log passed through: SecureBoot read 00 and our ESP path was
	// still in PCR[4] on a boot whose Tier 1 hook was working perfectly.
	//
	// Reconciliation below is therefore BEST-EFFORT: patch the record when it is present (offline
	// use of wbcl_sanitize.py on a complete log), never refuse because it is absent. HaveSnapshot
	// is kept only to report which case occurred.
	//
	(VOID)HaveSnapshot;

	//
	// The anchor and the not-already-present check only matter when we are actually inserting.
	// Requiring them unconditionally would make the size-capped (InsertAuthority=FALSE) caller fail
	// for reasons that cannot affect it.
	//
	if (InsertAuthority && (!HaveAnchor || HaveAuthorityAlready))
		return EFI_ABORTED;

	//
	// ---- OUTPUT BUFFER -------------------------------------------------------------------------
	// Caller-provided; worst case is the source plus one inserted record, since dropped events only
	// shrink it. Refuse rather than truncate.
	//
	CONST UINTN OutCap = DstCapacity;
	UINT8* Out = Dst;
	if (OutCap < SrcSize + (InsertAuthority ? TCG_AUTHORITY_BLOB_SIZE : 0) + 512)
		return EFI_BUFFER_TOO_SMALL;

	CopyMem(Out, SrcLog, HeaderEnd);
	UINTN OutPos = HeaderEnd;
	UINTN LastRecord = HeaderEnd;
	EFI_STATUS Status = EFI_SUCCESS;

	//
	// ---- PASS 2: emit --------------------------------------------------------------------------
	//
	// The PCR replay runs DURING emit rather than as a third pass. The snapshot record sits at a
	// fixed point in the stream, so by the time it is reached every event before it has already
	// been emitted and extended -- which is exactly the state the boot manager recorded. A
	// separate pass would have to reproduce the emit decisions and could drift from them.
	//
	// PCR 17-22 reset to all-ones on TPM 2.0 (DRTM, locality 4); every other PCR resets to zero.
	//
	UINT8 Pcr[SNAPSHOT_MAX_PCRS][SHA256_DIGEST_SIZE];
	SetMem(Pcr, sizeof(Pcr), 0x00);
	for (UINTN i = 17; i <= 22; i++)
		SetMem(Pcr[i], SHA256_DIGEST_SIZE, 0xFF);
	Pcr[0][SHA256_DIGEST_SIZE - 1] = StartupLocality;

	UINT8 SnapBuf[SNAPSHOT_HDR_SIZE + SNAPSHOT_MAX_PCRS * SHA256_DIGEST_SIZE];

	for (UINTN Off = HeaderEnd; Off < SrcSize; Off += Ref.RecordSize)
	{
		if (!ParseEvent(SrcLog, SrcSize, Off, &Ref))
			break;

		BOOLEAN Drop = FALSE;
		BOOLEAN Redigest = FALSE;
		CONST UINT8* Payload = Ref.Payload;
		UINT32 PayloadSize = Ref.PayloadSize;
		CONST UINT8* Preimage = Ref.Payload;
		UINTN PreimageSize = Ref.PayloadSize;

		//
		// Scratch for events whose payload we rewrite. Sized for the largest we touch (BootOrder is
		// tiny, Setup is well under 1 KB on this platform); anything larger fails closed below.
		//
		UINT8 Patched[512];

		switch (Ref.EventType)
		{
		case EV_EFI_BOOT_SERVICES_APPLICATION:
		case EV_EFI_BOOT_SERVICES_DRIVER:
		case EV_EFI_RUNTIME_SERVICES_DRIVER:
			Drop = ImageEventIsOurs(Ref.Payload, Ref.PayloadSize, SelfPaths, SelfCount);
			break;

		case EV_NO_ACTION:
		{
			//
			// Reconcile the boot manager's PCR snapshot with the log we are actually emitting.
			// Every event this transform touches is extended BEFORE the boot manager runs, so an
			// untouched snapshot contradicts the edited log on exactly the PCRs we changed --
			// MEASURED on the shipped log as PCR 1, 4 and 7.
			//
			// No redigest: EV_NO_ACTION is never extended and this record's own digest is all-zero
			// (MEASURED on all six baselines). The rewrite is also size-neutral, which the
			// LAML-capped in-place ACPI path depends on.
			//
			if (Ref.PayloadSize < SNAPSHOT_HDR_SIZE ||
				*(CONST UINT32*)Ref.Payload != SNAPSHOT_MAGIC)
				break;

			CONST UINT16 SnapCount = *(CONST UINT16*)(Ref.Payload + 8);
			CONST UINT16 SnapAlg   = *(CONST UINT16*)(Ref.Payload + 10);
			CONST UINT16 SnapSize  = *(CONST UINT16*)(Ref.Payload + 12);

			if (SnapAlg != TPM_ALG_SHA256 || SnapSize != SHA256_DIGEST_SIZE ||
				SnapCount > SNAPSHOT_MAX_PCRS ||
				Ref.PayloadSize != (UINT32)(SNAPSHOT_HDR_SIZE + SnapCount * SnapSize))
			{
				//
				// An unproven layout. Refuse rather than write a snapshot we do not understand:
				// a malformed record is a stronger signal than an unmodified one.
				//
				Status = EFI_UNSUPPORTED;
				goto Done;
			}

			CopyMem(SnapBuf, Ref.Payload, SNAPSHOT_HDR_SIZE);
			for (UINT16 i = 0; i < SnapCount; i++)
				CopyMem(SnapBuf + SNAPSHOT_HDR_SIZE + i * SnapSize, Pcr[i], SnapSize);

			Payload = SnapBuf;
			PayloadSize = Ref.PayloadSize;
			break;
		}

		case EV_EFI_VARIABLE_BOOT:
		{
			CONST CHAR16* Name = NULL;
			UINTN NameChars = 0;
			CONST UINT8* VData = NULL;
			UINTN VSize = 0;
			if (!SplitVariableData(Ref.Payload, Ref.PayloadSize, &Name, &NameChars, &VData, &VSize))
				break;

			if (NameChars == 8 &&
				Name[0] == L'B' && Name[1] == L'o' && Name[2] == L'o' && Name[3] == L't' &&
				LoadOptionIsOurs(VData, VSize, SelfPaths, SelfCount))
			{
				Drop = TRUE;
				break;
			}

			if (VariableNameIs(Name, NameChars, L"BootOrder"))
			{
				//
				// Rewrite BootOrder without our option numbers, then recompute over the VARIABLE
				// DATA ONLY -- the measured rule for EV_EFI_VARIABLE_BOOT, which differs from every
				// other variable event here.
				//
				CONST UINTN HeadBytes = (UINTN)(VData - Ref.Payload);
				if (Ref.PayloadSize > sizeof(Patched) || (VSize % sizeof(UINT16)) != 0)
				{
					Status = EFI_BUFFER_TOO_SMALL;
					goto Done;
				}
				CopyMem(Patched, Ref.Payload, HeadBytes);

				CONST UINT16* In = (CONST UINT16*)VData;
				CONST UINTN InCount = VSize / sizeof(UINT16);
				UINT16* OutOrder = (UINT16*)(Patched + HeadBytes);
				UINTN OutCount = 0;
				for (UINTN i = 0; i < InCount; i++)
				{
					BOOLEAN Ours = FALSE;
					for (UINTN k = 0; k < OurOptionCount; k++)
						if (In[i] == OurOptions[k])
							Ours = TRUE;
					if (!Ours)
						OutOrder[OutCount++] = In[i];
				}
				if (OutCount == InCount)
				{
					//
					// BootOrder named none of our options while our Boot#### entries exist: the log
					// is not internally consistent with what we detected. Refuse.
					//
					Status = EFI_ABORTED;
					goto Done;
				}

				CONST UINTN NewVSize = OutCount * sizeof(UINT16);
				*(UINT64*)(Patched + 24) = (UINT64)NewVSize;   // VariableDataLen
				Payload = Patched;
				PayloadSize = (UINT32)(HeadBytes + NewVSize);
				Preimage = Patched + HeadBytes;                // vardata ONLY
				PreimageSize = NewVSize;
				Redigest = TRUE;
			}
			break;
		}

		case EV_EFI_VARIABLE_DRIVER_CONFIG:
		{
			CONST CHAR16* Name = NULL;
			UINTN NameChars = 0;
			CONST UINT8* VData = NULL;
			UINTN VSize = 0;
			if (!SplitVariableData(Ref.Payload, Ref.PayloadSize, &Name, &NameChars, &VData, &VSize))
				break;
			CONST UINTN HeadBytes = (UINTN)(VData - Ref.Payload);

			if (Ref.PcrIndex == 7 && VariableNameIs(Name, NameChars, L"SecureBoot") && VSize >= 1)
			{
				if (Ref.PayloadSize > sizeof(Patched))
				{
					Status = EFI_BUFFER_TOO_SMALL;
					goto Done;
				}
				CopyMem(Patched, Ref.Payload, Ref.PayloadSize);
				Patched[HeadBytes] = 0x01;                     // SecureBoot -> enabled
				Payload = Patched;
				PayloadSize = Ref.PayloadSize;
				Preimage = Patched;                            // whole payload
				PreimageSize = Ref.PayloadSize;
				Redigest = TRUE;
			}
			else if (Ref.PcrIndex == 1 && VariableNameIs(Name, NameChars, L"Setup") && VSize >= 12)
			{
				//
				// measured across four real logs. Setup carries the Secure Boot state in
				// TWO adjacent bytes, matching the platform's separate enforcement/mode knobs
				// (see project_dell_sb_bios_topology_2026_07_26). Byte 10 is the SB enable bit;
				// byte 11 distinguishes Deployed from Audit:
				//
				//     state             [10] [11]
				//     SB-OFF             00   00
				//     Audit Mode         01   00
				//     SB-ON Deployed     01   01
				//
				// All 30 OTHER bytes of the 32-byte blob are byte-identical across all four logs,
				// so setting both of these makes Setup EXACTLY a genuine SB-ON-Deployed record --
				// this is a match, not an approximation.
				//
				// FIXED: this used to set byte 11 ONLY. That was derived by asking which
				// byte makes SB-ON unique (byte 11 does) instead of what a genuine SB-ON log looks
				// like byte-for-byte. On an SB-off machine the result was 00 01 -- a combination NO
				// real boot produces, so it was a stronger fingerprint than leaving Setup alone.
				// Caught statically by diffing the shipped TIER3 log against the SB-ON baseline;
				// tools/tcg_transform_selftest.c now asserts this so it cannot regress.
				//
				if (Ref.PayloadSize > sizeof(Patched))
				{
					Status = EFI_BUFFER_TOO_SMALL;
					goto Done;
				}
				CopyMem(Patched, Ref.Payload, Ref.PayloadSize);
				Patched[HeadBytes + 10] = 0x01;                // SB enable  (00 -> 01)
				Patched[HeadBytes + 11] = 0x01;                // Deployed, not Audit
				Payload = Patched;
				PayloadSize = Ref.PayloadSize;
				Preimage = Patched;
				PreimageSize = Ref.PayloadSize;
				Redigest = TRUE;
			}
			break;
		}

		default:
			break;
		}

		if (Drop)
			continue;

		LastRecord = OutPos;
		Status = EmitEvent(Out, OutCap, &OutPos,
						   Ref.PcrIndex, Ref.EventType,
						   Ref.Digests, Ref.DigestsSize,
						   Payload, PayloadSize,
						   Redigest, Preimage, PreimageSize);
		if (EFI_ERROR(Status))
			goto Done;

		//
		// Extend with the digest AS EMITTED, read back out of the output buffer. For a redigested
		// event that value was computed inside EmitEvent and exists nowhere else; replaying
		// Ref.Digests instead would silently reproduce the pre-patch chain.
		//
		if (Ref.EventType != EV_NO_ACTION && Ref.PcrIndex < SNAPSHOT_MAX_PCRS)
		{
			CONST UINT8* Emitted = FindSha256Digest(Out + LastRecord + 8, Ref.DigestsSize);
			if (Emitted == NULL)
			{
				Status = EFI_UNSUPPORTED;
				goto Done;
			}
			ExtendPcr(Pcr[Ref.PcrIndex], Emitted);
		}

		//
		// Insert the authority record immediately AFTER the DMA-Protection anchor, matching where a
		// genuine SB-on boot places it. Anchored, not indexed: indices shift with every drop.
		//
		if (InsertAuthority &&
			Ref.EventType == EV_EFI_ACTION && Ref.PcrIndex == 7 &&
			Ref.PayloadSize >= sizeof(mDmaAnchor) - 1 &&
			CompareMem(Ref.Payload, mDmaAnchor, sizeof(mDmaAnchor) - 1) == 0)
		{
			LastRecord = OutPos;
			Status = EmitEvent(Out, OutCap, &OutPos,
							   7, EV_EFI_VARIABLE_AUTHORITY,
							   Ref.Digests, Ref.DigestsSize,   // same bank layout as its neighbour
							   mTcgAuthorityBlob, TCG_AUTHORITY_BLOB_SIZE,
							   TRUE, mTcgAuthorityBlob, TCG_AUTHORITY_BLOB_SIZE);
			if (EFI_ERROR(Status))
				goto Done;

			//
			// The inserted record is extended into PCR[7] like any other. Omitting this would make
			// the snapshot disagree with the log by exactly this record's contribution.
			//
			{
				CONST UINT8* Emitted = FindSha256Digest(Out + LastRecord + 8, Ref.DigestsSize);
				if (Emitted == NULL)
				{
					Status = EFI_UNSUPPORTED;
					goto Done;
				}
				ExtendPcr(Pcr[7], Emitted);
			}
		}
	}

Done:
	if (EFI_ERROR(Status))
		return Status;

	(VOID)LastRecord;      // retained: the last-record offset is what a GetEventLog-style API needs

	//
	// Publish the finishing state for the bootmgr snapshot hook. Only on the SUCCESS path: a
	// transform that refused emitted the original log, so the true PCRs are the correct ones and
	// overwriting bootmgr's record with ours would manufacture a contradiction rather than remove
	// one. Re-sanitization on a later call simply refreshes this.
	//
	CopyMem(mSanitizedPcr, Pcr, sizeof(mSanitizedPcr));
	mSanitizedPcrValid = TRUE;

	*DstSize = OutPos;
	return EFI_SUCCESS;
}



UINTN
EFIAPI
FindLastRecordOffset(
	IN CONST UINT8* Log,
	IN UINTN Size
	)
{
	UINTN Offset = 0;
	UINTN Last = 0;
	TCG_EVENT_REF Ref;

	if (!SkipLogHeader(Log, Size, &Offset))
		return 0;

	while (Offset < Size && ParseEvent(Log, Size, Offset, &Ref))
	{
		Last = Offset;
		Offset += Ref.RecordSize;
	}
	return Last;
}
