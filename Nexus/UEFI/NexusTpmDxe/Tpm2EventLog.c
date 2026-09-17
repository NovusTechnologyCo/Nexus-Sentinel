/**
 * @file Tpm2EventLog.c
 * @brief TCG crypto-agile event log. Read Tpm2EventLog.h first -- the format and the reasoning
 *        live there.
 *
 * ⚠ LITTLE-ENDIAN THROUGHOUT. The event log is a firmware data structure the OS reads, not TPM
 * wire traffic, so `Tpm2Core`'s big-endian accessors are the WRONG tool in this file. The two
 * formats sit one header apart and getting them backwards produces a log that parses as garbage.
 * Local helpers are used so the mistake cannot be made by reaching for the nearest function.
 */

#include "Tpm2EventLog.h"

//
// Local little-endian writers. Byte-wise for the same reason as the big-endian ones: a log buffer
// carries no alignment guarantee, and a UINT32 store through a misaligned pointer is undefined.
//
STATIC
VOID
LeWrite16(
	OUT UINT8*  P,
	IN  UINT16  V
	)
{
	P[0] = (UINT8)(V);
	P[1] = (UINT8)(V >> 8);
}

STATIC
VOID
LeWrite32(
	OUT UINT8*  P,
	IN  UINT32  V
	)
{
	P[0] = (UINT8)(V);
	P[1] = (UINT8)(V >> 8);
	P[2] = (UINT8)(V >> 16);
	P[3] = (UINT8)(V >> 24);
}

STATIC
VOID
CopyBytes(
	OUT UINT8*       Dst,
	IN  CONST UINT8* Src,
	IN  UINT32       Len
	)
{
	UINT32 i;
	for (i = 0; i < Len; i++)
		Dst[i] = Src[i];
}

//
// The size of one TCG_PCR_EVENT2 entry carrying a single SHA-256 digest:
//
//   PCRIndex  4
//   EventType 4
//   count     4          TPML_DIGEST_VALUES.count
//   algId     2
//   digest    32
//   EventSize 4
//   Event     EventDataLen
//
#define EVENT2_FIXED_SIZE   (4 + 4 + 4 + 2 + TPM2_SHA256_DIGEST_SIZE + 4)

BOOLEAN
Tpm2EventLogInit(
	OUT TPM2_EVENT_LOG* Log,
	OUT UINT8*          Buffer,
	IN  UINT32          Capacity
	)
{
	//
	// The Spec ID event's payload, laid out field by field. Sizes are spelled out rather than
	// taken from sizeof() on EDK2's struct, because that struct has a trailing flexible member and
	// its sizeof does not describe what goes on the wire.
	//
	//   signature[16] + platformClass 4 + minor 1 + major 1 + errata 1 + uintnSize 1
	//   + numberOfAlgorithms 4 + (algId 2 + digestSize 2) * 1 + vendorInfoSize 1
	//
	CONST UINT32 SpecIdSize   = 16 + 4 + 1 + 1 + 1 + 1 + 4 + 4 + 1;
	CONST UINT32 HeaderEntry  = 4 + 4 + 20 + 4 + SpecIdSize;   /* 1.2-format entry */
	UINT8*       P;
	UINT32       i;

	if (Log == NULL || Buffer == NULL)
		return FALSE;

	//
	// ⚠ ZERO THE WHOLE BUFFER FIRST. AllocatePages does not, and for a while nothing else did
	// either -- measured as 13,863 bytes of high-entropy firmware leftovers sitting
	// immediately after the last real entry.
	//
	// (!) A TCG EVENT LOG CARRIES NO LENGTH. Consumers walk it until an entry fails to parse or a
	// zero header appears, so the tail is not spare space -- it is part of the contract. Arbitrary
	// bytes there get READ AS AN ENTRY, which is precisely what our own parser did before this.
	//
	// (!) AND IT IS PUBLISHED. The log lives in EfiACPIMemoryNVS and is handed to the OS, so an
	// unzeroed tail also discloses whatever the firmware last used this memory for.
	//
	// Written as a plain loop because this file depends on nothing but its own header -- that is
	// what lets tools/check_tpm2_core.py compile it on the host with no EDK2 at all.
	//
	{
		UINT32 ZeroWholeBuffer;
		for (ZeroWholeBuffer = 0; ZeroWholeBuffer < Capacity; ZeroWholeBuffer++)
			Buffer[ZeroWholeBuffer] = 0;
	}

	Log->Buffer          = Buffer;
	Log->Capacity        = Capacity;
	Log->Used            = 0;
	Log->LastEntryOffset = 0;
	Log->Count           = 0;
	Log->Truncated       = FALSE;

	if (Capacity < HeaderEntry)
	{
		//
		// Refuse rather than write a partial header. A truncated Spec ID event is worse than an
		// empty buffer: a parser would read a length field that runs past the end.
		//
		Log->Truncated = TRUE;
		return FALSE;
	}

	P = Buffer;

	//
	// ⚠ ENTRY 0 IS IN THE **1.2** FORMAT, DELIBERATELY, even though everything after it is
	// crypto-agile. That is what makes the log safe for a 1.2-only parser: it reads a familiar
	// 20-byte-digest entry, sees EV_NO_ACTION, and stops -- instead of misparsing agile entries as
	// 1.2 ones and walking off into nonsense.
	//
	LeWrite32(P, 0);                       P += 4;   /* PCRIndex  = 0            */
	LeWrite32(P, TPM2_EV_NO_ACTION);       P += 4;   /* EventType = EV_NO_ACTION */

	for (i = 0; i < 20; i++)                         /* Digest[20] = zero        */
		P[i] = 0;
	P += 20;

	LeWrite32(P, SpecIdSize);              P += 4;   /* EventSize                */

	//
	// TCG_EfiSpecIDEventStruct
	//
	{
		CONST CHAR8* Sig = TPM2_SPEC_ID_SIGNATURE;   /* "Spec ID Event03", 15 chars + NUL */
		for (i = 0; i < TPM2_SPEC_ID_SIGNATURE_SIZE; i++)
			P[i] = (UINT8)(i < 15 ? Sig[i] : 0);
		P += TPM2_SPEC_ID_SIGNATURE_SIZE;
	}

	LeWrite32(P, 0);  P += 4;              /* platformClass: 0 = client                     */
	*P++ = 0;                              /* specVersionMinor: 0 for TPM 2.0               */
	*P++ = 2;                              /* specVersionMajor: 2 for TPM 2.0               */
	*P++ = 0;                              /* specErrata                                    */

	//
	// uintnSize: 1 = 32-bit, 2 = 64-bit. This firmware is x64 only -- the version floor and every
	// IA32 path were removed from v2 -- so 2 is a statement of fact rather than a configuration.
	//
	*P++ = 2;

	LeWrite32(P, 1);  P += 4;              /* numberOfAlgorithms: one bank, SHA-256          */
	LeWrite16(P, TPM2_ALG_SHA256);         P += 2;
	LeWrite16(P, TPM2_SHA256_DIGEST_SIZE); P += 2;
	*P++ = 0;                              /* vendorInfoSize: none                           */

	Log->Used            = (UINT32)(P - Buffer);
	Log->LastEntryOffset = 0;
	Log->Count           = 1;

	return TRUE;
}

/**
 * Append one TCG_PCR_EVENT2. Assumes the digest is already computed and the PCR already extended.
 *
 * Returns FALSE and sets Truncated if it does not fit. It NEVER writes a partial entry -- the
 * whole point of the log is that it replays, and a half-written entry makes everything after it
 * unparseable.
 */
STATIC
BOOLEAN
AppendEvent2(
	IN OUT TPM2_EVENT_LOG* Log,
	IN     UINT32          PcrIndex,
	IN     UINT32          EventType,
	IN     CONST UINT8     Digest[TPM2_SHA256_DIGEST_SIZE],
	IN     CONST UINT8*    EventData,
	IN     UINT32          EventDataLen
	)
{
	UINT8* P;
	CONST UINT32 Need = EVENT2_FIXED_SIZE + EventDataLen;

	if (Log->Buffer == NULL)
		return FALSE;

	//
	// Overflow-safe: Need is computed from a bounded fixed size plus a caller length, so check
	// against remaining capacity rather than computing Used + Need, which could wrap.
	//
	if (Need > Log->Capacity || Log->Used > Log->Capacity - Need)
	{
		Log->Truncated = TRUE;
		return FALSE;
	}

	P = Log->Buffer + Log->Used;
	Log->LastEntryOffset = Log->Used;

	LeWrite32(P, PcrIndex);                 P += 4;
	LeWrite32(P, EventType);                P += 4;

	//
	// TPML_DIGEST_VALUES: a count, then one {algId, digest} per active bank. One bank here, and
	// the count is written from that fact rather than hardcoded alongside a loop that might later
	// disagree with it.
	//
	LeWrite32(P, 1);                        P += 4;
	LeWrite16(P, TPM2_ALG_SHA256);          P += 2;
	CopyBytes(P, Digest, TPM2_SHA256_DIGEST_SIZE);
	P += TPM2_SHA256_DIGEST_SIZE;

	LeWrite32(P, EventDataLen);             P += 4;
	if (EventDataLen != 0)
		CopyBytes(P, EventData, EventDataLen);

	Log->Used += Need;
	Log->Count++;
	return TRUE;
}

UINT32
Tpm2EventLogExtendDigest(
	IN OUT TPM2_EVENT_LOG* Log,
	IN OUT TPM2_PCR_BANK*  Bank,
	IN     UINT32          PcrIndex,
	IN     UINT32          EventType,
	IN     CONST UINT8     Digest[TPM2_SHA256_DIGEST_SIZE],
	IN     CONST UINT8*    EventData,
	IN     UINT32          EventDataLen
	)
{
	UINT32 Rc;

	if (Log == NULL || Bank == NULL || Digest == NULL)
		return TPM2_RC_VALUE;
	if (EventData == NULL && EventDataLen != 0)
		return TPM2_RC_VALUE;

	//
	// ⚠ EXTEND FIRST, LOG SECOND, AND REPORT THE EXTEND'S RESULT.
	//
	// If the extend fails there must be no log entry, because an entry describing a measurement
	// that did not happen is exactly the self-inconsistency that makes a log worse than useless.
	// The reverse order could leave one behind on an error path.
	//
	Rc = Tpm2PcrExtend(Bank, PcrIndex, Digest);
	if (Rc != TPM2_RC_SUCCESS)
		return Rc;

	//
	// A full log does NOT undo the extend, and does not turn into an error return. TCG2 specifies
	// that the extend happens regardless; `Log->Truncated` is how the caller learns the log is
	// incomplete. Returning an error here would tell a caller its measurement failed when it did
	// not.
	//
	(VOID)AppendEvent2(Log, PcrIndex, EventType, Digest, EventData, EventDataLen);

	return TPM2_RC_SUCCESS;
}

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
	)
{
	SHA256_CONTEXT Ctx;
	UINT8          Digest[TPM2_SHA256_DIGEST_SIZE];
	UINT32         Rc;
	UINT32         i;

	if (Log == NULL || Bank == NULL)
		return TPM2_RC_VALUE;
	if (Data == NULL && DataLen != 0)
		return TPM2_RC_VALUE;

	//
	// Hash the measured bytes. A zero-length measurement is legal and hashes the empty string --
	// that is a real, well-defined digest, not a special case to reject.
	//
	Sha256Init(&Ctx);
	if (DataLen != 0)
		Sha256Update(&Ctx, Data, DataLen);
	Sha256Final(&Ctx, Digest);

	Rc = Tpm2EventLogExtendDigest(Log, Bank, PcrIndex, EventType,
	                              Digest, EventData, EventDataLen);

	if (OutDigest != NULL && Rc == TPM2_RC_SUCCESS)
	{
		for (i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
			OutDigest[i] = Digest[i];
	}

	return Rc;
}
