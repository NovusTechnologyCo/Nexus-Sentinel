/**
 * @file TpmCrb.c
 * @brief The CRB servicer. See TpmCrb.h for why it exists and why it lives in the kernel.
 *
 * ⚠ THIS IS THE FIRST CODE IN THE PROJECT THAT WRITES MEMORY tpm.sys IS CONCURRENTLY READING.
 * Everything before it either owned its memory outright or only read. The rules that follow from
 * that are not stylistic:
 *
 *   - every access to the shared page is through a volatile pointer, so the compiler cannot cache,
 *     reorder or elide a register access it has no way to know is observed by another agent;
 *   - the command is COPIED OUT before it is parsed and the response COPIED IN after it is built,
 *     so the dispatcher never parses a buffer that the peer may still be writing;
 *   - state bits are written in the order the peer polls them, never the order that reads best.
 */

#include "uefi_shim/Uefi.h"

#include "TpmCrb.h"
#include "LogRing.h"
#include "../../Include/NexusCoreBoot.h"
#include "../../UEFI/NexusTpmDxe/RamCrb.h"
#include "../../UEFI/NexusTpmDxe/TpmState.h"
#include "../../UEFI/NexusTpmDxe/Tpm2Core.h"
#include "../../UEFI/NexusTpmDxe/Tpm2Dispatch.h"
#include "../../UEFI/NexusTpmDxe/Tpm2Entropy.h"
#include "../../UEFI/NexusTpmDxe/Tpm2Primary.h"

//
// (!) LAST, AND THAT POSITION IS THE POINT. This #defines every nt name to route through the
// exported NXC_NT_API pointer table, so the payload emits NO import table -- which the build
// gate enforces and which the manual-map scan depends on (no FF 25 thunks to match).
//
// It must come AFTER the WDK headers that declare those functions, or the declarations
// themselves get rewritten. The first build of this file omitted it entirely and produced seven
// imports -- MmMapIoSpace, MmUnmapIoSpace, KeInitializeDpc, KeInitializeTimer, KeSetTimer,
// KeCancelTimer, KeFlushQueuedDpcs -- caught by `import check` rather than by review.
//
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern volatile NEXUS_CORE_BOOT_BLOCK* NexusCoreBootSlot;

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define CrbLog NxcLogExt

//
// 10 ms. PTP Table 27 gives TIMEOUT_C = 200 ms for Idle->Ready, so this has a 20x margin. Stated
// as a relative 100ns interval -- KeSetTimer reads a negative due time as relative.
//
#define CRB_POLL_INTERVAL_MS   10

STATIC KTIMER   mTimer;
STATIC KDPC     mDpc;
STATIC BOOLEAN  mRunning = FALSE;

STATIC volatile UCHAR* mLoc   = NULL;    // region A, the locality page
STATIC volatile UCHAR* mState = NULL;    // region B, canonical state
STATIC ULONG           mLocSize = 0;
STATIC ULONG           mStateSize = 0;

STATIC TPM2_PCR_BANK*      mBank  = NULL;   // inside region B
STATIC NXC_TPM_CRB_TRACE*  mTrace = NULL;   // inside region B
STATIC ULONG64             mTracePhys = 0;

//
// Staging. The command is copied out of the shared buffer before parsing and the response built
// here before being copied back -- see the file header. NonPaged and preallocated because a DPC
// cannot allocate and cannot touch paged memory.
//
STATIC UCHAR mCmd[CRB_DATA_BUFFER_SIZE];
STATIC UCHAR mRsp[CRB_DATA_BUFFER_SIZE];

//
// ---------------------------------------------------------------------------------------------
// Volatile register access. Written out rather than cast at each site so that no access to the
// shared page can accidentally be made non-volatile.
// ---------------------------------------------------------------------------------------------
//

STATIC ULONG Rd32(ULONG Off)          { return *(volatile ULONG*)(mLoc + Off); }
STATIC void  Wr32(ULONG Off, ULONG V) { *(volatile ULONG*)(mLoc + Off) = V; }
STATIC UCHAR Rd8(ULONG Off)           { return *(volatile UCHAR*)(mLoc + Off); }
STATIC void  Wr8(ULONG Off, UCHAR V)  { *(volatile UCHAR*)(mLoc + Off) = V; }

/*
 * CRC-32 (reflected, poly 0xEDB88320), matching gBS->CalculateCrc32 so the DXE and this driver
 * agree about region B. Computed bitwise: a 1 KB table would be faster and this runs a handful of
 * times per boot over 776 bytes.
 */
STATIC
ULONG
Crc32(
	const void* Data,
	ULONG       Len
	)
{
	const UCHAR* P = (const UCHAR*)Data;
	ULONG Crc = 0xFFFFFFFFul;
	ULONG i, b;

	for (i = 0; i < Len; i++)
	{
		Crc ^= P[i];
		for (b = 0; b < 8; b++)
			Crc = (Crc >> 1) ^ (0xEDB88320ul & (ULONG)(-(LONG)(Crc & 1)));
	}
	return ~Crc;
}

/*
 * Does the full-capture buffer already hold an example of this command code?
 *
 * (!) ONE EXAMPLE EACH, NOT N COPIES OF THE LOUDEST -- and this is the survivorship problem
 * again, in the one buffer that was supposed to be immune to it.
 *
 * The boot answered TPM_RC_HANDLE to ten NV_ReadPublic calls and TPM_RC_TYPE to two
 * CreatePrimary calls. Every capture slot went to the HANDLE answers -- which are CORRECT, and
 * which we already understood -- and the two that named an unimplemented key type never got one.
 * The buffer filled with the most FREQUENT problem instead of the most INFORMATIVE.
 *
 * That is the same division of labour the census already encodes: counters say HOW MANY, and the
 * buffer says WHAT IT LOOKED LIKE. A second copy of a command whose shape is already recorded
 * adds nothing and costs the slot that a different problem needed.
 */
STATIC
BOOLEAN
FullAlreadyHas(
	ULONG CommandCode
	)
{
	ULONG Used = mTrace->FullWritten;
	ULONG i;

	if (Used > NXC_TPM_CRB_FULL_SLOTS)
		Used = NXC_TPM_CRB_FULL_SLOTS;
	for (i = 0; i < Used; i++)
		if (mTrace->Full[i].CommandCode == CommandCode)
			return TRUE;
	return FALSE;
}

/*
 * Re-seal region B after the bank changes.
 *
 * ⚠ PAYLOAD FIRST, HEADER SECOND. HeaderCrc covers PayloadChecksum, so reversing the order yields
 * a header whose CRC certifies a stale payload checksum -- a region that validates and is wrong.
 * The DXE's SyncCanonicalState has the same note for the same reason.
 */
STATIC
void
ResealState(void)
{
	NEXUS_TPM_STATE_HEADER* H = (NEXUS_TPM_STATE_HEADER*)mState;

	if (H == NULL || H->PayloadLength == 0)
		return;

	H->PayloadChecksum = Crc32((const UCHAR*)mState + H->HeaderSize, H->PayloadLength);
	H->HeaderCrc = Crc32((const void*)mState, (ULONG)OFFSET_OF(NEXUS_TPM_STATE_HEADER, HeaderCrc));
}

/*
 * Which census bucket a command code belongs to.
 *
 * (!) NOTHING IS DROPPED. A code outside the window lands in the catch-all rather than being
 * discarded, because "Windows sent something we do not have a bucket for" is a finding and
 * silence would hide it. That includes vendor codes, which have the high bit set and would
 * otherwise index far past the end of the array.
 */
/*
 * Milliseconds since the servicer started, for TPM2_ReadClock.
 *
 * (!) KeQueryPerformanceCounter REPORTS ITS OWN FREQUENCY, WHICH IS WHY IT IS USED HERE. The
 * obvious alternative is a TSC delta over a hardcoded frequency, and this codebase already
 * measured that going wrong: `EntryDurationUs` divided by an assumed 3 GHz and swung 6x across
 * boots doing identical work. Clock ends up inside signed attestation structures, so a value
 * that is wrong by a factor of six is a signature that verifies over a lie.
 *
 * ⚠ THE ORIGIN IS THE SERVICER START, NOT THE EPOCH. TPMS_TIME_INFO.time is defined as
 * milliseconds since the Time circuit was last reset, and for this TPM that moment is when the
 * servicer began answering. Anchoring to anything else would report a duration nothing here
 * actually measured.
 *
 * Safe at DISPATCH_LEVEL, which is where the DPC calls it.
 */
STATIC LARGE_INTEGER mClockOrigin;
STATIC LONG64        mClockFreq;

/*
 * The primary seeds, copied out of region B at start.
 *
 * (!) COPIED, NOT POINTED AT. Region B is mapped MmNonCached and shared with tpm.sys; reading
 * a seed through that mapping on every key derivation would be slow and, worse, would read
 * whatever is there NOW rather than what the DXE published. The seeds do not change during a
 * boot, so one copy at start is both faster and the only version that can be trusted.
 */
STATIC NEXUS_TPM_SEEDS mSeeds;

/*
 * (!) A HIERARCHY WITH NO SEED RETURNS FALSE, and TPM2_CreatePrimary then answers
 * TPM_RC_FAILURE. No seed, no key, never an invented one.
 */
STATIC
BOOLEAN
CrbSeedSource(
	UINT32 Hierarchy,
	UINT8* Seed,
	UINT32 SeedLen
	)
{
	CONST UCHAR* Src;
	ULONG i;

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

	for (i = 0; i < SeedLen; i++)
		Seed[i] = Src[i];
	return TRUE;
}

STATIC
BOOLEAN
CrbMillis(
	ULONG64* Out
	)
{
	LARGE_INTEGER Now;

	if (Out == NULL || mClockFreq <= 0)
		return FALSE;

	Now = KeQueryPerformanceCounter(NULL);

	//
	// Multiply BEFORE dividing, and in 64 bits. Dividing first would quantise every answer to
	// whole seconds at a 10 MHz counter, which is the resolution ReadClock is being asked for.
	//
	*Out = (ULONG64)(((Now.QuadPart - mClockOrigin.QuadPart) * 1000LL) / mClockFreq);
	return TRUE;
}

STATIC
ULONG
CensusBucket(
	ULONG CommandCode
	)
{
	ULONG Index;

	if (CommandCode < NXC_TPM_CRB_CENSUS_FIRST)
		return NXC_TPM_CRB_CENSUS_OTHER;

	Index = CommandCode - NXC_TPM_CRB_CENSUS_FIRST;
	if (Index >= NXC_TPM_CRB_CENSUS_OTHER)
		return NXC_TPM_CRB_CENSUS_OTHER;

	return Index;
}

/*
 * Fill one record. Shared by both rings so a refusal is described exactly the way the same
 * command would be described in the main ring -- two formats would mean two decoders, and the
 * decoders would drift.
 */
STATIC
void
FillRecord(
	NXC_TPM_CRB_RECORD*       R,
	ULONG                     Sequence,
	const TPM2_DISPATCH_INFO* Info,
	const UCHAR*              Head,
	ULONG                     HeadLen,
	const UCHAR*              Rsp,
	ULONG                     RspLen
	)
{
	ULONG i;

	R->Tsc          = __rdtsc();
	R->Sequence     = Sequence;
	R->CommandCode  = Info->CommandCode;
	R->CommandSize  = Info->CommandSize;
	R->InputSize    = Info->InputSize;
	R->ResponseCode = Info->ResponseCode;
	R->ResponseSize = Info->ResponseSize;
	R->Tag          = Info->Tag;
	R->Reserved     = 0;

	for (i = 0; i < sizeof(R->Head); i++)
		R->Head[i] = (i < HeadLen && Head != NULL) ? Head[i] : 0;

	//
	// (!) PADDED WITH ZERO, NOT LEFT ALONE. These records are reused as the ring turns over, so
	// a short response that only overwrote the first few bytes would otherwise be read together
	// with the tail of whatever occupied the slot before it.
	//
	for (i = 0; i < sizeof(R->Rsp); i++)
		R->Rsp[i] = (i < RspLen && Rsp != NULL) ? Rsp[i] : 0;
}

STATIC
void
TraceRecord(
	const TPM2_DISPATCH_INFO* Info,
	const UCHAR*              Head,
	ULONG                     HeadLen,
	const UCHAR*              Rsp,
	ULONG                     RspLen
	)
{
	NXC_TPM_CRB_CENSUS* C;
	ULONG Slot;

	if (mTrace == NULL)
		return;

	//
	// THE CENSUS FIRST, because it is the part that must survive. Both rings can turn over
	// within a single boot; these counters cannot, and they are what the next phase is scoped
	// from.
	//
	C = &mTrace->Census[CensusBucket(Info->CommandCode)];
	if (C->Count == 0)
		C->FirstRc = Info->ResponseCode;
	C->Count  = C->Count + 1;
	C->LastRc = Info->ResponseCode;

	//
	// (!) TPM_RC_COMMAND_CODE IS THE ONLY ANSWER THAT MEANS WE ARE MISSING SOMETHING. Every
	// other non-SUCCESS code is an answer -- often the CORRECT one, as TPM_RC_HANDLE is for an
	// object that does not exist. Counting them together made 70 correct answers look like
	// refusals and pushed the 4 that mattered out of the ring.
	//
	//
	// (!) THE ACCOUNTING IS A CLOSED IF/ELSE AND THE CAPTURE IS A SEPARATE TEST. Keeping them
	// welded together is what broke the Errored counter: the capture trigger widened from
	// "COMMAND_CODE" to "not SUCCESS", and the `else` that had counted everything else suddenly
	// meant "SUCCESS" -- so Errored read ZERO on a boot with 26 errors in it, while the per-command
	// rows underneath listed them. A header contradicting its own table is worse than either.
	//
	if (Info->ResponseCode == TPM2_RC_COMMAND_CODE)
	{
		C->Unimplemented = C->Unimplemented + 1;
		mTrace->Unimplemented = mTrace->Unimplemented + 1;
	}
	else if (Info->ResponseCode != TPM2_RC_SUCCESS)
	{
		C->Errored = C->Errored + 1;
		mTrace->Errored = mTrace->Errored + 1;
	}

	//
	// (!) FULL CAPTURE NOW COVERS ANY NON-SUCCESS ANSWER, NOT ONLY "we do not have that command".
	//
	// The boot answered every command Windows sent -- unimplemented reached ZERO -- and
	// the 2 KB capture buffer, which exists to show what to build next, went idle on exactly the
	// boot where the interesting commands became the ones we ERROR on. TPM2_CreatePrimary answered
	// TPM_RC_TYPE on parameter 2 twice, meaning Windows asked for a key type we do not implement,
	// and the census could say THAT but not say WHICH: the ring keeps 32 octets and a TPMT_PUBLIC
	// template does not start until later.
	//
	// So the trigger moves from "missing" to "not SUCCESS". Refusals stay first in the buffer by
	// arriving first; nothing else changes.
	//
	if (Info->ResponseCode != TPM2_RC_SUCCESS && !FullAlreadyHas(Info->CommandCode))
	{

		//
		// The "implement this" ring. Sequence is the MAIN ring sequence, so the record can be
		// located in the surrounding traffic while the main ring still holds it.
		//
		NXC_TPM_CRB_FULL* F;
		ULONG Take;
		ULONG i;

		Slot = mTrace->FullWritten % NXC_TPM_CRB_FULL_SLOTS;
		F = &mTrace->Full[Slot];

		F->Tsc          = __rdtsc();
		F->Sequence     = mTrace->Written;
		F->CommandCode  = Info->CommandCode;
		F->CommandSize  = Info->CommandSize;
		F->ResponseCode = Info->ResponseCode;
		F->Reserved     = 0;

		//
		// (!) CLAMP TO WHAT WE WERE HANDED, NOT TO WHAT THE HEADER CLAIMS. A command declaring
		// more than it delivered is exactly the malformed case worth recording, and trusting
		// CommandSize here would read past the end of the buffer to record it.
		//
		Take = Info->InputSize;
		if (Take > HeadLen)
			Take = HeadLen;
		if (Take > NXC_TPM_CRB_FULL_BYTES)
			Take = NXC_TPM_CRB_FULL_BYTES;
		F->Captured = Take;

		for (i = 0; i < NXC_TPM_CRB_FULL_BYTES; i++)
			F->Command[i] = (i < Take && Head != NULL) ? Head[i] : 0;

		mTrace->FullWritten = mTrace->FullWritten + 1;
	}

	Slot = mTrace->Written % NXC_TPM_CRB_TRACE_SLOTS;
	FillRecord(&mTrace->Slot[Slot], mTrace->Written, Info, Head, HeadLen, Rsp, RspLen);

	//
	// Written LAST, so a reader that catches the ring mid-update sees a complete record or an old
	// one, never half of a new one.
	//
	mTrace->Written = mTrace->Written + 1;
}

/*
 * One poll. Runs at DISPATCH_LEVEL.
 *
 * ⚠ THE ORDER OF THE STATE WRITES IS THE CONTRACT, not a preference. Software polls for the
 * acknowledgement bit; if the acknowledgement is visible before the state it announces, the peer
 * can observe "Ready" while the status register still says Idle.
 */
STATIC
void
ServiceOnce(void)
{
	ULONG Req;
	ULONG Start;
	ULONG LocCtrl;

	if (mTrace != NULL)
		mTrace->Polls = mTrace->Polls + 1;

	//
	// ---- locality ------------------------------------------------------------------------
	//
	// PTP Table 40: Granted SHALL be set when LOC_STATE.locAssigned is set for a locality that
	// requested access. We are locality-0-only, so a request is always grantable.
	//
	LocCtrl = Rd32(CRB_OFF_LOC_CTRL);
	if (LocCtrl != 0)
	{
		if (LocCtrl & CRB_LOC_CTRL_REQUEST_ACCESS)
		{
			Wr8(CRB_OFF_LOC_STATE,
			    (UCHAR)(CRB_LOC_STATE_TPM_REG_VALID | CRB_LOC_STATE_LOC_ASSIGNED));
			Wr32(CRB_OFF_LOC_STS, 1u);            /* Granted */
		}
		else if (LocCtrl & CRB_LOC_CTRL_RELINQUISH)
		{
			Wr32(CRB_OFF_LOC_STS, 0u);
			Wr8(CRB_OFF_LOC_STATE, (UCHAR)CRB_LOC_STATE_TPM_REG_VALID);
		}
		//
		// Cleared last: the peer treats the write as consumed once this reads back 0, so clearing
		// it before the state it requested is visible would advertise a transition that has not
		// happened yet.
		//
		Wr32(CRB_OFF_LOC_CTRL, 0u);
		if (mTrace != NULL)
			mTrace->Serviced = mTrace->Serviced + 1;
	}

	//
	// ---- Idle <-> Ready ------------------------------------------------------------------
	//
	Req = Rd32(CRB_OFF_CTRL_REQ);
	if (Req != 0)
	{
		//
		// ⚠ NORMATIVE, PTP §6.5.3.6.1: "For each write to this register, there SHALL be only one
		// field set to a 1. If a TPM receives a write with more than one field set, the TPM SHALL
		// ignore the entire cycle." Ignoring means leaving the register alone, not picking one.
		//
		CONST ULONG Both = CRB_REQ_COMMAND_READY | CRB_REQ_GO_IDLE;
		if ((Req & Both) == Both)
		{
			/* leave it exactly as written; the peer will time out and retry, which is correct */
		}
		else if (Req & CRB_REQ_COMMAND_READY)
		{
			Wr32(CRB_OFF_CTRL_STS, Rd32(CRB_OFF_CTRL_STS) & ~CRB_STS_TPM_IDLE);
			Wr32(CRB_OFF_CTRL_REQ, Req & ~CRB_REQ_COMMAND_READY);
			if (mTrace != NULL)
				mTrace->Serviced = mTrace->Serviced + 1;
		}
		else if (Req & CRB_REQ_GO_IDLE)
		{
			Wr32(CRB_OFF_CTRL_STS, Rd32(CRB_OFF_CTRL_STS) | CRB_STS_TPM_IDLE);
			Wr32(CRB_OFF_CTRL_REQ, Req & ~CRB_REQ_GO_IDLE);
			if (mTrace != NULL)
				mTrace->Serviced = mTrace->Serviced + 1;
		}
	}

	//
	// ---- a command ------------------------------------------------------------------------
	//
	Start = Rd32(CRB_OFF_CTRL_START);
	if (Start & CRB_START_BIT)
	{
		TPM2_DISPATCH_INFO Info;
		ULONG Declared;
		ULONG Take;
		ULONG Written;
		ULONG i;

		//
		// Copy the request OUT before parsing it. The peer has finished writing (it set Start), but
		// parsing in place would leave the dispatcher reading a buffer we do not control, and the
		// dispatcher's bounds checks are written against a buffer that cannot change underneath.
		//
		for (i = 0; i < sizeof(mCmd); i++)
			mCmd[i] = *(volatile UCHAR*)(mLoc + CRB_OFF_DATA_BUFFER + i);

		//
		// Trust the header's length only as far as the buffer allows. A declared size larger than
		// the buffer is a malformed command, and the dispatcher is given the smaller figure so it
		// can say so rather than read past the end.
		//
		Declared = ((ULONG)mCmd[2] << 24) | ((ULONG)mCmd[3] << 16) |
		           ((ULONG)mCmd[4] << 8)  | (ULONG)mCmd[5];
		Take = (Declared != 0 && Declared <= sizeof(mCmd)) ? Declared : (ULONG)sizeof(mCmd);

		Written = Tpm2Dispatch(mBank, mCmd, Take, mRsp, (UINT32)sizeof(mRsp), &Info);

		for (i = 0; i < Written; i++)
			*(volatile UCHAR*)(mLoc + CRB_OFF_DATA_BUFFER + i) = mRsp[i];

		ResealState();
		//
		// (!) THE WHOLE BUFFER, NOT 32 BYTES. TraceRecord still stores only 32 in the main ring
		// record; the full-capture ring needs the rest, and it can only keep what it is given.
		//
		TraceRecord(&Info, mCmd, (ULONG)sizeof(mCmd), mRsp, Written);

		//
		// ⚠ START IS CLEARED LAST, AND THAT IS THE HANDSHAKE. PTP §6.5.3: Command Execution lasts
		// "after receipt of a 1 to Start and prior to the TPM clearing Start to 0". Clearing it
		// before the response bytes are in place would tell the peer to read a buffer we have not
		// finished writing.
		//
		Wr32(CRB_OFF_CTRL_START, Start & ~CRB_START_BIT);
	}
}

STATIC
KDEFERRED_ROUTINE PollDpc;

STATIC
void
ArmTimer(void)
{
	LARGE_INTEGER Due;

	Due.QuadPart = -(LONGLONG)CRB_POLL_INTERVAL_MS * 10000;   /* relative, 100ns units */
	KeSetTimer(&mTimer, Due, &mDpc);
}

STATIC
void
PollDpc(
	_In_ PKDPC Dpc,
	_In_opt_ PVOID Context,
	_In_opt_ PVOID Arg1,
	_In_opt_ PVOID Arg2
	)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Arg1);
	UNREFERENCED_PARAMETER(Arg2);

	if (!mRunning || mLoc == NULL)
		return;

	ServiceOnce();

	//
	// ⚠ RE-ARM FROM THE DPC, because the nt call table has KeSetTimer but not KeSetTimerEx --
	// one-shot, not periodic. Adding the Ex variants is mechanically easy and not free: the DXE
	// resolves every name in NXC_NT_API_LIST from ntoskrnl and REFUSES THE WHOLE MAP if one
	// fails, so each new entry is a new way for NexusCore not to load at all.
	//
	// The mRunning check above is what makes this safe against Stop(): a DPC that runs after
	// Stop has cleared the flag returns here without re-arming.
	//
	ArmTimer();
}

NTSTATUS
NxcTpmCrbStart(void)
{
	volatile NEXUS_CORE_BOOT_BLOCK* CONST Block = NexusCoreBootSlot;
	NEXUS_TPM_STATE_HEADER* H;
	PHYSICAL_ADDRESS Pa;
	LARGE_INTEGER Freq;
	ULONG64 LocPhys, StatePhys;
	ULONG LocLen, StateLen;

	if (mRunning)
		return STATUS_SUCCESS;

	if (Block == NULL)
	{
		CrbLog("no boot block; nothing to service\n");
		return STATUS_NOT_FOUND;
	}

	LocPhys   = Block->TpmTransportBase;
	LocLen    = Block->TpmTransportSize;
	StatePhys = Block->TpmStateBase;
	StateLen  = Block->TpmStateSize;

	if (Block->TpmBootEpoch == 0 || LocPhys == 0 || LocLen == 0 || StatePhys == 0 || StateLen == 0)
	{
		CrbLog("DXE published no TPM regions this boot\n");
		return STATUS_NOT_FOUND;
	}

	if (StateLen < NXC_TPM_CRB_TRACE_OFFSET + sizeof(NXC_TPM_CRB_TRACE))
	{
		CrbLog("region B too small for header + trace (%u bytes)\n", StateLen);
		return STATUS_BUFFER_TOO_SMALL;
	}

	//
	// MmMapIoSpace, MmNonCached -- the same reasoning as PhysMem.c. The memory is EfiACPIMemoryNVS
	// and therefore absent from Windows' PFN database, so MmCopyMemory cannot reach it; and it is
	// shared with tpm.sys, so a cached mapping could satisfy a read from a stale line and report
	// "no request" when there was one.
	//
	Pa.QuadPart = (LONGLONG)LocPhys;
	mLoc = (volatile UCHAR*)MmMapIoSpace(Pa, LocLen, MmNonCached);
	if (mLoc == NULL)
	{
		CrbLog("MmMapIoSpace(locality 0x%llX +%u) FAILED\n", LocPhys, LocLen);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Pa.QuadPart = (LONGLONG)StatePhys;
	mState = (volatile UCHAR*)MmMapIoSpace(Pa, StateLen, MmNonCached);
	if (mState == NULL)
	{
		MmUnmapIoSpace((PVOID)mLoc, LocLen);
		mLoc = NULL;
		CrbLog("MmMapIoSpace(state 0x%llX +%u) FAILED\n", StatePhys, StateLen);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	mLocSize = LocLen;
	mStateSize = StateLen;

	//
	// ⚠ REFUSE A REGION THAT IS NOT OURS. The header was written by the DXE this same boot; a
	// mismatch means something overwrote it, and servicing commands out of memory we cannot
	// identify would answer the OS from whatever happens to be there.
	//
	H = (NEXUS_TPM_STATE_HEADER*)mState;
	if (H->Magic != NEXUS_TPM_STATE_MAGIC || H->HeaderSize != sizeof(NEXUS_TPM_STATE_HEADER))
	{
		CrbLog("region B header is not ours (magic 0x%llX) -- refusing to service\n", H->Magic);
		NxcTpmCrbStop();
		return STATUS_INVALID_DEVICE_STATE;
	}
	if (H->PayloadLength < sizeof(TPM2_PCR_BANK))
	{
		CrbLog("region B has no PCR bank (PayloadLength %u) -- refusing to service\n",
		       H->PayloadLength);
		NxcTpmCrbStop();
		return STATUS_INVALID_DEVICE_STATE;
	}

	mBank  = (TPM2_PCR_BANK*)((UCHAR*)mState + H->HeaderSize);
	mTrace = (NXC_TPM_CRB_TRACE*)((UCHAR*)mState + NXC_TPM_CRB_TRACE_OFFSET);
	mTracePhys = StatePhys + NXC_TPM_CRB_TRACE_OFFSET;

	//
	// A byte loop rather than RtlZeroMemory, which is not in the nt call table. Once at startup
	// over 4 KB; adding a table entry to save it would be a poor trade for the reason above.
	//
	{
		volatile UCHAR* Z = (volatile UCHAR*)mTrace;
		ULONG zi;
		for (zi = 0; zi < sizeof(*mTrace); zi++)
			Z[zi] = 0;
	}
	mTrace->Magic       = NXC_TPM_CRB_TRACE_MAGIC;
	mTrace->Version     = NXC_TPM_CRB_TRACE_VERSION;
	mTrace->SlotCount   = NXC_TPM_CRB_TRACE_SLOTS;
	mTrace->FullSlotCount = NXC_TPM_CRB_FULL_SLOTS;
	mTrace->FullBytes     = NXC_TPM_CRB_FULL_BYTES;
	mTrace->CensusFirst = NXC_TPM_CRB_CENSUS_FIRST;
	mTrace->CensusSlots = NXC_TPM_CRB_CENSUS_SLOTS;
	//
	// Sizes are published so the reader walks the arrays with our figures rather than its own.
	//
	mTrace->RecordSize  = (ULONG)sizeof(NXC_TPM_CRB_RECORD);
	mTrace->CensusSize  = (ULONG)sizeof(NXC_TPM_CRB_CENSUS);

	//
	// Install the entropy source before any command can be dispatched (kernel: post-ExitBootServices commands arrive over the CRB).
	// Without it TPM2_GetRandom answers TPM_RC_FAILURE rather than fabricating bytes.
	//
	Tpm2SetEntropySource(Tpm2RdrandEntropy);

	//
	// The clock, on the same rule: installed before any command can arrive, and if the counter
	// is unavailable TPM2_ReadClock answers TPM_RC_FAILURE rather than reporting a made-up time.
	//
	mClockOrigin = KeQueryPerformanceCounter(&Freq);
	mClockFreq   = Freq.QuadPart;
	Tpm2SetTimeSource(CrbMillis);

	//
	// The primary seeds the DXE published in region B, on the same rule as the two above:
	// installed before any command can arrive, and absent means CreatePrimary REFUSES.
	//
	// (!) THE PAYLOAD IS CHECKED BEFORE THE SEEDS ARE READ. A version-3 DXE publishes a
	// payload with no seed block at all, and reading past PayloadLength would hand a key
	// derivation whatever bytes happened to follow -- a seed that looks fine and is not.
	//
	{
		CONST NEXUS_TPM_STATE_HEADER* Sh = (CONST NEXUS_TPM_STATE_HEADER*)mState;
		CONST ULONG Need = (ULONG)(sizeof(TPM2_PCR_BANK) + sizeof(NEXUS_TPM_EXTEND_STATS) +
		                           sizeof(NEXUS_TPM_SEEDS));

		RtlZeroMemory(&mSeeds, sizeof(mSeeds));

		if (Sh->Version >= 4 && Sh->PayloadLength >= Need &&
		    (ULONG)Sh->HeaderSize + Need <= StateLen)
		{
			CONST UCHAR* P = (CONST UCHAR*)mState + Sh->HeaderSize +
			                 sizeof(TPM2_PCR_BANK) + sizeof(NEXUS_TPM_EXTEND_STATS);
			ULONG k;

			for (k = 0; k < sizeof(mSeeds); k++)
				((UCHAR*)&mSeeds)[k] = P[k];
		}

		Tpm2ObjectStoreReset();
		if (mSeeds.Magic == NEXUS_TPM_SEEDS_MAGIC)
		{
			Tpm2SetSeedSource(CrbSeedSource);
			CrbLog("primary seeds loaded from region B (flags 0x%08X)\n", mSeeds.Flags);
		}
		else
		{
			CrbLog("NO primary seeds in region B (version %u, payload %u);"
			       " CreatePrimary will refuse\n", Sh->Version, Sh->PayloadLength);
		}
	}

	KeInitializeDpc(&mDpc, PollDpc, NULL);
	KeInitializeTimer(&mTimer);
	mRunning = TRUE;
	ArmTimer();

	CrbLog("servicing locality 0x%llX (+%u), state 0x%llX (+%u), trace 0x%llX, every %u ms\n",
	       LocPhys, LocLen, StatePhys, StateLen, mTracePhys, CRB_POLL_INTERVAL_MS);
	return STATUS_SUCCESS;
}

void
NxcTpmCrbStop(void)
{
	if (mRunning)
	{
		//
		// ⚠ CLEAR THE FLAG FIRST, THEN CANCEL TWICE AROUND THE FLUSH. A DPC already in flight can
		// re-arm the timer between the cancel and the flush; it reads mRunning first, so clearing
		// the flag closes the window, and the second cancel collects a re-arm that slipped
		// through anyway. Cheap, and the alternative is a timer firing into an unmapped page.
		//
		mRunning = FALSE;
		KeCancelTimer(&mTimer);
		KeFlushQueuedDpcs();
		KeCancelTimer(&mTimer);
	}

	if (mState != NULL)
	{
		MmUnmapIoSpace((PVOID)mState, mStateSize);
		mState = NULL;
	}
	if (mLoc != NULL)
	{
		MmUnmapIoSpace((PVOID)mLoc, mLocSize);
		mLoc = NULL;
	}
	mBank = NULL;
	mTrace = NULL;
	mTracePhys = 0;
}

ULONG64
NxcTpmCrbTracePhys(void)
{
	return mRunning ? mTracePhys : 0;
}
