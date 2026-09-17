/**
 * @file LogRing.c
 * @brief Lock-free event ring. Read LogRing.h first -- the tearing and overrun rules matter.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "LogRing.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);

C_ASSERT((NXC_LOG_ENTRIES & (NXC_LOG_ENTRIES - 1)) == 0);   /* power of two -- see the header */
#define NXC_LOG_MASK   (NXC_LOG_ENTRIES - 1u)

/*
 * ⚠ STATIC, NOT ALLOCATED. The ring must be writable from a hook site, where an allocation failure
 * has nowhere to go and an allocator call could re-enter whatever was interposed on. A static array
 * in the driver's own data is always there, always mapped, and needs no init to be safe to touch.
 *
 * 1024 entries x 56 bytes = 56 KB of the image, which is the price of never failing.
 */
static NXCMD_LOG_ENTRY   gRing[NXC_LOG_ENTRIES];
static volatile LONG64   gNextSeq = 1;        /* sequence 0 means "empty slot", never issued */
static volatile LONG     gRingReady = 0;

NTSTATUS
NxcLogRingInit(
	void
	)
{
	if (InterlockedCompareExchange(&gRingReady, 1, 0) != 0)
		return STATUS_SUCCESS;    /* idempotent */

	RtlZeroMemory(gRing, sizeof(gRing));
	gNextSeq = 1;
	NxcLogExt("logring: %u entries, %u bytes\n", NXC_LOG_ENTRIES, (ULONG)sizeof(gRing));
	return STATUS_SUCCESS;
}

void
NxcLogRingWrite(
	_In_ UINT32 Kind,
	_In_ UINT64 A,
	_In_ UINT64 B,
	_In_ UINT64 C
	)
{
	/*
	 * No lock, no allocation, no call out of this function. A hook runs in whatever context it
	 * interposed on -- possibly at raised IRQL, possibly inside the allocator or logger a lock would
	 * reach into -- so anything that could block or re-enter is a deadlock against code we do not
	 * control.
	 */
	CONST UINT64 Seq = (UINT64)InterlockedIncrement64(&gNextSeq) - 1;
	NXCMD_LOG_ENTRY* CONST E = &gRing[Seq & NXC_LOG_MASK];

	/*
	 * ⚠ SEQUENCE IS WRITTEN LAST, and the order is the only tearing protection there is. A reader
	 * can catch this slot mid-write; if it sees a sequence that does not match the slot it is
	 * reading, the entry is still being filled and must be skipped rather than believed.
	 *
	 * Cleared FIRST for the same reason -- a stale sequence from the previous lap would make a
	 * half-written entry look complete.
	 */
	E->Sequence  = 0;
	E->Kind      = Kind;
	E->A         = A;
	E->B         = B;
	E->C         = C;
	E->Timestamp = __rdtsc();
	E->Cpu       = KeGetCurrentProcessorNumberEx(NULL);
	E->ProcessId = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();

	/*
	 * ⚠ THE ORDER ABOVE IS THE ONLY TEARING PROTECTION, AND UNTIL NOW NOTHING ENFORCED IT.
	 *
	 * These are plain non-volatile stores. The C abstract machine is free to sink `E->Sequence`
	 * above `E->Cpu` / `E->ProcessId`, and a reader would then match the sequence at BOTH of its
	 * checks while copying a payload still carrying the previous lap's identity -- one event's
	 * identity on another event's data, which the header calls worse than dropping entries.
	 *
	 * It does not happen today, and the reason is an accident rather than a guarantee: the two
	 * external calls just above are opaque to the optimiser and act as implicit barriers, and x64 is
	 * store-ordered so the hardware never reorders. Enabling LTO/PGO, changing compiler, or
	 * inlining those calls removes that accident silently.
	 *
	 * `_WriteBarrier` is compile-time only -- it emits no instruction on x64 and costs nothing at
	 * run time.; the invariant was documented and unenforced.
	 */
	_WriteBarrier();
	E->Sequence  = Seq;
}

NTSTATUS
NxcLogRingDrain(
	_In_ UINT64 Since,
	_Out_writes_(Cap) NXCMD_LOG_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Lost,
	_Out_ UINT64* Head
	)
{
	*Got  = 0;
	*Lost = 0;
	*Head = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST UINT64 Next = (UINT64)gNextSeq;      /* one past the newest issued sequence */
	*Head = Next;

	if (Next <= 1)
		return STATUS_SUCCESS;                 /* nothing has ever been written */

	CONST UINT64 Newest = Next - 1;

	/*
	 * The oldest sequence STILL RESIDENT. Anything older has been overwritten by a later lap, which
	 * is the overrun the caller has to be told about.
	 */
	CONST UINT64 Oldest = (Newest >= NXC_LOG_ENTRIES) ? (Newest - NXC_LOG_ENTRIES + 1) : 0;

	UINT64 From = (Since >= Oldest) ? (Since + 1) : Oldest;

	/*
	 * ⚠ LOST IS COMPUTED, NOT GUESSED. If the caller's last-seen sequence is older than what still
	 * exists, the difference is exactly how many entries were overwritten before they got to them.
	 * Reporting that is the difference between an incomplete log and a MISLEADING one.
	 */
	if (Since != 0 && Since + 1 < Oldest)
		*Lost = (UINT32)((Oldest - (Since + 1)) > 0xFFFFFFFFULL
		                 ? 0xFFFFFFFFULL : (Oldest - (Since + 1)));

	UINT32 n = 0;
	for (UINT64 s = From; s <= Newest && n < Cap; s++)
	{
		CONST NXCMD_LOG_ENTRY* CONST E = &gRing[s & NXC_LOG_MASK];

		/*
		 * Skip a slot whose sequence does not match what belongs there: it is either mid-write (the
		 * writer has not published its sequence yet) or has already been reused by a later lap while
		 * we walked. Either way it is not the entry we are looking for, and copying it would report
		 * one event's data under another's identity.
		 */
		if (E->Sequence != s)
			continue;

		Out[n] = *E;

		/* Re-check AFTER the copy. If the sequence changed underneath us the copy is torn, so drop
		 * it rather than hand back a blend of two events.
		 *
		 * ⚠ THE BARRIER IS WHAT MAKES THIS A RE-CHECK. Without it the compiler is entitled to
		 * common-subexpression the two `E->Sequence` loads into one -- `E` is a plain const pointer,
		 * not volatile -- and the second test would then be comparing the FIRST load's value, which
		 * always matches and detects nothing. Compile-time only; free on x64. */
		_ReadBarrier();
		if (E->Sequence != s)
			continue;

		n++;
	}

	*Got = n;
	return STATUS_SUCCESS;
}
