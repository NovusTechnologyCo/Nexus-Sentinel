/**
 * @file Capture.c
 * @brief Image-load watch and pristine capture. Rationale and the hard constraint live in Capture.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Capture.h"
#include "Arena.h"
#include "../../Include/NexusCoreBoot.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define CapLog NxcLogExt

/*
 * Watch entries. Small and static: this is consulted on EVERY image load in the system, so it must
 * be cheap and must never allocate on that path.
 */
#define NXC_MAX_WATCH        8u
#define NXC_WATCH_NAME_MAX  64u

/*
 * Refuse to capture anything larger than this. a large anti-tamper kernel module is ~1.4 MB; the cap is generous
 * for a real target and still bounds the damage if a watch name matches something enormous.
 *
 * ⚠ THE ARENA IS 16 MB AND IS SHARED with every mapped module. A capture is a PERMANENT tenant --
 * nothing frees it -- so an unbounded capture would quietly consume the space modules need and the
 * symptom would be a map failing much later for no visible reason.
 */
#define NXC_CAPTURE_MAX     (8u * 1024u * 1024u)

/*
 * ============================================================================================
 * ⚠ SLOT STATES AND THE LOCK -- ADDED WITH `capture clear`, AND REQUIRED BY IT
 * ============================================================================================
 *
 * This table was previously lock-free and used `Name[0] == '\0'` to mean "free". That was SAFE ONLY
 * WHILE NOTHING COULD RELEASE A SLOT: entries were added and captured, never removed, so the notify
 * callback and the command path could never disagree about what a slot meant.
 *
 * `capture clear` breaks that, and not in a way that merely leaks:
 *
 *   1. The notify claims slot i and starts copying an image into a fresh arena buffer.
 *   2. A command clears slot i. PristineBase is still 0, so it frees nothing.
 *   3. `watch` reuses slot i for a DIFFERENT module -- it looks free.
 *   4. The notify finishes and writes its PristineBase into slot i.
 *
 * The new watch is now marked captured, holding the OLD module's pristine bytes under the NEW
 * module's name. Every later `read --pristine` answers confidently from the wrong image, and nothing
 * anywhere reports an error. That is the worst failure this codebase can produce, so `clear` could
 * not be added until the table could express "in flight".
 *
 * A GENERATION COUNTER, not just a state, because a state alone cannot tell "still my slot" from
 * "cleared and re-armed while I was copying" -- both end at ARMED. The notify records the generation
 * when it claims the slot and rechecks it before publishing; a mismatch means the slot was recycled,
 * so its buffer is released and its result discarded.
 *
 * ⚠ THE LOCK IS NEVER HELD ACROSS THE COPY. It raises to DISPATCH_LEVEL, and MmCopyMemory and the
 * arena both require <= APC_LEVEL. Claim under the lock, copy at PASSIVE, publish under the lock.
 */
#define NXC_WATCH_FREE       0u   /* slot unused                                            */
#define NXC_WATCH_ARMED      1u   /* named, waiting for the image to load                   */
#define NXC_WATCH_CAPTURING  2u   /* the notify owns this slot RIGHT NOW -- do not recycle  */
#define NXC_WATCH_CAPTURED   3u   /* PristineBase holds an arena buffer                     */

typedef struct _NXC_WATCH_ENTRY
{
	CHAR    Name[NXC_WATCH_NAME_MAX];   /* ASCII, NUL-terminated                    */
	UINT64  PristineBase;               /* arena buffer, 0 until captured           */
	ULONG   PristineSize;
	UINT64  LiveBase;                   /* where it was loaded, for reference       */
	ULONG   State;                      /* NXC_WATCH_*                              */
	ULONG   Generation;                 /* bumped on every arm and every clear      */
} NXC_WATCH_ENTRY;

static NXC_WATCH_ENTRY gWatch[NXC_MAX_WATCH];
static KSPIN_LOCK      gWatchLock;
static volatile LONG   gNotifyRegistered = 0;

/** ASCII case-insensitive compare of two NUL-terminated watch names. */
static BOOLEAN
NameEqualsCi(
	_In_z_ CONST CHAR* A,
	_In_z_ CONST CHAR* B
	)
{
	for (ULONG k = 0; k < NXC_WATCH_NAME_MAX; k++)
	{
		CONST CHAR a = A[k], b = B[k];
		CONST CHAR la = (a >= 'A' && a <= 'Z') ? (CHAR)(a + 32) : a;
		CONST CHAR lb = (b >= 'A' && b <= 'Z') ? (CHAR)(b + 32) : b;
		if (la != lb)
			return FALSE;
		if (a == '\0')
			return TRUE;
	}
	return TRUE;
}

/*
 * ⚠ EXECUTABLE-POOL TRAMPOLINE, and it is not decoration -- see the kCFG note in NxcCaptureInit.
 * 16 bytes is enough for `jmp qword ptr [rip+0]` plus the 8-byte target.
 */
static void* gNotifyTrampoline = NULL;

/* ASCII case-insensitive compare of a UNICODE_STRING tail against a watch name. */
static BOOLEAN
NameMatches(
	_In_ CONST UNICODE_STRING* Full,
	_In_z_ CONST CHAR* Wanted
	)
{
	if (Full == NULL || Full->Buffer == NULL || Full->Length == 0)
		return FALSE;

	CONST USHORT Chars = (USHORT)(Full->Length / sizeof(WCHAR));

	/*
	 * Match the FILE NAME, not the full path. PsSetLoadImageNotifyRoutine reports something like
	 * \SystemRoot\System32\drivers\foo.sys, and a watch list of full paths would be both unusable
	 * and wrong the moment a target loads from somewhere else.
	 */
	USHORT Start = 0;
	for (USHORT i = 0; i < Chars; i++)
	{
		if (Full->Buffer[i] == L'\\' || Full->Buffer[i] == L'/')
			Start = (USHORT)(i + 1);
	}

	ULONG j = 0;
	for (USHORT i = Start; i < Chars; i++, j++)
	{
		CONST WCHAR w = Full->Buffer[i];
		CONST CHAR  c = Wanted[j];
		if (c == '\0' || w > 0x7F)
			return FALSE;

		CONST CHAR lw = (w >= L'A' && w <= L'Z') ? (CHAR)(w + 32) : (CHAR)w;
		CONST CHAR lc = (c >= 'A' && c <= 'Z')   ? (CHAR)(c + 32) : c;
		if (lw != lc)
			return FALSE;
	}
	return Wanted[j] == '\0';
}

/**
 * The callback. Runs at PASSIVE_LEVEL for every image load on the system.
 *
 * ⚠ RECORDS ONLY. It must not call into a mapped module -- see the constraint block in Capture.h.
 * It must also stay CHEAP: this is on the path of every process launch and every driver load.
 */
static VOID
NxcImageLoadNotify(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
	)
{
	UNREFERENCED_PARAMETER(ProcessId);

	if (FullImageName == NULL || ImageInfo == NULL || ImageInfo->ImageBase == NULL)
		return;

	CONST ULONG Size = (ULONG)ImageInfo->ImageSize;

	/*
	 * PHASE 1 -- CLAIM, under the lock. Find an ARMED slot whose name matches and mark it CAPTURING
	 * so neither `clear` nor `watch` can recycle it while the copy is in flight.
	 */
	KIRQL Irql;
	ULONG Slot = NXC_MAX_WATCH;
	ULONG Gen  = 0;
	CHAR  Name[NXC_WATCH_NAME_MAX];
	Name[0] = '\0';

	KeAcquireSpinLock(&gWatchLock, &Irql);
	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		if (gWatch[i].State != NXC_WATCH_ARMED)
			continue;                       /* FREE, in flight, or already has the first load */
		if (!NameMatches(FullImageName, gWatch[i].Name))
			continue;

		gWatch[i].State    = NXC_WATCH_CAPTURING;
		gWatch[i].LiveBase = (UINT64)(ULONG_PTR)ImageInfo->ImageBase;
		Slot = i;
		Gen  = gWatch[i].Generation;
		for (ULONG k = 0; k < NXC_WATCH_NAME_MAX; k++)
		{
			Name[k] = gWatch[i].Name[k];
			if (Name[k] == '\0') break;
		}
		break;
	}
	KeReleaseSpinLock(&gWatchLock, Irql);

	if (Slot == NXC_MAX_WATCH)
		return;

	/*
	 * PHASE 2 -- COPY, at PASSIVE and WITHOUT THE LOCK. Both the arena and MmCopyMemory require
	 * <= APC_LEVEL, so holding a DISPATCH_LEVEL lock across this would be a bugcheck, not a slowdown.
	 */
	void*    Buf = NULL;
	SIZE_T   Got = 0;
	NTSTATUS St  = STATUS_SUCCESS;

	if (Size == 0 || Size > NXC_CAPTURE_MAX)
	{
		CapLog("[capture] '%s' is %u bytes -- outside the %u cap, NOT captured\n",
		       Name, Size, NXC_CAPTURE_MAX);
	}
	else if ((Buf = NxcArenaAllocFor(NXC_OWNER_HOST, Size, NULL)) == NULL)
	{
		CapLog("[capture] '%s': arena has no room for %u bytes -- NOT captured\n", Name, Size);
	}
	else
	{
		/*
		 * MmCopyMemory, not a raw copy, for the same reason the read path uses it: the image was
		 * mapped moments ago and parts of it may not be resident. This returns a status and a
		 * transferred count instead of faulting, and we have no SEH.
		 *
		 * A PARTIAL capture is kept, not discarded -- most of a pristine image is still the most
		 * informative artifact available, and the recorded size says exactly how much is real.
		 */
		MM_COPY_ADDRESS Src;
		Src.VirtualAddress = ImageInfo->ImageBase;
		St = MmCopyMemory(Buf, Src, Size, MM_COPY_MEMORY_VIRTUAL, &Got);

		if (Got == 0)
		{
			CapLog("[capture] '%s': unreadable at load (0x%08X) -- NOT captured\n", Name, St);
			NxcArenaFreeFor(NXC_OWNER_HOST, Buf);
			Buf = NULL;
		}
	}

	/*
	 * PHASE 3 -- PUBLISH, under the lock, ONLY IF THE SLOT IS STILL OURS.
	 *
	 * The generation check is the whole point. If the slot was cleared and re-armed while we copied,
	 * publishing here would file these bytes under whatever name the slot now carries -- the exact
	 * mis-attribution described at the top of this file.
	 */
	BOOLEAN Recycled = FALSE;

	KeAcquireSpinLock(&gWatchLock, &Irql);
	if (gWatch[Slot].State == NXC_WATCH_CAPTURING && gWatch[Slot].Generation == Gen)
	{
		if (Buf != NULL)
		{
			gWatch[Slot].PristineSize = (ULONG)Got;
			gWatch[Slot].PristineBase = (UINT64)(ULONG_PTR)Buf;
			gWatch[Slot].State        = NXC_WATCH_CAPTURED;
		}
		else
		{
			/* Nothing captured. Back to ARMED so the NEXT load of this image is still taken --
			 * a transient arena shortage must not silently disarm the watch forever. */
			gWatch[Slot].State = NXC_WATCH_ARMED;
		}
	}
	else
	{
		Recycled = TRUE;
	}
	KeReleaseSpinLock(&gWatchLock, Irql);

	if (Recycled)
	{
		/* Freed OUTSIDE the lock -- the arena needs PASSIVE. Logged rather than swallowed: it is
		 * rare enough that seeing it means something raced, which is worth knowing. */
		if (Buf != NULL)
			NxcArenaFreeFor(NXC_OWNER_HOST, Buf);
		CapLog("[capture] '%s': slot %u was cleared mid-capture -- result DISCARDED\n", Name, Slot);
		return;
	}

	if (Buf != NULL)
		CapLog("[capture] '%s' PRISTINE at %p, %llu of %u bytes (live %p)\n",
		       Name, Buf, (ULONG64)Got, Size, ImageInfo->ImageBase);
}

NTSTATUS
NxcCaptureEnsureRegistered(
	void
	)
{
	if (gNotifyRegistered != 0)
		return STATUS_SUCCESS;

	/*
	 * ============================================================================================
	 * ⚠ THE TRAMPOLINE IS A kCFG REQUIREMENT, not a v1 habit copied forward.
	 * ============================================================================================
	 *
	 * The kernel calls this callback INDIRECTLY through a stored pointer, and indirect calls in the
	 * kernel go through nt!_guard_dispatch_icall, which validates the target against the kCFG
	 * bitmap. Our image is deliberately absent from the loaded-module list, so nothing ever
	 * registered its functions as valid indirect targets. Executable POOL is treated as a valid
	 * target, so the kernel calls the trampoline and the trampoline performs a DIRECT jmp to the
	 * real handler -- and a direct jmp is not an indirect call, so it is never checked.
	 *
	 * v1 reached the same conclusion and its comment says "CFG-trusted"; this is that finding
	 * carried forward WITH the reason attached rather than the pattern alone.
	 *
	 * ⚠ OPEN QUESTION, deliberately resolved the SAFE way. Research (Connor McGarr; Black Hat 2025
	 * KCFG/KCET) says kCFG is "only fully enabled when HVCI is enabled", but that the dispatch
	 * routines are present and calls still pass through them without VBS -- what HVCI adds is
	 * read-only protection OF THE BITMAP. Whether a direct registration would actually be REJECTED
	 * on this VBS-off machine is therefore not settled, and the failure mode is a bugcheck during
	 * boot. Taking the proven path.
	 *
	 * That is a measurable experiment worth running later, not a guess to make now: register
	 * directly, boot, and see whether the callback fires. If it does, this allocation and its FF-25
	 * bytes can go -- which would be a real win, because POOL_FLAG_NON_PAGED_EXECUTE with a tag is
	 * exactly the enumerable artifact the arena exists to avoid, and FF 25 is the byte pattern the
	 * payload design removes everywhere else.
	 */
	if (gNotifyTrampoline == NULL)
	{
		gNotifyTrampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 16, 'pCxN');
		if (gNotifyTrampoline == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;

		UCHAR* CONST t = (UCHAR*)gNotifyTrampoline;
		t[0] = 0xFF; t[1] = 0x25;                       /* jmp qword ptr [rip+0] */
		t[2] = 0x00; t[3] = 0x00; t[4] = 0x00; t[5] = 0x00;
		*(UINT64*)(t + 6) = (UINT64)(ULONG_PTR)NxcImageLoadNotify;
	}

	CONST NTSTATUS St =
		PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)gNotifyTrampoline);

	if (NT_SUCCESS(St))
	{
		InterlockedExchange(&gNotifyRegistered, 1);
		CapLog("[capture] image-load notify registered (via trampoline at %p)\n", gNotifyTrampoline);
	}
	else
	{
		CapLog("[capture] PsSetLoadImageNotifyRoutine failed 0x%08X -- capture inactive\n", St);
	}
	return St;
}

/*
 * ============================================================================================
 * BOOT WATCH LIST -- the only way to capture something that loads before you can ask.
 * ============================================================================================
 *
 * `PlatformCtl watch` cannot help with a BOOT DRIVER: by the time a usermode process exists to
 * issue the command, the target loaded long ago, and nothing is captured retroactively. That is a
 * chicken-and-egg problem for exactly the class of target most worth capturing.
 *
 * These names are armed inside DriverEntry instead, which is early enough because NexusCore reaches
 * its entry via a hijacked BOOT DRIVER'S entry point -- so it is already running while the rest of
 * the boot drivers are still loading, and sees every image that loads after that point.
 *
 * ⚠ WHAT IT CANNOT SEE: anything that loaded BEFORE NexusCore's entry, which includes the hijacked
 * driver itself and everything ordered ahead of it. That is a real limit, not an oversight -- there
 * is no point in the boot where we run and nothing has loaded yet.
 *
 * COMPILE-TIME rather than a persisted UEFI variable, deliberately. A second variable would be a
 * second non-standard artifact on the system, and this design keeps exactly one
 * (NexusCommand.h: "one non-standard variable name serves both directions, because a second name
 * would be a second thing to find"). Changing the list costs a rebuild and a deploy -- which this
 * workflow does routinely anyway -- and buys no new thing for anyone to discover.
 *
 * EMPTY BY DEFAULT, on purpose: an unattended capture of something nobody asked for is a surprise,
 * and every entry here costs arena that mapped modules need.
 */
static CONST CHAR* CONST gBootWatch[] =
{
	/* e.g. "eaanticheat.sys", */
	NULL   /* keeps the array valid when nothing is listed -- do not remove */
};

NTSTATUS
NxcCaptureInit(
	void
	)
{
	KeInitializeSpinLock(&gWatchLock);

	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		gWatch[i].Name[0]    = '\0';
		gWatch[i].State      = NXC_WATCH_FREE;
		gWatch[i].Generation = 0;
	}

	/*
	 * Armed BEFORE the notify is registered, so there is no window where an image loads, the notify
	 * is live, and the list is still empty. Ordering matters more than it looks: the whole reason
	 * this list exists is to be ready earlier than a command can be issued.
	 */
	for (ULONG i = 0; i < ARRAYSIZE(gBootWatch); i++)
	{
		if (gBootWatch[i] == NULL)
			continue;
		CONST NTSTATUS Wst = NxcCaptureWatch(gBootWatch[i]);
		if (!NT_SUCCESS(Wst))
			CapLog("[capture] boot watch '%s' REFUSED 0x%08X\n", gBootWatch[i], Wst);
	}

	/*
	 * Non-fatal by design, and retryable. If PsSetLoadImageNotifyRoutine is not yet available this
	 * early in boot -- which v1 observed and worked around -- the command path can call
	 * NxcCaptureEnsureRegistered later and recover without a reboot.
	 */
	return NxcCaptureEnsureRegistered();
}

NTSTATUS
NxcCaptureWatch(
	_In_z_ CONST CHAR* Name
	)
{
	if (Name == NULL || Name[0] == '\0')
		return STATUS_INVALID_PARAMETER;

	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	ULONG Free = NXC_MAX_WATCH;
	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		if (gWatch[i].State == NXC_WATCH_FREE)
		{
			if (Free == NXC_MAX_WATCH)
				Free = i;
			continue;
		}
		/* Case-insensitive duplicate check, so "Foo.sys" and "foo.sys" are one entry. */
		if (NameEqualsCi(gWatch[i].Name, Name))
		{
			KeReleaseSpinLock(&gWatchLock, Irql);
			return STATUS_OBJECT_NAME_COLLISION;
		}
	}

	if (Free == NXC_MAX_WATCH)
	{
		KeReleaseSpinLock(&gWatchLock, Irql);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG i = 0;
	for (; i < NXC_WATCH_NAME_MAX - 1 && Name[i] != '\0'; i++)
		gWatch[Free].Name[i] = Name[i];
	gWatch[Free].Name[i] = '\0';

	gWatch[Free].PristineBase = 0;
	gWatch[Free].PristineSize = 0;
	gWatch[Free].LiveBase     = 0;
	gWatch[Free].State        = NXC_WATCH_ARMED;
	gWatch[Free].Generation++;   /* invalidates any capture still in flight against this slot */

	KeReleaseSpinLock(&gWatchLock, Irql);

	CapLog("[capture] watching '%s'\n", Name);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcCaptureList(
	_Out_writes_(Cap) NXCMD_CAPTURE_ENTRY* Out,
	_In_ ULONG Cap,
	_Out_ ULONG* Got
	)
{
	*Got = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	ULONG n = 0;
	for (ULONG i = 0; i < NXC_MAX_WATCH && n < Cap; i++)
	{
		if (gWatch[i].State == NXC_WATCH_FREE)
			continue;

		Out[n].PristineBase = gWatch[i].PristineBase;
		Out[n].LiveBase     = gWatch[i].LiveBase;
		Out[n].PristineSize = gWatch[i].PristineSize;
		Out[n].State        = gWatch[i].State;
		for (ULONG k = 0; k < sizeof(Out[n].Name); k++)
		{
			Out[n].Name[k] = (NXCMD_U8)gWatch[i].Name[k];
			if (gWatch[i].Name[k] == '\0') break;
		}
		Out[n].Name[sizeof(Out[n].Name) - 1] = '\0';
		n++;
	}

	KeReleaseSpinLock(&gWatchLock, Irql);

	*Got = n;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcCaptureClear(
	_In_opt_z_ CONST CHAR* Name,
	_Out_ ULONG* OutCleared,
	_Out_ ULONG* OutBusy
	)
{
	*OutCleared = 0;
	*OutBusy    = 0;

	/*
	 * Buffers are collected under the lock and freed AFTER releasing it -- the arena requires
	 * PASSIVE_LEVEL and the lock runs at DISPATCH. Doing it the obvious way round is a bugcheck.
	 */
	UINT64 ToFree[NXC_MAX_WATCH];
	ULONG  nFree = 0;
	ULONG  Cleared = 0, Busy = 0;

	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		if (gWatch[i].State == NXC_WATCH_FREE)
			continue;
		if (Name != NULL && !NameEqualsCi(gWatch[i].Name, Name))
			continue;

		/*
		 * A CAPTURE IN FLIGHT IS REFUSED, NOT WAITED FOR. The notify holds no lock while it copies,
		 * so there is nothing to wait on here without blocking at DISPATCH_LEVEL. Reporting it lets
		 * the caller simply re-run -- and the generation bump means that even if the notify publishes
		 * in between, the slot is consistent either way.
		 */
		if (gWatch[i].State == NXC_WATCH_CAPTURING)
		{
			Busy++;
			continue;
		}

		if (gWatch[i].PristineBase != 0)
			ToFree[nFree++] = gWatch[i].PristineBase;

		gWatch[i].Name[0]      = '\0';
		gWatch[i].PristineBase = 0;
		gWatch[i].PristineSize = 0;
		gWatch[i].LiveBase     = 0;
		gWatch[i].State        = NXC_WATCH_FREE;
		gWatch[i].Generation++;
		Cleared++;
	}

	KeReleaseSpinLock(&gWatchLock, Irql);

	/*
	 * THE ARENA IS ACTUALLY RELEASED. Clearing only the slot would leave the capture resident
	 * forever -- and Capture.c's own header calls a permanent tenant in a shared 16 MB arena a map
	 * failure much later for no visible reason. A `clear` that leaks is not a clear.
	 */
	for (ULONG i = 0; i < nFree; i++)
		NxcArenaFreeFor(NXC_OWNER_HOST, (void*)(ULONG_PTR)ToFree[i]);

	*OutCleared = Cleared;
	*OutBusy    = Busy;

	CapLog("[capture] clear '%s': %u cleared (%u arena buffers freed), %u busy\n",
	       (Name != NULL) ? Name : "*", Cleared, nFree, Busy);
	return (Cleared == 0 && Busy == 0) ? STATUS_NOT_FOUND : STATUS_SUCCESS;
}

NTSTATUS
NxcCaptureFind(
	_In_z_ CONST CHAR* Name,
	_Out_ UINT64* OutBase,
	_Out_ ULONG* OutSize
	)
{
	*OutBase = 0;
	*OutSize = 0;

	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	NTSTATUS St = STATUS_NOT_FOUND;
	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		/* CAPTURED only. An ARMED or in-flight slot has no bytes yet, and answering from one would
		 * hand back a zero base that reads as a successful capture of nothing. */
		if (gWatch[i].State != NXC_WATCH_CAPTURED)
			continue;
		if (!NameEqualsCi(gWatch[i].Name, Name))
			continue;

		*OutBase = gWatch[i].PristineBase;
		*OutSize = gWatch[i].PristineSize;
		St = STATUS_SUCCESS;
		break;
	}

	KeReleaseSpinLock(&gWatchLock, Irql);
	return St;
}

/*
 * ============================================================================================
 * READ THE CAPTURED BYTES -- and it must be a DIRECT copy, not MmCopyMemory.
 * ============================================================================================
 *
 * ⚠ THE READ PATH USED MmCopyMemory ON THE ARENA AND IT ALWAYS FAILED. `read <mod> --pristine`
 * resolved the capture correctly, printed its base and SizeOfImage, and then refused with
 * STATUS_INVALID_ADDRESS (0xC0000141) every single time -- so `capture list` said CAPTURED while
 * every attempt to retrieve those bytes was rejected. measured against a real
 * usermode image load (version.dll, 45056 bytes, CAPTURED, unreadable).
 *
 * WHY: MmCopyMemory(MM_COPY_MEMORY_VIRTUAL) is the RIGHT primitive for reading ANOTHER MODULE'S
 * memory -- it returns a status instead of faulting on a page that is unmapped or paged out, which
 * is exactly what the LIVE read needs and why the capture itself uses it to read the image. But a
 * pristine copy lives in OUR ARENA, which is EFI runtime memory reserved by the DXE. Those frames
 * are not in Windows' PFN database, so the validation MmCopyMemory performs before copying has
 * nothing to consult and it refuses the address.
 *
 * The correct primitive for our own arena is a plain copy, which is what NxcFileCapturePull already
 * does for the byte arena and why `fcap pull` works while this did not. Same memory, two consumers,
 * one of them using a primitive that cannot read it.
 *
 * ⚠ SAFE BECAUSE THE BOUNDS COME FROM THE RECORD, NOT THE CALLER. The offset and length are clamped
 * against the slot's own PristineSize under the lock, so a caller cannot walk off the end of the
 * allocation -- which is the protection MmCopyMemory was implicitly being relied on to provide.
 *
 * ⚠ THE COPY HAPPENS UNDER THE SPIN LOCK, and that is a deliberate difference from the CAPTURE path
 * (which explicitly does not hold it across its copy). Capture copies up to a megabyte from foreign
 * memory that may fault; this copies a bounded, already-resident arena buffer, so the lock is held
 * only long enough to keep a concurrent `capture clear` from freeing the buffer mid-read.
 */
NTSTATUS
NxcCaptureRead(
	_In_z_ CONST CHAR* Name,
	_In_ UINT64 Offset,
	_In_ ULONG Length,
	_Out_writes_bytes_(Length) void* Out,
	_Out_ ULONG* OutGot
	)
{
	*OutGot = 0;
	if (Out == NULL || Length == 0)
		return STATUS_INVALID_PARAMETER;

	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	NTSTATUS St = STATUS_NOT_FOUND;
	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		if (gWatch[i].State != NXC_WATCH_CAPTURED)
			continue;
		if (!NameEqualsCi(gWatch[i].Name, Name))
			continue;

		if (gWatch[i].PristineBase == 0 || gWatch[i].PristineSize == 0)
		{
			St = STATUS_NOT_FOUND;
			break;
		}
		if (Offset >= (UINT64)gWatch[i].PristineSize)
		{
			St = STATUS_INVALID_PARAMETER;
			break;
		}

		CONST UINT64 Avail = (UINT64)gWatch[i].PristineSize - Offset;
		CONST ULONG  Take  = (Avail < (UINT64)Length) ? (ULONG)Avail : Length;

		RtlCopyMemory(Out, (CONST UINT8*)(ULONG_PTR)gWatch[i].PristineBase + Offset, Take);
		*OutGot = Take;
		St = STATUS_SUCCESS;
		break;
	}

	KeReleaseSpinLock(&gWatchLock, Irql);
	return St;
}

void
NxcCaptureStats(
	_Out_ ULONG* OutWatched,
	_Out_ ULONG* OutCaptured
	)
{
	KIRQL Irql;
	KeAcquireSpinLock(&gWatchLock, &Irql);

	ULONG w = 0, c = 0;
	for (ULONG i = 0; i < NXC_MAX_WATCH; i++)
	{
		if (gWatch[i].State == NXC_WATCH_FREE)
			continue;
		w++;
		if (gWatch[i].State == NXC_WATCH_CAPTURED)
			c++;
	}

	KeReleaseSpinLock(&gWatchLock, Irql);

	*OutWatched = w;
	*OutCaptured = c;
}
