/**
 * @file Capture.h
 * @brief Watch for image loads and take a PRISTINE copy before the image modifies itself.
 *
 * ============================================================================================
 * WHY A PRISTINE COPY IS WORTH THE MACHINERY
 * ============================================================================================
 *
 * A packed or self-decrypting module is two different things at two different times: what the
 * loader mapped, and what it turned itself into. Reading it live gives you the second. Reading the
 * file on disk gives you neither, because the loader has applied relocations and the on-disk bytes
 * are not what ran.
 *
 * Capturing at image-load -- BEFORE the entry point runs -- gives the first. Diffing the two shows
 * exactly what the module did to itself, which for a self-descrambling target is the single most
 * informative artifact available. v1 built this for one such target and it is the idea from that codebase most
 * worth keeping.
 *
 * ============================================================================================
 * ⚠ THE NOTIFY RECORDS. IT DOES NOT DISPATCH. Read this before extending it.
 * ============================================================================================
 *
 * This callback must never call into a mapped MODULE. Module command handlers are safe without
 * rundown protection for exactly one reason (see NexusHost.h): every command including unmap is
 * serialised by NxcCommandHandler's interlocked guard, so a handler cannot be running while its own
 * teardown does. A kernel callback runs OUTSIDE that guard, on an arbitrary thread, at an arbitrary
 * time -- so a module invoked from here could be executing while its extent is being poisoned.
 *
 * Keeping this callback to "record facts into Core-owned memory" preserves the invariant. If a
 * module ever needs to be notified of an image load, the correct shape is for the module to POLL a
 * command, not for the notify to call it. Breaking that means implementing real rundown protection
 * first, not afterwards.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"   /* NXCMD_CAPTURE_ENTRY, shared with PlatformCtl */

/**
 * Register the image-load notification. Call once, late in DriverEntry.
 *
 * NOT fatal if it fails. Capture is an added capability, and a foothold that refuses to finish
 * booting because an optional subsystem could not start is strictly worse than one without it.
 *
 * ⚠ MAY LEGITIMATELY FAIL EARLY IN BOOT. v1 found PsSetLoadImageNotifyRoutine is not always
 * available at the point a boot-time mapped driver runs, and retried on every later init. The
 * registration is therefore idempotent and re-attemptable: NxcCaptureEnsureRegistered() can be
 * called again from the command path, so a failure at boot is recoverable without a reboot.
 */
NTSTATUS
NxcCaptureInit(
	void
	);

/**
 * Re-attempt registration if the boot-time attempt failed. Idempotent; returns success when the
 * notify is already live.
 */
NTSTATUS
NxcCaptureEnsureRegistered(
	void
	);

/**
 * Add a module name to the watch list. Case-insensitive, matched against the loading image's name.
 *
 * OPT-IN, and deliberately so: the notify fires for EVERY image load on the system, and copying
 * every one of them would exhaust the arena in seconds and slow every process launch. A watch entry
 * says "this one is worth a megabyte".
 *
 * @retval STATUS_SUCCESS            watching
 * @retval STATUS_INSUFFICIENT_RESOURCES  watch table full
 * @retval STATUS_OBJECT_NAME_COLLISION   already watched (not an error; reported for clarity)
 */
NTSTATUS
NxcCaptureWatch(
	_In_z_ CONST CHAR* Name
	);

/*
 * ⚠ HOW MUCH `NxcCaptureRead` WILL COPY UNDER THE LOCK IN ONE CALL.
 *
 * The read holds `gWatchLock` (a spinlock, so DISPATCH_LEVEL) across its copy, because that is what
 * stops a concurrent `capture clear` freeing the buffer mid-read. Correct invariant, but a pristine
 * capture is up to NXC_CAPTURE_MAX = 8 MB, and holding a DISPATCH spinlock for the ~800 us that
 * takes stalls every core that touches the same lock -- `NxcImageLoadNotify` takes it on EVERY
 * image load in the system, so every driver load and process start would spin behind one read.
 *
 * 64 KB is ~6 us of hold, which is the order a spinlock is meant for. Callers resume with a larger
 * Offset; the read already reports what it PRODUCED, so a short return is data rather than an
 * error. Chosen over releasing the lock across the copy, which is the obvious fix and reintroduces
 * exactly the read-after-free this codebase has already paid for twice.
 */
#define NXC_CAPTURE_READ_CHUNK  (64u * 1024u)

/**
 * Look up a captured pristine copy by name.
 *
 * ⚠⚠ THE RETURNED POINTER IS NOT DURABLE. USE `NxcCaptureRead` IF YOU INTEND TO DEREFERENCE IT.
 *
 * This contract used to read "remains valid until the driver goes away", and that was true when
 * watches could only ever be ADDED -- pristine buffers were never released, so the pointer really
 * did have driver lifetime. `NxcCaptureClear` broke that: it returns the buffer to the arena, which
 * POISONS the range with 0xCC and puts it back on the free list for the next allocator.
 *
 * A caller that stores this pointer and dereferences it after a `capture clear` reads poison, or
 * bytes now owned by somebody else. Nothing here takes a reference or extends a lock on the
 * caller's behalf.
 *
 * `NxcCaptureRead` exists precisely for this: it copies under the watch lock, so the buffer cannot
 * be freed mid-read. This entry point remains for callers that only want to know WHETHER a capture
 * exists and how big it is. Contract corrected by review,.
 *
 * @param OutBase  receives the CAPTURED BUFFER, not the live image -- Core's memory, in the arena.
 *                 Treat as valid only for the duration of this call; it may be freed by a
 *                 concurrent `capture clear` at any point afterwards.
 * @param OutSize  bytes captured, which is SizeOfImage as reported at load time
 *
 * @retval STATUS_SUCCESS   found
 * @retval STATUS_NOT_FOUND not watched, or watched but never loaded since
 */
NTSTATUS
NxcCaptureFind(
	_In_z_ CONST CHAR* Name,
	_Out_ UINT64* OutBase,
	_Out_ ULONG* OutSize
	);

/**
 * List the watch table. Answers "what is armed and what actually fired" -- the one thing the watch
 * could not report, which made every capture a matter of trusting that it had happened.
 */
/**
 * Copy captured bytes out of the arena.
 *
 * (!) A DIRECT COPY, because MmCopyMemory CANNOT READ THE ARENA. The read path used to call
 * MmCopyMemory(MM_COPY_MEMORY_VIRTUAL) on the pristine base and it failed every time with
 * STATUS_INVALID_ADDRESS: our arena is EFI runtime memory whose frames are absent from Windows' PFN
 * database, so the validation that makes MmCopyMemory safe for FOREIGN memory has nothing to
 * consult. `capture list` reported CAPTURED while every retrieval was refused.
 *
 * Bounds come from the slot's own PristineSize under the lock, so the caller cannot read past the
 * allocation -- which is the protection MmCopyMemory was implicitly providing.
 *
 * @param Offset  byte offset into the captured image
 * @param OutGot  bytes ACTUALLY copied -- clamped to the capture, never assumed to equal Length
 */
NTSTATUS
NxcCaptureRead(
	_In_z_ CONST CHAR* Name,
	_In_ UINT64 Offset,
	_In_ ULONG Length,
	_Out_writes_bytes_(Length) void* Out,
	_Out_ ULONG* OutGot
	);

NTSTATUS
NxcCaptureList(
	_Out_writes_(Cap) NXCMD_CAPTURE_ENTRY* Out,
	_In_ ULONG Cap,
	_Out_ ULONG* Got
	);

/**
 * Release watch entries and THEIR ARENA BUFFERS.
 *
 * @param Name  one entry, case-insensitive; NULL clears every entry
 * @param OutBusy  entries skipped because a capture was IN FLIGHT. Refused rather than waited for:
 *                 the notify holds no lock while copying, so there is nothing to wait on without
 *                 blocking at DISPATCH_LEVEL. Re-running is the answer, and the generation counter
 *                 keeps the slot consistent whichever way the race lands.
 *
 * @retval STATUS_NOT_FOUND  nothing matched and nothing was busy
 */
NTSTATUS
NxcCaptureClear(
	_In_opt_z_ CONST CHAR* Name,
	_Out_ ULONG* OutCleared,
	_Out_ ULONG* OutBusy
	);

/** Watch-list entries in use, and how many have actually captured, for the status report. */
void
NxcCaptureStats(
	_Out_ ULONG* OutWatched,
	_Out_ ULONG* OutCaptured
	);
