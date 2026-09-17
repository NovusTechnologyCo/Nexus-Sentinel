/**
 * @file LogRing.h
 * @brief A lock-free ring the hook path writes to and usermode drains.
 *
 * ============================================================================================
 * ⚠ ITS FIRST PRODUCER IS THE COMMAND PATH, NOT A HOOK -- AND THAT IS DELIBERATE
 * ============================================================================================
 *
 * The plan pairs this with the inline hook, which does not exist yet. Building a ring with no writer
 * would mean shipping something whose only exercise is a synthetic test written to make it pass --
 * which is the shape of a stub even when the code is real.
 *
 * So the ring's first producer is `NxcCommandHandler` itself: every command serviced records one
 * entry. That makes it (a) genuinely useful on its own, as an audit trail of what the driver was
 * asked to do, and (b) exercised under REAL concurrent use before a hook ever depends on it. When
 * the hook arrives it becomes a second producer, not the first.
 *
 * ============================================================================================
 * ⚠ WHY LOCK-FREE, AND WHY THAT CONSTRAINS THE DESIGN
 * ============================================================================================
 *
 * A hook runs in whatever context it interposed on -- arbitrary thread, possibly at raised IRQL,
 * possibly inside the very allocator or logger a lock would call into. Taking a lock there risks
 * deadlock against code we do not control and cannot see.
 *
 * So: a single `InterlockedIncrement64` claims a slot, and the writer fills it. No lock, no
 * allocation, no call out of the ring. Capacity is a POWER OF TWO so the index becomes a bitwise
 * AND -- a division at a hook site is a cost paid on every interposed call, and worse, `%` on a
 * 64-bit value is a helper call this driver would have to import.
 *
 * ============================================================================================
 * ⚠ OVERRUN IS DETECTED AND REPORTED, NOT HIDDEN
 * ============================================================================================
 *
 * The ring overwrites its oldest entries rather than stopping, for the reason the PT buffer is
 * circular: the interesting moment is almost always the most recent, and a log that filled up an
 * hour ago holds the least useful window it could.
 *
 * But a log that silently drops entries is worse than no log -- it produces a plausible, incomplete
 * story with nothing marking the gap. So every entry carries a monotonically increasing SEQUENCE,
 * and the reader compares the sequence it expected against the one it got. A gap is reported as a
 * count of LOST entries. Same discipline as `count` vs `total` everywhere else here: truncation must
 * never be able to read as completeness.
 *
 * ⚠ A SLOT CAN BE TORN. A reader may catch a slot mid-write, and there is no lock to prevent it. The
 * sequence number is written LAST, so an entry whose sequence does not match its slot position is
 * still being written and is skipped rather than reported as data.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/* Entries in the ring. POWER OF TWO -- see the masking note above. */
#define NXC_LOG_ENTRIES   1024u

/** Start the ring. Idempotent; safe to call before anything logs. */
NTSTATUS NxcLogRingInit(void);

/**
 * Record one event. Callable from any context: no lock, no allocation, no call out.
 *
 * @param Kind  NXCMD_LOG_KIND_*
 */
void NxcLogRingWrite(
	_In_ UINT32 Kind,
	_In_ UINT64 A,
	_In_ UINT64 B,
	_In_ UINT64 C
	);

/**
 * Drain entries newer than @p Since into @p Out.
 *
 * @param Since  the highest sequence the caller already has; 0 for everything still resident
 * @param Got    entries written
 * @param Lost   entries that were OVERWRITTEN before the caller got them. Non-zero means the reader
 *               fell behind the writer -- the log is incomplete and says so.
 * @param Head   the writer's current sequence, so the caller knows where to resume
 */
NTSTATUS NxcLogRingDrain(
	_In_ UINT64 Since,
	_Out_writes_(Cap) NXCMD_LOG_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Lost,
	_Out_ UINT64* Head
	);
