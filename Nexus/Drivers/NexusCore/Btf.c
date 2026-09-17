/*
 * Btf.c -- branch-stepping (D119). Read Btf.h for the contract and the one-shot rule.
 */

/*
 * ⚠ THE PAYLOAD CARRIES NO IMPORT TABLE, so every nt call goes through NexusNtApi. The order is
 * load-bearing -- typed table, extern, redirects -- because the redirect header is nothing but
 * `#define KeFoo (NexusNtApi.KeFoo)`, and including it before the extern expands to a reference to
 * an undeclared identifier at the CALL SITE.
 */
/* ⚠ ntddk FIRST. NexusNtApi.h declares its table in terms of ntddk types, so including it before
 * them fails inside that header at line 498 and blames it, not this file. BpDispatch.c has the same
 * ordering for the same reason. */
#include <ntddk.h>
#include <intrin.h>   /* __readmsr / __writemsr / _mm_pause */

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

#include "Btf.h"
#include "BpDispatch.h"   /* NxcBpdClaimEnabled -- the interlock, checked in the kernel */
#include "Bp.h"           /* NXC_BP_MAX_CPUS -- one bound, not a second that must agree with it */

#define IA32_DEBUGCTL   0x000001D9u
#define DEBUGCTL_BTF    (1ULL << 1)

/*
 * ⚠ CR3 IS THE IDENTITY, NOT THE PID. The dispatcher runs on the exception path with no safe way to
 * resolve a pid, and CR3 is what the hardware hands it. The pid is carried alongside for REPORTING
 * only -- the same split the breakpoint slots make, for the same reason.
 */
static volatile LONG64 gBtfCr3     = 0;   /* masked frame; 0 = not armed */
static volatile LONG   gBtfPid     = 0;
static volatile LONG   gBtfArmed   = 0;

/*
 * ⚠⚠ NO LOCK. THE FIRST VERSION HAD ONE AND IT WAS THE CLOCK_WATCHDOG SHAPE AGAIN.
 *
 * A spin lock here is taken at #DB time -- at whatever IRQL the trap arrived on -- and also by the
 * DRAIN, which runs at PASSIVE and copies up to 8192 records. A PASSIVE holder can be PREEMPTED
 * mid-copy while every branching core spins on it above DISPATCH_LEVEL, unable to yield. That is
 * not a slow path, it is a wedged core, and a core that stops answering the clock is exactly what
 * bugchecked this machine by a different route.
 *
 * So it is a CIRCULAR buffer driven by two monotonic indices and no mutual exclusion at all:
 *
 *   - the trap path RESERVES index W with a CAS, and writes at W % MAX;
 *   - the CAS is not an unconditional increment, because A DROP MUST NOT CONSUME AN INDEX. If it
 *     did, slot W%MAX would still hold the previous lap's record while the drain waited for index
 *     W, and the drain would stall there forever -- a full ring turning into a dead one;
 *   - gBtfCommit[slot] is written LAST and holds W+1, so the drain accepts a slot only when the
 *     marker is exactly the index it wants. A slot still being filled, or holding an older lap,
 *     is refused rather than guessed at;
 *   - the drain consumes only the CONTIGUOUS COMMITTED PREFIX and advances Read, which FREES those
 *     slots for reuse.
 *
 * ⚠⚠ AND THE FIRST VERSION WAS NOT A RING AT ALL. gBtfWrite indexed straight into the array, so
 * once it passed MAX every further branch dropped forever and draining freed nothing. Usermode was
 * then given a continuous adaptive drain to keep up with the stream, and it kept exactly 8192
 * records -- because there was nothing to keep up WITH. measured.
 *
 * The branch-rate path is one CAS and four stores, and cannot block.
 */
static NXC_BTF_REC     gBtfRing[NXC_BTF_MAX_RECORDS];
static volatile LONG64 gBtfCommit[NXC_BTF_MAX_RECORDS];   /* slot -> the write index that filled it, + 1 */
static volatile LONG64 gBtfWrite   = 0;   /* monotonic; live records are [Read, Write)                   */
static volatile LONG64 gBtfRead    = 0;   /* monotonic; advancing it FREES slots for reuse               */
static volatile LONG64 gBtfSeq     = 0;   /* monotonic across the whole arming                       */
static volatile LONG64 gBtfDropped = 0;
static volatile LONG64 gBtfTaken   = 0;
static volatile LONG64 gBtfTfFailed = 0;
static volatile LONG64 gBtfFiltStart = 0;   /* inclusive; 0/0 = record everything */
static volatile LONG64 gBtfFiltEnd   = 0;
static volatile LONG64 gBtfFiltered  = 0;   /* seen, deliberately not recorded -- NOT a loss */
static volatile LONG   gBtfDraining = 0;   /* stopping: clear TF on trap, do not re-arm */

/*
 * ================================================================================================
 * RING-0 BRANCH STEPPING (D120) -- IA32_FMASK bit 8
 * ================================================================================================
 *
 * TF does not reach the kernel by itself. SDM vol 2, SYSCALL: `RFLAGS := RFLAGS AND NOT(IA32_FMASK)`
 * -- so every bit set in IA32_FMASK (0xC0000084) is CLEARED on entry, and Windows sets it to 0x4700:
 * TF | IF | DF | NT. Clearing bit 8 there, and only bit 8, lets a stepped thread's TF survive its own
 * syscall, so the kernel path it entered is branch-stepped like any other code.
 *
 * ⚠⚠ THIS DEFEATS A DELIBERATE OS PROPERTY, and that is stated rather than glossed: masking TF is
 * how Windows stops usermode single-stepping from following a thread into ring 0. It is opt-in
 * (`--kernel`), it is restored exactly, and the value is MEASURED per core before being touched --
 * 0x4700 is what the documentation says, not what this machine was observed to hold.
 *
 * ⚠ SCOPE IS STILL EFLAGS.TF. FMASK is per-core, but clearing the bit changes nothing for a thread
 * whose TF is clear -- and only the target's is set. Other processes' syscalls on that core are
 * unaffected, which is what makes this narrower than it first sounds.
 *
 * ⚠ AND OUR OWN HANDLER CANNOT SELF-STEP. SDM vol 3: an interrupt or trap gate "clears the TF flag
 * in the EFLAGS register after it saves the contents of the EFLAGS register on the stack". The #DB
 * that branch stepping generates therefore runs the dispatcher with TF ALREADY CLEAR. Ring-0
 * self-pollution is answered by the architecture, not by us being careful.
 *
 * ⚠ NOT A GENERAL MSR SURFACE, DELIBERATELY. An arbitrary WRMSR primitive exposed to usermode is a
 * well-known route to kernel execution (write IA32_LSTAR, call a syscall). This touches ONE bit of
 * ONE MSR, from the kernel, with the original saved -- there is no caller-supplied MSR number and no
 * caller-supplied value.
 */
#define IA32_FMASK      0xC0000084u
#define FMASK_TF        (1ULL << 8)

static volatile LONG64 gBtfFmaskSaved[NXC_BP_MAX_CPUS];
static volatile LONG   gBtfKernelOn = 0;

static ULONG_PTR
BtfFmaskOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_BP_MAX_CPUS)
		return 0;

	if (Context != 0)
	{
		/* ⚠ MEASURE, THEN MODIFY. The saved value is this core's own, read now -- not 0x4700 taken
		 * on faith from documentation, and not one core's value applied to all of them. */
		CONST UINT64 Cur = __readmsr(IA32_FMASK);
		InterlockedExchange64(&gBtfFmaskSaved[Cpu], (LONG64)Cur);
		__writemsr(IA32_FMASK, Cur & ~FMASK_TF);
	}
	else
	{
		CONST LONG64 Saved = gBtfFmaskSaved[Cpu];
		if (Saved != 0)
		{
			/* Restore the WHOLE saved value, not just the bit: if anything else changed it while we
			 * held it, putting back exactly what we found is the only defensible answer. */
			__writemsr(IA32_FMASK, (UINT64)Saved);
			InterlockedExchange64(&gBtfFmaskSaved[Cpu], 0);
		}
	}
	return 0;
}

UINT64
NxcBtfFmaskSaved(
	_In_ UINT32 Cpu
	)
{
	return (Cpu < NXC_BP_MAX_CPUS) ? (UINT64)gBtfFmaskSaved[Cpu] : 0;
}

BOOLEAN NxcBtfKernelOn(void) { return (gBtfKernelOn != 0) ? TRUE : FALSE; }

static ULONG_PTR
BtfSetOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	/*
	 * ⚠ READ-MODIFY-WRITE. DEBUGCTL is a shared register: LBR's enable moved off it on this part but
	 * BTS, TR and the freeze bits still live here, and constructing it from scratch would silently
	 * disarm whatever else set them. Only bit 1 is touched.
	 */
	CONST UINT64 Ctl = __readmsr(IA32_DEBUGCTL);

	if (Context != 0)
		__writemsr(IA32_DEBUGCTL, Ctl | DEBUGCTL_BTF);
	else
		__writemsr(IA32_DEBUGCTL, Ctl & ~DEBUGCTL_BTF);

	return 0;
}

NTSTATUS
NxcBtfArm(
	_In_ UINT32 Pid,
	_In_ UINT64 FilterStart,
	_In_ UINT64 FilterEnd,
	_In_ BOOLEAN Kernel
	)
{
	/*
	 * ⚠ THE CR3 IS RESOLVED HERE, NOT PASSED IN. Usermode has no business holding a CR3, and a
	 * caller-supplied one would let a typo arm branch-stepping against an arbitrary address space --
	 * which, unlike a wrong breakpoint, floods that process with #DB the moment its TF is set.
	 * Resolved exactly the way `bp set` does it, through the same proven DTB offset and the same
	 * fail-closed refusal, so there is one derivation and not a second that must agree with it.
	 */
	/*
	 * ⚠⚠ THE INTERLOCK, AND IT IS NOT ADVISORY. Every branch of the target raises a #DB. If claiming
	 * is off the dispatcher passes them through, and a passed-through single-step is delivered to the
	 * target as STATUS_SINGLE_STEP and KILLS it -- while we are the reason the trap exists at all.
	 *
	 * ⚠ THE SENTENCE THAT USED TO BE HERE WAS FALSE, AND IT IS WHY THE DATA BRANCH SHIPPED A GATE
	 * (corrected). It read: "Every other surface here can be armed with claiming off and
	 * merely produce nothing." A DATA breakpoint armed with claiming off did NOT produce nothing --
	 * its #DB is reported as STATUS_SINGLE_STEP exactly like this one, and killed the target just
	 * the same. BpDispatch now claims on OWNERSHIP alone, so no surface has that failure mode.
	 *
	 * THIS REFUSAL STAYS -- it is the interlock in its correct place: refuse to ARM, rather than arm
	 * and then decline to handle what the arming causes. It refuses in the KERNEL where the flag is
	 * authoritative, rather than trusting a usermode check a second caller would not make.
	 */
	if (!NxcBpdClaimEnabled())
		return STATUS_DEVICE_NOT_READY;

	/*
	 * ⚠⚠⚠ --kernel IS A HARD BLOCK. IT BUGCHECKED THIS MACHINE ON AND THE REASON IS
	 * STRUCTURAL, NOT A BUG TO BE FIXED.
	 *
	 *     UNEXPECTED_KERNEL_MODE_TRAP (7f), arg1 = 8 = EXCEPTION_DOUBLE_FAULT
	 *     FAILURE_BUCKET_ID: 0x7f_8_STACKPTR_ERROR_nt!KiDebugTrapOrFault
	 *     BAD_STACK_POINTER: 0000008def10f7e0     <-- a USER stack, at CPL 0
	 *     PROCESS_NAME:      chain8.exe
	 *
	 * SYSCALL completes with CPL 0, RIP at IA32_LSTAR, and RSP STILL THE USER STACK -- the kernel
	 * switches stacks in software, several instructions later. Masking TF in IA32_FMASK is what
	 * stops a debug exception being taken in that window. Clear it and the #DB fires at LSTAR's
	 * first instruction; KiDebugTrapOrFault is not on an IST, so the CPU pushes the trap frame onto
	 * the USER stack at CPL 0, and that is the double fault above.
	 *
	 * ⚠ D120's tier 2 said FMASK's TF bit "prevents user-mode single-stepping from continuing into
	 * kernel-mode code during system calls" and I read that as a SECURITY property to opt out of. It
	 * is also a STRUCTURAL one: there is no valid kernel stack yet. Same class of mistake as hooking
	 * an IDT handler entry before swapgs -- see NXC_HOOK_IS_IDT_HANDLER, which is blocked for the
	 * mirror-image reason.
	 *
	 * No filter and no scoping can avoid it: the trap happens before any of our code runs.
	 */
	if (Kernel)
		return STATUS_ACCESS_DENIED;

	PEPROCESS Proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Proc)) || Proc == NULL)
		return STATUS_NOT_FOUND;

	CONST UINT32 DtbOff = NxcTranslateDtbOffset();
	if (DtbOff == 0)
	{
		ObfDereferenceObject(Proc);
		/* Distinct from NOT_FOUND on purpose: "no such process" and "we cannot derive its CR3" send
		 * the reader to completely different places (D-note in Bp.c, same trap). */
		return STATUS_NOT_CAPABLE;
	}

	CONST UINT64 Cr3 = *(UINT64*)((UINT8*)Proc + DtbOff);
	ObfDereferenceObject(Proc);

	CONST UINT64 Frame = Cr3 & 0x000FFFFFFFFFF000ULL;
	if (Frame == 0)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠ ONE TARGET AT A TIME, AND A SECOND ARM IS REFUSED RATHER THAN SILENTLY RETARGETED. The ring
	 * carries no address-space field, so records from two targets would be indistinguishable after
	 * the fact -- exactly the "attributing one process's addresses to another" failure the hit drain
	 * had to be fixed for.
	 */
	if (InterlockedCompareExchange(&gBtfArmed, 1, 0) != 0)
		return STATUS_DEVICE_BUSY;

	/*
	 * ⚠ THE COMMIT MARKERS ARE ZEROED, NOT JUST REWOUND. They hold write-index+1 from the PREVIOUS
	 * arming, and both indices restart at 0 -- so a leftover marker of 1 would make the next drain
	 * accept slot 0 as committed and hand back a record from a DIFFERENT PROCESS as if it belonged
	 * to this one. Safe here and only here: nothing is stepping yet, because no target has TF set.
	 */
	RtlZeroMemory(gBtfRing, sizeof(gBtfRing));
	RtlZeroMemory((void*)gBtfCommit, sizeof(gBtfCommit));
	InterlockedExchange64(&gBtfWrite, 0);
	InterlockedExchange64(&gBtfRead, 0);

	InterlockedExchange64(&gBtfCr3, (LONG64)Frame);
	InterlockedExchange(&gBtfPid, (LONG)Pid);
	InterlockedExchange64(&gBtfSeq, 0);
	InterlockedExchange64(&gBtfDropped, 0);
	InterlockedExchange64(&gBtfTaken, 0);
	InterlockedExchange64(&gBtfTfFailed, 0);
	InterlockedExchange64(&gBtfFiltered, 0);

	/* A reversed pair would silently record nothing; refuse it by normalising to "no filter". */
	if (FilterEnd >= FilterStart)
	{
		InterlockedExchange64(&gBtfFiltStart, (LONG64)FilterStart);
		InterlockedExchange64(&gBtfFiltEnd,   (LONG64)FilterEnd);
	}
	else
	{
		InterlockedExchange64(&gBtfFiltStart, 0);
		InterlockedExchange64(&gBtfFiltEnd,   0);
	}

	/*
	 * ⚠ CR3 IS PUBLISHED BEFORE THE MSR. If the MSR went first, a trap could arrive on another core
	 * between the two and find gBtfCr3 still zero -- classified as not ours and passed through to
	 * the target as STATUS_SINGLE_STEP, which kills it. Publishing the target first means the worst
	 * case is a trap we could have claimed and did not, and that direction is survivable.
	 */
	/*
	 * ⚠ FMASK BEFORE BTF, and both before anything can trap. Unmasking TF changes nothing on its own
	 * -- no thread has TF set yet -- so the ordering costs nothing, and doing it the other way round
	 * would leave a window where the target steps ring 3 and silently stops at its first syscall.
	 */
	if (Kernel)
	{
		InterlockedExchange(&gBtfKernelOn, 1);
		(void)KeIpiGenericCall(BtfFmaskOnEachCpu, 1);
	}

	(void)KeIpiGenericCall(BtfSetOnEachCpu, 1);
	return STATUS_SUCCESS;
}

BOOLEAN
NxcBtfDraining(void)
{
	return (gBtfDraining != 0) ? TRUE : FALSE;
}

NTSTATUS
NxcBtfDisarm(void)
{
	if (InterlockedCompareExchange(&gBtfArmed, 0, 1) != 1)
		return STATUS_INVALID_DEVICE_STATE;

	/*
	 * ⚠⚠ THE DRAIN, AND WITHOUT IT THE TARGET DIED ROUGHLY ONE RUN IN FOUR.
	 *
	 * Stopping branch stepping means clearing EFLAGS.TF in the target. Usermode holds the thread
	 * handles, so that looked like usermode's job -- and it CANNOT DO IT UNDER LOAD. Measured
	 * with the target taking ~2.3 million traps a second, SuspendThread and
	 * Thread32Next come back with nothing ("0 of 0 thread(s) examined") because nothing in that
	 * process gets scheduled long enough to be caught. TF therefore stayed SET, this function then
	 * cleared the CR3 and stopped claiming, and the next step was passed through and delivered as
	 * STATUS_SINGLE_STEP:
	 *
	 *     run 1 : passthru delta 0   alive=True    why=8 MATCH_BTF
	 *     run 2 : passthru delta 0   alive=True    why=8 MATCH_BTF
	 *     run 3 : passthru delta 1   alive=FALSE   why=3 NO_SLOT      <-- died
	 *     run 4 : passthru delta 0   alive=True    why=8 MATCH_BTF
	 *
	 * ⚠ SO THE KERNEL STOPS THE STEPPING, using the one mechanism that IS reliably reaching that
	 * thread -- the trap itself. While draining we keep claiming, and on each trap the dispatcher
	 * CLEARS TF in the frame instead of re-setting it. A thread cannot escape this: to escape it
	 * would have to execute, and executing is what traps.
	 *
	 * Usermode still clears TF as well, for threads BLOCKED in a syscall that never trap during the
	 * drain. Neither side covers both cases; together they do.
	 */
	InterlockedExchange(&gBtfDraining, 1);

	/*
	 * ⚠ THE MSR GOES FIRST HERE, THE MIRROR OF THE ARM ORDER AND FOR THE MIRROR REASON. Clearing the
	 * target first would leave BTF set on the cores with nothing willing to claim the traps it
	 * causes, and those reach the target as STATUS_SINGLE_STEP. Stop the source, then stop claiming.
	 *
	 * ⚠ THIS DOES NOT CLEAR THE TARGET'S EFLAGS.TF -- the caller set it and the caller clears it.
	 * With BTF off and TF still set the thread steps per INSTRUCTION, so the usermode side must
	 * clear TF, and it is the only side holding the thread handle to do it with.
	 */
	(void)KeIpiGenericCall(BtfSetOnEachCpu, 0);

	/*
	 * ⚠ CR3 IS STILL PUBLISHED HERE -- we are still claiming. With BTF off and TF not yet cleared
	 * the target steps per INSTRUCTION, which is a storm, but every one of those traps is claimed
	 * and each clears TF in its own frame, so the storm is what ENDS the stepping.
	 *
	 * Wait for it to go quiet: sample the trap counter and stop when it stops moving. Bounded, so a
	 * target that is descheduled forever cannot hang this command -- and if the bound is hit, TF may
	 * still be set on a thread that never ran, which is exactly the case usermode's own clear covers.
	 */
	LONG64 Last = gBtfTaken;
	for (UINT32 i = 0; i < 100u; i++)     /* <= ~1 s */
	{
		LARGE_INTEGER Interval;
		Interval.QuadPart = -100000LL;    /* 10 ms, relative */
		(void)KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		CONST LONG64 Now = gBtfTaken;
		if (Now == Last)
			break;                        /* two samples with no trap: nothing is stepping */
		Last = Now;
	}

	InterlockedExchange64(&gBtfCr3, 0);
	InterlockedExchange(&gBtfDraining, 0);

	/*
	 * ⚠ RESTORED LAST AND UNCONDITIONALLY. Leaving TF unmasked would leave ANY future thread that
	 * sets its own TF able to follow itself into the kernel -- a property of the machine we removed
	 * and did not put back. Done AFTER the drain, so a thread still mid-syscall is not stranded
	 * stepping code whose traps we have already stopped claiming.
	 */
	if (InterlockedCompareExchange(&gBtfKernelOn, 0, 1) == 1)
		(void)KeIpiGenericCall(BtfFmaskOnEachCpu, 0);

	/* Records are NOT discarded. Disarming is not throwing away what was already captured. */
	return STATUS_SUCCESS;
}

BOOLEAN
NxcBtfIsTarget(
	_In_ UINT64 Cr3FrameMasked
	)
{
	CONST LONG64 Target = gBtfCr3;
	return (Target != 0 && (UINT64)Target == Cr3FrameMasked) ? TRUE : FALSE;
}

void
NxcBtfOnTrap(
	_In_ UINT64  Rip,
	_In_ BOOLEAN TfRestored
	)
{
	CONST UINT64 Seq = (UINT64)InterlockedIncrement64(&gBtfSeq);
	InterlockedIncrement64(&gBtfTaken);

	/*
	 * ⚠⚠ THIS COUNTER WAS DEAD AND THE COMPILER SAID SO IN ONE LINE.
	 *
	 * gBtfTfFailed was declared, reset on arm, exposed through NxcBtfTfFailed() and reported by
	 * `bp btf` -- and NOTHING EVER INCREMENTED IT, because this definition took one parameter while
	 * the header declared two and BpDispatch.c passed two. Under the x64 convention the extra
	 * argument simply sat in RDX and was discarded, so the whole path built and ran, and the command
	 * reported "TF-failed: 0" no matter how many times TF could not be put back.
	 *
	 * That is the exact failure this project bans: reporting a number the surface did not produce.
	 * The single warning C4029 that named it had been passing by every build.
	 *
	 * ⚠ AND FALSE HERE IS A TRACE-ENDING EVENT, not a detail. Without TF written back into the trap
	 * frame the thread takes no further #DB, so the trace stops dead -- indistinguishable from a
	 * target that stopped branching unless it is counted, which is why the counter exists.
	 */
	if (!TfRestored)
		InterlockedIncrement64(&gBtfTfFailed);

	/*
	 * ⚠ FILTERED OUT BEFORE A SLOT IS RESERVED. Reserving first and abandoning the slot would
	 * leave an uncommitted hole, and the drain stops at the first of those -- so one filtered branch
	 * would truncate the whole trace behind it. Counted, and NOT as a drop: a drop is a branch that
	 * qualified and was lost, this is the command doing what it was told.
	 */
	CONST LONG64 FStart = gBtfFiltStart;
	CONST LONG64 FEnd   = gBtfFiltEnd;
	if (FEnd != 0 && (Rip < (UINT64)FStart || Rip > (UINT64)FEnd))
	{
		InterlockedIncrement64(&gBtfFiltered);
	}
	else
	{
	/*
	 * ⚠⚠ A REAL RING, AND THE FIRST VERSION WAS NOT ONE. measured.
	 *
	 * gBtfWrite used to be a monotonic index straight into the array, so once it passed 8192 EVERY
	 * further branch dropped forever and draining freed nothing. Usermode was then given a
	 * continuous adaptive drain to keep up with the stream -- and it kept exactly 8192 records,
	 * because there was nothing to keep up WITH. The buffer was one-shot wearing a ring's name.
	 *
	 * ⚠ RESERVATION IS A CAS, NOT AN UNCONDITIONAL INCREMENT. A drop must NOT consume an index: if
	 * it did, slot w%MAX would still hold the previous lap's record while the drain waited for
	 * index w, and the drain would stall there permanently -- turning a full ring into a dead one.
	 * Indices are therefore consumed only by writes that actually happen, so [Read, Write) is always
	 * exactly the set of records that exist.
	 *
	 * Contention is near zero in practice: one thread is being stepped, so one core reserves.
	 */
	LONG64 Idx = -1;
	for (;;)
	{
		CONST LONG64 W = gBtfWrite;
		if (W - gBtfRead >= (LONG64)NXC_BTF_MAX_RECORDS)
			break;                                   /* full -- and no index consumed */
		if (InterlockedCompareExchange64(&gBtfWrite, W + 1, W) == W)
		{
			Idx = W;
			break;
		}
	}

	if (Idx >= 0)
	{
		CONST LONG64 Slot = Idx % (LONG64)NXC_BTF_MAX_RECORDS;
		NXC_BTF_REC* CONST R = &gBtfRing[Slot];
		R->Rip       = Rip;
		R->Cpu       = KeGetCurrentProcessorNumberEx(NULL);
		R->Reserved0 = 0;

		R->Sequence = Seq;

		/*
		 * ⚠⚠ THE COMMIT MARKER IS A SEPARATE ARRAY, AND IT HAS TO BE ONCE SLOTS ARE REUSED.
		 *
		 * The non-wrapping version used `Sequence != 0` to mean "committed". That cannot survive a
		 * ring: slot w%MAX still holds the SEQUENCE of record w-MAX, which is non-zero, so every
		 * stale record would read as committed and the drain would hand back the previous lap.
		 *
		 * gBtfCommit[slot] holds the write index that filled it, plus one. The drain wants index r
		 * and accepts the slot only if the marker is exactly r+1 -- so a slot still being filled, or
		 * holding an older lap, is refused rather than guessed at. Written LAST and with a barrier,
		 * because it is what publishes the other three fields.
		 */
		InterlockedExchange64(&gBtfCommit[Slot], Idx + 1);
	}
	else
	{
		/*
		 * ⚠ THE RING STOPS RATHER THAN WRAPPING, AND THE DROP IS COUNTED. A wrap would hand back a
		 * trace whose beginning is missing with nothing saying so, and a control-flow trace read from
		 * the wrong starting point is worse than a short one -- it looks complete. Sequence numbers
		 * keep going, so the gap between the last kept record and the drop count is exact.
		 *
		 * gBtfWrite deliberately keeps climbing past the ring: decrementing it back would race with
		 * another core's reservation and could hand the same slot to two writers.
		 */
		InterlockedIncrement64(&gBtfDropped);
	}

	/*
	 * ⚠⚠ RE-ARM. THE HARDWARE CLEARED BTF WHEN IT RAISED THIS #DB (SDM 19.4.3). Without this the
	 * next trap is a per-INSTRUCTION step, not a branch step -- a flood, not a silence. This is the
	 * only place in the driver that can do it, because it is the only code that runs between two
	 * branches of the stepped thread.
	 */
	}

	if (gBtfDraining == 0)
		__writemsr(IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL) | DEBUGCTL_BTF);
}

NTSTATUS
NxcBtfDrain(
	_Out_writes_(Cap) NXC_BTF_REC* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT64* Dropped
	)
{
	if (Out == NULL || Got == NULL || Total == NULL || Dropped == NULL)
		return STATUS_INVALID_PARAMETER;

	*Got     = 0;
	*Total   = 0;
	*Dropped = (UINT64)gBtfDropped;

	CONST LONG64 Start   = gBtfRead;
	CONST LONG64 Written = gBtfWrite;

	/*
	 * ⚠ ONLY THE CONTIGUOUS COMMITTED PREFIX. A slot can be RESERVED and not yet filled by another
	 * core; its commit marker is then not r+1 and the prefix ends there. Stopping hands back a short
	 * drain -- which the caller sees, because Total says what remains -- instead of a record whose
	 * Rip is whatever the slot held on its previous lap.
	 *
	 * ⚠ OLDEST FIRST, because this is a CONTROL-FLOW TRACE and its order is its meaning. The hit ring
	 * hands back newest-first and that is right for evidence you sample; it would be wrong here,
	 * where reading the sequence backwards inverts every call into a return.
	 *
	 * ⚠ AND THE COPY IS OUTSIDE ANY MUTUAL EXCLUSION, deliberately: a slot in [Read, Write) that is
	 * committed is not revisited by the trap path until Read passes it, and Read is advanced only
	 * here. Nothing in this function can make a branching core wait.
	 */
	UINT32 Take = 0;
	while (Take < Cap && (Start + (LONG64)Take) < Written)
	{
		CONST LONG64 Want = Start + (LONG64)Take;
		CONST LONG64 Slot = Want % (LONG64)NXC_BTF_MAX_RECORDS;
		if (gBtfCommit[Slot] != Want + 1)
			break;   /* reserved, not yet committed -- the prefix ends here */
		Out[Take] = gBtfRing[Slot];
		Take++;
	}

	/* Advance the read cursor. Nothing is moved: the old version shuffled the remainder down, and
	 * that copy was the whole reason a lock had to be held long enough to matter. */
	InterlockedExchange64(&gBtfRead, Start + (LONG64)Take);

	LONG64 Remaining = Written - (Start + (LONG64)Take);
	if (Remaining < 0) Remaining = 0;

	*Got   = Take;
	*Total = (UINT32)Remaining;   /* D3: what is STILL HELD, so a truncated drain cannot read as complete */
	return STATUS_SUCCESS;
}

BOOLEAN NxcBtfArmed(void)   { return (gBtfArmed != 0) ? TRUE : FALSE; }
UINT32  NxcBtfPid(void)     { return (UINT32)gBtfPid; }
UINT64  NxcBtfTaken(void)   { return (UINT64)gBtfTaken; }
UINT64  NxcBtfDropped(void) { return (UINT64)gBtfDropped; }
UINT64  NxcBtfTfFailed(void){ return (UINT64)gBtfTfFailed; }
UINT64  NxcBtfFiltered(void){ return (UINT64)gBtfFiltered; }
