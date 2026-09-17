/**
 * @file Bp.c
 * @brief Read debug registers, per-CPU and per-thread. STAGE 1: nothing is armed. Reasoning in Bp.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "Bp.h"
#include "Freeze.h"
#include "Threads.h"
#include "Processes.h"
#include "Translate.h"
#include "BpDispatch.h"
#include "Idt.h"   /* NxcIdtDeriveVolatileGprs */
#include "Hook.h"          /* NxcHookExceptionObserverCount -- the live arming interlock */

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define BpLog NxcLogExt

/*
 * DR7 layout (SDM Vol 3, 17.2.4). Written out because every field is a two-bit slice at a computed
 * shift, and one wrong shift reports a breakpoint as watching the wrong thing in the wrong way --
 * well-formed and false, which is the failure this file must not produce.
 *
 *   bits 0..7    L0 G0 L1 G1 L2 G2 L3 G3
 *   bit  13      GD   general detect -- see the hazard note in Bp.h
 *   bits 16..17  R/W0   00 exec, 01 write, 10 I/O, 11 read-write
 *   bits 18..19  LEN0   00 1 byte, 01 2 bytes, 10 8 bytes, 11 4 bytes
 *   ... R/Wn at 16 + n*4, LENn at 18 + n*4
 */
#define DR7_RW_SHIFT(n)   (16u + (n) * 4u)
#define DR7_LEN_SHIFT(n)  (18u + (n) * 4u)

/*
 * CONTEXT_DEBUG_REGISTERS for AMD64. Defined here because it lives in winnt.h, which the km build
 * does not pull in -- the same reason NXC_RUNTIME_FUNCTION is written out in Idt.h. Asking for ONLY
 * the debug registers matters: a full CONTEXT_ALL would make the kernel gather FP and vector state
 * this has no use for, on every thread of the target.
 */
#define NXC_CONTEXT_AMD64             0x00100000L
#define NXC_CONTEXT_DEBUG_REGISTERS   (NXC_CONTEXT_AMD64 | 0x00000010L)

static NXC_BP_CPU* volatile gBpOut = NULL;
static volatile LONG        gBpCap = 0;

static ULONG_PTR
BpReadOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	NXC_BP_CPU* CONST Out = gBpOut;
	if (Out == NULL)
		return 0;

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= (ULONG)gBpCap || Cpu >= NXC_BP_MAX_CPUS)
		return 0;

	NXC_BP_CPU* CONST C = &Out[Cpu];
	C->CpuNumber = Cpu;

	/*
	 * ⚠ DR4 AND DR5 ARE NEVER TOUCHED. With CR4.DE clear they ALIAS DR6/DR7; with it set they raise
	 * #UD. Neither is information, and one of them is a bugcheck here.
	 */
	C->Dr[0] = __readdr(0);
	C->Dr[1] = __readdr(1);
	C->Dr[2] = __readdr(2);
	C->Dr[3] = __readdr(3);
	C->Dr6   = __readdr(6);
	C->Dr7   = __readdr(7);

	UINT32 Enabled = 0;
	for (UINT32 i = 0; i < 4; i++)
	{
		C->Local[i]  = (UINT8)((C->Dr7 >> (i * 2u)) & 1u);
		C->Global[i] = (UINT8)((C->Dr7 >> (i * 2u + 1u)) & 1u);
		C->Type[i]   = (UINT8)((C->Dr7 >> DR7_RW_SHIFT(i)) & 3u);
		C->Len[i]    = (UINT8)((C->Dr7 >> DR7_LEN_SHIFT(i)) & 3u);

		/*
		 * ⚠ THE OWNER, WHICH THE DRIVER HAS ALWAYS KNOWN AND NEVER SAID. `gBpSlotPid` is set when a
		 * slot is armed and cleared when it is released; the dispatcher already stamps hit records
		 * with it. Reporting it here is what lets usermode ask whether that process is still alive.
		 *
		 * Safe at this IRQL: a plain read of a static array, no lock, no dereference. This runs
		 * inside an IPI on every core, so anything else would be a problem.
		 *
		 * 0 means the slot is not armed -- gclear zeroes it, so a stale pid cannot outlive a slot.
		 */
		/* Through the accessor: gBpSlotPid is defined further down this file, and the header
		 * declaration is what makes the read legal here without moving the definition. */
		C->OwnerPid[i] = NxcBpSlotPid(i);

		if (C->Local[i] || C->Global[i])
			Enabled++;
	}
	C->Enabled = Enabled;
	return 0;
}

NTSTATUS
NxcBpRead(
	_Out_writes_(Cap) NXC_BP_CPU* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	CONST ULONG Cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	CONST ULONG Use  = (Cpus < Cap) ? Cpus : Cap;
	*Total = (UINT32)Cpus;

	RtlZeroMemory(Out, (SIZE_T)Use * sizeof(NXC_BP_CPU));

	gBpOut = Out;
	gBpCap = (LONG)Use;
	(void)KeIpiGenericCall(BpReadOnEachCpu, 0);
	gBpOut = NULL;
	gBpCap = 0;

	UINT32 Busy = 0;
	for (ULONG i = 0; i < Use; i++)
		if (Out[i].Enabled != 0)
			Busy++;

	if (Busy != 0)
	{
		/* The reason the read comes first: four registers per core, and anything can own them.
		 * Arming over a live breakpoint steals it as silently as arming PT over Ipt.sys would. */
		BpLog("bp: %u of %lu core(s) already have a debug register ENABLED\n", Busy, Use);
	}

	*Got = (UINT32)Use;
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * STAGE 2 -- ARMING, behind an interlock that makes the fatal state impossible.
 * ============================================================================================= */

/* Defined below with the read path it was written for; declared here because the arming path needs
 * the same refusal and the two must never diverge into separate frozen checks. */
static BOOLEAN BpProcessIsFrozen(_In_ UINT32 Pid);

/*
 * What we have armed. Also the classifier's slot table: `bp set` records the target's CR3 here and
 * NxcBpdClassify compares the faulting CR3 against it, which is what stops us claiming a debugger's
 * breakpoint that happens to occupy the same slot number in a different thread.
 */
static NXC_BPD_SLOT gBpSlots[NXC_BPD_MAX_SLOTS];

/* Per-slot opt-in to bounding the PT buffer at each trap -- see NxcBpSlotSetPtBound. */
static volatile LONG gBpSlotPtBound[NXC_BPD_MAX_SLOTS];
static UINT32       gBpSlotPid[NXC_BPD_MAX_SLOTS];

BOOLEAN
NxcBpHandlerInstalled(void)
{
	/*
	 * ⚠⚠ ASKS THE HOOK TABLE. It used to `return FALSE` under a comment calling itself "the single
	 * line that changes when item 15 lands" (: the dispatcher is now named and
	 * `bp dispatch install` targets it -- the design notes).
	 *
	 * Item 15 landing did NOT make the answer TRUE. It made it ANSWERABLE, which is a different
	 * thing, and the distinction is the whole point:
	 *
	 *   - a hardcoded TRUE is a fake verdict, and a far more dangerous one than the FALSE it
	 *     replaced. Arming a debug register while nothing observes the dispatcher kills the target
	 *     on its first hit -- precisely the outcome the original refusal existed to prevent;
	 *   - it would go on claiming a handler exists after `bp dispatch remove`, so the guard would
	 *     be wrong exactly when it matters;
	 *   - and it would be unfalsifiable, which this project treats as disqualifying on its own.
	 *
	 * A count of live NXC_HOOK_FLAG_EXCEPTION hooks is a FACT, so it follows install and remove
	 * without anyone remembering to update it.
	 */
	return (NxcHookExceptionObserverCount() > 0) ? TRUE : FALSE;
}

/*
 * The APC probe's kernel routine. Runs in the target thread at APC_LEVEL. It does the MINIMUM a
 * special kernel APC legally can: free the object the enqueuer allocated, and record that it ran.
 * Nothing here touches the target's state -- the question is only whether it executes at all.
 */
static volatile LONG64 gApcProbeRan = 0;

static void
BpApcProbeRoutine(
	_In_ PVOID Apc,
	_In_ PVOID* NormalRoutine,
	_In_ PVOID* NormalContext,
	_In_ PVOID* SystemArgument1,
	_In_ PVOID* SystemArgument2
	)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	InterlockedIncrement64(&gApcProbeRan);
	ExFreePoolWithTag(Apc, 'aBxN');
}

NTSTATUS
NxcBpCtxProbe(
	_In_ UINT32 CrossPid,
	_Out_ UINT64* OutSelf,
	_Out_ UINT64* OutSameProcess,
	_Out_ UINT64* OutCrossProcess,
	_Out_ UINT64* OutIrql,
	_Out_ UINT64* OutApcInsert,
	_Out_ UINT64* OutApcRan,
	_Out_ UINT64* OutFlagProbe
	)
{
	/*
	 * ⚠⚠ A POSITIVE CONTROL FOR PsGetContextThread, WHICH HAS NEVER WORKED HERE.
	 *
	 * measured: every thread of a live usermode process refuses with
	 * STATUS_UNSUCCESSFUL, and `bp list` has been reading 0 contexts of N threads since stage 1 --
	 * while printing "no thread has a debug register set", which its own count never supported. A
	 * read that fails and a read that finds nothing are opposite facts and looked identical.
	 *
	 * Windows takes a COMPLETELY DIFFERENT PATH for the current thread (capture in place) than for
	 * any other (queue a special kernel APC onto the target and wait). Probing all three cases in
	 * one call is what separates "this API cannot work from this driver at all" from "the APC
	 * rendezvous is what fails", and four hardware runs of inference did not.
	 *
	 * READS ONLY. Nothing is armed, no context is written, no DR is touched.
	 */
	*OutApcInsert    = 0;
	*OutApcRan       = 0;
	*OutFlagProbe    = 0;
	*OutSelf         = (UINT64)(ULONG_PTR)STATUS_NOT_SUPPORTED;
	*OutSameProcess  = (UINT64)(ULONG_PTR)STATUS_NOT_FOUND;
	*OutCrossProcess = (UINT64)(ULONG_PTR)STATUS_NOT_FOUND;

	/*
	 * ⚠ THE IRQL WE ARE ACTUALLY AT. Established by disassembling ntoskrnl:
	 * PsGetContextThread has EXACTLY ONE STATUS_UNSUCCESSFUL path --
	 *
	 *     KeInitializeEvent -> KeInitializeApc -> KeInsertQueueApc
	 *                                             test al, al
	 *                                             je -> mov eax, 0xC0000001
	 *
	 * -- so the API is refusing because KeInsertQueueApc returned FALSE, which happens when the
	 * TARGET thread cannot take an APC. It fires for our OWN thread too, which means Windows has no
	 * direct-capture shortcut here: every case goes through the APC, and the caller's own state is
	 * therefore a suspect. CR8 is an intrinsic, so this costs no nt import.
	 */
	*OutIrql = (UINT64)(__readcr8() & 0xFull);

	CONTEXT* CONST Ctx = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), 'pBxN');
	if (Ctx == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	/* 1. THE CURRENT THREAD. */
	RtlZeroMemory(Ctx, sizeof(*Ctx));
	Ctx->ContextFlags = NXC_CONTEXT_DEBUG_REGISTERS;
	*OutSelf = (UINT64)(ULONG_PTR)PsGetContextThread(PsGetCurrentThread(), Ctx, KernelMode);

	/*
	 * ⚠⚠ WHICH ContextFlags ARE REFUSED -- the instrumentation that replaces guessing.
	 *
	 * ntoskrnl cannot be probed from inside, but the FLAGS are the one input we control, and
	 * PsGetContextThread's main path returns a status PROPAGATED from sub_920F2C rather than any
	 * immediate we can grep for. So vary the request instead of reading the callee:
	 *
	 *   CONTROL  succeeds, DEBUG_REGISTERS fails  -> the debug-register request specifically is
	 *                                                rejected, and the whole per-thread DR design
	 *                                                is unavailable regardless of the caller.
	 *   ALL fail                                   -> nothing about DRs; PsGetContextThread cannot
	 *                                                serve THIS caller at all.
	 *
	 * Either answer is decisive, and neither needs another hardware round to interpret.
	 */
	{
		static CONST UINT32 kFlagSets[4] = {
			NXC_CONTEXT_AMD64 | 0x00000001L,   /* CONTEXT_CONTROL          */
			NXC_CONTEXT_AMD64 | 0x00000002L,   /* CONTEXT_INTEGER          */
			NXC_CONTEXT_AMD64 | 0x00000010L,   /* CONTEXT_DEBUG_REGISTERS  */
			NXC_CONTEXT_AMD64 | 0x0000000BL    /* CONTEXT_FULL             */
		};
		UINT64 Packed = 0;
		for (UINT32 i = 0; i < 4; i++)
		{
			RtlZeroMemory(Ctx, sizeof(*Ctx));
			Ctx->ContextFlags = kFlagSets[i];
			CONST NTSTATUS St =
				PsGetContextThread(PsGetCurrentThread(), Ctx, KernelMode);
			/* One nibble each: 0 = succeeded, 1 = refused. The STATUS is already known to be
			 * 0xC0000001 everywhere; what is unknown is WHICH REQUESTS it refuses. */
			Packed |= ((UINT64)(NT_SUCCESS(St) ? 0u : 1u)) << (i * 4);
		}
		*OutFlagProbe = Packed;
		BpLog("bp ctxprobe: flags CONTROL/INTEGER/DEBUG/FULL refused-mask 0x%llX\n", Packed);
	}

	/* 2 and 3. ANOTHER thread -- in our own process, then in the target's. Both go through the APC
	 *    rendezvous, so a split between 1 and these two names the APC path exactly. */
	CONST UINT32 SelfPid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

	for (UINT32 Pass = 0; Pass < 2; Pass++)
	{
		CONST UINT32 Pid = (Pass == 0) ? SelfPid : CrossPid;
		UINT64* CONST Out = (Pass == 0) ? OutSameProcess : OutCrossProcess;

		if (Pid == 0)
			continue;

		UINT32 Cap = 64;
		NXCMD_THREAD_ENTRY* CONST List = (NXCMD_THREAD_ENTRY*)ExAllocatePool2(
			POOL_FLAG_NON_PAGED, (SIZE_T)Cap * sizeof(NXCMD_THREAD_ENTRY), 'lBxN');
		if (List == NULL)
			continue;

		UINT32 Listed = 0, Found = 0, SweptTo = 0;
		if (NT_SUCCESS(NxcEnumThreads(Pid, List, Cap, &Listed, &Found, &SweptTo)))
		{
			for (UINT32 i = 0; i < Listed; i++)
			{
				if (List[i].Terminating)
					continue;

				PETHREAD Thread = NULL;
				if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)List[i].ThreadId,
				                                         &Thread)) || Thread == NULL)
					continue;

				/* Skip our own thread here -- case 1 already covers it, and including it would
				 * let the direct path masquerade as a working APC rendezvous. */
				if (Thread == PsGetCurrentThread())
				{
					ObfDereferenceObject(Thread);
					continue;
				}

				RtlZeroMemory(Ctx, sizeof(*Ctx));
				Ctx->ContextFlags = NXC_CONTEXT_DEBUG_REGISTERS;
				*Out = (UINT64)(ULONG_PTR)PsGetContextThread(Thread, Ctx, KernelMode);
				ObfDereferenceObject(Thread);
				break;      /* one representative thread is the whole question */
			}
		}
		ExFreePoolWithTag(List, 'lBxN');
	}

	ExFreePoolWithTag(Ctx, 'pBxN');

	/*
	 * ⚠⚠ THE DISCRIMINATOR. PsGetContextThread's only failure is KeInsertQueueApc returning FALSE,
	 * and it fails for our OWN thread at PASSIVE with the exports correctly bound. Two very
	 * different worlds explain that, and nothing measured so far separates them:
	 *
	 *   - this driver cannot queue an APC AT ALL (its dispatch thread is in a state that refuses
	 *     them), in which case every per-thread context operation is dead as designed; or
	 *   - PsGetContextThread does something before the insert that we do not, and a plain APC
	 *     queued from here works fine.
	 *
	 * So queue one DIRECTLY, to our own thread only -- the zero-risk case. No code runs in another
	 * process; the routine records that it ran and frees the object.
	 */
	{
		/* KAPC is 0x58 bytes on x64; sized generously rather than pulled from a header the km build
		 * does not carry -- the same reason NXC_RUNTIME_FUNCTION is written out by hand in Idt.h.
		 * NON-PAGED: an APC object must never be pageable. */
		UINT8* CONST Apc = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, 'aBxN');
		if (Apc != NULL)
		{
			KeInitializeApc(Apc, (PVOID)PsGetCurrentThread(), 0 /* OriginalApcEnvironment */,
			                (PVOID)BpApcProbeRoutine, NULL, NULL, KernelMode, NULL);
			*OutApcInsert = KeInsertQueueApc(Apc, NULL, NULL, 0) ? 1ull : 0ull;

			/*
			 * ⚠ ONLY FREE IT IF THE INSERT FAILED. A successful insert leaves the object owned by
			 * the kernel's APC queue until the routine runs; freeing it here would be a
			 * use-after-free inside the dispatcher. The routine frees it in the success case.
			 */
			if (*OutApcInsert == 0)
				ExFreePoolWithTag(Apc, 'aBxN');
		}
	}

	BpLog("bp ctxprobe: self 0x%08X, same-process 0x%08X, cross-process(pid %u) 0x%08X\n",
	      (UINT32)*OutSelf, (UINT32)*OutSameProcess, CrossPid, (UINT32)*OutCrossProcess);
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * GLOBAL ARMING -- the architecture that is actually available to us.
 *
 * ⚠ WHY THIS EXISTS AT ALL. measured (D54): PsGetContextThread refuses this caller for
 * EVERY ContextFlags, so per-thread CONTEXT is unavailable and the design Bp.h describes cannot
 * run. Cheat Engine's DBKKernel hit the same wall -- its threads.c has both context APIs commented
 * out -- and moved to GLOBAL debug registers with the owning process identified in its own handler.
 * That is the path, and the attribution half was built while solving item 15.
 *
 * ⚠⚠ AND WHY IT IS INTERLOCKED ON CLAIMING. A GLOBAL breakpoint watches a LINEAR ADDRESS ON EVERY
 * CPU, regardless of which address space is loaded. A completely unrelated process with unrelated
 * data at the same linear address WILL trap. With nothing claiming, that process receives
 * STATUS_SINGLE_STEP and dies -- and it would look like that program crashed on its own.
 *
 * So arming globally REQUIRES the claim path to be live. Not a warning: a refusal.
 * ============================================================================================= */

/*
 * ⚠ A BATCH, NOT A SINGLE SLOT -- and the count is what closes `bp fork`'s arming window.
 *
 * Arming two sites as two separate NxcBpSetGlobal calls means two IPI rounds, and between them only
 * site 0 is live. A hit taken there is REAL but UNPAIRED, and an unpaired hit is indistinguishable
 * in the record from half of a paired capture. Measured as not-biting on 08-07 (19/19), which is
 * evidence and not a guarantee.
 *
 * One array with a count covers both cases in ONE expression, so the single-slot path and the pair
 * path cannot drift -- rather than a second "arm two" routine that has to agree with this one.
 */
static volatile UINT64 gArmAddress[NXC_BPD_MAX_SLOTS];
static volatile UINT32 gArmSlot[NXC_BPD_MAX_SLOTS];
static volatile UINT32 gArmType[NXC_BPD_MAX_SLOTS];
static volatile UINT32 gArmLen[NXC_BPD_MAX_SLOTS];
static volatile UINT32 gArmCount   = 0;

/*
 * ⚠ SET ONLY BY NxcBpSetFork. While it holds, NxcBpSetGlobal APPENDS to the batch and does NOT
 * broadcast -- so a pair passes through every gate of the ordinary arming path and then goes live
 * in ONE IPI round, with no instant where only one site is armed.
 *
 * Deferring rather than writing a second "arm two slots" routine: that routine would have to keep
 * agreeing with this one's gate list forever, which is the shape behind most of this session's bugs.
 */
static volatile LONG gArmDeferIpi = 0;
static volatile LONG   gArmEnable  = 0;   /* 1 = arm, 0 = disarm this slot */

static ULONG_PTR
BpArmOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	CONST UINT32 Count = gArmCount;
	if (Count == 0 || Count > NXC_BPD_MAX_SLOTS)
		return 0;

	/*
	 * ⚠ EVERY SLOT IN THE BATCH IS PROGRAMMED BEFORE THIS CORE RETURNS, which is the entire point:
	 * the pair goes live together on each core, so there is no window in which one site is armed and
	 * the other is not.
	 */
	for (UINT32 b = 0; b < Count; b++)
	{
	CONST UINT32 Slot = gArmSlot[b];
	if (Slot >= NXC_BPD_MAX_SLOTS)
		continue;

	/*
	 * ⚠ READ-MODIFY-WRITE, exactly as the per-thread path did. Another agent may own a DIFFERENT
	 * slot on this core -- a debugger, an anti-cheat -- and constructing DR7 from scratch would
	 * disarm theirs silently. Only this slot's bits are touched.
	 */
	UINT64 Dr7 = __readdr(7);

	CONST UINT64 EnableMask = 3ULL << (Slot * 2u);            /* L and G for this slot */
	CONST UINT64 FieldMask  = 0xFULL << DR7_RW_SHIFT(Slot);   /* R/W and LEN           */

	Dr7 &= ~(EnableMask | FieldMask);

	if (gArmEnable)
	{
		/*
		 * ⚠ G, NOT L -- and this is the whole reason the approach works. Windows CLEARS the local
		 * bits across a context switch (Ke386SanitizeDr), which is exactly why Bp.h rejected raw
		 * per-CPU arming as "works sometimes". The GLOBAL bit is not cleared, so the breakpoint
		 * stays live on this core across every thread that runs on it -- and attribution is done
		 * afterwards, by CR3, in the classifier.
		 */
		Dr7 |= 2ULL << (Slot * 2u);                                   /* G only, never L */
		Dr7 |= ((UINT64)(gArmType[b] & 3u)) << DR7_RW_SHIFT(Slot);
		Dr7 |= ((UINT64)(gArmLen[b]  & 3u)) << DR7_LEN_SHIFT(Slot);

		switch (Slot)
		{
		case 0:  __writedr(0, gArmAddress[b]); break;
		case 1:  __writedr(1, gArmAddress[b]); break;
		case 2:  __writedr(2, gArmAddress[b]); break;
		default: __writedr(3, gArmAddress[b]); break;
		}
	}
	else
	{
		switch (Slot)
		{
		case 0:  __writedr(0, 0); break;
		case 1:  __writedr(1, 0); break;
		case 2:  __writedr(2, 0); break;
		default: __writedr(3, 0); break;
		}
	}

	/* DR7 last: the address must be in place before the enable bit makes it live. */
	__writedr(7, Dr7);
	}   /* end of the batch loop -- every slot in the request is live before this core returns */

	return 0;
}

UINT32
NxcBpOwnedSlotMask(
	_In_reads_(NXC_BPD_MAX_SLOTS) CONST UINT64* Dr
	)
{
	/*
	 * ⚠ WHICH ENABLED SLOTS ARE OURS -- the datum `bp list`'s contention check never had.
	 *
	 * It warned "ALREADY IN USE, arming over one steals it silently" for EVERY enabled slot,
	 * including the ones we had just armed ourselves (measured: it warned about
	 * stealing a breakpoint from us). A check that cannot tell its own work from a stranger's is
	 * useless at exactly the moment it matters -- with our slot 0 live, a genuinely foreign
	 * breakpoint appearing in slot 1 would read identically.
	 *
	 * Matched on slot index AND address, not index alone: another agent using the same slot number
	 * for a different address is precisely the contention worth reporting.
	 */
	UINT32 Mask = 0;
	for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
	{
		if (gBpSlots[i].Armed && gBpSlots[i].Address == Dr[i])
			Mask |= (1u << i);
	}
	return Mask;
}

UINT32
NxcBpSlotPid(
	_In_ UINT32 Slot
	)
{
	return (Slot < NXC_BPD_MAX_SLOTS) ? gBpSlotPid[Slot] : 0u;
}

CONST NXC_BPD_SLOT*
NxcBpSlotTable(void)
{
	/*
	 * ⚠ READ-ONLY VIEW FOR THE CLASSIFIER. The slot table lives here because `bp set` owns it, but
	 * NxcBpdClassify runs in the exception observer, in another file, on the system's exception
	 * path. Handing out one const pointer beats mirroring the table into BpDispatch.c: two copies
	 * that must agree is the defect shape this project keeps paying for, and a stale mirror would
	 * mean claiming an exception against a breakpoint that is no longer armed.
	 */
	return gBpSlots;
}

NTSTATUS
NxcBpSetGlobal(
	_In_ UINT32 Pid,
	_In_ UINT64 Address,
	_In_ UINT32 Type,
	_In_ UINT32 Len,
	_Out_ UINT32* OutSlot,
	_Out_ UINT32* OutCpus
	)
{
	*OutSlot = NXC_BPD_MAX_SLOTS;
	*OutCpus = 0;

	/* ⚠ GATE 1: something must be OBSERVING the dispatcher, or a hit kills the target outright. */
	if (!NxcBpHandlerInstalled())
	{
		BpLog("bp gset: REFUSED -- nothing is observing the exception dispatcher.\n");
		return STATUS_DEVICE_NOT_READY;
	}

	/*
	 * ⚠⚠ GATE 2, AND IT IS THE ONE THAT MAKES THIS SAFE TO EXIST. A global DR fires in EVERY
	 * process at that linear address. Observing is not enough -- the observer must CLAIM, or an
	 * unrelated process that happens to touch the same linear address receives STATUS_SINGLE_STEP
	 * and dies, looking for all the world like it crashed by itself.
	 */
	{
		UINT32 Enabled = 0;
		UINT64 Claimed = 0, Refused = 0;
		NxcBpdClaimState(&Enabled, &Claimed, &Refused);
		if (Enabled == 0)
		{
			BpLog("bp gset: REFUSED -- claiming is DISABLED. A global breakpoint fires in every "
			      "process at that linear address, and with nothing claiming it, an unrelated "
			      "process would take a STATUS_SINGLE_STEP and die.\n");
			return STATUS_INVALID_DEVICE_STATE;
		}
	}

	/* ⚠ GATE 3: EXECUTE breakpoints cannot be resumed without EFLAGS.RF, so the claim path refuses
	 * them -- arming one would mean a #DB nobody can swallow, forever. Refused HERE too rather than
	 * left to fail later: the two checks share the reason, not just the outcome. */
	if (Type == 0u)
	{
		/*
		 * ⚠⚠ EXECUTE IS NO LONGER UNCONDITIONALLY REFUSED -- IT IS GATED ON A PROVEN OFFSET.
		 *
		 * An execute breakpoint traps BEFORE the instruction retires, so the claim path must set
		 * EFLAGS.RF in the target's KTRAP_FRAME or the same instruction traps forever. That offset is
		 * DERIVED from live trap frames and fails closed (32 agreeing frames, zero disagreements);
		 * until it is proven, arming one would mean a #DB nobody can resume.
		 *
		 * ⚠ REFUSED HERE AS WELL AS IN THE CLAIM PATH, and the two consult THE SAME PREDICATE. Two
		 * checks that must agree is how install and remove drifted apart
		 * (an earlier finding); one shared
		 * expression is the structural answer.
		 *
		 * ⚠ AND THE REFUSAL NAMES ITS CAUSE. A flat "not supported" for two different states is the
		 * shape that misdiagnosed `bp set` five times running
		 * (an earlier finding).
		 */
		UINT32 EfOffset = 0;
		if (!NxcBpdEflagsProven(&EfOffset))
		{
			BpLog("bp gset: REFUSED -- EXECUTE breakpoints need EFLAGS.RF in the target's "
			      "KTRAP_FRAME, and the offset is NOT YET PROVEN (candidate +0x%X). The dispatcher "
			      "hook derives it from live frames; `bp dispatch status` reports the agreement "
			      "count. Nothing else is required -- exceptions arrive on their own.\n",
			      EfOffset);
			return STATUS_NOT_SUPPORTED;
		}

		/*
		 * ⚠ AN EXECUTE BREAKPOINT MUST HAVE LEN 00 (one byte). R/W=00 with any other length is
		 * UNDEFINED per the SDM -- not merely discouraged. The per-thread path has enforced this
		 * since it was written; the global path never reached the check because it refused execute
		 * outright, so lifting that refusal without bringing the rule across would have opened
		 * exactly the hole the older path was careful to close.
		 */
		if (Len != 0u)
		{
			BpLog("bp gset: REFUSED -- an EXECUTE breakpoint requires LEN=1 byte; R/W=00 with any "
			      "other length is UNDEFINED per the SDM. Drop --len.\n");
			return STATUS_INVALID_PARAMETER;
		}

		BpLog("bp gset: EXECUTE permitted -- KTRAP_FRAME.EFlags PROVEN at +0x%X, so the claim path "
		      "can set RF and resume past the trapping instruction.\n", EfOffset);
	}

	/* Alignment, per the SDM: the CPU MASKS the low bits by LEN, so an unaligned data breakpoint
	 * silently watches a different address. Same rule as the per-thread path, same reason. */
	{
		UINT64 AlignMask;
		switch (Len)
		{
		case 1u:  AlignMask = 1u; break;
		case 2u:  AlignMask = 7u; break;
		case 3u:  AlignMask = 3u; break;
		default:  AlignMask = 0u; break;
		}
		if ((Address & AlignMask) != 0)
		{
			BpLog("bp gset: REFUSED -- %llX is not %u-byte aligned.\n",
			      Address, (UINT32)(AlignMask + 1u));
			return STATUS_DATATYPE_MISALIGNMENT;
		}
	}

	/*
	 * ⚠ DERIVE THE VOLATILE-GPR OFFSETS HERE, AND NOWHERE EARLIER. Gate 4 of that derivation requires
	 * the EFlags offset PROVEN FROM LIVE TRAP FRAMES, which does not exist at driver load or at hook
	 * install -- it accumulates from real exception traffic. Arming is the first moment it is
	 * available, and it runs at PASSIVE where decoding a function is affordable.
	 *
	 * ⚠ FAILURE IS NOT FATAL TO THE ARM. A breakpoint without register capture is still a working
	 * breakpoint; what must never happen is a hit record claiming registers it could not derive. The
	 * map simply stays invalid and NXC_BPD_PRESENT_VOLGPR stays clear.
	 */
	{
		UINT32 ProvenEflags = 0;
		if (NxcBpdEflagsProven(&ProvenEflags))
		{
			NXC_GPR_MAP Map;
			CONST NTSTATUS GSt = NxcIdtDeriveVolatileGprs(1u /* #DB gate */, ProvenEflags, &Map);
			NxcBpdSetGprStatus(GSt, Map.Gate);   /* travels to `bp dispatch status`; the log does not */

			/*
			 * ⚠ PUBLISHED ON BOTH PATHS. The map carries Begin and the first decoded bytes, and those
			 * matter MOST when the derivation refused -- that is the whole comparison. Safe because
			 * BpdRecordHit gates every read on Map.Valid, which a refusal leaves FALSE, so an invalid
			 * map is diagnostic data that can never become register values in a hit record.
			 */
			NxcBpdSetGprMap(&Map);

			/*
			 * ⚠ R12-R15 ARE A SEPARATE DERIVATION, ANCHORED ON THE FUNNEL, NOT THE TRAP ENTRY.
			 * KEXCEPTION_FRAME is built by the funnel, and its base is proven there by
			 * `mov rdx, rsp`. Independent of the volatile map on purpose: two structures, two
			 * anchors, two proofs, and a failure in one must never supply the other.
			 */
			NXC_NVGPR_MAP NvMap;
			CONST NTSTATUS NSt = NxcIdtDeriveNonvolatileGprs(NxcBpdFunnelVa(), &NvMap);
			NxcBpdSetNvGprMap(&NvMap);
			if (!NT_SUCCESS(NSt) || !NvMap.Valid)
				BpLog("bp gset: R12-R15 NOT derived (0x%08X, gate %u) -- reported ABSENT, not zero.\n",
				      NSt, NvMap.Gate);

			if (!NT_SUCCESS(GSt) || !Map.Valid)
				BpLog("bp gset: volatile GPRs NOT derived (0x%08X, gate %u) -- hits will report them "
				      "ABSENT rather than zero. The breakpoint itself is unaffected.\n",
				      GSt, Map.Gate);
		}
	}

	UINT32 Slot = NXC_BPD_MAX_SLOTS;
	for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
		if (!gBpSlots[i].Armed) { Slot = i; break; }
	if (Slot == NXC_BPD_MAX_SLOTS)
		return STATUS_INSUFFICIENT_RESOURCES;

	/* The target's CR3 -- what makes a hit ATTRIBUTABLE rather than merely detected. Without it a
	 * global breakpoint is indistinguishable from everyone else's. */
	PEPROCESS Proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Proc)) || Proc == NULL)
		return STATUS_NOT_FOUND;

	CONST UINT32 DtbOff = NxcTranslateDtbOffset();
	if (DtbOff == 0)
	{
		ObfDereferenceObject(Proc);
		return STATUS_NOT_CAPABLE;
	}
	CONST UINT64 Cr3 = *(UINT64*)((UINT8*)Proc + DtbOff);
	ObfDereferenceObject(Proc);

	/*
	 * ⚠ THE SLOT IS RECORDED BEFORE THE REGISTERS ARE WRITTEN. The instant DR7's G bit goes live on
	 * the first core, a #DB can arrive on another -- and the classifier reads this table to decide
	 * whether to claim it. Arming first would leave a window where our own breakpoint classifies as
	 * "not ours" and kills the target.
	 */
	gBpSlots[Slot].Cr3      = Cr3 & 0x000FFFFFFFFFF000ULL;
	gBpSlots[Slot].Address  = Address;
	gBpSlots[Slot].Type     = Type;
	gBpSlots[Slot].WantStep = 0;
	gBpSlots[Slot].Global   = 1;   /* changes what a foreign CR3 MEANS -- see NXC_BPD_SLOT::Global */
	gBpSlots[Slot].Armed    = 1;
	gBpSlotPid[Slot]        = Pid;

	gArmAddress[0] = Address;
	gArmSlot[0]    = Slot;
	gArmType[0]    = Type;
	gArmLen[0]     = Len;
	gArmCount      = 1;
	gArmEnable     = 1;
	(void)KeIpiGenericCall(BpArmOnEachCpu, 0);

	*OutSlot = Slot;
	*OutCpus = (UINT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	BpLog("bp gset: slot %u armed GLOBALLY on %u core(s) at %llX for pid %u (cr3 %llX)\n",
	      Slot, *OutCpus, Address, Pid, gBpSlots[Slot].Cr3);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcBpClearGlobal(
	_In_ UINT32 Slot
	)
{
	if (Slot >= NXC_BPD_MAX_SLOTS || !gBpSlots[Slot].Armed)
		return STATUS_NOT_FOUND;

	/*
	 * ⚠ REGISTERS FIRST, TABLE SECOND -- the mirror image of arming, and for the mirror reason.
	 * Clearing the table first would leave the DR live with no slot backing it, so a hit in that
	 * window classifies as "not ours" and kills whatever process took it.
	 */
	gArmSlot[0] = Slot;
	gArmCount   = 1;
	gArmEnable  = 0;
	(void)KeIpiGenericCall(BpArmOnEachCpu, 0);

	RtlZeroMemory(&gBpSlots[Slot], sizeof(gBpSlots[Slot]));
	gBpSlotPid[Slot] = 0;

	/* ⚠ THE OPT-IN DIES WITH THE SLOT. A stale flag would make the NEXT arming of this slot pay the
	 * TraceEn toggle on every trap with nobody having asked -- and unrequested cost is exactly what
	 * "off by default" existed to prevent. */
	InterlockedExchange(&gBpSlotPtBound[Slot], 0);

	BpLog("bp gclear: slot %u disarmed on every core\n", Slot);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcBpSetFork(
	_In_ UINT32 Pid,
	_In_ UINT64 Va0,
	_In_ UINT64 Va1,
	_Out_ UINT32* OutSlot0,
	_Out_ UINT32* OutSlot1,
	_Out_ UINT32* OutCpus
	)
{
	*OutSlot0 = 0;
	*OutSlot1 = 0;
	*OutCpus  = 0;

	/*
	 * ⚠ TWO SLOTS ON ONE ADDRESS IS NOT A FORK. It would burn a slot and report every execution
	 * twice, and doubled counts are worse than missing ones because they look like data. Refused
	 * before anything is armed, so the refusal costs nothing to undo.
	 */
	if (Va0 == Va1)
	{
		BpLog("bp fork: REFUSED -- both sites are 0x%llX. A fork needs TWO DISTINCT code addresses; "
		      "arming one twice burns a slot and doubles its hit count.\n", Va0);
		return STATUS_INVALID_PARAMETER;
	}

	/*
	 * Type 0 / Len 0 = EXECUTE, one byte. Not a parameter: a fork point is a CODE address, so there
	 * is no data variant to choose between, and R/W=00 with any other length is UNDEFINED per the SDM.
	 * Every other gate (claiming enabled, EFLAGS.RF proven, alignment, slot availability) lives in
	 * NxcBpSetGlobal and is reached through it rather than restated -- one expression, not two that
	 * must agree.
	 */
	UINT32 Cpus0 = 0, Cpus1 = 0;

	/*
	 * ⚠⚠ ONE IPI ROUND FOR BOTH SITES. Two separate arms leave a window in which only site 0 is live,
	 * and a hit taken there is REAL but UNPAIRED -- indistinguishable in the record from half of a
	 * paired capture. It measured as not-biting (19/19 exactly), which is evidence and
	 * not a guarantee; "worth doing only if a measurement shows it" was settling for the easier one.
	 *
	 * DEFERRED rather than DUPLICATED: both sites still pass through every gate in NxcBpSetGlobal --
	 * claiming enabled, RF proven, alignment, slot availability, CR3 lookup. A second "arm two slots"
	 * routine would have to agree with that list forever, which is the shape that has produced most
	 * of this session's defects.
	 */
	InterlockedExchange(&gArmDeferIpi, 1);
	gArmCount = 0;

	CONST NTSTATUS St0 = NxcBpSetGlobal(Pid, Va0, 0u, 0u, OutSlot0, &Cpus0);
	if (!NT_SUCCESS(St0))
	{
		InterlockedExchange(&gArmDeferIpi, 0);
		gArmCount = 0;
		BpLog("bp fork: site 0 (0x%llX) refused (0x%08X) -- nothing was armed.\n", Va0, St0);
		return St0;
	}

	CONST NTSTATUS St1 = NxcBpSetGlobal(Pid, Va1, 0u, 0u, OutSlot1, &Cpus1);

	InterlockedExchange(&gArmDeferIpi, 0);
	if (!NT_SUCCESS(St1))
	{
		/*
		 * ⚠ ROLL BACK, AND THIS IS THE WHOLE REASON THE COMMAND EXISTS. Leaving site 0 armed after
		 * reporting failure produces hits that are TRUE but UNPAIRED, and an unpaired hit is
		 * indistinguishable in the record from half of a paired capture. "The command failed" and
		 * "nothing is armed" have to be one fact, not two that happen to agree.
		 */
		/* ⚠ NOTHING IS LIVE IN SILICON YET -- the broadcast never happened -- so this releases a
		 * RESERVED slot rather than disarming hardware. There is no instant at which site 0 was
		 * armed alone, which is the whole point of deferring. */
		gArmCount = 0;
		CONST NTSTATUS Undo = NxcBpClearGlobal(*OutSlot0);

		BpLog("bp fork: site 1 (0x%llX) refused (0x%08X); site 0 slot %u rolled back (0x%08X). "
		      "Nothing is armed.\n", Va1, St1, *OutSlot0, Undo);

		*OutSlot0 = 0;
		return St1;
	}

	/*
	 * ⚠ REPORT THE SMALLER COUNT (D3). Each arm programs DR7 through its own IPI round, so the two
	 * can in principle differ; saying "24" when one round reached 23 would be reporting the request
	 * rather than the result. The pair is only as armed as its weaker site.
	 */
	/* Both slots sit in the batch; ONE broadcast makes the pair live together on every core. */
	(void)KeIpiGenericCall(BpArmOnEachCpu, 0);
	gArmCount = 0;

	UNREFERENCED_PARAMETER(Cpus0);
	UNREFERENCED_PARAMETER(Cpus1);
	*OutCpus = (UINT32)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	BpLog("bp fork: slots %u+%u armed EXECUTE at 0x%llX / 0x%llX for pid %u on %u core(s). "
	      "⚠ the two arms are separate IPI rounds, so a hit on site 0 taken before site 1 went live "
	      "is unpaired -- the sequence numbers make that visible rather than silent.\n",
	      *OutSlot0, *OutSlot1, Va0, Va1, Pid, *OutCpus);

	return STATUS_SUCCESS;
}

void
NxcBpSlotSetPtBound(
	_In_ UINT32 Slot,
	_In_ BOOLEAN On
	)
{
	if (Slot < NXC_BPD_MAX_SLOTS)
		InterlockedExchange(&gBpSlotPtBound[Slot], On ? 1 : 0);
}

BOOLEAN
NxcBpSlotPtBound(
	_In_ UINT32 Slot
	)
{
	return (Slot < NXC_BPD_MAX_SLOTS) && (gBpSlotPtBound[Slot] != 0);
}

BOOLEAN
NxcBpProcessHasBreakpoints(
	_In_ UINT32 Pid
	)
{
	for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
	{
		if (gBpSlots[i].Armed && gBpSlotPid[i] == Pid)
			return TRUE;
	}
	return FALSE;
}

/**
 * Write DR0-3/DR7 into one thread's saved CONTEXT.
 *
 * ⚠ READ-MODIFY-WRITE, NEVER A BLIND WRITE. The thread may already have debug registers set by
 * somebody else -- a debugger, or an earlier `bp set` of ours on a different slot. Constructing DR7
 * from scratch would silently disarm theirs, which is the same theft `lbr arm` refuses to commit
 * against a contended ring. So the current context is fetched, one slot is modified, and the rest is
 * left exactly as found.
 */
static NTSTATUS
BpApplyToThread(
	_In_ PETHREAD Thread,
	_In_ CONTEXT* Ctx,
	_In_ UINT32 Slot,
	_In_ UINT64 Address,
	_In_ UINT32 Type,
	_In_ UINT32 Len,
	_In_ BOOLEAN Enable,
	/* 0 = no failure, 1 = PsGetContextThread refused, 2 = PsSetContextThread refused. Optional so
	 * the disarm path, which has nowhere to report it, can pass NULL. */
	_Out_opt_ UINT32* OutStage
	)
{
	if (OutStage != NULL)
		*OutStage = 0;

	RtlZeroMemory(Ctx, sizeof(*Ctx));
	Ctx->ContextFlags = NXC_CONTEXT_DEBUG_REGISTERS;

	/*
	 * ⚠ WHICH CALL FAILED IS THE WHOLE QUESTION. This function returns early on a GET failure and
	 * finally on a SET failure, and both surface to the caller as one indistinguishable status --
	 * so "22 threads refused" was reported as PsSetContextThread refusing when the GET may never
	 * have succeeded. Three separate wrong causes were named today by inferring instead of
	 * measuring; the stage is now recorded rather than assumed.
	 */
	CONST NTSTATUS GetSt = PsGetContextThread(Thread, Ctx, KernelMode);
	if (!NT_SUCCESS(GetSt))
	{
		if (OutStage != NULL)
			*OutStage = 1;      /* PsGetContextThread */
		return GetSt;
	}

	switch (Slot)
	{
	case 0: Ctx->Dr0 = Enable ? Address : 0; break;
	case 1: Ctx->Dr1 = Enable ? Address : 0; break;
	case 2: Ctx->Dr2 = Enable ? Address : 0; break;
	default: Ctx->Dr3 = Enable ? Address : 0; break;
	}

	/* Clear this slot's L/G pair and its R/W + LEN field, then set only what we want. */
	CONST UINT64 EnableMask = 3ULL << (Slot * 2u);
	CONST UINT64 FieldMask  = 0xFULL << DR7_RW_SHIFT(Slot);

	UINT64 Dr7 = Ctx->Dr7 & ~(EnableMask | FieldMask);

	if (Enable)
	{
		/*
		 * L (local), not G (global). Windows uses the local bits and clears them across a task
		 * switch, which matches per-thread semantics; setting G would leave the breakpoint live for
		 * whatever ran next on that core -- exactly the "works sometimes" failure D22 warned about.
		 */
		Dr7 |= 1ULL << (Slot * 2u);
		Dr7 |= ((UINT64)(Type & 3u)) << DR7_RW_SHIFT(Slot);
		Dr7 |= ((UINT64)(Len  & 3u)) << DR7_LEN_SHIFT(Slot);
	}

	Ctx->Dr7          = Dr7;
	Ctx->ContextFlags = NXC_CONTEXT_DEBUG_REGISTERS;

	CONST NTSTATUS SetSt = PsSetContextThread(Thread, Ctx, KernelMode);
	if (!NT_SUCCESS(SetSt) && OutStage != NULL)
		*OutStage = 2;          /* PsSetContextThread */
	return SetSt;
}

NTSTATUS
NxcBpSet(
	_In_ UINT32 Pid,
	_In_ UINT64 Address,
	_In_ UINT32 Type,
	_In_ UINT32 Len,
	_Out_ UINT32* OutSlot,
	_Out_ UINT32* OutThreads,
	_Out_ UINT64* OutDiag,
	_Out_ UINT64* OutDiag2
	)
{
	*OutSlot    = NXC_BPD_MAX_SLOTS;
	*OutThreads = 0;
	*OutDiag    = 0;   /* zeroed up front: every early refusal below returns before the loop */
	*OutDiag2   = 0;

	/*
	 * ⚠⚠ THE INTERLOCK. An armed debug register with no handler on the exception path raises #DB on
	 * its first hit, and the target receives STATUS_SINGLE_STEP and DIES -- looking exactly like the
	 * target crashing on its own. Bp.h has said so in prose since this file existed; prose is not an
	 * interlock. This is.
	 */
	if (!NxcBpHandlerInstalled())
	{
		/* ⚠ SAYS WHAT TO DO, because the reason changed. This used to read "item 15 is not built",
		 * which is no longer true and would send a reader to build something that exists. The
		 * dispatcher is identified and hookable; nothing is hooked on it AT THIS MOMENT. */
		BpLog("bp set: REFUSED -- nothing is observing the exception dispatcher right now, so a "
		      "#DB we cause would not be intercepted and would kill the target on its first hit. "
		      "Run `bp dispatch install` first; this refusal clears by itself once it succeeds.\n");
		return STATUS_DEVICE_NOT_READY;
	}

	/*
	 * ⚠⚠ THE TWO ENCODING RULES THE PROCESSOR DOES NOT ENFORCE FOR YOU. Intel SDM: the CPU "uses
	 * the LEN bits to MASK the low-order bits of the addresses in the debug address registers", so
	 * an unaligned data breakpoint does not fail -- it silently watches a DIFFERENT address.
	 * "Improperly aligned code or data breakpoint addresses will not yield the expected results."
	 *
	 * That is the worst outcome this surface can produce: armed, reported as success, watching
	 * somewhere else. It would look exactly like a breakpoint that never gets hit, and the search
	 * would go anywhere except the LEN field.
	 *
	 * DR7 LEN encoding is 00=1, 01=2, 10=8, 11=4 -- deliberately NOT numeric order, so the mask is
	 * derived from the MEANING rather than from the bit value.
	 */
	{
		UINT64 AlignMask;
		switch (Len)
		{
		case 1u:  AlignMask = 1u; break;   /* 2 bytes -- word aligned  */
		case 2u:  AlignMask = 7u; break;   /* 8 bytes -- qword aligned */
		case 3u:  AlignMask = 3u; break;   /* 4 bytes -- dword aligned */
		default:  AlignMask = 0u; break;   /* 1 byte  -- any address   */
		}

		if ((Address & AlignMask) != 0)
		{
			BpLog("bp set: REFUSED -- %llX is not %u-byte aligned. The CPU MASKS the low bits by "
			      "LEN, so this would arm silently on %llX and watch the wrong place.\n",
			      Address, (UINT32)(AlignMask + 1u), Address & ~AlignMask);
			return STATUS_DATATYPE_MISALIGNMENT;
		}

		/*
		 * ⚠ AN EXECUTE BREAKPOINT MUST HAVE LEN 00. R/W=00 with any other length is UNDEFINED per
		 * the SDM -- not merely discouraged. Refused rather than silently corrected: quietly
		 * rewriting a caller's request is how a command starts lying about what it did.
		 */
		if (Type == 0u && Len != 0u)
		{
			BpLog("bp set: REFUSED -- an EXECUTE breakpoint requires LEN=1 byte; R/W=00 with any "
			      "other length is UNDEFINED. Drop --len2/4/8, or use --write / --rw.\n");
			return STATUS_INVALID_PARAMETER_MIX;
		}
	}

	if (BpProcessIsFrozen(Pid))
	{
		BpLog("bp set: pid %u is FROZEN -- PsSetContextThread would queue an APC that is never "
		      "delivered, and this call would never return\n", Pid);
		return STATUS_INVALID_DEVICE_STATE;
	}

	UINT32 Slot = NXC_BPD_MAX_SLOTS;
	for (UINT32 i = 0; i < NXC_BPD_MAX_SLOTS; i++)
	{
		if (!gBpSlots[i].Armed) { Slot = i; break; }
	}
	if (Slot == NXC_BPD_MAX_SLOTS)
	{
		BpLog("bp set: all %u debug-register slots are in use\n", NXC_BPD_MAX_SLOTS);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* The target's CR3, which is what makes a hit ATTRIBUTABLE rather than merely detected. */
	PEPROCESS Proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Proc)) || Proc == NULL)
		return STATUS_NOT_FOUND;

	CONST UINT32 DtbOff = NxcTranslateDtbOffset();
	if (DtbOff == 0)
	{
		ObfDereferenceObject(Proc);
		BpLog("bp set: the EPROCESS DirectoryTableBase offset is not proven -- without a CR3 a hit "
		      "cannot be attributed, and an unattributable breakpoint is one we would have to claim "
		      "blindly\n");
		/*
		 * ⚠⚠ NOT STATUS_DEVICE_NOT_READY. It was, and it shares that code with the "nothing is
		 * observing the dispatcher" refusal above -- so usermode, which can only see the status,
		 * printed the INTERLOCK explanation for this failure. On that produced a
		 * confident, specific and WRONG diagnosis: "no #DB handler is installed" while one was
		 * demonstrably live and observing, pointing the reader at item 15, which was complete.
		 *
		 * Two refusals with different causes must not be distinguishable only by guessing. A wrong
		 * diagnosis is worse than a bare failure -- it sends the next hour somewhere useless.
		 */
		return STATUS_NOT_CAPABLE;
	}
	CONST UINT64 Cr3 = *(UINT64*)((UINT8*)Proc + DtbOff);
	ObfDereferenceObject(Proc);

	enum { BP_MAX_THREADS = 512 };
	NXCMD_THREAD_ENTRY* CONST List =
		(NXCMD_THREAD_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                     BP_MAX_THREADS * sizeof(NXCMD_THREAD_ENTRY), 'sBxN');
	if (List == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	UINT32 Listed = 0, Found = 0, SweptTo = 0;
	CONST NTSTATUS ESt = NxcEnumThreads(Pid, List, BP_MAX_THREADS, &Listed, &Found, &SweptTo);
	if (!NT_SUCCESS(ESt))
	{
		ExFreePoolWithTag(List, 'sBxN');
		return ESt;
	}

	CONTEXT* CONST Ctx = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), 'cBxN');
	if (Ctx == NULL)
	{
		ExFreePoolWithTag(List, 'sBxN');
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/*
	 * ⚠⚠ COUNT WHY, NOT JUST HOW MANY. This loop used to discard every reason and return a bare
	 * STATUS_UNSUCCESSFUL when nothing armed -- which is what it did on the first live attempt
	 * (pid 4). "0 of N armed" with no cause is the same failure shape as a classifier
	 * that only counts rejects: it says the attempt failed and nothing about which of four quite
	 * different things went wrong.
	 *
	 * The first apply failure's NTSTATUS is kept and RETURNED in place of the generic code, because
	 * the reason PsSetContextThread refused IS the finding -- and for a kernel-thread target it is
	 * a very different answer from a usermode one.
	 */
	UINT32 Armed = 0, SkipTerminating = 0, SkipLookup = 0, ApplyFailed = 0;
	UINT32 GetFailed = 0, SetFailed = 0, FirstGetSt = 0, FirstSetSt = 0;
	NTSTATUS FirstApplyFailure = STATUS_SUCCESS;

	for (UINT32 i = 0; i < Listed; i++)
	{
		if (List[i].Terminating)
		{
			SkipTerminating++;
			continue;
		}

		PETHREAD Thread = NULL;
		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)List[i].ThreadId, &Thread)) ||
		    Thread == NULL)
		{
			SkipLookup++;
			continue;
		}

		UINT32 Stage = 0;
		CONST NTSTATUS ASt = BpApplyToThread(Thread, Ctx, Slot, Address, Type, Len, TRUE, &Stage);
		if (NT_SUCCESS(ASt))
		{
			Armed++;
		}
		else
		{
			ApplyFailed++;
			if (Stage == 1) { GetFailed++; if (FirstGetSt == 0) FirstGetSt = (UINT32)ASt; }
			else            { SetFailed++; if (FirstSetSt == 0) FirstSetSt = (UINT32)ASt; }
			if (FirstApplyFailure == STATUS_SUCCESS)
				FirstApplyFailure = ASt;
		}

		ObfDereferenceObject(Thread);
	}

	ExFreePoolWithTag(Ctx, 'cBxN');
	ExFreePoolWithTag(List, 'sBxN');

	/*
	 * ⚠⚠ THE BREAKDOWN GOES BACK TO THE CALLER, NOT ONLY TO BpLog. On this returned a
	 * bare STATUS_UNSUCCESSFUL and logged the counts to DbgPrint, where the operator cannot see
	 * them -- so usermode invented a cause ("every thread refused the context write") that the
	 * numbers did not support. The generic code in fact proves the OPPOSITE: FirstApplyFailure was
	 * never set, so BpApplyToThread was never reached, so the loss is in ENUMERATION.
	 *
	 * A diagnostic the operator cannot read is not reported. Packed rather than a new wire struct:
	 * four 16-bit counts in one qword, unpacked and printed by PlatformCtl.
	 */
	*OutDiag = ((UINT64)(Found           & 0xFFFFu))
	         | ((UINT64)(SkipTerminating & 0xFFFFu) << 16)
	         | ((UINT64)(SkipLookup      & 0xFFFFu) << 32)
	         | ((UINT64)(ApplyFailed     & 0xFFFFu) << 48);

	/*
	 * WHICH call refused, and with what. Reported separately from the return status because that
	 * status is AMBIGUOUS: PsGet/SetContextThread can themselves return STATUS_UNSUCCESSFUL, which
	 * is indistinguishable from this function's own generic fallback. The counts and these two
	 * statuses are the authority; the single returned NTSTATUS is not.
	 */
	*OutDiag2 = ((UINT64)FirstGetSt) | ((UINT64)FirstSetSt << 32);
	if (GetFailed != 0 || SetFailed != 0)
		BpLog("bp set: apply stage -- %u refused at PsGetContextThread (first 0x%08X), "
		      "%u at PsSetContextThread (first 0x%08X)\n",
		      GetFailed, FirstGetSt, SetFailed, FirstSetSt);

	if (Armed == 0)
	{
		BpLog("bp set: 0 of %u thread(s) armed for pid %u -- %u terminating, %u lookup failed, "
		      "%u refused by PsSetContextThread (first status 0x%08X).\n",
		      Found, Pid, SkipTerminating, SkipLookup, ApplyFailed, (UINT32)FirstApplyFailure);

		/* Return the REAL reason when there is one. A generic failure code here would hide the
		 * one piece of information that distinguishes "this thread cannot take a context" from
		 * "there was nothing to arm" -- and the generic code is itself evidence that NOTHING was
		 * ever applied, which is a different failure entirely. */
		return (FirstApplyFailure != STATUS_SUCCESS) ? FirstApplyFailure : STATUS_UNSUCCESSFUL;
	}

	gBpSlots[Slot].Cr3      = Cr3;
	gBpSlots[Slot].Address  = Address;
	gBpSlots[Slot].Armed    = 1;
	gBpSlots[Slot].WantStep = 0;
	/* The claim path refuses to swallow an EXECUTE breakpoint -- see NXC_BPD_SLOT::Type. Recorded
	 * here, at the one place a slot is armed, so the enforcement cannot be bypassed by a caller. */
	gBpSlots[Slot].Type     = Type;
	gBpSlotPid[Slot]        = Pid;

	*OutSlot    = Slot;
	*OutThreads = Armed;

	/* ⚠ COVERAGE IS POINT-IN-TIME AND IS REPORTED AS SUCH. A thread created after this line has its
	 * own context and none of our registers. */
	BpLog("bp set: slot %u on %llX for pid %u -- %u of %u live thread(s) armed. COVERAGE IS A "
	      "SNAPSHOT: threads created later are NOT covered.\n", Slot, Address, Pid, Armed, Found);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcBpClear(
	_In_ UINT32 Slot,
	_Out_ UINT32* OutThreads
	)
{
	*OutThreads = 0;

	if (Slot >= NXC_BPD_MAX_SLOTS || !gBpSlots[Slot].Armed)
		return STATUS_NOT_FOUND;

	/*
	 * ⚠⚠ A GLOBAL SLOT CANNOT BE CLEARED FROM HERE, AND SILENTLY TRYING WAS THE DEFECT
	 *.
	 *
	 * This function releases a breakpoint by walking the target's THREADS and rewriting each
	 * thread CONTEXT through BpApplyToThread. That is the right mechanism for a slot armed
	 * per-thread, and it is STRUCTURALLY INCAPABLE of releasing one armed by `bp gset`: a global
	 * arm writes DR0-3 and DR7 on every logical processor via KeIpiGenericCall(BpArmOnEachCpu),
	 * and NOTHING in this function issues an IPI.
	 *
	 * Clearing a global slot here therefore zeroed gBpSlots[Slot] -- the BOOKKEEPING -- while
	 * leaving the DEBUG REGISTERS ARMED MACHINE-WIDE. The hardware keeps trapping with no slot
	 * record behind it, and since RtlZeroMemory leaves Type reading 0, the dispatcher then
	 * classifies those traps as an EXECUTE breakpoint on a slot that no longer exists.
	 *
	 * REFUSED, not silently redirected. NxcBpClearGlobal is a different operation with a different
	 * blast radius -- every core, not one process -- and substituting it for what the caller asked
	 * for is not this function's decision to make.
	 */
	if (gBpSlots[Slot].Global != 0)
	{
		BpLog("bp clear: slot %u is GLOBAL -- use `bp gclear %u`. Clearing it here would zero the "
		      "slot record while leaving DR0-3/DR7 armed on every core.\n", Slot, Slot);
		return STATUS_INVALID_DEVICE_STATE;
	}

	CONST UINT32 Pid = gBpSlotPid[Slot];

	if (BpProcessIsFrozen(Pid))
	{
		BpLog("bp clear: pid %u is FROZEN -- thaw before clearing, or the APC never arrives\n", Pid);
		return STATUS_INVALID_DEVICE_STATE;
	}

	enum { BP_MAX_THREADS = 512 };
	NXCMD_THREAD_ENTRY* CONST List =
		(NXCMD_THREAD_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                     BP_MAX_THREADS * sizeof(NXCMD_THREAD_ENTRY), 'sBxN');
	if (List == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	UINT32 Listed = 0, Found = 0, SweptTo = 0;
	(void)NxcEnumThreads(Pid, List, BP_MAX_THREADS, &Listed, &Found, &SweptTo);

	CONTEXT* CONST Ctx = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), 'cBxN');
	if (Ctx == NULL)
	{
		ExFreePoolWithTag(List, 'sBxN');
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	UINT32 Cleared = 0;
	for (UINT32 i = 0; i < Listed; i++)
	{
		if (List[i].Terminating)
			continue;

		PETHREAD Thread = NULL;
		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)List[i].ThreadId, &Thread)) ||
		    Thread == NULL)
			continue;

		if (NT_SUCCESS(BpApplyToThread(Thread, Ctx, Slot, 0, 0, 0, FALSE, NULL)))
			Cleared++;

		ObfDereferenceObject(Thread);
	}

	ExFreePoolWithTag(Ctx, 'cBxN');
	ExFreePoolWithTag(List, 'sBxN');

	/*
	 * ⚠ THE SLOT IS RELEASED EVEN IF SOME THREADS COULD NOT BE REACHED. A thread that exited between
	 * the sweep and the write took its context with it, so there is nothing left to disarm there --
	 * and keeping the slot marked armed would leak it permanently. What is reported is how many
	 * threads were actually written, never an assumption that the process is clean.
	 */
	RtlZeroMemory(&gBpSlots[Slot], sizeof(gBpSlots[Slot]));
	gBpSlotPid[Slot] = 0;

	*OutThreads = Cleared;
	BpLog("bp clear: slot %u released -- %u thread(s) written of %u found\n", Slot, Cleared, Found);
	return STATUS_SUCCESS;
}

/** Is this pid in the freeze registry? The deadlock check -- see the D22 note in Bp.h. */
static BOOLEAN
BpProcessIsFrozen(
	_In_ UINT32 Pid
	)
{
	UINT32 Frozen[64];
	UINT32 Count = 0;

	if (!NT_SUCCESS(NxcFreezeList(Frozen, 64, &Count)))
		return FALSE;

	for (UINT32 i = 0; i < Count && i < 64; i++)
		if (Frozen[i] == Pid)
			return TRUE;

	return FALSE;
}

NTSTATUS
NxcBpReadThreads(
	_In_ UINT32 Pid,
	_Out_writes_(Cap) NXCMD_BP_THREAD* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT32* OutRefusedFrozen,
	_Out_ UINT32* OutReadFailed
	)
{
	*Got              = 0;
	*Total            = 0;
	*OutRefusedFrozen = 0;
	*OutReadFailed    = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠⚠ THE REFUSAL THAT KEEPS THIS FROM HANGING THE MACHINE. `PsGetContextThread` on a thread other
	 * than the current one queues an APC and WAITS for delivery (ReactOS `ps/debug.c`; get and set
	 * share one routine). A SUSPENDED thread never runs, so it never delivers, so the caller blocks
	 * forever -- and the natural workflow, freeze-then-inspect, walks straight into it.
	 *
	 * Refused rather than attempted, because the failure is a hang and not an error: the machine
	 * would look completely healthy while this command never returned.
	 */
	if (BpProcessIsFrozen(Pid))
	{
		*OutRefusedFrozen = 1;
		BpLog("bp: pid %u is FROZEN -- refusing to read thread contexts, the APC would never be "
		      "delivered and this call would never return\n", Pid);
		return STATUS_INVALID_DEVICE_STATE;
	}

	/*
	 * ⚠ THE THREAD LIST COMES FROM `NxcEnumThreads`, NOT FROM A SWEEP WRITTEN HERE. This function had
	 * its own copy of the CID loop, which is how the project had THREE sweeps of one namespace -- and
	 * two of them disagreed about its size (0x40000 vs 0x80000) under a comment claiming
	 * they matched. A duplicated loop is a second place for that to happen. Calling the enumerator
	 * makes the ceiling, the 4-step, the ownership filter and the terminating rule shared by
	 * construction, and `bp` inherits every future correction to them for free.
	 */
	NXCMD_THREAD_ENTRY* CONST List =
		(NXCMD_THREAD_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                     (SIZE_T)Cap * sizeof(NXCMD_THREAD_ENTRY), 'lBxN');
	if (List == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	UINT32 Listed = 0, Found = 0, SweptTo = 0, ReadFailed = 0;
	CONST NTSTATUS EnumSt = NxcEnumThreads(Pid, List, Cap, &Listed, &Found, &SweptTo);
	if (!NT_SUCCESS(EnumSt))
	{
		ExFreePoolWithTag(List, 'lBxN');
		return EnumSt;
	}

	/*
	 * CONTEXT is large and must be 16-byte aligned (it carries XMM state). Pool gives that alignment
	 * and keeps a ~1.2 KB structure off a kernel stack, which is the more important half.
	 */
	CONTEXT* CONST Ctx = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), 'pBxN');
	if (Ctx == NULL)
	{
		ExFreePoolWithTag(List, 'lBxN');
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	UINT32 Wrote = 0;

	for (UINT32 i = 0; i < Listed && Wrote < Cap; i++)
	{
		/*
		 * A terminating thread is skipped rather than queried: its context is being torn down, and
		 * asking for it is both meaningless and a needless APC against a thread on its way out. The
		 * enumerator REPORTS this rather than filtering it (the zombie lesson), so the decision to
		 * skip is made here, where the reason is specific to reading a context.
		 */
		if (List[i].Terminating)
			continue;

		PETHREAD Thread = NULL;
		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)List[i].ThreadId, &Thread)) ||
		    Thread == NULL)
		{
			/* Exited between the sweep and now. Normal, and the count difference will show it. */
			continue;
		}

		RtlZeroMemory(Ctx, sizeof(*Ctx));
		Ctx->ContextFlags = NXC_CONTEXT_DEBUG_REGISTERS;

		/*
		 * ⚠⚠ A FAILED READ IS NOT AN EMPTY RESULT, AND CONFLATING THEM LIED FOR THE WHOLE OF STAGE 1.
		 * A skipped thread used to vanish silently, so `Got = 0, Total = 21` reached usermode and was
		 * printed as "no thread has a debug register set" -- a claim about 21 threads NONE of which
		 * were successfully examined. measured: PsGetContextThread refuses this driver for
		 * every thread and every ContextFlags, so that verdict was ALWAYS false, and the count that
		 * disproved it was printed one line above.
		 */
		if (NT_SUCCESS(PsGetContextThread(Thread, Ctx, KernelMode)))
		{
			NXCMD_BP_THREAD* CONST E = &Out[Wrote];
			E->ThreadId = List[i].ThreadId;
			E->Dr[0] = Ctx->Dr0;
			E->Dr[1] = Ctx->Dr1;
			E->Dr[2] = Ctx->Dr2;
			E->Dr[3] = Ctx->Dr3;
			E->Dr7   = Ctx->Dr7;

			/* L or G -- the pair for slot i sits at bits 2i and 2i+1, so a 2-bit test covers both. */
			UINT32 Enabled = 0;
			for (UINT32 b = 0; b < 4; b++)
				if ((Ctx->Dr7 >> (b * 2u)) & 3u)
					Enabled++;
			E->Enabled = Enabled;

			Wrote++;
		}
		else
		{
			ReadFailed++;
		}

		ObfDereferenceObject(Thread);
	}

	ExFreePoolWithTag(Ctx, 'pBxN');
	ExFreePoolWithTag(List, 'lBxN');

	*Got        = Wrote;
	*Total      = Found;
	*OutReadFailed = ReadFailed;

	BpLog("bp: pid %u -- %u thread(s) found, %u listed, %u context(s) read (swept to 0x%X)\n",
	      Pid, Found, Listed, Wrote, SweptTo);
	return STATUS_SUCCESS;
}
