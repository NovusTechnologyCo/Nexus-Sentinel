/*
 * Calls.c -- CALL EVIDENCE. What a hooked function was actually asked to do.
 *
 * ==================================================================================================
 * BUILD-PLAN ITEMS B-01 (file capture) AND B-02 (object/registry visibility), UNBLOCKED.
 * ==================================================================================================
 *
 * BOTH WERE FILED AS BLOCKED, NEEDING A DECISION. The decision was taken and it was
 * "build it": FltRegisterFilter / ObRegisterCallbacks / CmRegisterCallbackEx genuinely refuse a
 * manually mapped image -- every one wants a DriverObject we do not have and cannot manufacture --
 * but that is a fact about REGISTRATION, not about the evidence. NtCreateFile is ordinary kernel
 * code at an ordinary address. An inline hook on it needs no DriverObject, no registration, and no
 * entry in PsLoadedModuleList. The blocked APIs were ONE ROUTE to the evidence and were mistaken for
 * the evidence itself -- an earlier finding, where "not possible"
 * almost always turns out to mean "not possible WITH WHAT EXISTS".
 *
 * WHAT THIS FILE ADDS OVER THE LOGGING HOOK THAT ALREADY WORKED. The log ring records the target VA
 * and two argument qwords. For every function these two items care about, that is precisely the
 * wrong two:
 *
 *     NtCreateFile (out handle, access, OBJECT_ATTRIBUTES, ...)  -- the PATH is behind arg 3
 *     NtOpenProcess(out handle, access, OBJECT_ATTRIBUTES, CID)  -- the target PID is behind arg 4
 *     NtSetValueKey(key, UNICODE_STRING*, ...)                   -- the VALUE NAME is behind arg 2
 *
 * A hook recording args 1-2 reports "NtCreateFile ran 4213 times" and never once says which file.
 * That is instrumentation that looks like it works, which is worse than none. So the thunk now
 * forwards four arguments and this file DEREFERENCES the one carrying a name.
 *
 * ⚠ THE KERNEL IS TOLD WHICH ARGUMENT HOLDS THE NAME; IT NEVER GUESSES (D5/D6). A table here mapping
 * "NtCreateFile" to "arg 3 is an OBJECT_ATTRIBUTES" would be per-prototype knowledge pinned in ring
 * 0, and being wrong about it means dereferencing an ACCESS_MASK as a pointer. PlatformCtl knows the
 * prototypes, sends the shape, and pays nothing for being wrong. Here we read what we were told to
 * read and REPORT WHAT WE ACTUALLY GOT.
 *
 * ⚠ AND "GOT NOTHING" IS SEVEN DISTINCT ANSWERS, NOT A BLANK -- see NXCMD_CALL_NAME_*. A name absent
 * because the operator passed no shape flag, because the caller legitimately passed NULL attributes,
 * and because the string was paged out are three different facts calling for three different next
 * actions. Collapsing them into an empty field is the defect that cost four boots and three correct
 * fixes on the wrong input (an earlier finding).
 */

#include <ntddk.h>
#include <intrin.h>

#include "../../Include/NexusCoreBoot.h"   /* NXC_PTE_* flag bits */
#include "../../Include/NexusCommand.h"

/* ⚠ NXC_NT_API_TYPED FIRST. Without it NexusNtApi.h emits only the LIST macro and the struct stays
 * undeclared, so the `extern` below fails to parse and every redirected call reports itself as an
 * undeclared identifier -- one missing define, eight errors, none of them naming it. */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "Arena.h"
#include "Pte.h"
#include "Hook.h"
#include "Calls.h"
#include "FileCapture.h"

/* The host's resolved nt table. Declared before the redirect header, which rewrites every call
 * below into a field reference on it. */
extern volatile NXC_NT_API NexusNtApi;

/* ⚠ THE PAYLOAD CARRIES NO IMPORT TABLE. Every nt call below reaches the host's resolved table
 * through this header; without it the names link against nothing and `tools/check_no_imports.py`
 * fails the build. It is included LAST so it rewrites only our own call sites. */
#include "../../Include/NexusNtApiRedirect.h"

/*
 * The ring. NULL until `calls init` reserves it, and every producer checks that first -- a hook
 * installed with --calls before the ring exists must record NOTHING rather than fault, because the
 * producer runs at the target's IRQL inside somebody else's syscall.
 */
static NXCMD_CALL_ENTRY* volatile gRing       = NULL;
static LONG                      gSlots       = 0;
static UINT64                    gExtent      = 0;
static volatile LONG64           gTicket      = 0;   /* monotonic; never reset by a read      */
static volatile LONG64           gDropped     = 0;   /* producer could not record, with cause */
static volatile LONG64           gNamed       = 0;   /* records that carry a name             */

/*
 * ⚠ THE ARENA, NOT POOL (D4). This memory is written from inside a hook on a system call path; pool
 * would be a second allocator on that path and an owner-tagged arena block is bounded by
 * construction. It is also never freed -- the image has no unload -- so a leak is not a failure mode
 * that needs guarding, but an unbounded allocation would be.
 */
NTSTATUS
NxcCallsInit(
	_In_  UINT32  Slots,
	_Out_ UINT32* OutSlots
	)
{
	*OutSlots = 0;

	if (gRing != NULL)
	{
		/* Already reserved. Re-reserving would strand the first block for the life of the boot and
		 * silently orphan any records in it, so the existing ring is REPORTED rather than replaced. */
		*OutSlots = (UINT32)gSlots;
		return STATUS_SUCCESS;
	}

	if (Slots == 0 || Slots > 4096)
		return STATUS_INVALID_PARAMETER;

	ULONG Extent = 0;
	void* CONST Mem = NxcArenaAlloc((ULONG)((SIZE_T)Slots * sizeof(NXCMD_CALL_ENTRY)), &Extent);
	if (Mem == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(Mem, (SIZE_T)Slots * sizeof(NXCMD_CALL_ENTRY));

	gExtent = (UINT64)Extent;
	gSlots  = (LONG)Slots;

	/* ⚠ THE POINTER IS PUBLISHED LAST. A producer tests gRing and then uses gSlots; publishing the
	 * pointer first would leave a window where the ring exists with a slot count of zero. */
	InterlockedExchangePointer((void* volatile*)&gRing, Mem);

	*OutSlots = Slots;
	return STATUS_SUCCESS;
}

/*
 * Is this address safe to read RIGHT NOW, from the context we are in?
 *
 * ⚠ NxcPteQuery RATHER THAN MmIsAddressValid. The walk goes through the SELF-MAP, whose pages are
 * never paged out, so it is legal at ANY IRQL -- MmIsAddressValid is documented at <= DISPATCH.
 * A hook on an Nt* entry runs at PASSIVE today, but the guard should not be the thing that makes
 * that true.
 *
 * ⚠ USER-MODE POINTERS ARE NOT REQUIRED TO BE USER PAGES, AND KERNEL ONES ARE NOT FORBIDDEN. Zw*
 * callers inside the kernel pass KERNEL addresses through the identical parameters. So the test is
 * "resident and readable", plus the consistency check that a user-range VA maps a user page -- a
 * user-range address on a supervisor page is a straddle or a race, and is refused.
 */
static BOOLEAN
CallsReadable(
	_In_ UINT64 Va,
	_In_ UINT32 Bytes
	)
{
	if (Va == 0 || Bytes == 0)
		return FALSE;

	/* Canonical-form check. A non-canonical dereference is a #GP, not a page fault, and no PTE walk
	 * would have caught it. */
	CONST UINT64 High = Va >> 47;
	if (High != 0 && High != 0x1FFFFull)
		return FALSE;

	/* ⚠ EVERY PAGE THE READ SPANS, not just the first. A UNICODE_STRING buffer 8 bytes from a page
	 * boundary is the common case for a long path, and checking only the start would fault on the
	 * second page while reporting the address as validated. */
	CONST UINT64 First = Va & ~0xFFFull;
	CONST UINT64 Last  = (Va + Bytes - 1) & ~0xFFFull;
	CONST BOOLEAN UserRange = (Va < 0x0000800000000000ull);

	for (UINT64 P = First; P <= Last; P += 0x1000ull)
	{
		NXC_PTE_INFO Pte;
		if (!NT_SUCCESS(NxcPteQuery(P, &Pte)))
			return FALSE;
		if ((Pte.Flags & (NXC_PTE_VALID | NXC_PTE_PRESENT)) != (NXC_PTE_VALID | NXC_PTE_PRESENT))
			return FALSE;
		if (UserRange && (Pte.Flags & NXC_PTE_USER) == 0)
			return FALSE;
	}
	return TRUE;
}

/*
 * Copy a UNICODE_STRING's characters into the record.
 *
 * ⚠ SMAP IS ACTIVE (CR4 bit 21) AND THIS READS USER MEMORY FROM RING 0. Without EFLAGS.AC the read
 * is a fault, not a wrong value. AC is NOT cleared on interrupt delivery on this part (that
 * behaviour ended with Broadwell), so an interrupt taken inside the window would run a handler with
 * supervisor access to user pages enabled -- the window therefore clears IF as well, and both are
 * restored from the saved copy rather than by writing assumed values back.
 *
 * ⚠ THE LENGTH IS READ ONCE AND CLAMPED, NEVER TRUSTED. Length is UNDER THE CALLER'S CONTROL --
 * a usermode process is free to pass 0xFFFF with a one-page buffer, and this runs before the target
 * has probed anything. Both the byte count and the resulting char count are bounded here.
 */
static void
CallsCaptureUnicodeString(
	_Inout_ NXCMD_CALL_ENTRY* Rec,
	_In_    UINT64            UStrVa
	)
{
	if (!CallsReadable(UStrVa, 16))   /* USHORT Length, USHORT Max, ULONG pad, PWCH Buffer */
	{
		Rec->NameWhy = NXCMD_CALL_NAME_BAD_PTR;
		return;
	}

	UINT16 Length = 0;
	UINT64 Buffer = 0;
	{
		CONST UINT64 SavedFlags = __readeflags();
		__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
		Length = *(volatile UINT16*)(ULONG_PTR)UStrVa;
		Buffer = *(volatile UINT64*)(ULONG_PTR)(UStrVa + 8);
		__writeeflags(SavedFlags);
	}

	if (Length == 0)
	{
		Rec->NameWhy = NXCMD_CALL_NAME_EMPTY;
		return;
	}
	if (Buffer == 0)
	{
		Rec->NameWhy = NXCMD_CALL_NAME_BAD_PTR;
		return;
	}

	/* ⚠ REPORT WHAT WAS AVAILABLE AS WELL AS WHAT WAS TAKEN (D3). A path clipped at 128 chars and a
	 * path that is 128 chars long are different facts, and only NameCharsAvail separates them. */
	CONST UINT32 AvailChars = (UINT32)(Length / sizeof(WCHAR));
	Rec->NameCharsAvail = (NXCMD_U16)((AvailChars > 0xFFFFu) ? 0xFFFFu : AvailChars);

	UINT32 WantChars = AvailChars;
	BOOLEAN Clipped = FALSE;
	if (WantChars > NXCMD_CALL_NAME_CHARS)
	{
		WantChars = NXCMD_CALL_NAME_CHARS;
		Clipped = TRUE;
	}

	if (!CallsReadable(Buffer, WantChars * (UINT32)sizeof(WCHAR)))
	{
		/* ⚠ DISTINGUISHED FROM A BAD POINTER. The descriptor read fine and named a buffer that is
		 * simply not resident -- pageable usermode string, PASSIVE_LEVEL, entirely normal. The SAME
		 * call will produce the name on a later hit, which is a completely different instruction to
		 * the operator than "that pointer is garbage". */
		Rec->NameWhy = NXCMD_CALL_NAME_NOT_RESIDENT;
		return;
	}

	{
		CONST UINT64 SavedFlags = __readeflags();
		__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
		for (UINT32 i = 0; i < WantChars; i++)
			Rec->Name[i] = (NXCMD_U16)*(volatile UINT16*)(ULONG_PTR)(Buffer + (UINT64)i * 2ull);
		__writeeflags(SavedFlags);
	}

	Rec->NameChars = (NXCMD_U16)WantChars;
	Rec->NameWhy   = Clipped ? NXCMD_CALL_NAME_TRUNCATED : NXCMD_CALL_NAME_OK;
	InterlockedIncrement64(&gNamed);
}

/*
 * OBJECT_ATTRIBUTES -> ObjectName -> the string.
 *
 * ⚠ ObjectName IS AT +0x10 AND THAT IS A PUBLIC, FROZEN LAYOUT, not a derived offset:
 *     +0x00 ULONG Length; +0x08 HANDLE RootDirectory; +0x10 PUNICODE_STRING ObjectName;
 * OBJECT_ATTRIBUTES is part of the documented DDK interface -- InitializeObjectAttributes has
 * compiled against this layout since NT 3.1 and every driver ever shipped depends on it. This is the
 * one class of offset that is not a per-boot guess. (Contrast KTRAP_FRAME.EFlags at +0x178, which is
 * internal, unpublished, and is DERIVED FROM LIVE FRAMES rather than pinned.)
 *
 * ⚠ A NULL ObjectName IS LEGAL AND COMMON, not a failure: NtCreateFile with a RootDirectory handle
 * and a relative name still has one, but NtOpenProcess called with a CLIENT_ID and no name has
 * ObjectName == NULL by design. Filing that as an error would make the normal case look broken.
 */
static void
CallsCaptureObjectAttributes(
	_Inout_ NXCMD_CALL_ENTRY* Rec,
	_In_    UINT64            OaVa
	)
{
	if (OaVa == 0)
	{
		Rec->NameWhy = NXCMD_CALL_NAME_NULL_OA;
		return;
	}
	if (!CallsReadable(OaVa, 0x18))
	{
		Rec->NameWhy = NXCMD_CALL_NAME_BAD_PTR;
		return;
	}

	UINT64 NamePtr = 0;
	{
		CONST UINT64 SavedFlags = __readeflags();
		__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
		NamePtr = *(volatile UINT64*)(ULONG_PTR)(OaVa + 0x10);
		__writeeflags(SavedFlags);
	}

	if (NamePtr == 0)
	{
		Rec->NameWhy = NXCMD_CALL_NAME_NULL_OA;
		return;
	}

	CallsCaptureUnicodeString(Rec, NamePtr);
}

/*
 * CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } -- two pointer-sized fields, offsets 0
 * and 8, and it has had that layout since NT 3.1. This is the fact B-02 is actually asking for:
 * NtOpenProcess's arg4 is a POINTER to one, so recording the argument records an address in the
 * caller's stack and never says which process is being opened.
 *
 * ⚠ A NULL CLIENT_ID IS LEGAL AND ORDINARY -- opening by name through the OBJECT_ATTRIBUTES is the
 * other half of NtOpenProcess's interface. NULL_OA is reused to say so, because "the caller did not
 * supply this one" is the identical fact in both directions.
 */
static void
CallsCaptureClientId(
	_Inout_ NXCMD_CALL_ENTRY* Rec,
	_In_    UINT64            CidVa
	)
{
	if (CidVa == 0)
	{
		Rec->CidWhy = NXCMD_CALL_NAME_NULL_OA;
		return;
	}
	if (!CallsReadable(CidVa, 16))
	{
		Rec->CidWhy = NXCMD_CALL_NAME_BAD_PTR;
		return;
	}

	CONST UINT64 SavedFlags = __readeflags();
	__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
	CONST UINT64 UniqueProcess = *(volatile UINT64*)(ULONG_PTR)CidVa;
	CONST UINT64 UniqueThread  = *(volatile UINT64*)(ULONG_PTR)(CidVa + 8);
	__writeeflags(SavedFlags);

	Rec->TargetPid = (NXCMD_U32)UniqueProcess;
	Rec->TargetTid = (NXCMD_U32)UniqueThread;
	Rec->CidWhy    = NXCMD_CALL_NAME_OK;
}

/*
 * NtProtectVirtualMemory(ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect,
 *                        PULONG OldProtect)
 *
 * ⚠ ARGUMENTS 2 AND 3 ARE POINTERS, AND RECORDING THEM RAW RECORDS NOTHING. They address the
 * caller's own stack. The region being reprotected is behind them, and this is the only context in
 * which those addresses mean anything at all -- we are on the caller's thread, in its CR3.
 *
 * ⚠ THE "BEFORE" SIDE COMES FROM THE PTE, NOT FROM OldProtect. OldProtect is an OUT parameter: at
 * entry it points at uninitialised caller memory, so reading it here would record stack garbage
 * that looks exactly like a protection value. The page tables already hold the answer.
 *
 * ⚠ AND IT IS READ BEFORE THE CALL RUNS, WHICH IS THE WHOLE POINT. An entry hook is the last
 * moment the OLD mapping still exists. Sampling after the fact -- which is all `regions` can ever
 * do -- cannot see a protection that has already been replaced.
 */
static void
CallsCaptureProtection(
	_Inout_ NXCMD_CALL_ENTRY* Rec,
	_In_    UINT64            BaseVa,      /* arg2: PVOID*  */
	_In_    UINT64            SizeVa       /* arg3: PSIZE_T */
	)
{
	if (BaseVa == 0 || SizeVa == 0)
	{
		Rec->ProtWhy = NXCMD_CALL_NAME_NULL_OA;
		return;
	}

	/* ⚠ CHECKED SEPARATELY, NOT AS ONE SPAN. The two pointers are independent caller-supplied
	 * addresses and are under no obligation to be adjacent -- a single range check across both
	 * would cover whatever happens to lie between them. */
	if (!CallsReadable(BaseVa, 8) || !CallsReadable(SizeVa, 8))
	{
		Rec->ProtWhy = NXCMD_CALL_NAME_NOT_RESIDENT;
		return;
	}

	UINT64 Base = 0;
	UINT64 Size = 0;
	{
		/* SMAP: same AC-set / IF-clear window as every other user read on this path. */
		CONST UINT64 SavedFlags = __readeflags();
		__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
		Base = *(volatile UINT64*)(ULONG_PTR)BaseVa;
		Size = *(volatile UINT64*)(ULONG_PTR)SizeVa;
		__writeeflags(SavedFlags);
	}

	Rec->ProtBase = (NXCMD_U64)Base;
	Rec->ProtSize = (NXCMD_U64)Size;

	if (Base == 0)
	{
		/* The pointers read fine and named nothing. Distinct from a bad pointer: this is a caller
		 * asking the kernel to choose, not a pointer we failed to follow. */
		Rec->ProtWhy = NXCMD_CALL_NAME_EMPTY;
		return;
	}

	/*
	 * ⚠ NxcPteQuery, NOT NxcTranslate -- reasoning in full beside NXCMD_CALL_ENTRY.ProtPte. Short
	 * form: NxcTranslate allocates from paged pool per level and is PASSIVE-only; this path is hit
	 * thousands of times per second by the target it was built for. The self-map allocates nothing.
	 *
	 * ⚠ A FAILED WALK IS A RESULT, NOT AN ERROR. An unmapped or not-yet-committed VA is exactly
	 * what a caller reprotecting freshly reserved memory would produce, and "no PTE yet" is a
	 * meaningful thing to have recorded -- it distinguishes a first commit from a re-protection.
	 */
	NXC_PTE_INFO Pte;
	if (NT_SUCCESS(NxcPteQuery(Base, &Pte)))
	{
		Rec->ProtPte = (NXCMD_U32)Pte.Flags;
		Rec->ProtWhy = NXCMD_CALL_NAME_OK;
	}
	else
	{
		Rec->ProtPte = 0;
		Rec->ProtWhy = NXCMD_CALL_NAME_NOT_RESIDENT;
	}
}

/*
 * Record one observed call. Runs INSIDE the hook, at the target's IRQL, in the caller's context.
 *
 * ⚠ THE SLOT IS CLAIMED WITH ONE InterlockedIncrement64 AND THE RING WRAPS. There is no lock and no
 * allocation, because there cannot be either on a system call path. The ticket is monotonic for the
 * life of the boot, so `#4102 of 4102` tells an operator how much history the window actually holds
 * -- a counter reset by reads would make a wrapped ring indistinguishable from a quiet one.
 *
 * ⚠ Sequence IS ZEROED BEFORE THE OVERWRITE AND WRITTEN LAST. A reader draining concurrently would
 * otherwise see a record whose sequence says "new" while its name is still the previous occupant's
 * -- half of one call and half of another, with nothing marking it as such.
 */
void
NxcCallsRecord(
	_In_ UINT64 TargetVa,
	_In_ UINT64 ReturnAddress,
	_In_ UINT64 Arg1,
	_In_ UINT64 Arg2,
	_In_ UINT64 Arg3,
	_In_ UINT64 Arg4,
	_In_ UINT64 EntryRsp,
	_In_ UINT32 Flags
	)
{
	NXCMD_CALL_ENTRY* CONST Ring = gRing;
	if (Ring == NULL || gSlots <= 0)
	{
		/* Counted, not silent: a --calls hook with no ring is an operator error that must be
		 * VISIBLE, and "0 records" alone reads as "the function was never called". */
		InterlockedIncrement64(&gDropped);
		return;
	}

	CONST LONG64 Ticket = InterlockedIncrement64(&gTicket);
	NXCMD_CALL_ENTRY* CONST Rec = &Ring[(UINT64)(Ticket - 1) % (UINT64)gSlots];

	*(volatile UINT64*)&Rec->Sequence = 0;

	Rec->TargetVa       = TargetVa;
	Rec->ReturnAddress  = ReturnAddress;
	Rec->Arg[0]         = Arg1;
	Rec->Arg[1]         = Arg2;
	Rec->Arg[2]         = Arg3;
	Rec->Arg[3]         = Arg4;
	Rec->NameChars      = 0;
	Rec->NameCharsAvail = 0;
	Rec->NameWhy        = NXCMD_CALL_NAME_NOT_ASKED;
	Rec->TargetPid      = 0;
	Rec->TargetTid      = 0;
	Rec->CidWhy         = NXCMD_CALL_NAME_NOT_ASKED;
	Rec->StackWhy       = NXCMD_CALL_NAME_NOT_ASKED;
	Rec->ProtBase       = 0;
	Rec->ProtSize       = 0;
	Rec->ProtPte        = 0;
	Rec->ProtWhy        = NXCMD_CALL_NAME_NOT_ASKED;
	for (UINT32 i = 0; i < NXCMD_CALL_STACK_ARGS; i++)
		Rec->StackArg[i] = 0;

	/*
	 * ⚠ ARGUMENTS 5..10, UNCONDITIONALLY -- no shape flag gates these.
	 *
	 * They are raw qwords from a location the ABI fixes, not a dereference of something whose type we
	 * were told: reading them cannot be wrong the way following a mis-declared pointer can. And the
	 * cost of NOT having them is a second hardware run every time a question turns out to hinge on
	 * argument 5, which is most of the interesting ones -- NtSetInformationFile's
	 * FileInformationClass being the immediate example. Six qwords behind one residency check is
	 * cheaper than discovering they were needed.
	 *
	 * ⚠ ONE CHECK COVERS THE WHOLE SPAN because it is contiguous: 0x28..0x58 from the entry rsp.
	 * CallsReadable walks every page the range touches, so a run that straddles a boundary is handled
	 * rather than half-read.
	 */
	if (EntryRsp != 0)
	{
		CONST UINT64 StackVa = EntryRsp + 0x28ull;
		if (CallsReadable(StackVa, NXCMD_CALL_STACK_ARGS * 8u))
		{
			CONST UINT64 SavedFlags = __readeflags();
			__writeeflags((SavedFlags | 0x00040000ull) & ~0x00000200ull);
			for (UINT32 i = 0; i < NXCMD_CALL_STACK_ARGS; i++)
				Rec->StackArg[i] = *(volatile UINT64*)(ULONG_PTR)(StackVa + (UINT64)i * 8ull);
			__writeeflags(SavedFlags);
			Rec->StackWhy = NXCMD_CALL_NAME_OK;
		}
		else
		{
			Rec->StackWhy = NXCMD_CALL_NAME_NOT_RESIDENT;
		}
	}
	else
	{
		/* The thunk did not supply it -- an older payload against a newer PlatformCtl. Distinguished
		 * from "unreadable" because the two call for opposite next steps. */
		Rec->StackWhy = NXCMD_CALL_NAME_BAD_PTR;
	}

	{
		/* ⚠ THE PERFORMANCE COUNTER, NOT rdtsc. TSC frequency is not what CPUID says on this part
		 * ("3 GHz") and swung 6x across boots doing identical work; KeQueryPerformanceCounter is the
		 * one clock whose ticks mean the same thing on every core of a hybrid CPU. */
		LARGE_INTEGER Pc = KeQueryPerformanceCounter(NULL);
		Rec->TimeStamp = (NXCMD_U64)Pc.QuadPart;
	}
	Rec->Pid = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();
	Rec->Tid = (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId();

	/*
	 * ⚠ THE SHAPE FLAGS ARE CHECKED IN ORDER AND ONLY ONE RUNS. Both set on one hook would mean two
	 * extractors writing the same Name[] and the second silently winning; refusing the combination
	 * belongs at INSTALL time, where the operator can see it, and this ordering makes the behaviour
	 * defined either way rather than dependent on which check came first.
	 */
	if ((Flags & NXC_HOOK_FLAG_OBJATTR3) != 0)
		CallsCaptureObjectAttributes(Rec, Arg3);
	else if ((Flags & NXC_HOOK_FLAG_USTR2) != 0)
		CallsCaptureUnicodeString(Rec, Arg2);

	/* ⚠ NOT part of the if/else chain above. The name and the CLIENT_ID are two different facts
	 * from two different arguments, and NtOpenProcess routinely carries one without the other --
	 * chaining them would mean an OBJECT_ATTRIBUTES name silently suppressing the pid. */
	if ((Flags & NXC_HOOK_FLAG_CID4) != 0)
		CallsCaptureClientId(Rec, Arg4);

	/* ⚠ ALSO INDEPENDENT, for the same reason as _CID4: this reads arguments 2 and 3 as a
	 * PVOID-star / PSIZE_T pair, which is a different fact from any name shape. NtProtectVirtualMemory
	 * has no OBJECT_ATTRIBUTES and no CLIENT_ID, so in practice it runs alone -- but chaining it
	 * would make that an assumption instead of a consequence. */
	if ((Flags & NXC_HOOK_FLAG_PROT) != 0)
		CallsCaptureProtection(Rec, Arg2, Arg3);

	/*
	 * ⚠ THE DELETE TRIGGER (B-01 / D110), AND IT GATES ON THE LOW DWORD.
	 *
	 * NtSetInformationFile(Handle, Iosb, Info, Length, FileInformationClass) -- the class is
	 * argument 5, which is StackArg[0], and it is a 32-BIT enum in a 64-bit stack slot. Measured
	 * one record read 0x40 and the next read 0x45004E00000004, whose low dword is 4
	 * (FileBasicInformation). The upper half is whatever occupied the slot beforehand -- the x64 ABI
	 * makes the caller STORE a ULONG, not zero the rest. Comparing the full qword would miss every
	 * delete whose slot happened to be dirty.
	 *
	 * FileDispositionInformation = 13, FileDispositionInformationEx = 64. Windows 11 uses the Ex
	 * form for an ordinary Remove-Item; both are accepted because a caller may use either and
	 * catching only the one we happened to observe would be a filter that works until it does not.
	 */
	if ((Flags & NXC_HOOK_FLAG_FCAP) != 0 && Rec->StackWhy == NXCMD_CALL_NAME_OK)
	{
		CONST UINT32 InfoClass = (UINT32)(Rec->StackArg[0] & 0xFFFFFFFFull);
		if (InfoClass == 13u || InfoClass == 64u)
		{
			NxcFileCaptureOnDelete(Arg1, InfoClass);
		}
		/*
		 * ⚠ THE OTHER DELETE, AND THE DISPOSITION HOOK CANNOT SEE IT AT ALL.
		 *
		 * NtCreateFile(..., CreateDisposition, CreateOptions, ...) puts CreateOptions in argument 9 =
		 * StackArg[4], and FILE_DELETE_ON_CLOSE is 0x1000. A file created that way is unlinked when
		 * the last handle closes, with NO disposition call anywhere -- so covering only
		 * NtSetInformationFile would claim "capture between create and delete" while missing an
		 * entire class of deletes.
		 *
		 * ⚠ ARG 9 IS CONFIRMED AGAINST LIVE DATA, not counted off a prototype. A capture from
		 * read `a9 = 0x400060` on an ordinary open: 0x20 SYNCHRONOUS_IO_NONALERT | 0x40
		 * NON_DIRECTORY_FILE | 0x400000 DISALLOW_EXCLUSIVE, with a8 = 1 (FILE_OPEN) beside it and
		 * a8 = 3 (FILE_OPEN_IF) on the write. Those are CreateOptions and CreateDisposition exactly
		 * where the ABI puts them.
		 *
		 * ⚠ AND THE NAME MUST ALREADY BE IN HAND -- this rides on the OBJATTR3 extractor having run,
		 * because at the NtCreateFile ENTRY the handle does not exist yet (arg1 is an out-parameter),
		 * so the path is the only thing there is to queue.
		 */
		CONST UINT32 CreateOptions = (UINT32)(Rec->StackArg[4] & 0xFFFFFFFFull);
		if ((CreateOptions & 0x00001000u) != 0 && Rec->NameChars != 0 &&
		    (Rec->NameWhy == NXCMD_CALL_NAME_OK || Rec->NameWhy == NXCMD_CALL_NAME_TRUNCATED))
		{
			NxcFileCaptureOnCreateDeleteOnClose(Rec->Name, Rec->NameChars, CreateOptions);
		}
	}

	*(volatile UINT64*)&Rec->Sequence = (UINT64)Ticket;
}

/*
 * Drain to the caller's buffer (D2). Reports Got AND Total AND Dropped (D3) -- "12 records" without
 * "of 4102 seen" cannot distinguish a quiet system from a ring that wrapped 340 times.
 */
NTSTATUS
NxcCallsRead(
	_Out_writes_(Cap) NXCMD_CALL_ENTRY* Out,
	_In_  UINT32  Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutDropped,
	_Out_ UINT64* OutNamed
	)
{
	*OutGot     = 0;
	*OutTotal   = (UINT64)gTicket;
	*OutDropped = (UINT64)gDropped;
	*OutNamed   = (UINT64)gNamed;

	NXCMD_CALL_ENTRY* CONST Ring = gRing;
	if (Ring == NULL || gSlots <= 0)
		return STATUS_INVALID_DEVICE_STATE;
	if (Cap == 0)
		return STATUS_BUFFER_TOO_SMALL;

	CONST UINT64 Total = (UINT64)gTicket;
	CONST UINT64 Held  = (Total < (UINT64)gSlots) ? Total : (UINT64)gSlots;
	CONST UINT64 Want  = (Held < (UINT64)Cap) ? Held : (UINT64)Cap;

	/*
	 * NEWEST FIRST. The interesting record after a burst is the last one, and a reader that has to
	 * count backwards from a wrap point to find it will eventually get that arithmetic wrong.
	 */
	UINT32 Got = 0;
	for (UINT64 i = 0; i < Want; i++)
	{
		CONST UINT64 Seq = Total - i;                 /* Total, Total-1, ... */
		CONST NXCMD_CALL_ENTRY* CONST Src = &Ring[(Seq - 1) % (UINT64)gSlots];

		/* ⚠ SKIP A RECORD BEING WRITTEN RIGHT NOW rather than copying it half-formed. Sequence 0 is
		 * the producer's in-progress marker; a mismatch means it wrapped past us mid-drain. */
		CONST UINT64 Have = *(volatile UINT64*)&Src->Sequence;
		if (Have == 0 || Have != Seq)
			continue;

		Out[Got] = *Src;
		Got++;
	}

	*OutGot = Got;
	return STATUS_SUCCESS;
}

void
NxcCallsStats(
	_Out_ UINT32* OutSlots,
	_Out_ UINT64* OutTotal,
	_Out_ UINT64* OutDropped,
	_Out_ UINT64* OutNamed,
	_Out_ UINT64* OutExtent
	)
{
	*OutSlots   = (gRing != NULL) ? (UINT32)gSlots : 0u;
	*OutTotal   = (UINT64)gTicket;
	*OutDropped = (UINT64)gDropped;
	*OutNamed   = (UINT64)gNamed;
	*OutExtent  = gExtent;
}
