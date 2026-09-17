/**
 * @file Hook.c
 * @brief Inline hook: one aligned 8-byte store, through an alias, or nothing. Reasoning in Hook.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "Hook.h"
#include "Alias.h"
#include "Arena.h"
#include "Pte.h"
#include "hde/hde64.h"
#include "LogRing.h"
#include "Lbr.h"
#include "BpDispatch.h"
#include "Idt.h"
#include "Calls.h"
#include "TpmTrace.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define HookLog NxcLogExt

/* Sink for NxcLbrSnapCounters' overwrite count on the paths that do not report it -- the hook
 * selftest and the LBR-slot accounting want taken/dropped/slots only. A named sink rather than a
 * NULL, so the callee never has to test a pointer on a path that runs at the target's IRQL. */
static UINT32 SnapOverDiscard = 0;

static NXC_HOOK_ENTRY gHooks[NXC_MAX_HOOKS];
static UINT32         gHookCount = 0;

/*
 * The stage-1 stub and the trampoline live in one arena extent per hook, laid out as
 *
 *     [ stub: 14 bytes ][ trampoline: stolen bytes + 14 ]
 *
 * so a single allocation and a single protect call cover both, and freeing one cannot leave the
 * other behind. The stub comes FIRST because its address is what the E9 has to reach, and keeping
 * it at the extent base makes that address the one the arena reported rather than an offset into it.
 */
#define NXC_HOOK_EXTENT_BYTES  (NXC_HOOK_STUB_BYTES + NXC_HOOK_MAX_STOLEN + 14u)

/*
 * The bottom of canonical kernel space on x64. Anything below is a usermode VA, which this command
 * does not take -- Command.c bounds usermode buffers with the mirror-image pair of constants.
 */
#define NXC_KERNEL_VA_FLOOR    0xFFFF800000000000ULL

/* Upper bound for the per-processor re-entry guard. Sized past this machine's 24 logical
 * processors; a CPU number at or above it is refused rather than indexed with. */
#define NXC_MAX_TRACE_CPUS_FOR_HOOK  64u

/* ------------------------------------------------------------------------------------------ */

/**
 * Write one qword through an alias, with every other core held in an interrupt.
 *
 * ⚠ THE BROADCAST IS NOT FOR ATOMICITY. The store is already indivisible -- x86 guarantees that for
 * a naturally aligned qword, and the caller has checked the alignment. The broadcast is what
 * satisfies the OTHER half of the SDM's cross-modifying-code rule: the processors that will EXECUTE
 * the changed bytes must perform a serializing operation between the write and the execution.
 * Entering and returning from this IPI is that serializing event, on every core, by construction.
 *
 * Exactly one core performs the store. The rest are here only to be serialized.
 */
typedef struct _NXC_PATCH_CTX
{
	volatile UINT64* Where;    /* the ALIAS of the aligned qword, never the target VA */
	UINT64           Value;
	volatile LONG    Claimed;
} NXC_PATCH_CTX;

static NXC_PATCH_CTX* volatile gPatchCtx = NULL;

static ULONG_PTR
PatchOnEachCpu(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	NXC_PATCH_CTX* CONST Ctx = gPatchCtx;
	if (Ctx == NULL)
		return 0;

	/* First core in writes; the others fall through, and their return from this interrupt is the
	 * serializing operation the SDM asks for. */
	if (InterlockedCompareExchange(&Ctx->Claimed, 1, 0) == 0)
		*Ctx->Where = Ctx->Value;

	return 0;
}

/**
 * Replace the aligned qword at Aligned with Value, atomically, everywhere.
 *
 * Builds the alias, stores, tears the alias down. The alias is deliberately short-lived: a writable
 * mapping of executable kernel code is exactly the artefact this project exists to FIND, and leaving
 * one live for the lifetime of a hook would be leaving one behind on purpose.
 */
static NTSTATUS
StoreQwordAtomic(
	_In_ UINT64 Aligned,
	_In_ UINT64 Value
	)
{
	if ((Aligned & 7u) != 0)
		return STATUS_INVALID_PARAMETER;   /* caller error; the whole design rests on this */

	NXC_ALIAS Alias;
	RtlZeroMemory(&Alias, sizeof(Alias));

	CONST NTSTATUS St = NxcAliasCreate(Aligned, sizeof(UINT64), &Alias);
	if (!NT_SUCCESS(St))
		return St;

	/*
	 * ⚠ WritableVa ALREADY POINTS AT `Aligned`. DO NOT ADD THE PAGE OFFSET.
	 *
	 * THIS LINE BUGCHECKED THE MACHINE (IRQL_NOT_LESS_OR_EQUAL). It used to read
	 *
	 *     Ctx.Where = (UINT8*)Alias.WritableVa + (Aligned & (PAGE_SIZE - 1));
	 *
	 * on the assumption that the alias maps the PAGE and the caller indexes into it. It does not.
	 * NxcAliasCreate builds the MDL with MmInitializeMdl(Mdl, TargetVa, Bytes), which puts
	 * TargetVa & 0xFFF into the MDL's ByteOffset, and the DDI is explicit that "the virtual address
	 * returned by MmMapLockedPagesWithReservedMapping does include the byte offset that the MDL
	 * specifies". So the offset was applied twice, and the store landed up to 4088 bytes past the
	 * mapping -- inside the reservation, which is two pages, but outside the one page whose PTEs
	 * were actually filled.
	 *
	 * A touch of reserved-but-unmapped VA is a page fault. At PASSIVE that is a survivable mistake.
	 * This one happens INSIDE KeIpiGenericCall at IPI_LEVEL, where a fault is not an error path --
	 * it is the bugcheck, on every core at once.
	 *
	 * ⚠ AND `alias test` PASSED THROUGHOUT, because NxcAliasSelfTest aliases a freshly allocated
	 * PAGE-ALIGNED page. Offset zero makes adding the offset twice indistinguishable from adding it
	 * once. The test exercised the only case where the bug is invisible. That is now fixed in
	 * Alias.c: the self-test uses a deliberately unaligned target, and NxcAliasCreate itself proves
	 * the mapping lands where it claims before returning.
	 */
	NXC_PATCH_CTX Ctx;
	Ctx.Where   = (volatile UINT64*)Alias.WritableVa;
	Ctx.Value   = Value;
	Ctx.Claimed = 0;

	gPatchCtx = &Ctx;
	(void)KeIpiGenericCall(PatchOnEachCpu, 0);
	gPatchCtx = NULL;

	NxcAliasDestroy(&Alias);

	return (Ctx.Claimed != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------------------------------ */

/**
 * Decode forward from Va until at least Need whole instructions' worth of bytes are covered.
 *
 * ⚠ REJECTS RELATIVE AND RIP-RELATIVE INSTRUCTIONS rather than relocating them. v1 adjusted disp32
 * for RIP-relative operands, which is more capable and is also more places to be quietly wrong; and
 * it does not generalise -- a `call rel32` among the stolen bytes cannot be fixed by adjusting its
 * displacement at all, because the corrected target may not be reachable in 32 bits and re-encoding
 * it changes the instruction's LENGTH, which changes where the jump back has to land.
 *
 * Refusing names a real property of the target ("this entry cannot be hooked this way") instead of
 * producing a trampoline that is right for most functions.
 */
static UINT32
DecodePrologue(
	_In_ CONST UINT8* Va,
	_In_ UINT32 Need,
	_Out_ UINT32* OutDetail
	)
{
	*OutDetail = NXC_HOOK_OK;

	UINT32 Total = 0;
	while (Total < Need)
	{
		if (Total >= NXC_HOOK_MAX_STOLEN)
		{
			*OutDetail = NXC_HOOK_DECODE_FAILED;
			return 0;
		}

		hde64s Hs;
		CONST unsigned Len = hde64_disasm(Va + Total, &Hs);

		if (Len == 0 || (Hs.flags & F_ERROR) != 0)
		{
			*OutDetail = NXC_HOOK_DECODE_FAILED;
			return 0;
		}

		/* F_RELATIVE covers rel8/rel32 branches and calls. */
		if ((Hs.flags & F_RELATIVE) != 0)
		{
			*OutDetail = NXC_HOOK_RELATIVE_INSN;
			return 0;
		}

		/* RIP-relative addressing: mod == 00 and r/m == 101 means disp32 is relative to RIP, so the
		 * same encoding at a different address reads a different location. */
		if ((Hs.flags & F_MODRM) != 0 && Hs.modrm_mod == 0 && Hs.modrm_rm == 5)
		{
			*OutDetail = NXC_HOOK_RELATIVE_INSN;
			return 0;
		}

		Total += Len;
	}

	return Total;
}

/**
 * Every byte of [Va, Va+Bytes) is a valid, resident kernel address.
 *
 * MmIsAddressValid is checked per PAGE rather than per byte, and it is genuinely the right call
 * here despite its reputation: there is no SEH in this image, so a probe that RAISES on a bad
 * address is not an option, and this one returns.
 */
static BOOLEAN
RangeIsResident(
	_In_ UINT64 Va,
	_In_ UINT32 Bytes
	)
{
	for (UINT64 P = Va & ~(UINT64)(PAGE_SIZE - 1); P < Va + Bytes; P += PAGE_SIZE)
	{
		if (!MmIsAddressValid((PVOID)(ULONG_PTR)P))
			return FALSE;
	}
	return TRUE;
}

/** Splice Count bytes of Patch into Original at ByteOffset, leaving the rest of the qword alone. */
static UINT64
SpliceQword(
	_In_ UINT64 Original,
	_In_ UINT32 ByteOffset,
	_In_reads_(Count) CONST UINT8* Patch,
	_In_ UINT32 Count
	)
{
	UINT8 B[8];
	for (UINT32 i = 0; i < 8; i++)
		B[i] = (UINT8)(Original >> (8u * i));

	for (UINT32 i = 0; i < Count; i++)
		B[ByteOffset + i] = Patch[i];

	UINT64 Out = 0;
	for (UINT32 i = 0; i < 8; i++)
		Out |= (UINT64)B[i] << (8u * i);
	return Out;
}

/**
 * Give an extent back, AFTER putting its pages back the way the arena expects them.
 *
 * ⚠ THE PROTECT MUST BE REVERTED FIRST, AND THIS IS NOT TIDINESS -- IT IS A BUGCHECK OTHERWISE.
 * NxcArenaFree POISONS the extent before releasing it. Once the stub page has been made R-X for
 * execution, that poison write lands on a read-only page, and with CR0.WP set and no SEH in this
 * image a write fault is not an error path; it is the end of the machine.
 *
 * Found by reading rather than by running, which is the only acceptable way to find this one: every
 * path that reaches it is an ERROR path, so a test would have to fail in exactly the right place to
 * expose it, and the failure would present as a bugcheck with the arena's name on it rather than
 * the hook's.
 */
static void
ReleaseExtent(
	_In_ UINT32 ExtentId,
	_In_ UINT64 StubVa,
	_In_ BOOLEAN WasProtected
	)
{
	if (WasProtected)
	{
		CONST NTSTATUS RSt = NxcPteProtectRange(StubVa, NXC_HOOK_EXTENT_BYTES, TRUE, FALSE, TRUE);
		if (!NT_SUCCESS(RSt))
		{
			/*
			 * ⚠ LEAK THE EXTENT RATHER THAN FREE IT. If the pages cannot be made writable again,
			 * handing them to an allocator that will write to them is the bugcheck this function
			 * exists to prevent. An arena extent that is never reclaimed costs one page for the
			 * boot; the alternative costs the boot.
			 */
			HookLog("hook: could NOT make extent %u writable again (0x%08X) -- LEAKING it rather "
			        "than letting the arena poison a read-only page\n", ExtentId, RSt);
			return;
		}
	}

	/*
	 * ⚠ FREED BY BASE, NOT BY THE STORED EXTENT ID -- and this caller is why that matters most.
	 *
	 * An extent id is a position in an array the allocator SHIFTS on every split and every coalesce,
	 * so it is only meaningful while the lock that produced it is still held. `gHooks[Slot].ExtentId`
	 * was stored at install and used here at REMOVE, which can be minutes and any number of arena
	 * mutations later -- by then it can name a completely different extent, and freeing it would
	 * release memory belonging to something else.
	 *
	 * `StubVa` IS the extent base: `NxcArenaAlloc` returned it and `NxcPteProtectRange` above is
	 * already trusting it as the base of the whole NXC_HOOK_EXTENT_BYTES range. The owner is
	 * NXC_OWNER_HOST because the allocation went through `NxcArenaAlloc`, which is defined as
	 * `NxcArenaAllocFor(NXC_OWNER_HOST, ...)`.
	 */
	(void)NxcArenaFreeFor(NXC_OWNER_HOST, (void*)(ULONG_PTR)StubVa);
}

/** Write `jmp qword ptr [rip+0]` followed by Target. Clobbers no register at all. */
static void
WriteAbsoluteJmp(
	_Out_writes_(14) UINT8* Dst,
	_In_ UINT64 Target
	)
{
	Dst[0] = 0xFF;
	Dst[1] = 0x25;
	Dst[2] = 0x00;
	Dst[3] = 0x00;
	Dst[4] = 0x00;
	Dst[5] = 0x00;
	for (UINT32 i = 0; i < 8; i++)
		Dst[6 + i] = (UINT8)(Target >> (8u * i));
}

/* ------------------------------------------------------------------------------------------ */

NTSTATUS
NxcHookInstall(
	_In_ UINT64 TargetVa,
	_In_ UINT32 Flags,
	_In_ UINT32 FilterPid,
	_Out_ UINT32* OutDetail,
	_Out_ INT64* OutDelta,
	_Out_ UINT32* OutStolen
	)
{
	*OutDetail = NXC_HOOK_OK;
	*OutDelta  = 0;
	*OutStolen = 0;

	if (TargetVa == 0)
		return STATUS_INVALID_PARAMETER;

	/* --- refusals that cost nothing, before anything is allocated -------------------------- */

	CONST UINT32 ByteOffset = (UINT32)(TargetVa & 7u);
	if (ByteOffset > 3)
	{
		/*
		 * ⚠ A REAL LIMIT, REPORTED AS ONE. Five bytes starting at offset 4 or beyond run into the
		 * next qword, and no single store covers two qwords. Widening to two stores would reintroduce
		 * exactly the tearing this design exists to avoid, so the answer is that this entry is not
		 * hookable by this mechanism -- not that the mechanism should be relaxed.
		 */
		*OutDetail = NXC_HOOK_BAD_ALIGN;
		HookLog("hook: %llX is at qword offset %u -- 5 bytes would straddle two qwords, REFUSED\n",
		        TargetVa, ByteOffset);
		return STATUS_INVALID_ADDRESS;
	}

	if (TargetVa < NXC_KERNEL_VA_FLOOR)
	{
		/*
		 * ⚠ KERNEL VAs ONLY (D14.6). A usermode address here would be interpreted in whatever
		 * process happened to be current, which is not the process the caller meant and is a
		 * different command besides. Refused as not-resident rather than given its own code,
		 * because from the target's point of view that is exactly what it is.
		 */
		*OutDetail = NXC_HOOK_NOT_RESIDENT;
		HookLog("hook: %llX is not a kernel VA -- this command patches kernel code only\n", TargetVa);
		return STATUS_INVALID_ADDRESS;
	}

	if (!RangeIsResident(TargetVa, NXC_HOOK_MAX_STOLEN))
	{
		*OutDetail = NXC_HOOK_NOT_RESIDENT;
		HookLog("hook: %llX is not resident\n", TargetVa);
		return STATUS_INVALID_ADDRESS;
	}

	/*
	 * ⚠⚠⚠ NEVER HOOK AN IDT GATE'S HANDLER ENTRY. THIS BUGCHECKED THE MACHINE
	 * (CLOCK_WATCHDOG_TIMEOUT) AND THE REASON IS STRUCTURAL, NOT A BUG TO FIX.
	 *
	 * An interrupt/trap handler is entered by the CPU, not called. At its FIRST instruction:
	 *
	 *   1. **GS IS STILL THE USER GS.** Swapping it is the handler's own first job (`swapgs`). Our
	 *      thunk calls `KeGetCurrentProcessorNumberEx`, which is a GS-relative read of the PCR -- on
	 *      the wrong GS that dereferences USER-CONTROLLED memory, inside a trap handler, with
	 *      interrupts disabled. A core wedged there stops answering the clock, which is precisely
	 *      what CLOCK_WATCHDOG_TIMEOUT reports.
	 *   2. **INTERRUPTS ARE OFF** (an interrupt gate clears IF), so anything that faults, spins or
	 *      waits there hangs that core outright rather than failing.
	 *   3. **hde64 CANNOT DECODE `swapgs`.** The decoder is from 2009 and this project already hit
	 *      that exact wall building the IDT escape table -- `0F 01 F8` was the stop. So the
	 *      stolen-byte count for such a prologue is untrustworthy even before the GS problem, and
	 *      the install SUCCEEDING is not evidence it decoded correctly.
	 *
	 * Any one of those is fatal. Together they mean the entry of an IDT handler is not hookable by
	 * this mechanism, at all, and no amount of care in the handler changes it -- the damage is done
	 * before our C code is reached.
	 *
	 * ⚠ CHECKED AGAINST THE LIVE IDT, NOT A LIST OF NAMES. Whatever the gates point at right now is
	 * refused, so this cannot be defeated by a different Windows build, a different vector, or a
	 * caller that derived the address some other way. It is the CPU's own table.
	 *
	 * ⚠ AND IT DOES NOT BAN HOOKING THE EXCEPTION PATH -- only its ENTRY POINTS. A function CALLED
	 * by a handler, after the prologue has run `swapgs` and established a sane context, is an
	 * ordinary C function and remains a legitimate target.
	 */
	{
		UINT32 IdtVector = 0;
		if (NxcIdtIsGateHandler(TargetVa, &IdtVector))
		{
			*OutDetail = NXC_HOOK_IS_IDT_HANDLER;
			HookLog("hook: %llX is the IDT handler for vector %u -- REFUSED. An ISR entry runs "
			        "BEFORE swapgs with interrupts off, so the thunk's GS-relative PCR read would "
			        "dereference USER memory inside a trap handler. This bugchecked the machine on "
			        "2026-07-30 (CLOCK_WATCHDOG_TIMEOUT).\n", TargetVa, IdtVector);
			return STATUS_ACCESS_DENIED;
		}
	}

	/*
	 * ⚠ LBR SAMPLING NEEDS THE LOGGING DETOUR AND A RING TO WRITE INTO. Both are refused rather than
	 * ignored, because both failures are SILENT in the worst way: the no-op detour never reaches C,
	 * so a --lbr hook without --log would install cleanly, report success, take every hit, and
	 * capture nothing at all. That is a command that lies about what it did.
	 */
	/*
	 * ⚠ THE PROTECTION SHAPE WRITES INTO NXCMD_CALL_ENTRY, SO IT NEEDS THE RECORD, NOT THE LOG LINE.
	 * Refused for the same reason --lbr is: the hit path takes `--calls` or the log ring, never both
	 * (one hit, one record), so _PROT without _CALLS would install cleanly, fire on every call, and
	 * drop every protection transition into a three-qword log line that cannot hold them. Silent, and
	 * indistinguishable from "the target never reprotected anything" -- which is precisely the
	 * conclusion this shape exists to make provable.
	 */
	if ((Flags & NXC_HOOK_FLAG_PROT) != 0 && (Flags & NXC_HOOK_FLAG_CALLS) == 0)
	{
		*OutDetail = NXC_HOOK_OK;
		HookLog("hook: --prot records into the call ring and needs --calls; the log ring's three "
		        "payload qwords cannot carry base/size/PTE. REFUSED rather than silently dropped\n");
		return STATUS_INVALID_PARAMETER_MIX;
	}

	if ((Flags & NXC_HOOK_FLAG_LBR) != 0)
	{
		if ((Flags & NXC_HOOK_FLAG_LOG) == 0)
		{
			*OutDetail = NXC_HOOK_OK;
			HookLog("hook: --lbr needs the LOGGING detour -- the no-op stub never reaches C, so "
			        "there is nowhere to sample from. REFUSED rather than installed as a no-op\n");
			return STATUS_INVALID_PARAMETER_MIX;
		}

		UINT32 Taken = 0, Dropped = 0, Slots = 0;
		NxcLbrSnapCounters(&Taken, &Dropped, &Slots, &SnapOverDiscard);
		if (Slots == 0)
		{
			*OutDetail = NXC_HOOK_OK;
			HookLog("hook: --lbr needs a snapshot ring; none is reserved. Run `lbr snap init` "
			        "first -- the capture path cannot allocate, it runs at the target's IRQL\n");
			return STATUS_INVALID_DEVICE_STATE;
		}
	}

	/*
	 * ⚠ THE TARGET PAGE MUST BE EXECUTABLE, AND THIS IS THE GUARD THAT KEEPS THIS COMMAND FROM
	 * BEING A HOST-CRASHER.
	 *
	 * Without it, `hook <any resident kernel address>` happily length-decodes whatever bytes are
	 * there -- a stack, a pool block, a page of pointers -- because a length decoder has no notion
	 * of whether its input is code. It would then splice five bytes into live DATA and report
	 * success. The corruption would land somewhere unrelated, later, with nothing pointing back
	 * here.
	 *
	 * An executable mapping is not proof the address is a function entry; nothing available here is.
	 * It IS proof the bytes are meant to be executed, which rules out the entire class of accidents
	 * where a mistyped or stale address quietly destroys unrelated state.
	 *
	 * Refused when the walk fails too: an address whose PTE cannot be read is not one to patch on
	 * the strength of MmIsAddressValid alone.
	 */
	NXC_PTE_INFO Pte;
	CONST NTSTATUS QSt = NxcPteQuery(TargetVa, &Pte);
	if (!NT_SUCCESS(QSt) ||
	    (Pte.Flags & (NXC_PTE_VALID | NXC_PTE_PRESENT)) != (NXC_PTE_VALID | NXC_PTE_PRESENT) ||
	    (Pte.Flags & NXC_PTE_EXECUTE) == 0)
	{
		*OutDetail = NXC_HOOK_NOT_RESIDENT;
		HookLog("hook: %llX is not executable (walk 0x%08X, flags 0x%08X) -- REFUSED before "
		        "decoding, because a length decoder cannot tell code from data\n",
		        TargetVa, QSt, Pte.Flags);
		return STATUS_INVALID_ADDRESS;
	}

	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active != 0 && gHooks[i].TargetVa == TargetVa)
		{
			*OutDetail = NXC_HOOK_ALREADY;
			return STATUS_ALREADY_COMMITTED;
		}
	}

	UINT32 Slot = NXC_MAX_HOOKS;
	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active == 0) { Slot = i; break; }
	}
	if (Slot == NXC_MAX_HOOKS)
	{
		*OutDetail = NXC_HOOK_NO_SLOT;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* --- decode the prologue BEFORE allocating, so a refusal leaks nothing ------------------ */

	UINT32 Detail = NXC_HOOK_OK;
	CONST UINT32 Stolen = DecodePrologue((CONST UINT8*)(ULONG_PTR)TargetVa, 5u, &Detail);
	if (Stolen == 0)
	{
		*OutDetail = Detail;
		HookLog("hook: %llX prologue not usable (detail %u)\n", TargetVa, Detail);
		return STATUS_NOT_SUPPORTED;
	}

	/* --- the stub and trampoline ----------------------------------------------------------- */

	ULONG ExtentId = 0;
	void* CONST Extent = NxcArenaAlloc(NXC_HOOK_EXTENT_BYTES, &ExtentId);
	if (Extent == NULL)
	{
		*OutDetail = NXC_HOOK_NO_TRAMPOLINE;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	CONST UINT64 StubVa = (UINT64)(ULONG_PTR)Extent;
	CONST UINT64 TrampVa = StubVa + NXC_HOOK_STUB_BYTES;

	/*
	 * ⚠ THE RANGE CHECK HAPPENS HERE, NOT EARLIER, because the thing that has to be reachable is the
	 * STUB, and the stub's address is not known until the arena has chosen one. The delta is always
	 * reported: "out of range" and "out of range by 40 bytes" call for completely different work, and
	 * whether our arena lands within 2 GB of a given kernel target is not something to assume in
	 * either direction on a machine whose self-map index is randomised every boot.
	 */
	CONST INT64 Delta = (INT64)StubVa - (INT64)(TargetVa + 5);
	*OutDelta = Delta;

	if (Delta > 0x7FFFFFFFLL || Delta < -0x80000000LL)
	{
		*OutDetail = NXC_HOOK_OUT_OF_RANGE;
		HookLog("hook: stub at %llX is %lld bytes from %llX -- rel32 cannot reach, REFUSED\n",
		        StubVa, Delta, TargetVa);
		ReleaseExtent(ExtentId, StubVa, FALSE);
		return STATUS_NOT_SUPPORTED;
	}

	/*
	 * ⚠ THE PROBE EXITS HERE, having done EVERYTHING except write. Alignment, kernel-VA, residency,
	 * prologue decode, slot availability, a REAL arena allocation and the REAL delta from the address
	 * that allocation returned. Stopping any earlier would report the distance to a stub the actual
	 * install would not have used, which is the one number the probe exists to produce.
	 */
	if (Flags & NXC_HOOK_FLAG_PROBE)
	{
		ReleaseExtent(ExtentId, StubVa, FALSE);
		HookLog("hook probe: %llX -- %u byte(s) stealable, stub would sit at %llX, delta %lld, "
		        "rel32 REACHES (nothing was patched)\n",
		        TargetVa, Stolen, StubVa, Delta);
		return STATUS_SUCCESS;
	}

	/* Trampoline: the stolen instructions, then an absolute jump back to just past them. */
	RtlCopyMemory((void*)(ULONG_PTR)TrampVa, (CONST void*)(ULONG_PTR)TargetVa, Stolen);
	WriteAbsoluteJmp((UINT8*)(ULONG_PTR)TrampVa + Stolen, TargetVa + Stolen);

	/*
	 * ⚠ THE ENTRY IS POPULATED BEFORE THE STUB IS BUILT, AND BEFORE ANYTHING IS PATCHED.
	 *
	 * A --log stub carries `&gHooks[Slot]` as an immediate and the thunk reads TrampolineVa out of
	 * it on every call. Filling the entry after the patch went live -- which is what the original
	 * ordering did, harmlessly, when the stub was a self-contained no-op -- would mean the first
	 * call through the hook reading TrampolineVa == 0 and jumping to address zero, at the entry of
	 * a live kernel function.
	 *
	 * Active stays 0 until the patch is verified, so a failure below leaves a fully described but
	 * inactive slot, which the cleanup zeroes.
	 */
	gHooks[Slot].TargetVa     = TargetVa;
	gHooks[Slot].HandlerVa    = StubVa;
	gHooks[Slot].TrampolineVa = TrampVa;
	gHooks[Slot].StolenBytes  = Stolen;
	gHooks[Slot].ExtentId     = (UINT32)ExtentId;
	gHooks[Slot].Active       = 0;

	if ((Flags & NXC_HOOK_FLAG_LOG) != 0)
	{
		/*
		 * STAGE 2 stub -- ten bytes to carry the context, then into the shared thunk:
		 *
		 *     49 BA <imm64>              mov r10, &gHooks[Slot]
		 *     FF 25 00000000 <qword>     jmp qword ptr [rip+0]  -> NxcHookThunk
		 *
		 * r10 is volatile AND dead at a function entry (arguments arrive in rcx/rdx/r8/r9 and
		 * xmm0-3, and no correct function reads r10 before writing it), so this costs the target
		 * nothing. Everything else -- saving the volatile set, the C call, restoring, the tail jump
		 * -- lives in HookThunk.asm, where it is readable. Hand-encoding sixty bytes per hook here
		 * would put the difficult part in the one place it cannot be reviewed.
		 */
		UINT8* CONST S = (UINT8*)(ULONG_PTR)StubVa;
		S[0] = 0x49;
		S[1] = 0xBA;
		CONST UINT64 Ctx = (UINT64)(ULONG_PTR)&gHooks[Slot];
		for (UINT32 i = 0; i < 8; i++)
			S[2 + i] = (UINT8)(Ctx >> (8u * i));
		WriteAbsoluteJmp(S + 10, (UINT64)(ULONG_PTR)&NxcHookThunk);
	}
	else
	{
		/*
		 * STAGE 1 stub -- jump straight into the trampoline, touching NO register at all, not even
		 * RAX (`jmp [rip+0]` reads its destination from data). Kept as the DEFAULT rather than
		 * replaced, because it is the variant that has been proven on hardware and the one whose
		 * failure mode is smallest. Logging is opt-in for the same reason a diagnostic is.
		 */
		WriteAbsoluteJmp((UINT8*)(ULONG_PTR)StubVa, TrampVa);
	}

	/* Both are code now. RX, not RWX -- writable executable memory is the artefact this project
	 * exists to find, and leaving one behind on purpose would be indefensible. */
	CONST NTSTATUS PSt = NxcPteProtectRange(StubVa, NXC_HOOK_EXTENT_BYTES, FALSE, TRUE, TRUE);
	if (!NT_SUCCESS(PSt))
	{
		*OutDetail = NXC_HOOK_NO_TRAMPOLINE;
		HookLog("hook: could not make the stub executable (0x%08X)\n", PSt);
		RtlZeroMemory(&gHooks[Slot], sizeof(gHooks[Slot]));
		ReleaseExtent(ExtentId, StubVa, FALSE);
		return PSt;
	}

	/* --- the patch ------------------------------------------------------------------------- */

	CONST UINT64 Aligned  = TargetVa & ~(UINT64)7;
	CONST UINT64 Original = *(volatile UINT64*)(ULONG_PTR)Aligned;

	UINT8 Patch[5];
	Patch[0] = 0xE9;
	CONST INT32 Rel = (INT32)Delta;
	for (UINT32 i = 0; i < 4; i++)
		Patch[1 + i] = (UINT8)(((UINT32)Rel) >> (8u * i));

	CONST UINT64 Patched = SpliceQword(Original, ByteOffset, Patch, 5);

	CONST NTSTATUS SSt = StoreQwordAtomic(Aligned, Patched);
	if (!NT_SUCCESS(SSt))
	{
		*OutDetail = NXC_HOOK_VERIFY_FAILED;
		HookLog("hook: the atomic store did not happen (0x%08X)\n", SSt);
		RtlZeroMemory(&gHooks[Slot], sizeof(gHooks[Slot]));
		ReleaseExtent(ExtentId, StubVa, TRUE);
		return SSt;
	}

	/*
	 * ⚠ READ BACK THROUGH THE ORIGINAL VA, NEVER THE ALIAS. The alias has already been torn down,
	 * which is deliberate: reading through it would prove only that the alias remembers its own
	 * write. An alias mapping the WRONG frames would pass that test perfectly while the target was
	 * untouched. Only the original VA answers the question that matters.
	 */
	CONST UINT64 Readback = *(volatile UINT64*)(ULONG_PTR)Aligned;
	if (Readback != Patched)
	{
		*OutDetail = NXC_HOOK_VERIFY_FAILED;
		HookLog("hook: read-back %llX != stored %llX -- the write did not land\n",
		        Readback, Patched);
		/* Put back what was there. If THIS fails there is nothing further to try, and the log is
		 * the only record; it is still better than leaving a half-known qword unrecorded. */
		(void)StoreQwordAtomic(Aligned, Original);
		RtlZeroMemory(&gHooks[Slot], sizeof(gHooks[Slot]));
		ReleaseExtent(ExtentId, StubVa, TRUE);
		return STATUS_UNSUCCESSFUL;
	}

	/* Only what the patch itself produced. The rest was written before the stub was built, because
	 * a --log stub reads TrampolineVa out of this entry on its very first call. */
	gHooks[Slot].AlignedVa     = Aligned;
	gHooks[Slot].OriginalQword = Original;
	gHooks[Slot].PatchedQword  = Patched;

	/*
	 * InstallFlags BEFORE Active, and that order is load-bearing rather than tidy. The patch is
	 * ALREADY IN at this point, so a hit can arrive between these two stores; the hit path tests
	 * Active first, so setting it last means a hook is never visible as live with flags of zero.
	 * Reversed, the first hits of an LBR-sampling hook would silently take no snapshot -- and the
	 * first hits are exactly the ones worth having.
	 *
	 * ⚠ FilterPid IS PART OF THAT ORDERING, NOT AN AFTERTHOUGHT. Published after Active it would
	 * read as 0 -- "record everything" -- for the first hits, which on a syscall this hot is
	 * hundreds of foreign records written before the scope takes effect.
	 */
	gHooks[Slot].InstallFlags  = Flags;
	gHooks[Slot].FilterPid     = FilterPid;
	gHooks[Slot].Active        = 1;
	gHookCount++;

	HookLog("hook: %llX -> stub %llX -> trampoline %llX (+%u stolen, %s), qword %llX -> %llX\n",
	        TargetVa, StubVa, TrampVa, Stolen,
	        ((Flags & NXC_HOOK_FLAG_LOG) != 0) ? "LOGGING" : "no-op",
	        Original, Patched);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcHookRemove(
	_In_ UINT64 TargetVa,
	_Out_ UINT32* OutDetail
	)
{
	*OutDetail = NXC_HOOK_OK;

	UINT32 Slot = NXC_MAX_HOOKS;
	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active != 0 && gHooks[i].TargetVa == TargetVa) { Slot = i; break; }
	}
	if (Slot == NXC_MAX_HOOKS)
		return STATUS_NOT_FOUND;

	NXC_HOOK_ENTRY* CONST H = &gHooks[Slot];

	/*
	 * ⚠ IS IT STILL OURS? If the qword no longer holds what we left there, something else patched
	 * this function after we did. Writing our saved original back would then destroy THEIR patch,
	 * and a jump into a trampoline they still believe is live is a bugcheck with our name nowhere
	 * near it. One unknown is better than two, so this refuses and says so.
	 */
	CONST UINT64 Now = *(volatile UINT64*)(ULONG_PTR)H->AlignedVa;
	if (Now != H->PatchedQword)
	{
		*OutDetail = NXC_HOOK_FOREIGN_PATCH;
		HookLog("hook: %llX now reads %llX, not the %llX we wrote -- someone else patched over "
		        "us. NOT restoring; that would destroy their patch.\n",
		        TargetVa, Now, H->PatchedQword);
		return STATUS_UNSUCCESSFUL;
	}

	CONST NTSTATUS St = StoreQwordAtomic(H->AlignedVa, H->OriginalQword);
	if (!NT_SUCCESS(St))
	{
		*OutDetail = NXC_HOOK_VERIFY_FAILED;
		return St;
	}

	if (*(volatile UINT64*)(ULONG_PTR)H->AlignedVa != H->OriginalQword)
	{
		*OutDetail = NXC_HOOK_VERIFY_FAILED;
		HookLog("hook: restore of %llX did not read back -- the patch is STILL LIVE\n", TargetVa);
		return STATUS_UNSUCCESSFUL;
	}

	/*
	 * ⚠ FREE THE TRAMPOLINE ONLY AFTER THE RESTORE IS VERIFIED, and the order is the whole point: a
	 * thread already inside the stub is on its way to the trampoline. Freeing first would hand those
	 * bytes back to the arena while something is about to execute them.
	 *
	 * Even this order has a window -- a thread that entered the stub microseconds ago is still in
	 * flight. It is not closed here, and pretending otherwise by adding a delay would be worse than
	 * saying so: a sleep long enough to feel safe is not a proof, it is a guess with a number on it.
	 */
	ReleaseExtent(H->ExtentId, H->HandlerVa, TRUE);

	RtlZeroMemory(H, sizeof(*H));
	if (gHookCount != 0)
		gHookCount--;

	HookLog("hook: %llX restored\n", TargetVa);
	return STATUS_SUCCESS;
}

void
NxcHookRemoveAll(
	void
	)
{
	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active == 0)
			continue;

		UINT32 Detail = 0;
		CONST NTSTATUS St = NxcHookRemove(gHooks[i].TargetVa, &Detail);
		if (!NT_SUCCESS(St))
		{
			/*
			 * ⚠ THIS IS THE WORST OUTCOME THIS FILE HAS, and it is logged rather than hidden: a live
			 * patch pointing into memory that is about to go away. There is no safe action left --
			 * forcing the restore would overwrite whatever replaced us, and freeing the trampoline
			 * would leave the patch jumping into reclaimed memory. The record is what remains.
			 */
			HookLog("hook: COULD NOT REMOVE %llX (detail %u) -- a live patch will outlive us\n",
			        gHooks[i].TargetVa, Detail);
		}
	}
}

/* ------------------------------------------------------------------------------------------ */

/*
 * The offset HookThunk.asm uses to reach TrampolineVa. Asserted rather than trusted: the assembly
 * hard-codes 16, so reordering this struct would turn a field access into a jump to whatever
 * happens to be at +16 -- at the entry of a hooked function, on every call. A build break is the
 * only acceptable way for that to be discovered.
 */
C_ASSERT(FIELD_OFFSET(NXC_HOOK_ENTRY, TrampolineVa) == 16);

/**
 * ⚠ RUNS AT THE HOOKED FUNCTION'S IRQL, IN ITS THREAD, WITH ITS LOCKS HELD.
 *
 * Everything this does must be safe in a context we know nothing about. NxcLogRingWrite is built
 * for exactly that -- one InterlockedIncrement64 to claim a slot, no lock, no allocation, no call
 * out of the ring -- which is why the ring existed before the hook did and had a real producer
 * (the command path) before this one arrived.
 *
 * ⚠ AND IT MUST NOT RE-ENTER ITSELF. If a hooked function is reached from inside this handler --
 * directly, or because the target is something the logging path itself touches -- the result is
 * unbounded recursion at arbitrary IRQL, which is a double fault rather than a hang. The guard is
 * per-processor and set for the duration; a hit that arrives while the flag is set is COUNTED and
 * dropped rather than followed.
 *
 * Counting matters: a silently ignored recursive hit would make the log read as though the call
 * never happened, which is the same failure the ring's sequence numbers exist to prevent.
 */
static volatile LONG gInHandler[NXC_MAX_TRACE_CPUS_FOR_HOOK];
static volatile LONG64 gHookHits = 0;
static volatile LONG64 gHookReentries = 0;
/* Hits that were REAL but belonged to another process. Counted, never silent -- see the filter. */
static volatile LONG64 gHookFiltered  = 0;

/*
 * ⚠⚠ RETURNS THE CLAIM DECISION, AND ZERO IS THE ONLY SAFE DEFAULT.
 *
 * 0 = continue into the target (what every hook has always done). Non-zero = the thunk RETURNS TO
 * THE TARGET'S CALLER and the target never runs at all.
 *
 * This function serves EVERY hook, not only the dispatcher, so a stray non-zero would silently
 * swallow an unrelated hooked call. Every exit below therefore returns 0 explicitly; only the one
 * branch that has classified a #DB as ours can return 1.
 */
UINT64
NxcHookOnHit(
	_In_ NXC_HOOK_ENTRY* Entry,
	_In_ UINT64 Arg1,
	_In_ UINT64 Arg2,
	_In_ UINT64 ReturnAddress,
	/* The target's arg3. For KiDispatchException that is the KTRAP_FRAME -- forwarded because
	 * resuming an EXECUTE breakpoint needs EFLAGS.RF set in it, and Windows hands us the pointer
	 * rather than making us derive it. For an Nt* entry point it is usually the OBJECT_ATTRIBUTES.
	 * Opaque here; only the observer that asked for it interprets it. */
	_In_ UINT64 Arg3,
	/* The target's arg4. Added for B-02: NtOpenProcess puts the CLIENT_ID -- the pid
	 * being opened -- in argument four, so three would have stopped one short of the only question
	 * that item exists to answer. */
	_In_ UINT64 Arg4,
	/* The target's ENTRY RSP. Arguments 5 and beyond live at EntryRsp+0x28 under the x64 ABI, so
	 * this one value reaches all of them -- NtSetInformationFile's FileInformationClass (arg 5, the
	 * only thing that says a DELETE is happening) and NtCreateFile's CreateOptions (arg 9, which
	 * carries FILE_DELETE_ON_CLOSE) included. Opaque here; read only by the capture that asked. */
	_In_ UINT64 EntryRsp
	)
{
	if (Entry == NULL)
		return 0;

	/*
	 * ⚠⚠ FREEZE THE LBR RING FIRST -- BEFORE THE RE-ENTRY GUARD, BEFORE ANY nt CALL, BEFORE ANYTHING.
	 *
	 * MEASURED (D36): with the freeze inside NxcLbrSnapTake, this handler burned 23 OF 32 ENTRIES
	 * before the ring was read. `KeGetCurrentProcessorNumberEx` below is an INDIRECT CALL through the
	 * nt API table, and so are the attribution calls further in; every one of them, and everything
	 * they call, is a branch the hardware dutifully records over the history we came to collect. The
	 * first working trace reached two hops back and stopped, for exactly that reason.
	 *
	 * Freezing costs NOTHING: `rdmsr`/`wrmsr` are not control transfers, so the ring is preserved
	 * exactly as the hit found it. Only the `call` into this function is spent -- one entry, and it
	 * is unavoidable in any design that reaches C at all.
	 *
	 * ⚠ IT RUNS EVEN WHEN THIS HOOK IS NOT SAMPLING. The read of IA32_LBR_CTL is one RDMSR, and the
	 * write is skipped entirely when EN is already clear -- so a non-LBR hook pays a single register
	 * read. Making it conditional on the flag would mean testing `Entry->InstallFlags` first, which is
	 * a load and a branch, i.e. paying in the currency we are trying to save.
	 */
	CONST UINT64 FrozenCtl = NxcLbrFreezeRing();

	CONST ULONG Cpu = KeGetCurrentProcessorNumberEx(NULL);
	if (Cpu >= NXC_MAX_TRACE_CPUS_FOR_HOOK)
	{
		NxcLbrThawRing(FrozenCtl);   /* EVERY exit thaws -- see below */
		return 0;
	}

	if (InterlockedCompareExchange(&gInHandler[Cpu], 1, 0) != 0)
	{
		InterlockedIncrement64(&gHookReentries);
		NxcLbrThawRing(FrozenCtl);
		return 0;
	}

	InterlockedIncrement64(&gHookHits);

	/*
	 * ⚠⚠ THE EXCEPTION-PATH VARIANT DIVERGES HERE, BEFORE THE RING WRITE, AND THAT ORDER IS THE
	 * WHOLE REASON IT IS SAFE TO HOOK THE DISPATCHER AT ALL.
	 *
	 * `KiDispatchException` runs for EVERY dispatched exception on the machine. Writing a ring entry
	 * per hit would flood a 4096-entry ring in well under a second, destroy every other record in it,
	 * and add a lock-free store plus a timestamp to the system's exception path -- for events that
	 * are almost all somebody else's. So this variant COUNTS by exception code and writes a ring
	 * entry only for the one code it is here for.
	 *
	 * ⚠ AND IT RETURNS EARLY, so no LBR snapshot is taken either. ~96 RDMSRs on every exception in
	 * the system would be a measurable slowdown of Windows itself, which is not a diagnostic -- it is
	 * a fault we introduced.
	 */
	if (Entry->InstallFlags & NXC_HOOK_FLAG_EXCEPTION)
	{
		/* ⚠ Arg2 IS THE KEXCEPTION_FRAME, and it has been arriving here unused since the thunk was
		 * written. KiDispatchException(Record, ExceptionFrame, TrapFrame, ...) -- arg2 holds the
		 * nonvolatiles (R12-R15 at ExceptionFrame+0x118..0x130 on this build, base proven from the
		 * funnel's own `mov rdx, rsp`). No assembly change was needed: the value was already there. */
		CONST UINT64 Claim = NxcBpdOnException(Arg1, ReturnAddress, Arg3, Arg2);
		InterlockedExchange(&gInHandler[Cpu], 0);
		NxcLbrThawRing(FrozenCtl);
		/* The ONE path that may swallow a call. NxcBpdOnException returns non-zero only for a #DB
		 * its classifier matched to an armed DATA slot with our CR3, and only when claiming has
		 * been explicitly enabled. Everything else here returns 0. */
		return Claim;
	}

	/*
	 * ==============================================================================================
	 * ⚠⚠ THE PID FILTER. Without it a hook on a hot syscall is not a capture surface.
	 * ==============================================================================================
	 *
	 * measured: `hook nt NtProtectVirtualMemory --calls --prot` took ~500 hits/second on
	 * an IDLE desktop -- 75297 in a few minutes. A 512-slot ring wraps in about one second, and the
	 * selftest's own record was overwritten before a second process could start and drain it, twice
	 * in a row. The capture was not wrong; it was buried under every other process on the machine.
	 *
	 * ⚠ THE HIT IS COUNTED FIRST AND THE FILTERING IS COUNTED SEPARATELY (D3). A filtered hook still
	 * reports that it is live and firing, because "0 records" and "12000 hits, none yours" are
	 * completely different situations and the operator must not have to guess which one they have.
	 * Silently returning would make a correctly-scoped hook look identical to a broken one.
	 *
	 * ⚠ PLACED AFTER THE EXCEPTION VARIANT ON PURPOSE. That path does its own CR3 matching and its
	 * return value CLAIMS an exception, so filtering it here would change what the machine does
	 * rather than what we record. A filter must subtract from the RECORD, never from behaviour.
	 *
	 * ⚠ AND IT IS A PID, NOT A CR3, WHICH IS THE RIGHT TOOL ONLY FOR RING 3. The kernel is mapped
	 * into every address space, so neither a pid nor a CR3 scopes kernel-side execution -- that is
	 * what the PT/LBR IP-range filter is for. This scopes SYSCALLS BY CALLER, which is exactly the
	 * question "which process reprotected that page" asks.
	 */
	if (Entry->FilterPid != 0 &&
	    (UINT32)(ULONG_PTR)PsGetCurrentProcessId() != Entry->FilterPid)
	{
		InterlockedIncrement64(&gHookFiltered);
		InterlockedExchange(&gInHandler[Cpu], 0);
		NxcLbrThawRing(FrozenCtl);
		return 0;
	}

	/*
	 * ⚠ CALL EVIDENCE INSTEAD OF THE LOG LINE, NOT AS WELL AS IT (B-01/B-02).
	 *
	 * The log ring carries three payload qwords, so a --calls hook writing there too would record
	 * the SAME call twice at different fidelities, and every consumer would then have to know which
	 * copy to believe. Worse, the two would disagree the moment one gained a field -- the
	 * two-expressions-that-must-agree shape this project keeps getting bitten by. One hit, one
	 * record, in the ring that can hold all of it.
	 *
	 * The name extraction happens INSIDE NxcCallsRecord, here, in the caller's context: this is the
	 * only place the usermode string pointers in Arg2/Arg3 are dereferenceable at all. A drain
	 * command running later in PlatformCtl's context would find those addresses meaningless.
	 */
	/*
	 * TPM observation is ADDITIVE and deliberately sits outside the calls/log choice below.
	 *
	 * Its payload fits neither store -- not the log ring's three qwords, not an NXCMD_CALL_ENTRY --
	 * so folding it into that if/else would have put TPM records somewhere `tpmtrace dump` never
	 * looks. That is precisely the failure documented on NXC_HOOK_FLAG_ALL, where a hook
	 * fired correctly and the drain reported zero because the hits went to the other store.
	 *
	 * It records and returns. It does not touch the IRP, so the target's TPM command proceeds
	 * exactly as it would have (TpmTrace.h explains why the instrument must not be a mechanism).
	 */
	if ((Entry->InstallFlags & NXC_HOOK_FLAG_TPM) != 0)
	{
		NxcTpmTraceRecord(Arg1, Arg2);
	}

	if ((Entry->InstallFlags & NXC_HOOK_FLAG_CALLS) != 0)
	{
		NxcCallsRecord(Entry->TargetVa, ReturnAddress, Arg1, Arg2, Arg3, Arg4, EntryRsp,
		               Entry->InstallFlags);
	}
	else
	{
		NxcLogRingWrite(NXCMD_LOG_KIND_HOOK, Entry->TargetVa, Arg1, Arg2);
	}

	/*
	 * ⚠ THE LBR SNAPSHOT IS TAKEN HERE, AND HERE IS THE ENTIRE POINT (D23). We are on the TARGET'S
	 * OWN THREAD, microseconds after the target's own branches, so the ring right now is the path
	 * INTO this function and nothing else. LBR has no CR3 filter, so this is the only moment at
	 * which a ring can be attributed to a process at all -- a read from a command thread would
	 * describe whoever happened to run last on that core.
	 *
	 * ⚠ INSIDE THE RE-ENTRY GUARD ON PURPOSE. NxcLbrSnapTake issues ~96 RDMSRs; taking that on a
	 * re-entrant hit would multiply the cost exactly where the guard exists to bound it.
	 *
	 * ⚠ AND AFTER THE RING WRITE, so a hit is recorded even if the snapshot ring is full. The log
	 * entry is cheap and always available; the snapshot is expensive and bounded. Losing the record
	 * that a hit happened because the expensive part ran out would be the wrong thing to lose.
	 */
	if (Entry->InstallFlags & NXC_HOOK_FLAG_LBR)
		NxcLbrSnapTake(Entry->TargetVa, FrozenCtl);

	InterlockedExchange(&gInHandler[Cpu], 0);

	/*
	 * ⚠⚠ EVERY PATH OUT OF THIS FUNCTION MUST THAW, AND THE EARLY RETURNS ABOVE DO. A frozen ring
	 * left behind is not a small leak: LBR_CTL.EN stays clear on that core, so the hardware records
	 * NOTHING from then on, `lbr read` shows an armed core with an empty ring, and every later
	 * capture is silently empty. That is the failure mode this project keeps naming -- looks healthy,
	 * produces nothing -- and a single missed return would cause it.
	 */
	NxcLbrThawRing(FrozenCtl);
	return 0;
}

/**
 * ⚠ COUNTED BY WALKING THE TABLE, NOT BY A COUNTER INCREMENTED AT INSTALL. A counter is a second
 * piece of state that must be decremented on EVERY removal path -- including the refusal paths --
 * and one missed decrement would permanently refuse to free the snapshot ring. The table is the
 * truth; asking it is cheap and cannot drift.
 */
UINT32
NxcHookLbrSamplerCount(void)
{
	UINT32 Count = 0;
	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active && (gHooks[i].InstallFlags & NXC_HOOK_FLAG_LBR))
			Count++;
	}
	return Count;
}

UINT32
NxcHookExceptionObserverCount(void)
{
	UINT32 Count = 0;
	for (UINT32 i = 0; i < NXC_MAX_HOOKS; i++)
	{
		if (gHooks[i].Active && (gHooks[i].InstallFlags & NXC_HOOK_FLAG_EXCEPTION))
			Count++;
	}
	return Count;
}

/** Hits and refused re-entries, for `hook list`. Counters, not a verdict. */
void
NxcHookCounters(
	_Out_ UINT64* OutHits,
	_Out_ UINT64* OutReentries,
	_Out_ UINT64* OutFiltered
	)
{
	*OutHits      = (UINT64)gHookHits;
	*OutReentries = (UINT64)gHookReentries;
	*OutFiltered  = (UINT64)gHookFiltered;
}

/**
 * The victim. Its ONLY caller is NxcHookSelfTest.
 *
 * ⚠ THE ATTRIBUTES ARE THE TEST, NOT DECORATION.
 *
 * `noinline` because an inlined function has no entry to patch, and the test would then be hooking
 * whatever the compiler left at that address -- passing or failing for reasons unrelated to the
 * hook. `optimize("", off)` for the same reason from the other direction: at /O2 this collapses to
 * `lea eax, [rcx+1234h]; ret`, which is correct and hookable, but it is correct BY LUCK. A prologue
 * that happened to start with a RIP-relative instruction would be refused by DecodePrologue and the
 * self-test would report a hook failure when nothing was wrong with the hook.
 *
 * `volatile` on the local keeps the body from being folded away entirely, so there is a real
 * prologue of real instructions to steal.
 *
 * The value is arbitrary and only has to be something a wrong control flow would not produce.
 */
#define NXC_HOOK_VICTIM_ADD   0x1234u

#pragma optimize("", off)
static __declspec(noinline) UINT32
HookVictim(
	_In_ UINT32 X
	)
{
	volatile UINT32 V = X;
	V += NXC_HOOK_VICTIM_ADD;
	return V;
}
#pragma optimize("", on)

NTSTATUS
NxcHookSelfTest(
	_Out_ UINT32* OutDetail,
	_Out_ UINT32* OutDetail2,
	_Out_ UINT64* OutHits
	)
{
	*OutDetail  = NXC_HOOK_ST_OK;
	*OutDetail2 = NXC_HOOK_OK;
	*OutHits    = 0;

	CONST UINT32 In       = 7u;
	CONST UINT32 Expected = In + NXC_HOOK_VICTIM_ADD;
	CONST UINT64 Va       = (UINT64)(ULONG_PTR)&HookVictim;

	/*
	 * ⚠ SNAPSHOT THE COUNTER FIRST. THE CHECK IS A DELTA, NOT A TOTAL.
	 *
	 * gHookHits is cumulative for the life of the boot, and this was originally asserted as
	 * `Hits != 0`. That is sound exactly once: on the FIRST run of a boot. Every run after it would
	 * pass on the leftover count from an earlier run even if the thunk had stopped reaching C
	 * entirely -- the check would be reading history and reporting it as this run's evidence.
	 *
	 * Caught by its own output: `selftest` printed "1 ring hit(s)" and the harness,
	 * running the same command minutes later, printed "2 hit(s)" for a single logging pass. The
	 * number was cumulative and the check was written as though it were not.
	 */
	UINT64 HitsBefore = 0, ReentriesBefore = 0;
	UINT64 FilteredBefore = 0;
	NxcHookCounters(&HitsBefore, &ReentriesBefore, &FilteredBefore);

	/* 1. Baseline. Measured, not assumed -- if this is already wrong, everything after it is noise. */
	if (HookVictim(In) != Expected)
	{
		*OutDetail = NXC_HOOK_ST_BASELINE;
		return STATUS_UNSUCCESSFUL;
	}

	CONST UINT64 Before = *(volatile UINT64*)(ULONG_PTR)(Va & ~(UINT64)7);

	/*
	 * 2. Install. BOTH VARIANTS ARE TESTED, in two passes over the same sequence.
	 *
	 * Pass 0 is the no-op stub: control flow only, no register touched. Pass 1 is the --log stub,
	 * which loads r10, runs the thunk, saves and restores the whole volatile set, and calls into C
	 * at whatever IRQL the victim was reached at. If pass 1 fails where pass 0 passed, the fault is
	 * in the THUNK and not in the patch -- which is the entire reason they are separate stubs rather
	 * than one stub that grew a feature.
	 */
	/*
	 * ⚠ PASS 2 EXISTS BECAUSE STAGE 3 HAD NEVER CAPTURED ANYTHING. `lbr snap init/drain/free` was
	 * covered by the harness, and `hook --log` was covered -- but the JOIN between them, a hook hit
	 * actually driving NxcLbrSnapTake into a populated record, had never once executed. Two verified
	 * halves do not make a verified whole, and the seam is where this project keeps finding defects.
	 *
	 * It runs against the same victim we own, so nothing foreign is patched to prove it.
	 */
	for (UINT32 Pass = 0; Pass < 3; Pass++)
	{
	CONST UINT32 UseFlags = (Pass == 0) ? 0u
	                      : (Pass == 1) ? NXC_HOOK_FLAG_LOG
	                                    : (NXC_HOOK_FLAG_LOG | NXC_HOOK_FLAG_LBR);

	/*
	 * Pass 2 needs a ring to write into and LBR actually recording, and it must leave neither behind.
	 * Reserved here rather than by the caller so the test is self-contained: a selftest that depends
	 * on the operator having run two other commands first is a selftest that will be run wrong.
	 */
	UINT32 SnapBefore = 0, SnapDropBefore = 0, SnapSlots = 0;
	if (Pass == 2)
	{
		/* Fill-and-stop: the selftest wants the FIRST snapshots its own victim produces, which is
		 * exactly what the default mode keeps. */
		if (!NT_SUCCESS(NxcLbrSnapInit(8, 0)))
		{
			*OutDetail = NXC_HOOK_ST_NO_SNAP_RING;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		UINT32 ArmedCores = 0, Contended = 0, Unsupported = 0;
		/*
		 * ⚠ ARMED WITH --kernel ON PURPOSE, WHICH IS THE OPPOSITE OF THE NORMAL DEFAULT. The victim
		 * and the hook stub are both RING 0, so a ring-3-only arm -- correct for a real target --
		 * would record none of the branches this test is trying to observe, and the pass would fail
		 * for a reason that has nothing to do with the capture path. Self-polluting is exactly what
		 * is wanted when the thing under test IS our own code.
		 */
		if (!NT_SUCCESS(NxcLbrArm(NXCMD_LBR_ARM_KERNEL, &ArmedCores, &Contended, &Unsupported)) ||
		    ArmedCores == 0)
		{
			(void)NxcLbrSnapFree();
			*OutDetail  = NXC_HOOK_ST_NO_LBR;
			*OutDetail2 = Contended;   /* nonzero = somebody else owns it, which is not our failure */
			return STATUS_DEVICE_BUSY;
		}

		NxcLbrSnapCounters(&SnapBefore, &SnapDropBefore, &SnapSlots, &SnapOverDiscard);
	}

	UINT32 D = 0, StolenBytes = 0;
	INT64  Delta = 0;
	CONST NTSTATUS ISt = NxcHookInstall(Va, UseFlags, 0, &D, &Delta, &StolenBytes);
	if (!NT_SUCCESS(ISt))
	{
		*OutDetail  = NXC_HOOK_ST_INSTALL;
		*OutDetail2 = D;
		HookLog("hook: selftest could not install on its own victim %llX (detail %u, delta %lld)\n",
		        Va, D, Delta);
		return ISt;
	}

	/*
	 * 3. ⚠ THE TEST. The detour is a no-op, so the original answer can only come back if the patched
	 * jump reached the stub, the stub reached the trampoline, the stolen instructions ran correctly
	 * at their NEW address, and the jump back landed exactly at target+N. There is no path to the
	 * right answer that skips any of that.
	 */
	CONST UINT32 Hooked = HookVictim(In);

	UINT32 Got = 0, Total = 0;
	NXC_HOOK_ENTRY Snap[NXC_MAX_HOOKS];
	(void)NxcHookList(Snap, NXC_MAX_HOOKS, &Got, &Total);

	BOOLEAN Listed = FALSE;
	for (UINT32 i = 0; i < Got; i++)
	{
		if (Snap[i].TargetVa == Va) { Listed = TRUE; break; }
	}

	/* 4. Remove FIRST, then judge. Returning early on a wrong answer would leave the patch in. */
	UINT32 RD = 0;
	CONST NTSTATUS RSt = NxcHookRemove(Va, &RD);

	if (Hooked != Expected)
	{
		*OutDetail = NXC_HOOK_ST_WRONG_ANSWER;
		HookLog("hook: selftest got %u, expected %u -- THE DETOUR CHANGED THE RESULT\n",
		        Hooked, Expected);
		return STATUS_UNSUCCESSFUL;
	}
	if (!Listed)
	{
		*OutDetail = NXC_HOOK_ST_NOT_LISTED;
		return STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(RSt))
	{
		*OutDetail  = NXC_HOOK_ST_REMOVE;
		*OutDetail2 = RD;
		return RSt;
	}

	/* 5. And it really is back: both the behaviour and the bytes. */
	if (HookVictim(In) != Expected)
	{
		*OutDetail = NXC_HOOK_ST_AFTER;
		return STATUS_UNSUCCESSFUL;
	}
	if (*(volatile UINT64*)(ULONG_PTR)(Va & ~(UINT64)7) != Before)
	{
		/* Behaviour alone is not enough: the stolen bytes could be restored wrongly and still
		 * happen to compute the same answer for this one input. The bytes are the real check. */
		*OutDetail = NXC_HOOK_ST_NOT_RESTORED;
		return STATUS_UNSUCCESSFUL;
	}

	/*
	 * ⚠ PASS 2'S ACTUAL CHECK: did the hit produce a POPULATED snapshot? Everything above proves the
	 * hook fired; this proves the LBR capture path ran INSIDE it and wrote something real.
	 *
	 * Three conditions, kept separate because each fails differently and one boolean would hide
	 * which: a snapshot was taken at all; it carries entries rather than being the empty record a
	 * snapshot deliberately stores when LBR_CTL.EN is clear; and it is attributed to THIS thread,
	 * which is the property that makes hook-sampled LBR worth having in the first place.
	 */
	if (Pass == 2)
	{
		UINT32 TakenAfter = 0, DroppedAfter = 0, Slots2 = 0;
		NxcLbrSnapCounters(&TakenAfter, &DroppedAfter, &Slots2, &SnapOverDiscard);

		NXCMD_LBR_SNAPSHOT* CONST Snap =
			(NXCMD_LBR_SNAPSHOT*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                     sizeof(NXCMD_LBR_SNAPSHOT), 'tSxN');
		UINT32 SnapGot = 0, SnapTotal = 0, SnapEntries = 0;
		BOOLEAN Populated = FALSE, MineThread = FALSE;

		if (Snap != NULL)
		{
			if (NT_SUCCESS(NxcLbrSnapDrain(Snap, 1, &SnapGot, &SnapTotal)) && SnapGot != 0)
			{
				SnapEntries = Snap->Valid;
				Populated   = (Snap->Valid != 0);
				MineThread  = (Snap->ThreadId == (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId());
			}
			ExFreePoolWithTag(Snap, 'tSxN');
		}

		/* Leave nothing armed and nothing reserved, whichever way the checks go. */
		UINT32 Disarmed = 0;
		(void)NxcLbrDisarm(&Disarmed);
		(void)NxcLbrSnapFree();

		if (TakenAfter <= SnapBefore)
		{
			*OutDetail  = NXC_HOOK_ST_NO_SNAPSHOT;
			*OutDetail2 = DroppedAfter;
			HookLog("hook: selftest pass 2 -- the hook fired but NO SNAPSHOT was taken (%u before, "
			        "%u after, %u dropped). The --lbr flag never reached the hit path.\n",
			        SnapBefore, TakenAfter, DroppedAfter);
			return STATUS_UNSUCCESSFUL;
		}

		if (!Populated)
		{
			*OutDetail  = NXC_HOOK_ST_EMPTY_SNAPSHOT;
			*OutDetail2 = SnapGot;
			HookLog("hook: selftest pass 2 -- a snapshot was taken but is EMPTY. LBR was not "
			        "recording at the moment of the hit.\n");
			return STATUS_UNSUCCESSFUL;
		}

		if (!MineThread)
		{
			/*
			 * ⚠ THE ATTRIBUTION CHECK, and it is the entire point of sampling from a hook. If the
			 * record does not carry the thread that took the hit, a ring cannot be tied to a
			 * process -- and hook-sampled LBR would be worth no more than reading the ring from a
			 * command thread, which LBR's missing CR3 filter already makes useless.
			 */
			*OutDetail = NXC_HOOK_ST_WRONG_THREAD;
			HookLog("hook: selftest pass 2 -- the snapshot is attributed to the WRONG THREAD.\n");
			return STATUS_UNSUCCESSFUL;
		}

		HookLog("hook: selftest pass 2 PASSED -- snapshot on the hitting thread, %u LBR entr(ies)\n",
		        SnapEntries);
	}

	HookLog("hook: selftest pass %u PASSED on %llX (%s, delta %lld)\n",
	        Pass, Va, (UseFlags != 0) ? "LOGGING" : "no-op", Delta);
	}

	/*
	 * The logging pass must have produced exactly one ring entry, and no re-entry. Zero hits with a
	 * passing pass 1 would mean the thunk restored everything correctly and never actually reached
	 * the C handler -- a detour that looks perfect precisely because it does nothing.
	 */
	UINT64 Hits = 0, Reentries = 0;
	UINT64 Filtered = 0;
	NxcHookCounters(&Hits, &Reentries, &Filtered);

	/* THE DELTA, not the total -- see the snapshot above for why the difference is the whole check. */
	CONST UINT64 Gained = (Hits > HitsBefore) ? (Hits - HitsBefore) : 0;
	*OutHits = Gained;

	if (Gained == 0)
	{
		*OutDetail  = NXC_HOOK_ST_NO_HIT;
		*OutDetail2 = 0;
		HookLog("hook: selftest -- the LOGGING pass added no hit (total still %llu). The thunk "
		        "returned cleanly without reaching the handler.\n", Hits);
		return STATUS_UNSUCCESSFUL;
	}

	HookLog("hook: selftest PASSED all three passes on %llX (+%llu hit(s) this run, %llu total, "
	        "%llu refused re-entry)\n", Va, Gained, Hits, Reentries);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcHookList(
	_Out_writes_(Cap) NXC_HOOK_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = gHookCount;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	UINT32 N = 0;
	for (UINT32 i = 0; i < NXC_MAX_HOOKS && N < Cap; i++)
	{
		if (gHooks[i].Active == 0)
			continue;
		Out[N++] = gHooks[i];
	}

	*Got = N;
	return STATUS_SUCCESS;
}
