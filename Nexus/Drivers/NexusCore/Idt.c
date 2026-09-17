/**
 * @file Idt.c
 * @brief Read the IDT and derive the exception dispatcher's candidates. Reasoning in Idt.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <intrin.h>

#include "Idt.h"
#include "hde/hde64.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define IdtLog NxcLogExt

/*
 * The x64 IDT gate descriptor, 16 bytes (SDM Vol 3, 6.14.1). Written out rather than referenced
 * because the handler address is SPLIT ACROSS THREE FIELDS, and reassembling it from the wrong ones
 * yields an address that is well-formed and wrong -- which is the failure this whole file exists to
 * avoid producing.
 */
#pragma pack(push, 1)
typedef struct _NXC_IDT_GATE
{
	UINT16 OffsetLow;
	UINT16 Selector;
	UINT8  Ist;            /* bits 2:0 select an IST stack; the rest must be zero */
	UINT8  Attributes;     /* P, DPL, type                                        */
	UINT16 OffsetMiddle;
	UINT32 OffsetHigh;
	UINT32 Reserved;
} NXC_IDT_GATE;
#pragma pack(pop)

C_ASSERT(sizeof(NXC_IDT_GATE) == 16);

/* The 10-byte operand `sidt` stores: a 2-byte limit followed by the 8-byte base. */
#pragma pack(push, 1)
typedef struct _NXC_IDTR
{
	UINT16 Limit;
	UINT64 Base;
} NXC_IDTR;
#pragma pack(pop)

C_ASSERT(sizeof(NXC_IDTR) == 10);

/**
 * Length of an instruction hde64 cannot decode, or 0 if this is not one of them.
 *
 * ⚠ hde64 IS FROM 2009 AND THE KERNEL IS NOT. Measured on hardware: the probe stopped at
 * exactly the same place on all three vectors, and the bytes it captured were
 *
 *     0F 01 F8   0F AE E8   65 48 8B 24 25 A8 01 00 00
 *     swapgs     lfence     mov rsp, gs:[1A8h]
 *
 * -- the classic kernel trap entry. `0F 01 /r` is opcode group 7, whose REGISTER forms (mod = 11)
 * are the later additions: SWAPGS, RDTSCP, MONITOR, MWAIT, XGETBV, XSETBV. hde64's table treats
 * them as invalid, so the decode died three bytes into every handler's real work and the dispatcher
 * transfer was always past the wall.
 *
 * ⚠ I PREDICTED ENDBR64 AND WAS WRONG. The probe reported the raw bytes precisely so a guess could
 * be contradicted by data, and it was. ENDBR64 is listed here anyway -- this kernel is CET-built, so
 * it will turn up -- but it is listed because it is real, not because it was the theory.
 *
 * ⚠ A FIXED TABLE, NOT A RESYNC. Each entry is an exact byte prefix with a known length. Skipping an
 * unknown byte and hoping is what would let this walk into the middle of an instruction and report
 * jumps that no code contains, which is the failure the .pdata cross-check exists to catch.
 * Patching hde64's tables was the alternative and was rejected: it is vendored third-party code, and
 * a local table states plainly WHICH encodings we handle beyond it.
 */
static UINT32
FixedLengthEscape(
	_In_ CONST UINT8* P,
	_In_ UINT32 Avail
	)
{
	if (Avail >= 4 && P[0] == 0xF3 && P[1] == 0x0F && P[2] == 0x1E && P[3] == 0xFA)
		return 4;    /* endbr64 -- CET; this kernel is built with it */

	if (Avail >= 3 && P[0] == 0x0F && P[1] == 0x01)
	{
		/* Group 7 register forms. mod == 11, so ModRM >= 0xC0. The memory forms (SGDT/SIDT/LGDT/
		 * LIDT/SMSW/LMSW/INVLPG) hde64 already handles, so they are deliberately not claimed here. */
		if (P[2] >= 0xC0)
			return 3;
	}

	if (Avail >= 3 && P[0] == 0x0F && P[1] == 0xAE && P[2] >= 0xC0)
		return 3;    /* lfence / mfence / sfence, the register forms of group 15 */

	if (Avail >= 2 && P[0] == 0x0F && (P[1] == 0x05 || P[1] == 0x07))
		return 2;    /* syscall / sysret */

	/*
	 * ⚠ MOV to/from CONTROL and DEBUG REGISTERS -- `0F 20`/`0F 21`/`0F 22`/`0F 23`, always 3 bytes
	 * (the ModRM's mod field is ignored; the operand is always a register).
	 *
	 * Added after the EFLAGS derivation reported "(not derived)" across three boots. The
	 * exception path does `mov r10, cr8` at ntoskrnl+0x6BFCA5 -- FIVE INSTRUCTIONS before the
	 * `test [rbp+0F8h], 200h` the derivation exists to find. A decode that dies there never reaches
	 * the pattern, and the failure looks identical to "the pattern is not present".
	 */
	if (Avail >= 3 && P[0] == 0x0F && P[1] >= 0x20 && P[1] <= 0x23)
		return 3;

	return 0;
}

/**
 * FixedLengthEscape, but tolerating a REX prefix in front.
 *
 * ⚠ WITHOUT THIS, EVERY ENTRY ABOVE IS UNREACHABLE FOR REX-PREFIXED FORMS. `mov r10, cr8` encodes as
 * `45 0F 20 C2` -- REX.R|REX.B first -- so a table keyed on `P[0] == 0x0F` never matches it. The
 * escapes were written for the un-prefixed spellings and silently did nothing for the prefixed ones,
 * which is the only spelling that appears at the site that mattered.
 */
static UINT32
FixedLengthEscapeRex(
	_In_ CONST UINT8* P,
	_In_ UINT32 Avail
	)
{
	CONST UINT32 Direct = FixedLengthEscape(P, Avail);
	if (Direct != 0)
		return Direct;

	if (Avail >= 2 && P[0] >= 0x40 && P[0] <= 0x4F)
	{
		CONST UINT32 Inner = FixedLengthEscape(P + 1, Avail - 1);
		if (Inner != 0)
			return Inner + 1;
	}

	return 0;
}

NTSTATUS
NxcIdtProbe(
	_In_ UINT32 Vector,
	_In_ UINT64 DirectVa,
	_Out_ NXC_IDT_PROBE* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	if (Vector > 255)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ⚠ THE IDT IS PER-PROCESSOR, so this describes WHICHEVER CORE IS RUNNING THIS CALL. That is
	 * fine for the purpose -- the handler addresses are the same on every core because they are
	 * addresses in ntoskrnl, not per-core state -- but it is a fact and not an assumption, and the
	 * base is reported so a caller comparing two runs can see it change.
	 */
	NXC_IDTR Idtr;
	RtlZeroMemory(&Idtr, sizeof(Idtr));
	__sidt(&Idtr);

	Out->IdtBase  = Idtr.Base;
	Out->IdtLimit = Idtr.Limit;
	Out->Vector   = (UINT16)Vector;

	if (DirectVa != 0)
	{
		/*
		 * Following a chain, not reading a gate. The IDTR is still reported because it costs nothing
		 * and identifies which core answered -- the table is per-processor.
		 */
		Out->HandlerVa = DirectVa;
	}
	else
	{
		if (Idtr.Base == 0)
			return STATUS_UNSUCCESSFUL;

		/* Limit is the LAST valid byte, so the table holds (Limit + 1) / 16 gates. */
		CONST UINT32 Gates = ((UINT32)Idtr.Limit + 1u) / (UINT32)sizeof(NXC_IDT_GATE);
		if (Vector >= Gates)
			return STATUS_INVALID_PARAMETER;

		CONST NXC_IDT_GATE* CONST G =
			(CONST NXC_IDT_GATE*)(ULONG_PTR)(Idtr.Base + (UINT64)Vector * sizeof(NXC_IDT_GATE));

		if (!MmIsAddressValid((PVOID)(ULONG_PTR)G))
			return STATUS_INVALID_ADDRESS;

		/* Present bit. A gate with P clear has no handler and its offset fields mean nothing. */
		if ((G->Attributes & 0x80u) == 0)
		{
			IdtLog("idt: vector %u is NOT PRESENT\n", Vector);
			return STATUS_NOT_FOUND;
		}

		Out->HandlerVa = (UINT64)G->OffsetLow
		               | ((UINT64)G->OffsetMiddle << 16)
		               | ((UINT64)G->OffsetHigh   << 32);
	}

	if (Out->HandlerVa == 0 || !MmIsAddressValid((PVOID)(ULONG_PTR)Out->HandlerVa))
		return STATUS_INVALID_ADDRESS;

	/* ⚠ KERNEL VAs ONLY, even on the direct path. A caller-supplied address is only ever one this
	 * probe already derived, but the bound is cheap and keeps a usermode VA from being decoded in
	 * whatever process happens to be current. */
	if (Out->HandlerVa < 0xFFFF800000000000ULL)
		return STATUS_INVALID_ADDRESS;

	/*
	 * ⚠ .pdata GIVES THE EXACT BOUNDS, WITH NO SYMBOLS AND NO GUESSING WHERE THE FUNCTION ENDS.
	 * Decoding "forward a bit and hope" would run off the end into the next function and report its
	 * calls as this one's -- addresses that are real, from a function nobody asked about.
	 */
	ULONG64 ImageBase = 0;
	CONST NXC_RUNTIME_FUNCTION* CONST Rf =
		(CONST NXC_RUNTIME_FUNCTION*)RtlLookupFunctionEntry(Out->HandlerVa, &ImageBase, NULL);
	if (Rf == NULL || ImageBase == 0)
	{
		IdtLog("idt: vector %u handler %llX has NO .pdata entry -- a leaf, or not in an image\n",
		       Vector, Out->HandlerVa);
		return STATUS_NOT_FOUND;
	}

	Out->HandlerBegin = (UINT64)ImageBase + Rf->BeginAddress;
	Out->HandlerEnd   = (UINT64)ImageBase + Rf->EndAddress;

	if (Out->HandlerEnd <= Out->HandlerBegin)
		return STATUS_UNSUCCESSFUL;

	CONST UINT32 Len = (UINT32)(Out->HandlerEnd - Out->HandlerBegin);
	CONST UINT8* CONST Body = (CONST UINT8*)(ULONG_PTR)Out->HandlerBegin;

	/*
	 * Decode the body and collect DIRECT transfers -- both `call rel32` AND `jmp rel32`.
	 *
	 * ⚠ THE TAIL JUMP IS THE ONE THAT MATTERS, AND THE FIRST VERSION MISSED IT ENTIRELY. Collecting
	 * only E8 found ZERO targets on all three probed vectors on hardware, which read as "the handler
	 * makes no direct calls" when the truth is that a trap handler does not CALL the dispatcher. By
	 * the time the entry stub finishes, the trap frame is already built and the stack is arranged for
	 * the dispatcher to return through -- so the transfer is a JMP, not a call. Looking only for
	 * calls made the single most important edge in the function invisible by construction.
	 *
	 * Indirect transfers are still skipped: `call [reg]` names no target in the instruction, so
	 * reporting anything for it would be invention rather than derivation.
	 */
	UINT32 At = 0;
	while (At < Len)
	{
		/*
		 * ⚠⚠ DO NOT STOP DECODING WHEN THE TABLE FILLS -- KEEP COUNTING.
		 *
		 * This used to `break`, and that clipped the number the dispatcher derivation
		 * RANKS ON. KiDispatchException scored 15 against an offline-measured 28: the table filled
		 * at 16 and the decode stopped, so 15 was a FLOOR reported as if it were a count.
		 *
		 * It happened to still win, which is the dangerous part. Two candidates that both saturate
		 * would tie at 15, and the spec's tie-check would REFUSE a resolution that is perfectly
		 * decidable -- a correct-looking failure on a build nobody has seen, with nothing in the
		 * output hinting the scores were truncated rather than equal.
		 *
		 * Storing is still capped (the wire struct is fixed), but ExternalStarts counts every
		 * qualifying transfer to the end of the function, so the RANK is never clipped even when
		 * the LIST is. StopReason 2 still marks the list as partial, because it is.
		 */
		CONST BOOLEAN TableFull = (Out->TargetCount >= NXC_IDT_MAX_TARGETS);
		if (TableFull && Out->StopReason == 0)
		{
			Out->StopReason = 2;
			Out->StopOffset = At;
		}

		if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + At)))
		{
			Out->StopReason = 3;
			Out->StopOffset = At;
			break;
		}

		/* Try the escape table BEFORE hde64, because these are exactly the encodings it reports as
		 * errors -- asking it first and only then falling back would mean interpreting its error as
		 * "unknown" when it is really "newer than the decoder". */
		CONST UINT32 Escape = FixedLengthEscape(Body + At, Len - At);
		if (Escape != 0)
		{
			At += Escape;
			continue;
		}

		hde64s Hs;
		CONST unsigned Ilen = hde64_disasm(Body + At, &Hs);
		if (Ilen == 0 || (Hs.flags & F_ERROR) != 0)
		{
			/*
			 * ⚠ CAPTURE WHAT WAS ACTUALLY THERE. "The decode stopped" is not a finding; the bytes
			 * are. An encoding this decoder does not know (hde64 predates CET, so `endbr64` and
			 * friends are candidates) is identifiable from the bytes and from nothing else.
			 */
			Out->StopReason = 1;
			Out->StopOffset = At;
			for (UINT32 i = 0; i < 16 && (At + i) < Len; i++)
			{
				if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + At + i)))
					break;
				Out->StopBytes[i] = Body[At + i];
			}
			break;
		}

		CONST BOOLEAN IsCall = (Body[At] == 0xE8 && Ilen == 5);
		CONST BOOLEAN IsJump = (Body[At] == 0xE9 && Ilen == 5);

		if (IsCall || IsJump)
		{
			INT32 Rel = 0;
			for (UINT32 i = 0; i < 4; i++)
				Rel |= (INT32)((UINT32)Body[At + 1 + i] << (8u * i));

			CONST UINT64 Target = Out->HandlerBegin + At + 5 + (INT64)Rel;

			/*
			 * ⚠⚠ RSB STUFFING IS NOT A CALL GRAPH EDGE, AND DROPPING IT HERE IS LOAD-BEARING.
			 *
			 * Spectre-v2 return-stack-buffer fill is a dense run of REAL `call` instructions to
			 * targets a few bytes ahead -- a genuine E8 with a genuine rel32, so nothing about the
			 * encoding distinguishes it. Only the tiny forward displacement does.
			 *
			 * Measured on this build: KiExceptionDispatch (RVA 0x6C0100) contains 27 of these
			 * against 10 real calls. Counting them is what made it look like "1281 bytes with 40
			 * calls" in the first structural pass, and that inflated shape is what got it filed as
			 * a dispatcher candidate on the wrong evidence.
			 *
			 * It matters far more now than it did then: the design notes ranks
			 * candidates by TargetCount, so an unfiltered probe does not merely add noise -- it
			 * ranks whichever function has the most RSB fill first and hands back a confident wrong
			 * dispatcher address to be patched into live kernel code. The measured margins the spec
			 * relies on (9 vs 0, then 28 vs 9) only exist against filtered counts.
			 *
			 * Forward-only and < 0x40: a backward call is an ordinary call to an earlier function.
			 */
			if (IsCall && Target > (Out->HandlerBegin + At) &&
			    (Target - (Out->HandlerBegin + At)) < 0x40)
			{
				Out->RsbFiltered++;
				At += Ilen;
				continue;
			}

			/*
			 * Classify FIRST, so the uncapped tally is computed whether or not there is room to
			 * store the entry. This is the value the derivation ranks on.
			 */
			CONST UINT32 IsInternalT =
				(Target >= Out->HandlerBegin && Target < Out->HandlerEnd) ? 1u : 0u;
			UINT32 IsStartT = 0;
			UINT64 FBeginT = 0, FEndT = 0;
			if (MmIsAddressValid((PVOID)(ULONG_PTR)Target))
			{
				ULONG64 TB = 0;
				CONST NXC_RUNTIME_FUNCTION* CONST Tf2 =
					(CONST NXC_RUNTIME_FUNCTION*)RtlLookupFunctionEntry(Target, &TB, NULL);
				if (Tf2 != NULL && TB != 0)
				{
					FBeginT  = (UINT64)TB + Tf2->BeginAddress;
					FEndT    = (UINT64)TB + Tf2->EndAddress;
					IsStartT = (FBeginT == Target) ? 1u : 0u;
				}
			}
			if (IsStartT && !IsInternalT)
				Out->ExternalStarts++;

			if (TableFull)
			{
				At += Ilen;
				continue;               /* counted above; there is simply nowhere to put it */
			}

			NXC_IDT_TARGET* CONST T = &Out->Targets[Out->TargetCount];
			T->Va         = Target;
			T->CallSite   = At;
			T->IsTailJump = IsJump ? 1u : 0u;
			T->IsInternal = IsInternalT;
			T->FuncBegin  = FBeginT;
			T->FuncEnd    = FEndT;
			/*
			 * ⚠ THE CHECK THAT TURNS A PLAUSIBLE ADDRESS INTO A CHECKABLE ONE, computed above with
			 * the uncapped tally so both use ONE expression. A call whose target is not the START
			 * of a .pdata function means this scan drifted into the middle of an instruction, or
			 * the bounds were wrong -- so the derivation reports itself broken instead of handing
			 * back something well-formed and wrong.
			 */
			T->IsFunctionStart = IsStartT;

			Out->TargetCount++;
		}

		At += Ilen;
	}

	if (Out->StopReason == 0 && At >= Len)
		Out->StopOffset = At;   /* reached the end of the function cleanly */

	Out->DecodedBytes = At;

	/*
	 * ============================================================================================
	 * ⚠ THE SCAN. Covers the WHOLE function regardless of where the linear decode gave up.
	 * ============================================================================================
	 *
	 * The linear decode is precise but fragile, and hardware has now shown it failing twice for the
	 * same reason: hde64 is a 2009 length decoder and this kernel is not. Round one it stopped at
	 * SWAPGS (`0F 01 F8`). Round two, with that handled, it stopped at `F3 0F 01 E8` / `F3 0F 01 29`
	 * / `F3 48 0F 1E CA` -- SETSSBSY, RSTORSSP, RDSSPQ: CET shadow-stack management, which is present
	 * precisely because CR4.CET is set on this machine. Each round cost a reboot to discover one more
	 * encoding, and there is no reason to believe the third round would be the last.
	 *
	 * ⚠ THE LENGTH DECODER WAS NEVER LOAD-BEARING FOR THIS QUESTION. What is needed is "which
	 * addresses does this handler transfer to", and the .pdata cross-check ALREADY answers whether a
	 * candidate is real. So: scan every byte for E8/E9, compute the target, and keep only the ones
	 * that land exactly on a .pdata function START. A byte that merely happens to be 0xE9 inside some
	 * other instruction produces a target that is not a function start and is discarded -- the
	 * validation is not a tidy-up, it is what makes an unaligned scan sound.
	 *
	 * That inverts the dependency in the right direction: the decode is a precision aid, and the
	 * cross-check is the thing being relied on. It was validated at 17/17 offline before any of this
	 * ran, which is why it can carry the weight.
	 *
	 * Targets already found by the linear decode are not duplicated; the scan fills in what the
	 * decoder could not reach.
	 */
	for (UINT32 Scan = 0; Scan + 5 <= Len && Out->TargetCount < NXC_IDT_MAX_TARGETS; Scan++)
	{
		if (Body[Scan] != 0xE8 && Body[Scan] != 0xE9)
			continue;

		if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + Scan + 4)))
			break;

		INT32 Rel = 0;
		for (UINT32 i = 0; i < 4; i++)
			Rel |= (INT32)((UINT32)Body[Scan + 1 + i] << (8u * i));

		CONST UINT64 Target = Out->HandlerBegin + Scan + 5 + (INT64)Rel;

		if (!MmIsAddressValid((PVOID)(ULONG_PTR)Target))
			continue;

		/* ⚠ THE FILTER THAT MAKES AN UNALIGNED SCAN SOUND. Only exact .pdata function starts
		 * survive; anything else is a coincidental 0xE8/0xE9 byte inside another instruction. */
		ULONG64 SBase = 0;
		CONST NXC_RUNTIME_FUNCTION* CONST Sf =
			(CONST NXC_RUNTIME_FUNCTION*)RtlLookupFunctionEntry(Target, &SBase, NULL);
		if (Sf == NULL || SBase == 0)
			continue;

		CONST UINT64 FBegin = (UINT64)SBase + Sf->BeginAddress;
		if (FBegin != Target)
			continue;

		/* Skip anything inside our own function -- an internal branch says nothing about transfers,
		 * and the linear decode already reports those it saw.
		 *
		 * ⚠ THIS ALSO COVERS RSB STUFFING, so the explicit < 0x40 filter the linear decode needs is
		 * deliberately absent here rather than forgotten: the fill calls target the next few bytes
		 * of THIS function, so they are internal by construction and are dropped above. Do not
		 * "restore symmetry" by adding one -- and do not remove this check thinking the RSB filter
		 * upstream already handled it, because the two paths reject on different grounds. */
		if (Target >= Out->HandlerBegin && Target < Out->HandlerEnd)
			continue;

		BOOLEAN Dup = FALSE;
		for (UINT32 i = 0; i < Out->TargetCount; i++)
		{
			if (Out->Targets[i].Va == Target) { Dup = TRUE; break; }
		}
		if (Dup)
			continue;

		NXC_IDT_TARGET* CONST T = &Out->Targets[Out->TargetCount];
		T->Va              = Target;
		T->CallSite        = Scan;
		T->IsTailJump      = (Body[Scan] == 0xE9) ? 1u : 0u;
		T->FuncBegin       = FBegin;
		T->FuncEnd         = (UINT64)SBase + Sf->EndAddress;
		T->IsFunctionStart = 1u;
		T->IsInternal      = 0u;
		T->FoundByScan     = 1u;
		Out->TargetCount++;

		/*
		 * ⚠⚠ COUNT IT HERE TOO. Every target this loop stores is by construction external and a
		 * .pdata function start -- the two `continue`s above guarantee exactly that -- so it is
		 * precisely what ExternalStarts measures.
		 *
		 * OMITTING THIS BROKE THE DERIVATION IMMEDIATELY. ExternalStarts was added to
		 * the linear decode only; vector 1's handler decodes ~132 of its 424 bytes before stalling,
		 * so this scan is where its transfers actually come from. Its score read 0, the caller's
		 * `> 0` guard skipped expanding it, its depth-2 set fell 9 -> 5, the three-vector
		 * intersection went to EMPTY, and `bp dispatch install` refused. Vectors 3 and 14 were
		 * untouched at 13 and 27, which is what identified the path.
		 *
		 * The irony is on the record: the comment 40 lines up warns that these two paths reject on
		 * different grounds and must be maintained as two. A counter added to one of them is the
		 * same defect in the other direction. If a value summarises this function, BOTH paths
		 * update it, or neither does.
		 */
		Out->ExternalStarts++;
	}

	IdtLog("idt: vector %u -> %llX [%llX..%llX], decoded %u of %u bytes, %u direct call(s)\n",
	       Vector, Out->HandlerVa, Out->HandlerBegin, Out->HandlerEnd, At, Len, Out->TargetCount);
	return STATUS_SUCCESS;
}

BOOLEAN
NxcIdtIsGateHandler(
	_In_ UINT64 Va,
	_Out_opt_ UINT32* OutVector
	)
{
	if (OutVector != NULL)
		*OutVector = 0;

	if (Va == 0)
		return FALSE;

	NXC_IDTR Idtr;
	RtlZeroMemory(&Idtr, sizeof(Idtr));
	__sidt(&Idtr);

	if (Idtr.Base == 0)
	{
		/*
		 * ⚠ FAIL CLOSED. If the table cannot be read, "is this an ISR entry?" is UNANSWERED, not
		 * answered no -- and the caller uses this to decide whether patching would bugcheck the
		 * machine. Reporting TRUE refuses a hook that might have been fine; reporting FALSE permits
		 * one that takes the box down.
		 */
		return TRUE;
	}

	CONST UINT32 Gates = ((UINT32)Idtr.Limit + 1u) / (UINT32)sizeof(NXC_IDT_GATE);

	for (UINT32 v = 0; v < Gates && v < 256u; v++)
	{
		CONST NXC_IDT_GATE* CONST G =
			(CONST NXC_IDT_GATE*)(ULONG_PTR)(Idtr.Base + (UINT64)v * sizeof(NXC_IDT_GATE));

		if (!MmIsAddressValid((PVOID)(ULONG_PTR)G))
			continue;
		if ((G->Attributes & 0x80u) == 0)
			continue;   /* not present -- its offset fields mean nothing */

		CONST UINT64 Handler = (UINT64)G->OffsetLow
		                     | ((UINT64)G->OffsetMiddle << 16)
		                     | ((UINT64)G->OffsetHigh   << 32);

		if (Handler == Va)
		{
			if (OutVector != NULL)
				*OutVector = v;
			return TRUE;
		}
	}

	return FALSE;
}

/* ================================================================================================
 * KTRAP_FRAME.EFlags, DERIVED FROM ntoskrnl's OWN CODE.
 * ============================================================================================= */

NTSTATUS
NxcIdtDeriveEflagsOffset(
	_In_ UINT64 FunnelVa,
	_Out_ UINT32* OutOffset,
	_Out_ UINT32* OutSites
	)
{
	*OutOffset = 0;
	*OutSites  = 0;

	/*
	 * ⚠⚠ WHY THIS IS A DERIVATION AND NOT A PINNED OFFSET.
	 *
	 * Item 14 needs EXECUTE breakpoints, and resuming one without setting EFLAGS.RF re-enters the
	 * same instruction forever. RF lives in the target's KTRAP_FRAME, whose layout is unexported and
	 * changes between builds -- pinning it is exactly what this project bans, and a wrong offset
	 * writes a flag into the middle of somebody else's saved register state on the exception path.
	 *
	 * But ntoskrnl STATES the offset itself. The stack-switch wrapper on the exception path decides
	 * whether to re-enable interrupts by testing EFLAGS.IF in the trap frame it was handed:
	 *
	 *     test dword ptr [rbp + 0xF8], 0x200        F7 85 F8 00 00 00  00 02 00 00
	 *
	 * 0x200 is bit 9, IF, and it can only be tested against the saved EFLAGS. So the displacement IS
	 * KTRAP_FRAME.EFlags, read out of the binary on the machine we are running on. Decoding one
	 * instruction whose meaning is unambiguous is not pinning; it is the same move that located the
	 * dispatcher from IDT gates.
	 *
	 * ⚠ THE FUNNEL IS THE ANCHOR, not a hardcoded RVA. KiExceptionDispatch is already derived from
	 * the live IDT (the design notes), and the wrapper is one of its direct
	 * callees -- so this walks from a fact rather than from a constant.
	 *
	 * ⚠⚠ AND THAT REASONING IS RIGHT ABOUT THE BIT AND WRONG ABOUT THE BASE. measured
	 * against this machine's own ntoskrnl with `tools/ntos_eflags_offset.py`, BEFORE this shipped.
	 * The real site on the exception path is:
	 *
	 *     mov  r9b, [rbp+0F0h]                 ; SegCs low byte -> PreviousMode
	 *     and  r9b, 1
	 *     lea  r8,  [rbp-80h]                  ; arg3 of KiDispatchException: THE TRAP FRAME
	 *     test dword ptr [rbp+0F8h], 200h      ; the EFLAGS.IF test
	 *
	 * The frame pointer is BIASED: TrapFrame = rbp - 0x80. So the field is at 0x80 + 0xF8 = +0x178,
	 * and the raw displacement 0xF8 is KTRAP_FRAME.**Dr6**. Returning it would have written EFLAGS.RF
	 * into the saved debug-status register of a live trap frame on every resumed execute breakpoint.
	 * (`lea rbp,[rsp+80h]` appears at 43 sites in this image -- the idiom is routine, not exotic.)
	 *
	 * ⚠ SO THIS RECOVERS THE BIAS, AND REFUSES WHEN IT CANNOT. It looks for the `lea <reg>, [rbp-B]`
	 * that forms the trap-frame pointer in the same function and adds B back. A site whose base
	 * cannot be established is DISCARDED, never assumed to be zero -- assuming zero is the failure
	 * above, and a derivation that silently falls back to it is worse than one that finds nothing.
	 *
	 * ⚠ AND IT IS ONLY A CROSS-CHECK NOW. The offset actually written to is derived from LIVE TRAP
	 * FRAMES (BpDispatch.c, BpdDeriveEflags) by matching the faulting RIP against the architectural
	 * IRET tail. Two INDEPENDENT methods which must agree; this one is not trusted alone again.
	 */
	NXC_IDT_PROBE Probe;
	CONST NTSTATUS PSt = NxcIdtProbe(0, FunnelVa, &Probe);
	if (!NT_SUCCESS(PSt))
		return PSt;

	UINT32  FirstOffset = 0, Agreeing = 0, Disagreeing = 0;
	/* Functions whose decode hit an encoding hde64 cannot read. Counted and REPORTED, never absorbed:
	 * a scan that stopped early and a pattern that is absent are DIFFERENT ANSWERS. */
	UINT32  Aborted = 0;
	/* Set when the SegCs/PreviousMode byte read is found one slot below the EFlags site, off the
	 * SAME base register -- a SECOND field identified by a DIFFERENT idiom, agreeing on one layout. */
	BOOLEAN CsCorroborated = FALSE;

	/*
	 * ⚠⚠ THE FUNNEL'S OWN BODY IS SCANNED FIRST, AND OMITTING IT IS WHY THIS ORACLE NEVER FIRED.
	 *
	 * measured with the corrected build actually deployed: the EFLAGS.IF test is at
	 * ntoskrnl+0x6BFCB0, inside the function 0x6BFC00..0x6C0101 -- which is the FUNNEL'S OWN
	 * function. This loop only ever walked TRANSFER TARGETS, so it never looked at the function it
	 * started from, and reported "(not derived)" on every boot. The corroboration added in D70 was
	 * scanning regions that do not contain the pattern.
	 *
	 * ⚠ AND THE SIZE CAP REJECTED IT BY ONE BYTE. `(End - Begin) > 0x400` carried the justification
	 * "the wrapper is tens of bytes; a huge function is not it" -- an assumption never measured. The
	 * real function is 0x501 bytes. Raised to 0x2000 and re-justified: the bound exists only to stop
	 * an unbounded decode, not to express a belief about how large the right function is. A guess
	 * about size had veto power over a measurement, which is backwards.
	 *
	 * Index t == TargetCount means "the funnel itself"; below that, its transfer targets.
	 */
	for (UINT32 t = 0; t <= Probe.TargetCount; t++)
	{
		UINT64 Begin, End;

		if (t == Probe.TargetCount)
		{
			Begin = Probe.HandlerBegin;
			End   = Probe.HandlerEnd;
		}
		else
		{
			if (Probe.Targets[t].IsFunctionStart == 0 || Probe.Targets[t].IsInternal != 0)
				continue;

			Begin = Probe.Targets[t].FuncBegin;
			End   = Probe.Targets[t].FuncEnd;
		}

		/* A bound against an unbounded decode -- NOT a claim about the right function's size. */
		if (Begin == 0 || End <= Begin || (End - Begin) > 0x2000)
			continue;

		CONST UINT8* CONST Body = (CONST UINT8*)(ULONG_PTR)Begin;
		CONST UINT32 Len = (UINT32)(End - Begin);

		/*
		 * ⚠ FIRST PASS: RECOVER THE FRAME-POINTER BIAS, because without it the displacement found
		 * below means nothing. The trap-frame pointer is formed as `lea <reg>, [rbp - B]` and handed
		 * to KiDispatchException as arg3, so rbp = TrapFrame + B and a displacement D off rbp is the
		 * field at D + B.
		 *
		 * REX.W 8D /r with mod=01 and rm=101 is `lea r64, [rbp+disp8]`; the disp8 is NEGATIVE for the
		 * bias form. Only one distinct bias may be present -- two different ones in a single function
		 * means the base cannot be attributed to a specific `test`, and the whole function is skipped
		 * rather than resolved by picking one.
		 */
		UINT32  Bias      = 0;
		BOOLEAN BiasFound = FALSE;
		BOOLEAN BiasAmbig = FALSE;
		for (UINT32 B = 0; B + 4 <= Len; B++)
		{
			if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + B)))
				break;

			/* 48/4C 8D <modrm> -- REX.W (optionally REX.R for r8-r15) then LEA. */
			if ((Body[B] != 0x48 && Body[B] != 0x4C) || Body[B + 1] != 0x8D)
				continue;

			CONST UINT8 Modrm = Body[B + 2];
			if ((Modrm >> 6) != 1u || (Modrm & 7u) != 5u)
				continue;   /* need [rbp + disp8] exactly */

			CONST INT32 Disp8 = (INT32)(INT8)Body[B + 3];
			if (Disp8 >= 0)
				continue;   /* the bias form subtracts; a positive disp is some other addressing */

			CONST UINT32 Candidate = (UINT32)(-Disp8);
			if (!BiasFound)
			{
				Bias = Candidate;
				BiasFound = TRUE;
			}
			else if (Bias != Candidate)
			{
				BiasAmbig = TRUE;
			}
		}

		if (!BiasFound || BiasAmbig)
		{
			/* ⚠ NOT "assume zero". A function whose base cannot be established contributes NOTHING;
			 * counting it with an unproven base is how 0xF8 nearly became the answer. */
			continue;
		}

		UINT32 At = 0;
		while (At + 4 < Len)
		{
			if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + At)))
				break;

			hde64s Hs;
			CONST unsigned ILen = hde64_disasm(Body + At, &Hs);
			if (ILen == 0 || (Hs.flags & F_ERROR) != 0)
			{
				/*
				 * ⚠⚠ hde64 IS FROM 2009 AND THIS FUNCTION IS NOT. The probe loop 400 lines up has
				 * handled that since it was written; THIS loop just `break`ed, and the difference
				 * cost three boots of "(not derived)".
				 *
				 * The exception path does `mov r10, cr8` (`45 0F 20 C2`) at ntoskrnl+0x6BFCA5 --
				 * FIVE INSTRUCTIONS before the `test [rbp+0F8h], 200h` this function exists to find.
				 * The decode died there and returned "no sites", which is indistinguishable from
				 * "the pattern is not present". A silent break turned a decoder limitation into a
				 * false statement about the kernel.
				 */
				CONST UINT32 Escape = FixedLengthEscapeRex(Body + At, Len - At);
				if (Escape != 0)
				{
					At += Escape;
					continue;
				}

				/*
				 * ⚠ AND AN ABORT IS REPORTED, NEVER ABSORBED. Returning silently here is what made
				 * the last three readings unfalsifiable: "(not derived)" meant both "scanned and
				 * absent" and "never scanned". The bytes go in the log so the NEXT unknown encoding
				 * is a five-minute fix rather than another round of hardware guessing.
				 */
				Aborted++;
				IdtLog("idt: EFlags scan ABORTED in %llX at +0x%X -- undecodable %02X %02X %02X %02X. "
				       "NOT the same as 'pattern absent'.\n",
				       Begin, At, Body[At],
				       (At + 1 < Len) ? Body[At + 1] : 0,
				       (At + 2 < Len) ? Body[At + 2] : 0,
				       (At + 3 < Len) ? Body[At + 3] : 0);
				break;
			}

			/*
			 * TEST r/m32, imm32 is opcode 0xF7 with ModRM.reg == 0. The immediate must be exactly
			 * 0x200 -- EFLAGS.IF -- and the operand must be memory (mod != 3), because a test
			 * against a REGISTER says nothing about a structure offset.
			 */
			if (Body[At] == 0xF7 && Hs.modrm_reg == 0 && Hs.modrm_mod != 3 &&
			    Hs.imm.imm32 == 0x200u)
			{
				CONST UINT32 Raw = (Hs.modrm_mod == 1) ? (UINT32)Hs.disp.disp8 : Hs.disp.disp32;

				/*
				 * ⚠ THE BIAS IS ADDED HERE, AND THIS IS THE WHOLE FIX. `Raw` is measured from the
				 * BIASED frame pointer; the structure offset is Raw + Bias. On this build that is
				 * 0xF8 + 0x80 = 0x178, KTRAP_FRAME.EFlags. Using Raw alone yields 0xF8 -- Dr6.
				 *
				 * ⚠ AND THE TEST MUST BE AGAINST rbp. A `test [rcx+D], 0x200` in the same function is
				 * about some other structure entirely, and the bias recovered above does not apply to
				 * it. mod!=3 was already required; requiring rm==5 (and no SIB) makes the base rbp.
				 */
				if ((Hs.modrm_rm & 7u) != 5u)
				{
					At += ILen;
					continue;
				}

				CONST UINT32 Disp = Raw + Bias;

				/* A trap frame is roughly 0x190 bytes; EFlags is nowhere near either end. A
				 * displacement outside that is a coincidental match, not the field. */
				if (Disp >= 0x40 && Disp <= 0x180)
				{
					if (Agreeing == 0)
					{
						FirstOffset = Disp;
						Agreeing = 1;

						/*
						 * ⚠ LOOK FOR THE SegCs BYTE READ AT (this displacement - 8), OFF THE SAME BASE.
						 * `mov r8b/r9b, [rbp+disp32]` is REX(.R) + 8A /r with mod=10, rm=101 -- the
						 * exception path reads the saved CS's low byte and masks bit 0 to get
						 * PreviousMode. SegCs sits ONE SLOT BELOW EFlags in the architectural IRET
						 * tail, so finding it there identifies a SECOND field by a DIFFERENT idiom --
						 * real corroboration, unlike two copies of the same `test` which only prove
						 * the compiler emitted one access twice.
						 *
						 * Searched across the whole function rather than adjacently: the two accesses
						 * need not neighbour each other, and requiring that would make this depend on
						 * instruction scheduling.
						 */
						CONST UINT32 WantDisp = Raw - 8u;
						for (UINT32 c = 0; c + 7 <= Len; c++)
						{
							if (!MmIsAddressValid((PVOID)(ULONG_PTR)(Body + c)))
								break;
						
							if ((Body[c] != 0x44 && Body[c] != 0x45 &&
							     Body[c] != 0x40 && Body[c] != 0x41) ||
							    Body[c + 1] != 0x8A)
								continue;
						
							CONST UINT8 M = Body[c + 2];
							if ((M >> 6) != 2u || (M & 7u) != 5u)
								continue;   /* need [rbp + disp32] */
						
							UINT32 D2 = 0;
							for (UINT32 b = 0; b < 4; b++)
								D2 |= ((UINT32)Body[c + 3 + b]) << (8u * b);
						
							if (D2 == WantDisp)
							{
								CsCorroborated = TRUE;
								break;
							}
						}
					}
					else if (Disp == FirstOffset)
					{
						Agreeing++;
					}
					else
					{
						Disagreeing++;
					}
				}
			}

			At += ILen;
		}
	}

	if (Disagreeing != 0)
	{
		IdtLog("idt: EFlags offset DISAGREEMENT -- %u site(s) said 0x%X and %u said otherwise. "
		       "REFUSING; a contested offset is worse than none.\n",
		       Agreeing, FirstOffset, Disagreeing);
		return STATUS_UNSUCCESSFUL;
	}

	*OutOffset = FirstOffset;
	*OutSites  = Agreeing;

	/*
	 * ⚠⚠ "TWO SITES" WAS THE WRONG CORROBORATION, AND IT MADE THIS ORACLE INERT. Measured on hardware
	 * exactly ONE qualifying site exists, so the >=2 rule returned STATUS_NOT_FOUND and
	 * the cross-check reported "(not derived)" — a guard that never fires, which is worth nothing.
	 *
	 * ⚠ AND TWO COPIES OF THE SAME TEST WOULD HAVE BEEN WEAK CORROBORATION ANYWAY. Two
	 * `test [rbp+D], 0x200` sites agreeing proves the compiler emitted the same access twice; it does
	 * NOT independently establish that the field is EFlags, because both readings rest on the same
	 * inference about the same instruction shape.
	 *
	 * ⚠ SO THE CORROBORATION IS A DIFFERENT FIELD ENTIRELY. The exception path derives PreviousMode
	 * from the saved CS by reading its low byte and masking the ring bit:
	 *
	 *     mov  r9b, [rbp+0F0h]     ; SegCs low byte
	 *     and  r9b, 1              ; ring -> PreviousMode
	 *
	 * `SegCs` sits ONE SLOT BELOW `EFlags` in the architectural IRET tail, so if this byte read
	 * appears at exactly (EFlags displacement - 8) off the SAME base, two DIFFERENT fields identified
	 * by two DIFFERENT idioms agree on one frame layout. That is genuine independent corroboration,
	 * and it is what the live derivation checks too (CS at tail+8, EFlags at tail+0x10).
	 */
	if (Agreeing >= 1 && CsCorroborated)
	{
		IdtLog("idt: KTRAP_FRAME.EFlags derived at +0x%X -- %u EFLAGS.IF site(s), CORROBORATED by "
		       "the SegCs/PreviousMode read one slot below at the same base.\n",
		       FirstOffset, Agreeing);
		return STATUS_SUCCESS;
	}

	if (Agreeing < 2)
	{
		/*
		 * ⚠ TWO DIFFERENT ANSWERS, AND THEY MUST NOT SHARE A MESSAGE. "Scanned the whole function and
		 * the pattern is absent" is a statement about the KERNEL. "The decode aborted partway" is a
		 * statement about OUR DECODER. One text for both is what made three consecutive readings of
		 * "(not derived)" unfalsifiable, and sent two fixes at the wrong cause.
		 */
		if (Aborted != 0)
			IdtLog("idt: EFlags NOT derived -- %u function(s) hit an UNDECODABLE instruction, so the "
			       "scan never completed. This says NOTHING about whether the pattern is present.\n",
			       Aborted);
		else
			IdtLog("idt: EFlags offset 0x%X found at %u site, NOT corroborated by the SegCs read -- "
			       "the scan COMPLETED, so the pattern really is absent or uncorroborated.\n",
			       FirstOffset, Agreeing);
		return STATUS_NOT_FOUND;
	}

	IdtLog("idt: KTRAP_FRAME.EFlags derived at +0x%X, agreed by %u sites\n", FirstOffset, Agreeing);
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * THE VOLATILE GPRs, DECODED FROM THE TRAP ENTRY. Reasoning and the four gates are in Idt.h.
 * ============================================================================================= */

/* x86-64 register numbers for the seven, in the order the trap entry stores them. Used to map a
 * ModRM.reg (plus REX.R) back to a slot, and to enforce the contiguity check in gate 3. */
static CONST UINT8 gGprRegNum[NXC_GPR_COUNT] = { 0u, 1u, 2u, 8u, 9u, 10u, 11u };

/**
 * The decoder, over a plain byte range so the self-test can drive it with synthetic bytes.
 *
 * ⚠ PURE AND RANGE-BASED ON PURPOSE. A self-test that exercises a reimplementation proves the
 * reimplementation; this is the function the live path calls, driven by different bytes.
 */
static NTSTATUS
IdtDeriveGprsFromBody(
	_In_reads_(Len) CONST UINT8* Body,
	_In_ UINT32 Len,
	_In_ UINT32 ProvenEflags,
	_Out_ NXC_GPR_MAP* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	/* ---- GATE 1: exactly one frame-pointer bias ------------------------------------------- */
	UINT32  Bias = 0;
	BOOLEAN BiasFound = FALSE, BiasAmbiguous = FALSE;

	for (UINT32 i = 0; i + 8 <= Len; i++)
	{
		/* `lea rbp, [rsp + disp]` -- REX.W, 8D, ModRM.reg = rbp(5), rm = 4 (SIB), SIB base = rsp. */
		if (Body[i] != 0x48 || Body[i + 1] != 0x8D)
			continue;
		if (((Body[i + 2] >> 3) & 7u) != 5u || (Body[i + 2] & 7u) != 4u)
			continue;
		if ((Body[i + 3] & 7u) != 4u)
			continue;

		CONST UINT8 Mod = Body[i + 2] >> 6;
		INT32 Disp;
		if (Mod == 1u)      Disp = (INT32)(INT8)Body[i + 4];
		else if (Mod == 2u) Disp = (INT32)(((UINT32)Body[i + 4])       |
		                                   ((UINT32)Body[i + 5] << 8)  |
		                                   ((UINT32)Body[i + 6] << 16) |
		                                   ((UINT32)Body[i + 7] << 24));
		else continue;

		if (Disp <= 0)
			continue;   /* the bias form is rsp PLUS a positive displacement */

		if (!BiasFound) { Bias = (UINT32)Disp; BiasFound = TRUE; }
		else if (Bias != (UINT32)Disp) { BiasAmbiguous = TRUE; }
	}

	if (!BiasFound || BiasAmbiguous)
	{
		Out->Gate = BiasAmbiguous ? NXC_GPR_GATE_BIAS_AMBIG : NXC_GPR_GATE_NO_BIAS;
		IdtLog("idt: GPR derivation REFUSED -- %s frame-pointer bias. No store can be attributed to a "
		       "structure offset without one, and guessing is how 0xF8 nearly became Dr6.\n",
		       BiasAmbiguous ? "AMBIGUOUS" : "NO");
		return STATUS_NOT_FOUND;
	}

	Out->Bias = Bias;

	/* ---- GATE 2: find each register's FIRST rbp-relative 64-bit store ---------------------- */
	BOOLEAN Seen[NXC_GPR_COUNT];
	RtlZeroMemory(Seen, sizeof(Seen));

	for (UINT32 i = 0; i + 4 <= Len; i++)
	{
		CONST UINT8 Rex = Body[i];
		if (Rex < 0x48u || Rex > 0x4Fu)
			continue;
		if (Body[i + 1] != 0x89u)
			continue;               /* MOV r/m64, r64 */

		CONST UINT8 Modrm = Body[i + 2];
		if ((Modrm & 7u) != 5u)
			continue;               /* base must be rbp -- a store off ANY other register says
			                         * nothing about this frame, and the bias does not apply to it */

		CONST UINT8 Mod = Modrm >> 6;
		INT32 Disp;
		if (Mod == 1u)      Disp = (INT32)(INT8)Body[i + 3];
		else if (Mod == 2u)
		{
			if (i + 7 > Len) continue;
			Disp = (INT32)(((UINT32)Body[i + 3])       | ((UINT32)Body[i + 4] << 8) |
			               ((UINT32)Body[i + 5] << 16) | ((UINT32)Body[i + 6] << 24));
		}
		else continue;

		CONST UINT8 Reg = (UINT8)((((Modrm >> 3) & 7u) | ((Rex & 4u) ? 8u : 0u)));

		CONST INT64 Resolved = (INT64)Disp + (INT64)Bias;
		if (Resolved < 0 || Resolved > 0x190)
			continue;               /* outside any plausible trap frame */

		for (UINT32 g = 0; g < NXC_GPR_COUNT; g++)
		{
			if (gGprRegNum[g] != Reg || Seen[g])
				continue;
			/* ⚠ FIRST STORE WINS. rdx is stored TWICE by this prologue -- once as Rdx and again
			 * into the Dr0 slot. Gate 3 independently rejects the second, but taking the first is
			 * what makes the two checks agree rather than fight. */
			Out->Offset[g] = (UINT32)Resolved;
			Seen[g] = TRUE;
			break;
		}
	}

	for (UINT32 g = 0; g < NXC_GPR_COUNT; g++)
	{
		if (!Seen[g])
		{
			Out->Gate = NXC_GPR_GATE_MISSING_REG;
			IdtLog("idt: GPR derivation REFUSED -- register slot %u never stored. A PARTIAL map is "
			       "worse than none: the missing one would read as zero.\n", g);
			return STATUS_NOT_FOUND;
		}
	}

	/* ---- GATE 3: the seven must form a CONTIGUOUS 8-byte run, in order --------------------- */
	for (UINT32 g = 1; g < NXC_GPR_COUNT; g++)
	{
		if (Out->Offset[g] != Out->Offset[g - 1] + 8u)
		{
			Out->Gate = NXC_GPR_GATE_GAP;
			IdtLog("idt: GPR derivation REFUSED -- slot %u at 0x%X does not follow slot %u at 0x%X by "
			       "8. The volatile set is contiguous in KTRAP_FRAME; a gap means a coincidental "
			       "store was attributed.\n", g, Out->Offset[g], g - 1, Out->Offset[g - 1]);
			return STATUS_UNSUCCESSFUL;
		}
	}

	/* ---- GATE 4: this function must re-yield the PROVEN EFlags offset ---------------------- */
	for (UINT32 i = 0; i + 10 <= Len; i++)
	{
		if (Body[i] != 0xF7u)
			continue;
		CONST UINT8 Modrm = Body[i + 1];
		if (((Modrm >> 3) & 7u) != 0u || (Modrm >> 6) == 3u || (Modrm & 7u) != 5u)
			continue;

		CONST UINT8 Mod = Modrm >> 6;
		UINT32 Raw, p;
		if (Mod == 1u)      { Raw = Body[i + 2]; p = i + 3; }
		else if (Mod == 2u) { Raw = ((UINT32)Body[i + 2]) | ((UINT32)Body[i + 3] << 8) |
		                            ((UINT32)Body[i + 4] << 16) | ((UINT32)Body[i + 5] << 24);
		                      p = i + 6; }
		else continue;

		if (p + 4 > Len)
			continue;

		/* Any EFLAGS bit test identifies the field; 0x200 (IF) and 0x100 (TF) both appear here. */
		CONST UINT32 Imm = ((UINT32)Body[p]) | ((UINT32)Body[p + 1] << 8) |
		                   ((UINT32)Body[p + 2] << 16) | ((UINT32)Body[p + 3] << 24);
		if (Imm != 0x200u && Imm != 0x100u)
			continue;

		Out->EflagsSeen = Raw + Bias;
		break;
	}

	if (ProvenEflags != 0u)
	{
		if (Out->EflagsSeen == 0u)
		{
			Out->Gate = NXC_GPR_GATE_NO_EFLAGS;
			IdtLog("idt: GPR derivation REFUSED -- this function yielded no EFLAGS test, so its bias "
			       "0x%X is UNCORROBORATED against the proven offset 0x%X.\n", Bias, ProvenEflags);
			return STATUS_NOT_FOUND;
		}
		if (Out->EflagsSeen != ProvenEflags)
		{
			Out->Gate = NXC_GPR_GATE_EFLAGS_BAD;
			IdtLog("idt: GPR derivation REFUSED -- bias 0x%X puts EFLAGS at 0x%X, but LIVE TRAP FRAMES "
			       "proved 0x%X. A CONTESTED bias is worse than none; not reconciling.\n",
			       Bias, Out->EflagsSeen, ProvenEflags);
			return STATUS_UNSUCCESSFUL;
		}
	}

	Out->Valid = TRUE;
	Out->Gate  = NXC_GPR_GATE_OK;
	IdtLog("idt: volatile GPRs derived -- bias 0x%X, Rax..R11 at 0x%X..0x%X, EFLAGS cross-check 0x%X\n",
	       Bias, Out->Offset[0], Out->Offset[NXC_GPR_COUNT - 1], Out->EflagsSeen);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcIdtDeriveVolatileGprs(
	_In_ UINT32 Vector,
	_In_ UINT32 ProvenEflags,
	_Out_ NXC_GPR_MAP* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	/* The IDT gate gives the handler address EXACTLY; .pdata gives the function it lives in. */
	NXC_IDT_PROBE Probe;
	CONST NTSTATUS PSt = NxcIdtProbe(Vector, 0, &Probe);
	if (!NT_SUCCESS(PSt))
		return PSt;

	if (Probe.HandlerBegin == 0 || Probe.HandlerEnd <= Probe.HandlerBegin)
		return STATUS_NOT_FOUND;

	CONST UINT64 Span = Probe.HandlerEnd - Probe.HandlerBegin;
	if (Span > 0x2000)
		return STATUS_NOT_FOUND;   /* a bound against an unbounded decode, not a belief about size */

	if (!MmIsAddressValid((PVOID)(ULONG_PTR)Probe.HandlerBegin) ||
	    !MmIsAddressValid((PVOID)(ULONG_PTR)(Probe.HandlerEnd - 1)))
		return STATUS_INVALID_ADDRESS;

	NTSTATUS DSt = IdtDeriveGprsFromBody((CONST UINT8*)(ULONG_PTR)Probe.HandlerBegin,
	                                     (UINT32)Span, ProvenEflags, Out);

	/*
	 * ============================================================================================
	 * ⚠⚠ THE GATE HANDLER IS A SHIM ON THIS BUILD, AND THAT IS WHY THIS EXISTS.
	 * ============================================================================================
	 *
	 * measured against the LIVE kernel (10.0.26100.8972 -- the archived snapshot was
	 * 8737 and every anchor had moved). Vector 1's handler is a KVA-shadow shim:
	 *
	 *     push rsi/r11/r10/r9/r8/rcx/rax/rdx ; sub rsp,0x98 ; movaps xmm0-5 ; test [rsp+0xE0],1
	 *
	 * It never establishes a frame pointer, so gate 1 refused with NO_BIAS -- CORRECTLY. The chain is
	 * one level deeper than the derivation assumed:
	 *
	 *     IDT gate 0x6B7580 -> shim -> jmp at +0x147 -> trap entry 0x6B7740, which builds the frame
	 *
	 * ⚠ THE TRANSFER IS READ, NOT GUESSED. 41 functions on this build carry the same frame-building
	 * idiom and are indistinguishable by shape; choosing one by resemblance is exactly what was
	 * falsified THREE TIMES while identifying the dispatcher. So this walks the shim's own transfer
	 * targets and requires EXACTLY ONE of them to satisfy all four gates. Zero refuses. Two or more
	 * refuses -- an ambiguous anchor is worse than none, for the same reason a contested bias is.
	 *
	 * Only attempted when the handler itself failed: a build whose gate handler DOES build the frame
	 * needs no indirection, and trying anyway would risk finding a second qualifying function.
	 */
	if (!NT_SUCCESS(DSt))
	{
		NXC_GPR_MAP Found;
		UINT32 Hits = 0;

		RtlZeroMemory(&Found, sizeof(Found));

		for (UINT32 t = 0; t < Probe.TargetCount; t++)
		{
			if (Probe.Targets[t].IsFunctionStart == 0 || Probe.Targets[t].IsInternal != 0)
				continue;

			CONST UINT64 TB = Probe.Targets[t].FuncBegin;
			CONST UINT64 TE = Probe.Targets[t].FuncEnd;
			if (TB == 0 || TE <= TB || (TE - TB) > 0x2000)
				continue;
			if (!MmIsAddressValid((PVOID)(ULONG_PTR)TB) ||
			    !MmIsAddressValid((PVOID)(ULONG_PTR)(TE - 1)))
				continue;

			NXC_GPR_MAP Try;
			CONST NTSTATUS TSt = IdtDeriveGprsFromBody((CONST UINT8*)(ULONG_PTR)TB,
			                                           (UINT32)(TE - TB), ProvenEflags, &Try);
			if (NT_SUCCESS(TSt) && Try.Valid)
			{
				Hits++;
				if (Hits == 1)
				{
					Found = Try;
					Found.Begin = TB;
				}
			}
		}

		if (Hits == 1)
		{
			IdtLog("idt: gate handler is a SHIM -- followed its transfer to the trap entry at %llX\n",
			       Found.Begin);
			*Out = Found;
			DSt  = STATUS_SUCCESS;
		}
		else if (Hits > 1)
		{
			IdtLog("idt: GPR derivation REFUSED -- %u transfer targets of the gate handler each build "
			       "a frame. An AMBIGUOUS anchor is worse than none; not choosing by shape.\n", Hits);
			Out->Gate = NXC_GPR_GATE_BIAS_AMBIG;
			DSt = STATUS_UNSUCCESSFUL;
		}
		/* Hits == 0: keep the handler's own refusal and its gate, which already names the reason. */
	}

	/*
	 * ⚠ RECORDED AFTER the decode, because IdtDeriveGprsFromBody zeroes Out on entry. These say WHAT
	 * WAS ACTUALLY DECODED -- the address and its first 16 bytes -- so "the live binary differs from
	 * my offline copy" and "the bounds are not the function I think they are" stop being competing
	 * stories and become a byte comparison.
	 */
	/*
	 * ⚠ REPORT THE FUNCTION ACTUALLY DECODED, WHICH IS NOT ALWAYS THE HANDLER. When the shim-follow
	 * above succeeded, Out->Begin already holds the TRAP ENTRY; unconditionally storing
	 * Probe.HandlerBegin here would discard exactly the address the follow was written to find, and
	 * the byte dump would then describe the shim while the decode described something else. Caught
	 * while writing it -- the assignment was already below the new block.
	 */
	if (Out->Begin == 0)
		Out->Begin = Probe.HandlerBegin;

	if (MmIsAddressValid((PVOID)(ULONG_PTR)Out->Begin))
	{
		Out->First[0] = *(CONST volatile UINT64*)(ULONG_PTR)Out->Begin;
		Out->First[1] = *(CONST volatile UINT64*)(ULONG_PTR)(Out->Begin + 8);
	}

	return DSt;
}

/* ================================================================================================
 * THE GPR SELF-TEST -- built from the cases that must FAIL.
 *
 * ⚠ A TIDY PROLOGUE PASSES AGAINST A DERIVATION THAT CHECKS NOTHING, so a suite of tidy prologues
 * measures nothing. Each fixture below removes exactly one of the four gates' preconditions, so a
 * gate that stops working takes a case with it instead of going quietly.
 * ============================================================================================= */

/* Byte builders, so a fixture reads as the instruction it is rather than as a hex blob. */
/*
 * ⚠⚠ disp32, NOT disp8, AND THE SELF-TEST CAUGHT ME GETTING THIS WRONG.
 *
 * `lea rbp, [rsp+0x80]` CANNOT be encoded with an 8-bit displacement: 0x80 as a signed byte is
 * -128. The first cut emitted `mod=01, disp8=0x80`, so the derivation read a NEGATIVE bias,
 * rejected it (the bias form requires rsp PLUS a positive displacement) and found no bias at all --
 * failing the one POSITIVE fixture while every refusal fixture still passed, because "no bias" is
 * what they were testing for anyway. 1 of 8, and the 1 was the case that proves the thing works.
 *
 * The real trap entry at ntoskrnl+0x6B724C uses mod=10 with disp32, which is why the offline scan
 * reported +0x80 correctly and the fixture did not. A fixture that cannot encode what the target
 * actually contains is testing a shape the derivation will never see.
 *
 * ModRM 0xAC = mod 10, reg 101 (rbp), rm 100 (SIB); SIB 0x24 = base rsp, no index.
 */
#define LEA_RBP_RSP(disp)   0x48, 0x8D, 0xAC, 0x24, \
                            (UINT8)((disp) & 0xFF), (UINT8)(((disp) >> 8) & 0xFF), \
                            (UINT8)(((disp) >> 16) & 0xFF), (UINT8)(((disp) >> 24) & 0xFF)
#define MOV_RBP_RAX(disp8)  0x48, 0x89, 0x45, (UINT8)(disp8)
#define MOV_RBP_RCX(disp8)  0x48, 0x89, 0x4D, (UINT8)(disp8)
#define MOV_RBP_RDX(disp8)  0x48, 0x89, 0x55, (UINT8)(disp8)
#define MOV_RBP_R8(disp8)   0x4C, 0x89, 0x45, (UINT8)(disp8)
#define MOV_RBP_R9(disp8)   0x4C, 0x89, 0x4D, (UINT8)(disp8)
#define MOV_RBP_R10(disp8)  0x4C, 0x89, 0x55, (UINT8)(disp8)
#define MOV_RBP_R11(disp8)  0x4C, 0x89, 0x5D, (UINT8)(disp8)
#define MOV_RCX_RAX(disp8)  0x48, 0x89, 0x41, (UINT8)(disp8)   /* base rcx -- must be IGNORED */
#define TEST_RBP_IF         0xF7, 0x85, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00

/* The real shape: bias 0x80, the seven at 0x30..0x60, EFLAGS resolving to 0x178. */
static CONST UINT8 gFixGood[] = {
	LEA_RBP_RSP(0x80),
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),   /* -0x50, -0x48, -0x40 */
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xD0),  MOV_RBP_R10(0xD8), MOV_RBP_R11(0xE0),
	MOV_RBP_RDX(0x58),                    /* the SECOND rdx store (into Dr0) -- must be ignored */
	TEST_RBP_IF
};

/* Two conflicting biases -- no store can be attributed. GATE 1. */
static CONST UINT8 gFixTwoBias[] = {
	LEA_RBP_RSP(0x80), LEA_RBP_RSP(0x60),
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xD0),  MOV_RBP_R10(0xD8), MOV_RBP_R11(0xE0),
	TEST_RBP_IF
};

/* No bias at all. GATE 1. */
static CONST UINT8 gFixNoBias[] = {
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xD0),  MOV_RBP_R10(0xD8), MOV_RBP_R11(0xE0),
	TEST_RBP_IF
};

/* R11 never stored -- a PARTIAL map, which would read as zero. GATE 2. */
static CONST UINT8 gFixMissing[] = {
	LEA_RBP_RSP(0x80),
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xD0),  MOV_RBP_R10(0xD8),
	TEST_RBP_IF
};

/* R9 displaced so the run has a GAP -- a coincidental store attributed to a slot. GATE 3. */
static CONST UINT8 gFixGap[] = {
	LEA_RBP_RSP(0x80),
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xE8),  MOV_RBP_R10(0xD8), MOV_RBP_R11(0xE0),
	TEST_RBP_IF
};

/* Bias 0x70 puts EFLAGS at 0x168, contradicting the proven 0x178. GATE 4. */
static CONST UINT8 gFixBadBias[] = {
	LEA_RBP_RSP(0x70),
	MOV_RBP_RAX(0xC0), MOV_RBP_RCX(0xC8), MOV_RBP_RDX(0xD0),
	MOV_RBP_R8(0xD8),  MOV_RBP_R9(0xE0),  MOV_RBP_R10(0xE8), MOV_RBP_R11(0xF0),
	TEST_RBP_IF
};

/* Correct shape but NO EFLAGS test -- the bias is uncorroborated. GATE 4. */
static CONST UINT8 gFixNoEflags[] = {
	LEA_RBP_RSP(0x80),
	MOV_RBP_RAX(0xB0), MOV_RBP_RCX(0xB8), MOV_RBP_RDX(0xC0),
	MOV_RBP_R8(0xC8),  MOV_RBP_R9(0xD0),  MOV_RBP_R10(0xD8), MOV_RBP_R11(0xE0)
};

/* Every store off RCX instead of rbp. The bias does not apply to another base register, and
 * attributing them anyway would produce a complete-looking map of the wrong structure. GATE 2. */
static CONST UINT8 gFixWrongBase[] = {
	LEA_RBP_RSP(0x80),
	MOV_RCX_RAX(0xB0), MOV_RCX_RAX(0xB8), MOV_RCX_RAX(0xC0),
	TEST_RBP_IF
};

NTSTATUS
NxcIdtGprSelfTest(
	_Out_ UINT32* OutRun,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirstFailure
	)
{
	typedef struct { PCSTR Name; CONST UINT8* Body; UINT32 Len; BOOLEAN Expect; } GPR_CASE;

	CONST GPR_CASE Cases[] = {
		{ "real shape (bias 0x80, run 0x30..0x60, 2nd rdx ignored)",
		  gFixGood,      (UINT32)sizeof(gFixGood),      TRUE  },
		{ "two conflicting biases",   gFixTwoBias,  (UINT32)sizeof(gFixTwoBias),  FALSE },
		{ "no bias at all",           gFixNoBias,   (UINT32)sizeof(gFixNoBias),   FALSE },
		{ "R11 never stored",         gFixMissing,  (UINT32)sizeof(gFixMissing),  FALSE },
		{ "gap in the run",           gFixGap,      (UINT32)sizeof(gFixGap),      FALSE },
		{ "bias contradicts proven EFLAGS", gFixBadBias, (UINT32)sizeof(gFixBadBias), FALSE },
		{ "no EFLAGS test to corroborate",  gFixNoEflags, (UINT32)sizeof(gFixNoEflags), FALSE },
		{ "stores off RCX, not rbp",  gFixWrongBase,(UINT32)sizeof(gFixWrongBase),FALSE },
	};

	CONST UINT32 Count = (UINT32)(sizeof(Cases) / sizeof(Cases[0]));
	UINT32 Failed = 0, First = 0xFFFFFFFFu;

	*OutRun = 0; *OutFailed = 0; *OutFirstFailure = 0xFFFFFFFFu;

	for (UINT32 i = 0; i < Count; i++)
	{
		NXC_GPR_MAP Map;
		/* 0x178 is passed as the PROVEN offset -- the same value live trap frames established, so
		 * gate 4 is exercised rather than skipped. */
		CONST NTSTATUS St = IdtDeriveGprsFromBody(Cases[i].Body, Cases[i].Len, 0x178u, &Map);
		CONST BOOLEAN Got = (BOOLEAN)(NT_SUCCESS(St) && Map.Valid);

		BOOLEAN Ok = (Got == Cases[i].Expect);

		/* For the positive case the VALUES matter, not just the verdict: a derivation that succeeds
		 * with the wrong offsets is the failure this whole exercise exists to prevent. */
		if (Ok && Cases[i].Expect)
			Ok = (BOOLEAN)(Map.Offset[NXC_GPR_RAX] == 0x30u && Map.Offset[NXC_GPR_RCX] == 0x38u &&
			               Map.Offset[NXC_GPR_RDX] == 0x40u && Map.Offset[NXC_GPR_R8]  == 0x48u &&
			               Map.Offset[NXC_GPR_R9]  == 0x50u && Map.Offset[NXC_GPR_R10] == 0x58u &&
			               Map.Offset[NXC_GPR_R11] == 0x60u && Map.Bias == 0x80u &&
			               Map.EflagsSeen == 0x178u);

		if (!Ok)
		{
			IdtLog("idt: GPR selftest case %u \"%s\" FAILED -- expected %s, got %s (rax=0x%X bias=0x%X)\n",
			       i, Cases[i].Name, Cases[i].Expect ? "SUCCESS" : "REFUSAL",
			       Got ? "SUCCESS" : "REFUSAL", Map.Offset[NXC_GPR_RAX], Map.Bias);
			Failed++;
			if (First == 0xFFFFFFFFu) First = i;
		}
		(*OutRun)++;
	}

	*OutFailed = Failed;
	*OutFirstFailure = First;

	if (Failed != 0)
	{
		IdtLog("idt: GPR selftest %u of %u FAILED -- the derivation is not sound and its offsets must "
		       "not be used.\n", Failed, Count);
		return STATUS_UNSUCCESSFUL;
	}

	IdtLog("idt: GPR selftest %u/%u OK -- accepts the real shape and refuses ambiguous bias, missing "
	       "bias, partial map, gapped run, contradicted bias, uncorroborated bias, wrong base.\n",
	       Count, Count);
	return STATUS_SUCCESS;
}

/* ================================================================================================
 * R12-R15, DECODED FROM THE FUNNEL. Reasoning and the four gates are in Idt.h.
 * ============================================================================================= */

/* Architectural order, as the funnel stores them. Used to map ModRM.reg+REX.R back to a slot and to
 * enforce contiguity -- the same structural check that made the volatile run trustworthy. */
static CONST UINT8 gNvGprRegNum[NXC_NVGPR_COUNT] = { 12u, 13u, 14u, 15u };

static NTSTATUS
IdtDeriveNvGprsFromBody(
	_In_reads_(Len) CONST UINT8* Body,
	_In_ UINT32 Len,
	_Out_ NXC_NVGPR_MAP* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	/*
	 * ---- GATE 4 FIRST: PROVE THE BASE. -----------------------------------------------------
	 *
	 * `mov rdx, rsp` (48 8B D4) is what makes ExceptionFrame == rsp. Checked BEFORE anything else
	 * because without it every displacement below is a number with no referent -- which is exactly
	 * how 0xF8 nearly became Dr6. Ordering the cheap decisive test first is not an optimisation, it
	 * is refusing to compute on an unproven base.
	 */
	BOOLEAN BaseProven = FALSE;
	for (UINT32 i = 0; i + 3 <= Len; i++)
	{
		if (Body[i] == 0x48u && Body[i + 1] == 0x8Bu && Body[i + 2] == 0xD4u)
		{
			BaseProven = TRUE;
			break;
		}
	}

	if (!BaseProven)
	{
		Out->Gate = NXC_GPR_GATE_NO_BIAS;
		IdtLog("idt: R12-R15 REFUSED -- no `mov rdx, rsp`, so the ExceptionFrame base is UNPROVEN. "
		       "A displacement off an unknown base is not a structure offset.\n");
		return STATUS_NOT_FOUND;
	}

	/*
	 * ---- GATES 1-3, EVALUATED AS A PAIR: EACH CANDIDATE BASE AGAINST ITS OWN STORES. ---------
	 *
	 * ⚠⚠ THE FIRST CUT REQUIRED EXACTLY ONE `lea <reg>,[rsp+B]` IN THE FUNCTION, AND THE FUNNEL HAS
	 * TWO. Measured on 10.0.26100.8972:
	 *
	 *     +0x007  lea rax, [rsp+0x100]     <- the nonvolatile save base
	 *     +0x05F  lea rax, [rsp+0x138]     <- something else, also positive
	 *
	 * so the uniqueness test tripped BIAS_AMBIG and R12-R15 came back ABSENT on hardware. The rule
	 * was copied from the volatile derivation, where the trap entry genuinely has one -- a rule that
	 * held for one function assumed to hold for another with a different shape.
	 *
	 * ⚠ SELECTING THE BASE INDEPENDENTLY WAS THE MISTAKE, not the count. A base means nothing on its
	 * own; what identifies it is that the four stores hung off it form a COMPLETE CONTIGUOUS RUN. So
	 * each candidate is tried in full and the requirement moves to the result: EXACTLY ONE candidate
	 * may yield a valid run. That is strictly stronger than uniqueness -- an unrelated `lea` cannot
	 * fool it, and two candidates that both produce runs still refuse rather than picking one.
	 */
	UINT32  Base = 0;
	UINT32  Winners = 0;
	UINT32  WinOffsets[NXC_NVGPR_COUNT];
	BOOLEAN AnyCandidate = FALSE;

	RtlZeroMemory(WinOffsets, sizeof(WinOffsets));

	for (UINT32 i = 0; i + 8 <= Len; i++)
	{
		if ((Body[i] != 0x48u && Body[i] != 0x4Cu) || Body[i + 1] != 0x8Du)
			continue;
		CONST UINT8 M = Body[i + 2];
		if ((M & 7u) != 4u)
			continue;               /* need a SIB */
		if ((Body[i + 3] & 7u) != 4u)
			continue;               /* SIB base must be rsp */

		CONST UINT8 Mod = M >> 6;
		INT32 Cand;
		if (Mod == 1u)      Cand = (INT32)(INT8)Body[i + 4];
		else if (Mod == 2u) Cand = (INT32)(((UINT32)Body[i + 4])       |
		                                   ((UINT32)Body[i + 5] << 8)  |
		                                   ((UINT32)Body[i + 6] << 16) |
		                                   ((UINT32)Body[i + 7] << 24));
		else continue;

		if (Cand <= 0)
			continue;

		AnyCandidate = TRUE;

		/*
		 * ⚠⚠ THE PAIRING IS BY POSITION AND DESTINATION REGISTER, NOT BY ARITHMETIC.
		 *
		 * A first attempt tried each candidate base against every store and asked which produced a
		 * complete contiguous run. That discriminates NOTHING: the same four store instructions
		 * resolve to a complete run under ANY base, because changing the base shifts all four
		 * offsets uniformly. Both of the funnel's `lea`s would have "won" and it would have refused
		 * as ambiguous all over again -- a different mechanism reaching the identical wrong answer.
		 *
		 * What actually binds a store to a `lea` is that the `lea` wrote the store's BASE REGISTER
		 * and is the most recent one to have done so. In the funnel:
		 *
		 *     +0x007  lea rax,[rsp+0x100]   <- writes rax
		 *     +0x04F  mov [rax+0x18], r12   <- rax still holds 0x100 here
		 *     +0x05F  lea rax,[rsp+0x138]   <- AFTER the stores; cannot own them
		 *
		 * So a store is attributed to the nearest PRECEDING `lea` with a matching destination.
		 */
		CONST UINT8 LeaDest = (UINT8)((((M >> 3) & 7u)) | ((Body[i] & 4u) ? 8u : 0u));

		/* ---- try THIS base: collect each register's FIRST store attributed to it ------------ */
		UINT32  TryOff[NXC_NVGPR_COUNT];
		BOOLEAN Seen[NXC_NVGPR_COUNT];
		RtlZeroMemory(TryOff, sizeof(TryOff));
		RtlZeroMemory(Seen, sizeof(Seen));

		for (UINT32 j = i + 1; j + 4 <= Len; j++)
		{
			/* REX.WR (0x4C) is required: R12-R15 all need REX.R for the reg field. */
			if (Body[j] != 0x4Cu || Body[j + 1] != 0x89u)
				continue;

			CONST UINT8 SM  = Body[j + 2];
			CONST UINT8 SMod = SM >> 6;
			CONST UINT8 SRm  = SM & 7u;
			if (SRm == 4u || SRm == 5u)
				continue;           /* a SIB or rbp form is not the [reg+disp] shape used here */

			/*
			 * ⚠ THE STORE'S BASE REGISTER MUST BE THE ONE THIS `lea` WROTE. Without this the loop
			 * attributes every store to every candidate and the whole pairing collapses back to
			 * arithmetic that cannot discriminate.
			 */
			if ((UINT8)(SRm | ((Body[j] & 1u) ? 8u : 0u)) != LeaDest)
				continue;

			/*
			 * ⚠ AND A LATER `lea` TO THE SAME REGISTER ENDS THIS ONE'S REACH. Past that point the
			 * register holds a different value, so any store beyond it belongs to the other base --
			 * which is exactly what separates the funnel's 0x100 from its 0x138.
			 */
			BOOLEAN Superseded = FALSE;
			for (UINT32 k = i + 1; k + 8 <= j; k++)
			{
				if ((Body[k] != 0x48u && Body[k] != 0x4Cu) || Body[k + 1] != 0x8Du)
					continue;
				CONST UINT8 KM = Body[k + 2];
				if ((KM & 7u) != 4u || (Body[k + 3] & 7u) != 4u)
					continue;
				if ((UINT8)((((KM >> 3) & 7u)) | ((Body[k] & 4u) ? 8u : 0u)) == LeaDest)
				{
					Superseded = TRUE;
					break;
				}
			}
			if (Superseded)
				continue;

			UINT32 P = j + 3;
			INT32 SDisp;
			if (SMod == 1u)      SDisp = (INT32)(INT8)Body[P];
			else if (SMod == 2u)
			{
				if (j + 7 > Len) continue;
				SDisp = (INT32)(((UINT32)Body[P]) | ((UINT32)Body[P + 1] << 8) |
				                ((UINT32)Body[P + 2] << 16) | ((UINT32)Body[P + 3] << 24));
			}
			else continue;

			CONST UINT8 Reg = (UINT8)(((SM >> 3) & 7u) | 8u);   /* REX.R is set, so +8 */

			CONST INT64 Resolved = (INT64)SDisp + (INT64)Cand;
			if (Resolved < 0 || Resolved > 0x400)
				continue;

			for (UINT32 g = 0; g < NXC_NVGPR_COUNT; g++)
			{
				if (gNvGprRegNum[g] != Reg || Seen[g])
					continue;
				TryOff[g] = (UINT32)Resolved;
				Seen[g] = TRUE;
				break;
			}
		}

		/* Complete? */
		BOOLEAN Complete = TRUE;
		for (UINT32 g = 0; g < NXC_NVGPR_COUNT; g++)
			if (!Seen[g]) { Complete = FALSE; break; }
		if (!Complete)
			continue;

		/* Contiguous, 8-byte stride, architectural order? This is what makes a base THE base. */
		BOOLEAN Contig = TRUE;
		for (UINT32 g = 1; g < NXC_NVGPR_COUNT; g++)
			if (TryOff[g] != TryOff[g - 1] + 8u) { Contig = FALSE; break; }
		if (!Contig)
			continue;

		Winners++;
		if (Winners == 1)
		{
			Base = (UINT32)Cand;
			for (UINT32 g = 0; g < NXC_NVGPR_COUNT; g++)
				WinOffsets[g] = TryOff[g];
		}
	}

	if (Winners == 0)
	{
		/* ⚠ THE TWO REASONS ARE DIFFERENT AND MUST NOT SHARE A GATE. No `lea` at all is a statement
		 * about the function; candidates present but none producing a run is a statement about the
		 * stores. */
		Out->Gate = AnyCandidate ? NXC_GPR_GATE_MISSING_REG : NXC_GPR_GATE_NO_BIAS;
		IdtLog("idt: R12-R15 REFUSED -- %s\n",
		       AnyCandidate ? "candidate save bases exist but none yields a complete contiguous run"
		                    : "no `lea <reg>,[rsp+B]` in the funnel at all");
		return STATUS_NOT_FOUND;
	}

	if (Winners > 1)
	{
		Out->Gate = NXC_GPR_GATE_BIAS_AMBIG;
		IdtLog("idt: R12-R15 REFUSED -- %u save bases each yield a complete run. AMBIGUOUS; not "
		       "choosing one.\n", Winners);
		return STATUS_UNSUCCESSFUL;
	}

	Out->SaveBase = Base;
	for (UINT32 g = 0; g < NXC_NVGPR_COUNT; g++)
		Out->Offset[g] = WinOffsets[g];

	/*
	 * ⚠ NO SEPARATE GATE 3 ANY MORE -- contiguity is now a CONDITION OF SELECTION rather than a
	 * check applied afterwards. A base only becomes a candidate winner by producing a complete
	 * contiguous run, so a surviving map cannot fail it. Re-testing here would be a second
	 * expression of the same rule, which is the drift this project keeps paying for; a gapped run
	 * simply means that base loses, and the GAP outcome is reported by the "none yields a complete
	 * contiguous run" refusal above.
	 */
	Out->Gate  = NXC_GPR_GATE_OK;
	Out->Valid = TRUE;
	IdtLog("idt: R12-R15 derived -- save base rsp+0x%X, R12..R15 at KEXCEPTION_FRAME+0x%X..0x%X\n",
	       Base, Out->Offset[0], Out->Offset[NXC_NVGPR_COUNT - 1]);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcIdtDeriveNonvolatileGprs(
	_In_ UINT64 FunnelVa,
	_Out_ NXC_NVGPR_MAP* Out
	)
{
	RtlZeroMemory(Out, sizeof(*Out));

	NXC_IDT_PROBE Probe;
	CONST NTSTATUS PSt = NxcIdtProbe(0, FunnelVa, &Probe);
	if (!NT_SUCCESS(PSt))
		return PSt;

	if (Probe.HandlerBegin == 0 || Probe.HandlerEnd <= Probe.HandlerBegin)
		return STATUS_NOT_FOUND;

	CONST UINT64 Span = Probe.HandlerEnd - Probe.HandlerBegin;
	if (Span > 0x2000)
	{
		Out->Gate = NXC_GPR_GATE_UNREADABLE;
		return STATUS_NOT_FOUND;
	}

	if (!MmIsAddressValid((PVOID)(ULONG_PTR)Probe.HandlerBegin) ||
	    !MmIsAddressValid((PVOID)(ULONG_PTR)(Probe.HandlerEnd - 1)))
	{
		Out->Gate = NXC_GPR_GATE_UNREADABLE;
		return STATUS_INVALID_ADDRESS;
	}

	return IdtDeriveNvGprsFromBody((CONST UINT8*)(ULONG_PTR)Probe.HandlerBegin, (UINT32)Span, Out);
}

/* ================================================================================================
 * THE R12-R15 SELF-TEST -- again built from the cases that must FAIL.
 * ⚠ Gate 4 (the proven base) gets its own negative fixture, because it is the gate whose absence
 * produced the +0xF8/Dr6 near-miss and the one most tempting to skip when the numbers look right.
 * ============================================================================================= */

#define MOV_RDX_RSP    0x48, 0x8B, 0xD4                      /* proves ExceptionFrame == rsp   */
#define LEA_RAX_RSP(d) 0x48, 0x8D, 0x84, 0x24, \
                       (UINT8)((d) & 0xFF), (UINT8)(((d) >> 8) & 0xFF), \
                       (UINT8)(((d) >> 16) & 0xFF), (UINT8)(((d) >> 24) & 0xFF)
#define MOV_RAX_R12(d) 0x4C, 0x89, 0x60, (UINT8)(d)
#define MOV_RAX_R13(d) 0x4C, 0x89, 0x68, (UINT8)(d)
#define MOV_RAX_R14(d) 0x4C, 0x89, 0x70, (UINT8)(d)
#define MOV_RAX_R15(d) 0x4C, 0x89, 0x78, (UINT8)(d)

/* The real shape: base rsp+0x100, R12..R15 at +0x18..+0x30 -> EF+0x118..0x130. */
static CONST UINT8 gNvGood[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28), MOV_RAX_R15(0x30),
	MOV_RDX_RSP
};

/* No `mov rdx, rsp` -- the base is UNPROVEN even though every offset looks right. GATE 4. */
static CONST UINT8 gNvNoBase[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28), MOV_RAX_R15(0x30)
};

/*
 * ⚠⚠ THE FIXTURE THAT WAS MISSING, AND ITS ABSENCE IS WHY R12-R15 CAME BACK ABSENT ON HARDWARE.
 *
 * TWO `lea`s, only ONE of which has stores hung off it. The real funnel is exactly this shape:
 *
 *     +0x007  lea rax, [rsp+0x100]     <- the save base, four stores follow
 *     +0x05F  lea rax, [rsp+0x138]     <- unrelated, no R12-R15 stores
 *
 * The first cut required exactly one `lea` in the function and refused this as AMBIGUOUS. Every
 * fixture in the original suite had a single `lea`, so the suite passed 5/5 while the derivation
 * could not read the one function it was written for -- a suite made of tidy cases testing the one
 * shape where the defect is invisible.
 *
 * MUST NOW SUCCEED, with the run resolved against 0x100 and the 0x138 candidate simply losing.
 */
static CONST UINT8 gNvTwoLeaOneRun[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28), MOV_RAX_R15(0x30),
	LEA_RAX_RSP(0x138),
	MOV_RDX_RSP
};

/*
 * Two bases that BOTH yield a complete contiguous run -- genuinely ambiguous, and the one case where
 * refusing is still right. Stores appear twice, at displacements that resolve completely under each
 * base in turn. GATE 1.
 */
static CONST UINT8 gNvTwoBase[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28), MOV_RAX_R15(0x30),
	LEA_RAX_RSP(0x0C0),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28), MOV_RAX_R15(0x30),
	MOV_RDX_RSP
};

/* R15 never stored -- a PARTIAL map. GATE 2. */
static CONST UINT8 gNvMissing[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x28),
	MOV_RDX_RSP
};

/* R14 displaced -- a GAP in the run. GATE 3. */
static CONST UINT8 gNvGap[] = {
	LEA_RAX_RSP(0x100),
	MOV_RAX_R12(0x18), MOV_RAX_R13(0x20), MOV_RAX_R14(0x40), MOV_RAX_R15(0x30),
	MOV_RDX_RSP
};

NTSTATUS
NxcIdtNvGprSelfTest(
	_Out_ UINT32* OutRun,
	_Out_ UINT32* OutFailed,
	_Out_ UINT32* OutFirst
	)
{
	typedef struct { PCSTR Name; CONST UINT8* Body; UINT32 Len; BOOLEAN Expect; } NV_CASE;

	CONST NV_CASE Cases[] = {
		{ "real shape (base rsp+0x100, run +0x18..+0x30)", gNvGood,    (UINT32)sizeof(gNvGood),    TRUE  },
		{ "no `mov rdx, rsp` -- base UNPROVEN",            gNvNoBase,  (UINT32)sizeof(gNvNoBase),  FALSE },
		{ "two `lea`s, only ONE owning stores (the REAL funnel shape)",
		                                                   gNvTwoLeaOneRun, (UINT32)sizeof(gNvTwoLeaOneRun), TRUE  },
		{ "two bases, EACH owning a complete run",          gNvTwoBase, (UINT32)sizeof(gNvTwoBase), FALSE },
		{ "R15 never stored",                              gNvMissing, (UINT32)sizeof(gNvMissing), FALSE },
		{ "gap in the run",                                gNvGap,     (UINT32)sizeof(gNvGap),     FALSE },
	};

	CONST UINT32 Count = (UINT32)(sizeof(Cases) / sizeof(Cases[0]));
	UINT32 Failed = 0, First = 0xFFFFFFFFu;

	*OutRun = 0; *OutFailed = 0; *OutFirst = 0xFFFFFFFFu;

	for (UINT32 i = 0; i < Count; i++)
	{
		NXC_NVGPR_MAP M;
		CONST NTSTATUS St = IdtDeriveNvGprsFromBody(Cases[i].Body, Cases[i].Len, &M);
		CONST BOOLEAN Got = (BOOLEAN)(NT_SUCCESS(St) && M.Valid);

		BOOLEAN Ok = (Got == Cases[i].Expect);

		/* The positive case asserts VALUES too: succeeding with wrong offsets is the failure this
		 * exists to prevent, and a verdict-only suite cannot see it. */
		if (Ok && Cases[i].Expect)
			Ok = (BOOLEAN)(M.Offset[NXC_NVGPR_R12] == 0x118u &&
			               M.Offset[NXC_NVGPR_R13] == 0x120u &&
			               M.Offset[NXC_NVGPR_R14] == 0x128u &&
			               M.Offset[NXC_NVGPR_R15] == 0x130u &&
			               M.SaveBase == 0x100u);

		if (!Ok)
		{
			IdtLog("idt: NVGPR selftest case %u \"%s\" FAILED -- expected %s, got %s (R12=0x%X)\n",
			       i, Cases[i].Name, Cases[i].Expect ? "SUCCESS" : "REFUSAL",
			       Got ? "SUCCESS" : "REFUSAL", M.Offset[NXC_NVGPR_R12]);
			Failed++;
			if (First == 0xFFFFFFFFu) First = i;
		}
		(*OutRun)++;
	}

	*OutFailed = Failed;
	*OutFirst  = First;

	if (Failed != 0)
	{
		IdtLog("idt: NVGPR selftest %u of %u FAILED -- R12-R15 must not be used.\n", Failed, Count);
		return STATUS_UNSUCCESSFUL;
	}

	IdtLog("idt: NVGPR selftest %u/%u OK -- refuses an unproven base, two bases, a partial map and "
	       "a gapped run.\n", Count, Count);
	return STATUS_SUCCESS;
}
