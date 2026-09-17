//
// NexusPgLocate -- semantic location of the PatchGuard init routines. See NexusPgLocate.h.
//

//
// (!) DELIBERATELY SELF-CONTAINED: NexusPe.h, Zydis, and BaseMemoryLib. No NexusBootDxe.h,
// no DXE services, no driver state. That is what lets this exact source be compiled and run
// against real ntoskrnl images on the host -- which matters more here than anywhere else in
// the driver, because the addresses this file produces get written to.
//
#include "NexusPgLocate.h"

#include <Zydis/Zydis.h>
#include <Library/BaseMemoryLib.h>

//
// KUSER_SHARED_DATA sits at a fixed architectural address on x64 and KdDebuggerEnabled at a
// fixed offset in it, so this value is an ABI CONSTANT -- more durable than any instruction
// sequence, including the ones matched below.
//
#define KD_DEBUGGER_ENABLED         0xFFFFF780000002D4ULL

//
// The mask KiVerifyScopesExecute loads. A 64-bit constant is a semantic choice rather than an
// encoding accident, which is what makes it a good handle.
//
#define KIVERIFY_SCOPES_MASK        0xFEFFFFFFFFFFFFFFULL

//
// How far into KiSwInterruptDispatch to look for the g_PgContext load. Measured on all four
// reference builds the load is at +29 and the nearest other RIP-relative load into a register
// is at +625 or absent within 1 KB, so this window has roughly 5x margin.
//
#define DISPATCH_SCAN_BYTES         128

//
// (!) A SLIDING WINDOW, NOT A DECODED FUNCTION.
//
// The first draft of this decoded each function into arrays of 1,024 instructions and their
// operands. ZydisDecodedOperand is large and ZYDIS_MAX_OPERAND_COUNT is 10, so that was
// roughly 650 KB of static data reserved in a DXE image to look at five instructions at a
// time. Every pattern below spans at most five, so five is what is kept.
//
#define PG_WINDOW                   5

typedef struct _PG_INSN
{
	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
	CONST UINT8* Address;
} PG_INSN;

typedef struct _PG_EXPORTS
{
	UINT8* KeBugCheckEx;
	UINT8* HalPerformEndOfInterrupt;
	UINT8* KeSetCoalescableTimer;
} PG_EXPORTS;

typedef struct _PG_FUNCTION
{
	UINT8* Start;
	UINT32 Size;
	UINT32 CallCount;
	BOOLEAN CallsHalPerformEndOfInterrupt;
	BOOLEAN CallsKeSetCoalescableTimer;
} PG_FUNCTION;


STATIC
PEFI_IMAGE_SECTION_HEADER
EFIAPI
SectionForRva(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN UINT32 Rva
	)
{
	CONST PEFI_IMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CONST UINT32 Span = Sections[i].Misc.VirtualSize > Sections[i].SizeOfRawData
			? Sections[i].Misc.VirtualSize
			: Sections[i].SizeOfRawData;
		if (Rva >= Sections[i].VirtualAddress && Rva < Sections[i].VirtualAddress + Span)
			return &Sections[i];
	}
	return NULL;
}


STATIC
BOOLEAN
EFIAPI
SectionIsNamed(
	IN PEFI_IMAGE_SECTION_HEADER Section,
	IN CONST CHAR8* Name
	)
{
	if (Section == NULL)
		return FALSE;
	for (UINTN i = 0; i < 8; ++i)
	{
		CONST CHAR8 Want = Name[i];
		if (Section->Name[i] != (UINT8)Want)
			return FALSE;
		if (Want == '\0')
			return TRUE;
	}
	return TRUE;
}


//
// Summarise a function by BYTE-SCANNING for direct calls rather than disassembling it.
//
// (!) THIS IS WHAT MAKES THE PASS AFFORDABLE AT BOOT. Fully decoding 12 MB of ntoskrnl would
// cost seconds. A 0xE8 scan is one pass over the bytes and answers "does this call any of the
// three exports I care about", which is all the structural filters need. Only functions that
// survive those filters reach Zydis.
//
// It can false-positive on an 0xE8 byte inside an immediate or inside data mixed into code.
// Acceptable HERE because the result only ever NARROWS a candidate set that is then confirmed
// semantically. It is never proof on its own.
//
STATIC
VOID
EFIAPI
SummariseFunction(
	IN CONST PG_EXPORTS* Exports,
	IN OUT PG_FUNCTION* Function
	)
{
	Function->CallCount = 0;
	Function->CallsHalPerformEndOfInterrupt = FALSE;
	Function->CallsKeSetCoalescableTimer = FALSE;

	CONST UINT8* Body = Function->Start;
	CONST UINT32 Length = Function->Size;

	for (UINT32 i = 0; i + 5 <= Length; )
	{
		if (Body[i] != 0xE8)
		{
			i++;
			continue;
		}

		INT32 Displacement;
		CopyMem(&Displacement, &Body[i + 1], sizeof(Displacement));
		CONST UINT8* Callee = Body + i + 5 + Displacement;

		Function->CallCount++;
		if (Callee == Exports->HalPerformEndOfInterrupt)
			Function->CallsHalPerformEndOfInterrupt = TRUE;
		if (Callee == Exports->KeSetCoalescableTimer)
			Function->CallsKeSetCoalescableTimer = TRUE;

		i += 5;
	}
}


//
// Cheap byte pre-scan for a constant, so a function is only decoded when it could match.
//
// (!) THE SAME DISCIPLINE THE 0xE8 SCAN ABOVE USES, APPLIED TO THE INIT-ONLY TARGETS. Without
// it, every function in INIT (666 KB in ntoskrnl 26100) is fully decoded to look for two
// 64-bit constants. NexusBootLocate was written without this and a boot spent long enough in
// it to look hung; the measurement is in that file's header.
//
// A match here is not proof -- the bytes could be data, or part of a larger immediate. It only
// decides who gets decoded; the semantic test below still decides who matches.
//
//
// (!) DERIVE THE NEEDLE FROM THE CONSTANT, NEVER HAND-TYPE IT.
//
// The first attempt spelled 0xFFFFF780000002D4 out as bytes by hand and dropped the 0x80,
// writing D4 02 00 00 00 F7 FF FF instead of D4 02 00 00 80 F7 FF FF. The pre-scan then
// matched nothing, both KdDebuggerEnabled readers came back NULL, and the whole patch refused
// -- caught only because check_pglocate.py compares every target against the oracle.
//
// A needle that cannot disagree with the #define it came from removes the entire class.
//
STATIC
VOID
EFIAPI
ConstantNeedle(
	IN UINT64 Value,
	OUT UINT8 Needle[8]
	)
{
	for (UINTN i = 0; i < 8; ++i)
		Needle[i] = (UINT8)(Value >> (i * 8));
}


STATIC
BOOLEAN
EFIAPI
ContainsBytes(
	IN CONST UINT8* Body,
	IN UINT32 Size,
	IN CONST UINT8* Needle,
	IN UINT32 NeedleSize
	)
{
	if (Size < NeedleSize)
		return FALSE;

	CONST UINT32 Last = Size - NeedleSize;
	for (UINT32 i = 0; i <= Last; ++i)
	{
		if (Body[i] != Needle[0])
			continue;

		UINT32 j = 1;
		while (j < NeedleSize && Body[i + j] == Needle[j])
			j++;
		if (j == NeedleSize)
			return TRUE;
	}
	return FALSE;
}


//
// 'mov REG64, imm64' carrying a specific constant.
//
// (!) THE TEST IS ON THE OPERAND, NOT THE MNEMONIC. Capstone calls this form movabs and the
// host prototype matches it by name; Zydis reports a plain MOV with a 64-bit immediate. A
// port that looked for a movabs mnemonic here would silently match nothing.
//
STATIC
BOOLEAN
EFIAPI
IsImmediateLoad(
	IN CONST PG_INSN* Insn,
	IN UINT64 Value
	)
{
	if (Insn->Instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
		Insn->Instruction.operand_count < 2)
		return FALSE;
	if (Insn->Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return FALSE;
	if (Insn->Operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return FALSE;
	return (BOOLEAN)(Insn->Operands[1].imm.value.u == Value);
}


//
// 'mov REG8, byte ptr [abs]' -- absolute memory operand, no base, no index.
//
STATIC
BOOLEAN
EFIAPI
IsAbsoluteMemoryLoad(
	IN CONST PG_INSN* Insn,
	IN UINT64 Address
	)
{
	if (Insn->Instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
		Insn->Instruction.operand_count < 2)
		return FALSE;
	if (Insn->Operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
		return FALSE;
	if (Insn->Operands[1].mem.base != ZYDIS_REGISTER_NONE ||
		Insn->Operands[1].mem.index != ZYDIS_REGISTER_NONE)
		return FALSE;
	return (BOOLEAN)((UINT64)Insn->Operands[1].mem.disp.value == Address);
}


//
// KiMcaDeferredRecoveryService: zero a register, then fan it out into four DISTINCT others.
//
// (!) MNEMONICS ALONE ARE USELESS HERE. 'xor; mov; mov; mov; mov' matched 1,756 of 30,872
// functions in the host prototype -- zeroing a register and moving it about is the most
// ordinary thing in compiled code. What distinguishes this site is DATA FLOW, not opcodes.
// Checking operands took 1,756 to 1.
//
STATIC
BOOLEAN
EFIAPI
IsZeroThenFanout(
	IN CONST PG_INSN* Window[PG_WINDOW],
	IN UINTN FanoutWidth
	)
{
	CONST PG_INSN* Xor = Window[0];
	if (Xor->Instruction.mnemonic != ZYDIS_MNEMONIC_XOR ||
		Xor->Instruction.operand_count < 2)
		return FALSE;
	if (Xor->Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
		Xor->Operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return FALSE;
	if (Xor->Operands[0].reg.value != Xor->Operands[1].reg.value)
		return FALSE;

	CONST ZydisRegister Source = ZydisRegisterGetLargestEnclosing(
		ZYDIS_MACHINE_MODE_LONG_64, Xor->Operands[0].reg.value);

	ZydisRegister Seen[PG_WINDOW];
	UINTN SeenCount = 0;

	for (UINTN k = 1; k <= FanoutWidth; ++k)
	{
		CONST PG_INSN* Mov = Window[k];
		if (Mov->Instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
			Mov->Instruction.operand_count < 2)
			return FALSE;
		if (Mov->Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
			Mov->Operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
			return FALSE;

		if (ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,
											Mov->Operands[1].reg.value) != Source)
			return FALSE;

		CONST ZydisRegister To = ZydisRegisterGetLargestEnclosing(
			ZYDIS_MACHINE_MODE_LONG_64, Mov->Operands[0].reg.value);

		for (UINTN s = 0; s < SeenCount; ++s)
		{
			if (Seen[s] == To)
				return FALSE;      // a repeated destination is a different shape of code
		}
		if (SeenCount < ARRAY_SIZE(Seen))
			Seen[SeenCount++] = To;
	}

	return TRUE;
}


//
// KeInitAmd64SpecificState: neg; sbb; and; add; ror -- the CPU-stepping arithmetic.
//
STATIC
BOOLEAN
EFIAPI
IsSteppingArithmetic(
	IN CONST PG_INSN* Window[PG_WINDOW]
	)
{
	STATIC CONST ZydisMnemonic Wanted[] = {
		ZYDIS_MNEMONIC_NEG, ZYDIS_MNEMONIC_SBB, ZYDIS_MNEMONIC_AND,
		ZYDIS_MNEMONIC_ADD, ZYDIS_MNEMONIC_ROR
	};

	for (UINTN k = 0; k < ARRAY_SIZE(Wanted); ++k)
	{
		if (Window[k]->Instruction.mnemonic != Wanted[k])
			return FALSE;
	}
	return TRUE;
}


//
// KiSwInterrupt: sti; lea; call; cli -- interrupts enabled around a dispatch call, then
// disabled. Yields the call target.
//
STATIC
BOOLEAN
EFIAPI
IsInterruptDispatchSite(
	IN CONST PG_INSN* Window[PG_WINDOW],
	OUT UINT8** DispatchTarget
	)
{
	if (Window[0]->Instruction.mnemonic != ZYDIS_MNEMONIC_STI)
		return FALSE;
	if (Window[1]->Instruction.mnemonic != ZYDIS_MNEMONIC_LEA)
		return FALSE;
	if (Window[2]->Instruction.mnemonic != ZYDIS_MNEMONIC_CALL)
		return FALSE;
	if (Window[3]->Instruction.mnemonic != ZYDIS_MNEMONIC_CLI)
		return FALSE;
	if (Window[2]->Operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return FALSE;

	//
	// (!) READ THE CALL'S OPERAND. The code this replaces indexed a FIXED BYTE OFFSET into
	// its own signature -- byte 5 assumed to be E8, byte 10 the cli after it -- and read the
	// displacement from there. It carried a runtime check for exactly that assumption because
	// the original ASSERT compiled away in release builds. Decoding removes the assumption
	// rather than guarding it.
	//
	ZyanU64 Absolute = 0;
	if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Window[2]->Instruction,
												&Window[2]->Operands[0],
												(ZyanU64)(UINTN)Window[2]->Address,
												&Absolute)))
		return FALSE;

	*DispatchTarget = (UINT8*)(UINTN)Absolute;
	return TRUE;
}


//
// The g_PgContext load: first 'mov REG, [rip+disp]' within the dispatch routine.
//
STATIC
UINT8*
EFIAPI
FindPgContextLoad(
	IN ZydisDecoder* Decoder,
	IN CONST UINT8* Dispatch
	)
{
	UINT32 Offset = 0;

	while (Offset < DISPATCH_SCAN_BYTES)
	{
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(Decoder,
												Dispatch + Offset,
												DISPATCH_SCAN_BYTES - Offset,
												&Instruction,
												Operands)))
		{
			Offset++;
			continue;
		}

		if (Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			Instruction.operand_count >= 2 &&
			Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			Operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			ZyanU64 Absolute = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Operands[1],
													(ZyanU64)(UINTN)(Dispatch + Offset),
													&Absolute)))
				return (UINT8*)(UINTN)Absolute;
		}

		Offset += Instruction.length;
	}

	return NULL;
}


EFI_STATUS
EFIAPI
NexusPgLocateTargets(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT NEXUS_PG_TARGETS* Targets
	)
{
	if (ImageBase == NULL || NtHeaders == NULL || Targets == NULL)
		return EFI_INVALID_PARAMETER;

	SetMem(Targets, sizeof(*Targets), 0);

	if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION)
		return EFI_UNSUPPORTED;

	CONST PEFI_IMAGE_DATA_DIRECTORY ExceptionDirectory =
		&NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (ExceptionDirectory->VirtualAddress == 0 || ExceptionDirectory->Size == 0)
		return EFI_UNSUPPORTED;

	CONST PIMAGE_RUNTIME_FUNCTION_ENTRY Table =
		(PIMAGE_RUNTIME_FUNCTION_ENTRY)(ImageBase + ExceptionDirectory->VirtualAddress);
	CONST UINT32 EntryCount =
		ExceptionDirectory->Size / (UINT32)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	PG_EXPORTS Exports;
	Exports.KeBugCheckEx =
		(UINT8*)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "KeBugCheckEx");
	Exports.HalPerformEndOfInterrupt =
		(UINT8*)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "HalPerformEndOfInterrupt");
	Exports.KeSetCoalescableTimer =
		(UINT8*)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "KeSetCoalescableTimer");

	//
	// Long mode, always: PE32 images are refused by RtlpImageNtHeaderEx before anything gets
	// here, so there is no 32-bit arm to select.
	//
	ZydisDecoder Decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64,
										ZYDIS_STACK_WIDTH_64)))
		return EFI_DEVICE_ERROR;

	UINT8* McaService = NULL;
	UINT8* CcCandidate = NULL;
	UINT8* ExpCandidate = NULL;
	UINTN CcCount = 0, ExpCount = 0;
	UINTN KeInitCount = 0, VerifyCount = 0, SwInterruptCount = 0, McaCount = 0;

	//
	// ONE PASS over the exception directory. Each function is summarised cheaply, structural
	// filters decide who gets disassembled, and the semantic tests decide who matches.
	//
	for (UINT32 Index = 0; Index < EntryCount; ++Index)
	{
		CONST UINT32 BeginRva = Table[Index].BeginAddress;
		CONST UINT32 EndRva = Table[Index].EndAddress;
		if (EndRva <= BeginRva || EndRva - BeginRva > 0x20000)
			continue;

		//
		// Resolve to the PRIMARY entry, and only consider a function at its own primary. A
		// .pdata entry is not a function: 18.6% of entries in 26100 and 27.3% in 19041 are
		// chained fragments of a function that starts elsewhere, and processing those would
		// both waste time and report fragment addresses.
		//
		UINT8* CONST Start = FindFunctionStart(ImageBase, NtHeaders, ImageBase + BeginRva);
		if (Start == NULL || Start != ImageBase + BeginRva)
			continue;

		CONST PEFI_IMAGE_SECTION_HEADER Section = SectionForRva(NtHeaders, BeginRva);
		CONST BOOLEAN InText = SectionIsNamed(Section, ".text");
		CONST BOOLEAN InInit = SectionIsNamed(Section, "INIT");
		if (!InText && !InInit)
			continue;

		PG_FUNCTION Function;
		Function.Start = Start;
		Function.Size = EndRva - BeginRva;
		SummariseFunction(&Exports, &Function);

		//
		// Structural filters. Everything past here is a decode, so these are what keep the
		// pass affordable -- and for KiSwInterrupt and KiMcaDeferredRecoveryService they are
		// also the conjunct that makes the semantic pattern unique, because their siblings
		// share the semantics exactly.
		//
		CONST BOOLEAN MaybeSwInterrupt =
			InText && Function.Size > 1024 && Function.CallsHalPerformEndOfInterrupt;
		CONST BOOLEAN MaybeMca = InText && Function.Size < 64;
		CONST BOOLEAN MaybeKeInit =
			InInit && Function.Size >= 60 && Function.Size <= 100 && Function.CallCount == 1;

		//
		// Both remaining INIT targets are identified by a 64-bit constant, so the constant's
		// bytes have to be present for the function to be a candidate at all. Gating on that
		// is what keeps INIT from being disassembled in full.
		//
		UINT8 ScopesMaskNeedle[8];
		UINT8 KdEnabledNeedle[8];
		ConstantNeedle(KIVERIFY_SCOPES_MASK, ScopesMaskNeedle);
		ConstantNeedle(KD_DEBUGGER_ENABLED, KdEnabledNeedle);

		CONST BOOLEAN MaybeVerify = InInit &&
			ContainsBytes(Start, Function.Size, ScopesMaskNeedle, sizeof(ScopesMaskNeedle));
		CONST BOOLEAN MaybeKdReader = InInit &&
			ContainsBytes(Start, Function.Size, KdEnabledNeedle, sizeof(KdEnabledNeedle));

		if (!MaybeSwInterrupt && !MaybeMca && !MaybeKeInit && !MaybeVerify && !MaybeKdReader)
			continue;

		//
		// Sliding window over the decode. Window[0] is the oldest of the last PG_WINDOW
		// instructions, so a pattern is tested as soon as enough have accumulated.
		//
		STATIC PG_INSN Ring[PG_WINDOW];
		CONST PG_INSN* Window[PG_WINDOW];
		UINTN Head = 0, Filled = 0;
		UINT32 Offset = 0;

		//
		// (!) MATCHES ARE RECORDED PER FUNCTION, NOT PER WINDOW. A single function can
		// satisfy a pattern at several offsets -- the stepping arithmetic appears more than
		// once in some builds -- and counting those as separate hits would make a unique
		// target look ambiguous and get it discarded.
		//
		BOOLEAN FoundKdRead = FALSE;
		BOOLEAN MatchedKeInit = FALSE, MatchedVerify = FALSE, MatchedMca = FALSE;
		BOOLEAN MatchedSwInterrupt = FALSE;
		UINT8* SwSite = NULL;
		UINT8* SwDispatch = NULL;
		UINT32 SwLength = 0;

		while (Offset < Function.Size)
		{
			PG_INSN* CONST Slot = &Ring[(Head + Filled) % PG_WINDOW];

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder,
													Start + Offset,
													Function.Size - Offset,
													&Slot->Instruction,
													Slot->Operands)))
			{
				// Data inside a function, or a form Zydis will not decode. Resynchronise a
				// byte at a time rather than abandoning the function.
				Offset++;
				continue;
			}

			Slot->Address = Start + Offset;
			Offset += Slot->Instruction.length;

			if (Filled < PG_WINDOW)
				Filled++;
			else
				Head = (Head + 1) % PG_WINDOW;

			if (Filled < PG_WINDOW)
				continue;

			for (UINTN k = 0; k < PG_WINDOW; ++k)
				Window[k] = &Ring[(Head + k) % PG_WINDOW];

			if (MaybeKeInit && !MatchedKeInit && IsSteppingArithmetic(Window))
				MatchedKeInit = TRUE;

			if (MaybeVerify && !MatchedVerify &&
				IsImmediateLoad(Window[0], KIVERIFY_SCOPES_MASK))
				MatchedVerify = TRUE;

			if (MaybeMca && !MatchedMca && IsZeroThenFanout(Window, 4))
				MatchedMca = TRUE;

			if (MaybeSwInterrupt && !MatchedSwInterrupt)
			{
				UINT8* Dispatch = NULL;
				if (IsInterruptDispatchSite(Window, &Dispatch))
				{
					MatchedSwInterrupt = TRUE;
					//
					// The patch spans sti through cli inclusive -- what the NOPs replace.
					// Computed from the decode rather than hardcoded, so a different encoding
					// changes the length instead of corrupting the tail.
					//
					SwSite = (UINT8*)Window[0]->Address;
					SwLength = (UINT32)((Window[3]->Address +
										Window[3]->Instruction.length) - Window[0]->Address);
					SwDispatch = Dispatch;
				}
			}

			//
			// The two KdDebuggerEnabled readers.
			//
			// (!) SEPARATED BY WHAT THEY DO, NOT BY ORDINAL. The code this replaces took the
			// FIRST such reader in INIT as CcInitializeBcbProfiler and the SECOND as
			// ExpLicenseWatchInitWorker. Sound only while there are exactly two in that
			// order; a third silently stubs the wrong function, which the host mutation test
			// demonstrates by planting one.
			//
			//   CcInitializeBcbProfiler loads the ADDRESS into a 64-bit register and goes on
			//   to arm a timer. KeSetCoalescableTimer is PatchGuard's own scheduling route,
			//   firing 2-130 s after boot -- which is what confirms this routine ARMS PG.
			//
			//   ExpLicenseWatchInitWorker DEREFERENCES the byte and is an order of magnitude
			//   smaller.
			//
			// Do NOT substitute "calls ExAllocatePool2" as the discriminator, tempting as it
			// is since the old code already uses that export as a version probe: on 19041
			// this routine calls ExAllocatePoolWithTag, so that test picks the wrong function
			// across a release boundary. Nor "ExpLicenseWatchInitWorker calls KeBugCheckEx" --
			// on 19041 it has no exported callees at all.
			//
			if (MaybeKdReader && !FoundKdRead)
			{
				if (Function.CallsKeSetCoalescableTimer &&
					IsImmediateLoad(Window[0], KD_DEBUGGER_ENABLED))
				{
					FoundKdRead = TRUE;
					if (CcCandidate == NULL)
						CcCandidate = Start;
					CcCount++;
				}
				else if (!Function.CallsKeSetCoalescableTimer &&
						IsAbsoluteMemoryLoad(Window[0], KD_DEBUGGER_ENABLED))
				{
					FoundKdRead = TRUE;
					if (ExpCandidate == NULL)
						ExpCandidate = Start;
					ExpCount++;
				}
			}
		}

		//
		// Per-function accounting. The FIRST matching function supplies the address; a second
		// one only bumps the count, which is what turns a would-be wrong answer into no
		// answer at all.
		//
		if (MatchedKeInit && KeInitCount++ == 0)
			Targets->KeInitAmd64SpecificState = Start;

		if (MatchedVerify && VerifyCount++ == 0)
			Targets->KiVerifyScopesExecute = Start;

		if (MatchedMca && McaCount++ == 0)
			McaService = Start;

		if (MatchedSwInterrupt && SwInterruptCount++ == 0)
		{
			Targets->KiSwInterruptPatchSite = SwSite;
			Targets->KiSwInterruptPatchLength = SwLength;
			Targets->KiSwInterruptDispatch = SwDispatch;
		}
	}

	//
	// (!) AMBIGUITY IS A FAILURE, NOT A CHOICE. If a predicate matched more than one
	// function we do not have the target -- we have a set containing it. Taking the first
	// would be a three-byte write to something we could not name.
	//
	Targets->CcInitializeBcbProfiler = (CcCount == 1) ? CcCandidate : NULL;
	Targets->ExpLicenseWatchInitWorker = (ExpCount == 1) ? ExpCandidate : NULL;

	if (KeInitCount != 1)
		Targets->KeInitAmd64SpecificState = NULL;
	if (VerifyCount != 1)
		Targets->KiVerifyScopesExecute = NULL;
	if (SwInterruptCount != 1)
	{
		Targets->KiSwInterruptPatchSite = NULL;
		Targets->KiSwInterruptPatchLength = 0;
		Targets->KiSwInterruptDispatch = NULL;
	}
	if (McaCount != 1)
		McaService = NULL;

	//
	// The two routines that CALL KiMcaDeferredRecoveryService are the patch targets, not the
	// routine itself. Found with the same cheap 0xE8 scan the summariser uses, then resolved
	// to function starts -- the code this replaces linearly disassembled all of .text for it.
	//
	if (McaService != NULL)
	{
		CONST PEFI_IMAGE_SECTION_HEADER TextSection =
			SectionForRva(NtHeaders, (UINT32)(UINTN)(McaService - ImageBase));

		if (SectionIsNamed(TextSection, ".text"))
		{
			CONST UINT8* Scan = ImageBase + TextSection->VirtualAddress;
			CONST UINT32 ScanSize = TextSection->SizeOfRawData;
			UINTN Found = 0;

			for (UINT32 i = 0; i + 5 <= ScanSize && Found < 2; )
			{
				if (Scan[i] != 0xE8)
				{
					i++;
					continue;
				}

				INT32 Displacement;
				CopyMem(&Displacement, &Scan[i + 1], sizeof(Displacement));
				if (Scan + i + 5 + Displacement == McaService)
				{
					UINT8* CONST Caller = FindFunctionStart(ImageBase, NtHeaders, Scan + i);
					if (Caller != NULL &&
						(Found == 0 ||
						Caller != Targets->KiMcaDeferredRecoveryServiceCallers[0]))
					{
						Targets->KiMcaDeferredRecoveryServiceCallers[Found] = Caller;
						Found++;
					}
				}

				i += 5;
			}

			if (Found != 2)
			{
				Targets->KiMcaDeferredRecoveryServiceCallers[0] = NULL;
				Targets->KiMcaDeferredRecoveryServiceCallers[1] = NULL;
			}
		}
	}

	//
	// g_PgContext, decoded forward from the dispatch routine.
	//
	if (Targets->KiSwInterruptDispatch != NULL)
	{
		UINT8* CONST PgContext = FindPgContextLoad(&Decoder, Targets->KiSwInterruptDispatch);

		//
		// (!) VALIDATE WHERE THE POINTER WOULD LAND. Every other target takes a 3-byte stub;
		// this one takes an 8-BYTE POINTER WRITE, so a wrong address is not a failed patch,
		// it is an arbitrary kernel write. The code this replaces validated that the
		// INSTRUCTION lay inside a .pdata function and never checked the TARGET at all.
		// Those are different claims and only the second is about where the write goes.
		//
		if (PgContext != NULL)
		{
			CONST PEFI_IMAGE_SECTION_HEADER PgSection =
				SectionForRva(NtHeaders, (UINT32)(UINTN)(PgContext - ImageBase));
			if (PgSection != NULL &&
				(PgSection->Characteristics & EFI_IMAGE_SCN_MEM_WRITE) != 0 &&
				(PgSection->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) == 0)
			{
				Targets->PgContext = PgContext;
			}
		}
	}

	//
	// What the caller cannot proceed without. KiSwInterrupt and g_PgContext are survivable --
	// the system boots without them, it simply bugchecks if int 20h is ever issued from
	// kernel mode -- so they are not required here.
	//
	if (Targets->KeInitAmd64SpecificState == NULL ||
		Targets->CcInitializeBcbProfiler == NULL)
		return EFI_NOT_FOUND;

	return EFI_SUCCESS;
}
