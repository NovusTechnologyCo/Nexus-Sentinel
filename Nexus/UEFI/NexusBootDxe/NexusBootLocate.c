//
// NexusBootLocate -- find the hook targets in bootmgfw.efi and winload.efi.
// See NexusBootLocate.h. Self-contained like NexusPgLocate, for the same reason: this exact
// source is compiled and run against real boot files on the host.
//

#include "NexusBootLocate.h"

#include <Zydis/Zydis.h>
#include <Library/BaseMemoryLib.h>

#define IMGARCH_STATUS_CONSTANT     0xD0000009u
#define PCR_SNAPSHOT_MAGIC          0xADF01995u
#define OSL_SETUP_DISPLACEMENT      0x124

//
// How far into a function to look for the home-space spills. The prologue is the first few
// instructions by definition; scanning further would start counting ordinary stores.
//
#define PROLOGUE_INSTRUCTIONS       12


typedef struct _BL_SECTION
{
	CONST UINT8* Base;      // mapped address of the section
	UINT32 Rva;
	UINT32 Size;
} BL_SECTION;


//
// (!) CHEAP BYTE PRE-SCAN BEFORE ANY DECODE. THIS IS NOT AN OPTIMISATION, IT IS THE
// DIFFERENCE BETWEEN BOOTING AND APPEARING TO HANG.
//
// The first version of this file decoded EVERY function in .text to look for a constant.
// Measured on the host, with a warm cache and a modern CPU:
//
//     NexusPgLocate, ntoskrnl 12.5 MB, WITH pre-filters :   167 ms
//     NexusBootLocate, bootmgfw 3 MB, WITHOUT           : 1,231 ms
//
// Thirty times worse per byte, and that is the FAVOURABLE environment. In a DXE, before
// ExitBootServices, on firmware-mapped memory, it was slow enough to look like a hung boot --
// which is exactly how it presented. ZydisDecoderDecodeFull fills a ~300-byte instruction and
// ten ~64-byte operands per call; at roughly 400,000 instructions for bootmgfw's .text that is
// hundreds of megabytes of writes to find one immediate.
//
// NexusPgLocate already carried this discipline and says so in its own comments. Not applying
// it here was an oversight, not a judgement.
//
// The pre-scan may match bytes that are not the instruction we want -- an immediate inside a
// larger one, or data mixed into code. That is fine, and is the same bargain NexusPgLocate
// makes with its 0xE8 scan: the scan only ever NARROWS the set, and the semantic test that
// follows is what decides. It is never proof on its own.
//
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
// Does this function contain a direct call to `Target`? Same 0xE8 scan NexusPgLocate uses.
//
STATIC
BOOLEAN
EFIAPI
CallsTarget(
	IN CONST UINT8* Body,
	IN UINT32 Size,
	IN CONST UINT8* Target
	)
{
	for (UINT32 i = 0; i + 5 <= Size; )
	{
		if (Body[i] != 0xE8)
		{
			i++;
			continue;
		}

		INT32 Displacement;
		CopyMem(&Displacement, &Body[i + 1], sizeof(Displacement));
		if (Body + i + 5 + Displacement == Target)
			return TRUE;

		i += 5;
	}
	return FALSE;
}


STATIC
BOOLEAN
EFIAPI
FindTextSection(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT BL_SECTION* Section
	)
{
	CONST PEFI_IMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CONST UINT8* Name = Sections[i].Name;
		if (Name[0] == '.' && Name[1] == 't' && Name[2] == 'e' && Name[3] == 'x' &&
			Name[4] == 't' && Name[5] == '\0')
		{
			Section->Base = ImageBase + Sections[i].VirtualAddress;
			Section->Rva = Sections[i].VirtualAddress;
			Section->Size = Sections[i].SizeOfRawData;
			return TRUE;
		}
	}
	return FALSE;
}


//
// Normalise a register to its 64-bit enclosing form, so ECX and RCX compare equal. The
// prologue stores 32-bit halves of 64-bit argument registers (r8d for r8), and treating
// those as different registers is how an arity count comes out wrong.
//
STATIC
ZydisRegister
EFIAPI
WideRegister(
	IN ZydisRegister Register
	)
{
	return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, Register);
}


//
// How many of RCX, RDX, R8, R9 the prologue spills to memory -- i.e. the function's arity.
//
// (!) THIS IS THE FUNCTION'S SIGNATURE, READ OFF ITS PROLOGUE. Microsoft x64 gives every
// function shadow space for its first four register arguments, and a function that uses them
// after a call spills them there on entry. A routine taking one argument spills one.
//
STATIC
UINTN
EFIAPI
CountHomedParameters(
	IN ZydisDecoder* Decoder,
	IN CONST UINT8* Function,
	IN UINT32 Size
	)
{
	CONST ZydisRegister Params[4] =
		{ ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9 };
	BOOLEAN Seen[4] = { FALSE, FALSE, FALSE, FALSE };

	UINT32 Offset = 0;
	UINTN Decoded = 0;
	UINT32 Limit = (Size < 96) ? Size : 96;

	while (Offset < Limit && Decoded < PROLOGUE_INSTRUCTIONS)
	{
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(Decoder, Function + Offset, Limit - Offset,
												&Instruction, Operands)))
			break;

		Decoded++;
		Offset += Instruction.length;

		if (Instruction.mnemonic != ZYDIS_MNEMONIC_MOV || Instruction.operand_count < 2)
			continue;
		if (Operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY)
			continue;
		if (Operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
			continue;

		CONST ZydisRegister Wide = WideRegister(Operands[1].reg.value);
		for (UINTN p = 0; p < 4; ++p)
		{
			if (Wide == Params[p])
				Seen[p] = TRUE;
		}
	}

	UINTN Count = 0;
	for (UINTN p = 0; p < 4; ++p)
	{
		if (Seen[p])
			Count++;
	}
	return Count;
}


//
// Walk the exception directory, calling back for each PRIMARY function in .text.
//
// Same rule as NexusPgLocate: a .pdata entry is not a function, so an entry that resolves
// somewhere other than its own start is a chained fragment and is skipped -- its function
// will be visited at its own primary entry.
//
typedef BOOLEAN (EFIAPI *BL_FUNCTION_CALLBACK)(
	IN CONST UINT8* Function,
	IN UINT32 Size,
	IN VOID* Context
	);

STATIC
VOID
EFIAPI
ForEachTextFunction(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST BL_SECTION* Text,
	IN BL_FUNCTION_CALLBACK Callback,
	IN VOID* Context
	)
{
	if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION)
		return;

	CONST PEFI_IMAGE_DATA_DIRECTORY Directory =
		&NtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (Directory->VirtualAddress == 0 || Directory->Size == 0)
		return;

	CONST PIMAGE_RUNTIME_FUNCTION_ENTRY Table =
		(PIMAGE_RUNTIME_FUNCTION_ENTRY)(ImageBase + Directory->VirtualAddress);
	CONST UINT32 Count = Directory->Size / (UINT32)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	for (UINT32 i = 0; i < Count; ++i)
	{
		CONST UINT32 Begin = Table[i].BeginAddress;
		CONST UINT32 End = Table[i].EndAddress;
		if (End <= Begin || End - Begin > 0x20000)
			continue;
		if (Begin < Text->Rva || Begin >= Text->Rva + Text->Size)
			continue;

		UINT8* CONST Start = FindFunctionStart(ImageBase, NtHeaders, ImageBase + Begin);
		if (Start == NULL || Start != ImageBase + Begin)
			continue;

		if (!Callback(Start, End - Begin, Context))
			return;
	}
}


//
// ---------------------------------------------------------------- ImgArchEfiStartBootApplication

typedef struct _IMGARCH_CONTEXT
{
	ZydisDecoder* Decoder;
	UINT8* Match;
	UINTN Matches;
} IMGARCH_CONTEXT;

STATIC
BOOLEAN
EFIAPI
ImgArchCallback(
	IN CONST UINT8* Function,
	IN UINT32 Size,
	IN VOID* Context
	)
{
	IMGARCH_CONTEXT* CONST Ctx = (IMGARCH_CONTEXT*)Context;

	// The 32-bit immediate, little-endian. Absent means this function cannot be the one.
	STATIC CONST UINT8 Needle[4] = { 0x09, 0x00, 0x00, 0xD0 };
	if (!ContainsBytes(Function, Size, Needle, sizeof(Needle)))
		return TRUE;

	UINT32 Offset = 0;

	while (Offset < Size)
	{
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(Ctx->Decoder, Function + Offset, Size - Offset,
												&Instruction, Operands)))
		{
			Offset++;
			continue;
		}
		Offset += Instruction.length;

		if (Instruction.mnemonic != ZYDIS_MNEMONIC_MOV || Instruction.operand_count < 2)
			continue;
		if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
			continue;
		if (Operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
			continue;
		if ((UINT32)Operands[1].imm.value.u != IMGARCH_STATUS_CONSTANT)
			continue;

		//
		// Into R8D specifically: the constant is being passed as the THIRD argument. Any
		// register would match six functions in bootmgfw; R8D narrows it to two.
		//
		if (WideRegister(Operands[0].reg.value) != ZYDIS_REGISTER_R8)
			continue;

		//
		// And the containing function must itself take at least three arguments. This is what
		// separates the real one (homes RCX, RDX, R8) from the 321-byte decoy (homes RCX).
		//
		if (CountHomedParameters(Ctx->Decoder, Function, Size) < 3)
			continue;

		Ctx->Matches++;
		if (Ctx->Match == NULL)
			Ctx->Match = (UINT8*)Function;
		return TRUE;    // keep going: a second match means ambiguity, which must be caught
	}

	return TRUE;
}


EFI_STATUS
EFIAPI
NexusBootLocateImgArchStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	)
{
	if (ImageBase == NULL || NtHeaders == NULL || Found == NULL)
		return EFI_INVALID_PARAMETER;
	*Found = NULL;

	BL_SECTION Text;
	if (!FindTextSection(ImageBase, NtHeaders, &Text))
		return EFI_NOT_FOUND;

	ZydisDecoder Decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64,
										ZYDIS_STACK_WIDTH_64)))
		return EFI_DEVICE_ERROR;

	IMGARCH_CONTEXT Ctx;
	Ctx.Decoder = &Decoder;
	Ctx.Match = NULL;
	Ctx.Matches = 0;

	ForEachTextFunction(ImageBase, NtHeaders, &Text, ImgArchCallback, &Ctx);

	if (Ctx.Matches != 1)
		return EFI_NOT_FOUND;   // none, or more than one -- either way we do not have it

	*Found = Ctx.Match;
	return EFI_SUCCESS;
}


//
// ---------------------------------------------------------------- BuildPcrSnapshotData

typedef struct _SNAPSHOT_CONTEXT
{
	ZydisDecoder* Decoder;
	UINT8* Match;
	UINTN Matches;
} SNAPSHOT_CONTEXT;

STATIC
BOOLEAN
EFIAPI
SnapshotCallback(
	IN CONST UINT8* Function,
	IN UINT32 Size,
	IN VOID* Context
	)
{
	SNAPSHOT_CONTEXT* CONST Ctx = (SNAPSHOT_CONTEXT*)Context;

	// The snapshot magic as a little-endian immediate.
	STATIC CONST UINT8 Needle[4] = { 0x95, 0x19, 0xF0, 0xAD };
	if (!ContainsBytes(Function, Size, Needle, sizeof(Needle)))
		return TRUE;

	UINT32 Offset = 0;

	while (Offset < Size)
	{
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(Ctx->Decoder, Function + Offset, Size - Offset,
												&Instruction, Operands)))
		{
			Offset++;
			continue;
		}
		Offset += Instruction.length;

		if (Instruction.operand_count < 2)
			continue;
		if (Operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
			continue;
		if ((UINT32)Operands[1].imm.value.u != PCR_SNAPSHOT_MAGIC)
			continue;

		Ctx->Matches++;
		if (Ctx->Match == NULL)
			Ctx->Match = (UINT8*)Function;
		return TRUE;
	}

	return TRUE;
}


EFI_STATUS
EFIAPI
NexusBootLocateBuildPcrSnapshotData(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	)
{
	if (ImageBase == NULL || NtHeaders == NULL || Found == NULL)
		return EFI_INVALID_PARAMETER;
	*Found = NULL;

	BL_SECTION Text;
	if (!FindTextSection(ImageBase, NtHeaders, &Text))
		return EFI_NOT_FOUND;

	ZydisDecoder Decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64,
										ZYDIS_STACK_WIDTH_64)))
		return EFI_DEVICE_ERROR;

	SNAPSHOT_CONTEXT Ctx;
	Ctx.Decoder = &Decoder;
	Ctx.Match = NULL;
	Ctx.Matches = 0;

	ForEachTextFunction(ImageBase, NtHeaders, &Text, SnapshotCallback, &Ctx);

	if (Ctx.Matches != 1)
		return EFI_NOT_FOUND;

	*Found = Ctx.Match;
	return EFI_SUCCESS;
}


//
// ---------------------------------------------------------------- OslFwpKernelSetupPhase1

typedef struct _OSLSETUP_CONTEXT
{
	ZydisDecoder* Decoder;
	CONST UINT8* BlBdStop;
	UINT8* Match;
	UINTN Matches;
} OSLSETUP_CONTEXT;

STATIC
BOOLEAN
EFIAPI
OslSetupCallback(
	IN CONST UINT8* Function,
	IN UINT32 Size,
	IN VOID* Context
	)
{
	OSLSETUP_CONTEXT* CONST Ctx = (OSLSETUP_CONTEXT*)Context;

	// Nine functions in winload call BlBdStop. Everything else is skipped without decoding.
	if (!CallsTarget(Function, Size, Ctx->BlBdStop))
		return TRUE;

	UINT32 Offset = 0;
	BOOLEAN PendingStore = FALSE;

	while (Offset < Size)
	{
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
		CONST UINT8* CONST Address = Function + Offset;

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(Ctx->Decoder, Address, Size - Offset,
												&Instruction, Operands)))
		{
			Offset++;
			PendingStore = FALSE;
			continue;
		}
		Offset += Instruction.length;

		//
		// A call to the EXPORTED BlBdStop, immediately after a store to [REG+0x124].
		// "Immediately" is what makes it unique: nine functions in winload call BlBdStop.
		//
		if (PendingStore &&
			Instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			Instruction.operand_count >= 1 &&
			Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			ZyanU64 Target = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Operands[0],
													(ZyanU64)(UINTN)Address, &Target)) &&
				(CONST UINT8*)(UINTN)Target == Ctx->BlBdStop)
			{
				Ctx->Matches++;
				if (Ctx->Match == NULL)
					Ctx->Match = (UINT8*)Function;
				return TRUE;
			}
		}

		PendingStore = (BOOLEAN)(Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
								Instruction.operand_count >= 2 &&
								Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								Operands[0].mem.disp.value == OSL_SETUP_DISPLACEMENT);
	}

	return TRUE;
}


EFI_STATUS
EFIAPI
NexusBootLocateOslFwpKernelSetupPhase1(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	)
{
	if (ImageBase == NULL || NtHeaders == NULL || Found == NULL)
		return EFI_INVALID_PARAMETER;
	*Found = NULL;

	BL_SECTION Text;
	if (!FindTextSection(ImageBase, NtHeaders, &Text))
		return EFI_NOT_FOUND;

	//
	// (!) THE ANCHOR IS AN EXPORT, AND WITHOUT IT THERE IS NO SEARCH. Refusing here is
	// correct: a winload that does not export BlBdStop is not one this predicate was measured
	// against, and guessing would put a trampoline on an unidentified function.
	//
	CONST UINT8* CONST BlBdStop =
		(CONST UINT8*)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlBdStop");
	if (BlBdStop == NULL)
		return EFI_NOT_FOUND;

	ZydisDecoder Decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64,
										ZYDIS_STACK_WIDTH_64)))
		return EFI_DEVICE_ERROR;

	OSLSETUP_CONTEXT Ctx;
	Ctx.Decoder = &Decoder;
	Ctx.BlBdStop = BlBdStop;
	Ctx.Match = NULL;
	Ctx.Matches = 0;

	ForEachTextFunction(ImageBase, NtHeaders, &Text, OslSetupCallback, &Ctx);

	if (Ctx.Matches != 1)
		return EFI_NOT_FOUND;

	*Found = Ctx.Match;
	return EFI_SUCCESS;
}
