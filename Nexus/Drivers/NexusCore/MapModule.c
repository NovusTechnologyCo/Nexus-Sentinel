/**
 * @file MapModule.c
 * @brief NexusCore's RUNTIME mapper: map a further driver into the arena, post-boot.
 *
 * This is the job NexusCore exists for. The EFI layer maps exactly one driver -- NexusCore -- before
 * the kernel starts; NexusCore maps the rest on demand, which is the division v1 used too
 * ("provides on-demand manual mapping of additional drivers post-Windows boot").
 *
 * ============================================================================================
 * HOW THIS DIFFERS FROM THE EFI MAPPER, AND WHY
 * ============================================================================================
 *
 * The EFI mapper (Nexus/UEFI/NexusBootDxe/MapNexusCore.c) had luxuries this does not:
 *
 *   - it ran with gBS available, so it could AllocatePages. We cannot: gBS is long gone, and
 *     ExAllocatePool2 is precisely the enumerable, pool-tagged allocation the arena exists to avoid.
 *     So extents come from NxcArenaAlloc.
 *   - it ran before the kernel executed, so nothing could be concurrently calling into the image.
 *     We are live, which is why every module must satisfy the TEARDOWN CONTRACT (NexusModule.h)
 *     before it is allowed anywhere near the arena.
 *   - it knew ntoskrnl's base because winload handed it over. We get it from the boot block (ABI 3),
 *     rather than deriving it by scanning kernel memory backwards for "MZ".
 *
 * ============================================================================================
 * THE ORDER OF OPERATIONS IS NOT ARBITRARY
 * ============================================================================================
 *
 * The descriptor is validated BEFORE the entry point is called, and the module is REFUSED outright if
 * it has no valid descriptor. That ordering is the entire point of building the contract first: a
 * module that cannot be torn down must never become resident, because by the time you discover it
 * the only options are leaving it forever or the v1 failure mode.
 *
 * Concretely, refusing costs an error message. Accepting costs a machine that destabilises minutes
 * later in unrelated code, which is what v1 did and why its unmap was never usable.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>
#include <stdarg.h>

#include "MapModule.h"
#include "Arena.h"
#include "Pte.h"
#include "../../Include/NexusCoreBoot.h"
#include "../../Include/NexusModule.h"
#include "../../Include/NexusHost.h"

/*
 * Payload source: nt calls route through the exported table, so this image emits no import table
 * and therefore no FF 25 thunks for the published manual-map scan (see NexusNtApi.h).
 * `extern` because NexusCore.c owns the single instance.
 */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

/* Minimal PE structures. Declared locally so this file needs no SDK image headers in kernel mode. */
#pragma pack(push, 1)
typedef struct { USHORT e_magic; USHORT pad[29]; ULONG e_lfanew; } NXP_DOS;
typedef struct { USHORT Machine; USHORT NumberOfSections; ULONG TimeDateStamp;
                 ULONG PointerToSymbolTable; ULONG NumberOfSymbols;
                 USHORT SizeOfOptionalHeader; USHORT Characteristics; } NXP_FILE;
typedef struct { ULONG VirtualAddress; ULONG Size; } NXP_DIR;
/*
 * ⚠ PE32+ HAS NO BaseOfData. This struct carried one, and it cost a live debugging cycle.
 *
 * IMAGE_OPTIONAL_HEADER32 is  ... BaseOfCode, BaseOfData, ImageBase(4) ...
 * IMAGE_OPTIONAL_HEADER64 is  ... BaseOfCode, ImageBase(8) ...   <- no BaseOfData at all.
 *
 * With the extra ULONG present and #pragma pack(1) in force, every field from ImageBase onward read
 * FOUR BYTES LATE: this struct's SizeOfImage returned the real SizeOfHeaders, and its SizeOfHeaders
 * returned the real CheckSum.
 *
 * measured, first live `map`: SizeOfImage came back 0x400 (the real SizeOfHeaders)
 * instead of 0x7000, so `EntryRva >= SizeOfImage` was 0x1020 >= 0x400 -- true -- and every module
 * was refused at the size sanity check. NOTHING could ever have been mapped at runtime.
 *
 * It survived because the EFI mapper has its OWN (correct) structs, so NexusCore maps fine at boot,
 * and because Pte.c only reads FileHeader fields, so per-section protections worked too. Only this
 * one path was wrong, and only the runtime map exercised it.
 *
 * The offsets below are asserted for exactly this reason -- a hand-written PE view that is never
 * checked against the format is a silent decoder for a different file layout.
 */
typedef struct { USHORT Magic; UCHAR MajorLinker; UCHAR MinorLinker; ULONG SizeOfCode;
                 ULONG SizeOfInitData; ULONG SizeOfUninitData; ULONG AddressOfEntryPoint;
                 ULONG BaseOfCode; ULONGLONG ImageBase; ULONG SectionAlignment;
                 ULONG FileAlignment; USHORT MajorOs; USHORT MinorOs; USHORT MajorImage;
                 USHORT MinorImage; USHORT MajorSubsys; USHORT MinorSubsys; ULONG Win32Version;
                 ULONG SizeOfImage; ULONG SizeOfHeaders; ULONG CheckSum; USHORT Subsystem;
                 USHORT DllCharacteristics; ULONGLONG SizeOfStackReserve;
                 ULONGLONG SizeOfStackCommit; ULONGLONG SizeOfHeapReserve;
                 ULONGLONG SizeOfHeapCommit; ULONG LoaderFlags; ULONG NumberOfRvaAndSizes;
                 NXP_DIR Directory[16]; } NXP_OPT64;
typedef struct { ULONG Signature; NXP_FILE FileHeader; NXP_OPT64 OptionalHeader; } NXP_NT64;
typedef struct { UCHAR Name[8]; ULONG VirtualSize; ULONG VirtualAddress; ULONG SizeOfRawData;
                 ULONG PointerToRawData; ULONG PtrReloc; ULONG PtrLine; USHORT NumReloc;
                 USHORT NumLine; ULONG Characteristics; } NXP_SECTION;
typedef struct { ULONG VirtualAddress; ULONG SizeOfBlock; } NXP_BASE_RELOC;
typedef struct { ULONG Characteristics; ULONG TimeDateStamp; ULONG ForwarderChain;
                 ULONG Name; ULONG FirstThunk; } NXP_IMPORT_DESC;
typedef struct { ULONG Characteristics; ULONG TimeDateStamp; USHORT MajorVersion;
                 USHORT MinorVersion; ULONG Name; ULONG Base; ULONG NumberOfFunctions;
                 ULONG NumberOfNames; ULONG AddressOfFunctions; ULONG AddressOfNames;
                 ULONG AddressOfNameOrdinals; } NXP_EXPORT_DIR;

/*
 * IMAGE_LOAD_CONFIG_DIRECTORY64, only as far as SecurityCookie -- everything past it is irrelevant
 * here and modelling more would be more surface to get wrong.
 *
 * Spelled out field by field rather than reaching for offset 0x58 with a cast, so the offset can be
 * ASSERTED against the published layout. That is the direct lesson of the NXP_OPT64 BaseOfData bug:
 * a hand-written view of a binary format that is never checked against the format is a silent decoder
 * for something else.
 */
typedef struct { ULONG Size; ULONG TimeDateStamp; USHORT MajorVersion; USHORT MinorVersion;
                 ULONG GlobalFlagsClear; ULONG GlobalFlagsSet; ULONG CriticalSectionTimeout;
                 ULONGLONG DeCommitFreeBlockThreshold; ULONGLONG DeCommitTotalFreeThreshold;
                 ULONGLONG LockPrefixTable; ULONGLONG MaximumAllocationSize;
                 ULONGLONG VirtualMemoryThreshold; ULONGLONG ProcessAffinityMask;
                 ULONG ProcessHeapFlags; USHORT CSDVersion; USHORT DependentLoadFlags;
                 ULONGLONG EditList; ULONGLONG SecurityCookie; } NXP_LOAD_CONFIG64;
#pragma pack(pop)

/*
 * LAYOUT LOCK against the PE32+ format, not against our own opinion of it.
 *
 * These are the published IMAGE_OPTIONAL_HEADER64 offsets. The BaseOfData bug above passed every
 * test we had -- it compiled, it linked, NexusCore booted, protections applied -- and produced a
 * decoder for PE32 wearing a PE32+ label. Only a check against the FORMAT catches that; a check
 * against another copy of our own struct would have agreed with it.
 */
C_ASSERT(sizeof(NXP_OPT64) == 240);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, AddressOfEntryPoint) ==  16);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, ImageBase)           ==  24);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, SectionAlignment)    ==  32);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, SizeOfImage)         ==  56);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, SizeOfHeaders)       ==  60);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, NumberOfRvaAndSizes) == 108);
C_ASSERT(FIELD_OFFSET(NXP_OPT64, Directory)           == 112);

C_ASSERT(sizeof(NXP_NT64) == 264);
C_ASSERT(FIELD_OFFSET(NXP_NT64, FileHeader)     ==  4);
C_ASSERT(FIELD_OFFSET(NXP_NT64, OptionalHeader) == 24);

C_ASSERT(sizeof(NXP_DOS) == 64);
C_ASSERT(FIELD_OFFSET(NXP_DOS, e_lfanew) == 60);

C_ASSERT(sizeof(NXP_SECTION) == 40);
C_ASSERT(FIELD_OFFSET(NXP_SECTION, VirtualSize)      ==  8);
C_ASSERT(FIELD_OFFSET(NXP_SECTION, VirtualAddress)   == 12);
C_ASSERT(FIELD_OFFSET(NXP_SECTION, SizeOfRawData)    == 16);
C_ASSERT(FIELD_OFFSET(NXP_SECTION, PointerToRawData) == 20);
C_ASSERT(FIELD_OFFSET(NXP_SECTION, Characteristics)  == 36);

C_ASSERT(sizeof(NXP_EXPORT_DIR) == 40);
C_ASSERT(FIELD_OFFSET(NXP_EXPORT_DIR, NumberOfFunctions)   == 20);
C_ASSERT(FIELD_OFFSET(NXP_EXPORT_DIR, AddressOfNames)      == 32);
C_ASSERT(FIELD_OFFSET(NXP_EXPORT_DIR, AddressOfNameOrdinals) == 36);

C_ASSERT(sizeof(NXP_IMPORT_DESC) == 20);
C_ASSERT(FIELD_OFFSET(NXP_IMPORT_DESC, Name)       == 12);
C_ASSERT(FIELD_OFFSET(NXP_IMPORT_DESC, FirstThunk) == 16);

/* SecurityCookie MUST land at 0x58. The EFI mapper reaches it by that literal offset; asserting it
 * here means the two agree because the FORMAT says so, not because both used the same number. */
C_ASSERT(FIELD_OFFSET(NXP_LOAD_CONFIG64, SecurityCookie) == 0x58);
C_ASSERT(FIELD_OFFSET(NXP_LOAD_CONFIG64, EditList)       == 0x50);
C_ASSERT(FIELD_OFFSET(NXP_LOAD_CONFIG64, ProcessHeapFlags) == 0x48);

#define NXP_DIR_EXPORT   0
#define NXP_DIR_IMPORT   1
#define NXP_DIR_BASERELOC 5
#define NXP_DIR_TLS       9
#define NXP_DIR_LOAD_CONFIG 10

extern void NxcLogExt(_In_z_ PCSTR Format, ...);   /* NexusCore.c owns the one logging path */
#define MapLog NxcLogExt

/* Set once from DriverEntry: where ntoskrnl lives, per boot block ABI 3. */
static UCHAR* gNtBase = NULL;
static ULONG  gNtSize = 0;

/* One record per resident module, so unmap has something to act on. */
typedef struct _NXC_MODULE_SLOT
{
	BOOLEAN                  Valid;

	/*
	 * ⚠ NO ExtentId HERE, DELIBERATELY. Such a field would look like the durable teardown handle
	 * and would not be one.
	 *
	 * An extent id is an index into the arena's extent array, and BOTH arena paths shift that array
	 * (allocation splits and shifts up, free coalesces and shifts down). A stored id therefore goes
	 * stale the moment any other module is mapped or unmapped. Using it at teardown would either hit a
	 * now-free slot -- refused, with this module's real extent leaking forever -- or hit ANOTHER
	 * module's in-use extent and poison a live image.
	 *
	 * It would also be incomplete even when valid: a module gets further extents through
	 * NEXUS_HOST_API::Alloc, so the image's id alone reclaims the image and leaks everything the module
	 * allocated.
	 *
	 * TEARDOWN USES NxcArenaFreeOwner(Slot). The slot index IS the owner id (see the Owner assignment
	 * at map time), which is stable for as long as the module is resident -- unlike the extent index.
	 * The field is absent rather than present-and-unused, because anyone writing unmap would reach
	 * for something named ExtentId and it would appear to work in testing.
	 */
	UCHAR*                   Base;
	ULONG                    Size;
	NEXUS_MODULE_DESCRIPTOR* Descriptor;

	/*
	 * TEARDOWN STARTED AND COULD NOT BE FINISHED SAFELY. The memory stays booked to this module
	 * FOREVER and is never reclaimed, reused, or torn down again.
	 *
	 * Two ways in, both from NxcMapUnmap: COMMIT returned FAILED (the contract calls that
	 * unrecoverable -- PREPARE already promised teardown was possible, so the module is now in a state
	 * neither side can describe), or the DRAIN never reached ActiveCount == 0.
	 *
	 * ⚠ LEAKING IS THE CORRECT OUTCOME HERE, not a shortcut. Both cases mean "something may still be
	 * executing inside this image". Reclaiming would hand those pages to the next module and turn a
	 * contained leak into cross-module corruption that surfaces far from its cause. The arena is a
	 * fixed 16 MB reservation, so the worst case is a bounded loss of address space that a reboot
	 * clears -- traded against a class of bug that is close to undebuggable.
	 *
	 * Kept DISTINCT from Valid rather than folded into it: the extent is still allocated and must
	 * still be reported as used, so the slot cannot simply be freed, and it must never be presented as
	 * a healthy running module either.
	 */
	BOOLEAN                  Zombie;

	/*
	 * ONE HOST API PER MODULE, stored HERE rather than in the module's own image.
	 *
	 * Two reasons, both load-bearing:
	 *   - Owner is per-module, so a single shared instance could not carry it. Owner is what makes
	 *     "reclaim everything this module allocated" exactly true at teardown.
	 *   - It must outlive nothing and precede nothing. Living in NexusCore's own .data means the
	 *     module can be unmapped and its memory poisoned without leaving a dangling structure the
	 *     host still points at -- the failure v1's unmap actually produced.
	 */
	NEXUS_HOST_API           Host;
} NXC_MODULE_SLOT;

static NXC_MODULE_SLOT gModules[NXC_MAX_MODULES];

/*
 * ============================================================================================
 * MODULE-OWNED COMMANDS. A mapped module can claim an opcode and be driven from usermode.
 * ============================================================================================
 *
 * Small fixed table, no allocation: this is looked at on every command and lives for the life of
 * the driver. NXC_MAX_MODULES modules x a few opcodes each is the realistic ceiling.
 *
 * ⚠ EVERY ENTRY IS A FUNCTION POINTER INTO A MODULE'S IMAGE -- memory that unmap POISONS and then
 * hands to the next module. A stale entry here does not merely dangle; it makes a usermode opcode
 * execute whatever the NEXT module happens to place at that address. That is why registrations are
 * cleared at teardown (NxcCommandUnregisterOwner) and why the handler is bounds-checked at
 * registration rather than trusted.
 */
#define NXC_MAX_MODULE_COMMANDS 32u

typedef struct _NXC_MODULE_COMMAND
{
	ULONG          Opcode;      /* 0 = free slot                       */
	ULONG          Owner;       /* module id that registered it        */
	NXH_COMMAND_FN Handler;     /* inside that module's image, checked */
} NXC_MODULE_COMMAND;

static NXC_MODULE_COMMAND gModuleCommands[NXC_MAX_MODULE_COMMANDS];

/* Defined further down, next to the lookup and the owner-retire it belongs with; declared here
 * because NxcMapModule installs it into each slot's host struct long before that point. */
static NXH_U32 HostRegisterCommand(NXH_U64 Owner, NXH_U32 Opcode, NXH_COMMAND_FN Handler);

/*
 * Arena shims with the host-facing signature. The arena takes an extent id out-parameter because
 * NexusCore needs it; a module does not and must not -- handing a module the id that identifies its
 * own extent would let it free an extent it does not own by passing a different number.
 *
 * Ownership is therefore enforced BY THE SIGNATURE: a module can only ever name itself.
 */
static void*
HostAlloc(
	NXH_U64 Owner,
	NXH_U32 Bytes
	)
{
	ULONG ExtentId = 0;
	return NxcArenaAllocFor((ULONG)Owner, Bytes, &ExtentId);
}

static void
HostFree(
	NXH_U64 Owner,
	void*   Block
	)
{
	/*
	 * ⚠ THIS WAS A NO-OP UNTIL, and the no-op was MEASURABLY WRONG.
	 *
	 * The old reasoning: the arena freed only by extent id, a module holds only a pointer, reverse
	 * mapping was "real work the arena does not expose", so reclaim was left to NxcArenaFreeOwner at
	 * teardown -- "correct, just coarser". The comment even congratulated itself for saying so out loud
	 * rather than shipping a silent no-op.
	 *
	 * It was not merely coarser. NexusTestModule allocates 4096 bytes and frees them, with its own
	 * comment insisting it must not leak "because a test module that leaks an extent would make every
	 * subsequent arena reading a lie". Because this returned without freeing, the arena reported 32 KB
	 * used for a 28 KB module -- and I explained that 4 KB away as a guard page, which was wrong twice
	 * over. A no-op Free is indistinguishable from a working one until something counts bytes.
	 *
	 * The lookup being avoided is a bounded linear scan under the arena lock. NxcArenaFreeFor does it,
	 * and checks the owner so a module cannot free an extent it does not own.
	 */
	CONST NTSTATUS Status = NxcArenaFreeFor((ULONG)Owner, Block);
	if (!NT_SUCCESS(Status))
	{
		/*
		 * Reported, not swallowed. A module freeing a pointer it never owned -- or freeing twice -- is a
		 * bug in that module, and the arena refusing it is the correct outcome; hiding the refusal would
		 * leave the module believing memory was released.
		 */
		MapLog("host Free(%p) by owner %llu REFUSED 0x%08X (not a live extent it owns)\n",
		       Block, (unsigned long long)Owner, Status);
	}
}

void
NxcMapInit(
	_In_opt_ void* NtBase,
	_In_ ULONG NtSize
	)
{
	gNtBase = (UCHAR*)NtBase;
	gNtSize = NtSize;
	for (ULONG i = 0; i < NXC_MAX_MODULES; i++)
		gModules[i].Valid = FALSE;
}

static NXP_NT64*
NtHeaders(
	UCHAR* Base,
	ULONG Size
	)
{
	if (Base == NULL || Size < sizeof(NXP_DOS))
		return NULL;
	CONST NXP_DOS* Dos = (CONST NXP_DOS*)Base;
	if (Dos->e_magic != 0x5A4D)                         /* 'MZ' */
		return NULL;
	if (Dos->e_lfanew == 0 || Dos->e_lfanew + sizeof(NXP_NT64) > Size)
		return NULL;
	NXP_NT64* Nt = (NXP_NT64*)(Base + Dos->e_lfanew);
	if (Nt->Signature != 0x00004550)                    /* 'PE\0\0' */
		return NULL;
	if (Nt->OptionalHeader.Magic != 0x20B)              /* PE32+ */
		return NULL;
	return Nt;
}

/*
 * ============================================================================================
 * WHICH refusal, not just THAT there was one.
 * ============================================================================================
 *
 * NxcMapModule returns STATUS_INVALID_IMAGE_FORMAT from SEVENTEEN places. A `map` that comes back
 * 0xC000007B therefore says only "something about the image was wrong", and answering "which"
 * previously meant reconstructing every check by hand against the file offline -- which I did, got
 * a clean pass on all of them, and still had a failing map. A signal that cannot distinguish its
 * own causes is the failure shape this project keeps paying for; PteProbeDiag exists for exactly
 * this reason on the page-table side.
 *
 * __LINE__ rather than a named enum deliberately: there is nothing to keep in sync, it cannot drift
 * from the code it describes, and "refused at MapModule.c:443" points at the precise check. The
 * cost is that line numbers move when the file is edited -- which is fine, because the number is
 * always read against the build it came from, never stored.
 */
static ULONG gLastRefusalLine = 0;

/* NXCMD_SCRUB_* / NXCMD_MAP_* bits from the most recent map, surfaced the same way. */
static NXCMD_U32 gLastDiagFlags = 0;

NXCMD_U32
NxcMapLastDiagFlags(
	void
	)
{
	return gLastDiagFlags;
}

static NTSTATUS
MapRefuseAt(
	_In_ ULONG Line,
	_In_ NTSTATUS Status
	)
{
	gLastRefusalLine = Line;
	return Status;
}

ULONG
NxcMapLastRefusalLine(
	void
	)
{
	return gLastRefusalLine;
}

/**
 * Resolve an export by name from a mapped image. Used for ntoskrnl imports AND for finding the
 * module's own descriptor -- one walker, two callers, so a bug shows up in both rather than hiding.
 */
static void*
FindExport(
	UCHAR* ImageBase,
	ULONG ImageSize,
	PCSTR Name
	)
{
	NXP_NT64* Nt = NtHeaders(ImageBase, ImageSize);
	if (Nt == NULL || Nt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_EXPORT)
		return NULL;

	CONST ULONG DirRva = Nt->OptionalHeader.Directory[NXP_DIR_EXPORT].VirtualAddress;
	CONST ULONG DirSize = Nt->OptionalHeader.Directory[NXP_DIR_EXPORT].Size;
	if (DirRva == 0 || DirSize == 0 || DirRva + DirSize > ImageSize)
		return NULL;

	CONST NXP_EXPORT_DIR* Exp = (CONST NXP_EXPORT_DIR*)(ImageBase + DirRva);
	if (Exp->AddressOfNames == 0 || Exp->AddressOfFunctions == 0 ||
		Exp->AddressOfNameOrdinals == 0)
		return NULL;
	if (Exp->AddressOfNames + Exp->NumberOfNames * sizeof(ULONG) > ImageSize)
		return NULL;

	CONST ULONG* Names = (CONST ULONG*)(ImageBase + Exp->AddressOfNames);
	CONST USHORT* Ordinals = (CONST USHORT*)(ImageBase + Exp->AddressOfNameOrdinals);
	CONST ULONG* Functions = (CONST ULONG*)(ImageBase + Exp->AddressOfFunctions);

	for (ULONG i = 0; i < Exp->NumberOfNames; i++)
	{
		if (Names[i] == 0 || Names[i] >= ImageSize)
			continue;
		CONST CHAR* Candidate = (CONST CHAR*)(ImageBase + Names[i]);

		ULONG k = 0;
		while (Candidate[k] != '\0' && Name[k] != '\0' && Candidate[k] == Name[k])
			k++;
		if (Candidate[k] != '\0' || Name[k] != '\0')
			continue;

		if (Ordinals[i] >= Exp->NumberOfFunctions)
			return NULL;
		CONST ULONG FuncRva = Functions[Ordinals[i]];
		if (FuncRva == 0 || FuncRva >= ImageSize)
			return NULL;

		/*
		 * Reject FORWARDED exports. A forwarder's "address" points into the export directory at a
		 * "Dll.Function" string, not code -- calling it jumps into ASCII. The EFI mapper never had to
		 * care because nothing it resolved was forwarded; at runtime, refusing explicitly is cheaper
		 * than the bugcheck.
		 */
		if (FuncRva >= DirRva && FuncRva < DirRva + DirSize)
			return NULL;

		return ImageBase + FuncRva;
	}
	return NULL;
}

/** Apply base relocations for Delta. Mirrors the EFI side's PeRelocate.h walk deliberately. */
static BOOLEAN
ApplyRelocations(
	UCHAR* Base,
	ULONG Size,
	LONGLONG Delta
	)
{
	if (Delta == 0)
		return TRUE;

	NXP_NT64* Nt = NtHeaders(Base, Size);
	if (Nt == NULL || Nt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_BASERELOC)
		return FALSE;

	CONST ULONG DirRva = Nt->OptionalHeader.Directory[NXP_DIR_BASERELOC].VirtualAddress;
	CONST ULONG DirSize = Nt->OptionalHeader.Directory[NXP_DIR_BASERELOC].Size;
	if (DirRva == 0 || DirSize == 0 || DirRva + DirSize > Size)
		return FALSE;

	ULONG Offset = 0;
	while (Offset < DirSize)
	{
		CONST NXP_BASE_RELOC* Block = (CONST NXP_BASE_RELOC*)(Base + DirRva + Offset);
		if (Block->SizeOfBlock < sizeof(NXP_BASE_RELOC) ||
			Offset + Block->SizeOfBlock > DirSize)
			return FALSE;

		CONST ULONG Count = (Block->SizeOfBlock - sizeof(NXP_BASE_RELOC)) / sizeof(USHORT);
		CONST USHORT* Entries = (CONST USHORT*)((CONST UCHAR*)Block + sizeof(NXP_BASE_RELOC));

		for (ULONG i = 0; i < Count; i++)
		{
			CONST USHORT Type = (USHORT)(Entries[i] >> 12);
			CONST ULONG Where = Block->VirtualAddress + (Entries[i] & 0x0FFF);

			if (Type == 0)                    /* IMAGE_REL_BASED_ABSOLUTE: padding */
				continue;
			if (Type != 10)                   /* DIR64 is the only type x64 images use */
				return FALSE;
			if (Where + sizeof(ULONGLONG) > Size)
				return FALSE;

			*(ULONGLONG*)(Base + Where) += (ULONGLONG)Delta;
		}
		Offset += Block->SizeOfBlock;
	}
	return TRUE;
}

/**
 * Seed the /GS security cookie in a mapped module.
 *
 * ============================================================================================
 * -- the EFI mapper does this and the RUNTIME mapper did not
 * ============================================================================================
 *
 * A manually mapped image gets no CRT init, so nothing calls __security_init_cookie(), and a mapped
 * driver must NOT call it itself (BlackAlien's testdriver says so outright). If the image carries a
 * load config with a SecurityCookie pointer and the cookie is left at its file value, every
 * /GS-instrumented function corrupts its own frame check -- and __security_check_cookie's failure path
 * is __fastfail, i.e. an immediate bugcheck with no diagnostic.
 *
 * ⚠ WHY THIS WAS INVISIBLE, which is the part worth remembering: NexusCore.sys DOES carry a load
 * config with a live SecurityCookie (measured: rva 0x7390, cookie VA 0x1800080c0) and the EFI mapper
 * seeds it correctly -- so the boot path was always fine. NexusTestModule.sys carries NO load config
 * at all (rva 0), so the only module ever pushed through the runtime mapper could not exercise this.
 * A passing test proved nothing here. Exactly the same shape as the PE32+ bug: the EFI path correct,
 * the runtime path wrong, and the gap hidden because only one of them was being tested.
 *
 * SentinelHV and NexusKernel are ordinary /GS-enabled drivers, so this WOULD have fired on the first
 * real module.
 *
 * Reading the load config at RUNTIME from directory[10], rather than from the build-time constants the
 * EFI side bakes in via embed_driver.py -- we do not know a runtime module's layout ahead of time.
 */
static void
SeedSecurityCookie(
	UCHAR* Base,
	ULONG  Size
	)
{
	NXP_NT64* CONST Nt = NtHeaders(Base, Size);
	if (Nt == NULL || Nt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_LOAD_CONFIG)
		return;

	CONST ULONG DirRva  = Nt->OptionalHeader.Directory[NXP_DIR_LOAD_CONFIG].VirtualAddress;
	CONST ULONG DirSize = Nt->OptionalHeader.Directory[NXP_DIR_LOAD_CONFIG].Size;
	if (DirRva == 0 || DirSize == 0 || DirRva + DirSize > Size)
		return;                      /* no load config: nothing to seed, and that is normal */

	/* Older/smaller load configs stop before SecurityCookie. Refuse to read past what exists. */
	if (DirSize < FIELD_OFFSET(NXP_LOAD_CONFIG64, SecurityCookie) + sizeof(ULONGLONG))
		return;

	CONST NXP_LOAD_CONFIG64* CONST Cfg = (CONST NXP_LOAD_CONFIG64*)(Base + DirRva);

	/*
	 * The field holds a VIRTUAL ADDRESS of the cookie variable against the image's LINK base.
	 * ApplyRelocations has already rewritten it to our mapped base, which is why this must run AFTER
	 * relocations -- so convert back to an RVA and bounds-check before dereferencing.
	 */
	CONST ULONGLONG CookieVa = Cfg->SecurityCookie;
	if (CookieVa < (ULONGLONG)(ULONG_PTR)Base)
		return;
	CONST ULONGLONG CookieRva = CookieVa - (ULONGLONG)(ULONG_PTR)Base;
	if (CookieRva + sizeof(ULONGLONG) > (ULONGLONG)Size)
		return;

	/* Mix independent sources; a bare TSC is guessable across a reboot. */
	ULONGLONG Cookie = __rdtsc();
	Cookie ^= ((ULONGLONG)(ULONG_PTR)Base << 13);
	Cookie ^= (ULONGLONG)Size * 0x9E3779B97F4A7C15ULL;
	Cookie *= 0xFF51AFD7ED558CCDULL;
	Cookie ^= (Cookie >> 33);
	Cookie &= 0x0000FFFFFFFFFFFFULL;          /* x64 keeps the low 48 bits */

	/*
	 * Reject the two values the GS check reads as "never initialised": zero and the compiler default.
	 * Landing on either silently disables the protection this function exists to enable, which is
	 * worse than not running -- it would look done.
	 */
	if (Cookie == 0 || Cookie == 0x00002B992DDFA232ULL)
		Cookie = 0x0000123456789ABCULL ^ __rdtsc();

	*(ULONGLONG*)(Base + CookieRva) = Cookie;
	gLastDiagFlags |= NXCMD_MAP_COOKIE_SEED;
	MapLog("seeded /GS cookie at rva %#llx\n", CookieRva);
}

/**
 * Erase the import metadata from a mapped module, then CHECK that it is gone.
 *
 * ============================================================================================
 * FOUND BY STEP-BY-STEP DIFF AGAINST THE EFI MAPPER,
 * ============================================================================================
 *
 * The EFI mapper has always done this (ScrubImportMetadata). The runtime mapper never did -- grep for
 * "scrub" in this file returned nothing. So every module mapped at runtime kept its full import
 * directory resident: descriptors, the module-name string "ntoskrnl.exe", and every imported function
 * name, all sitting in memory belonging to no loaded module.
 *
 * Why it was invisible: our own modules are built to have NO import table at all (they reach the
 * kernel through NEXUS_HOST_API), and NexusTestModule accordingly has none -- so the only module ever
 * mapped had nothing to scrub. Third time this exact shape has bitten: the EFI path correct, the
 * runtime path absent, and the gap hidden because the only test subject could not reach it.
 *
 * BindImports exists precisely to accept modules that DO import, and SentinelHV and NexusKernel are
 * ordinary drivers that were never written against the host API. They will arrive with full import
 * tables.
 *
 * Returns the NXM_SCRUB_* bits so the outcome reaches usermode. "Scrubbed" and "nothing to scrub" are
 * BOTH good and must be distinguishable -- the EFI side learned that when a payload with no imports
 * reported "imports scrubbed: no", which reads as a failure and is in fact the strongest result.
 */
static NXCMD_U32
ScrubImportMetadata(
	UCHAR* Base,
	ULONG  Size
	)
{
	NXP_NT64* CONST Nt = NtHeaders(Base, Size);
	if (Nt == NULL || Nt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_IMPORT)
		return NXCMD_SCRUB_NO_IMPORTS;

	CONST ULONG DirRva  = Nt->OptionalHeader.Directory[NXP_DIR_IMPORT].VirtualAddress;
	CONST ULONG DirSize = Nt->OptionalHeader.Directory[NXP_DIR_IMPORT].Size;
	if (DirRva == 0 || DirSize == 0 || DirRva + DirSize > Size)
		return NXCMD_SCRUB_NO_IMPORTS;

	for (NXP_IMPORT_DESC* Desc = (NXP_IMPORT_DESC*)(Base + DirRva); Desc->Name != 0; Desc++)
	{
		if ((UCHAR*)(Desc + 1) > Base + Size || Desc->Name >= Size)
			break;

		CONST ULONG LookupRva = Desc->Characteristics != 0 ? Desc->Characteristics : Desc->FirstThunk;

		/*
		 * Zero the function-name strings BEFORE the lookup table that points at them -- the table is
		 * how we find them, so erasing it first would orphan every name and leave them resident.
		 */
		if (LookupRva != 0 && LookupRva < Size)
		{
			ULONGLONG* Lookup = (ULONGLONG*)(Base + LookupRva);
			for (; *Lookup != 0; Lookup++)
			{
				if ((*Lookup & 0x8000000000000000ULL) != 0)
					continue;                       /* by ordinal: no name string exists */
				CONST ULONG NameRva = (ULONG)(*Lookup & 0xFFFFFFFFULL);
				if (NameRva + sizeof(USHORT) >= Size)
					continue;

				CHAR* CONST Name = (CHAR*)(Base + NameRva + sizeof(USHORT));
				ULONG Len = 0;
				while (NameRva + sizeof(USHORT) + Len < Size && Name[Len] != '\0')
					Len++;
				RtlZeroMemory(Base + NameRva, sizeof(USHORT) + Len);
			}

			/* Then the table itself, up to and including its NULL terminator. */
			ULONGLONG* Walk = (ULONGLONG*)(Base + LookupRva);
			ULONG Entries = 0;
			while ((LookupRva + (Entries + 1) * sizeof(ULONGLONG)) <= Size && Walk[Entries] != 0)
				Entries++;
			RtlZeroMemory(Base + LookupRva, (Entries + 1) * sizeof(ULONGLONG));
		}

		/* The module name, e.g. "ntoskrnl.exe". */
		CHAR* CONST Module = (CHAR*)(Base + Desc->Name);
		ULONG ModLen = 0;
		while (Desc->Name + ModLen < Size && Module[ModLen] != '\0')
			ModLen++;
		RtlZeroMemory(Module, ModLen);
	}

	RtlZeroMemory(Base + DirRva, DirSize);

	/*
	 * And the DIRECTORY ENTRY, so nothing can walk back to a table we just erased. Safe here because
	 * this runs before NxcPteProtectImage makes the header page read-only.
	 */
	Nt->OptionalHeader.Directory[NXP_DIR_IMPORT].VirtualAddress = 0;
	Nt->OptionalHeader.Directory[NXP_DIR_IMPORT].Size = 0;

	NXCMD_U32 Flags = NXCMD_SCRUB_DONE;

	/*
	 * VERIFY, do not assume. The point of scrubbing is that a string is gone; "the code that erases it
	 * ran" is not the same claim. Re-scan the mapped image for "ntoskrnl" case-insensitively.
	 *
	 * ⚠ THAT NEEDLE ONLY, deliberately -- matching the EFI side. Scanning for API names like
	 * "ExAllocatePool2" would match our own DbgPrint format strings, which are not import metadata and
	 * are a separate accepted exposure. A verifier that fails for the wrong reason trains you to
	 * ignore it.
	 */
	CONST CHAR Needle[] = "ntoskrnl";
	CONST ULONG NeedleLen = sizeof(Needle) - 1;
	BOOLEAN Found = FALSE;
	for (ULONG i = 0; i + NeedleLen <= Size && !Found; i++)
	{
		ULONG j = 0;
		for (; j < NeedleLen; j++)
		{
			CHAR c = (CHAR)Base[i + j];
			if (c >= 'A' && c <= 'Z')
				c = (CHAR)(c + ('a' - 'A'));
			if (c != Needle[j])
				break;
		}
		if (j == NeedleLen)
			Found = TRUE;
	}
	if (!Found)
		Flags |= NXCMD_SCRUB_VERIFIED;

	MapLog("import metadata scrubbed%s\n",
	       Found ? " -- but 'ntoskrnl' RESIDUE REMAINS" : " and verified absent");
	return Flags;
}

/** Bind every import against ntoskrnl. Refuses anything else, exactly like the EFI mapper. */
static NTSTATUS
BindImports(
	UCHAR* Base,
	ULONG Size
	)
{
	NXP_NT64* Nt = NtHeaders(Base, Size);
	if (Nt == NULL)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	if (Nt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_IMPORT)
		return STATUS_SUCCESS;                 /* no imports at all is legal */

	CONST ULONG DirRva = Nt->OptionalHeader.Directory[NXP_DIR_IMPORT].VirtualAddress;
	if (DirRva == 0)
		return STATUS_SUCCESS;
	if (DirRva >= Size)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	for (NXP_IMPORT_DESC* Desc = (NXP_IMPORT_DESC*)(Base + DirRva); Desc->Name != 0; Desc++)
	{
		if ((UCHAR*)(Desc + 1) > Base + Size || Desc->Name >= Size)
			return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

		/*
		 * ntoskrnl only. We resolve one module's exports, so an import from hal.dll or a WDF library
		 * would leave a NULL thunk that bugchecks on first call with nothing pointing at the cause.
		 * Refuse the whole map instead -- the module author can see this message; a future crash dump
		 * cannot.
		 */
		CONST CHAR* Module = (CONST CHAR*)(Base + Desc->Name);
		if (!((Module[0] == 'n' || Module[0] == 'N') &&
		      (Module[1] == 't' || Module[1] == 'T') &&
		      (Module[2] == 'o' || Module[2] == 'O')))
		{
			MapLog("module imports from '%s' -- only ntoskrnl.exe is resolvable, REFUSED\n", Module);
			return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
		}

		CONST ULONG LookupRva = Desc->Characteristics != 0 ? Desc->Characteristics : Desc->FirstThunk;
		if (LookupRva == 0 || LookupRva >= Size || Desc->FirstThunk >= Size)
			return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

		ULONGLONG* Lookup = (ULONGLONG*)(Base + LookupRva);
		ULONGLONG* Target = (ULONGLONG*)(Base + Desc->FirstThunk);

		for (; *Lookup != 0; Lookup++, Target++)
		{
			if ((*Lookup & 0x8000000000000000ULL) != 0)
			{
				MapLog("module imports by ORDINAL -- unsupported, REFUSED\n");
				return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
			}

			CONST ULONG NameRva = (ULONG)(*Lookup & 0xFFFFFFFFULL);
			if (NameRva + sizeof(USHORT) >= Size)
				return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

			PCSTR FuncName = (PCSTR)(Base + NameRva + sizeof(USHORT));
			void* Resolved = FindExport(gNtBase, gNtSize, FuncName);
			if (Resolved == NULL)
			{
				MapLog("unresolved import '%s', REFUSED\n", FuncName);
				return MapRefuseAt(__LINE__, STATUS_PROCEDURE_NOT_FOUND);
			}
			*Target = (ULONGLONG)(ULONG_PTR)Resolved;
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS
NxcMapModule(
	_In_reads_bytes_(ImageBytes) const void* RawImage,
	_In_ ULONG ImageBytes,
	_Out_ ULONG* OutModuleId
	)
{
	if (OutModuleId != NULL)
		*OutModuleId = NXC_MODULE_NONE;
	if (RawImage == NULL || ImageBytes < 0x200)
		return MapRefuseAt(__LINE__, STATUS_INVALID_PARAMETER);
	if (gNtBase == NULL || gNtSize == 0)
	{
		MapLog("no ntoskrnl base from the boot block -- cannot bind imports\n");
		return MapRefuseAt(__LINE__, STATUS_DEVICE_NOT_READY);
	}

	/*
	 * Reset per-map diagnostics. Without this they OR together across maps and the second module
	 * inherits the first one's flags -- a stale-success report, which is the failure shape this whole
	 * review keeps turning up.
	 *
	 * ⚠ THE REFUSAL LINE WAS MISSED HERE, and this comment sat directly above the omission (fixed
	 * MEASURED on hardware). gLastRefusalLine was set by MapRefuseAt and cleared by
	 * nothing, so it survived across operations: a `map` that SUCCEEDED printed
	 * "refused: MapModule.c:1252 <-- the exact check that rejected this image" -- a line left behind
	 * by the PREVIOUS unmap. A successful operation reporting someone else's refusal reason.
	 *
	 * Cleared for BOTH map and unmap. Any diagnostic that outlives the operation it describes will
	 * eventually be read as belonging to the current one.
	 */
	gLastDiagFlags   = 0;
	gLastRefusalLine = 0;

	/* Validate the raw PE before committing an extent to it. */
	NXP_NT64* SrcNt = NtHeaders((UCHAR*)RawImage, ImageBytes);
	if (SrcNt == NULL)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	if (SrcNt->FileHeader.Machine != 0x8664)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	CONST ULONG SizeOfImage = SrcNt->OptionalHeader.SizeOfImage;
	CONST ULONG SizeOfHeaders = SrcNt->OptionalHeader.SizeOfHeaders;
	CONST ULONG EntryRva = SrcNt->OptionalHeader.AddressOfEntryPoint;
	if (SizeOfImage == 0 || SizeOfHeaders > ImageBytes || EntryRva >= SizeOfImage)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	/*
	 * ============================================================================================
	 * SECTIONS MUST BE PAGE-ALIGNED, because page protection cannot be finer than a page.
	 * ============================================================================================
	 *
	 * And it is a hole I half-closed myself. When the header-page guard
	 * went in, its comment recorded that "MapModule validates Machine and PE32+ and does NOT validate
	 * SectionAlignment" -- then guarded only the header range and left the SECTION side of the same
	 * hole open.
	 *
	 * NxcPteProtectImage applies each section's own characteristics to the PAGES covering it. With
	 * SectionAlignment below 0x1000 two sections share a page, both protect calls hit that page, and
	 * the LAST ONE WINS. Both outcomes are bad and neither is reported:
	 *
	 *   .rdata wins over .text  -> the code page becomes non-executable, and the entry call faults
	 *   .text wins over .data   -> a writable data page becomes EXECUTABLE, silently breaking W^X
	 *                              on the one image we went to all this trouble to protect
	 *
	 * Every real x64 driver uses 0x1000, so this is not a case that arises by accident -- which is
	 * exactly why it is worth refusing rather than trusting. A crafted image is the input this path
	 * exists to survive.
	 *
	 * Refused here rather than clamped in Pte.c: an image whose sections cannot be independently
	 * protected is not one we can honour the protection contract for, and the contract is the point.
	 */
	if (SrcNt->OptionalHeader.SectionAlignment < NXC_ARENA_ALIGN)
	{
		MapLog("SectionAlignment %u < page size -- sections would share pages and protections would\n"
		       "        collide, REFUSED\n", SrcNt->OptionalHeader.SectionAlignment);
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	}

	/*
	 * REFUSE a module carrying a TLS directory. We do not process TLS callbacks, and silently
	 * skipping them is the worst option available: a C/C++ module's static initialisers would never
	 * run, so it would start with uninitialised state and fail later in a way that looks like a logic
	 * bug in the module rather than a missing step in the mapper.
	 *
	 * MEASURED before choosing to refuse rather than implement: SentinelHV.sys,
	 * NexusKernel.sys and NexusCore.sys ALL have TLS rva=0 size=0. Nothing we intend to map uses it,
	 * so implementing the walk would be untested code guarding a case that does not occur -- while
	 * refusing costs one line and converts a silent failure into a loud one.
	 *
	 * trident-dll-manual-mapper/injector.cpp:303 does implement the walk if this ever becomes real.
	 */
	if (SrcNt->OptionalHeader.NumberOfRvaAndSizes > NXP_DIR_TLS &&
		SrcNt->OptionalHeader.Directory[NXP_DIR_TLS].Size != 0)
	{
		MapLog("module has a TLS directory -- callbacks are NOT processed, REFUSED rather than "
		       "silently skipped\n");
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	}

	/*
	 * Require relocations up front. Without them the image can only run at its link base, which the
	 * arena will not honour. Caught here rather than after a successful-looking map.
	 */
	if (SrcNt->OptionalHeader.NumberOfRvaAndSizes <= NXP_DIR_BASERELOC ||
		SrcNt->OptionalHeader.Directory[NXP_DIR_BASERELOC].Size == 0)
	{
		MapLog("module has NO base relocations -- cannot be mapped anywhere, REFUSED\n");
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	}

	ULONG Slot = NXC_MODULE_NONE;
	for (ULONG i = 0; i < NXC_MAX_MODULES; i++)
	{
		if (!gModules[i].Valid) { Slot = i; break; }
	}
	if (Slot == NXC_MODULE_NONE)
		return MapRefuseAt(__LINE__, STATUS_INSUFFICIENT_RESOURCES);

	ULONG ExtentId = 0;
	/*
	 * Allocated under the MODULE's own id, not the host's. Teardown reclaims by owner, so an image
	 * booked to NXC_OWNER_HOST would survive its module's unmap -- leaking the largest extent of all,
	 * and leaving executable code resident after the module was declared gone.
	 */
	UCHAR* Base = (UCHAR*)NxcArenaAllocFor(Slot, SizeOfImage, &ExtentId);
	if (Base == NULL)
	{
		MapLog("arena has no extent for %u KB (largest allocatable %u KB)\n",
		       SizeOfImage / 1024, NxcArenaLargestFree() / 1024);
		return MapRefuseAt(__LINE__, STATUS_INSUFFICIENT_RESOURCES);
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	/* Headers, then sections to their RVAs -- a raw file is not a mapped image. */
	for (ULONG i = 0; i < SizeOfHeaders; i++)
		Base[i] = ((CONST UCHAR*)RawImage)[i];

	CONST NXP_SECTION* Sections = (CONST NXP_SECTION*)
		((CONST UCHAR*)&SrcNt->OptionalHeader + SrcNt->FileHeader.SizeOfOptionalHeader);

	for (USHORT i = 0; i < SrcNt->FileHeader.NumberOfSections; i++)
	{
		CONST NXP_SECTION* S = &Sections[i];
		if (S->SizeOfRawData == 0)
			continue;                          /* .bss-style: arena already zeroed it */
		if ((ULONGLONG)S->PointerToRawData + S->SizeOfRawData > ImageBytes ||
			(ULONGLONG)S->VirtualAddress + S->SizeOfRawData > SizeOfImage)
		{
			MapLog("section %u out of bounds, REFUSED\n", i);
			Status = MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
			goto Fail;
		}
		for (ULONG b = 0; b < S->SizeOfRawData; b++)
			Base[S->VirtualAddress + b] = ((CONST UCHAR*)RawImage)[S->PointerToRawData + b];
	}

	if (!ApplyRelocations(Base, SizeOfImage,
	                      (LONGLONG)((ULONGLONG)(ULONG_PTR)Base - SrcNt->OptionalHeader.ImageBase)))
	{
		MapLog("relocation walk failed, REFUSED\n");
		Status = MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
		goto Fail;
	}

	/*
	 * AFTER relocations, BEFORE the entry runs. Relocations rewrite the SecurityCookie field to our
	 * mapped base, so seeding earlier would read a link-base VA; the entry may execute
	 * /GS-instrumented code on its very first frame, so seeding later is too late.
	 */
	SeedSecurityCookie(Base, SizeOfImage);

	Status = BindImports(Base, SizeOfImage);
	if (!NT_SUCCESS(Status))
		goto Fail;

	/*
	 * Scrub AFTER binding -- the names are what binding needs, so erasing them first would break the
	 * bind -- and BEFORE NxcPteProtectImage, because clearing the import DIRECTORY ENTRY writes into
	 * the header page, which the protection pass makes read-only.
	 */
	gLastDiagFlags |= ScrubImportMetadata(Base, SizeOfImage);

	/*
	 * ============================================================================================
	 * THE GATE: no valid teardown descriptor, no residency. Checked BEFORE the entry point runs.
	 * ============================================================================================
	 *
	 * This is why the contract was built before this command. A module that cannot be torn down must
	 * never become resident -- once its DriverEntry has run and registered callbacks, the only
	 * remaining options are leaving it mapped forever or reproducing v1's instability. Refusing here
	 * costs one log line.
	 */
	NEXUS_MODULE_DESCRIPTOR* Desc =
		(NEXUS_MODULE_DESCRIPTOR*)FindExport(Base, SizeOfImage, NEXUS_MODULE_EXPORT_NAME);
	if (Desc == NULL)
	{
		MapLog("module exports no '%s' -- not unmappable, REFUSED\n", NEXUS_MODULE_EXPORT_NAME);
		Status = MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
		goto Fail;
	}
	if (Desc->Magic != NEXUS_MODULE_MAGIC)
	{
		MapLog("descriptor magic 0x%llX wrong, REFUSED\n", Desc->Magic);
		Status = MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
		goto Fail;
	}
	if (Desc->Abi != NEXUS_MODULE_ABI ||
		Desc->StructSize != (NXM_U32)sizeof(NEXUS_MODULE_DESCRIPTOR))
	{
		MapLog("descriptor abi=%u size=%u, expected %u/%u, REFUSED\n",
		       Desc->Abi, Desc->StructSize,
		       (ULONG)NEXUS_MODULE_ABI, (ULONG)sizeof(NEXUS_MODULE_DESCRIPTOR));
		Status = MapRefuseAt(__LINE__, STATUS_REVISION_MISMATCH);
		goto Fail;
	}
	if (Desc->Prepare == NULL || Desc->Commit == NULL)
	{
		MapLog("descriptor is missing Prepare/Commit -- not unmappable, REFUSED\n");
		Status = MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
		goto Fail;
	}

	/*
	 * ============================================================================================
	 * HAND THE MODULE ITS HOST API. Must happen BEFORE protections are applied.
	 * ============================================================================================
	 *
	 * Without this the module can do nothing legitimate: no import table it may rely on, no pool, and
	 * no way to name itself when allocating from the arena. Arena ownership was already implemented
	 * and was, until now, unreachable from a module -- bookkeeping for an operation nobody could
	 * perform.
	 *
	 * ORDER IS LOAD-BEARING, twice over:
	 *   - AFTER the descriptor has been validated, so we are writing into a structure we have proven
	 *     is ours (magic, ABI and size all checked above) rather than into an arbitrary export;
	 *   - BEFORE NxcPteProtectImage, because a module that declares its descriptor `const` puts it in
	 *     .rdata, and this write would fault the moment that section goes read-only. Ordering it here
	 *     means a const descriptor is merely wrong rather than fatal.
	 */
	gModules[Slot].Host.Magic      = NEXUS_HOST_MAGIC;
	gModules[Slot].Host.Abi        = NEXUS_HOST_ABI;
	gModules[Slot].Host.StructSize = (NXH_U32)sizeof(NEXUS_HOST_API);
	gModules[Slot].Host.Owner      = (NXH_U64)Slot;
	gModules[Slot].Host.Alloc      = HostAlloc;
	gModules[Slot].Host.Free       = HostFree;
	gModules[Slot].Host.Log        = (NXH_LOG_FN)NxcLogExt;
	gModules[Slot].Host.NtApi      = (void*)&NexusNtApi;
	gModules[Slot].Host.KernelBase = (NXH_U64)(ULONG_PTR)gNtBase;
	gModules[Slot].Host.KernelSize = (NXH_U32)gNtSize;
	gModules[Slot].Host.Reserved0  = 0;
	gModules[Slot].Host.RegisterCommand = HostRegisterCommand;

	Desc->Host = (NXM_U64)(ULONG_PTR)&gModules[Slot].Host;

	/*
	 * ============================================================================================
	 * PER-SECTION PAGE PROTECTIONS, applied BEFORE the entry point runs.
	 * ============================================================================================
	 *
	 * Everything up to here has been WRITING the image -- sections copied, relocations applied,
	 * imports bound. Tightening protections any earlier would mean fighting our own mapper for write
	 * access. Doing it any later means the module's DriverEntry has already executed out of memory
	 * that was writable while it ran, which is precisely the window worth closing.
	 *
	 * So: last write, first execution. The module gets RX code and NX data from the moment any of its
	 * code runs, matching what a normally loaded driver looks like.
	 *
	 * ⚠ FATAL ON FAILURE, CHANGED -- and this is a correctness rule now, not a hardening
	 * policy. It was previously non-fatal on the reasoning that an unprotected module is still a
	 * correctly mapped module, so refusing would turn hardening into a functional dependency.
	 *
	 * THAT REASONING DIED WITH THE NX ARENA. NexusCore now clears X across the whole arena at boot
	 * (see the block in NexusCore.c), so arena memory arrives non-executable and X is granted ONLY by
	 * this call, per section, from the section's own characteristics. A section that fails to get its
	 * protections applied therefore does not get its X bit either -- and if that section is .text,
	 * calling the entry point below is a guaranteed fault, not a degraded-but-working module.
	 *
	 * So there is no "runs unprotected" outcome available any more. The choice is refuse, or bugcheck
	 * a moment later with no connection back to here. Refusing costs one log line.
	 *
	 * REFUSED > 0 IS ALSO FATAL, not just an outright failure return. NxcPteProtectImage reports a
	 * per-section refusal through the counter and still returns success, because skipping one section
	 * beats abandoning the other six -- correct when the fallback was RWX, wrong now, because the one
	 * skipped section is exactly the one that will fault.
	 *
	 * Safe to `goto Fail` from here: this is BEFORE the entry point runs, so no module code has
	 * executed and the extent can be reclaimed without the teardown contract (see the Fail comment).
	 *
	 * BroadcastFlush = TRUE, and this is the reason the parameter exists: unlike NexusCore's own boot
	 * entry, this runs with every processor online. Any of them may hold a cached translation for
	 * these VAs, and a local INVLPG would leave other cores writing to pages we believe are
	 * read-only -- with no symptom until something is already corrupt.
	 */
	{
		UINT32 ProtApplied = 0;
		UINT32 ProtRefused = 0;
		CONST NTSTATUS ProtStatus =
			NxcPteProtectImage((UINT64)(ULONG_PTR)Base, SizeOfImage, TRUE, &ProtApplied, &ProtRefused);

		if (!NT_SUCCESS(ProtStatus))
		{
			MapLog("per-section protections FAILED 0x%08X -- arena is NX, so this module's code\n"
			       "        would fault on entry. REFUSED.\n", ProtStatus);
			Status = ProtStatus;
			goto Fail;
		}
		if (ProtRefused != 0)
		{
			MapLog("per-section protections: %u applied but %u REFUSED -- a refused section keeps\n"
			       "        the arena's NX, so entry would fault. REFUSED.\n",
			       ProtApplied, ProtRefused);
			Status = MapRefuseAt(__LINE__, STATUS_NOT_SUPPORTED);
			goto Fail;
		}

		MapLog("per-section protections: %u applied, 0 refused\n", ProtApplied);
	}

	/*
	 * Record BEFORE calling the entry: if the entry misbehaves, unmap still has what it needs.
	 *
	 * "What it needs" is Base/Size/Descriptor and the OWNER, which is Slot itself -- not an extent id.
	 * See the note in NXC_MODULE_SLOT for why storing one would be a trap.
	 */
	gModules[Slot].Valid = TRUE;
	gModules[Slot].Base = Base;
	gModules[Slot].Size = SizeOfImage;
	gModules[Slot].Descriptor = Desc;

	MapLog("mapped '%s' at %p (%u KB), descriptor ok, flags 0x%08X\n",
	       (PCSTR)Desc->Name, Base, SizeOfImage / 1024, Desc->Flags);

	/*
	 * Call the entry as DriverEntry(NULL, NULL) -- the same convention the EFI mapper uses for
	 * NexusCore, and the one umap documents for mapped drivers ("must be designed to function
	 * without a real driver object").
	 *
	 * ============================================================================================
	 * CALLED INLINE, DELIBERATELY -- and why that is safe HERE but not for NexusCore's own entry
	 * ============================================================================================
	 *
	 * Tier-2 research says a mapped driver's entry must return promptly or risk PatchGuard attention,
	 * with persistent work on a spawned thread. That constraint is REAL, but its severity depends
	 * entirely on WHO IS WAITING:
	 *
	 *   NexusCore's own entry  runs on the HIJACKED BOOT DRIVER'S INIT PATH. Blocking there stalls
	 *                          boot. That is the exposed case, and it is now MEASURED -- the driver
	 *                          records EntryDurationUs into the boot block and PlatformCtl flags
	 *                          anything over 50 ms.
	 *   THIS call             runs from a usermode-initiated `map` command, long after boot. Nothing
	 *                          on the boot path is waiting; a slow module stalls the caller's own
	 *                          request and nothing else.
	 *
	 * So inline is correct here, and it matches both references: BlackAlien's Mapper.cpp calls
	 * `driverEntry(nullptr, nullptr)` inline, and v1's mapper did too -- v1 put its long work on
	 * PsCreateSystemThread INSIDE the modules themselves, not in the mapper.
	 * The obligation belongs to the module, which is where NexusModule.h states it.
	 *
	 * ⚠ IF THIS EVER MOVES ONTO A BOOT PATH, revisit: it would then need the module's status without
	 * blocking, which inline cannot give.
	 */
	typedef NTSTATUS (*NXC_ENTRY_FN)(PDRIVER_OBJECT, PUNICODE_STRING);
	CONST NXC_ENTRY_FN Entry = (NXC_ENTRY_FN)(Base + EntryRva);
	CONST NTSTATUS EntryStatus = Entry(NULL, NULL);

	if (!NT_SUCCESS(EntryStatus))
	{
		/*
		 * The entry failed. DO NOT free the extent here: the module may already have registered
		 * callbacks before failing, and freeing now is exactly the v1 bug. Leave it resident and let
		 * `unmap` run the full contract -- Prepare/Commit exist for precisely this state.
		 */
		MapLog("entry returned 0x%08X -- module left RESIDENT; run unmap to tear it down safely\n",
		       EntryStatus);
		if (OutModuleId != NULL)
			*OutModuleId = Slot;
		return EntryStatus;
	}

	if (OutModuleId != NULL)
		*OutModuleId = Slot;
	return STATUS_SUCCESS;

Fail:
	/*
	 * Safe to reclaim: every failure reaching here happens BEFORE the entry point ran, so no module
	 * code has executed and nothing can be registered or in flight. That is the only condition under
	 * which freeing without the teardown contract is legitimate.
	 *
	 * ⚠ EVERY `goto Fail` is also before NxcRegisterExceptionTable, so there is no dynamic function
	 * table to remove here. If a future failure path is added AFTER that call, it MUST unregister
	 * first -- a live table over a reclaimed extent makes the unwinder walk reused memory during the
	 * next unrelated exception anywhere in the system.
	 */
	/*
	 * ⚠ FREED BY BASE AND OWNER, NOT BY THE EXTENT ID. The id was produced by the allocation at the
	 * top of this function, and everything between there and here -- header copy, section copy,
	 * relocation, import binding -- can run alongside `NxcImageLoadNotify`, which allocates and frees
	 * arena extents from a notify callback on another thread. Every split and coalesce SHIFTS the
	 * extent array, so by the time this failure path runs the id can name a different extent, and
	 * freeing it would release someone else's memory. `Base` is the stable identity.
	 */
	if (Base != NULL)
		(void)NxcArenaFreeFor(Slot, Base);
	return Status;
}

/*
 * ============================================================================================
 * KERNEL MODULE LOOKUP -- walk PsLoadedModuleList to resolve a module name to base + size.
 * ============================================================================================
 *
 * Needed by NXCMD_OP_READ, which addresses a target by NAME rather than by address: an address
 * would be useless across boots (KASLR) and the caller has no way to learn it otherwise.
 *
 * PsLoadedModuleList is a DATA export from ntoskrnl, and FindExport resolves it exactly like a
 * function -- an export is an RVA, and the table does not care what lives there. So this needs no
 * new import, no ZwQuerySystemInformation, and no allocation.
 */

/*
 * The loader entry, as much of it as we need. Layout is Windows-internal and undocumented, which is
 * precisely why it is VALIDATED rather than trusted -- see NxcFindKernelModule.
 */
typedef struct _NXC_LDR_ENTRY
{
	LIST_ENTRY     InLoadOrderLinks;            /* 0x00 */
	LIST_ENTRY     InMemoryOrderLinks;          /* 0x10 */
	LIST_ENTRY     InInitializationOrderLinks;  /* 0x20 */
	PVOID          DllBase;                     /* 0x30 */
	PVOID          EntryPoint;                  /* 0x38 */
	ULONG          SizeOfImage;                 /* 0x40 */
	UNICODE_STRING FullDllName;                 /* 0x48 */
	UNICODE_STRING BaseDllName;                 /* 0x58 */
} NXC_LDR_ENTRY;

C_ASSERT(FIELD_OFFSET(NXC_LDR_ENTRY, DllBase)     == 0x30);
C_ASSERT(FIELD_OFFSET(NXC_LDR_ENTRY, SizeOfImage) == 0x40);
C_ASSERT(FIELD_OFFSET(NXC_LDR_ENTRY, BaseDllName) == 0x58);

/* ASCII vs UTF-16 compare, case-insensitive, bounded by the UNICODE_STRING's own Length. */
static BOOLEAN
LdrNameMatches(
	_In_ CONST UNICODE_STRING* Name,
	_In_z_ CONST CHAR* Wanted
	)
{
	if (Name->Buffer == NULL || Name->Length == 0)
		return FALSE;

	CONST USHORT Chars = (USHORT)(Name->Length / sizeof(WCHAR));
	ULONG i = 0;

	for (; i < Chars; i++)
	{
		CONST WCHAR w = Name->Buffer[i];
		CONST CHAR  c = Wanted[i];
		if (c == '\0')
			return FALSE;                       /* module name is longer than the request */
		if (w > 0x7F)
			return FALSE;                       /* non-ASCII cannot match an ASCII request */

		CONST CHAR lw = (w >= 'A' && w <= 'Z') ? (CHAR)(w + 32) : (CHAR)w;
		CONST CHAR lc = (c >= 'A' && c <= 'Z') ? (CHAR)(c + 32) : c;
		if (lw != lc)
			return FALSE;
	}

	return Wanted[i] == '\0';                   /* both ended together */
}

void*
NxcResolveNtExport(
	_In_z_ CONST CHAR* Name
	)
{
	if (gNtBase == NULL || gNtSize == 0)
		return NULL;
	return FindExport(gNtBase, gNtSize, Name);
}

/*
 * The running ntoskrnl's extent, for code that must SCAN it rather than look a name up.
 *
 * Needed by the SSDT resolver: the entire registry syscall family (NtSetValueKey, NtCreateKey,
 * NtDeleteKey, ...) is NOT exported -- only the Zw forms are -- so reaching those functions means
 * finding KiServiceTable, and finding KiServiceTable means searching .text for the instruction pair
 * that loads it. measured by enumerating the export directory rather than assumed.
 */
BOOLEAN
NxcGetNtImage(
	_Out_ UINT64* OutBase,
	_Out_ UINT32* OutSize
	)
{
	*OutBase = (UINT64)(ULONG_PTR)gNtBase;
	*OutSize = (UINT32)gNtSize;
	return (gNtBase != NULL && gNtSize != 0);
}

NTSTATUS
NxcFindKernelModule(
	_In_z_ CONST CHAR* Name,
	_Out_ UINT64* OutBase,
	_Out_ ULONG* OutSize
	)
{
	*OutBase = 0;
	*OutSize = 0;

	if (gNtBase == NULL || gNtSize == 0)
		return MapRefuseAt(__LINE__, STATUS_INVALID_DEVICE_STATE);

	LIST_ENTRY* CONST Head = (LIST_ENTRY*)FindExport(gNtBase, gNtSize, "PsLoadedModuleList");
	if (Head == NULL)
		return MapRefuseAt(__LINE__, STATUS_PROCEDURE_NOT_FOUND);

	/*
	 * ⚠ THE OFFSETS ABOVE ARE UNDOCUMENTED, SO THEY ARE PROVEN BEFORE THEY ARE USED.
	 *
	 * We already know ntoskrnl's base independently -- the DXE measured it and put it in the boot
	 * block. ntoskrnl is a member of this list, so if our DllBase offset is right we MUST encounter
	 * gNtBase while walking. If we never do, the structure moved under us and every field we read is
	 * garbage: refuse rather than return a plausible wrong answer.
	 *
	 * That turns a hardcoded Windows-internal offset into a checked assumption, verified against a
	 * value from a completely different source. A layout change then produces a clean refusal
	 * instead of a wild base address handed to a memory read.
	 */
	BOOLEAN     SelfSeen = FALSE;
	UINT64      FoundBase = 0;
	ULONG       FoundSize = 0;
	ULONG       Guard = 0;

	for (LIST_ENTRY* Cur = Head->Flink; Cur != Head && Guard < 4096; Cur = Cur->Flink, Guard++)
	{
		NXC_LDR_ENTRY* CONST Entry = CONTAINING_RECORD(Cur, NXC_LDR_ENTRY, InLoadOrderLinks);

		if (!MmIsAddressValid(Entry) || !MmIsAddressValid(&Entry->BaseDllName))
			break;

		if ((UCHAR*)Entry->DllBase == gNtBase)
			SelfSeen = TRUE;

		if (FoundBase == 0 && LdrNameMatches(&Entry->BaseDllName, Name))
		{
			FoundBase = (UINT64)(ULONG_PTR)Entry->DllBase;
			FoundSize = Entry->SizeOfImage;
		}
	}

	if (!SelfSeen)
	{
		/* The walk never found the one module we can independently verify. Do not trust anything
		 * else it produced -- including a "match" that may be a coincidence in mislaid memory. */
		MapLog("[read] PsLoadedModuleList walk did not contain ntoskrnl (%p) -- LDR layout changed?\n",
		       gNtBase);
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	}

	if (FoundBase == 0)
		return MapRefuseAt(__LINE__, STATUS_NOT_FOUND);

	*OutBase = FoundBase;
	*OutSize = FoundSize;
	return STATUS_SUCCESS;
}

/*
 * ================================================================================================
 * ENUMERATE every loaded kernel module -- the kernel counterpart to `modules <pid>`.
 *
 * ⚠ SAME WALK, SAME SELF-CHECK. This deliberately mirrors NxcFindKernelModule above rather than
 * introducing a second traversal of the same undocumented structure: it requires encountering
 * ntoskrnl -- whose base the DXE measured independently and put in the boot block -- or it refuses
 * everything. A layout change then produces a clean refusal instead of a list of plausible garbage
 * bases, and there is only one place where that guarantee lives.
 *
 * ⚠ THE NAME IS COPIED, NOT POINTED AT. BaseDllName is a UNICODE_STRING whose Buffer is a separate
 * kernel allocation and is NOT NUL-terminated. Returning the pointer would hand the caller a kernel
 * VA it cannot read -- recording an address instead of the fact behind it. Each name is narrowed to
 * ASCII into the record, and truncation or an unreadable buffer is FLAGGED rather than hidden.
 *
 * Reports what it PRODUCED and what EXISTS (D3): Written is how many records fit, Total is how many
 * modules the list holds, so a partial page is visibly partial.
 * ================================================================================================
 */
NTSTATUS
NxcEnumKernelModules(
	_In_ UINT32 FirstIndex,
	_Out_writes_(Capacity) NXCMD_KMODULE* Out,
	_In_ UINT32 Capacity,
	_Out_ UINT32* OutWritten,
	_Out_ UINT32* OutTotal
	)
{
	*OutWritten = 0;
	*OutTotal   = 0;

	if (Out == NULL || Capacity == 0)
		return MapRefuseAt(__LINE__, STATUS_INVALID_PARAMETER);
	if (gNtBase == NULL || gNtSize == 0)
		return MapRefuseAt(__LINE__, STATUS_INVALID_DEVICE_STATE);

	LIST_ENTRY* CONST Head = (LIST_ENTRY*)FindExport(gNtBase, gNtSize, "PsLoadedModuleList");
	if (Head == NULL)
		return MapRefuseAt(__LINE__, STATUS_PROCEDURE_NOT_FOUND);

	BOOLEAN SelfSeen = FALSE;
	UINT32  Index    = 0;
	UINT32  Written  = 0;
	ULONG   Guard    = 0;

	for (LIST_ENTRY* Cur = Head->Flink; Cur != Head && Guard < 4096; Cur = Cur->Flink, Guard++)
	{
		NXC_LDR_ENTRY* CONST Entry = CONTAINING_RECORD(Cur, NXC_LDR_ENTRY, InLoadOrderLinks);

		if (!MmIsAddressValid(Entry) || !MmIsAddressValid(&Entry->BaseDllName))
			break;

		CONST BOOLEAN IsNt = ((UCHAR*)Entry->DllBase == gNtBase);
		if (IsNt)
			SelfSeen = TRUE;

		/* Counted BEFORE the paging window is applied, so Total is the real list length rather
		 * than "however many happened to fit". */
		Index++;

		if (Index <= FirstIndex || Written >= Capacity)
			continue;

		NXCMD_KMODULE* CONST R = &Out[Written];
		RtlZeroMemory(R, sizeof(*R));
		R->Base        = (UINT64)(ULONG_PTR)Entry->DllBase;
		R->EntryPoint  = (UINT64)(ULONG_PTR)Entry->EntryPoint;
		R->SizeOfImage = Entry->SizeOfImage;
		R->Flags       = IsNt ? NXCMD_KMOD_IS_NTOSKRNL : 0u;

		{
			CONST USHORT WChars = (USHORT)(Entry->BaseDllName.Length / sizeof(WCHAR));
			CONST WCHAR* CONST Src = Entry->BaseDllName.Buffer;
			if (Src == NULL || !MmIsAddressValid((PVOID)Src))
			{
				R->Flags |= NXCMD_KMOD_NAME_UNREAD;
			}
			else
			{
				CONST USHORT Max = (USHORT)(sizeof(R->Name) - 1u);
				CONST USHORT N   = (WChars > Max) ? Max : WChars;
				for (USHORT c = 0; c < N; c++)
				{
					CONST WCHAR W = Src[c];
					/* Narrow to ASCII. A driver name outside ASCII is itself worth seeing, so it
					 * becomes '?' rather than being dropped -- an unprintable byte in a name is
					 * evidence, not noise. */
					R->Name[c] = (W >= 0x20 && W < 0x7F) ? (char)W : '?';
				}
				R->Name[N] = '\0';
				if (WChars > Max)
					R->Flags |= NXCMD_KMOD_NAME_TRUNC;
			}
		}
		Written++;
	}

	if (!SelfSeen)
	{
		MapLog("[kmodules] walk did not contain ntoskrnl (%p) -- LDR layout changed, refusing\n",
		       gNtBase);
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);
	}

	*OutWritten = Written;
	*OutTotal   = Index;
	return STATUS_SUCCESS;
}

/**
 * NEXUS_HOST_API::RegisterCommand. Called BY A MODULE, so every argument is suspect.
 *
 * Owner is not taken on trust either: a module could pass any id. It is checked against a live slot,
 * and the handler must fall inside THAT slot's image -- so even a module lying about its owner can
 * only ever register a pointer into the image it actually occupies.
 */
static NXH_U32
HostRegisterCommand(
	NXH_U64 Owner,
	NXH_U32 Opcode,
	NXH_COMMAND_FN Handler
	)
{
	if (Owner >= NXC_MAX_MODULES || Handler == NULL)
		return 1;

	NXC_MODULE_SLOT* CONST Slot = &gModules[(ULONG)Owner];
	if (!Slot->Valid || Slot->Zombie || Slot->Base == NULL || Slot->Size == 0)
		return 2;

	/*
	 * Core's own opcodes are not available. A module that could claim NXCMD_OP_UNMAP would be able
	 * to refuse its own teardown, which turns a recoverable refusal into a module that cannot be
	 * removed without a reboot.
	 */
	if (Opcode < NXCMD_OP_MODULE_FIRST)
		return 3;

	/*
	 * ⚠ THE BOUNDS CHECK IS THE SECURITY PROPERTY. Without it this is an arbitrary-kernel-call
	 * primitive: register any address, then invoke it from usermode with a chosen opcode. With it,
	 * the worst a module can do is call into itself, which it could do anyway.
	 */
	CONST UCHAR* CONST H = (CONST UCHAR*)(ULONG_PTR)Handler;
	if (H < Slot->Base || H >= Slot->Base + Slot->Size)
	{
		MapLog("[cmd] module %llu tried to register a handler outside its image -- REFUSED\n", Owner);
		return 4;
	}

	ULONG Free = NXC_MAX_MODULE_COMMANDS;
	for (ULONG i = 0; i < NXC_MAX_MODULE_COMMANDS; i++)
	{
		if (gModuleCommands[i].Opcode == Opcode)
			return 5;                                   /* taken -- first claim wins, no silent steal */
		if (gModuleCommands[i].Opcode == 0 && Free == NXC_MAX_MODULE_COMMANDS)
			Free = i;
	}
	if (Free == NXC_MAX_MODULE_COMMANDS)
		return 6;

	gModuleCommands[Free].Handler = Handler;
	gModuleCommands[Free].Owner   = (ULONG)Owner;
	gModuleCommands[Free].Opcode  = Opcode;             /* LAST: publishes the entry */

	MapLog("[cmd] module %llu registered opcode 0x%X\n", Owner, Opcode);
	return 0;
}

NXH_COMMAND_FN
NxcCommandLookup(
	_In_ ULONG Opcode
	)
{
	if (Opcode < NXCMD_OP_MODULE_FIRST)
		return NULL;

	for (ULONG i = 0; i < NXC_MAX_MODULE_COMMANDS; i++)
	{
		if (gModuleCommands[i].Opcode == Opcode)
			return gModuleCommands[i].Handler;
	}
	return NULL;
}

ULONG
NxcCommandUnregisterOwner(
	_In_ ULONG Owner
	)
{
	ULONG Cleared = 0;
	for (ULONG i = 0; i < NXC_MAX_MODULE_COMMANDS; i++)
	{
		if (gModuleCommands[i].Opcode != 0 && gModuleCommands[i].Owner == Owner)
		{
			/* Opcode FIRST: it is what NxcCommandLookup matches on, so clearing it retires the
			 * entry before the pointer it guards is wiped. */
			gModuleCommands[i].Opcode  = 0;
			gModuleCommands[i].Handler = NULL;
			gModuleCommands[i].Owner   = 0;
			Cleared++;
		}
	}
	return Cleared;
}

ULONG
NxcMapCount(
	void
	)
{
	ULONG n = 0;
	for (ULONG i = 0; i < NXC_MAX_MODULES; i++)
		if (gModules[i].Valid) n++;
	return n;
}

/**
 * Cross-processor rendezvous for teardown step 4. Deliberately empty -- ARRIVING is the entire job.
 *
 * KeIpiGenericCall raises every processor to IPI_LEVEL and holds them until all have arrived, so when
 * it returns no processor can still be mid-instruction inside the image we are about to poison.
 *
 * ⚠ Runs at IPI_LEVEL: nothing may be done here beyond returning. No logging, no allocation, no
 * touching the module.
 *
 * NexusModule.h's step 4 names KeGenericCallDpc (Ophion's primitive). KeIpiGenericCall is used
 * instead because it is a STRICTER barrier -- a true rendezvous rather than a DPC queued per
 * processor -- and because it is already bound in NexusNtApi and already proven in this driver by
 * Pte.c's TLB invalidation. Choosing the primitive we can verify over the one a reference happened to
 * use; the contract specifies the guarantee, not the API.
 */
static ULONG_PTR
UnmapBarrierIpi(
	_In_ ULONG_PTR Context
	)
{
	UNREFERENCED_PARAMETER(Context);
	return 0;
}

/**
 * Tear down and reclaim a mapped module -- the six steps of NexusModule.h's contract.
 *
 * ============================================================================================
 * THE ORDER IS THE DESIGN. Every step exists because skipping it produces a specific failure.
 * ============================================================================================
 *
 *   1. PREPARE   ask; a refusal leaves the module RUNNING and is a SUCCESSFUL outcome
 *   2. COMMIT    the module releases everything; failure here is unrecoverable by contract
 *   3. DRAIN     wait out ActiveCount -- no kernel refcount exists to consult
 *   4. BARRIER   KeIpiGenericCall, so no processor is inside the image
 *   5. UNPROTECT restore the range to writable  <-- see below, this one is NOT in the contract
 *   6. POISON +
 *      RECLAIM   NxcArenaFreeOwner, which does both
 *
 * ⚠ STEP 5 IS THE INTEGRATION BUG, and it is why unmap could not simply call NxcArenaFreeOwner.
 *
 * The arena poisons a freed extent with a plain memory write, which is correct for arena memory --
 * NxcArenaInit leaves the whole reservation RW- by default. But a MAPPED MODULE is not plain arena
 * memory by the time it is running: NxcPteProtectImage has applied each PE section's own
 * characteristics, so .text is R-X and .rdata is R--. Poisoning writes straight into a read-only
 * page and BUGCHECKS.
 *
 * The two halves were built in separate sessions and each is right on its own; only their meeting
 * point is wrong. Nothing in either file's comments hinted at it, and the failure would have appeared
 * as a bugcheck inside the arena -- pointing at the allocator rather than at the mapper that changed
 * the protections. Restoring RW- here, immediately before the free and after the barrier, is the fix.
 *
 * NX is deliberately NOT restored along with W: the range is about to be poisoned, and leaving it
 * non-executable means a stale CALL into it faults on NX before it can even reach the poison.
 *
 * @param ModuleId  slot id returned by NxcMapModule -- ALSO the arena owner id
 * @return STATUS_SUCCESS reclaimed; STATUS_DEVICE_BUSY the module refused (still running, intact);
 *         anything else failed, and the refusal line says where.
 */
NTSTATUS
NxcMapUnmap(
	_In_ ULONG ModuleId
	)
{
	/*
	 * Same reset as the map path, and for the same reason: a diagnostic that outlives its operation
	 * gets read as belonging to the next one. NXCMD_UNMAP_COMMITTED in particular MUST start clear --
	 * it is the flag that says whether anything was destroyed.
	 */
	gLastDiagFlags   = 0;
	gLastRefusalLine = 0;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return MapRefuseAt(__LINE__, STATUS_INVALID_DEVICE_STATE);

	if (ModuleId >= NXC_MAX_MODULES)
		return MapRefuseAt(__LINE__, STATUS_INVALID_PARAMETER);

	NXC_MODULE_SLOT* const Slot = &gModules[ModuleId];

	if (!Slot->Valid)
		return MapRefuseAt(__LINE__, STATUS_NOT_FOUND);

	/*
	 * Already failed a teardown. Retrying would re-enter a module that may be mid-anything.
	 *
	 * The flag matters as much as the refusal: without it the reader reports this as an ordinary
	 * pre-teardown refusal and tells the user nothing leaked, when this slot's memory is exactly what
	 * IS permanently leaked.
	 */
	if (Slot->Zombie)
	{
		gLastDiagFlags |= NXCMD_UNMAP_ZOMBIE;
		return MapRefuseAt(__LINE__, STATUS_UNSUCCESSFUL);
	}

	NEXUS_MODULE_DESCRIPTOR* const Desc = Slot->Descriptor;

	/*
	 * The descriptor lives INSIDE the module's own image, so the module can corrupt it -- including
	 * its function pointers. Everything below calls through those pointers, so they are validated
	 * against the image extent FIRST. An unvalidated Prepare/Commit is a wild call, and a wild call
	 * from kernel mode is a bugcheck with a stack that blames us.
	 *
	 * Re-validated at teardown rather than trusted from map time on purpose: map-time validation
	 * proves what the bytes were BEFORE the module ran, and a module that scribbled over its own
	 * descriptor since is exactly the case that must not reach a call instruction.
	 */
	if ((UCHAR*)Desc < Slot->Base ||
		(UCHAR*)Desc + sizeof(NEXUS_MODULE_DESCRIPTOR) > Slot->Base + Slot->Size)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	if (Desc->Magic != NEXUS_MODULE_MAGIC)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	if (Desc->Abi != NEXUS_MODULE_ABI)
		return MapRefuseAt(__LINE__, STATUS_REVISION_MISMATCH);

	if (Desc->Prepare == NULL || Desc->Commit == NULL)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	if ((UCHAR*)(ULONG_PTR)Desc->Prepare < Slot->Base ||
		(UCHAR*)(ULONG_PTR)Desc->Prepare >= Slot->Base + Slot->Size ||
		(UCHAR*)(ULONG_PTR)Desc->Commit  < Slot->Base ||
		(UCHAR*)(ULONG_PTR)Desc->Commit  >= Slot->Base + Slot->Size)
		return MapRefuseAt(__LINE__, STATUS_INVALID_IMAGE_FORMAT);

	/*
	 * ---- STEP 1: PREPARE ----
	 *
	 * A refusal is a SUCCESSFUL outcome of unmap, not an error: the module stays mapped, running and
	 * completely untouched, which is the entire reason the contract has two phases. Reported as
	 * STATUS_DEVICE_BUSY so the caller can tell "it said no" from "it broke".
	 */
	const NXM_U32 PrepareResult = Desc->Prepare();
	if (PrepareResult != NXM_TEARDOWN_OK)
	{
		MapLog("[unmap] module %lu REFUSED teardown (prepare=%lu); left running and intact\n",
			   ModuleId, (ULONG)PrepareResult);
		return MapRefuseAt(__LINE__, STATUS_DEVICE_BUSY);
	}

	/*
	 * Retire this module's opcodes NOW -- earliest safe point, and before anything is destroyed.
	 *
	 * PREPARE has just promised the module is no longer taking new work, so a live handler pointing
	 * into it is already wrong. Done here rather than after COMMIT so that even the ZOMBIE path (a
	 * failed COMMIT, which never reclaims) leaves no callable entry pointing into a module in an
	 * indeterminate state.
	 *
	 * Safe against an in-flight call by construction, not by luck: every command including this one
	 * runs under NxcCommandHandler's interlocked guard, so no module handler can be executing right
	 * now. See the RegisterCommand note in NexusHost.h -- that argument is what stands in for
	 * rundown protection, and it depends on the command channel remaining the only caller.
	 */
	{
		CONST ULONG Retired = NxcCommandUnregisterOwner(ModuleId);
		if (Retired != 0)
			MapLog("[unmap] module %lu: retired %lu registered opcode(s)\n", ModuleId, Retired);
	}

	/*
	 * ---- STEP 2: COMMIT ----
	 *
	 * Past this point there is no way back. PREPARE has already told the module to stop taking work,
	 * so it is no longer serving anyone even if COMMIT fails.
	 */
	/*
	 * Set BEFORE the call, not after: if COMMIT itself is what goes wrong, the flag must already say
	 * that teardown began. Setting it afterwards would report the one case it exists to describe as
	 * though nothing had been touched.
	 */
	gLastDiagFlags |= NXCMD_UNMAP_COMMITTED;

	const NXM_U32 CommitResult = Desc->Commit();
	if (CommitResult != NXM_TEARDOWN_OK)
	{
		/*
		 * The contract calls this unrecoverable, and it means it. PREPARE promised teardown was
		 * possible; COMMIT then failed partway, so the module's state is now something neither side
		 * can describe -- some callbacks unregistered, some not; some threads joined, some not.
		 *
		 * We do NOT reclaim. Leaking the extent is the correct trade: see NXC_MODULE_SLOT::Zombie.
		 */
		Slot->Zombie = TRUE;
		MapLog("[unmap] module %lu COMMIT FAILED (%lu) -- extent leaked deliberately, never reused\n",
			   ModuleId, (ULONG)CommitResult);
		return MapRefuseAt(__LINE__, STATUS_UNSUCCESSFUL);
	}

	/*
	 * Contract cross-check, diagnostic only. The module is supposed to set TORN_DOWN once COMMIT
	 * succeeded. COMMIT's return value is the authority, so a missing flag does not stop teardown --
	 * but it means the module does not fully implement the contract, and that is worth knowing before
	 * its next bug is blamed on the mapper.
	 */
	if ((Desc->Flags & NXM_FLAG_TORN_DOWN) == 0)
		MapLog("[unmap] module %lu: COMMIT ok but NXM_FLAG_TORN_DOWN not set (contract not fully met)\n",
			   ModuleId);

	/*
	 * ---- STEP 3: DRAIN ----
	 *
	 * There is no kernel refcount for a manually mapped image, so ActiveCount is the only signal that
	 * nothing is inside the module's entry points. The module maintains it; see NexusModule.h for why
	 * that stays module-owned and what makes a lie survivable.
	 *
	 * ⚠ THE BOUND IS ~1 SECOND, NOT 64 MILLISECONDS. A *relative* KeDelayExecutionThread does not
	 * expire after the interval -- it expires on the next system clock TICK, ~15.6 ms by default. That
	 * cost 86% of DriverEntry once already (measured), so it is stated here rather than
	 * rediscovered: 64 iterations of a nominal 1 ms is roughly 1 s of real time.
	 *
	 * The common case costs nothing: a quiesced module reads zero on the first check and never sleeps.
	 */
	BOOLEAN Drained = (Desc->ActiveCount == 0);
	for (ULONG i = 0; !Drained && i < 64; i++)
	{
		LARGE_INTEGER Delay;
		Delay.QuadPart = -10000LL;                    /* nominal 1 ms; really ~15.6 ms, see above */
		KeDelayExecutionThread(KernelMode, FALSE, &Delay);
		Drained = (Desc->ActiveCount == 0);
	}

	if (!Drained)
	{
		/*
		 * Something is still inside the module. Poisoning now would corrupt a live execution, so the
		 * extent leaks instead -- the same trade as a failed COMMIT, for the same reason.
		 */
		Slot->Zombie = TRUE;
		MapLog("[unmap] module %lu DRAIN TIMEOUT (ActiveCount=%lu) -- extent leaked deliberately\n",
			   ModuleId, (ULONG)Desc->ActiveCount);
		return MapRefuseAt(__LINE__, STATUS_DEVICE_BUSY);
	}

	/*
	 * ---- STEP 4: BARRIER ----
	 *
	 * ActiveCount reaching zero says no processor is inside an ENTRY POINT. It does not say no
	 * processor is inside the IMAGE -- one could be mid-instruction in a leaf routine that never
	 * touches the counter. The rendezvous closes that gap: when it returns, every processor has passed
	 * through a known point.
	 */
	KeIpiGenericCall(UnmapBarrierIpi, 0);

	/*
	 * ---- STEP 5: UNPROTECT ---- (see the header comment: this is the arena/mapper integration bug)
	 *
	 * Writable, NOT executable. If this fails the extent is NOT reclaimed, because the free path would
	 * fault on the first read-only section and take the machine down -- a leak beats a bugcheck.
	 */
	const NTSTATUS ProtStatus = NxcPteProtectRange((UINT64)(ULONG_PTR)Slot->Base,
												   (UINT64)Slot->Size,
												   TRUE,   /* Writable  -- so poison can be written */
												   FALSE,  /* Executable -- stale calls die on NX   */
												   TRUE);  /* BroadcastFlush                        */
	if (!NT_SUCCESS(ProtStatus))
	{
		Slot->Zombie = TRUE;
		MapLog("[unmap] module %lu: could not restore RW before poison (0x%08X) -- extent leaked\n",
			   ModuleId, ProtStatus);
		return MapRefuseAt(__LINE__, ProtStatus);
	}

	/*
	 * ---- STEP 6: POISON + RECLAIM ----
	 *
	 * By OWNER, never by a stored extent id -- the module's image is only its FIRST extent, and
	 * anything it obtained through NEXUS_HOST_API::Alloc is booked to the same owner. See the note in
	 * NXC_MODULE_SLOT for why an ExtentId field would look like the right handle and silently leak.
	 *
	 * ⚠ Desc points INTO the image and is dead the instant this returns. Nothing below may touch it.
	 */
	const ULONG FreedExtents = NxcArenaFreeOwner(ModuleId);

	Slot->Valid      = FALSE;
	Slot->Base       = NULL;
	Slot->Size       = 0;
	Slot->Descriptor = NULL;
	RtlZeroMemory(&Slot->Host, sizeof(Slot->Host));

	if (FreedExtents == 0)
	{
		/*
		 * The slot is gone but nothing was reclaimed, so the arena still counts this memory as used
		 * with no owner able to release it. Not fatal and not silently swallowed: the arena reading is
		 * now permanently short, and a "leak" that only shows up as an unexplained number later is
		 * exactly the kind of thing this codebase keeps having to re-derive.
		 */
		MapLog("[unmap] module %lu: teardown completed but arena freed 0 extents -- memory unaccounted\n",
			   ModuleId);
		return MapRefuseAt(__LINE__, STATUS_UNSUCCESSFUL);
	}

	MapLog("[unmap] module %lu torn down and reclaimed (%lu extent(s))\n", ModuleId, FreedExtents);
	return STATUS_SUCCESS;
}
