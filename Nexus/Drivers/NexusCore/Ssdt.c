/*
 * Ssdt.c -- reach a syscall body that ntoskrnl does not export.
 *
 * ==================================================================================================
 * WHY. measured BY ENUMERATING THE EXPORT DIRECTORY, NOT ASSUMED.
 * ==================================================================================================
 *
 * `hook nt <name>` resolves through ntoskrnl's export table, and the first hardware run of B-02b
 * came back "'NtSetValueKey' IS NOT AN NTOSKRNL EXPORT". That is correct, and it is not specific to
 * that one name -- the ENTIRE registry family is Zw-only:
 *
 *     EXPORTED      NtCreateFile NtOpenFile NtOpenProcess NtOpenThread NtWriteFile NtReadFile
 *                   NtSetInformationFile NtDuplicateObject NtClose NtDeviceIoControlFile ...
 *     NOT EXPORTED  NtCreateKey NtOpenKey NtSetValueKey NtDeleteValueKey NtQueryValueKey
 *                   NtDeleteKey NtOpenSection NtTerminateProcess     (all have Zw forms)
 *
 * ⚠⚠ AND HOOKING THE Zw FORM WOULD HAVE LOOKED LIKE A FIX WHILE ANSWERING THE WRONG QUESTION.
 * `ZwSetValueKey` is not the function -- it is a stub that sets PreviousMode = KernelMode and enters
 * the service dispatcher. A USERMODE registry write never executes a single byte of it: the syscall
 * instruction lands in KiSystemCall64, which indexes KiServiceTable and jumps straight to the
 * NtSetValueKey body. So a hook on the Zw stub catches KERNEL callers only, would have recorded a
 * handful of records from other drivers, and would have reported "registry visibility works" while
 * being blind to every process on the machine. That is the exact shape of a summary value fed by one
 * of the paths that produce it (an earlier finding).
 *
 * ⚠ IT WOULD ALSO HAVE BEEN THE EASY, WRONG ANSWER TO A REAL REFUSAL. The refusal message said the
 * name was not exported; the settling move is to hook the name that IS. Not possible with what
 * exists is nearly always not possible with what exists YET
 * (an earlier finding).
 *
 * ==================================================================================================
 * THE CHAIN, DERIVED END TO END, WITH NOTHING PINNED
 * ==================================================================================================
 *
 *   1. Find KeServiceDescriptorTable by scanning ntoskrnl .text for the instruction pair that loads
 *      it, then VALIDATING the structure the displacement lands on.
 *   2. Read KiServiceTable (its Base) and the service Limit from that structure.
 *   3. Turn the requested name into a service INDEX by decoding the `mov eax, imm32` inside the
 *      corresponding Zw stub -- which IS exported, and whose only job is to carry that number.
 *   4. routine = KiServiceTable + (KiServiceTable[index] >> 4).
 *
 * Every step is re-derived per boot. Nothing here survives a reboot and nothing needs to.
 */

#include <ntddk.h>

#include "../../Include/NexusCoreBoot.h"
#include "../../Include/NexusCommand.h"
#include "MapModule.h"
#include "Pte.h"
#include "LogRing.h"
#include "Ssdt.h"

/* Same extern Command.c uses -- the driver log, which is where a derivation that refuses has to say
 * WHY, since a NULL return carries no reason and this one has several. */
extern void NxcLogExt(_In_z_ PCSTR Format, ...);

/* Cached for the life of the boot. KASLR moves ntoskrnl between boots and nothing else moves it
 * during one, so re-scanning .text on every resolve would be pure cost. Zero means "not yet
 * derived"; a failed derivation is NOT cached, so a transient failure can be retried. */
static UINT64 gServiceTable = 0;
static UINT32 gServiceLimit = 0;

/* Is this a plausible kernel code address inside the running ntoskrnl? Used to validate every
 * pointer this file derives, so a pattern that matched the wrong bytes fails here rather than
 * becoming a hook target. */
static BOOLEAN
SsdtInNtImage(
	_In_ UINT64 Va,
	_In_ UINT64 Base,
	_In_ UINT32 Size
	)
{
	return (Va >= Base && Va < Base + (UINT64)Size);
}

static BOOLEAN
SsdtReadable(
	_In_ UINT64 Va,
	_In_ UINT32 Bytes
	)
{
	CONST UINT64 First = Va & ~0xFFFull;
	CONST UINT64 Last  = (Va + Bytes - 1) & ~0xFFFull;

	if (Va < 0xFFFF800000000000ull)
		return FALSE;

	for (UINT64 P = First; P <= Last; P += 0x1000ull)
	{
		NXC_PTE_INFO Pte;
		if (!NT_SUCCESS(NxcPteQuery(P, &Pte)))
			return FALSE;
		if ((Pte.Flags & (NXC_PTE_VALID | NXC_PTE_PRESENT)) != (NXC_PTE_VALID | NXC_PTE_PRESENT))
			return FALSE;
	}
	return TRUE;
}

/*
 * Locate KeServiceDescriptorTable.
 *
 * ⚠ THE PATTERN IS THE SEARCH, THE STRUCTURE IS THE PROOF. KiSystemServiceRepeat loads both
 * descriptor tables back to back:
 *
 *     4C 8D 15 xx xx xx xx     lea r10, [rip+disp]   ; KeServiceDescriptorTable
 *     4C 8D 1D xx xx xx xx     lea r11, [rip+disp]   ; KeServiceDescriptorTableShadow
 *
 * That byte pair also occurs by coincidence in a multi-megabyte image, so matching it is where the
 * search STARTS, never where it ends. Each candidate is followed to the structure it names and that
 * structure is checked: Base must point into ntoskrnl, and Limit must be a plausible service count.
 * A decoded displacement is not a struct offset until the struct agrees
 * (an earlier finding).
 *
 * ⚠ NOT ANCHORED ON IA32_LSTAR, deliberately. LSTAR points at KiSystemCall64Shadow when KVA shadow
 * is enabled, which is a small trampoline that jumps elsewhere -- so a forward scan from LSTAR
 * either finds the pattern or silently runs off into unrelated code depending on a mitigation
 * setting. Scanning .text and validating the hit does not care which stub is installed.
 */
static BOOLEAN
SsdtDerive(void)
{
	if (gServiceTable != 0)
		return TRUE;

	UINT64 Base = 0;
	UINT32 Size = 0;
	if (!NxcGetNtImage(&Base, &Size) || Size < 0x1000)
		return FALSE;

	CONST UINT8* CONST Image = (CONST UINT8*)(ULONG_PTR)Base;

	for (UINT32 i = 0; i + 14 < Size; i++)
	{
		if (Image[i] != 0x4C || Image[i + 1] != 0x8D || Image[i + 2] != 0x15)
			continue;
		if (Image[i + 7] != 0x4C || Image[i + 8] != 0x8D || Image[i + 9] != 0x1D)
			continue;

		/* rip-relative: the displacement is measured from the END of the instruction. */
		CONST INT32  Disp = *(CONST INT32*)&Image[i + 3];
		CONST UINT64 Kdt  = Base + (UINT64)i + 7ull + (UINT64)(INT64)Disp;

		if (!SsdtInNtImage(Kdt, Base, Size) || !SsdtReadable(Kdt, 0x20))
			continue;

		/*
		 * SYSTEM_SERVICE_TABLE { PVOID Base; PVOID Count; ULONG_PTR Limit; PVOID Number; }
		 * Only Base and Limit are load-bearing here, and both are checked.
		 */
		CONST UINT64 TableBase  = *(CONST UINT64*)(ULONG_PTR)Kdt;
		CONST UINT64 TableLimit = *(CONST UINT64*)(ULONG_PTR)(Kdt + 0x10);

		if (!SsdtInNtImage(TableBase, Base, Size))
			continue;
		/* Windows 11 has ~500 services. A limit outside this band means the bytes matched were not
		 * a descriptor table, whatever else they were. */
		if (TableLimit < 0x100ull || TableLimit > 0x1000ull)
			continue;
		if (!SsdtReadable(TableBase, (UINT32)(TableLimit * 4ull)))
			continue;

		gServiceTable = TableBase;
		gServiceLimit = (UINT32)TableLimit;
		NxcLogExt("ssdt: KiServiceTable = %llX, %u services (KeServiceDescriptorTable %llX, "
		          "found at ntoskrnl+%X)\n", TableBase, gServiceLimit, Kdt, i);
		return TRUE;
	}

	NxcLogExt("ssdt: no candidate survived validation across %u bytes of ntoskrnl -- the lea pair "
	          "was found or not, but no match named a structure whose Base was in-image and whose "
	          "Limit was a plausible service count\n", Size);
	return FALSE;
}

/*
 * Decode the service index out of an exported Zw stub.
 *
 * Every Zw stub on x64 is the same shape, and the only part this needs is the immediate:
 *
 *     48 8B C4              mov  rax, rsp
 *     FA                    cli
 *     ...
 *     B8 xx xx xx xx        mov  eax, <SERVICE INDEX>
 *
 * ⚠ THE SCAN IS BOUNDED AND THE FIRST B8 IS TAKEN. These stubs are ~32 bytes and contain exactly one
 * `mov eax, imm32`; searching further would risk decoding the NEXT stub's immediate and returning a
 * confidently wrong index -- which would resolve to a real, valid, completely unrelated syscall.
 */
static BOOLEAN
SsdtIndexFromZwStub(
	_In_  CONST CHAR* ZwName,
	_Out_ UINT32*     OutIndex
	)
{
	*OutIndex = 0;

	CONST UINT8* CONST Stub = (CONST UINT8*)NxcResolveNtExport(ZwName);
	if (Stub == NULL || !SsdtReadable((UINT64)(ULONG_PTR)Stub, 32))
		return FALSE;

	for (UINT32 i = 0; i < 24; i++)
	{
		if (Stub[i] != 0xB8)
			continue;
		CONST UINT32 Index = *(CONST UINT32*)&Stub[i + 1];
		/* A service index is small. Anything else means the 0xB8 was part of some other encoding. */
		if (Index >= gServiceLimit)
			return FALSE;
		*OutIndex = Index;
		return TRUE;
	}
	return FALSE;
}

/*
 * "NtSetValueKey" -> the address of the real NtSetValueKey body.
 *
 * ⚠ THE NAME IS TRANSLATED TO ITS Zw TWIN ONLY TO BORROW THE INDEX. The address returned is the one
 * KiServiceTable holds, which is what a usermode `syscall` actually reaches -- never the stub the
 * index was read out of.
 */
/*
 * ⚠⚠ RESOLVE BY INDEX, WHEN NEITHER NAME EXISTS TO RESOLVE FROM.
 *
 * `NxcResolveSyscallRoutine` derives its index from the **Zw twin's** stub, which requires
 * ZwXxx to be exported. measured on this build:
 *
 *     NtProtectVirtualMemory / ZwProtectVirtualMemory   exported      -> hookable
 *     NtWriteVirtualMemory   / ZwWriteVirtualMemory     NEITHER       -> both routes dead-end
 *     NtReadVirtualMemory    / ZwReadVirtualMemory      NEITHER
 *
 * So the whole cross-process read/write family is unreachable by name from inside the kernel. It is
 * NOT unreachable in principle: usermode ntdll exports those stubs and every one begins
 * `4C 8B D1 B8 <imm32>` -- mov r10,rcx ; mov eax,INDEX -- so the caller can read the service index
 * and hand it over. Verified in usermode first: NtWriteVirtualMemory = 58, NtReadVirtualMemory = 63,
 * NtProtectVirtualMemory = 80, NtAllocateVirtualMemory = 24, NtCreateFile = 85.
 *
 * ⚠ THE INDEX IS UNTRUSTED INPUT. It comes from usermode, so it is bounds-checked against the
 * table's own service count and the resulting routine is verified to live inside ntoskrnl -- the
 * same two gates the name path uses, for the same reason: a bad index otherwise patches whatever
 * that slot points at.
 *
 * @return the routine, or NULL if the index is out of range or lands outside ntoskrnl
 */
void*
NxcResolveSyscallByIndex(
	_In_ UINT32 Index
	)
{
	if (!SsdtDerive())
		return NULL;

	if (Index >= gServiceLimit)
	{
		NxcLogExt("ssdt: index %u is beyond the table's %u services -- refused\n",
		          Index, gServiceLimit);
		return NULL;
	}

	UINT64 Base = 0;
	UINT32 Size = 0;
	if (!NxcGetNtImage(&Base, &Size))
		return NULL;

	CONST INT32  Entry   = *(CONST INT32*)(ULONG_PTR)(gServiceTable + (UINT64)Index * 4ull);
	CONST UINT64 Routine = gServiceTable + (UINT64)(INT64)(Entry >> 4);

	if (!SsdtInNtImage(Routine, Base, Size) || !SsdtReadable(Routine, 16))
	{
		NxcLogExt("ssdt: index %u -> %llX, which is NOT inside ntoskrnl -- refused\n",
		          Index, Routine);
		return NULL;
	}

	NxcLogExt("ssdt: service index %u -> %llX (by index, no name involved)\n", Index, Routine);
	return (void*)(ULONG_PTR)Routine;
}

void*
NxcResolveSyscallRoutine(
	_In_z_ CONST CHAR* NtName
	)
{
	if (NtName == NULL || NtName[0] != 'N' || NtName[1] != 't')
		return NULL;
	if (!SsdtDerive())
		return NULL;

	/* "NtSetValueKey" -> "ZwSetValueKey", in place, bounded. */
	CHAR ZwName[64];
	UINT32 n = 0;
	while (NtName[n] != '\0' && n < sizeof(ZwName) - 1)
	{
		ZwName[n] = NtName[n];
		n++;
	}
	if (NtName[n] != '\0')
		return NULL;              /* longer than any real syscall name -- refuse rather than clip */
	ZwName[n] = '\0';
	ZwName[0] = 'Z';
	ZwName[1] = 'w';

	UINT32 Index = 0;
	if (!SsdtIndexFromZwStub(ZwName, &Index))
		return NULL;

	UINT64 Base = 0;
	UINT32 Size = 0;
	if (!NxcGetNtImage(&Base, &Size))
		return NULL;

	/*
	 * The entry is a 32-bit value: routine = KiServiceTable + (entry >> 4). The low four bits are
	 * the argument-count hint the dispatcher uses for stack copying, which is why the shift is
	 * arithmetic on a SIGNED value -- entries below the table base are negative.
	 */
	CONST INT32  Entry   = *(CONST INT32*)(ULONG_PTR)(gServiceTable + (UINT64)Index * 4ull);
	CONST UINT64 Routine = gServiceTable + (UINT64)(INT64)(Entry >> 4);

	if (!SsdtInNtImage(Routine, Base, Size) || !SsdtReadable(Routine, 16))
	{
		NxcLogExt("ssdt: %s -> index %u -> %llX, which is NOT inside ntoskrnl -- refused\n",
		          NtName, Index, Routine);
		return NULL;
	}

	NxcLogExt("ssdt: %s resolved via %s, service index %u -> %llX\n", NtName, ZwName, Index, Routine);
	return (void*)(ULONG_PTR)Routine;
}

void
NxcSsdtStats(
	_Out_ UINT64* OutTable,
	_Out_ UINT32* OutLimit
	)
{
	/* Derive on demand so `status` can report it without a hook ever being installed. */
	(void)SsdtDerive();
	*OutTable = gServiceTable;
	*OutLimit = gServiceLimit;
}
