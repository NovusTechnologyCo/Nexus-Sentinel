/**
 * @file Regions.c
 * @brief User-VA region enumeration. Rationale and the metadata-only constraint live in Regions.h.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "Regions.h"
/* For NxcResolveNtExport -- PsProcessType is a DATA export the function-only nt table cannot carry. */
#include "MapModule.h"
/* NxcTranslate -- walks the TARGET's page tables from its own CR3, so the PTE can be read
 * without KeStackAttachProcess (D1: no SEH in a mapped image, a missed detach corrupts a
 * thread). What the CPU enforces, beside what the VAD recorded. */
#include "Translate.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define RegLog NxcLogExt

/*
 * MEMORY_BASIC_INFORMATION and the MemoryBasicInformation class live in ntifs.h, which this
 * translation unit does not include (ntddk only, same as the rest of the payload). Mirrored here
 * with the layout pinned, rather than pulling in a header that would change what else is visible.
 *
 * Layout is stable across Win10/11 x64 and v1 relied on the same mirror.
 */
typedef struct _NXC_MBI
{
	PVOID  BaseAddress;
	PVOID  AllocationBase;
	ULONG  AllocationProtect;
	ULONG  __alignment1;
	SIZE_T RegionSize;
	ULONG  State;
	ULONG  Protect;
	ULONG  Type;
	ULONG  __alignment2;
} NXC_MBI;

C_ASSERT(sizeof(NXC_MBI) == 48);
C_ASSERT(FIELD_OFFSET(NXC_MBI, RegionSize) == 24);
C_ASSERT(FIELD_OFFSET(NXC_MBI, State)      == 32);
C_ASSERT(FIELD_OFFSET(NXC_MBI, Protect)    == 36);
C_ASSERT(FIELD_OFFSET(NXC_MBI, Type)       == 40);

#define NXC_MEM_BASIC_INFORMATION_CLASS   0u    /* MemoryBasicInformation          */
#define NXC_MEM_MAPPED_FILENAME_CLASS     2u    /* MemoryMappedFilenameInformation */

/*
 * Iteration cap. v1 used 65536 and explained why: a heavily fragmented Themida process shows 4-10K
 * regions, and manually mapped DLLs sit ABOVE the loader's footprint -- so a cap near 4096 would
 * stop before reaching exactly the regions this surface exists to find.
 *
 * It is a runaway guard, not a limit on legitimate results: if it is ever hit, that is reported as
 * NXC_REGION_FLAG_TRUNCATED rather than silently returning a short list.
 */
#define NXC_REGION_WALK_CAP  65536u

/*
 * Where the user address space ends. The walk stops here rather than running to the kernel boundary:
 * everything above is either non-canonical or kernel, and querying it wastes iterations against the
 * cap that legitimate regions need.
 */
#define NXC_USER_VA_END      0x00007FFFFFFF0000ULL

NTSTATUS
NxcEnumRegions(
	_In_ ULONG ProcessId,
	_Out_writes_(MaxCount) NXC_REGION* Out,
	_In_ ULONG MaxCount,
	_Out_ ULONG* OutCount,
	_Out_ ULONG* OutTotal
	)
{
	*OutCount = 0;
	*OutTotal = 0;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	PVOID Process = NULL;
	CONST NTSTATUS Lookup =
		PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
	if (!NT_SUCCESS(Lookup) || Process == NULL)
		return STATUS_NOT_FOUND;

	/*
	 * ============================================================================================
	 * A HANDLE, NOT AN ATTACH. Cross-surface decision D1 (the design notes).
	 * ============================================================================================
	 *
	 * v1 attached with KeStackAttachProcess and queried ZwCurrentProcess(). This targets the process
	 * by HANDLE instead, and the difference is not stylistic:
	 *
	 *   - KeStackAttachProcess mutates the CALLING THREAD's address space for the duration. With no
	 *     SEH, a missed detach on any path leaves this thread running in another process, corrupting
	 *     whatever it touches next. No attach means that failure mode does not exist.
	 *   - S4's process reads use MmCopyVirtualMemory, which takes source and target PEPROCESS and
	 *     needs no attach at all. Had this surface attached, the two would have reached a process
	 *     two different ways -- which is exactly the inconsistency the cross-surface review caught,
	 *     and it caught it because the review ran to completion before this was built.
	 *
	 * AccessMode = KernelMode bypasses the access check deliberately: we already hold a referenced
	 * PEPROCESS from PsLookupProcessByProcessId, and checking the caller's token would be answering
	 * a different question than "can the kernel see this process".
	 *
	 * PsProcessType is a DATA export, so it comes from NxcResolveNtExport rather than the
	 * function-only NXC_NT_API table -- and it is resolved BY NAME, so no per-build offset.
	 */
	void** CONST PsProcessTypePtr = (void**)NxcResolveNtExport("PsProcessType");
	if (PsProcessTypePtr == NULL || *PsProcessTypePtr == NULL)
	{
		ObfDereferenceObject(Process);
		RegLog("[regions] PsProcessType unresolved -- cannot open a process handle\n");
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	HANDLE ProcHandle = NULL;
	CONST NTSTATUS Opened = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
	                                              PROCESS_QUERY_INFORMATION, *PsProcessTypePtr,
	                                              KernelMode, &ProcHandle);
	if (!NT_SUCCESS(Opened) || ProcHandle == NULL)
	{
		ObfDereferenceObject(Process);
		RegLog("[regions] ObOpenObjectByPointer failed 0x%08X for pid %lu\n", Opened, ProcessId);
		return Opened;
	}

	ULONG64 Address = 0;
	ULONG   Walked  = 0;
	ULONG   Stored  = 0;
	ULONG   Total   = 0;
	BOOLEAN Truncated = FALSE;

	while (Address < NXC_USER_VA_END && Walked < NXC_REGION_WALK_CAP)
	{
		NXC_MBI Mbi;
		RtlZeroMemory(&Mbi, sizeof(Mbi));
		SIZE_T Returned = 0;

		/*
		 * METADATA ONLY. This is the whole walk -- no page of the target is ever touched, which is
		 * why the absence of SEH is safe by construction rather than by care. ZwQueryVirtualMemory
		 * returns NTSTATUS on a bad address instead of raising.
		 */
		CONST NTSTATUS Qst = ZwQueryVirtualMemory(ProcHandle,
		                                          (PVOID)(ULONG_PTR)Address,
		                                          NXC_MEM_BASIC_INFORMATION_CLASS,
		                                          &Mbi, sizeof(Mbi), &Returned);
		Walked++;

		if (!NT_SUCCESS(Qst))
			break;                       /* end of the address space, or an unqueryable hole */

		if (Mbi.RegionSize == 0)
			break;                       /* no forward progress -- would loop forever */

		/* MEM_FREE is skipped: it is most of the address space and carries no information. */
		if (Mbi.State != MEM_FREE)
		{
			Total++;
			if (Stored < MaxCount)
			{
				Out[Stored].BaseAddress    = (UINT64)(ULONG_PTR)Mbi.BaseAddress;
				/* See Regions.h: this is what stops a mapped image's trailing page -- which lies
				 * OUTSIDE [DllBase, DllBase+SizeOfImage) -- from reading as unclaimed code. */
				Out[Stored].AllocationBase = (UINT64)(ULONG_PTR)Mbi.AllocationBase;
				Out[Stored].RegionSize     = (UINT64)Mbi.RegionSize;
				Out[Stored].State       = Mbi.State;
				Out[Stored].Protect     = Mbi.Protect;
				Out[Stored].Type        = Mbi.Type;

				/*
				 * MEM_IMAGE and MEM_MAPPED are file-backed by definition; MEM_PRIVATE never is.
				 * Derived from Type rather than by querying the filename for every region -- that
				 * would be thousands of extra kernel calls to answer a question Type already
				 * settles, and the PATH is not needed until a caller has decided a region matters.
				 */
				Out[Stored].Flags = (Mbi.Type == MEM_IMAGE || Mbi.Type == MEM_MAPPED)
				                  ? NXC_REGION_FLAG_HAS_FILE : 0;

				/*
				 * ---- WHAT THE CPU ENFORCES, not what was requested ------------------------
				 *
				 * Mbi.Protect is the VAD's record of a REQUEST. This walks the live PTE for the
				 * region's first page from the target's own CR3. A disagreement between the two
				 * is a finding: an archived capture recorded 882 VADs with ZERO executable in a
				 * process that was plainly running.
				 *
				 * COMMITTED PAGES ONLY -- a reserved region has no PTE to read, and asking would
				 * be a guaranteed-failed walk per region. Failure leaves 0, which means NOT
				 * TRANSLATED rather than "no rights"; XLAT_PRESENT is what says the walk worked.
				 *
				 * FIRST PAGE ONLY. A region can be huge and per-page walking would cost a full
				 * descent for every 4 KB of the address space. One page answers "does the PTE
				 * agree with the VAD here"; a caller that cares about a specific page has
				 * `va2pa`.
				 */
				Out[Stored].PteFlags = 0;
				if (Mbi.State == MEM_COMMIT)
				{
					NXC_XLAT Xl;
					if (NT_SUCCESS(NxcTranslate(Process, (UINT64)(ULONG_PTR)Mbi.BaseAddress, &Xl)))
						Out[Stored].PteFlags = Xl.Flags;
				}
				Stored++;
			}
		}

		CONST ULONG64 Next = (ULONG64)(ULONG_PTR)Mbi.BaseAddress + (ULONG64)Mbi.RegionSize;
		if (Next <= Address)
			break;                       /* defensive: never move backwards */
		Address = Next;
	}

	if (Walked >= NXC_REGION_WALK_CAP)
		Truncated = TRUE;

	/* Handle first, then the reference -- reverse order of acquisition, and neither can be skipped
	 * on any path because the walk has no early return. */
	ZwClose(ProcHandle);
	ObfDereferenceObject(Process);

	/*
	 * TRUNCATION IS REPORTED, NOT SWALLOWED -- on the first entry so it is visible even to a caller
	 * that reads nothing else. A short list that looks complete is how a manual map gets missed, and
	 * missing one is this surface's entire failure mode.
	 */
	if (Truncated && Stored > 0)
		Out[0].Flags |= NXC_REGION_FLAG_TRUNCATED;

	*OutCount = Stored;
	*OutTotal = Total;

	RegLog("[regions] pid %lu: %lu regions (%lu returned%s)\n",
	       ProcessId, Total, Stored, Truncated ? ", WALK CAPPED" : "");
	return STATUS_SUCCESS;
}

/*
 * ============================================================================================
 * LOADER MODULE LIST — the other half of the manual-map comparison.
 * ============================================================================================
 *
 * `NxcEnumRegions` asks the memory manager what EXISTS. This asks the loader what it ADMITS TO.
 * Neither is interesting alone; the SUBTRACTION is the finding.
 *
 * ⚠ EVERY READ BELOW CROSSES A PROCESS BOUNDARY. `PsGetProcessPeb` returns a usermode VA in the
 * TARGET, and every pointer reached from it likewise. One `MmCopyVirtualMemory` per hop, no attach
 * (D1) — each hop returns a status instead of faulting, which is what makes this safe with no SEH.
 */

/* PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offsets — undocumented, and therefore VALIDATED below
 * rather than trusted. x64 Win10/11 layout, the same one v1 relied on. */
#define NXC_PEB_OFF_LDR                 0x018
#define NXC_LDR_OFF_INLOADORDER         0x010
#define NXC_LDRENT_OFF_DLLBASE          0x030
#define NXC_LDRENT_OFF_SIZEOFIMAGE      0x040
#define NXC_LDRENT_OFF_BASEDLLNAME      0x058

#define NXC_MODULE_WALK_CAP  1024u

/* One cross-process read. Returns TRUE only on a COMPLETE read -- a partial here means a broken
 * pointer chase, and continuing from half a pointer is how a walk goes somewhere arbitrary. */
static BOOLEAN
ReadTarget(
	_In_ PVOID Process,
	_In_ UINT64 Va,
	_Out_writes_bytes_(Len) void* Buf,
	_In_ ULONG Len
	)
{
	if (Va == 0)
		return FALSE;

	SIZE_T Copied = 0;
	CONST NTSTATUS St = MmCopyVirtualMemory(Process, (PVOID)(ULONG_PTR)Va,
	                                        PsGetCurrentProcess(), Buf,
	                                        Len, KernelMode, &Copied);
	return (NT_SUCCESS(St) && Copied == Len);
}

NTSTATUS
NxcEnumModules(
	_In_ ULONG ProcessId,
	_Out_writes_(MaxCount) NXC_MODULE_ENTRY* Out,
	_In_ ULONG MaxCount,
	_Out_ ULONG* OutCount,
	_Out_ ULONG* OutTotal
	)
{
	*OutCount = 0;
	*OutTotal = 0;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	PVOID Process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process)) ||
	    Process == NULL)
		return STATUS_NOT_FOUND;

	NTSTATUS Result = STATUS_SUCCESS;

	CONST UINT64 Peb = (UINT64)(ULONG_PTR)PsGetProcessPeb(Process);
	if (Peb == 0)
	{
		/* A process with no PEB is not an error worth inventing detail for -- it is a system
		 * process, or one that has already torn down. Reported as an empty list, not a failure. */
		RegLog("[modules] pid %lu has no PEB (system process?)\n", ProcessId);
		ObfDereferenceObject(Process);
		return STATUS_SUCCESS;
	}

	UINT64 Ldr = 0, ListHead = 0, Cur = 0;
	if (!ReadTarget(Process, Peb + NXC_PEB_OFF_LDR, &Ldr, sizeof(Ldr)) || Ldr == 0)
	{
		ObfDereferenceObject(Process);
		RegLog("[modules] pid %lu: PEB.Ldr unreadable -- 32-bit process, or it exited\n", ProcessId);
		return STATUS_INVALID_ADDRESS;
	}

	ListHead = Ldr + NXC_LDR_OFF_INLOADORDER;
	if (!ReadTarget(Process, ListHead, &Cur, sizeof(Cur)))
	{
		ObfDereferenceObject(Process);
		return STATUS_INVALID_ADDRESS;
	}

	ULONG Walked = 0, Stored = 0, Total = 0;

	while (Cur != 0 && Cur != ListHead && Walked < NXC_MODULE_WALK_CAP)
	{
		Walked++;

		/* InLoadOrderLinks is at offset 0 of the entry, so the link IS the entry base. */
		CONST UINT64 Entry = Cur;

		UINT64 DllBase = 0;
		ULONG  SizeOfImage = 0;
		if (!ReadTarget(Process, Entry + NXC_LDRENT_OFF_DLLBASE, &DllBase, sizeof(DllBase)))
			break;
		if (!ReadTarget(Process, Entry + NXC_LDRENT_OFF_SIZEOFIMAGE, &SizeOfImage, sizeof(SizeOfImage)))
			break;

		/*
		 * ⚠ THE OFFSET SELF-CHECK. The FIRST entry of InLoadOrderModuleList is always the process's
		 * own EXE, so its DllBase must be a plausible usermode image base. If the very first entry
		 * reads as zero or as a kernel address, the layout moved and every subsequent field is
		 * garbage -- refuse rather than return a believable-looking list.
		 *
		 * Same discipline as NxcFindKernelModule proving itself against gNtBase: an undocumented
		 * offset is a checked assumption, never a trusted constant.
		 */
		if (Walked == 1 &&
		    (DllBase == 0 || DllBase >= NXC_USER_VA_END))
		{
			RegLog("[modules] pid %lu: first entry DllBase %p implausible -- PEB layout changed?\n",
			       ProcessId, (PVOID)(ULONG_PTR)DllBase);
			Result = STATUS_INVALID_IMAGE_FORMAT;
			break;
		}

		if (DllBase != 0)
		{
			Total++;
			if (Stored < MaxCount)
			{
				NXC_MODULE_ENTRY* CONST E = &Out[Stored];
				RtlZeroMemory(E, sizeof(*E));
				E->DllBase     = DllBase;
				E->SizeOfImage = SizeOfImage;

				/* BaseDllName is a UNICODE_STRING: USHORT Length, USHORT Max, ULONG pad, PWSTR Buf. */
				struct { USHORT Length; USHORT Max; ULONG Pad; UINT64 Buffer; } Name;
				if (ReadTarget(Process, Entry + NXC_LDRENT_OFF_BASEDLLNAME, &Name, sizeof(Name)) &&
				    Name.Buffer != 0 && Name.Length != 0)
				{
					WCHAR Wide[64];
					ULONG Chars = Name.Length / sizeof(WCHAR);
					if (Chars > (ULONG)(RTL_NUMBER_OF(Wide)))
						Chars = RTL_NUMBER_OF(Wide);

					if (ReadTarget(Process, Name.Buffer, Wide, Chars * (ULONG)sizeof(WCHAR)))
					{
						ULONG o = 0;
						for (; o < Chars && o < sizeof(E->Name) - 1; o++)
							E->Name[o] = (Wide[o] <= 0x7F) ? (UINT8)Wide[o] : (UINT8)'?';
						E->Name[o] = '\0';
					}
				}
				Stored++;
			}
		}

		UINT64 Next = 0;
		if (!ReadTarget(Process, Cur, &Next, sizeof(Next)))
			break;
		if (Next == Cur)
			break;                       /* self-link: corrupt, would spin forever */
		Cur = Next;
	}

	ObfDereferenceObject(Process);

	*OutCount = Stored;
	*OutTotal = Total;
	RegLog("[modules] pid %lu: %lu modules (%lu returned)\n", ProcessId, Total, Stored);
	return Result;
}

/*
 * ==================================================================================================
 * WHICH FILE IS BEHIND ONE MAPPING -- NxcRegionFile
 * ==================================================================================================
 *
 * ⚠ ONE REGION, ASKED FOR DELIBERATELY. NxcEnumRegions derives HAS_FILE from Type alone so the walk
 * never pays a filename query per region -- see the comment beside NXC_REGION_FLAG_HAS_FILE, which
 * ends "a caller wanting the path can ask for that region specifically once it has decided the
 * region matters". This is that ask, and keeping it separate is what stops a 65536-region walk from
 * turning into 65536 extra kernel calls.
 *
 * ⚠ SAME HANDLE DISCIPLINE AS THE WALK (D1). ObOpenObjectByPointer on a referenced PEPROCESS, never
 * KeStackAttachProcess -- with no SEH in this image, a missed detach corrupts whatever the calling
 * thread touches next. The handle is closed on EVERY path.
 *
 * ⚠ METADATA ONLY. ZwQueryVirtualMemory returns NTSTATUS and does not raise; no page of the target
 * is read. That is what makes this safe by construction rather than by care.
 */
NTSTATUS
NxcRegionFile(
	_In_  ULONG   ProcessId,
	_In_  UINT64  Address,
	_Out_writes_bytes_(MaxBytes) VOID* Out,
	_In_  ULONG   MaxBytes,
	_Out_ ULONG*  OutBytes
	)
{
	*OutBytes = 0;

	if (Out == NULL || MaxBytes < sizeof(WCHAR))
		return STATUS_INVALID_PARAMETER;
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	PEPROCESS Process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process)) ||
	    Process == NULL)
		return STATUS_NOT_FOUND;

	void** CONST PsProcessTypePtr = (void**)NxcResolveNtExport("PsProcessType");
	if (PsProcessTypePtr == NULL || *PsProcessTypePtr == NULL)
	{
		ObfDereferenceObject(Process);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	HANDLE ProcHandle = NULL;
	CONST NTSTATUS Opened = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL,
	                                              PROCESS_QUERY_INFORMATION, *PsProcessTypePtr,
	                                              KernelMode, &ProcHandle);
	ObfDereferenceObject(Process);
	if (!NT_SUCCESS(Opened) || ProcHandle == NULL)
		return Opened;

	/*
	 * ⚠ THE RETURNED SHAPE IS A UNICODE_STRING FOLLOWED BY ITS BUFFER, IN ONE ALLOCATION. The
	 * Buffer pointer points INSIDE the block we supplied, so the string is copied out relative to
	 * that -- never dereferenced as an independent address, which would be a pointer from another
	 * context.
	 *
	 * Sized generously: a DOS path can reach 32767 WCHARs, but a section name is a device path and
	 * in practice far shorter. 2 KB covers every real case and bounds the pool cost of a query the
	 * caller makes one region at a time.
	 */
	enum { NAME_BYTES = 2048 };
	UCHAR* CONST Buf = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, NAME_BYTES, 'fRxN');
	if (Buf == NULL)
	{
		ZwClose(ProcHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	SIZE_T Returned = 0;
	CONST NTSTATUS Qst = ZwQueryVirtualMemory(ProcHandle, (PVOID)(ULONG_PTR)Address,
	                                          NXC_MEM_MAPPED_FILENAME_CLASS,
	                                          Buf, NAME_BYTES, &Returned);
	ZwClose(ProcHandle);

	if (!NT_SUCCESS(Qst))
	{
		ExFreePoolWithTag(Buf, 'fRxN');
		/*
		 * ⚠ STATUS_FILE_INVALID IS A REAL ANSWER, NOT A FAILURE: the region is mapped but backed by
		 * the pagefile rather than a file on disk. Passed through unchanged so the caller can say
		 * so -- an executable MEM_MAPPED region with no backing file is closer to allocated code
		 * than to a DLL, which is exactly the distinction this command exists to sharpen.
		 */
		return Qst;
	}

	CONST UNICODE_STRING* CONST Name = (CONST UNICODE_STRING*)Buf;
	if (Name->Length == 0 || Name->Buffer == NULL)
	{
		ExFreePoolWithTag(Buf, 'fRxN');
		return STATUS_NOT_FOUND;
	}

	ULONG Bytes = Name->Length;
	if (Bytes > MaxBytes)
		Bytes = (ULONG)(MaxBytes & ~1u);     /* whole WCHARs only -- half a code unit is not a char */

	RtlCopyMemory(Out, Name->Buffer, Bytes);
	*OutBytes = Bytes;

	ExFreePoolWithTag(Buf, 'fRxN');
	return STATUS_SUCCESS;
}
