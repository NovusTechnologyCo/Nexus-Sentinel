/**
 * @file NexusNtApi.h
 * @brief nt imports as a POINTER STRUCT, so mapped images carry no import table at all.
 *
 * ============================================================================================
 * WHY -- a PUBLISHED detection targets the import table we would otherwise have
 * ============================================================================================
 *
 * tulach.cc, "Detecting manually mapped drivers": scan kernel memory for absolute indirect jumps
 * (FF 25 = `jmp qword ptr [rip+disp]`), check the instruction lies in a kernel address range,
 * resolve the import slot it references, and test whether it points into ntoskrnl. Code that calls
 * nt through an IAT thunk while belonging to NO KNOWN MODULE is a manually mapped driver.
 *
 * It never reads a name, so scrubbing import NAMES -- which the EFI mapper does -- is useless
 * against it. The structure itself is the signature.
 *
 * ⚠ RESEARCH RESULT, so nobody re-derives this (all three tiers):
 *   TIER 1  reference material: NO precedent. Every reference payload ships a normal import table --
 *           redlotus.sys dir @0x605C, CheatDriver.sys @0x5000. None of them solve this.
 *   TIER 2  hash/name resolution into a pointer table IS documented (packers, VMProtected drivers:
 *           walk exports, match, store the VA). Detection confirmed as FF-25-gadget based.
 *   TIER 3  v1 never did it either -- always a normal import table, same exposure.
 *
 * "No precedent" was ALSO true of KiInvertedFunctionTable, which we DECLINED. The difference is what
 * failure costs: getting this wrong means the module fails to bind, cleanly, at map time. Getting the
 * inverted table wrong corrupts unwinding for the ENTIRE system with delayed global symptoms. Same
 * evidence, opposite decisions, because risk is half the question.
 *
 * ============================================================================================
 * HOW IT WORKS, and why calls stop being FF 25
 * ============================================================================================
 *
 * A direct `ExAllocatePool2(...)` call against an imported symbol makes the linker emit an import
 * descriptor plus a thunk, and the call reaches nt via `FF 25`. Calling through a POINTER FIELD makes
 * the compiler emit `call qword ptr [reg+disp]` -- an indirect call through a REGISTER holding our
 * struct address. No thunk, no import descriptor, nothing the scan matches.
 *
 * The MAPPER resolves the names; the PAYLOAD never contains an import table. Names in the mapper are
 * fine -- it is not the thing being scanned for a mapped-driver IAT. (NexusCore's DbgPrint format
 * strings already contain API names anyway; that is a separate, accepted exposure, and is exactly why
 * removing the TABLE is the whole fix here rather than hiding names.)
 *
 * ============================================================================================
 * THE X-MACRO IS LOAD-BEARING
 * ============================================================================================
 *
 * The struct fields and the resolver's name list are BOTH generated from NXC_NT_API_LIST below, so
 * they cannot drift. Two hand-maintained parallel lists is precisely the shape that produced the
 * Setup-byte bug (analysis and action list disagreeing) -- one source, mechanically expanded, removes
 * the possibility rather than documenting the hazard.
 *
 * TO ADD AN API: add one X() line. Struct field, typedef and resolver entry follow automatically.
 */

#pragma once

/*
 * The nt surface NexusCore uses. Each line is: X(Name, ReturnType, ParameterList).
 *
 * Deliberately MINIMAL -- every entry is a kernel facility a scanner can infer we depend on, so the
 * list doubles as the honest statement of our capability footprint. Keep it short.
 */
/*
 * ⚠ MUST PRECEDE THE LIST. ntddk.h defines PsGetCurrentProcess as a MACRO aliasing
 * IoGetCurrentProcess, and the list below is an X-macro -- so without this the preprocessor rewrites
 * the entry before it is ever expanded, and the generated struct field AND the generated name string
 * both come out as "IoGetCurrentProcess". The build then fails on a member that does not exist under
 * the name every call site uses, which is a confusing way to discover a name collision.
 *
 * Undoing it here (rather than in the redirect header, which is included LATER and is therefore too
 * late to affect this list) makes the field, the resolution string and the redirect all agree.
 */
#undef PsGetCurrentProcess

#define NXC_NT_API_LIST(X)                                                                    \
	X(vDbgPrintExWithPrefix, ULONG,   (PCCH, ULONG, ULONG, PCCH, va_list))                     \
	X(KeGetCurrentIrql,      KIRQL,   (void))                                                  \
	X(KeDelayExecutionThread, NTSTATUS, (KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER))            \
	X(ExAllocatePool2,       PVOID,    (POOL_FLAGS, SIZE_T, ULONG))                            \
	X(ExFreePoolWithTag,     VOID,     (PVOID, ULONG))                                         \
	X(RtlInitUnicodeString,  VOID,     (PUNICODE_STRING, PCWSTR))                              \
	X(KeInitializeSpinLock,  VOID,     (PKSPIN_LOCK))                                          \
	X(KeAcquireSpinLockRaiseToDpc, KIRQL, (PKSPIN_LOCK))                                       \
	X(KeReleaseSpinLock,     VOID,     (PKSPIN_LOCK, KIRQL))                                   \
	X(MmIsAddressValid,      BOOLEAN,   (PVOID))                                               \
	X(KeIpiGenericCall,      ULONG_PTR, (PKIPI_BROADCAST_WORKER, ULONG_PTR))                   \
	/* ⚠ TIMER + DPC: a MODULE can own ASYNCHRONOUS work. See the note above the #define.        \
	 * ⚠ EVERY LINE IN THIS MACRO NEEDS A TRAILING BACKSLASH, COMMENTS INCLUDED. A comment line   \
	 * without one ENDS the definition, and everything below it becomes stray top-level code --   \
	 * which is exactly what happened here.                                         \
	 */                                                                                          \
	X(KeInitializeDpc,       VOID,      (PRKDPC, PKDEFERRED_ROUTINE, PVOID))                   \
	X(KeInitializeTimer,     VOID,      (PKTIMER))                                             \
	X(KeSetTimer,            BOOLEAN,   (PKTIMER, LARGE_INTEGER, PKDPC))                       \
	X(KeCancelTimer,         BOOLEAN,   (PKTIMER))                                             \
	X(KeFlushQueuedDpcs,     VOID,      (void))                                                \
	/*                                                                                          \
	 * RtlLookupFunctionEntry -- the whole reason phase 3's exception chokepoint is resolvable   \
	 * at all. `KiDispatchException` and `KdTrap` are NOT exported (measured off this machine's  \
	 * ntoskrnl, the design notes D15), so the dispatcher has to be DERIVED on a build nobody has    \
	 * seen. This returns the .pdata RUNTIME_FUNCTION covering any kernel address, which gives   \
	 * both the exact bounds to decode within and -- applied to a call target -- whether that    \
	 * target is a real function START rather than somewhere a drifted decode pointed.           \
	 *                                                                                           \
	 * Validated offline against this machine's ntoskrnl before being relied on: 17 of 17 direct \
	 * call targets across four exported functions landed exactly on .pdata starts               \
	 * (tools/ntos_callgraph.py).                                                                \
	 */                                                                                          \
	X(RtlLookupFunctionEntry, PVOID,     (ULONG64, PULONG64, PVOID))                           \
	/*                                                                                          \
	 * Thread enumeration, for `threads <pid>` and the per-thread debug registers item 13 needs. \
	 * EVERY ONE MEASURED against this machine's ntoskrnl before being listed: v1 wrongly         \
	 * believed PsGetThreadTeb was unexported, and separately relied on PsGetNextProcessThread,   \
	 * which genuinely is NOT exported and so could never have worked (the design notes D20).         \
	 */                                                                                          \
	X(PsLookupThreadByThreadId, NTSTATUS, (HANDLE, PETHREAD*))                                  \
	X(PsGetThreadProcessId,  HANDLE,    (PETHREAD))                                             \
	X(PsGetThreadId,         HANDLE,    (PETHREAD))                                             \
	X(PsGetThreadTeb,        PVOID,     (PETHREAD))                                             \
	X(PsIsThreadTerminating, BOOLEAN,   (PETHREAD))                                             \
	X(PsGetThreadCreateTime, LONGLONG,  (PETHREAD))                                             \
	/*                                                                                          \
	 * PsGetContextThread -- `bp list`'s per-thread view. EXPORTED (measured). v1 reached for      \
	 * Zw{Get,Set}ContextThread instead, resolved them with MmGetSystemRoutineAddress, got NULL,   \
	 * and bailed: its hardware breakpoints could never have run with this sitting one name away.  \
	 *                                                                                            \
	 * ⚠ IT QUEUES AN APC AND WAITS when the thread is not the current one, so it MUST NOT be      \
	 * called against a suspended thread -- see the refusal in Bp.c (the design notes D22).            \
	 */                                                                                          \
	X(PsGetContextThread,    NTSTATUS,  (PETHREAD, PCONTEXT, KPROCESSOR_MODE))                   \
	/* PsGetCurrentThreadId -- the ATTRIBUTION half of an LBR snapshot taken in a hook. The pid    \
	 * says which process; without the tid, two threads of one target are indistinguishable, and   \
	 * a call path is a per-THREAD fact. Called at the hooked function's IRQL, which this is safe  \
	 * at (it reads the current ETHREAD's Cid). */                                                 \
	X(PsGetCurrentThreadId,  HANDLE,    (void))                                                   \
	/* PsSetContextThread -- the WRITE side of `bp set`. Exported (measured, RVA 0xA97390). Same     \
	 * APC-and-wait behaviour as the get side, so it carries the same frozen-process refusal: a      \
	 * suspended thread never delivers, and the caller would block forever (D22). */                 \
	X(PsSetContextThread,    NTSTATUS,  (PETHREAD, PCONTEXT, KPROCESSOR_MODE))                     \
	/*                                                                                            \
	 * KeInitializeApc / KeInsertQueueApc -- NOT used to queue work. They exist to ANSWER ONE      \
	 * QUESTION that six hardware runs could not: why PsGetContextThread refuses every thread.      \
	 *                                                                                            \
	 * ntoskrnl was disassembled: PsGetContextThread has exactly ONE failure path, and   \
	 * it is `KeInsertQueueApc` returning FALSE. It refuses even for OUR OWN thread, at PASSIVE,    \
	 * with the exports correctly resolved -- so the suspect is this driver's dispatch context      \
	 * rather than anything about breakpoints. Queuing an APC DIRECTLY and comparing separates      \
	 * "this driver cannot queue an APC at all" from "PsGetContextThread does something else        \
	 * first". Both are exported (RVA 0x41A0C0 and 0x2D4EA0, measured).                             \
	 */                                                                                           \
	X(KeInitializeApc,       void,      (PVOID, PVOID, int, PVOID, PVOID, PVOID, KPROCESSOR_MODE, PVOID)) \
	X(KeInsertQueueApc,      BOOLEAN,   (PVOID, PVOID, PVOID, KPRIORITY))                          \
	/*                                                                                          \
	 * The command path. MmCopyVirtualMemory is undocumented but EXPORTED (verified against      \
	 * this machine's ntoskrnl, 2026-07-27) and is the ONLY safe way to read the caller's         \
	 * buffer: ProbeForRead's correct use requires try/except against another thread freeing or   \
	 * re-protecting the range, and we have no SEH in a mapped driver at all. This returns        \
	 * NTSTATUS instead of raising, which is the entire reason it is here.                        \
	 */                                                                                          \
	X(MmCopyVirtualMemory,   NTSTATUS,  (PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T,            \
	                                     KPROCESSOR_MODE, PSIZE_T))                             \
	/*                                                                                          \
	 * NXCMD_OP_READ's source-side read. DOCUMENTED (unlike MmCopyVirtualMemory) and purpose-    \
	 * built for exactly this: it is what crash-dump and live-debug code uses to read memory     \
	 * that MIGHT not be readable, returning NTSTATUS rather than faulting.                      \
	 *                                                                                          \
	 * ⚠ IT REPORTS PARTIAL SUCCESS via NumberOfBytesTransferred, and that is why it is here     \
	 * rather than a second MmCopyVirtualMemory. A range inside a valid image can be partly      \
	 * paged out; an all-or-nothing read would discard the readable part and report only         \
	 * "failed". The caller is REQUIRED to inspect the transferred count, not assume the         \
	 * requested length.                                                                         \
	 */                                                                                          \
	X(MmCopyMemory,          NTSTATUS,  (PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T))       \
	/*                                                                                          \
	 * The RAM map. THIS IS A SAFETY GATE, NOT AN INFORMATIONAL CALL, and it is the whole        \
	 * reason NXCMD_OP_READ_PHYS is allowed to exist on this machine.                            \
	 *                                                                                          \
	 * MmCopyMemory with MM_COPY_MEMORY_PHYSICAL will map and read WHATEVER physical address it  \
	 * is handed. It does not know, and cannot know, whether that address is RAM or a device     \
	 * register -- and reading a device register is not a read: it can clear a status bit, pop   \
	 * a FIFO, or hang on an unpopulated bus address. THAT CLASS OF ACCESS FROZE THIS HOST       \
	 * TWICE via MmMapIoSpace, which is why v1's physical-read implementation is    \
	 * not being ported.                                                                         \
	 *                                                                                          \
	 * So every physical read is checked for full containment in ONE range from this list        \
	 * before it is issued. The freeze becomes structurally unreachable rather than merely       \
	 * avoided by care -- which is the difference we are redeveloping for.                       \
	 *                                                                                          \
	 * ⚠ RETURNS PAGED-POOL MEMORY THE CALLER MUST FREE, terminated by a zero entry (both        \
	 * BaseAddress and NumberOfBytes zero) rather than by a count. Free with tag 0: the pool     \
	 * block carries ntoskrnl's own tag, and ExFreePoolWithTag verifies a NON-ZERO tag against   \
	 * the block and bugchecks 0xC2 on a mismatch. Tag 0 is the documented skip-the-check value  \
	 * and is exactly what ExFreePool passes.                                                    \
	 */                                                                                          \
	X(MmGetPhysicalMemoryRanges, PPHYSICAL_MEMORY_RANGE, (void))                                \
	/*                                                                                          \
	 * THE ORACLE THAT PROVES Translate.c, and its only caller is that proof.                    \
	 *                                                                                          \
	 * It translates a VA in the CURRENT context only, so it cannot answer the question          \
	 * NxcTranslate exists for. What it can do is translate a page we own, independently of our  \
	 * arithmetic -- so agreeing with it proves the derived EPROCESS offset, the entry format,   \
	 * the index math and the large-page handling all at once.                                   \
	 *                                                                                          \
	 * ⚠ INDEPENDENT, not a mirror. Checking our walk against another implementation OF THE SAME \
	 * WALK would only catch transcription drift; a shared misreading of the entry format would  \
	 * pass. This is the kernel's own translation, arrived at by different code.                 \
	 */                                                                                          \
	X(MmGetPhysicalAddress,  PHYSICAL_ADDRESS, (PVOID))                                         \
	/*                                                                                          \
	 * Process metadata, for NXCMD_OP_PROCS. All four are EXPORTED ACCESSORS, which is the whole \
	 * reason these fields were the ones chosen: every alternative that reads EPROCESS at a      \
	 * pinned offset answers confidently from a NEIGHBOURING FIELD once the layout moves, and    \
	 * this path pins no offset anywhere.                                                        \
	 *                                                                                          \
	 * ⚠ PsGetProcessImageFileName returns a POINTER INTO a fixed 15-char array, not a string    \
	 * pointer, and it is NOT guaranteed NUL-terminated when the name fills the field. Copy it   \
	 * bounded; see Processes.c.                                                                 \
	 *                                                                                          \
	 * (Presence in ntoskrnl's export table was VERIFIED against the real binary before these    \
	 * were added -- an unresolvable name fails DriverEntry, so "it is probably exported" is not \
	 * good enough here.)                                                                        \
	 */                                                                                          \
	X(PsGetProcessImageFileName, PCHAR,   (PVOID))                                              \
	X(PsGetProcessInheritedFromUniqueProcessId, HANDLE, (PVOID))                                \
	X(PsGetProcessSessionId, ULONG,       (PVOID))                                              \
	X(PsGetProcessCreateTimeQuadPart, LONGLONG, (PVOID))                                        \
	/*                                                                                          \
	 * Freeze/thaw, for `read --atomic`. Whole-process, which is why these were chosen over      \
	 * enumerating and suspending threads -- and PsSuspendThread/PsResumeThread are NOT           \
	 * exported anyway (verified against the real ntoskrnl).                                     \
	 *                                                                                          \
	 * ⚠ PsSuspendProcess IS REFERENCE-COUNTED: two suspends require two resumes. Freeze.c        \
	 * refuses a second freeze rather than nesting, so the count is never something a caller     \
	 * has to track.                                                                             \
	 */                                                                                          \
	X(PsSuspendProcess,      NTSTATUS,   (PVOID))                                               \
	X(PsResumeProcess,       NTSTATUS,   (PVOID))                                               \
	/*                                                                                          \
	 * The refusal predicates, and they are the SAFETY of the freeze path rather than polish.    \
	 * Suspending a system or protected process does not fail -- it succeeds and hangs the       \
	 * machine, reporting nothing. Asking the kernel which processes those are beats a PID       \
	 * denylist, which would be wrong the moment a build changes.                                \
	 */                                                                                          \
	X(PsIsSystemProcess,     BOOLEAN,    (PVOID))                                               \
	X(PsIsProtectedProcess,  BOOLEAN,    (PVOID))                                               \
	X(PsIsProtectedProcessLight, BOOLEAN, (PVOID))                                              \
	/*                                                                                          \
	 * Which CPU am I, and how many are there -- for the per-core-type trace probe.              \
	 *                                                                                          \
	 * ⚠ THE Ex FORMS, NOT KeGetCurrentProcessorNumber. The non-Ex version is limited to a        \
	 * single processor GROUP, so on a machine with more than 64 logical processors it           \
	 * numbers CPUs ambiguously across groups -- two different cores answering the same index    \
	 * and overwriting each other's probe slot. ALL_PROCESSOR_GROUPS makes the count match the   \
	 * numbering, which is the invariant the probe's slot indexing depends on.                   \
	 */                                                                                          \
	X(KeGetCurrentProcessorNumberEx, ULONG, (PPROCESSOR_NUMBER))                                \
	X(KeQueryActiveProcessorCountEx, ULONG, (USHORT))                                           \
	/*                                                                                          \
	 * Intel PT output regions and ToPA tables. PHYSICALLY CONTIGUOUS is a hardware               \
	 * requirement, not a preference: a ToPA entry holds one physical base and a size code, so   \
	 * a region scattered across frames cannot be described at all.                              \
	 *                                                                                          \
	 * ⚠ THESE CAN FAIL ON A FRAGMENTED SYSTEM AND THAT IS NOT A BUG. Trace.c reports partial    \
	 * success per CPU rather than treating it as an error, because "18 of 24 CPUs got buffers"  \
	 * is actionable while "allocation failed" reads as "PT does not work here".                 \
	 */                                                                                          \
	X(MmAllocateContiguousMemory, PVOID,  (SIZE_T, PHYSICAL_ADDRESS))                           \
	X(MmFreeContiguousMemory,     VOID,   (PVOID))                                              \
	/*                                                                                          \
	 * ⚠ THE ALIGNED ALLOCATOR, and Intel PT needs it rather than the plain one above.           \
	 *                                                                                          \
	 * A ToPA entry stores an output region's base in bits 63:12 with a SIZE CODE, so the region \
	 * MUST be aligned to its own size -- a 256 KB region needs a 256 KB-aligned base or the low  \
	 * bits are simply unrepresentable. MmAllocateContiguousMemory promises only PAGE alignment,  \
	 * so with it the requirement is CHECKED BUT NEVER REQUESTED and satisfying it is luck.       \
	 *                                                                                          \
	 * BoundaryAddressMultiple is what asks: it names a boundary the allocation must not CROSS,   \
	 * and an allocation of exactly N bytes that cannot cross an N-byte boundary must start on    \
	 * one. That turns "allocate, then refuse if it happens to be misaligned" into "allocate      \
	 * something usable or fail honestly".                                                        \
	 */                                                                                          \
	X(MmAllocateContiguousMemorySpecifyCache, PVOID, (SIZE_T, PHYSICAL_ADDRESS,                  \
	                                                  PHYSICAL_ADDRESS, PHYSICAL_ADDRESS,        \
	                                                  MEMORY_CACHING_TYPE))                      \
	/*                                                                                          \
	 * Big-pool enumeration (SystemBigPoolInformation, class 66).                                \
	 *                                                                                          \
	 * ⚠ THE PROBE-WITH-NULL IDIOM DOES NOT WORK FOR THIS CLASS. Some Windows versions return    \
	 * STATUS_INFO_LENGTH_MISMATCH WITHOUT writing back a required length, so a caller that      \
	 * trusts the returned size loops forever on zero. Pool.c grows its buffer instead, using    \
	 * the returned length only when it is actually present. v1 hit this and left the note that  \
	 * saved us finding it again.                                                                \
	 */                                                                                          \
	X(ZwQuerySystemInformation, NTSTATUS, (ULONG, PVOID, ULONG, PULONG))                        \
	/*                                                                                          \
	 * The WRITABLE ALIAS pair, for inline hooks under active CET. See Alias.h and D11.          \
	 *                                                                                          \
	 * ⚠ THESE FOUR REPLACE MmProbeAndLockPages AND MmMapLockedPagesSpecifyCache, which are      \
	 * DELIBERATELY ABSENT from this list. Both RAISE on failure, and this driver has no SEH --  \
	 * so their failure path is a bugcheck, not an error code, and no amount of checking a       \
	 * return value helps because they do not return on it.                                      \
	 *                                                                                          \
	 * Reserve-then-map is the shape that fails by returning NULL: MmAllocateMappingAddress can  \
	 * fail and says so, and mapping into an ALREADY RESERVED range cannot fail for want of      \
	 * system PTEs. Adding either raising API back here would quietly reintroduce the bugcheck.  \
	 */                                                                                          \
	X(MmAllocateMappingAddress, PVOID,   (SIZE_T, ULONG))                                       \
	X(MmFreeMappingAddress,     VOID,    (PVOID, ULONG))                                        \
	X(MmMapLockedPagesWithReservedMapping, PVOID, (PVOID, ULONG, PMDL, MEMORY_CACHING_TYPE))    \
	X(MmUnmapReservedMapping,   VOID,    (PVOID, ULONG, PMDL))                                  \
	/*                                                                                          \
	 * Image-load capture. WORKS FROM A MANUALLY MAPPED IMAGE -- v1 proved it on this machine,   \
	 * and its sibling PsSetCreateProcessNotifyRoutineEx does NOT (it returns                    \
	 * STATUS_ACCESS_DENIED without FORCE_INTEGRITY). The non-Ex forms are the usable ones.      \
	 *                                                                                          \
	 * ⚠ The registered pointer must be kCFG-valid, which our image is not -- see the trampoline \
	 * note in Capture.c. Registering a function from this image DIRECTLY is the thing that      \
	 * needs the trampoline, not a style preference.                                             \
	 */                                                                                          \
	X(PsSetLoadImageNotifyRoutine, NTSTATUS, (PLOAD_IMAGE_NOTIFY_ROUTINE))                      \
	/*                                                                                          \
	 * REGION ENUMERATION (S1). Reaching another process's user VA space from kernel.           \
	 *                                                                                          \
	 * ⚠ ZwQueryVirtualMemory RETURNS NTSTATUS AND DOES NOT RAISE, which is the entire reason    \
	 * this surface is buildable in an image with no SEH. The walk reads METADATA ONLY -- it     \
	 * never touches a target page -- so there is nothing left that could fault.                 \
	 *                                                                                          \
	 * Opaque types on purpose: MEMORY_INFORMATION_CLASS and KAPC_STATE live in ntifs.h, and     \
	 * this header must stay includable from a translation unit that has only ntddk.h. The       \
	 * class is passed as ULONG and the APC state as a caller-provided buffer.                   \
	 */                                                                                          \
	X(PsLookupProcessByProcessId, NTSTATUS, (HANDLE, PVOID*))                                   \
	X(ZwQueryVirtualMemory,   NTSTATUS,  (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T))        \
	/*                                                                                          \
	 * ⚠ KeStackAttachProcess / KeUnstackDetachProcess are DELIBERATELY ABSENT. Region             \
	 * enumeration reaches a process by HANDLE and reads reach it by PEPROCESS, so nothing needs   \
	 * an attach (cross-surface decision D1). They were briefly listed here while Regions.c        \
	 * followed v1's attach-based shape; removed with it, because an entry the mapper RESOLVES     \
	 * but nothing calls is a bind that can fail on a future kernel for no benefit whatsoever.     \
	 * Add them back only alongside a caller and a reason.                                         \
	 */                                                                                          \
	X(ObfDereferenceObject,   LONG_PTR,  (PVOID))                                               \
	/*                                                                                          \
	 * A process HANDLE from a PEPROCESS, so ZwQueryVirtualMemory can target another process     \
	 * WITHOUT KeStackAttachProcess. AccessMode = KernelMode bypasses the access check, which is  \
	 * why this is used rather than ZwOpenProcess -- we already hold a referenced PEPROCESS and    \
	 * an access check against the caller's token would be answering a different question.        \
	 *                                                                                          \
	 * Needs PsProcessType, a DATA export -- resolved via NxcResolveNtExport, not this table.     \
	 */                                                                                          \
	X(ObOpenObjectByPointer,  NTSTATUS,  (PVOID, ULONG, PVOID, ACCESS_MASK, PVOID,               \
	                                      KPROCESSOR_MODE, PHANDLE))                             \
	X(ZwClose,                NTSTATUS,  (HANDLE))                                              \
	/*                                                                                          \
	 * The target's PEB, for the loader module list. Returns a USERMODE VA in the TARGET's        \
	 * address space -- so every field reached from it is a cross-process read, one                \
	 * MmCopyVirtualMemory per hop, never an attach (cross-surface decision D1).                   \
	 */                                                                                          \
	X(PsGetProcessPeb,        PVOID,     (PVOID))                                               \
	X(PsGetCurrentProcess,   PEPROCESS, (VOID))                                                \
	X(PsGetCurrentProcessId, HANDLE,    (VOID))                                                \
	/*                                                                                          \
	 * A REAL clock. EntryDurationUs was a TSC delta divided by a hardcoded 3000 ("assume        \
	 * 3 GHz") and swung 6x across boots doing identical work. KeQueryPerformanceCounter reports  \
	 * its own frequency, so elapsed time needs no assumed constant. Previously rejected as       \
	 * "another nt import for a diagnostic" -- correct when the diagnostic was decorative, wrong  \
	 * now that a real question depends on it.                                                    \
	 */                                                                                          \
	X(KeQueryPerformanceCounter, LARGE_INTEGER, (PLARGE_INTEGER))                              \
	/*                                                                                          \
	 * FILE CONTENT CAPTURE -- B-01's second half, per D110.                                     \
	 *                                                                                           \
	 * The hook QUEUES a path and returns; these run on a worker thread at PASSIVE holding        \
	 * nothing. Doing the I/O in the hook would mean issuing file operations from inside           \
	 * NtSetInformationFile for that very file, against locks the filesystem is already holding.   \
	 *                                                                                             \
	 * The file is opened BY PATH rather than through the caller's handle (v1 made the same         \
	 * choice) and read NON-CACHED, so what is captured is what is on disk.                         \
	 *                                                                                              \
	 * ⚠ EVERY ONE OF THESE ALSO NEEDS AN ENTRY IN NexusNtApiRedirect.h. That file cannot be         \
	 * generated from this list -- the preprocessor cannot emit #define directives -- so the two      \
	 * are maintained by hand and drift is caught MECHANICALLY: a missing redirect becomes a real      \
	 * import and tools/check_no_imports.py fails the build.                                           \
	 */                                                                                                \
	X(ZwCreateFile,          NTSTATUS,  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, \
	                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG))  \
	X(ZwReadFile,            NTSTATUS,  (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,  \
	                                     PVOID, ULONG, PLARGE_INTEGER, PULONG))                     \
	X(ZwQueryInformationFile, NTSTATUS, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,                   \
	                                     FILE_INFORMATION_CLASS))                                  \
	X(PsCreateSystemThread,  NTSTATUS,  (PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID,  \
	                                     PKSTART_ROUTINE, PVOID))                                 \
	X(KeInitializeEvent,     VOID,      (PRKEVENT, EVENT_TYPE, BOOLEAN))                         \
	X(KeSetEvent,            LONG,      (PRKEVENT, KPRIORITY, BOOLEAN))                          \
	X(KeWaitForSingleObject, NTSTATUS,  (PVOID, KWAIT_REASON, KPROCESSOR_MODE, BOOLEAN,          \
	                                     PLARGE_INTEGER))                                        \
	/*                                                                                          \
	 * ⚠ THESE TWO ARE WHAT LETS THE HOOK DO ALMOST NOTHING.                                     \
	 *                                                                                            \
	 * NtSetInformationFile hands us a HANDLE, and a handle is process-relative and dies with the  \
	 * process -- useless to a worker running in System. ObReferenceObjectByHandle converts it to a  \
	 * FILE_OBJECT pointer that is context-independent and reference-counted, which is the whole of   \
	 * the hook's work: no FS I/O, no name query, no allocation, on the caller's thread inside its    \
	 * own syscall.                                                                                   \
	 *                                                                                                \
	 * ObQueryNameString then runs on the WORKER, where the answer is the FULL object path            \
	 * (\Device\HarddiskVolumeN\...) rather than the volume-relative string FileNameInformation       \
	 * returns -- and volume-relative is not openable, which is the entire point of resolving it.     \
	 *                                                                                                \
	 * Needs IoFileObjectType, a DATA export -- resolved via NxcResolveNtExport, exactly as           \
	 * PsProcessType is above, and not through this table.                                            \
	 */                                                                                                \
	X(ObReferenceObjectByHandle, NTSTATUS, (HANDLE, ACCESS_MASK, PVOID, KPROCESSOR_MODE,             \
	                                        PVOID*, PVOID))                                          \
	X(ObQueryNameString,     NTSTATUS,  (PVOID, PVOID, ULONG, PULONG))                              \
	/*                                                                                             \
	 * ⚠⚠ THE HANDLE IS WHAT SURVIVES A POSIX UNLINK, AND REOPENING BY PATH NEVER CAN.              \
	 *                                                                                               \
	 * measured. The first content-capture run resolved the full path perfectly and then    \
	 * failed to reopen it with STATUS_OBJECT_NAME_NOT_FOUND. That is not a lost race that a faster     \
	 * worker would win: Windows 11's Remove-Item uses FileDispositionInformationEx (class 64) with     \
	 * POSIX semantics, which unlinks the NAME as soon as the call completes while the data stays       \
	 * reachable through handles that are already open. There is no window to be quick in.              \
	 *                                                                                                  \
	 * So the hook DUPLICATES the caller's handle into the kernel handle table instead. A duplicated     \
	 * handle keeps reading after the name is gone -- that is precisely what POSIX semantics are for --  \
	 * and holding it also defers a CLASSIC (class 13) delete, which fires on the last handle close.     \
	 * One primitive fixes both dispositions.                                                            \
	 *                                                                                                    \
	 * ZwCreateEvent is for the read itself: ZwReadFile may return STATUS_PENDING on a handle that is      \
	 * not synchronous, and waiting on the FILE handle is only correct when it is. An explicit event is    \
	 * correct in both cases.                                                                              \
	 */                                                                                                    \
	X(ZwDuplicateObject,     NTSTATUS,  (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)) \
	X(ZwCreateEvent,         NTSTATUS,  (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,      \
	                                     BOOLEAN))                                                  \
	X(ZwWaitForSingleObject, NTSTATUS,  (HANDLE, BOOLEAN, PLARGE_INTEGER))                          \
	/*                                                                                              \
	 * ⚠ THE ToPA FILL INTERRUPT, AND WHY IT ARRIVES AS AN NMI (D111).                   \
	 *                                                                                              \
	 * Counting Intel PT buffer wraps exactly means catching the performance-monitoring interrupt    \
	 * the ToPA INT bit raises at every region fill. BOTH reference implementations catch it the      \
	 * same way -- HalSetSystemInformation(HalProfileSourceInterruptHandler, ...) -- and that route   \
	 * is CLOSED to us: the name is not in ntoskrnl.exe's exports on this machine, and hal.dll is a   \
	 * 30 KB stub that does not carry it either, so a payload with no import table cannot reach it    \
	 * without a signature scan.                                                                     \
	 *                                                                                              \
	 * The local APIC's LVT Performance Counter entry can deliver as NMI instead (delivery mode      \
	 * 100b), and an NMI has a REGISTRATION API that is exported and needs no DriverObject. That is  \
	 * the whole reason this pair is here rather than the Hal call.                                  \
	 *                                                                                              \
	 * ⚠ AND IT IS THE BETTER MECHANISM ANYWAY, not merely the available one. Cheat Engine's own      \
	 * comment on the Hal route reads "It has no restore/undo hook" -- installing it destroys        \
	 * whatever handler was there until the next reboot. Displacing the LVT PC entry is REVERSIBLE:   \
	 * the previous value is saved per core and written back on disarm.                              \
	 */                                                                                             \
	X(KeRegisterNmiCallback,   PVOID,   (PVOID, PVOID))                                             \
	X(KeDeregisterNmiCallback, NTSTATUS,(PVOID))                                                    \
	/*                                                                                              \
	 * ⚠⚠ MmMapIoSpace, AND WHY THIS IS NOT THE USE THAT FROZE THIS HOST TWICE.                      \
	 *                                                                                              \
	 * Read the MmGetPhysicalMemoryRanges block above first. The freezes came from        \
	 * mapping an address that was BELIEVED to be RAM and turned out to be a device register --      \
	 * where a read is not a read: it can clear a status bit, pop a FIFO, or hang on an unpopulated  \
	 * bus address. The defect was that the physical address was ARBITRARY, supplied by a caller,    \
	 * with nothing establishing what lived there. The cure was to check every physical read for     \
	 * containment in the RAM map, which is still in force and unchanged.                            \
	 *                                                                                              \
	 * THIS use inverts every one of those properties:                                              \
	 *   - the address is not arbitrary -- it is IA32_APIC_BASE[51:12], the CPU telling us where its \
	 *     own local APIC is. No caller supplies it and it cannot be pointed anywhere else.          \
	 *   - it is KNOWN to be a device register page. That is the point, not a surprise.              \
	 *   - the only register touched is the LVT Performance Counter entry at offset 0x340, whose     \
	 *     read and write semantics are architectural and side-effect-free.                          \
	 *   - one page, MmNonCached, mapped once at PASSIVE and unmapped on disarm.                     \
	 *                                                                                              \
	 * ⚠ AND IT EXISTS ONLY FOR xAPIC MODE. In x2APIC the same register is MSR 0x834 and none of     \
	 * this is reached. It was originally a REFUSAL -- "xAPIC: LVT PC is MMIO, deliberately          \
	 * refused" -- which was naming a limit rather than fixing it: the exact shape                   \
	 * An earlier finding warns about. Mapping happens OUTSIDE    \
	 * the IPI broadcast precisely because MmMapIoSpace is PASSIVE-only, which was the real          \
	 * obstacle behind the refusal.                                                                  \
	 */                                                                                             \
	X(MmMapIoSpace,          PVOID,     (PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE))            \
	X(MmUnmapIoSpace,        void,      (PVOID, SIZE_T))

/*
 * ============================================================================================
 * The typed half is KERNEL-ONLY. The UEFI mapper includes this header too -- for the NAME LIST --
 * and has no NTSTATUS/KIRQL/PVOID, so everything needing kernel types sits behind this guard.
 * Define NXC_NT_API_TYPED before including from a kernel source.
 * ============================================================================================
 */
#ifdef NXC_NT_API_TYPED

/* Function-pointer typedefs, one per entry. */
#define NXC_NT_TYPEDEF(Name, Ret, Params) typedef Ret (NTAPI *NXC_PFN_##Name) Params;
NXC_NT_API_LIST(NXC_NT_TYPEDEF)
#undef NXC_NT_TYPEDEF

/**
 * The resolved table. One instance per image, EXPORTED so the mapper can find it by name from the
 * image's own export directory -- the same mechanism already proven for NexusCoreBootSlot, and it
 * needs no pinned RVA, so the payload's layout can change without touching the mapper.
 *
 * `volatile` because the mapper fills it from a completely different execution context (UEFI, before
 * the kernel runs) and the compiler must not cache or reorder around those writes.
 */
#define NXC_NT_FIELD(Name, Ret, Params) NXC_PFN_##Name Name;
typedef struct _NXC_NT_API
{
	/*
	 * Magic first, so the mapper can verify it resolved OUR struct and not some other export that
	 * happens to share the name. Checked before a single pointer is written.
	 */
	unsigned long long Magic;
	NXC_NT_API_LIST(NXC_NT_FIELD)
} NXC_NT_API;
#undef NXC_NT_FIELD

#endif /* NXC_NT_API_TYPED */

/*
 * ---------------------------------------------------------------------------------------------
 * UNTYPED HALF -- usable from BOTH the kernel payload and the UEFI mapper.
 * ---------------------------------------------------------------------------------------------
 *
 * The mapper does not need the typed struct. It needs the export name, the magic, and the names in
 * FIELD ORDER, then writes one 64-bit pointer per slot after the magic. Generating that list from
 * the same X-macro is what guarantees the mapper's write order matches the struct's field order --
 * two hand-kept lists here would be the Setup-byte bug again, in a place where a mismatch means
 * calling the wrong kernel function.
 */
#define NXC_NT_NAME_ONE(Name, Ret, Params) #Name,
#define NXC_NT_API_NAMES  { NXC_NT_API_LIST(NXC_NT_NAME_ONE) }

/*
 * Slot layout the mapper writes: [0] = magic (UINT64), then one UINT64 pointer per entry, in list
 * order. Matches the packed struct above exactly -- both are generated from NXC_NT_API_LIST.
 */
#define NXC_NT_SLOT_MAGIC     0
#define NXC_NT_SLOT_FIRST_FN  1

/* 'NXNT' -- validated by the mapper before filling, and by the payload before first use. */
#define NXC_NT_API_MAGIC   0x544E584EULL

/* Export name the mapper resolves to find the table. */
#define NXC_NT_API_EXPORT  "NexusNtApi"

/*
 * Count of entries, for the mapper's "resolved N of N" check. Computed from the same list, so it
 * cannot disagree with the struct.
 */
#define NXC_NT_COUNT_ONE(Name, Ret, Params) + 1
#define NXC_NT_API_COUNT  (0 NXC_NT_API_LIST(NXC_NT_COUNT_ONE))

/*
 * Call-site redirects live in NexusNtApiRedirect.h, NOT here. They were originally at the bottom of
 * this file behind an #ifdef, included a second time after the instance was declared -- which did
 * nothing, because `#pragma once` above makes the second include a no-op. The payload kept emitting
 * all nine imports while the build stayed clean. Split out so the mechanism cannot silently fail
 * that way again.
 */
