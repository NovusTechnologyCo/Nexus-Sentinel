/**
 * @file NexusNtApiRedirect.h
 * @brief Call-site redirects that route bare nt names through the NexusNtApi table.
 *
 * SEPARATE FILE ON PURPOSE, and it deliberately has NO `#pragma once`.
 *
 * These macros originally lived at the bottom of NexusNtApi.h behind an #ifdef, included a second
 * time after the table instance was declared. That silently did NOTHING: NexusNtApi.h has
 * `#pragma once`, so the second include was a no-op, the redirects never expanded, and the payload
 * still emitted all nine imports. The build was clean and the .sys still had a full import table --
 * a failure that looked exactly like success, caught only by checking the import directory
 * afterwards rather than trusting the code to have done what it said.
 *
 * (Same family as the other "reads as available but is not" traps this project keeps hitting. The
 * check that caught it -- dumpbin on the built binary -- is the one worth keeping.)
 *
 * INCLUDE THIS ONLY IN PAYLOAD SOURCES, and only AFTER the NexusNtApi instance is declared or
 * extern'd. The mapper must never include it: it needs the real APIs.
 *
 * WHY name-for-name redirection is safe: the preprocessor will not re-expand a macro inside its own
 * expansion, so `#define ExAllocatePool2 (NexusNtApi.ExAllocatePool2)` leaves the inner field
 * reference alone. Call sites are untouched.
 *
 * ⚠ THIS IS A SECOND LIST alongside NXC_NT_API_LIST and cannot be generated from it -- the
 * preprocessor cannot emit #define directives. Drift is caught MECHANICALLY, not by review: forget an
 * entry and that function is emitted as a real import, which puts the import table back. The
 * verification step for this file is therefore not reading it, it is:
 *
 *     dumpbin /IMPORTS NexusCore.sys      -> the import directory must be EMPTY
 */

#define vDbgPrintExWithPrefix       (NexusNtApi.vDbgPrintExWithPrefix)
#define KeGetCurrentIrql            (NexusNtApi.KeGetCurrentIrql)
#define KeDelayExecutionThread      (NexusNtApi.KeDelayExecutionThread)
#define ExAllocatePool2             (NexusNtApi.ExAllocatePool2)
#define ExFreePoolWithTag           (NexusNtApi.ExFreePoolWithTag)
#define RtlInitUnicodeString        (NexusNtApi.RtlInitUnicodeString)
#define KeInitializeSpinLock        (NexusNtApi.KeInitializeSpinLock)
#define KeAcquireSpinLockRaiseToDpc (NexusNtApi.KeAcquireSpinLockRaiseToDpc)
#define KeReleaseSpinLock           (NexusNtApi.KeReleaseSpinLock)
#define MmIsAddressValid            (NexusNtApi.MmIsAddressValid)
#define KeInitializeDpc   (NexusNtApi.KeInitializeDpc)
#define KeInitializeTimer (NexusNtApi.KeInitializeTimer)
#define KeSetTimer        (NexusNtApi.KeSetTimer)
#define KeCancelTimer     (NexusNtApi.KeCancelTimer)
#define KeFlushQueuedDpcs (NexusNtApi.KeFlushQueuedDpcs)
#define KeIpiGenericCall            (NexusNtApi.KeIpiGenericCall)
#define RtlLookupFunctionEntry      (NexusNtApi.RtlLookupFunctionEntry)
#define PsLookupThreadByThreadId    (NexusNtApi.PsLookupThreadByThreadId)
#define PsGetThreadProcessId        (NexusNtApi.PsGetThreadProcessId)
#define PsGetThreadId               (NexusNtApi.PsGetThreadId)
#define PsGetThreadTeb              (NexusNtApi.PsGetThreadTeb)
#define PsIsThreadTerminating       (NexusNtApi.PsIsThreadTerminating)
#define PsGetThreadCreateTime       (NexusNtApi.PsGetThreadCreateTime)
#define PsGetContextThread          (NexusNtApi.PsGetContextThread)
#define PsGetCurrentThreadId        (NexusNtApi.PsGetCurrentThreadId)
#define PsSetContextThread          (NexusNtApi.PsSetContextThread)
/* Diagnostic only -- see the note in NexusNtApi.h. THE REDIRECT IS THE SECOND LIST: an entry added
 * to NXC_NT_API_LIST and missed here is emitted as a real import and fails the no-imports gate. */
#define KeInitializeApc             (NexusNtApi.KeInitializeApc)
#define KeInsertQueueApc            (NexusNtApi.KeInsertQueueApc)
#define MmCopyVirtualMemory         (NexusNtApi.MmCopyVirtualMemory)
/*  MISSED when MmCopyMemory was added to NXC_NT_API_LIST for NXCMD_OP_READ, and the
 * drift did exactly what the warning above says it would: NexusCore shipped with a live import
 * table (ntoskrnl.exe!MmCopyMemory), a new `fothk` thunk section, and `scrub VERIFIED: NO`. Caught
 * by the status report, not by review -- which is the argument for the dumpbin check being part of
 * the build rather than a thing to remember. */
#define MmCopyMemory                (NexusNtApi.MmCopyMemory)
#define MmGetPhysicalMemoryRanges   (NexusNtApi.MmGetPhysicalMemoryRanges)
#define MmGetPhysicalAddress        (NexusNtApi.MmGetPhysicalAddress)
#define PsGetProcessImageFileName   (NexusNtApi.PsGetProcessImageFileName)
#define PsGetProcessInheritedFromUniqueProcessId \
                                    (NexusNtApi.PsGetProcessInheritedFromUniqueProcessId)
#define PsGetProcessSessionId       (NexusNtApi.PsGetProcessSessionId)
#define PsGetProcessCreateTimeQuadPart (NexusNtApi.PsGetProcessCreateTimeQuadPart)
#define PsSuspendProcess            (NexusNtApi.PsSuspendProcess)
#define PsResumeProcess             (NexusNtApi.PsResumeProcess)
#define PsIsSystemProcess           (NexusNtApi.PsIsSystemProcess)
#define PsIsProtectedProcess        (NexusNtApi.PsIsProtectedProcess)
#define PsIsProtectedProcessLight   (NexusNtApi.PsIsProtectedProcessLight)
#define KeGetCurrentProcessorNumberEx (NexusNtApi.KeGetCurrentProcessorNumberEx)
#define KeQueryActiveProcessorCountEx (NexusNtApi.KeQueryActiveProcessorCountEx)
#define MmAllocateContiguousMemory  (NexusNtApi.MmAllocateContiguousMemory)
#define MmFreeContiguousMemory      (NexusNtApi.MmFreeContiguousMemory)
#define MmAllocateContiguousMemorySpecifyCache \
                                    (NexusNtApi.MmAllocateContiguousMemorySpecifyCache)
#define ZwQuerySystemInformation    (NexusNtApi.ZwQuerySystemInformation)
#define MmAllocateMappingAddress    (NexusNtApi.MmAllocateMappingAddress)
#define MmFreeMappingAddress        (NexusNtApi.MmFreeMappingAddress)
#define MmMapLockedPagesWithReservedMapping \
                                    (NexusNtApi.MmMapLockedPagesWithReservedMapping)
#define MmUnmapReservedMapping      (NexusNtApi.MmUnmapReservedMapping)
#define PsSetLoadImageNotifyRoutine (NexusNtApi.PsSetLoadImageNotifyRoutine)
#define PsLookupProcessByProcessId  (NexusNtApi.PsLookupProcessByProcessId)
#define ZwQueryVirtualMemory        (NexusNtApi.ZwQueryVirtualMemory)
#define ObfDereferenceObject        (NexusNtApi.ObfDereferenceObject)
#define ObOpenObjectByPointer       (NexusNtApi.ObOpenObjectByPointer)
#define ZwClose                     (NexusNtApi.ZwClose)
#define PsGetProcessPeb             (NexusNtApi.PsGetProcessPeb)

/*
 * ntddk.h already defines PsGetCurrentProcess as a MACRO aliasing IoGetCurrentProcess, so without
 * the #undef our definition is a redefinition (C4005) and, worse, every call site in this driver
 * would expand to IoGetCurrentProcess -- a DIFFERENT symbol, which the mapper never resolved and
 * which would therefore be a call through a zeroed table slot. Undefine first, then take over the
 * name. Both spellings are exported by ntoskrnl; we resolve and call the Ps one deliberately.
 */
#undef  PsGetCurrentProcess
#define PsGetCurrentProcess         (NexusNtApi.PsGetCurrentProcess)
#undef  PsGetCurrentProcessId
#define PsGetCurrentProcessId       (NexusNtApi.PsGetCurrentProcessId)
#define KeQueryPerformanceCounter   (NexusNtApi.KeQueryPerformanceCounter)

/*
 * KeAcquireSpinLock is a wdm.h MACRO expanding to KeAcquireSpinLockRaiseToDpc. Undefine the SDK
 * wrapper and supply our own, otherwise its expansion re-introduces a direct reference and the
 * import comes straight back.
 */
#undef KeAcquireSpinLock
#define KeAcquireSpinLock(Lock, OldIrql) (*(OldIrql) = KeAcquireSpinLockRaiseToDpc(Lock))

/*
 * FILE CONTENT CAPTURE (D110). Twins of the NXC_NT_API_LIST entries added -- and this
 * file is the half that is easy to forget, which is precisely why forgetting it is a BUILD BREAK
 * rather than a review item: a missing redirect emits a real import and check_no_imports.py fails.
 */
#define ZwCreateFile                (NexusNtApi.ZwCreateFile)
#define ZwReadFile                  (NexusNtApi.ZwReadFile)
#define ZwQueryInformationFile      (NexusNtApi.ZwQueryInformationFile)
#define PsCreateSystemThread        (NexusNtApi.PsCreateSystemThread)
#define KeInitializeEvent           (NexusNtApi.KeInitializeEvent)
#define KeSetEvent                  (NexusNtApi.KeSetEvent)
#define KeWaitForSingleObject       (NexusNtApi.KeWaitForSingleObject)
#define ObReferenceObjectByHandle   (NexusNtApi.ObReferenceObjectByHandle)
#define ObQueryNameString           (NexusNtApi.ObQueryNameString)
#define ZwDuplicateObject           (NexusNtApi.ZwDuplicateObject)
#define KeRegisterNmiCallback       (NexusNtApi.KeRegisterNmiCallback)
#define KeDeregisterNmiCallback     (NexusNtApi.KeDeregisterNmiCallback)
#define MmMapIoSpace                (NexusNtApi.MmMapIoSpace)
#define MmUnmapIoSpace              (NexusNtApi.MmUnmapIoSpace)
#define ZwCreateEvent               (NexusNtApi.ZwCreateEvent)
#define ZwWaitForSingleObject       (NexusNtApi.ZwWaitForSingleObject)
