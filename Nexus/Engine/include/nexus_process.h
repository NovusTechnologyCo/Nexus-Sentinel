/**
 * @file nexus_process.h
 * @brief Process, module, thread, and handle operations.
 *
 * Provides the core process lifecycle APIs: enumeration of running
 * processes, opening a process with tiered access levels, module and
 * thread enumeration (including extended NtQueryInformationThread data),
 * thread control (suspend/resume/context), and handle enumeration.
 */

#ifndef NEXUS_PROCESS_H
#define NEXUS_PROCESS_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Process Types
 * ============================================================================ */

/* Process information structure */
typedef struct NexusProcessInfo {
    uint32_t pid;
    uint32_t parentPid;
    wchar_t name[260];
    wchar_t path[520];
    int is32Bit;  /* 1 if WOW64/32-bit process, 0 if 64-bit */
} NexusProcessInfo;

/* Module information structure */
typedef struct NexusModuleInfo {
    uint64_t baseAddress;
    uint64_t size;
    wchar_t name[260];
    wchar_t path[520];
} NexusModuleInfo;

/* Thread information structure (extended from x64dbg patterns) */
typedef struct NexusThreadInfo {
    uint32_t threadId;
    uint32_t ownerProcessId;
    int32_t basePriority;
    int32_t deltaPriority;
    uint64_t startAddress;      /* Thread start address (if available) */
    uint64_t tebAddress;        /* Thread Environment Block address */
    uint32_t state;             /* Thread state flags */
    uint32_t waitReason;        /* Wait reason if suspended/waiting */
    uint32_t suspendCount;      /* Current suspend count (from NtQueryInformationThread) */
    uint32_t lastError;         /* Last Win32 error from TEB */
    int32_t lastStatus;         /* Last NTSTATUS from TEB */
    uint64_t kernelTime;        /* Kernel mode time in 100ns units */
    uint64_t userTime;          /* User mode time in 100ns units */
    uint64_t cycleTime;         /* CPU cycles consumed */
    wchar_t name[64];           /* Thread description (Windows 10 1607+) */
} NexusThreadInfo;

/* Thread state flags */
typedef enum NexusThreadState {
    NEXUS_THREAD_STATE_RUNNING = 0x0001,
    NEXUS_THREAD_STATE_SUSPENDED = 0x0002,
    NEXUS_THREAD_STATE_WAITING = 0x0004,
    NEXUS_THREAD_STATE_TERMINATED = 0x0008
} NexusThreadState;

/* Handle information structure */
typedef struct NexusHandleInfo {
    uint64_t handle;                /* Handle value */
    uint32_t objectTypeIndex;       /* Object type index */
    uint32_t grantedAccess;         /* Access mask */
    wchar_t typeName[64];           /* Object type name (File, Key, etc.) */
    wchar_t objectName[520];        /* Object name (path, key name, etc.) */
} NexusHandleInfo;

/* ============================================================================
 * Process Access Levels
 * ============================================================================ */

/**
 * Process access level - determines which rights are requested.
 * Using tiered access improves compatibility and reduces detection.
 */
typedef enum NexusProcessAccess {
    /** Query-only: Get process info, no memory access */
    NEXUS_PROCESS_QUERY         = 0,
    /** Read-only: Query + read process memory */
    NEXUS_PROCESS_READ          = 1,
    /** Read-write: Query + read/write process memory (default) */
    NEXUS_PROCESS_READWRITE     = 2,
    /** Full: Read-write + thread control (suspend/resume/inject) */
    NEXUS_PROCESS_FULL          = 3,
    /** Debug: Full + debug events (requires SeDebugPrivilege) */
    NEXUS_PROCESS_DEBUG         = 4
} NexusProcessAccess;

/* ============================================================================
 * Process Operations
 * ============================================================================ */

/**
 * Enumerate running processes.
 * @param buffer Array to receive process info
 * @param bufferCount Size of buffer array
 * @param processCount Output: number of processes found
 * @return NEXUS_OK, or NEXUS_ERROR_INSUFFICIENT_BUFFER if buffer too small
 */
NEXUS_API NexusResult Nexus_EnumerateProcesses(
    NexusProcessInfo* buffer,
    size_t bufferCount,
    size_t* processCount
);

/**
 * Open a process for memory operations (read-write access).
 * This is a convenience wrapper for Nexus_OpenProcessEx with NEXUS_PROCESS_READWRITE.
 * @param pid Process ID to open
 * @param handle Output: handle for subsequent operations
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_OpenProcess(
    uint32_t pid,
    NexusProcessHandle* handle
);

/**
 * Open a process with specific access level.
 * Uses tiered access rights based on actual needs (best practice).
 * @param pid Process ID to open
 * @param access Desired access level
 * @param handle Output: handle for subsequent operations
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_OpenProcessEx(
    uint32_t pid,
    NexusProcessAccess access,
    NexusProcessHandle* handle
);

/**
 * Get the access level of an opened process handle.
 * @param handle Process handle
 * @param access Output: access level
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetProcessAccess(
    NexusProcessHandle handle,
    NexusProcessAccess* access
);

/**
 * Close a process handle.
 * @param handle Handle to close
 */
NEXUS_API void Nexus_CloseProcess(NexusProcessHandle handle);

/**
 * Get information about an opened process.
 * @param handle Process handle
 * @param info Output: process information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetProcessInfo(
    NexusProcessHandle handle,
    NexusProcessInfo* info
);

/**
 * Get the raw Windows process handle.
 * @param handle Nexus process handle
 * @param rawHandle Output: raw Windows HANDLE
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetRawHandle(
    NexusProcessHandle handle,
    void** rawHandle
);

/* ============================================================================
 * Module Operations
 * ============================================================================ */

/**
 * Enumerate modules in a process.
 * @param handle Process handle
 * @param buffer Array to receive module info
 * @param bufferCount Size of buffer array
 * @param moduleCount Output: number of modules found
 * @return NEXUS_OK, or NEXUS_ERROR_INSUFFICIENT_BUFFER if buffer too small
 */
NEXUS_API NexusResult Nexus_EnumerateModules(
    NexusProcessHandle handle,
    NexusModuleInfo* buffer,
    size_t bufferCount,
    size_t* moduleCount
);

/* ============================================================================
 * Thread Operations
 * ============================================================================ */

/**
 * Enumerate threads in a process.
 * Now includes extended info from NtQueryInformationThread (TEB, suspend count, times).
 */
NEXUS_API NexusResult Nexus_EnumerateThreads(
    NexusProcessHandle handle,
    NexusThreadInfo* buffer,
    size_t bufferCount,
    size_t* threadCount
);

/**
 * Get detailed information about a specific thread.
 * Uses NtQueryInformationThread for extended data (x64dbg pattern).
 * @param threadId Thread ID
 * @param info Output: thread information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetThreadInfo(
    uint32_t threadId,
    NexusThreadInfo* info
);

/**
 * Get the TEB (Thread Environment Block) address for a thread.
 * @param threadId Thread ID
 * @param tebAddress Output: TEB address in target process
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetThreadTeb(
    uint32_t threadId,
    uint64_t* tebAddress
);

/**
 * Get the thread's last error and NTSTATUS from TEB.
 * @param handle Process handle (needed to read TEB memory)
 * @param threadId Thread ID
 * @param lastError Output: Win32 last error (GetLastError() value)
 * @param lastStatus Output: NTSTATUS from last NT call
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetThreadLastError(
    NexusProcessHandle handle,
    uint32_t threadId,
    uint32_t* lastError,
    int32_t* lastStatus
);

/**
 * Get thread suspend count without suspending.
 * @param threadId Thread ID
 * @param suspendCount Output: current suspend count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetThreadSuspendCount(
    uint32_t threadId,
    uint32_t* suspendCount
);

/**
 * Suspend a thread.
 */
NEXUS_API NexusResult Nexus_SuspendThread(uint32_t threadId);

/**
 * Resume a thread.
 */
NEXUS_API NexusResult Nexus_ResumeThread(uint32_t threadId);

/**
 * Terminate a thread.
 * WARNING: This can cause undefined behavior in the target process.
 */
NEXUS_API NexusResult Nexus_TerminateThread(uint32_t threadId, uint32_t exitCode);

/**
 * Set thread priority.
 */
NEXUS_API NexusResult Nexus_SetThreadPriority(uint32_t threadId, int32_t priority);

/**
 * Get thread priority.
 */
NEXUS_API NexusResult Nexus_GetThreadPriority(uint32_t threadId, int32_t* priority);

/**
 * Get thread context (registers).
 */
NEXUS_API NexusResult Nexus_GetThreadContext(
    uint32_t threadId,
    void* context,
    size_t contextSize
);

/**
 * Set thread context (registers).
 */
NEXUS_API NexusResult Nexus_SetThreadContext(
    uint32_t threadId,
    const void* context,
    size_t contextSize
);

/* ============================================================================
 * Handle Operations
 * ============================================================================ */

/**
 * Enumerate handles in a process.
 */
NEXUS_API NexusResult Nexus_EnumerateHandles(
    NexusProcessHandle handle,
    NexusHandleInfo* buffer,
    size_t bufferCount,
    size_t* handleCount
);

/**
 * Get information about a specific handle.
 */
NEXUS_API NexusResult Nexus_GetHandleInfo(
    NexusProcessHandle handle,
    uint64_t targetHandle,
    NexusHandleInfo* info
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_PROCESS_H */
