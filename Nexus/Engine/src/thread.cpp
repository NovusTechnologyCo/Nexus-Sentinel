/**
 * @file thread.cpp
 * @brief Thread operations: enumeration, suspend/resume, context, priority, and TEB access.
 *
 * Enumerates threads via CreateToolhelp32Snapshot, queries extended
 * information (TEB address, suspend count, kernel/user time, cycle
 * count, thread name) via NtQueryInformationThread, and provides
 * thread control APIs (suspend, resume, terminate, priority, context
 * get/set).
 */

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <winternl.h>

/* Forward declaration of internal handle structure */
struct NexusProcessHandleData {
    HANDLE hProcess;
    DWORD pid;
    bool is32Bit;
    NexusProcessAccess accessLevel;
};

/* ============================================================================
 * NT API Types and Function Pointers (for extended thread info)
 * ============================================================================ */

/* Thread information classes not in standard headers */
typedef enum _THREADINFOCLASS_EX {
    ThreadBasicInformation_Ex = 0,
    ThreadTimes_Ex = 1,
    ThreadPriority_Ex = 2,
    ThreadBasePriority_Ex = 3,
    ThreadAffinityMask_Ex = 4,
    ThreadImpersonationToken_Ex = 5,
    ThreadDescriptorTableEntry_Ex = 6,
    ThreadEnableAlignmentFaultFixup_Ex = 7,
    ThreadEventPair_Reusable_Ex = 8,
    ThreadQuerySetWin32StartAddress_Ex = 9,
    ThreadZeroTlsCell_Ex = 10,
    ThreadPerformanceCount_Ex = 11,
    ThreadAmILastThread_Ex = 12,
    ThreadIdealProcessor_Ex = 13,
    ThreadPriorityBoost_Ex = 14,
    ThreadSetTlsArrayAddress_Ex = 15,
    ThreadIsIoPending_Ex = 16,
    ThreadHideFromDebugger_Ex = 17,
    ThreadBreakOnTermination_Ex = 18,
    ThreadSwitchLegacyState_Ex = 19,
    ThreadIsTerminated_Ex = 20,
    ThreadLastSystemCall_Ex = 21,
    ThreadIoPriority_Ex = 22,
    ThreadCycleTime_Ex = 23,
    ThreadPagePriority_Ex = 24,
    ThreadActualBasePriority_Ex = 25,
    ThreadTebInformation_Ex = 26,
    ThreadCSwitchMon_Ex = 27,
    ThreadCSwitchPmu_Ex = 28,
    ThreadWow64Context_Ex = 29,
    ThreadGroupInformation_Ex = 30,
    ThreadUmsInformation_Ex = 31,
    ThreadCounterProfiling_Ex = 32,
    ThreadIdealProcessorEx_Ex = 33,
    ThreadCpuAccountingInformation_Ex = 34,
    ThreadSuspendCount_Ex = 35,
    ThreadDescription_Ex = 38,
} THREADINFOCLASS_EX;

/* Thread basic information structure */
typedef struct _THREAD_BASIC_INFORMATION_EX {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION_EX;

/* Thread cycle time */
typedef struct _THREAD_CYCLE_TIME_INFORMATION {
    ULONGLONG AccumulatedCycles;
} THREAD_CYCLE_TIME_INFORMATION;

/* Kernel/user times structure */
typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;

/* Function pointer types */
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS_EX ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

typedef HRESULT (WINAPI *PFN_GetThreadDescription)(
    HANDLE hThread,
    PWSTR* ppszThreadDescription
);

/* Cached function pointers */
static PFN_NtQueryInformationThread g_pNtQueryInformationThread = nullptr;
static PFN_GetThreadDescription g_pGetThreadDescription = nullptr;
static bool g_ntFunctionsInitialized = false;

/* Initialize NT function pointers */
static void InitNtFunctions() {
    if (g_ntFunctionsInitialized) return;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_pNtQueryInformationThread = (PFN_NtQueryInformationThread)
            GetProcAddress(hNtdll, "NtQueryInformationThread");
    }

    /* GetThreadDescription is Windows 10 1607+ */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        g_pGetThreadDescription = (PFN_GetThreadDescription)
            GetProcAddress(hKernel32, "GetThreadDescription");
    }

    g_ntFunctionsInitialized = true;
}

/* TEB offsets for reading LastErrorValue and LastStatusValue */
/* These are stable across Windows versions */
#ifdef _WIN64
    #define TEB_LAST_ERROR_OFFSET 0x68
    #define TEB_LAST_STATUS_OFFSET 0x1250
#else
    #define TEB_LAST_ERROR_OFFSET 0x34
    #define TEB_LAST_STATUS_OFFSET 0xBF4
#endif

/* ============================================================================
 * Thread Enumeration (Enhanced with NT API)
 * ============================================================================ */

/* Internal helper to fill extended thread info using NT APIs */
static void FillExtendedThreadInfo(HANDLE hThread, NexusThreadInfo* info) {
    InitNtFunctions();

    if (!g_pNtQueryInformationThread) return;

    /* Get TEB address and basic info */
    THREAD_BASIC_INFORMATION_EX basicInfo = {};
    NTSTATUS status = g_pNtQueryInformationThread(
        hThread,
        ThreadBasicInformation_Ex,
        &basicInfo,
        sizeof(basicInfo),
        nullptr
    );
    if (NT_SUCCESS(status)) {
        info->tebAddress = reinterpret_cast<uint64_t>(basicInfo.TebBaseAddress);
    }

    /* Get start address */
    PVOID startAddress = nullptr;
    status = g_pNtQueryInformationThread(
        hThread,
        ThreadQuerySetWin32StartAddress_Ex,
        &startAddress,
        sizeof(startAddress),
        nullptr
    );
    if (NT_SUCCESS(status)) {
        info->startAddress = reinterpret_cast<uint64_t>(startAddress);
    }

    /* Get suspend count (Windows 8.1+) */
    ULONG suspendCount = 0;
    status = g_pNtQueryInformationThread(
        hThread,
        ThreadSuspendCount_Ex,
        &suspendCount,
        sizeof(suspendCount),
        nullptr
    );
    if (NT_SUCCESS(status)) {
        info->suspendCount = suspendCount;
        if (suspendCount > 0) {
            info->state |= NEXUS_THREAD_STATE_SUSPENDED;
        }
    }

    /* Get thread times */
    KERNEL_USER_TIMES times = {};
    status = g_pNtQueryInformationThread(
        hThread,
        ThreadTimes_Ex,
        &times,
        sizeof(times),
        nullptr
    );
    if (NT_SUCCESS(status)) {
        info->kernelTime = times.KernelTime.QuadPart;
        info->userTime = times.UserTime.QuadPart;
    }

    /* Get cycle time */
    THREAD_CYCLE_TIME_INFORMATION cycleTime = {};
    status = g_pNtQueryInformationThread(
        hThread,
        ThreadCycleTime_Ex,
        &cycleTime,
        sizeof(cycleTime),
        nullptr
    );
    if (NT_SUCCESS(status)) {
        info->cycleTime = cycleTime.AccumulatedCycles;
    }

    /* Get thread description (Windows 10 1607+) */
    if (g_pGetThreadDescription) {
        PWSTR description = nullptr;
        HRESULT hr = g_pGetThreadDescription(hThread, &description);
        if (SUCCEEDED(hr) && description) {
            wcsncpy_s(info->name, 64, description, _TRUNCATE);
            LocalFree(description);
        }
    }
}

NEXUS_API NexusResult Nexus_EnumerateThreads(
    NexusProcessHandle handle,
    NexusThreadInfo* buffer,
    size_t bufferCount,
    size_t* threadCount
) {
    if (!handle || !threadCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    DWORD targetPid = procData->pid;

    /* Create toolhelp snapshot */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    std::vector<NexusThreadInfo> threads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == targetPid) {
                NexusThreadInfo info = {};
                info.threadId = te32.th32ThreadID;
                info.ownerProcessId = te32.th32OwnerProcessID;
                info.basePriority = te32.tpBasePri;
                info.deltaPriority = te32.tpDeltaPri;
                info.state = NEXUS_THREAD_STATE_RUNNING;

                /* Fill extended info using NT APIs */
                HANDLE hThread = OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    te32.th32ThreadID
                );
                if (hThread) {
                    FillExtendedThreadInfo(hThread, &info);
                    CloseHandle(hThread);
                }

                threads.push_back(info);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    *threadCount = threads.size();

    /* Copy to output buffer */
    if (buffer && bufferCount > 0) {
        size_t toCopy = (threads.size() < bufferCount) ? threads.size() : bufferCount;
        for (size_t i = 0; i < toCopy; i++) {
            buffer[i] = threads[i];
        }

        if (threads.size() > bufferCount) {
            return NEXUS_ERROR_INSUFFICIENT_BUFFER;
        }
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Extended Thread Information APIs
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetThreadInfo(
    uint32_t threadId,
    NexusThreadInfo* info
) {
    if (!info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(info, 0, sizeof(NexusThreadInfo));
    info->threadId = threadId;
    info->state = NEXUS_THREAD_STATE_RUNNING;

    HANDLE hThread = OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE,
        threadId
    );
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Get basic priority */
    info->basePriority = GetThreadPriority(hThread);

    /* Fill extended info */
    FillExtendedThreadInfo(hThread, info);

    CloseHandle(hThread);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadTeb(
    uint32_t threadId,
    uint64_t* tebAddress
) {
    if (!tebAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InitNtFunctions();
    if (!g_pNtQueryInformationThread) {
        return NEXUS_ERROR_UNKNOWN;
    }

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    THREAD_BASIC_INFORMATION_EX basicInfo = {};
    NTSTATUS status = g_pNtQueryInformationThread(
        hThread,
        ThreadBasicInformation_Ex,
        &basicInfo,
        sizeof(basicInfo),
        nullptr
    );

    CloseHandle(hThread);

    if (!NT_SUCCESS(status)) {
        return NEXUS_ERROR_UNKNOWN;
    }

    *tebAddress = reinterpret_cast<uint64_t>(basicInfo.TebBaseAddress);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadLastError(
    NexusProcessHandle handle,
    uint32_t threadId,
    uint32_t* lastError,
    int32_t* lastStatus
) {
    if (!handle) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);

    /* First get the TEB address */
    uint64_t tebAddress = 0;
    NexusResult res = Nexus_GetThreadTeb(threadId, &tebAddress);
    if (res != NEXUS_OK || tebAddress == 0) {
        return res;
    }

    /* Read LastErrorValue from TEB */
    if (lastError) {
        SIZE_T bytesRead = 0;
        DWORD errorValue = 0;
        if (ReadProcessMemory(
            procData->hProcess,
            reinterpret_cast<LPCVOID>(tebAddress + TEB_LAST_ERROR_OFFSET),
            &errorValue,
            sizeof(errorValue),
            &bytesRead
        )) {
            *lastError = errorValue;
        } else {
            *lastError = 0;
        }
    }

    /* Read LastStatusValue from TEB */
    if (lastStatus) {
        SIZE_T bytesRead = 0;
        LONG statusValue = 0;
        if (ReadProcessMemory(
            procData->hProcess,
            reinterpret_cast<LPCVOID>(tebAddress + TEB_LAST_STATUS_OFFSET),
            &statusValue,
            sizeof(statusValue),
            &bytesRead
        )) {
            *lastStatus = statusValue;
        } else {
            *lastStatus = 0;
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadSuspendCount(
    uint32_t threadId,
    uint32_t* suspendCount
) {
    if (!suspendCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InitNtFunctions();
    if (!g_pNtQueryInformationThread) {
        return NEXUS_ERROR_UNKNOWN;
    }

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    ULONG count = 0;
    NTSTATUS status = g_pNtQueryInformationThread(
        hThread,
        ThreadSuspendCount_Ex,
        &count,
        sizeof(count),
        nullptr
    );

    CloseHandle(hThread);

    if (!NT_SUCCESS(status)) {
        /* Fallback: suspend/resume to get count (less ideal) */
        return NEXUS_ERROR_UNKNOWN;
    }

    *suspendCount = count;
    return NEXUS_OK;
}

/* ============================================================================
 * Thread Control
 * ============================================================================ */

NEXUS_API NexusResult Nexus_SuspendThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD result = SuspendThread(hThread);
    CloseHandle(hThread);

    if (result == (DWORD)-1) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ResumeThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD result = ResumeThread(hThread);
    CloseHandle(hThread);

    if (result == (DWORD)-1) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadContext(
    uint32_t threadId,
    void* context,
    size_t contextSize
) {
    if (!context || contextSize < sizeof(CONTEXT)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Suspend thread to get consistent context */
    SuspendThread(hThread);

    CONTEXT* ctx = static_cast<CONTEXT*>(context);
    ctx->ContextFlags = CONTEXT_ALL;

    BOOL success = GetThreadContext(hThread, ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!success) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SetThreadContext(
    uint32_t threadId,
    const void* context,
    size_t contextSize
) {
    if (!context || contextSize < sizeof(CONTEXT)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Suspend thread to set context safely */
    SuspendThread(hThread);

    const CONTEXT* ctx = static_cast<const CONTEXT*>(context);
    BOOL success = SetThreadContext(hThread, ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!success) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TerminateThread(uint32_t threadId, uint32_t exitCode) {
    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    BOOL success = TerminateThread(hThread, exitCode);
    CloseHandle(hThread);

    if (!success) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SetThreadPriority(uint32_t threadId, int32_t priority) {
    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    BOOL success = SetThreadPriority(hThread, priority);
    CloseHandle(hThread);

    if (!success) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadPriority(uint32_t threadId, int32_t* priority) {
    if (!priority) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    int result = GetThreadPriority(hThread);
    CloseHandle(hThread);

    if (result == THREAD_PRIORITY_ERROR_RETURN) {
        return NEXUS_ERROR_UNKNOWN;
    }

    *priority = result;
    return NEXUS_OK;
}
