/**
 * @file process_thread.cpp
 * @brief Thread operations: enumeration, info, TEB, suspend/resume, context, and priority.
 *
 * Implements Nexus_EnumerateThreads, Nexus_GetThreadInfo (with extended
 * NtQueryInformationThread data), TEB access, suspend/resume/terminate,
 * context get/set, and priority management.
 */

#include "process_internal.h"

/* ============================================================================
 * Thread Operations Implementation
 * ============================================================================ */

/* NT structures for thread info */
typedef struct _THREAD_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    struct {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static PFN_NtQueryInformationThread g_pNtQueryInformationThread = nullptr;
static std::once_flag g_ntThreadInitFlag;

static void InitNtThreadFunctions() {
    std::call_once(g_ntThreadInitFlag, []() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            g_pNtQueryInformationThread = (PFN_NtQueryInformationThread)
                GetProcAddress(hNtdll, "NtQueryInformationThread");
        }
    });
}

NEXUS_API NexusResult Nexus_EnumerateThreads(
    NexusProcessHandle handle,
    NexusThreadInfo* buffer,
    size_t bufferCount,
    size_t* threadCount)
{
    if (!handle || !threadCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);
    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    InitNtThreadFunctions();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        *threadCount = 0;
        return NEXUS_ERROR_UNKNOWN;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    size_t count = 0;
    NexusResult result = NEXUS_OK;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == data->pid) {
                if (buffer && count < bufferCount) {
                    NexusThreadInfo* info = &buffer[count];
                    memset(info, 0, sizeof(*info));

                    info->threadId = te32.th32ThreadID;
                    info->ownerProcessId = te32.th32OwnerProcessID;
                    info->basePriority = te32.tpBasePri;
                    info->deltaPriority = te32.tpDeltaPri;

                    /* Get extended info using NtQueryInformationThread */
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        if (g_pNtQueryInformationThread) {
                            THREAD_BASIC_INFORMATION tbi;
                            ULONG returnLength;
                            NTSTATUS status = g_pNtQueryInformationThread(
                                hThread, 0 /* ThreadBasicInformation */,
                                &tbi, sizeof(tbi), &returnLength);
                            if (status >= 0) {
                                info->tebAddress = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
                            }
                        }

                        /* Get thread times */
                        FILETIME createTime, exitTime, kernelTime, userTime;
                        if (GetThreadTimes(hThread, &createTime, &exitTime, &kernelTime, &userTime)) {
                            ULARGE_INTEGER kt, ut;
                            kt.LowPart = kernelTime.dwLowDateTime;
                            kt.HighPart = kernelTime.dwHighDateTime;
                            ut.LowPart = userTime.dwLowDateTime;
                            ut.HighPart = userTime.dwHighDateTime;
                            info->kernelTime = kt.QuadPart;
                            info->userTime = ut.QuadPart;
                        }

                        CloseHandle(hThread);
                    }
                }
                count++;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    *threadCount = count;

    if (buffer && count > bufferCount) {
        result = NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return result;
}

NEXUS_API NexusResult Nexus_GetThreadInfo(
    uint32_t threadId,
    NexusThreadInfo* info)
{
    if (!info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InitNtThreadFunctions();

    memset(info, 0, sizeof(*info));
    info->threadId = threadId;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Get basic info using NtQueryInformationThread */
    if (g_pNtQueryInformationThread) {
        THREAD_BASIC_INFORMATION tbi;
        ULONG returnLength;
        NTSTATUS status = g_pNtQueryInformationThread(
            hThread, 0 /* ThreadBasicInformation */,
            &tbi, sizeof(tbi), &returnLength);
        if (status >= 0) {
            info->tebAddress = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
            info->ownerProcessId = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(tbi.ClientId.UniqueProcess));
            info->basePriority = tbi.BasePriority;
        }
    }

    /* Get thread times */
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetThreadTimes(hThread, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER kt, ut;
        kt.LowPart = kernelTime.dwLowDateTime;
        kt.HighPart = kernelTime.dwHighDateTime;
        ut.LowPart = userTime.dwLowDateTime;
        ut.HighPart = userTime.dwHighDateTime;
        info->kernelTime = kt.QuadPart;
        info->userTime = ut.QuadPart;
    }

    /* Get thread priority */
    info->deltaPriority = GetThreadPriority(hThread);

    CloseHandle(hThread);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadTeb(
    uint32_t threadId,
    uint64_t* tebAddress)
{
    if (!tebAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InitNtThreadFunctions();
    *tebAddress = 0;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (g_pNtQueryInformationThread) {
        THREAD_BASIC_INFORMATION tbi;
        ULONG returnLength;
        NTSTATUS status = g_pNtQueryInformationThread(
            hThread, 0 /* ThreadBasicInformation */,
            &tbi, sizeof(tbi), &returnLength);
        if (status >= 0) {
            *tebAddress = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
        }
    }

    CloseHandle(hThread);
    return (*tebAddress != 0) ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_GetThreadLastError(
    NexusProcessHandle handle,
    uint32_t threadId,
    uint32_t* lastError,
    int32_t* lastStatus)
{
    if (!handle || !lastError || !lastStatus) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);
    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    uint64_t tebAddress;
    NexusResult result = Nexus_GetThreadTeb(threadId, &tebAddress);
    if (result != NEXUS_OK) {
        return result;
    }

    const size_t LAST_ERROR_OFFSET = 0x68;  /* 64-bit offset */
    const size_t LAST_STATUS_OFFSET = 0x1250; /* 64-bit offset */

    SIZE_T bytesRead;
    uint32_t error;
    int32_t status;

    if (!ReadProcessMemory(data->hProcess, (LPCVOID)(tebAddress + LAST_ERROR_OFFSET),
                           &error, sizeof(error), &bytesRead)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (!ReadProcessMemory(data->hProcess, (LPCVOID)(tebAddress + LAST_STATUS_OFFSET),
                           &status, sizeof(status), &bytesRead)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    *lastError = error;
    *lastStatus = status;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetThreadSuspendCount(
    uint32_t threadId,
    uint32_t* suspendCount)
{
    if (!suspendCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *suspendCount = 0;

    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD count = SuspendThread(hThread);
    if (count != (DWORD)-1) {
        ResumeThread(hThread);  /* Restore original count */
        *suspendCount = count;
    }

    CloseHandle(hThread);
    return (count != (DWORD)-1) ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_SuspendThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD result = SuspendThread(hThread);
    CloseHandle(hThread);

    return (result != (DWORD)-1) ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_ResumeThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD result = ResumeThread(hThread);
    CloseHandle(hThread);

    return (result != (DWORD)-1) ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_TerminateThread(uint32_t threadId, uint32_t exitCode) {
    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    BOOL result = TerminateThread(hThread, exitCode);
    CloseHandle(hThread);

    return result ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_SetThreadPriority(uint32_t threadId, int32_t priority) {
    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    BOOL result = SetThreadPriority(hThread, priority);
    CloseHandle(hThread);

    return result ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
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

NEXUS_API NexusResult Nexus_GetThreadContext(
    uint32_t threadId,
    void* context,
    size_t contextSize)
{
    if (!context || contextSize < sizeof(CONTEXT)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        return NEXUS_ERROR_UNKNOWN;
    }

    CONTEXT* ctx = static_cast<CONTEXT*>(context);
    ctx->ContextFlags = CONTEXT_ALL;

    BOOL result = GetThreadContext(hThread, ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);

    return result ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_SetThreadContext(
    uint32_t threadId,
    const void* context,
    size_t contextSize)
{
    if (!context || contextSize < sizeof(CONTEXT)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        return NEXUS_ERROR_UNKNOWN;
    }

    const CONTEXT* ctx = static_cast<const CONTEXT*>(context);
    BOOL result = SetThreadContext(hThread, ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);

    return result ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

/* ============================================================================
 * Handle Operations (stubs)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EnumerateHandles(
    NexusProcessHandle handle,
    NexusHandleInfo* buffer,
    size_t bufferCount,
    size_t* handleCount)
{
    (void)handle;
    (void)buffer;
    (void)bufferCount;
    if (handleCount) *handleCount = 0;
    return NEXUS_ERROR_NOT_IMPLEMENTED;
}

NEXUS_API NexusResult Nexus_GetHandleInfo(
    NexusProcessHandle handle,
    uint64_t targetHandle,
    NexusHandleInfo* info)
{
    (void)handle;
    (void)targetHandle;
    (void)info;
    return NEXUS_ERROR_NOT_IMPLEMENTED;
}
