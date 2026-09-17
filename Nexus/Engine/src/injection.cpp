/**
 * @file injection.cpp
 * @brief Code and DLL injection: shellcode, LoadLibrary, remote call, and cleanup.
 *
 * Implements shellcode injection, DLL injection via CreateRemoteThread +
 * LoadLibraryW, remote function execution, and injected-memory cleanup.
 * Uses NtCreateThreadEx when the STEALTH flag is set for reduced
 * visibility to anti-cheat/anti-debug systems.
 *
 * Manual-map injection is split into injection_manualmap.cpp.
 */

#include "injection_internal.h"

/* ============================================================================
 * NT Injection Initialization
 * ============================================================================ */

static PFN_NtCreateThreadEx g_pNtCreateThreadEx = nullptr;
static bool g_ntInjectionFunctionsInitialized = false;

static void InitNtInjectionFunctions() {
    if (g_ntInjectionFunctionsInitialized) return;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_pNtCreateThreadEx = (PFN_NtCreateThreadEx)
            GetProcAddress(hNtdll, "NtCreateThreadEx");
    }

    g_ntInjectionFunctionsInitialized = true;
}

/**
 * Create a remote thread using NtCreateThreadEx (stealthier than CreateRemoteThread).
 * Falls back to CreateRemoteThread if NtCreateThreadEx is not available.
 */
static HANDLE CreateRemoteThreadEx_Stealth(
    HANDLE hProcess,
    LPVOID lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    bool skipThreadAttach,
    bool hideFromDebugger
) {
    InitNtInjectionFunctions();

    if (g_pNtCreateThreadEx) {
        HANDLE hThread = nullptr;
        ULONG createFlags = 0;

        if (dwCreationFlags & CREATE_SUSPENDED) {
            createFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
        }
        if (skipThreadAttach) {
            createFlags |= THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH;
        }
        if (hideFromDebugger) {
            createFlags |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        }

        NTSTATUS status = g_pNtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            hProcess,
            lpStartAddress,
            lpParameter,
            createFlags,
            0,      /* ZeroBits */
            0,      /* StackSize (0 = default) */
            0,      /* MaximumStackSize (0 = default) */
            nullptr /* AttributeList */
        );

        if (NT_SUCCESS(status)) {
            return hThread;
        }
    }

    /* Fallback to standard CreateRemoteThread */
    return CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress),
        lpParameter,
        dwCreationFlags,
        nullptr
    );
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static uint64_t GetLoadLibraryWAddress() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return 0;

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    return reinterpret_cast<uint64_t>(pLoadLibrary);
}

/* ============================================================================
 * Shellcode Injection
 * ============================================================================ */

NEXUS_API NexusResult Nexus_InjectShellcode(
    NexusProcessHandle handle,
    const void* shellcode,
    size_t shellcodeSize,
    uint64_t parameter,
    uint32_t flags,
    NexusInjectionResult* result
) {
    if (!handle || !shellcode || shellcodeSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (result) {
        memset(result, 0, sizeof(NexusInjectionResult));
    }

    /* Allocate memory in target process for shellcode */
    void* remoteShellcode = VirtualAllocEx(
        procData->hProcess,
        nullptr,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteShellcode) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Write shellcode to target process */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(procData->hProcess, remoteShellcode, shellcode, shellcodeSize, &bytesWritten)) {
        VirtualFreeEx(procData->hProcess, remoteShellcode, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    FlushInstructionCache(procData->hProcess, remoteShellcode, shellcodeSize);

    /* Create remote thread to execute shellcode */
    HANDLE hThread = nullptr;

    if (flags & NEXUS_INJECT_FLAG_STEALTH) {
        bool skipAttach = (flags & NEXUS_INJECT_FLAG_SKIP_ATTACH) != 0;
        bool hideThread = (flags & NEXUS_INJECT_FLAG_HIDE_THREAD) != 0;

        hThread = CreateRemoteThreadEx_Stealth(
            procData->hProcess,
            remoteShellcode,
            reinterpret_cast<void*>(static_cast<uintptr_t>(parameter)),
            0,
            skipAttach,
            hideThread
        );
    } else {
        hThread = CreateRemoteThread(
            procData->hProcess,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode),
            reinterpret_cast<void*>(static_cast<uintptr_t>(parameter)),
            0,
            nullptr
        );
    }

    if (!hThread) {
        VirtualFreeEx(procData->hProcess, remoteShellcode, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD threadId = GetThreadId(hThread);
    DWORD exitCode = 0;

    if (flags & NEXUS_INJECT_FLAG_WAIT) {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &exitCode);
    }

    CloseHandle(hThread);

    if (result) {
        result->baseAddress = reinterpret_cast<uint64_t>(remoteShellcode);
        result->entryPoint = reinterpret_cast<uint64_t>(remoteShellcode);
        result->threadId = threadId;
        result->exitCode = exitCode;
        result->success = 1;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * DLL Injection (LoadLibrary method)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_InjectDll(
    NexusProcessHandle handle,
    const wchar_t* dllPath,
    uint32_t flags,
    NexusInjectionResult* result
) {
    if (!handle || !dllPath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (result) {
        memset(result, 0, sizeof(NexusInjectionResult));
    }

    uint64_t loadLibraryAddr = GetLoadLibraryWAddress();
    if (!loadLibraryAddr) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    size_t pathLen = wcslen(dllPath) + 1;
    size_t pathSize = pathLen * sizeof(wchar_t);

    /* Allocate memory for path in target process */
    void* remotePath = VirtualAllocEx(
        procData->hProcess,
        nullptr,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remotePath) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(procData->hProcess, remotePath, dllPath, pathSize, &bytesWritten)) {
        VirtualFreeEx(procData->hProcess, remotePath, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Create remote thread to call LoadLibraryW */
    HANDLE hThread = nullptr;

    if (flags & NEXUS_INJECT_FLAG_STEALTH) {
        bool skipAttach = (flags & NEXUS_INJECT_FLAG_SKIP_ATTACH) != 0;
        bool hideThread = (flags & NEXUS_INJECT_FLAG_HIDE_THREAD) != 0;

        hThread = CreateRemoteThreadEx_Stealth(
            procData->hProcess,
            reinterpret_cast<LPVOID>(loadLibraryAddr),
            remotePath,
            0,
            skipAttach,
            hideThread
        );
    } else {
        hThread = CreateRemoteThread(
            procData->hProcess,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
            remotePath,
            0,
            nullptr
        );
    }

    if (!hThread) {
        VirtualFreeEx(procData->hProcess, remotePath, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD threadId = GetThreadId(hThread);
    DWORD exitCode = 0;
    uint64_t dllBase = 0;

    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &exitCode);

    if (procData->is32Bit) {
        dllBase = exitCode;
    } else {
        /* For 64-bit, GetExitCodeThread only returns DWORD (truncated HMODULE) */
        dllBase = exitCode;
    }

    CloseHandle(hThread);
    VirtualFreeEx(procData->hProcess, remotePath, 0, MEM_RELEASE);

    if (result) {
        result->baseAddress = dllBase;
        result->entryPoint = 0;
        result->threadId = threadId;
        result->exitCode = exitCode;
        result->success = (dllBase != 0) ? 1 : 0;
    }

    return (dllBase != 0) ? NEXUS_OK : NEXUS_ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * Remote Function Call
 * ============================================================================ */

NEXUS_API NexusResult Nexus_CallRemoteFunction(
    NexusProcessHandle handle,
    uint64_t functionAddress,
    uint64_t parameter,
    uint32_t flags,
    NexusInjectionResult* result
) {
    if (!handle || functionAddress == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (result) {
        memset(result, 0, sizeof(NexusInjectionResult));
    }

    HANDLE hThread = CreateRemoteThread(
        procData->hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress),
        reinterpret_cast<void*>(static_cast<uintptr_t>(parameter)),
        0,
        nullptr
    );

    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD threadId = GetThreadId(hThread);
    DWORD exitCode = 0;

    if (flags & NEXUS_INJECT_FLAG_WAIT) {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &exitCode);
    }

    CloseHandle(hThread);

    if (result) {
        result->baseAddress = functionAddress;
        result->entryPoint = functionAddress;
        result->threadId = threadId;
        result->exitCode = exitCode;
        result->success = 1;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Cleanup
 * ============================================================================ */

NEXUS_API NexusResult Nexus_FreeInjectedMemory(
    NexusProcessHandle handle,
    uint64_t address
) {
    if (!handle || address == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (!VirtualFreeEx(procData->hProcess, reinterpret_cast<void*>(address), 0, MEM_RELEASE)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    return NEXUS_OK;
}
