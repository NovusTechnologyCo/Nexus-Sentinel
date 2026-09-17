/**
 * @file process.cpp
 * @brief Process enumeration, open/close, info, raw handle, and module enumeration.
 *
 * Implements the core process lifecycle APIs: snapshot-based enumeration
 * via CreateToolhelp32Snapshot, tiered-access OpenProcess with automatic
 * fallback to lower privilege levels, WOW64/ARM64 detection via
 * IsWow64Process2, and module enumeration.
 *
 * Thread and handle operations are split into process_thread.cpp.
 */

#include "process_internal.h"

/**
 * @brief Check whether a process is running as 32-bit (WOW64 or ARM32 emulation).
 *
 * Prefers IsWow64Process2 (Windows 10 1709+) for correct ARM64 detection;
 * falls back to the legacy IsWow64Process on older builds.
 *
 * @param hProcess  Open process handle with at least PROCESS_QUERY_LIMITED_INFORMATION.
 * @return TRUE if the process is 32-bit, FALSE if native 64-bit.
 */
static BOOL IsProcess32Bit(HANDLE hProcess) {
    /* Thread-safe initialization using std::call_once */
    typedef BOOL (WINAPI *PFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
    static PFN_IsWow64Process2 pIsWow64Process2 = nullptr;
    static std::once_flag g_wow64InitFlag;

    std::call_once(g_wow64InitFlag, []() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            pIsWow64Process2 = (PFN_IsWow64Process2)GetProcAddress(hKernel32, "IsWow64Process2");
        }
    });

    if (pIsWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (pIsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
            if (processMachine == IMAGE_FILE_MACHINE_I386 ||
                processMachine == IMAGE_FILE_MACHINE_ARMNT) {
                return TRUE;
            }
            return FALSE;
        }
    }

    // Fallback to IsWow64Process for older Windows
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        return isWow64;
    }
    return FALSE;
}

/* ============================================================================
 * Process Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EnumerateProcesses(
    NexusProcessInfo* buffer,
    size_t bufferCount,
    size_t* processCount
) {
    if (!processCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        *processCount = 0;
        if (err == ERROR_ACCESS_DENIED) return NEXUS_ERROR_ACCESS_DENIED;
        if (err == ERROR_INVALID_PARAMETER) return NEXUS_ERROR_INVALID_PARAMETER;
        return NEXUS_ERROR_UNKNOWN;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    size_t count = 0;
    NexusResult result = NEXUS_OK;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            /* Skip system processes (PID 0 = System Idle, PID 4 = System) */
            if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) {
                continue;
            }

            if (buffer && count < bufferCount) {
                NexusProcessInfo* info = &buffer[count];
                info->pid = pe32.th32ProcessID;
                info->parentPid = pe32.th32ParentProcessID;
                wcsncpy_s(info->name, 260, pe32.szExeFile, _TRUNCATE);
                info->path[0] = L'\0';
                info->is32Bit = 0;

                /* Try to get full path and bitness */
                HANDLE hProc = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    pe32.th32ProcessID
                );
                if (hProc) {
                    DWORD pathLen = 520;
                    QueryFullProcessImageNameW(hProc, 0, info->path, &pathLen);
                    info->is32Bit = IsProcess32Bit(hProc) ? 1 : 0;
                    CloseHandle(hProc);
                }
            }
            count++;
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    *processCount = count;

    if (buffer && count > bufferCount) {
        result = NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return result;
}

/**
 * @brief Map a NexusProcessAccess tier to a Windows PROCESS_* access mask.
 *
 * Each tier includes all rights of the tiers below it plus additional
 * capabilities (e.g. FULL adds thread control and synchronization).
 *
 * @param access  Desired access level.
 * @return Bitwise OR of Windows PROCESS_* constants.
 */
static DWORD GetAccessRightsForLevel(NexusProcessAccess access) {
    switch (access) {
        case NEXUS_PROCESS_QUERY:
            return PROCESS_QUERY_INFORMATION;

        case NEXUS_PROCESS_READ:
            return PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

        case NEXUS_PROCESS_READWRITE:
            return PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

        case NEXUS_PROCESS_FULL:
            return PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                   PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
                   SYNCHRONIZE;

        case NEXUS_PROCESS_DEBUG:
            return PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                   PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
                   PROCESS_DUP_HANDLE | SYNCHRONIZE;

        default:
            return PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    }
}

NEXUS_API NexusResult Nexus_OpenProcessEx(
    uint32_t pid,
    NexusProcessAccess access,
    NexusProcessHandle* handle
) {
    if (!handle) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *handle = nullptr;

    NexusProcessAccess requestedAccess = access;
    DWORD desiredAccess = GetAccessRightsForLevel(access);

    HANDLE hProcess = OpenProcess(desiredAccess, FALSE, pid);

    /* If access denied, try falling back to lower access level */
    if (!hProcess && access > NEXUS_PROCESS_QUERY) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            if (access >= NEXUS_PROCESS_READWRITE) {
                desiredAccess = GetAccessRightsForLevel(NEXUS_PROCESS_READ);
                hProcess = OpenProcess(desiredAccess, FALSE, pid);
                if (hProcess) {
                    access = NEXUS_PROCESS_READ;
                }
            }
            if (!hProcess) {
                desiredAccess = GetAccessRightsForLevel(NEXUS_PROCESS_QUERY);
                hProcess = OpenProcess(desiredAccess, FALSE, pid);
                if (hProcess) {
                    access = NEXUS_PROCESS_QUERY;
                }
            }
        }
    }

    if (!hProcess) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
        return NEXUS_ERROR_NOT_FOUND;
    }

    auto* data = static_cast<NexusProcessHandleData*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NexusProcessHandleData))
    );

    if (!data) {
        CloseHandle(hProcess);
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    data->magic = NEXUS_PROCESS_HANDLE_MAGIC;
    data->hProcess = hProcess;
    data->pid = pid;
    data->is32Bit = IsProcess32Bit(hProcess);
    data->requestedAccess = requestedAccess;
    data->actualAccess = access;

    *handle = data;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_OpenProcess(
    uint32_t pid,
    NexusProcessHandle* handle
) {
    return Nexus_OpenProcessEx(pid, NEXUS_PROCESS_READWRITE, handle);
}

NEXUS_API NexusResult Nexus_GetProcessAccess(
    NexusProcessHandle handle,
    NexusProcessAccess* access
) {
    if (!handle || !access) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    *access = data->actualAccess;
    return NEXUS_OK;
}

NEXUS_API void Nexus_CloseProcess(NexusProcessHandle handle) {
    if (!handle) return;

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return;
    }

    if (data->hProcess) {
        CloseHandle(data->hProcess);
        data->hProcess = NULL;
    }

    data->magic = NEXUS_PROCESS_HANDLE_FREED;

    SecureZeroMemory(data, sizeof(NexusProcessHandleData));

    HeapFree(GetProcessHeap(), 0, data);
}

NEXUS_API NexusResult Nexus_GetProcessInfo(
    NexusProcessHandle handle,
    NexusProcessInfo* info
) {
    if (!handle || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    info->pid = data->pid;
    info->is32Bit = data->is32Bit ? 1 : 0;

    info->parentPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == data->pid) {
                    info->parentPid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    DWORD pathLen = 520;
    if (QueryFullProcessImageNameW(data->hProcess, 0, info->path, &pathLen)) {
        const wchar_t* lastSlash = wcsrchr(info->path, L'\\');
        if (lastSlash) {
            wcsncpy_s(info->name, 260, lastSlash + 1, _TRUNCATE);
        } else {
            wcsncpy_s(info->name, 260, info->path, _TRUNCATE);
        }
    } else {
        info->name[0] = L'\0';
        info->path[0] = L'\0';
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetRawHandle(
    NexusProcessHandle handle,
    void** rawHandle
) {
    if (!handle || !rawHandle) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    *rawHandle = data->hProcess;
    return NEXUS_OK;
}

/* ============================================================================
 * Module Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EnumerateModules(
    NexusProcessHandle handle,
    NexusModuleInfo* buffer,
    size_t bufferCount,
    size_t* moduleCount
) {
    if (!handle || !moduleCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->magic != NEXUS_PROCESS_HANDLE_MAGIC) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    DWORD flags = TH32CS_SNAPMODULE;
    if (data->is32Bit) {
        flags |= TH32CS_SNAPMODULE32;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(flags, data->pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        *moduleCount = 0;
        if (err == ERROR_ACCESS_DENIED) return NEXUS_ERROR_ACCESS_DENIED;
        if (err == ERROR_PARTIAL_COPY) return NEXUS_ERROR_PARTIAL;
        return NEXUS_ERROR_UNKNOWN;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(me32);

    size_t count = 0;
    NexusResult result = NEXUS_OK;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (buffer && count < bufferCount) {
                NexusModuleInfo* info = &buffer[count];
                info->baseAddress = reinterpret_cast<uint64_t>(me32.modBaseAddr);
                info->size = me32.modBaseSize;
                wcsncpy_s(info->name, 260, me32.szModule, _TRUNCATE);
                wcsncpy_s(info->path, 520, me32.szExePath, _TRUNCATE);
            }
            count++;
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);

    *moduleCount = count;

    if (buffer && count > bufferCount) {
        result = NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return result;
}
