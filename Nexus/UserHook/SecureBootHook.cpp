/**
 * @file SecureBootHook.cpp
 * @brief User-mode DLL to hook NtQuerySystemInformation and monitor SecureBoot queries
 *
 * This DLL can be injected into processes (like EA anti-cheat) to monitor
 * when they query SecureBoot status via NtQuerySystemInformation.
 *
 * Build: cl /LD /O2 SecureBootHook.cpp /link /OUT:SecureBootHook.dll
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

/* SystemInformation classes we're monitoring */
#define SystemSecureBootInformation        0x91   /* 145 */
#define SystemSecureBootPolicyInformation  0xAF   /* 175 */
#define SystemCodeIntegrityInformation     103

/* NexusKernel IOCTL for logging ETW events */
#define NEXUS_DEVICE_TYPE   0x8000
#define NEXUS_IOCTL_BASE    0x800
#define CTL_CODE_NEXUS(code) \
    (ULONG)((NEXUS_DEVICE_TYPE << 16) | (0 << 14) | ((NEXUS_IOCTL_BASE + (code)) << 2) | 0)

#define IOCTL_NEXUS_ETW_LOG_EVENT  CTL_CODE_NEXUS(0xDD)  /* Custom IOCTL for logging from user-mode */

/* Event structure to send to kernel */
#pragma pack(push, 1)
typedef struct _SECUREBOOT_QUERY_EVENT {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG InfoClass;
    LONG  Status;
    ULONG ReturnLength;
    UCHAR ResultData[16];  /* First 16 bytes of result */
} SECUREBOOT_QUERY_EVENT, *PSECUREBOOT_QUERY_EVENT;
#pragma pack(pop)

/* Original function type */
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/* Globals */
static PFN_NtQuerySystemInformation g_OriginalNtQuerySystemInformation = NULL;
static BYTE g_OriginalBytes[14] = {0};
static PVOID g_HookAddress = NULL;
static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_Lock;
static BOOL g_Initialized = FALSE;
static FILE* g_LogFile = NULL;

/* Statistics */
static volatile LONG g_TotalCalls = 0;
static volatile LONG g_SecureBootQueries = 0;
static volatile LONG g_CodeIntegrityQueries = 0;

/**
 * @brief Log a message to debug output and optionally to file
 */
static void LogMessage(const char* format, ...)
{
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA(buffer);

    if (g_LogFile) {
        fprintf(g_LogFile, "%s", buffer);
        fflush(g_LogFile);
    }
}

/**
 * @brief Send event to kernel driver
 */
static void SendEventToKernel(ULONG infoClass, NTSTATUS status, PVOID resultData, ULONG resultLen)
{
    if (g_DriverHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    SECUREBOOT_QUERY_EVENT event = {0};
    event.ProcessId = GetCurrentProcessId();
    event.ThreadId = GetCurrentThreadId();
    event.InfoClass = infoClass;
    event.Status = status;
    event.ReturnLength = resultLen;

    if (resultData && resultLen > 0) {
        memcpy(event.ResultData, resultData, min(resultLen, sizeof(event.ResultData)));
    }

    DWORD bytesReturned = 0;
    DeviceIoControl(
        g_DriverHandle,
        IOCTL_NEXUS_ETW_LOG_EVENT,
        &event, sizeof(event),
        NULL, 0,
        &bytesReturned, NULL
    );
}

/**
 * @brief Our hooked NtQuerySystemInformation
 */
static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    InterlockedIncrement(&g_TotalCalls);

    /* Call original function */
    NTSTATUS status = g_OriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    ULONG infoClass = (ULONG)SystemInformationClass;

    /* Check if this is a security-related query */
    BOOL isSecurityQuery = FALSE;
    const char* queryName = NULL;

    if (infoClass == SystemSecureBootInformation) {
        InterlockedIncrement(&g_SecureBootQueries);
        isSecurityQuery = TRUE;
        queryName = "SystemSecureBootInformation";
    }
    else if (infoClass == SystemSecureBootPolicyInformation) {
        InterlockedIncrement(&g_SecureBootQueries);
        isSecurityQuery = TRUE;
        queryName = "SystemSecureBootPolicyInformation";
    }
    else if (infoClass == SystemCodeIntegrityInformation) {
        InterlockedIncrement(&g_CodeIntegrityQueries);
        isSecurityQuery = TRUE;
        queryName = "SystemCodeIntegrityInformation";
    }

    if (isSecurityQuery) {
        /* Get caller address for logging */
        PVOID returnAddress = _ReturnAddress();

        /* Log the query */
        LogMessage("[SecureBootHook] %s (0x%X) called from 0x%p, Status=0x%08X\n",
            queryName, infoClass, returnAddress, status);

        /* Log result data if successful */
        if (NT_SUCCESS(status) && SystemInformation && SystemInformationLength > 0) {
            if (infoClass == SystemSecureBootInformation && SystemInformationLength >= 1) {
                UCHAR secureBootEnabled = *(PUCHAR)SystemInformation;
                LogMessage("[SecureBootHook]   -> SecureBootEnabled: %s\n",
                    secureBootEnabled ? "YES" : "NO");
            }
            else if (infoClass == SystemCodeIntegrityInformation && SystemInformationLength >= 8) {
                ULONG ciOptions = *(PULONG)((PUCHAR)SystemInformation + 4);
                LogMessage("[SecureBootHook]   -> CodeIntegrityOptions: 0x%08X\n", ciOptions);
            }
        }

        /* Send to kernel driver */
        SendEventToKernel(infoClass, status, SystemInformation,
            ReturnLength ? *ReturnLength : SystemInformationLength);
    }

    return status;
}

/**
 * @brief Create a trampoline for the original function
 */
static PVOID CreateTrampoline(PVOID originalFunc, SIZE_T prologSize)
{
    /* Allocate executable memory for trampoline */
    PVOID trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        return NULL;
    }

    /* Copy original bytes */
    memcpy(trampoline, originalFunc, prologSize);

    /* Add jump back to original function + prologSize */
    PUCHAR jumpBack = (PUCHAR)trampoline + prologSize;

    /* x64: jmp [rip+0] followed by 8-byte address */
    jumpBack[0] = 0xFF;
    jumpBack[1] = 0x25;
    jumpBack[2] = 0x00;
    jumpBack[3] = 0x00;
    jumpBack[4] = 0x00;
    jumpBack[5] = 0x00;
    *(PVOID*)(jumpBack + 6) = (PUCHAR)originalFunc + prologSize;

    return trampoline;
}

/**
 * @brief Install inline hook
 */
static BOOL InstallHook(void)
{
    /* Get NtQuerySystemInformation address */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        LogMessage("[SecureBootHook] Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    g_HookAddress = GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!g_HookAddress) {
        LogMessage("[SecureBootHook] Failed to find NtQuerySystemInformation\n");
        return FALSE;
    }

    LogMessage("[SecureBootHook] NtQuerySystemInformation at %p\n", g_HookAddress);

    /* Save original bytes (14 bytes for x64 jmp) */
    memcpy(g_OriginalBytes, g_HookAddress, sizeof(g_OriginalBytes));

    /* Create trampoline (assume 14+ byte prolog - we'll use 16 to be safe) */
    PVOID trampoline = CreateTrampoline(g_HookAddress, 16);
    if (!trampoline) {
        LogMessage("[SecureBootHook] Failed to create trampoline\n");
        return FALSE;
    }

    g_OriginalNtQuerySystemInformation = (PFN_NtQuerySystemInformation)trampoline;
    LogMessage("[SecureBootHook] Trampoline at %p\n", trampoline);

    /* Build hook jump: FF 25 00 00 00 00 [8-byte address] */
    BYTE hookJump[14];
    hookJump[0] = 0xFF;
    hookJump[1] = 0x25;
    hookJump[2] = 0x00;
    hookJump[3] = 0x00;
    hookJump[4] = 0x00;
    hookJump[5] = 0x00;
    *(PVOID*)(hookJump + 6) = (PVOID)HookedNtQuerySystemInformation;

    /* Make original function writable */
    DWORD oldProtect;
    if (!VirtualProtect(g_HookAddress, sizeof(hookJump), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogMessage("[SecureBootHook] VirtualProtect failed: %d\n", GetLastError());
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Install hook */
    memcpy(g_HookAddress, hookJump, sizeof(hookJump));

    /* Restore protection */
    VirtualProtect(g_HookAddress, sizeof(hookJump), oldProtect, &oldProtect);

    /* Flush instruction cache */
    FlushInstructionCache(GetCurrentProcess(), g_HookAddress, sizeof(hookJump));

    LogMessage("[SecureBootHook] Hook installed successfully\n");
    return TRUE;
}

/**
 * @brief Remove the hook
 */
static void RemoveHook(void)
{
    if (!g_HookAddress || !g_OriginalNtQuerySystemInformation) {
        return;
    }

    /* Make writable */
    DWORD oldProtect;
    if (VirtualProtect(g_HookAddress, sizeof(g_OriginalBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        /* Restore original bytes */
        memcpy(g_HookAddress, g_OriginalBytes, sizeof(g_OriginalBytes));
        VirtualProtect(g_HookAddress, sizeof(g_OriginalBytes), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), g_HookAddress, sizeof(g_OriginalBytes));
    }

    /* Free trampoline */
    if (g_OriginalNtQuerySystemInformation) {
        VirtualFree((PVOID)g_OriginalNtQuerySystemInformation, 0, MEM_RELEASE);
        g_OriginalNtQuerySystemInformation = NULL;
    }

    LogMessage("[SecureBootHook] Hook removed\n");
}

/**
 * @brief Initialize the hook DLL
 */
static BOOL Initialize(void)
{
    if (g_Initialized) {
        return TRUE;
    }

    InitializeCriticalSection(&g_Lock);

    /* Open log file in temp directory */
    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, "SecureBootHook.log");
    fopen_s(&g_LogFile, logPath, "a");

    LogMessage("\n[SecureBootHook] ========== DLL Loaded ==========\n");
    LogMessage("[SecureBootHook] Process: %d (%S)\n", GetCurrentProcessId(), GetCommandLineW());
    LogMessage("[SecureBootHook] Log file: %s\n", logPath);

    /* Try to connect to kernel driver */
    g_DriverHandle = CreateFileW(
        L"\\\\.\\NexusKernel",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (g_DriverHandle != INVALID_HANDLE_VALUE) {
        LogMessage("[SecureBootHook] Connected to NexusKernel driver\n");
    } else {
        LogMessage("[SecureBootHook] NexusKernel driver not available (standalone mode)\n");
    }

    /* Install the hook */
    if (!InstallHook()) {
        LogMessage("[SecureBootHook] Failed to install hook\n");
        return FALSE;
    }

    g_Initialized = TRUE;
    return TRUE;
}

/**
 * @brief Cleanup
 */
static void Cleanup(void)
{
    if (!g_Initialized) {
        return;
    }

    RemoveHook();

    LogMessage("[SecureBootHook] Stats: Total=%d, SecureBoot=%d, CodeIntegrity=%d\n",
        g_TotalCalls, g_SecureBootQueries, g_CodeIntegrityQueries);
    LogMessage("[SecureBootHook] ========== DLL Unloaded ==========\n\n");

    if (g_DriverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }

    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = NULL;
    }

    DeleteCriticalSection(&g_Lock);
    g_Initialized = FALSE;
}

/**
 * @brief DLL entry point
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        return Initialize();

    case DLL_PROCESS_DETACH:
        Cleanup();
        break;
    }

    return TRUE;
}

/**
 * @brief Export function to get hook statistics
 */
extern "C" __declspec(dllexport) void GetHookStats(PLONG total, PLONG secureBoot, PLONG codeIntegrity)
{
    if (total) *total = g_TotalCalls;
    if (secureBoot) *secureBoot = g_SecureBootQueries;
    if (codeIntegrity) *codeIntegrity = g_CodeIntegrityQueries;
}

/**
 * @brief Export function to check if hook is active
 */
extern "C" __declspec(dllexport) BOOL IsHookActive(void)
{
    return g_Initialized && g_OriginalNtQuerySystemInformation != NULL;
}
