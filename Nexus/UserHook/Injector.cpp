/**
 * @file Injector.cpp
 * @brief Simple DLL injector for SecureBootHook.dll
 *
 * Usage: Injector.exe <PID or ProcessName> [DLL path]
 *
 * Build: cl /O2 Injector.cpp /link /OUT:Injector.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Find process ID by name
 */
DWORD FindProcessByName(const wchar_t* processName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

/**
 * @brief Inject DLL into target process
 */
BOOL InjectDLL(DWORD pid, const wchar_t* dllPath)
{
    printf("[*] Opening process %d...\n", pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid
    );

    if (!hProcess) {
        printf("[!] OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    /* Get full path */
    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(dllPath, MAX_PATH, fullPath, NULL)) {
        wcscpy_s(fullPath, dllPath);
    }

    printf("[*] DLL path: %S\n", fullPath);

    /* Check if DLL exists */
    if (GetFileAttributesW(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL file not found: %S\n", fullPath);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Allocate memory in target process for DLL path */
    SIZE_T pathSize = (wcslen(fullPath) + 1) * sizeof(wchar_t);
    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBuffer) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[*] Allocated remote buffer at %p\n", remoteBuffer);

    /* Write DLL path to target process */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, fullPath, pathSize, &written)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Get LoadLibraryW address */
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    PVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryW");

    if (!loadLibraryAddr) {
        printf("[!] Failed to find LoadLibraryW\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[*] LoadLibraryW at %p\n", loadLibraryAddr);

    /* Create remote thread to load DLL */
    printf("[*] Creating remote thread...\n");

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteBuffer, 0, NULL
    );

    if (!hThread) {
        printf("[!] CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Wait for thread to complete */
    printf("[*] Waiting for DLL to load...\n");
    WaitForSingleObject(hThread, 5000);

    /* Get exit code (DLL base address) */
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        printf("[!] DLL injection failed (LoadLibrary returned NULL)\n");
        printf("[!] Check if DLL is 64-bit and target process is 64-bit\n");
        return FALSE;
    }

    printf("[+] DLL injected successfully! Base: 0x%08X\n", exitCode);
    return TRUE;
}

/**
 * @brief Print usage
 */
void PrintUsage(const char* argv0)
{
    printf("SecureBootHook DLL Injector\n");
    printf("Usage: %s <PID or ProcessName> [DLL path]\n\n", argv0);
    printf("Examples:\n");
    printf("  %s 1234                          - Inject into PID 1234\n", argv0);
    printf("  %s notepad.exe                   - Inject into notepad.exe\n", argv0);
    printf("  %s 1234 C:\\path\\to\\hook.dll   - Use custom DLL path\n", argv0);
    printf("\nDefault DLL: SecureBootHook.dll (in same directory as injector)\n");
}

int main(int argc, char* argv[])
{
    printf("=== SecureBootHook DLL Injector ===\n\n");

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    /* Parse target (PID or process name) */
    DWORD targetPid = 0;
    char* endPtr = NULL;
    targetPid = strtoul(argv[1], &endPtr, 10);

    if (*endPtr != '\0') {
        /* Not a number, treat as process name */
        wchar_t processName[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, processName, MAX_PATH);

        printf("[*] Looking for process: %S\n", processName);
        targetPid = FindProcessByName(processName);

        if (targetPid == 0) {
            printf("[!] Process not found: %s\n", argv[1]);
            return 1;
        }
    }

    printf("[*] Target PID: %d\n", targetPid);

    /* Get DLL path */
    wchar_t dllPath[MAX_PATH];

    if (argc >= 3) {
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, dllPath, MAX_PATH);
    } else {
        /* Use default: SecureBootHook.dll in same directory */
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);

        /* Replace exe name with dll name */
        wchar_t* lastSlash = wcsrchr(exePath, L'\\');
        if (lastSlash) {
            wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - exePath) - 1, L"SecureBootHook.dll");
            wcscpy_s(dllPath, exePath);
        } else {
            wcscpy_s(dllPath, L"SecureBootHook.dll");
        }
    }

    /* Inject */
    if (InjectDLL(targetPid, dllPath)) {
        printf("\n[+] Injection successful!\n");
        printf("[*] Check %%TEMP%%\\SecureBootHook.log for monitoring output\n");
        printf("[*] Use DebugView to see real-time output\n");
        return 0;
    }

    return 1;
}
