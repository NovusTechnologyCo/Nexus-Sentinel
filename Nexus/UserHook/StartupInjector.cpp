/**
 * @file StartupInjector.cpp
 * @brief Launches a process suspended and injects before it runs
 *
 * This bypasses anti-injection by hooking before protections initialize.
 * Usage: StartupInjector.exe "C:\path\to\target.exe" [args]
 *
 * Build: cl /O2 StartupInjector.cpp /link /OUT:StartupInjector.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/**
 * @brief Inject DLL into a suspended process
 */
BOOL InjectIntoSuspended(HANDLE hProcess, HANDLE hThread, const wchar_t* dllPath)
{
    printf("[*] Injecting into suspended process...\n");

    /* Get full path */
    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(dllPath, MAX_PATH, fullPath, NULL)) {
        wcscpy_s(fullPath, dllPath);
    }

    printf("[*] DLL: %S\n", fullPath);

    /* Check DLL exists */
    if (GetFileAttributesW(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL not found\n");
        return FALSE;
    }

    /* Allocate memory for DLL path */
    SIZE_T pathSize = (wcslen(fullPath) + 1) * sizeof(wchar_t);
    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBuffer) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        return FALSE;
    }

    /* Write DLL path */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, fullPath, pathSize, &written)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Get LoadLibraryW */
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    PVOID loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");

    /* Queue APC to load DLL when thread resumes */
    printf("[*] Queuing APC to main thread...\n");
    if (!QueueUserAPC((PAPCFUNC)loadLibrary, hThread, (ULONG_PTR)remoteBuffer)) {
        printf("[!] QueueUserAPC failed: %d\n", GetLastError());

        /* Fallback: create remote thread */
        printf("[*] Trying CreateRemoteThread...\n");
        HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)loadLibrary, remoteBuffer, 0, NULL);

        if (!hRemote) {
            printf("[!] CreateRemoteThread failed: %d\n", GetLastError());
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            return FALSE;
        }

        WaitForSingleObject(hRemote, 5000);
        CloseHandle(hRemote);
    }

    printf("[+] Injection queued successfully\n");
    return TRUE;
}

void PrintUsage(const char* exe)
{
    printf("Startup Injector - Injects DLL before process runs\n\n");
    printf("Usage: %s \"<target.exe>\" [args]\n\n", exe);
    printf("The hook DLL (SecureBootHook.dll) must be in the same directory.\n");
    printf("\nExample:\n");
    printf("  %s \"C:\\Games\\BF\\EAAntiCheat.GameServiceLauncher.exe\"\n", exe);
}

int main(int argc, char* argv[])
{
    printf("=== Startup Injector ===\n\n");

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    /* Build command line */
    wchar_t cmdLine[4096] = {0};
    for (int i = 1; i < argc; i++) {
        wchar_t arg[1024];
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, arg, 1024);

        if (i > 1) wcscat_s(cmdLine, L" ");

        /* Quote if contains spaces */
        if (wcschr(arg, L' ')) {
            wcscat_s(cmdLine, L"\"");
            wcscat_s(cmdLine, arg);
            wcscat_s(cmdLine, L"\"");
        } else {
            wcscat_s(cmdLine, arg);
        }
    }

    printf("[*] Command: %S\n", cmdLine);

    /* Get DLL path (same directory as this exe) */
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash) {
        wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - dllPath) - 1, L"SecureBootHook.dll");
    }

    /* Create process suspended */
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    printf("[*] Creating process suspended...\n");

    if (!CreateProcessW(
            NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            NULL, NULL, &si, &pi))
    {
        printf("[!] CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Process created: PID=%d, TID=%d\n", pi.dwProcessId, pi.dwThreadId);

    /* Inject while suspended */
    BOOL injected = InjectIntoSuspended(pi.hProcess, pi.hThread, dllPath);

    /* Resume process */
    printf("[*] Resuming process...\n");
    ResumeThread(pi.hThread);

    if (injected) {
        printf("\n[+] Process launched with hook!\n");
        printf("[*] Monitor: %%TEMP%%\\SecureBootHook.log\n");
    } else {
        printf("\n[!] Injection failed, process running without hook\n");
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return injected ? 0 : 1;
}
