// NexusInject.exe -- minimal classic UM DLL injector for live tracing.
// Usage: NexusInject.exe <PID> <DllPath>
//
// Path:
//   1. OpenProcess(PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ|QUERY_INFORMATION)
//   2. VirtualAllocEx for the path string
//   3. WriteProcessMemory the path
//   4. CreateRemoteThread targeting kernel32!LoadLibraryW with the path as arg
//   5. Wait for the thread, report module handle (0 = LoadLibraryW returned NULL)
//
// If OpenProcess fails (e.g. EAAC ObRegisterCallbacks downgrades), prints the
// downgraded access rights so we can pick a path that uses what we got.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"Usage: NexusInject.exe <PID> <DllPath>\n");
        return 1;
    }
    DWORD pid = _wtoi(argv[1]);
    LPCWSTR dllPath = argv[2];

    DWORD pathBytes = (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t));

    wprintf(L"[+] Target PID  : %lu\n", pid);
    wprintf(L"[+] DLL Path    : %s\n", dllPath);
    wprintf(L"[+] Path bytes  : %lu\n", pathBytes);

    // Try high-priv first
    DWORD desiredFull =
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(desiredFull, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        wprintf(L"[-] OpenProcess(0x%lX) failed: %lu (0x%lX)\n", desiredFull, err, err);
        // Try minimum-required
        DWORD minRights = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
        hProc = OpenProcess(minRights, FALSE, pid);
        if (!hProc) {
            err = GetLastError();
            wprintf(L"[-] OpenProcess(0x%lX) also failed: %lu (0x%lX)\n", minRights, err, err);
            return 2;
        }
        wprintf(L"[!] Using reduced rights 0x%lX\n", minRights);
    } else {
        wprintf(L"[+] OpenProcess OK with full rights\n");
    }

    LPVOID remotePath = VirtualAllocEx(hProc, NULL, pathBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        wprintf(L"[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 3;
    }
    wprintf(L"[+] Remote path buffer at %p\n", remotePath);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remotePath, dllPath, pathBytes, &written) ||
        written != pathBytes)
    {
        wprintf(L"[-] WriteProcessMemory failed: %lu (wrote=%zu)\n",
            GetLastError(), written);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 4;
    }

    // Resolve LoadLibraryW from local kernel32 (same address in target — kernel32 is
    // ASLR-mapped at the same base for all processes in a boot session)
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        wprintf(L"[-] GetModuleHandleW(kernel32.dll) failed\n");
        return 5;
    }
    FARPROC pLoadLibW = GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLibW) {
        wprintf(L"[-] GetProcAddress(LoadLibraryW) failed\n");
        return 6;
    }
    wprintf(L"[+] LoadLibraryW @ %p\n", pLoadLibW);

    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibW, remotePath, 0, &threadId);
    if (!hThread) {
        DWORD err = GetLastError();
        wprintf(L"[-] CreateRemoteThread failed: %lu (0x%lX)\n", err, err);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 7;
    }
    wprintf(L"[+] Remote thread TID=%lu created\n", threadId);

    DWORD wait = WaitForSingleObject(hThread, 5000);
    if (wait == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        // exitCode is the truncated return value of LoadLibraryW (low 32 bits of HMODULE)
        wprintf(L"[+] Thread completed; LoadLibraryW low32 = 0x%lX (%s)\n",
            exitCode, exitCode ? L"likely success" : L"failed inside loader");
    } else if (wait == WAIT_TIMEOUT) {
        wprintf(L"[!] Thread did not exit in 5s -- may be hung in loader\n");
    } else {
        wprintf(L"[-] WaitForSingleObject failed: %lu\n", GetLastError());
    }

    CloseHandle(hThread);
    // Don't free remotePath in case the DLL still references it briefly
    CloseHandle(hProc);
    wprintf(L"[+] Done. Check C:\\NexusSpy_%lu.log\n", pid);
    return 0;
}
