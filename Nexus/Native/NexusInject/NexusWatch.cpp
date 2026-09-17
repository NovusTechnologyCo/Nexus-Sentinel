// NexusWatch.exe -- detect target process spawn, suspend, inject spy DLL, resume, tail log.
//
// Usage:
//   NexusWatch.exe <ProcessImageName> <DllPath>
// Example:
//   NexusWatch.exe EAAntiCheat.GameServiceLauncher.exe C:\path\to\NexusSpy.dll
//
// Strategy:
//   1. Tight 25ms polling loop using NtQuerySystemInformation(SystemProcessInformation).
//   2. On new PID matching <ProcessImageName>:
//      a. OpenProcess(PROCESS_ALL_ACCESS)
//      b. NtSuspendProcess  -- freezes target before its main runs much
//      c. Manual-map the spy DLL (allocate RWX, write image, reloc, IAT, shellcode call DllMain)
//      d. NtResumeProcess
//      e. Print log file path; tail it
//   3. After log is created, follow it with simple ReadFile loop.
//
// This is racing the launcher's tier-1 check; with NtSuspendProcess the race is fine
// because we can suspend at any point in startup and inject while the launcher is frozen.

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtSuspendProcess(HANDLE);
extern "C" NTSTATUS NTAPI NtResumeProcess(HANDLE);

// ===== Re-implement the manual mapper inline =====

static const unsigned char SC_TEMPLATE[] = {
    0x48, 0xB9, 0,0,0,0,0,0,0,0,
    0xBA, 0x01, 0x00, 0x00, 0x00,
    0x45, 0x33, 0xC0,
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB8, 0,0,0,0,0,0,0,0,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
};
#define SC_LEN 39
#define SC_OFF_HMOD  2
#define SC_OFF_ENTRY 24

static BYTE* ReadFileFully(const wchar_t* path, DWORD* outSize) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)malloc(sz);
    DWORD got = 0;
    ReadFile(h, buf, sz, &got, NULL);
    CloseHandle(h);
    *outSize = got;
    return buf;
}

static int ManualMap(HANDLE hProc, const wchar_t* dllPath, ULONG_PTR* outRemoteBase) {
    DWORD fileSize;
    BYTE* fileBuf = ReadFileFully(dllPath, &fileSize);
    if (!fileBuf) { wprintf(L"[mm] open DLL failed: %lu\n", GetLastError()); return -1; }

    if (*(WORD*)fileBuf != 'ZM') return -2;
    DWORD e_lfanew = *(DWORD*)(fileBuf + 0x3C);
    if (*(DWORD*)(fileBuf + e_lfanew) != 0x4550) return -3;
    IMAGE_NT_HEADERS64* nth = (IMAGE_NT_HEADERS64*)(fileBuf + e_lfanew);
    DWORD sizeOfImage = nth->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nth->OptionalHeader.SizeOfHeaders;
    ULONGLONG imageBase = nth->OptionalHeader.ImageBase;
    DWORD entryRva = nth->OptionalHeader.AddressOfEntryPoint;
    WORD nSec = nth->FileHeader.NumberOfSections;

    BYTE* localImg = (BYTE*)VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memset(localImg, 0, sizeOfImage);
    memcpy(localImg, fileBuf, sizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nSec; i++) {
        if (sec[i].SizeOfRawData) {
            memcpy(localImg + sec[i].VirtualAddress,
                   fileBuf + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }
    }

    BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        wprintf(L"[mm] VirtualAllocEx failed: %lu\n", GetLastError());
        return -4;
    }

    LONGLONG delta = (LONGLONG)remoteBase - (LONGLONG)imageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY rd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.Size) {
            BYTE* p = localImg + rd.VirtualAddress;
            BYTE* pEnd = p + rd.Size;
            while (p < pEnd) {
                IMAGE_BASE_RELOCATION* rb = (IMAGE_BASE_RELOCATION*)p;
                if (rb->SizeOfBlock == 0) break;
                int n = (rb->SizeOfBlock - sizeof(*rb)) / 2;
                WORD* entries = (WORD*)(rb + 1);
                for (int i = 0; i < n; i++) {
                    int type = entries[i] >> 12;
                    int off = entries[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* addr = (ULONGLONG*)(localImg + rb->VirtualAddress + off);
                        *addr += delta;
                    }
                }
                p += rb->SizeOfBlock;
            }
        }
    }

    IMAGE_DATA_DIRECTORY id = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id.Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(localImg + id.VirtualAddress);
        for (; imp->Name; imp++) {
            const char* dn = (const char*)(localImg + imp->Name);
            HMODULE hMod = LoadLibraryA(dn);
            if (!hMod) { wprintf(L"[mm] miss DLL %hs\n", dn); return -5; }
            ULONGLONG* oft = (ULONGLONG*)(localImg + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            ULONGLONG* ft = (ULONGLONG*)(localImg + imp->FirstThunk);
            for (; *oft; oft++, ft++) {
                FARPROC fn;
                if (*oft & IMAGE_ORDINAL_FLAG64) fn = GetProcAddress(hMod, (LPCSTR)(*oft & 0xFFFF));
                else { IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(localImg + *oft); fn = GetProcAddress(hMod, ibn->Name); }
                if (!fn) return -6;
                *ft = (ULONGLONG)fn;
            }
        }
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteBase, localImg, sizeOfImage, &written)) {
        wprintf(L"[mm] WPM failed: %lu\n", GetLastError()); return -7;
    }

    BYTE sc[SC_LEN];
    memcpy(sc, SC_TEMPLATE, SC_LEN);
    *(ULONGLONG*)(sc + SC_OFF_HMOD) = (ULONGLONG)remoteBase;
    *(ULONGLONG*)(sc + SC_OFF_ENTRY) = (ULONGLONG)remoteBase + entryRva;

    BYTE* remoteSc = (BYTE*)VirtualAllocEx(hProc, NULL, 0x100,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteSc) return -8;
    if (!WriteProcessMemory(hProc, remoteSc, sc, SC_LEN, &written)) return -9;

    DWORD tid = 0;
    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, &tid);
    if (!hT) return -10;
    WaitForSingleObject(hT, 5000);
    DWORD ec = 0;
    GetExitCodeThread(hT, &ec);
    CloseHandle(hT);

    VirtualFree(localImg, 0, MEM_RELEASE);
    free(fileBuf);
    *outRemoteBase = (ULONG_PTR)remoteBase;
    wprintf(L"[mm] DllMain return = 0x%lX (remoteBase=%p)\n", ec, remoteBase);
    return 0;
}

// ===== Process detection =====

static DWORD FindProcess(const wchar_t* targetName, DWORD ignorePid) {
    DWORD pids[1024];
    DWORD bytesReturned = 0;
    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) return 0;
    DWORD count = bytesReturned / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++) {
        DWORD pid = pids[i];
        if (pid == 0 || pid == 4 || pid == ignorePid) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) continue;
        wchar_t baseName[MAX_PATH];
        DWORD nlen = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, baseName, &nlen)) {
            // Get the basename
            wchar_t* lastSlash = wcsrchr(baseName, L'\\');
            const wchar_t* base = lastSlash ? lastSlash + 1 : baseName;
            if (_wcsicmp(base, targetName) == 0) {
                CloseHandle(h);
                return pid;
            }
        }
        CloseHandle(h);
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"Usage: NexusWatch.exe <TargetImageName> <DllPath>\n");
        wprintf(L"  Example: NexusWatch.exe EAAntiCheat.GameServiceLauncher.exe C:\\path\\NexusSpy.dll\n");
        return 1;
    }
    const wchar_t* targetName = argv[1];
    const wchar_t* dllPath = argv[2];

    wprintf(L"[+] Watching for process: %s\n", targetName);
    wprintf(L"[+] DLL to inject       : %s\n", dllPath);
    wprintf(L"[+] Polling interval    : 25ms\n");
    wprintf(L"[+] Press Ctrl+C to stop\n\n");

    DWORD seenPid = 0; // last PID we already injected into

    while (true) {
        DWORD pid = FindProcess(targetName, seenPid);
        if (pid != 0) {
            wprintf(L"[!] DETECTED %s @ PID=%lu\n", targetName, pid);

            // 1. OpenProcess (suspend rights + everything we need)
            HANDLE hProc = OpenProcess(
                PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                FALSE, pid);
            if (!hProc) {
                wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
                seenPid = pid;
                Sleep(100);
                continue;
            }

            // 2. SUSPEND immediately
            NTSTATUS susp = NtSuspendProcess(hProc);
            wprintf(L"[+] NtSuspendProcess status=0x%lX\n", susp);

            // 3. Manual map
            ULONG_PTR remoteBase = 0;
            int rc = ManualMap(hProc, dllPath, &remoteBase);
            wprintf(L"[+] ManualMap rc=%d\n", rc);

            // 4. RESUME
            NTSTATUS res = NtResumeProcess(hProc);
            wprintf(L"[+] NtResumeProcess status=0x%lX\n", res);

            wprintf(L"[+] Log path: C:\\ProgramData\\NexusSpy_%lu.log\n", pid);
            CloseHandle(hProc);
            seenPid = pid;
            // Keep watching for re-launches
        }
        Sleep(25);
    }
    return 0;
}
