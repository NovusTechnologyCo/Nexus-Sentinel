// NexusWatchExternal.exe -- out-of-process bait-string scanner.
//
// Purpose: detect when "cheatengine-x86_64.exe" (positive control) or
// "cheatengine-x86_66.exe" (negative control) literals appear inside the
// EAAC launcher's address space, WITHOUT injecting any thread or DLL
// into the launcher (which trips Themida packer31 self-integrity).
//
// Mechanism:
//   * OpenProcess with the smallest possible right set: PROCESS_QUERY_INFORMATION
//     and PROCESS_VM_READ (no VM_WRITE, no VM_OPERATION, no CREATE_THREAD).
//     EAAC's ObRegisterCallbacks downgrades these only when a real driver is
//     attached -- we open BEFORE the launcher loads its driver.
//   * Every poll interval (default 25 ms): VirtualQueryEx walks the launcher's
//     VAD tree. Each committed RW/RWX region <= 64 MB is ReadProcessMemory'd
//     into a local buffer and memmem-scanned for each bait string in both
//     ASCII and UTF-16 LE.
//   * On every hit (deduplicated by (address, bait)), prints a line with:
//       timestamp, addr, bait_label, region_type, region_size,
//       module_name (if image-backed), 64 hex bytes around the hit.
//
// Usage:
//   NexusWatchExternal.exe <pid>              -- attach to a running PID
//   NexusWatchExternal.exe --watch-name <name> -- poll until a process with
//       that name appears, then attach. Useful for racing the launcher start.
//
// Output:
//   * stdout (live console)
//   * C:\ProgramData\NexusWatchExt_<targetPid>.log  (verbose, full hex)

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

// ---- Bait config ----
struct Bait {
    const char* label;
    const char* a;
    const wchar_t* w;
};
static const Bait BAITS[] = {
    { "POS_cheatengine_x64",    "cheatengine-x86_64.exe", L"cheatengine-x86_64.exe" },
    { "NEG_cheatengine_x66",    "cheatengine-x86_66.exe", L"cheatengine-x86_66.exe" },
    { "POS_CheatEngine_proper", "Cheat Engine.exe",        L"Cheat Engine.exe"        },
    { "POS_x64dbg",             "x64dbg.exe",              L"x64dbg.exe"              },
    { "POS_windbg",             "windbg.exe",              L"windbg.exe"              },
};
static const size_t BAIT_COUNT = sizeof(BAITS) / sizeof(BAITS[0]);

// ---- Dedup ring ----
struct Seen {
    void*  addr;
    int    baitIdx;
    int    encoding; // 0 ASCII, 1 UTF-16
};
#define MAX_SEEN 1024
static Seen g_seen[MAX_SEEN];
static int  g_seenCount = 0;

static bool MarkSeen(void* a, int b, int e) {
    for (int i = 0; i < g_seenCount; i++) {
        if (g_seen[i].addr == a && g_seen[i].baitIdx == b && g_seen[i].encoding == e)
            return false;
    }
    if (g_seenCount < MAX_SEEN) {
        g_seen[g_seenCount].addr     = a;
        g_seen[g_seenCount].baitIdx  = b;
        g_seen[g_seenCount].encoding = e;
        g_seenCount++;
        return true;
    }
    return true;
}

// ---- Logging ----
static FILE* g_log = NULL;
static CRITICAL_SECTION g_logCs;
static bool  g_autoDumpMapped = false;
static bool  g_didAutoDump    = false; // one-shot

static void LogLine(const char* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    char ts[40];
    sprintf_s(ts, sizeof(ts), "%02d:%02d:%02d.%03d",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    vsprintf_s(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    EnterCriticalSection(&g_logCs);
    printf("%s %s\n", ts, buf); fflush(stdout);
    if (g_log) {
        fprintf(g_log, "%s %s\n", ts, buf);
        fflush(g_log);
    }
    LeaveCriticalSection(&g_logCs);
}

// ---- memmem ----
static const unsigned char* memmem_ci0(const unsigned char* hay, size_t hlen,
                                       const void* needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    const unsigned char* n = (const unsigned char*)needle;
    unsigned char first = n[0];
    size_t limit = hlen - nlen;
    for (size_t i = 0; i <= limit; i++) {
        if (hay[i] == first && memcmp(hay + i, n, nlen) == 0) return hay + i;
    }
    return NULL;
}

// ---- Module-name helper ----
static void DescribeRemoteAddr(HANDLE hProc, void* addr,
                               char* out, size_t outsz) {
    HMODULE mods[512];
    DWORD needed = 0;
    if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        DWORD nmod = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < nmod; i++) {
            MODULEINFO mi;
            if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
                ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
                ULONG_PTR end  = base + mi.SizeOfImage;
                if ((ULONG_PTR)addr >= base && (ULONG_PTR)addr < end) {
                    char modPath[MAX_PATH] = {0};
                    GetModuleFileNameExA(hProc, mods[i], modPath, MAX_PATH);
                    const char* bn = strrchr(modPath, '\\');
                    sprintf_s(out, outsz, "image:%s+0x%zX",
                              bn ? bn + 1 : modPath,
                              (ULONG_PTR)addr - base);
                    return;
                }
            }
        }
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const char* type =
            (mbi.Type == MEM_IMAGE)   ? "IMAGE"   :
            (mbi.Type == MEM_MAPPED)  ? "MAPPED"  :
            (mbi.Type == MEM_PRIVATE) ? "PRIVATE" : "?";
        sprintf_s(out, outsz, "%s prot=0x%X size=0x%zX",
                  type, mbi.Protect, mbi.RegionSize);
    } else {
        strcpy_s(out, outsz, "<no-info>");
    }
}

// ---- Find process by name (substring, case-insensitive).
//      If multiple matches, prefer the HIGHEST PID (most-recently-created)
//      AND skip processes whose threads are all suspended (frozen zombies).
static bool IsProcessSuspended(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int total = 0, suspended = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                total++;
                HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                                       te.th32ThreadID);
                if (ht) {
                    // Use NtQueryInformationThread via dynamic resolve to get
                    // suspend count. Simpler: SuspendThread(ht) returns prior
                    // suspend count, then ResumeThread to undo. Avoid: we want
                    // ZERO interference. Skip suspend probe -- just count threads.
                    CloseHandle(ht);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    // Heuristic: a real launcher that has been running for >1s has many threads.
    // A spawn-suspended zombie has exactly 1 thread (the suspended primary).
    return (total <= 1);
}

static DWORD FindProcessByName(const char* needle) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD bestPid = 0;
    if (Process32First(snap, &pe)) {
        do {
            char nm[260];
            int j = 0;
            for (int i = 0; pe.szExeFile[i] && j < 259; i++) {
                char c = (char)pe.szExeFile[i];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                nm[j++] = c;
            }
            nm[j] = 0;
            char nd[260]; j = 0;
            for (int i = 0; needle[i] && j < 259; i++) {
                char c = needle[i];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                nd[j++] = c;
            }
            nd[j] = 0;
            if (strstr(nm, nd)) {
                if (IsProcessSuspended(pe.th32ProcessID)) continue; // skip zombie
                if (pe.th32ProcessID > bestPid) bestPid = pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return bestPid;
}

// Forward decl for auto-dump support.
static int DumpRegion(DWORD pid, ULONG_PTR addr, SIZE_T size, const char* outPath);

// Try to auto-dump the MAPPED region containing addr. One-shot.
// Walks the FULL allocation (all sub-regions sharing the same AllocationBase)
// not just the contiguous-protection chunk that VirtualQueryEx returns.
static void MaybeAutoDumpMapped(HANDLE hProc, DWORD pid, void* hit) {
    if (!g_autoDumpMapped || g_didAutoDump) return;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, hit, &mbi, sizeof(mbi)) != sizeof(mbi)) return;
    if (mbi.Type != MEM_MAPPED) return;
    g_didAutoDump = true;

    void* allocBase = mbi.AllocationBase;
    // Walk forward from allocBase summing RegionSize while AllocationBase matches.
    SIZE_T total = 0;
    unsigned char* probe = (unsigned char*)allocBase;
    SIZE_T cap = 16 * 1024 * 1024; // safety cap 16 MB
    while (total < cap) {
        MEMORY_BASIC_INFORMATION m2;
        if (VirtualQueryEx(hProc, probe, &m2, sizeof(m2)) != sizeof(m2)) break;
        if (m2.AllocationBase != allocBase) break;
        total += m2.RegionSize;
        probe = (unsigned char*)m2.BaseAddress + m2.RegionSize;
        // safety: if RegionSize is 0 break to avoid infinite loop
        if (m2.RegionSize == 0) break;
    }

    char outPath[MAX_PATH];
    sprintf_s(outPath, sizeof(outPath),
              "C:\\ProgramData\\eaac_mapped_autodump_%lu.bin", pid);
    LogLine("[AUTO-DUMP] MAPPED allocation: base=%p full_size=0x%zX "
            "(first_chunk=0x%zX) -> %s",
            allocBase, total, mbi.RegionSize, outPath);
    int rc = DumpRegion(pid, (ULONG_PTR)allocBase, total, outPath);
    LogLine("[AUTO-DUMP] result=%d", rc);
}

// ---- Scan one region ----
static int ScanRegion(HANDLE hProc, void* base, SIZE_T size) {
    if (size == 0 || size > 64 * 1024 * 1024) return 0;
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, size,
                                                     MEM_COMMIT | MEM_RESERVE,
                                                     PAGE_READWRITE);
    if (!buf) return 0;
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, base, buf, size, &got) || got == 0) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }
    int newHits = 0;
    for (size_t b = 0; b < BAIT_COUNT; b++) {
        // ASCII
        size_t alen = strlen(BAITS[b].a);
        const unsigned char* p = buf;
        while (true) {
            const unsigned char* h = memmem_ci0(p, got - (p - buf), BAITS[b].a, alen);
            if (!h) break;
            void* remoteAddr = (void*)((unsigned char*)base + (h - buf));
            if (MarkSeen(remoteAddr, (int)b, 0)) {
                char where[256] = {0};
                DescribeRemoteAddr(hProc, remoteAddr, where, sizeof(where));
                char hex[200] = {0};
                size_t off = h - buf;
                size_t hexlen = (off + 64 <= got) ? 64 : (got - off);
                for (size_t i = 0; i < hexlen; i++) {
                    sprintf_s(hex + i*2, sizeof(hex) - i*2, "%02x", h[i]);
                }
                LogLine("[FOUND-A] addr=%p bait=%s region=[%s] bytes=%s",
                        remoteAddr, BAITS[b].label, where, hex);
                newHits++;
                if (BAITS[b].label[0] == 'P') { // POS_*
                    MaybeAutoDumpMapped(hProc, GetProcessId(hProc), remoteAddr);
                }
            }
            p = h + 1;
            if (p >= buf + got) break;
        }
        // UTF-16 LE
        size_t wlen = wcslen(BAITS[b].w) * sizeof(wchar_t);
        p = buf;
        while (true) {
            const unsigned char* h = memmem_ci0(p, got - (p - buf), BAITS[b].w, wlen);
            if (!h) break;
            void* remoteAddr = (void*)((unsigned char*)base + (h - buf));
            if (MarkSeen(remoteAddr, (int)b, 1)) {
                char where[256] = {0};
                DescribeRemoteAddr(hProc, remoteAddr, where, sizeof(where));
                char hex[200] = {0};
                size_t off = h - buf;
                size_t hexlen = (off + 64 <= got) ? 64 : (got - off);
                for (size_t i = 0; i < hexlen; i++) {
                    sprintf_s(hex + i*2, sizeof(hex) - i*2, "%02x", h[i]);
                }
                LogLine("[FOUND-W] addr=%p bait=%s region=[%s] bytes=%s",
                        remoteAddr, BAITS[b].label, where, hex);
                newHits++;
                if (BAITS[b].label[0] == 'P') { // POS_*
                    MaybeAutoDumpMapped(hProc, GetProcessId(hProc), remoteAddr);
                }
            }
            p = h + 2;
            if (p >= buf + got) break;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return newHits;
}

// ---- Attach + scan loop ----
static int RunWatcher(DWORD pid, DWORD pollMs, DWORD totalSeconds) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        DWORD e = GetLastError();
        printf("[-] OpenProcess(PID=%lu) failed: %lu (0x%lX)\n", pid, e, e);
        return 2;
    }
    LogLine("[+] Attached PID=%lu rights=QI|VMR poll=%lums duration=%lus baits=%zu",
            pid, pollMs, totalSeconds, BAIT_COUNT);

    SYSTEM_INFO si; GetSystemInfo(&si);
    void* pmin = si.lpMinimumApplicationAddress;
    void* pmax = si.lpMaximumApplicationAddress;

    DWORD startTick = GetTickCount();
    int   pass = 0;
    while ((GetTickCount() - startTick) < totalSeconds * 1000) {
        pass++;
        int regions = 0;
        int hits = 0;
        unsigned char* addr = (unsigned char*)pmin;
        while (addr < (unsigned char*)pmax) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            unsigned char* next = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
            bool readable = (mbi.State == MEM_COMMIT) &&
                            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                                            PAGE_EXECUTE_READ |
                                            PAGE_EXECUTE_READWRITE |
                                            PAGE_EXECUTE_WRITECOPY |
                                            PAGE_WRITECOPY));
            if (readable && mbi.RegionSize <= 64*1024*1024) {
                hits += ScanRegion(hProc, mbi.BaseAddress, mbi.RegionSize);
                regions++;
            }
            if (next <= addr) break;
            addr = next;
        }
        if (pass <= 4 || hits > 0 || (pass % 40) == 0) {
            LogLine("[pass %d] regions=%d new_hits=%d total_seen=%d",
                    pass, regions, hits, g_seenCount);
        }
        // Check if target is still alive
        DWORD ec = 0;
        if (GetExitCodeProcess(hProc, &ec) && ec != STILL_ACTIVE) {
            LogLine("[!] target PID=%lu exited (code=0x%lX) at pass %d",
                    pid, ec, pass);
            break;
        }
        Sleep(pollMs);
    }
    LogLine("[done] passes=%d total_seen=%d", pass, g_seenCount);
    CloseHandle(hProc);
    return 0;
}

static int DumpRegion(DWORD pid, ULONG_PTR addr, SIZE_T size, const char* outPath) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 2;
    }
    // Round addr DOWN to page base, round size UP to whole pages.
    ULONG_PTR base = addr & ~(ULONG_PTR)0xFFF;
    SIZE_T    rem  = (addr - base) + size;
    SIZE_T    pad  = (rem + 0xFFF) & ~(SIZE_T)0xFFF;
    printf("[*] dumping %zu bytes from %p (page-aligned base %p) of PID %lu\n",
           pad, (void*)addr, (void*)base, pid);

    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, pad,
                                                     MEM_COMMIT | MEM_RESERVE,
                                                     PAGE_READWRITE);
    if (!buf) { CloseHandle(hProc); return 3; }
    SIZE_T got = 0;
    ReadProcessMemory(hProc, (LPCVOID)base, buf, pad, &got);
    if (got == 0) {
        printf("[-] ReadProcessMemory got 0 bytes (err=%lu)\n", GetLastError());
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 4;
    }
    FILE* fo = NULL;
    if (fopen_s(&fo, outPath, "wb") != 0 || !fo) {
        printf("[-] fopen %s failed\n", outPath);
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 5;
    }
    fwrite(buf, 1, got, fo);
    fclose(fo);
    VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    printf("[+] wrote %zu bytes to %s\n", got, outPath);

    // Print region description
    HANDLE hp2 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE, pid);
    if (hp2) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hp2, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            const char* type =
                (mbi.Type == MEM_IMAGE)   ? "IMAGE"   :
                (mbi.Type == MEM_MAPPED)  ? "MAPPED"  :
                (mbi.Type == MEM_PRIVATE) ? "PRIVATE" : "?";
            printf("[i] region: type=%s prot=0x%lX state=0x%lX size=0x%zX base=%p\n",
                   type, (unsigned long)mbi.Protect,
                   (unsigned long)mbi.State, mbi.RegionSize, mbi.AllocationBase);
        }
        CloseHandle(hp2);
    }
    return 0;
}

static void Usage(void) {
    printf("Usage:\n");
    printf("  NexusWatchExternal.exe <pid>\n");
    printf("  NexusWatchExternal.exe --watch-name <substr> [--timeout 60]\n");
    printf("  NexusWatchExternal.exe <pid>  --poll 25 --duration 120\n");
    printf("  NexusWatchExternal.exe --dump <pid> <addr_hex> <size_hex> [--out path]\n");
    printf("  NexusWatchExternal.exe --watch-name <substr> --auto-dump-mapped\n");
    printf("Defaults: poll=25ms duration=120s log=C:\\ProgramData\\NexusWatchExt_<pid>.log\n");
    printf("--auto-dump-mapped: auto-saves first MAPPED bait region to\n");
    printf("                    C:\\ProgramData\\eaac_mapped_autodump_<pid>.bin\n");
}

int main(int argc, char** argv) {
    InitializeCriticalSection(&g_logCs);

    if (argc < 2) { Usage(); return 1; }

    DWORD pid = 0;
    DWORD pollMs = 25;
    DWORD duration = 120;
    const char* watchName = NULL;
    DWORD watchTimeout = 60;
    bool  dumpMode = false;
    ULONG_PTR dumpAddr = 0;
    SIZE_T dumpSize = 0;
    const char* dumpOut = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watch-name") == 0 && i + 1 < argc) {
            watchName = argv[++i];
        } else if (strcmp(argv[i], "--poll") == 0 && i + 1 < argc) {
            pollMs = (DWORD)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = (DWORD)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            watchTimeout = (DWORD)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dump") == 0 && i + 3 < argc) {
            dumpMode = true;
            pid       = (DWORD)strtoul(argv[++i], NULL, 0);
            dumpAddr  = (ULONG_PTR)_strtoui64(argv[++i], NULL, 16);
            dumpSize  = (SIZE_T)_strtoui64(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            dumpOut = argv[++i];
        } else if (strcmp(argv[i], "--auto-dump-mapped") == 0) {
            g_autoDumpMapped = true;
        } else {
            DWORD v = (DWORD)atoi(argv[i]);
            if (v > 0) pid = v;
        }
    }

    if (dumpMode) {
        char defOut[MAX_PATH];
        if (!dumpOut) {
            sprintf_s(defOut, sizeof(defOut),
                      "C:\\ProgramData\\NexusWatchExt_dump_%lu_%llX_%llX.bin",
                      pid, (unsigned long long)dumpAddr,
                      (unsigned long long)dumpSize);
            dumpOut = defOut;
        }
        return DumpRegion(pid, dumpAddr, dumpSize, dumpOut);
    }

    if (watchName) {
        printf("[*] Watching for process containing '%s' (timeout %lus)...\n",
               watchName, watchTimeout);
        DWORD startT = GetTickCount();
        while ((GetTickCount() - startT) < watchTimeout * 1000) {
            pid = FindProcessByName(watchName);
            if (pid) break;
            Sleep(50);
        }
        if (!pid) {
            printf("[-] Timed out waiting for '%s'\n", watchName);
            return 3;
        }
        printf("[+] Found PID=%lu for '%s'\n", pid, watchName);
    }

    if (!pid) { Usage(); return 1; }

    char logPath[MAX_PATH];
    sprintf_s(logPath, sizeof(logPath),
              "C:\\ProgramData\\NexusWatchExt_%lu.log", pid);
    if (fopen_s(&g_log, logPath, "w") != 0) {
        g_log = NULL;
        printf("[!] couldn't open %s for write -- continuing stdout-only\n", logPath);
    } else {
        printf("[+] log: %s\n", logPath);
    }

    return RunWatcher(pid, pollMs, duration);
}
