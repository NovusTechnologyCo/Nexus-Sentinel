// NexusSpyEnumHooks.cpp -- Win32 process / window enumeration API hooks.
//
// Goal: capture every (input, returned-string, caller-RIP) tuple for the
// APIs the launcher MUST use to gather process and window data, regardless
// of what hash function it pipes the result into afterward.
//
// APIs hooked:
//   kernel32!QueryFullProcessImageNameW   -- PID -> full exe path
//   psapi!K32GetModuleFileNameExW         -- handle -> module path (alias on K32)
//   user32!GetWindowTextW                 -- HWND -> window title
//   user32!GetClassNameW                  -- HWND -> window class name
//   user32!RealGetWindowClassW            -- HWND -> "real" class name
//   ntdll!NtQuerySystemInformation        -- class 5 = SystemProcessInformation
//
// The caller RIP we log = the RA from _ReturnAddress(), which is the
// instruction in the LAUNCHER that called the API. Cross-referencing those
// RIPs back into IDA tells us exactly which discriminator function feeds
// process/window names into the matcher.

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include "MinHook.h"

#pragma intrinsic(_ReturnAddress)

extern "C" void NexusSpyLog(const char* fmt, ...);

// ---- helpers ----
static void WideToAsciiSafe(const wchar_t* in, int max_chars, char* out, size_t outsz) {
    if (!in || outsz < 2) { if (outsz) out[0] = 0; return; }
    size_t j = 0;
    int    i = 0;
    while (i < max_chars && j < outsz - 1) {
        wchar_t c = in[i++];
        if (c == 0) break;
        out[j++] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    out[j] = 0;
}

static bool LooksInteresting(const char* s) {
    if (!s || !*s) return false;
    // Log anything containing exe/dll/sys, or any window class/title at all.
    // We want broad capture; filtering can happen offline.
    return true;
}

// ====================================================================
// Matcher-input capture: thread-local buffer of the most recent
// QueryFullProcessImageNameW return value, plus a known-label scanner
// that fires when the launcher concatenates a recovered Theia label
// (e.g., "CheatEngine") into the alert string.
// ====================================================================

// Latest exe path returned by QFPIN on this thread. Populated in
// hk_QueryFullProcessImageNameW; read when MatchKnownLabel() fires.
static __declspec(thread) wchar_t g_lastQFPIN_w[1024];
static __declspec(thread) DWORD   g_lastQFPIN_pid;

// 51 cheat-tool labels recovered via Theia decryption (key F7BBA59B48 / xor 0x9D)
// from logs/eaac_griffin_decrypted_all.txt (see captures/eaac_blocklist_FINAL.md).
// When the launcher copies/concatenates one of these strings, it has just
// matched a running process to that category — log the pair.
static const wchar_t* const kBlocklistLabels[] = {
    L"AlisInjector", L"AntiCheatExpert", L"ArtMoney", L"AutoHotkey", L"Badware",
    L"BattlEye", L"CFFExplorer", L"CheatEngine", L"CheatEngineLinux", L"CheatToolSet",
    L"Chimpeon", L"CronusZen", L"DTrace", L"EasyAntiCheat", L"EasyAntiCheatEOS",
    L"ExtremeInjector", L"FaceInjector", L"FaceIT", L"GHBasicInjector", L"GHInjector",
    L"GTuner", L"HookLoader", L"Interception", L"Invalid", L"Javelin", L"Linux",
    L"LunarInjector", L"MagnetRAMCapture", L"Npcap", L"PEbear", L"ProcessHacker",
    L"ProcExp", L"ProcMon", L"Proxifier", L"PS4Macro", L"ReClass", L"ReWASD",
    L"Squalr", L"TSearch", L"UnknowncheatsGeneric", L"Vanguard", L"ViGemBus",
    L"VirtualController", L"WinDbg", L"WinDivert", L"Windows10Injector",
    L"WinObjEx", L"Wireshark", L"x64dbg", L"Xenos", L"XimTools",
};
static const int kBlocklistLabelCount = (int)(sizeof(kBlocklistLabels)/sizeof(kBlocklistLabels[0]));

// Alert template fragment unique to the EAAC detection dialog (pre-label).
// Matching this anywhere in a wide string says "alert is being built right now."
static const wchar_t* const kAlertFragment = L"the same time as the game";

// Case-insensitive wcsstr (CRT _wcsicmp lacks substring; roll our own).
static const wchar_t* WcsIStr(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle || !*needle) return NULL;
    size_t nlen = wcslen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nlen) {
            wchar_t a = hay[i];
            wchar_t b = needle[i];
            if (!a) return NULL;
            if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
            if (a != b) break;
            i++;
        }
        if (i == nlen) return hay;
    }
    return NULL;
}

// Scan src for any known label OR the alert template fragment.
// Returns the matched needle (label or fragment) or NULL.
static const wchar_t* MatchKnownLabel(const wchar_t* src) {
    if (!src) return NULL;
    __try {
        // Length safety: cap scan at 4 KB of wchar to avoid pathological input.
        size_t cap = 0;
        while (cap < 4096 && src[cap]) cap++;
        if (cap < 4) return NULL;
        // Alert template fragment first — most distinctive
        if (WcsIStr(src, kAlertFragment)) {
            return kAlertFragment;
        }
        // Each label
        for (int k = 0; k < kBlocklistLabelCount; k++) {
            const wchar_t* m = WcsIStr(src, kBlocklistLabels[k]);
            if (m) return kBlocklistLabels[k];
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}

static void LogMatchHit(const char* tag, const wchar_t* src, const wchar_t* matched, void* ret) {
    char srcA[640], matchedA[80], qfpA[1024];
    WideToAsciiSafe(src,     320, srcA,     sizeof(srcA));
    WideToAsciiSafe(matched, 64,  matchedA, sizeof(matchedA));
    WideToAsciiSafe(g_lastQFPIN_w, 1023, qfpA, sizeof(qfpA));
    NexusSpyLog("[!!!MATCH:%s] label=\"%s\" lastQFPIN=\"%s\" lastQFPIN_pid=%lu src=\"%s\" caller=%p",
                tag, matchedA, qfpA, g_lastQFPIN_pid, srcA, ret);
}

// ====================================================================
// kernel32!QueryFullProcessImageNameW
// ====================================================================
typedef BOOL (WINAPI *PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
static PFN_QueryFullProcessImageNameW o_QueryFullProcessImageNameW;

static BOOL WINAPI hk_QueryFullProcessImageNameW(
    HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)
{
    DWORD origCap = lpdwSize ? *lpdwSize : 0;
    BOOL  ok = o_QueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
    if (ok && lpExeName && lpdwSize) {
        char name[1024];
        DWORD lenChars = *lpdwSize;
        WideToAsciiSafe(lpExeName, (int)lenChars, name, sizeof(name));
        void* ret = _ReturnAddress();
        DWORD pid = GetProcessId(hProcess);
        NexusSpyLog("[QueryFullProcessImageNameW] pid=%lu flags=0x%lX path=\"%s\" caller=%p",
                    pid, dwFlags, name, ret);

        // Capture latest QFPIN return into thread-local for matcher correlation.
        DWORD copy = lenChars;
        if (copy > 1023) copy = 1023;
        __try {
            for (DWORD k = 0; k < copy; k++) g_lastQFPIN_w[k] = lpExeName[k];
            g_lastQFPIN_w[copy] = 0;
            g_lastQFPIN_pid = pid;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return ok;
}

// ====================================================================
// kernelbase!K32GetModuleFileNameExW (a.k.a. GetModuleFileNameExW)
// ====================================================================
typedef DWORD (WINAPI *PFN_K32GetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
static PFN_K32GetModuleFileNameExW o_K32GetModuleFileNameExW;

static DWORD WINAPI hk_K32GetModuleFileNameExW(
    HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    DWORD r = o_K32GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);
    if (r > 0 && lpFilename) {
        char name[1024];
        WideToAsciiSafe(lpFilename, (int)r, name, sizeof(name));
        void* ret = _ReturnAddress();
        DWORD pid = GetProcessId(hProcess);
        NexusSpyLog("[K32GetModuleFileNameExW] pid=%lu hMod=%p path=\"%s\" caller=%p",
                    pid, hModule, name, ret);
    }
    return r;
}

// ====================================================================
// user32!GetWindowTextW
// ====================================================================
typedef int (WINAPI *PFN_GetWindowTextW)(HWND, LPWSTR, int);
static PFN_GetWindowTextW o_GetWindowTextW;

static int WINAPI hk_GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount) {
    int r = o_GetWindowTextW(hWnd, lpString, nMaxCount);
    if (r > 0 && lpString) {
        char buf[600];
        WideToAsciiSafe(lpString, r, buf, sizeof(buf));
        void* ret = _ReturnAddress();
        NexusSpyLog("[GetWindowTextW] hwnd=%p len=%d title=\"%s\" caller=%p",
                    hWnd, r, buf, ret);
    }
    return r;
}

// ====================================================================
// user32!GetClassNameW
// ====================================================================
typedef int (WINAPI *PFN_GetClassNameW)(HWND, LPWSTR, int);
static PFN_GetClassNameW o_GetClassNameW;

static int WINAPI hk_GetClassNameW(HWND hWnd, LPWSTR lpClassName, int nMaxCount) {
    int r = o_GetClassNameW(hWnd, lpClassName, nMaxCount);
    if (r > 0 && lpClassName) {
        char buf[300];
        WideToAsciiSafe(lpClassName, r, buf, sizeof(buf));
        void* ret = _ReturnAddress();
        NexusSpyLog("[GetClassNameW] hwnd=%p len=%d class=\"%s\" caller=%p",
                    hWnd, r, buf, ret);
    }
    return r;
}

// ====================================================================
// user32!RealGetWindowClassW
// ====================================================================
typedef UINT (WINAPI *PFN_RealGetWindowClassW)(HWND, LPWSTR, UINT);
static PFN_RealGetWindowClassW o_RealGetWindowClassW;

static UINT WINAPI hk_RealGetWindowClassW(HWND hWnd, LPWSTR pszType, UINT cchType) {
    UINT r = o_RealGetWindowClassW(hWnd, pszType, cchType);
    if (r > 0 && pszType) {
        char buf[300];
        WideToAsciiSafe(pszType, (int)r, buf, sizeof(buf));
        void* ret = _ReturnAddress();
        NexusSpyLog("[RealGetWindowClassW] hwnd=%p len=%u class=\"%s\" caller=%p",
                    hWnd, r, buf, ret);
    }
    return r;
}

// ====================================================================
// user32!EnumWindows / user32!EnumThreadWindows  (entry markers)
// ====================================================================
typedef BOOL (WINAPI *PFN_EnumWindows)(WNDENUMPROC, LPARAM);
static PFN_EnumWindows o_EnumWindows;

static BOOL WINAPI hk_EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
    void* ret = _ReturnAddress();
    NexusSpyLog("[EnumWindows] callback=%p lParam=%p caller=%p",
                lpEnumFunc, (void*)lParam, ret);
    return o_EnumWindows(lpEnumFunc, lParam);
}

typedef BOOL (WINAPI *PFN_EnumThreadWindows)(DWORD, WNDENUMPROC, LPARAM);
static PFN_EnumThreadWindows o_EnumThreadWindows;

static BOOL WINAPI hk_EnumThreadWindows(DWORD tid, WNDENUMPROC cb, LPARAM lp) {
    void* ret = _ReturnAddress();
    NexusSpyLog("[EnumThreadWindows] tid=%lu callback=%p lParam=%p caller=%p",
                tid, cb, (void*)lp, ret);
    return o_EnumThreadWindows(tid, cb, lp);
}

// ====================================================================
// ntdll!NtQuerySystemInformation  (only log class 5 = SystemProcessInformation)
// ====================================================================
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
static PFN_NtQuerySystemInformation o_NtQuerySystemInformation;

#define SystemProcessInformation 5

// SYSTEM_PROCESS_INFORMATION layout (relevant prefix):
//   0x00 ULONG NextEntryOffset
//   0x04 ULONG NumberOfThreads
//   0x08 BYTE[0x30] (timing/perf counters incl. CreateTime/UserTime/KernelTime)
//   0x38 UNICODE_STRING ImageName  (Length + MaxLen + Buffer)
//   0x48 LONG  BasePriority
//   0x50 HANDLE UniqueProcessId
struct SPI_Header {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE  pad[0x30];
    USHORT ImageNameLength;
    USHORT ImageNameMaxLen;
    BYTE  pad2[4];
    PWSTR ImageNameBuffer;
    LONG  BasePriority;
    HANDLE UniqueProcessId;
};

static NTSTATUS NTAPI hk_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS s = o_NtQuerySystemInformation(SystemInformationClass,
        SystemInformation, SystemInformationLength, ReturnLength);
    if (SystemInformationClass == SystemProcessInformation && s == 0 &&
        SystemInformation && ReturnLength)
    {
        void* ret = _ReturnAddress();
        ULONG retLen = *ReturnLength;
        NexusSpyLog("[NtQuerySystemInformation] class=5 buf=%p outLen=%lu caller=%p",
                    SystemInformation, retLen, ret);

        // Walk the SYSTEM_PROCESS_INFORMATION array; log entries whose
        // ImageName contains an interesting substring.
        __try {
            BYTE* p = (BYTE*)SystemInformation;
            BYTE* end = p + retLen;
            int  total = 0;
            int  matched = 0;
            while (p < end) {
                SPI_Header* h = (SPI_Header*)p;
                if (h->ImageNameLength > 0 && h->ImageNameBuffer) {
                    char nm[260];
                    int chars = h->ImageNameLength / 2;
                    if (chars > 259) chars = 259;
                    WideToAsciiSafe(h->ImageNameBuffer, chars, nm, sizeof(nm));
                    // Filter -- only log interesting matches to keep volume sane
                    bool interesting = (
                        strstr(nm, "cheat") || strstr(nm, "Cheat") ||
                        strstr(nm, "engine") || strstr(nm, "Engine") ||
                        strstr(nm, "boring") || strstr(nm, "Boring") ||
                        strstr(nm, "x64dbg") || strstr(nm, "ollydbg") ||
                        strstr(nm, "windbg") || strstr(nm, "ida")
                    );
                    if (interesting) {
                        NexusSpyLog("  [NtQSI-process] pid=%llu name=\"%s\" caller=%p",
                                    (unsigned long long)(uintptr_t)h->UniqueProcessId,
                                    nm, ret);
                        matched++;
                    }
                    total++;
                }
                if (h->NextEntryOffset == 0) break;
                p += h->NextEntryOffset;
            }
            // First 3 calls log full count; later ones only on hit
            static int logCallCount = 0;
            if (logCallCount < 3 || matched > 0) {
                NexusSpyLog("  [NtQSI-summary] total_processes=%d matched=%d caller=%p",
                            total, matched, ret);
            }
            logCallCount++;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return s;
}

// ====================================================================
// kernel32!CreateToolhelp32Snapshot + Process32FirstW + Process32NextW
// ====================================================================
typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
static PFN_CreateToolhelp32Snapshot o_CreateToolhelp32Snapshot;

static HANDLE WINAPI hk_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    HANDLE h = o_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    void* ret = _ReturnAddress();
    NexusSpyLog("[CreateToolhelp32Snapshot] flags=0x%lX pid=%lu -> %p caller=%p",
                dwFlags, th32ProcessID, h, ret);
    return h;
}

// PROCESSENTRY32W layout (the relevant tail field):
//   0x00 DWORD   dwSize
//   0x04 DWORD   cntUsage
//   0x08 DWORD   th32ProcessID
//   0x10 ULONG_PTR th32DefaultHeapID
//   0x18 DWORD   th32ModuleID
//   0x1C DWORD   cntThreads
//   0x20 DWORD   th32ParentProcessID
//   0x24 LONG    pcPriClassBase
//   0x28 DWORD   dwFlags
//   0x2C WCHAR   szExeFile[MAX_PATH]
struct PE32W_Layout {
    DWORD     dwSize, cntUsage, th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID, cntThreads, th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    WCHAR     szExeFile[260];
};

typedef BOOL (WINAPI *PFN_Process32FirstW)(HANDLE, PE32W_Layout*);
typedef BOOL (WINAPI *PFN_Process32NextW)(HANDLE, PE32W_Layout*);
static PFN_Process32FirstW o_Process32FirstW;
static PFN_Process32NextW  o_Process32NextW;

static BOOL WINAPI hk_Process32FirstW(HANDLE h, PE32W_Layout* pe) {
    BOOL ok = o_Process32FirstW(h, pe);
    if (ok && pe) {
        char name[300];
        WideToAsciiSafe(pe->szExeFile, 260, name, sizeof(name));
        void* ret = _ReturnAddress();
        NexusSpyLog("[Process32FirstW] pid=%lu name=\"%s\" caller=%p",
                    pe->th32ProcessID, name, ret);
    }
    return ok;
}

// One-shot self-dump: when triggered, write the launcher's full virtual image
// to a file so we can load it in IDA at the exact build that produced our
// captured RIPs. Triggered on first Process32NextW call returning a bait name.
static volatile LONG g_selfDumped = 0;
static volatile LONG g_selfDumpScheduled = 0;

// RVA of the .rdata page that holds the encrypted blobs the discriminator
// passes to the Theia decryptor (for registry path / value-name strings).
// In v8/v9 self-dumps this page was uncommitted; in NexusDSEFix kdumps it
// was populated. So waiting for it to commit before snapshotting is the
// signal that the discriminator's late-phase work has happened.
static const DWORD BLOB_PAGE_RVA = 0xB4E000;

// Doing the dump (forward declaration so the dumper thread can call it).
static void SelfDumpLauncherImage_Internal(const char* trigger);

// Background thread: poll the blob page until it commits AND has non-zero
// data, then dump. Falls back after a hard cap so we always get something.
static DWORD WINAPI SelfDumpDeferredThread(LPVOID param) {
    BYTE* base = (BYTE*)GetModuleHandleW(NULL);
    if (!base) return 0;
    BYTE* probe = base + BLOB_PAGE_RVA;

    const DWORD POLL_MS = 50;
    const DWORD HARD_CAP_MS = 8000;   // give the discriminator up to 8s
    DWORD elapsed = 0;

    char trigger_reason[128];
    strcpy_s(trigger_reason, sizeof(trigger_reason),
             "blob page populated (discriminator finished decryption)");

    while (elapsed < HARD_CAP_MS) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(probe, &mbi, sizeof(mbi)) == sizeof(mbi)
            && mbi.State == MEM_COMMIT
            && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        {
            // Page is committed + readable. Check if it has actual data.
            __try {
                bool has_data = false;
                BYTE* p = probe;
                for (int i = 0; i < 0x1000; i++) {
                    if (p[i] != 0) { has_data = true; break; }
                }
                if (has_data) {
                    NexusSpyLog("[self-dump] blob page populated after %lums", elapsed);
                    break;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // probe failed, keep waiting
            }
        }
        Sleep(POLL_MS);
        elapsed += POLL_MS;
    }

    if (elapsed >= HARD_CAP_MS) {
        sprintf_s(trigger_reason, sizeof(trigger_reason),
                  "HARD CAP reached (%lums) — dumping anyway", elapsed);
        NexusSpyLog("[self-dump] %s", trigger_reason);
    }

    SelfDumpLauncherImage_Internal(trigger_reason);
    return 0;
}

// Schedule deferred dump (one-shot). Returns immediately; dump happens on
// background thread so we don't block the launcher's discriminator loop.
static void SelfDumpLauncherImage(const char* trigger) {
    if (InterlockedCompareExchange(&g_selfDumpScheduled, 1, 0) != 0) return;
    NexusSpyLog("[self-dump] scheduled trigger='%s' — waiting for blob page commit", trigger);
    HANDLE h = CreateThread(NULL, 0, SelfDumpDeferredThread, NULL, 0, NULL);
    if (h) CloseHandle(h);
}

static void SelfDumpLauncherImage_Internal(const char* trigger) {
    if (InterlockedCompareExchange(&g_selfDumped, 1, 0) != 0) return;

    HMODULE hMod = GetModuleHandleW(NULL);  // launcher EXE main image
    if (!hMod) {
        NexusSpyLog("[self-dump] GetModuleHandleW(NULL) failed");
        return;
    }
    BYTE* base = (BYTE*)hMod;

    // Parse PE header to find SizeOfImage
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        NexusSpyLog("[self-dump] bad DOS sig");
        return;
    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        NexusSpyLog("[self-dump] bad PE sig");
        return;
    }
    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD pid = GetCurrentProcessId();

    char path[MAX_PATH];
    sprintf_s(path, sizeof(path),
              "C:\\ProgramData\\launcher_selfdump_%lu_base_%llX.bin",
              pid, (unsigned long long)(uintptr_t)base);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        NexusSpyLog("[self-dump] CreateFile failed err=%lu path=%s",
                    GetLastError(), path);
        return;
    }
    NexusSpyLog("[self-dump] trigger='%s' base=%p size=0x%lX -> %s",
                trigger, base, sizeOfImage, path);

    // Page-granular dump (4 KB). For each committed page, temporarily set
    // PAGE_EXECUTE_READWRITE so execute-only Themida pages become readable,
    // dump, then restore original protection.
    const DWORD PAGE_SZ = 0x1000;
    BYTE pageBuf[0x1000];
    BYTE zeros[0x1000] = {0};
    DWORD written = 0;
    DWORD failed_pages = 0;
    DWORD reprotected_pages = 0;
    DWORD execonly_dumped = 0;

    for (DWORD off = 0; off < sizeOfImage; off += PAGE_SZ) {
        DWORD thisPage = PAGE_SZ;
        if (off + thisPage > sizeOfImage) thisPage = sizeOfImage - off;
        BYTE* p = base + off;

        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T qr = VirtualQuery(p, &mbi, sizeof(mbi));
        if (qr != sizeof(mbi) || mbi.State != MEM_COMMIT) {
            DWORD w;
            WriteFile(h, zeros, thisPage, &w, NULL);
            failed_pages++;
            continue;
        }

        DWORD prot = mbi.Protect & 0xFF;
        bool readable = (prot == PAGE_READONLY ||
                         prot == PAGE_READWRITE ||
                         prot == PAGE_EXECUTE_READ ||
                         prot == PAGE_EXECUTE_READWRITE ||
                         prot == PAGE_WRITECOPY ||
                         prot == PAGE_EXECUTE_WRITECOPY) &&
                        !(mbi.Protect & PAGE_GUARD);

        DWORD oldProt = 0;
        bool needRestore = false;
        if (!readable) {
            // Try to add read access (covers PAGE_EXECUTE only, etc.)
            if (VirtualProtect(p, thisPage, PAGE_EXECUTE_READWRITE, &oldProt)) {
                needRestore = true;
                reprotected_pages++;
                if (prot == PAGE_EXECUTE) execonly_dumped++;
            } else {
                DWORD w;
                WriteFile(h, zeros, thisPage, &w, NULL);
                failed_pages++;
                continue;
            }
        }

        DWORD w = 0;
        __try {
            // Copy through a stack buffer first so a page fault on read
            // is caught here, not mid-WriteFile.
            memcpy(pageBuf, p, thisPage);
            WriteFile(h, pageBuf, thisPage, &w, NULL);
            written += w;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            WriteFile(h, zeros, thisPage, &w, NULL);
            failed_pages++;
        }

        if (needRestore) {
            DWORD tmp;
            VirtualProtect(p, thisPage, oldProt, &tmp);
        }
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    NexusSpyLog("[self-dump] complete written=0x%lX failed_pages=%lu "
                "reprotected_pages=%lu execonly_dumped=%lu",
                written, failed_pages, reprotected_pages, execonly_dumped);
}

// ====================================================================
// Bucket-table dumper: when Process32NextW returns to a launcher RIP
// we haven't seen before, walk the surrounding bytes to find the
// inline hash-bucket cluster (imul reg, reg, 0x3B + cmp reg32, imm32 chain)
// and dump every immediate. One-shot per caller. Pure memory read; we
// never patch Themida-protected code.
// ====================================================================

#define MAX_TRACKED_CALLERS 16
#define BUCKET_DUMPER_SCAN_FWD  0x2000   // bytes to scan forward of caller
#define BUCKET_DUMPER_SCAN_BACK 0x800    // bytes to scan backward of caller

static volatile LONG     g_dumpedCallerCount  = 0;
static void* volatile    g_dumpedCallers[MAX_TRACKED_CALLERS];

static bool MarkCallerDumped(void* caller) {
    LONG n = g_dumpedCallerCount;
    for (LONG i = 0; i < n && i < MAX_TRACKED_CALLERS; i++) {
        if (g_dumpedCallers[i] == caller) return false;   // already dumped
    }
    LONG slot = InterlockedIncrement(&g_dumpedCallerCount) - 1;
    if (slot >= MAX_TRACKED_CALLERS) return false;
    g_dumpedCallers[slot] = caller;
    return true;
}

static BOOL SafeReadByte(const BYTE* p, BYTE* out) {
    __try {
        *out = *p;
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// Returns true if [p..p+len) is fully readable.
static BOOL SafeReadable(const BYTE* p, SIZE_T len) {
    BYTE tmp;
    if (!SafeReadByte(p, &tmp)) return FALSE;
    if (!SafeReadByte(p + len - 1, &tmp)) return FALSE;
    return TRUE;
}

// Read u32 little-endian.
static UINT32 ReadU32(const BYTE* p) {
    return (UINT32)p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

// Walks the launcher .text region surrounding 'caller_rip' looking for:
//   1. The hash multiplier instruction (imul reg, reg, 0x3B): byte pattern 0x6B with imm8=0x3B
//      and ModR/M.mod=3. Optional REX prefix.
//   2. A cluster of `cmp reg32, imm32` instructions:
//        81 F8/F9/FA/FB/FD/FE/FF imm32   (cmp eax/ecx/edx/ebx/ebp/esi/edi)
//        41 81 F8..FF imm32              (cmp r8d..r15d)
// We treat any 6+ matches within 0x100 bytes as a bucket cluster.
static void DumpBucketClusterAroundCaller(void* caller_rip) {
    BYTE* base = (BYTE*)caller_rip;
    BYTE* lo   = base - BUCKET_DUMPER_SCAN_BACK;
    BYTE* hi   = base + BUCKET_DUMPER_SCAN_FWD;

    int   imul3b_count = 0;
    BYTE* imul3b_first = NULL;

    struct CmpHit { BYTE* at; const char* reg; UINT32 imm; };
    enum { MAX_HITS = 256 };
    CmpHit hits[MAX_HITS];
    int    nHits = 0;

    __try {
        for (BYTE* p = lo; p + 8 < hi; p++) {
            if (!SafeReadable(p, 8)) {
                p += 0xFF;       // skip ahead — likely unmapped page
                continue;
            }

            // imul reg, reg, 0x3B (imm8 form): [REX] 6B mod_rm imm8
            BYTE b0 = p[0];
            int  rex = 0;
            BYTE op  = b0;
            if (b0 >= 0x40 && b0 <= 0x4F) { rex = 1; op = p[1]; }
            if (op == 0x6B) {
                BYTE modrm = p[1 + rex];
                BYTE imm8  = p[2 + rex];
                if ((modrm >> 6) == 3 && imm8 == 0x3B) {
                    imul3b_count++;
                    if (!imul3b_first) imul3b_first = p;
                }
            }

            // cmp reg32, imm32 -- single-byte reg form
            //   81 F8 imm32 = cmp eax,
            //   81 F9 imm32 = cmp ecx,
            //   81 FA imm32 = cmp edx,
            //   81 FB imm32 = cmp ebx,
            //   81 FD imm32 = cmp ebp,
            //   81 FE imm32 = cmp esi,
            //   81 FF imm32 = cmp edi,
            // (skip FC = cmp esp; never used)
            if (b0 == 0x81 && p[1] >= 0xF8 && p[1] <= 0xFF && p[1] != 0xFC) {
                if (nHits < MAX_HITS) {
                    static const char* regs[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
                    hits[nHits].at  = p;
                    hits[nHits].reg = regs[p[1] - 0xF8];
                    hits[nHits].imm = ReadU32(p + 2);
                    nHits++;
                }
            }
            // 41 81 F8..FF imm32 = cmp r8d..r15d, imm32
            if (b0 == 0x41 && p[1] == 0x81 && p[2] >= 0xF8 && p[2] <= 0xFF && p[2] != 0xFC) {
                if (nHits < MAX_HITS) {
                    static const char* regs[] = {"r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
                    hits[nHits].at  = p;
                    hits[nHits].reg = regs[p[2] - 0xF8];
                    hits[nHits].imm = ReadU32(p + 3);
                    nHits++;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NexusSpyLog("[bucket-dump] EXCEPTION during scan caller=%p (partial: %d hits)",
                    caller_rip, nHits);
    }

    NexusSpyLog("[bucket-dump] caller=%p scan_window=[%p..%p] imul0x3B_sites=%d cmp_imm32_sites=%d",
                caller_rip, lo, hi, imul3b_count, nHits);
    if (imul3b_first) {
        NexusSpyLog("[bucket-dump] imul0x3B first @ %p (offset=%lld from caller)",
                    imul3b_first, (long long)(imul3b_first - base));
    }

    // Walk hits and emit DENSE clusters (>= 5 cmp imm32 within 0x100 bytes).
    int i = 0;
    int cluster_idx = 0;
    while (i < nHits) {
        int j = i + 1;
        while (j < nHits && (hits[j].at - hits[j-1].at) < 0x80) j++;
        int n = j - i;
        if (n >= 5) {
            // Filter immediates: drop tiny values (likely loop counters / state IDs)
            int kept = 0, dropped_small = 0;
            for (int k = i; k < j; k++) {
                if (hits[k].imm >= 0x10000) kept++;
                else dropped_small++;
            }
            NexusSpyLog("[bucket-dump:cluster%d] caller=%p span=[%p..%p] count=%d kept(>=0x10000)=%d small=%d",
                        cluster_idx, caller_rip, hits[i].at, hits[j-1].at, n, kept, dropped_small);
            for (int k = i; k < j; k++) {
                NexusSpyLog("    [bucket-dump:cluster%d] at=%p offset=%+lld cmp %s, 0x%08X",
                            cluster_idx, hits[k].at, (long long)(hits[k].at - base),
                            hits[k].reg, hits[k].imm);
            }
            cluster_idx++;
        }
        i = j;
    }
    NexusSpyLog("[bucket-dump:end] caller=%p clusters_emitted=%d", caller_rip, cluster_idx);

    // ----------------------------------------------------------------
    // Phase 2: data-pointer dump.
    // The cmp imm32 clusters above are Themida state-machine tokens, not
    // bucket hashes. The real bucket table is referenced via RIP-relative
    // memory operands. Scan for `lea reg, [rip+disp32]` and
    // `mov reg, [rip+disp32]` instructions, follow each to its target,
    // and dump the first 256 bytes (or until obvious garbage).
    // ----------------------------------------------------------------
    int   data_refs_found = 0;
    void* seen_targets[64] = { 0 };
    int   seen_count = 0;
    __try {
        for (BYTE* p = lo; p + 8 < hi; p++) {
            if (!SafeReadable(p, 8)) { p += 0xFF; continue; }
            BYTE b0 = p[0];
            int  rex = 0;
            BYTE op_b = b0;
            int  off_modrm = 1;
            if (b0 >= 0x40 && b0 <= 0x4F) {
                rex = 1;
                op_b = p[1];
                off_modrm = 2;
            }
            // lea r64, [rip+disp32] : REX.W [48|4C] 8D modrm[mod=00 r/m=101] disp32
            // mov r64, [rip+disp32] : REX.W [48|4C] 8B modrm[mod=00 r/m=101] disp32
            // mov r32, [rip+disp32] :        8B modrm[...]  (rare for code refs)
            if (op_b != 0x8D && op_b != 0x8B) continue;
            BYTE modrm = p[off_modrm];
            if ((modrm >> 6) != 0) continue;
            if ((modrm & 7) != 5) continue;   // not [rip+disp32]
            INT32 disp = (INT32)ReadU32(p + off_modrm + 1);
            BYTE* tgt = p + off_modrm + 1 + 4 + disp;
            // Sanity bound: target must be within the launcher process address
            // space; we'll check by attempting to read 16 bytes there.
            if (!SafeReadable(tgt, 16)) continue;
            // Dedupe — track up to 64 unique targets per caller
            bool dup = false;
            for (int s = 0; s < seen_count; s++) {
                if (seen_targets[s] == tgt) { dup = true; break; }
            }
            if (dup) continue;
            if (seen_count < 64) seen_targets[seen_count++] = tgt;

            const char* op_name = (op_b == 0x8D) ? "lea" : "mov";
            // Hexdump first 256 bytes of target (was 64)
            char hex[600];
            int  hj = 0;
            __try {
                int dump_n = 256;
                for (int k = 0; k < dump_n && hj < (int)sizeof(hex) - 4; k++) {
                    BYTE bv;
                    if (!SafeReadByte(tgt + k, &bv)) { hex[hj++]='?'; hex[hj++]='?'; continue; }
                    static const char* hexc = "0123456789ABCDEF";
                    hex[hj++] = hexc[bv >> 4];
                    hex[hj++] = hexc[bv & 0xF];
                }
                hex[hj] = 0;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                strcpy_s(hex, "<read fault>");
            }
            NexusSpyLog("[data-ref] caller=%p insn@%p offset=%+lld %s reg, [rip+%d] -> %p  first64=%s",
                        caller_rip, p, (long long)(p - base), op_name, disp, tgt, hex);
            data_refs_found++;
            if (data_refs_found >= 32) break;   // cap volume per caller
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NexusSpyLog("[data-ref] EXCEPTION during scan caller=%p", caller_rip);
    }
    NexusSpyLog("[data-ref:end] caller=%p data_refs=%d (capped at 32)",
                caller_rip, data_refs_found);

    // ----------------------------------------------------------------
    // Phase 3: locate Theia decryptor + key pool.
    // Theia uses the magic constant 0x80808081 (encoded as `mov eax, imm32`
    // = B8 81 80 80 80). Near every Theia site there's a `lea reg, [rip+disp32]`
    // that loads the *key pool* base address. Capture each pool, plus
    // the surrounding XOR-constant (typical pattern: `xor reg, imm8`).
    // ----------------------------------------------------------------
    int theia_sites = 0;
    int pool_refs = 0;
    void* seen_pools[32] = { 0 };
    int   seen_pool_count = 0;
    __try {
        for (BYTE* p = lo; p + 8 < hi; p++) {
            if (!SafeReadable(p, 5)) { p += 0xFF; continue; }
            // mov eax, 0x80808081 = B8 81 80 80 80
            if (p[0] != 0xB8 || p[1] != 0x81 || p[2] != 0x80 || p[3] != 0x80 || p[4] != 0x80)
                continue;
            theia_sites++;
            NexusSpyLog("[theia-site] caller=%p site@%p offset=%+lld (mov eax, 0x80808081)",
                        caller_rip, p, (long long)(p - base));

            // Scan a +/- 0x100 window around the Theia site for `lea reg, [rip+disp32]`
            // that loads pointers into a plausible key-pool region. The key pool is
            // typically a 16+ KB block in .rdata.
            BYTE* lea_lo = (p > base + 0x100) ? p - 0x100 : base;
            BYTE* lea_hi = p + 0x100;
            for (BYTE* q = lea_lo; q + 8 < lea_hi; q++) {
                if (!SafeReadable(q, 8)) continue;
                BYTE qb = q[0];
                int  rex_q = 0;
                BYTE op_q = qb;
                int  off_modrm_q = 1;
                if (qb >= 0x40 && qb <= 0x4F) {
                    rex_q = 1;
                    op_q = q[1];
                    off_modrm_q = 2;
                }
                if (op_q != 0x8D) continue;   // require `lea`, not `mov`
                BYTE modrm_q = q[off_modrm_q];
                if ((modrm_q >> 6) != 0) continue;
                if ((modrm_q & 7) != 5) continue;
                INT32 disp_q = (INT32)ReadU32(q + off_modrm_q + 1);
                BYTE* tgt_q = q + off_modrm_q + 1 + 4 + disp_q;
                if (!SafeReadable(tgt_q, 32)) continue;
                bool dup = false;
                for (int s = 0; s < seen_pool_count; s++) {
                    if (seen_pools[s] == tgt_q) { dup = true; break; }
                }
                if (dup) continue;
                if (seen_pool_count < 32) seen_pools[seen_pool_count++] = tgt_q;
                // Dump 256 bytes of candidate key pool
                char hex[600];
                int hj = 0;
                __try {
                    int dump_n = 256;
                    for (int k = 0; k < dump_n && hj < (int)sizeof(hex) - 4; k++) {
                        BYTE bv;
                        if (!SafeReadByte(tgt_q + k, &bv)) { hex[hj++]='?'; hex[hj++]='?'; continue; }
                        static const char* hexc = "0123456789ABCDEF";
                        hex[hj++] = hexc[bv >> 4];
                        hex[hj++] = hexc[bv & 0xF];
                    }
                    hex[hj] = 0;
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    strcpy_s(hex, "<read fault>");
                }
                NexusSpyLog("[theia-pool] caller=%p site@%p lea@%p disp=%d -> %p first256=%s",
                            caller_rip, p, q, disp_q, tgt_q, hex);
                pool_refs++;
                if (pool_refs >= 16) break;
            }
            // Also: try to read a possible `xor reg, imm` within +/- 0x40 of Theia site.
            BYTE* xlo = (p > base + 0x40) ? p - 0x40 : base;
            BYTE* xhi = p + 0x40;
            for (BYTE* q = xlo; q + 4 < xhi; q++) {
                if (!SafeReadable(q, 4)) continue;
                // 0x83 /6 ib  -- xor reg, imm8 (forms F0..F7 modrm)
                if (q[0] == 0x83 && q[1] >= 0xF0 && q[1] <= 0xF7) {
                    NexusSpyLog("[theia-xor8] caller=%p site@%p xor@%p modrm=0x%02X imm8=0x%02X",
                                caller_rip, p, q, q[1], q[2]);
                }
                // REX 0x48/0x49 + 0x83 /6 ib
                if ((q[0] == 0x48 || q[0] == 0x49) && q[1] == 0x83 && q[2] >= 0xF0 && q[2] <= 0xF7) {
                    NexusSpyLog("[theia-xor8r] caller=%p site@%p xor@%p modrm=0x%02X imm8=0x%02X",
                                caller_rip, p, q, q[2], q[3]);
                }
            }
            if (theia_sites >= 8) break;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NexusSpyLog("[theia-pool] EXCEPTION caller=%p", caller_rip);
    }
    NexusSpyLog("[theia-pool:end] caller=%p theia_sites=%d pool_refs=%d",
                caller_rip, theia_sites, pool_refs);
}

static BOOL WINAPI hk_Process32NextW(HANDLE h, PE32W_Layout* pe) {
    BOOL ok = o_Process32NextW(h, pe);
    if (ok && pe) {
        char name[300];
        WideToAsciiSafe(pe->szExeFile, 260, name, sizeof(name));
        void* ret = _ReturnAddress();
        NexusSpyLog("[Process32NextW] pid=%lu name=\"%s\" caller=%p",
                    pe->th32ProcessID, name, ret);

        // ONE-SHOT per caller RIP: dump the surrounding hash-bucket cluster.
        // Done from inside the safe Process32NextW forwarder hook — we only
        // READ memory; we don't patch the Themida-protected matcher itself.
        if (MarkCallerDumped(ret)) {
            __try {
                DumpBucketClusterAroundCaller(ret);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                NexusSpyLog("[bucket-dump] outer EXCEPTION for caller=%p", ret);
            }
        }

        // First time we see a bait name come through, dump the launcher image.
        if (strstr(name, "cheatengine") || strstr(name, "Cheat") ||
            strstr(name, "boring_innocent")) {
            SelfDumpLauncherImage("Process32NextW returned bait name");
        }
    }
    return ok;
}

// ====================================================================
// Public installer
// ====================================================================
#define HK(mod, name) \
    do { \
        void* p = (void*)GetProcAddress(GetModuleHandleA(mod), #name); \
        if (p) { \
            if (MH_CreateHook(p, (LPVOID)hk_##name, (LPVOID*)&o_##name) == MH_OK \
                && MH_EnableHook(p) == MH_OK) { \
                NexusSpyLog("[enum-hook] %s!%s @ %p", mod, #name, p); \
            } else { \
                NexusSpyLog("[enum-hook] FAILED %s!%s @ %p", mod, #name, p); \
            } \
        } else { \
            NexusSpyLog("[enum-hook] not found: %s!%s", mod, #name); \
        } \
    } while (0)

// ====================================================================
// LAUNCHER-INTERNAL HOOK: the Themida string-decryption-with-cache
// function at RVA 0xE6780 in EAAntiCheat.GameServiceLauncher.exe.
//
// Signature inferred from F5 / call sites:
//   void* __fastcall TheiaDecrypt(void* enc_blob_ptr, __int64 length);
//
// Captures every (enc_va, length) -> (plaintext) the launcher decrypts.
// One live run with detection firing produces the complete encrypted-
// string dictionary (registry paths, blocklist labels, error templates,
// etc.) without any cipher reversing.
// ====================================================================
typedef void* (__fastcall *PFN_TheiaDecrypt)(void* enc, __int64 len);
static PFN_TheiaDecrypt o_TheiaDecrypt;

static void HexDumpToStr(const void* p, size_t n, char* out, size_t outsz) {
    static const char hexc[] = "0123456789abcdef";
    const unsigned char* b = (const unsigned char*)p;
    size_t j = 0;
    for (size_t i = 0; i < n && j + 3 < outsz; i++) {
        out[j++] = hexc[b[i] >> 4];
        out[j++] = hexc[b[i] & 0xF];
        out[j++] = ' ';
    }
    if (j > 0) j--; // drop trailing space
    out[j] = 0;
}

static void* __fastcall hk_TheiaDecrypt(void* enc, __int64 len) {
    char hex_in[256];
    size_t copy = (len > 32) ? 32 : (size_t)len;
    HexDumpToStr(enc, copy, hex_in, sizeof(hex_in));

    void* out = o_TheiaDecrypt(enc, len);

    char hex_out[256] = "<null>";
    char ascii_out[200] = "";
    char wide_out[200] = "";
    if (out) {
        size_t copy_out = (len > 64) ? 64 : (size_t)len;
        HexDumpToStr(out, copy_out, hex_out, sizeof(hex_out));
        // ASCII rendering
        const unsigned char* p = (const unsigned char*)out;
        size_t j = 0;
        for (size_t i = 0; i < copy_out && j < sizeof(ascii_out) - 1; i++) {
            ascii_out[j++] = (p[i] >= 0x20 && p[i] < 0x7F) ? (char)p[i] : '.';
        }
        ascii_out[j] = 0;
        // UTF-16-LE rendering
        size_t wcount = copy_out / 2;
        WideToAsciiSafe((const wchar_t*)out, (int)wcount, wide_out, sizeof(wide_out));
    }

    void* ret = _ReturnAddress();
    NexusSpyLog("[TheiaDecrypt] enc_va=%p len=%lld caller=%p\n"
                "    enc[0..32]: %s\n"
                "    out hex   : %s\n"
                "    out ascii : \"%s\"\n"
                "    out utf16 : \"%s\"",
                enc, (long long)len, ret, hex_in, hex_out, ascii_out, wide_out);
    return out;
}

// ====================================================================
// IAT-SLOT PATCH HOOK on the launcher's per-process check dispatch.
//
// Discriminator code at RVA 0xDD1C0..0xDD1EA in the launcher EXE:
//     mov  rcx, [rsi+0x38]            ; rcx = check-object pointer
//     test rcx, rcx ; je out
//     mov  rax, [rcx]                 ; rax = vtable
//     mov  rax, [rax+0x10]            ; rax = vtable[2] = real check fn
//     mov  rdx, r14                   ; rdx = &PROCESSENTRY32W (just-enumerated proc)
//     call qword ptr [rip+0x6BFAE7]   ; <-- IAT slot at base+0x79CCC0
//     test al, al ; je out_of_loop    ; non-zero return = continue scanning
//     call Process32NextW             ; advance to next process
//
// We replace the IAT slot value with our trampoline. Per call:
//   1. Trampoline preserves rax (= vtable[2] target) + rcx/rdx (args)
//   2. Calls our C logger with (rcx, rdx, rax)
//   3. Logger calls the original Themida dispatcher (saved at install)
//   4. Returns the result
//
// This catches the call regardless of any lazy IAT rewriting Themida does.
// ====================================================================

typedef BOOL (__fastcall *PFN_VtableCheck)(void* this_ptr, void* pe);
static void* g_origDispatcher = nullptr;
static BYTE* g_vtblTrampoline = nullptr;
static volatile LONG g_vtblCallCount = 0;
static volatile LONG g_vtblMatchCount = 0;

extern "C" BOOL __fastcall NexusSpy_VtableLogger(
    void* this_ptr, void* pe_void, void* vtable2)
{
    LONG count = InterlockedIncrement(&g_vtblCallCount);

    // PE32W layout: dwSize(4) cntUsage(4) th32ProcessID(4) ... szExeFile@offset 44 (260 wchars)
    DWORD pid = 0;
    char  name[300] = "?";
    if (pe_void) {
        const PE32W_Layout* pe = (const PE32W_Layout*)pe_void;
        pid = pe->th32ProcessID;
        WideToAsciiSafe(pe->szExeFile, 260, name, sizeof(name));
    }

    // Call the original dispatcher (preserved value of the IAT slot)
    BOOL result;
    if (g_origDispatcher) {
        result = ((PFN_VtableCheck)g_origDispatcher)(this_ptr, pe_void);
    } else {
        result = TRUE;
    }

    // Log: every match (al!=0 means "continue scanning" — see disasm above)
    // Plus first 5 calls for sanity, plus every match (rare).
    bool log_it = (count <= 5) || !result;   // !result means a match was found
    if (!result) InterlockedIncrement(&g_vtblMatchCount);

    if (log_it) {
        NexusSpyLog("[VTBL-CHECK] #%ld this=%p pid=%lu name=\"%s\" "
                    "vtable[2]=%p result=%d %s",
                    count, this_ptr, pid, name, vtable2, result,
                    !result ? "<<< MATCH (loop will exit) >>>" : "");
    }
    return result;
}

static void InstallVtableCheckHook(void) {
    HMODULE hMod = GetModuleHandleW(NULL);
    if (!hMod) {
        NexusSpyLog("[vtbl-hook] GetModuleHandleW failed");
        return;
    }
    BYTE* base = (BYTE*)hMod;
    void** iatSlot = (void**)(base + 0x79CCC0);

    // Allocate RWX trampoline buffer (absolute call rax inside, no +/-2GB constraint)
    g_vtblTrampoline = (BYTE*)VirtualAlloc(NULL, 0x40,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (!g_vtblTrampoline) {
        NexusSpyLog("[vtbl-hook] VirtualAlloc failed err=%lu", GetLastError());
        return;
    }

    // Trampoline bytes:
    //   50                          push rax              (save vtable[2])
    //   48 83 EC 28                 sub rsp, 0x28         (shadow space + 16-byte align)
    //   4C 8B 44 24 28              mov r8, [rsp+0x28]    (pass saved rax as 3rd arg)
    //   48 B8 <imm64 logger>        mov rax, imm64
    //   FF D0                       call rax
    //   48 83 C4 28                 add rsp, 0x28
    //   48 83 C4 08                 add rsp, 8            (drop the saved rax)
    //   C3                          ret
    BYTE tramp[] = {
        0x50,
        0x48, 0x83, 0xEC, 0x28,
        0x4C, 0x8B, 0x44, 0x24, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0x48, 0x83, 0xC4, 0x08,
        0xC3
    };
    void* loggerAddr = (void*)&NexusSpy_VtableLogger;
    memcpy(&tramp[12], &loggerAddr, 8);
    memcpy(g_vtblTrampoline, tramp, sizeof(tramp));

    // Patch IAT slot
    DWORD oldProt;
    if (!VirtualProtect(iatSlot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
        NexusSpyLog("[vtbl-hook] VirtualProtect(RW) failed err=%lu", GetLastError());
        return;
    }
    g_origDispatcher = *iatSlot;
    *iatSlot = (void*)g_vtblTrampoline;
    DWORD tmp;
    VirtualProtect(iatSlot, sizeof(void*), oldProt, &tmp);

    NexusSpyLog("[vtbl-hook] IAT slot at %p patched: orig=%p -> trampoline=%p (logger=%p)",
                iatSlot, g_origDispatcher, g_vtblTrampoline, loggerAddr);
}

// Forward declaration (defined later)
static void UnicodeStringToAscii(PUNICODE_STRING us, char* out, size_t outsz);

// ====================================================================
// ntdll!NtCreateFile / NtOpenFile / NtMapViewOfSection / NtCreateSection
// Captures every file the launcher opens AND every section/mapping it
// creates. If the blocklist is loaded from a separate file we haven't
// identified, this catches it.
// ====================================================================
typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
    DWORD, ULONG, ULONG);

static PFN_NtCreateFile        o_NtCreateFile;
static PFN_NtOpenFile          o_NtOpenFile;
static PFN_NtMapViewOfSection  o_NtMapViewOfSection;

static NTSTATUS NTAPI hk_NtCreateFile(PHANDLE phFile, ACCESS_MASK access,
    POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb, PLARGE_INTEGER size,
    ULONG attrs, ULONG share, ULONG disp, ULONG opts, PVOID eaBuf, ULONG eaLen)
{
    char path[600] = "";
    if (oa && oa->ObjectName) UnicodeStringToAscii(oa->ObjectName, path, sizeof(path));
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtCreateFile(phFile, access, oa, iosb, size, attrs, share, disp, opts, eaBuf, eaLen);
    NexusSpyLog("[NtCreateFile] path=\"%s\" access=0x%lX disp=0x%lX -> 0x%lX caller=%p",
                path, (unsigned long)access, (unsigned long)disp, (unsigned long)rv, ret);
    return rv;
}

static NTSTATUS NTAPI hk_NtOpenFile(PHANDLE phFile, ACCESS_MASK access,
    POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb, ULONG share, ULONG opts)
{
    char path[600] = "";
    if (oa && oa->ObjectName) UnicodeStringToAscii(oa->ObjectName, path, sizeof(path));
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtOpenFile(phFile, access, oa, iosb, share, opts);
    NexusSpyLog("[NtOpenFile] path=\"%s\" access=0x%lX -> 0x%lX caller=%p",
                path, (unsigned long)access, (unsigned long)rv, ret);
    return rv;
}

static NTSTATUS NTAPI hk_NtMapViewOfSection(HANDLE sec, HANDLE proc,
    PVOID* base, ULONG_PTR zb, SIZE_T cs, PLARGE_INTEGER off, PSIZE_T vs,
    DWORD inherit, ULONG alloc, ULONG prot)
{
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtMapViewOfSection(sec, proc, base, zb, cs, off, vs, inherit, alloc, prot);
    PVOID mapped = base ? *base : NULL;
    SIZE_T mapsz = vs ? *vs : 0;
    NexusSpyLog("[NtMapViewOfSection] sec=%p proc=%p -> base=%p size=%llu prot=0x%lX rv=0x%lX caller=%p",
                sec, proc, mapped, (unsigned long long)mapsz, (unsigned long)prot, (unsigned long)rv, ret);
    return rv;
}

// ====================================================================
// HEAP ALLOCATION TRACKING (added 2026-05-01)
// Hooks RtlAllocateHeap + NtAllocateVirtualMemory in the launcher process.
// Goal: locate where the decrypted exe-list entries get written when the
// launcher's discriminator iterates the cipher-encoded blocklist.
//
// Theory: launcher decrypts each ~23-byte entry into a recycled scratch
// buffer; that buffer is allocated once at startup. Filtering allocations
// by size class (16-256B = entry buffer, 1-4KB = batch buffer, 4KB+ for
// label-list region) gives candidate VAs to poll externally.
//
// Each event logs: (size, returned VA, caller RIP, allocator-specific flags).
// External tool can sort by allocation size + frequency to find the hot
// per-call entry buffer.
// ====================================================================
typedef PVOID    (NTAPI *PFN_RtlAllocateHeap)(PVOID heap, ULONG flags, SIZE_T size);
typedef BOOLEAN  (NTAPI *PFN_RtlFreeHeap)(PVOID heap, ULONG flags, PVOID memory);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE proc, PVOID* base,
                                                      ULONG_PTR zb, PSIZE_T size,
                                                      ULONG type, ULONG prot);

static PFN_RtlAllocateHeap         o_RtlAllocateHeap;
static PFN_RtlFreeHeap             o_RtlFreeHeap;
static PFN_NtAllocateVirtualMemory o_NtAllocateVirtualMemory;

// Filter: only log RtlAllocateHeap calls in size range that could hold
// an exe-list entry buffer or label region. Skip tiny housekeeping allocs.
static volatile LONG g_heapLogCounter = 0;

static PVOID NTAPI hk_RtlAllocateHeap(PVOID heap, ULONG flags, SIZE_T size) {
    PVOID rv = o_RtlAllocateHeap(heap, flags, size);
    // Only log allocations in the "interesting" size band:
    //   16..256 bytes  (per-entry decrypt scratch — most likely candidate)
    //   1024..16384    (label-region or entry-array)
    if (rv && ((size >= 16 && size <= 256) || (size >= 1024 && size <= 16384))) {
        // Throttle to prevent log explosion: log every Nth in this band.
        LONG ctr = InterlockedIncrement(&g_heapLogCounter);
        if (ctr <= 5000 || (ctr % 50) == 0) {
            void* caller = _ReturnAddress();
            NexusSpyLog("[heap-alloc] heap=%p size=%llu va=%p caller=%p flags=0x%lX",
                        heap, (unsigned long long)size, rv, caller, flags);
        }
    }
    return rv;
}

// RtlFreeHeap: dump buffer contents BEFORE free. The just-freed contents
// are what the launcher LAST WROTE to this buffer — perfect capture point
// for decrypted exe-list entries that landed in temporary scratch buffers.
//
// Filter: only log frees for buffers that had a recent ALLOC matching our
// interest size band (16..256B). The allocator stores the original size in
// the heap-block header just before the user data: `*(PSIZE_T)(memory - 8)`
// is unreliable on modern heaps (HEAP_HE encryption), so we just look at
// what's printable in the first 64 bytes — if it's UTF-16-LE printable text,
// log the whole thing.
static BOOLEAN NTAPI hk_RtlFreeHeap(PVOID heap, ULONG flags, PVOID memory) {
    if (memory != NULL) {
        // Heuristic: peek the first 64 bytes. If it looks like UTF-16-LE
        // ASCII (every other byte is 0x00 with printable chars between),
        // OR pure printable ASCII, log it.
        __try {
            const unsigned char* p = (const unsigned char*)memory;
            int printable_ascii = 0;
            int printable_utf16 = 0;
            int i;
            for (i = 0; i < 48; i++) {
                if (p[i] >= 0x20 && p[i] < 0x7F) printable_ascii++;
                if ((i & 1) == 0 && p[i] >= 0x20 && p[i] < 0x7F && p[i+1] == 0) printable_utf16++;
                if ((i & 1) == 0 && p[i] == 0 && p[i+1] == 0 && i >= 8) break;  // null terminator
            }
            if (printable_ascii >= 6 || printable_utf16 >= 4) {
                // Capture ASCII rendering
                char ascii[80] = {0};
                int j = 0;
                for (int k = 0; k < 64 && j < 78; k++) {
                    ascii[j++] = (p[k] >= 0x20 && p[k] < 0x7F) ? (char)p[k] : '.';
                }
                ascii[j] = 0;
                // UTF-16 rendering
                char utf16str[80] = {0};
                int u = 0;
                for (int k = 0; k < 64 && u < 78; k += 2) {
                    if (p[k+1] == 0 && p[k] >= 0x20 && p[k] < 0x7F) {
                        utf16str[u++] = (char)p[k];
                    } else if (p[k] == 0 && p[k+1] == 0) {
                        break;
                    } else {
                        utf16str[u++] = '.';
                    }
                }
                utf16str[u] = 0;
                void* caller = _ReturnAddress();
                NexusSpyLog("[heap-free] heap=%p va=%p caller=%p ascii=\"%s\" utf16=\"%s\"",
                            heap, memory, caller, ascii, utf16str);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return o_RtlFreeHeap(heap, flags, memory);
}

static NTSTATUS NTAPI hk_NtAllocateVirtualMemory(HANDLE proc, PVOID* base,
                                                  ULONG_PTR zb, PSIZE_T size,
                                                  ULONG type, ULONG prot) {
    NTSTATUS rv = o_NtAllocateVirtualMemory(proc, base, zb, size, type, prot);
    if (NT_SUCCESS(rv) && base && size && (type & MEM_COMMIT)) {
        void* caller = _ReturnAddress();
        // Log every committed allocation — they're rare and each one matters
        NexusSpyLog("[NtAllocVM] proc=%p base=%p size=%llu type=0x%lX prot=0x%lX caller=%p",
                    proc, *base, (unsigned long long)*size, type, prot, caller);
    }
    return rv;
}

// ====================================================================
// kernel32!OpenProcess + bcrypt!BCryptHashData/OpenAlgorithmProvider +
// ntdll!RtlCompareMemory/RtlEqualUnicodeString + kernel32!lstrcmpW
//
// Captures the inner-loop machinery of the launcher's per-process
// matcher: OpenProcess(pid) -> QueryFullProcessImageNameW -> hash/compare.
// ====================================================================
typedef HANDLE  (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
typedef NTSTATUS(WINAPI *PFN_BCryptOpenAlgorithmProvider)(void*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI *PFN_BCryptHashData)(void*, PUCHAR, ULONG, ULONG);
typedef SIZE_T  (NTAPI  *PFN_RtlCompareMemory)(const VOID*, const VOID*, SIZE_T);
typedef BOOLEAN (NTAPI  *PFN_RtlEqualUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
typedef int     (WINAPI *PFN_lstrcmpW)(LPCWSTR, LPCWSTR);
typedef int     (WINAPI *PFN_lstrcmpiW)(LPCWSTR, LPCWSTR);
typedef int     (__cdecl*PFN_wcsicmp)(const wchar_t*, const wchar_t*);
typedef int     (__cdecl*PFN_memcmp)(const void*, const void*, size_t);
static PFN_OpenProcess               o_OpenProcess;
static PFN_BCryptOpenAlgorithmProvider o_BCryptOpenAlgorithmProvider;
static PFN_BCryptHashData            o_BCryptHashData;
static PFN_RtlCompareMemory          o_RtlCompareMemory;
static PFN_RtlEqualUnicodeString     o_RtlEqualUnicodeString;
static PFN_lstrcmpW                  o_lstrcmpW;
static PFN_lstrcmpiW                 o_lstrcmpiW;

static HANDLE WINAPI hk_OpenProcess(DWORD dwAccess, BOOL bInherit, DWORD dwPid) {
    void* ret = _ReturnAddress();
    HANDLE h = o_OpenProcess(dwAccess, bInherit, dwPid);
    NexusSpyLog("[OpenProcess] pid=%lu access=0x%lX inherit=%d -> handle=%p caller=%p",
                dwPid, dwAccess, bInherit, h, ret);
    return h;
}

static NTSTATUS WINAPI hk_BCryptOpenAlgorithmProvider(void* phAlgo, LPCWSTR pszAlgId,
                                                      LPCWSTR pszImpl, ULONG dwFlags) {
    char alg[200] = "?", impl[200] = "?";
    if (pszAlgId) WideToAsciiSafe(pszAlgId, 64, alg, sizeof(alg));
    if (pszImpl)  WideToAsciiSafe(pszImpl,  64, impl, sizeof(impl));
    void* ret = _ReturnAddress();
    NTSTATUS s = o_BCryptOpenAlgorithmProvider(phAlgo, pszAlgId, pszImpl, dwFlags);
    NexusSpyLog("[BCryptOpenAlg] alg=\"%s\" impl=\"%s\" flags=0x%lX -> 0x%lX caller=%p",
                alg, impl, dwFlags, (unsigned long)s, ret);
    return s;
}

static NTSTATUS WINAPI hk_BCryptHashData(void* hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    void* ret = _ReturnAddress();
    NTSTATUS s = o_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
    char hex[200] = "";
    char asc[100] = "";
    if (pbInput && cbInput > 0) {
        ULONG copy = cbInput > 64 ? 64 : cbInput;
        HexDumpToStr(pbInput, copy, hex, sizeof(hex));
        for (ULONG k = 0; k < copy && k < sizeof(asc) - 1; k++) {
            asc[k] = (pbInput[k] >= 0x20 && pbInput[k] < 0x7F) ? (char)pbInput[k] : '.';
        }
        asc[copy < sizeof(asc) - 1 ? copy : sizeof(asc) - 1] = 0;
    }
    NexusSpyLog("[BCryptHashData] hHash=%p len=%lu -> 0x%lX caller=%p\n"
                "    hex   : %s\n"
                "    ascii : \"%s\"",
                hHash, cbInput, (unsigned long)s, ret, hex, asc);
    return s;
}

static SIZE_T NTAPI hk_RtlCompareMemory(const VOID* s1, const VOID* s2, SIZE_T len) {
    void* ret = _ReturnAddress();
    SIZE_T r = o_RtlCompareMemory(s1, s2, len);
    // Only log when the comparison is short (likely a hash compare, not bulk memcmp)
    if (len <= 64) {
        char ah[200] = "", bh[200] = "";
        HexDumpToStr(s1, (size_t)len, ah, sizeof(ah));
        HexDumpToStr(s2, (size_t)len, bh, sizeof(bh));
        NexusSpyLog("RtlCompareMemory(%llu) a=%s b=%s caller=%p",
                    (unsigned long long)len, ah, bh, ret);
    }
    return r;
}

static BOOLEAN NTAPI hk_RtlEqualUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN ci) {
    void* ret = _ReturnAddress();
    BOOLEAN r = o_RtlEqualUnicodeString(s1, s2, ci);
    char a[200] = "", b[200] = "";
    if (s1 && s1->Buffer) WideToAsciiSafe(s1->Buffer, s1->Length / 2, a, sizeof(a));
    if (s2 && s2->Buffer) WideToAsciiSafe(s2->Buffer, s2->Length / 2, b, sizeof(b));
    NexusSpyLog("RtlEqualUnicodeString a=\"%s\" b=\"%s\" ci=%d caller=%p",
                a, b, ci, ret);
    return r;
}

static int WINAPI hk_lstrcmpW(LPCWSTR s1, LPCWSTR s2) {
    void* ret = _ReturnAddress();
    int r = o_lstrcmpW(s1, s2);
    char a[200] = "", b[200] = "";
    if (s1) WideToAsciiSafe(s1, 100, a, sizeof(a));
    if (s2) WideToAsciiSafe(s2, 100, b, sizeof(b));
    NexusSpyLog("lstrcmpW a=\"%s\" b=\"%s\" -> %d caller=%p", a, b, r, ret);
    return r;
}

static int WINAPI hk_lstrcmpiW(LPCWSTR s1, LPCWSTR s2) {
    void* ret = _ReturnAddress();
    int r = o_lstrcmpiW(s1, s2);
    char a[200] = "", b[200] = "";
    if (s1) WideToAsciiSafe(s1, 100, a, sizeof(a));
    if (s2) WideToAsciiSafe(s2, 100, b, sizeof(b));
    NexusSpyLog("lstrcmpiW a=\"%s\" b=\"%s\" -> %d caller=%p", a, b, r, ret);
    return r;
}

// ====================================================================
// advapi32 registry-API hooks
//
// The discriminator's case -527410169 / 505629796 / 637317694 paths
// call RegQueryValueExW / RegOpenKeyExW / RegCloseKey through Themida-
// resolved thunks. By the time these calls reach advapi32, the
// arguments have already been Theia-DECRYPTED. Hooking these gives us
// the plaintext registry path + value name without solving the cipher.
//
// Themida only watches launcher .rdata IAT slots (per 2026-04-27 finding).
// System DLL exports are fair game for MinHook entry-point hooks.
// ====================================================================
typedef LSTATUS (WINAPI *PFN_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *PFN_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *PFN_RegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI *PFN_RegCloseKey)(HKEY);
static PFN_RegOpenKeyExW    o_RegOpenKeyExW;
static PFN_RegQueryValueExW o_RegQueryValueExW;
static PFN_RegGetValueW     o_RegGetValueW;
static PFN_RegCloseKey      o_RegCloseKey;

static const char* HKeyName(HKEY h) {
    switch ((uintptr_t)h) {
        case 0x80000000: return "HKCR";
        case 0x80000001: return "HKCU";
        case 0x80000002: return "HKLM";
        case 0x80000003: return "HKU";
        case 0x80000005: return "HKCC";
        default:         return "<handle>";
    }
}

static LSTATUS WINAPI hk_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD opts,
                                        REGSAM samDesired, PHKEY phkResult)
{
    char subkey[600] = "";
    if (lpSubKey) WideToAsciiSafe(lpSubKey, 256, subkey, sizeof(subkey));
    void* ret = _ReturnAddress();
    LSTATUS rv = o_RegOpenKeyExW(hKey, lpSubKey, opts, samDesired, phkResult);
    NexusSpyLog("[RegOpenKeyExW] hKey=%s subkey=\"%s\" sam=0x%lX -> %ld %s caller=%p",
                HKeyName(hKey), subkey, (unsigned long)samDesired, (long)rv,
                (rv == 0 ? "OK" : "ERR"), ret);
    return rv;
}

static LSTATUS WINAPI hk_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName,
                                           LPDWORD lpReserved, LPDWORD lpType,
                                           LPBYTE lpData, LPDWORD lpcbData)
{
    char vname[600] = "";
    if (lpValueName) WideToAsciiSafe(lpValueName, 256, vname, sizeof(vname));
    void* ret = _ReturnAddress();
    LSTATUS rv = o_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    DWORD typeOut = lpType ? *lpType : 0;
    DWORD sizeOut = lpcbData ? *lpcbData : 0;
    char preview[300] = "";
    if (rv == 0 && lpData && lpcbData && sizeOut > 0 && sizeOut < 600) {
        if (typeOut == REG_SZ || typeOut == REG_EXPAND_SZ) {
            WideToAsciiSafe((const wchar_t*)lpData, (int)(sizeOut / 2),
                            preview, sizeof(preview));
        } else if (typeOut == REG_DWORD && sizeOut == 4) {
            sprintf_s(preview, sizeof(preview), "0x%lX", *(DWORD*)lpData);
        } else {
            // Hex dump first 32 bytes
            HexDumpToStr(lpData, sizeOut > 32 ? 32 : sizeOut, preview, sizeof(preview));
        }
    }
    NexusSpyLog("[RegQueryValueExW] hKey=%p value=\"%s\" type=%lu size=%lu -> %ld data=%s caller=%p",
                hKey, vname, typeOut, sizeOut, (long)rv, preview, ret);
    return rv;
}

static LSTATUS WINAPI hk_RegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue,
                                       DWORD dwFlags, LPDWORD pdwType,
                                       PVOID pvData, LPDWORD pcbData)
{
    char subkey[400] = "", value[200] = "";
    if (lpSubKey) WideToAsciiSafe(lpSubKey, 256, subkey, sizeof(subkey));
    if (lpValue)  WideToAsciiSafe(lpValue,  128, value,  sizeof(value));
    void* ret = _ReturnAddress();
    LSTATUS rv = o_RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    NexusSpyLog("[RegGetValueW] hKey=%s subkey=\"%s\" value=\"%s\" flags=0x%lX -> %ld caller=%p",
                HKeyName(hkey), subkey, value, (unsigned long)dwFlags, (long)rv, ret);
    return rv;
}

static LSTATUS WINAPI hk_RegCloseKey(HKEY hKey) {
    LSTATUS rv = o_RegCloseKey(hKey);
    return rv;  // very high call volume, only return — don't log every close
}

// ====================================================================
// ntdll Nt*Key hooks - the syscall layer below kernelbase.
// Catches EVERY registry call regardless of how the launcher routes it.
// (Themida tolerates ntdll entry hooks - NtQuerySystemInformation has
//  been running clean for many spawns.)
// ====================================================================
typedef NTSTATUS (NTAPI *PFN_NtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtOpenKeyEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryValueKey)(HANDLE, PUNICODE_STRING, int,
                                               PVOID, ULONG, PULONG);
static PFN_NtOpenKey       o_NtOpenKey;
static PFN_NtOpenKeyEx     o_NtOpenKeyEx;
static PFN_NtQueryValueKey o_NtQueryValueKey;

static void UnicodeStringToAscii(PUNICODE_STRING us, char* out, size_t outsz) {
    if (!us || !us->Buffer || us->Length == 0) {
        if (outsz) out[0] = 0;
        return;
    }
    int wchars = us->Length / sizeof(wchar_t);
    WideToAsciiSafe(us->Buffer, wchars, out, outsz);
}

static NTSTATUS NTAPI hk_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes)
{
    char path[600] = "";
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        UnicodeStringToAscii(ObjectAttributes->ObjectName, path, sizeof(path));
    }
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    NexusSpyLog("[NtOpenKey] path=\"%s\" access=0x%lX -> 0x%lX %s caller=%p",
                path, (unsigned long)DesiredAccess, (unsigned long)rv,
                (NT_SUCCESS(rv) ? "OK" : "ERR"), ret);
    return rv;
}

static NTSTATUS NTAPI hk_NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
{
    char path[600] = "";
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        UnicodeStringToAscii(ObjectAttributes->ObjectName, path, sizeof(path));
    }
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
    NexusSpyLog("[NtOpenKeyEx] path=\"%s\" access=0x%lX opts=0x%lX -> 0x%lX %s caller=%p",
                path, (unsigned long)DesiredAccess, (unsigned long)OpenOptions,
                (unsigned long)rv, (NT_SUCCESS(rv) ? "OK" : "ERR"), ret);
    return rv;
}

static NTSTATUS NTAPI hk_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
                                          int KeyValueInformationClass, PVOID KeyValueInformation,
                                          ULONG Length, PULONG ResultLength)
{
    char vname[600] = "";
    UnicodeStringToAscii(ValueName, vname, sizeof(vname));
    void* ret = _ReturnAddress();
    NTSTATUS rv = o_NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
                                     KeyValueInformation, Length, ResultLength);
    NexusSpyLog("[NtQueryValueKey] hKey=%p value=\"%s\" cls=%d -> 0x%lX caller=%p",
                KeyHandle, vname, KeyValueInformationClass, (unsigned long)rv, ret);
    return rv;
}

// ====================================================================
// Schannel SSPI DecryptMessage / EncryptMessage hooks
//
// EAAC uses Windows Schannel (schannel.DLL + sspicli.DLL loaded into
// launcher) for TLS to its Skyfall backend (eaanticheat.ac.ea.com).
// All gRPC requests/responses pass through SSPI's
// EncryptMessage/DecryptMessage at some point.
//
// After DecryptMessage returns SEC_E_OK, the SecBufferDesc contains
// the decrypted plaintext in the SECBUFFER_DATA buffer. Logging that
// captures the gRPC response payload — which per prior intel
// (eaac_cheat_blocklist_is_skyfall_2026_04_25.md) holds the
// runtime-fetched cheat-tool blocklist.
//
// Hook surface = sspicli.dll (system DLL forwarder) — safe per the
// 2026-04-27 Themida-tolerance findings.
// ====================================================================

#define SECURITY_WIN32
#include <sspi.h>
#pragma comment(lib, "secur32.lib")

typedef SECURITY_STATUS (SEC_ENTRY *PFN_DecryptMessage)(
    PCtxtHandle phContext, PSecBufferDesc pMessage,
    ULONG MessageSeqNo, PULONG pfQOP);
typedef SECURITY_STATUS (SEC_ENTRY *PFN_EncryptMessage)(
    PCtxtHandle phContext, ULONG fQOP,
    PSecBufferDesc pMessage, ULONG MessageSeqNo);

static PFN_DecryptMessage o_DecryptMessage;
static PFN_EncryptMessage o_EncryptMessage;

static void LogSecBufferDesc(const char* tag, PSecBufferDesc pMessage,
                              SECURITY_STATUS rv, void* caller)
{
    if (!pMessage || rv != SEC_E_OK) return;
    for (ULONG i = 0; i < pMessage->cBuffers; i++) {
        SecBuffer* sb = &pMessage->pBuffers[i];
        if (!sb || sb->BufferType != SECBUFFER_DATA) continue;
        if (!sb->pvBuffer || sb->cbBuffer == 0) continue;

        ULONG sz   = sb->cbBuffer;
        ULONG copy = sz > 256 ? 256 : sz;
        char hex[600] = "";
        char asciiv[260] = "";
        const unsigned char* p = (const unsigned char*)sb->pvBuffer;

        size_t hj = 0;
        for (ULONG k = 0; k < copy && hj + 3 < sizeof(hex); k++) {
            static const char hc[] = "0123456789abcdef";
            hex[hj++] = hc[p[k] >> 4];
            hex[hj++] = hc[p[k] & 0xF];
            hex[hj++] = ' ';
        }
        if (hj > 0) hj--;
        hex[hj] = 0;

        size_t aj = 0;
        for (ULONG k = 0; k < copy && aj < sizeof(asciiv) - 1; k++) {
            asciiv[aj++] = (p[k] >= 0x20 && p[k] < 0x7F) ? (char)p[k] : '.';
        }
        asciiv[aj] = 0;

        NexusSpyLog("[%s] buf[%lu] type=DATA size=%lu caller=%p\n"
                    "    hex   : %s%s\n"
                    "    ascii : \"%s\"%s",
                    tag, (unsigned long)i, (unsigned long)sz, caller,
                    hex, sz > 256 ? " ..." : "",
                    asciiv, sz > 256 ? " ..." : "");
    }
}

static SECURITY_STATUS SEC_ENTRY hk_DecryptMessage(
    PCtxtHandle phContext, PSecBufferDesc pMessage,
    ULONG MessageSeqNo, PULONG pfQOP)
{
    void* ret = _ReturnAddress();
    SECURITY_STATUS rv = o_DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);
    LogSecBufferDesc("Schannel-DECRYPT", pMessage, rv, ret);
    return rv;
}

static SECURITY_STATUS SEC_ENTRY hk_EncryptMessage(
    PCtxtHandle phContext, ULONG fQOP,
    PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    void* ret = _ReturnAddress();
    // Log BEFORE the call — at this point the data buffer holds plaintext
    // (it'll be replaced with ciphertext in-place after EncryptMessage)
    LogSecBufferDesc("Schannel-ENCRYPT", pMessage, SEC_E_OK, ret);
    return o_EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);
}

// ====================================================================
// Matcher-output hooks: detect when the launcher concatenates a recovered
// blocklist label OR the alert-template fragment into a wide string.
// We hook write-side wide string APIs (lstrcpyW / lstrcatW / wsprintfW)
// because those are the moment the alert dialog text is being assembled.
// We also hook substring-search APIs (wcsstr / wcsrchr) because the
// architecture-suffix stripping logic (e.g., turning
// "cheatengine-x86_64.exe" -> "cheatengine.exe" before hashing) is
// almost certainly built on those primitives.
// ====================================================================

typedef LPWSTR (WINAPI *PFN_lstrcpyW)(LPWSTR, LPCWSTR);
static PFN_lstrcpyW o_lstrcpyW_match;

static LPWSTR WINAPI hk_lstrcpyW_match(LPWSTR dst, LPCWSTR src) {
    if (src) {
        const wchar_t* m = MatchKnownLabel(src);
        if (m) {
            void* ret = _ReturnAddress();
            LogMatchHit("lstrcpyW", src, m, ret);
        }
    }
    return o_lstrcpyW_match(dst, src);
}

typedef LPWSTR (WINAPI *PFN_lstrcatW)(LPWSTR, LPCWSTR);
static PFN_lstrcatW o_lstrcatW_match;

static LPWSTR WINAPI hk_lstrcatW_match(LPWSTR dst, LPCWSTR src) {
    if (src) {
        const wchar_t* m = MatchKnownLabel(src);
        if (m) {
            void* ret = _ReturnAddress();
            LogMatchHit("lstrcatW.src", src, m, ret);
        }
    }
    if (dst) {
        const wchar_t* m = MatchKnownLabel(dst);
        if (m) {
            void* ret = _ReturnAddress();
            LogMatchHit("lstrcatW.dst", dst, m, ret);
        }
    }
    return o_lstrcatW_match(dst, src);
}

// wsprintfW(LPWSTR, LPCWSTR fmt, ...) is varargs — hook the underlying
// wvsprintfW (non-vararg, takes va_list) which wsprintfW calls into.
typedef int (WINAPI *PFN_wvsprintfW)(LPWSTR, LPCWSTR, va_list);
static PFN_wvsprintfW o_wvsprintfW_match;

static int WINAPI hk_wvsprintfW_match(LPWSTR dst, LPCWSTR fmt, va_list ap) {
    int r = o_wvsprintfW_match(dst, fmt, ap);
    if (r > 0 && dst) {
        const wchar_t* m = MatchKnownLabel(dst);
        if (m) {
            void* ret = _ReturnAddress();
            LogMatchHit("wvsprintfW", dst, m, ret);
        }
    }
    return r;
}

// ucrtbase!wcsstr — substring search. Used by suffix strippers.
typedef wchar_t* (__cdecl *PFN_wcsstr)(const wchar_t*, const wchar_t*);
static PFN_wcsstr o_wcsstr_match;

static wchar_t* __cdecl hk_wcsstr_match(const wchar_t* hay, const wchar_t* needle) {
    wchar_t* r = o_wcsstr_match(hay, needle);
    // Log only when the haystack is OUR captured QFPIN path (suffix strip on it)
    // OR the needle looks like an architecture suffix.
    if (needle && hay) {
        __try {
            // arch-suffix sentinel: needle starts with '-' and contains digits/letters
            if (needle[0] == L'-' && wcslen(needle) <= 16) {
                char hayA[640], ndlA[40];
                WideToAsciiSafe(hay,    320, hayA, sizeof(hayA));
                WideToAsciiSafe(needle, 32,  ndlA, sizeof(ndlA));
                void* ret = _ReturnAddress();
                NexusSpyLog("[wcsstr.archstrip] hay=\"%s\" needle=\"%s\" found=%s caller=%p",
                            hayA, ndlA, r ? "YES" : "no", ret);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return r;
}

// ucrtbase!wcsrchr — find last char (often '\\' for path basename, or '-' for arch).
typedef wchar_t* (__cdecl *PFN_wcsrchr)(const wchar_t*, wchar_t);
static PFN_wcsrchr o_wcsrchr_match;

static wchar_t* __cdecl hk_wcsrchr_match(const wchar_t* s, wchar_t c) {
    wchar_t* r = o_wcsrchr_match(s, c);
    // Filter: only log on chars that mean basename / arch-suffix splitting,
    // and only if s contains ".exe" (signals it's a process-name-like buffer).
    if (s && (c == L'-' || c == L'_' || c == L'.' || c == L'\\' || c == L'/')) {
        __try {
            if (WcsIStr(s, L".exe") || WcsIStr(s, L".EXE")) {
                char hayA[640];
                WideToAsciiSafe(s, 320, hayA, sizeof(hayA));
                void* ret = _ReturnAddress();
                NexusSpyLog("[wcsrchr.basename] s=\"%s\" needle='%c' found=%s caller=%p",
                            hayA, (char)((c < 0x20 || c >= 0x7F) ? '?' : (char)c),
                            r ? "YES" : "no", ret);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return r;
}

// Install matcher-output hooks (separate from generic HK macro since these
// trampolines have a "_match" suffix so they don't collide with the
// existing lstrcpyW/lstrcatW hooks elsewhere in the spy DLL).
static void InstallMatcherCaptureHooks(void) {
    struct H { const char* mod; const char* fn; void* hook; void** orig; };
    H entries[] = {
        { "kernel32.dll", "lstrcpyW",   (void*)hk_lstrcpyW_match,   (void**)&o_lstrcpyW_match   },
        { "kernel32.dll", "lstrcatW",   (void*)hk_lstrcatW_match,   (void**)&o_lstrcatW_match   },
        { "user32.dll",   "wvsprintfW", (void*)hk_wvsprintfW_match, (void**)&o_wvsprintfW_match },
        { "ucrtbase.dll", "wcsstr",     (void*)hk_wcsstr_match,     (void**)&o_wcsstr_match     },
        { "ucrtbase.dll", "wcsrchr",    (void*)hk_wcsrchr_match,    (void**)&o_wcsrchr_match    },
    };
    for (const H& e : entries) {
        HMODULE m = GetModuleHandleA(e.mod);
        if (!m) {
            NexusSpyLog("[matcher-hook] module not loaded: %s", e.mod);
            continue;
        }
        void* p = (void*)GetProcAddress(m, e.fn);
        if (!p) {
            NexusSpyLog("[matcher-hook] not found: %s!%s", e.mod, e.fn);
            continue;
        }
        if (MH_CreateHook(p, e.hook, e.orig) == MH_OK && MH_EnableHook(p) == MH_OK) {
            NexusSpyLog("[matcher-hook] installed %s!%s @ %p", e.mod, e.fn, p);
        } else {
            NexusSpyLog("[matcher-hook] FAILED %s!%s @ %p", e.mod, e.fn, p);
        }
    }
}

// ====================================================================
// Cipher-function hook: locate the SSE2 cipher function by byte
// signature inside launcher private exec memory and MinHook its entry
// point. Captures every (input_buffer, output_buffer, length) pair so we
// can recover all decryptions the launcher performs at startup
// (especially the 51 label decryptions and any blocklist exe-name
// decryptions if they happen).
// ====================================================================

// Signature: bytes from the cipher function (fo 0x154A05 in BF800000 dump).
// 66 0F FE CB     paddd xmm1, xmm3
// 66 44 0F EF E9  pxor  xmm13, xmm1
// 66 41 0F 6F E5  movdqa xmm4, xmm13
// 66 0F 72 D4 08  psrld xmm4, 8
// Distinctive enough to find uniquely in launcher memory.
static const BYTE CIPHER_SIG[] = {
    0x66, 0x0F, 0xFE, 0xCB,
    0x66, 0x44, 0x0F, 0xEF, 0xE9,
    0x66, 0x41, 0x0F, 0x6F, 0xE5,
    0x66, 0x0F, 0x72, 0xD4, 0x08,
};

typedef void (*PFN_Cipher)(void* arg1, void* arg2, void* arg3, void* arg4);
static PFN_Cipher o_Cipher = NULL;
static void*      g_CipherEntry = NULL;
static volatile LONG g_CipherCallCount = 0;

static void NTAPI hk_Cipher_dump_args(const char* phase, void* a1, void* a2, void* a3, void* a4) {
    char ascii[200] = {0};
    char hex[300] = {0};
    int j = 0;
    __try {
        BYTE* pb = (BYTE*)a2;   // assume rdx is output buffer
        if (pb) {
            for (int i = 0; i < 96 && j < 280; i++) {
                static const char* hxd = "0123456789ABCDEF";
                hex[j++] = hxd[pb[i] >> 4];
                hex[j++] = hxd[pb[i] & 0xF];
            }
            hex[j] = 0;
            j = 0;
            for (int i = 0; i < 64 && j < 190; i++) {
                BYTE b = pb[i];
                ascii[j++] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            }
            ascii[j] = 0;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        strcpy_s(ascii, "<read fault>");
    }
    NexusSpyLog("[cipher:%s] call#%ld a1=%p a2=%p a3=%p a4=%p ascii=\"%s\" hex=%s",
                phase, g_CipherCallCount, a1, a2, a3, a4, ascii, hex);
}

static void hk_Cipher(void* a1, void* a2, void* a3, void* a4) {
    LONG n = InterlockedIncrement(&g_CipherCallCount);

    // Snapshot input buffer (assume rcx = input ciphertext OR a context struct)
    char hex_in[300] = {0};
    int j = 0;
    __try {
        BYTE* pb = (BYTE*)a1;
        if (pb) {
            for (int i = 0; i < 64 && j < 280; i++) {
                static const char* hxd = "0123456789ABCDEF";
                hex_in[j++] = hxd[pb[i] >> 4];
                hex_in[j++] = hxd[pb[i] & 0xF];
            }
            hex_in[j] = 0;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        strcpy_s(hex_in, "<read fault>");
    }
    NexusSpyLog("[cipher:enter] call#%ld a1=%p a2=%p a3=%p a4=%p in_hex=%s",
                n, a1, a2, a3, a4, hex_in);

    // Call original
    o_Cipher(a1, a2, a3, a4);

    // Snapshot output (typically a2 = rdx = output buffer)
    hk_Cipher_dump_args("exit", a1, a2, a3, a4);
}

static void* FindByteSignature(BYTE* haystack, SIZE_T n, const BYTE* needle, SIZE_T m) {
    if (n < m) return NULL;
    for (SIZE_T i = 0; i + m <= n; i++) {
        if (haystack[i] != needle[0]) continue;
        if (memcmp(haystack + i, needle, m) == 0) return haystack + i;
    }
    return NULL;
}

static void InstallCipherHook(void) {
    NexusSpyLog("[cipher-hook] starting search for cipher function...");
    // Walk launcher private executable memory regions
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    void* sig_match = NULL;
    int regions_scanned = 0;
    while ((SIZE_T)addr < 0x7FFFFFFFFFFF) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;
        BYTE* base = (BYTE*)mbi.BaseAddress;
        SIZE_T sz = mbi.RegionSize;
        BYTE* next = base + sz;
        if (next <= addr) break;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.Protect != PAGE_NOACCESS && sz < 64*1024*1024) {
            DWORD prot = mbi.Protect;
            // Executable regions only
            if (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY) {
                // Read with try/except in case of guard pages
                // Filter: only consider regions >= 0x100000 (1 MB).
                // The GSL.dll containing the cipher is ~1.4 MB, our own
                // NexusSpy.dll is ~200 KB, so a size cutoff cleanly excludes us.
                if (sz < 0x100000) {
                    addr = next;
                    continue;
                }
                __try {
                    void* hit = FindByteSignature(base, sz, CIPHER_SIG, sizeof(CIPHER_SIG));
                    if (hit) {
                        // Walk back up to 64 KB looking for clean Win64 prologue
                        // pattern `48 89 5C 24 08` (mov [rsp+8], rbx).
                        // Pick the LAST occurrence before the sig — that's the
                        // closest function start.
                        BYTE* p = (BYTE*)hit;
                        BYTE* fn_start = NULL;
                        SIZE_T max_back = (SIZE_T)(p - base);
                        if (max_back > 0x10000) max_back = 0x10000;
                        for (SIZE_T delta = max_back; delta >= 5; delta--) {
                            BYTE* c = p - delta;
                            if (c[0] == 0x48 && c[1] == 0x89 && c[2] == 0x5C &&
                                c[3] == 0x24 && c[4] == 0x08) {
                                fn_start = c;
                                break;
                            }
                        }
                        // Fallback: try `48 89 4C 24 08` (mov [rsp+8], rcx -- arg homing)
                        if (!fn_start) {
                            for (SIZE_T delta = max_back; delta >= 5; delta--) {
                                BYTE* c = p - delta;
                                if (c[0] == 0x48 && c[1] == 0x89 && c[2] == 0x4C &&
                                    c[3] == 0x24 && c[4] == 0x08) {
                                    fn_start = c;
                                    break;
                                }
                            }
                        }
                        NexusSpyLog("[cipher-hook] sig found @ %p (region %p..%p prot=0x%X) -> fn_start=%p (delta=-0x%llX)",
                                    hit, base, next, prot, fn_start,
                                    fn_start ? (unsigned long long)((BYTE*)hit - fn_start) : 0);
                        if (fn_start && !sig_match) {
                            sig_match = fn_start;
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    NexusSpyLog("[cipher-hook] EXCEPTION scanning %p", base);
                }
                regions_scanned++;
            }
        }
        addr = next;
    }
    NexusSpyLog("[cipher-hook] scanned %d exec regions", regions_scanned);
    if (!sig_match) {
        NexusSpyLog("[cipher-hook] NO cipher signature found");
        return;
    }
    g_CipherEntry = sig_match;

    // ================================================================
    // SAFE-DISCOVERY MODE (post-Themida-CRC-detection lesson 2026-04-27).
    // Hooking the cipher in-process trips Themida's image CRC within ~11s.
    // Instead, we LOG the cipher VA prominently so the user can install
    // an EPT-shadow hook via SentinelHV using:
    //
    //     NexusDSEFix --ept-hook <HV_BASE> 0x<CIPHER_VA>
    //
    // SHV's dual-EPT hook places CPUID in a SHADOW page (secondary EPT
    // execute view); Themida reads original bytes via primary EPT and
    // sees no modification. CPUID VM-exits are captured by SHV.
    // ================================================================
    NexusSpyLog("[cipher-hook] **** SAFE-DISCOVERY MODE ****");
    NexusSpyLog("[cipher-hook] **** CIPHER_VA = %p ****", sig_match);
    NexusSpyLog("[cipher-hook] **** install via:  NexusDSEFix --ept-hook <HV_BASE> 0x%llX ****",
                (unsigned long long)sig_match);
    NexusSpyLog("[cipher-hook] (in-process patching disabled to avoid Themida CRC trip)");
}

// Install hook on sub_7FF6281A6780 (RVA 0xE6780 in launcher EXE).
static void InstallTheiaDecryptHook(void) {
    HMODULE hMod = GetModuleHandleW(NULL);   // launcher EXE main image
    if (!hMod) {
        NexusSpyLog("[theia-hook] GetModuleHandleW(NULL) failed");
        return;
    }
    BYTE*  base   = (BYTE*)hMod;
    void*  target = base + 0xE6780;
    if (MH_CreateHook(target, (LPVOID)hk_TheiaDecrypt, (LPVOID*)&o_TheiaDecrypt) == MH_OK
        && MH_EnableHook(target) == MH_OK) {
        NexusSpyLog("[theia-hook] installed at base+0xE6780 = %p (base=%p)",
                    target, base);
    } else {
        NexusSpyLog("[theia-hook] FAILED at base+0xE6780 = %p (base=%p)",
                    target, base);
    }
}

// =====================================================================
// AUTO-DISCOVER + HOOK ALL Theia decryptors.
// 0xE6780 NEVER fired across 45 launcher runs (per logs at C:\ProgramData\
// NexusSpy_*.log). The exe-list is decrypted by a DIFFERENT Theia function.
//
// Per prior session map (captures/theia_mass_unlock/SESSION_FINDINGS.md),
// 10 distinct Theia decryptors exist. The "wipe-after-use" comparator
// at 0x4211C0 and densest at 0xEA880 are top candidates.
//
// Approach: scan launcher .text for `mov reg, 0x80808081` (Theia magic),
// walk back to function prologue, hook each unique function entry. Each
// hook captures (rcx_arg, rdx_arg, return_value, output_buf_first_64B).
// =====================================================================
#define MAX_AUTO_THEIA 16
typedef void* (__fastcall *PFN_TheiaGeneric)(void*, __int64, void*, void*);
static PFN_TheiaGeneric g_AutoOrig[MAX_AUTO_THEIA];
static void*            g_AutoTarget[MAX_AUTO_THEIA];
static int              g_AutoIndex[MAX_AUTO_THEIA];  // 0..15 for routing
static int              g_AutoCount = 0;

static void LogTheiaCall(int idx, void* target, void* a1, __int64 a2, void* a3, void* a4, void* result) {
    char hex_a1[200] = "";
    char hex_a3[200] = "";
    char hex_a4[200] = "";
    char hex_res[200] = "<null>";
    char ascii_res[200] = "";
    char wide_res[200] = "";
    auto safehex = [](void* p, size_t n, char* out, size_t outsz) {
        __try {
            HexDumpToStr(p, n, out, outsz);
        } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(out, outsz, "<faulted>"); }
    };
    if (a1) safehex(a1, 32, hex_a1, sizeof(hex_a1));
    if (a3) safehex(a3, 32, hex_a3, sizeof(hex_a3));
    if (a4) safehex(a4, 32, hex_a4, sizeof(hex_a4));
    if (result) {
        size_t n_res = 64;
        safehex(result, n_res, hex_res, sizeof(hex_res));
        __try {
            const unsigned char* p = (const unsigned char*)result;
            size_t j = 0;
            for (size_t i = 0; i < n_res && j < sizeof(ascii_res) - 1; i++) {
                ascii_res[j++] = (p[i] >= 0x20 && p[i] < 0x7F) ? (char)p[i] : '.';
            }
            ascii_res[j] = 0;
            WideToAsciiSafe((const wchar_t*)result, (int)(n_res / 2), wide_res, sizeof(wide_res));
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    void* caller = _ReturnAddress();
    NexusSpyLog("[auto-theia#%d] target=%p caller=%p\n"
                "    arg1=%p arg2=%lld arg3=%p arg4=%p result=%p\n"
                "    a1[0..32]: %s\n"
                "    a3[0..32]: %s\n"
                "    a4[0..32]: %s\n"
                "    result hex: %s\n"
                "    result ascii: \"%s\"\n"
                "    result utf16: \"%s\"",
                idx, target, caller, a1, (long long)a2, a3, a4, result,
                hex_a1, hex_a3, hex_a4, hex_res, ascii_res, wide_res);
}

// 16 trampoline thunks — each is a separate hook target so MinHook can
// install them. Each routes to LogTheiaCall with its own index.
#define AUTO_THUNK(N) \
static void* __fastcall hk_AutoTheia##N(void* a1, __int64 a2, void* a3, void* a4) { \
    void* result = g_AutoOrig[N](a1, a2, a3, a4); \
    LogTheiaCall(N, g_AutoTarget[N], a1, a2, a3, a4, result); \
    return result; \
}
AUTO_THUNK(0) AUTO_THUNK(1) AUTO_THUNK(2)  AUTO_THUNK(3)
AUTO_THUNK(4) AUTO_THUNK(5) AUTO_THUNK(6)  AUTO_THUNK(7)
AUTO_THUNK(8) AUTO_THUNK(9) AUTO_THUNK(10) AUTO_THUNK(11)
AUTO_THUNK(12) AUTO_THUNK(13) AUTO_THUNK(14) AUTO_THUNK(15)

static void* g_AutoThunks[MAX_AUTO_THEIA] = {
    (void*)hk_AutoTheia0, (void*)hk_AutoTheia1, (void*)hk_AutoTheia2, (void*)hk_AutoTheia3,
    (void*)hk_AutoTheia4, (void*)hk_AutoTheia5, (void*)hk_AutoTheia6, (void*)hk_AutoTheia7,
    (void*)hk_AutoTheia8, (void*)hk_AutoTheia9, (void*)hk_AutoTheia10, (void*)hk_AutoTheia11,
    (void*)hk_AutoTheia12, (void*)hk_AutoTheia13, (void*)hk_AutoTheia14, (void*)hk_AutoTheia15,
};

// Hardcoded RVAs of the 10 Theia decryptor functions identified in
// captures/theia_mass_unlock/SESSION_FINDINGS.md. Hooking these by RVA
// is much safer than auto-walking-back-to-prologue (which crashed last run).
// 0xE6780 is excluded — already hooked separately and never fires anyway.
struct TheiaHookSite { DWORD func_rva; const char* note; };
static const TheiaHookSite kTheiaSites[] = {
    { 0x4211C0, "CIPHER COMPARATOR (wipe-after-use, top suspect for exe-list)" },
    { 0xEA880,  "densest 8-site decryptor (likely main string decrypt)" },
    { 0x835B0,  "7-site multi-pass decryptor" },
    { 0xB4910,  "4-site decryptor" },
    { 0xFE300,  "4-site decryptor" },
    { 0xD46F0,  "3-site decryptor" },
    { 0xC5A2D,  "2-site decryptor" },
    { 0xF6910,  "2-site decryptor" },
    { 0x2B460,  "1-site decryptor" },
    { 0xA0590,  "1-site decryptor" },
};
static const int kTheiaSiteCount = sizeof(kTheiaSites) / sizeof(kTheiaSites[0]);

static void InstallAllTheiaHooks(void) {
    HMODULE hMod = GetModuleHandleW(NULL);
    if (!hMod) {
        NexusSpyLog("[auto-theia] GetModuleHandleW(NULL) failed");
        return;
    }
    BYTE* base = (BYTE*)hMod;

    // Sanity-check launcher binary identity by checking each candidate
    // for a plausible function-prologue byte (avoid hooking junk if the
    // build's RVAs have shifted).
    for (int i = 0; i < kTheiaSiteCount && g_AutoCount < MAX_AUTO_THEIA; i++) {
        DWORD this_rva = kTheiaSites[i].func_rva;
        const char* this_note = kTheiaSites[i].note;
        void* target = base + this_rva;
        BYTE first_byte = 0;
        __try { first_byte = *(BYTE*)target; }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            NexusSpyLog("[auto-theia#%d] SKIP RVA 0x%X read-fault (%s)",
                        g_AutoCount, this_rva, this_note);
            continue;
        }
        // Plausible function-start bytes: 0x48 (mov), 0x40 (push), 0x41 (REX push), 0x53/0x55/0x56/0x57 (push),
        // 0xE9 (jmp — for thunks), 0x4C (mov r12+).
        bool plausible = (first_byte == 0x48 || first_byte == 0x40 || first_byte == 0x41
                       || first_byte == 0x4C || first_byte == 0x53 || first_byte == 0x55
                       || first_byte == 0x56 || first_byte == 0x57 || first_byte == 0xE9
                       || first_byte == 0xFF);
        if (!plausible) {
            NexusSpyLog("[auto-theia#%d] SKIP RVA 0x%X first_byte=0x%02X not a prologue (%s)",
                        g_AutoCount, this_rva, first_byte, this_note);
            continue;
        }

        int slot = g_AutoCount;
        g_AutoTarget[slot] = target;
        MH_STATUS s_create = MH_CreateHook(target, g_AutoThunks[slot], (LPVOID*)&g_AutoOrig[slot]);
        if (s_create != MH_OK) {
            NexusSpyLog("[auto-theia#%d] CreateHook FAILED rva=0x%X target=%p status=%d",
                        slot, this_rva, target, (int)s_create);
            continue;
        }
        MH_STATUS s_enable = MH_EnableHook(target);
        if (s_enable != MH_OK) {
            NexusSpyLog("[auto-theia#%d] EnableHook FAILED rva=0x%X target=%p status=%d",
                        slot, this_rva, target, (int)s_enable);
            continue;
        }
        NexusSpyLog("[auto-theia#%d] installed rva=0x%X target=%p first=0x%02X (%s)",
                    slot, this_rva, target, first_byte, this_note);
        g_AutoCount++;
    }
    NexusSpyLog("[auto-theia] %d/%d hooks active", g_AutoCount, kTheiaSiteCount);
}

extern "C" void NexusSpyEnumHooksInstall(void) {
    HK("kernel32.dll",   QueryFullProcessImageNameW);
    HK("kernelbase.dll", K32GetModuleFileNameExW);
    HK("user32.dll",     GetWindowTextW);
    HK("user32.dll",     GetClassNameW);
    HK("user32.dll",     RealGetWindowClassW);
    HK("user32.dll",     EnumWindows);
    HK("user32.dll",     EnumThreadWindows);
    HK("ntdll.dll",      NtQuerySystemInformation);
    HK("kernel32.dll",   CreateToolhelp32Snapshot);
    HK("kernel32.dll",   Process32FirstW);
    HK("kernel32.dll",   Process32NextW);
    HK("advapi32.dll",   RegOpenKeyExW);
    HK("advapi32.dll",   RegQueryValueExW);
    HK("advapi32.dll",   RegGetValueW);
    HK("ntdll.dll",      NtOpenKey);
    HK("ntdll.dll",      NtOpenKeyEx);
    HK("ntdll.dll",      NtQueryValueKey);
    HK("sspicli.dll",    DecryptMessage);
    HK("sspicli.dll",    EncryptMessage);
    HK("kernel32.dll",   OpenProcess);
    HK("bcrypt.dll",     BCryptOpenAlgorithmProvider);
    HK("bcrypt.dll",     BCryptHashData);
    HK("ntdll.dll",      RtlCompareMemory);
    HK("ntdll.dll",      RtlEqualUnicodeString);
    HK("kernel32.dll",   lstrcmpW);
    HK("kernel32.dll",   lstrcmpiW);
    HK("ntdll.dll",      NtCreateFile);
    HK("ntdll.dll",      NtOpenFile);
    HK("ntdll.dll",      NtMapViewOfSection);
    HK("ntdll.dll",      RtlAllocateHeap);
    HK("ntdll.dll",      RtlFreeHeap);          // capture buffer contents at free
    HK("ntdll.dll",      NtAllocateVirtualMemory);
    // RegCloseKey hook on KERNELBASE caused Themida PACKER_* crash (2026-04-27).
    // KernelBase is the actual implementation; patching it has wider blast
    // radius than patching advapi32 forwarders. Skip it — we don't need close
    // events anyway.
    // DISABLED 2026-05-01: launcher .text hooks trip Themida CRC (PACKER_*.dmp).
    // Even shadow-EPT via SHV crashed (0x50 page-fault, see dump 050126-26625).
    // These remain commented as reference for future EPT-bulletproof rework.
    // InstallTheiaDecryptHook();      // base+0xE6780 — never fired across 45 runs anyway
    // InstallAllTheiaHooks();          // hardcoded RVAs — 0x4211C0 install -> Themida CRC trip
    InstallMatcherCaptureHooks();      // safe — only watches wide-string copies
    InstallCipherHook();               // safe — discovery-only (no patch)
    // InstallVtableCheckHook();  // DISABLED: Themida CRC-checks the IAT slot
                                   // and crashes (PACKER_* dump in eaanticheat\Crashdumps).
                                   // Need a different hook mechanism (mid-instruction
                                   // patch, hardware breakpoint, or post-init delayed
                                   // install) before re-enabling.
    NexusSpyLog("=== NexusSpyEnumHooksInstall complete ===");
}
