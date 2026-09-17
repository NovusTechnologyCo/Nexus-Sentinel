// NexusWatchString.cpp -- bait-string memory access watcher.
//
// Goal: capture the EXACT instruction (RIP) inside the EAAC launcher that
// reads the bytes of "cheatengine-x86_64.exe" out of any committed buffer,
// regardless of whether the comparison is inlined / hashed / direct-syscalled.
//
// Mechanism (no hardware breakpoints, no DR0-DR3 -- avoids EAAC anti-debug):
//   1. Watcher thread VirtualQuery-walks every committed RW page > 4 KB.
//   2. memcmp-scans each page for both UTF-16 LE and ASCII forms of the
//      bait strings.
//   3. On first hit, marks the containing page with PAGE_GUARD via
//      VirtualProtect. Any subsequent read of any byte on that page raises
//      STATUS_GUARD_PAGE_VIOLATION (0x80000001).
//   4. Our VEH catches the exception, logs ContextRecord->Rip + the exact
//      faulting address (ExceptionRecord->ExceptionInformation[1]), then
//      single-steps past the faulting instruction (TF=1) to retrieve normal
//      execution. After the single step, re-arms PAGE_GUARD and continues.
//
// Negative control: a second bait string "cheatengine-x86_66.exe" is also
// armed. If positive bait fires but negative does not, we know the comparison
// is exact-name discriminating (not blanket "anything containing 'cheat'").
//
// Bait strings are *populated by us* in a private allocation, so we can
// pre-arm them. We also scan for naturally-occurring instances in case the
// launcher allocates its own buffer that happens to contain the name.
//
// All output goes to NexusSpy_<PID>.log via the shared Log() function in
// NexusSpy.cpp.

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <stdio.h>
#include <string.h>

// Provided by NexusSpy.cpp:
extern "C" void NexusSpyLog(const char* fmt, ...);

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001L)
#endif
#ifndef STATUS_SINGLE_STEP
#define STATUS_SINGLE_STEP ((DWORD)0x80000004L)
#endif

// =====================================================================
// Bait config
// =====================================================================
struct Bait {
    const char*  name;     // human-readable label
    const wchar_t* w;      // UTF-16 form
    const char*  a;        // ASCII form
    bool         is_positive_control;
};

static const Bait BAITS[] = {
    { "POS_cheatengine_x64",   L"cheatengine-x86_64.exe", "cheatengine-x86_64.exe", true  },
    { "NEG_cheatengine_x66",   L"cheatengine-x86_66.exe", "cheatengine-x86_66.exe", false },
    { "POS_CheatEngine_proper",L"Cheat Engine.exe",        "Cheat Engine.exe",       true  },
};
static const size_t BAIT_COUNT = sizeof(BAITS) / sizeof(BAITS[0]);

// =====================================================================
// Tracked guarded pages (max ~64; we won't ever need that many)
// =====================================================================
struct GuardedPage {
    void*   page;        // page-aligned base
    SIZE_T  size;        // always 0x1000
    DWORD   origProt;    // protection to restore after each fault
    int     baitIdx;     // which bait sits on this page
    LONG64  hitCount;
};
#define MAX_GUARDED 64
static GuardedPage g_guarded[MAX_GUARDED];
static volatile LONG g_guardedCount = 0;
static CRITICAL_SECTION g_guardCs;

// =====================================================================
// Helpers
// =====================================================================
static void* PageBase(void* p) {
    return (void*)((ULONG_PTR)p & ~(ULONG_PTR)0xFFF);
}

static bool AlreadyGuarded(void* page) {
    for (LONG i = 0; i < g_guardedCount; i++) {
        if (g_guarded[i].page == page) return true;
    }
    return false;
}

static bool ArmGuardPage(void* hitAddr, int baitIdx) {
    void* page = PageBase(hitAddr);
    EnterCriticalSection(&g_guardCs);
    bool dup = AlreadyGuarded(page);
    if (!dup && g_guardedCount < MAX_GUARDED) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(page, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            LeaveCriticalSection(&g_guardCs);
            NexusSpyLog("[watch] VirtualQuery failed @ %p", page);
            return false;
        }
        DWORD oldProt = 0;
        DWORD newProt = mbi.Protect | PAGE_GUARD;
        if (!VirtualProtect(page, 0x1000, newProt, &oldProt)) {
            LeaveCriticalSection(&g_guardCs);
            NexusSpyLog("[watch] VirtualProtect-arm failed @ %p err=%lu",
                        page, GetLastError());
            return false;
        }
        GuardedPage* g = &g_guarded[g_guardedCount++];
        g->page     = page;
        g->size     = 0x1000;
        g->origProt = mbi.Protect;
        g->baitIdx  = baitIdx;
        g->hitCount = 0;
        LeaveCriticalSection(&g_guardCs);
        NexusSpyLog("[watch] ARMED page=%p bait=%s hitAt=%p origProt=0x%lX",
                    page, BAITS[baitIdx].name, hitAddr, mbi.Protect);
        return true;
    }
    LeaveCriticalSection(&g_guardCs);
    return false;
}

static GuardedPage* FindGuardedByAddr(void* addr) {
    void* page = PageBase(addr);
    for (LONG i = 0; i < g_guardedCount; i++) {
        if (g_guarded[i].page == page) return &g_guarded[i];
    }
    return NULL;
}

// =====================================================================
// Vectored exception handler -- the payload
// =====================================================================
// We need to allow execution to continue past the faulting instruction with
// the page READABLE for one instruction, then re-arm the guard. Standard
// trick: clear the guard (already auto-cleared on first fault), set TF=1,
// return EXCEPTION_CONTINUE_EXECUTION. Next single-step exception fires; we
// re-arm and clear TF.
static volatile LONG g_pendingReArmIdx = -1;

static LONG NTAPI WatchVeh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == STATUS_GUARD_PAGE_VIOLATION) {
        // ExceptionInformation[0] = 0 (read) / 1 (write) / 8 (DEP)
        // ExceptionInformation[1] = faulting linear address
        ULONG_PTR access = (ULONG_PTR)ep->ExceptionRecord->ExceptionInformation[0];
        void*     addr   = (void*)ep->ExceptionRecord->ExceptionInformation[1];
        GuardedPage* g = FindGuardedByAddr(addr);
        if (g) {
            void* rip = (void*)ep->ContextRecord->Rip;
            DWORD tid = GetCurrentThreadId();
            LONG64 hits = InterlockedIncrement64(&g->hitCount);
            // Read 16 bytes at the fault addr to confirm contents
            char hex[40] = {0};
            __try {
                const unsigned char* b = (const unsigned char*)addr;
                for (int i = 0; i < 16; i++) {
                    sprintf_s(hex + i*2, sizeof(hex) - i*2, "%02x", b[i]);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(hex, sizeof(hex), "??"); }
            NexusSpyLog("[GUARD] tid=%lu access=%s rip=%p faultAddr=%p "
                        "page=%p bait=%s bytes=%s hit#%lld",
                        tid, access ? "WRITE" : "READ", rip, addr,
                        g->page, BAITS[g->baitIdx].name, hex, (long long)hits);
            // Set TF so next instruction triggers SINGLE_STEP and we re-arm.
            ep->ContextRecord->EFlags |= 0x100;
            // Page is now non-guarded for one step; remember which to re-arm.
            // Use slot index, not pointer, to avoid TOCTOU in case array shifts.
            LONG idx = (LONG)(g - g_guarded);
            InterlockedExchange(&g_pendingReArmIdx, idx);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == STATUS_SINGLE_STEP) {
        LONG idx = InterlockedExchange(&g_pendingReArmIdx, -1);
        if (idx >= 0 && idx < g_guardedCount) {
            GuardedPage* g = &g_guarded[idx];
            DWORD tmp;
            VirtualProtect(g->page, g->size, g->origProt | PAGE_GUARD, &tmp);
            // EFlags TF auto-clears on single-step delivery.
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // not ours -- pass through
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// =====================================================================
// Page-level pattern scan
// =====================================================================
static bool PageContains(const void* page, SIZE_T pageSize,
                         const void* needle, SIZE_T nlen,
                         const void** outHit) {
    if (pageSize < nlen) return false;
    const unsigned char* p = (const unsigned char*)page;
    SIZE_T limit = pageSize - nlen + 1;
    for (SIZE_T i = 0; i < limit; i++) {
        if (p[i] == ((const unsigned char*)needle)[0]) {
            if (memcmp(p + i, needle, nlen) == 0) {
                *outHit = p + i;
                return true;
            }
        }
    }
    return false;
}

static int ScanAndArmRange(void* base, SIZE_T size) {
    int armed = 0;
    // Iterate page-by-page so we don't carry stale page pointers across boundaries.
    unsigned char* p = (unsigned char*)base;
    SIZE_T off = 0;
    while (off < size) {
        SIZE_T pgRem = 0x1000 - ((ULONG_PTR)(p + off) & 0xFFF);
        SIZE_T span  = pgRem;
        if (off + span > size) span = size - off;
        for (size_t b = 0; b < BAIT_COUNT; b++) {
            const void* hit = NULL;
            // ASCII
            SIZE_T alen = strlen(BAITS[b].a);
            if (span >= alen && PageContains(p + off, span, BAITS[b].a, alen, &hit)) {
                if (ArmGuardPage((void*)hit, (int)b)) armed++;
            }
            // UTF-16 LE
            SIZE_T wlen = wcslen(BAITS[b].w) * sizeof(wchar_t);
            if (span >= wlen && PageContains(p + off, span, BAITS[b].w, wlen, &hit)) {
                if (ArmGuardPage((void*)hit, (int)b)) armed++;
            }
        }
        off += span;
    }
    return armed;
}

// =====================================================================
// Plant our own bait copies so we ALWAYS have at least one armed page,
// regardless of whether the launcher allocates the literal itself.
// =====================================================================
static void* g_baitBuffer = NULL;

static void PlantBaitInOwnAllocation(void) {
    // Allocate a fresh RW page in the launcher's address space, fill with
    // every bait (ASCII + UTF-16) at known offsets, then arm.
    g_baitBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
    if (!g_baitBuffer) {
        NexusSpyLog("[watch] VirtualAlloc bait failed err=%lu", GetLastError());
        return;
    }
    char* p = (char*)g_baitBuffer;
    SIZE_T off = 0;
    for (size_t i = 0; i < BAIT_COUNT; i++) {
        SIZE_T alen = strlen(BAITS[i].a) + 1;
        memcpy(p + off, BAITS[i].a, alen);
        NexusSpyLog("[watch] bait planted A %p '%s' (%s)",
                    p + off, BAITS[i].a, BAITS[i].name);
        off += alen + 16;
        SIZE_T wlen = (wcslen(BAITS[i].w) + 1) * sizeof(wchar_t);
        memcpy(p + off, BAITS[i].w, wlen);
        NexusSpyLog("[watch] bait planted W %p (UTF-16 %s)",
                    p + off, BAITS[i].name);
        off += wlen + 16;
    }
    // Arm the whole page (one guard covers everything).
    ArmGuardPage(g_baitBuffer, 0);
}

// =====================================================================
// Heap-only scan + LOG-ONLY mode (no PAGE_GUARD on launcher image pages,
// to avoid colliding with Themida packer31 self-integrity checks).
//
// Two-phase strategy:
//   Phase 1 (LOG mode): scan every 25 ms. When a bait string is found in
//     ANY committed region (heap, stack, VirtualAlloc, AND image), log
//     address + module name + 64-byte hex context + neighboring strings.
//     No memory protection change. Zero crash risk.
//   Phase 2 (GUARD mode, opt-in): only arm PAGE_GUARD on pages NOT backed
//     by an image (i.e. heap/stack/private allocations). EAAC's process
//     enum buffer always lives in heap, so this still catches it. Themida
//     code pages live in image regions and are never armed.
//
// Phase 1 alone gives us "yes/no the literal exists in launcher memory"
// and "where does it live", which already differentiates the three
// hypotheses (inlined cmp / hashed cmp / cross-process).
// =====================================================================

// Was-seen tracking so we don't re-log the same address every pass.
struct SeenHit { void* addr; int baitIdx; };
#define MAX_SEEN 256
static SeenHit g_seen[MAX_SEEN];
static volatile LONG g_seenCount = 0;

static bool AlreadySeen(void* addr) {
    for (LONG i = 0; i < g_seenCount; i++) {
        if (g_seen[i].addr == addr) return true;
    }
    return false;
}
static void RememberSeen(void* addr, int baitIdx) {
    if (g_seenCount < MAX_SEEN) {
        g_seen[g_seenCount].addr   = addr;
        g_seen[g_seenCount].baitIdx = baitIdx;
        InterlockedIncrement(&g_seenCount);
    }
}

static void DescribeRegion(void* addr, char* out, size_t outsz) {
    HMODULE mod = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)addr, &mod) && mod) {
        char modPath[MAX_PATH] = {0};
        GetModuleFileNameA(mod, modPath, MAX_PATH);
        const char* base = strrchr(modPath, '\\');
        sprintf_s(out, outsz, "image:%s", base ? base + 1 : modPath);
        return;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const char* type =
            (mbi.Type == MEM_IMAGE)   ? "IMAGE"   :
            (mbi.Type == MEM_MAPPED)  ? "MAPPED"  :
            (mbi.Type == MEM_PRIVATE) ? "PRIVATE" : "?";
        sprintf_s(out, outsz, "%s prot=0x%X size=0x%zX",
                  type, mbi.Protect, mbi.RegionSize);
    } else {
        strcpy_s(out, outsz, "<query failed>");
    }
}

static bool IsImageBacked(void* addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return true; // be safe
    return mbi.Type == MEM_IMAGE;
}

static void LogHit(void* addr, int baitIdx) {
    if (AlreadySeen(addr)) return;
    RememberSeen(addr, baitIdx);
    char where[256] = {0};
    DescribeRegion(addr, where, sizeof(where));
    char hex[160] = {0};
    __try {
        const unsigned char* b = (const unsigned char*)addr;
        for (int i = 0; i < 64; i++) {
            sprintf_s(hex + i*2, sizeof(hex) - i*2, "%02x", b[i]);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { strcpy_s(hex, sizeof(hex), "??"); }
    NexusSpyLog("[FOUND] addr=%p bait=%s region=[%s] bytes=%s",
                addr, BAITS[baitIdx].name, where, hex);
}

// Scan a region for ALL bait strings, logging each occurrence. Optionally
// arm PAGE_GUARD on heap-only pages.
static int ScanRegionLogOnly(void* base, SIZE_T size, bool armHeap) {
    int armed = 0;
    unsigned char* p = (unsigned char*)base;
    SIZE_T off = 0;
    while (off < size) {
        SIZE_T pgRem = 0x1000 - ((ULONG_PTR)(p + off) & 0xFFF);
        SIZE_T span  = pgRem;
        if (off + span > size) span = size - off;
        for (size_t b = 0; b < BAIT_COUNT; b++) {
            const void* hit = NULL;
            SIZE_T alen = strlen(BAITS[b].a);
            if (span >= alen && PageContains(p + off, span, BAITS[b].a, alen, &hit)) {
                LogHit((void*)hit, (int)b);
                if (armHeap && !IsImageBacked((void*)hit)) {
                    if (ArmGuardPage((void*)hit, (int)b)) armed++;
                }
            }
            SIZE_T wlen = wcslen(BAITS[b].w) * sizeof(wchar_t);
            if (span >= wlen && PageContains(p + off, span, BAITS[b].w, wlen, &hit)) {
                LogHit((void*)hit, (int)b);
                if (armHeap && !IsImageBacked((void*)hit)) {
                    if (ArmGuardPage((void*)hit, (int)b)) armed++;
                }
            }
        }
        off += span;
    }
    return armed;
}

// Read environment variable NEXUS_WATCH_GUARD; if set to "1", enable
// PAGE_GUARD arming on heap pages. Default OFF after the Themida crash.
static bool ShouldArmHeap(void) {
    char v[8] = {0};
    DWORD n = GetEnvironmentVariableA("NEXUS_WATCH_GUARD", v, sizeof(v));
    return (n > 0 && v[0] == '1');
}

static DWORD WINAPI WatchThread(LPVOID) {
    InitializeCriticalSection(&g_guardCs);
    AddVectoredExceptionHandler(1, WatchVeh);
    bool armHeap = ShouldArmHeap();
    NexusSpyLog("=== NexusWatchString live. PID=%lu, %zu baits, "
                "mode=%s, VEH installed ===",
                GetCurrentProcessId(), BAIT_COUNT,
                armHeap ? "LOG+GUARD-heap-only" : "LOG-ONLY (safe)");

    // Skip planting -- we want only naturally-occurring copies. Planted bait
    // would just trigger our own scanner.

    SYSTEM_INFO si; GetSystemInfo(&si);
    void* pmin = si.lpMinimumApplicationAddress;
    void* pmax = si.lpMaximumApplicationAddress;

    int passes = 0;
    while (passes < 1200) {  // ~60s
        passes++;
        unsigned char* addr = (unsigned char*)pmin;
        int armedThisPass = 0;
        int scannedRegions = 0;
        int hitsThisPass = 0;
        LONG seenBefore = g_seenCount;
        while (addr < (unsigned char*)pmax) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            unsigned char* next = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
            bool readable = (mbi.State == MEM_COMMIT) &&
                            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY |
                                            PAGE_EXECUTE_READ |
                                            PAGE_EXECUTE_READWRITE |
                                            PAGE_EXECUTE_WRITECOPY |
                                            PAGE_WRITECOPY));
            if (readable && mbi.RegionSize <= 64*1024*1024) {
                __try {
                    int a = ScanRegionLogOnly(mbi.BaseAddress, mbi.RegionSize, armHeap);
                    if (a > 0) armedThisPass += a;
                    scannedRegions++;
                } __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            if (next <= addr) break;
            addr = next;
        }
        hitsThisPass = (int)(g_seenCount - seenBefore);
        if (passes <= 4 || hitsThisPass > 0 || (passes % 40) == 0) {
            NexusSpyLog("[watch] pass %d: regions=%d new_hits=%d "
                        "total_seen=%ld armed_this_pass=%d total_armed=%ld",
                        passes, scannedRegions, hitsThisPass,
                        g_seenCount, armedThisPass, g_guardedCount);
        }
        Sleep(25);
    }
    NexusSpyLog("[watch] scanner exiting after %d passes. seen=%ld armed=%ld",
                passes, g_seenCount, g_guardedCount);
    return 0;
}

// =====================================================================
// Public entry point invoked from NexusSpy.cpp's InitThread.
// =====================================================================
extern "C" void NexusWatchStringStart(void) {
    HANDLE t = CreateThread(NULL, 0, WatchThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
