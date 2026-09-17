// NexusSpy.dll -- minimal MinHook-based spy DLL for tracing the EAAC
// launcher's Tier-1 compare-loop.

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "MinHook.h"

#pragma intrinsic(_ReturnAddress)

extern "C" {
    typedef struct _MD5_CTX { ULONG i[2]; ULONG buf[4]; UCHAR in[64]; UCHAR digest[16]; } MD5_CTX;
}

static HANDLE g_hLog = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logCs;
static volatile LONG g_logInited = 0;
static UCHAR  g_lastMd5Input[256];
static ULONG  g_lastMd5InputLen = 0;

static void Log(const char* fmt, ...) {
    if (g_hLog == INVALID_HANDLE_VALUE) return;
    char buf[2048];
    SYSTEMTIME st; GetLocalTime(&st);
    int n = sprintf_s(buf, sizeof(buf), "%02d:%02d:%02d.%03d ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    int n2 = vsprintf_s(buf + n, sizeof(buf) - n - 2, fmt, ap);
    va_end(ap);
    if (n2 < 0) return;
    int total = n + n2;
    buf[total++] = '\n'; buf[total] = 0;
    EnterCriticalSection(&g_logCs);
    DWORD w; WriteFile(g_hLog, buf, total, &w, NULL);
    FlushFileBuffers(g_hLog);
    LeaveCriticalSection(&g_logCs);
}

// Exported wrapper so other TUs (NexusWatchString.cpp) can log to the same file.
extern "C" void NexusSpyLog(const char* fmt, ...) {
    if (g_hLog == INVALID_HANDLE_VALUE) return;
    char buf[2048];
    SYSTEMTIME st; GetLocalTime(&st);
    int n = sprintf_s(buf, sizeof(buf), "%02d:%02d:%02d.%03d ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    int n2 = vsprintf_s(buf + n, sizeof(buf) - n - 2, fmt, ap);
    va_end(ap);
    if (n2 < 0) return;
    int total = n + n2;
    buf[total++] = '\n'; buf[total] = 0;
    EnterCriticalSection(&g_logCs);
    DWORD w; WriteFile(g_hLog, buf, total, &w, NULL);
    FlushFileBuffers(g_hLog);
    LeaveCriticalSection(&g_logCs);
}

// extern "C" void NexusWatchStringStart(void);  // moved to NexusWatchExternal.exe
extern "C" void NexusSpyEnumHooksInstall(void);

static void U2A(PCUNICODE_STRING us, char* out, size_t outsz) {
    if (!us || !us->Buffer || !us->Length) { out[0] = 0; return; }
    USHORT n = us->Length / sizeof(WCHAR);
    if (n > (USHORT)(outsz - 4)) n = (USHORT)(outsz - 4);
    USHORT j = 0;
    for (USHORT i = 0; i < n; i++) {
        WCHAR c = us->Buffer[i];
        out[j++] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    out[j] = 0;
}

static void HexDump(const void* p, size_t n, char* out, size_t outsz) {
    const unsigned char* b = (const unsigned char*)p;
    if (!p) { out[0] = 0; return; }
    size_t lim = n < (outsz - 1) / 2 ? n : (outsz - 1) / 2;
    if (lim > 64) lim = 64;
    for (size_t i = 0; i < lim; i++) sprintf_s(out + i*2, outsz - i*2, "%02x", b[i]);
}

// Filter: only log compares involving strings that LOOK like process names
static bool LooksLikeProcessName(const char* s) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n < 3 || n > 64) return false;
    if (strstr(s, ".exe") || strstr(s, ".dll") || strstr(s, ".sys")) return true;
    if (strstr(s, "cheat") || strstr(s, "Cheat") || strstr(s, "CHEAT")) return true;
    if (strstr(s, "engine") || strstr(s, "Engine")) return true;
    if (strstr(s, "x64dbg") || strstr(s, "windbg") || strstr(s, "ollydbg")) return true;
    return false;
}

// === Hook trampolines ===
typedef BOOLEAN (NTAPI *PFN_RtlEqualUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
typedef LONG    (NTAPI *PFN_RtlCompareUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
typedef BOOLEAN (NTAPI *PFN_RtlPrefixUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
typedef SIZE_T  (NTAPI *PFN_RtlCompareMemory)(VOID const*, VOID const*, SIZE_T);
typedef int     (__cdecl *PFN_wcscmp)(const wchar_t*, const wchar_t*);
typedef int     (__cdecl *PFN_wcsicmp)(const wchar_t*, const wchar_t*);
typedef int     (__cdecl *PFN_strcmp)(const char*, const char*);
typedef int     (__cdecl *PFN_stricmp)(const char*, const char*);
typedef int     (__cdecl *PFN_memcmp)(const void*, const void*, size_t);
typedef VOID    (NTAPI *PFN_MD5Init)(MD5_CTX*);
typedef VOID    (NTAPI *PFN_MD5Update)(MD5_CTX*, UCHAR*, ULONG);
typedef VOID    (NTAPI *PFN_MD5Final)(MD5_CTX*);

static PFN_RtlEqualUnicodeString    o_RtlEqualUnicodeString;
static PFN_RtlCompareUnicodeString  o_RtlCompareUnicodeString;
static PFN_RtlPrefixUnicodeString   o_RtlPrefixUnicodeString;
static PFN_RtlCompareMemory         o_RtlCompareMemory;
static PFN_wcscmp                   o_wcscmp;
static PFN_wcsicmp                  o_wcsicmp;
static PFN_strcmp                   o_strcmp;
static PFN_stricmp                  o_stricmp;
static PFN_memcmp                   o_memcmp;
static PFN_MD5Init                  o_MD5Init;
static PFN_MD5Update                o_MD5Update;
static PFN_MD5Final                 o_MD5Final;

static BOOLEAN NTAPI hk_RtlEqualUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN ci) {
    char a[256], b[256];
    U2A(s1, a, sizeof(a));
    U2A(s2, b, sizeof(b));
    if (LooksLikeProcessName(a) || LooksLikeProcessName(b)) {
        void* ret = _ReturnAddress();
        Log("RtlEqualUnicodeString a=\"%s\" b=\"%s\" ci=%d caller=%p", a, b, ci, ret);
    }
    return o_RtlEqualUnicodeString(s1, s2, ci);
}

static LONG NTAPI hk_RtlCompareUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN ci) {
    char a[256], b[256];
    U2A(s1, a, sizeof(a));
    U2A(s2, b, sizeof(b));
    if (LooksLikeProcessName(a) || LooksLikeProcessName(b)) {
        void* ret = _ReturnAddress();
        Log("RtlCompareUnicodeString a=\"%s\" b=\"%s\" ci=%d caller=%p", a, b, ci, ret);
    }
    return o_RtlCompareUnicodeString(s1, s2, ci);
}

static BOOLEAN NTAPI hk_RtlPrefixUnicodeString(PCUNICODE_STRING px, PCUNICODE_STRING s, BOOLEAN ci) {
    char a[256], b[256];
    U2A(px, a, sizeof(a));
    U2A(s, b, sizeof(b));
    if (LooksLikeProcessName(a) || LooksLikeProcessName(b)) {
        void* ret = _ReturnAddress();
        Log("RtlPrefixUnicodeString prefix=\"%s\" str=\"%s\" ci=%d caller=%p", a, b, ci, ret);
    }
    return o_RtlPrefixUnicodeString(px, s, ci);
}

static SIZE_T NTAPI hk_RtlCompareMemory(VOID const* a, VOID const* b, SIZE_T n) {
    if (n >= 4 && n <= 64) {
        char ax[150], bx[150];
        HexDump(a, n, ax, sizeof(ax));
        HexDump(b, n, bx, sizeof(bx));
        void* ret = _ReturnAddress();
        Log("RtlCompareMemory(%zu) a=%s b=%s caller=%p", n, ax, bx, ret);
    }
    return o_RtlCompareMemory(a, b, n);
}

static int __cdecl hk_wcscmp(const wchar_t* a, const wchar_t* b) {
    char ax[256], bx[256];
    if (a) {
        size_t i = 0;
        while (i < 255 && a[i]) { ax[i] = (a[i] >= 0x20 && a[i] < 0x7F) ? (char)a[i] : '?'; i++; }
        ax[i] = 0;
    } else { ax[0] = 0; }
    if (b) {
        size_t i = 0;
        while (i < 255 && b[i]) { bx[i] = (b[i] >= 0x20 && b[i] < 0x7F) ? (char)b[i] : '?'; i++; }
        bx[i] = 0;
    } else { bx[0] = 0; }
    if (LooksLikeProcessName(ax) || LooksLikeProcessName(bx)) {
        void* ret = _ReturnAddress();
        Log("wcscmp a=\"%s\" b=\"%s\" caller=%p", ax, bx, ret);
    }
    return o_wcscmp(a, b);
}

static int __cdecl hk_wcsicmp(const wchar_t* a, const wchar_t* b) {
    char ax[256], bx[256];
    if (a) {
        size_t i = 0;
        while (i < 255 && a[i]) { ax[i] = (a[i] >= 0x20 && a[i] < 0x7F) ? (char)a[i] : '?'; i++; }
        ax[i] = 0;
    } else { ax[0] = 0; }
    if (b) {
        size_t i = 0;
        while (i < 255 && b[i]) { bx[i] = (b[i] >= 0x20 && b[i] < 0x7F) ? (char)b[i] : '?'; i++; }
        bx[i] = 0;
    } else { bx[0] = 0; }
    if (LooksLikeProcessName(ax) || LooksLikeProcessName(bx)) {
        void* ret = _ReturnAddress();
        Log("wcsicmp a=\"%s\" b=\"%s\" caller=%p", ax, bx, ret);
    }
    return o_wcsicmp(a, b);
}

static int __cdecl hk_strcmp(const char* a, const char* b) {
    if (a && b && (LooksLikeProcessName(a) || LooksLikeProcessName(b))) {
        void* ret = _ReturnAddress();
        Log("strcmp a=\"%.200s\" b=\"%.200s\" caller=%p", a, b, ret);
    }
    return o_strcmp(a, b);
}

static int __cdecl hk_stricmp(const char* a, const char* b) {
    if (a && b && (LooksLikeProcessName(a) || LooksLikeProcessName(b))) {
        void* ret = _ReturnAddress();
        Log("stricmp a=\"%.200s\" b=\"%.200s\" caller=%p", a, b, ret);
    }
    return o_stricmp(a, b);
}

static int __cdecl hk_memcmp(const void* a, const void* b, size_t n) {
    if (n >= 4 && n <= 32) {
        char ax[100], bx[100];
        HexDump(a, n, ax, sizeof(ax));
        HexDump(b, n, bx, sizeof(bx));
        void* ret = _ReturnAddress();
        Log("memcmp(%zu) a=%s b=%s caller=%p", n, ax, bx, ret);
    }
    return o_memcmp(a, b, n);
}

static VOID NTAPI hk_MD5Init(MD5_CTX* ctx) {
    g_lastMd5InputLen = 0;
    o_MD5Init(ctx);
}

static VOID NTAPI hk_MD5Update(MD5_CTX* ctx, UCHAR* buf, ULONG len) {
    ULONG remaining = sizeof(g_lastMd5Input) - g_lastMd5InputLen;
    if (remaining > 0 && buf) {
        ULONG copy_n = len < remaining ? len : remaining;
        memcpy(g_lastMd5Input + g_lastMd5InputLen, buf, copy_n);
        g_lastMd5InputLen += copy_n;
    }
    o_MD5Update(ctx, buf, len);
}

static VOID NTAPI hk_MD5Final(MD5_CTX* ctx) {
    o_MD5Final(ctx);
    char inbuf[600];
    HexDump(g_lastMd5Input, g_lastMd5InputLen, inbuf, sizeof(inbuf));
    char asbuf[300]; size_t j = 0;
    for (ULONG i = 0; i < g_lastMd5InputLen && j < sizeof(asbuf) - 1; i++) {
        UCHAR c = g_lastMd5Input[i];
        asbuf[j++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
    }
    asbuf[j] = 0;
    char digest[40];
    HexDump(ctx->digest, 16, digest, sizeof(digest));
    void* ret = _ReturnAddress();
    Log("MD5 input(%lu)=\"%s\" hex=%s -> digest=%s caller=%p",
        g_lastMd5InputLen, asbuf, inbuf, digest, ret);
}

#define HOOK(mod, name) \
    do { \
        void* p = (void*)GetProcAddress(GetModuleHandleA(mod), #name); \
        if (p) { \
            if (MH_CreateHook(p, (LPVOID)hk_##name, (LPVOID*)&o_##name) == MH_OK) { \
                MH_EnableHook(p); \
                Log("[hook]  %s!%s @ %p installed", mod, #name, p); \
            } else { \
                Log("[ERROR] %s!%s hook failed", mod, #name); \
            } \
        } else { \
            Log("[skip]  %s!%s not found", mod, #name); \
        } \
    } while (0)

static DWORD WINAPI InitThread(LPVOID) {
    DWORD pid = GetCurrentProcessId();
    char path[MAX_PATH];
    // Try ProgramData first (writable for everyone), then TEMP, then USERPROFILE.
    char temp[MAX_PATH] = {0};
    DWORD got = GetEnvironmentVariableA("ProgramData", temp, MAX_PATH);
    if (got == 0 || got >= MAX_PATH) {
        got = GetEnvironmentVariableA("TEMP", temp, MAX_PATH);
    }
    if (got == 0 || got >= MAX_PATH) {
        got = GetEnvironmentVariableA("USERPROFILE", temp, MAX_PATH);
    }
    if (got == 0 || got >= MAX_PATH) {
        // Last resort: try CWD
        strcpy_s(temp, MAX_PATH, ".");
    }
    sprintf_s(path, sizeof(path), "%s\\NexusSpy_%lu.log", temp, pid);
    g_hLog = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hLog == INVALID_HANDLE_VALUE) {
        // Fall back to TEMP explicitly
        char temp2[MAX_PATH] = {0};
        GetEnvironmentVariableA("TEMP", temp2, MAX_PATH);
        sprintf_s(path, sizeof(path), "%s\\NexusSpy_%lu.log", temp2, pid);
        g_hLog = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (g_hLog == INVALID_HANDLE_VALUE) {
        // Last resort: signal via OutputDebugString that we couldn't open a log
        OutputDebugStringA("NexusSpy: CreateFileA failed for all candidate paths!");
        return 1;
    }
    // Side-channel: write the path itself to a debugger so we know where to look.
    char dbgmsg[MAX_PATH + 64];
    sprintf_s(dbgmsg, sizeof(dbgmsg), "NexusSpy log: %s", path);
    OutputDebugStringA(dbgmsg);
    InitializeCriticalSection(&g_logCs);

    Log("=== NexusSpy injected into PID=%lu ===", pid);

    if (MH_Initialize() != MH_OK) {
        Log("[ERROR] MH_Initialize failed");
        return 1;
    }

    HOOK("ntdll.dll",     RtlEqualUnicodeString);
    HOOK("ntdll.dll",     RtlCompareUnicodeString);
    HOOK("ntdll.dll",     RtlPrefixUnicodeString);
    HOOK("ntdll.dll",     RtlCompareMemory);
    HOOK("ntdll.dll",     MD5Init);
    HOOK("ntdll.dll",     MD5Update);
    HOOK("ntdll.dll",     MD5Final);
    HOOK("ucrtbase.dll",  wcscmp);
    HOOK("ucrtbase.dll",  wcsicmp);
    HOOK("ucrtbase.dll",  strcmp);
    HOOK("ucrtbase.dll",  stricmp);
    HOOK("ucrtbase.dll",  memcmp);

    Log("=== Hooks installed. Tracing live. ===");

    // Watcher disabled in v3 -- both PAGE_GUARD and pure VEH variants tripped
    // Themida packer31 self-integrity (PACKER_*.dmp aborts). The bait scanning
    // is now done EXTERNALLY by NexusWatchExternal.exe so nothing extra runs
    // inside the launcher's address space.
    // NexusWatchStringStart();

    // v4: install process/window enumeration hooks. Each hook logs caller RIP
    // so we can cross-reference back into IDA and find the discriminator
    // function. Adds: QueryFullProcessImageNameW, K32GetModuleFileNameExW,
    // GetWindowTextW, GetClassNameW, RealGetWindowClassW, EnumWindows,
    // EnumThreadWindows, NtQuerySystemInformation, CreateToolhelp32Snapshot.
    NexusSpyEnumHooksInstall();

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
