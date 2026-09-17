/**
 * @file hook_engine_veh.cpp
 * @brief VEH + INT3 hook backend -- exception handling, address map, arm/disarm
 *
 * Instead of MinHook's 5-byte JMP patches (detected by EAC integrity scans),
 * we write a single 0xCC (INT3) byte at each function entry. A Vectored
 * Exception Handler catches the breakpoint, captures arguments, and redirects
 * execution to MinHook's trampoline (which preserves the original prologue).
 *
 * This file contains:
 * - Address hash table for O(1) VEH lookup (AddrMap_Insert/Lookup)
 * - VEH registration strategies (ntdll direct, kernel32, UEF, deep-unhook,
 *   manual VEH list insertion)
 * - VEH handler (VehHookHandler) with entry-only capture
 * - Unhandled exception filter fallback
 * - INT3 arm/disarm (Veh_ArmAll/Veh_DisarmAll)
 *
 * NOTE: Per-thread return capture stack and return stub are DISABLED
 * (wrapped in #if 0). Entry-only capture is used instead.
 *
 * Extracted from hook_engine.cpp for maintainability.
 */

#include "hook_engine_internal.h"

// ============================================================
// Address -> Slot Hash Table
// ============================================================
// Fast O(1) lookup from function address to hook slot index.
// Used by the VEH handler on every EXCEPTION_BREAKPOINT.

static AddrMapEntry* g_addrMap = NULL;

void AddrMap_Insert(void* addr, int slot)
{
    if (!g_addrMap) return;
    uintptr_t hash = (uintptr_t)addr;
    hash ^= hash >> 4;
    hash ^= hash >> 16;
    int idx = (int)(hash & (ADDR_MAP_SIZE - 1));
    for (int i = 0; i < 64; i++)
    {
        int pos = (idx + i) & (ADDR_MAP_SIZE - 1);
        if (g_addrMap[pos].addr == NULL)
        {
            g_addrMap[pos].addr = addr;
            g_addrMap[pos].slot = slot;
            return;
        }
    }
    DbgLog("[veh] WARN: AddrMap_Insert failed for %p (table full)", addr);
}

static int AddrMap_Lookup(void* addr)
{
    if (!g_addrMap) return -1;
    uintptr_t hash = (uintptr_t)addr;
    hash ^= hash >> 4;
    hash ^= hash >> 16;
    int idx = (int)(hash & (ADDR_MAP_SIZE - 1));
    for (int i = 0; i < 64; i++)
    {
        int pos = (idx + i) & (ADDR_MAP_SIZE - 1);
        if (g_addrMap[pos].addr == addr) return g_addrMap[pos].slot;
        if (g_addrMap[pos].addr == NULL) return -1;
    }
    return -1;
}

// ---- Original Bytes (saved before int3 write) ----
static uint8_t* g_savedBytes = NULL;  // g_savedBytes[slotIndex]

// ---- VEH Handle ----
PVOID g_vehHandle = NULL;

// Track which exception handler method was used for proper cleanup
VehMethodType g_vehMethod = VEH_METHOD_NONE;
static LPTOP_LEVEL_EXCEPTION_FILTER g_prevUnhandledFilter = NULL;

// ntdll direct VEH registration -- bypasses kernel32 hooks (EAC blocks
// kernel32!AddVectoredExceptionHandler, returning NULL with error 127).
typedef PVOID (NTAPI *PFN_RtlAddVectoredExceptionHandler)(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler);
typedef ULONG (NTAPI *PFN_RtlRemoveVectoredExceptionHandler)(PVOID VectoredHandlerHandle);
PFN_RtlAddVectoredExceptionHandler g_pfnRtlAddVEH = NULL;
PFN_RtlRemoveVectoredExceptionHandler g_pfnRtlRemoveVEH = NULL;

// VEH registration bypass strategies (deep-unhook + manual list insertion)
#include "hook_engine_veh_reg.cpp"


// ============================================================
// Per-Thread Return Capture Stack (DISABLED -- entry-only capture active)
// ============================================================

#if 0
// ============================================================
// DISABLED: Return Value Capture via Return Address Hijacking
// ============================================================
// This subsystem was disabled because return address hijacking
// interacts badly with SEH unwinding, CFG, and shadow stacks.
// The VEH handler now sends events at entry-only (no return capture).
// Kept for reference -- may be useful for non-EAC targets.
// ============================================================

#define MAX_RETURN_DEPTH 256

typedef struct {
    void*    realReturnAddr;
    int      slotIndex;
    uint64_t timestampQpc;
    uint64_t argValues[MAX_PARAMS];
    int      paramCount;
} RetCapEntry;

typedef struct {
    int depth;
    RetCapEntry entries[MAX_RETURN_DEPTH];
} RetCapStack;

// ---- Return Stub (runtime-generated machine code) ----
static uint8_t* g_returnStub = NULL;

// HandleReturnCapture: called by the return stub.
// Pops the per-thread return capture stack, serializes the event, and
// returns the real return address.
#ifdef _M_X64
static void* HandleReturnCaptureX64(uint64_t returnValue)
#elif defined(_M_IX86)
static void* __cdecl HandleReturnCaptureX86(uint32_t returnValue)
#endif
{
    // Set reentrancy guard -- we'll call SerializeAndSendEvent which may
    // trigger hooked functions (HeapAlloc, etc.) that we must not capture.
    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
        DirectTlsSet(g_tlsReentrancy, (void*)1);

    void* realRetAddr = NULL;

    RetCapStack* rcs = (g_tlsReturnCapture != TLS_OUT_OF_INDEXES)
        ? (RetCapStack*)DirectTlsGet(g_tlsReturnCapture) : NULL;

    if (rcs && rcs->depth > 0)
    {
        rcs->depth--;
        RetCapEntry* ent = &rcs->entries[rcs->depth];
        realRetAddr = ent->realReturnAddr;

        // Compute duration
        LARGE_INTEGER tsNow;
        QueryPerformanceCounter(&tsNow);
        uint64_t durationQpc = (uint64_t)tsNow.QuadPart - ent->timestampQpc;
        DWORD lastError = GetLastError();

        InterlockedIncrement(&g_dispatchCount);

        // Serialize and send event via ring buffer
        SerializeAndSendEvent(
            ent->slotIndex,
            GetCurrentThreadId(),
            ent->timestampQpc,
            durationQpc,
            (uint64_t)returnValue,
            lastError,
            ent->argValues,
            ent->paramCount,
            realRetAddr);

        SetLastError(lastError);
    }
    else
    {
        // Stack underflow -- should never happen.
        DbgLog("[veh] CRITICAL: return capture stack empty, cannot find real return address!");
        // Best we can do is crash cleanly.
        realRetAddr = NULL;
    }

    // Clear reentrancy guard
    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
        DirectTlsSet(g_tlsReentrancy, NULL);

    return realRetAddr;
}

// ---- Create Return Stub ----
bool Veh_CreateReturnStub(void)
{
    g_returnStub = (uint8_t*)VirtualAlloc(NULL, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_returnStub) return false;
    memset(g_returnStub, 0xCC, 64);

    int off = 0;

#ifdef _M_X64
    // x64 return stub (30 bytes):
    // RAX = return value from hooked function
    // Stack: function already did RET, RSP is where original caller expects

    // push rax              ; save return value
    g_returnStub[off++] = 0x50;
    // sub rsp, 0x20         ; shadow space (0x20 = 32 bytes)
    g_returnStub[off++] = 0x48; g_returnStub[off++] = 0x83;
    g_returnStub[off++] = 0xEC; g_returnStub[off++] = 0x20;
    // mov rcx, rax          ; arg1 = return value
    g_returnStub[off++] = 0x48; g_returnStub[off++] = 0x89; g_returnStub[off++] = 0xC1;
    // mov rax, <HandleReturnCaptureX64>  ; absolute 64-bit address
    g_returnStub[off++] = 0x48; g_returnStub[off++] = 0xB8;
    *(uint64_t*)(g_returnStub + off) = (uint64_t)&HandleReturnCaptureX64;
    off += 8;
    // call rax
    g_returnStub[off++] = 0xFF; g_returnStub[off++] = 0xD0;
    // add rsp, 0x20         ; clean shadow
    g_returnStub[off++] = 0x48; g_returnStub[off++] = 0x83;
    g_returnStub[off++] = 0xC4; g_returnStub[off++] = 0x20;
    // mov rcx, rax          ; save real return addr
    g_returnStub[off++] = 0x48; g_returnStub[off++] = 0x89; g_returnStub[off++] = 0xC1;
    // pop rax               ; restore return value
    g_returnStub[off++] = 0x58;
    // jmp rcx               ; go to real caller
    g_returnStub[off++] = 0xFF; g_returnStub[off++] = 0xE1;

#elif defined(_M_IX86)
    // x86 return stub (19 bytes):
    // EAX = return value, EDX = upper 32 for 64-bit returns

    // push edx              ; save EDX
    g_returnStub[off++] = 0x52;
    // push eax              ; save EAX (return value)
    g_returnStub[off++] = 0x50;
    // push eax              ; arg1 = return value (already on stack from push above)
    g_returnStub[off++] = 0x50;
    // mov eax, <HandleReturnCaptureX86>
    g_returnStub[off++] = 0xB8;
    *(uint32_t*)(g_returnStub + off) = (uint32_t)(uintptr_t)&HandleReturnCaptureX86;
    off += 4;
    // call eax
    g_returnStub[off++] = 0xFF; g_returnStub[off++] = 0xD0;
    // add esp, 4            ; clean arg1
    g_returnStub[off++] = 0x83; g_returnStub[off++] = 0xC4; g_returnStub[off++] = 0x04;
    // mov ecx, eax          ; save real return addr
    g_returnStub[off++] = 0x89; g_returnStub[off++] = 0xC1;
    // pop eax               ; restore return value
    g_returnStub[off++] = 0x58;
    // pop edx               ; restore EDX
    g_returnStub[off++] = 0x5A;
    // jmp ecx               ; go to real caller
    g_returnStub[off++] = 0xFF; g_returnStub[off++] = 0xE1;
#endif

    return true;
}
#endif // disabled return capture subsystem

// ============================================================
// VEH Handler
// ============================================================

static volatile LONG g_vehHitCount = 0;       // breakpoints matched to our hooks
static volatile LONG g_vehMissCount = 0;      // breakpoints NOT in our table
static volatile LONG g_vehNonBpCount = 0;     // non-breakpoint exceptions seen

LONG CALLBACK VehHookHandler(EXCEPTION_POINTERS* ep)
{
    // Fast reject: only handle EXCEPTION_BREAKPOINT (INT3).
    // This check is hit for every exception in the process, must be instant.
    if (ep->ExceptionRecord->ExceptionCode != STATUS_BREAKPOINT)
    {
        InterlockedIncrement(&g_vehNonBpCount);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Look up the exception address in our hook table.
    void* excAddr = ep->ExceptionRecord->ExceptionAddress;
    int slot = AddrMap_Lookup(excAddr);
    if (slot < 0)
    {
        InterlockedIncrement(&g_vehMissCount);
        return EXCEPTION_CONTINUE_SEARCH;  // not our breakpoint
    }

    // This is our breakpoint -- log periodically for diagnostics
    LONG hitNum = InterlockedIncrement(&g_vehHitCount);
    if (hitNum <= 5 || hitNum % 1000 == 0)
    {
        HookRegistration* r = &g_hookSlots[slot];
        DbgLog("[veh] HIT #%d: slot=%d %s!%s addr=%p tid=%u",
            (int)hitNum, slot, r->moduleName, r->funcName, excAddr, GetCurrentThreadId());
    }

    HookRegistration* reg = &g_hookSlots[slot];
    if (!reg->active || !reg->trampoline)
        return EXCEPTION_CONTINUE_SEARCH;

    // ---- Suppress during setup ----
    if (g_suppressCapture)
    {
#ifdef _M_X64
        ep->ContextRecord->Rip = (DWORD64)reg->trampoline;
#elif defined(_M_IX86)
        ep->ContextRecord->Eip = (DWORD)reg->trampoline;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ---- Reentrancy guard ----
    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES &&
        DirectTlsGet(g_tlsReentrancy) != NULL)
    {
        // Already inside a hook dispatch -- skip capture, call original.
#ifdef _M_X64
        ep->ContextRecord->Rip = (DWORD64)reg->trampoline;
#elif defined(_M_IX86)
        ep->ContextRecord->Eip = (DWORD)reg->trampoline;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Set reentrancy guard (cleared after event serialization)
    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
        DirectTlsSet(g_tlsReentrancy, (void*)1);

    // ---- Capture arguments ----
    uint64_t argValues[MAX_PARAMS] = {0};
    int nParams = reg->paramCount;

#ifdef _M_X64
    if (nParams > 0) argValues[0] = ep->ContextRecord->Rcx;
    if (nParams > 1) argValues[1] = ep->ContextRecord->Rdx;
    if (nParams > 2) argValues[2] = ep->ContextRecord->R8;
    if (nParams > 3) argValues[3] = ep->ContextRecord->R9;
    if (nParams > 4)
    {
        uint64_t* stackBase = (uint64_t*)ep->ContextRecord->Rsp;
        for (int i = 4; i < nParams && i < MAX_PARAMS; i++)
            argValues[i] = stackBase[1 + i];
    }
    void* retAddr = *(void**)ep->ContextRecord->Rsp;
#elif defined(_M_IX86)
    uint32_t* stackArgs = (uint32_t*)(ep->ContextRecord->Esp + 4);
    for (int i = 0; i < nParams && i < MAX_PARAMS; i++)
        argValues[i] = (uint64_t)stackArgs[i];
    void* retAddr = *(void**)ep->ContextRecord->Esp;
#endif

    // ---- Send event immediately (entry-only capture) ----
    // No return address hijacking -- send args now with returnValue=0, duration=0.
    // Return hijacking was causing crashes: modifying the stack return address
    // interacts badly with SEH unwinding, CFG, and shadow stacks.
    LARGE_INTEGER tsNow;
    QueryPerformanceCounter(&tsNow);
    InterlockedIncrement(&g_dispatchCount);

    SerializeAndSendEvent(
        slot,
        GetCurrentThreadId(),
        (uint64_t)tsNow.QuadPart,
        0,      // duration = 0 (entry-only, no return capture)
        0,      // returnValue = 0
        0,      // lastError = 0
        argValues, nParams,
        retAddr);

    // Clear reentrancy guard -- the original function and its callees
    // should be capturable (they'll set the guard when they fire).
    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
        DirectTlsSet(g_tlsReentrancy, NULL);

    // ---- Redirect to trampoline ----
    // The trampoline (created by MH_CreateHook) contains a copy of the
    // original function's first N bytes followed by a JMP to original+N.
    // This executes the original function without hitting our INT3.
#ifdef _M_X64
    ep->ContextRecord->Rip = (DWORD64)reg->trampoline;
#elif defined(_M_IX86)
    ep->ContextRecord->Eip = (DWORD)reg->trampoline;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ---- Unhandled Exception Filter Wrapper ----
// Fallback when VEH registration is blocked by anti-cheat.
// SetUnhandledExceptionFilter installs via a simple global pointer
// (BasepCurrentTopLevelFilter) -- completely different from VEH linked list.
//
// Difference from VEH: this fires LAST (after all SEH handlers), not FIRST.
// For INT3 at function entry there's typically no SEH handler above us on
// the stack, so the breakpoint propagates to our filter.
//
// Return EXCEPTION_CONTINUE_EXECUTION if we handled it,
// EXCEPTION_EXECUTE_HANDLER to let the default handler run,
// or call the previous filter if it wasn't our breakpoint.
static volatile LONG g_unhandledFilterCalls = 0;

LONG WINAPI UnhandledHookFilter(EXCEPTION_POINTERS* ep)
{
    LONG callNum = InterlockedIncrement(&g_unhandledFilterCalls);
    if (callNum <= 5 || callNum % 100 == 0)
        DbgLog("[unhandled] Filter called #%d: code=0x%08X addr=%p",
            (int)callNum, ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress);

    if (ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
    {
        void* excAddr = ep->ExceptionRecord->ExceptionAddress;
        int slot = AddrMap_Lookup(excAddr);
        if (slot >= 0)
        {
            // Delegate to the VEH handler -- same logic
            LONG result = VehHookHandler(ep);
            if (result == EXCEPTION_CONTINUE_EXECUTION)
                return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Not our breakpoint -- chain to previous filter
    if (g_prevUnhandledFilter)
        return g_prevUnhandledFilter(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================
// INT3 Arm/Disarm
// ============================================================

int Veh_ArmAll(void)
{
    HANDLE hProc = GetCurrentProcess();
    int armed = 0;
    int armFailed = 0;

    for (int i = 0; i < g_nextSlot; i++)
    {
        if (!g_hookSlots[i].active || !g_hookSlots[i].trampoline)
            continue;

        void* addr = g_hookSlots[i].originalFunc;

        // Skip if already armed (INT3 already written)
        if (*(volatile uint8_t*)addr == 0xCC)
            continue;

        // Save original byte
        g_savedBytes[i] = *(uint8_t*)addr;

        // Write INT3: try VirtualProtect + direct write first (avoids
        // WriteProcessMemory which EAC may hook). Fall back to
        // WriteProcessMemory if VirtualProtect fails.
        bool ok = false;
        DWORD oldProtect = 0;
        if (VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            *(volatile uint8_t*)addr = 0xCC;
            DWORD tmp;
            VirtualProtect(addr, 1, oldProtect, &tmp);
            FlushInstructionCache(hProc, addr, 1);
            ok = true;
        }
        else
        {
            // Fallback: WriteProcessMemory handles page permissions internally
            uint8_t cc = 0xCC;
            SIZE_T written = 0;
            if (WriteProcessMemory(hProc, addr, &cc, 1, &written) && written == 1)
            {
                FlushInstructionCache(hProc, addr, 1);
                ok = true;
            }
        }

        if (ok)
            armed++;
        else
        {
            armFailed++;
            if (armFailed <= 5)
                DbgLog("[veh] Arm failed: slot=%d %s!%s err=%u",
                    i, g_hookSlots[i].moduleName, g_hookSlots[i].funcName,
                    GetLastError());
        }
    }

    DbgLog("[veh] ArmAll: %d armed, %d failed", armed, armFailed);
    return armed;
}

void Veh_DisarmAll(void)
{
    HANDLE hProc = GetCurrentProcess();

    for (int i = 0; i < g_nextSlot; i++)
    {
        if (!g_hookSlots[i].active || !g_savedBytes)
            continue;

        void* addr = g_hookSlots[i].originalFunc;

        // Restore original byte (VirtualProtect + direct write, fallback to WriteProcessMemory)
        DWORD oldProtect = 0;
        if (VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            *(volatile uint8_t*)addr = g_savedBytes[i];
            DWORD tmp;
            VirtualProtect(addr, 1, oldProtect, &tmp);
        }
        else
        {
            SIZE_T written = 0;
            WriteProcessMemory(hProc, addr, &g_savedBytes[i], 1, &written);
        }
        FlushInstructionCache(hProc, addr, 1);
    }
}

// ============================================================
// VEH Initialization Helpers (called from hook_engine.cpp)
// ============================================================

bool Veh_Init(int maxHooks)
{
    // Resolve ntdll VEH functions -- bypasses kernel32 hooks.
    // EAC hooks kernel32!AddVectoredExceptionHandler, causing it to return NULL.
    // ntdll!RtlAddVectoredExceptionHandler is the underlying implementation.
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
        {
            g_pfnRtlAddVEH = (PFN_RtlAddVectoredExceptionHandler)
                GetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler");
            g_pfnRtlRemoveVEH = (PFN_RtlRemoveVectoredExceptionHandler)
                GetProcAddress(hNtdll, "RtlRemoveVectoredExceptionHandler");
        }
        DbgLog("[hook] VEH ntdll resolve: RtlAddVEH=%p RtlRemoveVEH=%p",
            g_pfnRtlAddVEH, g_pfnRtlRemoveVEH);
    }

    // Address hash table for O(1) lookup in VEH handler
    g_addrMap = (AddrMapEntry*)VirtualAlloc(NULL,
        ADDR_MAP_SIZE * sizeof(AddrMapEntry),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_addrMap)
        return false;
    memset(g_addrMap, 0, ADDR_MAP_SIZE * sizeof(AddrMapEntry));

    // Saved original bytes (one per slot, restored on disarm)
    g_savedBytes = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)maxHooks);
    if (!g_savedBytes)
    {
        VirtualFree(g_addrMap, 0, MEM_RELEASE);
        g_addrMap = NULL;
        return false;
    }

    // Install exception handler DURING init -- before any hooks are registered.
    // This enables "arm-on-register" mode: each hook is armed with INT3 immediately
    // when registered, so events start flowing as soon as the first hook is created.
    //
    // SPEED-FIRST strategy for anti-cheat processes:
    // 1. SetUnhandledExceptionFilter (instant, single pointer write)
    // 2. ntdll direct RtlAddVectoredExceptionHandler (fast, single call)
    // 3. kernel32 AddVectoredExceptionHandler (fast, may be blocked)
    // 4. VEH manual insert via data scan -- DEFERRED to EnableAll (scans ntdll .data,
    //    which may trigger EAC integrity checks and cause PACKER crash)
    //
    // The ntdll data section scan is deferred because EAC has been observed killing
    // the process during the scan. Hooks start flowing with whatever handler succeeds
    // here; EnableAll upgrades to manual VEH insert later if possible.
    {
        PVOID vehResult = NULL;

        // Method A: ntdll direct call (fast, fires FIRST on exceptions)
        if (g_pfnRtlAddVEH)
        {
            vehResult = g_pfnRtlAddVEH(1, VehHookHandler);
            if (vehResult)
            {
                g_vehHandle = vehResult;
                g_vehMethod = VEH_METHOD_API;
                DbgLog("[hook] VEH installed during init: ntdll direct (%p)", vehResult);
            }
        }

        // Method B: kernel32 (fast, may be blocked by anti-cheat)
        if (!vehResult)
        {
            vehResult = AddVectoredExceptionHandler(1, VehHookHandler);
            if (vehResult)
            {
                g_vehHandle = vehResult;
                g_vehMethod = VEH_METHOD_API;
                DbgLog("[hook] VEH installed during init: kernel32 (%p)", vehResult);
            }
        }

        // Method C: SetUnhandledExceptionFilter (instant, fires LAST after all SEH)
        if (!vehResult)
        {
            g_prevUnhandledFilter = SetUnhandledExceptionFilter(UnhandledHookFilter);
            if (g_prevUnhandledFilter != UnhandledHookFilter)
            {
                g_vehMethod = VEH_METHOD_UNHANDLED;
                g_vehHandle = (PVOID)1;
                DbgLog("[hook] Exception handler installed during init: SetUnhandledExceptionFilter");
            }
        }

        // Method D (manual VEH insert via ntdll data scan) is DEFERRED to EnableAll
        // to avoid triggering EAC integrity checks during init.
    }

    return true;
}

void Veh_Shutdown(void)
{
    if (g_addrMap)
    {
        VirtualFree(g_addrMap, 0, MEM_RELEASE);
        g_addrMap = NULL;
    }
    if (g_savedBytes)
    {
        HeapFree(GetProcessHeap(), 0, g_savedBytes);
        g_savedBytes = NULL;
    }
    // Clean up exception handler
    switch (g_vehMethod)
    {
    case VEH_METHOD_MANUAL:
        VehRemove_ManualEntry();
        g_vehHandle = NULL;
        break;
    case VEH_METHOD_UNHANDLED:
        SetUnhandledExceptionFilter(g_prevUnhandledFilter);
        g_prevUnhandledFilter = NULL;
        g_vehHandle = NULL;
        break;
    case VEH_METHOD_API:
        if (g_vehHandle)
        {
            if (g_pfnRtlRemoveVEH)
                g_pfnRtlRemoveVEH(g_vehHandle);
            else
                RemoveVectoredExceptionHandler(g_vehHandle);
            g_vehHandle = NULL;
        }
        break;
    default:
        break;
    }
    g_vehMethod = VEH_METHOD_NONE;
}

void Veh_GetDiagnostics(int* outVehHits, int* outVehMisses, int* outVehNonBp, int* outUnhandledCalls)
{
    if (outVehHits) *outVehHits = (int)g_vehHitCount;
    if (outVehMisses) *outVehMisses = (int)g_vehMissCount;
    if (outVehNonBp) *outVehNonBp = (int)g_vehNonBpCount;
    if (outUnhandledCalls) *outUnhandledCalls = (int)g_unhandledFilterCalls;
}

uint8_t* Veh_GetSavedBytes(void)
{
    return g_savedBytes;
}
