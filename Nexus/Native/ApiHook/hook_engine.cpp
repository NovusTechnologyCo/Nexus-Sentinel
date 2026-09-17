/**
 * @file hook_engine.cpp
 * @brief Core hooking engine for NexusApiHook -- initialization, registration, and lifecycle
 *
 * This file contains the global state definitions and the public API functions:
 * HookEngine_Initialize, HookEngine_Shutdown, HookEngine_RegisterHook,
 * HookEngine_EnableAll, HookEngine_DisableAll, and utility accessors.
 *
 * The implementation is split across several files:
 * - hook_engine.cpp        -- globals and public API (this file)
 * - hook_engine_stubs.cpp  -- runtime x64/x86 stub code generation
 * - hook_engine_veh.cpp    -- VEH/INT3 backend, address map, arm/disarm
 * - hook_dispatch.cpp      -- GenericDispatch and CallOriginal
 * - hook_events.cpp        -- event serialization, ring buffer, drain thread
 * - hook_blacklist.cpp     -- function blacklist
 *
 * @see hook_engine.h           Public API and HookRegistration structure
 * @see hook_engine_internal.h  Internal shared state and forward declarations
 * @see protocol.h              Wire protocol for MSG_EVENT serialization
 */

#include "hook_engine_internal.h"
#include "minhook/include/MinHook.h"

// ============================================================
// Global definitions (declared extern in hook_engine_internal.h)
// ============================================================

HookRegistration* g_hookSlots = NULL;
int g_maxSlots = 0;
int g_nextSlot = 0;
bool g_initialized = false;

DWORD g_tlsReentrancy = TLS_OUT_OF_INDEXES;
DWORD g_tlsSendBuffer = TLS_OUT_OF_INDEXES;

volatile bool g_suppressCapture = false;
bool g_useJmpMode = false;
LARGE_INTEGER g_qpcFrequency;

EventRingSlot* g_eventRing = NULL;
volatile LONG g_ringHead = 0;
volatile LONG g_ringTail = 0;
HANDLE g_hDrainThread = NULL;
HANDLE g_hDrainEvent = NULL;
volatile bool g_drainRunning = false;

volatile LONG g_dispatchCount = 0;
volatile LONG g_enqueueCount = 0;
volatile LONG g_drainCount = 0;
volatile LONG g_dropCount = 0;

uint8_t* g_stubBlock = NULL;

DWORD g_tlsReturnCapture = TLS_OUT_OF_INDEXES;  // unused (return capture disabled)

// ============================================================
// Hook Engine Public API
// ============================================================

bool HookEngine_Initialize(int maxHooks)
{
    if (g_initialized) return true;

    // Enforce a minimum and cap to uint16_t protocol limit
    if (maxHooks < 16) maxHooks = 16;
    if (maxHooks > 65535) maxHooks = 65535;

    QueryPerformanceFrequency(&g_qpcFrequency);

    // Allocate TLS indices BEFORE hooks are enabled (TlsAlloc is not yet hooked).
    // All subsequent access uses DirectTlsGet/DirectTlsSet via TEB.
    g_tlsReentrancy = TlsAlloc();
    if (g_tlsReentrancy == TLS_OUT_OF_INDEXES)
        return false;

    g_tlsSendBuffer = TlsAlloc();
    if (g_tlsSendBuffer == TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsReentrancy);
        g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        return false;
    }

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK)
    {
        TlsFree(g_tlsReentrancy);
        g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        TlsFree(g_tlsSendBuffer);
        g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
        return false;
    }

    // Allocate event ring buffer and start drain thread BEFORE hooks are enabled.
    g_eventRing = (EventRingSlot*)VirtualAlloc(NULL,
        EVENT_RING_SLOTS * sizeof(EventRingSlot),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_eventRing)
    {
        MH_Uninitialize();
        TlsFree(g_tlsReentrancy); g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        TlsFree(g_tlsSendBuffer); g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
        return false;
    }
    memset(g_eventRing, 0, EVENT_RING_SLOTS * sizeof(EventRingSlot));
    g_ringHead = 0;
    g_ringTail = 0;

    g_hDrainEvent = CreateEventA(NULL, FALSE, FALSE, NULL); // auto-reset
    g_drainRunning = true;
    g_hDrainThread = CreateThread(NULL, 0, DrainThreadProc, NULL, 0, NULL);

    // Allocate RWX block for runtime-generated stubs.
    SIZE_T stubBlockSize = (SIZE_T)maxHooks * STUB_SIZE;
    g_stubBlock = (uint8_t*)VirtualAlloc(NULL,
        stubBlockSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_stubBlock)
    {
        g_drainRunning = false;
        if (g_hDrainEvent) SetEvent(g_hDrainEvent);
        if (g_hDrainThread) { WaitForSingleObject(g_hDrainThread, 2000); CloseHandle(g_hDrainThread); g_hDrainThread = NULL; }
        if (g_hDrainEvent) { CloseHandle(g_hDrainEvent); g_hDrainEvent = NULL; }
        VirtualFree(g_eventRing, 0, MEM_RELEASE); g_eventRing = NULL;
        MH_Uninitialize();
        TlsFree(g_tlsReentrancy); g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        TlsFree(g_tlsSendBuffer); g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
        return false;
    }
    memset(g_stubBlock, 0xCC, stubBlockSize); // INT3 fill for safety

    // Allocate hook registration array
    g_hookSlots = (HookRegistration*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        (SIZE_T)maxHooks * sizeof(HookRegistration));
    if (!g_hookSlots)
    {
        VirtualFree(g_stubBlock, 0, MEM_RELEASE); g_stubBlock = NULL;
        g_drainRunning = false;
        if (g_hDrainEvent) SetEvent(g_hDrainEvent);
        if (g_hDrainThread) { WaitForSingleObject(g_hDrainThread, 2000); CloseHandle(g_hDrainThread); g_hDrainThread = NULL; }
        if (g_hDrainEvent) { CloseHandle(g_hDrainEvent); g_hDrainEvent = NULL; }
        VirtualFree(g_eventRing, 0, MEM_RELEASE); g_eventRing = NULL;
        MH_Uninitialize();
        TlsFree(g_tlsReentrancy); g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        TlsFree(g_tlsSendBuffer); g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
        return false;
    }

    // ---- VEH-specific allocations and exception handler install ----
    if (!Veh_Init(maxHooks))
    {
        HeapFree(GetProcessHeap(), 0, g_hookSlots); g_hookSlots = NULL;
        VirtualFree(g_stubBlock, 0, MEM_RELEASE); g_stubBlock = NULL;
        g_drainRunning = false;
        if (g_hDrainEvent) SetEvent(g_hDrainEvent);
        if (g_hDrainThread) { WaitForSingleObject(g_hDrainThread, 2000); CloseHandle(g_hDrainThread); g_hDrainThread = NULL; }
        if (g_hDrainEvent) { CloseHandle(g_hDrainEvent); g_hDrainEvent = NULL; }
        VirtualFree(g_eventRing, 0, MEM_RELEASE); g_eventRing = NULL;
        MH_Uninitialize();
        TlsFree(g_tlsReentrancy); g_tlsReentrancy = TLS_OUT_OF_INDEXES;
        TlsFree(g_tlsSendBuffer); g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
        return false;
    }

    g_maxSlots = maxHooks;
    g_nextSlot = 0;
    g_initialized = true;

    // If all VEH methods failed and we're stuck on SetUnhandledExceptionFilter
    // (or no handler at all), switch to JMP detour mode. INT3 exceptions in
    // processes with anti-cheat VEH handlers (EAC) get intercepted by their VEH
    // before reaching our UEF -> PACKER crash. JMP detours generate no exceptions.
    if (g_vehMethod == VEH_METHOD_UNHANDLED || g_vehMethod == VEH_METHOD_NONE)
    {
        g_useJmpMode = true;
        // Remove the UEF handler -- not needed in JMP mode
        if (g_vehMethod == VEH_METHOD_UNHANDLED)
        {
            // Veh_Shutdown handles cleanup, but we need to signal JMP mode first
        }
        g_vehHandle = (PVOID)1; // sentinel so RegisterHook logic proceeds
        g_vehMethod = VEH_METHOD_NONE;
        DbgLog("[hook] JMP detour mode enabled (VEH unavailable -- anti-cheat safe)");
    }

    DbgLog("[hook] Engine initialized: maxHooks=%d, stubBlockSize=%zu, registrationSize=%zu, vehAddrMap=%d",
        maxHooks, stubBlockSize, (SIZE_T)maxHooks * sizeof(HookRegistration), ADDR_MAP_SIZE);
    return true;
}

void HookEngine_Shutdown(void)
{
    if (!g_initialized) return;

    // Dump final diagnostics
    int vehHits = 0, vehMisses = 0, vehNonBp = 0, unhandledCalls = 0;
    Veh_GetDiagnostics(&vehHits, &vehMisses, &vehNonBp, &unhandledCalls);

    DbgLog("[hook] === SHUTDOWN DIAGNOSTICS ===");
    DbgLog("[hook]   Registered hooks: %d, jmpMode: %d", g_nextSlot, (int)g_useJmpMode);
    DbgLog("[hook]   VEH method: %d", g_vehMethod);
    DbgLog("[hook]   VEH hits: %d, misses: %d, non-BP: %d",
        vehHits, vehMisses, vehNonBp);
    DbgLog("[hook]   Dispatches: %d, enqueued: %d, drained: %d, dropped: %d",
        (int)g_dispatchCount, (int)g_enqueueCount, (int)g_drainCount, (int)g_dropCount);
    DbgLog("[hook]   UnhandledFilter calls: %d", unhandledCalls);

    // In JMP mode, MH_DisableHook restores original bytes. MH_Uninitialize frees
    // MinHook's internal trampoline allocations. In VEH mode, MH_EnableHook was
    // never called so MH_DisableHook is a no-op.
    MH_Uninitialize();

    // Stop drain thread
    g_drainRunning = false;
    if (g_hDrainEvent) SetEvent(g_hDrainEvent); // wake it up
    if (g_hDrainThread)
    {
        WaitForSingleObject(g_hDrainThread, 2000);
        CloseHandle(g_hDrainThread);
        g_hDrainThread = NULL;
    }
    if (g_hDrainEvent) { CloseHandle(g_hDrainEvent); g_hDrainEvent = NULL; }

    // Free ring buffer
    if (g_eventRing)
    {
        VirtualFree(g_eventRing, 0, MEM_RELEASE);
        g_eventRing = NULL;
    }

    // Free stub block
    if (g_stubBlock)
    {
        VirtualFree(g_stubBlock, 0, MEM_RELEASE);
        g_stubBlock = NULL;
    }

    // Free VEH structures and exception handler
    Veh_Shutdown();

    // Free hook registration array
    if (g_hookSlots)
    {
        HeapFree(GetProcessHeap(), 0, g_hookSlots);
        g_hookSlots = NULL;
    }

    if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsReentrancy);
        g_tlsReentrancy = TLS_OUT_OF_INDEXES;
    }
    if (g_tlsSendBuffer != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsSendBuffer);
        g_tlsSendBuffer = TLS_OUT_OF_INDEXES;
    }
    if (g_tlsReturnCapture != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsReturnCapture);
        g_tlsReturnCapture = TLS_OUT_OF_INDEXES;
    }

    g_maxSlots = 0;
    g_nextSlot = 0;
    g_initialized = false;
}

int HookEngine_RegisterHook(
    const char* moduleName,
    const char* funcName,
    uint8_t paramCount,
    const ParamMeta* params)
{
    if (!g_initialized || g_nextSlot >= g_maxSlots)
        return -1;

    // HOOK_LIMIT removed -- blacklist approach handles dangerous functions.

    // Reject blacklisted functions -- these are either dangerous to hook
    // (e.g. VirtualProtect used by MinHook) or so noisy they saturate the ring buffer.
    if (IsBlacklisted(funcName))
        return -1;

    // Resolve function address -- only hook modules already loaded in the target process.
    // Do NOT use LoadLibraryA: loading unused DLLs (Aclui.dll, Activeds.dll, etc.) wastes
    // time, bloats the process, and may trigger anti-cheat module scanning.
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return -1;

    void* target = (void*)GetProcAddress(hMod, funcName);
    if (!target) return -1;

    int slot = g_nextSlot;
    HookRegistration* reg = &g_hookSlots[slot];

    reg->slotIndex = (uint16_t)slot;
    strncpy_s(reg->moduleName, sizeof(reg->moduleName), moduleName, _TRUNCATE);
    strncpy_s(reg->funcName, sizeof(reg->funcName), funcName, _TRUNCATE);
    reg->originalFunc = target;
    reg->paramCount = paramCount > MAX_PARAMS ? MAX_PARAMS : paramCount;

    if (params && paramCount > 0)
    {
        memcpy(reg->params, params, sizeof(ParamMeta) * reg->paramCount);
    }

    // Create MinHook detour: target -> runtime stub, trampoline for calling original
#ifdef _M_X64
    void* stub = CreateStub64(slot);
#elif defined(_M_IX86)
    void* stub = CreateStub32(slot, reg->paramCount);
#endif
    if (!stub)
    {
        memset(reg, 0, sizeof(*reg));
        return -1;
    }
    reg->stubAddress = stub;
#ifdef _M_IX86
    reg->stackCleanupBytes = (uint16_t)(reg->paramCount * 4);
#endif

    // MH_CreateHook creates the trampoline (copies original prologue + JMP back).
    // The stub is passed as the detour target.
    // - INT3 mode: MH_EnableHook is NEVER called. We write INT3 + VEH dispatch.
    // - JMP mode:  MH_EnableHook is called in EnableAll to write JMP -> stub.
    MH_STATUS status = MH_CreateHook(target, stub, &reg->trampoline);
    if (status != MH_OK)
    {
        memset(reg, 0, sizeof(*reg));
        return -1;
    }

    // Register in VEH address hash table for O(1) lookup on breakpoint
    if (!g_useJmpMode)
        AddrMap_Insert(target, slot);

    reg->active = true;
    g_nextSlot++;

    // INT3 mode: Arm immediately if not suppressed. During bulk registration
    // (g_suppressCapture=true), defer INT3 writing to EnableAll.
    // JMP mode: All hooks are batch-enabled in EnableAll via MH_EnableHook.
    uint8_t* savedBytes = Veh_GetSavedBytes();
    if (!g_useJmpMode && g_vehHandle && savedBytes && !g_suppressCapture)
    {
        savedBytes[slot] = *(uint8_t*)target;

        DWORD oldProtect = 0;
        if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            *(volatile uint8_t*)target = 0xCC;
            DWORD tmp;
            VirtualProtect(target, 1, oldProtect, &tmp);
            FlushInstructionCache(GetCurrentProcess(), target, 1);
        }
        else
        {
            uint8_t cc = 0xCC;
            SIZE_T written = 0;
            WriteProcessMemory(GetCurrentProcess(), target, &cc, 1, &written);
            FlushInstructionCache(GetCurrentProcess(), target, 1);
        }
    }

    if (slot < 5 || slot % 500 == 0 || slot == g_maxSlots - 1)
        DbgLog("[hook] slot=%d: %s!%s (params=%d)", slot, moduleName, funcName, paramCount);

    return slot;
}

bool HookEngine_EnableAll(void)
{
    DbgLog("[hook] EnableAll: %d active slots, jmpMode=%d, method=%d, dispatched=%d, enqueued=%d, drained=%d, dropped=%d",
        g_nextSlot, (int)g_useJmpMode, g_vehMethod,
        (int)g_dispatchCount, (int)g_enqueueCount, (int)g_drainCount, (int)g_dropCount);

    if (g_useJmpMode)
    {
        // JMP DETOUR MODE: Batch-enable all hooks via MinHook's JMP patches.
        // MH_EnableHook(MH_ALL_HOOKS) suspends threads, writes 5-byte JMP at each
        // function entry -> our stub -> GenericDispatch -> trampoline. No exceptions.
        g_suppressCapture = true;
        MH_STATUS mhStatus = MH_EnableHook(MH_ALL_HOOKS);
        g_suppressCapture = false;

        if (mhStatus == MH_OK)
            DbgLog("[hook] JMP batch-enable: OK (%d hooks)", g_nextSlot);
        else
            DbgLog("[hook] JMP batch-enable: FAILED status=%d", (int)mhStatus);

        DbgLog("[hook] EnableAll done: jmpMode=1, hooks=%d", g_nextSlot);
        return mhStatus == MH_OK;
    }

    // INT3 + VEH MODE (normal processes):

    // If exception handler wasn't installed during init (shouldn't happen), try now
    if (!g_vehHandle)
    {
        DbgLog("[hook] WARNING: No exception handler from init -- installing fallback");
        // Use SetUnhandledExceptionFilter as emergency fallback
        g_vehHandle = (PVOID)1;
        g_vehMethod = VEH_METHOD_UNHANDLED;
    }

    // If we're on SetUnhandledExceptionFilter, try upgrading to VEH for reliability
    // NOTE: VehRegister_ManualInsert is intentionally SKIPPED here -- it scans ntdll's
    // .data section which triggers EAC/anti-cheat integrity checks (PACKER crash).
    // Only use safe API-based methods for the upgrade attempt.
    if (g_vehMethod == VEH_METHOD_UNHANDLED)
    {
        PVOID vehUpgrade = NULL;
        if (g_pfnRtlAddVEH)
            vehUpgrade = g_pfnRtlAddVEH(1, VehHookHandler);
        if (!vehUpgrade)
            vehUpgrade = AddVectoredExceptionHandler(1, VehHookHandler);

        if (vehUpgrade)
        {
            g_vehHandle = vehUpgrade;
            g_vehMethod = VEH_METHOD_API;
            DbgLog("[hook] Upgraded from UnhandledFilter to VEH (method=%d)", g_vehMethod);
        }
        else
        {
            DbgLog("[hook] VEH upgrade failed -- keeping SetUnhandledExceptionFilter (may miss INT3)");
        }
    }

    // Batch-arm all registered hooks that weren't armed during RegisterHook
    // (deferred when g_suppressCapture was true during bulk registration).
    if (g_vehHandle)
    {
        int armed = Veh_ArmAll();
        DbgLog("[hook] Batch-armed %d hooks", armed);
    }

    DbgLog("[hook] EnableAll done: method=%d, handle=%p", g_vehMethod, g_vehHandle);
    return g_vehHandle != NULL;
}

bool HookEngine_DisableAll(void)
{
    g_suppressCapture = true;

    if (g_useJmpMode)
    {
        // JMP mode: disable all MinHook JMP patches (restores original bytes)
        MH_DisableHook(MH_ALL_HOOKS);
        DbgLog("[hook] JMP batch-disable: all hooks disabled");
    }
    else
    {
        // INT3 mode: disarm all INT3 breakpoints -- restore original bytes.
        Veh_DisarmAll();

        // Remove exception handler based on which method was used.
        switch (g_vehMethod)
        {
        case VEH_METHOD_MANUAL:
            VehRemove_ManualEntry();
            g_vehHandle = NULL;
            break;

        case VEH_METHOD_UNHANDLED:
            // Handler cleanup handled by Veh_Shutdown or next init
            g_vehHandle = NULL;
            DbgLog("[hook] Restored previous UnhandledExceptionFilter");
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
    }
    g_vehMethod = VEH_METHOD_NONE;

    g_suppressCapture = false;
    return true;
}

void* HookEngine_GetSlotFunction(int slotIndex)
{
    if (slotIndex < 0 || slotIndex >= g_maxSlots)
        return NULL;
    return g_hookSlots[slotIndex].stubAddress;
}

void* HookEngine_SuppressGuard(void)
{
    // Set global suppress -- prevents ALL threads from entering full VEH dispatch.
    // Critical during registration: the target process's main thread may call hooked
    // functions (GetProcAddress, VirtualQuery, etc.) and full VEH dispatch with return
    // hijacking on those threads causes crashes (they have no TLS reentrancy guard set).
    g_suppressCapture = true;
    if (g_tlsReentrancy == TLS_OUT_OF_INDEXES) return NULL;
    void* old = DirectTlsGet(g_tlsReentrancy);
    DirectTlsSet(g_tlsReentrancy, (void*)1);
    return old;
}

void HookEngine_RestoreGuard(void* savedState)
{
    // Clear global suppress -- resume normal event capture on all threads.
    g_suppressCapture = false;
    if (g_tlsReentrancy == TLS_OUT_OF_INDEXES) return;
    DirectTlsSet(g_tlsReentrancy, savedState);
}

HookRegistration* HookEngine_GetRegistration(int slotIndex)
{
    if (slotIndex < 0 || slotIndex >= g_maxSlots)
        return NULL;
    return &g_hookSlots[slotIndex];
}
