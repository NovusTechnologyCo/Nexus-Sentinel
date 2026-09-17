/**
 * @file hook_engine.h
 * @brief Public API for the NexusApiHook hooking engine
 *
 * Manages hook slot registration, MinHook trampoline creation, and the
 * generic dispatch entry point. Hook slots are dynamically allocated at
 * initialization time -- there is no compile-time limit on hook count.
 *
 * ## Typical Usage
 * 1. Call HookEngine_Initialize(maxHooks) to allocate slot arrays and install
 *    the exception handler
 * 2. Call HookEngine_RegisterHook() for each API to monitor (hooks are armed
 *    immediately on registration)
 * 3. Call HookEngine_EnableAll() to upgrade the exception handler and enable
 *    full event capture
 * 4. At shutdown, call HookEngine_DisableAll() then HookEngine_Shutdown()
 *
 * ## Thread Safety
 * HookEngine_RegisterHook is NOT thread-safe (call from worker thread only).
 * GenericDispatch is designed for concurrent execution from any thread.
 * SuppressGuard/RestoreGuard manage per-thread reentrancy state.
 */
#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Metadata describing a single function parameter for event capture */
typedef struct {
    uint8_t  flags;                         // PARAM_FLAG_* bitmask
    char     name[MAX_PARAM_NAME];          // parameter name (UTF-8)
    char     type[MAX_PARAM_NAME];          // parameter type (UTF-8)
} ParamMeta;

/** @brief Complete registration state for a single hook slot */
typedef struct {
    bool        active;                     // slot is in use
    uint16_t    slotIndex;                  // index into g_hookSlots[]
    uint16_t    configIndex;                // index in MSG_CONFIGURE list (for host-side lookup)
    char        moduleName[MAX_MODULE_NAME];// e.g. "kernel32.dll"
    char        funcName[MAX_FUNC_NAME];    // e.g. "CreateFileW"
    void*       originalFunc;               // original function address
    void*       trampoline;                 // MinHook trampoline (call to reach original)
    uint8_t     paramCount;                 // number of parameters
    ParamMeta   params[MAX_PARAMS];         // parameter metadata
    void*       stubAddress;                // runtime-generated hook stub (x64 or x86)
    uint16_t    stackCleanupBytes;          // x86: RET N bytes for __stdcall cleanup (paramCount * 4)
} HookRegistration;

/**
 * @brief Initialize the hook engine with a specific capacity
 *
 * Allocates TLS indices, initializes MinHook, creates the event ring buffer
 * and drain thread, allocates RWX stub block, and installs the exception
 * handler. Must be called before any other HookEngine function.
 *
 * @param[in] maxHooks  Maximum number of hooks that can be registered (min 16)
 * @return true on success, false on resource allocation failure
 */
bool HookEngine_Initialize(int maxHooks);

/**
 * @brief Shut down the hook engine and release all resources
 *
 * Disables all hooks, uninitializes MinHook, stops the drain thread,
 * frees the ring buffer and stub block, removes the exception handler,
 * and releases TLS indices. Safe to call if not initialized (no-op).
 */
void HookEngine_Shutdown(void);

/**
 * @brief Register a hook on the specified module!function
 *
 * Resolves the function address via GetModuleHandle/GetProcAddress, creates
 * a MinHook trampoline, generates a runtime stub, and arms the hook (INT3
 * or JMP) immediately. The hook is active as soon as this returns.
 *
 * @param[in] moduleName  DLL name (e.g., "kernel32.dll")
 * @param[in] funcName    Exported function name (e.g., "CreateFileW")
 * @param[in] paramCount  Number of parameters to capture
 * @param[in] params      Array of parameter metadata (flags, name, type)
 * @return Slot index (>= 0) on success, -1 on failure
 */
int HookEngine_RegisterHook(
    const char* moduleName,
    const char* funcName,
    uint8_t paramCount,
    const ParamMeta* params);

/**
 * @brief Enable all registered hooks and upgrade the exception handler
 *
 * In VEH mode, attempts manual VEH list insertion if the initial handler
 * was suboptimal. In JMP mode, calls MH_EnableHook on all slots.
 *
 * @return true if hooks are active
 */
bool HookEngine_EnableAll(void);

/**
 * @brief Disable all registered hooks
 *
 * In VEH mode, disarms all INT3 breakpoints by restoring original bytes.
 * In JMP mode, calls MH_DisableHook on all slots. Removes the exception
 * handler and stops the drain thread.
 *
 * @return true on success
 */
bool HookEngine_DisableAll(void);

/**
 * @brief Get the runtime stub address for a slot (used as MinHook detour target)
 *
 * @param[in] slotIndex  Hook slot index
 * @return Pointer to the runtime-generated stub, or NULL
 */
void* HookEngine_GetSlotFunction(int slotIndex);

/**
 * @brief Get the full registration info for a hook slot
 *
 * @param[in] slotIndex  Hook slot index
 * @return Pointer to the HookRegistration, or NULL if out of range
 */
HookRegistration* HookEngine_GetRegistration(int slotIndex);

/**
 * @brief Suppress hook event capture on the current thread
 *
 * Sets the per-thread reentrancy guard so that any hooked functions called
 * by the current code path will execute the original without capturing events.
 * Used to protect pipe I/O, hook registration, and other internal operations.
 *
 * @return Opaque previous guard state -- pass to HookEngine_RestoreGuard()
 */
void* HookEngine_SuppressGuard(void);

/**
 * @brief Restore the reentrancy guard to a previously saved state
 *
 * @param[in] savedState  Value returned by HookEngine_SuppressGuard()
 */
void HookEngine_RestoreGuard(void* savedState);

/**
 * @brief Generic dispatch entry point called by every hook stub
 *
 * Checks the reentrancy guard, captures function arguments, calls the
 * original function via the MinHook trampoline, captures the return value
 * and duration, then serializes and enqueues the event.
 */
#ifdef _M_X64
/**
 * @brief x64 generic dispatch (called by runtime-generated stubs)
 *
 * @param[in] slotIndex      Hook slot that fired
 * @param[in] a1             First register arg (RCX)
 * @param[in] a2             Second register arg (RDX)
 * @param[in] a3             Third register arg (R8)
 * @param[in] a4             Fourth register arg (R9)
 * @param[in] returnAddress  Pointer to return address on stack (for stack args)
 * @return Return value from the original function
 */
uint64_t GenericDispatch(int slotIndex, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, void* returnAddress);
#elif defined(_M_IX86)
/**
 * @brief x86 generic dispatch (called by runtime-generated __stdcall stubs)
 *
 * @param[in] slotIndex  Hook slot that fired
 * @param[in] argPtr     Pointer to first arg on caller's stack (ESP+4 at entry)
 * @return Return value from the original function (EDX:EAX for 64-bit returns)
 */
uint64_t __cdecl GenericDispatch32(int slotIndex, uint32_t* argPtr);
#endif

#ifdef __cplusplus
}
#endif
