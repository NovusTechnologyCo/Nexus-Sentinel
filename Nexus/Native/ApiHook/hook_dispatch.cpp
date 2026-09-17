/**
 * @file hook_dispatch.cpp
 * @brief Generic dispatch and CallOriginal trampoline invocation
 *
 * Contains GenericDispatch (x64) / GenericDispatch32 (x86) and the
 * CallOriginal / CallOriginal32 functions with all PFN typedefs.
 * These are the hot-path functions called by every hook stub.
 *
 * Extracted from hook_engine.cpp for maintainability.
 */

#include "hook_engine_internal.h"

// ============================================================
// Generic Dispatch
// ============================================================

#ifdef _M_X64

uint64_t GenericDispatch(int slotIndex, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, void* returnAddress)
{
    HookRegistration* reg = &g_hookSlots[slotIndex];
    if (!reg->active || !reg->trampoline)
    {
        // Should not happen, but safety fallback
        return 0;
    }

    // ---- Suppress during hook enable/disable ----
    if (g_suppressCapture)
    {
        return CallOriginal(reg->trampoline, reg->paramCount, a1, a2, a3, a4, returnAddress);
    }

    // ---- Per-thread re-entrancy guard ----
    // Uses DirectTlsGet/DirectTlsSet for direct TEB access -- no kernel32 calls.
    if (g_tlsReentrancy == TLS_OUT_OF_INDEXES)
    {
        return CallOriginal(reg->trampoline, reg->paramCount, a1, a2, a3, a4, returnAddress);
    }
    if (DirectTlsGet(g_tlsReentrancy) != NULL)
    {
        return CallOriginal(reg->trampoline, reg->paramCount, a1, a2, a3, a4, returnAddress);
    }
    DirectTlsSet(g_tlsReentrancy, (void*)1);

    LONG dispNum = InterlockedIncrement(&g_dispatchCount);
    if (dispNum <= 5)
    {
        DbgLog("[event] dispatch #%d: slot=%d func=%s tid=%u",
            dispNum, slotIndex, reg->funcName, GetCurrentThreadId());
    }

    // ---- Capture with full exception protection ----
    uint64_t retVal = 0;
    __try
    {
        // ---- Capture pre-call state ----
        LARGE_INTEGER tsStart;
        QueryPerformanceCounter(&tsStart);

        // Collect argument values (first 4 from registers, rest from stack)
        uint64_t argValues[MAX_PARAMS] = {0};
        int nParams = reg->paramCount;
        if (nParams > 0) argValues[0] = a1;
        if (nParams > 1) argValues[1] = a2;
        if (nParams > 2) argValues[2] = a3;
        if (nParams > 3) argValues[3] = a4;

        if (nParams > 4)
        {
            uint64_t* stackBase = (uint64_t*)returnAddress;
            for (int i = 4; i < nParams && i < MAX_PARAMS; i++)
            {
                __try
                {
                    argValues[i] = stackBase[1 + i];
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    argValues[i] = 0;
                }
            }
        }

        // ---- Call original function ----
        retVal = CallOriginal(reg->trampoline, reg->paramCount, a1, a2, a3, a4, returnAddress);

        // ---- Capture post-call state ----
        DWORD lastError = GetLastError();

        LARGE_INTEGER tsEnd;
        QueryPerformanceCounter(&tsEnd);

        uint64_t durationQpc = (uint64_t)(tsEnd.QuadPart - tsStart.QuadPart);
        uint32_t threadId = GetCurrentThreadId();

        // ---- Serialize and send event ----
        SerializeAndSendEvent(
            slotIndex, threadId,
            (uint64_t)tsStart.QuadPart, durationQpc,
            retVal, lastError,
            argValues, nParams,
            returnAddress);

        // Restore last error WHILE reentrancy guard is still active.
        SetLastError(lastError);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgLog("!!! Hook dispatch crash: slot=%d func=%s code=0x%08X tid=%u",
            slotIndex, reg->funcName, GetExceptionCode(), GetCurrentThreadId());

        __try
        {
            retVal = CallOriginal(reg->trampoline, reg->paramCount, a1, a2, a3, a4, returnAddress);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    // ---- Clear re-entrancy guard ----
    DirectTlsSet(g_tlsReentrancy, NULL);

    return retVal;
}

// ============================================================
// Call Original via Trampoline
// ============================================================
// On x64, the calling convention passes first 4 args in registers (RCX, RDX, R8, R9).
// Additional args go on the stack. Since this is caller-clean, we can safely cast the
// trampoline to function pointers of varying arity.

typedef uint64_t (*PFN0)(void);
typedef uint64_t (*PFN1)(uint64_t);
typedef uint64_t (*PFN2)(uint64_t, uint64_t);
typedef uint64_t (*PFN3)(uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN4)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN7)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN9)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN10)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN11)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN12)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN13)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN14)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN15)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*PFN16)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t CallOriginal(void* trampoline, int paramCount,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, void* returnAddress)
{
    // For args > 4, read from caller's stack
    uint64_t a[MAX_PARAMS] = {a1, a2, a3, a4};
    if (paramCount > 4)
    {
        uint64_t* stackBase = (uint64_t*)returnAddress;
        for (int i = 4; i < paramCount && i < MAX_PARAMS; i++)
        {
            __try { a[i] = stackBase[1 + i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { a[i] = 0; }
        }
    }

    switch (paramCount)
    {
    case 0:  return ((PFN0)trampoline)();
    case 1:  return ((PFN1)trampoline)(a[0]);
    case 2:  return ((PFN2)trampoline)(a[0], a[1]);
    case 3:  return ((PFN3)trampoline)(a[0], a[1], a[2]);
    case 4:  return ((PFN4)trampoline)(a[0], a[1], a[2], a[3]);
    case 5:  return ((PFN5)trampoline)(a[0], a[1], a[2], a[3], a[4]);
    case 6:  return ((PFN6)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7:  return ((PFN7)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8:  return ((PFN8)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    case 9:  return ((PFN9)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
    case 10: return ((PFN10)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
    case 11: return ((PFN11)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
    case 12: return ((PFN12)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]);
    case 13: return ((PFN13)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12]);
    case 14: return ((PFN14)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13]);
    case 15: return ((PFN15)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14]);
    case 16: return ((PFN16)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    default:
        // Fallback for 0 or unexpected: call with 4 args (safe on x64 caller-clean)
        return ((PFN4)trampoline)(a1, a2, a3, a4);
    }
}

#elif defined(_M_IX86)

// ============================================================
// Call Original via Trampoline (x86)
// ============================================================
// On x86, __stdcall functions pop their arguments. We cast the trampoline
// to the correct __stdcall function pointer type based on paramCount.

typedef uint32_t (__stdcall *PFN32_0)(void);
typedef uint32_t (__stdcall *PFN32_1)(uint32_t);
typedef uint32_t (__stdcall *PFN32_2)(uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_3)(uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_4)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_5)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_6)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_7)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_8)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_9)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_10)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_11)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_12)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_13)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_14)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_15)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *PFN32_16)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

uint32_t CallOriginal32(void* trampoline, int paramCount, uint32_t* a)
{
    switch (paramCount)
    {
    case 0:  return ((PFN32_0)trampoline)();
    case 1:  return ((PFN32_1)trampoline)(a[0]);
    case 2:  return ((PFN32_2)trampoline)(a[0], a[1]);
    case 3:  return ((PFN32_3)trampoline)(a[0], a[1], a[2]);
    case 4:  return ((PFN32_4)trampoline)(a[0], a[1], a[2], a[3]);
    case 5:  return ((PFN32_5)trampoline)(a[0], a[1], a[2], a[3], a[4]);
    case 6:  return ((PFN32_6)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7:  return ((PFN32_7)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8:  return ((PFN32_8)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    case 9:  return ((PFN32_9)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
    case 10: return ((PFN32_10)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
    case 11: return ((PFN32_11)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
    case 12: return ((PFN32_12)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]);
    case 13: return ((PFN32_13)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12]);
    case 14: return ((PFN32_14)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13]);
    case 15: return ((PFN32_15)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14]);
    case 16: return ((PFN32_16)trampoline)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    default:
        return ((PFN32_4)trampoline)(a[0], a[1], a[2], a[3]);
    }
}

// ============================================================
// Generic Dispatch (x86)
// ============================================================
// Called from runtime-generated stubs via __cdecl convention.
// argPtr points to the first argument on the original caller's stack.

uint64_t __cdecl GenericDispatch32(int slotIndex, uint32_t* argPtr)
{
    HookRegistration* reg = &g_hookSlots[slotIndex];
    if (!reg->active || !reg->trampoline)
        return 0;

    // ---- Suppress during hook enable/disable ----
    if (g_suppressCapture)
    {
        return (uint64_t)CallOriginal32(reg->trampoline, reg->paramCount, argPtr);
    }

    // ---- Per-thread re-entrancy guard ----
    if (g_tlsReentrancy == TLS_OUT_OF_INDEXES)
    {
        return (uint64_t)CallOriginal32(reg->trampoline, reg->paramCount, argPtr);
    }
    if (DirectTlsGet(g_tlsReentrancy) != NULL)
    {
        return (uint64_t)CallOriginal32(reg->trampoline, reg->paramCount, argPtr);
    }
    DirectTlsSet(g_tlsReentrancy, (void*)1);

    LONG dispNum = InterlockedIncrement(&g_dispatchCount);
    if (dispNum <= 5)
    {
        DbgLog("[event] dispatch #%d: slot=%d func=%s tid=%u",
            dispNum, slotIndex, reg->funcName, GetCurrentThreadId());
    }

    // ---- Capture with full exception protection ----
    uint32_t retVal32 = 0;
    __try
    {
        LARGE_INTEGER tsStart;
        QueryPerformanceCounter(&tsStart);

        // Collect argument values (zero-extend uint32_t to uint64_t for wire protocol)
        uint64_t argValues[MAX_PARAMS] = {0};
        int nParams = reg->paramCount;
        for (int i = 0; i < nParams && i < MAX_PARAMS; i++)
        {
            __try { argValues[i] = (uint64_t)argPtr[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { argValues[i] = 0; }
        }

        // ---- Call original function ----
        retVal32 = CallOriginal32(reg->trampoline, reg->paramCount, argPtr);

        // ---- Capture post-call state ----
        DWORD lastError = GetLastError();

        LARGE_INTEGER tsEnd;
        QueryPerformanceCounter(&tsEnd);

        uint64_t durationQpc = (uint64_t)(tsEnd.QuadPart - tsStart.QuadPart);
        uint32_t threadId = GetCurrentThreadId();

        // Return address is at argPtr[-1] (one slot before first arg on x86 stack)
        void* returnAddress = (void*)*((uint32_t*)argPtr - 1);

        // ---- Serialize and send event ----
        SerializeAndSendEvent(
            slotIndex, threadId,
            (uint64_t)tsStart.QuadPart, durationQpc,
            (uint64_t)retVal32, lastError,
            argValues, nParams,
            returnAddress);

        SetLastError(lastError);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgLog("!!! Hook dispatch crash: slot=%d func=%s code=0x%08X tid=%u",
            slotIndex, reg->funcName, GetExceptionCode(), GetCurrentThreadId());

        __try
        {
            retVal32 = CallOriginal32(reg->trampoline, reg->paramCount, argPtr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    // ---- Clear re-entrancy guard ----
    DirectTlsSet(g_tlsReentrancy, NULL);

    return (uint64_t)retVal32;
}

#endif // _M_X64 / _M_IX86
