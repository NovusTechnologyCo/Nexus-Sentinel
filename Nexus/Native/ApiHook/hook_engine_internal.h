/**
 * @file hook_engine_internal.h
 * @brief Internal shared state for the hook engine implementation files
 *
 * This header exposes the globals, TLS helpers, and forward declarations needed
 * by the split implementation files (hook_engine.cpp, hook_blacklist.cpp,
 * hook_dispatch.cpp, hook_events.cpp). It is NOT part of the public API.
 *
 * All globals are defined in hook_engine.cpp and declared extern here.
 */
#pragma once

#include "hook_engine.h"
#include "protocol.h"
#include "pipe_client.h"

#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ---- DbgLog from dllmain.cpp (uses ntdll direct, safe to call from hooks) ----
extern "C" void DbgLog(const char* fmt, ...);

// ---- ntdll I/O types and function pointers (shared by pipe_client.cpp, dllmain.cpp) ----
// These bypass hooked kernel32 ReadFile/WriteFile to prevent infinite recursion
// when hooked APIs send events.

typedef struct _HOOK_IO_STATUS_BLOCK {
    union {
        LONG Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} HOOK_IO_STATUS_BLOCK;

typedef LONG (NTAPI *PFN_NtWriteFile)(
    HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
    HOOK_IO_STATUS_BLOCK* IoStatusBlock, const void* Buffer, ULONG Length,
    LARGE_INTEGER* ByteOffset, ULONG* Key);

typedef LONG (NTAPI *PFN_NtReadFile)(
    HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
    HOOK_IO_STATUS_BLOCK* IoStatusBlock, void* Buffer, ULONG Length,
    LARGE_INTEGER* ByteOffset, ULONG* Key);

typedef LONG (NTAPI *PFN_NtFlushBuffersFile)(
    HANDLE FileHandle, HOOK_IO_STATUS_BLOCK* IoStatusBlock);

// ---- Shared globals (defined in hook_engine.cpp) ----

extern HookRegistration* g_hookSlots;
extern int g_maxSlots;
extern int g_nextSlot;
extern bool g_initialized;

extern DWORD g_tlsReentrancy;
extern DWORD g_tlsSendBuffer;
extern DWORD g_tlsReturnCapture;

extern volatile bool g_suppressCapture;
extern bool g_useJmpMode;
extern uint8_t* g_stubBlock;

extern LARGE_INTEGER g_qpcFrequency;

// ---- Diagnostic counters ----
extern volatile LONG g_dispatchCount;
extern volatile LONG g_enqueueCount;
extern volatile LONG g_drainCount;
extern volatile LONG g_dropCount;

// ---- TLS inline helpers ----
// CRITICAL: Cannot use TlsGetValue/TlsSetValue (kernel32 -- may be hooked -> recursion).
// Cannot use __declspec(thread) (fails on pre-existing threads in packaged/UWP apps).
// Solution: TlsAlloc during init (before hooks enabled), then read/write via TEB directly.

#ifdef _M_X64
#define TEB_TLS_SLOTS_OFFSET       0x1480   // TEB->TlsSlots[64] on x64
#define TEB_TLS_EXPANSION_OFFSET   0x1780   // TEB->TlsExpansionSlots on x64
static __forceinline char* GetTebPtr(void) { return (char*)__readgsqword(0x30); }
#elif defined(_M_IX86)
#define TEB_TLS_SLOTS_OFFSET       0x0E10   // TEB->TlsSlots[64] on x86
#define TEB_TLS_EXPANSION_OFFSET   0x0F94   // TEB->TlsExpansionSlots on x86
static __forceinline char* GetTebPtr(void) { return (char*)__readfsdword(0x18); }
#endif

#define TLS_MINIMUM_AVAILABLE      64

static __forceinline void* DirectTlsGet(DWORD index)
{
    char* teb = GetTebPtr();
    if (index < TLS_MINIMUM_AVAILABLE)
        return *(void**)(teb + TEB_TLS_SLOTS_OFFSET + index * sizeof(void*));
    void** expansion = *(void***)(teb + TEB_TLS_EXPANSION_OFFSET);
    if (!expansion) return NULL;
    return expansion[index - TLS_MINIMUM_AVAILABLE];
}

static __forceinline void DirectTlsSet(DWORD index, void* value)
{
    char* teb = GetTebPtr();
    if (index < TLS_MINIMUM_AVAILABLE)
        *(void**)(teb + TEB_TLS_SLOTS_OFFSET + index * sizeof(void*)) = value;
    else
    {
        void** expansion = *(void***)(teb + TEB_TLS_EXPANSION_OFFSET);
        if (expansion)
            expansion[index - TLS_MINIMUM_AVAILABLE] = value;
    }
}

// ---- Event ring buffer constants ----
#define EVENT_RING_SLOTS  4096
#define EVENT_SLOT_SIZE   4096   // max serialized event size per slot

struct EventRingSlot
{
    volatile LONG ready;  // 0 = empty, 1 = filled
    uint32_t len;
    uint8_t data[EVENT_SLOT_SIZE];
};

extern EventRingSlot* g_eventRing;
extern volatile LONG g_ringHead;
extern volatile LONG g_ringTail;
extern HANDLE g_hDrainThread;
extern HANDLE g_hDrainEvent;
extern volatile bool g_drainRunning;

// ---- Stub size (shared between hook_engine.cpp and hook_engine_stubs.cpp) ----
#ifdef _M_X64
#define STUB_SIZE 64
#elif defined(_M_IX86)
#define STUB_SIZE 32
#endif

// ---- VEH address map constants and types (hook_engine_veh.cpp) ----
#define ADDR_MAP_SIZE 32768  // power of 2, must be > 2x max hooks
typedef struct { void* addr; int slot; } AddrMapEntry;

// ---- VEH handler method tracking ----
typedef enum { VEH_METHOD_NONE, VEH_METHOD_API, VEH_METHOD_MANUAL, VEH_METHOD_UNHANDLED } VehMethodType;

// ---- VEH list entry layout (manual insertion) ----
// Memory layout of a VEH list entry
// x64: 40 bytes (ListEntry=16 + ListLock=8 + RefCount=4 + pad=4 + EncodedHandler=8)
// x86: 20 bytes (ListEntry=8  + ListLock=4 + RefCount=4 + EncodedHandler=4)
#pragma pack(push, 8)
typedef struct {
    LIST_ENTRY ListEntry;       // 0x00
    PVOID      ListLock;        // x64: 0x10, x86: 0x08
    ULONG      RefCount;        // x64: 0x18, x86: 0x0C
#ifdef _M_X64
    ULONG      _pad;            // 0x1C (alignment, x64 only)
#endif
    PVOID      EncodedHandler;  // x64: 0x20, x86: 0x10
} VEH_ENTRY;
#pragma pack(pop)

// Offset from RTL_VECTORED_HANDLER_LIST base to LIST_ENTRY
// x64: SRWLOCK is 8 bytes -> LIST_ENTRY at offset 8
// x86: SRWLOCK is 4 bytes -> LIST_ENTRY at offset 4
#ifdef _M_X64
#define VEH_LIST_HEAD_OFFSET  8
#else
#define VEH_LIST_HEAD_OFFSET  4
#endif

// ---- VEH globals (defined in hook_engine_veh.cpp) ----
extern PVOID g_vehHandle;
extern VehMethodType g_vehMethod;

// ntdll VEH function pointers (defined in hook_engine_veh.cpp)
typedef PVOID (NTAPI *PFN_RtlAddVectoredExceptionHandler_t)(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler);
typedef ULONG (NTAPI *PFN_RtlRemoveVectoredExceptionHandler_t)(PVOID VectoredHandlerHandle);
extern PFN_RtlAddVectoredExceptionHandler_t g_pfnRtlAddVEH;
extern PFN_RtlRemoveVectoredExceptionHandler_t g_pfnRtlRemoveVEH;

// ---- Forward declarations for cross-file calls ----

// Serializes event and enqueues to ring buffer (hook_events.cpp)
void SerializeAndSendEvent(int slotIndex, uint32_t threadId,
    uint64_t timestampQpc, uint64_t durationQpc,
    uint64_t returnValue, uint32_t lastError,
    uint64_t* argValues, int paramCount,
    void* returnAddress);

// Enqueue raw event data into the ring buffer (hook_events.cpp)
void EventQueue_Enqueue(const uint8_t* data, uint32_t len);

// Drain thread entry point (hook_events.cpp)
DWORD WINAPI DrainThreadProc(LPVOID param);

// Blacklist check (hook_blacklist.cpp)
bool IsBlacklisted(const char* funcName);

// Call original function via trampoline (hook_dispatch.cpp)
#ifdef _M_X64
uint64_t CallOriginal(void* trampoline, int paramCount,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, void* returnAddress);
#elif defined(_M_IX86)
uint32_t CallOriginal32(void* trampoline, int paramCount, uint32_t* argPtr);
#endif

// Runtime stub generation (hook_engine_stubs.cpp)
#ifdef _M_X64
void* CreateStub64(int slotIndex);
#elif defined(_M_IX86)
void* CreateStub32(int slotIndex, int paramCount);
#endif

// VEH backend (hook_engine_veh.cpp)
void AddrMap_Insert(void* addr, int slot);
bool Veh_Init(int maxHooks);
void Veh_Shutdown(void);
// Veh_CreateReturnStub -- disabled (return capture subsystem wrapped in #if 0)
int Veh_ArmAll(void);
void Veh_DisarmAll(void);
void VehRemove_ManualEntry(void);
void Veh_GetDiagnostics(int* outVehHits, int* outVehMisses, int* outVehNonBp, int* outUnhandledCalls);
uint8_t* Veh_GetSavedBytes(void);
LONG CALLBACK VehHookHandler(EXCEPTION_POINTERS* ep);
LONG WINAPI UnhandledHookFilter(EXCEPTION_POINTERS* ep);
