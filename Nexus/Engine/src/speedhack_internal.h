/**
 * @file speedhack_internal.h
 * @brief Internal header shared by speedhack.cpp and speedhack_hook.cpp.
 */

#pragma once

#include "nexus_api.h"
#include "ldisasm.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstring>
#include <cmath>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct NexusProcessHandleData {
    uint32_t magic;
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;
    NexusProcessAccess actualAccess;
};

#pragma pack(push, 1)
struct SpeedhackSharedData {
    double speedMultiplier;
    uint32_t enabled;
    uint32_t padding;
    int64_t initialQPC;
    int64_t virtualOffset;
    uint64_t hookCount;
};
#pragma pack(pop)

static_assert(offsetof(SpeedhackSharedData, speedMultiplier) == 0, "speedMultiplier offset");
static_assert(offsetof(SpeedhackSharedData, enabled) == 8, "enabled offset");
static_assert(offsetof(SpeedhackSharedData, initialQPC) == 16, "initialQPC offset");
static_assert(offsetof(SpeedhackSharedData, virtualOffset) == 24, "virtualOffset offset");
static_assert(offsetof(SpeedhackSharedData, hookCount) == 32, "hookCount offset");

struct SpeedhackState {
    NexusProcessHandleData* process;
    uint32_t method;
    void* sharedMemory;
    void* hookCode;
    size_t hookCodeSize;
    bool initialized;
    bool isEnabled;

    uint8_t originalBytes[32];
    size_t stolenBytesCount;

    uint64_t qpcAddressInTarget;
};

/* ============================================================================
 * Cross-File Function Prototypes (defined in speedhack_hook.cpp)
 * ============================================================================ */

uint64_t GetRemoteFunctionAddress(DWORD pid, const wchar_t* moduleName,
                                  const char* functionName, bool is32BitTarget);

size_t Build32BitHook(uint8_t* buffer, size_t bufferSize,
                      uint64_t hookBaseAddr, uint64_t sharedDataAddr,
                      uint64_t originalFuncAddr, const uint8_t* stolenBytes,
                      size_t stolenBytesCount);

size_t Build64BitHook(uint8_t* buffer, size_t bufferSize,
                      uint64_t hookBaseAddr, uint64_t sharedDataAddr,
                      uint64_t originalFuncAddr, const uint8_t* stolenBytes,
                      size_t stolenBytesCount);
