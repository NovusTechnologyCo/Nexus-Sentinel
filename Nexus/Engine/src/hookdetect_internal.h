/**
 * @file hookdetect_internal.h
 * @brief Internal header shared by hookdetect.cpp and hookdetect_scan.cpp.
 *
 * Defines hook-result structures, scan-context state, and cross-file
 * helper prototypes for the hook-detection subsystem.
 */

#pragma once

#include "../include/nexus_hook.h"
#include "../include/nexus_api.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <cstring>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

// Must match process.cpp
struct NexusProcessHandleData {
    uint32_t magic;
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;
    NexusProcessAccess actualAccess;
};

// Internal storage for scan results
struct HookScanContext {
    std::vector<NexusHookInfo> hooks;
    std::vector<NexusInlineHookInfo> inlineHooks;
    std::vector<NexusIatHookInfo> iatHooks;
    NexusHookScanResult stats;
    std::mutex mutex;
};

/* ============================================================================
 * Global State (defined in hookdetect.cpp)
 * ============================================================================ */

extern HookScanContext g_scanContext;
extern std::mutex g_contextMutex;

/* ============================================================================
 * Constants
 * ============================================================================ */

static const DWORD MAX_EXPORTS = 100000;
static const DWORD MAX_IMPORTS = 100000;
static const LONG MAX_E_LFANEW = 0x10000000;

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- hookdetect.cpp --- */
bool ReadProcessMem(HANDLE process, uint64_t address, void* buffer, size_t size);
bool GetModuleForAddress(HANDLE process, uint64_t address, wchar_t* moduleName,
                         size_t nameLen, uint64_t* moduleBase);
bool GetModulePath(HANDLE process, uint64_t moduleBase, wchar_t* path, size_t pathLen);
bool ReadDiskBytes(const wchar_t* modulePath, uint64_t moduleBase, uint32_t rva,
                   uint8_t* buffer, size_t size, bool is64Bit);
