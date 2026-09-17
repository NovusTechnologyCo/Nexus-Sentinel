/**
 * @file stackwalk_internal.h
 * @brief Internal header shared by stackwalk.cpp and stackwalk_walk.cpp.
 */

#pragma once

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstring>
#include <algorithm>
#include <memory>
#include <unordered_map>

#pragma comment(lib, "dbghelp.lib")

/* Forward declarations from other modules */
extern NexusResult Nexus_ReadMemory(NexusProcessHandle handle, uint64_t address, void* buffer, size_t size, size_t* bytesRead);
extern NexusResult Nexus_EnumerateModules(NexusProcessHandle handle, NexusModuleInfo* buffer, size_t bufferCount, size_t* moduleCount);
extern NexusResult Nexus_EnumerateThreads(NexusProcessHandle handle, NexusThreadInfo* buffer, size_t bufferCount, size_t* threadCount);
extern NexusResult Nexus_GetRawHandle(NexusProcessHandle handle, void** rawHandle);
extern NexusResult Nexus_GetProcessInfo(NexusProcessHandle handle, NexusProcessInfo* info);

/* ============================================================================
 * Internal Types
 * ============================================================================ */

struct ModuleCache {
    uint64_t baseAddress;
    uint64_t size;
    std::wstring name;
    std::wstring path;
};

struct StackWalkerContext {
    NexusProcessHandle process;
    HANDLE rawHandle;
    bool is32BitProcess;

    std::vector<ModuleCache> modules;
    bool modulesCached;

    bool symbolsInitialized;

    std::mutex mutex;
};

/* Global container for stack walker ownership */
extern std::mutex g_stackWalkerMutex;
extern std::unordered_map<void*, std::unique_ptr<StackWalkerContext>> g_stackWalkers;

/* ============================================================================
 * Cross-File Function Prototypes (defined in stackwalk_walk.cpp)
 * ============================================================================ */

void StackResolveSymbolForFrame(StackWalkerContext* ctx, uint64_t address,
                                NexusStackFrame* frame, uint32_t flags);

NexusResult StackWalkImpl64(StackWalkerContext* ctx, CONTEXT* context,
                            uint32_t flags, NexusStackFrame* frames,
                            size_t maxFrames, size_t* frameCount);

#ifdef _WIN64
NexusResult StackWalkImpl32(StackWalkerContext* ctx, WOW64_CONTEXT* context,
                            uint32_t flags, NexusStackFrame* frames,
                            size_t maxFrames, size_t* frameCount);
#endif
