/**
 * @file trace_internal.h
 * @brief Internal header shared by trace.cpp and trace_classify.cpp.
 */

#pragma once

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <memory>
#include <unordered_map>

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

extern NexusResult Nexus_GetRawHandle(NexusProcessHandle handle, void** rawHandle);
extern NexusResult Nexus_ReadMemory(NexusProcessHandle handle, uint64_t address, void* buffer, size_t size, size_t* bytesRead);

/* ============================================================================
 * Internal Types
 * ============================================================================ */

struct TraceRegisterEntry {
    NexusTraceRegisters regs;
    uint64_t entryIndex;
};

struct TraceContext {
    NexusDebuggerHandle debugger;
    NexusProcessHandle process;
    HANDLE rawProcessHandle;

    // Configuration
    NexusTraceConfig config;
    uint32_t tracingThreadId;

    // State
    std::atomic<bool> isRunning;
    std::atomic<bool> shouldStop;
    uint64_t nextIndex;
    uint32_t currentCallDepth;

    // Ring buffer for entries
    std::deque<NexusTraceEntry> entries;
    std::vector<TraceRegisterEntry> registerSnapshots;

    // Statistics
    NexusTraceStats stats;

    std::mutex mutex;
};

/* ============================================================================
 * Global Trace Container
 * ============================================================================ */

extern std::mutex g_traceMutex;
extern std::unordered_map<void*, std::unique_ptr<TraceContext>> g_traces;

/* ============================================================================
 * Cross-File Function Prototypes (defined in trace_classify.cpp)
 * ============================================================================ */

bool IsCallInstruction(const uint8_t* bytes, size_t size);
bool IsRetInstruction(const uint8_t* bytes, size_t size);
bool IsBranchInstruction(const uint8_t* bytes, size_t size);
uint64_t GetTargetAddress(uint64_t rip, const uint8_t* bytes, size_t size);
size_t TraceGetInstructionLength(const uint8_t* bytes, size_t maxLen, bool is64Bit);
void DisassembleInstruction(uint64_t address, const uint8_t* bytes,
                            size_t size, char* output, size_t outputSize);
