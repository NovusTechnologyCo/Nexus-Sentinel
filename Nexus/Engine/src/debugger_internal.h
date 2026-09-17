/**
 * @file debugger_internal.h
 * @brief Internal header shared by debugger.cpp and debugger_module.cpp.
 *
 * Defines the DebuggerContext structure (breakpoint storage, process
 * handle, debug-loop state), helper function prototypes, and common
 * includes for the debugger implementation.
 */

#pragma once

#include "nexus_api.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <memory>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

// Internal process context structure (must match process.cpp)
struct ProcessContext {
    HANDLE processHandle;
    DWORD processId;
    bool is32Bit;
};

// Internal breakpoint data
struct BreakpointData {
    NexusBreakpoint info;
    int hwRegister;     // -1 for software, 0-3 for DR0-DR3
    bool needsActivation; // For module-relative BPs that are resolved but not yet activated
};

// Debug event queue item
struct QueuedDebugEvent {
    DEBUG_EVENT winEvent;
    bool handled;
};

// Software breakpoint step-over state
struct StepOverState {
    uint64_t breakpointId;      // Which breakpoint we're stepping over
    uint64_t address;           // Address of the breakpoint
    uint8_t originalByte;       // Original byte to restore after step
};

// Debugger context
struct DebuggerContext {
    ProcessContext* process;
    DWORD processId;
    bool attached;
    bool detaching;

    std::unordered_map<uint64_t, BreakpointData> breakpoints;
    uint64_t nextBreakpointId;

    std::mutex mutex;
    std::queue<QueuedDebugEvent> eventQueue;
    std::mutex eventMutex;

    // Track which hardware registers are in use per thread
    std::unordered_map<DWORD, uint8_t> hwBpInUse; // Bitmask per thread

    // Pending single-step threads
    std::unordered_map<DWORD, bool> singleStepPending;

    // Software breakpoint step-over tracking (per thread)
    std::unordered_map<DWORD, StepOverState> stepOverPending;

    // Track if initial system breakpoint has been seen
    bool initialBreakpointSeen;
};

/* ============================================================================
 * Global State (defined in debugger.cpp)
 * ============================================================================ */

extern std::mutex g_debuggerMutex;
extern std::unordered_map<void*, std::unique_ptr<DebuggerContext>> g_debuggers;

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- debugger.cpp --- */
bool ReadMem(HANDLE process, uint64_t address, void* buffer, size_t size);
bool WriteMem(HANDLE process, uint64_t address, const void* buffer, size_t size);
uint64_t FindModuleBase(HANDLE hProcess, DWORD processId, const wchar_t* moduleName);
void ExtractModuleName(const wchar_t* fullPath, wchar_t* moduleName, size_t maxLen);
bool FindModuleForAddress(DWORD processId, uint64_t address,
                          wchar_t* moduleName, size_t nameLen, uint64_t* moduleBase);
void ApplyHwBreakpointToAllThreads(DebuggerContext* dbg, BreakpointData& bp, bool enable);
int FindFreeHwRegister(DebuggerContext* dbg);

/* --- debugger_module.cpp --- */
void OnModuleLoad(DebuggerContext* dbg, uint64_t moduleBase, const wchar_t* modulePath);
void OnModuleUnload(DebuggerContext* dbg, uint64_t moduleBase);
