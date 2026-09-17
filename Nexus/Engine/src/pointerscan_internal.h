/**
 * @file pointerscan_internal.h
 * @brief Internal header shared by pointerscan.cpp and pointerscan_scan.cpp.
 */

#pragma once

#include "nexus_api.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <fstream>

/* ============================================================================
 * NT Structures
 * ============================================================================ */

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationThreadFunc)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

/* ============================================================================
 * Validation Limits
 * ============================================================================ */

static const size_t MAX_POINTER_RESULTS_LOAD = 100000000;  // 100M results max
static const size_t MAX_REVERSE_MAP_ENTRIES = 50000000;     // 50M entries max

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct ProcessContext {
    HANDLE processHandle;
    DWORD processId;
    bool is32Bit;
};

struct ModuleRange {
    uint64_t base;
    uint64_t end;
    std::wstring name;
    std::wstring path;
    bool isSystemModule;
};

struct ThreadStackRange {
    uint64_t stackBase;
    uint64_t stackLimit;
    uint32_t threadId;
    std::wstring name;
};

struct PointerEntry {
    uint64_t address;
    uint64_t target;
};

struct PointerScanContext {
    ProcessContext* process;
    NexusPointerScanParams params;

    std::vector<ModuleRange> modules;
    std::vector<ThreadStackRange> threadStacks;

    std::vector<NexusPointerPath> results;
    std::mutex resultsMutex;
    size_t maxResults;
    std::atomic<size_t> resultCount;

    std::unordered_map<uint64_t, std::vector<uint64_t>> reversePointerMap;
    std::vector<std::pair<uint64_t, uint64_t>> validRegions;

    std::unordered_map<uint64_t, uint32_t> globalVisitCount;
    std::mutex visitedMutex;

    std::atomic<uint64_t> addressesScanned;
    std::atomic<uint64_t> addressesTotal;
    std::atomic<uint32_t> currentLevel;
    std::atomic<bool> isComplete;
    std::atomic<bool> cancelled;

    std::thread workerThread;
    bool threadStarted;
};

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- pointerscan_scan.cpp --- */
bool PtrScanReadMem(HANDLE process, uint64_t address, void* buffer, size_t size);
void ScanWorker(PointerScanContext* ctx);
