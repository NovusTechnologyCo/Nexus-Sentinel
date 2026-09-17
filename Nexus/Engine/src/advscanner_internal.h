/**
 * @file advscanner_internal.h
 * @brief Internal header shared by advscanner.cpp and advscanner_scan.cpp.
 *
 * Defines the NexusAdvScanner structure (thread pool, result vectors,
 * undo stack, progress state) and declares comparison and worker
 * helper functions.
 */

#pragma once

#include "nexus_api.h"

#define NOMINMAX
#include <windows.h>
#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <cmath>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct ScanResult {
    uint64_t address;
    NexusScanValue value;
};

struct NexusAdvScanner {
    NexusProcessHandle process;
    std::vector<ScanResult> results;
    std::deque<std::vector<ScanResult>> undoStack;
    NexusScanConfig lastConfig;
    NexusScanStats stats;

    /* Progress callback */
    NexusScanProgressCallback progressCallback;
    void* progressUserData;

    /* Thread control */
    std::atomic<bool> scanning;
    std::atomic<bool> cancelRequested;
    std::atomic<uint64_t> bytesScanned;
    std::atomic<size_t> resultsFound;

    std::mutex resultsMutex;
    std::chrono::high_resolution_clock::time_point scanStartTime;

    NexusAdvScanner() : process(nullptr), progressCallback(nullptr),
                        progressUserData(nullptr), scanning(false),
                        cancelRequested(false), bytesScanned(0), resultsFound(0) {
        memset(&lastConfig, 0, sizeof(lastConfig));
        memset(&stats, 0, sizeof(stats));
    }
};

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- advscanner.cpp --- */
size_t GetValueSize(NexusScanValueType type, const NexusScanConfig* config = nullptr);
bool CompareNextScan(const NexusScanValue* oldVal, const void* newMem,
                     const NexusScanConfig* config);
void ExtractValue(const void* mem, NexusScanValueType type, NexusScanValue* outVal, size_t stringLen = 0);
