/**
 * @file codecave_internal.h
 * @brief Internal header shared by codecave.cpp and codecave_scan.cpp.
 */

#pragma once

#include "nexus_api.h"
#include "process_internal.h"

#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cstring>

/* ============================================================================
 * Cross-File Function Prototypes (defined in codecave_scan.cpp)
 * ============================================================================ */

bool RegionMatchesOptions(const MEMORY_BASIC_INFORMATION& mbi, uint32_t options);

void ScanRegionForCaves(
    HANDLE hProcess,
    const MEMORY_BASIC_INFORMATION& mbi,
    const NexusCodeCaveScanConfig* config,
    std::vector<NexusCodeCaveEntry>& results,
    size_t maxResults,
    NexusCodeCaveScanStats* stats);
