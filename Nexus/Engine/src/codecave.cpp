/**
 * @file codecave.cpp
 * @brief Code-cave scanner public API: default config, scan, and find-best-cave.
 *
 * Provides the public entry points for code-cave scanning: default
 * configuration, full scan with statistics, and a convenience
 * find-best-cave function that selects the optimal cave for a
 * given size and proximity requirement.
 *
 * The scan implementation is in codecave_scan.cpp.
 */

#include "codecave_internal.h"

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetCodeCaveScanDefaultConfig(
    NexusCodeCaveScanConfig* config
) {
    if (!config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(config, 0, sizeof(NexusCodeCaveScanConfig));
    config->minSize = 16;
    config->maxSize = 0; /* Unlimited */
    config->fillType = NEXUS_CAVE_ZEROS;
    config->options = NEXUS_CAVE_OPT_EXECUTABLE | NEXUS_CAVE_OPT_MODULE_ONLY;
    config->startAddress = 0;
    config->endAddress = 0;
    config->nearAddress = 0;
    config->maxDistance = 0;
    /* moduleFilter already zeroed */

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ScanCodeCavesEx(
    NexusProcessHandle process,
    const NexusCodeCaveScanConfig* config,
    NexusCodeCaveEntry* results,
    size_t maxResults,
    size_t* resultCount,
    NexusCodeCaveScanStats* stats
) {
    if (!process || !config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* handleData = reinterpret_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = handleData->hProcess;

    /* Initialize stats */
    NexusCodeCaveScanStats localStats = {};
    auto startTime = std::chrono::high_resolution_clock::now();

    /* Collect results in a vector for sorting/filtering */
    std::vector<NexusCodeCaveEntry> foundCaves;
    size_t effectiveMax = results ? maxResults : SIZE_MAX;

    /* Determine address space bounds */
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uint64_t minAddr = reinterpret_cast<uint64_t>(sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr = handleData->is32Bit ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

    /* Walk memory regions */
    uint64_t address = minAddr;
    MEMORY_BASIC_INFORMATION mbi;

    while (address < maxAddr) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }

        if (RegionMatchesOptions(mbi, config->options)) {
            localStats.regionsScanned++;
            ScanRegionForCaves(hProcess, mbi, config, foundCaves, effectiveMax, &localStats);
        }

        /* Move to next region */
        uint64_t nextAddr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextAddr <= address) break; /* Prevent infinite loop */
        address = nextAddr;
    }

    /* Sort by near-address preference if requested */
    if ((config->options & NEXUS_CAVE_OPT_NEAR_ADDRESS) && config->nearAddress > 0) {
        std::sort(foundCaves.begin(), foundCaves.end(),
            [&config](const NexusCodeCaveEntry& a, const NexusCodeCaveEntry& b) {
                int64_t distA = static_cast<int64_t>(a.address) - static_cast<int64_t>(config->nearAddress);
                int64_t distB = static_cast<int64_t>(b.address) - static_cast<int64_t>(config->nearAddress);
                if (distA < 0) distA = -distA;
                if (distB < 0) distB = -distB;
                return distA < distB;
            });
    }

    /* Calculate elapsed time */
    auto endTime = std::chrono::high_resolution_clock::now();
    localStats.elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    /* Copy results to output buffer */
    size_t copyCount = 0;
    if (results && maxResults > 0) {
        copyCount = (foundCaves.size() < maxResults) ? foundCaves.size() : maxResults;
        memcpy(results, foundCaves.data(), copyCount * sizeof(NexusCodeCaveEntry));
    }

    if (resultCount) {
        *resultCount = foundCaves.size();
    }

    if (stats) {
        *stats = localStats;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ScanCodeCaves(
    NexusProcessHandle process,
    const NexusCodeCaveScanConfig* config,
    NexusCodeCaveEntry* results,
    size_t maxResults,
    size_t* resultCount
) {
    return Nexus_ScanCodeCavesEx(process, config, results, maxResults, resultCount, nullptr);
}

NEXUS_API NexusResult Nexus_FindBestCodeCave(
    NexusProcessHandle process,
    size_t requiredSize,
    uint64_t nearAddress,
    int64_t maxDistance,
    NexusCodeCaveEntry* cave
) {
    if (!process || !cave || requiredSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Create config optimized for finding a single suitable cave */
    NexusCodeCaveScanConfig config;
    Nexus_GetCodeCaveScanDefaultConfig(&config);
    config.minSize = requiredSize;
    config.fillType = NEXUS_CAVE_ZEROS; /* Zeros are most common */

    if (nearAddress > 0) {
        config.options |= NEXUS_CAVE_OPT_NEAR_ADDRESS;
        config.nearAddress = nearAddress;
        config.maxDistance = maxDistance > 0 ? maxDistance : INT64_MAX;
    }

    /* Scan for caves */
    std::vector<NexusCodeCaveEntry> results(100); /* Get up to 100 candidates */
    size_t foundCount = 0;

    NexusResult res = Nexus_ScanCodeCaves(process, &config, results.data(), results.size(), &foundCount);
    if (res != NEXUS_OK) {
        return res;
    }

    if (foundCount == 0) {
        /* Try NOPs if zeros didn't find anything */
        config.fillType = NEXUS_CAVE_NOPS;
        res = Nexus_ScanCodeCaves(process, &config, results.data(), results.size(), &foundCount);
        if (res != NEXUS_OK) {
            return res;
        }
    }

    if (foundCount == 0) {
        /* Try INT3s as last resort */
        config.fillType = NEXUS_CAVE_INTS;
        res = Nexus_ScanCodeCaves(process, &config, results.data(), results.size(), &foundCount);
        if (res != NEXUS_OK) {
            return res;
        }
    }

    if (foundCount == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    /* Results are already sorted by distance if nearAddress was specified */
    /* Find the first one that meets size requirement (they all should, but verify) */
    for (size_t i = 0; i < foundCount && i < results.size(); i++) {
        if (results[i].size >= requiredSize) {
            *cave = results[i];
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}
