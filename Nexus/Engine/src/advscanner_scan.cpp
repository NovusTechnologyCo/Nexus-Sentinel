/**
 * @file advscanner_scan.cpp
 * @brief Advanced scanner: next scan, undo, reset, result queries, stats, and persistence.
 *
 * Implements the next-scan (filter existing results), undo (restore
 * previous result set), result pagination, statistics retrieval, and
 * binary save/load of scan results to disk.
 *
 * Core helpers and first-scan logic are in advscanner.cpp.
 */

#include "advscanner_internal.h"
#include <cstdio>

extern "C" {

/* ============================================================================
 * Next Scan & Undo/Reset
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AdvScanNext(
    NexusAdvScannerHandle scanner,
    const NexusScanConfig* config
) {
    if (!scanner || !config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (scanner->scanning) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (scanner->results.empty()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    /* Save undo state */
    scanner->undoStack.push_back(scanner->results);
    if (scanner->undoStack.size() > 10) {
        scanner->undoStack.pop_front();
    }

    scanner->scanning = true;
    scanner->scanStartTime = std::chrono::high_resolution_clock::now();
    scanner->cancelRequested = false;

    std::vector<ScanResult> newResults;
    size_t valueSize = GetValueSize(config->valueType, config);
    std::vector<uint8_t> buffer(valueSize);

    for (const auto& result : scanner->results) {
        if (scanner->cancelRequested) break;

        size_t bytesRead = 0;
        NexusResult res = Nexus_ReadMemory(scanner->process, result.address,
                                            buffer.data(), valueSize, &bytesRead);
        if (res != NEXUS_OK || bytesRead < valueSize) continue;

        if (CompareNextScan(&result.value, buffer.data(), config)) {
            ScanResult newRes;
            newRes.address = result.address;
            ExtractValue(buffer.data(), config->valueType, &newRes.value, valueSize);
            newResults.push_back(newRes);
        }
    }

    scanner->results = std::move(newResults);

    /* Update stats */
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = endTime - scanner->scanStartTime;
    scanner->stats.elapsedMs = elapsed.count();
    scanner->stats.resultsFound = scanner->results.size();
    scanner->stats.isComplete = 1;

    scanner->scanning = false;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanUndo(NexusAdvScannerHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (scanner->undoStack.empty()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    scanner->results = scanner->undoStack.back();
    scanner->undoStack.pop_back();
    scanner->stats.resultsFound = scanner->results.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanReset(NexusAdvScannerHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    scanner->cancelRequested = true;
    while (scanner->scanning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    scanner->results.clear();
    scanner->undoStack.clear();
    memset(&scanner->stats, 0, sizeof(scanner->stats));

    return NEXUS_OK;
}

/* ============================================================================
 * Result Queries & Management
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AdvScanGetResultCount(
    NexusAdvScannerHandle scanner,
    size_t* count
) {
    if (!scanner || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *count = scanner->results.size();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanGetResults(
    NexusAdvScannerHandle scanner,
    size_t offset,
    NexusScanResultEntry* results,
    size_t maxResults,
    size_t* resultCount
) {
    if (!scanner || !results || !resultCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t available = scanner->results.size();
    if (offset >= available) {
        *resultCount = 0;
        return NEXUS_OK;
    }

    size_t toCopy = std::min(maxResults, available - offset);
    for (size_t i = 0; i < toCopy; i++) {
        results[i].address = scanner->results[offset + i].address;
        results[i].currentValue = scanner->results[offset + i].value;
        results[i].previousValue = scanner->results[offset + i].value;
    }

    *resultCount = toCopy;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanRefreshValues(NexusAdvScannerHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t valueSize = GetValueSize(scanner->lastConfig.valueType, &scanner->lastConfig);
    std::vector<uint8_t> buffer(valueSize);

    for (auto& result : scanner->results) {
        size_t bytesRead = 0;
        if (Nexus_ReadMemory(scanner->process, result.address,
                              buffer.data(), valueSize, &bytesRead) == NEXUS_OK) {
            ExtractValue(buffer.data(), scanner->lastConfig.valueType, &result.value, valueSize);
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanGetStats(
    NexusAdvScannerHandle scanner,
    NexusScanStats* stats
) {
    if (!scanner || !stats) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *stats = scanner->stats;
    stats->resultsFound = scanner->results.size();

    if (scanner->scanning) {
        stats->bytesScanned = scanner->bytesScanned;
        stats->isComplete = 0;

        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = now - scanner->scanStartTime;
        stats->elapsedMs = elapsed.count();

        if (stats->elapsedMs > 0) {
            stats->scanSpeedMBps = (stats->bytesScanned / 1048576.0) /
                                    (stats->elapsedMs / 1000.0);
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanSetProgressCallback(
    NexusAdvScannerHandle scanner,
    NexusScanProgressCallback callback,
    void* userData
) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    scanner->progressCallback = callback;
    scanner->progressUserData = userData;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanCancel(NexusAdvScannerHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    scanner->cancelRequested = true;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanIsScanning(
    NexusAdvScannerHandle scanner,
    int32_t* inProgress
) {
    if (!scanner || !inProgress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *inProgress = scanner->scanning ? 1 : 0;
    return NEXUS_OK;
}

/* ============================================================================
 * Save/Load Results
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AdvScanSaveResults(
    NexusAdvScannerHandle scanner,
    const char* filePath
) {
    if (!scanner || !filePath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    FILE* f = nullptr;
    if (fopen_s(&f, filePath, "wb") != 0 || !f) return NEXUS_ERROR_UNKNOWN;

    /* Simple binary format: header + results */
    uint32_t magic = 0x4E535352; /* "NSSR" - Nexus Scan Save Results */
    uint32_t version = 1;
    size_t count = scanner->results.size();
    NexusScanValueType valueType = scanner->lastConfig.valueType;

    fwrite(&magic, sizeof(magic), 1, f);
    fwrite(&version, sizeof(version), 1, f);
    fwrite(&valueType, sizeof(valueType), 1, f);
    fwrite(&count, sizeof(count), 1, f);

    for (const auto& result : scanner->results) {
        fwrite(&result.address, sizeof(result.address), 1, f);
        fwrite(&result.value, sizeof(result.value), 1, f);
    }

    fclose(f);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanLoadResults(
    NexusAdvScannerHandle scanner,
    const char* filePath
) {
    if (!scanner || !filePath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    FILE* f = nullptr;
    if (fopen_s(&f, filePath, "rb") != 0 || !f) return NEXUS_ERROR_NOT_FOUND;

    uint32_t magic, version;
    NexusScanValueType valueType;
    size_t count;

    if (fread(&magic, sizeof(magic), 1, f) != 1 ||
        fread(&version, sizeof(version), 1, f) != 1 ||
        fread(&valueType, sizeof(valueType), 1, f) != 1 ||
        fread(&count, sizeof(count), 1, f) != 1) {
        fclose(f);
        return NEXUS_ERROR_UNKNOWN;
    }

    if (magic != 0x4E535352 || version != 1) {
        fclose(f);
        return NEXUS_ERROR_UNKNOWN;
    }

    /* Validate count to prevent DoS via unlimited resize */
    static const size_t MAX_RESULTS_LOAD = 100000000;
    if (count > MAX_RESULTS_LOAD) {
        fclose(f);
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    scanner->results.clear();
    try {
        scanner->results.resize(count);
    } catch (const std::bad_alloc&) {
        fclose(f);
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        if (fread(&scanner->results[i].address, sizeof(uint64_t), 1, f) != 1 ||
            fread(&scanner->results[i].value, sizeof(NexusScanValue), 1, f) != 1) {
            scanner->results.clear();
            fclose(f);
            return NEXUS_ERROR_UNKNOWN;
        }
    }

    scanner->lastConfig.valueType = valueType;
    scanner->stats.resultsFound = count;

    fclose(f);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanGetDefaultConfig(NexusScanConfig* config) {
    if (!config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(config, 0, sizeof(*config));
    config->valueType = NEXUS_SCAN_INT32;
    config->compareType = NEXUS_CMP_EXACT;
    config->options = NEXUS_SCANOPT_WRITABLE;
    config->alignment = 0; /* Auto */
    config->startAddress = 0;
    config->endAddress = 0;
    config->floatTolerance = 0.0001f;
    config->threadCount = 0; /* Auto */

    return NEXUS_OK;
}

} /* extern "C" */
