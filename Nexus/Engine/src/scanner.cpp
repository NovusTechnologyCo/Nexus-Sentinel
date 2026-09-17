/**
 * @file scanner.cpp
 * @brief Basic memory scanner: create/destroy, first/next scan, progress, results, and refresh.
 *
 * Implements the simple scan workflow: create a session, perform a first
 * scan to snapshot memory and find matching values, then iteratively
 * narrow results with next-scan comparisons (increased, decreased,
 * changed, unchanged, exact, range, etc.).
 *
 * Pattern parsing and matching helpers live in scanner_scan.cpp.
 */

#include "scanner_internal.h"

/* ============================================================================
 * Scanner API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ScanCreate(
    NexusProcessHandle handle,
    NexusScanHandle* scan
) {
    if (!handle || !scan) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = new NexusScanData();
    scanData->processHandle = handle;

    *scan = scanData;
    return NEXUS_OK;
}

NEXUS_API void Nexus_ScanDestroy(NexusScanHandle scan) {
    if (scan) {
        auto* scanData = static_cast<NexusScanData*>(scan);
        delete scanData;
    }
}

NEXUS_API NexusResult Nexus_ScanFirst(
    NexusScanHandle scan,
    const NexusScanParams* params
) {
    if (!scan || !params) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);

    /* Reset state */
    scanData->results.clear();
    scanData->hasFirstScan = false;
    scanData->isComplete = false;
    scanData->wasCancelled = false;
    scanData->bytesScanned = 0;
    scanData->regionsScanned = 0;

    scanData->valueType = params->valueType;
    scanData->caseSensitive = (params->flags & NEXUS_SCAN_FLAG_CASE_SENSITIVE) != 0;

    /* Handle value size based on type */
    switch (params->valueType) {
        case NEXUS_VALUE_STRING:
            if (params->value.stringValue.data == nullptr) {
                scanData->isComplete = true;
                return NEXUS_ERROR_INVALID_PARAMETER;
            }
            scanData->searchString = std::string(
                params->value.stringValue.data,
                params->value.stringValue.length > 0
                    ? params->value.stringValue.length
                    : strlen(params->value.stringValue.data)
            );
            scanData->valueSize = static_cast<uint32_t>(scanData->searchString.length());
            break;

        case NEXUS_VALUE_WSTRING:
            if (params->value.stringValue.data == nullptr) {
                scanData->isComplete = true;
                return NEXUS_ERROR_INVALID_PARAMETER;
            }
            {
                const wchar_t* wstr = reinterpret_cast<const wchar_t*>(params->value.stringValue.data);
                size_t wlen = params->value.stringValue.length > 0
                    ? params->value.stringValue.length / sizeof(wchar_t)
                    : wcslen(wstr);
                scanData->searchWString = std::wstring(wstr, wlen);
                scanData->valueSize = static_cast<uint32_t>(scanData->searchWString.length() * sizeof(wchar_t));
            }
            break;

        case NEXUS_VALUE_AOB:
            if (params->value.stringValue.data == nullptr) {
                scanData->isComplete = true;
                return NEXUS_ERROR_INVALID_PARAMETER;
            }
            {
                size_t patternLen = params->value.stringValue.length > 0
                    ? params->value.stringValue.length
                    : strlen(params->value.stringValue.data);
                if (!ParseAOBPattern(params->value.stringValue.data, patternLen, scanData->aobPattern)) {
                    scanData->isComplete = true;
                    return NEXUS_ERROR_INVALID_PARAMETER;
                }
                scanData->valueSize = static_cast<uint32_t>(scanData->aobPattern.size());
            }
            break;

        default:
            scanData->valueSize = GetValueSize(params->valueType);
            break;
    }

    uint32_t alignment = params->alignment;
    bool useLastDigits = (params->flags & NEXUS_SCAN_FLAG_LAST_DIGITS) != 0;
    uint64_t lastDigitsMask = 0;
    uint64_t lastDigitsValue = 0;

    if (useLastDigits && alignment > 0) {
        lastDigitsValue = alignment;

        lastDigitsMask = 0xF;
        while (lastDigitsMask < alignment && lastDigitsMask < 0xFFFFFFFF) {
            lastDigitsMask = (lastDigitsMask << 4) | 0xF;
        }

        alignment = 1;
    } else if (alignment == 0) {
        alignment = (params->flags & NEXUS_SCAN_FLAG_ALIGNED)
            ? GetDefaultAlignment(params->valueType)
            : 1;
    }

    /* Capture memory snapshot */
    NexusMemorySnapshot snapshot = nullptr;
    uint32_t snapshotFlags = NEXUS_SNAPSHOT_SCANNABLE;

    if (params->flags & NEXUS_SCAN_FLAG_WRITABLE) {
        snapshotFlags |= NEXUS_SNAPSHOT_WRITABLE;
    }
    if (params->flags & NEXUS_SCAN_FLAG_EXECUTABLE) {
        snapshotFlags |= NEXUS_SNAPSHOT_EXECUTABLE;
    }

    NexusResult res = Nexus_CaptureMemoryMap(scanData->processHandle, snapshotFlags, &snapshot);
    if (res != NEXUS_OK) {
        scanData->isComplete = true;
        return res;
    }

    /* Get snapshot stats */
    NexusSnapshotStats stats;
    Nexus_GetSnapshotStats(snapshot, &stats);
    scanData->bytesTotal = stats.totalBytes;
    scanData->regionsTotal = stats.regionCount;

    /* Reserve space for results (estimate) */
    scanData->results.reserve(1000000);  /* 1M initial capacity */

    /* Allocate read buffer */
    const size_t CHUNK_SIZE = 64 * 1024;  /* 64KB chunks */
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    /* Process each region */
    for (size_t regionIdx = 0; regionIdx < stats.regionCount; regionIdx++) {
        if (scanData->wasCancelled) {
            break;
        }

        NexusMemoryRegionEx region;
        if (Nexus_GetSnapshotRegion(snapshot, regionIdx, &region) != NEXUS_OK) {
            continue;
        }

        /* Skip non-readable regions */
        if (region.isGuard) {
            continue;
        }

        uint64_t regionAddr = region.baseAddress;
        uint64_t regionEnd = regionAddr + region.size;
        uint64_t regionBytesScanned = 0;

        while (regionAddr < regionEnd && !scanData->wasCancelled) {
            size_t toRead = static_cast<size_t>(
                std::min(static_cast<uint64_t>(CHUNK_SIZE), regionEnd - regionAddr)
            );

            size_t bytesRead = 0;
            res = Nexus_ReadMemory(scanData->processHandle, regionAddr, buffer.data(), toRead, &bytesRead);

            if (res == NEXUS_OK || res == NEXUS_ERROR_PARTIAL_READ) {
                /* Scan this chunk */
                uint64_t scanEnd = bytesRead - scanData->valueSize;

                for (size_t offset = 0; offset <= scanEnd; offset += alignment) {
                    uint64_t addr = regionAddr + offset;

                    /* Skip if using LastDigits mode and address doesn't match pattern */
                    if (useLastDigits && (addr & lastDigitsMask) != lastDigitsValue) {
                        continue;
                    }

                    uint8_t* valuePtr = buffer.data() + offset;

                    bool match = false;

                    switch (params->valueType) {
                        case NEXUS_VALUE_INT8: {
                            int8_t val = ReadValueFromBuffer<int8_t>(valuePtr);
                            match = CompareValues<int64_t>(val, params->value.intValue, params->valueMax.intValueMax,
                                                           params->scanType, 0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_INT16: {
                            int16_t val = ReadValueFromBuffer<int16_t>(valuePtr);
                            match = CompareValues<int64_t>(val, params->value.intValue, params->valueMax.intValueMax,
                                                           params->scanType, 0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_INT32: {
                            int32_t val = ReadValueFromBuffer<int32_t>(valuePtr);
                            match = CompareValues<int64_t>(val, params->value.intValue, params->valueMax.intValueMax,
                                                           params->scanType, 0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_INT64: {
                            int64_t val = ReadValueFromBuffer<int64_t>(valuePtr);
                            match = CompareValues<int64_t>(val, params->value.intValue, params->valueMax.intValueMax,
                                                           params->scanType, 0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_FLOAT32: {
                            float val = ReadValueFromBuffer<float>(valuePtr);
                            match = CompareValues<double>(val, params->value.floatValue, params->valueMax.floatValueMax,
                                                          params->scanType, 0.0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_FLOAT64: {
                            double val = ReadValueFromBuffer<double>(valuePtr);
                            match = CompareValues<double>(val, params->value.floatValue, params->valueMax.floatValueMax,
                                                          params->scanType, 0.0, params->floatEpsilon);
                            break;
                        }
                        case NEXUS_VALUE_STRING: {
                            if (offset + scanData->searchString.length() <= bytesRead) {
                                match = CompareStrings(
                                    reinterpret_cast<const char*>(valuePtr),
                                    scanData->searchString.c_str(),
                                    scanData->searchString.length(),
                                    scanData->caseSensitive
                                );
                            }
                            break;
                        }
                        case NEXUS_VALUE_WSTRING: {
                            if (offset + scanData->searchWString.length() * sizeof(wchar_t) <= bytesRead) {
                                match = CompareWStrings(
                                    reinterpret_cast<const wchar_t*>(valuePtr),
                                    scanData->searchWString.c_str(),
                                    scanData->searchWString.length(),
                                    scanData->caseSensitive
                                );
                            }
                            break;
                        }
                        case NEXUS_VALUE_AOB: {
                            if (offset + scanData->aobPattern.size() <= bytesRead) {
                                match = MatchAOBPattern(valuePtr, scanData->aobPattern);
                            }
                            break;
                        }
                        default:
                            break;
                    }

                    if (match) {
                        ScanResultEntry entry;
                        entry.address = addr;
                        entry.previousValue = ValueToUint64(valuePtr, scanData->valueSize);
                        scanData->results.push_back(entry);
                    }
                }
            }

            regionAddr += bytesRead;
            if (bytesRead == 0) break;  /* Prevent infinite loop */

            regionBytesScanned += bytesRead;
            scanData->bytesScanned = scanData->bytesScanned + bytesRead;
        }

        scanData->regionsScanned = regionIdx + 1;
    }

    Nexus_ReleaseSnapshot(snapshot);

    scanData->hasFirstScan = true;
    scanData->isComplete = true;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ScanNext(
    NexusScanHandle scan,
    const NexusScanParams* params
) {
    if (!scan || !params) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);

    if (!scanData->hasFirstScan) {
        return NEXUS_ERROR_INVALID_HANDLE;  /* Must do first scan first */
    }

    scanData->isComplete = false;
    scanData->wasCancelled = false;
    scanData->bytesScanned = 0;
    scanData->regionsScanned = 0;
    scanData->bytesTotal = scanData->results.size() * scanData->valueSize;
    scanData->regionsTotal = scanData->results.size();

    /* Filter existing results */
    std::vector<ScanResultEntry> newResults;
    newResults.reserve(scanData->results.size());

    /* Use dynamic buffer for variable-length types */
    std::vector<uint8_t> buffer(std::max(static_cast<size_t>(scanData->valueSize), static_cast<size_t>(8)));

    for (size_t i = 0; i < scanData->results.size(); i++) {
        if (scanData->wasCancelled) {
            break;
        }

        const auto& entry = scanData->results[i];

        size_t bytesRead = 0;
        NexusResult res = Nexus_ReadMemory(scanData->processHandle, entry.address,
                                            buffer.data(), scanData->valueSize, &bytesRead);

        if (res != NEXUS_OK || bytesRead != scanData->valueSize) {
            continue;  /* Skip unreadable addresses */
        }

        bool match = false;
        uint64_t previousValue = entry.previousValue;

        switch (scanData->valueType) {
            case NEXUS_VALUE_INT8: {
                int8_t current = ReadValueFromBuffer<int8_t>(buffer.data());
                int8_t prev = static_cast<int8_t>(previousValue);
                match = CompareValues<int64_t>(current, params->value.intValue, params->valueMax.intValueMax,
                                               params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_INT16: {
                int16_t current = ReadValueFromBuffer<int16_t>(buffer.data());
                int16_t prev = static_cast<int16_t>(previousValue);
                match = CompareValues<int64_t>(current, params->value.intValue, params->valueMax.intValueMax,
                                               params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_INT32: {
                int32_t current = ReadValueFromBuffer<int32_t>(buffer.data());
                int32_t prev = static_cast<int32_t>(previousValue);
                match = CompareValues<int64_t>(current, params->value.intValue, params->valueMax.intValueMax,
                                               params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_INT64: {
                int64_t current = ReadValueFromBuffer<int64_t>(buffer.data());
                int64_t prev = static_cast<int64_t>(previousValue);
                match = CompareValues<int64_t>(current, params->value.intValue, params->valueMax.intValueMax,
                                               params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_FLOAT32: {
                float current = ReadValueFromBuffer<float>(buffer.data());
                float prev;
                memcpy(&prev, &previousValue, sizeof(float));
                match = CompareValues<double>(current, params->value.floatValue, params->valueMax.floatValueMax,
                                              params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_FLOAT64: {
                double current = ReadValueFromBuffer<double>(buffer.data());
                double prev;
                memcpy(&prev, &previousValue, sizeof(double));
                match = CompareValues<double>(current, params->value.floatValue, params->valueMax.floatValueMax,
                                              params->scanType, prev, params->floatEpsilon);
                break;
            }
            case NEXUS_VALUE_STRING: {
                match = CompareStrings(
                    reinterpret_cast<const char*>(buffer.data()),
                    scanData->searchString.c_str(),
                    scanData->searchString.length(),
                    scanData->caseSensitive
                );
                break;
            }
            case NEXUS_VALUE_WSTRING: {
                match = CompareWStrings(
                    reinterpret_cast<const wchar_t*>(buffer.data()),
                    scanData->searchWString.c_str(),
                    scanData->searchWString.length(),
                    scanData->caseSensitive
                );
                break;
            }
            case NEXUS_VALUE_AOB: {
                match = MatchAOBPattern(buffer.data(), scanData->aobPattern);
                break;
            }
            default:
                break;
        }

        if (match) {
            ScanResultEntry newEntry;
            newEntry.address = entry.address;
            newEntry.previousValue = ValueToUint64(buffer.data(), scanData->valueSize);
            newResults.push_back(newEntry);
        }

        scanData->bytesScanned = (i + 1) * scanData->valueSize;
        scanData->regionsScanned = i + 1;
    }

    scanData->results = std::move(newResults);
    scanData->isComplete = true;

    return NEXUS_OK;
}

NEXUS_API void Nexus_ScanCancel(NexusScanHandle scan) {
    if (scan) {
        auto* scanData = static_cast<NexusScanData*>(scan);
        scanData->wasCancelled = true;
    }
}

NEXUS_API NexusResult Nexus_ScanGetProgress(
    NexusScanHandle scan,
    NexusScanProgress* progress
) {
    if (!scan || !progress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);

    progress->bytesScanned = scanData->bytesScanned;
    progress->bytesTotal = scanData->bytesTotal;
    progress->regionsScanned = scanData->regionsScanned;
    progress->regionsTotal = scanData->regionsTotal;
    progress->resultsFound = scanData->results.size();
    progress->isComplete = scanData->isComplete ? 1 : 0;
    progress->wasCancelled = scanData->wasCancelled ? 1 : 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ScanGetResultCount(
    NexusScanHandle scan,
    uint64_t* count
) {
    if (!scan || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);
    *count = scanData->results.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ScanGetResults(
    NexusScanHandle scan,
    uint64_t startIndex,
    NexusScanResult* buffer,
    size_t bufferCount,
    size_t* resultsReturned
) {
    if (!scan || !buffer || !resultsReturned || bufferCount == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);

    if (startIndex >= scanData->results.size()) {
        *resultsReturned = 0;
        return NEXUS_OK;
    }

    size_t available = scanData->results.size() - static_cast<size_t>(startIndex);
    size_t toCopy = (available < bufferCount) ? available : bufferCount;

    /* Use dynamic buffer for variable-length types (but limit to 8 bytes for result storage) */
    size_t readSize = std::min(static_cast<size_t>(scanData->valueSize), static_cast<size_t>(8));
    std::vector<uint8_t> valueBuffer(std::max(static_cast<size_t>(scanData->valueSize), static_cast<size_t>(8)));

    for (size_t i = 0; i < toCopy; i++) {
        const auto& entry = scanData->results[static_cast<size_t>(startIndex) + i];

        buffer[i].address = entry.address;

        /* Read current value */
        size_t bytesRead = 0;
        NexusResult res = Nexus_ReadMemory(scanData->processHandle, entry.address,
                                            valueBuffer.data(), readSize, &bytesRead);

        if (res == NEXUS_OK && bytesRead == readSize) {
            memcpy(&buffer[i].currentValue, valueBuffer.data(), std::min(readSize, static_cast<size_t>(8)));
        } else {
            memset(&buffer[i].currentValue, 0, sizeof(buffer[i].currentValue));
        }

        /* Copy previous value */
        memcpy(&buffer[i].previousValue, &entry.previousValue, sizeof(uint64_t));
    }

    *resultsReturned = toCopy;
    return NEXUS_OK;
}

NEXUS_API void Nexus_ScanReset(NexusScanHandle scan) {
    if (scan) {
        auto* scanData = static_cast<NexusScanData*>(scan);
        scanData->results.clear();
        scanData->hasFirstScan = false;
        scanData->isComplete = true;
        scanData->wasCancelled = false;
    }
}

NEXUS_API NexusResult Nexus_ScanRefreshValues(NexusScanHandle scan) {
    if (!scan) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* scanData = static_cast<NexusScanData*>(scan);

    /* For string/AOB types, only store the first 8 bytes in previousValue */
    size_t readSize = std::min(static_cast<size_t>(scanData->valueSize), static_cast<size_t>(8));
    std::vector<uint8_t> buffer(std::max(static_cast<size_t>(scanData->valueSize), static_cast<size_t>(8)));

    for (auto& entry : scanData->results) {
        size_t bytesRead = 0;
        NexusResult res = Nexus_ReadMemory(scanData->processHandle, entry.address,
                                            buffer.data(), readSize, &bytesRead);

        if (res == NEXUS_OK && bytesRead == readSize) {
            entry.previousValue = ValueToUint64(buffer.data(), static_cast<uint32_t>(readSize));
        }
    }

    return NEXUS_OK;
}
