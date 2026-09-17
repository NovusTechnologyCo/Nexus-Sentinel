/**
 * @file advscanner.cpp
 * @brief Advanced memory scanner core: comparison helpers, worker thread, and first-scan.
 *
 * Multi-threaded memory scanner with CE-compatible three-state region
 * filtering.  Implements value-size helpers, typed comparison functions
 * for all scan modes, the worker-thread entry point that partitions
 * memory regions across CPU cores, and the first-scan code path.
 *
 * Next scan, undo, result queries, and persistence are in advscanner_scan.cpp.
 */

#include "advscanner_internal.h"

/* ============================================================================
 * Helper Functions (non-static, declared in advscanner_internal.h)
 * ============================================================================ */

size_t GetValueSize(NexusScanValueType type, const NexusScanConfig* config) {
    switch (type) {
        case NEXUS_SCAN_BYTE: return 1;
        case NEXUS_SCAN_INT16: return 2;
        case NEXUS_SCAN_INT32: return 4;
        case NEXUS_SCAN_INT64: return 8;
        case NEXUS_SCAN_FLOAT: return 4;
        case NEXUS_SCAN_DOUBLE: return 8;
        case NEXUS_SCAN_STRING:
        case NEXUS_SCAN_WSTRING:
            /* For strings, use the length from config if available */
            if (config && config->value1.stringVal.length > 0) {
                return config->value1.stringVal.length;
            }
            return 1; /* Minimum 1 byte for string scan */
        case NEXUS_SCAN_AOB:
            if (config && config->value1.aobVal.length > 0) {
                return config->value1.aobVal.length;
            }
            return 1;
        default: return 4;
    }
}

static uint32_t GetDefaultAlignment(NexusScanValueType type, uint32_t configAlignment) {
    if (configAlignment != 0) return configAlignment;
    return static_cast<uint32_t>(GetValueSize(type));
}

static bool CompareValues(const void* mem, const NexusScanConfig* config) {
    switch (config->valueType) {
        case NEXUS_SCAN_BYTE: {
            uint8_t val = *static_cast<const uint8_t*>(mem);
            uint8_t cmp = config->value1.byteVal;
            uint8_t cmp2 = config->value2.byteVal;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return val == cmp;
                case NEXUS_CMP_NOT_EQUAL: return val != cmp;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_INT16: {
            int16_t val = *static_cast<const int16_t*>(mem);
            int16_t cmp = config->value1.int16Val;
            int16_t cmp2 = config->value2.int16Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return val == cmp;
                case NEXUS_CMP_NOT_EQUAL: return val != cmp;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_INT32: {
            int32_t val = *static_cast<const int32_t*>(mem);
            int32_t cmp = config->value1.int32Val;
            int32_t cmp2 = config->value2.int32Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return val == cmp;
                case NEXUS_CMP_NOT_EQUAL: return val != cmp;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_INT64: {
            int64_t val = *static_cast<const int64_t*>(mem);
            int64_t cmp = config->value1.int64Val;
            int64_t cmp2 = config->value2.int64Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return val == cmp;
                case NEXUS_CMP_NOT_EQUAL: return val != cmp;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_FLOAT: {
            float val = *static_cast<const float*>(mem);
            float cmp = config->value1.floatVal;
            float cmp2 = config->value2.floatVal;
            float tol = config->floatTolerance;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return std::fabs(val - cmp) <= tol;
                case NEXUS_CMP_NOT_EQUAL: return std::fabs(val - cmp) > tol;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_DOUBLE: {
            double val = *static_cast<const double*>(mem);
            double cmp = config->value1.doubleVal;
            double cmp2 = config->value2.doubleVal;
            double tol = static_cast<double>(config->floatTolerance);
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return std::fabs(val - cmp) <= tol;
                case NEXUS_CMP_NOT_EQUAL: return std::fabs(val - cmp) > tol;
                case NEXUS_CMP_GREATER: return val > cmp;
                case NEXUS_CMP_GREATER_EQUAL: return val >= cmp;
                case NEXUS_CMP_LESS: return val < cmp;
                case NEXUS_CMP_LESS_EQUAL: return val <= cmp;
                case NEXUS_CMP_BETWEEN: return val >= cmp && val <= cmp2;
                case NEXUS_CMP_UNKNOWN: return true;
                default: return false;
            }
        }
        case NEXUS_SCAN_AOB: {
            const uint8_t* bytes = static_cast<const uint8_t*>(mem);
            for (size_t i = 0; i < config->value1.aobVal.length; i++) {
                if (config->value1.aobVal.mask[i] != 0) {
                    if (bytes[i] != config->value1.aobVal.bytes[i]) {
                        return false;
                    }
                }
            }
            return true;
        }
        case NEXUS_SCAN_STRING: {
            const char* str = static_cast<const char*>(mem);
            if (config->options & NEXUS_SCANOPT_CASE_INSENSITIVE) {
                return _strnicmp(str, config->value1.stringVal.data,
                                 config->value1.stringVal.length) == 0;
            }
            return strncmp(str, config->value1.stringVal.data,
                           config->value1.stringVal.length) == 0;
        }
        default:
            return false;
    }
}

bool CompareNextScan(const NexusScanValue* oldVal, const void* newMem,
                     const NexusScanConfig* config) {
    switch (config->valueType) {
        case NEXUS_SCAN_BYTE: {
            uint8_t oldV = oldVal->byteVal;
            uint8_t newV = *static_cast<const uint8_t*>(newMem);
            uint8_t delta = config->value1.byteVal;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return newV == config->value1.byteVal;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return newV == static_cast<uint8_t>(oldV + delta);
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return newV == static_cast<uint8_t>(oldV - delta);
                case NEXUS_CMP_CHANGED: return newV != oldV;
                case NEXUS_CMP_UNCHANGED: return newV == oldV;
                default: return CompareValues(newMem, config);
            }
        }
        case NEXUS_SCAN_INT16: {
            int16_t oldV = oldVal->int16Val;
            int16_t newV = *static_cast<const int16_t*>(newMem);
            int16_t delta = config->value1.int16Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return newV == config->value1.int16Val;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return newV == static_cast<int16_t>(oldV + delta);
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return newV == static_cast<int16_t>(oldV - delta);
                case NEXUS_CMP_CHANGED: return newV != oldV;
                case NEXUS_CMP_UNCHANGED: return newV == oldV;
                default: return CompareValues(newMem, config);
            }
        }
        case NEXUS_SCAN_INT32: {
            int32_t oldV = oldVal->int32Val;
            int32_t newV = *static_cast<const int32_t*>(newMem);
            int32_t delta = config->value1.int32Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return newV == config->value1.int32Val;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return newV == oldV + delta;
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return newV == oldV - delta;
                case NEXUS_CMP_CHANGED: return newV != oldV;
                case NEXUS_CMP_UNCHANGED: return newV == oldV;
                default: return CompareValues(newMem, config);
            }
        }
        case NEXUS_SCAN_INT64: {
            int64_t oldV = oldVal->int64Val;
            int64_t newV = *static_cast<const int64_t*>(newMem);
            int64_t delta = config->value1.int64Val;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return newV == config->value1.int64Val;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return newV == oldV + delta;
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return newV == oldV - delta;
                case NEXUS_CMP_CHANGED: return newV != oldV;
                case NEXUS_CMP_UNCHANGED: return newV == oldV;
                default: return CompareValues(newMem, config);
            }
        }
        case NEXUS_SCAN_FLOAT: {
            float oldV = oldVal->floatVal;
            float newV = *static_cast<const float*>(newMem);
            float delta = config->value1.floatVal;
            float tol = config->floatTolerance;
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return std::fabs(newV - config->value1.floatVal) <= tol;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return std::fabs(newV - (oldV + delta)) <= tol;
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return std::fabs(newV - (oldV - delta)) <= tol;
                case NEXUS_CMP_CHANGED: return std::fabs(newV - oldV) > tol;
                case NEXUS_CMP_UNCHANGED: return std::fabs(newV - oldV) <= tol;
                default: return CompareValues(newMem, config);
            }
        }
        case NEXUS_SCAN_DOUBLE: {
            double oldV = oldVal->doubleVal;
            double newV = *static_cast<const double*>(newMem);
            double delta = config->value1.doubleVal;
            double tol = static_cast<double>(config->floatTolerance);
            switch (config->compareType) {
                case NEXUS_CMP_EXACT: return std::fabs(newV - config->value1.doubleVal) <= tol;
                case NEXUS_CMP_INCREASED: return newV > oldV;
                case NEXUS_CMP_INCREASED_BY: return std::fabs(newV - (oldV + delta)) <= tol;
                case NEXUS_CMP_DECREASED: return newV < oldV;
                case NEXUS_CMP_DECREASED_BY: return std::fabs(newV - (oldV - delta)) <= tol;
                case NEXUS_CMP_CHANGED: return std::fabs(newV - oldV) > tol;
                case NEXUS_CMP_UNCHANGED: return std::fabs(newV - oldV) <= tol;
                default: return CompareValues(newMem, config);
            }
        }
        default:
            /* STRING, WSTRING, AOB fall through to first-scan comparison */
            return CompareValues(newMem, config);
    }
}

void ExtractValue(const void* mem, NexusScanValueType type, NexusScanValue* outVal, size_t stringLen) {
    memset(outVal, 0, sizeof(*outVal));
    switch (type) {
        case NEXUS_SCAN_BYTE:
            outVal->byteVal = *static_cast<const uint8_t*>(mem);
            break;
        case NEXUS_SCAN_INT16:
            outVal->int16Val = *static_cast<const int16_t*>(mem);
            break;
        case NEXUS_SCAN_INT32:
            outVal->int32Val = *static_cast<const int32_t*>(mem);
            break;
        case NEXUS_SCAN_INT64:
            outVal->int64Val = *static_cast<const int64_t*>(mem);
            break;
        case NEXUS_SCAN_FLOAT:
            outVal->floatVal = *static_cast<const float*>(mem);
            break;
        case NEXUS_SCAN_DOUBLE:
            outVal->doubleVal = *static_cast<const double*>(mem);
            break;
        case NEXUS_SCAN_STRING:
        case NEXUS_SCAN_WSTRING: {
            size_t len = (stringLen > 0) ? stringLen : 255;
            if (len > 255) len = 255;
            memcpy(outVal->stringVal.data, mem, len);
            outVal->stringVal.data[len] = '\0';
            outVal->stringVal.length = len;
            break;
        }
        case NEXUS_SCAN_AOB: {
            size_t len = (stringLen > 0) ? stringLen : 255;
            if (len > 255) len = 255;
            memcpy(outVal->aobVal.bytes, mem, len);
            memset(outVal->aobVal.mask, 0xFF, len);
            outVal->aobVal.length = len;
            break;
        }
        default:
            break;
    }
}

static bool ShouldScanRegion(const NexusMemoryRegion* region, uint32_t options) {
    /* Skip non-committed memory */
    if (region->state != MEM_COMMIT) return false;

    /* Check protection flags - CE compatible definitions */
    bool isWritable = (region->protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    bool isExecutable = (region->protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    bool isCopyOnWrite = (region->protection & (PAGE_WRITECOPY |
                          PAGE_EXECUTE_WRITECOPY)) != 0;

    if ((options & NEXUS_SCANOPT_WRITABLE) && !isWritable) return false;
    if ((options & NEXUS_SCANOPT_WRITABLE_EXCLUDE) && isWritable) return false;
    if ((options & NEXUS_SCANOPT_EXECUTABLE) && !isExecutable) return false;
    if ((options & NEXUS_SCANOPT_EXECUTABLE_EXCLUDE) && isExecutable) return false;
    if ((options & NEXUS_SCANOPT_COPYONWRITE) && !isCopyOnWrite) return false;
    if ((options & NEXUS_SCANOPT_COPYONWRITE_EXCLUDE) && isCopyOnWrite) return false;

    /* Skip guard pages, no-access, etc. */
    if (region->protection & (PAGE_GUARD | PAGE_NOACCESS)) return false;

    /* Skip MEM_MAPPED by default */
    if (region->type == MEM_MAPPED) return false;

    return true;
}

/* ============================================================================
 * Worker Thread Functions
 * ============================================================================ */

struct ScanTask {
    uint64_t baseAddress;
    uint64_t size;
};

/* Default buffer size for memory scanning: 512KB */
static const size_t SCAN_BUFFER_SIZE = 512 * 1024;

static void ScanWorker(NexusAdvScanner* scanner, const NexusScanConfig* config,
                       const std::vector<ScanTask>& tasks, size_t taskStart, size_t taskEnd,
                       std::vector<ScanResult>& localResults) {
    size_t valueSize = GetValueSize(config->valueType, config);
    uint32_t alignment = GetDefaultAlignment(config->valueType, config->alignment);

    /* LastDigits mode: alignment field contains the digit pattern to match */
    bool useLastDigits = (config->options & NEXUS_SCANOPT_LAST_DIGITS) != 0;
    uint64_t lastDigitsMask = 0;
    uint64_t lastDigitsValue = 0;

    if (useLastDigits && config->alignment > 0) {
        lastDigitsValue = config->alignment;
        lastDigitsMask = 0xF;
        while (lastDigitsMask < config->alignment && lastDigitsMask < 0xFFFFFFFF) {
            lastDigitsMask = (lastDigitsMask << 4) | 0xF;
        }
        alignment = 1;
    }

    /* Pre-allocate buffer at CE's default size (512KB) */
    std::vector<uint8_t> buffer(SCAN_BUFFER_SIZE);

    for (size_t t = taskStart; t < taskEnd && !scanner->cancelRequested; t++) {
        const ScanTask& task = tasks[t];

        uint64_t currentAddr = task.baseAddress;
        uint64_t endAddr = task.baseAddress + task.size;

        while (currentAddr < endAddr && !scanner->cancelRequested) {
            size_t chunkSize = static_cast<size_t>(std::min(
                static_cast<uint64_t>(SCAN_BUFFER_SIZE),
                endAddr - currentAddr
            ));

            if (buffer.size() < chunkSize) {
                buffer.resize(chunkSize);
            }

            size_t bytesRead = 0;
            NexusResult result = Nexus_ReadMemory(scanner->process, currentAddr,
                                                   buffer.data(), chunkSize, &bytesRead);

            if (result == NEXUS_OK && bytesRead >= valueSize) {
                size_t startOffset = 0;
                if (alignment > 1) {
                    size_t misalignment = static_cast<size_t>(currentAddr % alignment);
                    if (misalignment != 0) {
                        startOffset = alignment - misalignment;
                    }
                }

                size_t scanEnd = bytesRead - valueSize;
                for (size_t offset = startOffset; offset <= scanEnd; offset += alignment) {
                    if (scanner->cancelRequested) break;

                    uint64_t addr = currentAddr + offset;

                    if (useLastDigits && (addr & lastDigitsMask) != lastDigitsValue) {
                        continue;
                    }

                    if (CompareValues(buffer.data() + offset, config)) {
                        ScanResult res;
                        res.address = addr;
                        ExtractValue(buffer.data() + offset, config->valueType, &res.value, valueSize);
                        localResults.push_back(res);
                    }
                }
            }

            size_t advance = (bytesRead > 0) ? bytesRead : chunkSize;
            if (alignment == 1 && advance > valueSize && currentAddr + advance < endAddr) {
                advance -= (valueSize - 1);
            }
            currentAddr += advance;
            scanner->bytesScanned += advance;
        }
    }
}

/* ============================================================================
 * Core Scan API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_AdvScanCreate(
    NexusProcessHandle process,
    NexusAdvScannerHandle* scanner
) {
    if (!process || !scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusAdvScanner* adv = new (std::nothrow) NexusAdvScanner();
    if (!adv) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    adv->process = process;
    *scanner = adv;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanDestroy(NexusAdvScannerHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    scanner->cancelRequested = true;

    auto start = std::chrono::steady_clock::now();
    while (scanner->scanning) {
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    delete scanner;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AdvScanFirst(
    NexusAdvScannerHandle scanner,
    const NexusScanConfig* config
) {
    if (!scanner || !config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (scanner->scanning) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    /* Save undo state */
    if (!scanner->results.empty()) {
        scanner->undoStack.push_back(scanner->results);
        if (scanner->undoStack.size() > 10) {
            scanner->undoStack.pop_front();
        }
    }

    /* Reset state */
    scanner->results.clear();
    scanner->cancelRequested = false;
    scanner->bytesScanned = 0;
    scanner->resultsFound = 0;
    scanner->lastConfig = *config;
    scanner->scanning = true;
    scanner->scanStartTime = std::chrono::high_resolution_clock::now();

    /* Enumerate memory regions */
    size_t regionCount = 0;
    Nexus_EnumerateMemoryRegions(scanner->process, nullptr, 0, &regionCount);
    std::vector<NexusMemoryRegion> regions(regionCount);
    Nexus_EnumerateMemoryRegions(scanner->process, regions.data(), regionCount, &regionCount);

    /* Build task list */
    std::vector<ScanTask> tasks;
    uint64_t totalBytes = 0;

    for (size_t i = 0; i < regionCount; i++) {
        if (!ShouldScanRegion(&regions[i], config->options)) continue;

        uint64_t start = regions[i].baseAddress;
        uint64_t end = start + regions[i].size;

        if (config->startAddress != 0 && end <= config->startAddress) continue;
        if (config->endAddress != 0 && start >= config->endAddress) continue;

        if (config->startAddress != 0 && start < config->startAddress) {
            start = config->startAddress;
        }
        if (config->endAddress != 0 && end > config->endAddress) {
            end = config->endAddress;
        }

        ScanTask task;
        task.baseAddress = start;
        task.size = end - start;
        tasks.push_back(task);
        totalBytes += task.size;
    }

    scanner->stats.totalBytes = totalBytes;
    scanner->stats.regionsScanned = tasks.size();

    /* Determine thread count */
    uint32_t threadCount = config->threadCount;
    if (threadCount == 0) {
        threadCount = std::thread::hardware_concurrency();
        if (threadCount == 0) threadCount = 4;
    }
    if (threadCount > tasks.size()) {
        threadCount = static_cast<uint32_t>(tasks.size());
    }
    if (threadCount == 0) threadCount = 1;

    scanner->stats.threadsUsed = threadCount;

    /* Launch worker threads */
    std::vector<std::thread> threads;
    std::vector<std::vector<ScanResult>> threadResults(threadCount);

    size_t tasksPerThread = tasks.size() / threadCount;
    size_t remainder = tasks.size() % threadCount;
    size_t taskStart = 0;

    for (uint32_t t = 0; t < threadCount; t++) {
        size_t taskEnd = taskStart + tasksPerThread + (t < remainder ? 1 : 0);
        threads.emplace_back(ScanWorker, scanner, config, std::ref(tasks),
                             taskStart, taskEnd, std::ref(threadResults[t]));
        taskStart = taskEnd;
    }

    /* Wait for threads and collect results */
    for (auto& thread : threads) {
        thread.join();
    }

    /* Merge results */
    for (const auto& tr : threadResults) {
        scanner->results.insert(scanner->results.end(), tr.begin(), tr.end());
    }

    /* Sort by address */
    std::sort(scanner->results.begin(), scanner->results.end(),
              [](const ScanResult& a, const ScanResult& b) {
                  return a.address < b.address;
              });

    /* Update stats */
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = endTime - scanner->scanStartTime;
    scanner->stats.elapsedMs = elapsed.count();
    scanner->stats.bytesScanned = scanner->bytesScanned;
    scanner->stats.resultsFound = scanner->results.size();
    scanner->stats.isComplete = 1;
    scanner->stats.wasCancelled = scanner->cancelRequested ? 1 : 0;

    if (scanner->stats.elapsedMs > 0) {
        scanner->stats.scanSpeedMBps = (scanner->stats.bytesScanned / 1048576.0) /
                                        (scanner->stats.elapsedMs / 1000.0);
    }

    scanner->scanning = false;
    return NEXUS_OK;
}

} /* extern "C" */
