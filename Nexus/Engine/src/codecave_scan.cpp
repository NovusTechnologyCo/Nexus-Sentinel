/**
 * @file codecave_scan.cpp
 * @brief Code-cave scan implementation: region filtering, fill-byte detection, and per-region scan.
 *
 * Iterates over process memory regions, applies protection/type filters,
 * reads each region, and scans for contiguous runs of fill bytes (00, 90,
 * CC, or any repeating byte) that meet the minimum-size threshold.
 *
 * Public API entry points are in codecave.cpp.
 */

#include "codecave_internal.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static bool IsProtectionExecutable(DWORD protect) {
    return (protect & PAGE_EXECUTE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsProtectionWritable(DWORD protect) {
    return (protect & PAGE_READWRITE) ||
           (protect & PAGE_WRITECOPY) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsProtectionReadable(DWORD protect) {
    return (protect & PAGE_READONLY) ||
           (protect & PAGE_READWRITE) ||
           (protect & PAGE_WRITECOPY) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

/**
 * Check if a byte matches the fill type criteria.
 */
static bool IsFillByte(uint8_t byte, uint32_t fillType, uint8_t firstByte, bool isFirst) {
    switch (fillType) {
        case NEXUS_CAVE_ZEROS:
            return byte == 0x00;
        case NEXUS_CAVE_NOPS:
            return byte == 0x90;
        case NEXUS_CAVE_INTS:
            return byte == 0xCC;
        case NEXUS_CAVE_ANY_FILL:
            /* For ANY_FILL, the first byte sets the pattern */
            if (isFirst) return true;
            return byte == firstByte;
        default:
            return false;
    }
}

/**
 * Get module name for an address.
 */
static void GetModuleNameForAddress(HANDLE hProcess, uint64_t address, wchar_t* moduleName, size_t maxLen, uint64_t* moduleBase) {
    moduleName[0] = L'\0';
    *moduleBase = 0;

    wchar_t mappedName[MAX_PATH];
    if (GetMappedFileNameW(hProcess, reinterpret_cast<LPVOID>(address), mappedName, MAX_PATH) > 0) {
        /* Extract just the filename from the full path */
        wchar_t* lastSlash = wcsrchr(mappedName, L'\\');
        if (lastSlash) {
            wcsncpy_s(moduleName, maxLen, lastSlash + 1, _TRUNCATE);
        } else {
            wcsncpy_s(moduleName, maxLen, mappedName, _TRUNCATE);
        }

        /* Get module base by querying the region's allocation base */
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            *moduleBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        }
    }
}

/**
 * Apply 16-byte alignment to an address.
 */
static uint64_t AlignTo16(uint64_t address) {
    return (address + 15) & ~static_cast<uint64_t>(15);
}

/* ============================================================================
 * Region Filtering
 * ============================================================================ */

/**
 * Check if a region matches the scan options.
 */
bool RegionMatchesOptions(const MEMORY_BASIC_INFORMATION& mbi, uint32_t options) {
    /* Must be committed memory */
    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    /* Check executable filter */
    if ((options & NEXUS_CAVE_OPT_EXECUTABLE) && !IsProtectionExecutable(mbi.Protect)) {
        return false;
    }

    /* Check writable filter */
    if ((options & NEXUS_CAVE_OPT_WRITABLE) && !IsProtectionWritable(mbi.Protect)) {
        return false;
    }

    /* Check module-only filter */
    if ((options & NEXUS_CAVE_OPT_MODULE_ONLY) && mbi.Type != MEM_IMAGE) {
        return false;
    }

    /* Check private-only filter */
    if ((options & NEXUS_CAVE_OPT_PRIVATE) && mbi.Type != MEM_PRIVATE) {
        return false;
    }

    /* Must be readable to scan */
    if (!IsProtectionReadable(mbi.Protect)) {
        return false;
    }

    return true;
}

/* ============================================================================
 * Scan Implementation
 * ============================================================================ */

/* Chunk size for reading memory (64KB for good syscall amortization) */
static constexpr size_t SCAN_CHUNK_SIZE = 64 * 1024;

/**
 * Scan a single memory region for code caves.
 */
void ScanRegionForCaves(
    HANDLE hProcess,
    const MEMORY_BASIC_INFORMATION& mbi,
    const NexusCodeCaveScanConfig* config,
    std::vector<NexusCodeCaveEntry>& results,
    size_t maxResults,
    NexusCodeCaveScanStats* stats
) {
    uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    size_t regionSize = mbi.RegionSize;

    /* Check address range constraints */
    uint64_t scanStart = regionBase;
    uint64_t scanEnd = regionBase + regionSize;

    if (config->startAddress > 0 && scanEnd <= config->startAddress) {
        return; /* Region is before start address */
    }
    if (config->endAddress > 0 && scanStart >= config->endAddress) {
        return; /* Region is after end address */
    }

    /* Adjust scan bounds */
    if (config->startAddress > 0 && scanStart < config->startAddress) {
        scanStart = config->startAddress;
    }
    if (config->endAddress > 0 && scanEnd > config->endAddress) {
        scanEnd = config->endAddress;
    }

    size_t adjustedSize = static_cast<size_t>(scanEnd - scanStart);
    if (adjustedSize == 0) return;

    /* Check near-address filter */
    if ((config->options & NEXUS_CAVE_OPT_NEAR_ADDRESS) && config->nearAddress > 0 && config->maxDistance > 0) {
        int64_t distStart = static_cast<int64_t>(scanStart) - static_cast<int64_t>(config->nearAddress);
        int64_t distEnd = static_cast<int64_t>(scanEnd) - static_cast<int64_t>(config->nearAddress);

        /* Check if region is within distance */
        if (distStart > 0 && distStart > config->maxDistance) return;
        if (distEnd < 0 && (-distEnd) > config->maxDistance) return;
    }

    /* Allocate read buffer */
    std::vector<uint8_t> buffer(SCAN_CHUNK_SIZE);

    /* Track current cave */
    uint64_t caveStart = 0;
    size_t caveSize = 0;
    uint8_t caveFillByte = 0;
    bool inCave = false;

    /* Get module info for this region */
    wchar_t moduleName[64];
    uint64_t moduleBase = 0;
    GetModuleNameForAddress(hProcess, regionBase, moduleName, 64, &moduleBase);

    /* Check module filter */
    if (config->moduleFilter[0] != L'\0') {
        if (_wcsicmp(moduleName, config->moduleFilter) != 0) {
            return; /* Module doesn't match filter */
        }
    }

    /* Lambda to emit a cave */
    auto emitCave = [&]() {
        if (!inCave || caveSize < config->minSize) return;
        if (config->maxSize > 0 && caveSize > config->maxSize) return;
        if (results.size() >= maxResults) return;

        uint64_t finalAddress = caveStart;
        size_t finalSize = caveSize;

        /* Apply alignment if requested */
        if (config->options & NEXUS_CAVE_OPT_ALIGN_16) {
            uint64_t aligned = AlignTo16(caveStart);
            if (aligned > caveStart) {
                size_t adjustment = static_cast<size_t>(aligned - caveStart);
                if (adjustment >= caveSize) return; /* Too small after alignment */
                finalAddress = aligned;
                finalSize = caveSize - adjustment;
            }
            if (finalSize < config->minSize) return;
        }

        NexusCodeCaveEntry entry = {};
        entry.address = finalAddress;
        entry.size = finalSize;
        entry.fillByte = caveFillByte;
        entry.protection = mbi.Protect;
        wcsncpy_s(entry.moduleName, 64, moduleName, _TRUNCATE);
        entry.moduleBase = moduleBase;

        results.push_back(entry);

        if (stats) {
            stats->cavesFound++;
            stats->totalCaveBytes += finalSize;
            if (finalSize > stats->largestCave) {
                stats->largestCave = finalSize;
            }
        }
    };

    /* Scan the region in chunks */
    uint64_t currentAddr = scanStart;
    size_t remaining = adjustedSize;

    while (remaining > 0 && results.size() < maxResults) {
        size_t toRead = (remaining < SCAN_CHUNK_SIZE) ? remaining : SCAN_CHUNK_SIZE;

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(currentAddr), buffer.data(), toRead, &bytesRead)) {
            /* Read failed, emit any pending cave and skip this chunk */
            emitCave();
            inCave = false;
            currentAddr += toRead;
            remaining -= toRead;
            continue;
        }

        if (stats) {
            stats->bytesScanned += bytesRead;
        }

        /* Scan the buffer */
        for (size_t i = 0; i < bytesRead; i++) {
            uint8_t byte = buffer[i];
            uint64_t addr = currentAddr + i;

            bool isFill;
            if (!inCave) {
                /* Start of potential new cave */
                isFill = IsFillByte(byte, config->fillType, 0, true);
                if (isFill) {
                    caveStart = addr;
                    caveSize = 1;
                    caveFillByte = byte;
                    inCave = true;
                }
            } else {
                /* Continue existing cave */
                isFill = IsFillByte(byte, config->fillType, caveFillByte, false);
                if (isFill) {
                    caveSize++;
                } else {
                    /* Cave ended */
                    emitCave();
                    inCave = false;

                    /* Check if this byte starts a new cave */
                    isFill = IsFillByte(byte, config->fillType, 0, true);
                    if (isFill) {
                        caveStart = addr;
                        caveSize = 1;
                        caveFillByte = byte;
                        inCave = true;
                    }
                }
            }
        }

        currentAddr += bytesRead;
        remaining -= bytesRead;
    }

    /* Emit final cave if any */
    emitCave();
}
