/**
 * @file snapshot.cpp
 * @brief Memory snapshot capture, filtering, and region queries.
 *
 * Captures a point-in-time view of a process's virtual address space
 * by walking VirtualQueryEx.  Supports flag-based filtering (committed,
 * reserved, image, private, mapped, protection attributes), extended
 * region metadata (mapped file names, module attribution), statistics
 * aggregation, and address-based region lookup via binary search.
 */

#include "nexus_api.h"

#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <algorithm>
#include <memory>
#include <unordered_map>
#include <mutex>

/* Forward declaration of internal handle structure (must match process.cpp) */
struct NexusProcessHandleData {
    uint32_t magic;              /* Validation magic number */
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;  /* What was originally requested */
    NexusProcessAccess actualAccess;     /* What was actually granted */
};

/* Internal snapshot structure */
struct NexusSnapshotData {
    std::vector<NexusMemoryRegionEx> regions;
    NexusSnapshotStats stats;
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static bool IsProtectionReadable(DWORD protect) {
    return (protect & PAGE_READONLY) ||
           (protect & PAGE_READWRITE) ||
           (protect & PAGE_WRITECOPY) ||
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

static bool IsProtectionExecutable(DWORD protect) {
    return (protect & PAGE_EXECUTE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

static bool IsProtectionGuard(DWORD protect) {
    return (protect & PAGE_GUARD) != 0;
}

static bool IsProtectionNoAccess(DWORD protect) {
    return (protect & PAGE_NOACCESS) != 0;
}

/* Check if a region matches the filter flags */
static bool RegionMatchesFilter(const MEMORY_BASIC_INFORMATION& mbi, uint32_t flags) {
    /* Check state filters */
    bool stateMatch = false;
    if ((flags & NEXUS_SNAPSHOT_COMMITTED) && mbi.State == MEM_COMMIT) stateMatch = true;
    if ((flags & NEXUS_SNAPSHOT_RESERVED) && mbi.State == MEM_RESERVE) stateMatch = true;

    if (!stateMatch && (flags & (NEXUS_SNAPSHOT_COMMITTED | NEXUS_SNAPSHOT_RESERVED))) {
        return false;
    }

    /* Check type filters */
    bool typeMatch = false;
    if ((flags & NEXUS_SNAPSHOT_PRIVATE) && mbi.Type == MEM_PRIVATE) typeMatch = true;
    if ((flags & NEXUS_SNAPSHOT_IMAGE) && mbi.Type == MEM_IMAGE) typeMatch = true;
    if ((flags & NEXUS_SNAPSHOT_MAPPED) && mbi.Type == MEM_MAPPED) typeMatch = true;

    if (!typeMatch && (flags & (NEXUS_SNAPSHOT_PRIVATE | NEXUS_SNAPSHOT_IMAGE | NEXUS_SNAPSHOT_MAPPED))) {
        return false;
    }

    /* Check protection filters */
    if ((flags & NEXUS_SNAPSHOT_READABLE) && !IsProtectionReadable(mbi.Protect)) {
        return false;
    }
    if ((flags & NEXUS_SNAPSHOT_WRITABLE) && !IsProtectionWritable(mbi.Protect)) {
        return false;
    }
    if ((flags & NEXUS_SNAPSHOT_EXECUTABLE) && !IsProtectionExecutable(mbi.Protect)) {
        return false;
    }

    /* Check exclusion filters */
    if ((flags & NEXUS_SNAPSHOT_NO_GUARD) && IsProtectionGuard(mbi.Protect)) {
        return false;
    }
    if ((flags & NEXUS_SNAPSHOT_NO_NOACCESS) && IsProtectionNoAccess(mbi.Protect)) {
        return false;
    }

    return true;
}

/* Try to get module name for an address */
static void GetModuleNameForAddress(HANDLE hProcess, uint64_t address, wchar_t* moduleName, size_t maxLen) {
    moduleName[0] = L'\0';

    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(address), &hMod)) {
        /* This only works for our own process, so we use a different approach */
    }

    /* Use GetMappedFileName for the target process */
    wchar_t mappedName[MAX_PATH];
    if (GetMappedFileNameW(hProcess, reinterpret_cast<LPVOID>(address), mappedName, MAX_PATH) > 0) {
        /* Extract just the filename from the full path */
        wchar_t* lastSlash = wcsrchr(mappedName, L'\\');
        if (lastSlash) {
            wcsncpy_s(moduleName, maxLen, lastSlash + 1, _TRUNCATE);
        } else {
            wcsncpy_s(moduleName, maxLen, mappedName, _TRUNCATE);
        }
    }
}

/* ============================================================================
 * Snapshot Management
 * ============================================================================ */

// Global container to manage snapshot ownership
static std::mutex g_snapshotMutex;
static std::unordered_map<void*, std::unique_ptr<NexusSnapshotData>> g_snapshots;

/* ============================================================================
 * Memory Snapshot Functions
 * ============================================================================ */

NEXUS_API NexusResult Nexus_CaptureMemoryMap(
    NexusProcessHandle handle,
    uint32_t flags,
    NexusMemorySnapshot* snapshot
) {
    if (!handle || !snapshot) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* processData = static_cast<NexusProcessHandleData*>(handle);

    /* Create snapshot structure using unique_ptr */
    auto snapData = std::make_unique<NexusSnapshotData>();
    memset(&snapData->stats, 0, sizeof(NexusSnapshotStats));

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t address = 0;
    uint64_t maxAddress = processData->is32Bit ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

    while (address < maxAddress) {
        SIZE_T queryResult = VirtualQueryEx(
            processData->hProcess,
            reinterpret_cast<LPCVOID>(address),
            &mbi,
            sizeof(mbi)
        );

        if (queryResult == 0) {
            break;
        }

        /* Check if region matches filter */
        if (mbi.State != MEM_FREE && RegionMatchesFilter(mbi, flags)) {
            NexusMemoryRegionEx region;
            region.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            region.isExecutable = IsProtectionExecutable(mbi.Protect) ? 1 : 0;
            region.isWritable = IsProtectionWritable(mbi.Protect) ? 1 : 0;
            region.isGuard = IsProtectionGuard(mbi.Protect) ? 1 : 0;

            /* Get module name for image regions */
            if (mbi.Type == MEM_IMAGE) {
                GetModuleNameForAddress(processData->hProcess, region.baseAddress,
                                        region.moduleName, 260);
            } else {
                region.moduleName[0] = L'\0';
            }

            snapData->regions.push_back(region);

            /* Update stats */
            snapData->stats.totalBytes += mbi.RegionSize;
            if (mbi.State == MEM_COMMIT) {
                snapData->stats.committedBytes += mbi.RegionSize;
            }
            if (mbi.Type == MEM_IMAGE) {
                snapData->stats.imageBytes += mbi.RegionSize;
            } else if (mbi.Type == MEM_PRIVATE) {
                snapData->stats.privateBytes += mbi.RegionSize;
            } else if (mbi.Type == MEM_MAPPED) {
                snapData->stats.mappedBytes += mbi.RegionSize;
            }
        }

        /* Move to next region */
        address = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;

        /* Prevent infinite loop on overflow */
        if (address < reinterpret_cast<uint64_t>(mbi.BaseAddress)) {
            break;
        }
    }

    snapData->stats.regionCount = snapData->regions.size();

    // Store unique_ptr in global container and return raw pointer
    auto* rawPtr = snapData.get();
    {
        std::lock_guard<std::mutex> lock(g_snapshotMutex);
        g_snapshots[rawPtr] = std::move(snapData);
    }

    *snapshot = rawPtr;

    return NEXUS_OK;
}

NEXUS_API void Nexus_ReleaseSnapshot(NexusMemorySnapshot snapshot) {
    if (snapshot) {
        // Remove from global container (unique_ptr handles deletion)
        std::lock_guard<std::mutex> lock(g_snapshotMutex);
        g_snapshots.erase(snapshot);
    }
}

NEXUS_API NexusResult Nexus_GetSnapshotStats(
    NexusMemorySnapshot snapshot,
    NexusSnapshotStats* stats
) {
    if (!snapshot || !stats) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* snapData = static_cast<NexusSnapshotData*>(snapshot);
    *stats = snapData->stats;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetSnapshotRegionCount(
    NexusMemorySnapshot snapshot,
    size_t* count
) {
    if (!snapshot || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* snapData = static_cast<NexusSnapshotData*>(snapshot);
    *count = snapData->regions.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetSnapshotRegion(
    NexusMemorySnapshot snapshot,
    size_t index,
    NexusMemoryRegionEx* region
) {
    if (!snapshot || !region) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* snapData = static_cast<NexusSnapshotData*>(snapshot);

    if (index >= snapData->regions.size()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *region = snapData->regions[index];
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetSnapshotRegions(
    NexusMemorySnapshot snapshot,
    size_t startIndex,
    NexusMemoryRegionEx* buffer,
    size_t bufferCount,
    size_t* regionsReturned
) {
    if (!snapshot || !buffer || !regionsReturned || bufferCount == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* snapData = static_cast<NexusSnapshotData*>(snapshot);

    if (startIndex >= snapData->regions.size()) {
        *regionsReturned = 0;
        return NEXUS_OK;
    }

    size_t available = snapData->regions.size() - startIndex;
    size_t toCopy = (available < bufferCount) ? available : bufferCount;

    for (size_t i = 0; i < toCopy; i++) {
        buffer[i] = snapData->regions[startIndex + i];
    }

    *regionsReturned = toCopy;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_FindRegionByAddress(
    NexusMemorySnapshot snapshot,
    uint64_t address,
    NexusMemoryRegionEx* region
) {
    if (!snapshot || !region) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* snapData = static_cast<NexusSnapshotData*>(snapshot);

    /* Binary search since regions are sorted by address */
    auto it = std::lower_bound(
        snapData->regions.begin(),
        snapData->regions.end(),
        address,
        [](const NexusMemoryRegionEx& r, uint64_t addr) {
            return r.baseAddress + r.size <= addr;
        }
    );

    if (it != snapData->regions.end() &&
        address >= it->baseAddress &&
        address < it->baseAddress + it->size) {
        *region = *it;
        return NEXUS_OK;
    }

    return NEXUS_ERROR_NOT_FOUND;
}
