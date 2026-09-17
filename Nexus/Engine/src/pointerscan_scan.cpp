/**
 * @file pointerscan_scan.cpp
 * @brief Pointer scanner algorithm: reverse pointer map, recursive path search, and scan worker.
 *
 * Builds a reverse pointer map (target -> set of addresses that point to it),
 * then recursively searches for chains from static module bases to the target
 * address within depth and offset bounds.  The scan worker runs on a
 * background thread with cancellation support.
 *
 * API functions and module loading are in pointerscan.cpp.
 */

#include "pointerscan_internal.h"

/* ============================================================================
 * Memory & Validation Helpers
 * ============================================================================ */

bool PtrScanReadMem(HANDLE process, uint64_t address, void* buffer, size_t size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(process, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

static bool IsValidPointerTarget(PointerScanContext* ctx, uint64_t address) {
    if (address == 0) return false;

    const auto& regions = ctx->validRegions;
    if (regions.empty()) return false;

    size_t left = 0;
    size_t right = regions.size();

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (regions[mid].second <= address) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    if (left > 0) {
        const auto& region = regions[left - 1];
        if (address >= region.first && address < region.second) {
            return true;
        }
    }

    if (left < regions.size()) {
        const auto& region = regions[left];
        if (address >= region.first && address < region.second) {
            return true;
        }
    }

    return false;
}

static bool IsStaticAddress(PointerScanContext* ctx, uint64_t address, NexusPointerPath* path) {
    uint64_t maxOffset = ctx->params.maxOffset;

    for (const auto& mod : ctx->modules) {
        bool withinModule = (address >= mod.base && address < mod.end);
        bool beforeModule = (address >= mod.base - maxOffset && address < mod.base);

        if (withinModule || beforeModule) {
            if (mod.isSystemModule && !ctx->params.includeSystemModules) {
                return false;
            }
            path->moduleBase = mod.base;
            wcsncpy_s(path->moduleName, mod.name.c_str(), 63);
            path->moduleName[63] = L'\0';
            return true;
        }
    }

    uint64_t stackSize = ctx->params.stackSize;
    if (stackSize == 0) stackSize = 4096;
    for (const auto& stack : ctx->threadStacks) {
        uint64_t rangeStart = (stack.stackBase > stackSize) ? (stack.stackBase - stackSize) : 0;
        if (address >= rangeStart && address <= stack.stackBase) {
            path->moduleBase = stack.stackBase;
            wcsncpy_s(path->moduleName, stack.name.c_str(), 63);
            path->moduleName[63] = L'\0';
            return true;
        }
    }

    return false;
}

/* ============================================================================
 * Reverse Pointer Map
 * ============================================================================ */

static void BuildPointerMap(PointerScanContext* ctx) {
    HANDLE process = ctx->process->processHandle;
    size_t pointerSize = ctx->params.is64Bit ? 8 : 4;
    uint32_t alignment = ctx->params.alignment;
    if (alignment == 0) alignment = (uint32_t)pointerSize;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t address = 0;
    std::vector<std::pair<uint64_t, uint64_t>> regions;

    while (VirtualQueryEx(process, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (ctx->cancelled) return;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            bool isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
            if (!ctx->params.scanWritable || isWritable) {
                regions.push_back({(uint64_t)mbi.BaseAddress, mbi.RegionSize});
            }
        }

        address = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        if (address == 0) break;
    }

    ctx->addressesTotal = 0;
    for (const auto& r : regions) {
        ctx->addressesTotal += r.second / alignment;
    }

    ctx->validRegions.clear();
    for (const auto& r : regions) {
        ctx->validRegions.push_back({r.first, r.first + r.second});
    }
    std::sort(ctx->validRegions.begin(), ctx->validRegions.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });

    const size_t CHUNK_SIZE = 64 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    for (const auto& region : regions) {
        if (ctx->cancelled) return;

        uint64_t regionBase = region.first;
        uint64_t regionSize = region.second;

        for (uint64_t offset = 0; offset < regionSize; offset += CHUNK_SIZE) {
            if (ctx->cancelled) return;

            size_t chunkSize = (size_t)min((uint64_t)CHUNK_SIZE, regionSize - offset);
            SIZE_T bytesRead;

            if (!ReadProcessMemory(process, (LPCVOID)(regionBase + offset), buffer.data(), chunkSize, &bytesRead)) {
                continue;
            }

            for (size_t i = 0; i + pointerSize <= bytesRead; i += alignment) {
                uint64_t value;
                if (pointerSize == 8) {
                    value = *reinterpret_cast<uint64_t*>(&buffer[i]);
                } else {
                    value = *reinterpret_cast<uint32_t*>(&buffer[i]);
                }

                if (value >= 0x10000 && value < 0x7FFFFFFFFFFF) {
                    if (IsValidPointerTarget(ctx, value)) {
                        if (ctx->reversePointerMap.size() < MAX_REVERSE_MAP_ENTRIES) {
                            uint64_t pointerAddr = regionBase + offset + i;
                            ctx->reversePointerMap[value].push_back(pointerAddr);
                        }
                    }
                }

                ctx->addressesScanned++;
            }
        }
    }
}

/* ============================================================================
 * Recursive Path Finding
 * ============================================================================ */

static bool MaxResultsReached(PointerScanContext* ctx) {
    return ctx->resultCount.load(std::memory_order_acquire) >= ctx->maxResults;
}

static bool MarkGlobalVisited(PointerScanContext* ctx, uint64_t addr) {
    std::lock_guard<std::mutex> lock(ctx->visitedMutex);
    uint32_t& count = ctx->globalVisitCount[addr];
    uint32_t maxVisits = ctx->params.maxVisitsPerAddress;
    if (maxVisits == 0) maxVisits = 4;
    if (count >= maxVisits) return true;
    count++;
    return false;
}

static void FindPaths(PointerScanContext* ctx, uint64_t target,
                      std::vector<int64_t>& currentOffsets, int level,
                      std::unordered_set<uint64_t>& pathVisited) {
    if (ctx->cancelled) return;
    if (level > (int)ctx->params.maxLevel) return;
    if (currentOffsets.size() >= 8) return;
    if (MaxResultsReached(ctx)) return;

    if (pathVisited.count(target)) return;
    pathVisited.insert(target);

    ctx->currentLevel = level;

    int64_t maxOffset = ctx->params.maxOffset;
    size_t pointerSize = ctx->params.is64Bit ? 8 : 4;
    uint32_t maxOffsetsPerNode = ctx->params.maxOffsetsPerNode;
    bool allowNegative = ctx->params.allowNegativeOffsets != 0;

    bool applyOffsetLimit = (maxOffsetsPerNode > 0) && (level > 1);
    uint32_t differentOffsetsInThisNode = 0;

    int64_t startOffset = allowNegative ? -maxOffset : 0;

    for (int64_t offset = startOffset; offset <= maxOffset; offset += pointerSize) {
        if (ctx->cancelled || MaxResultsReached(ctx)) return;

        if (applyOffsetLimit && differentOffsetsInThisNode >= maxOffsetsPerNode) {
            break;
        }

        uint64_t searchAddr = target - offset;
        if (searchAddr < 0x10000) continue;

        auto it = ctx->reversePointerMap.find(searchAddr);
        if (it != ctx->reversePointerMap.end()) {
            differentOffsetsInThisNode++;

            for (uint64_t pointerAddr : it->second) {
                if (ctx->cancelled || MaxResultsReached(ctx)) return;

                if (pathVisited.count(pointerAddr)) continue;

                std::vector<int64_t> newOffsets = currentOffsets;
                newOffsets.push_back(offset);

                NexusPointerPath path = {};
                if (IsStaticAddress(ctx, pointerAddr, &path)) {
                    if (MaxResultsReached(ctx)) return;

                    path.baseAddress = pointerAddr;
                    path.offsetCount = (uint32_t)newOffsets.size();
                    for (size_t i = 0; i < newOffsets.size() && i < 8; i++) {
                        path.offsets[i] = newOffsets[newOffsets.size() - 1 - i];
                    }

                    {
                        std::lock_guard<std::mutex> lock(ctx->resultsMutex);
                        if (ctx->results.size() < ctx->maxResults) {
                            ctx->results.push_back(path);
                            ctx->resultCount.store(ctx->results.size(), std::memory_order_release);
                        } else {
                            return;
                        }
                    }
                } else if (level < (int)ctx->params.maxLevel) {
                    if (MaxResultsReached(ctx)) return;

                    if (MarkGlobalVisited(ctx, pointerAddr)) continue;

                    std::unordered_set<uint64_t> newPathVisited = pathVisited;
                    FindPaths(ctx, pointerAddr, newOffsets, level + 1, newPathVisited);
                }
            }
        }
    }
}

/* ============================================================================
 * Scan Worker Thread
 * ============================================================================ */

void ScanWorker(PointerScanContext* ctx) {
    // Phase 1: Build reverse pointer map
    ctx->currentLevel = 0;
    BuildPointerMap(ctx);

    if (ctx->cancelled) {
        ctx->isComplete = true;
        return;
    }

    // Phase 2: Find paths from target
    ctx->addressesScanned = 0;
    ctx->addressesTotal = ctx->reversePointerMap.size();

    std::vector<int64_t> initialOffsets;
    std::unordered_set<uint64_t> visited;
    FindPaths(ctx, ctx->params.targetAddress, initialOffsets, 1, visited);

    ctx->isComplete = true;
}
