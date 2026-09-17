/**
 * @file pointerscan.cpp
 * @brief Pointer scanner API: lifecycle, progress, results, rescan, persistence, and module loading.
 *
 * Manages pointer-scan sessions: creation/destruction, async scan
 * start/cancel, progress queries, paginated result retrieval, rescan
 * for path validation, and binary save/load of results.  Also
 * enumerates modules and thread stacks to identify static base
 * addresses.
 *
 * The recursive scan algorithm is in pointerscan_scan.cpp.
 */

#include "pointerscan_internal.h"

/* ============================================================================
 * Module & Thread Stack Loading
 * ============================================================================ */

static bool IsSystemModulePath(const std::wstring& path) {
    std::wstring lowerPath = path;
    for (auto& c : lowerPath) c = towlower(c);

    if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
    if (lowerPath.find(L"\\windows\\winsxs\\") != std::wstring::npos) return true;

    size_t lastSlash = lowerPath.rfind(L'\\');
    std::wstring fileName = (lastSlash != std::wstring::npos) ? lowerPath.substr(lastSlash + 1) : lowerPath;

    if (fileName == L"coreclr.dll") return false;
    if (fileName == L"hostfxr.dll") return false;
    if (fileName == L"hostpolicy.dll") return false;

    if (fileName.find(L"system.") == 0) return true;
    if (fileName.find(L"microsoft.") == 0) return true;
    if (fileName == L"mscorlib.dll") return true;
    if (fileName == L"netstandard.dll") return true;

    return false;
}

static void LoadModules(PointerScanContext* ctx) {
    HANDLE process = ctx->process->processHandle;

    HMODULE modules[1024];
    DWORD needed;

    if (EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; i++) {
            MODULEINFO modInfo;
            wchar_t modName[MAX_PATH];
            wchar_t modPath[MAX_PATH];

            if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)) &&
                GetModuleBaseNameW(process, modules[i], modName, MAX_PATH)) {

                ModuleRange range;
                range.base = (uint64_t)modInfo.lpBaseOfDll;
                range.end = range.base + modInfo.SizeOfImage;
                range.name = modName;

                if (GetModuleFileNameExW(process, modules[i], modPath, MAX_PATH)) {
                    range.path = modPath;
                    range.isSystemModule = IsSystemModulePath(range.path);
                } else {
                    range.path = modName;
                    range.isSystemModule = false;
                }

                ctx->modules.push_back(range);
            }
        }
    }
}

static void LoadThreadStacks(PointerScanContext* ctx) {
    HANDLE process = ctx->process->processHandle;
    DWORD processId = ctx->process->processId;

    static NtQueryInformationThreadFunc NtQueryInformationThread = nullptr;
    if (!NtQueryInformationThread) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            NtQueryInformationThread = (NtQueryInformationThreadFunc)GetProcAddress(ntdll, "NtQueryInformationThread");
        }
    }
    if (!NtQueryInformationThread) return;

    std::vector<DWORD> threadIds;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                threadIds.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);

    std::sort(threadIds.begin(), threadIds.end());

    uint64_t kernel32Base = 0, kernel32Size = 0;
    for (const auto& mod : ctx->modules) {
        std::wstring lowerName = mod.name;
        for (auto& c : lowerName) c = towlower(c);
        if (lowerName == L"kernel32.dll") {
            kernel32Base = mod.base;
            kernel32Size = mod.end - mod.base;
            break;
        }
    }

    int stackIndex = 0;
    uint32_t maxStacks = ctx->params.threadStackCount;
    if (maxStacks == 0) maxStacks = 2;
    for (DWORD threadId : threadIds) {
        if (stackIndex >= (int)maxStacks) break;

        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!thread) continue;

        THREAD_BASIC_INFORMATION tbi = {};
        NTSTATUS status = NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi), nullptr);
        CloseHandle(thread);

        if (status != 0 || !tbi.TebBaseAddress) continue;

        uint64_t stackBase = 0, stackLimit = 0;
        if (ctx->params.is64Bit) {
            uint64_t tebAddr = (uint64_t)tbi.TebBaseAddress;
            PtrScanReadMem(process, tebAddr + 0x08, &stackBase, 8);
            PtrScanReadMem(process, tebAddr + 0x10, &stackLimit, 8);
        } else {
            uint32_t base32 = 0, limit32 = 0;
            uint64_t tebAddr = (uint64_t)tbi.TebBaseAddress;
            PtrScanReadMem(process, tebAddr + 0x04, &base32, 4);
            PtrScanReadMem(process, tebAddr + 0x08, &limit32, 4);
            stackBase = base32;
            stackLimit = limit32;
        }

        if (stackBase > stackLimit && stackLimit > 0) {
            uint64_t stackReference = 0;
            size_t scanSize = ctx->params.stackSize;
            if (scanSize == 0) scanSize = 4096;

            if (kernel32Base > 0 && kernel32Size > 0) {
                std::vector<uint8_t> stackBuf(scanSize);
                uint64_t scanStart = stackBase - scanSize;
                if (PtrScanReadMem(process, scanStart, stackBuf.data(), scanSize)) {
                    size_t ptrSize = ctx->params.is64Bit ? 8 : 4;
                    for (int i = (int)(scanSize / ptrSize) - 1; i >= 0; i--) {
                        uint64_t ptr;
                        if (ptrSize == 8) {
                            ptr = *reinterpret_cast<uint64_t*>(&stackBuf[i * ptrSize]);
                        } else {
                            ptr = *reinterpret_cast<uint32_t*>(&stackBuf[i * ptrSize]);
                        }
                        if (ptr >= kernel32Base && ptr < kernel32Base + kernel32Size) {
                            stackReference = scanStart + (i * ptrSize);
                            break;
                        }
                    }
                }
            }

            if (stackReference == 0) {
                stackReference = stackBase;
            }

            ThreadStackRange stack;
            stack.stackBase = stackReference;
            stack.stackLimit = stackLimit;
            stack.threadId = threadId;
            stack.name = L"threadstack" + std::to_wstring(stackIndex);
            ctx->threadStacks.push_back(stack);
            stackIndex++;
        }
    }
}

/* ============================================================================
 * Scanner Lifecycle
 * ============================================================================ */

NEXUS_API NexusResult Nexus_PointerScanCreate(
    NexusProcessHandle process,
    NexusPointerScanHandle* scan
) {
    if (!process || !scan) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = new PointerScanContext();
    ctx->process = static_cast<ProcessContext*>(process);
    ctx->addressesScanned = 0;
    ctx->addressesTotal = 0;
    ctx->currentLevel = 0;
    ctx->isComplete = false;
    ctx->cancelled = false;
    ctx->threadStarted = false;
    ctx->maxResults = 10000;
    ctx->resultCount = 0;

    LoadModules(ctx);

    *scan = ctx;
    return NEXUS_OK;
}

NEXUS_API void Nexus_PointerScanDestroy(NexusPointerScanHandle scan) {
    if (!scan) return;

    auto* ctx = static_cast<PointerScanContext*>(scan);

    ctx->cancelled = true;
    if (ctx->threadStarted && ctx->workerThread.joinable()) {
        ctx->workerThread.join();
    }

    delete ctx;
}

NEXUS_API NexusResult Nexus_PointerScanStart(
    NexusPointerScanHandle scan,
    const NexusPointerScanParams* params
) {
    if (!scan || !params) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);

    if (params->maxLevel < 1 || params->maxLevel > 7) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ctx->params = *params;

    if (ctx->params.alignment == 0) {
        ctx->params.alignment = ctx->params.is64Bit ? 8 : 4;
    }
    if (ctx->params.maxOffset == 0) {
        ctx->params.maxOffset = 4095;
    }
    ctx->maxResults = ctx->params.maxResults > 0 ? ctx->params.maxResults : 10000;
    if (ctx->params.maxOffsetsPerNode == 0) {
        ctx->params.maxOffsetsPerNode = 3;
    }

    ctx->results.clear();
    ctx->reversePointerMap.clear();
    ctx->globalVisitCount.clear();
    ctx->validRegions.clear();
    ctx->threadStacks.clear();
    ctx->addressesScanned = 0;
    ctx->addressesTotal = 0;
    ctx->currentLevel = 0;
    ctx->isComplete = false;
    ctx->cancelled = false;
    ctx->resultCount = 0;

    LoadThreadStacks(ctx);

    if (ctx->threadStarted && ctx->workerThread.joinable()) {
        ctx->workerThread.join();
    }
    ctx->workerThread = std::thread(ScanWorker, ctx);
    ctx->threadStarted = true;

    return NEXUS_OK;
}

NEXUS_API void Nexus_PointerScanCancel(NexusPointerScanHandle scan) {
    if (!scan) return;
    auto* ctx = static_cast<PointerScanContext*>(scan);
    ctx->cancelled = true;
}

/* ============================================================================
 * Progress & Results
 * ============================================================================ */

NEXUS_API NexusResult Nexus_PointerScanGetProgress(
    NexusPointerScanHandle scan,
    NexusPointerScanProgress* progress
) {
    if (!scan || !progress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);

    progress->addressesScanned = ctx->addressesScanned;
    progress->addressesTotal = ctx->addressesTotal;
    progress->currentLevel = ctx->currentLevel;
    progress->isComplete = ctx->isComplete ? 1 : 0;
    progress->wasCancelled = ctx->cancelled ? 1 : 0;
    progress->pathsFound = ctx->resultCount.load(std::memory_order_relaxed);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_PointerScanGetResultCount(
    NexusPointerScanHandle scan,
    uint64_t* count
) {
    if (!scan || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);
    std::lock_guard<std::mutex> lock(ctx->resultsMutex);
    *count = ctx->results.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_PointerScanGetResults(
    NexusPointerScanHandle scan,
    uint64_t startIndex,
    NexusPointerPath* buffer,
    size_t bufferCount,
    size_t* pathsReturned
) {
    if (!scan || !pathsReturned) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);
    std::lock_guard<std::mutex> lock(ctx->resultsMutex);

    *pathsReturned = 0;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    if (startIndex >= ctx->results.size()) {
        return NEXUS_OK;
    }

    size_t available = ctx->results.size() - (size_t)startIndex;
    size_t toCopy = min(available, bufferCount);

    for (size_t i = 0; i < toCopy; i++) {
        buffer[i] = ctx->results[(size_t)startIndex + i];
    }

    *pathsReturned = toCopy;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_PointerScanRescan(
    NexusPointerScanHandle scan,
    uint64_t newTargetAddress
) {
    if (!scan) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);
    std::lock_guard<std::mutex> lock(ctx->resultsMutex);

    HANDLE process = ctx->process->processHandle;
    size_t pointerSize = ctx->params.is64Bit ? 8 : 4;

    std::vector<NexusPointerPath> validPaths;

    for (auto& path : ctx->results) {
        uint64_t currentAddr = path.baseAddress;

        bool valid = true;
        for (uint32_t i = 0; i < path.offsetCount && valid; i++) {
            uint64_t ptrValue;
            if (pointerSize == 8) {
                if (!PtrScanReadMem(process, currentAddr, &ptrValue, 8)) {
                    valid = false;
                    break;
                }
            } else {
                uint32_t ptr32;
                if (!PtrScanReadMem(process, currentAddr, &ptr32, 4)) {
                    valid = false;
                    break;
                }
                ptrValue = ptr32;
            }

            currentAddr = ptrValue + path.offsets[i];
        }

        if (valid && currentAddr == newTargetAddress) {
            validPaths.push_back(path);
        }
    }

    ctx->results = std::move(validPaths);
    return NEXUS_OK;
}

/* ============================================================================
 * Save/Load
 * ============================================================================ */

NEXUS_API NexusResult Nexus_PointerScanSave(
    NexusPointerScanHandle scan,
    const wchar_t* path
) {
    if (!scan || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);
    std::lock_guard<std::mutex> lock(ctx->resultsMutex);

    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    uint32_t magic = 0x4E585053; // "NXPS"
    uint32_t version = 1;
    uint64_t count = ctx->results.size();

    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    file.write(reinterpret_cast<const char*>(&ctx->params), sizeof(ctx->params));
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& result : ctx->results) {
        file.write(reinterpret_cast<const char*>(&result), sizeof(result));
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_PointerScanLoad(
    NexusPointerScanHandle scan,
    const wchar_t* path
) {
    if (!scan || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<PointerScanContext*>(scan);
    std::lock_guard<std::mutex> lock(ctx->resultsMutex);

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    uint32_t magic, version;
    uint64_t count;

    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != 0x4E585053) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    file.read(reinterpret_cast<char*>(&ctx->params), sizeof(ctx->params));
    file.read(reinterpret_cast<char*>(&count), sizeof(count));

    if (count > MAX_POINTER_RESULTS_LOAD) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ctx->results.clear();
    try {
        ctx->results.resize((size_t)count);
    } catch (const std::bad_alloc&) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        file.read(reinterpret_cast<char*>(&ctx->results[i]), sizeof(NexusPointerPath));
        if (!file) {
            ctx->results.clear();
            return NEXUS_ERROR_UNKNOWN;
        }
    }

    ctx->isComplete = true;

    return NEXUS_OK;
}
