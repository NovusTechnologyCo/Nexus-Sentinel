/**
 * @file memory.cpp
 * @brief Core memory operations: region enumeration, read/write, protected write, and allocation.
 *
 * Implements the fundamental remote-process memory primitives:
 *   - VirtualQueryEx-based region enumeration with 32/64-bit awareness
 *   - ReadProcessMemory / WriteProcessMemory wrappers with error mapping
 *   - Protected write: automatic VirtualProtectEx toggle for code patching
 *   - Near allocation: spiral search within +/-2 GB for rel32 addressing
 *   - Standard allocate / free / protect / query wrappers
 *   - Mapped-file-name retrieval via GetMappedFileNameW
 *
 * Typed accessors live in memory_typed.cpp; the page cache in memory_cache.cpp.
 */

#include "memory_internal.h"

#include <vector>

/* ============================================================================
 * Memory Region Enumeration
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_EnumerateMemoryRegions(
    NexusProcessHandle handle,
    NexusMemoryRegion* buffer,
    size_t bufferCount,
    size_t* regionCount
) {
    if (!handle || !regionCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    size_t count = 0;
    NexusResult result = NEXUS_OK;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t address = 0;

    /* For 32-bit processes, limit scan range */
    /* Note: 0x7FFE0000 accounts for the 64KB boundary at top of user space */
    uint64_t maxAddress = data->is32Bit ? 0x7FFE0000ULL : 0x7FFFFFFFFFFFULL;

    while (address < maxAddress) {
        SIZE_T queryResult = VirtualQueryEx(
            data->hProcess,
            reinterpret_cast<LPCVOID>(address),
            &mbi,
            sizeof(mbi)
        );

        if (queryResult == 0) {
            break;
        }

        /* Only report committed or reserved regions */
        if (mbi.State != MEM_FREE) {
            if (buffer && count < bufferCount) {
                NexusMemoryRegion* region = &buffer[count];
                region->baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                region->allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
                region->size = mbi.RegionSize;
                region->allocationSize = 0;  /* Not calculated during enumeration for performance */
                region->protection = mbi.Protect;
                region->allocationProtect = mbi.AllocationProtect;
                region->state = mbi.State;
                region->type = mbi.Type;
            }
            count++;
        }

        /* Move to next region */
        address = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;

        /* Prevent infinite loop on overflow */
        if (address < reinterpret_cast<uint64_t>(mbi.BaseAddress)) {
            break;
        }
    }

    *regionCount = count;

    if (buffer && count > bufferCount) {
        result = NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return result;
}

/* ============================================================================
 * Memory Read/Write
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ReadMemory(
    NexusProcessHandle handle,
    uint64_t address,
    void* buffer,
    size_t size,
    size_t* bytesRead
) {
    if (!handle || !buffer || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    SIZE_T read = 0;
    BOOL success = ReadProcessMemory(
        data->hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &read
    );

    if (bytesRead) {
        *bytesRead = read;
    }

    if (!success) {
        DWORD err = GetLastError();
        if (err == ERROR_PARTIAL_COPY && read > 0) {
            return NEXUS_ERROR_PARTIAL_READ;
        }
        if (err == ERROR_ACCESS_DENIED) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
        return NEXUS_ERROR_UNKNOWN;
    }

    if (read < size) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_WriteMemory(
    NexusProcessHandle handle,
    uint64_t address,
    const void* buffer,
    size_t size,
    size_t* bytesWritten
) {
    if (!handle || !buffer || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    SIZE_T written = 0;
    BOOL success = WriteProcessMemory(
        data->hProcess,
        reinterpret_cast<LPVOID>(address),
        buffer,
        size,
        &written
    );

    if (bytesWritten) {
        *bytesWritten = written;
    }

    if (!success) {
        DWORD err = GetLastError();
        if (err == ERROR_PARTIAL_COPY && written > 0) {
            return NEXUS_ERROR_PARTIAL_WRITE;
        }
        if (err == ERROR_ACCESS_DENIED) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
        return NEXUS_ERROR_UNKNOWN;
    }

    if (written < size) {
        return NEXUS_ERROR_PARTIAL_WRITE;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Protected Memory Write (v0.24.0)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_WriteMemoryProtected(
    NexusProcessHandle handle,
    uint64_t address,
    const void* buffer,
    size_t size,
    size_t* bytesWritten
) {
    if (!handle || !buffer || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    /* First, try normal write - this will succeed if memory is already writable */
    SIZE_T written = 0;
    if (WriteProcessMemory(data->hProcess, reinterpret_cast<LPVOID>(address),
                          buffer, size, &written)) {
        if (bytesWritten) *bytesWritten = written;
        return (written == size) ? NEXUS_OK : NEXUS_ERROR_PARTIAL_WRITE;
    }

    /* Write failed - likely due to protection. Change protection temporarily. */
    DWORD lastError = GetLastError();
    if (lastError != ERROR_ACCESS_DENIED && lastError != ERROR_NOACCESS) {
        /* Different error - not a protection issue */
        if (bytesWritten) *bytesWritten = written;
        return NEXUS_ERROR_UNKNOWN;
    }

    /*
     * Handle writes that span multiple pages.
     * We need to change protection for each page that the write touches.
     */
    uint64_t pageSize = 0x1000; /* Standard 4KB page */
    uint64_t startPage = address & ~(pageSize - 1);
    uint64_t endAddress = address + size;
    uint64_t endPage = (endAddress + pageSize - 1) & ~(pageSize - 1);

    /* Store original protections for each page */
    std::vector<std::pair<uint64_t, DWORD>> pageProtections;
    bool protectionChanged = true;

    for (uint64_t page = startPage; page < endPage; page += pageSize) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(data->hProcess, reinterpret_cast<LPCVOID>(page),
                          &mbi, sizeof(mbi)) == 0) {
            protectionChanged = false;
            break;
        }

        /* Determine new protection - keep execute if present, add write */
        DWORD newProtect = PAGE_READWRITE;
        if (mbi.Protect & PAGE_EXECUTE) {
            newProtect = PAGE_EXECUTE_READWRITE;
        } else if (mbi.Protect & PAGE_EXECUTE_READ) {
            newProtect = PAGE_EXECUTE_READWRITE;
        } else if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
            /* Already writable - shouldn't happen but handle it */
            newProtect = PAGE_EXECUTE_READWRITE;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(data->hProcess, reinterpret_cast<LPVOID>(page),
                             pageSize, newProtect, &oldProtect)) {
            /* If we fail to change protection, restore what we changed */
            for (auto& pp : pageProtections) {
                DWORD ignored;
                VirtualProtectEx(data->hProcess, reinterpret_cast<LPVOID>(pp.first),
                                pageSize, pp.second, &ignored);
            }
            if (bytesWritten) *bytesWritten = 0;
            return NEXUS_ERROR_ACCESS_DENIED;
        }

        pageProtections.push_back({page, oldProtect});
    }

    /* Now try the write again */
    written = 0;
    BOOL success = WriteProcessMemory(data->hProcess, reinterpret_cast<LPVOID>(address),
                                      buffer, size, &written);

    /* Restore original protections */
    for (auto& pp : pageProtections) {
        DWORD ignored;
        VirtualProtectEx(data->hProcess, reinterpret_cast<LPVOID>(pp.first),
                        pageSize, pp.second, &ignored);
    }

    /* Flush instruction cache if we wrote to executable memory */
    if (success) {
        FlushInstructionCache(data->hProcess, reinterpret_cast<LPCVOID>(address), size);
    }

    if (bytesWritten) {
        *bytesWritten = written;
    }

    if (!success) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return (written == size) ? NEXUS_OK : NEXUS_ERROR_PARTIAL_WRITE;
}

/* ============================================================================
 * Near Memory Allocation (v0.24.0)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AllocateNear(
    NexusProcessHandle handle,
    uint64_t nearAddress,
    size_t size,
    uint32_t protection,
    uint64_t* allocatedAddress
) {
    if (!handle || size == 0 || !allocatedAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    /* For 32-bit processes, we can allocate anywhere - the entire address space is reachable */
    if (data->is32Bit) {
        LPVOID addr = VirtualAllocEx(data->hProcess, nullptr, size,
                                     MEM_COMMIT | MEM_RESERVE, protection);
        if (addr) {
            *allocatedAddress = reinterpret_cast<uint64_t>(addr);
            return NEXUS_OK;
        }
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    /*
     * For 64-bit: We need to allocate within ±2GB of the target address
     * for relative 32-bit addressing (jmp rel32, call rel32, etc.)
     */
    const int64_t maxOffset = 0x7FFFFFFFLL - static_cast<int64_t>(size);
    const int64_t minOffset = -0x80000000LL;

    /* Calculate search range */
    uint64_t minAddress = (static_cast<int64_t>(nearAddress) + minOffset > 0)
        ? nearAddress + minOffset : 0x10000; /* Avoid null page area */
    uint64_t maxAddress = nearAddress + maxOffset;

    /* Clamp to user space */
    if (maxAddress > 0x7FFFFFFFFFFFULL) {
        maxAddress = 0x7FFFFFFFFFFFULL;
    }

    /* Round up to page boundary */
    uint64_t allocationGranularity = 0x10000; /* 64KB alignment for VirtualAlloc */
    size_t roundedSize = (size + 0xFFF) & ~0xFFF; /* Round up to page size */

    /*
     * Search strategy: Start near the target and spiral outward.
     * First try below, then above, alternating with increasing distance.
     */
    uint64_t searchStart = nearAddress & ~(allocationGranularity - 1);

    /* Try addresses below first (often more free space) */
    for (uint64_t offset = 0; offset < static_cast<uint64_t>(maxOffset); offset += allocationGranularity) {
        /* Try below */
        if (searchStart >= offset + allocationGranularity) {
            uint64_t tryAddr = searchStart - offset - allocationGranularity;
            if (tryAddr >= minAddress) {
                LPVOID addr = VirtualAllocEx(data->hProcess,
                                            reinterpret_cast<LPVOID>(tryAddr),
                                            roundedSize,
                                            MEM_COMMIT | MEM_RESERVE,
                                            protection);
                if (addr) {
                    *allocatedAddress = reinterpret_cast<uint64_t>(addr);
                    return NEXUS_OK;
                }
            }
        }

        /* Try above */
        uint64_t tryAddr = searchStart + offset + allocationGranularity;
        if (tryAddr <= maxAddress && tryAddr + roundedSize > tryAddr) { /* Check for overflow */
            LPVOID addr = VirtualAllocEx(data->hProcess,
                                        reinterpret_cast<LPVOID>(tryAddr),
                                        roundedSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        protection);
            if (addr) {
                *allocatedAddress = reinterpret_cast<uint64_t>(addr);
                return NEXUS_OK;
            }
        }
    }

    /* Last resort - let the OS choose and hope it's close enough */
    LPVOID addr = VirtualAllocEx(data->hProcess, nullptr, size,
                                 MEM_COMMIT | MEM_RESERVE, protection);
    if (addr) {
        uint64_t allocated = reinterpret_cast<uint64_t>(addr);
        int64_t distance = static_cast<int64_t>(allocated) - static_cast<int64_t>(nearAddress);

        /* Check if it's within range */
        if (distance >= minOffset && distance <= maxOffset) {
            *allocatedAddress = allocated;
            return NEXUS_OK;
        }

        /* Not within range - free and fail */
        VirtualFreeEx(data->hProcess, addr, 0, MEM_RELEASE);
    }

    return NEXUS_ERROR_OUT_OF_MEMORY;
}

/* ============================================================================
 * Memory Allocation & Protection
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AllocateMemory(
    NexusProcessHandle handle,
    uint64_t* address,
    size_t size,
    uint32_t allocationType,
    uint32_t protection
) {
    if (!handle || !address || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    LPVOID preferredAddress = (*address != 0) ? reinterpret_cast<LPVOID>(*address) : nullptr;

    LPVOID result = VirtualAllocEx(
        data->hProcess,
        preferredAddress,
        size,
        allocationType,
        protection
    );

    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
        return NEXUS_ERROR_UNKNOWN;
    }

    *address = reinterpret_cast<uint64_t>(result);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_FreeMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint32_t freeType
) {
    if (!handle || address == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    /* For MEM_RELEASE, size must be 0 */
    SIZE_T freeSize = (freeType == MEM_RELEASE) ? 0 : size;

    BOOL result = VirtualFreeEx(
        data->hProcess,
        reinterpret_cast<LPVOID>(address),
        freeSize,
        freeType
    );

    if (!result) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProtectMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint32_t newProtection,
    uint32_t* oldProtection
) {
    if (!handle || address == 0 || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    DWORD oldProt = 0;
    BOOL result = VirtualProtectEx(
        data->hProcess,
        reinterpret_cast<LPVOID>(address),
        size,
        newProtection,
        &oldProt
    );

    if (!result) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (oldProtection) {
        *oldProtection = oldProt;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_QueryMemory(
    NexusProcessHandle handle,
    uint64_t address,
    NexusMemoryRegion* region
) {
    if (!handle || !region) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result = VirtualQueryEx(
        data->hProcess,
        reinterpret_cast<LPCVOID>(address),
        &mbi,
        sizeof(mbi)
    );

    if (result == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    region->baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    region->allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
    region->size = mbi.RegionSize;
    region->protection = mbi.Protect;
    region->allocationProtect = mbi.AllocationProtect;
    region->state = mbi.State;
    region->type = mbi.Type;

    /* Calculate total allocation size by walking regions from AllocationBase */
    region->allocationSize = 0;
    if (mbi.AllocationBase) {
        uint64_t addr = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        MEMORY_BASIC_INFORMATION walkMbi;
        while (VirtualQueryEx(data->hProcess, reinterpret_cast<LPCVOID>(addr), &walkMbi, sizeof(walkMbi))) {
            if (walkMbi.AllocationBase != mbi.AllocationBase) break;
            region->allocationSize += walkMbi.RegionSize;
            addr += walkMbi.RegionSize;
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetMappedFileName(
    NexusProcessHandle handle,
    uint64_t address,
    wchar_t* fileName,
    size_t fileNameSize
) {
    if (!handle || !fileName || fileNameSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    DWORD len = GetMappedFileNameW(
        data->hProcess,
        reinterpret_cast<LPVOID>(address),
        fileName,
        (DWORD)(fileNameSize - 1)
    );

    if (len == 0) {
        fileName[0] = L'\0';
        return NEXUS_ERROR_NOT_FOUND;
    }

    fileName[len] = L'\0';
    return NEXUS_OK;
}

} /* extern "C" */
