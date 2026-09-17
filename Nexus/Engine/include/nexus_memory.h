/**
 * @file nexus_memory.h
 * @brief Memory read/write, region enumeration, snapshots, PE parsing, and pointer resolution.
 *
 * Central header for all remote-process memory operations: raw and typed
 * reads/writes, protected writes with automatic VirtualProtect handling,
 * near-allocation for relative addressing, memory region enumeration,
 * page cache for repeated lookups, memory snapshots, PE export/import/section
 * parsing, multi-level pointer resolution, address expression evaluation,
 * and memory dump/fill utilities.
 */

#ifndef NEXUS_MEMORY_H
#define NEXUS_MEMORY_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * PE Types
 * ============================================================================ */

/* Export/symbol information structure */
typedef struct NexusExportInfo {
    uint64_t address;               /* RVA of the export */
    uint32_t ordinal;               /* Export ordinal */
    uint32_t isForwarded;           /* 1 if forwarded to another DLL */
    char name[256];                 /* Export name (ANSI) */
    char forwardName[256];          /* Forwarded name (DLL.Function) */
} NexusExportInfo;

/* Section information structure */
typedef struct NexusSectionInfo {
    uint64_t virtualAddress;        /* RVA of section */
    uint64_t virtualSize;           /* Virtual size */
    uint64_t rawAddress;            /* File offset */
    uint64_t rawSize;               /* Size in file */
    uint32_t characteristics;       /* Section flags */
    char name[16];                  /* Section name */
} NexusSectionInfo;

/* Import information structure */
typedef struct NexusImportInfo {
    uint64_t iatAddress;            /* Address in IAT */
    uint32_t ordinal;               /* Import ordinal (0 if by name) */
    uint32_t isOrdinal;             /* 1 if imported by ordinal */
    char moduleName[260];           /* DLL name */
    char functionName[256];         /* Function name */
} NexusImportInfo;

/* ============================================================================
 * Memory Region Types
 * ============================================================================ */

/* Memory region information structure */
typedef struct NexusMemoryRegion {
    uint64_t baseAddress;
    uint64_t allocationBase;
    uint64_t size;
    uint64_t allocationSize;  /* Size of full allocation from AllocationBase */
    uint32_t protection;      /* PAGE_* constants */
    uint32_t allocationProtect;
    uint32_t state;           /* MEM_COMMIT, MEM_RESERVE, MEM_FREE */
    uint32_t type;            /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
} NexusMemoryRegion;

/* Extended memory region with additional metadata for snapshots (x64dbg pattern) */
typedef struct NexusMemoryRegionEx {
    uint64_t baseAddress;
    uint64_t size;
    uint32_t protection;    /* PAGE_* constants */
    uint32_t state;         /* MEM_COMMIT, MEM_RESERVE, MEM_FREE */
    uint32_t type;          /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
    int isExecutable;       /* 1 if PAGE_EXECUTE_* */
    int isWritable;         /* 1 if PAGE_*WRITE* */
    int isGuard;            /* 1 if PAGE_GUARD */
    wchar_t moduleName[260]; /* Module name if MEM_IMAGE, empty otherwise */
    wchar_t mappedFileName[520]; /* Mapped file name (from GetMappedFileNameW) */
    uint32_t isCached;      /* 1 if from cache, 0 if freshly queried */
} NexusMemoryRegionEx;

/* ============================================================================
 * Memory Page Cache (x64dbg pattern for performance)
 * ============================================================================ */

/** Opaque handle for memory page cache */
typedef struct NexusMemoryCache* NexusMemoryCacheHandle;

/** Cache entry for a memory page/region */
typedef struct NexusCachedPage {
    uint64_t baseAddress;
    uint64_t size;
    uint32_t protection;
    uint32_t state;
    uint32_t type;
    uint64_t timestamp;     /* Query time for cache invalidation */
    wchar_t mappedFileName[520];
} NexusCachedPage;

/* Memory snapshot filter flags */
typedef enum NexusSnapshotFlags {
    NEXUS_SNAPSHOT_COMMITTED     = 0x0001,  /* Include MEM_COMMIT regions */
    NEXUS_SNAPSHOT_RESERVED      = 0x0002,  /* Include MEM_RESERVE regions */
    NEXUS_SNAPSHOT_PRIVATE       = 0x0004,  /* Include MEM_PRIVATE regions */
    NEXUS_SNAPSHOT_IMAGE         = 0x0008,  /* Include MEM_IMAGE regions */
    NEXUS_SNAPSHOT_MAPPED        = 0x0010,  /* Include MEM_MAPPED regions */
    NEXUS_SNAPSHOT_READABLE      = 0x0020,  /* Include readable regions */
    NEXUS_SNAPSHOT_WRITABLE      = 0x0040,  /* Include writable regions */
    NEXUS_SNAPSHOT_EXECUTABLE    = 0x0080,  /* Include executable regions */
    NEXUS_SNAPSHOT_NO_GUARD      = 0x0100,  /* Exclude PAGE_GUARD regions */
    NEXUS_SNAPSHOT_NO_NOACCESS   = 0x0200,  /* Exclude PAGE_NOACCESS regions */

    /* Common presets */
    NEXUS_SNAPSHOT_SCANNABLE     = 0x0325,  /* Committed + Private + Readable + NoGuard + NoNoaccess */
    NEXUS_SNAPSHOT_ALL           = 0x001F   /* All states and types (no protection filter) */
} NexusSnapshotFlags;

/* Memory snapshot statistics */
typedef struct NexusSnapshotStats {
    size_t regionCount;         /* Total number of regions in snapshot */
    uint64_t totalBytes;        /* Total bytes across all regions */
    uint64_t committedBytes;    /* Bytes in MEM_COMMIT regions */
    uint64_t imageBytes;        /* Bytes in MEM_IMAGE regions */
    uint64_t privateBytes;      /* Bytes in MEM_PRIVATE regions */
    uint64_t mappedBytes;       /* Bytes in MEM_MAPPED regions */
} NexusSnapshotStats;

/* ============================================================================
 * PE Parsing Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetModuleExports(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusExportInfo* buffer,
    size_t bufferCount,
    size_t* exportCount
);

NEXUS_API NexusResult Nexus_GetModuleSections(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusSectionInfo* buffer,
    size_t bufferCount,
    size_t* sectionCount
);

NEXUS_API NexusResult Nexus_GetModuleImports(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusImportInfo* buffer,
    size_t bufferCount,
    size_t* importCount
);

NEXUS_API NexusResult Nexus_FindExportByName(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    const char* exportName,
    NexusExportInfo* exportInfo
);

NEXUS_API NexusResult Nexus_FindExportByOrdinal(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    uint32_t ordinal,
    NexusExportInfo* exportInfo
);

/* ============================================================================
 * Memory Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EnumerateMemoryRegions(
    NexusProcessHandle handle,
    NexusMemoryRegion* buffer,
    size_t bufferCount,
    size_t* regionCount
);

NEXUS_API NexusResult Nexus_AllocateMemory(
    NexusProcessHandle handle,
    uint64_t* address,
    size_t size,
    uint32_t allocationType,
    uint32_t protection
);

NEXUS_API NexusResult Nexus_FreeMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint32_t freeType
);

NEXUS_API NexusResult Nexus_ProtectMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint32_t newProtection,
    uint32_t* oldProtection
);

NEXUS_API NexusResult Nexus_QueryMemory(
    NexusProcessHandle handle,
    uint64_t address,
    NexusMemoryRegion* region
);

/**
 * Get mapped file name for a memory region (x64dbg pattern).
 * Uses GetMappedFileNameW to identify file-backed memory regions.
 *
 * @param handle Process handle
 * @param address Address within the region
 * @param fileName Output: file name (device path format)
 * @param fileNameSize Size of fileName buffer in characters
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if not mapped
 */
NEXUS_API NexusResult Nexus_GetMappedFileName(
    NexusProcessHandle handle,
    uint64_t address,
    wchar_t* fileName,
    size_t fileNameSize
);

/* ============================================================================
 * Memory Page Cache API (x64dbg pattern for 3x+ performance)
 * ============================================================================ */

/**
 * Create a memory page cache for a process.
 * Caches memory region queries for faster repeated lookups.
 *
 * @param handle Process handle
 * @param cache Output: cache handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_MemCacheCreate(
    NexusProcessHandle handle,
    NexusMemoryCacheHandle* cache
);

/**
 * Destroy a memory page cache.
 *
 * @param cache Cache handle
 */
NEXUS_API void Nexus_MemCacheDestroy(NexusMemoryCacheHandle cache);

/**
 * Refresh the memory page cache (query all regions again).
 * Call this after significant process memory changes.
 *
 * @param cache Cache handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_MemCacheRefresh(NexusMemoryCacheHandle cache);

/**
 * Query memory region using cache (fast path).
 * Returns cached data if available, otherwise queries and caches.
 *
 * @param cache Cache handle
 * @param address Address to query
 * @param region Output: region info
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_MemCacheQuery(
    NexusMemoryCacheHandle cache,
    uint64_t address,
    NexusMemoryRegionEx* region
);

/**
 * Get all cached regions.
 *
 * @param cache Cache handle
 * @param regions Output array (can be NULL to just get count)
 * @param maxRegions Maximum regions to return
 * @param regionCount Output: actual region count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_MemCacheGetAll(
    NexusMemoryCacheHandle cache,
    NexusMemoryRegionEx* regions,
    size_t maxRegions,
    size_t* regionCount
);

/**
 * Invalidate a specific address range in the cache.
 * Use after memory allocation/deallocation.
 *
 * @param cache Cache handle
 * @param address Start address
 * @param size Size of range to invalidate
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_MemCacheInvalidate(
    NexusMemoryCacheHandle cache,
    uint64_t address,
    size_t size
);

/* ============================================================================
 * Memory Snapshots
 * ============================================================================ */

NEXUS_API NexusResult Nexus_CaptureMemoryMap(
    NexusProcessHandle handle,
    uint32_t flags,
    NexusMemorySnapshot* snapshot
);

NEXUS_API void Nexus_ReleaseSnapshot(NexusMemorySnapshot snapshot);

NEXUS_API NexusResult Nexus_GetSnapshotStats(
    NexusMemorySnapshot snapshot,
    NexusSnapshotStats* stats
);

NEXUS_API NexusResult Nexus_GetSnapshotRegionCount(
    NexusMemorySnapshot snapshot,
    size_t* count
);

NEXUS_API NexusResult Nexus_GetSnapshotRegion(
    NexusMemorySnapshot snapshot,
    size_t index,
    NexusMemoryRegionEx* region
);

NEXUS_API NexusResult Nexus_GetSnapshotRegions(
    NexusMemorySnapshot snapshot,
    size_t startIndex,
    NexusMemoryRegionEx* buffer,
    size_t bufferCount,
    size_t* regionsReturned
);

NEXUS_API NexusResult Nexus_FindRegionByAddress(
    NexusMemorySnapshot snapshot,
    uint64_t address,
    NexusMemoryRegionEx* region
);

/* ============================================================================
 * Memory Read/Write
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ReadMemory(
    NexusProcessHandle handle,
    uint64_t address,
    void* buffer,
    size_t size,
    size_t* bytesRead
);

NEXUS_API NexusResult Nexus_WriteMemory(
    NexusProcessHandle handle,
    uint64_t address,
    const void* buffer,
    size_t size,
    size_t* bytesWritten
);

/**
 * Write memory with automatic protection handling.
 * Temporarily changes page protection if needed, writes, then restores.
 * This is safer than manually managing VirtualProtectEx for code patching.
 *
 * @param handle Process handle
 * @param address Address to write to
 * @param buffer Data to write
 * @param size Number of bytes to write
 * @param bytesWritten Output: actual bytes written (optional)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_WriteMemoryProtected(
    NexusProcessHandle handle,
    uint64_t address,
    const void* buffer,
    size_t size,
    size_t* bytesWritten
);

/**
 * Allocate memory near a target address (within ±2GB for relative addressing).
 * Useful for code hooks that need relative jumps.
 *
 * @param handle Process handle
 * @param nearAddress Target address to allocate near
 * @param size Size to allocate
 * @param protection Memory protection (PAGE_*)
 * @param allocatedAddress Output: allocated address
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AllocateNear(
    NexusProcessHandle handle,
    uint64_t nearAddress,
    size_t size,
    uint32_t protection,
    uint64_t* allocatedAddress
);

/* ============================================================================
 * Typed Memory Read Helpers
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ReadU8(NexusProcessHandle handle, uint64_t address, uint8_t* value);
NEXUS_API NexusResult Nexus_ReadU16(NexusProcessHandle handle, uint64_t address, uint16_t* value);
NEXUS_API NexusResult Nexus_ReadU32(NexusProcessHandle handle, uint64_t address, uint32_t* value);
NEXUS_API NexusResult Nexus_ReadU64(NexusProcessHandle handle, uint64_t address, uint64_t* value);
NEXUS_API NexusResult Nexus_ReadF32(NexusProcessHandle handle, uint64_t address, float* value);
NEXUS_API NexusResult Nexus_ReadF64(NexusProcessHandle handle, uint64_t address, double* value);
NEXUS_API NexusResult Nexus_ReadPointer(NexusProcessHandle handle, uint64_t address, uint64_t* value);

NEXUS_API NexusResult Nexus_ReadCString(
    NexusProcessHandle handle,
    uint64_t address,
    char* buffer,
    size_t bufferSize,
    size_t* charsRead
);

NEXUS_API NexusResult Nexus_ReadWString(
    NexusProcessHandle handle,
    uint64_t address,
    wchar_t* buffer,
    size_t bufferSize,
    size_t* charsRead
);

/* ============================================================================
 * Typed Memory Write Helpers
 * ============================================================================ */

NEXUS_API NexusResult Nexus_WriteU8(NexusProcessHandle handle, uint64_t address, uint8_t value);
NEXUS_API NexusResult Nexus_WriteU16(NexusProcessHandle handle, uint64_t address, uint16_t value);
NEXUS_API NexusResult Nexus_WriteU32(NexusProcessHandle handle, uint64_t address, uint32_t value);
NEXUS_API NexusResult Nexus_WriteU64(NexusProcessHandle handle, uint64_t address, uint64_t value);
NEXUS_API NexusResult Nexus_WriteF32(NexusProcessHandle handle, uint64_t address, float value);
NEXUS_API NexusResult Nexus_WriteF64(NexusProcessHandle handle, uint64_t address, double value);

/* ============================================================================
 * Pointer Resolution
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ResolvePointer(
    NexusProcessHandle handle,
    uint64_t baseAddress,
    const int64_t* offsets,
    size_t offsetCount,
    uint64_t* resultAddress
);

NEXUS_API NexusResult Nexus_ResolvePointerAndRead(
    NexusProcessHandle handle,
    uint64_t baseAddress,
    const int64_t* offsets,
    size_t offsetCount,
    void* buffer,
    size_t size,
    size_t* bytesRead
);

NEXUS_API NexusResult Nexus_ResolvePointerBatch(
    NexusProcessHandle handle,
    const uint64_t* baseAddresses,
    const int64_t* const* offsetArrays,
    const size_t* offsetCounts,
    size_t count,
    uint64_t* resultAddresses,
    int* successFlags
);

/* ============================================================================
 * Address Resolution (v0.29.0)
 * ============================================================================ */

/**
 * Resolve an address expression to an absolute address.
 * Supports formats like:
 *   - "0x12345678" (hex address)
 *   - "kernel32.dll+0x1234" (module+offset)
 *   - "[0x12345678]" (dereference)
 *   - "kernel32.dll+0x1234+10" (module+offset+offset)
 *
 * @param handle Process handle
 * @param expression Address expression string
 * @param address Output: resolved address
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ResolveAddressExpression(
    NexusProcessHandle handle,
    const char* expression,
    uint64_t* address
);

/* ============================================================================
 * Memory Dump (v0.29.0)
 * ============================================================================ */

/**
 * Dump a memory region to a file.
 *
 * @param handle Process handle
 * @param address Start address
 * @param size Size to dump
 * @param filePath Output file path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DumpMemoryRegion(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    const wchar_t* filePath
);

/* Note: Nexus_DumpModule moved to nexus_dumper.h with enhanced signature */

/* ============================================================================
 * Fill Memory (v0.29.0)
 * ============================================================================ */

/**
 * Fill a memory region with a byte value.
 * Automatically handles memory protection changes.
 *
 * @param handle Process handle
 * @param address Start address
 * @param size Size to fill
 * @param fillByte Byte value to fill with
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_FillMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint8_t fillByte
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_MEMORY_H */
