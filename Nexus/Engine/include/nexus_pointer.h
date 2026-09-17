/**
 * @file nexus_pointer.h
 * @brief Pointer-path scanner for finding stable pointer chains to target addresses.
 *
 * Builds a reverse pointer map of the target process, then searches for
 * chains of dereferences (base -> offset -> ... -> target) that begin at
 * static module addresses.  Supports depth limiting, offset bounds,
 * rescan for path validation, and result persistence.
 */

#ifndef NEXUS_POINTER_H
#define NEXUS_POINTER_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Pointer Scanner Types
 * ============================================================================ */

/* Pointer scan parameters */
typedef struct NexusPointerScanParams {
    uint64_t targetAddress;         /* Address to find pointers to */
    uint64_t baseStart;             /* Start of base address range (0 for auto) */
    uint64_t baseEnd;               /* End of base address range (0 for auto) */
    uint32_t maxLevel;              /* Maximum pointer chain depth (1-7) */
    uint32_t maxOffset;             /* Maximum offset per level */
    uint32_t alignment;             /* Pointer alignment (usually 4 or 8) */
    uint32_t is64Bit;               /* 1 for 64-bit pointers, 0 for 32-bit */
    uint32_t scanWritable;          /* 1 to only scan writable memory */
    uint32_t scanStatic;            /* 1 to only find paths starting from static bases */
    uint32_t maxResults;            /* Maximum results to find (0 for unlimited, default 10000) */
    uint32_t includeSystemModules;  /* 0 to exclude system DLLs (default), 1 to include */
    uint32_t maxOffsetsPerNode;     /* Max different offsets per node (0=unlimited, default 3 like CE) */
    uint32_t allowNegativeOffsets;  /* 1 to allow negative offsets (default), 0 for positive only */
    uint32_t maxVisitsPerAddress;   /* Max times an address can be visited (0=default 4, tuned to match CE) */
    uint32_t threadStackCount;      /* Number of thread stacks to use (0=default 2, CE default) */
    uint32_t stackSize;             /* Stack size for static detection (0=default 4096, CE default) */
} NexusPointerScanParams;

/* Pointer path result - a chain of offsets from a base */
typedef struct NexusPointerPath {
    uint64_t baseAddress;           /* Static base address (module base + offset) */
    uint64_t moduleBase;            /* Module base address */
    wchar_t moduleName[64];         /* Module name containing base */
    int64_t offsets[8];             /* Offset chain */
    uint32_t offsetCount;           /* Number of offsets in chain */
    uint32_t reserved;              /* Padding */
} NexusPointerPath;

/* Pointer scan progress */
typedef struct NexusPointerScanProgress {
    uint64_t addressesScanned;      /* Addresses checked */
    uint64_t addressesTotal;        /* Total addresses to check */
    uint64_t pathsFound;            /* Number of valid paths found */
    uint32_t currentLevel;          /* Current scan depth */
    uint32_t isComplete;            /* 1 if scan is done */
    uint32_t wasCancelled;          /* 1 if scan was cancelled */
    uint32_t reserved;              /* Padding */
} NexusPointerScanProgress;

/* ============================================================================
 * Pointer Scanner Operations
 * ============================================================================ */

/**
 * Create a pointer scanner session.
 * @param process Process handle
 * @param scan Output: pointer scan handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanCreate(
    NexusProcessHandle process,
    NexusPointerScanHandle* scan
);

/**
 * Destroy a pointer scanner session and free resources.
 * @param scan Pointer scan handle
 */
NEXUS_API void Nexus_PointerScanDestroy(NexusPointerScanHandle scan);

/**
 * Start a pointer scan.
 * Scans memory to find all pointer paths to the target address.
 * This is an asynchronous operation - use GetProgress to monitor.
 *
 * @param scan Pointer scan handle
 * @param params Scan parameters
 * @return NEXUS_OK if scan started
 */
NEXUS_API NexusResult Nexus_PointerScanStart(
    NexusPointerScanHandle scan,
    const NexusPointerScanParams* params
);

/**
 * Cancel an in-progress pointer scan.
 * @param scan Pointer scan handle
 */
NEXUS_API void Nexus_PointerScanCancel(NexusPointerScanHandle scan);

/**
 * Get pointer scan progress.
 * @param scan Pointer scan handle
 * @param progress Output: progress information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanGetProgress(
    NexusPointerScanHandle scan,
    NexusPointerScanProgress* progress
);

/**
 * Get the number of pointer paths found.
 * @param scan Pointer scan handle
 * @param count Output: number of paths
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanGetResultCount(
    NexusPointerScanHandle scan,
    uint64_t* count
);

/**
 * Get pointer paths (paginated).
 * @param scan Pointer scan handle
 * @param startIndex Starting index
 * @param buffer Array to receive paths
 * @param bufferCount Size of buffer array
 * @param pathsReturned Output: number of paths returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanGetResults(
    NexusPointerScanHandle scan,
    uint64_t startIndex,
    NexusPointerPath* buffer,
    size_t bufferCount,
    size_t* pathsReturned
);

/**
 * Rescan with existing results to filter invalid paths.
 * Call after the target value has changed location.
 *
 * @param scan Pointer scan handle
 * @param newTargetAddress New address of the target value
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanRescan(
    NexusPointerScanHandle scan,
    uint64_t newTargetAddress
);

/**
 * Save pointer scan results to file.
 * @param scan Pointer scan handle
 * @param path File path (UTF-16)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanSave(
    NexusPointerScanHandle scan,
    const wchar_t* path
);

/**
 * Load pointer scan results from file.
 * @param scan Pointer scan handle (must be created first)
 * @param path File path (UTF-16)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PointerScanLoad(
    NexusPointerScanHandle scan,
    const wchar_t* path
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_POINTER_H */
