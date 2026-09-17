/**
 * @file nexus_pageprotect.h
 * @brief Memory page protection query and manipulation.
 *
 * Query and modify per-page protection attributes (read/write/execute,
 * guard, no-access) for target process memory.  Wraps VirtualProtectEx
 * with additional safety checks and batch operations.
 */

#ifndef NEXUS_PAGEPROTECT_H
#define NEXUS_PAGEPROTECT_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Page Protection Constants
 * ============================================================================ */

typedef enum NexusPageProtection {
    NEXUS_PAGE_NOACCESS = 0x01,
    NEXUS_PAGE_READONLY = 0x02,
    NEXUS_PAGE_READWRITE = 0x04,
    NEXUS_PAGE_WRITECOPY = 0x08,
    NEXUS_PAGE_EXECUTE = 0x10,
    NEXUS_PAGE_EXECUTE_READ = 0x20,
    NEXUS_PAGE_EXECUTE_READWRITE = 0x40,
    NEXUS_PAGE_EXECUTE_WRITECOPY = 0x80,
    NEXUS_PAGE_GUARD = 0x100,
    NEXUS_PAGE_NOCACHE = 0x200,
    NEXUS_PAGE_WRITECOMBINE = 0x400,
    NEXUS_PAGE_TARGETS_INVALID = 0x40000000,
    NEXUS_PAGE_TARGETS_NO_UPDATE = 0x40000000
} NexusPageProtection;

typedef enum NexusMemoryState {
    NEXUS_MEM_COMMIT = 0x1000,
    NEXUS_MEM_RESERVE = 0x2000,
    NEXUS_MEM_FREE = 0x10000
} NexusMemoryState;

typedef enum NexusMemoryType {
    NEXUS_MEM_PRIVATE = 0x20000,
    NEXUS_MEM_MAPPED = 0x40000,
    NEXUS_MEM_IMAGE = 0x1000000
} NexusMemoryType;

/* ============================================================================
 * Page Structures
 * ============================================================================ */

typedef struct NexusPageInfo {
    uint64_t baseAddress;               /* Page base address */
    uint64_t allocationBase;            /* Allocation base */
    uint32_t allocationProtect;         /* Initial protection */
    uint32_t reserved1;
    size_t regionSize;                  /* Region size */
    uint32_t state;                     /* NexusMemoryState */
    uint32_t protect;                   /* Current protection */
    uint32_t type;                      /* NexusMemoryType */
    uint32_t reserved2;
    wchar_t moduleName[260];            /* Module name (if image) */
    uint32_t partitionId;               /* Partition ID */
    uint32_t reserved3;
} NexusPageInfo;

typedef struct NexusPageStats {
    size_t totalVirtualSize;            /* Total virtual size */
    size_t committedSize;               /* Committed memory */
    size_t reservedSize;                /* Reserved memory */
    size_t freeSize;                    /* Free space */
    size_t privateSize;                 /* Private pages */
    size_t mappedSize;                  /* Mapped pages */
    size_t imageSize;                   /* Image pages */
    uint32_t executablePages;           /* Pages with execute */
    uint32_t writablePages;             /* Pages with write */
    uint32_t rwxPages;                  /* Pages with RWX */
    uint32_t guardedPages;              /* Pages with guard */
    uint32_t regionCount;               /* Number of regions */
} NexusPageStats;

typedef struct NexusWorkingSetPage {
    uint64_t virtualAddress;            /* Virtual address */
    uint64_t physicalAddress;           /* Physical address (if available) */
    uint32_t protection;                /* Page protection */
    uint32_t shareCount;                /* Share count */
    uint32_t isShared;                  /* Is shared page */
    uint32_t isModified;                /* Page modified (dirty) */
    uint32_t isLocked;                  /* Page locked */
    uint32_t wsIndex;                   /* Working set index */
} NexusWorkingSetPage;

typedef struct NexusWorkingSetStats {
    size_t workingSetSize;              /* Current working set */
    size_t peakWorkingSetSize;          /* Peak working set */
    size_t minimumWorkingSet;           /* Minimum allowed */
    size_t maximumWorkingSet;           /* Maximum allowed */
    uint32_t pageFaultCount;            /* Page faults */
    uint32_t reserved;
    size_t sharedWorkingSet;            /* Shared pages size */
    size_t privateWorkingSet;           /* Private pages size */
    uint32_t pageCount;                 /* Total page count */
    uint32_t sharedPageCount;           /* Shared page count */
    uint32_t privatePageCount;          /* Private page count */
    uint32_t reserved2;
} NexusWorkingSetStats;

/* Page change callback */
typedef void (*NexusPageChangeCallback)(
    uint64_t address,
    size_t size,
    uint32_t oldProtection,
    uint32_t newProtection
);

/* ============================================================================
 * Page Protection Access
 * ============================================================================ */

/**
 * Get page protection for address.
 */
NEXUS_API NexusResult Nexus_PageGetProtection(
    NexusProcessHandle process,
    uint64_t address,
    uint32_t* protection
);

/**
 * Get page protection as string.
 */
NEXUS_API NexusResult Nexus_PageGetProtectionString(
    NexusProcessHandle process,
    uint64_t address,
    char* buffer,
    size_t bufferSize
);

/**
 * Get detailed page information.
 */
NEXUS_API NexusResult Nexus_PageGetInfo(
    NexusProcessHandle process,
    uint64_t address,
    NexusPageInfo* info
);

/**
 * Get pages in address range.
 */
NEXUS_API NexusResult Nexus_PageGetRange(
    NexusProcessHandle process,
    uint64_t startAddress,
    uint64_t endAddress,
    NexusPageInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Page Protection Modification
 * ============================================================================ */

/**
 * Set page protection.
 */
NEXUS_API NexusResult Nexus_PageSetProtection(
    NexusProcessHandle process,
    uint64_t address,
    size_t size,
    uint32_t newProtection,
    uint32_t* oldProtection
);

/**
 * Make page executable.
 */
NEXUS_API NexusResult Nexus_PageMakeExecutable(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Make page writable.
 */
NEXUS_API NexusResult Nexus_PageMakeWritable(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Make page read-only.
 */
NEXUS_API NexusResult Nexus_PageMakeReadOnly(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Remove all protection (PAGE_EXECUTE_READWRITE).
 */
NEXUS_API NexusResult Nexus_PageMakeFullAccess(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Set PAGE_GUARD on page.
 */
NEXUS_API NexusResult Nexus_PageSetGuard(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Remove PAGE_GUARD from page.
 */
NEXUS_API NexusResult Nexus_PageRemoveGuard(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/* ============================================================================
 * Page Analysis
 * ============================================================================ */

/**
 * Find pages with specific protection.
 */
NEXUS_API NexusResult Nexus_PageFindByProtection(
    NexusProcessHandle process,
    uint32_t protection,
    NexusPageInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find executable pages.
 */
NEXUS_API NexusResult Nexus_PageFindExecutable(
    NexusProcessHandle process,
    NexusPageInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find writable+executable pages (RWX).
 */
NEXUS_API NexusResult Nexus_PageFindRwx(
    NexusProcessHandle process,
    NexusPageInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get page statistics for process.
 */
NEXUS_API NexusResult Nexus_PageGetStats(
    NexusProcessHandle process,
    NexusPageStats* stats
);

/**
 * Check if address is readable.
 */
NEXUS_API NexusResult Nexus_PageIsReadable(
    NexusProcessHandle process,
    uint64_t address,
    uint32_t* isReadable
);

/**
 * Check if address is writable.
 */
NEXUS_API NexusResult Nexus_PageIsWritable(
    NexusProcessHandle process,
    uint64_t address,
    uint32_t* isWritable
);

/**
 * Check if address is executable.
 */
NEXUS_API NexusResult Nexus_PageIsExecutable(
    NexusProcessHandle process,
    uint64_t address,
    uint32_t* isExecutable
);

/* ============================================================================
 * Memory Protection Events
 * ============================================================================ */

/**
 * Set callback for page protection changes.
 */
NEXUS_API NexusResult Nexus_PageSetChangeCallback(
    NexusDebuggerHandle debugger,
    NexusPageChangeCallback callback
);

/**
 * Monitor page protection changes in range.
 */
NEXUS_API NexusResult Nexus_PageMonitorRange(
    NexusDebuggerHandle debugger,
    uint64_t startAddress,
    uint64_t endAddress,
    uint32_t* monitorId
);

/**
 * Stop monitoring page protection.
 */
NEXUS_API NexusResult Nexus_PageStopMonitor(
    NexusDebuggerHandle debugger,
    uint32_t monitorId
);

/* ============================================================================
 * Working Set
 * ============================================================================ */

/**
 * Get working set information.
 */
NEXUS_API NexusResult Nexus_PageGetWorkingSet(
    NexusProcessHandle process,
    NexusWorkingSetPage* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get working set statistics.
 */
NEXUS_API NexusResult Nexus_PageGetWorkingSetStats(
    NexusProcessHandle process,
    NexusWorkingSetStats* stats
);

/**
 * Check if page is in working set.
 */
NEXUS_API NexusResult Nexus_PageIsInWorkingSet(
    NexusProcessHandle process,
    uint64_t address,
    uint32_t* isInWorkingSet
);

/**
 * Lock pages in working set.
 */
NEXUS_API NexusResult Nexus_PageLock(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Unlock pages from working set.
 */
NEXUS_API NexusResult Nexus_PageUnlock(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/* ============================================================================
 * DEP/NX
 * ============================================================================ */

/**
 * Check if DEP is enabled for process.
 */
NEXUS_API NexusResult Nexus_PageGetDepPolicy(
    NexusProcessHandle process,
    uint32_t* depEnabled,
    uint32_t* permanentDep
);

/**
 * Set DEP policy for process (if allowed).
 */
NEXUS_API NexusResult Nexus_PageSetDepPolicy(
    NexusProcessHandle process,
    uint32_t enable
);

/**
 * Add DEP exception for address range.
 */
NEXUS_API NexusResult Nexus_PageAddDepException(
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_PAGEPROTECT_H */
