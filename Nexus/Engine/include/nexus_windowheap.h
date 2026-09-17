/**
 * @file nexus_windowheap.h
 * @brief Window, GDI object, and heap enumeration for target processes.
 *
 * Enumerate top-level and child windows, GDI handles, and process
 * heaps with per-block information.  Useful for UI analysis and
 * heap-based memory exploration.
 */

#ifndef NEXUS_WINDOWHEAP_H
#define NEXUS_WINDOWHEAP_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Window Structures
 * ============================================================================ */

typedef struct NexusWindowInfo {
    uint64_t hwnd;                      /* Window handle */
    uint64_t parentHwnd;                /* Parent window handle */
    uint64_t ownerHwnd;                 /* Owner window handle */
    uint32_t processId;                 /* Owner process ID */
    uint32_t threadId;                  /* Owner thread ID */
    wchar_t className[256];             /* Window class name */
    wchar_t windowText[256];            /* Window text/title */
    int32_t x;                          /* X position */
    int32_t y;                          /* Y position */
    int32_t width;                      /* Width */
    int32_t height;                     /* Height */
    uint32_t style;                     /* Window style */
    uint32_t exStyle;                   /* Extended style */
    uint32_t isVisible;                 /* 1 if visible */
    uint32_t isEnabled;                 /* 1 if enabled */
    uint32_t isUnicode;                 /* 1 if Unicode window */
    uint32_t reserved;
    uint64_t wndProc;                   /* Window procedure address */
    uint64_t userData;                  /* User data pointer */
} NexusWindowInfo;

typedef struct NexusGdiObject {
    uint64_t handle;                    /* GDI object handle */
    uint32_t objectType;                /* GDI object type */
    uint32_t processId;                 /* Owner process ID */
    uint32_t unique;                    /* Unique identifier */
    uint32_t reserved;
    uint64_t kernelAddress;             /* Kernel object address */
} NexusGdiObject;

/* ============================================================================
 * Heap Structures
 * ============================================================================ */

typedef struct NexusHeapInfo {
    uint64_t heapId;                    /* Heap identifier */
    uint64_t baseAddress;               /* Heap base address */
    uint64_t reservedSize;              /* Reserved size */
    uint64_t committedSize;             /* Committed size */
    uint32_t flags;                     /* Heap flags */
    uint32_t blockCount;                /* Number of blocks */
    uint32_t isDefault;                 /* 1 if default process heap */
    uint32_t reserved;
} NexusHeapInfo;

typedef struct NexusHeapBlock {
    uint64_t address;                   /* Block address */
    uint64_t size;                      /* Block size */
    uint64_t heapId;                    /* Parent heap ID */
    uint32_t flags;                     /* Block flags */
    uint32_t isFree;                    /* 1 if free block */
    uint32_t isMoveable;                /* 1 if moveable */
    uint32_t reserved;
} NexusHeapBlock;

typedef struct NexusHeapStats {
    uint32_t heapCount;                 /* Number of heaps */
    uint64_t totalReserved;             /* Total reserved memory */
    uint64_t totalCommitted;            /* Total committed memory */
    uint64_t totalFreeBlocks;           /* Total free blocks */
    uint64_t totalUsedBlocks;           /* Total used blocks */
    uint64_t largestFreeBlock;          /* Largest free block */
    uint32_t fragmentationPercent;      /* Fragmentation percentage */
    uint32_t reserved;
} NexusHeapStats;

/* ============================================================================
 * Window Enumeration
 * ============================================================================ */

/**
 * Get all windows for process.
 */
NEXUS_API NexusResult Nexus_WindowGetAll(
    uint32_t processId,
    NexusWindowInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get top-level windows for process.
 */
NEXUS_API NexusResult Nexus_WindowGetTopLevel(
    uint32_t processId,
    NexusWindowInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get child windows.
 */
NEXUS_API NexusResult Nexus_WindowGetChildren(
    uint64_t parentHwnd,
    NexusWindowInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get window info by handle.
 */
NEXUS_API NexusResult Nexus_WindowGetInfo(
    uint64_t hwnd,
    NexusWindowInfo* info
);

/**
 * Find windows by class name.
 */
NEXUS_API NexusResult Nexus_WindowFindByClass(
    uint32_t processId,
    const wchar_t* className,
    NexusWindowInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find windows by title.
 */
NEXUS_API NexusResult Nexus_WindowFindByTitle(
    uint32_t processId,
    const wchar_t* title,
    uint32_t partialMatch,
    NexusWindowInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Window Operations
 * ============================================================================ */

/**
 * Get window text.
 */
NEXUS_API NexusResult Nexus_WindowGetText(
    uint64_t hwnd,
    wchar_t* buffer,
    size_t bufferSize
);

/**
 * Set window text.
 */
NEXUS_API NexusResult Nexus_WindowSetText(
    uint64_t hwnd,
    const wchar_t* text
);

/**
 * Get window procedure address.
 */
NEXUS_API NexusResult Nexus_WindowGetProc(
    NexusProcessHandle process,
    uint64_t hwnd,
    uint64_t* wndProc
);

/**
 * Post message to window.
 */
NEXUS_API NexusResult Nexus_WindowPostMessage(
    uint64_t hwnd,
    uint32_t msg,
    uint64_t wParam,
    uint64_t lParam
);

/**
 * Send message to window.
 */
NEXUS_API NexusResult Nexus_WindowSendMessage(
    uint64_t hwnd,
    uint32_t msg,
    uint64_t wParam,
    uint64_t lParam,
    uint64_t* result
);

/* ============================================================================
 * GDI Object Enumeration
 * ============================================================================ */

/**
 * Get GDI objects for process.
 */
NEXUS_API NexusResult Nexus_GdiGetObjects(
    uint32_t processId,
    NexusGdiObject* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get GDI objects by type.
 */
NEXUS_API NexusResult Nexus_GdiGetObjectsByType(
    uint32_t processId,
    uint32_t objectType,
    NexusGdiObject* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get GDI object count.
 */
NEXUS_API NexusResult Nexus_GdiGetObjectCount(
    uint32_t processId,
    uint32_t* count
);

/* ============================================================================
 * Heap Enumeration
 * ============================================================================ */

/**
 * Get heaps for process.
 */
NEXUS_API NexusResult Nexus_HeapGetAll(
    NexusProcessHandle process,
    NexusHeapInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get default process heap.
 */
NEXUS_API NexusResult Nexus_HeapGetDefault(
    NexusProcessHandle process,
    NexusHeapInfo* info
);

/**
 * Get heap blocks.
 */
NEXUS_API NexusResult Nexus_HeapGetBlocks(
    NexusProcessHandle process,
    uint64_t heapId,
    NexusHeapBlock* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get heap blocks in address range.
 */
NEXUS_API NexusResult Nexus_HeapGetBlocksInRange(
    NexusProcessHandle process,
    uint64_t heapId,
    uint64_t startAddress,
    uint64_t endAddress,
    NexusHeapBlock* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find heap containing address.
 */
NEXUS_API NexusResult Nexus_HeapFindByAddress(
    NexusProcessHandle process,
    uint64_t address,
    NexusHeapInfo* info
);

/**
 * Get heap statistics.
 */
NEXUS_API NexusResult Nexus_HeapGetStats(
    NexusProcessHandle process,
    NexusHeapStats* stats
);

/**
 * Get statistics for specific heap.
 */
NEXUS_API NexusResult Nexus_HeapGetHeapStats(
    NexusProcessHandle process,
    uint64_t heapId,
    NexusHeapStats* stats
);

/* ============================================================================
 * Heap Validation
 * ============================================================================ */

/**
 * Validate heap integrity.
 */
NEXUS_API NexusResult Nexus_HeapValidate(
    NexusProcessHandle process,
    uint64_t heapId,
    uint32_t* isValid
);

/**
 * Validate all heaps.
 */
NEXUS_API NexusResult Nexus_HeapValidateAll(
    NexusProcessHandle process,
    uint32_t* validCount,
    uint32_t* invalidCount
);

/**
 * Find corrupted heap blocks.
 */
NEXUS_API NexusResult Nexus_HeapFindCorruption(
    NexusProcessHandle process,
    uint64_t heapId,
    NexusHeapBlock* buffer,
    size_t bufferCount,
    size_t* count
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_WINDOWHEAP_H */
