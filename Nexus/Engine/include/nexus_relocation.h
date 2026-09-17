/**
 * @file nexus_relocation.h
 * @brief PE relocation table manipulation and ASLR support.
 *
 * Read, modify, add, and strip base relocation entries in PE files.
 * Used by the dumper and manual-map injector to handle ASLR.
 * Modelled on the TitanEngine relocation API.
 */

#ifndef NEXUS_RELOCATION_H
#define NEXUS_RELOCATION_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Relocation Types
 * ============================================================================ */

typedef enum NexusRelocationType {
    NEXUS_RELOC_ABSOLUTE = 0,           /* No relocation required */
    NEXUS_RELOC_HIGH = 1,               /* Add high 16 bits of delta */
    NEXUS_RELOC_LOW = 2,                /* Add low 16 bits of delta */
    NEXUS_RELOC_HIGHLOW = 3,            /* Add full 32 bits of delta */
    NEXUS_RELOC_HIGHADJ = 4,            /* Add high 16 bits, adjusted */
    NEXUS_RELOC_DIR64 = 10              /* 64-bit address relocation */
} NexusRelocationType;

/* ============================================================================
 * Relocation Structures
 * ============================================================================ */

typedef struct NexusRelocationEntry {
    uint32_t rva;                       /* RVA of relocation */
    uint32_t type;                      /* NexusRelocationType */
    uint32_t blockRva;                  /* RVA of relocation block */
    uint32_t reserved;
} NexusRelocationEntry;

typedef struct NexusRelocationBlock {
    uint32_t pageRva;                   /* Page RVA (base for entries) */
    uint32_t blockSize;                 /* Size of block including header */
    uint32_t entryCount;                /* Number of entries in block */
    uint32_t reserved;
} NexusRelocationBlock;

typedef struct NexusRelocationStats {
    uint32_t totalBlocks;               /* Number of relocation blocks */
    uint32_t totalEntries;              /* Total relocation entries */
    uint32_t highLowCount;              /* 32-bit relocations */
    uint32_t dir64Count;                /* 64-bit relocations */
    uint32_t otherCount;                /* Other relocation types */
    uint32_t tableSize;                 /* Total relocation table size */
    uint64_t minRva;                    /* Minimum relocated RVA */
    uint64_t maxRva;                    /* Maximum relocated RVA */
} NexusRelocationStats;

/* ============================================================================
 * Relocation Table Reading
 * ============================================================================ */

/**
 * Get relocation statistics.
 */
NEXUS_API NexusResult Nexus_RelocGetStats(
    intptr_t peHandle,
    NexusRelocationStats* stats
);

/**
 * Get all relocation entries.
 */
NEXUS_API NexusResult Nexus_RelocGetEntries(
    intptr_t peHandle,
    NexusRelocationEntry* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get relocation entries in address range.
 */
NEXUS_API NexusResult Nexus_RelocGetInRange(
    intptr_t peHandle,
    uint32_t startRva,
    uint32_t endRva,
    NexusRelocationEntry* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get relocation blocks.
 */
NEXUS_API NexusResult Nexus_RelocGetBlocks(
    intptr_t peHandle,
    NexusRelocationBlock* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check if RVA has relocation.
 */
NEXUS_API NexusResult Nexus_RelocHasEntry(
    intptr_t peHandle,
    uint32_t rva,
    uint32_t* hasReloc
);

/* ============================================================================
 * Relocation Table Modification
 * ============================================================================ */

/**
 * Add a relocation entry.
 */
NEXUS_API NexusResult Nexus_RelocAddEntry(
    intptr_t peHandle,
    uint32_t rva,
    uint32_t type
);

/**
 * Add multiple relocation entries.
 */
NEXUS_API NexusResult Nexus_RelocAddEntries(
    intptr_t peHandle,
    const NexusRelocationEntry* entries,
    size_t count
);

/**
 * Remove a relocation entry.
 */
NEXUS_API NexusResult Nexus_RelocRemoveEntry(
    intptr_t peHandle,
    uint32_t rva
);

/**
 * Remove relocations in address range.
 */
NEXUS_API NexusResult Nexus_RelocRemoveRange(
    intptr_t peHandle,
    uint32_t startRva,
    uint32_t endRva
);

/**
 * Clear all relocations.
 */
NEXUS_API NexusResult Nexus_RelocClear(intptr_t peHandle);

/* ============================================================================
 * Relocation Processing
 * ============================================================================ */

/**
 * Apply relocations to loaded image.
 */
NEXUS_API NexusResult Nexus_RelocApply(
    NexusProcessHandle process,
    uint64_t moduleBase,
    uint64_t newBase
);

/**
 * Rebase PE file to new image base.
 */
NEXUS_API NexusResult Nexus_RelocRebase(
    intptr_t peHandle,
    uint64_t newImageBase
);

/**
 * Strip relocation table (for ASLR-disabled executables).
 */
NEXUS_API NexusResult Nexus_RelocStrip(intptr_t peHandle);

/**
 * Rebuild relocation table from analysis.
 */
NEXUS_API NexusResult Nexus_RelocRebuild(
    intptr_t peHandle,
    uint64_t knownImageBase
);

/* ============================================================================
 * ASLR Control
 * ============================================================================ */

/**
 * Check if PE has ASLR enabled.
 */
NEXUS_API NexusResult Nexus_RelocIsAslrEnabled(
    intptr_t peHandle,
    uint32_t* isEnabled
);

/**
 * Enable ASLR for PE (set DynamicBase flag).
 */
NEXUS_API NexusResult Nexus_RelocEnableAslr(intptr_t peHandle);

/**
 * Disable ASLR for PE (clear DynamicBase flag).
 */
NEXUS_API NexusResult Nexus_RelocDisableAslr(intptr_t peHandle);

/**
 * Check if PE has high entropy ASLR.
 */
NEXUS_API NexusResult Nexus_RelocIsHighEntropyAslr(
    intptr_t peHandle,
    uint32_t* isHighEntropy
);

/**
 * Set high entropy ASLR flag.
 */
NEXUS_API NexusResult Nexus_RelocSetHighEntropyAslr(
    intptr_t peHandle,
    uint32_t enable
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_RELOCATION_H */
