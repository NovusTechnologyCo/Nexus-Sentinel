/**
 * @file nexus_dumper.h
 * @brief Process memory dumping, import reconstruction, and unpacking support.
 *
 * Dump a running process to a valid PE file on disk, optionally
 * reconstructing the import table and finding the original entry point
 * (OEP).  Modelled on the TitanEngine dumping workflow.
 */

#ifndef NEXUS_DUMPER_H
#define NEXUS_DUMPER_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Dump Options
 * ============================================================================ */

typedef enum NexusDumpFlags {
    NEXUS_DUMP_FLAG_NONE = 0,
    NEXUS_DUMP_FLAG_FIX_HEADER = 0x0001,        /* Fix PE header fields */
    NEXUS_DUMP_FLAG_FIX_SECTIONS = 0x0002,      /* Realign section data */
    NEXUS_DUMP_FLAG_FIX_IMPORTS = 0x0004,       /* Rebuild import table */
    NEXUS_DUMP_FLAG_FIX_RELOCATIONS = 0x0008,   /* Fix relocations for new base */
    NEXUS_DUMP_FLAG_REMOVE_OVERLAY = 0x0010,    /* Remove overlay data */
    NEXUS_DUMP_FLAG_PRESERVE_OVERLAY = 0x0020,  /* Keep overlay data */
    NEXUS_DUMP_FLAG_UNMAP_FILE = 0x0040,        /* Create unmapped dump */
    NEXUS_DUMP_FLAG_WIPE_HEADER = 0x0080        /* Zero PE header (stealth) */
} NexusDumpFlags;

typedef enum NexusOepFindMethod {
    NEXUS_OEP_AUTO = 0,                 /* Auto-detect best method */
    NEXUS_OEP_TRACE_ENTRY = 1,          /* Trace from entry point */
    NEXUS_OEP_API_HOOK = 2,             /* Hook common APIs */
    NEXUS_OEP_SECTION_JUMP = 3,         /* Watch for section jumps */
    NEXUS_OEP_MEMORY_BREAKPOINT = 4,    /* Memory breakpoints */
    NEXUS_OEP_HARDWARE_BREAKPOINT = 5   /* Hardware breakpoints */
} NexusOepFindMethod;

typedef enum NexusUnpackerType {
    NEXUS_UNPACKER_GENERIC = 0,
    NEXUS_UNPACKER_UPX = 1,
    NEXUS_UNPACKER_ASPACK = 2,
    NEXUS_UNPACKER_PECOMPACT = 3,
    NEXUS_UNPACKER_THEMIDA = 4,
    NEXUS_UNPACKER_VMPROTECT = 5
} NexusUnpackerType;

/* ============================================================================
 * Dump Structures
 * ============================================================================ */

typedef struct NexusDumpInfo {
    wchar_t outputPath[260];            /* Output file path */
    uint64_t baseAddress;               /* Module base address */
    uint64_t entryPoint;                /* Entry point (RVA) */
    uint64_t imageSize;                 /* Image size in memory */
    uint64_t fileSize;                  /* Resulting file size */
    uint32_t sectionCount;              /* Number of sections */
    uint32_t flags;                     /* Dump flags used */
    uint32_t wasRepaired;               /* 1 if repairs were needed */
    uint32_t reserved;
} NexusDumpInfo;

typedef struct NexusOepSearchResult {
    uint64_t oepAddress;                /* Found OEP address */
    uint64_t oepRva;                    /* OEP as RVA */
    uint32_t confidence;                /* Confidence 0-100 */
    uint32_t method;                    /* Method that found it */
    uint64_t searchTime;                /* Time taken (ms) */
    uint32_t instructionsTraced;        /* Instructions traced */
    uint32_t reserved;
    char signature[64];                 /* Compiler/packer signature */
} NexusOepSearchResult;

typedef struct NexusUnpackResult {
    uint64_t originalBase;              /* Original base address */
    uint64_t unpackedBase;              /* Unpacked base address */
    uint64_t originalOep;               /* Original (packed) entry point */
    uint64_t realOep;                   /* Real (unpacked) entry point */
    uint64_t unpackedSize;              /* Size of unpacked code */
    uint32_t packerType;                /* Detected packer type */
    uint32_t success;                   /* 1 if successful */
    wchar_t packerName[64];             /* Packer name string */
    wchar_t outputPath[260];            /* Path to unpacked file */
} NexusUnpackResult;

/* ============================================================================
 * Process Dumping
 * ============================================================================ */

/**
 * Dump an entire process to file.
 */
NEXUS_API NexusResult Nexus_DumpProcess(
    NexusProcessHandle handle,
    const wchar_t* outputPath,
    uint32_t flags,
    NexusDumpInfo* info
);

/**
 * Dump a specific module to file.
 */
NEXUS_API NexusResult Nexus_DumpModule(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    const wchar_t* outputPath,
    uint32_t flags,
    NexusDumpInfo* info
);

/**
 * Dump a memory region to file.
 */
NEXUS_API NexusResult Nexus_DumpRegion(
    NexusProcessHandle handle,
    uint64_t startAddress,
    uint64_t size,
    const wchar_t* outputPath
);

/**
 * Dump memory to buffer.
 */
NEXUS_API NexusResult Nexus_DumpToBuffer(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/* ============================================================================
 * OEP Finding
 * ============================================================================ */

/**
 * Find original entry point of packed executable.
 */
NEXUS_API NexusResult Nexus_FindOep(
    NexusDebuggerHandle debugger,
    uint32_t method,
    uint32_t timeout,
    NexusOepSearchResult* result
);

/**
 * Find OEP using trace from entry point.
 */
NEXUS_API NexusResult Nexus_FindOepByTrace(
    NexusDebuggerHandle debugger,
    uint32_t maxInstructions,
    NexusOepSearchResult* result
);

/**
 * Find OEP by hooking common APIs.
 */
NEXUS_API NexusResult Nexus_FindOepByApiHook(
    NexusDebuggerHandle debugger,
    const char** apiNames,
    size_t apiCount,
    NexusOepSearchResult* result
);

/**
 * Cancel OEP search.
 */
NEXUS_API void Nexus_CancelOepSearch(NexusDebuggerHandle debugger);

/* ============================================================================
 * Generic Unpacker
 * ============================================================================ */

/**
 * Detect packer type.
 */
NEXUS_API NexusResult Nexus_DetectPacker(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    uint32_t* packerType,
    wchar_t* packerName,
    size_t nameSize
);

/**
 * Unpack a module automatically.
 */
NEXUS_API NexusResult Nexus_Unpack(
    NexusDebuggerHandle debugger,
    uint64_t moduleBase,
    const wchar_t* outputPath,
    NexusUnpackResult* result
);

/**
 * Unpack with specific unpacker.
 */
NEXUS_API NexusResult Nexus_UnpackWith(
    NexusDebuggerHandle debugger,
    uint64_t moduleBase,
    uint32_t unpackerType,
    const wchar_t* outputPath,
    NexusUnpackResult* result
);

/* ============================================================================
 * Dump Repair
 * ============================================================================ */

/**
 * Repair a dumped PE file.
 */
NEXUS_API NexusResult Nexus_RepairDump(
    const wchar_t* dumpPath,
    uint32_t flags
);

/**
 * Fix PE header of dumped file.
 */
NEXUS_API NexusResult Nexus_FixDumpHeader(
    const wchar_t* dumpPath,
    uint64_t newEntryPoint
);

/**
 * Realign sections in dumped file.
 */
NEXUS_API NexusResult Nexus_RealignDumpSections(
    const wchar_t* dumpPath
);

/**
 * Strip overlay from dumped file.
 */
NEXUS_API NexusResult Nexus_StripDumpOverlay(
    const wchar_t* dumpPath
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_DUMPER_H */
