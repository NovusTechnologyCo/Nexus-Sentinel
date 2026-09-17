/**
 * @file nexus_import.h
 * @brief Import and export table manipulation and IAT reconstruction.
 *
 * Read and rebuild import/export tables in PE files, add or remove
 * import entries, and reconstruct the IAT after process dumping.
 * Modelled on the TitanEngine import/export API.
 */

#ifndef NEXUS_IMPORT_H
#define NEXUS_IMPORT_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Import/Export Structures
 * ============================================================================ */

typedef struct NexusImportModule {
    wchar_t name[260];                  /* DLL name */
    uint32_t firstThunkRva;             /* RVA of first thunk */
    uint32_t originalFirstThunkRva;     /* RVA of original first thunk */
    uint32_t functionCount;             /* Number of imported functions */
    uint32_t boundTimestamp;            /* Bound import timestamp */
    uint32_t isBound;                   /* 1 if imports are bound */
    uint32_t isDelayLoad;               /* 1 if delay-load import */
} NexusImportModule;

typedef struct NexusImportFunction {
    wchar_t moduleName[260];            /* Module name */
    char functionName[256];             /* Function name */
    uint16_t ordinal;                   /* Ordinal (if by ordinal) */
    uint16_t hint;                      /* Hint value */
    uint32_t thunkRva;                  /* RVA of IAT entry */
    uint64_t thunkValue;                /* Current IAT value */
    uint32_t isByOrdinal;               /* 1 if import by ordinal */
    uint32_t reserved;
} NexusImportFunction;

typedef struct NexusExportFunction {
    char name[256];                     /* Function name */
    uint32_t ordinal;                   /* Export ordinal */
    uint32_t rva;                       /* Function RVA */
    uint32_t isForwarder;               /* 1 if forwarded export */
    char forwarderName[256];            /* Forwarder string */
} NexusExportFunction;

typedef struct NexusExportDirectory {
    wchar_t dllName[260];               /* Export DLL name */
    uint32_t characteristics;           /* Export characteristics */
    uint32_t timestamp;                 /* Export timestamp */
    uint16_t majorVersion;              /* Major version */
    uint16_t minorVersion;              /* Minor version */
    uint32_t base;                      /* Ordinal base */
    uint32_t numberOfFunctions;         /* Total functions */
    uint32_t numberOfNames;             /* Named functions */
    uint32_t addressTableRva;           /* Address table RVA */
    uint32_t namePointerRva;            /* Name pointer RVA */
    uint32_t ordinalTableRva;           /* Ordinal table RVA */
} NexusExportDirectory;

typedef struct NexusIatReconstructInfo {
    uint32_t modulesFound;              /* Modules identified */
    uint32_t functionsFound;            /* Functions identified */
    uint32_t unknownThunks;             /* Unresolved thunks */
    uint32_t iatSize;                   /* Reconstructed IAT size */
    uint64_t iatRva;                    /* IAT RVA */
    uint32_t success;                   /* 1 if successful */
    uint32_t reserved;
} NexusIatReconstructInfo;

/* ============================================================================
 * Import Table Reading
 * ============================================================================ */

/**
 * Get import modules.
 */
NEXUS_API NexusResult Nexus_ImportGetModules(
    intptr_t peHandle,
    NexusImportModule* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get imports for a module.
 */
NEXUS_API NexusResult Nexus_ImportGetFunctions(
    intptr_t peHandle,
    const wchar_t* moduleName,
    NexusImportFunction* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get all imports.
 */
NEXUS_API NexusResult Nexus_ImportGetAll(
    intptr_t peHandle,
    NexusImportFunction* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find import by name.
 */
NEXUS_API NexusResult Nexus_ImportFind(
    intptr_t peHandle,
    const wchar_t* moduleName,
    const char* functionName,
    NexusImportFunction* info
);

/**
 * Find import by ordinal.
 */
NEXUS_API NexusResult Nexus_ImportFindByOrdinal(
    intptr_t peHandle,
    const wchar_t* moduleName,
    uint16_t ordinal,
    NexusImportFunction* info
);

/* ============================================================================
 * Import Table Modification
 * ============================================================================ */

/**
 * Add import module.
 */
NEXUS_API NexusResult Nexus_ImportAddModule(
    intptr_t peHandle,
    const wchar_t* moduleName
);

/**
 * Add import function.
 */
NEXUS_API NexusResult Nexus_ImportAddFunction(
    intptr_t peHandle,
    const wchar_t* moduleName,
    const char* functionName,
    uint32_t* thunkRva
);

/**
 * Add import by ordinal.
 */
NEXUS_API NexusResult Nexus_ImportAddByOrdinal(
    intptr_t peHandle,
    const wchar_t* moduleName,
    uint16_t ordinal,
    uint32_t* thunkRva
);

/**
 * Delete import module.
 */
NEXUS_API NexusResult Nexus_ImportDeleteModule(
    intptr_t peHandle,
    const wchar_t* moduleName
);

/**
 * Delete import function.
 */
NEXUS_API NexusResult Nexus_ImportDeleteFunction(
    intptr_t peHandle,
    const wchar_t* moduleName,
    const char* functionName
);

/**
 * Clear all imports.
 */
NEXUS_API NexusResult Nexus_ImportClear(intptr_t peHandle);

/* ============================================================================
 * IAT Reconstruction
 * ============================================================================ */

/**
 * Reconstruct IAT from running process.
 */
NEXUS_API NexusResult Nexus_ImportReconstructIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    intptr_t peHandle,
    NexusIatReconstructInfo* info
);

/**
 * Fix IAT entries in dump.
 */
NEXUS_API NexusResult Nexus_ImportFixIat(
    intptr_t peHandle,
    uint64_t originalBase
);

/**
 * Trace IAT entries to find real functions.
 */
NEXUS_API NexusResult Nexus_ImportTraceIat(
    NexusProcessHandle process,
    uint64_t iatAddress,
    size_t iatSize,
    NexusImportFunction* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Export Table Reading
 * ============================================================================ */

/**
 * Get export directory info.
 */
NEXUS_API NexusResult Nexus_ExportGetInfo(
    intptr_t peHandle,
    NexusExportDirectory* info
);

/**
 * Get all exports.
 */
NEXUS_API NexusResult Nexus_ExportGetAll(
    intptr_t peHandle,
    NexusExportFunction* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find export by name.
 */
NEXUS_API NexusResult Nexus_ExportFind(
    intptr_t peHandle,
    const char* functionName,
    NexusExportFunction* info
);

/**
 * Find export by ordinal.
 */
NEXUS_API NexusResult Nexus_ExportFindByOrdinal(
    intptr_t peHandle,
    uint32_t ordinal,
    NexusExportFunction* info
);

/* ============================================================================
 * Export Table Modification
 * ============================================================================ */

/**
 * Set export DLL name.
 */
NEXUS_API NexusResult Nexus_ExportSetDllName(
    intptr_t peHandle,
    const wchar_t* dllName
);

/**
 * Add export function.
 */
NEXUS_API NexusResult Nexus_ExportAdd(
    intptr_t peHandle,
    const char* functionName,
    uint32_t rva,
    uint32_t* ordinal
);

/**
 * Delete export function.
 */
NEXUS_API NexusResult Nexus_ExportDelete(
    intptr_t peHandle,
    const char* functionName
);

/**
 * Clear export table.
 */
NEXUS_API NexusResult Nexus_ExportClear(intptr_t peHandle);

/**
 * Rebuild export table.
 */
NEXUS_API NexusResult Nexus_ExportRebuild(intptr_t peHandle);

/* ============================================================================
 * Delay-Load Imports
 * ============================================================================ */

/**
 * Get delay-load modules.
 */
NEXUS_API NexusResult Nexus_DelayImportGetModules(
    intptr_t peHandle,
    NexusImportModule* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get delay-load functions.
 */
NEXUS_API NexusResult Nexus_DelayImportGetFunctions(
    intptr_t peHandle,
    const wchar_t* moduleName,
    NexusImportFunction* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Convert delay-load to regular import.
 */
NEXUS_API NexusResult Nexus_DelayImportConvert(
    intptr_t peHandle,
    const wchar_t* moduleName
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_IMPORT_H */
