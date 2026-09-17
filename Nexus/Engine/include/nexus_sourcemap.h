/**
 * @file nexus_sourcemap.h
 * @brief Source-file and line-number mapping from debug symbols.
 *
 * Maps addresses to source files and line numbers (and vice versa)
 * using PDB information loaded by the symbol handler.
 */

#ifndef NEXUS_SOURCEMAP_H
#define NEXUS_SOURCEMAP_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Source Map Structures
 * ============================================================================ */

typedef struct NexusSourceLine {
    uint64_t address;                   /* Address in process */
    uint32_t lineNumber;                /* Source line number */
    uint32_t columnNumber;              /* Column number (if available) */
    wchar_t sourceFile[260];            /* Source file path */
    uint32_t isStatement;               /* 1 if statement start */
    uint32_t reserved;
} NexusSourceLine;

typedef struct NexusSourceFile {
    wchar_t path[260];                  /* Full source file path */
    wchar_t fileName[64];               /* File name only */
    uint32_t lineCount;                 /* Number of lines with code */
    uint32_t checksum;                  /* File checksum (if available) */
    uint64_t firstAddress;              /* First code address in file */
    uint64_t lastAddress;               /* Last code address in file */
    uint32_t hasSource;                 /* 1 if source text available */
    uint32_t reserved;
} NexusSourceFile;

typedef struct NexusLocalVariable {
    char name[128];                     /* Variable name */
    uint64_t address;                   /* Address (if static) */
    int32_t stackOffset;                /* Stack offset (if local) */
    uint32_t registerIndex;             /* Register (if in register) */
    uint32_t locationType;              /* Where variable is stored */
    uint32_t typeIndex;                 /* Type index in symbol info */
    uint32_t size;                      /* Variable size in bytes */
    uint32_t scopeStart;                /* Scope start (line number) */
    uint32_t scopeEnd;                  /* Scope end (line number) */
    wchar_t typeName[128];              /* Type name string */
} NexusLocalVariable;

typedef struct NexusFunctionInfo {
    char name[256];                     /* Function name */
    wchar_t moduleName[260];            /* Module name */
    uint64_t address;                   /* Function start address */
    uint64_t endAddress;                /* Function end address */
    uint32_t size;                      /* Function size */
    uint32_t lineNumber;                /* Source line number */
    wchar_t sourceFile[260];            /* Source file path */
    uint32_t parameterCount;            /* Number of parameters */
    uint32_t localCount;                /* Number of local variables */
} NexusFunctionInfo;

/* ============================================================================
 * Source Line Lookup
 * ============================================================================ */

/**
 * Get source line for address.
 */
NEXUS_API NexusResult Nexus_SourceGetLine(
    NexusProcessHandle process,
    uint64_t address,
    NexusSourceLine* line
);

/**
 * Get address for source line.
 */
NEXUS_API NexusResult Nexus_SourceGetAddress(
    NexusProcessHandle process,
    const wchar_t* sourceFile,
    uint32_t lineNumber,
    uint64_t* address
);

/**
 * Get source lines in address range.
 */
NEXUS_API NexusResult Nexus_SourceGetLinesInRange(
    NexusProcessHandle process,
    uint64_t startAddress,
    uint64_t endAddress,
    NexusSourceLine* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get next source line.
 */
NEXUS_API NexusResult Nexus_SourceGetNextLine(
    NexusProcessHandle process,
    uint64_t currentAddress,
    NexusSourceLine* line
);

/**
 * Get previous source line.
 */
NEXUS_API NexusResult Nexus_SourceGetPrevLine(
    NexusProcessHandle process,
    uint64_t currentAddress,
    NexusSourceLine* line
);

/* ============================================================================
 * Source File Operations
 * ============================================================================ */

/**
 * Get all source files for module.
 */
NEXUS_API NexusResult Nexus_SourceGetFiles(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusSourceFile* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get source file info.
 */
NEXUS_API NexusResult Nexus_SourceGetFileInfo(
    NexusProcessHandle process,
    const wchar_t* sourceFile,
    NexusSourceFile* info
);

/**
 * Get source text for file.
 */
NEXUS_API NexusResult Nexus_SourceGetText(
    NexusProcessHandle process,
    const wchar_t* sourceFile,
    uint32_t startLine,
    uint32_t lineCount,
    wchar_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Check if source file exists on disk.
 */
NEXUS_API NexusResult Nexus_SourceFileExists(
    const wchar_t* sourceFile,
    uint32_t* exists
);

/* ============================================================================
 * Function Information
 * ============================================================================ */

/**
 * Get function containing address.
 */
NEXUS_API NexusResult Nexus_SourceGetFunction(
    NexusProcessHandle process,
    uint64_t address,
    NexusFunctionInfo* info
);

/**
 * Get function by name.
 */
NEXUS_API NexusResult Nexus_SourceFindFunction(
    NexusProcessHandle process,
    const char* functionName,
    NexusFunctionInfo* info
);

/**
 * Get functions in module.
 */
NEXUS_API NexusResult Nexus_SourceGetFunctions(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusFunctionInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get functions in source file.
 */
NEXUS_API NexusResult Nexus_SourceGetFunctionsInFile(
    NexusProcessHandle process,
    const wchar_t* sourceFile,
    NexusFunctionInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Local Variables
 * ============================================================================ */

/**
 * Get local variables at address.
 */
NEXUS_API NexusResult Nexus_SourceGetLocals(
    NexusProcessHandle process,
    uint64_t address,
    NexusLocalVariable* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get function parameters.
 */
NEXUS_API NexusResult Nexus_SourceGetParameters(
    NexusProcessHandle process,
    uint64_t functionAddress,
    NexusLocalVariable* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get local variable value.
 */
NEXUS_API NexusResult Nexus_SourceGetLocalValue(
    NexusProcessHandle process,
    uint32_t threadId,
    const NexusLocalVariable* variable,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesRead
);

/**
 * Set local variable value.
 */
NEXUS_API NexusResult Nexus_SourceSetLocalValue(
    NexusProcessHandle process,
    uint32_t threadId,
    const NexusLocalVariable* variable,
    const uint8_t* value,
    size_t valueSize
);

/* ============================================================================
 * Source Path Configuration
 * ============================================================================ */

/**
 * Add source search path.
 */
NEXUS_API NexusResult Nexus_SourceAddSearchPath(
    NexusProcessHandle process,
    const wchar_t* searchPath
);

/**
 * Remove source search path.
 */
NEXUS_API NexusResult Nexus_SourceRemoveSearchPath(
    NexusProcessHandle process,
    const wchar_t* searchPath
);

/**
 * Clear source search paths.
 */
NEXUS_API NexusResult Nexus_SourceClearSearchPaths(
    NexusProcessHandle process
);

/**
 * Get source search paths.
 */
NEXUS_API NexusResult Nexus_SourceGetSearchPaths(
    NexusProcessHandle process,
    wchar_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Set source file mapping (remap from symbol path to local path).
 */
NEXUS_API NexusResult Nexus_SourceSetFileMapping(
    NexusProcessHandle process,
    const wchar_t* symbolPath,
    const wchar_t* localPath
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_SOURCEMAP_H */
