/**
 * @file nexus_scanner.h
 * @brief Memory scanning: first scan, rescan, value types, and advanced multi-threaded scanning.
 *
 * Two scanner tiers are provided:
 *   - Basic scanner (Nexus_Scan*): simple first-scan / next-scan workflow
 *     for integer, float, string, and AOB pattern matching.
 *   - Advanced scanner (Nexus_AdvScan*): multi-threaded, supports undo,
 *     save/load, progress callbacks, and CE-compatible three-state
 *     region filtering (writable/executable/copy-on-write include/exclude).
 *
 * Also includes the code-cave scanner for locating injectable regions,
 * pattern scanning utilities, and auto-analysis/type-guessing heuristics.
 */

#ifndef NEXUS_SCANNER_H
#define NEXUS_SCANNER_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Basic Scanner Types
 * ============================================================================ */

/* Value types for scanning */
typedef enum NexusValueType {
    NEXUS_VALUE_INT8 = 0,
    NEXUS_VALUE_INT16 = 1,
    NEXUS_VALUE_INT32 = 2,
    NEXUS_VALUE_INT64 = 3,
    NEXUS_VALUE_FLOAT32 = 4,
    NEXUS_VALUE_FLOAT64 = 5,
    NEXUS_VALUE_STRING = 6,         /* ANSI string */
    NEXUS_VALUE_WSTRING = 7,        /* Wide string (UTF-16) */
    NEXUS_VALUE_AOB = 8,            /* Array of bytes */
    NEXUS_VALUE_ALL = 9             /* Scan all types (first scan only) */
} NexusValueType;

/* Scan comparison types */
typedef enum NexusScanType {
    NEXUS_SCAN_EXACT = 0,           /* Value equals target */
    NEXUS_SCAN_UNKNOWN = 1,         /* Unknown initial value (first scan) */
    NEXUS_SCAN_RANGE = 2,           /* Value between min and max */
    NEXUS_SCAN_GREATER = 3,         /* Value > target */
    NEXUS_SCAN_LESS = 4,            /* Value < target */
    NEXUS_SCAN_INCREASED = 5,       /* Value increased (any amount) */
    NEXUS_SCAN_INCREASED_BY = 6,    /* Value increased by specific amount */
    NEXUS_SCAN_DECREASED = 7,       /* Value decreased (any amount) */
    NEXUS_SCAN_DECREASED_BY = 8,    /* Value decreased by specific amount */
    NEXUS_SCAN_CHANGED = 9,         /* Value changed */
    NEXUS_SCAN_UNCHANGED = 10       /* Value unchanged */
} NexusScanType;

/* Scan options/flags */
typedef enum NexusScanFlags {
    NEXUS_SCAN_FLAG_NONE = 0,
    NEXUS_SCAN_FLAG_ALIGNED = 0x0001,       /* Scan only aligned addresses */
    NEXUS_SCAN_FLAG_WRITABLE = 0x0002,      /* Only writable memory */
    NEXUS_SCAN_FLAG_EXECUTABLE = 0x0004,    /* Only executable memory */
    NEXUS_SCAN_FLAG_CASE_SENSITIVE = 0x0008,/* Case-sensitive string compare */
    NEXUS_SCAN_FLAG_UNICODE = 0x0010,       /* Treat strings as Unicode */
    NEXUS_SCAN_FLAG_HEX_STRING = 0x0020,    /* Input is hex string for AOB */
    NEXUS_SCAN_FLAG_LAST_DIGITS = 0x0040    /* Match addresses ending in specified digits */
} NexusScanFlags;

/* Scan parameters structure */
typedef struct NexusScanParams {
    NexusValueType valueType;
    NexusScanType scanType;
    uint32_t flags;                 /* NexusScanFlags OR'd together */
    uint32_t alignment;             /* Alignment (1, 2, 4, 8) or 0 for default */

    /* Value storage - use appropriate field based on valueType */
    union {
        int64_t intValue;           /* For integer types */
        double floatValue;          /* For float types */
        struct {
            const char* data;       /* String or AOB data */
            size_t length;          /* Length (0 = null-terminated for strings) */
        } stringValue;
    } value;

    /* For range scans */
    union {
        int64_t intValueMax;
        double floatValueMax;
    } valueMax;

    /* Float comparison epsilon (0 for exact) */
    double floatEpsilon;
} NexusScanParams;

/* Scan progress information */
typedef struct NexusScanProgress {
    uint64_t bytesScanned;          /* Bytes processed so far */
    uint64_t bytesTotal;            /* Total bytes to scan */
    uint64_t regionsScanned;        /* Regions processed */
    uint64_t regionsTotal;          /* Total regions */
    uint64_t resultsFound;          /* Results found so far */
    int isComplete;                 /* 1 if scan finished */
    int wasCancelled;               /* 1 if cancelled */
} NexusScanProgress;

/* Scan result entry */
typedef struct NexusScanResult {
    uint64_t address;               /* Address of the match */
    union {
        int64_t intValue;
        double floatValue;
        uint8_t bytes[8];           /* Raw bytes for display */
    } currentValue;
    union {
        int64_t intValue;
        double floatValue;
        uint8_t bytes[8];
    } previousValue;                /* Only valid for rescan */
} NexusScanResult;

/* ============================================================================
 * Basic Scanner Operations
 * ============================================================================ */

/**
 * Create a new scan session.
 * A scan session holds the state for first scan and subsequent rescans.
 *
 * @param handle Process handle
 * @param scan Output: scan handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanCreate(
    NexusProcessHandle handle,
    NexusScanHandle* scan
);

/**
 * Destroy a scan session and free all resources.
 * @param scan Scan handle
 */
NEXUS_API void Nexus_ScanDestroy(NexusScanHandle scan);

/**
 * Start a first scan with the given parameters.
 * This captures a memory snapshot and scans for matching values.
 *
 * @param scan Scan handle
 * @param params Scan parameters
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanFirst(
    NexusScanHandle scan,
    const NexusScanParams* params
);

/**
 * Perform a rescan (next scan) with the given parameters.
 * Filters existing results based on new criteria.
 *
 * @param scan Scan handle (must have previous results)
 * @param params Scan parameters
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanNext(
    NexusScanHandle scan,
    const NexusScanParams* params
);

/**
 * Cancel an in-progress scan.
 * @param scan Scan handle
 */
NEXUS_API void Nexus_ScanCancel(NexusScanHandle scan);

/**
 * Get the current scan progress.
 * @param scan Scan handle
 * @param progress Output: progress information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanGetProgress(
    NexusScanHandle scan,
    NexusScanProgress* progress
);

/**
 * Get the number of results from the last scan.
 * @param scan Scan handle
 * @param count Output: number of results
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanGetResultCount(
    NexusScanHandle scan,
    uint64_t* count
);

/**
 * Get scan results.
 * Results are sorted by address.
 *
 * @param scan Scan handle
 * @param startIndex Starting index (0-based)
 * @param buffer Array to receive results
 * @param bufferCount Size of buffer array
 * @param resultsReturned Output: number of results returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanGetResults(
    NexusScanHandle scan,
    uint64_t startIndex,
    NexusScanResult* buffer,
    size_t bufferCount,
    size_t* resultsReturned
);

/**
 * Reset a scan session to allow a new first scan.
 * Clears all previous results.
 * @param scan Scan handle
 */
NEXUS_API void Nexus_ScanReset(NexusScanHandle scan);

/**
 * Read current values for all results.
 * Updates the currentValue field in all stored results.
 * Useful for updating the display without rescanning.
 *
 * @param scan Scan handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanRefreshValues(NexusScanHandle scan);

/* ============================================================================
 * Advanced Memory Scanner (v0.25.0)
 * ============================================================================ */

/* NexusAdvScannerHandle is defined in nexus_common.h */

/** Scan value types */
typedef enum NexusScanValueType {
    NEXUS_SCAN_BYTE = 0,          /* 1-byte integer */
    NEXUS_SCAN_INT16,             /* 2-byte integer */
    NEXUS_SCAN_INT32,             /* 4-byte integer */
    NEXUS_SCAN_INT64,             /* 8-byte integer */
    NEXUS_SCAN_FLOAT,             /* 4-byte float */
    NEXUS_SCAN_DOUBLE,            /* 8-byte double */
    NEXUS_SCAN_STRING,            /* ASCII string */
    NEXUS_SCAN_WSTRING,           /* Unicode string */
    NEXUS_SCAN_AOB,               /* Array of bytes (pattern) */
    NEXUS_SCAN_ALL                /* All types (for unknown initial) */
} NexusScanValueType;

/** Scan comparison types */
typedef enum NexusScanCompareType {
    NEXUS_CMP_EXACT = 0,          /* Exact value match */
    NEXUS_CMP_NOT_EQUAL,          /* Not equal to value */
    NEXUS_CMP_GREATER,            /* Greater than value */
    NEXUS_CMP_GREATER_EQUAL,      /* Greater than or equal */
    NEXUS_CMP_LESS,               /* Less than value */
    NEXUS_CMP_LESS_EQUAL,         /* Less than or equal */
    NEXUS_CMP_BETWEEN,            /* Between two values (inclusive) */
    NEXUS_CMP_INCREASED,          /* Value increased (next scan) */
    NEXUS_CMP_INCREASED_BY,       /* Value increased by X */
    NEXUS_CMP_DECREASED,          /* Value decreased (next scan) */
    NEXUS_CMP_DECREASED_BY,       /* Value decreased by X */
    NEXUS_CMP_CHANGED,            /* Value changed (next scan) */
    NEXUS_CMP_UNCHANGED,          /* Value unchanged (next scan) */
    NEXUS_CMP_UNKNOWN             /* Unknown initial value */
} NexusScanCompareType;

/** Scan options flags
 * CE three-state checkbox behavior:
 * - Checked (Include): Only scan regions WITH property
 * - Unchecked (Exclude): Only scan regions WITHOUT property
 * - Indeterminate (DontCare): Don't filter by this property
 */
typedef enum NexusScanOptions {
    NEXUS_SCANOPT_NONE = 0,
    /* Include flags (must HAVE property) */
    NEXUS_SCANOPT_WRITABLE = 0x0001,
    NEXUS_SCANOPT_EXECUTABLE = 0x0002,
    NEXUS_SCANOPT_COPYONWRITE = 0x0004,
    NEXUS_SCANOPT_MAPPED = 0x0008,
    NEXUS_SCANOPT_IMAGE = 0x0010,
    NEXUS_SCANOPT_HEAP = 0x0020,
    NEXUS_SCANOPT_STACK = 0x0040,
    /* Other options */
    NEXUS_SCANOPT_CASE_INSENSITIVE = 0x0100,
    NEXUS_SCANOPT_UNICODE = 0x0200,
    NEXUS_SCANOPT_HEX_STRING = 0x0400,
    NEXUS_SCANOPT_PAUSE_WHILE_SCAN = 0x1000,
    NEXUS_SCANOPT_FAST_SCAN = 0x2000,
    NEXUS_SCANOPT_LAST_DIGITS = 0x4000,
    /* Exclude flags (must NOT have property) */
    NEXUS_SCANOPT_WRITABLE_EXCLUDE = 0x010000,
    NEXUS_SCANOPT_EXECUTABLE_EXCLUDE = 0x020000,
    NEXUS_SCANOPT_COPYONWRITE_EXCLUDE = 0x040000
} NexusScanOptions;

/** Scan value union */
typedef union NexusScanValue {
    uint8_t byteVal;
    int16_t int16Val;
    int32_t int32Val;
    int64_t int64Val;
    float floatVal;
    double doubleVal;
    struct {
        char data[256];
        size_t length;
    } stringVal;
    struct {
        uint8_t bytes[256];
        uint8_t mask[256];       /* 0xFF = exact, 0x00 = wildcard */
        size_t length;
    } aobVal;
} NexusScanValue;

/** Scan configuration */
typedef struct NexusScanConfig {
    NexusScanValueType valueType;
    NexusScanCompareType compareType;
    uint32_t options;
    uint32_t alignment;           /* 0 = auto (size of type), 1 = byte-aligned */
    uint64_t startAddress;        /* 0 = process start */
    uint64_t endAddress;          /* 0 = process end */
    NexusScanValue value1;        /* Primary value */
    NexusScanValue value2;        /* Secondary value (for BETWEEN) */
    float floatTolerance;         /* Tolerance for float comparison (0 = exact) */
    uint32_t threadCount;         /* 0 = auto (CPU cores) */
} NexusScanConfig;

/** Scan result entry */
typedef struct NexusScanResultEntry {
    uint64_t address;
    NexusScanValue currentValue;
    NexusScanValue previousValue;
} NexusScanResultEntry;

/** Scan progress callback */
typedef void (*NexusScanProgressCallback)(
    uint64_t bytesScanned,
    uint64_t totalBytes,
    size_t resultsFound,
    void* userData
);

/** Scan statistics */
typedef struct NexusScanStats {
    uint64_t totalBytes;          /* Total bytes to scan */
    uint64_t bytesScanned;        /* Bytes scanned so far */
    size_t regionsScanned;        /* Memory regions scanned */
    size_t resultsFound;          /* Results found */
    uint32_t threadsUsed;         /* Threads used */
    double elapsedMs;             /* Elapsed time in milliseconds */
    double scanSpeedMBps;         /* Scan speed in MB/s */
    int32_t isComplete;           /* 1 if scan complete */
    int32_t wasCancelled;         /* 1 if scan was cancelled */
} NexusScanStats;

/* ============================================================================
 * Advanced Scanner Operations
 * ============================================================================ */

/**
 * Create an advanced scanner for a process.
 *
 * @param process Process handle
 * @param scanner Output: scanner handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanCreate(
    NexusProcessHandle process,
    NexusAdvScannerHandle* scanner
);

/**
 * Destroy an advanced scanner.
 *
 * @param scanner Scanner handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanDestroy(
    NexusAdvScannerHandle scanner
);

/**
 * Perform a first scan (initial scan).
 *
 * @param scanner Scanner handle
 * @param config Scan configuration
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanFirst(
    NexusAdvScannerHandle scanner,
    const NexusScanConfig* config
);

/**
 * Perform a next scan (filter existing results).
 *
 * @param scanner Scanner handle
 * @param config Scan configuration (compareType and values used)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanNext(
    NexusAdvScannerHandle scanner,
    const NexusScanConfig* config
);

/**
 * Undo the last scan (restore previous results).
 *
 * @param scanner Scanner handle
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if no undo available
 */
NEXUS_API NexusResult Nexus_AdvScanUndo(
    NexusAdvScannerHandle scanner
);

/**
 * Reset scanner (clear all results).
 *
 * @param scanner Scanner handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanReset(
    NexusAdvScannerHandle scanner
);

/**
 * Get number of results.
 *
 * @param scanner Scanner handle
 * @param count Output: result count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanGetResultCount(
    NexusAdvScannerHandle scanner,
    size_t* count
);

/**
 * Get scan results.
 *
 * @param scanner Scanner handle
 * @param offset Starting index
 * @param results Output array
 * @param maxResults Maximum results to return
 * @param resultCount Output: number of results returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanGetResults(
    NexusAdvScannerHandle scanner,
    size_t offset,
    NexusScanResultEntry* results,
    size_t maxResults,
    size_t* resultCount
);

/**
 * Update current values of all results (re-read from memory).
 *
 * @param scanner Scanner handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanRefreshValues(
    NexusAdvScannerHandle scanner
);

/**
 * Get scan statistics.
 *
 * @param scanner Scanner handle
 * @param stats Output: statistics
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanGetStats(
    NexusAdvScannerHandle scanner,
    NexusScanStats* stats
);

/**
 * Set progress callback.
 *
 * @param scanner Scanner handle
 * @param callback Progress callback function
 * @param userData User data passed to callback
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanSetProgressCallback(
    NexusAdvScannerHandle scanner,
    NexusScanProgressCallback callback,
    void* userData
);

/**
 * Cancel an ongoing scan.
 *
 * @param scanner Scanner handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanCancel(
    NexusAdvScannerHandle scanner
);

/**
 * Check if a scan is in progress.
 *
 * @param scanner Scanner handle
 * @param inProgress Output: 1 if scan in progress, 0 otherwise
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanIsScanning(
    NexusAdvScannerHandle scanner,
    int32_t* inProgress
);

/**
 * Save scan results to file.
 *
 * @param scanner Scanner handle
 * @param filePath File path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanSaveResults(
    NexusAdvScannerHandle scanner,
    const char* filePath
);

/**
 * Load scan results from file.
 *
 * @param scanner Scanner handle
 * @param filePath File path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanLoadResults(
    NexusAdvScannerHandle scanner,
    const char* filePath
);

/**
 * Get default scan configuration.
 *
 * @param config Output: default configuration
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AdvScanGetDefaultConfig(
    NexusScanConfig* config
);

/* ============================================================================
 * Code Cave Scanner (v0.26.0)
 * ============================================================================ */

/** Code cave fill byte type */
typedef enum NexusCodeCaveFillType {
    NEXUS_CAVE_ZEROS = 0,           /* Scan for 00 bytes */
    NEXUS_CAVE_NOPS = 1,            /* Scan for 90 (NOP) bytes */
    NEXUS_CAVE_INTS = 2,            /* Scan for CC (INT3) bytes */
    NEXUS_CAVE_ANY_FILL = 3         /* Any repeating byte pattern */
} NexusCodeCaveFillType;

/** Code cave scan options */
typedef enum NexusCodeCaveOptions {
    NEXUS_CAVE_OPT_NONE = 0,
    NEXUS_CAVE_OPT_EXECUTABLE = 0x0001,     /* Only scan executable regions */
    NEXUS_CAVE_OPT_WRITABLE = 0x0002,       /* Only scan writable regions */
    NEXUS_CAVE_OPT_MODULE_ONLY = 0x0004,    /* Only scan within modules */
    NEXUS_CAVE_OPT_PRIVATE = 0x0008,        /* Only scan private memory */
    NEXUS_CAVE_OPT_ALIGN_16 = 0x0010,       /* Align results to 16-byte boundary */
    NEXUS_CAVE_OPT_NEAR_ADDRESS = 0x0020    /* Prefer caves near a target address */
} NexusCodeCaveOptions;

/** Code cave result entry */
typedef struct NexusCodeCaveEntry {
    uint64_t address;               /* Starting address of the cave */
    size_t size;                    /* Size of the cave in bytes */
    uint8_t fillByte;               /* The fill byte found (00, 90, CC, etc.) */
    uint8_t reserved[3];
    uint32_t protection;            /* Memory protection flags */
    wchar_t moduleName[64];         /* Module name if within a module */
    uint64_t moduleBase;            /* Module base address */
} NexusCodeCaveEntry;

/** Code cave scan configuration */
typedef struct NexusCodeCaveScanConfig {
    size_t minSize;                 /* Minimum cave size in bytes (default: 16) */
    size_t maxSize;                 /* Maximum cave size to report (0 = unlimited) */
    uint32_t fillType;              /* NexusCodeCaveFillType */
    uint32_t options;               /* NexusCodeCaveOptions */
    uint64_t startAddress;          /* Start address (0 = process start) */
    uint64_t endAddress;            /* End address (0 = process end) */
    uint64_t nearAddress;           /* Target address for NEAR_ADDRESS option */
    int64_t maxDistance;            /* Max distance from nearAddress (for NEAR_ADDRESS) */
    wchar_t moduleFilter[64];       /* Only scan this module (empty = all) */
} NexusCodeCaveScanConfig;

/** Code cave scan statistics */
typedef struct NexusCodeCaveScanStats {
    uint64_t bytesScanned;          /* Total bytes scanned */
    size_t regionsScanned;          /* Memory regions scanned */
    size_t cavesFound;              /* Total caves found */
    size_t totalCaveBytes;          /* Total bytes in all caves */
    size_t largestCave;             /* Size of largest cave */
    double elapsedMs;               /* Scan time in milliseconds */
} NexusCodeCaveScanStats;

/**
 * Scan for code caves in process memory.
 * Code caves are contiguous regions of fill bytes (zeros, NOPs, INT3s)
 * that can be used for code injection.
 *
 * @param process Process handle
 * @param config Scan configuration
 * @param results Output array for results
 * @param maxResults Maximum number of results to return
 * @param resultCount Output: number of caves found
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanCodeCaves(
    NexusProcessHandle process,
    const NexusCodeCaveScanConfig* config,
    NexusCodeCaveEntry* results,
    size_t maxResults,
    size_t* resultCount
);

/**
 * Scan for code caves and return statistics.
 *
 * @param process Process handle
 * @param config Scan configuration
 * @param results Output array for results (can be NULL)
 * @param maxResults Maximum number of results
 * @param resultCount Output: number of caves found
 * @param stats Output: scan statistics
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ScanCodeCavesEx(
    NexusProcessHandle process,
    const NexusCodeCaveScanConfig* config,
    NexusCodeCaveEntry* results,
    size_t maxResults,
    size_t* resultCount,
    NexusCodeCaveScanStats* stats
);

/**
 * Find the best code cave for a given size requirement.
 * Searches for a cave that meets the size requirement and is
 * optionally near a target address.
 *
 * @param process Process handle
 * @param requiredSize Minimum required size
 * @param nearAddress Preferred address (0 = any location)
 * @param maxDistance Maximum distance from nearAddress (0 = unlimited)
 * @param cave Output: found cave
 * @return NEXUS_OK if found, NEXUS_ERROR_NOT_FOUND if no suitable cave
 */
NEXUS_API NexusResult Nexus_FindBestCodeCave(
    NexusProcessHandle process,
    size_t requiredSize,
    uint64_t nearAddress,
    int64_t maxDistance,
    NexusCodeCaveEntry* cave
);

/**
 * Get default code cave scan configuration.
 *
 * @param config Output: default configuration
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetCodeCaveScanDefaultConfig(
    NexusCodeCaveScanConfig* config
);

/* ============================================================================
 * Pattern Scanning (v0.29.0)
 * ============================================================================ */

/** Pattern scan options */
typedef enum NexusPatternScanOptions {
    NEXUS_PATSCAN_NONE = 0,
    NEXUS_PATSCAN_FIRST_MATCH = 0x0001,     /* Stop after first match */
    NEXUS_PATSCAN_EXECUTABLE = 0x0002,       /* Only scan executable regions */
    NEXUS_PATSCAN_WRITABLE = 0x0004,         /* Only scan writable regions */
    NEXUS_PATSCAN_MODULE_ONLY = 0x0008       /* Only scan within modules */
} NexusPatternScanOptions;

/**
 * Scan for a byte pattern with wildcard support.
 * Pattern format: "DE AD ?? EF" (wildcards: ??, **, *)
 *
 * @param process Process handle
 * @param pattern Pattern string
 * @param startAddress Start address (0 = process start)
 * @param endAddress End address (0 = process end)
 * @param options Scan options (NexusPatternScanOptions)
 * @param results Output array for matching addresses
 * @param maxResults Maximum results to return
 * @param resultCount Output: number of results found
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PatternScan(
    NexusProcessHandle process,
    const char* pattern,
    uint64_t startAddress,
    uint64_t endAddress,
    uint32_t options,
    uint64_t* results,
    size_t maxResults,
    size_t* resultCount
);

/**
 * Scan for a byte pattern within a specific module.
 *
 * @param process Process handle
 * @param pattern Pattern string
 * @param moduleName Module name to scan
 * @param options Scan options
 * @param results Output array for matching addresses
 * @param maxResults Maximum results to return
 * @param resultCount Output: number of results found
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_PatternScanModule(
    NexusProcessHandle process,
    const char* pattern,
    const char* moduleName,
    uint32_t options,
    uint64_t* results,
    size_t maxResults,
    size_t* resultCount
);

/* ============================================================================
 * Type Detection / Auto-Analysis (v0.29.0)
 * ============================================================================ */

/** Type detection flags */
typedef enum NexusTypeGuessFlags {
    NEXUS_TYPE_MIGHT_BE_POINTER = 0x0001,
    NEXUS_TYPE_MIGHT_BE_FLOAT = 0x0002,
    NEXUS_TYPE_MIGHT_BE_STRING = 0x0004,
    NEXUS_TYPE_IS_ZERO = 0x0008
} NexusTypeGuessFlags;

/** Guessed type result */
typedef struct NexusGuessedType {
    int32_t primaryType;        /* Most likely type (NexusScanValueType) */
    int32_t secondaryType;      /* Alternative type */
    float confidence;           /* Confidence level (0.0 - 1.0) */
    uint32_t flags;             /* NexusTypeGuessFlags */
} NexusGuessedType;

/** Auto-analyzed structure field */
typedef struct NexusGuessedField {
    uint32_t offset;            /* Offset from base address */
    int32_t type;               /* Guessed type */
    uint32_t size;              /* Size in bytes */
    float confidence;           /* Confidence level */
    char comment[64];           /* Description/comment */
} NexusGuessedField;

/**
 * Guess the value type at an address using heuristics.
 *
 * @param process Process handle
 * @param address Address to analyze
 * @param result Output: guessed type information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GuessValueType(
    NexusProcessHandle process,
    uint64_t address,
    NexusGuessedType* result
);

/**
 * Auto-analyze a memory region to detect structure fields.
 *
 * @param process Process handle
 * @param baseAddress Base address of structure
 * @param size Size to analyze
 * @param fields Output array for guessed fields
 * @param maxFields Maximum fields to return
 * @param fieldCount Output: number of fields detected
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_AutoAnalyzeStructure(
    NexusProcessHandle process,
    uint64_t baseAddress,
    size_t size,
    NexusGuessedField* fields,
    size_t maxFields,
    size_t* fieldCount
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_SCANNER_H */
