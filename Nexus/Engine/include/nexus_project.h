/**
 * @file nexus_project.h
 * @brief Project management for saving and loading address lists and configurations.
 *
 * A project (.nsp) groups address entries (with optional pointer chains),
 * value-type metadata, freeze/display flags, and target-process information
 * into a JSON file.  The API supports CRUD on address entries, value refresh
 * against a live process, and full serialization.
 */

#ifndef NEXUS_PROJECT_H
#define NEXUS_PROJECT_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Project Types
 * ============================================================================ */

/* Value types for address entries (matches scan value types) */
typedef enum NexusAddressValueType {
    NEXUS_ADDR_VALUE_INT8 = 0,
    NEXUS_ADDR_VALUE_INT16 = 1,
    NEXUS_ADDR_VALUE_INT32 = 2,
    NEXUS_ADDR_VALUE_INT64 = 3,
    NEXUS_ADDR_VALUE_FLOAT32 = 4,
    NEXUS_ADDR_VALUE_FLOAT64 = 5,
    NEXUS_ADDR_VALUE_STRING = 6,
    NEXUS_ADDR_VALUE_AOB = 7,
    NEXUS_ADDR_VALUE_POINTER = 8   /* Address is a pointer chain */
} NexusAddressValueType;

/* Address entry flags */
typedef enum NexusAddressFlags {
    NEXUS_ADDR_FLAG_NONE = 0,
    NEXUS_ADDR_FLAG_FROZEN = 0x0001,       /* Value is frozen (write on change) */
    NEXUS_ADDR_FLAG_HIDDEN = 0x0002,       /* Hidden from UI */
    NEXUS_ADDR_FLAG_READONLY = 0x0004,     /* Read-only display */
    NEXUS_ADDR_FLAG_POINTER = 0x0008       /* Address is a pointer chain */
} NexusAddressFlags;

/* Address list entry */
typedef struct NexusAddressEntry {
    uint64_t id;                    /* Unique entry ID */
    uint64_t address;               /* Static address or base for pointer */
    NexusAddressValueType valueType;
    uint32_t flags;                 /* NexusAddressFlags OR'd together */
    wchar_t description[256];       /* User description */
    wchar_t groupName[64];          /* Group/category name */

    /* For pointer chains */
    int64_t offsets[16];            /* Pointer offsets (max 16 levels) */
    uint32_t offsetCount;           /* Number of offsets */

    /* Current value (updated on refresh) */
    union {
        int64_t intValue;
        double floatValue;
        uint8_t bytes[8];
    } currentValue;
} NexusAddressEntry;

/* Project metadata */
typedef struct NexusProjectInfo {
    wchar_t name[256];              /* Project name */
    wchar_t targetProcess[260];     /* Target process name */
    uint32_t targetPid;             /* Last attached PID (0 if none) */
    uint32_t schemaVersion;         /* Project file schema version */
    uint64_t addressCount;          /* Number of address entries */
    uint64_t createdTime;           /* Creation timestamp (Unix time) */
    uint64_t modifiedTime;          /* Last modified timestamp */
} NexusProjectInfo;

/* ============================================================================
 * Project Operations
 * ============================================================================ */

/**
 * Create a new empty project.
 * @param project Output: project handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectCreate(NexusProjectHandle* project);

/**
 * Destroy a project and free all resources.
 * @param project Project handle
 */
NEXUS_API void Nexus_ProjectDestroy(NexusProjectHandle project);

/**
 * Load a project from file.
 * @param path File path (UTF-16)
 * @param project Output: project handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectLoad(
    const wchar_t* path,
    NexusProjectHandle* project
);

/**
 * Save a project to file.
 * @param project Project handle
 * @param path File path (UTF-16)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectSave(
    NexusProjectHandle project,
    const wchar_t* path
);

/**
 * Get project metadata.
 * @param project Project handle
 * @param info Output: project info
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectGetInfo(
    NexusProjectHandle project,
    NexusProjectInfo* info
);

/**
 * Set project name.
 * @param project Project handle
 * @param name New project name (UTF-16)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectSetName(
    NexusProjectHandle project,
    const wchar_t* name
);

/**
 * Set target process name.
 * @param project Project handle
 * @param processName Process name (UTF-16)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectSetTargetProcess(
    NexusProjectHandle project,
    const wchar_t* processName
);

/* ============================================================================
 * Address List Operations
 * ============================================================================ */

/**
 * Add an address entry to the project.
 * @param project Project handle
 * @param entry Address entry to add
 * @param id Output: assigned entry ID
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectAddAddress(
    NexusProjectHandle project,
    const NexusAddressEntry* entry,
    uint64_t* id
);

/**
 * Remove an address entry from the project.
 * @param project Project handle
 * @param id Entry ID to remove
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if ID doesn't exist
 */
NEXUS_API NexusResult Nexus_ProjectRemoveAddress(
    NexusProjectHandle project,
    uint64_t id
);

/**
 * Update an address entry in the project.
 * @param project Project handle
 * @param entry Updated entry (uses entry->id to identify)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectUpdateAddress(
    NexusProjectHandle project,
    const NexusAddressEntry* entry
);

/**
 * Get an address entry by ID.
 * @param project Project handle
 * @param id Entry ID
 * @param entry Output: address entry
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if ID doesn't exist
 */
NEXUS_API NexusResult Nexus_ProjectGetAddress(
    NexusProjectHandle project,
    uint64_t id,
    NexusAddressEntry* entry
);

/**
 * Get the number of address entries.
 * @param project Project handle
 * @param count Output: number of entries
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectGetAddressCount(
    NexusProjectHandle project,
    uint64_t* count
);

/**
 * Get address entries (paginated).
 * @param project Project handle
 * @param startIndex Starting index
 * @param buffer Array to receive entries
 * @param bufferCount Size of buffer array
 * @param entriesReturned Output: number of entries returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectGetAddresses(
    NexusProjectHandle project,
    uint64_t startIndex,
    NexusAddressEntry* buffer,
    size_t bufferCount,
    size_t* entriesReturned
);

/**
 * Refresh current values for all address entries.
 * Requires an attached process.
 * @param project Project handle
 * @param process Process handle to read values from
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectRefreshValues(
    NexusProjectHandle project,
    NexusProcessHandle process
);

/**
 * Clear all address entries from the project.
 * @param project Project handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ProjectClearAddresses(NexusProjectHandle project);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_PROJECT_H */
