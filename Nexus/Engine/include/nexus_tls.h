/**
 * @file nexus_tls.h
 * @brief TLS (Thread Local Storage) directory manipulation and callback management.
 *
 * Read and modify the TLS directory in PE files, enumerate TLS callbacks,
 * and manage TLS data for unpacking and analysis scenarios.
 * Modelled on the TitanEngine TLS API.
 */

#ifndef NEXUS_TLS_H
#define NEXUS_TLS_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TLS Structures
 * ============================================================================ */

typedef struct NexusTlsInfo {
    uint64_t dataStartVa;               /* Start of TLS template data */
    uint64_t dataEndVa;                 /* End of TLS template data */
    uint64_t indexAddress;              /* Address of TLS index */
    uint64_t callbacksAddress;          /* Address of callbacks array */
    uint32_t zeroFillSize;              /* Size of zero fill */
    uint32_t characteristics;           /* TLS characteristics */
    uint32_t dataSize;                  /* Size of template data */
    uint32_t callbackCount;             /* Number of callbacks */
    uint32_t hasCallbacks;              /* 1 if has callbacks */
    uint32_t reserved;
} NexusTlsInfo;

typedef struct NexusTlsCallback {
    uint64_t address;                   /* Callback address */
    uint32_t index;                     /* Callback index */
    uint32_t isActive;                  /* 1 if callback is active */
    char symbolName[128];               /* Symbol name (if known) */
} NexusTlsCallback;

/* ============================================================================
 * TLS Directory Access
 * ============================================================================ */

/**
 * Check if PE has TLS directory.
 */
NEXUS_API NexusResult Nexus_TlsHasDirectory(
    intptr_t peHandle,
    uint32_t* hasTls
);

/**
 * Get TLS information.
 */
NEXUS_API NexusResult Nexus_TlsGetInfo(
    intptr_t peHandle,
    NexusTlsInfo* info
);

/**
 * Get TLS callbacks.
 */
NEXUS_API NexusResult Nexus_TlsGetCallbacks(
    intptr_t peHandle,
    NexusTlsCallback* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get TLS template data.
 */
NEXUS_API NexusResult Nexus_TlsGetData(
    intptr_t peHandle,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/* ============================================================================
 * TLS Directory Modification
 * ============================================================================ */

/**
 * Create TLS directory.
 */
NEXUS_API NexusResult Nexus_TlsCreate(
    intptr_t peHandle,
    uint32_t dataSize,
    uint32_t zeroFillSize
);

/**
 * Delete TLS directory.
 */
NEXUS_API NexusResult Nexus_TlsDelete(intptr_t peHandle);

/**
 * Set TLS template data.
 */
NEXUS_API NexusResult Nexus_TlsSetData(
    intptr_t peHandle,
    const uint8_t* data,
    size_t dataSize
);

/**
 * Set TLS characteristics.
 */
NEXUS_API NexusResult Nexus_TlsSetCharacteristics(
    intptr_t peHandle,
    uint32_t characteristics
);

/* ============================================================================
 * TLS Callback Management
 * ============================================================================ */

/**
 * Add TLS callback.
 */
NEXUS_API NexusResult Nexus_TlsAddCallback(
    intptr_t peHandle,
    uint64_t callbackRva
);

/**
 * Remove TLS callback.
 */
NEXUS_API NexusResult Nexus_TlsRemoveCallback(
    intptr_t peHandle,
    uint32_t index
);

/**
 * Clear all TLS callbacks.
 */
NEXUS_API NexusResult Nexus_TlsClearCallbacks(intptr_t peHandle);

/**
 * Replace TLS callback.
 */
NEXUS_API NexusResult Nexus_TlsReplaceCallback(
    intptr_t peHandle,
    uint32_t index,
    uint64_t newCallbackRva
);

/* ============================================================================
 * Runtime TLS Operations
 * ============================================================================ */

/**
 * Get TLS value for thread.
 */
NEXUS_API NexusResult Nexus_TlsGetValue(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t tlsIndex,
    uint64_t* value
);

/**
 * Set TLS value for thread.
 */
NEXUS_API NexusResult Nexus_TlsSetValue(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t tlsIndex,
    uint64_t value
);

/**
 * Get TLS slot data for thread.
 */
NEXUS_API NexusResult Nexus_TlsGetSlotData(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t tlsIndex,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesRead
);

/**
 * Hook TLS callback (set breakpoint before callback).
 */
NEXUS_API NexusResult Nexus_TlsHookCallback(
    NexusDebuggerHandle debugger,
    uint32_t callbackIndex,
    uint32_t* breakpointId
);

/**
 * Skip TLS callbacks (bypass during debugging).
 */
NEXUS_API NexusResult Nexus_TlsSkipCallbacks(
    NexusDebuggerHandle debugger,
    uint32_t skip
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_TLS_H */
