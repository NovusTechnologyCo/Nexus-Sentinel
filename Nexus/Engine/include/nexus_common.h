/**
 * @file nexus_common.h
 * @brief Common types, result codes, opaque handles, and engine lifecycle.
 *
 * This is the foundational header for the Nexus Engine. It defines the
 * shared vocabulary used across the entire public API: result codes for
 * error handling, opaque handle types for resource management, version
 * constants, and the engine initialization/shutdown entry points.
 *
 * Every other Nexus header includes this file. Consumers who include
 * nexus_api.h (the master header) get this automatically.
 */

#ifndef NEXUS_COMMON_H
#define NEXUS_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Export/Import macros */
#ifdef NEXUS_ENGINE_EXPORTS
    #define NEXUS_API __declspec(dllexport)
#else
    #define NEXUS_API __declspec(dllimport)
#endif

/* Version information */
#define NEXUS_VERSION_MAJOR 1
#define NEXUS_VERSION_MINOR 0
#define NEXUS_VERSION_PATCH 0

/* ============================================================================
 * Result Codes
 * ============================================================================ */

/**
 * @brief Engine-wide result codes returned by all Nexus API functions.
 *
 * Functions return NEXUS_OK (0) on success. Non-zero values indicate
 * specific failure modes. Use Nexus_GetErrorString() to convert a
 * result code to a human-readable message.
 */
typedef enum NexusResult {
    NEXUS_OK = 0,                        /**< Operation completed successfully. */
    NEXUS_ERROR_INVALID_HANDLE = 1,      /**< The supplied handle is invalid or has been freed. */
    NEXUS_ERROR_INVALID_PARAMETER = 2,   /**< One or more parameters are NULL or out of range. */
    NEXUS_ERROR_ACCESS_DENIED = 3,       /**< Insufficient privileges or the OS denied the request. */
    NEXUS_ERROR_NOT_FOUND = 4,           /**< The requested item (process, symbol, region) was not found. */
    NEXUS_ERROR_INSUFFICIENT_BUFFER = 5, /**< The caller-supplied buffer is too small for all results. */
    NEXUS_ERROR_PARTIAL_READ = 6,        /**< A memory read completed only partially. */
    NEXUS_ERROR_PARTIAL_WRITE = 7,       /**< A memory write completed only partially. */
    NEXUS_ERROR_OUT_OF_MEMORY = 8,       /**< Heap allocation failed. */
    NEXUS_ERROR_PARTIAL = 9,             /**< Generic partial-completion indicator. */
    NEXUS_ERROR_NOT_IMPLEMENTED = 10,    /**< The requested feature is not yet implemented. */
    NEXUS_ERROR_ALREADY_EXISTS = 11,     /**< A resource with the same identifier already exists. */
    NEXUS_ERROR_TIMEOUT = 12,            /**< The operation timed out. */
    NEXUS_ERROR_CANCELLED = 13,          /**< The operation was cancelled by the caller. */
    NEXUS_ERROR_ALREADY_RUNNING = 14,    /**< An asynchronous operation is already in progress. */
    NEXUS_ERROR_INVALID_STATE = 15,      /**< The object is not in the correct state for this call. */
    NEXUS_ERROR_BUFFER_TOO_SMALL = 16,   /**< Alias for insufficient-buffer in some contexts. */
    NEXUS_ERROR_UNKNOWN = 255            /**< An unrecognised or OS-level error occurred. */
} NexusResult;

/* ============================================================================
 * Opaque Handle Types
 * ============================================================================ */

typedef void* NexusProcessHandle;
typedef void* NexusMemorySnapshot;
typedef void* NexusScanHandle;
typedef struct NexusAdvScanner* NexusAdvScannerHandle;
typedef void* NexusDebuggerHandle;
typedef void* NexusStackWalkerHandle;
typedef void* NexusPointerScanHandle;
typedef void* NexusProjectHandle;
typedef void* NexusTableHandle;
typedef void* NexusSpeedhackHandle;
typedef void* NexusAssemblerHandle;
typedef void* NexusSignatureHandle;
typedef void* NexusSignatureScannerHandle;
typedef void* NexusTraceHandle;
typedef void* NexusAddressFileHandle;
typedef void* NexusTrainerHandle;
typedef void* NexusStructureHandle;
typedef void* NexusKernelHandle;
typedef void* NexusCFGHandle;

/* ============================================================================
 * Version & Initialization
 * ============================================================================ */

/**
 * @brief Retrieve the engine version triplet.
 *
 * Any output pointer may be NULL if that component is not needed.
 *
 * @param[out] major Major version number.
 * @param[out] minor Minor version number.
 * @param[out] patch Patch version number.
 */
NEXUS_API void Nexus_GetVersion(int* major, int* minor, int* patch);

/**
 * @brief Initialise the Nexus Engine. Must be called once before any other API.
 *
 * Calling this function more than once is safe; subsequent calls return
 * NEXUS_OK immediately without reinitialising.
 *
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_Initialize(void);

/**
 * @brief Shut down the Nexus Engine and release all global resources.
 *
 * After this call, no other Nexus API functions should be used unless
 * Nexus_Initialize() is called again. Calling Nexus_Shutdown() when
 * the engine is not initialised is a safe no-op.
 */
NEXUS_API void Nexus_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_COMMON_H */
