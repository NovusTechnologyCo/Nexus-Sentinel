/**
 * @file nexus_etw.h
 * @brief ETW (Event Tracing for Windows) API for real-time process monitoring.
 *
 * Clean-room implementation of ETW tracing that captures file, registry,
 * network, process, thread, and image-load events.  Supports predicate-based
 * filtering, JSON serialization of events, and event correlation.
 *
 * Architecture supports privilege escalation path:
 *   User Mode ETW -> Kernel ETW Session -> Kernel Driver -> Hypervisor
 */

#ifndef NEXUS_ETW_H
#define NEXUS_ETW_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Opaque Handle
 * ============================================================================ */

typedef void* NexusEtwHandle;

/* ============================================================================
 * ETW Provider Flags - Which event categories to capture
 * ============================================================================ */

typedef enum NexusEtwProviders {
    NEXUS_ETW_NONE              = 0,
    NEXUS_ETW_PROCESS           = 0x0001,   /* Process create/exit */
    NEXUS_ETW_THREAD            = 0x0002,   /* Thread create/exit */
    NEXUS_ETW_IMAGE_LOAD        = 0x0004,   /* DLL/EXE load/unload */
    NEXUS_ETW_FILE_IO           = 0x0008,   /* File operations */
    NEXUS_ETW_REGISTRY          = 0x0010,   /* Registry operations (high volume!) */
    NEXUS_ETW_NETWORK           = 0x0020,   /* TCP/UDP activity */
    NEXUS_ETW_DISK_IO           = 0x0040,   /* Low-level disk I/O */
    NEXUS_ETW_VIRTUAL_ALLOC     = 0x0080,   /* VirtualAlloc/Free */
    NEXUS_ETW_CONTEXT_SWITCH    = 0x0100,   /* Thread context switches (very high volume!) */
    NEXUS_ETW_SYSTEM_CALL       = 0x0200,   /* System calls (high volume!) */
    NEXUS_ETW_ALPC              = 0x0400,   /* Advanced Local Procedure Calls */
    NEXUS_ETW_DNS               = 0x0800,   /* DNS query/response events */
    NEXUS_ETW_RPC               = 0x1000,   /* RPC/COM activity */

    /* Common presets */
    NEXUS_ETW_BASIC             = NEXUS_ETW_PROCESS | NEXUS_ETW_THREAD | NEXUS_ETW_IMAGE_LOAD,
    NEXUS_ETW_PROCMON           = NEXUS_ETW_BASIC | NEXUS_ETW_FILE_IO | NEXUS_ETW_REGISTRY | NEXUS_ETW_NETWORK,
    NEXUS_ETW_SECURITY          = NEXUS_ETW_PROCMON | NEXUS_ETW_DNS | NEXUS_ETW_RPC,
    NEXUS_ETW_ALL               = 0x1FFF
} NexusEtwProviders;

/* ============================================================================
 * ETW Event Categories (matches NexusEtwProviders but for individual events)
 * ============================================================================ */

typedef enum NexusEtwEventCategory {
    NEXUS_ETW_CAT_UNKNOWN       = 0,
    NEXUS_ETW_CAT_PROCESS       = 1,
    NEXUS_ETW_CAT_THREAD        = 2,
    NEXUS_ETW_CAT_IMAGE         = 3,
    NEXUS_ETW_CAT_FILE          = 4,
    NEXUS_ETW_CAT_REGISTRY      = 5,
    NEXUS_ETW_CAT_NETWORK       = 6,
    NEXUS_ETW_CAT_DISK          = 7,
    NEXUS_ETW_CAT_MEMORY        = 8,
    NEXUS_ETW_CAT_SYSCALL       = 9,
    NEXUS_ETW_CAT_ALPC          = 10,
    NEXUS_ETW_CAT_DNS           = 11,
    NEXUS_ETW_CAT_RPC           = 12
} NexusEtwEventCategory;

/* ============================================================================
 * ETW Event Operations (subcategories)
 * ============================================================================ */

typedef enum NexusEtwOperation {
    /* Process */
    NEXUS_ETW_OP_PROCESS_START      = 100,
    NEXUS_ETW_OP_PROCESS_EXIT       = 101,

    /* Thread */
    NEXUS_ETW_OP_THREAD_START       = 200,
    NEXUS_ETW_OP_THREAD_EXIT        = 201,

    /* Image */
    NEXUS_ETW_OP_IMAGE_LOAD         = 300,
    NEXUS_ETW_OP_IMAGE_UNLOAD       = 301,

    /* File */
    NEXUS_ETW_OP_FILE_CREATE        = 400,
    NEXUS_ETW_OP_FILE_READ          = 401,
    NEXUS_ETW_OP_FILE_WRITE         = 402,
    NEXUS_ETW_OP_FILE_DELETE        = 403,
    NEXUS_ETW_OP_FILE_RENAME        = 404,
    NEXUS_ETW_OP_FILE_CLOSE         = 405,
    NEXUS_ETW_OP_FILE_QUERY_INFO    = 406,
    NEXUS_ETW_OP_FILE_SET_INFO      = 407,

    /* Registry */
    NEXUS_ETW_OP_REG_OPEN           = 500,
    NEXUS_ETW_OP_REG_CREATE         = 501,
    NEXUS_ETW_OP_REG_QUERY          = 502,
    NEXUS_ETW_OP_REG_SET            = 503,
    NEXUS_ETW_OP_REG_DELETE         = 504,
    NEXUS_ETW_OP_REG_ENUM_KEY       = 505,
    NEXUS_ETW_OP_REG_ENUM_VALUE     = 506,
    NEXUS_ETW_OP_REG_CLOSE          = 507,

    /* Network */
    NEXUS_ETW_OP_NET_TCP_CONNECT    = 600,
    NEXUS_ETW_OP_NET_TCP_DISCONNECT = 601,
    NEXUS_ETW_OP_NET_TCP_SEND       = 602,
    NEXUS_ETW_OP_NET_TCP_RECV       = 603,
    NEXUS_ETW_OP_NET_TCP_ACCEPT     = 604,
    NEXUS_ETW_OP_NET_UDP_SEND       = 610,
    NEXUS_ETW_OP_NET_UDP_RECV       = 611,

    /* Memory */
    NEXUS_ETW_OP_MEM_ALLOC          = 700,
    NEXUS_ETW_OP_MEM_FREE           = 701,
    NEXUS_ETW_OP_MEM_PROTECT        = 702,

    /* DNS */
    NEXUS_ETW_OP_DNS_QUERY_START    = 800,
    NEXUS_ETW_OP_DNS_QUERY_COMPLETE = 801,

    /* RPC */
    NEXUS_ETW_OP_RPC_CLIENT_CALL    = 900,
    NEXUS_ETW_OP_RPC_SERVER_CALL    = 901,

    /* Other */
    NEXUS_ETW_OP_OTHER              = 999
} NexusEtwOperation;

/* ============================================================================
 * ETW Filter Predicate - For advanced event filtering
 * ============================================================================ */

typedef enum NexusEtwFilterOp {
    NEXUS_ETW_FILTER_OP_EQUALS      = 0,    /* Exact match */
    NEXUS_ETW_FILTER_OP_NOT_EQUALS  = 1,    /* Not equal */
    NEXUS_ETW_FILTER_OP_CONTAINS    = 2,    /* String contains */
    NEXUS_ETW_FILTER_OP_STARTS_WITH = 3,    /* String starts with */
    NEXUS_ETW_FILTER_OP_ENDS_WITH   = 4,    /* String ends with */
    NEXUS_ETW_FILTER_OP_GREATER     = 5,    /* Numeric greater than */
    NEXUS_ETW_FILTER_OP_LESS        = 6     /* Numeric less than */
} NexusEtwFilterOp;

typedef enum NexusEtwFilterField {
    NEXUS_ETW_FIELD_PID             = 0,    /* Process ID */
    NEXUS_ETW_FIELD_PNAME           = 1,    /* Process name */
    NEXUS_ETW_FIELD_PATH            = 2,    /* Path/filename */
    NEXUS_ETW_FIELD_CATEGORY        = 3,    /* Event category */
    NEXUS_ETW_FIELD_OPERATION       = 4,    /* Event operation */
    NEXUS_ETW_FIELD_LEVEL           = 5     /* Event severity level */
} NexusEtwFilterField;

typedef struct NexusEtwFilter {
    uint32_t field;                 /* NexusEtwFilterField */
    uint32_t operation;             /* NexusEtwFilterOp */
    union {
        uint64_t numericValue;      /* For PID, category, operation, level */
        wchar_t stringValue[260];   /* For pname, path */
    } value;
} NexusEtwFilter;

/* ============================================================================
 * Predicate Composition Types (Phase 4 - sealighter pattern)
 * ============================================================================ */

typedef void* NexusEtwPredicateHandle;

typedef enum NexusEtwPredicateType {
    NEXUS_ETW_PRED_FIELD_MATCH  = 0,    /* Single field filter */
    NEXUS_ETW_PRED_ANY_OF       = 1,    /* OR: any child must match */
    NEXUS_ETW_PRED_ALL_OF       = 2,    /* AND: all children must match */
    NEXUS_ETW_PRED_NONE_OF      = 3     /* NOR: no children may match */
} NexusEtwPredicateType;

/* ============================================================================
 * Kernel-Level Event Filter (Phase 3 - EVENT_FILTER_DESCRIPTOR)
 *
 * Pushes event ID filtering to the kernel ETW subsystem.
 * This is more efficient than user-mode filtering because events
 * are filtered before being delivered to the trace consumer.
 * ============================================================================ */

typedef struct NexusEtwKernelFilter {
    uint8_t providerId[16];         /* GUID of provider to filter */
    uint16_t* eventIds;             /* Event IDs to include (NULL = all) */
    size_t eventIdCount;            /* Number of event IDs */
    uint16_t* excludeIds;           /* Event IDs to exclude */
    size_t excludeIdCount;          /* Number of excluded IDs */
    uint8_t level;                  /* Minimum level (0 = all) */
    uint64_t matchAnyKeyword;       /* Keyword filter (0 = all) */
} NexusEtwKernelFilter;

/* ============================================================================
 * ETW Configuration Flags
 * ============================================================================ */

typedef enum NexusEtwConfigFlags {
    NEXUS_ETW_FLAG_NONE             = 0,
    NEXUS_ETW_FLAG_STACK_WALK       = 0x0001,   /* Capture call stacks (requires admin) */
    NEXUS_ETW_FLAG_INCLUDE_RAW      = 0x0002,   /* Include raw event data */
    NEXUS_ETW_FLAG_USE_KERNEL_LOGGER = 0x0004   /* Use NT Kernel Logger (more efficient) */
} NexusEtwConfigFlags;

/* ============================================================================
 * ETW Configuration
 * ============================================================================ */

typedef struct NexusEtwConfig {
    uint32_t providers;             /* Bitmask of NexusEtwProviders */
    uint32_t targetPid;             /* Filter to specific PID (0 = all) */
    uint32_t bufferSizeKb;          /* Per-buffer size in KB (default: 64) */
    uint32_t minBuffers;            /* Minimum buffer count (default: 8) */
    uint32_t maxBuffers;            /* Maximum buffer count (default: 64) */
    uint32_t flushTimerMs;          /* Flush timer in milliseconds (default: 1000) */
    uint32_t maxEventsPerSecond;    /* Rate limit (0 = unlimited) */
    uint32_t flags;                 /* NexusEtwConfigFlags bitmask */
    wchar_t sessionName[64];        /* Custom session name (empty = auto) */
} NexusEtwConfig;

/* ============================================================================
 * ETW Event Structure - Returned by event callback or polling
 * ============================================================================ */

typedef struct NexusEtwEvent {
    /* Event identification */
    uint64_t sequenceNumber;        /* Monotonic sequence number */
    uint64_t timestamp;             /* Timestamp in 100ns intervals since 1601 */

    /* Classification */
    uint32_t category;              /* NexusEtwEventCategory */
    uint32_t operation;             /* NexusEtwOperation */

    /* Process/Thread context */
    uint32_t processId;
    uint32_t threadId;

    /* Resolved process name (Phase 2 - cached) */
    wchar_t processName[64];

    /* Result/Status */
    int32_t status;                 /* NTSTATUS or Win32 error code */
    uint64_t duration;              /* Duration in 100ns intervals (if available) */

    /* Path/Name (null-terminated, up to 520 chars) */
    wchar_t path[520];

    /* Additional context-specific data */
    union {
        /* File I/O */
        struct {
            uint64_t offset;
            uint64_t size;
            uint32_t shareMode;
            uint32_t createOptions;
        } file;

        /* Registry */
        struct {
            uint32_t dataType;      /* REG_SZ, REG_DWORD, etc. */
            uint32_t dataSize;
            wchar_t valueName[256];
        } registry;

        /* Network */
        struct {
            uint32_t localAddr;     /* IPv4 address (network byte order) */
            uint32_t remoteAddr;
            uint16_t localPort;
            uint16_t remotePort;
            uint32_t size;          /* Bytes sent/received */
        } network;

        /* Process */
        struct {
            uint32_t parentPid;
            uint32_t sessionId;
            uint32_t exitCode;
            wchar_t imageName[260];
            wchar_t commandLine[520];
        } process;

        /* Image load */
        struct {
            uint64_t imageBase;
            uint64_t imageSize;
            uint32_t imageChecksum;
            wchar_t fileName[260];
        } image;

        /* Memory */
        struct {
            uint64_t baseAddress;
            uint64_t regionSize;
            uint32_t allocationType;
            uint32_t protection;
        } memory;

        /* DNS */
        struct {
            wchar_t queryName[256];      /* Domain name queried */
            uint32_t queryType;          /* DNS query type (A, AAAA, etc.) */
            uint32_t queryStatus;        /* Result status */
            uint32_t responseFlags;
            wchar_t queryResult[256];    /* Resolved IP addresses */
        } dns;

        /* RPC */
        struct {
            wchar_t interfaceName[128];  /* RPC interface name */
            wchar_t procedureName[128];  /* Procedure being called */
            wchar_t endpoint[128];       /* RPC endpoint */
            uint32_t protocol;           /* Transport protocol */
            uint32_t authLevel;          /* Authentication level */
        } rpc;

        /* Raw data for unhandled events */
        uint8_t raw[1024];
    } data;

    /* Stack walk data (if NEXUS_ETW_FLAG_STACK_WALK enabled) */
    struct {
        uint64_t addresses[32];          /* Return addresses on stack */
        uint32_t depth;                  /* Number of valid addresses */
        uint32_t reserved;
    } stack;

    /* Size of valid data in union */
    uint32_t dataSize;
    uint32_t reserved;
} NexusEtwEvent;

/* ============================================================================
 * Event Correlation Types (Phase 5 - wtrace pattern)
 * ============================================================================ */

typedef enum NexusEtwCorrelationType {
    NEXUS_ETW_CORR_NONE         = 0,
    NEXUS_ETW_CORR_FILE_IO      = 0x0001,   /* File open/close, read/write */
    NEXUS_ETW_CORR_REGISTRY     = 0x0002,   /* Registry open/close */
    NEXUS_ETW_CORR_NETWORK      = 0x0004,   /* TCP connect/disconnect */
    NEXUS_ETW_CORR_RPC          = 0x0008,   /* RPC call start/end */
    NEXUS_ETW_CORR_DNS          = 0x0010,   /* DNS query start/complete */
    NEXUS_ETW_CORR_PROCESS      = 0x0020,   /* Process start/exit */
    NEXUS_ETW_CORR_ALL          = 0xFFFF
} NexusEtwCorrelationType;

typedef struct NexusEtwCorrelatedEvent {
    NexusEtwEvent startEvent;       /* Start of operation */
    NexusEtwEvent endEvent;         /* End of operation */
    uint64_t duration;              /* Duration in 100ns intervals */
    uint32_t correlationType;       /* NexusEtwCorrelationType */
    uint32_t correlationId;         /* Unique ID for this correlation */
} NexusEtwCorrelatedEvent;

typedef void (*NexusEtwCorrelatedCallback)(const NexusEtwCorrelatedEvent* event, void* userContext);

/* ============================================================================
 * ETW Statistics
 * ============================================================================ */

typedef struct NexusEtwStats {
    uint64_t eventsReceived;        /* Total events received */
    uint64_t eventsDropped;         /* Events dropped due to buffer overflow */
    uint64_t eventsFiltered;        /* Events filtered out by PID filter */
    uint64_t bytesReceived;         /* Total bytes processed */
    uint32_t buffersUsed;           /* Current buffer count */
    uint32_t buffersLost;           /* Buffers lost */
    uint32_t isRunning;             /* 1 if trace is active */
    uint32_t lastError;             /* Last Win32 error code */

    /* Schema cache statistics (Phase 1) */
    uint64_t schemaCacheHits;       /* Schema cache hits */
    uint64_t schemaCacheMisses;     /* Schema cache misses */
    uint32_t schemaCacheSize;       /* Current cache entries */
    uint32_t schemaCacheEvictions;  /* Total evictions */

    /* Process name cache statistics (Phase 2) */
    uint64_t processNameCacheHits;  /* Process name cache hits */
    uint64_t processNameCacheMisses;/* Process name cache misses */
    uint32_t processNameCacheSize;  /* Current cache entries */
    uint32_t reserved2;

    /* Event correlation statistics (Phase 5) */
    uint64_t correlatedEvents;      /* Number of events correlated */
    uint64_t pendingCorrelations;   /* Operations awaiting completion */
    uint64_t timedOutCorrelations;  /* Operations that timed out */
    uint64_t reserved3;
} NexusEtwStats;

/* ============================================================================
 * Event Callback Type
 * ============================================================================ */

/**
 * Callback function for real-time event delivery.
 * Called from the ETW processing thread - keep processing fast!
 *
 * @param event     Pointer to event data (valid only during callback)
 * @param userContext   User-provided context pointer
 */
typedef void (*NexusEtwEventCallback)(const NexusEtwEvent* event, void* userContext);

/* ============================================================================
 * ETW Session Management
 * ============================================================================ */

/**
 * Create an ETW tracing session.
 * Does not start tracing - call Nexus_EtwStart() to begin.
 *
 * @param config    Configuration options (NULL for defaults)
 * @param handle    Receives the ETW handle
 * @return          NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwCreate(
    const NexusEtwConfig* config,
    NexusEtwHandle* handle
);

/**
 * Destroy an ETW tracing session.
 * Automatically stops tracing if running.
 *
 * @param handle    ETW handle from Nexus_EtwCreate
 */
NEXUS_API void Nexus_EtwDestroy(NexusEtwHandle handle);

/**
 * Start ETW tracing.
 *
 * @param handle    ETW handle
 * @return          NEXUS_OK on success, NEXUS_ERROR_ACCESS_DENIED if admin required
 */
NEXUS_API NexusResult Nexus_EtwStart(NexusEtwHandle handle);

/**
 * Stop ETW tracing.
 *
 * @param handle    ETW handle
 * @return          NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwStop(NexusEtwHandle handle);

/**
 * Check if tracing is currently active.
 *
 * @param handle    ETW handle
 * @param isRunning Receives 1 if running, 0 if stopped
 * @return          NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwIsRunning(NexusEtwHandle handle, uint32_t* isRunning);

/* ============================================================================
 * Event Retrieval
 * ============================================================================ */

/**
 * Set callback for real-time event delivery.
 * The callback is invoked from the ETW processing thread.
 *
 * @param handle        ETW handle
 * @param callback      Callback function (NULL to disable)
 * @param userContext   User pointer passed to callback
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetCallback(
    NexusEtwHandle handle,
    NexusEtwEventCallback callback,
    void* userContext
);

/**
 * Poll for events (alternative to callback).
 * Events are copied to the provided buffer.
 *
 * @param handle        ETW handle
 * @param events        Buffer to receive events
 * @param maxEvents     Maximum events to retrieve
 * @param eventCount    Receives actual event count
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwPollEvents(
    NexusEtwHandle handle,
    NexusEtwEvent* events,
    size_t maxEvents,
    size_t* eventCount
);

/**
 * Get the number of pending events in the queue.
 *
 * @param handle        ETW handle
 * @param count         Receives pending event count
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetPendingCount(
    NexusEtwHandle handle,
    size_t* count
);

/**
 * Clear all pending events from the queue.
 *
 * @param handle        ETW handle
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwClearEvents(NexusEtwHandle handle);

/* ============================================================================
 * Configuration & Statistics
 * ============================================================================ */

/**
 * Update providers while tracing (add/remove event categories).
 *
 * @param handle        ETW handle
 * @param providers     New provider bitmask
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetProviders(
    NexusEtwHandle handle,
    uint32_t providers
);

/**
 * Update PID filter while tracing.
 *
 * @param handle        ETW handle
 * @param targetPid     New target PID (0 = all processes)
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetTargetPid(
    NexusEtwHandle handle,
    uint32_t targetPid
);

/**
 * Get current statistics.
 *
 * @param handle        ETW handle
 * @param stats         Receives statistics
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetStats(
    NexusEtwHandle handle,
    NexusEtwStats* stats
);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Convert timestamp to Windows FILETIME.
 *
 * @param timestamp     ETW timestamp (100ns intervals since 1601)
 * @param fileTime      Receives FILETIME (can cast to FILETIME*)
 */
NEXUS_API void Nexus_EtwTimestampToFileTime(
    uint64_t timestamp,
    uint64_t* fileTime
);

/**
 * Get human-readable operation name.
 *
 * @param operation     NexusEtwOperation value
 * @return              Static string (do not free)
 */
NEXUS_API const char* Nexus_EtwGetOperationName(uint32_t operation);

/**
 * Get human-readable category name.
 *
 * @param category      NexusEtwEventCategory value
 * @return              Static string (do not free)
 */
NEXUS_API const char* Nexus_EtwGetCategoryName(uint32_t category);

/**
 * Check if the current process has admin privileges (required for ETW).
 *
 * @param isAdmin       Receives 1 if admin, 0 if not
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwCheckAdminPrivilege(uint32_t* isAdmin);

/* ============================================================================
 * Filtering API
 * ============================================================================ */

/**
 * Add a filter predicate to the ETW session.
 * Multiple filters are AND'd together (all must match).
 * Filters with the same field are OR'd together (any can match).
 *
 * @param handle        ETW handle
 * @param filter        Filter predicate to add
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwAddFilter(
    NexusEtwHandle handle,
    const NexusEtwFilter* filter
);

/**
 * Clear all filter predicates.
 *
 * @param handle        ETW handle
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwClearFilters(NexusEtwHandle handle);

/**
 * Get the number of active filters.
 *
 * @param handle        ETW handle
 * @param count         Receives filter count
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetFilterCount(
    NexusEtwHandle handle,
    size_t* count
);

/* ============================================================================
 * Predicate Composition API (Phase 4 - sealighter pattern)
 *
 * Enables complex filter expressions using logical grouping:
 * - ANY_OF: OR logic - matches if any child predicate matches
 * - ALL_OF: AND logic - matches only if all children match
 * - NONE_OF: NOR logic - matches only if no children match
 *
 * Example: Match events from (pid=1234 OR pid=5678) AND path contains "System32"
 *   predAnyPid = CreatePredicate(ANY_OF)
 *     AddChild(predAnyPid, CreateFieldMatch(PID == 1234))
 *     AddChild(predAnyPid, CreateFieldMatch(PID == 5678))
 *   predAllOf = CreatePredicate(ALL_OF)
 *     AddChild(predAllOf, predAnyPid)
 *     AddChild(predAllOf, CreateFieldMatch(PATH contains "System32"))
 *   SetFilterPredicate(handle, predAllOf)
 * ============================================================================ */

/**
 * Create a predicate node for filter composition.
 *
 * @param type          Predicate type (NexusEtwPredicateType)
 * @param predicate     Receives the predicate handle
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwCreatePredicate(
    uint32_t type,
    NexusEtwPredicateHandle* predicate
);

/**
 * Set the field filter for a FIELD_MATCH predicate.
 *
 * @param predicate     Predicate handle (must be FIELD_MATCH type)
 * @param filter        Filter to apply
 * @return              NEXUS_OK on success, NEXUS_ERROR_INVALID_PARAMETER if wrong type
 */
NEXUS_API NexusResult Nexus_EtwPredicateSetFieldMatch(
    NexusEtwPredicateHandle predicate,
    const NexusEtwFilter* filter
);

/**
 * Add a child predicate to a composite predicate.
 * The child is moved into the parent and should not be destroyed separately.
 *
 * @param parent        Parent predicate (must be ANY_OF, ALL_OF, or NONE_OF)
 * @param child         Child predicate to add
 * @return              NEXUS_OK on success, NEXUS_ERROR_INVALID_PARAMETER if parent is FIELD_MATCH
 */
NEXUS_API NexusResult Nexus_EtwPredicateAddChild(
    NexusEtwPredicateHandle parent,
    NexusEtwPredicateHandle child
);

/**
 * Set the root filter predicate for the ETW session.
 * Replaces any existing simple filters. Pass NULL to clear.
 *
 * @param handle        ETW handle
 * @param predicate     Root predicate (ownership transferred to ETW session)
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetFilterPredicate(
    NexusEtwHandle handle,
    NexusEtwPredicateHandle predicate
);

/**
 * Destroy a predicate that has not been attached to an ETW session.
 * Do not call this for predicates that were passed to SetFilterPredicate or AddChild.
 *
 * @param predicate     Predicate handle to destroy
 */
NEXUS_API void Nexus_EtwDestroyPredicate(NexusEtwPredicateHandle predicate);

/* ============================================================================
 * Kernel-Level Filtering API (Phase 3 - EVENT_FILTER_DESCRIPTOR)
 *
 * Configure event ID filtering that runs in the kernel ETW subsystem.
 * Must be called BEFORE Nexus_EtwStart() - filters are applied when
 * providers are enabled and cannot be changed while tracing.
 * ============================================================================ */

/**
 * Add a kernel-level event filter for a provider.
 * This pushes filtering to the kernel, reducing callback overhead.
 *
 * @param handle        ETW handle
 * @param filter        Kernel filter configuration
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwAddKernelFilter(
    NexusEtwHandle handle,
    const NexusEtwKernelFilter* filter
);

/**
 * Clear all kernel-level event filters.
 * Must be called when trace is stopped.
 *
 * @param handle        ETW handle
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwClearKernelFilters(NexusEtwHandle handle);

/**
 * Get the number of kernel filters configured.
 *
 * @param handle        ETW handle
 * @param count         Receives filter count
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetKernelFilterCount(
    NexusEtwHandle handle,
    size_t* count
);

/* ============================================================================
 * Event Correlation API (Phase 5 - wtrace pattern)
 *
 * Correlates start/stop event pairs to track operation duration.
 * For example: File open -> operations -> File close becomes a single
 * correlated event with duration and both start/end data.
 * ============================================================================ */

/**
 * Enable event correlation for specified event types.
 * When enabled, matching start/stop events are paired and delivered
 * via the correlated callback instead of the regular callback.
 *
 * @param handle            ETW handle
 * @param correlationTypes  Bitmask of NexusEtwCorrelationType
 * @return                  NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwEnableCorrelation(
    NexusEtwHandle handle,
    uint32_t correlationTypes
);

/**
 * Set callback for correlated event delivery.
 * Called when a start/stop event pair is completed.
 *
 * @param handle        ETW handle
 * @param callback      Callback function (NULL to disable)
 * @param userContext   User pointer passed to callback
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetCorrelatedCallback(
    NexusEtwHandle handle,
    NexusEtwCorrelatedCallback callback,
    void* userContext
);

/**
 * Get correlation statistics.
 *
 * @param handle            ETW handle
 * @param pendingCount      Receives number of pending (uncompleted) operations
 * @param correlatedCount   Receives number of correlated events delivered
 * @param timedOutCount     Receives number of operations that timed out
 * @return                  NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetCorrelationStats(
    NexusEtwHandle handle,
    size_t* pendingCount,
    size_t* correlatedCount,
    size_t* timedOutCount
);

/**
 * Set correlation timeout.
 * Operations not completed within this time are discarded.
 * Default is 30 seconds.
 *
 * @param handle        ETW handle
 * @param timeoutMs     Timeout in milliseconds (0 = disable timeout)
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetCorrelationTimeout(
    NexusEtwHandle handle,
    uint32_t timeoutMs
);

/* ============================================================================
 * Schema Cache API (Phase 1 - krabsetw pattern)
 * ============================================================================ */

/**
 * Clear the TDH schema cache.
 * Useful when monitoring process changes or to free memory.
 *
 * @param handle        ETW handle
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwClearSchemaCache(NexusEtwHandle handle);

/**
 * Get the current schema cache size.
 *
 * @param handle        ETW handle
 * @param size          Receives cache entry count
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwGetSchemaCacheSize(
    NexusEtwHandle handle,
    size_t* size
);

/* ============================================================================
 * Process Name Cache API (Phase 2 - sealighter pattern)
 * ============================================================================ */

/**
 * Invalidate process name cache entry.
 * Call when a process exits to prevent stale data.
 *
 * @param handle        ETW handle
 * @param pid           Process ID to invalidate (0 = clear entire cache)
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwInvalidateProcessCache(
    NexusEtwHandle handle,
    uint32_t pid
);

/**
 * Resolve a process ID to its name.
 * Uses the internal cache with TTL-based expiration.
 *
 * @param handle        ETW handle
 * @param pid           Process ID to resolve
 * @param processName   Buffer to receive process name
 * @param bufferSize    Size of buffer in characters
 * @return              NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if process doesn't exist
 */
NEXUS_API NexusResult Nexus_EtwResolveProcessName(
    NexusEtwHandle handle,
    uint32_t pid,
    wchar_t* processName,
    size_t bufferSize
);

/* ============================================================================
 * JSON Configuration (Phase 6 - wtrace pattern)
 * ============================================================================ */

typedef struct NexusEtwJsonConfig {
    uint32_t pretty;            /* 0 = compact, 1 = pretty-printed */
    uint32_t includeTypes;      /* Include property type information */
    uint32_t includeRaw;        /* Include raw hex data */
    uint32_t unicodeEscape;     /* Escape non-ASCII as \uXXXX */
    uint32_t includeStack;      /* Include stack trace in output */
    uint32_t includeProcess;    /* Include process name */
    uint32_t reserved[2];
} NexusEtwJsonConfig;

/* ============================================================================
 * Rundown Configuration (Phase 6 - wtrace pattern)
 *
 * Rundown captures baseline state at trace start, providing information
 * about already-loaded modules, open files, and active connections.
 * ============================================================================ */

typedef struct NexusEtwRundownConfig {
    uint32_t enabled;           /* Enable rundown capture */
    uint32_t timeoutMs;         /* Max wait time for rundown (default: 3000) */
    uint32_t flags;             /* Rundown flags (reserved) */
    uint32_t reserved;
} NexusEtwRundownConfig;

/* ============================================================================
 * JSON Serialization API
 * ============================================================================ */

/**
 * Convert an ETW event to JSON format.
 * Useful for logging, external tool integration, or ElasticSearch export.
 *
 * @param event         Event to serialize
 * @param jsonBuffer    Buffer to receive JSON string
 * @param bufferSize    Size of buffer in bytes
 * @param bytesWritten  Receives actual bytes written (including null terminator)
 * @return              NEXUS_OK on success, NEXUS_ERROR_BUFFER_TOO_SMALL if buffer insufficient
 */
NEXUS_API NexusResult Nexus_EtwEventToJson(
    const NexusEtwEvent* event,
    char* jsonBuffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Get the required buffer size for JSON serialization.
 *
 * @param event         Event to serialize
 * @param sizeNeeded    Receives required buffer size
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwEventJsonSize(
    const NexusEtwEvent* event,
    size_t* sizeNeeded
);

/**
 * Convert an ETW event to JSON with custom configuration.
 *
 * @param event         Event to serialize
 * @param config        JSON configuration (NULL for defaults)
 * @param jsonBuffer    Buffer to receive JSON string
 * @param bufferSize    Size of buffer in bytes
 * @param bytesWritten  Receives actual bytes written
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwEventToJsonEx(
    const NexusEtwEvent* event,
    const NexusEtwJsonConfig* config,
    char* jsonBuffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Set the JSON configuration for the ETW session.
 *
 * @param handle        ETW handle
 * @param config        JSON configuration
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetJsonConfig(
    NexusEtwHandle handle,
    const NexusEtwJsonConfig* config
);

/**
 * Configure rundown session for capturing baseline state.
 * Must be called before Nexus_EtwStart().
 *
 * @param handle        ETW handle
 * @param config        Rundown configuration
 * @return              NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EtwSetRundownConfig(
    NexusEtwHandle handle,
    const NexusEtwRundownConfig* config
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_ETW_H */
