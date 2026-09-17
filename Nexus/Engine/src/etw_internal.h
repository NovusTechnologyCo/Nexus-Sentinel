/**
 * @file etw_internal.h
 * @brief Internal header shared by all ETW source files (etw_core, etw_event, etw_filter, etw_json, etw_parse, etw_provider).
 */

#pragma once

#define NOMINMAX
#include "nexus_api.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <vector>
#include <string>
#include <unordered_map>
#include <condition_variable>
#include <cstdio>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

/* ============================================================================
 * ETW Provider GUIDs (defined in etw_core.cpp)
 * ============================================================================ */

extern "C" const GUID ProcessProviderGuid;
extern "C" const GUID FileProviderGuid;
extern "C" const GUID RegistryProviderGuid;
extern "C" const GUID NetworkProviderGuid;
extern "C" const GUID TcpIpProviderGuid;
extern "C" const GUID DnsClientProviderGuid;
extern "C" const GUID RpcProviderGuid;

/* ============================================================================
 * Callback Context Wrapper (for thread-safe access)
 * ============================================================================ */

struct CallbackContext {
    std::atomic<NexusEtwEventCallback> callback{nullptr};
    std::atomic<void*> userContext{nullptr};
};

/* ============================================================================
 * Schema Cache Structures (Phase 1 - krabsetw pattern)
 * ============================================================================ */

/* Schema key for cache lookup */
struct SchemaKey {
    GUID providerId;
    USHORT eventId;
    UCHAR version;
    UCHAR opcode;

    bool operator==(const SchemaKey& other) const {
        return IsEqualGUID(providerId, other.providerId) &&
               eventId == other.eventId &&
               version == other.version &&
               opcode == other.opcode;
    }
};

/* Hash function for SchemaKey */
struct SchemaKeyHash {
    size_t operator()(const SchemaKey& key) const {
        /* FNV-1a style hash combining all fields */
        size_t h = 2166136261u;
        const BYTE* guidBytes = (const BYTE*)&key.providerId;
        for (int i = 0; i < sizeof(GUID); i++) {
            h ^= guidBytes[i];
            h *= 16777619u;
        }
        h ^= key.eventId;
        h *= 16777619u;
        h ^= key.version;
        h *= 16777619u;
        h ^= key.opcode;
        h *= 16777619u;
        return h;
    }
};

/* Schema cache entry - stores SUCCESS with data or FAILURE status */
struct SchemaEntry {
    enum class State { SUCCESS, FAILURE };
    State state;
    std::vector<BYTE> traceEventInfo;   /* TRACE_EVENT_INFO buffer */
    uint64_t lastAccessTime;            /* For LRU eviction */
    TDHSTATUS failureStatus;            /* Error code if FAILURE */
};

/* Process name cache entry (Phase 2) */
struct ProcessNameEntry {
    std::wstring name;
    std::wstring fullPath;
    uint64_t lookupTime;
    bool valid;
};

/* ============================================================================
 * Predicate Composition Structures (Phase 4 - sealighter pattern)
 * ============================================================================ */

/* Predicate node for composable filter expressions */
struct PredicateNode {
    NexusEtwPredicateType type;
    NexusEtwFilter fieldFilter;
    std::vector<std::unique_ptr<PredicateNode>> children;

    PredicateNode() : type(NEXUS_ETW_PRED_FIELD_MATCH) {
        memset(&fieldFilter, 0, sizeof(fieldFilter));
    }

    explicit PredicateNode(NexusEtwPredicateType t) : type(t) {
        memset(&fieldFilter, 0, sizeof(fieldFilter));
    }

    /* Recursive evaluation — defined in etw_filter.cpp */
    bool evaluate(const NexusEtwEvent* event, const wchar_t* processName) const;
};

/* ============================================================================
 * Kernel-Level Event Filter Storage (Phase 3)
 * ============================================================================ */

/* Internal storage for kernel filter configuration */
struct KernelFilterConfig {
    GUID providerId;
    std::vector<USHORT> eventIds;       /* Event IDs to include */
    std::vector<USHORT> excludeIds;     /* Event IDs to exclude */
    UCHAR level;
    ULONGLONG matchAnyKeyword;

    KernelFilterConfig() : level(0), matchAnyKeyword(0) {
        memset(&providerId, 0, sizeof(providerId));
    }
};

/* ============================================================================
 * Event Correlation Structures (Phase 5 - wtrace pattern)
 * ============================================================================ */

/* Pending operation awaiting completion event */
struct PendingOperation {
    NexusEtwEvent startEvent;
    uint64_t startTime;
    uint32_t correlationType;
    uint32_t correlationId;
};

/* Correlation key for lookup - uses IRP/FileObject for file ops, Activity ID for RPC */
struct CorrelationKey {
    uint64_t key1;          /* Primary key (e.g., IRP pointer, FileObject) */
    uint64_t key2;          /* Secondary key (e.g., thread ID for disambiguation) */
    uint32_t type;          /* Correlation type */

    bool operator==(const CorrelationKey& other) const {
        return key1 == other.key1 && key2 == other.key2 && type == other.type;
    }
};

struct CorrelationKeyHash {
    size_t operator()(const CorrelationKey& key) const {
        size_t h = 2166136261u;
        h ^= (size_t)key.key1;
        h *= 16777619u;
        h ^= (size_t)key.key2;
        h *= 16777619u;
        h ^= key.type;
        return h;
    }
};

/* Correlation callback context */
struct CorrelationCallbackContext {
    std::atomic<NexusEtwCorrelatedCallback> callback{nullptr};
    std::atomic<void*> userContext{nullptr};
};

/* ============================================================================
 * Internal Context Structure
 * ============================================================================ */

struct NexusEtw {
    std::mutex mutex;
    std::atomic<bool> running{false};
    std::atomic<bool> stopRequested{false};

    /* Configuration */
    NexusEtwConfig config;

    /* Session handles */
    TRACEHANDLE sessionHandle{0};
    TRACEHANDLE traceHandle{INVALID_PROCESSTRACE_HANDLE};
    EVENT_TRACE_PROPERTIES* sessionProperties{nullptr};

    /* Consumer thread */
    std::thread consumerThread;

    /* Thread-safe callback (FIX: race condition on callback pointer) */
    CallbackContext callbackCtx;

    /* Event queue (for polling mode) */
    std::queue<NexusEtwEvent> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    static constexpr size_t MAX_QUEUE_SIZE = 100000;

    /* Statistics */
    std::atomic<uint64_t> eventsReceived{0};
    std::atomic<uint64_t> eventsDropped{0};
    std::atomic<uint64_t> eventsFiltered{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint32_t> lastError{0};
    std::atomic<uint64_t> sequenceNumber{0};
    std::atomic<uint32_t> buffersLost{0};

    /* Session name (must be unique per system) */
    std::wstring sessionName;

    /* Enabled provider handles (for cleanup) */
    std::vector<GUID> enabledProviders;

    /* Filter predicates */
    std::vector<NexusEtwFilter> filters;
    std::mutex filterMutex;

    /* Rate limiting state */
    std::atomic<uint64_t> eventsThisSecond{0};
    std::atomic<uint64_t> lastRateLimitReset{0};

    /* Schema cache (Phase 1 - krabsetw pattern) */
    std::unordered_map<SchemaKey, SchemaEntry, SchemaKeyHash> schemaCache;
    std::mutex schemaCacheMutex;
    static constexpr size_t MAX_SCHEMA_CACHE_SIZE = 4096;
    std::atomic<uint64_t> schemaCacheHits{0};
    std::atomic<uint64_t> schemaCacheMisses{0};
    std::atomic<uint32_t> schemaCacheEvictions{0};

    /* Process name cache (Phase 2 - sealighter pattern) */
    std::unordered_map<uint32_t, ProcessNameEntry> processNameCache;
    std::mutex processNameCacheMutex;
    static constexpr size_t MAX_PROCESS_NAME_CACHE = 1024;
    static constexpr uint64_t PROCESS_CACHE_TTL_MS = 30000;
    std::atomic<uint64_t> processNameCacheHits{0};
    std::atomic<uint64_t> processNameCacheMisses{0};

    /* Predicate composition (Phase 4 - sealighter pattern) */
    std::unique_ptr<PredicateNode> rootPredicate;

    /* Kernel-level event filters (Phase 3) */
    std::vector<KernelFilterConfig> kernelFilters;
    std::mutex kernelFilterMutex;

    /* Event correlation (Phase 5 - wtrace pattern) */
    std::unordered_map<CorrelationKey, PendingOperation, CorrelationKeyHash> pendingOperations;
    std::mutex correlationMutex;
    CorrelationCallbackContext correlationCallbackCtx;
    std::atomic<uint32_t> enabledCorrelationTypes{0};
    std::atomic<uint32_t> correlationTimeoutMs{30000};
    std::atomic<uint32_t> nextCorrelationId{1};
    std::atomic<uint64_t> correlatedEvents{0};
    std::atomic<uint64_t> timedOutCorrelations{0};
    static constexpr size_t MAX_PENDING_OPERATIONS = 10000;

    /* JSON configuration (Phase 6 - wtrace pattern) */
    NexusEtwJsonConfig jsonConfig;

    /* Rundown configuration (Phase 6 - wtrace pattern) */
    NexusEtwRundownConfig rundownConfig;
    bool rundownComplete{false};

    NexusEtw() {
        /* Default configuration */
        memset(&config, 0, sizeof(config));
        config.providers = NEXUS_ETW_BASIC;
        config.targetPid = 0;
        config.bufferSizeKb = 64;
        config.minBuffers = 8;
        config.maxBuffers = 64;
        config.flushTimerMs = 1000;

        /* Default JSON configuration */
        memset(&jsonConfig, 0, sizeof(jsonConfig));
        jsonConfig.includeStack = 1;
        jsonConfig.includeProcess = 1;

        /* Default rundown configuration */
        memset(&rundownConfig, 0, sizeof(rundownConfig));
        rundownConfig.enabled = 0;
        rundownConfig.timeoutMs = 3000;
    }

    ~NexusEtw() {
        stopTracing();
        freeSessionProperties();
    }

    void freeSessionProperties() {
        if (sessionProperties) {
            free(sessionProperties);
            sessionProperties = nullptr;
        }
    }

    bool allocateSessionProperties() {
        freeSessionProperties();

        /* Calculate size: properties + session name + log file name */
        size_t sessionNameSize = (sessionName.length() + 1) * sizeof(wchar_t);
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize + sizeof(wchar_t);

        sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (!sessionProperties) return false;

        memset(sessionProperties, 0, bufferSize);
        sessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
        sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sessionProperties->Wnode.ClientContext = 1; /* QPC timestamps */
        sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sessionProperties->MinimumBuffers = config.minBuffers;
        sessionProperties->MaximumBuffers = config.maxBuffers;
        sessionProperties->BufferSize = config.bufferSizeKb;
        /* FIX: FlushTimer resolution - ensure at least 1 second */
        sessionProperties->FlushTimer = (config.flushTimerMs < 1000) ? 1 : (config.flushTimerMs / 1000);
        sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        return true;
    }

    void stopTracing() {
        stopRequested = true;

        /* Disable all enabled providers (FIX: proper cleanup) */
        for (const GUID& providerGuid : enabledProviders) {
            if (sessionHandle != 0) {
                EnableTraceEx2(sessionHandle, &providerGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0, 0, 0, 0, nullptr);
            }
        }
        enabledProviders.clear();

        /* Stop the trace session */
        if (sessionHandle != 0 && sessionProperties) {
            ControlTraceW(sessionHandle, nullptr, sessionProperties, EVENT_TRACE_CONTROL_STOP);
            sessionHandle = 0;
        }

        /* Close consumer handle */
        if (traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(traceHandle);
            traceHandle = INVALID_PROCESSTRACE_HANDLE;
        }

        /* Wait for consumer thread */
        if (consumerThread.joinable()) {
            consumerThread.join();
        }

        running = false;
        stopRequested = false;

        /* FIX: Free session properties after stop to prevent leaks */
        freeSessionProperties();
    }
};

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================ */

extern thread_local NexusEtw* g_currentEtw;

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- etw_event.cpp --- */
void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW pLogFile);

/* --- etw_provider.cpp --- */
void consumerThreadFunc(NexusEtw* etw);
NexusResult enableKernelProviders(NexusEtw* etw);
NexusResult enableUserModeProviders(NexusEtw* etw);
NexusResult validateConfig(const NexusEtwConfig* config);

/* --- etw_event.cpp --- */
TDHSTATUS getCachedSchema(NexusEtw* etw, PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* pInfoOut);

/* --- etw_parse.cpp --- */
NexusEtwEventCategory mapProviderToCategory(const GUID& providerId, USHORT eventId);
NexusEtwOperation mapEventIdToOperation(NexusEtwEventCategory category, USHORT eventId, UCHAR opcode);
void parseEventProperties(PEVENT_RECORD pEvent, NexusEtwEvent* outEvent);
void parseStackTrace(PEVENT_RECORD pEvent, NexusEtwEvent* outEvent);

/* --- etw_filter.cpp --- */
bool passesFilters(NexusEtw* etw, const NexusEtwEvent* event, const wchar_t* processName);
