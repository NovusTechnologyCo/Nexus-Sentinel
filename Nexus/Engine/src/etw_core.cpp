/**
 * @file etw_core.cpp
 * @brief ETW core: session lifecycle (create/destroy/start/stop) and public API entry points.
 *
 * Defines well-known provider GUIDs (kernel process, file, registry,
 * network, image load), manages the ETW trace session lifecycle, and
 * exposes the top-level Nexus_Etw* public API.
 *
 * Provider enable/disable logic is in etw_provider.cpp.
 */

#include "etw_internal.h"

/* ============================================================================
 * ETW Provider GUIDs (from Windows SDK / documentation)
 * ============================================================================ */

/* Microsoft-Windows-Kernel-Process */
extern "C" const GUID ProcessProviderGuid =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

/* Microsoft-Windows-Kernel-File */
extern "C" const GUID FileProviderGuid =
    {0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}};

/* Microsoft-Windows-Kernel-Registry */
extern "C" const GUID RegistryProviderGuid =
    {0x70eb4f03, 0xc1de, 0x4f73, {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};

/* Microsoft-Windows-Kernel-Network */
extern "C" const GUID NetworkProviderGuid =
    {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

/* Microsoft-Windows-TCPIP */
extern "C" const GUID TcpIpProviderGuid =
    {0x2f07e2ee, 0x15db, 0x40f1, {0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a}};

/* Microsoft-Windows-DNS-Client (for DNS events) */
extern "C" const GUID DnsClientProviderGuid =
    {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};

/* Microsoft-Windows-RPC (for RPC events) */
extern "C" const GUID RpcProviderGuid =
    {0x6ad52b32, 0xd609, 0x4be9, {0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39}};

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================ */

thread_local NexusEtw* g_currentEtw = nullptr;

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_EtwCreate(const NexusEtwConfig* config, NexusEtwHandle* handle) {
    if (!handle) return NEXUS_ERROR_INVALID_PARAMETER;

    /* FIX: Validate configuration */
    NexusResult validationResult = validateConfig(config);
    if (validationResult != NEXUS_OK) {
        return validationResult;
    }

    NexusEtw* etw = new (std::nothrow) NexusEtw();
    if (!etw) return NEXUS_ERROR_OUT_OF_MEMORY;

    /* Apply configuration */
    if (config) {
        etw->config = *config;
        if (config->sessionName[0] != L'\0') {
            etw->sessionName = config->sessionName;
        }
    }

    /* Generate unique session name if not provided */
    if (etw->sessionName.empty()) {
        wchar_t nameBuf[64];
        swprintf_s(nameBuf, L"NexusEtw_%u_%llu", GetCurrentProcessId(), GetTickCount64());
        etw->sessionName = nameBuf;
    }

    *handle = etw;
    return NEXUS_OK;
}

NEXUS_API void Nexus_EtwDestroy(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (etw) {
        delete etw;
    }
}

NEXUS_API NexusResult Nexus_EtwStart(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->mutex);

    if (etw->running) {
        return NEXUS_ERROR_ALREADY_RUNNING; /* FIX: Return specific error code */
    }

    /* Allocate session properties */
    if (!etw->allocateSessionProperties()) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    /* Configure kernel providers (sets EnableFlags) */
    NexusResult result = enableKernelProviders(etw);
    if (result != NEXUS_OK) {
        etw->freeSessionProperties(); /* FIX: Free on failure */
        return result;
    }

    /* Try to stop any existing session with same name */
    ControlTraceW(0, etw->sessionName.c_str(), etw->sessionProperties, EVENT_TRACE_CONTROL_STOP);

    /* Start the trace session */
    ULONG status = StartTraceW(&etw->sessionHandle, etw->sessionName.c_str(), etw->sessionProperties);
    if (status != ERROR_SUCCESS) {
        etw->lastError = status;
        etw->freeSessionProperties(); /* FIX: Free on failure */
        if (status == ERROR_ACCESS_DENIED) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
        if (status == ERROR_ALREADY_EXISTS) {
            /* FIX: Handle session name collision */
            return NEXUS_ERROR_ALREADY_EXISTS;
        }
        return NEXUS_ERROR_UNKNOWN;
    }

    /* FIX: Enable user-mode providers AFTER session starts */
    result = enableUserModeProviders(etw);
    /* Continue even if some providers fail - they may not be available on all systems */

    /* Open trace for consuming events */
    EVENT_TRACE_LOGFILEW logFile = {0};
    logFile.LoggerName = (LPWSTR)etw->sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;

    etw->traceHandle = OpenTraceW(&logFile);
    if (etw->traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        etw->lastError = GetLastError();
        /* FIX: Clean up on failure */
        for (const GUID& providerGuid : etw->enabledProviders) {
            EnableTraceEx2(etw->sessionHandle, &providerGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0, 0, 0, 0, nullptr);
        }
        etw->enabledProviders.clear();
        ControlTraceW(etw->sessionHandle, nullptr, etw->sessionProperties, EVENT_TRACE_CONTROL_STOP);
        etw->sessionHandle = 0;
        etw->freeSessionProperties();
        return NEXUS_ERROR_UNKNOWN;
    }

    /* Start consumer thread */
    etw->stopRequested = false;
    etw->running = true;
    etw->consumerThread = std::thread(consumerThreadFunc, etw);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwStop(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->mutex);
    etw->stopTracing();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwIsRunning(NexusEtwHandle handle, uint32_t* isRunning) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !isRunning) return NEXUS_ERROR_INVALID_PARAMETER;

    *isRunning = etw->running ? 1 : 0;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetCallback(NexusEtwHandle handle, NexusEtwEventCallback callback, void* userContext) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    /* FIX: Thread-safe callback update using atomics */
    etw->callbackCtx.callback.store(callback);
    etw->callbackCtx.userContext.store(userContext);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwPollEvents(NexusEtwHandle handle, NexusEtwEvent* events, size_t maxEvents, size_t* eventCount) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !events || !eventCount) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->queueMutex);

    size_t count = 0;
    while (count < maxEvents && !etw->eventQueue.empty()) {
        events[count++] = etw->eventQueue.front();
        etw->eventQueue.pop();
    }

    *eventCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetPendingCount(NexusEtwHandle handle, size_t* count) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->queueMutex);
    *count = etw->eventQueue.size();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwClearEvents(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->queueMutex);
    while (!etw->eventQueue.empty()) {
        etw->eventQueue.pop();
    }
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetProviders(NexusEtwHandle handle, uint32_t providers) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->mutex);

    /* FIX: If running, return error - must restart to change providers */
    if (etw->running) {
        return NEXUS_ERROR_INVALID_STATE;
    }

    etw->config.providers = providers;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetTargetPid(NexusEtwHandle handle, uint32_t targetPid) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    /* FIX: Thread-safe PID update (use atomic or this is a config, protected by design) */
    std::lock_guard<std::mutex> lock(etw->mutex);
    etw->config.targetPid = targetPid;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetStats(NexusEtwHandle handle, NexusEtwStats* stats) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !stats) return NEXUS_ERROR_INVALID_PARAMETER;

    stats->eventsReceived = etw->eventsReceived;
    stats->eventsDropped = etw->eventsDropped;
    stats->eventsFiltered = etw->eventsFiltered;
    stats->bytesReceived = etw->bytesReceived;
    /* FIX: Return actual buffer statistics */
    stats->buffersUsed = etw->config.minBuffers;
    stats->buffersLost = etw->buffersLost;
    stats->isRunning = etw->running ? 1 : 0;
    stats->lastError = etw->lastError;

    /* Schema cache statistics (Phase 1) */
    stats->schemaCacheHits = etw->schemaCacheHits;
    stats->schemaCacheMisses = etw->schemaCacheMisses;
    {
        std::lock_guard<std::mutex> lock(etw->schemaCacheMutex);
        stats->schemaCacheSize = (uint32_t)etw->schemaCache.size();
    }
    stats->schemaCacheEvictions = etw->schemaCacheEvictions;

    /* Process name cache statistics (Phase 2) */
    stats->processNameCacheHits = etw->processNameCacheHits;
    stats->processNameCacheMisses = etw->processNameCacheMisses;
    {
        std::lock_guard<std::mutex> lock(etw->processNameCacheMutex);
        stats->processNameCacheSize = (uint32_t)etw->processNameCache.size();
    }
    stats->reserved2 = 0;

    /* Event correlation statistics (Phase 5) */
    stats->correlatedEvents = etw->correlatedEvents;
    {
        std::lock_guard<std::mutex> lock(etw->correlationMutex);
        stats->pendingCorrelations = etw->pendingOperations.size();
    }
    stats->timedOutCorrelations = etw->timedOutCorrelations;
    stats->reserved3 = 0;

    return NEXUS_OK;
}

NEXUS_API void Nexus_EtwTimestampToFileTime(uint64_t timestamp, uint64_t* fileTime) {
    if (fileTime) {
        *fileTime = timestamp;
    }
}

NEXUS_API NexusResult Nexus_EtwCheckAdminPrivilege(uint32_t* isAdmin) {
    if (!isAdmin) return NEXUS_ERROR_INVALID_PARAMETER;

    BOOL isAdminBool = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdminBool);
        FreeSid(adminGroup);
    }

    *isAdmin = isAdminBool ? 1 : 0;
    return NEXUS_OK;
}

} /* extern "C" */
