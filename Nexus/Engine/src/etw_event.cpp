/**
 * @file etw_event.cpp
 * @brief ETW event processing: schema cache, process-name cache, and ETW callbacks.
 *
 * Caches TDH event schemas for fast property lookup, maintains a PID-to-
 * process-name cache, and implements the EventRecordCallback that receives
 * raw EVENT_RECORD buffers from the consumer thread.
 *
 * Event parsing and classification are in etw_parse.cpp.
 */

#include "etw_internal.h"

/* ============================================================================
 * Schema Cache Functions (Phase 1)
 * ============================================================================ */

/**
 * TDH schema cache with LRU eviction.
 *
 * Caches both successes AND failures (krabsetw pattern).
 *
 * @param etw       ETW context
 * @param pEvent    Event record
 * @param pInfoOut  Receives pointer to cached TRACE_EVENT_INFO (or nullptr)
 * @return          TDH status code
 */
TDHSTATUS getCachedSchema(NexusEtw* etw, PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* pInfoOut) {
    *pInfoOut = nullptr;

    /* Build cache key from event header */
    SchemaKey key;
    key.providerId = pEvent->EventHeader.ProviderId;
    key.eventId = pEvent->EventHeader.EventDescriptor.Id;
    key.version = pEvent->EventHeader.EventDescriptor.Version;
    key.opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    uint64_t now = GetTickCount64();

    /* Check cache first */
    {
        std::lock_guard<std::mutex> lock(etw->schemaCacheMutex);
        auto it = etw->schemaCache.find(key);
        if (it != etw->schemaCache.end()) {
            /* Cache hit */
            it->second.lastAccessTime = now;
            etw->schemaCacheHits++;

            if (it->second.state == SchemaEntry::State::FAILURE) {
                /* Cached failure - return the error code */
                return it->second.failureStatus;
            }

            /* Cached success - return pointer to data */
            *pInfoOut = (PTRACE_EVENT_INFO)it->second.traceEventInfo.data();
            return ERROR_SUCCESS;
        }
    }

    /* Cache miss - fetch from TDH */
    etw->schemaCacheMisses++;

    DWORD bufferSize = 0;
    TDHSTATUS status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);

    SchemaEntry entry;
    entry.lastAccessTime = now;

    if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0) {
        /* Allocate and fetch schema */
        entry.traceEventInfo.resize(bufferSize);
        PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)entry.traceEventInfo.data();

        status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
        if (status == ERROR_SUCCESS) {
            entry.state = SchemaEntry::State::SUCCESS;
            entry.failureStatus = ERROR_SUCCESS;
        } else {
            /* Second call failed - cache as failure */
            entry.state = SchemaEntry::State::FAILURE;
            entry.failureStatus = status;
            entry.traceEventInfo.clear();
        }
    } else {
        /* Initial call failed (not just buffer too small) - cache as failure */
        entry.state = SchemaEntry::State::FAILURE;
        entry.failureStatus = (status != ERROR_SUCCESS) ? status : ERROR_NOT_FOUND;
    }

    /* Store in cache (with eviction if needed) */
    {
        std::lock_guard<std::mutex> lock(etw->schemaCacheMutex);

        /* Evict oldest entries if cache is full */
        while (etw->schemaCache.size() >= NexusEtw::MAX_SCHEMA_CACHE_SIZE) {
            /* Find oldest entry */
            auto oldest = etw->schemaCache.begin();
            uint64_t oldestTime = oldest->second.lastAccessTime;
            for (auto it = etw->schemaCache.begin(); it != etw->schemaCache.end(); ++it) {
                if (it->second.lastAccessTime < oldestTime) {
                    oldest = it;
                    oldestTime = it->second.lastAccessTime;
                }
            }
            etw->schemaCache.erase(oldest);
            etw->schemaCacheEvictions++;
        }

        /* Insert new entry */
        auto result = etw->schemaCache.emplace(key, std::move(entry));

        if (result.first->second.state == SchemaEntry::State::SUCCESS) {
            *pInfoOut = (PTRACE_EVENT_INFO)result.first->second.traceEventInfo.data();
            return ERROR_SUCCESS;
        } else {
            return result.first->second.failureStatus;
        }
    }
}

/* ============================================================================
 * Process Name Cache Functions (Phase 2)
 * ============================================================================ */

/**
 * Resolve process ID to process name with caching.
 *
 * @param etw   ETW context
 * @param pid   Process ID to resolve
 * @return      Pointer to cached process name (or nullptr if not found)
 */
static const wchar_t* resolveProcessNameCached(NexusEtw* etw, uint32_t pid) {
    if (pid == 0) return L"System Idle Process";
    if (pid == 4) return L"System";

    uint64_t now = GetTickCount64();

    /* Check cache first */
    {
        std::lock_guard<std::mutex> lock(etw->processNameCacheMutex);
        auto it = etw->processNameCache.find(pid);
        if (it != etw->processNameCache.end()) {
            /* Check TTL */
            if ((now - it->second.lookupTime) < NexusEtw::PROCESS_CACHE_TTL_MS) {
                etw->processNameCacheHits++;
                return it->second.valid ? it->second.name.c_str() : nullptr;
            }
            /* Entry expired - remove it */
            etw->processNameCache.erase(it);
        }
    }

    /* Cache miss - resolve from system */
    etw->processNameCacheMisses++;

    ProcessNameEntry entry;
    entry.lookupTime = now;
    entry.valid = false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t pathBuffer[MAX_PATH];
        DWORD pathLen = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &pathLen)) {
            entry.fullPath = pathBuffer;
            /* Extract filename from path */
            const wchar_t* lastSlash = wcsrchr(pathBuffer, L'\\');
            entry.name = lastSlash ? (lastSlash + 1) : pathBuffer;
            entry.valid = true;
        }
        CloseHandle(hProcess);
    }

    /* Store in cache */
    {
        std::lock_guard<std::mutex> lock(etw->processNameCacheMutex);

        /* Evict oldest if full */
        while (etw->processNameCache.size() >= NexusEtw::MAX_PROCESS_NAME_CACHE) {
            auto oldest = etw->processNameCache.begin();
            uint64_t oldestTime = oldest->second.lookupTime;
            for (auto it = etw->processNameCache.begin(); it != etw->processNameCache.end(); ++it) {
                if (it->second.lookupTime < oldestTime) {
                    oldest = it;
                    oldestTime = it->second.lookupTime;
                }
            }
            etw->processNameCache.erase(oldest);
        }

        auto result = etw->processNameCache.emplace(pid, std::move(entry));
        return result.first->second.valid ? result.first->second.name.c_str() : nullptr;
    }
}

/* ============================================================================
 * ETW Event Callback (called from ProcessTrace)
 * ============================================================================ */

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    NexusEtw* etw = g_currentEtw;
    if (!etw || etw->stopRequested) return;

    /* Rate limiting (FIX: implement maxEventsPerSecond) */
    if (etw->config.maxEventsPerSecond > 0) {
        uint64_t now = GetTickCount64();
        uint64_t lastReset = etw->lastRateLimitReset.load();
        if (now - lastReset >= 1000) {
            etw->eventsThisSecond = 0;
            etw->lastRateLimitReset = now;
        }
        if (etw->eventsThisSecond >= etw->config.maxEventsPerSecond) {
            etw->eventsFiltered++;
            return;
        }
        etw->eventsThisSecond++;
    }

    /* Filter by PID if configured (legacy filter - still supported) */
    if (etw->config.targetPid != 0 && pEvent->EventHeader.ProcessId != etw->config.targetPid) {
        etw->eventsFiltered++;
        return;
    }

    /* Map event to our structures */
    NexusEtwEvent event;
    memset(&event, 0, sizeof(event));

    event.sequenceNumber = ++etw->sequenceNumber;
    event.timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
    event.processId = pEvent->EventHeader.ProcessId;
    event.threadId = pEvent->EventHeader.ThreadId;

    /* Resolve and cache process name (Phase 2) */
    const wchar_t* processName = resolveProcessNameCached(etw, event.processId);
    if (processName) {
        wcsncpy_s(event.processName, processName, _TRUNCATE);
    } else {
        event.processName[0] = L'\0';
    }

    /* Determine category and operation */
    event.category = (uint32_t)mapProviderToCategory(pEvent->EventHeader.ProviderId, pEvent->EventHeader.EventDescriptor.Id);
    event.operation = (uint32_t)mapEventIdToOperation((NexusEtwEventCategory)event.category,
        pEvent->EventHeader.EventDescriptor.Id,
        pEvent->EventHeader.EventDescriptor.Opcode);

    /* Parse event-specific properties */
    parseEventProperties(pEvent, &event);

    /* Parse stack trace if available */
    if (etw->config.flags & NEXUS_ETW_FLAG_STACK_WALK) {
        parseStackTrace(pEvent, &event);
    }

    /* Apply predicate filters (FIX: advanced filtering with process name) */
    if (!passesFilters(etw, &event, processName)) {
        etw->eventsFiltered++;
        return;
    }

    etw->eventsReceived++;
    etw->bytesReceived += pEvent->UserDataLength;

    /* FIX: Thread-safe callback access using atomics */
    NexusEtwEventCallback callback = etw->callbackCtx.callback.load();
    void* userContext = etw->callbackCtx.userContext.load();

    /* Deliver via callback or queue */
    if (callback) {
        callback(&event, userContext);
    }
    else {
        std::lock_guard<std::mutex> lock(etw->queueMutex);
        if (etw->eventQueue.size() < NexusEtw::MAX_QUEUE_SIZE) {
            etw->eventQueue.push(event);
            etw->queueCondition.notify_one();
        }
        else {
            etw->eventsDropped++;
        }
    }
}

ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW pLogFile) {
    NexusEtw* etw = g_currentEtw;
    if (!etw || etw->stopRequested) return FALSE;

    /* Note: Buffer statistics are available via QueryTrace at session level,
       not in the logfile callback structure. We track drops in the event callback. */
    (void)pLogFile;

    return TRUE; /* Continue processing */
}

/* ============================================================================
 * Schema Cache API (Phase 1)
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_EtwClearSchemaCache(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->schemaCacheMutex);
    etw->schemaCache.clear();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetSchemaCacheSize(NexusEtwHandle handle, size_t* size) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !size) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->schemaCacheMutex);
    *size = etw->schemaCache.size();
    return NEXUS_OK;
}

/* ============================================================================
 * Process Name Cache API (Phase 2)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwInvalidateProcessCache(NexusEtwHandle handle, uint32_t pid) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->processNameCacheMutex);
    if (pid == 0) {
        /* Clear entire cache */
        etw->processNameCache.clear();
    } else {
        /* Remove specific entry */
        etw->processNameCache.erase(pid);
    }
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwResolveProcessName(
    NexusEtwHandle handle,
    uint32_t pid,
    wchar_t* processName,
    size_t bufferSize
) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !processName || bufferSize == 0) return NEXUS_ERROR_INVALID_PARAMETER;

    const wchar_t* name = resolveProcessNameCached(etw, pid);
    if (!name) {
        processName[0] = L'\0';
        return NEXUS_ERROR_NOT_FOUND;
    }

    wcsncpy_s(processName, bufferSize, name, _TRUNCATE);
    return NEXUS_OK;
}

} /* extern "C" */
