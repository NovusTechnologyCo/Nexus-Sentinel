/**
 * @file etw_provider.cpp
 * @brief ETW provider management: consumer thread, EnableTraceEx2, and config validation.
 *
 * Runs the real-time event consumer thread (ProcessTrace), enables
 * providers via EnableTraceEx2 with keyword/level filtering, sets up
 * kernel and user-mode provider configurations, and validates session
 * config before start.
 *
 * Session lifecycle and public API are in etw_core.cpp.
 */

#include "etw_internal.h"

/* ============================================================================
 * Consumer Thread
 * ============================================================================ */

void consumerThreadFunc(NexusEtw* etw) {
    g_currentEtw = etw;

    /* ProcessTrace blocks until the session is stopped */
    ULONG status = ProcessTrace(&etw->traceHandle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        etw->lastError = status;
    }

    g_currentEtw = nullptr;
}

/* ============================================================================
 * Enable Individual Provider via EnableTraceEx2
 * ============================================================================ */

/* Find kernel filter for a specific provider */
static const KernelFilterConfig* findKernelFilter(NexusEtw* etw, const GUID& providerGuid) {
    std::lock_guard<std::mutex> lock(etw->kernelFilterMutex);
    for (const auto& filter : etw->kernelFilters) {
        if (IsEqualGUID(filter.providerId, providerGuid)) {
            return &filter;
        }
    }
    return nullptr;
}

static NexusResult enableProvider(NexusEtw* etw, const GUID& providerGuid, UCHAR level, ULONGLONG matchAnyKeyword) {
    ENABLE_TRACE_PARAMETERS params = {0};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    /* Enable stack walking if requested */
    if (etw->config.flags & NEXUS_ETW_FLAG_STACK_WALK) {
        params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
    }

    /* Phase 3: Check for kernel-level event ID filter */
    std::vector<BYTE> filterDescBuffer;
    std::vector<EVENT_FILTER_DESCRIPTOR> filterDescs;
    const KernelFilterConfig* kernelFilter = findKernelFilter(etw, providerGuid);

    if (kernelFilter && (!kernelFilter->eventIds.empty() || !kernelFilter->excludeIds.empty())) {
        /* Build EVENT_FILTER_EVENT_ID structure for include list */
        if (!kernelFilter->eventIds.empty()) {
            /* EVENT_FILTER_EVENT_ID: BOOLEAN FilterIn + UCHAR Reserved + USHORT Count + USHORT Events[] */
            size_t filterSize = offsetof(EVENT_FILTER_EVENT_ID, Events) +
                               kernelFilter->eventIds.size() * sizeof(USHORT);
            size_t startOffset = filterDescBuffer.size();
            filterDescBuffer.resize(startOffset + filterSize);

            EVENT_FILTER_EVENT_ID* eventFilter = (EVENT_FILTER_EVENT_ID*)(filterDescBuffer.data() + startOffset);
            eventFilter->FilterIn = TRUE;  /* Include these events */
            eventFilter->Reserved = 0;
            eventFilter->Count = (USHORT)kernelFilter->eventIds.size();
            memcpy(eventFilter->Events, kernelFilter->eventIds.data(),
                   kernelFilter->eventIds.size() * sizeof(USHORT));

            EVENT_FILTER_DESCRIPTOR desc = {0};
            desc.Ptr = (ULONGLONG)eventFilter;
            desc.Size = (ULONG)filterSize;
            desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
            filterDescs.push_back(desc);
        }

        /* Build EVENT_FILTER_EVENT_ID structure for exclude list */
        if (!kernelFilter->excludeIds.empty()) {
            size_t filterSize = offsetof(EVENT_FILTER_EVENT_ID, Events) +
                               kernelFilter->excludeIds.size() * sizeof(USHORT);
            size_t startOffset = filterDescBuffer.size();
            filterDescBuffer.resize(startOffset + filterSize);

            EVENT_FILTER_EVENT_ID* eventFilter = (EVENT_FILTER_EVENT_ID*)(filterDescBuffer.data() + startOffset);
            eventFilter->FilterIn = FALSE;  /* Exclude these events */
            eventFilter->Reserved = 0;
            eventFilter->Count = (USHORT)kernelFilter->excludeIds.size();
            memcpy(eventFilter->Events, kernelFilter->excludeIds.data(),
                   kernelFilter->excludeIds.size() * sizeof(USHORT));

            EVENT_FILTER_DESCRIPTOR desc = {0};
            desc.Ptr = (ULONGLONG)eventFilter;
            desc.Size = (ULONG)filterSize;
            desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
            filterDescs.push_back(desc);
        }

        /* Apply filter descriptors */
        if (!filterDescs.empty()) {
            params.FilterDescCount = (ULONG)filterDescs.size();
            params.EnableFilterDesc = filterDescs.data();
        }

        /* Use filter-specified level and keywords if provided */
        if (kernelFilter->level > 0) {
            level = kernelFilter->level;
        }
        if (kernelFilter->matchAnyKeyword != 0) {
            matchAnyKeyword = kernelFilter->matchAnyKeyword;
        }
    }

    ULONG status = EnableTraceEx2(
        etw->sessionHandle,
        &providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        level,
        matchAnyKeyword,
        0,  /* matchAllKeyword */
        0,  /* timeout */
        &params
    );

    if (status != ERROR_SUCCESS) {
        etw->lastError = status;
        return NEXUS_ERROR_UNKNOWN;
    }

    /* Track enabled provider for cleanup */
    etw->enabledProviders.push_back(providerGuid);
    return NEXUS_OK;
}

/* ============================================================================
 * Enable Kernel Providers
 * ============================================================================ */

NexusResult enableKernelProviders(NexusEtw* etw) {
    /* Build enable flags for NT Kernel Logger */
    ULONG enableFlags = 0;

    if (etw->config.providers & NEXUS_ETW_PROCESS) {
        enableFlags |= EVENT_TRACE_FLAG_PROCESS;
    }
    if (etw->config.providers & NEXUS_ETW_THREAD) {
        enableFlags |= EVENT_TRACE_FLAG_THREAD;
    }
    if (etw->config.providers & NEXUS_ETW_IMAGE_LOAD) {
        enableFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;
    }
    if (etw->config.providers & NEXUS_ETW_FILE_IO) {
        enableFlags |= EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_DISK_FILE_IO;
    }
    if (etw->config.providers & NEXUS_ETW_REGISTRY) {
        enableFlags |= EVENT_TRACE_FLAG_REGISTRY;
    }
    if (etw->config.providers & NEXUS_ETW_NETWORK) {
        enableFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP;
    }
    if (etw->config.providers & NEXUS_ETW_DISK_IO) {
        enableFlags |= EVENT_TRACE_FLAG_DISK_IO;
    }
    if (etw->config.providers & NEXUS_ETW_VIRTUAL_ALLOC) {
        enableFlags |= EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
    }
    if (etw->config.providers & NEXUS_ETW_CONTEXT_SWITCH) {
        enableFlags |= EVENT_TRACE_FLAG_CSWITCH;
    }
    if (etw->config.providers & NEXUS_ETW_SYSTEM_CALL) {
        enableFlags |= EVENT_TRACE_FLAG_SYSTEMCALL;
    }
    if (etw->config.providers & NEXUS_ETW_ALPC) {
        enableFlags |= EVENT_TRACE_FLAG_ALPC;
    }

    /* Set enable flags on session properties */
    etw->sessionProperties->EnableFlags = enableFlags;

    return NEXUS_OK;
}

/* ============================================================================
 * Enable User-Mode Providers (DNS, RPC, etc.)
 * ============================================================================ */

NexusResult enableUserModeProviders(NexusEtw* etw) {
    NexusResult result = NEXUS_OK;

    /* FIX: Actually enable providers via EnableTraceEx2! */

    /* Enable DNS provider */
    if (etw->config.providers & NEXUS_ETW_DNS) {
        result = enableProvider(etw, DnsClientProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        if (result != NEXUS_OK) {
            /* DNS provider may not be available - continue anyway */
        }
    }

    /* Enable RPC provider */
    if (etw->config.providers & NEXUS_ETW_RPC) {
        result = enableProvider(etw, RpcProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        if (result != NEXUS_OK) {
            /* RPC provider may not be available - continue anyway */
        }
    }

    /* For non-kernel-logger sessions, enable kernel providers too */
    if (!(etw->config.flags & NEXUS_ETW_FLAG_USE_KERNEL_LOGGER)) {
        if (etw->config.providers & NEXUS_ETW_PROCESS) {
            enableProvider(etw, ProcessProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        }
        if (etw->config.providers & NEXUS_ETW_FILE_IO) {
            enableProvider(etw, FileProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        }
        if (etw->config.providers & NEXUS_ETW_REGISTRY) {
            enableProvider(etw, RegistryProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        }
        if (etw->config.providers & NEXUS_ETW_NETWORK) {
            enableProvider(etw, NetworkProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
            enableProvider(etw, TcpIpProviderGuid, TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF);
        }
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Configuration Validation (FIX: validate config parameters)
 * ============================================================================ */

NexusResult validateConfig(const NexusEtwConfig* config) {
    if (!config) return NEXUS_OK; /* NULL config uses defaults */

    /* Validate buffer size */
    if (config->bufferSizeKb != 0 && (config->bufferSizeKb < 4 || config->bufferSizeKb > 16384)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Validate buffer counts */
    if (config->minBuffers > config->maxBuffers && config->maxBuffers != 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Validate min buffers */
    if (config->minBuffers != 0 && config->minBuffers < 2) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    return NEXUS_OK;
}
