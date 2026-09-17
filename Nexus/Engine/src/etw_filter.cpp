/**
 * @file etw_filter.cpp
 * @brief ETW event filtering: predicate evaluation, composition, and correlation.
 *
 * Evaluates user-defined filter predicates against incoming ETW events,
 * supports AND/OR/NOT composition, kernel-level pre-filtering hints,
 * and event-correlation rules for linking related events.
 */

#include "etw_internal.h"

/* ============================================================================
 * Filter Evaluation
 * ============================================================================ */

static bool evaluateFilter(const NexusEtwFilter& filter, const NexusEtwEvent* event, const wchar_t* processName) {
    switch ((NexusEtwFilterField)filter.field) {
    case NEXUS_ETW_FIELD_PID:
        switch ((NexusEtwFilterOp)filter.operation) {
        case NEXUS_ETW_FILTER_OP_EQUALS: return event->processId == filter.value.numericValue;
        case NEXUS_ETW_FILTER_OP_NOT_EQUALS: return event->processId != filter.value.numericValue;
        case NEXUS_ETW_FILTER_OP_GREATER: return event->processId > filter.value.numericValue;
        case NEXUS_ETW_FILTER_OP_LESS: return event->processId < filter.value.numericValue;
        default: return false;
        }

    case NEXUS_ETW_FIELD_CATEGORY:
        switch ((NexusEtwFilterOp)filter.operation) {
        case NEXUS_ETW_FILTER_OP_EQUALS: return event->category == filter.value.numericValue;
        case NEXUS_ETW_FILTER_OP_NOT_EQUALS: return event->category != filter.value.numericValue;
        default: return false;
        }

    case NEXUS_ETW_FIELD_OPERATION:
        switch ((NexusEtwFilterOp)filter.operation) {
        case NEXUS_ETW_FILTER_OP_EQUALS: return event->operation == filter.value.numericValue;
        case NEXUS_ETW_FILTER_OP_NOT_EQUALS: return event->operation != filter.value.numericValue;
        default: return false;
        }

    case NEXUS_ETW_FIELD_PATH:
        switch ((NexusEtwFilterOp)filter.operation) {
        case NEXUS_ETW_FILTER_OP_EQUALS: return _wcsicmp(event->path, filter.value.stringValue) == 0;
        case NEXUS_ETW_FILTER_OP_NOT_EQUALS: return _wcsicmp(event->path, filter.value.stringValue) != 0;
        case NEXUS_ETW_FILTER_OP_CONTAINS: return wcsstr(event->path, filter.value.stringValue) != nullptr;
        case NEXUS_ETW_FILTER_OP_STARTS_WITH: return wcsncmp(event->path, filter.value.stringValue, wcslen(filter.value.stringValue)) == 0;
        case NEXUS_ETW_FILTER_OP_ENDS_WITH: {
            size_t pathLen = wcslen(event->path);
            size_t filterLen = wcslen(filter.value.stringValue);
            if (pathLen >= filterLen) {
                return wcscmp(event->path + pathLen - filterLen, filter.value.stringValue) == 0;
            }
            return false;
        }
        default: return false;
        }

    case NEXUS_ETW_FIELD_PNAME:
        if (processName) {
            switch ((NexusEtwFilterOp)filter.operation) {
            case NEXUS_ETW_FILTER_OP_EQUALS: return _wcsicmp(processName, filter.value.stringValue) == 0;
            case NEXUS_ETW_FILTER_OP_NOT_EQUALS: return _wcsicmp(processName, filter.value.stringValue) != 0;
            case NEXUS_ETW_FILTER_OP_CONTAINS: return wcsstr(processName, filter.value.stringValue) != nullptr;
            default: return false;
            }
        }
        return false;

    default:
        return true; /* Unknown field - pass through */
    }
}

bool passesFilters(NexusEtw* etw, const NexusEtwEvent* event, const wchar_t* processName) {
    std::lock_guard<std::mutex> lock(etw->filterMutex);

    /* Phase 4: Use composed predicate if set */
    if (etw->rootPredicate) {
        return etw->rootPredicate->evaluate(event, processName);
    }

    /* Backward compatibility: use simple filters */
    if (etw->filters.empty()) return true;

    /* Group filters by field for OR logic within same field */
    std::unordered_map<uint32_t, bool> fieldResults;

    for (const auto& filter : etw->filters) {
        bool result = evaluateFilter(filter, event, processName);
        auto it = fieldResults.find(filter.field);
        if (it == fieldResults.end()) {
            fieldResults[filter.field] = result;
        } else {
            /* OR logic for same field */
            fieldResults[filter.field] = it->second || result;
        }
    }

    /* AND logic across different fields */
    for (const auto& pair : fieldResults) {
        if (!pair.second) return false;
    }

    return true;
}

/* ============================================================================
 * PredicateNode::evaluate() - out-of-line member function definition
 * ============================================================================ */

bool PredicateNode::evaluate(const NexusEtwEvent* event, const wchar_t* processName) const {
    switch (type) {
    case NEXUS_ETW_PRED_FIELD_MATCH:
        return evaluateFilter(fieldFilter, event, processName);
    case NEXUS_ETW_PRED_ANY_OF:
        if (children.empty()) return true;
        for (const auto& child : children) {
            if (child->evaluate(event, processName)) return true;
        }
        return false;
    case NEXUS_ETW_PRED_ALL_OF:
        for (const auto& child : children) {
            if (!child->evaluate(event, processName)) return false;
        }
        return true;
    case NEXUS_ETW_PRED_NONE_OF:
        for (const auto& child : children) {
            if (child->evaluate(event, processName)) return false;
        }
        return true;
    default:
        return true;
    }
}

extern "C" {

/* ============================================================================
 * Filtering API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwAddFilter(NexusEtwHandle handle, const NexusEtwFilter* filter) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !filter) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->filterMutex);
    etw->filters.push_back(*filter);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwClearFilters(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->filterMutex);
    etw->filters.clear();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetFilterCount(NexusEtwHandle handle, size_t* count) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->filterMutex);
    *count = etw->filters.size();
    return NEXUS_OK;
}

/* ============================================================================
 * Predicate Composition API Implementation (Phase 4)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwCreatePredicate(uint32_t type, NexusEtwPredicateHandle* predicate) {
    if (!predicate) return NEXUS_ERROR_INVALID_PARAMETER;
    if (type > NEXUS_ETW_PRED_NONE_OF) return NEXUS_ERROR_INVALID_PARAMETER;

    auto node = new (std::nothrow) PredicateNode(static_cast<NexusEtwPredicateType>(type));
    if (!node) return NEXUS_ERROR_OUT_OF_MEMORY;

    *predicate = node;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwPredicateSetFieldMatch(NexusEtwPredicateHandle predicate, const NexusEtwFilter* filter) {
    if (!predicate || !filter) return NEXUS_ERROR_INVALID_PARAMETER;

    PredicateNode* node = static_cast<PredicateNode*>(predicate);
    if (node->type != NEXUS_ETW_PRED_FIELD_MATCH) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    node->fieldFilter = *filter;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwPredicateAddChild(NexusEtwPredicateHandle parent, NexusEtwPredicateHandle child) {
    if (!parent || !child) return NEXUS_ERROR_INVALID_PARAMETER;

    PredicateNode* parentNode = static_cast<PredicateNode*>(parent);
    PredicateNode* childNode = static_cast<PredicateNode*>(child);

    /* Only composite types can have children */
    if (parentNode->type == NEXUS_ETW_PRED_FIELD_MATCH) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Take ownership of child */
    parentNode->children.push_back(std::unique_ptr<PredicateNode>(childNode));
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetFilterPredicate(NexusEtwHandle handle, NexusEtwPredicateHandle predicate) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    std::lock_guard<std::mutex> lock(etw->filterMutex);

    /* Clear simple filters when setting predicate */
    etw->filters.clear();

    /* Take ownership (predicate can be NULL to clear) */
    etw->rootPredicate.reset(static_cast<PredicateNode*>(predicate));
    return NEXUS_OK;
}

NEXUS_API void Nexus_EtwDestroyPredicate(NexusEtwPredicateHandle predicate) {
    if (predicate) {
        delete static_cast<PredicateNode*>(predicate);
    }
}

/* ============================================================================
 * Kernel-Level Filter API Implementation (Phase 3)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwAddKernelFilter(NexusEtwHandle handle, const NexusEtwKernelFilter* filter) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !filter) return NEXUS_ERROR_INVALID_PARAMETER;

    /* Cannot modify kernel filters while tracing */
    if (etw->running) return NEXUS_ERROR_INVALID_STATE;

    KernelFilterConfig config;
    memcpy(&config.providerId, filter->providerId, sizeof(GUID));
    config.level = filter->level;
    config.matchAnyKeyword = filter->matchAnyKeyword;

    /* Copy event ID lists */
    if (filter->eventIds && filter->eventIdCount > 0) {
        config.eventIds.assign(filter->eventIds, filter->eventIds + filter->eventIdCount);
    }
    if (filter->excludeIds && filter->excludeIdCount > 0) {
        config.excludeIds.assign(filter->excludeIds, filter->excludeIds + filter->excludeIdCount);
    }

    std::lock_guard<std::mutex> lock(etw->kernelFilterMutex);

    /* Check if filter for this provider already exists - update it */
    for (auto& existing : etw->kernelFilters) {
        if (IsEqualGUID(existing.providerId, config.providerId)) {
            existing = std::move(config);
            return NEXUS_OK;
        }
    }

    /* Add new filter */
    etw->kernelFilters.push_back(std::move(config));
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwClearKernelFilters(NexusEtwHandle handle) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    /* Cannot modify kernel filters while tracing */
    if (etw->running) return NEXUS_ERROR_INVALID_STATE;

    std::lock_guard<std::mutex> lock(etw->kernelFilterMutex);
    etw->kernelFilters.clear();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetKernelFilterCount(NexusEtwHandle handle, size_t* count) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    std::lock_guard<std::mutex> lock(etw->kernelFilterMutex);
    *count = etw->kernelFilters.size();
    return NEXUS_OK;
}

/* ============================================================================
 * Event Correlation API Implementation (Phase 5)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwEnableCorrelation(NexusEtwHandle handle, uint32_t correlationTypes) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    etw->enabledCorrelationTypes = correlationTypes;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetCorrelatedCallback(NexusEtwHandle handle, NexusEtwCorrelatedCallback callback, void* userContext) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    etw->correlationCallbackCtx.callback = callback;
    etw->correlationCallbackCtx.userContext = userContext;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwGetCorrelationStats(NexusEtwHandle handle, size_t* pendingCount, size_t* correlatedCount, size_t* timedOutCount) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    if (pendingCount) {
        std::lock_guard<std::mutex> lock(etw->correlationMutex);
        *pendingCount = etw->pendingOperations.size();
    }
    if (correlatedCount) {
        *correlatedCount = (size_t)etw->correlatedEvents.load();
    }
    if (timedOutCount) {
        *timedOutCount = (size_t)etw->timedOutCorrelations.load();
    }
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetCorrelationTimeout(NexusEtwHandle handle, uint32_t timeoutMs) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw) return NEXUS_ERROR_INVALID_HANDLE;

    etw->correlationTimeoutMs = timeoutMs;
    return NEXUS_OK;
}

} /* extern "C" */
