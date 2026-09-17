/**
 * @file etw_parse.cpp
 * @brief ETW event parsing: provider-to-category mapping, property extraction, and stack traces.
 *
 * Maps provider GUIDs to semantic categories, maps event IDs to
 * operation names, extracts typed properties from TDH metadata,
 * and captures kernel stack traces from events.
 *
 * Caches, callbacks, and the public API surface are in etw_event.cpp.
 */

#include "etw_internal.h"

/* ============================================================================
 * Event Classification
 * ============================================================================ */

NexusEtwEventCategory mapProviderToCategory(const GUID& providerId, USHORT /*eventId*/) {
    if (IsEqualGUID(providerId, ProcessProviderGuid)) {
        return NEXUS_ETW_CAT_PROCESS;
    }
    if (IsEqualGUID(providerId, FileProviderGuid)) {
        return NEXUS_ETW_CAT_FILE;
    }
    if (IsEqualGUID(providerId, RegistryProviderGuid)) {
        return NEXUS_ETW_CAT_REGISTRY;
    }
    if (IsEqualGUID(providerId, NetworkProviderGuid) ||
        IsEqualGUID(providerId, TcpIpProviderGuid)) {
        return NEXUS_ETW_CAT_NETWORK;
    }
    if (IsEqualGUID(providerId, DnsClientProviderGuid)) {
        return NEXUS_ETW_CAT_DNS;
    }
    if (IsEqualGUID(providerId, RpcProviderGuid)) {
        return NEXUS_ETW_CAT_RPC;
    }
    return NEXUS_ETW_CAT_UNKNOWN;
}

NexusEtwOperation mapEventIdToOperation(NexusEtwEventCategory category, USHORT eventId, UCHAR opcode) {
    switch (category) {
    case NEXUS_ETW_CAT_PROCESS:
        switch (opcode) {
        case 1: return NEXUS_ETW_OP_PROCESS_START;
        case 2: return NEXUS_ETW_OP_PROCESS_EXIT;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_THREAD:
        switch (opcode) {
        case 1: return NEXUS_ETW_OP_THREAD_START;
        case 2: return NEXUS_ETW_OP_THREAD_EXIT;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_FILE:
        switch (eventId) {
        case 10: /* NameCreate */
        case 12: /* Create */
            return NEXUS_ETW_OP_FILE_CREATE;
        case 15: return NEXUS_ETW_OP_FILE_READ;
        case 16: return NEXUS_ETW_OP_FILE_WRITE;
        case 14: return NEXUS_ETW_OP_FILE_CLOSE;
        case 26: return NEXUS_ETW_OP_FILE_DELETE;
        case 19: return NEXUS_ETW_OP_FILE_RENAME;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_REGISTRY:
        switch (opcode) {
        case 10: return NEXUS_ETW_OP_REG_OPEN;
        case 11: return NEXUS_ETW_OP_REG_CREATE;
        case 13: return NEXUS_ETW_OP_REG_QUERY;
        case 14: return NEXUS_ETW_OP_REG_SET;
        case 12: return NEXUS_ETW_OP_REG_DELETE;
        case 15: return NEXUS_ETW_OP_REG_ENUM_KEY;
        case 16: return NEXUS_ETW_OP_REG_ENUM_VALUE;
        case 27: return NEXUS_ETW_OP_REG_CLOSE;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_NETWORK:
        /* TCP/IP events use different event IDs */
        switch (eventId) {
        case 10: return NEXUS_ETW_OP_NET_TCP_SEND;
        case 11: return NEXUS_ETW_OP_NET_TCP_RECV;
        case 12: return NEXUS_ETW_OP_NET_TCP_CONNECT;
        case 13: return NEXUS_ETW_OP_NET_TCP_DISCONNECT;
        case 14: return NEXUS_ETW_OP_NET_TCP_ACCEPT;
        case 26: return NEXUS_ETW_OP_NET_UDP_SEND;
        case 27: return NEXUS_ETW_OP_NET_UDP_RECV;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_DNS:
        switch (eventId) {
        case 1: case 3001: return NEXUS_ETW_OP_DNS_QUERY_START;
        case 2: case 3008: return NEXUS_ETW_OP_DNS_QUERY_COMPLETE;
        default: return NEXUS_ETW_OP_OTHER;
        }

    case NEXUS_ETW_CAT_RPC:
        switch (opcode) {
        case 1: return NEXUS_ETW_OP_RPC_CLIENT_CALL;
        case 2: return NEXUS_ETW_OP_RPC_SERVER_CALL;
        default: return NEXUS_ETW_OP_OTHER;
        }

    default:
        return NEXUS_ETW_OP_OTHER;
    }
}

/* ============================================================================
 * Event Property Parsing
 * ============================================================================ */

void parseEventProperties(PEVENT_RECORD pEvent, NexusEtwEvent* outEvent) {
    /* Use cached TDH schema (Phase 1 optimization) */
    PTRACE_EVENT_INFO pInfo = nullptr;

    /* Try to get cached schema using thread-local ETW context */
    if (g_currentEtw) {
        TDHSTATUS status = getCachedSchema(g_currentEtw, pEvent, &pInfo);
        if (status != ERROR_SUCCESS || !pInfo) {
            /* Fall back to raw data if schema not available */
            if (pEvent->UserDataLength > 0 && pEvent->UserDataLength <= sizeof(outEvent->data.raw)) {
                memcpy(outEvent->data.raw, pEvent->UserData, pEvent->UserDataLength);
                outEvent->dataSize = pEvent->UserDataLength;
            }
            return;
        }
    } else {
        /* No ETW context (shouldn't happen) - fall back to raw TDH call */
        DWORD bufferSize = 0;
        TDHSTATUS status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);

        if (status != ERROR_INSUFFICIENT_BUFFER) {
            if (pEvent->UserDataLength > 0 && pEvent->UserDataLength <= sizeof(outEvent->data.raw)) {
                memcpy(outEvent->data.raw, pEvent->UserData, pEvent->UserDataLength);
                outEvent->dataSize = pEvent->UserDataLength;
            }
            return;
        }

        static thread_local std::vector<BYTE> fallbackBuffer;
        fallbackBuffer.resize(bufferSize);
        pInfo = (PTRACE_EVENT_INFO)fallbackBuffer.data();

        status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
        if (status != ERROR_SUCCESS) {
            if (pEvent->UserDataLength > 0 && pEvent->UserDataLength <= sizeof(outEvent->data.raw)) {
                memcpy(outEvent->data.raw, pEvent->UserData, pEvent->UserDataLength);
                outEvent->dataSize = pEvent->UserDataLength;
            }
            return;
        }
    }

    /* Parse properties based on event type */
    TDHSTATUS propStatus;
    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO& propInfo = pInfo->EventPropertyInfoArray[i];
        LPCWSTR propName = (LPCWSTR)((BYTE*)pInfo + propInfo.NameOffset);

        /* Extract property value */
        PROPERTY_DATA_DESCRIPTOR dataDesc;
        dataDesc.PropertyName = (ULONGLONG)propName;
        dataDesc.ArrayIndex = ULONG_MAX;

        DWORD propSize = 0;
        propStatus = TdhGetPropertySize(pEvent, 0, nullptr, 1, &dataDesc, &propSize);
        if (propStatus != ERROR_SUCCESS || propSize == 0) continue;

        std::vector<BYTE> propData(propSize);
        propStatus = TdhGetProperty(pEvent, 0, nullptr, 1, &dataDesc, propSize, propData.data());
        if (propStatus != ERROR_SUCCESS) continue;

        /* Map common properties to our event structure */
        if (_wcsicmp(propName, L"FileName") == 0 ||
            _wcsicmp(propName, L"OpenPath") == 0 ||
            _wcsicmp(propName, L"KeyName") == 0 ||
            _wcsicmp(propName, L"ImageFileName") == 0) {
            wcsncpy_s(outEvent->path, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        else if (_wcsicmp(propName, L"ImageBase") == 0 && propSize >= sizeof(uint64_t)) {
            outEvent->data.image.imageBase = *(uint64_t*)propData.data();
        }
        else if (_wcsicmp(propName, L"ImageSize") == 0 && propSize >= sizeof(uint64_t)) {
            outEvent->data.image.imageSize = *(uint64_t*)propData.data();
        }
        else if (_wcsicmp(propName, L"ParentId") == 0 && propSize >= sizeof(uint32_t)) {
            outEvent->data.process.parentPid = *(uint32_t*)propData.data();
        }
        else if (_wcsicmp(propName, L"CommandLine") == 0) {
            wcsncpy_s(outEvent->data.process.commandLine, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        /* DNS-specific properties */
        else if (_wcsicmp(propName, L"QueryName") == 0) {
            wcsncpy_s(outEvent->data.dns.queryName, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        else if (_wcsicmp(propName, L"QueryType") == 0 && propSize >= sizeof(uint32_t)) {
            outEvent->data.dns.queryType = *(uint32_t*)propData.data();
        }
        else if (_wcsicmp(propName, L"QueryStatus") == 0 && propSize >= sizeof(uint32_t)) {
            outEvent->data.dns.queryStatus = *(uint32_t*)propData.data();
        }
        else if (_wcsicmp(propName, L"QueryResults") == 0) {
            wcsncpy_s(outEvent->data.dns.queryResult, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        /* RPC-specific properties */
        else if (_wcsicmp(propName, L"InterfaceUuid") == 0 || _wcsicmp(propName, L"Interface") == 0) {
            wcsncpy_s(outEvent->data.rpc.interfaceName, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        else if (_wcsicmp(propName, L"ProcNum") == 0 || _wcsicmp(propName, L"Procedure") == 0) {
            wcsncpy_s(outEvent->data.rpc.procedureName, (LPCWSTR)propData.data(), _TRUNCATE);
        }
        else if (_wcsicmp(propName, L"Endpoint") == 0) {
            wcsncpy_s(outEvent->data.rpc.endpoint, (LPCWSTR)propData.data(), _TRUNCATE);
        }
    }
}

/* ============================================================================
 * Stack Trace Parsing
 * ============================================================================ */

/* Parse stack trace from extended data */
void parseStackTrace(PEVENT_RECORD pEvent, NexusEtwEvent* outEvent) {
    for (USHORT i = 0; i < pEvent->ExtendedDataCount; i++) {
        EVENT_HEADER_EXTENDED_DATA_ITEM* item = &pEvent->ExtendedData[i];
        if (item->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            /* 64-bit stack trace */
            PEVENT_EXTENDED_ITEM_STACK_TRACE64 stack =
                (PEVENT_EXTENDED_ITEM_STACK_TRACE64)item->DataPtr;
            size_t count = (item->DataSize - sizeof(ULONG64)) / sizeof(ULONG64);
            if (count > 32) count = 32;
            for (size_t j = 0; j < count; j++) {
                outEvent->stack.addresses[j] = stack->Address[j];
            }
            outEvent->stack.depth = (uint32_t)count;
            break;
        }
        else if (item->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            /* 32-bit stack trace */
            PEVENT_EXTENDED_ITEM_STACK_TRACE32 stack =
                (PEVENT_EXTENDED_ITEM_STACK_TRACE32)item->DataPtr;
            size_t count = (item->DataSize - sizeof(ULONG64)) / sizeof(ULONG);
            if (count > 32) count = 32;
            for (size_t j = 0; j < count; j++) {
                outEvent->stack.addresses[j] = stack->Address[j];
            }
            outEvent->stack.depth = (uint32_t)count;
            break;
        }
    }
}
