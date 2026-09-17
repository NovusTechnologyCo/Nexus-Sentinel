/**
 * @file etw_json.cpp
 * @brief ETW JSON serialization: event-to-JSON conversion and configuration APIs.
 *
 * Converts parsed ETW events into JSON strings for logging, export,
 * and UI display.  Also provides name-lookup helpers for operation
 * codes and event categories, and configuration accessors.
 */

#include "etw_internal.h"

/* Helper to escape JSON strings */
static void escapeJsonString(const wchar_t* input, char* output, size_t maxLen) {
    size_t outIdx = 0;
    for (size_t i = 0; input[i] && outIdx < maxLen - 1; i++) {
        wchar_t ch = input[i];
        if (ch < 128) {
            char c = (char)ch;
            if (c == '"' || c == '\\') {
                if (outIdx < maxLen - 2) {
                    output[outIdx++] = '\\';
                    output[outIdx++] = c;
                }
            } else if (c >= 32) {
                output[outIdx++] = c;
            }
        }
        /* Skip non-ASCII for simplicity */
    }
    output[outIdx] = '\0';
}

/* Helper for extended JSON escape with unicode support */
static void escapeJsonStringEx(const wchar_t* input, char* output, size_t maxLen, bool unicodeEscape) {
    size_t outIdx = 0;
    for (size_t i = 0; input[i] && outIdx < maxLen - 8; i++) {
        wchar_t ch = input[i];
        if (ch == '"') {
            output[outIdx++] = '\\';
            output[outIdx++] = '"';
        } else if (ch == '\\') {
            output[outIdx++] = '\\';
            output[outIdx++] = '\\';
        } else if (ch == '\n') {
            output[outIdx++] = '\\';
            output[outIdx++] = 'n';
        } else if (ch == '\r') {
            output[outIdx++] = '\\';
            output[outIdx++] = 'r';
        } else if (ch == '\t') {
            output[outIdx++] = '\\';
            output[outIdx++] = 't';
        } else if (ch < 32) {
            /* Control character - escape as \uXXXX */
            int escLen = snprintf(output + outIdx, maxLen - outIdx, "\\u%04X", (unsigned int)ch);
            if (escLen > 0) outIdx += escLen;
        } else if (ch < 128) {
            /* ASCII printable */
            output[outIdx++] = (char)ch;
        } else if (unicodeEscape) {
            /* Non-ASCII - escape as \uXXXX */
            int escLen = snprintf(output + outIdx, maxLen - outIdx, "\\u%04X", (unsigned int)ch);
            if (escLen > 0) outIdx += escLen;
        } else {
            /* UTF-8 encode the character */
            if (ch < 0x800 && outIdx < maxLen - 2) {
                output[outIdx++] = (char)(0xC0 | (ch >> 6));
                output[outIdx++] = (char)(0x80 | (ch & 0x3F));
            } else if (outIdx < maxLen - 3) {
                output[outIdx++] = (char)(0xE0 | (ch >> 12));
                output[outIdx++] = (char)(0x80 | ((ch >> 6) & 0x3F));
                output[outIdx++] = (char)(0x80 | (ch & 0x3F));
            }
        }
    }
    output[outIdx] = '\0';
}

extern "C" {

NEXUS_API const char* Nexus_EtwGetOperationName(uint32_t operation) {
    switch ((NexusEtwOperation)operation) {
    case NEXUS_ETW_OP_PROCESS_START:    return "ProcessStart";
    case NEXUS_ETW_OP_PROCESS_EXIT:     return "ProcessExit";
    case NEXUS_ETW_OP_THREAD_START:     return "ThreadStart";
    case NEXUS_ETW_OP_THREAD_EXIT:      return "ThreadExit";
    case NEXUS_ETW_OP_IMAGE_LOAD:       return "ImageLoad";
    case NEXUS_ETW_OP_IMAGE_UNLOAD:     return "ImageUnload";
    case NEXUS_ETW_OP_FILE_CREATE:      return "FileCreate";
    case NEXUS_ETW_OP_FILE_READ:        return "FileRead";
    case NEXUS_ETW_OP_FILE_WRITE:       return "FileWrite";
    case NEXUS_ETW_OP_FILE_DELETE:      return "FileDelete";
    case NEXUS_ETW_OP_FILE_RENAME:      return "FileRename";
    case NEXUS_ETW_OP_FILE_CLOSE:       return "FileClose";
    case NEXUS_ETW_OP_FILE_QUERY_INFO:  return "FileQueryInfo";
    case NEXUS_ETW_OP_FILE_SET_INFO:    return "FileSetInfo";
    case NEXUS_ETW_OP_REG_OPEN:         return "RegOpen";
    case NEXUS_ETW_OP_REG_CREATE:       return "RegCreate";
    case NEXUS_ETW_OP_REG_QUERY:        return "RegQuery";
    case NEXUS_ETW_OP_REG_SET:          return "RegSet";
    case NEXUS_ETW_OP_REG_DELETE:       return "RegDelete";
    case NEXUS_ETW_OP_REG_ENUM_KEY:     return "RegEnumKey";
    case NEXUS_ETW_OP_REG_ENUM_VALUE:   return "RegEnumValue";
    case NEXUS_ETW_OP_REG_CLOSE:        return "RegClose";
    case NEXUS_ETW_OP_NET_TCP_CONNECT:  return "TcpConnect";
    case NEXUS_ETW_OP_NET_TCP_DISCONNECT: return "TcpDisconnect";
    case NEXUS_ETW_OP_NET_TCP_SEND:     return "TcpSend";
    case NEXUS_ETW_OP_NET_TCP_RECV:     return "TcpRecv";
    case NEXUS_ETW_OP_NET_TCP_ACCEPT:   return "TcpAccept";
    case NEXUS_ETW_OP_NET_UDP_SEND:     return "UdpSend";
    case NEXUS_ETW_OP_NET_UDP_RECV:     return "UdpRecv";
    case NEXUS_ETW_OP_MEM_ALLOC:        return "MemAlloc";
    case NEXUS_ETW_OP_MEM_FREE:         return "MemFree";
    case NEXUS_ETW_OP_MEM_PROTECT:      return "MemProtect";
    case NEXUS_ETW_OP_DNS_QUERY_START:  return "DnsQueryStart";
    case NEXUS_ETW_OP_DNS_QUERY_COMPLETE: return "DnsQueryComplete";
    case NEXUS_ETW_OP_RPC_CLIENT_CALL:  return "RpcClientCall";
    case NEXUS_ETW_OP_RPC_SERVER_CALL:  return "RpcServerCall";
    default:                            return "Unknown";
    }
}

NEXUS_API const char* Nexus_EtwGetCategoryName(uint32_t category) {
    switch ((NexusEtwEventCategory)category) {
    case NEXUS_ETW_CAT_PROCESS:     return "Process";
    case NEXUS_ETW_CAT_THREAD:      return "Thread";
    case NEXUS_ETW_CAT_IMAGE:       return "Image";
    case NEXUS_ETW_CAT_FILE:        return "File";
    case NEXUS_ETW_CAT_REGISTRY:    return "Registry";
    case NEXUS_ETW_CAT_NETWORK:     return "Network";
    case NEXUS_ETW_CAT_DISK:        return "Disk";
    case NEXUS_ETW_CAT_MEMORY:      return "Memory";
    case NEXUS_ETW_CAT_SYSCALL:     return "Syscall";
    case NEXUS_ETW_CAT_ALPC:        return "ALPC";
    case NEXUS_ETW_CAT_DNS:         return "DNS";
    case NEXUS_ETW_CAT_RPC:         return "RPC";
    default:                        return "Unknown";
    }
}

/* ============================================================================
 * JSON Serialization Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwEventToJson(const NexusEtwEvent* event, char* jsonBuffer, size_t bufferSize, size_t* bytesWritten) {
    if (!event || !jsonBuffer || !bytesWritten || bufferSize < 256) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    char pathEscaped[1024] = {0};
    escapeJsonString(event->path, pathEscaped, sizeof(pathEscaped));

    const char* categoryName = Nexus_EtwGetCategoryName(event->category);
    const char* operationName = Nexus_EtwGetOperationName(event->operation);

    int written = snprintf(jsonBuffer, bufferSize,
        "{"
        "\"sequenceNumber\":%llu,"
        "\"timestamp\":%llu,"
        "\"processId\":%u,"
        "\"threadId\":%u,"
        "\"category\":\"%s\","
        "\"operation\":\"%s\","
        "\"path\":\"%s\","
        "\"status\":%d",
        (unsigned long long)event->sequenceNumber,
        (unsigned long long)event->timestamp,
        event->processId,
        event->threadId,
        categoryName,
        operationName,
        pathEscaped,
        event->status
    );

    if (written < 0 || (size_t)written >= bufferSize) {
        return NEXUS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Add stack data if present */
    if (event->stack.depth > 0) {
        int stackWritten = snprintf(jsonBuffer + written, bufferSize - written,
            ",\"stack\":[");
        if (stackWritten > 0) {
            written += stackWritten;
            for (uint32_t i = 0; i < event->stack.depth && (size_t)written < bufferSize - 32; i++) {
                int addrWritten = snprintf(jsonBuffer + written, bufferSize - written,
                    "%s\"0x%llX\"",
                    i > 0 ? "," : "",
                    (unsigned long long)event->stack.addresses[i]);
                if (addrWritten > 0) written += addrWritten;
            }
            if ((size_t)written < bufferSize - 2) {
                jsonBuffer[written++] = ']';
            }
        }
    }

    /* Close JSON object */
    if ((size_t)written < bufferSize - 2) {
        jsonBuffer[written++] = '}';
        jsonBuffer[written] = '\0';
    }

    *bytesWritten = (size_t)written + 1;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwEventJsonSize(const NexusEtwEvent* event, size_t* sizeNeeded) {
    if (!event || !sizeNeeded) return NEXUS_ERROR_INVALID_PARAMETER;

    /* Estimate size: base fields + path + stack */
    *sizeNeeded = 512 + wcslen(event->path) * 2 + event->stack.depth * 20;
    return NEXUS_OK;
}

/* ============================================================================
 * JSON Configuration and Extended Serialization (Phase 6)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwEventToJsonEx(
    const NexusEtwEvent* event,
    const NexusEtwJsonConfig* config,
    char* jsonBuffer,
    size_t bufferSize,
    size_t* bytesWritten
) {
    if (!event || !jsonBuffer || !bytesWritten || bufferSize < 256) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Use defaults if no config provided */
    NexusEtwJsonConfig defaultConfig = {0};
    defaultConfig.includeStack = 1;
    defaultConfig.includeProcess = 1;
    if (!config) config = &defaultConfig;

    bool pretty = config->pretty != 0;
    bool unicodeEscape = config->unicodeEscape != 0;
    const char* nl = pretty ? "\n" : "";
    const char* indent = pretty ? "  " : "";

    char pathEscaped[2048] = {0};
    escapeJsonStringEx(event->path, pathEscaped, sizeof(pathEscaped), unicodeEscape);

    const char* categoryName = Nexus_EtwGetCategoryName(event->category);
    const char* operationName = Nexus_EtwGetOperationName(event->operation);

    int written = snprintf(jsonBuffer, bufferSize,
        "{%s"
        "%s\"sequenceNumber\": %llu,%s"
        "%s\"timestamp\": %llu,%s"
        "%s\"processId\": %u,%s"
        "%s\"threadId\": %u,%s"
        "%s\"category\": \"%s\",%s"
        "%s\"operation\": \"%s\",%s"
        "%s\"path\": \"%s\",%s"
        "%s\"status\": %d",
        nl,
        indent, (unsigned long long)event->sequenceNumber, nl,
        indent, (unsigned long long)event->timestamp, nl,
        indent, event->processId, nl,
        indent, event->threadId, nl,
        indent, categoryName, nl,
        indent, operationName, nl,
        indent, pathEscaped, nl,
        indent, event->status
    );

    if (written < 0 || (size_t)written >= bufferSize) {
        return NEXUS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Include type information if requested */
    if (config->includeTypes) {
        int typeWritten = snprintf(jsonBuffer + written, bufferSize - written,
            ",%s%s\"_types\": {%s"
            "%s%s\"sequenceNumber\": \"uint64\",%s"
            "%s%s\"timestamp\": \"uint64\",%s"
            "%s%s\"processId\": \"uint32\",%s"
            "%s%s\"threadId\": \"uint32\",%s"
            "%s%s\"status\": \"int32\"%s"
            "%s}",
            nl, indent, nl,
            indent, indent, nl,
            indent, indent, nl,
            indent, indent, nl,
            indent, indent, nl,
            indent, indent, nl,
            indent
        );
        if (typeWritten > 0) written += typeWritten;
    }

    /* Include stack trace if enabled and present */
    if (config->includeStack && event->stack.depth > 0) {
        int stackWritten = snprintf(jsonBuffer + written, bufferSize - written,
            ",%s%s\"stack\": [%s", nl, indent, pretty ? "\n" : "");
        if (stackWritten > 0) {
            written += stackWritten;
            for (uint32_t i = 0; i < event->stack.depth && (size_t)written < bufferSize - 32; i++) {
                int addrWritten;
                if (pretty) {
                    addrWritten = snprintf(jsonBuffer + written, bufferSize - written,
                        "%s%s\"0x%llX\"%s",
                        indent, indent,
                        (unsigned long long)event->stack.addresses[i],
                        i < event->stack.depth - 1 ? ",\n" : "\n");
                } else {
                    addrWritten = snprintf(jsonBuffer + written, bufferSize - written,
                        "%s\"0x%llX\"",
                        i > 0 ? "," : "",
                        (unsigned long long)event->stack.addresses[i]);
                }
                if (addrWritten > 0) written += addrWritten;
            }
            if ((size_t)written < bufferSize - 4) {
                if (pretty) {
                    written += snprintf(jsonBuffer + written, bufferSize - written, "%s]", indent);
                } else {
                    jsonBuffer[written++] = ']';
                }
            }
        }
    }

    /* Include raw hex data if enabled */
    if (config->includeRaw && event->dataSize > 0) {
        int rawWritten = snprintf(jsonBuffer + written, bufferSize - written,
            ",%s%s\"rawData\": \"", nl, indent);
        if (rawWritten > 0) {
            written += rawWritten;
            size_t maxRawBytes = (bufferSize - written - 4) / 2;
            size_t bytesToWrite = event->dataSize < maxRawBytes ? event->dataSize : maxRawBytes;
            for (size_t i = 0; i < bytesToWrite && (size_t)written < bufferSize - 4; i++) {
                int hexWritten = snprintf(jsonBuffer + written, bufferSize - written,
                    "%02X", event->data.raw[i]);
                if (hexWritten > 0) written += hexWritten;
            }
            if ((size_t)written < bufferSize - 2) {
                jsonBuffer[written++] = '"';
            }
        }
    }

    /* Close JSON object */
    if ((size_t)written < bufferSize - 4) {
        if (pretty) {
            jsonBuffer[written++] = '\n';
        }
        jsonBuffer[written++] = '}';
        jsonBuffer[written] = '\0';
    }

    *bytesWritten = (size_t)written + 1;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EtwSetJsonConfig(NexusEtwHandle handle, const NexusEtwJsonConfig* config) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !config) return NEXUS_ERROR_INVALID_PARAMETER;

    memcpy(&etw->jsonConfig, config, sizeof(NexusEtwJsonConfig));
    return NEXUS_OK;
}

/* ============================================================================
 * Rundown Session Support (Phase 6)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_EtwSetRundownConfig(NexusEtwHandle handle, const NexusEtwRundownConfig* config) {
    NexusEtw* etw = static_cast<NexusEtw*>(handle);
    if (!etw || !config) return NEXUS_ERROR_INVALID_PARAMETER;

    /* Cannot modify rundown config while tracing */
    if (etw->running) return NEXUS_ERROR_INVALID_STATE;

    memcpy(&etw->rundownConfig, config, sizeof(NexusEtwRundownConfig));
    return NEXUS_OK;
}

} /* extern "C" */
