/**
 * @file value.cpp
 * @brief Value parsing, formatting, type-size lookup, and batch read/write operations.
 *
 * Centralises all value-handling logic in the engine DLL so that the UI
 * and other consumers share a single, consistent implementation:
 *   - Nexus_ParseValue: string-to-NexusScanValue conversion for all types
 *   - Nexus_FormatValue: value-to-display-string with hex/signed/scientific modes
 *   - Nexus_GetTypeSize: byte size for a NexusScanValueType
 *   - Nexus_CalculateFloatTolerance: CE-compatible decimal-place tolerance
 *   - Nexus_BatchReadValues / Nexus_BatchWriteFrozen: efficient multi-address I/O
 */

#include "nexus_api.h"

#include <Windows.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <cmath>

/* Forward declaration of internal handle structure (must match process.cpp) */
struct NexusProcessHandleData {
    uint32_t magic;              /* Validation magic number */
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;  /* What was originally requested */
    NexusProcessAccess actualAccess;     /* What was actually granted */
};

/* ============================================================================
 * Type Size Helper
 * ============================================================================ */

NEXUS_API size_t Nexus_GetTypeSize(uint32_t valueType) {
    switch (static_cast<NexusScanValueType>(valueType)) {
        case NEXUS_SCAN_BYTE:   return 1;
        case NEXUS_SCAN_INT16:  return 2;
        case NEXUS_SCAN_INT32:  return 4;
        case NEXUS_SCAN_INT64:  return 8;
        case NEXUS_SCAN_FLOAT:  return 4;
        case NEXUS_SCAN_DOUBLE: return 8;
        case NEXUS_SCAN_STRING:
        case NEXUS_SCAN_WSTRING:
        case NEXUS_SCAN_AOB:
        case NEXUS_SCAN_ALL:
        default:
            return 0;  /* Variable length */
    }
}

/* ============================================================================
 * Float Tolerance Calculation (CE-compatible)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_CalculateFloatTolerance(
    const char* text,
    double* tolerance
) {
    if (!text || !tolerance) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Find decimal point */
    const char* decPoint = strchr(text, '.');
    if (!decPoint) {
        /* No decimal point - exact match (small tolerance for float imprecision) */
        *tolerance = 0.0;
        return NEXUS_OK;
    }

    /* Count digits after decimal point */
    int decimalPlaces = 0;
    const char* p = decPoint + 1;
    while (*p >= '0' && *p <= '9') {
        decimalPlaces++;
        p++;
    }

    if (decimalPlaces == 0) {
        *tolerance = 0.0;
    } else {
        /* CE-style: tolerance = 0.5 * 10^(-decimalPlaces)
         * e.g., "1.5" (1 decimal) -> tolerance = 0.05
         *       "1.50" (2 decimals) -> tolerance = 0.005
         */
        *tolerance = 0.5 * pow(10.0, -decimalPlaces);
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Value Parsing
 * ============================================================================ */

/* Helper: Parse hex string to bytes with wildcards */
static bool ParseAobPattern(const char* text, NexusScanValue* result) {
    result->aobVal.length = 0;
    memset(result->aobVal.bytes, 0, sizeof(result->aobVal.bytes));
    memset(result->aobVal.mask, 0, sizeof(result->aobVal.mask));

    const char* p = text;
    while (*p && result->aobVal.length < sizeof(result->aobVal.bytes)) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        /* Check for wildcard */
        if (*p == '?' || *p == '*') {
            result->aobVal.bytes[result->aobVal.length] = 0x00;
            result->aobVal.mask[result->aobVal.length] = 0x00;  /* Wildcard */
            result->aobVal.length++;
            p++;
            if (*p == '?' || *p == '*') p++;  /* Skip second ? in ?? */
            continue;
        }

        /* Parse hex byte */
        if (!isxdigit(*p)) {
            return false;
        }

        char hexByte[3] = { *p, 0, 0 };
        p++;
        if (isxdigit(*p)) {
            hexByte[1] = *p;
            p++;
        }

        result->aobVal.bytes[result->aobVal.length] = (uint8_t)strtoul(hexByte, nullptr, 16);
        result->aobVal.mask[result->aobVal.length] = 0xFF;  /* Exact match */
        result->aobVal.length++;
    }

    return result->aobVal.length > 0;
}

NEXUS_API NexusResult Nexus_ParseValue(
    const char* text,
    uint32_t valueType,
    int isHex,
    NexusScanValue* result
) {
    if (!text || !result) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(result, 0, sizeof(NexusScanValue));

    char* endPtr = nullptr;

    switch (static_cast<NexusScanValueType>(valueType)) {
        case NEXUS_SCAN_BYTE: {
            long val = strtol(text, &endPtr, isHex ? 16 : 10);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            if (val < -128 || val > 255) return NEXUS_ERROR_INVALID_PARAMETER;
            result->byteVal = static_cast<uint8_t>(val);
            break;
        }

        case NEXUS_SCAN_INT16: {
            long val = strtol(text, &endPtr, isHex ? 16 : 10);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            if (val < -32768 || val > 65535) return NEXUS_ERROR_INVALID_PARAMETER;
            result->int16Val = static_cast<int16_t>(val);
            break;
        }

        case NEXUS_SCAN_INT32: {
            long long val = strtoll(text, &endPtr, isHex ? 16 : 10);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            result->int32Val = static_cast<int32_t>(val);
            break;
        }

        case NEXUS_SCAN_INT64: {
            long long val = strtoll(text, &endPtr, isHex ? 16 : 10);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            result->int64Val = val;
            break;
        }

        case NEXUS_SCAN_FLOAT: {
            double val = strtod(text, &endPtr);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            result->floatVal = static_cast<float>(val);
            break;
        }

        case NEXUS_SCAN_DOUBLE: {
            double val = strtod(text, &endPtr);
            if (endPtr == text) return NEXUS_ERROR_INVALID_PARAMETER;
            result->doubleVal = val;
            break;
        }

        case NEXUS_SCAN_STRING: {
            size_t len = strlen(text);
            if (len >= sizeof(result->stringVal.data)) {
                len = sizeof(result->stringVal.data) - 1;
            }
            memcpy(result->stringVal.data, text, len);
            result->stringVal.data[len] = '\0';
            result->stringVal.length = len;
            break;
        }

        case NEXUS_SCAN_WSTRING: {
            /* Convert to wide string */
            size_t len = strlen(text);
            if (len >= sizeof(result->stringVal.data)) {
                len = sizeof(result->stringVal.data) - 1;
            }
            memcpy(result->stringVal.data, text, len);
            result->stringVal.data[len] = '\0';
            result->stringVal.length = len;
            break;
        }

        case NEXUS_SCAN_AOB: {
            if (!ParseAobPattern(text, result)) {
                return NEXUS_ERROR_INVALID_PARAMETER;
            }
            break;
        }

        default:
            return NEXUS_ERROR_INVALID_PARAMETER;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Value Formatting
 * ============================================================================ */

NEXUS_API NexusResult Nexus_FormatValue(
    const void* value,
    uint32_t valueType,
    uint32_t displayFlags,
    char* buffer,
    size_t bufferSize
) {
    if (!value || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    buffer[0] = '\0';
    bool hex = (displayFlags & NEXUS_FORMAT_HEX) != 0;
    bool isSigned = (displayFlags & NEXUS_FORMAT_SIGNED) != 0;

    switch (static_cast<NexusScanValueType>(valueType)) {
        case NEXUS_SCAN_BYTE: {
            uint8_t v = *static_cast<const uint8_t*>(value);
            if (hex) {
                snprintf(buffer, bufferSize, "%02X", v);
            } else if (isSigned) {
                snprintf(buffer, bufferSize, "%d", static_cast<int8_t>(v));
            } else {
                snprintf(buffer, bufferSize, "%u", v);
            }
            break;
        }

        case NEXUS_SCAN_INT16: {
            int16_t v = *static_cast<const int16_t*>(value);
            if (hex) {
                snprintf(buffer, bufferSize, "%04X", static_cast<uint16_t>(v));
            } else if (isSigned) {
                snprintf(buffer, bufferSize, "%d", v);
            } else {
                snprintf(buffer, bufferSize, "%u", static_cast<uint16_t>(v));
            }
            break;
        }

        case NEXUS_SCAN_INT32: {
            int32_t v = *static_cast<const int32_t*>(value);
            if (hex) {
                snprintf(buffer, bufferSize, "%08X", static_cast<uint32_t>(v));
            } else if (isSigned) {
                snprintf(buffer, bufferSize, "%d", v);
            } else {
                snprintf(buffer, bufferSize, "%u", static_cast<uint32_t>(v));
            }
            break;
        }

        case NEXUS_SCAN_INT64: {
            int64_t v = *static_cast<const int64_t*>(value);
            if (hex) {
                snprintf(buffer, bufferSize, "%016llX", static_cast<uint64_t>(v));
            } else if (isSigned) {
                snprintf(buffer, bufferSize, "%lld", v);
            } else {
                snprintf(buffer, bufferSize, "%llu", static_cast<uint64_t>(v));
            }
            break;
        }

        case NEXUS_SCAN_FLOAT: {
            float v = *static_cast<const float*>(value);
            if (displayFlags & NEXUS_FORMAT_SCIENTIFIC) {
                snprintf(buffer, bufferSize, "%e", v);
            } else if (displayFlags & NEXUS_FORMAT_TRUNCATE) {
                snprintf(buffer, bufferSize, "%.2f", v);
            } else {
                snprintf(buffer, bufferSize, "%g", v);
            }
            break;
        }

        case NEXUS_SCAN_DOUBLE: {
            double v = *static_cast<const double*>(value);
            if (displayFlags & NEXUS_FORMAT_SCIENTIFIC) {
                snprintf(buffer, bufferSize, "%e", v);
            } else if (displayFlags & NEXUS_FORMAT_TRUNCATE) {
                snprintf(buffer, bufferSize, "%.4f", v);
            } else {
                snprintf(buffer, bufferSize, "%g", v);
            }
            break;
        }

        case NEXUS_SCAN_STRING: {
            const char* str = static_cast<const char*>(value);
            snprintf(buffer, bufferSize, "%s", str);
            break;
        }

        case NEXUS_SCAN_WSTRING: {
            const wchar_t* wstr = static_cast<const wchar_t*>(value);
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer, (int)bufferSize, nullptr, nullptr);
            break;
        }

        case NEXUS_SCAN_AOB: {
            /* Format as hex bytes */
            const uint8_t* bytes = static_cast<const uint8_t*>(value);
            size_t pos = 0;
            for (size_t i = 0; i < 16 && pos < bufferSize - 3; i++) {
                if (i > 0 && pos < bufferSize - 4) {
                    buffer[pos++] = ' ';
                }
                snprintf(buffer + pos, bufferSize - pos, "%02X", bytes[i]);
                pos += 2;
            }
            break;
        }

        default:
            return NEXUS_ERROR_INVALID_PARAMETER;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Batch Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_BatchReadValues(
    NexusProcessHandle handle,
    const NexusBatchEntry* entries,
    size_t count,
    NexusBatchReadResult* results
) {
    if (!handle || !entries || !results || count == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t successCount = 0;

    for (size_t i = 0; i < count; i++) {
        const NexusBatchEntry* entry = &entries[i];
        NexusBatchReadResult* result = &results[i];

        memset(result, 0, sizeof(NexusBatchReadResult));

        /* Resolve pointer if needed */
        uint64_t finalAddress = entry->baseAddress;
        if (entry->offsetCount > 0) {
            NexusResult res = Nexus_ResolvePointer(
                handle,
                entry->baseAddress,
                entry->offsets,
                entry->offsetCount,
                &finalAddress
            );
            if (res != NEXUS_OK) {
                result->success = 0;
                continue;
            }
        }

        result->resolvedAddress = finalAddress;

        /* Determine size to read */
        size_t typeSize = Nexus_GetTypeSize(entry->valueType);
        if (typeSize == 0) {
            typeSize = 16;  /* Default for variable types */
        }
        result->valueSize = (uint32_t)typeSize;

        /* Read the value */
        size_t bytesRead = 0;
        NexusResult res = Nexus_ReadMemory(
            handle,
            finalAddress,
            result->value,
            typeSize,
            &bytesRead
        );

        if (res == NEXUS_OK || res == NEXUS_ERROR_PARTIAL_READ) {
            result->success = 1;
            successCount++;
        } else {
            result->success = 0;
        }
    }

    if (successCount == count) {
        return NEXUS_OK;
    } else if (successCount > 0) {
        return NEXUS_ERROR_PARTIAL_READ;
    } else {
        return NEXUS_ERROR_ACCESS_DENIED;
    }
}

NEXUS_API NexusResult Nexus_BatchWriteFrozen(
    NexusProcessHandle handle,
    const NexusBatchEntry* entries,
    size_t count,
    size_t* successCount
) {
    if (!handle || !entries || count == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t writeCount = 0;
    size_t frozenCount = 0;

    for (size_t i = 0; i < count; i++) {
        const NexusBatchEntry* entry = &entries[i];

        /* Skip non-frozen entries */
        if (!entry->isFrozen) {
            continue;
        }
        frozenCount++;

        /* Resolve pointer if needed */
        uint64_t finalAddress = entry->baseAddress;
        if (entry->offsetCount > 0) {
            NexusResult res = Nexus_ResolvePointer(
                handle,
                entry->baseAddress,
                entry->offsets,
                entry->offsetCount,
                &finalAddress
            );
            if (res != NEXUS_OK) {
                continue;
            }
        }

        /* Determine size to write */
        size_t typeSize = Nexus_GetTypeSize(entry->valueType);
        if (typeSize == 0) {
            typeSize = 8;  /* Default */
        }

        /* Write the frozen value */
        size_t bytesWritten = 0;
        NexusResult res = Nexus_WriteMemory(
            handle,
            finalAddress,
            entry->frozenValue,
            typeSize,
            &bytesWritten
        );

        if (res == NEXUS_OK) {
            writeCount++;
        }
    }

    if (successCount) {
        *successCount = writeCount;
    }

    if (frozenCount == 0) {
        return NEXUS_OK;  /* Nothing to write */
    } else if (writeCount == frozenCount) {
        return NEXUS_OK;
    } else if (writeCount > 0) {
        return NEXUS_ERROR_PARTIAL_WRITE;
    } else {
        return NEXUS_ERROR_ACCESS_DENIED;
    }
}
