/**
 * @file scanner_internal.h
 * @brief Internal header shared by scanner.cpp and scanner_scan.cpp.
 *
 * Defines the ScanContext structure (result storage, snapshot, scan
 * parameters) and declares helper functions for pattern parsing and
 * value comparison.
 */

#pragma once

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <atomic>
#include <string>
#include <cctype>
#include <cwctype>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/* Forward declaration of internal handle structure (must match process.cpp) */
struct NexusProcessHandleData {
    uint32_t magic;              /* Validation magic number */
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;  /* What was originally requested */
    NexusProcessAccess actualAccess;     /* What was actually granted */
};

/* Internal result storage - compact address-only for large result sets */
struct ScanResultEntry {
    uint64_t address;
    uint64_t previousValue;  /* Stored as raw bytes in uint64_t */
};

/* AOB pattern entry - nibble-based (x64dbg pattern for finer control) */
struct PatternNibble {
    uint8_t value;      /* 0-15 for data nibble */
    bool isWildcard;    /* True if this nibble is a wildcard */
};

/* AOB pattern entry - byte value with per-nibble wildcards (x64dbg pattern) */
struct AOBPatternByte {
    uint8_t value;              /* Full byte value (only meaningful if neither nibble is wildcard) */
    bool isWildcard;            /* True if entire byte is wildcard (both nibbles) */
    PatternNibble highNibble;   /* High nibble (bits 7-4) */
    PatternNibble lowNibble;    /* Low nibble (bits 3-0) */
    bool hasNibbleWildcard;     /* True if exactly one nibble is a wildcard */
};

/* Internal scan session structure */
struct NexusScanData {
    NexusProcessHandle processHandle;
    NexusValueType valueType;
    uint32_t valueSize;              /* Size in bytes for current value type */

    std::vector<ScanResultEntry> results;
    bool hasFirstScan;

    /* String/AOB pattern storage for rescans */
    std::string searchString;        /* For string searches */
    std::wstring searchWString;      /* For wide string searches */
    std::vector<AOBPatternByte> aobPattern;  /* For AOB searches */
    bool caseSensitive;

    /* Progress tracking */
    std::atomic<uint64_t> bytesScanned;
    std::atomic<uint64_t> bytesTotal;
    std::atomic<uint64_t> regionsScanned;
    std::atomic<uint64_t> regionsTotal;
    std::atomic<bool> isComplete;
    std::atomic<bool> wasCancelled;

    NexusScanData() :
        processHandle(nullptr),
        valueType(NEXUS_VALUE_INT32),
        valueSize(4),
        hasFirstScan(false),
        caseSensitive(true),
        bytesScanned(0),
        bytesTotal(0),
        regionsScanned(0),
        regionsTotal(0),
        isComplete(true),
        wasCancelled(false)
    {}
};

/* ============================================================================
 * Cross-File Function Prototypes (defined in scanner_scan.cpp)
 * ============================================================================ */

bool ParseAOBPattern(const char* pattern, size_t length, std::vector<AOBPatternByte>& result);
bool MatchAOBPattern(const uint8_t* memory, const std::vector<AOBPatternByte>& pattern);
bool CompareStrings(const char* memory, const char* pattern, size_t length, bool caseSensitive);
bool CompareWStrings(const wchar_t* memory, const wchar_t* pattern, size_t length, bool caseSensitive);
uint32_t GetValueSize(NexusValueType type);
uint32_t GetDefaultAlignment(NexusValueType type);
uint64_t ValueToUint64(const uint8_t* buffer, uint32_t size);

/* Read a value from memory buffer */
template<typename T>
static T ReadValueFromBuffer(const uint8_t* buffer) {
    T value;
    memcpy(&value, buffer, sizeof(T));
    return value;
}

/* Compare two values based on scan type */
template<typename T>
static bool CompareValues(T current, T target, T targetMax, NexusScanType scanType, T previousValue, double epsilon = 0.0) {
    switch (scanType) {
        case NEXUS_SCAN_EXACT:
            if constexpr (std::is_floating_point_v<T>) {
                if (epsilon > 0) {
                    return std::fabs(current - target) <= epsilon;
                }
            }
            return current == target;

        case NEXUS_SCAN_RANGE:
            return current >= target && current <= targetMax;

        case NEXUS_SCAN_GREATER:
            return current > target;

        case NEXUS_SCAN_LESS:
            return current < target;

        case NEXUS_SCAN_INCREASED:
            return current > previousValue;

        case NEXUS_SCAN_INCREASED_BY:
            if constexpr (std::is_floating_point_v<T>) {
                if (epsilon > 0) {
                    return std::fabs((current - previousValue) - target) <= epsilon;
                }
            }
            return (current - previousValue) == target;

        case NEXUS_SCAN_DECREASED:
            return current < previousValue;

        case NEXUS_SCAN_DECREASED_BY:
            if constexpr (std::is_floating_point_v<T>) {
                if (epsilon > 0) {
                    return std::fabs((previousValue - current) - target) <= epsilon;
                }
            }
            return (previousValue - current) == target;

        case NEXUS_SCAN_CHANGED:
            if constexpr (std::is_floating_point_v<T>) {
                if (epsilon > 0) {
                    return std::fabs(current - previousValue) > epsilon;
                }
            }
            return current != previousValue;

        case NEXUS_SCAN_UNCHANGED:
            if constexpr (std::is_floating_point_v<T>) {
                if (epsilon > 0) {
                    return std::fabs(current - previousValue) <= epsilon;
                }
            }
            return current == previousValue;

        case NEXUS_SCAN_UNKNOWN:
            return true;

        default:
            return false;
    }
}
