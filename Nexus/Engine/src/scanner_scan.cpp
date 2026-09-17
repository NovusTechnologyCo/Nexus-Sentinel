/**
 * @file scanner_scan.cpp
 * @brief Scanner helpers: AOB pattern parsing, string comparison, and value matching.
 *
 * Parses hex/wildcard AOB pattern strings (supporting nibble-level
 * wildcards like "4? 8B"), implements value-type-aware comparison
 * functions for all scan modes, and provides the core region-scan
 * loop used by Nexus_ScanFirst and Nexus_ScanNext.
 */

#include "scanner_internal.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Parse hex character to value (returns -1 if invalid) */
static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/**
 * Parse AOB pattern string with nibble-level wildcard support (x64dbg pattern).
 * Supports:
 *   - "48 8B ?? 90" - full byte wildcards
 *   - "4? 8B ?0 90" - nibble-level wildcards
 *   - "488B??90" or "4?8B?090" - no spaces
 *   - "* " - single wildcard byte (alternative syntax)
 */
bool ParseAOBPattern(const char* pattern, size_t length, std::vector<AOBPatternByte>& result) {
    result.clear();

    /* First pass: validate pattern isn't all wildcards */
    bool hasNonWildcard = false;
    for (size_t i = 0; i < length; i++) {
        if (HexCharToValue(pattern[i]) >= 0) {
            hasNonWildcard = true;
            break;
        }
    }
    if (!hasNonWildcard) {
        return false; /* Reject all-wildcard patterns (x64dbg pattern) */
    }

    size_t i = 0;
    while (i < length) {
        /* Skip whitespace */
        while (i < length && (pattern[i] == ' ' || pattern[i] == '\t')) {
            i++;
        }
        if (i >= length) break;

        /* Check for single wildcard character representing full byte */
        if (pattern[i] == '*') {
            AOBPatternByte pb = {};
            pb.value = 0;
            pb.isWildcard = true;
            pb.hasNibbleWildcard = false;
            pb.highNibble.isWildcard = true;
            pb.lowNibble.isWildcard = true;
            result.push_back(pb);
            i++;
            continue;
        }

        /* Parse first character (high nibble) */
        bool highIsWildcard = (pattern[i] == '?');
        int highValue = highIsWildcard ? 0 : HexCharToValue(pattern[i]);
        if (!highIsWildcard && highValue < 0) {
            return false; /* Invalid character */
        }
        i++;

        if (i >= length) {
            return false; /* Incomplete byte */
        }

        /* Parse second character (low nibble) */
        bool lowIsWildcard = (pattern[i] == '?');
        int lowValue = lowIsWildcard ? 0 : HexCharToValue(pattern[i]);
        if (!lowIsWildcard && lowValue < 0) {
            return false; /* Invalid character */
        }
        i++;

        /* Build the pattern byte with nibble info */
        AOBPatternByte pb = {};

        pb.highNibble.value = static_cast<uint8_t>(highValue);
        pb.highNibble.isWildcard = highIsWildcard;

        pb.lowNibble.value = static_cast<uint8_t>(lowValue);
        pb.lowNibble.isWildcard = lowIsWildcard;

        /* Compute full byte value and wildcard status */
        if (highIsWildcard && lowIsWildcard) {
            pb.isWildcard = true;
            pb.hasNibbleWildcard = false;
            pb.value = 0;
        } else if (highIsWildcard || lowIsWildcard) {
            pb.isWildcard = false;
            pb.hasNibbleWildcard = true;
            pb.value = static_cast<uint8_t>((highValue << 4) | lowValue);
        } else {
            pb.isWildcard = false;
            pb.hasNibbleWildcard = false;
            pb.value = static_cast<uint8_t>((highValue << 4) | lowValue);
        }

        result.push_back(pb);
    }

    return !result.empty();
}

/**
 * Match a single byte against pattern byte with nibble-level wildcard support.
 */
static bool MatchPatternByte(uint8_t byte, const AOBPatternByte& pattern) {
    /* Full byte wildcard - always matches */
    if (pattern.isWildcard) {
        return true;
    }

    /* No wildcards - exact match */
    if (!pattern.hasNibbleWildcard) {
        return byte == pattern.value;
    }

    /* Nibble-level matching */
    uint8_t highNibble = (byte >> 4) & 0x0F;
    uint8_t lowNibble = byte & 0x0F;

    if (!pattern.highNibble.isWildcard && highNibble != pattern.highNibble.value) {
        return false;
    }
    if (!pattern.lowNibble.isWildcard && lowNibble != pattern.lowNibble.value) {
        return false;
    }

    return true;
}

/* Compare memory against AOB pattern with nibble-level wildcard support */
bool MatchAOBPattern(const uint8_t* memory, const std::vector<AOBPatternByte>& pattern) {
    for (size_t i = 0; i < pattern.size(); i++) {
        if (!MatchPatternByte(memory[i], pattern[i])) {
            return false;
        }
    }
    return true;
}

/* Case-insensitive character comparison */
static bool CharsEqualIgnoreCase(char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

static bool WCharsEqualIgnoreCase(wchar_t a, wchar_t b) {
    return std::towlower(a) == std::towlower(b);
}

/* Compare strings with optional case sensitivity */
bool CompareStrings(const char* memory, const char* pattern, size_t length, bool caseSensitive) {
    if (caseSensitive) {
        return std::memcmp(memory, pattern, length) == 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (!CharsEqualIgnoreCase(memory[i], pattern[i])) {
            return false;
        }
    }
    return true;
}

bool CompareWStrings(const wchar_t* memory, const wchar_t* pattern, size_t length, bool caseSensitive) {
    if (caseSensitive) {
        return std::wmemcmp(memory, pattern, length) == 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (!WCharsEqualIgnoreCase(memory[i], pattern[i])) {
            return false;
        }
    }
    return true;
}

uint32_t GetValueSize(NexusValueType type) {
    switch (type) {
        case NEXUS_VALUE_INT8:    return 1;
        case NEXUS_VALUE_INT16:   return 2;
        case NEXUS_VALUE_INT32:   return 4;
        case NEXUS_VALUE_INT64:   return 8;
        case NEXUS_VALUE_FLOAT32: return 4;
        case NEXUS_VALUE_FLOAT64: return 8;
        default:                  return 4;
    }
}

uint32_t GetDefaultAlignment(NexusValueType type) {
    switch (type) {
        case NEXUS_VALUE_INT8:    return 1;
        case NEXUS_VALUE_INT16:   return 2;
        case NEXUS_VALUE_INT32:   return 4;
        case NEXUS_VALUE_INT64:   return 4;  /* Often 4-byte aligned even for 64-bit */
        case NEXUS_VALUE_FLOAT32: return 4;
        case NEXUS_VALUE_FLOAT64: return 4;
        default:                  return 1;
    }
}

/* Store value as uint64_t for result storage */
uint64_t ValueToUint64(const uint8_t* buffer, uint32_t size) {
    uint64_t result = 0;
    memcpy(&result, buffer, (size <= 8) ? size : 8);
    return result;
}
