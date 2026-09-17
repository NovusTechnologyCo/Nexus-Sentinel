/**
 * @file signature_scan.cpp
 * @brief Signature scanning: pattern parsing, matching, and memory-region scan loop.
 *
 * Parses hex/wildcard pattern strings into byte + mask arrays, performs
 * byte-level pattern matching with wildcard support, resolves module
 * base addresses, and iterates over process memory regions to find
 * all occurrences of a given pattern.
 */

#include "signature_internal.h"

/* ============================================================================
 * Pattern Parsing
 * ============================================================================ */

static bool ParseHexByte(const char* str, uint8_t& value) {
    if (!str || !str[0]) return false;

    char* end;
    unsigned long val = strtoul(str, &end, 16);
    if (end == str || val > 0xFF) return false;

    value = static_cast<uint8_t>(val);
    return true;
}

bool ParsePatternInternal(const std::string& pattern, ParsedPattern& result) {
    result.bytes.clear();
    result.mask.clear();

    std::string token;
    std::istringstream stream(pattern);

    while (stream >> token) {
        /* Skip commas and spaces */
        if (token == "," || token.empty()) continue;

        /* Handle wildcards: ??, ?, *, xx, XX */
        if (token == "??" || token == "?" || token == "*" ||
            token == "xx" || token == "XX" || token == "x" || token == "X") {
            result.bytes.push_back(0x00);
            result.mask.push_back(0x00);  /* Wildcard */
        }
        /* Handle hex bytes */
        else if (token.length() == 2) {
            uint8_t byte;
            if (!ParseHexByte(token.c_str(), byte)) {
                return false;  /* Invalid hex */
            }
            result.bytes.push_back(byte);
            result.mask.push_back(0xFF);  /* Exact match */
        }
        /* Handle single hex digit (e.g., "F" = "0F") */
        else if (token.length() == 1 && std::isxdigit(token[0])) {
            uint8_t byte;
            std::string padded = "0" + token;
            if (!ParseHexByte(padded.c_str(), byte)) {
                return false;
            }
            result.bytes.push_back(byte);
            result.mask.push_back(0xFF);
        }
        else {
            return false;  /* Invalid token */
        }
    }

    return !result.bytes.empty();
}

/* ============================================================================
 * Pattern Matching
 * ============================================================================ */

bool MatchPattern(const uint8_t* data, size_t dataSize,
                  const ParsedPattern& pattern, size_t offset) {
    if (offset + pattern.bytes.size() > dataSize) return false;

    for (size_t i = 0; i < pattern.bytes.size(); i++) {
        if (pattern.mask[i] != 0x00) {  /* Not a wildcard */
            if (data[offset + i] != pattern.bytes[i]) {
                return false;
            }
        }
    }

    return true;
}

std::vector<size_t> FindAllMatches(const uint8_t* data, size_t dataSize,
                                    const ParsedPattern& pattern,
                                    bool firstOnly) {
    std::vector<size_t> matches;

    if (pattern.bytes.empty() || dataSize < pattern.bytes.size()) {
        return matches;
    }

    size_t maxOffset = dataSize - pattern.bytes.size();

    for (size_t i = 0; i <= maxOffset; i++) {
        if (MatchPattern(data, dataSize, pattern, i)) {
            matches.push_back(i);
            if (firstOnly) break;
        }
    }

    return matches;
}

/* ============================================================================
 * Module Helpers
 * ============================================================================ */

void CacheModules(SignatureContext* ctx) {
    if (ctx->modulesCached) return;

    size_t count = 0;
    Nexus_EnumerateModules(ctx->process, nullptr, 0, &count);

    if (count > 0) {
        ctx->modules.resize(count);
        Nexus_EnumerateModules(ctx->process, ctx->modules.data(), count, &count);
        ctx->modules.resize(count);
    }

    ctx->modulesCached = true;
}

const NexusModuleInfo* FindModule(SignatureContext* ctx, const char* name) {
    CacheModules(ctx);

    if (!name || name[0] == '\0') return nullptr;

    /* Convert to wide string for comparison */
    wchar_t wideName[64];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wideName, 64);

    for (const auto& mod : ctx->modules) {
        if (_wcsicmp(mod.name, wideName) == 0) {
            return &mod;
        }
        /* Also check path */
        if (wcsstr(mod.path, wideName) != nullptr) {
            return &mod;
        }
    }

    return nullptr;
}

const NexusModuleInfo* FindModuleByAddress(SignatureContext* ctx, uint64_t address) {
    CacheModules(ctx);

    for (const auto& mod : ctx->modules) {
        if (address >= mod.baseAddress && address < mod.baseAddress + mod.size) {
            return &mod;
        }
    }

    return nullptr;
}

/* ============================================================================
 * Scanning
 * ============================================================================ */

void ScanModule(SignatureContext* ctx, SignatureEntry& sig,
                const NexusModuleInfo* mod, bool firstOnly) {
    if (ctx->scanCancelled) return;

    /* Read entire module */
    std::vector<uint8_t> buffer(mod->size);
    size_t bytesRead = 0;

    NexusResult result = Nexus_ReadMemory(ctx->process, mod->baseAddress,
                                           buffer.data(), buffer.size(), &bytesRead);

    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        return;
    }

    buffer.resize(bytesRead);
    ctx->bytesScanned += bytesRead;

    /* Find matches */
    auto offsets = FindAllMatches(buffer.data(), buffer.size(), sig.pattern, firstOnly);

    for (size_t offset : offsets) {
        NexusSignatureMatch match = {};
        match.address = mod->baseAddress + offset + sig.info.offset;
        match.moduleBase = mod->baseAddress;
        wcsncpy_s(match.moduleName, mod->name, 63);
        match.matchIndex = static_cast<uint32_t>(sig.matches.size());

        sig.matches.push_back(match);
        ctx->matchesFound++;

        if (firstOnly) break;
    }
}

void ScanAllMemory(SignatureContext* ctx, SignatureEntry& sig,
                   uint32_t flags, bool firstOnly) {
    if (ctx->scanCancelled) return;

    /* Get memory regions */
    size_t regionCount = 0;
    Nexus_EnumerateMemoryRegions(ctx->process, nullptr, 0, &regionCount);

    if (regionCount == 0) return;

    std::vector<NexusMemoryRegion> regions(regionCount);
    Nexus_EnumerateMemoryRegions(ctx->process, regions.data(), regionCount, &regionCount);

    /* Calculate total bytes */
    uint64_t total = 0;
    for (const auto& region : regions) {
        if (region.state == MEM_COMMIT) {
            bool include = true;

            if (flags & NEXUS_SIG_FLAG_EXECUTABLE) {
                if (!(region.protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    include = false;
                }
            }

            if (flags & NEXUS_SIG_FLAG_WRITABLE) {
                if (!(region.protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    include = false;
                }
            }

            if (include) {
                total += region.size;
            }
        }
    }
    ctx->bytesTotal = total;

    /* Scan each region */
    std::vector<uint8_t> buffer;

    for (const auto& region : regions) {
        if (ctx->scanCancelled) break;
        if (region.state != MEM_COMMIT) continue;

        /* Filter by protection */
        if (flags & NEXUS_SIG_FLAG_EXECUTABLE) {
            if (!(region.protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                continue;
            }
        }

        if (flags & NEXUS_SIG_FLAG_WRITABLE) {
            if (!(region.protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                continue;
            }
        }

        /* Skip guard pages */
        if (region.protection & PAGE_GUARD) continue;
        if (region.protection & PAGE_NOACCESS) continue;

        /* Read region */
        buffer.resize(region.size);
        size_t bytesRead = 0;

        NexusResult result = Nexus_ReadMemory(ctx->process, region.baseAddress,
                                               buffer.data(), buffer.size(), &bytesRead);

        if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
            continue;
        }

        buffer.resize(bytesRead);
        ctx->bytesScanned += bytesRead;

        /* Find matches */
        auto offsets = FindAllMatches(buffer.data(), buffer.size(), sig.pattern, firstOnly);

        for (size_t offset : offsets) {
            NexusSignatureMatch match = {};
            match.address = region.baseAddress + offset + sig.info.offset;

            /* Check if in a module */
            const NexusModuleInfo* mod = FindModuleByAddress(ctx, match.address);
            if (mod) {
                match.moduleBase = mod->baseAddress;
                wcsncpy_s(match.moduleName, mod->name, 63);
            }

            match.matchIndex = static_cast<uint32_t>(sig.matches.size());

            sig.matches.push_back(match);
            ctx->matchesFound++;

            if (firstOnly) return;
        }
    }
}
