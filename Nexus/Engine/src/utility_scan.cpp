/**
 * @file utility_scan.cpp
 * @brief Pattern scanning: Nexus_PatternScan and Nexus_PatternScanModule.
 *
 * Parses hex/wildcard pattern strings, iterates over process memory
 * regions (or a single module), and reports all matching addresses.
 *
 * Type detection, address resolution, and dump are in utility.cpp.
 */

#include "../include/nexus_api.h"
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <vector>
#include <string>
#include <algorithm>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

// Parse pattern string "DE AD ?? EF" into bytes and mask
static bool ParsePattern(const char* pattern, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask) {
    bytes.clear();
    mask.clear();

    const char* p = pattern;
    while (*p) {
        // Skip whitespace
        while (*p && isspace(*p)) p++;
        if (!*p) break;

        // Check for wildcard
        if (p[0] == '?' && p[1] == '?') {
            bytes.push_back(0);
            mask.push_back(0x00);  // Don't care
            p += 2;
        }
        else if (p[0] == '*' && p[1] == '*') {
            bytes.push_back(0);
            mask.push_back(0x00);
            p += 2;
        }
        else if (p[0] == '*' || p[0] == '?') {
            bytes.push_back(0);
            mask.push_back(0x00);
            p++;
        }
        else {
            // Parse hex byte
            char hex[3] = { p[0], p[1] ? p[1] : '0', 0 };
            char* end;
            uint8_t byte = (uint8_t)strtoul(hex, &end, 16);
            if (end == hex) return false;  // Parse error

            bytes.push_back(byte);
            mask.push_back(0xFF);  // Exact match

            p += (p[1] && isxdigit(p[1])) ? 2 : 1;
        }
    }

    return !bytes.empty();
}

// Match pattern against buffer
static bool MatchPattern(const uint8_t* data, size_t dataLen,
                         const uint8_t* pattern, const uint8_t* mask, size_t patternLen) {
    if (dataLen < patternLen) return false;

    for (size_t i = 0; i < patternLen; i++) {
        if (mask[i] && (data[i] & mask[i]) != (pattern[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * Pattern Scanning Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_PatternScan(
    NexusProcessHandle process,
    const char* pattern,
    uint64_t startAddress,
    uint64_t endAddress,
    uint32_t options,
    uint64_t* results,
    size_t maxResults,
    size_t* resultCount)
{
    if (!process || !pattern || !resultCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *resultCount = 0;

    // Parse the pattern
    std::vector<uint8_t> patternBytes;
    std::vector<uint8_t> patternMask;
    if (!ParsePattern(pattern, patternBytes, patternMask)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)process;

    // Default address range
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (startAddress == 0) startAddress = (uint64_t)sysInfo.lpMinimumApplicationAddress;
    if (endAddress == 0) endAddress = (uint64_t)sysInfo.lpMaximumApplicationAddress;

    // Scan memory regions
    const size_t CHUNK_SIZE = 0x10000;  // 64KB chunks
    std::vector<uint8_t> buffer(CHUNK_SIZE + patternBytes.size());

    uint64_t currentAddr = startAddress;
    while (currentAddr < endAddress && (!maxResults || *resultCount < maxResults)) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)currentAddr, &mbi, sizeof(mbi)) == 0) {
            currentAddr += 0x1000;  // Skip to next page
            continue;
        }

        // Skip non-committed memory
        if (mbi.State != MEM_COMMIT) {
            currentAddr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // Check protection filters
        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if ((options & NEXUS_PATSCAN_EXECUTABLE) && !isExecutable) {
            currentAddr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }
        if ((options & NEXUS_PATSCAN_WRITABLE) && !isWritable) {
            currentAddr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        // Check module filter
        if (options & NEXUS_PATSCAN_MODULE_ONLY) {
            if (mbi.Type != MEM_IMAGE) {
                currentAddr = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
        }

        // Scan this region in chunks
        uint64_t regionEnd = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > endAddress) regionEnd = endAddress;

        while (currentAddr < regionEnd && (!maxResults || *resultCount < maxResults)) {
            size_t readSize = (size_t)std::min((uint64_t)buffer.size(), regionEnd - currentAddr);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, (LPCVOID)currentAddr, buffer.data(), readSize, &bytesRead) && bytesRead > 0) {
                // Search for pattern in buffer
                for (size_t i = 0; i <= bytesRead - patternBytes.size(); i++) {
                    if (MatchPattern(buffer.data() + i, bytesRead - i,
                                    patternBytes.data(), patternMask.data(), patternBytes.size())) {
                        if (results && *resultCount < maxResults) {
                            results[*resultCount] = currentAddr + i;
                        }
                        (*resultCount)++;

                        if ((options & NEXUS_PATSCAN_FIRST_MATCH) ||
                            (maxResults && *resultCount >= maxResults)) {
                            return NEXUS_OK;
                        }
                    }
                }
            }

            // Advance with overlap for patterns spanning chunks
            currentAddr += bytesRead > patternBytes.size() ? bytesRead - patternBytes.size() + 1 : 1;
        }

        currentAddr = regionEnd;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_PatternScanModule(
    NexusProcessHandle process,
    const char* pattern,
    const char* moduleName,
    uint32_t options,
    uint64_t* results,
    size_t maxResults,
    size_t* resultCount)
{
    if (!process || !pattern || !moduleName || !resultCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)process;

    // Find module
    HMODULE modules[1024];
    DWORD needed;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    uint64_t moduleBase = 0;
    uint64_t moduleEnd = 0;

    size_t moduleCount = needed / sizeof(HMODULE);
    for (size_t i = 0; i < moduleCount; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            if (_stricmp(name, moduleName) == 0) {
                MODULEINFO info;
                if (GetModuleInformation(hProcess, modules[i], &info, sizeof(info))) {
                    moduleBase = (uint64_t)info.lpBaseOfDll;
                    moduleEnd = moduleBase + info.SizeOfImage;
                    break;
                }
            }
        }
    }

    if (moduleBase == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    return Nexus_PatternScan(process, pattern, moduleBase, moduleEnd, options, results, maxResults, resultCount);
}
