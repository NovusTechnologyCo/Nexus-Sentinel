/**
 * @file signature_internal.h
 * @brief Internal header shared by signature.cpp and signature_scan.cpp.
 */

#pragma once

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <atomic>
#include <mutex>
#include <memory>

/* Forward declarations from other modules */
extern NexusResult Nexus_ReadMemory(NexusProcessHandle handle, uint64_t address, void* buffer, size_t size, size_t* bytesRead);
extern NexusResult Nexus_EnumerateModules(NexusProcessHandle handle, NexusModuleInfo* buffer, size_t bufferCount, size_t* moduleCount);
extern NexusResult Nexus_EnumerateMemoryRegions(NexusProcessHandle handle, NexusMemoryRegion* buffer, size_t bufferCount, size_t* regionCount);
extern NexusResult Nexus_AssemblerAddSymbol(NexusAssemblerHandle assembler, const char* name, uint64_t address);

/* ============================================================================
 * Internal Types
 * ============================================================================ */

struct ParsedPattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;  /* 0xFF = exact match, 0x00 = wildcard */
};

struct SignatureEntry {
    uint32_t id;
    NexusSignatureInfo info;
    ParsedPattern pattern;
    std::vector<NexusSignatureMatch> matches;
};

struct SignatureContext {
    NexusProcessHandle process;

    std::map<uint32_t, SignatureEntry> signatures;
    uint32_t nextSigId;

    /* Cached module list */
    std::vector<NexusModuleInfo> modules;
    bool modulesCached;

    /* Scan state */
    std::atomic<bool> scanCancelled;
    std::atomic<bool> scanComplete;
    std::atomic<uint64_t> bytesScanned;
    std::atomic<uint64_t> bytesTotal;
    std::atomic<uint64_t> matchesFound;

    std::mutex scanMutex;
};

/* ============================================================================
 * Cross-File Function Prototypes (defined in signature_scan.cpp)
 * ============================================================================ */

bool ParsePatternInternal(const std::string& pattern, ParsedPattern& result);
bool MatchPattern(const uint8_t* data, size_t dataSize, const ParsedPattern& pattern, size_t offset);
std::vector<size_t> FindAllMatches(const uint8_t* data, size_t dataSize, const ParsedPattern& pattern, bool firstOnly = false);
void CacheModules(SignatureContext* ctx);
const NexusModuleInfo* FindModule(SignatureContext* ctx, const char* name);
const NexusModuleInfo* FindModuleByAddress(SignatureContext* ctx, uint64_t address);
void ScanModule(SignatureContext* ctx, SignatureEntry& sig, const NexusModuleInfo* mod, bool firstOnly);
void ScanAllMemory(SignatureContext* ctx, SignatureEntry& sig, uint32_t flags, bool firstOnly);
