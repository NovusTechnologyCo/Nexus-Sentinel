/**
 * @file addressfile_internal.h
 * @brief Internal header shared by addressfile.cpp and addressfile_cea.cpp.
 */

#pragma once

#include "nexus_api.h"
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

/* Forward declarations from other modules */
extern "C" {
    NexusResult Nexus_EnumerateModules(
        NexusProcessHandle handle,
        NexusModuleInfo* buffer,
        size_t bufferCount,
        size_t* modulesFound
    );
}

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct AddressEntry {
    int32_t moduleIndex;
    uint64_t offset;
    std::string description;

    /* Resolved at runtime */
    uint64_t resolvedAddress;
    std::string moduleName;
    bool isValid;
};

struct AddressFile {
    std::vector<std::string> modules;
    std::vector<AddressEntry> entries;
};

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

uint64_t AddrFileFindModuleBase(NexusProcessHandle process, const std::string& moduleName);
