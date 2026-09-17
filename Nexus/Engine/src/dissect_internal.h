/**
 * @file dissect_internal.h
 * @brief Internal header shared by dissect.cpp, dissect_persist.cpp, and dissect_enum.cpp.
 */

#pragma once

#include "nexus_api.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <map>
#include <cstring>
#include <atomic>
#include <mutex>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct StructElement {
    uint32_t id;
    int32_t offset;
    int32_t byteSize;
    NexusElementType varType;
    NexusDisplayMethod displayMethod;
    std::string name;
    std::string customTypeName;
    uint32_t childStructId;
    int32_t childStructOffset;
    uint32_t backgroundColor;
    int32_t arrayCount;
    int32_t bitOffset;
    int32_t bitSize;
    uint32_t flags;
    uint32_t enumDefinitionId;  /* Enum definition ID for NEXUS_ELEM_ENUMERATION */
};

struct DissectedStructure {
    uint32_t id;
    std::string name;
    int32_t size;
    uint32_t flags;
    std::vector<StructElement> elements;
    std::atomic<uint32_t> nextElementId{1};

    // Child structure references
    std::map<uint32_t, DissectedStructure*> childStructs;
};

struct StructInstance {
    uint32_t id;
    uint32_t structId;
    uint64_t baseAddress;
    std::string name;
    bool frozen;
    std::vector<uint8_t> snapshot;
};

/* ============================================================================
 * Enumeration Structures
 * ============================================================================ */

struct EnumDefinitionInternal {
    uint32_t id;
    std::string name;
    NexusElementType baseType;
    uint32_t flags;
    std::vector<NexusEnumValue> values;
};

/* ============================================================================
 * Global State (defined in dissect.cpp unless noted)
 * ============================================================================ */

/* Structure globals (defined in dissect.cpp) */
extern std::atomic<uint32_t> g_nextStructId;
extern std::atomic<uint32_t> g_nextInstanceId;
extern std::mutex g_structMutex;

/* Enumeration globals (defined in dissect_enum.cpp) */
extern std::map<uint32_t, EnumDefinitionInternal> g_enumRegistry;
extern std::atomic<uint32_t> g_nextEnumId;
extern std::mutex g_enumMutex;

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- dissect.cpp --- */
int32_t GetDefaultByteSize(NexusElementType varType);
void ElementToAPI(const StructElement& elem, NexusStructElement* out);
void APIToElement(const NexusStructElement* api, StructElement& elem);
