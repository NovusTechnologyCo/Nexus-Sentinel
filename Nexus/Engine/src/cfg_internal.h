/**
 * @file cfg_internal.h
 * @brief Internal header shared by cfg.cpp and cfg_analyze.cpp.
 */

#pragma once

#include "nexus_api.h"
#include "../third_party/amalgamated-dist/Zydis.h"

#include <vector>
#include <set>
#include <map>
#include <queue>
#include <algorithm>
#include <cstring>

/* Forward declarations from other modules */
extern NexusResult Nexus_ReadMemory(NexusProcessHandle handle, uint64_t address, void* buffer, size_t size, size_t* bytesRead);
extern NexusResult Nexus_GetRawHandle(NexusProcessHandle handle, void** rawHandle);

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct InternalBasicBlock {
    uint64_t startAddress;
    uint64_t endAddress;
    uint32_t flags;
    uint64_t trueTarget;
    uint64_t falseTarget;
    uint32_t instructionCount;
    uint32_t loopDepth;
    std::vector<NexusDisasmInstruction> instructions;
    std::vector<uint32_t> predecessors;
    std::vector<uint32_t> successors;
};

struct InternalCFG {
    NexusProcessHandle process;
    uint64_t entryAddress;
    uint64_t functionEnd;
    std::vector<InternalBasicBlock> blocks;
    std::vector<NexusCFGEdge> edges;
    std::map<uint64_t, uint32_t> addressToBlockIndex;
    uint32_t totalInstructions;
    uint32_t maxLoopDepth;
    bool isComplete;
};

/* ============================================================================
 * Cross-File Function Prototypes (defined in cfg_analyze.cpp)
 * ============================================================================ */

NexusResult CfgAnalyze(InternalCFG* cfg, size_t maxInstructions);
