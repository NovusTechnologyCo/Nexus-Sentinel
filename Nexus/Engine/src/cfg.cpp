/**
 * @file cfg.cpp
 * @brief Control flow graph public API: create/destroy, block/edge queries.
 *
 * Exposes the CFG analysis results to consumers: block count,
 * block-by-index/address lookup, edge enumeration, and predecessor/
 * successor queries.
 *
 * The three-phase analysis algorithm is in cfg_analyze.cpp.
 */

#include "cfg_internal.h"

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_CFGAnalyze(
    NexusProcessHandle process,
    uint64_t entryAddress,
    size_t maxInstructions,
    NexusCFGHandle* cfg
) {
    if (!process || !cfg || entryAddress == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = new InternalCFG();
    internalCfg->process = process;
    internalCfg->entryAddress = entryAddress;
    internalCfg->functionEnd = entryAddress;
    internalCfg->totalInstructions = 0;
    internalCfg->maxLoopDepth = 0;
    internalCfg->isComplete = false;

    NexusResult result = CfgAnalyze(internalCfg, maxInstructions);
    if (result != NEXUS_OK) {
        delete internalCfg;
        return result;
    }

    *cfg = reinterpret_cast<NexusCFGHandle>(internalCfg);
    return NEXUS_OK;
}

NEXUS_API void Nexus_CFGDestroy(NexusCFGHandle cfg) {
    if (cfg) {
        delete reinterpret_cast<InternalCFG*>(cfg);
    }
}

NEXUS_API NexusResult Nexus_CFGGetResult(NexusCFGHandle cfg, NexusCFGResult* result) {
    if (!cfg || !result) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    result->functionStart = internalCfg->entryAddress;
    result->functionEnd = internalCfg->functionEnd;
    result->blockCount = (uint32_t)internalCfg->blocks.size();
    result->edgeCount = (uint32_t)internalCfg->edges.size();
    result->instructionCount = internalCfg->totalInstructions;
    result->maxLoopDepth = internalCfg->maxLoopDepth;
    result->isComplete = internalCfg->isComplete ? 1 : 0;
    result->reserved = 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CFGGetBlocks(
    NexusCFGHandle cfg,
    NexusBasicBlock* blocks,
    size_t maxBlocks,
    size_t* blockCount
) {
    if (!cfg || !blocks || !blockCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    size_t count = std::min(maxBlocks, internalCfg->blocks.size());
    for (size_t i = 0; i < count; i++) {
        const InternalBasicBlock& ib = internalCfg->blocks[i];
        blocks[i].startAddress = ib.startAddress;
        blocks[i].endAddress = ib.endAddress;
        blocks[i].instructionCount = ib.instructionCount;
        blocks[i].flags = ib.flags;
        blocks[i].trueTarget = ib.trueTarget;
        blocks[i].falseTarget = ib.falseTarget;
        blocks[i].blockIndex = (uint32_t)i;
        blocks[i].loopDepth = ib.loopDepth;
    }

    *blockCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CFGGetEdges(
    NexusCFGHandle cfg,
    NexusCFGEdge* edges,
    size_t maxEdges,
    size_t* edgeCount
) {
    if (!cfg || !edges || !edgeCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    size_t count = std::min(maxEdges, internalCfg->edges.size());
    for (size_t i = 0; i < count; i++) {
        edges[i] = internalCfg->edges[i];
    }

    *edgeCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CFGGetBlockByAddress(
    NexusCFGHandle cfg,
    uint64_t address,
    NexusBasicBlock* block
) {
    if (!cfg || !block) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    for (size_t i = 0; i < internalCfg->blocks.size(); i++) {
        const InternalBasicBlock& ib = internalCfg->blocks[i];
        if (address >= ib.startAddress && address <= ib.endAddress) {
            block->startAddress = ib.startAddress;
            block->endAddress = ib.endAddress;
            block->instructionCount = ib.instructionCount;
            block->flags = ib.flags;
            block->trueTarget = ib.trueTarget;
            block->falseTarget = ib.falseTarget;
            block->blockIndex = (uint32_t)i;
            block->loopDepth = ib.loopDepth;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_CFGGetBlockInstructions(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    NexusDisasmInstruction* instructions,
    size_t maxInstructions,
    size_t* instructionCount
) {
    if (!cfg || !instructions || !instructionCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    if (blockIndex >= internalCfg->blocks.size()) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    const InternalBasicBlock& block = internalCfg->blocks[blockIndex];
    size_t count = std::min(maxInstructions, block.instructions.size());

    for (size_t i = 0; i < count; i++) {
        instructions[i] = block.instructions[i];
    }

    *instructionCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CFGGetPredecessors(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    uint32_t* predecessors,
    size_t maxPredecessors,
    size_t* predecessorCount
) {
    if (!cfg || !predecessors || !predecessorCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    if (blockIndex >= internalCfg->blocks.size()) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    const InternalBasicBlock& block = internalCfg->blocks[blockIndex];
    size_t count = std::min(maxPredecessors, block.predecessors.size());

    for (size_t i = 0; i < count; i++) {
        predecessors[i] = block.predecessors[i];
    }

    *predecessorCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CFGGetSuccessors(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    uint32_t* successors,
    size_t maxSuccessors,
    size_t* successorCount
) {
    if (!cfg || !successors || !successorCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    InternalCFG* internalCfg = reinterpret_cast<InternalCFG*>(cfg);

    if (blockIndex >= internalCfg->blocks.size()) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    const InternalBasicBlock& block = internalCfg->blocks[blockIndex];
    size_t count = std::min(maxSuccessors, block.successors.size());

    for (size_t i = 0; i < count; i++) {
        successors[i] = block.successors[i];
    }

    *successorCount = count;
    return NEXUS_OK;
}
