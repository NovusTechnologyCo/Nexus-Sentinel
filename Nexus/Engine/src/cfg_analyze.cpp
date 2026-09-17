/**
 * @file cfg_analyze.cpp
 * @brief CFG analysis core: basic-block detection, edge construction, and the 3-phase algorithm.
 *
 * Phase 1: linear disassembly to classify every instruction's flow type.
 * Phase 2: split the instruction stream into basic blocks at leaders.
 * Phase 3: build edges (fall-through, conditional, unconditional, call)
 * between blocks and populate predecessor/successor lists.
 */

#include "cfg_internal.h"

/* ============================================================================
 * Instruction Classification Helpers
 * ============================================================================ */

static bool IsBranchMnemonic(ZydisMnemonic mnemonic) {
    switch (mnemonic) {
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JKNZD:
        case ZYDIS_MNEMONIC_JKZD:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
            return true;
        default:
            return false;
    }
}

static bool IsUnconditionalJump(ZydisMnemonic mnemonic) {
    return mnemonic == ZYDIS_MNEMONIC_JMP;
}

static bool IsConditionalBranch(ZydisMnemonic mnemonic) {
    return IsBranchMnemonic(mnemonic) && !IsUnconditionalJump(mnemonic);
}

static bool IsCallMnemonic(ZydisMnemonic mnemonic) {
    return mnemonic == ZYDIS_MNEMONIC_CALL;
}

static bool IsReturnMnemonic(ZydisMnemonic mnemonic) {
    return mnemonic == ZYDIS_MNEMONIC_RET ||
           mnemonic == ZYDIS_MNEMONIC_IRET ||
           mnemonic == ZYDIS_MNEMONIC_IRETD ||
           mnemonic == ZYDIS_MNEMONIC_IRETQ;
}

static bool IsIndirectBranch(const ZydisDisassembledInstruction& inst) {
    if (!IsBranchMnemonic(inst.info.mnemonic)) {
        return false;
    }

    if (inst.info.operand_count > 0) {
        const auto& op = inst.operands[0];
        return op.type == ZYDIS_OPERAND_TYPE_REGISTER ||
               op.type == ZYDIS_OPERAND_TYPE_MEMORY;
    }
    return false;
}

static uint64_t GetBranchTarget(const ZydisDisassembledInstruction& inst, uint64_t address) {
    if (inst.info.operand_count > 0) {
        const auto& op = inst.operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            return address + inst.info.length + op.imm.value.s;
        }
    }
    return 0;
}

static void FillNexusInstruction(
    const ZydisDisassembledInstruction& zydisInst,
    uint64_t address,
    const uint8_t* bytes,
    NexusDisasmInstruction* outInst
) {
    memset(outInst, 0, sizeof(NexusDisasmInstruction));

    outInst->address = address;
    outInst->length = (uint8_t)zydisInst.info.length;

    size_t copyLen = std::min((size_t)zydisInst.info.length, sizeof(outInst->bytes));
    memcpy(outInst->bytes, bytes, copyLen);

    strncpy_s(outInst->text, sizeof(outInst->text), zydisInst.text, _TRUNCATE);

    const char* space = strchr(zydisInst.text, ' ');
    if (space) {
        size_t mnemonicLen = space - zydisInst.text;
        if (mnemonicLen < sizeof(outInst->mnemonic)) {
            strncpy_s(outInst->mnemonic, sizeof(outInst->mnemonic), zydisInst.text, mnemonicLen);
        }
    } else {
        strncpy_s(outInst->mnemonic, sizeof(outInst->mnemonic), zydisInst.text, _TRUNCATE);
    }

    outInst->isBranch = IsBranchMnemonic(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isCall = IsCallMnemonic(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isReturn = IsReturnMnemonic(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isConditional = IsConditionalBranch(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->branchTarget = GetBranchTarget(zydisInst, address);
}

/* ============================================================================
 * CFG Analysis (3-Phase Algorithm)
 * ============================================================================ */

NexusResult CfgAnalyze(InternalCFG* cfg, size_t maxInstructions) {
    if (maxInstructions == 0) {
        maxInstructions = 10000;
    }

    /* Phase 1: Find all basic block start addresses */
    std::set<uint64_t> blockStarts;
    std::set<uint64_t> visited;
    std::queue<uint64_t> workQueue;

    blockStarts.insert(cfg->entryAddress);
    workQueue.push(cfg->entryAddress);

    uint8_t buffer[16];
    size_t totalInstructions = 0;

    while (!workQueue.empty() && totalInstructions < maxInstructions) {
        uint64_t addr = workQueue.front();
        workQueue.pop();

        if (visited.count(addr)) {
            continue;
        }

        uint64_t currentAddr = addr;
        while (totalInstructions < maxInstructions) {
            if (visited.count(currentAddr)) {
                break;
            }
            visited.insert(currentAddr);

            size_t bytesRead;
            NexusResult res = Nexus_ReadMemory(cfg->process, currentAddr, buffer, sizeof(buffer), &bytesRead);
            if (res != NEXUS_OK || bytesRead < 1) {
                break;
            }

            ZydisDisassembledInstruction inst;
            if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentAddr, buffer, bytesRead, &inst))) {
                break;
            }

            totalInstructions++;
            uint64_t nextAddr = currentAddr + inst.info.length;

            if (currentAddr > cfg->functionEnd) {
                cfg->functionEnd = currentAddr;
            }

            if (IsReturnMnemonic(inst.info.mnemonic)) {
                break;
            }

            if (IsUnconditionalJump(inst.info.mnemonic)) {
                if (!IsIndirectBranch(inst)) {
                    uint64_t target = GetBranchTarget(inst, currentAddr);
                    if (target != 0 && !visited.count(target)) {
                        blockStarts.insert(target);
                        workQueue.push(target);
                    }
                }
                break;
            }

            if (IsConditionalBranch(inst.info.mnemonic)) {
                if (!IsIndirectBranch(inst)) {
                    uint64_t target = GetBranchTarget(inst, currentAddr);
                    if (target != 0 && !visited.count(target)) {
                        blockStarts.insert(target);
                        workQueue.push(target);
                    }
                }
                if (!visited.count(nextAddr)) {
                    blockStarts.insert(nextAddr);
                    workQueue.push(nextAddr);
                }
                break;
            }

            if (IsCallMnemonic(inst.info.mnemonic)) {
                currentAddr = nextAddr;
                continue;
            }

            if (blockStarts.count(nextAddr)) {
                break;
            }

            currentAddr = nextAddr;
        }
    }

    cfg->totalInstructions = (uint32_t)totalInstructions;

    /* Phase 2: Build basic blocks */
    std::vector<uint64_t> sortedStarts(blockStarts.begin(), blockStarts.end());
    std::sort(sortedStarts.begin(), sortedStarts.end());

    visited.clear();

    for (size_t i = 0; i < sortedStarts.size(); i++) {
        uint64_t blockAddr = sortedStarts[i];

        InternalBasicBlock block;
        block.startAddress = blockAddr;
        block.flags = 0;
        block.trueTarget = 0;
        block.falseTarget = 0;
        block.instructionCount = 0;
        block.loopDepth = 0;

        if (blockAddr == cfg->entryAddress) {
            block.flags |= NEXUS_BB_FLAG_ENTRY;
        }

        uint64_t currentAddr = blockAddr;
        uint64_t nextBlockStart = (i + 1 < sortedStarts.size()) ? sortedStarts[i + 1] : UINT64_MAX;

        while (currentAddr < nextBlockStart) {
            if (visited.count(currentAddr)) {
                break;
            }
            visited.insert(currentAddr);

            size_t bytesRead;
            NexusResult res = Nexus_ReadMemory(cfg->process, currentAddr, buffer, sizeof(buffer), &bytesRead);
            if (res != NEXUS_OK || bytesRead < 1) {
                break;
            }

            ZydisDisassembledInstruction inst;
            if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentAddr, buffer, bytesRead, &inst))) {
                break;
            }

            NexusDisasmInstruction nexusInst;
            FillNexusInstruction(inst, currentAddr, buffer, &nexusInst);
            block.instructions.push_back(nexusInst);
            block.instructionCount++;

            block.endAddress = currentAddr;
            uint64_t nextAddr = currentAddr + inst.info.length;

            if (IsReturnMnemonic(inst.info.mnemonic)) {
                block.flags |= NEXUS_BB_FLAG_EXIT;
                break;
            }

            if (IsUnconditionalJump(inst.info.mnemonic)) {
                block.flags |= NEXUS_BB_FLAG_UNCOND_BRANCH;
                if (IsIndirectBranch(inst)) {
                    block.flags |= NEXUS_BB_FLAG_INDIRECT;
                } else {
                    block.trueTarget = GetBranchTarget(inst, currentAddr);
                }
                break;
            }

            if (IsConditionalBranch(inst.info.mnemonic)) {
                block.flags |= NEXUS_BB_FLAG_COND_BRANCH;
                if (IsIndirectBranch(inst)) {
                    block.flags |= NEXUS_BB_FLAG_INDIRECT;
                } else {
                    block.trueTarget = GetBranchTarget(inst, currentAddr);
                }
                block.falseTarget = nextAddr;
                block.flags |= NEXUS_BB_FLAG_FALLTHROUGH;
                break;
            }

            if (IsCallMnemonic(inst.info.mnemonic)) {
                block.flags |= NEXUS_BB_FLAG_CALL;
            }

            if (nextAddr >= nextBlockStart) {
                block.falseTarget = nextAddr;
                block.flags |= NEXUS_BB_FLAG_FALLTHROUGH;
                break;
            }

            currentAddr = nextAddr;
        }

        if (block.instructionCount > 0) {
            cfg->addressToBlockIndex[block.startAddress] = (uint32_t)cfg->blocks.size();
            cfg->blocks.push_back(block);
        }
    }

    /* Phase 3: Build edges and predecessor/successor lists */
    for (uint32_t i = 0; i < cfg->blocks.size(); i++) {
        InternalBasicBlock& block = cfg->blocks[i];

        if (block.trueTarget != 0) {
            auto it = cfg->addressToBlockIndex.find(block.trueTarget);
            if (it != cfg->addressToBlockIndex.end()) {
                uint32_t targetIdx = it->second;

                NexusCFGEdge edge;
                edge.sourceBlock = i;
                edge.targetBlock = targetIdx;
                edge.edgeType = 1;
                edge.reserved = 0;

                if (block.trueTarget <= block.startAddress) {
                    edge.edgeType = 3;
                    cfg->blocks[targetIdx].flags |= NEXUS_BB_FLAG_LOOP_HEADER;
                }

                cfg->edges.push_back(edge);
                block.successors.push_back(targetIdx);
                cfg->blocks[targetIdx].predecessors.push_back(i);
            }
        }

        if ((block.flags & NEXUS_BB_FLAG_FALLTHROUGH) && block.falseTarget != 0) {
            auto it = cfg->addressToBlockIndex.find(block.falseTarget);
            if (it != cfg->addressToBlockIndex.end()) {
                uint32_t targetIdx = it->second;

                NexusCFGEdge edge;
                edge.sourceBlock = i;
                edge.targetBlock = targetIdx;
                edge.edgeType = 0;
                edge.reserved = 0;

                cfg->edges.push_back(edge);
                block.successors.push_back(targetIdx);
                cfg->blocks[targetIdx].predecessors.push_back(i);
            }
        }
    }

    cfg->isComplete = (totalInstructions < maxInstructions);

    return NEXUS_OK;
}
