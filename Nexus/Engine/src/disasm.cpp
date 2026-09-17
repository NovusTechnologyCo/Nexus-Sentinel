/**
 * @file disasm.cpp
 * @brief Disassembler core: single/multi decode, process-memory decode, navigation, and syntax control.
 *
 * Wraps the Zydis disassembly library to provide:
 *   - Single and batch instruction decoding from raw buffers
 *   - Decode directly from target-process memory via ReadProcessMemory
 *   - Backward navigation (DisasmBack) using heuristic multi-decode
 *   - Forward navigation (DisasmNext) by sequential decode
 *   - Fast lightweight decode for UI hit-testing
 *   - Syntax selection (Intel / AT&T)
 *
 * Thread-safe context and flow-control analysis live in disasm_flow.cpp.
 */

#include "disasm_internal.h"

#include <vector>
#include <mutex>

/* ============================================================================
 * Global State
 * ============================================================================ */

static ZydisFormatter g_formatter;
static bool g_formatterInitialized = false;
static NexusDisasmSyntax g_currentSyntax = NEXUS_SYNTAX_INTEL;

/* CRITICAL FIX: Mutex for thread safety of global formatter state */
static std::mutex g_disasmMutex;

/* ============================================================================
 * Shared Helper Functions (non-static, declared in disasm_internal.h)
 * ============================================================================ */

/* Convert our machine mode to Zydis machine mode */
ZydisMachineMode ConvertMachineMode(NexusMachineMode mode) {
    switch (mode) {
        case NEXUS_MODE_LONG_64:
            return ZYDIS_MACHINE_MODE_LONG_64;
        case NEXUS_MODE_LONG_COMPAT_32:
            return ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
        case NEXUS_MODE_LONG_COMPAT_16:
            return ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
        case NEXUS_MODE_LEGACY_32:
            return ZYDIS_MACHINE_MODE_LEGACY_32;
        case NEXUS_MODE_LEGACY_16:
            return ZYDIS_MACHINE_MODE_LEGACY_16;
        case NEXUS_MODE_REAL_16:
            return ZYDIS_MACHINE_MODE_REAL_16;
        default:
            return ZYDIS_MACHINE_MODE_LONG_64;
    }
}

/* Check if instruction is a branch/call/return */
bool IsBranch(ZydisMnemonic mnemonic) {
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

bool IsCall(ZydisMnemonic mnemonic) {
    return mnemonic == ZYDIS_MNEMONIC_CALL;
}

bool IsReturn(ZydisMnemonic mnemonic) {
    return mnemonic == ZYDIS_MNEMONIC_RET ||
           mnemonic == ZYDIS_MNEMONIC_IRET ||
           mnemonic == ZYDIS_MNEMONIC_IRETD ||
           mnemonic == ZYDIS_MNEMONIC_IRETQ;
}

bool IsConditional(ZydisMnemonic mnemonic) {
    switch (mnemonic) {
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
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

/* ============================================================================
 * Static Helper Functions
 * ============================================================================ */

/* Initialize the formatter if not already done */
[[maybe_unused]] static void InitFormatter() {
    if (!g_formatterInitialized) {
        ZydisFormatterStyle style = (g_currentSyntax == NEXUS_SYNTAX_ATT)
            ? ZYDIS_FORMATTER_STYLE_ATT
            : ZYDIS_FORMATTER_STYLE_INTEL;
        ZydisFormatterInit(&g_formatter, style);
        g_formatterInitialized = true;
    }
}

/* Fill our instruction structure from Zydis data */
static void FillInstruction(
    const ZydisDisassembledInstruction& zydisInst,
    uint64_t address,
    const uint8_t* bytes,
    NexusDisasmInstruction* outInst
) {
    memset(outInst, 0, sizeof(NexusDisasmInstruction));

    outInst->address = address;
    outInst->length = (uint8_t)zydisInst.info.length;

    /* Copy instruction bytes */
    size_t copyLen = std::min((size_t)zydisInst.info.length, sizeof(outInst->bytes));
    memcpy(outInst->bytes, bytes, copyLen);

    /* Copy formatted text */
    strncpy_s(outInst->text, sizeof(outInst->text), zydisInst.text, _TRUNCATE);

    /* Extract mnemonic from text (first word) */
    const char* space = strchr(zydisInst.text, ' ');
    if (space) {
        size_t mnemonicLen = space - zydisInst.text;
        if (mnemonicLen < sizeof(outInst->mnemonic)) {
            strncpy_s(outInst->mnemonic, sizeof(outInst->mnemonic), zydisInst.text, mnemonicLen);
        }
    } else {
        strncpy_s(outInst->mnemonic, sizeof(outInst->mnemonic), zydisInst.text, _TRUNCATE);
    }

    /* Fill in operand information */
    outInst->operandCount = 0;
    for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT && i < 5; i++) {
        const ZydisDecodedOperand& op = zydisInst.operands[i];

        if (op.type == ZYDIS_OPERAND_TYPE_UNUSED) {
            break;
        }

        /* Skip hidden/implicit operands */
        if (op.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
            op.visibility == ZYDIS_OPERAND_VISIBILITY_IMPLICIT) {
            continue;
        }

        NexusDisasmOperand& outOp = outInst->operands[outInst->operandCount];
        outOp.size = op.size;

        switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                outOp.type = NEXUS_OPERAND_REGISTER;
                outOp.reg.id = static_cast<uint16_t>(op.reg.value);
                break;

            case ZYDIS_OPERAND_TYPE_MEMORY:
                outOp.type = NEXUS_OPERAND_MEMORY;
                outOp.mem.segment = static_cast<uint16_t>(op.mem.segment);
                outOp.mem.base = static_cast<uint16_t>(op.mem.base);
                outOp.mem.index = static_cast<uint16_t>(op.mem.index);
                outOp.mem.scale = op.mem.scale;
                outOp.mem.disp = op.mem.disp.value;
                outOp.mem.hasDisp = op.mem.disp.has_displacement ? 1 : 0;
                break;

            case ZYDIS_OPERAND_TYPE_POINTER:
                outOp.type = NEXUS_OPERAND_POINTER;
                break;

            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                outOp.type = NEXUS_OPERAND_IMMEDIATE;
                outOp.imm.value = op.imm.value.u;
                outOp.imm.isSigned = op.imm.is_signed ? 1 : 0;
                outOp.imm.isRelative = op.imm.is_relative ? 1 : 0;
                break;

            default:
                outOp.type = NEXUS_OPERAND_UNUSED;
                break;
        }

        outInst->operandCount++;
    }

    /* Determine branch/call/return status */
    outInst->isBranch = IsBranch(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isCall = IsCall(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isReturn = IsReturn(zydisInst.info.mnemonic) ? 1 : 0;
    outInst->isConditional = IsConditional(zydisInst.info.mnemonic) ? 1 : 0;

    /* Calculate branch target for relative branches */
    if ((outInst->isBranch || outInst->isCall) && zydisInst.info.operand_count > 0) {
        const ZydisDecodedOperand& firstOp = zydisInst.operands[0];
        if (firstOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && firstOp.imm.is_relative) {
            /* Calculate absolute target address */
            outInst->branchTarget = address + zydisInst.info.length + firstOp.imm.value.s;
        }
    }
}

/* ============================================================================
 * Core Disassembly API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_DisasmDecode(
    NexusMachineMode mode,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusDisasmInstruction* instruction
) {
    if (!buffer || !instruction) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ZydisMachineMode machineMode = ConvertMachineMode(mode);
    ZydisDisassembledInstruction zydisInst;

    ZyanStatus status;
    if (g_currentSyntax == NEXUS_SYNTAX_ATT) {
        status = ZydisDisassembleATT(machineMode, address, buffer, bufferSize, &zydisInst);
    } else {
        status = ZydisDisassembleIntel(machineMode, address, buffer, bufferSize, &zydisInst);
    }

    if (!ZYAN_SUCCESS(status)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    FillInstruction(zydisInst, address, (const uint8_t*)buffer, instruction);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DisasmDecodeMultiple(
    NexusMachineMode mode,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    size_t maxInstructions,
    NexusDisasmInstruction* instructions,
    size_t* instructionCount
) {
    if (!buffer || !instructions || !instructionCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *instructionCount = 0;

    const uint8_t* bytes = (const uint8_t*)buffer;
    size_t offset = 0;
    uint64_t currentAddr = address;

    ZydisMachineMode machineMode = ConvertMachineMode(mode);

    while (offset < bufferSize && *instructionCount < maxInstructions) {
        ZydisDisassembledInstruction zydisInst;

        ZyanStatus status;
        if (g_currentSyntax == NEXUS_SYNTAX_ATT) {
            status = ZydisDisassembleATT(machineMode, currentAddr, bytes + offset,
                                          bufferSize - offset, &zydisInst);
        } else {
            status = ZydisDisassembleIntel(machineMode, currentAddr, bytes + offset,
                                            bufferSize - offset, &zydisInst);
        }

        if (!ZYAN_SUCCESS(status)) {
            /* Failed to decode - skip one byte and try again, or stop */
            break;
        }

        FillInstruction(zydisInst, currentAddr, bytes + offset, &instructions[*instructionCount]);

        offset += zydisInst.info.length;
        currentAddr += zydisInst.info.length;
        (*instructionCount)++;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DisasmDecodeProcess(
    NexusProcessHandle process,
    uint64_t address,
    size_t maxInstructions,
    NexusDisasmInstruction* instructions,
    size_t* instructionCount
) {
    if (!process || !instructions || !instructionCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Read memory from process */
    const size_t maxBytes = maxInstructions * 15; /* Max instruction length is 15 bytes */
    uint8_t* buffer = new uint8_t[maxBytes];
    if (!buffer) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    size_t bytesRead = 0;
    NexusResult result = Nexus_ReadMemory(process, address, buffer, maxBytes, &bytesRead);

    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        delete[] buffer;
        return result;
    }

    if (bytesRead == 0) {
        delete[] buffer;
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Determine machine mode based on process architecture */
    NexusProcessInfo info;
    Nexus_GetProcessInfo(process, &info);
    NexusMachineMode mode = info.is32Bit ? NEXUS_MODE_LEGACY_32 : NEXUS_MODE_LONG_64;

    /* Disassemble the buffer */
    result = Nexus_DisasmDecodeMultiple(mode, address, buffer, bytesRead,
                                        maxInstructions, instructions, instructionCount);

    delete[] buffer;
    return result;
}

NEXUS_API NexusResult Nexus_DisasmSetSyntax(NexusDisasmSyntax syntax) {
    /* CRITICAL FIX: Protect global state modification with mutex */
    std::lock_guard<std::mutex> lock(g_disasmMutex);
    g_currentSyntax = syntax;
    g_formatterInitialized = false; /* Force re-init with new style */
    return NEXUS_OK;
}

NEXUS_API const char* Nexus_DisasmGetRegisterName(uint16_t regId) {
    return ZydisRegisterGetString((ZydisRegister)regId);
}

/* ============================================================================
 * Backward/Forward Disassembly (x64dbg patterns)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_DisasmBack(
    NexusProcessHandle process,
    uint64_t address,
    int count,
    uint64_t* resultAddress
) {
    if (!process || !resultAddress || count < 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (count == 0) {
        *resultAddress = address;
        return NEXUS_OK;
    }

    /* Determine machine mode */
    NexusProcessInfo info;
    Nexus_GetProcessInfo(process, &info);
    ZydisMachineMode mode = info.is32Bit ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;

    /*
     * Algorithm: Look back by max_instruction_length * count bytes,
     * then disassemble forward, tracking instruction boundaries.
     * The instruction that ends at our target address is what we want.
     */
    const size_t MAX_INST_LEN = 15;
    const size_t lookbackSize = MAX_INST_LEN * (count + 16); /* Extra buffer for alignment */

    uint64_t startAddr = (address > lookbackSize) ? (address - lookbackSize) : 0;
    size_t bufSize = (size_t)(address - startAddr);

    if (bufSize == 0) {
        *resultAddress = address;
        return NEXUS_OK;
    }

    uint8_t* buffer = new uint8_t[bufSize];
    if (!buffer) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    size_t bytesRead = 0;
    NexusResult result = Nexus_ReadMemory(process, startAddr, buffer, bufSize, &bytesRead);
    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        delete[] buffer;
        return result;
    }

    /* Build list of instruction start addresses leading up to target */
    std::vector<uint64_t> instrAddrs;
    uint64_t currentAddr = startAddr;
    size_t offset = 0;

    while (offset < bytesRead && currentAddr < address) {
        instrAddrs.push_back(currentAddr);

        ZydisDisassembledInstruction zydisInst;
        ZyanStatus status = ZydisDisassembleIntel(mode, currentAddr, buffer + offset,
                                                   bytesRead - offset, &zydisInst);
        if (!ZYAN_SUCCESS(status)) {
            /* Can't decode - skip one byte */
            offset++;
            currentAddr++;
        } else {
            offset += zydisInst.info.length;
            currentAddr += zydisInst.info.length;
        }
    }

    delete[] buffer;

    /* Now find the instruction 'count' before target */
    if (instrAddrs.empty()) {
        *resultAddress = address;
        return NEXUS_OK;
    }

    int targetIdx = (int)instrAddrs.size() - count;
    if (targetIdx < 0) {
        targetIdx = 0;
    }

    *resultAddress = instrAddrs[targetIdx];
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DisasmNext(
    NexusProcessHandle process,
    uint64_t address,
    int count,
    uint64_t* resultAddress
) {
    if (!process || !resultAddress || count < 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (count == 0) {
        *resultAddress = address;
        return NEXUS_OK;
    }

    /* Determine machine mode */
    NexusProcessInfo info;
    Nexus_GetProcessInfo(process, &info);
    ZydisMachineMode mode = info.is32Bit ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;

    /* Read enough bytes for 'count' instructions (max 15 bytes each) */
    const size_t MAX_INST_LEN = 15;
    const size_t bufSize = MAX_INST_LEN * (count + 1);

    uint8_t* buffer = new uint8_t[bufSize];
    if (!buffer) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    size_t bytesRead = 0;
    NexusResult result = Nexus_ReadMemory(process, address, buffer, bufSize, &bytesRead);
    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        delete[] buffer;
        return result;
    }

    if (bytesRead == 0) {
        delete[] buffer;
        *resultAddress = address;
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Step forward through 'count' instructions */
    uint64_t currentAddr = address;
    size_t offset = 0;
    int stepped = 0;

    while (stepped < count && offset < bytesRead) {
        ZydisDisassembledInstruction zydisInst;
        ZyanStatus status = ZydisDisassembleIntel(mode, currentAddr, buffer + offset,
                                                   bytesRead - offset, &zydisInst);
        if (!ZYAN_SUCCESS(status)) {
            /* Can't decode - skip one byte */
            offset++;
            currentAddr++;
        } else {
            offset += zydisInst.info.length;
            currentAddr += zydisInst.info.length;
        }
        stepped++;
    }

    delete[] buffer;
    *resultAddress = currentAddr;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DisasmFast(
    NexusProcessHandle process,
    uint64_t address,
    uint8_t* length,
    int* isBranchOut,
    int* isCallOut,
    int* isReturnOut,
    uint64_t* branchTarget
) {
    if (!process || !length) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Read just enough for one instruction */
    uint8_t buffer[15];
    size_t bytesRead = 0;
    NexusResult result = Nexus_ReadMemory(process, address, buffer, 15, &bytesRead);
    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        return result;
    }

    if (bytesRead == 0) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Determine machine mode */
    NexusProcessInfo info;
    Nexus_GetProcessInfo(process, &info);
    ZydisMachineMode mode = info.is32Bit ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;

    /* Decode with minimal overhead (don't format text) */
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, mode,
                     info.is32Bit ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, buffer, bytesRead,
                                                &instruction, operands);
    if (!ZYAN_SUCCESS(status)) {
        *length = 1; /* Treat as single byte on failure */
        if (isBranchOut) *isBranchOut = 0;
        if (isCallOut) *isCallOut = 0;
        if (isReturnOut) *isReturnOut = 0;
        if (branchTarget) *branchTarget = 0;
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *length = instruction.length;

    if (isBranchOut) *isBranchOut = IsBranch(instruction.mnemonic) ? 1 : 0;
    if (isCallOut) *isCallOut = IsCall(instruction.mnemonic) ? 1 : 0;
    if (isReturnOut) *isReturnOut = IsReturn(instruction.mnemonic) ? 1 : 0;

    /* Calculate branch target */
    if (branchTarget) {
        *branchTarget = 0;
        if ((IsBranch(instruction.mnemonic) || IsCall(instruction.mnemonic)) &&
            instruction.operand_count > 0) {
            const ZydisDecodedOperand& firstOp = operands[0];
            if (firstOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && firstOp.imm.is_relative) {
                *branchTarget = address + instruction.length + firstOp.imm.value.s;
            }
        }
    }

    return NEXUS_OK;
}

} /* extern "C" */
