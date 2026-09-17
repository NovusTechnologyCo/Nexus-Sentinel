/**
 * @file disasm_flow.cpp
 * @brief Thread-safe disassembler context and flow-control analysis.
 *
 * Provides per-instance Zydis decoder/formatter pairs for lock-free
 * concurrent disassembly, plus detailed flow-control classification
 * (branch type, condition code, target address) and RFLAGS-based
 * branch prediction for conditional jumps and LOOP instructions.
 *
 * Core disassembly routines live in disasm.cpp.
 */

#include "disasm_internal.h"

/* ============================================================================
 * Thread-Safe Disassembler Context Implementation
 * ============================================================================ */

/* Internal context structure */
struct NexusDisasmContext {
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    NexusMachineMode mode;
    NexusDisasmSyntax syntax;
    bool initialized;
};

extern "C" {

NEXUS_API NexusResult Nexus_DisasmCreateContext(
    NexusMachineMode mode,
    NexusDisasmSyntax syntax,
    NexusDisasmContextHandle* context
) {
    if (!context) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusDisasmContext* ctx = new (std::nothrow) NexusDisasmContext();
    if (!ctx) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    ctx->mode = mode;
    ctx->syntax = syntax;
    ctx->initialized = false;

    /* Initialize decoder */
    ZydisMachineMode machineMode = ConvertMachineMode(mode);
    ZydisStackWidth stackWidth = (mode == NEXUS_MODE_LONG_64)
        ? ZYDIS_STACK_WIDTH_64
        : ZYDIS_STACK_WIDTH_32;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&ctx->decoder, machineMode, stackWidth))) {
        delete ctx;
        return NEXUS_ERROR_UNKNOWN;
    }

    /* Initialize formatter */
    ZydisFormatterStyle style = (syntax == NEXUS_SYNTAX_ATT)
        ? ZYDIS_FORMATTER_STYLE_ATT
        : ZYDIS_FORMATTER_STYLE_INTEL;

    if (!ZYAN_SUCCESS(ZydisFormatterInit(&ctx->formatter, style))) {
        delete ctx;
        return NEXUS_ERROR_UNKNOWN;
    }

    ctx->initialized = true;
    *context = ctx;
    return NEXUS_OK;
}

NEXUS_API void Nexus_DisasmDestroyContext(NexusDisasmContextHandle context) {
    if (context) {
        delete context;
    }
}

NEXUS_API NexusResult Nexus_DisasmDecodeWithContext(
    NexusDisasmContextHandle context,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusDisasmInstruction* instruction
) {
    if (!context || !buffer || !instruction) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (!context->initialized) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    ZydisDecodedInstruction decodedInst;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    ZyanStatus status = ZydisDecoderDecodeFull(
        &context->decoder,
        buffer,
        bufferSize,
        &decodedInst,
        operands
    );

    if (!ZYAN_SUCCESS(status)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Clear output */
    memset(instruction, 0, sizeof(NexusDisasmInstruction));

    instruction->address = address;
    instruction->length = (uint8_t)decodedInst.length;

    /* Copy instruction bytes */
    size_t copyLen = std::min((size_t)decodedInst.length, sizeof(instruction->bytes));
    memcpy(instruction->bytes, buffer, copyLen);

    /* Format instruction text */
    char textBuffer[128];
    status = ZydisFormatterFormatInstruction(
        &context->formatter,
        &decodedInst,
        operands,
        decodedInst.operand_count,
        textBuffer,
        sizeof(textBuffer),
        address,
        ZYAN_NULL
    );

    if (ZYAN_SUCCESS(status)) {
        strncpy_s(instruction->text, sizeof(instruction->text), textBuffer, _TRUNCATE);

        /* Extract mnemonic */
        const char* space = strchr(textBuffer, ' ');
        if (space) {
            size_t mnemonicLen = space - textBuffer;
            if (mnemonicLen < sizeof(instruction->mnemonic)) {
                strncpy_s(instruction->mnemonic, sizeof(instruction->mnemonic), textBuffer, mnemonicLen);
            }
        } else {
            strncpy_s(instruction->mnemonic, sizeof(instruction->mnemonic), textBuffer, _TRUNCATE);
        }
    }

    /* Fill operands */
    instruction->operandCount = 0;
    for (int i = 0; i < decodedInst.operand_count && i < 5; i++) {
        const ZydisDecodedOperand& op = operands[i];

        if (op.type == ZYDIS_OPERAND_TYPE_UNUSED) break;
        if (op.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
            op.visibility == ZYDIS_OPERAND_VISIBILITY_IMPLICIT) {
            continue;
        }

        NexusDisasmOperand& outOp = instruction->operands[instruction->operandCount];
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
        instruction->operandCount++;
    }

    /* Set flags */
    instruction->isBranch = IsBranch(decodedInst.mnemonic) ? 1 : 0;
    instruction->isCall = IsCall(decodedInst.mnemonic) ? 1 : 0;
    instruction->isReturn = IsReturn(decodedInst.mnemonic) ? 1 : 0;
    instruction->isConditional = IsConditional(decodedInst.mnemonic) ? 1 : 0;

    /* Calculate branch target */
    if ((instruction->isBranch || instruction->isCall) && decodedInst.operand_count > 0) {
        const ZydisDecodedOperand& firstOp = operands[0];
        if (firstOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && firstOp.imm.is_relative) {
            instruction->branchTarget = address + decodedInst.length + firstOp.imm.value.s;
        }
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Flow Control Analysis Implementation
 * ============================================================================ */

/* Get detailed flow control type from mnemonic */
static NexusFlowControlType GetFlowControlType(ZydisMnemonic mnemonic, bool* isConditionalOut, bool* isIndirectOut) {
    *isConditionalOut = false;
    *isIndirectOut = false;

    switch (mnemonic) {
        /* Unconditional jumps */
        case ZYDIS_MNEMONIC_JMP:
            return NEXUS_FLOW_UNCONDITIONAL_JMP;

        /* Conditional jumps */
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
            *isConditionalOut = true;
            return NEXUS_FLOW_CONDITIONAL_JMP;

        /* Call */
        case ZYDIS_MNEMONIC_CALL:
            return NEXUS_FLOW_CALL;

        /* Returns */
        case ZYDIS_MNEMONIC_RET:
            *isIndirectOut = true;
            return NEXUS_FLOW_RET;

        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
            *isIndirectOut = true;
            return NEXUS_FLOW_IRET;

        /* System calls */
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
            return NEXUS_FLOW_SYSCALL;

        case ZYDIS_MNEMONIC_SYSRET:
        case ZYDIS_MNEMONIC_SYSEXIT:
            *isIndirectOut = true;
            return NEXUS_FLOW_SYSRET;

        /* Interrupts */
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
            return NEXUS_FLOW_INT;

        /* Loops */
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
            *isConditionalOut = true;
            return NEXUS_FLOW_LOOP;

        /* Transactional memory */
        case ZYDIS_MNEMONIC_XBEGIN:
            *isConditionalOut = true;
            return NEXUS_FLOW_XBEGIN;

        case ZYDIS_MNEMONIC_XABORT:
            return NEXUS_FLOW_XABORT;

        default:
            return NEXUS_FLOW_NONE;
    }
}

/* Map Zydis mnemonic to condition code for branch prediction */
static uint32_t GetConditionCode(ZydisMnemonic mnemonic) {
    switch (mnemonic) {
        case ZYDIS_MNEMONIC_JO:  return 0;   /* Overflow */
        case ZYDIS_MNEMONIC_JNO: return 1;   /* Not overflow */
        case ZYDIS_MNEMONIC_JB:  return 2;   /* Below (CF=1) */
        case ZYDIS_MNEMONIC_JNB: return 3;   /* Not below (CF=0) */
        case ZYDIS_MNEMONIC_JZ:  return 4;   /* Zero (ZF=1) */
        case ZYDIS_MNEMONIC_JNZ: return 5;   /* Not zero (ZF=0) */
        case ZYDIS_MNEMONIC_JBE: return 6;   /* Below or equal */
        case ZYDIS_MNEMONIC_JNBE: return 7;  /* Not below or equal */
        case ZYDIS_MNEMONIC_JS:  return 8;   /* Sign (SF=1) */
        case ZYDIS_MNEMONIC_JNS: return 9;   /* Not sign (SF=0) */
        case ZYDIS_MNEMONIC_JP:  return 10;  /* Parity (PF=1) */
        case ZYDIS_MNEMONIC_JNP: return 11;  /* Not parity (PF=0) */
        case ZYDIS_MNEMONIC_JL:  return 12;  /* Less (SF!=OF) */
        case ZYDIS_MNEMONIC_JNL: return 13;  /* Not less (SF=OF) */
        case ZYDIS_MNEMONIC_JLE: return 14;  /* Less or equal */
        case ZYDIS_MNEMONIC_JNLE: return 15; /* Not less or equal */
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ: return 16; /* CX/ECX/RCX zero */
        case ZYDIS_MNEMONIC_LOOP:  return 17; /* Loop */
        case ZYDIS_MNEMONIC_LOOPE: return 18; /* Loop while equal */
        case ZYDIS_MNEMONIC_LOOPNE: return 19; /* Loop while not equal */
        default: return 0xFF;
    }
}

NEXUS_API NexusResult Nexus_DisasmGetFlowControl(
    NexusDisasmContextHandle context,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusFlowControlInfo* flowInfo
) {
    if (!buffer || !flowInfo) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(flowInfo, 0, sizeof(NexusFlowControlInfo));

    /* Decode instruction */
    ZydisDecodedInstruction decodedInst;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status;

    if (context && context->initialized) {
        status = ZydisDecoderDecodeFull(
            &context->decoder,
            buffer,
            bufferSize,
            &decodedInst,
            operands
        );
    } else {
        /* Use default 64-bit decoder */
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        status = ZydisDecoderDecodeFull(&decoder, buffer, bufferSize, &decodedInst, operands);
    }

    if (!ZYAN_SUCCESS(status)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Determine flow control type */
    bool isConditionalVal, isIndirectVal;
    flowInfo->type = GetFlowControlType(decodedInst.mnemonic, &isConditionalVal, &isIndirectVal);
    flowInfo->isConditional = isConditionalVal ? 1 : 0;
    flowInfo->isIndirect = isIndirectVal ? 1 : 0;
    flowInfo->fallthrough = address + decodedInst.length;
    flowInfo->conditionCode = GetConditionCode(decodedInst.mnemonic);

    /* Calculate target address */
    if (flowInfo->type != NEXUS_FLOW_NONE && decodedInst.operand_count > 0) {
        const ZydisDecodedOperand& firstOp = operands[0];

        if (firstOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (firstOp.imm.is_relative) {
                flowInfo->targetAddress = address + decodedInst.length + firstOp.imm.value.s;
            } else {
                flowInfo->targetAddress = firstOp.imm.value.u;
            }
        } else if (firstOp.type == ZYDIS_OPERAND_TYPE_REGISTER ||
                   firstOp.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            flowInfo->isIndirect = 1;
            flowInfo->targetAddress = 0; /* Cannot determine statically */
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DisasmGetFlowControlFromInstruction(
    const NexusDisasmInstruction* instruction,
    NexusFlowControlInfo* flowInfo
) {
    if (!instruction || !flowInfo) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Use the bytes from the instruction to analyze */
    return Nexus_DisasmGetFlowControl(
        nullptr,
        instruction->address,
        instruction->bytes,
        instruction->length,
        flowInfo
    );
}

/* RFLAGS bit positions */
#define RFLAGS_CF (1ULL << 0)   /* Carry flag */
#define RFLAGS_PF (1ULL << 2)   /* Parity flag */
#define RFLAGS_ZF (1ULL << 6)   /* Zero flag */
#define RFLAGS_SF (1ULL << 7)   /* Sign flag */
#define RFLAGS_OF (1ULL << 11)  /* Overflow flag */

NEXUS_API NexusResult Nexus_DisasmWillBranchExecute(
    const NexusDisasmInstruction* instruction,
    uint64_t rflags,
    uint64_t rcx,
    NexusBranchPrediction* prediction
) {
    if (!instruction || !prediction) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *prediction = NEXUS_BRANCH_UNKNOWN;

    /* Must be a branch or call instruction */
    if (!instruction->isBranch && !instruction->isCall && !instruction->isReturn) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Unconditional branches always taken */
    if (!instruction->isConditional) {
        *prediction = NEXUS_BRANCH_ALWAYS;
        return NEXUS_OK;
    }

    /* Extract flags */
    bool cf = (rflags & RFLAGS_CF) != 0;
    bool pf = (rflags & RFLAGS_PF) != 0;
    bool zf = (rflags & RFLAGS_ZF) != 0;
    bool sf = (rflags & RFLAGS_SF) != 0;
    bool of = (rflags & RFLAGS_OF) != 0;

    /* Get the mnemonic to determine condition */
    const char* mnemonic = instruction->mnemonic;
    bool taken = false;

    /* Compare mnemonic strings to determine branch type */
    if (strcmp(mnemonic, "jo") == 0 || strcmp(mnemonic, "JO") == 0) {
        taken = of;
    } else if (strcmp(mnemonic, "jno") == 0 || strcmp(mnemonic, "JNO") == 0) {
        taken = !of;
    } else if (strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "JB") == 0 ||
               strcmp(mnemonic, "jc") == 0 || strcmp(mnemonic, "JC") == 0 ||
               strcmp(mnemonic, "jnae") == 0 || strcmp(mnemonic, "JNAE") == 0) {
        taken = cf;
    } else if (strcmp(mnemonic, "jnb") == 0 || strcmp(mnemonic, "JNB") == 0 ||
               strcmp(mnemonic, "jnc") == 0 || strcmp(mnemonic, "JNC") == 0 ||
               strcmp(mnemonic, "jae") == 0 || strcmp(mnemonic, "JAE") == 0) {
        taken = !cf;
    } else if (strcmp(mnemonic, "jz") == 0 || strcmp(mnemonic, "JZ") == 0 ||
               strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "JE") == 0) {
        taken = zf;
    } else if (strcmp(mnemonic, "jnz") == 0 || strcmp(mnemonic, "JNZ") == 0 ||
               strcmp(mnemonic, "jne") == 0 || strcmp(mnemonic, "JNE") == 0) {
        taken = !zf;
    } else if (strcmp(mnemonic, "jbe") == 0 || strcmp(mnemonic, "JBE") == 0 ||
               strcmp(mnemonic, "jna") == 0 || strcmp(mnemonic, "JNA") == 0) {
        taken = cf || zf;
    } else if (strcmp(mnemonic, "jnbe") == 0 || strcmp(mnemonic, "JNBE") == 0 ||
               strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "JA") == 0) {
        taken = !cf && !zf;
    } else if (strcmp(mnemonic, "js") == 0 || strcmp(mnemonic, "JS") == 0) {
        taken = sf;
    } else if (strcmp(mnemonic, "jns") == 0 || strcmp(mnemonic, "JNS") == 0) {
        taken = !sf;
    } else if (strcmp(mnemonic, "jp") == 0 || strcmp(mnemonic, "JP") == 0 ||
               strcmp(mnemonic, "jpe") == 0 || strcmp(mnemonic, "JPE") == 0) {
        taken = pf;
    } else if (strcmp(mnemonic, "jnp") == 0 || strcmp(mnemonic, "JNP") == 0 ||
               strcmp(mnemonic, "jpo") == 0 || strcmp(mnemonic, "JPO") == 0) {
        taken = !pf;
    } else if (strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "JL") == 0 ||
               strcmp(mnemonic, "jnge") == 0 || strcmp(mnemonic, "JNGE") == 0) {
        taken = sf != of;
    } else if (strcmp(mnemonic, "jnl") == 0 || strcmp(mnemonic, "JNL") == 0 ||
               strcmp(mnemonic, "jge") == 0 || strcmp(mnemonic, "JGE") == 0) {
        taken = sf == of;
    } else if (strcmp(mnemonic, "jle") == 0 || strcmp(mnemonic, "JLE") == 0 ||
               strcmp(mnemonic, "jng") == 0 || strcmp(mnemonic, "JNG") == 0) {
        taken = zf || (sf != of);
    } else if (strcmp(mnemonic, "jnle") == 0 || strcmp(mnemonic, "JNLE") == 0 ||
               strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "JG") == 0) {
        taken = !zf && (sf == of);
    } else if (strcmp(mnemonic, "jcxz") == 0 || strcmp(mnemonic, "JCXZ") == 0 ||
               strcmp(mnemonic, "jecxz") == 0 || strcmp(mnemonic, "JECXZ") == 0 ||
               strcmp(mnemonic, "jrcxz") == 0 || strcmp(mnemonic, "JRCXZ") == 0) {
        taken = (rcx == 0);
    } else if (strcmp(mnemonic, "loop") == 0 || strcmp(mnemonic, "LOOP") == 0) {
        taken = (rcx != 1); /* Loop decrements then tests */
    } else if (strcmp(mnemonic, "loope") == 0 || strcmp(mnemonic, "LOOPE") == 0 ||
               strcmp(mnemonic, "loopz") == 0 || strcmp(mnemonic, "LOOPZ") == 0) {
        taken = (rcx != 1) && zf;
    } else if (strcmp(mnemonic, "loopne") == 0 || strcmp(mnemonic, "LOOPNE") == 0 ||
               strcmp(mnemonic, "loopnz") == 0 || strcmp(mnemonic, "LOOPNZ") == 0) {
        taken = (rcx != 1) && !zf;
    } else {
        /* Unknown conditional - return unknown */
        return NEXUS_OK;
    }

    *prediction = taken ? NEXUS_BRANCH_TAKEN : NEXUS_BRANCH_NOT_TAKEN;
    return NEXUS_OK;
}

} /* extern "C" */
