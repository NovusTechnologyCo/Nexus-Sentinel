/**
 * @file trace_classify.cpp
 * @brief Instruction classification for the trace logger.
 *
 * Classifies instructions as CALL, RET, conditional/unconditional branch,
 * computes branch-target addresses, provides instruction-length decoding,
 * and generates simplified disassembly text for trace entries.
 */

#include "trace_internal.h"

/* ============================================================================
 * Instruction Classification
 * ============================================================================ */

// Check if instruction is a CALL
bool IsCallInstruction(const uint8_t* bytes, size_t size) {
    if (size < 1) return false;

    // E8 xx xx xx xx - CALL rel32
    if (bytes[0] == 0xE8) return true;

    // FF /2 - CALL r/m
    if (bytes[0] == 0xFF && size >= 2) {
        uint8_t modrm = bytes[1];
        uint8_t reg = (modrm >> 3) & 7;
        if (reg == 2) return true;
    }

    // 9A - CALL far (16-bit mode, rare)
    if (bytes[0] == 0x9A) return true;

    return false;
}

// Check if instruction is a RET
bool IsRetInstruction(const uint8_t* bytes, size_t size) {
    if (size < 1) return false;

    // C3 - RET near
    // C2 xx xx - RET near imm16
    // CB - RETF
    // CA xx xx - RETF imm16
    return bytes[0] == 0xC3 || bytes[0] == 0xC2 ||
           bytes[0] == 0xCB || bytes[0] == 0xCA;
}

// Check if instruction is a conditional branch
bool IsBranchInstruction(const uint8_t* bytes, size_t size) {
    if (size < 1) return false;

    // Short conditional jumps: 70-7F
    if (bytes[0] >= 0x70 && bytes[0] <= 0x7F) return true;

    // Near conditional jumps: 0F 80-8F
    if (bytes[0] == 0x0F && size >= 2) {
        if (bytes[1] >= 0x80 && bytes[1] <= 0x8F) return true;
    }

    // LOOP/LOOPE/LOOPNE: E0-E2
    if (bytes[0] >= 0xE0 && bytes[0] <= 0xE2) return true;

    // JCXZ/JECXZ: E3
    if (bytes[0] == 0xE3) return true;

    return false;
}

// Get call/branch target address (simplified)
uint64_t GetTargetAddress(uint64_t rip, const uint8_t* bytes, size_t size) {
    if (size < 2) return 0;

    // E8 rel32 - CALL
    if (bytes[0] == 0xE8 && size >= 5) {
        int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
        return rip + 5 + offset;
    }

    // E9 rel32 - JMP
    if (bytes[0] == 0xE9 && size >= 5) {
        int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
        return rip + 5 + offset;
    }

    // EB rel8 - JMP short
    if (bytes[0] == 0xEB && size >= 2) {
        int8_t offset = static_cast<int8_t>(bytes[1]);
        return rip + 2 + offset;
    }

    // 70-7F rel8 - Jcc short
    if (bytes[0] >= 0x70 && bytes[0] <= 0x7F && size >= 2) {
        int8_t offset = static_cast<int8_t>(bytes[1]);
        return rip + 2 + offset;
    }

    // 0F 80-8F rel32 - Jcc near
    if (bytes[0] == 0x0F && size >= 6 && bytes[1] >= 0x80 && bytes[1] <= 0x8F) {
        int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[2]);
        return rip + 6 + offset;
    }

    return 0;
}

/* ============================================================================
 * Instruction Length Decoder
 * ============================================================================ */

// Get instruction length (simplified - handles common cases)
size_t TraceGetInstructionLength(const uint8_t* bytes, size_t maxLen, bool is64Bit) {
    if (maxLen < 1) return 0;

    size_t prefixLen = 0;

    // Skip prefixes
    while (prefixLen < maxLen && prefixLen < 4) {
        uint8_t b = bytes[prefixLen];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            prefixLen++;
        } else if (is64Bit && (b >= 0x40 && b <= 0x4F)) {
            // REX prefix
            prefixLen++;
            break;
        } else {
            break;
        }
    }

    if (prefixLen >= maxLen) return 1;

    uint8_t opcode = bytes[prefixLen];

    // Simple opcode length table for common instructions
    // NOP
    if (opcode == 0x90) return prefixLen + 1;

    // RET
    if (opcode == 0xC3 || opcode == 0xCB) return prefixLen + 1;
    if (opcode == 0xC2 || opcode == 0xCA) return prefixLen + 3;

    // PUSH/POP reg
    if ((opcode >= 0x50 && opcode <= 0x5F)) return prefixLen + 1;

    // MOV imm to reg
    if (opcode >= 0xB0 && opcode <= 0xB7) return prefixLen + 2;
    if (opcode >= 0xB8 && opcode <= 0xBF) return prefixLen + (is64Bit ? 9 : 5);

    // CALL/JMP rel32
    if (opcode == 0xE8 || opcode == 0xE9) return prefixLen + 5;

    // JMP short
    if (opcode == 0xEB) return prefixLen + 2;

    // Jcc short
    if (opcode >= 0x70 && opcode <= 0x7F) return prefixLen + 2;

    // INT3
    if (opcode == 0xCC) return prefixLen + 1;

    // Two-byte opcode
    if (opcode == 0x0F && prefixLen + 1 < maxLen) {
        uint8_t opcode2 = bytes[prefixLen + 1];

        // Jcc near
        if (opcode2 >= 0x80 && opcode2 <= 0x8F) return prefixLen + 6;

        // MOVZX/MOVSX
        if (opcode2 == 0xB6 || opcode2 == 0xB7 || opcode2 == 0xBE || opcode2 == 0xBF) {
            return prefixLen + 3; // Simplified
        }
    }

    // Default: assume ModR/M byte present for safety
    return prefixLen + 2;
}

/* ============================================================================
 * Disassembly
 * ============================================================================ */

// Simple disassembly placeholder
void DisassembleInstruction(uint64_t address, const uint8_t* bytes,
                            size_t size, char* output, size_t outputSize) {
    if (size == 0 || outputSize < 20) {
        output[0] = '\0';
        return;
    }

    // Common single-byte opcodes
    if (bytes[0] == 0x90) {
        strncpy_s(output, outputSize, "nop", _TRUNCATE);
        return;
    }
    if (bytes[0] == 0xC3) {
        strncpy_s(output, outputSize, "ret", _TRUNCATE);
        return;
    }
    if (bytes[0] == 0xCC) {
        strncpy_s(output, outputSize, "int3", _TRUNCATE);
        return;
    }

    // PUSH reg
    if (bytes[0] >= 0x50 && bytes[0] <= 0x57) {
        const char* regs[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
        snprintf(output, outputSize, "push %s", regs[bytes[0] - 0x50]);
        return;
    }

    // POP reg
    if (bytes[0] >= 0x58 && bytes[0] <= 0x5F) {
        const char* regs[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
        snprintf(output, outputSize, "pop %s", regs[bytes[0] - 0x58]);
        return;
    }

    // CALL rel32
    if (bytes[0] == 0xE8 && size >= 5) {
        int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
        snprintf(output, outputSize, "call 0x%llX", address + 5 + offset);
        return;
    }

    // JMP rel32
    if (bytes[0] == 0xE9 && size >= 5) {
        int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
        snprintf(output, outputSize, "jmp 0x%llX", address + 5 + offset);
        return;
    }

    // Default: show hex bytes
    char* p = output;
    size_t remaining = outputSize;
    for (size_t i = 0; i < size && i < 8 && remaining > 3; i++) {
        int written = snprintf(p, remaining, "%02X ", bytes[i]);
        if (written > 0) {
            p += written;
            remaining -= written;
        }
    }
    if (p > output) p[-1] = '\0'; // Remove trailing space
}
