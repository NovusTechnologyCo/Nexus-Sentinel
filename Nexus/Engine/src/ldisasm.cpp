/**
 * @file ldisasm.cpp
 * @brief Minimal x86/x64 length disassembler engine (LDE).
 *
 * Determines the byte length of an x86/x64 instruction by decoding
 * prefixes, opcode maps (1/2/3-byte), ModR/M, SIB, and displacement/
 * immediate fields.  Does not produce a full decode; only the length
 * is needed for copying whole instructions into hook trampolines.
 *
 * Based on common open-source LDE implementations.
 */

#include <cstdint>
#include <cstddef>

// Instruction flags
#define F_MODRM     0x01
#define F_SIB       0x02
#define F_DISP8     0x04
#define F_DISP32    0x08
#define F_IMM8      0x10
#define F_IMM16     0x20
#define F_IMM32     0x40
#define F_IMM64     0x80
#define F_RELATIVE  0x100

// Prefix flags
#define P_LOCK      0x01
#define P_REPNE     0x02
#define P_REP       0x04
#define P_SEG       0x08
#define P_66        0x10
#define P_67        0x20
#define P_REX       0x40

// ModR/M byte helpers
#define MODRM_MOD(b) (((b) >> 6) & 0x03)
#define MODRM_REG(b) (((b) >> 3) & 0x07)
#define MODRM_RM(b)  ((b) & 0x07)

// SIB byte helpers
#define SIB_BASE(b)  ((b) & 0x07)

// One-byte opcode flags (simplified - covers most common instructions)
static const uint16_t g_opcodeFlags[256] = {
    // 0x00-0x0F: ADD, OR, etc.
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    // 0x10-0x1F: ADC, SBB, etc.
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    // 0x20-0x2F: AND, SUB, etc.
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    // 0x30-0x3F: XOR, CMP, etc.
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM32, 0, 0,
    // 0x40-0x4F: INC/DEC (32-bit) or REX prefixes (64-bit)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x50-0x5F: PUSH/POP
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0x60-0x6F
    0, 0, F_MODRM, F_MODRM, 0, 0, 0, 0,
    F_IMM32, F_MODRM | F_IMM32, F_IMM8, F_MODRM | F_IMM8, 0, 0, 0, 0,
    // 0x70-0x7F: Jcc short
    F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE,
    F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE,
    F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE,
    F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE,
    // 0x80-0x8F
    F_MODRM | F_IMM8, F_MODRM | F_IMM32, F_MODRM | F_IMM8, F_MODRM | F_IMM8,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x90-0x9F: NOP, XCHG, etc.
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, F_IMM32 | F_IMM16, 0, 0, 0, 0, 0,
    // 0xA0-0xAF: MOV, TEST, STOS, etc.
    F_IMM32, F_IMM32, F_IMM32, F_IMM32, 0, 0, 0, 0,
    F_IMM8, F_IMM32, 0, 0, 0, 0, 0, 0,
    // 0xB0-0xBF: MOV imm
    F_IMM8, F_IMM8, F_IMM8, F_IMM8, F_IMM8, F_IMM8, F_IMM8, F_IMM8,
    F_IMM32, F_IMM32, F_IMM32, F_IMM32, F_IMM32, F_IMM32, F_IMM32, F_IMM32,
    // 0xC0-0xCF
    F_MODRM | F_IMM8, F_MODRM | F_IMM8, F_IMM16, 0,
    F_MODRM, F_MODRM, F_MODRM | F_IMM8, F_MODRM | F_IMM32,
    F_IMM16 | F_IMM8, 0, F_IMM16, 0, 0, F_IMM8, 0, 0,
    // 0xD0-0xDF
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_IMM8, F_IMM8, 0, 0,
    // x87 FPU - all have ModR/M
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0xE0-0xEF
    F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE, F_IMM8 | F_RELATIVE,
    F_IMM8, F_IMM8, F_IMM8, F_IMM8,
    F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_IMM16, F_IMM8 | F_RELATIVE,
    0, 0, 0, 0,
    // 0xF0-0xFF
    0, 0, 0, 0, 0, 0, F_MODRM, F_MODRM,
    0, 0, 0, 0, 0, 0, F_MODRM, F_MODRM,
};

// Two-byte opcode flags (0F xx)
static const uint16_t g_opcodeFlags0F[256] = {
    // 0x00-0x0F
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, 0, 0, 0, 0,
    0, 0, 0, 0, 0, F_MODRM, 0, 0,
    // 0x10-0x1F: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x20-0x2F
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, 0, 0, 0, 0,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x30-0x3F
    0, 0, 0, 0, 0, 0, 0, 0, F_MODRM, 0, F_MODRM, 0, 0, 0, 0, 0,
    // 0x40-0x4F: CMOVcc
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x50-0x5F: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x60-0x6F: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x70-0x7F: SSE
    F_MODRM | F_IMM8, F_MODRM | F_IMM8, F_MODRM | F_IMM8, F_MODRM | F_IMM8,
    F_MODRM, F_MODRM, F_MODRM, 0,
    F_MODRM, F_MODRM, 0, 0, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0x80-0x8F: Jcc near
    F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE,
    F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE,
    F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE,
    F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE, F_IMM32 | F_RELATIVE,
    // 0x90-0x9F: SETcc
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0xA0-0xAF
    0, 0, 0, F_MODRM, F_MODRM | F_IMM8, F_MODRM, 0, 0,
    0, 0, 0, F_MODRM, F_MODRM | F_IMM8, F_MODRM, F_MODRM, F_MODRM,
    // 0xB0-0xBF
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, 0, F_MODRM | F_IMM8, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0xC0-0xCF
    F_MODRM, F_MODRM, F_MODRM | F_IMM8, F_MODRM, F_MODRM | F_IMM8, F_MODRM | F_IMM8, F_MODRM | F_IMM8, F_MODRM,
    0, 0, 0, 0, 0, 0, 0, 0,
    // 0xD0-0xDF: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0xE0-0xEF: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    // 0xF0-0xFF: SSE
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM,
    F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, F_MODRM, 0,
};

/**
 * Get the length of a single x86/x64 instruction.
 *
 * @param code Pointer to the instruction bytes
 * @param is64Bit True for 64-bit mode, false for 32-bit
 * @return Instruction length in bytes, or 0 on error
 */
extern "C" size_t GetInstructionLength(const uint8_t* code, bool is64Bit) {
    if (!code) return 0;

    const uint8_t* p = code;
    uint32_t prefixes = 0;
    bool hasRex = false;
    bool operandSize16 = false;
    bool addressSize16 = false;

    // Parse prefixes
    while (true) {
        uint8_t b = *p;

        // Legacy prefixes
        if (b == 0xF0) { prefixes |= P_LOCK; p++; continue; }
        if (b == 0xF2) { prefixes |= P_REPNE; p++; continue; }
        if (b == 0xF3) { prefixes |= P_REP; p++; continue; }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { prefixes |= P_SEG; p++; continue; }
        if (b == 0x66) { prefixes |= P_66; operandSize16 = true; p++; continue; }
        if (b == 0x67) { prefixes |= P_67; addressSize16 = true; p++; continue; }

        // REX prefixes (64-bit only)
        if (is64Bit && (b >= 0x40 && b <= 0x4F)) {
            hasRex = true;
            prefixes |= P_REX;
            p++;
            continue;
        }

        break;
    }

    size_t prefixLen = p - code;

    // Get opcode
    uint8_t opcode = *p++;
    uint16_t flags;
    bool isTwoByteOpcode = false;

    if (opcode == 0x0F) {
        // Two-byte opcode
        isTwoByteOpcode = true;
        opcode = *p++;
        flags = g_opcodeFlags0F[opcode];
    } else {
        flags = g_opcodeFlags[opcode];
    }

    size_t length = p - code;

    // Handle ModR/M byte
    if (flags & F_MODRM) {
        uint8_t modrm = *p++;
        length++;

        uint8_t mod = MODRM_MOD(modrm);
        uint8_t rm = MODRM_RM(modrm);

        // Determine addressing mode size (32-bit vs 16-bit)
        bool addr32 = is64Bit ? !addressSize16 : !addressSize16;

        if (addr32) {
            // 32-bit addressing
            if (mod != 3) {
                // Not register-direct
                if (rm == 4) {
                    // SIB byte present
                    uint8_t sib = *p++;
                    length++;

                    if (mod == 0 && SIB_BASE(sib) == 5) {
                        // disp32
                        length += 4;
                        p += 4;
                    }
                }

                if (mod == 0 && rm == 5) {
                    // disp32 (or RIP-relative in 64-bit)
                    length += 4;
                    p += 4;
                } else if (mod == 1) {
                    // disp8
                    length++;
                    p++;
                } else if (mod == 2) {
                    // disp32
                    length += 4;
                    p += 4;
                }
            }
        } else {
            // 16-bit addressing (rare)
            if (mod == 0 && rm == 6) {
                length += 2;
                p += 2;
            } else if (mod == 1) {
                length++;
                p++;
            } else if (mod == 2) {
                length += 2;
                p += 2;
            }
        }
    }

    // Handle immediate operands
    bool operand64 = is64Bit && hasRex && (code[prefixLen] >= 0x40 && (code[prefixLen] & 0x08));

    if (flags & F_IMM8) {
        length++;
    }
    if (flags & F_IMM16) {
        length += 2;
    }
    if (flags & F_IMM32) {
        // In 64-bit mode with REX.W, some instructions use 64-bit immediate
        if (operand64 && !isTwoByteOpcode && (opcode >= 0xB8 && opcode <= 0xBF)) {
            length += 8; // MOV r64, imm64
        } else if (operandSize16) {
            length += 2;
        } else {
            length += 4;
        }
    }
    if (flags & F_IMM64) {
        length += 8;
    }

    // Sanity check - instructions shouldn't be longer than 15 bytes
    if (length > 15) {
        return 0;
    }

    return length;
}

/**
 * Calculate minimum bytes needed to copy for a hook.
 * Ensures we copy complete instructions.
 *
 * @param code Pointer to the code to analyze
 * @param minBytes Minimum number of bytes needed for the hook jump
 * @param is64Bit True for 64-bit code
 * @return Number of bytes to copy (>= minBytes), or 0 on error
 */
extern "C" size_t GetHookSize(const uint8_t* code, size_t minBytes, bool is64Bit) {
    if (!code || minBytes == 0) return 0;

    size_t total = 0;
    const uint8_t* p = code;

    while (total < minBytes) {
        size_t len = GetInstructionLength(p, is64Bit);
        if (len == 0) {
            // Failed to decode instruction
            return 0;
        }
        total += len;
        p += len;

        // Safety limit
        if (total > 32) {
            return 0;
        }
    }

    return total;
}
