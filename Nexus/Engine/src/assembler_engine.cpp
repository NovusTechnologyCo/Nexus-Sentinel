/**
 * @file assembler_engine.cpp
 * @brief x86/x64 instruction encoding engine.
 *
 * Contains opcode encoding tables, register name parsing, operand parsing,
 * ModR/M and SIB byte generation, immediate/displacement encoding, and the
 * core single-instruction assembler that converts a mnemonic + operands
 * into machine code at a given virtual address.
 *
 * The AA script parser is in assembler_script.cpp; public API in assembler.cpp.
 */

#include "assembler_internal.h"

// ============================================================================
// x86/x64 Instruction Encoding Tables
// ============================================================================

// Register encoding for ModR/M
enum class Reg8 : uint8_t { AL=0, CL=1, DL=2, BL=3, AH=4, CH=5, DH=6, BH=7, SPL=4, BPL=5, SIL=6, DIL=7, R8B=8, R9B=9, R10B=10, R11B=11, R12B=12, R13B=13, R14B=14, R15B=15 };
enum class Reg16 : uint8_t { AX=0, CX=1, DX=2, BX=3, SP=4, BP=5, SI=6, DI=7, R8W=8, R9W=9, R10W=10, R11W=11, R12W=12, R13W=13, R14W=14, R15W=15 };
enum class Reg32 : uint8_t { EAX=0, ECX=1, EDX=2, EBX=3, ESP=4, EBP=5, ESI=6, EDI=7, R8D=8, R9D=9, R10D=10, R11D=11, R12D=12, R13D=13, R14D=14, R15D=15 };
enum class Reg64 : uint8_t { RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8=8, R9=9, R10=10, R11=11, R12=12, R13=13, R14=14, R15=15 };

// Opcode table entry
struct OpcodeEntry {
    const char* mnemonic;
    uint8_t opcode[4];         // Up to 4-byte opcode
    uint8_t opcodeLen;
    uint8_t modrmReg;          // /r value for ModR/M (0xFF = use operand)
    OperandType op1Type;
    OperandType op2Type;
    bool hasModRM;
    bool hasImm;
    uint8_t immSize;           // 0, 1, 2, 4, 8
    bool is64BitDefault;       // Default 64-bit operand size
};

// Common x86/x64 opcodes (subset for basic operations)
static const OpcodeEntry g_opcodes[] = {
    // NOP
    {"nop", {0x90}, 1, 0xFF, OperandType::None, OperandType::None, false, false, 0, false},

    // RET
    {"ret", {0xC3}, 1, 0xFF, OperandType::None, OperandType::None, false, false, 0, false},
    {"retn", {0xC3}, 1, 0xFF, OperandType::None, OperandType::None, false, false, 0, false},

    // PUSH/POP (reg32/64)
    {"push", {0x50}, 1, 0xFF, OperandType::Reg64, OperandType::None, false, false, 0, true},
    {"pop", {0x58}, 1, 0xFF, OperandType::Reg64, OperandType::None, false, false, 0, true},

    // MOV r32, imm32
    {"mov", {0xB8}, 1, 0xFF, OperandType::Reg32, OperandType::Imm32, false, true, 4, false},
    // MOV r64, imm64
    {"mov", {0xB8}, 1, 0xFF, OperandType::Reg64, OperandType::Imm64, false, true, 8, false},
    // MOV r/m32, r32
    {"mov", {0x89}, 1, 0xFF, OperandType::Mem32, OperandType::Reg32, true, false, 0, false},
    // MOV r32, r/m32
    {"mov", {0x8B}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    // MOV r64, r/m64
    {"mov", {0x8B}, 1, 0xFF, OperandType::Reg64, OperandType::Mem64, true, false, 0, false},

    // ADD r32, r/m32
    {"add", {0x03}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    // ADD r/m32, imm32
    {"add", {0x81}, 1, 0, OperandType::Mem32, OperandType::Imm32, true, true, 4, false},
    // ADD r32, imm32
    {"add", {0x81}, 1, 0, OperandType::Reg32, OperandType::Imm32, true, true, 4, false},

    // SUB r32, r/m32
    {"sub", {0x2B}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    // SUB r/m32, imm32
    {"sub", {0x81}, 1, 5, OperandType::Mem32, OperandType::Imm32, true, true, 4, false},

    // XOR r32, r/m32
    {"xor", {0x33}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    {"xor", {0x33}, 1, 0xFF, OperandType::Reg32, OperandType::Reg32, true, false, 0, false},

    // AND r32, r/m32
    {"and", {0x23}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},

    // OR r32, r/m32
    {"or", {0x0B}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},

    // CMP r32, r/m32
    {"cmp", {0x3B}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    // CMP r/m32, imm32
    {"cmp", {0x81}, 1, 7, OperandType::Mem32, OperandType::Imm32, true, true, 4, false},

    // TEST r32, r/m32
    {"test", {0x85}, 1, 0xFF, OperandType::Mem32, OperandType::Reg32, true, false, 0, false},

    // JMP rel32
    {"jmp", {0xE9}, 1, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    // JMP rel8
    {"jmp", {0xEB}, 1, 0xFF, OperandType::Rel8, OperandType::None, false, true, 1, false},

    // CALL rel32
    {"call", {0xE8}, 1, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},

    // Conditional jumps (rel32)
    {"je", {0x0F, 0x84}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jz", {0x0F, 0x84}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jne", {0x0F, 0x85}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jnz", {0x0F, 0x85}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jg", {0x0F, 0x8F}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jge", {0x0F, 0x8D}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jl", {0x0F, 0x8C}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jle", {0x0F, 0x8E}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"ja", {0x0F, 0x87}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jae", {0x0F, 0x83}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jb", {0x0F, 0x82}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},
    {"jbe", {0x0F, 0x86}, 2, 0xFF, OperandType::Rel32, OperandType::None, false, true, 4, false},

    // LEA
    {"lea", {0x8D}, 1, 0xFF, OperandType::Reg32, OperandType::Mem32, true, false, 0, false},
    {"lea", {0x8D}, 1, 0xFF, OperandType::Reg64, OperandType::Mem64, true, false, 0, false},

    // INC/DEC
    {"inc", {0xFF}, 1, 0, OperandType::Mem32, OperandType::None, true, false, 0, false},
    {"dec", {0xFF}, 1, 1, OperandType::Mem32, OperandType::None, true, false, 0, false},

    // MOVZX/MOVSX
    {"movzx", {0x0F, 0xB6}, 2, 0xFF, OperandType::Reg32, OperandType::Mem8, true, false, 0, false},
    {"movzx", {0x0F, 0xB7}, 2, 0xFF, OperandType::Reg32, OperandType::Mem16, true, false, 0, false},
    {"movsx", {0x0F, 0xBE}, 2, 0xFF, OperandType::Reg32, OperandType::Mem8, true, false, 0, false},
    {"movsx", {0x0F, 0xBF}, 2, 0xFF, OperandType::Reg32, OperandType::Mem16, true, false, 0, false},

    // INT3 (debug breakpoint)
    {"int3", {0xCC}, 1, 0xFF, OperandType::None, OperandType::None, false, false, 0, false},
    {"int", {0xCD}, 1, 0xFF, OperandType::Imm8, OperandType::None, false, true, 1, false},

    // Sentinel
    {nullptr, {0}, 0, 0, OperandType::None, OperandType::None, false, false, 0, false}
};

// Register name tables
static const char* g_reg32Names[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static const char* g_reg64Names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
static const char* g_reg16Names[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
static const char* g_reg8Names[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};

// ============================================================================
// Helper Functions
// ============================================================================

std::string ToLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> Split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        result.push_back(Trim(item));
    }
    return result;
}

static bool ParseRegister(const std::string& name, uint8_t& reg, OperandType& type, bool& needsRex) {
    std::string lower = ToLower(name);
    needsRex = false;

    // 64-bit registers
    for (int i = 0; i < 16; i++) {
        if (lower == g_reg64Names[i]) {
            reg = static_cast<uint8_t>(i);
            type = OperandType::Reg64;
            needsRex = (i >= 8);
            return true;
        }
    }

    // 32-bit registers
    for (int i = 0; i < 16; i++) {
        if (lower == g_reg32Names[i]) {
            reg = static_cast<uint8_t>(i);
            type = OperandType::Reg32;
            needsRex = (i >= 8);
            return true;
        }
    }

    // 16-bit registers
    for (int i = 0; i < 16; i++) {
        if (lower == g_reg16Names[i]) {
            reg = static_cast<uint8_t>(i);
            type = OperandType::Reg16;
            needsRex = (i >= 8);
            return true;
        }
    }

    // 8-bit registers
    for (int i = 0; i < 8; i++) {
        if (lower == g_reg8Names[i]) {
            reg = static_cast<uint8_t>(i);
            type = OperandType::Reg8;
            return true;
        }
    }

    return false;
}

bool ParseNumber(const std::string& s, int64_t& value) {
    if (s.empty()) return false;

    std::string num = s;
    bool negative = false;
    if (num[0] == '-') {
        negative = true;
        num = num.substr(1);
    }

    try {
        if (num.size() > 2 && (num[0] == '0' && (num[1] == 'x' || num[1] == 'X'))) {
            // Hex
            value = std::stoull(num.substr(2), nullptr, 16);
        } else if (num.size() > 1 && num.back() == 'h') {
            // Hex with 'h' suffix
            value = std::stoull(num.substr(0, num.size() - 1), nullptr, 16);
        } else {
            // Decimal
            value = std::stoull(num, nullptr, 10);
        }
        if (negative) value = -value;
        return true;
    } catch (...) {
        return false;
    }
}

void SetError(AssemblerContext* ctx, NexusAssemblerError code, int line, const char* msg, const char* lineText) {
    ctx->hasError = true;
    ctx->lastError.errorCode = code;
    ctx->lastError.lineNumber = line;
    ctx->lastError.columnNumber = 0;
    strncpy_s(ctx->lastError.message, msg, sizeof(ctx->lastError.message) - 1);
    strncpy_s(ctx->lastError.lineText, lineText, sizeof(ctx->lastError.lineText) - 1);
}

// ============================================================================
// Instruction Encoding
// ============================================================================

static bool EncodeModRM(uint8_t mod, uint8_t reg, uint8_t rm, std::vector<uint8_t>& output) {
    output.push_back((mod << 6) | ((reg & 0x7) << 3) | (rm & 0x7));
    return true;
}

static bool EncodeSIB(uint8_t scale, uint8_t index, uint8_t base, std::vector<uint8_t>& output) {
    uint8_t ss = 0;
    switch (scale) {
        case 1: ss = 0; break;
        case 2: ss = 1; break;
        case 4: ss = 2; break;
        case 8: ss = 3; break;
        default: return false;
    }
    output.push_back((ss << 6) | ((index & 0x7) << 3) | (base & 0x7));
    return true;
}

static void EncodeImmediate(int64_t value, int size, std::vector<uint8_t>& output) {
    for (int i = 0; i < size; i++) {
        output.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

static bool ParseMemoryOperand(const std::string& s, Operand& op, AssemblerContext* ctx) {
    // Parse memory operand like [eax+ebx*4+10] or [rip+offset]
    std::string inner = s;

    // Remove brackets
    if (inner.front() == '[') inner = inner.substr(1);
    if (inner.back() == ']') inner = inner.substr(0, inner.size() - 1);
    inner = Trim(inner);

    op.base = 0xFF;
    op.index = 0xFF;
    op.scale = 1;
    op.disp = 0;

    // Split by + and -
    std::vector<std::string> parts;
    std::vector<bool> signs;  // true = positive

    std::string current;
    bool currentSign = true;
    for (size_t i = 0; i < inner.size(); i++) {
        if (inner[i] == '+' || inner[i] == '-') {
            if (!current.empty()) {
                parts.push_back(Trim(current));
                signs.push_back(currentSign);
            }
            currentSign = (inner[i] == '+');
            current.clear();
        } else {
            current += inner[i];
        }
    }
    if (!current.empty()) {
        parts.push_back(Trim(current));
        signs.push_back(currentSign);
    }

    for (size_t i = 0; i < parts.size(); i++) {
        std::string part = parts[i];
        bool positive = signs[i];

        // Check for scaled index (reg*scale)
        size_t starPos = part.find('*');
        if (starPos != std::string::npos) {
            std::string regName = Trim(part.substr(0, starPos));
            std::string scaleStr = Trim(part.substr(starPos + 1));

            uint8_t reg;
            OperandType regType;
            bool needsRex;
            if (!ParseRegister(regName, reg, regType, needsRex)) {
                return false;
            }

            int64_t scale;
            if (!ParseNumber(scaleStr, scale)) {
                return false;
            }

            op.index = reg;
            op.scale = static_cast<uint8_t>(scale);
            if (needsRex) op.hasRex = true;
        } else {
            // Try as register
            uint8_t reg;
            OperandType regType;
            bool needsRex;
            if (ParseRegister(part, reg, regType, needsRex)) {
                if (op.base == 0xFF) {
                    op.base = reg;
                    if (needsRex) op.hasRex = true;
                    if (regType == OperandType::Reg64) op.needsRexW = true;
                } else if (op.index == 0xFF) {
                    op.index = reg;
                    if (needsRex) op.hasRex = true;
                } else {
                    return false;  // Too many registers
                }
            } else {
                // Try as number/symbol
                int64_t value;
                if (ParseNumber(part, value)) {
                    op.disp += positive ? value : -value;
                } else {
                    // Could be a symbol
                    auto it = ctx->symbols.find(part);
                    if (it != ctx->symbols.end()) {
                        op.disp += positive ? it->second.address : -(int64_t)it->second.address;
                    } else {
                        auto lit = ctx->localLabels.find(part);
                        if (lit != ctx->localLabels.end()) {
                            op.disp += positive ? lit->second : -(int64_t)lit->second;
                        } else {
                            // Unknown symbol - save for later resolution
                            op.label = part;
                            op.type = OperandType::Label;
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Determine memory size based on context (default to 32-bit for now)
    op.type = ctx->is64Bit ? OperandType::Mem64 : OperandType::Mem32;
    return true;
}

bool ParseOperand(const std::string& s, Operand& op, AssemblerContext* ctx) {
    std::string trimmed = Trim(s);
    if (trimmed.empty()) {
        op.type = OperandType::None;
        return true;
    }

    // Check for size prefix
    std::string lower = ToLower(trimmed);
    bool hasSizePrefix = false;
    OperandType sizeType = OperandType::None;

    if (lower.starts_with("byte ptr ") || lower.starts_with("byte ")) {
        sizeType = OperandType::Mem8;
        hasSizePrefix = true;
        trimmed = Trim(trimmed.substr(lower.find("ptr") != std::string::npos ? 9 : 5));
    } else if (lower.starts_with("word ptr ") || lower.starts_with("word ")) {
        sizeType = OperandType::Mem16;
        hasSizePrefix = true;
        trimmed = Trim(trimmed.substr(lower.find("ptr") != std::string::npos ? 9 : 5));
    } else if (lower.starts_with("dword ptr ") || lower.starts_with("dword ")) {
        sizeType = OperandType::Mem32;
        hasSizePrefix = true;
        trimmed = Trim(trimmed.substr(lower.find("ptr") != std::string::npos ? 10 : 6));
    } else if (lower.starts_with("qword ptr ") || lower.starts_with("qword ")) {
        sizeType = OperandType::Mem64;
        hasSizePrefix = true;
        trimmed = Trim(trimmed.substr(lower.find("ptr") != std::string::npos ? 10 : 6));
    }

    // Memory operand
    if (trimmed.front() == '[') {
        if (!ParseMemoryOperand(trimmed, op, ctx)) {
            return false;
        }
        if (hasSizePrefix) {
            op.type = sizeType;
        }
        return true;
    }

    // Register
    uint8_t reg;
    OperandType regType;
    bool needsRex;
    if (ParseRegister(trimmed, reg, regType, needsRex)) {
        op.reg = reg;
        op.type = regType;
        op.hasRex = needsRex;
        op.needsRexW = (regType == OperandType::Reg64);
        return true;
    }

    // Immediate value
    int64_t value;
    if (ParseNumber(trimmed, value)) {
        op.disp = value;
        // Determine immediate size
        if (value >= -128 && value <= 127) {
            op.type = OperandType::Imm8;
        } else if (value >= -32768 && value <= 65535) {
            op.type = OperandType::Imm16;
        } else if (value >= -2147483648LL && value <= 4294967295LL) {
            op.type = OperandType::Imm32;
        } else {
            op.type = OperandType::Imm64;
        }
        return true;
    }

    // Symbol/label reference
    auto it = ctx->symbols.find(trimmed);
    if (it != ctx->symbols.end()) {
        op.disp = it->second.address;
        op.type = ctx->is64Bit ? OperandType::Imm64 : OperandType::Imm32;
        return true;
    }

    auto lit = ctx->localLabels.find(trimmed);
    if (lit != ctx->localLabels.end()) {
        op.disp = lit->second;
        op.type = OperandType::Rel32;
        return true;
    }

    // Unresolved label
    op.label = trimmed;
    op.type = OperandType::Label;
    return true;
}

bool AssembleInstruction(AssemblerContext* ctx, const std::string& mnemonic,
                         const Operand& op1, const Operand& op2,
                         std::vector<uint8_t>& output) {
    std::string mnemonicLower = ToLower(mnemonic);

    // Special handling for db/dw/dd/dq (define bytes)
    if (mnemonicLower == "db") {
        if (op1.type == OperandType::Imm8 || op1.type == OperandType::Imm16 ||
            op1.type == OperandType::Imm32 || op1.type == OperandType::Imm64) {
            output.push_back(static_cast<uint8_t>(op1.disp & 0xFF));
            return true;
        }
        return false;
    }
    if (mnemonicLower == "dw") {
        EncodeImmediate(op1.disp, 2, output);
        return true;
    }
    if (mnemonicLower == "dd") {
        EncodeImmediate(op1.disp, 4, output);
        return true;
    }
    if (mnemonicLower == "dq") {
        EncodeImmediate(op1.disp, 8, output);
        return true;
    }

    // Find matching opcode
    for (int i = 0; g_opcodes[i].mnemonic != nullptr; i++) {
        const OpcodeEntry& entry = g_opcodes[i];
        if (mnemonicLower != entry.mnemonic) continue;

        // Check operand compatibility (simplified)
        bool match = true;

        if (entry.op1Type == OperandType::None && op1.type != OperandType::None) match = false;
        if (entry.op2Type == OperandType::None && op2.type != OperandType::None) match = false;

        // More specific matching would go here...

        if (!match) continue;

        // Build instruction
        std::vector<uint8_t> instr;

        // REX prefix for 64-bit
        if (ctx->is64Bit) {
            uint8_t rex = 0x40;
            bool needsRex = false;

            if (op1.needsRexW || op2.needsRexW) {
                rex |= 0x08;  // REX.W
                needsRex = true;
            }
            if (op1.hasRex && op1.reg >= 8) {
                rex |= 0x04;  // REX.R
                needsRex = true;
            }
            if (op2.hasRex && op2.reg >= 8) {
                rex |= 0x01;  // REX.B
                needsRex = true;
            }

            if (needsRex) {
                instr.push_back(rex);
            }
        }

        // Opcode
        for (int j = 0; j < entry.opcodeLen; j++) {
            instr.push_back(entry.opcode[j]);
        }

        // Handle +r encoding (register encoded in opcode)
        if (entry.op1Type == OperandType::Reg64 || entry.op1Type == OperandType::Reg32) {
            if (mnemonicLower == "push" || mnemonicLower == "pop" ||
                (mnemonicLower == "mov" && (entry.op2Type == OperandType::Imm32 || entry.op2Type == OperandType::Imm64))) {
                instr.back() += (op1.reg & 0x7);
            }
        }

        // ModR/M byte
        if (entry.hasModRM) {
            uint8_t mod = 0x03;  // Register direct
            uint8_t reg = entry.modrmReg;
            uint8_t rm = 0;

            if (reg == 0xFF) {
                // Use operand register
                if (op2.type >= OperandType::Reg8 && op2.type <= OperandType::Reg64) {
                    reg = op2.reg & 0x7;
                } else {
                    reg = op1.reg & 0x7;
                }
            }

            if (op1.type >= OperandType::Mem8 && op1.type <= OperandType::Mem64) {
                // Memory operand
                if (op1.base == 0xFF && op1.index == 0xFF) {
                    // Displacement only
                    mod = 0x00;
                    rm = 0x05;  // disp32 in 32-bit, RIP-relative in 64-bit
                } else if (op1.disp == 0) {
                    mod = 0x00;
                    rm = op1.base & 0x7;
                } else if (op1.disp >= -128 && op1.disp <= 127) {
                    mod = 0x01;  // disp8
                    rm = op1.base & 0x7;
                } else {
                    mod = 0x02;  // disp32
                    rm = op1.base & 0x7;
                }

                // Need SIB byte?
                if (op1.index != 0xFF || (op1.base & 0x7) == 0x04) {
                    rm = 0x04;  // SIB follows
                }
            } else if (op1.type >= OperandType::Reg8 && op1.type <= OperandType::Reg64) {
                rm = op1.reg & 0x7;
            }

            if (op2.type >= OperandType::Reg8 && op2.type <= OperandType::Reg64) {
                reg = op2.reg & 0x7;
            }

            EncodeModRM(mod, reg, rm, instr);

            // SIB byte if needed
            if ((op1.type >= OperandType::Mem8 && op1.type <= OperandType::Mem64) &&
                (op1.index != 0xFF || (op1.base & 0x7) == 0x04)) {
                uint8_t index = (op1.index != 0xFF) ? (op1.index & 0x7) : 0x04;
                uint8_t base = (op1.base != 0xFF) ? (op1.base & 0x7) : 0x05;
                EncodeSIB(op1.scale, index, base, instr);
            }

            // Displacement
            if (op1.type >= OperandType::Mem8 && op1.type <= OperandType::Mem64) {
                if (op1.base == 0xFF && op1.index == 0xFF) {
                    EncodeImmediate(op1.disp, 4, instr);
                } else if (op1.disp != 0) {
                    if (op1.disp >= -128 && op1.disp <= 127) {
                        EncodeImmediate(op1.disp, 1, instr);
                    } else {
                        EncodeImmediate(op1.disp, 4, instr);
                    }
                }
            }
        }

        // Immediate value
        if (entry.hasImm) {
            if (entry.immSize > 0) {
                int64_t immValue = 0;

                if (op1.type == OperandType::Rel32 || op1.type == OperandType::Rel8 || op1.type == OperandType::Label) {
                    // Relative offset - will be patched later
                    immValue = op1.disp;
                } else if (op2.type >= OperandType::Imm8 && op2.type <= OperandType::Imm64) {
                    immValue = op2.disp;
                } else if (op1.type >= OperandType::Imm8 && op1.type <= OperandType::Imm64) {
                    immValue = op1.disp;
                }

                EncodeImmediate(immValue, entry.immSize, instr);
            }
        }

        output.insert(output.end(), instr.begin(), instr.end());
        return true;
    }

    return false;
}
