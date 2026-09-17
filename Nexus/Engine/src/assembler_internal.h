/**
 * @file assembler_internal.h
 * @brief Internal header shared by assembler.cpp, assembler_engine.cpp, and assembler_script.cpp.
 *
 * Defines the AssemblerContext structure (symbol table, allocation tracking,
 * process handle, architecture mode), encoding-table types, and cross-file
 * helper prototypes for the auto-assembler subsystem.
 */

#pragma once

#include "nexus_api.h"
#include "nexus_process.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>

/* ============================================================================
 * Forward Declarations from Other Modules
 * ============================================================================ */

extern NexusResult Nexus_ReadMemory(NexusProcessHandle handle, uint64_t address, void* buffer, size_t size, size_t* bytesRead);
extern NexusResult Nexus_WriteMemory(NexusProcessHandle handle, uint64_t address, const void* buffer, size_t size, size_t* bytesWritten);
extern NexusResult Nexus_AllocateMemory(NexusProcessHandle handle, uint64_t* address, size_t size, uint32_t allocationType, uint32_t protection);
extern NexusResult Nexus_FreeMemory(NexusProcessHandle handle, uint64_t address, size_t size, uint32_t freeType);
extern NexusResult Nexus_ProtectMemory(NexusProcessHandle handle, uint64_t address, size_t size, uint32_t newProtection, uint32_t* oldProtection);
extern NexusResult Nexus_GetRawHandle(NexusProcessHandle handle, void** rawHandle);
extern NexusResult Nexus_EnumerateModules(NexusProcessHandle handle, NexusModuleInfo* buffer, size_t bufferCount, size_t* moduleCount);
extern NexusResult Nexus_InjectDll(NexusProcessHandle handle, const wchar_t* dllPath, uint32_t flags, NexusInjectionResult* result);

/* ============================================================================
 * Operand Types & Structures (shared by engine + script)
 * ============================================================================ */

enum class OperandType {
    None,
    Reg8, Reg16, Reg32, Reg64,
    Mem8, Mem16, Mem32, Mem64,
    Imm8, Imm16, Imm32, Imm64,
    Rel8, Rel32,  // Relative offsets for jumps
    Label         // Unresolved label
};

struct Operand {
    OperandType type = OperandType::None;
    uint8_t reg = 0;           // Register index
    uint8_t base = 0xFF;       // Base register (0xFF = none)
    uint8_t index = 0xFF;      // Index register (0xFF = none)
    uint8_t scale = 1;         // Scale factor (1, 2, 4, 8)
    int64_t disp = 0;          // Displacement or immediate value
    std::string label;         // Label name (for unresolved references)
    bool hasRex = false;       // Needs REX prefix
    bool needsRexW = false;    // Needs REX.W
};

/* ============================================================================
 * Assembler State Structures
 * ============================================================================ */

struct Allocation {
    std::string name;
    uint64_t address;
    size_t size;
    uint32_t protection;
};

struct SymbolEntry {
    std::string name;
    uint64_t address;
    NexusSymbolType type;
    uint32_t size;
};

struct PendingRelocation {
    size_t offset;          // Offset in output buffer
    std::string label;      // Target label
    int relocSize;          // 1 for rel8, 4 for rel32
    uint64_t instrAddr;     // Address of instruction (for relative calc)
};

struct AssemblerContext {
    NexusProcessHandle process;
    NexusAssemblerArch arch;
    bool is64Bit;

    std::unordered_map<std::string, SymbolEntry> symbols;
    std::vector<Allocation> allocations;
    std::vector<Allocation> globalAllocations;  // Persist across enable/disable

    // Error state
    NexusAssemblerErrorInfo lastError;
    bool hasError;

    // Assembly state
    std::vector<uint8_t> outputBuffer;
    uint64_t currentAddress;
    std::vector<PendingRelocation> pendingRelocations;
    std::unordered_map<std::string, uint64_t> localLabels;

    // Script state
    bool inEnableSection;
    bool inDisableSection;
    std::vector<uint8_t> originalBytes;  // Saved original code
    std::unordered_map<std::string, std::vector<uint8_t>> savedOriginalBytes;

    // Preprocessor defines
    std::unordered_map<std::string, std::string> defines;

    // Strict mode ({$strict} directive)
    bool strictMode;
};

struct ScriptLine {
    int lineNumber;
    std::string text;
    std::string trimmed;
};

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- assembler_engine.cpp --- */
std::string ToLower(const std::string& str);
std::string Trim(const std::string& str);
std::vector<std::string> Split(const std::string& str, char delimiter);
void SetError(AssemblerContext* ctx, NexusAssemblerError code, int line, const char* msg, const char* lineText = "");
bool ParseNumber(const std::string& str, int64_t& value);
bool ParseOperand(const std::string& s, Operand& op, AssemblerContext* ctx);
bool AssembleInstruction(AssemblerContext* ctx, const std::string& mnemonic,
                         const Operand& op1, const Operand& op2,
                         std::vector<uint8_t>& output);

/* --- assembler_script.cpp --- */
bool ParseAndAssembleLine(AssemblerContext* ctx, const std::string& line, int lineNumber);
bool ResolveRelocations(AssemblerContext* ctx);
int GetInstructionLengthInternal(const uint8_t* code, bool is64Bit);
std::string ExpandDefines(AssemblerContext* ctx, const std::string& line);
uint64_t ResolveModuleOffset(AssemblerContext* ctx, const std::string& expr);
