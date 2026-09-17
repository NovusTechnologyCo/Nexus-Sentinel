/**
 * @file assembler.cpp
 * @brief Auto-Assembler public API: context management, instruction assembly, scripts, symbols, and hooks.
 *
 * Implements the NEXUS_API assembler entry points: creating/destroying
 * assembler contexts, assembling single and multi-line instructions,
 * executing full Auto-Assembler scripts (with [ENABLE]/[DISABLE] sections),
 * managing named symbols, tracking remote allocations, writing code,
 * allocating code caves, disassembling from the target, and installing/
 * removing JMP hooks.
 *
 * The instruction-encoding engine is in assembler_engine.cpp; the AA
 * script parser is in assembler_script.cpp.
 */

#include "assembler_internal.h"

extern "C" {

// ============================================================================
// Public API Implementation
// ============================================================================

NEXUS_API NexusResult Nexus_AssemblerCreate(
    NexusProcessHandle process,
    NexusAssemblerArch arch,
    NexusAssemblerHandle* assembler)
{
    if (!process || !assembler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = new AssemblerContext();
    ctx->process = process;
    ctx->arch = arch;
    ctx->is64Bit = (arch == NEXUS_ASM_X64);
    ctx->hasError = false;
    ctx->currentAddress = 0;
    ctx->inEnableSection = false;
    ctx->inDisableSection = false;
    ctx->strictMode = false;

    *assembler = ctx;
    return NEXUS_OK;
}

NEXUS_API void Nexus_AssemblerDestroy(NexusAssemblerHandle assembler) {
    if (assembler) {
        AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

        /* Free regular allocations (alloc). globalalloc are intentionally leaked
         * to survive across enable/disable cycles, matching CE behavior. */
        for (const auto& alloc : ctx->allocations) {
            Nexus_FreeMemory(ctx->process, alloc.address, 0, MEM_RELEASE);
        }
        ctx->allocations.clear();

        delete ctx;
    }
}

NEXUS_API NexusResult Nexus_AssembleInstruction(
    NexusAssemblerHandle assembler,
    uint64_t address,
    const char* instruction,
    uint8_t* output,
    size_t outputSize,
    size_t* bytesWritten)
{
    if (!assembler || !instruction || !output || !bytesWritten) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    ctx->hasError = false;
    ctx->outputBuffer.clear();
    ctx->currentAddress = address;
    ctx->pendingRelocations.clear();

    if (!ParseAndAssembleLine(ctx, instruction, 1)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (!ResolveRelocations(ctx)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (ctx->outputBuffer.size() > outputSize) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(output, ctx->outputBuffer.data(), ctx->outputBuffer.size());
    *bytesWritten = ctx->outputBuffer.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssembleInstructions(
    NexusAssemblerHandle assembler,
    uint64_t address,
    const char* instructions,
    uint8_t* output,
    size_t outputSize,
    size_t* bytesWritten)
{
    if (!assembler || !instructions || !output || !bytesWritten) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    ctx->hasError = false;
    ctx->outputBuffer.clear();
    ctx->currentAddress = address;
    ctx->pendingRelocations.clear();
    ctx->localLabels.clear();

    // Parse lines
    std::istringstream stream(instructions);
    std::string line;
    int lineNum = 0;

    while (std::getline(stream, line)) {
        lineNum++;
        if (!ParseAndAssembleLine(ctx, line, lineNum)) {
            return NEXUS_ERROR_INVALID_PARAMETER;
        }
    }

    if (!ResolveRelocations(ctx)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (ctx->outputBuffer.size() > outputSize) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(output, ctx->outputBuffer.data(), ctx->outputBuffer.size());
    *bytesWritten = ctx->outputBuffer.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerExecuteScript(
    NexusAssemblerHandle assembler,
    const char* script,
    int enable)
{
    if (!assembler || !script) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    ctx->hasError = false;
    ctx->outputBuffer.clear();
    ctx->pendingRelocations.clear();
    ctx->defines.clear();
    ctx->strictMode = false;

    // Parse script into sections
    std::istringstream stream(script);
    std::string line;
    int lineNum = 0;
    bool inTargetSection = false;
    bool hasSection = false;

    // Track multiple code regions: address -> assembled bytes
    struct CodeRegion {
        uint64_t address;
        std::vector<uint8_t> code;
    };
    std::vector<CodeRegion> codeRegions;

    while (std::getline(stream, line)) {
        lineNum++;
        std::string trimmed = Trim(line);

        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == ';') continue;
        if (trimmed.size() >= 2 && trimmed[0] == '/' && trimmed[1] == '/') continue;

        // Expand defines before section check
        trimmed = ExpandDefines(ctx, trimmed);

        std::string lower = ToLower(trimmed);

        // Section markers
        if (lower == "[enable]") {
            inTargetSection = (enable != 0);
            hasSection = true;
            continue;
        }
        if (lower == "[disable]") {
            inTargetSection = (enable == 0);
            hasSection = true;
            continue;
        }

        // Only process lines in target section (or all lines if no sections)
        if (hasSection && !inTargetSection) {
            continue;
        }

        // Check for address specification (e.g., "game.exe+1234:")
        if (trimmed.back() == ':' && trimmed.find('+') != std::string::npos) {
            // Save current code region if we have buffered code
            if (!ctx->outputBuffer.empty() && ctx->currentAddress != 0) {
                codeRegions.push_back({ctx->currentAddress, ctx->outputBuffer});
                ctx->outputBuffer.clear();
                ctx->pendingRelocations.clear();
            }

            std::string addrExpr = trimmed.substr(0, trimmed.size() - 1);
            uint64_t resolved = ResolveModuleOffset(ctx, addrExpr);
            if (resolved != 0) {
                ctx->currentAddress = resolved;
            } else {
                SetError(ctx, NEXUS_ASM_ERROR_MODULE_NOT_FOUND, lineNum,
                         ("Cannot resolve address: " + addrExpr).c_str(), line.c_str());
                return NEXUS_ERROR_INVALID_PARAMETER;
            }
            continue;
        }

        // Process AA commands and assembly
        if (!ParseAndAssembleLine(ctx, trimmed, lineNum)) {
            return NEXUS_ERROR_INVALID_PARAMETER;
        }
    }

    // Resolve relocations for final region
    if (!ResolveRelocations(ctx)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Save final code region
    if (!ctx->outputBuffer.empty() && ctx->currentAddress != 0) {
        codeRegions.push_back({ctx->currentAddress, ctx->outputBuffer});
    }

    // Write all code regions to process
    for (const auto& region : codeRegions) {
        uint32_t oldProtect;
        Nexus_ProtectMemory(ctx->process, region.address, region.code.size(),
                            PAGE_EXECUTE_READWRITE, &oldProtect);

        NexusResult result = Nexus_WriteMemory(ctx->process, region.address,
                                                region.code.data(), region.code.size(), nullptr);

        Nexus_ProtectMemory(ctx->process, region.address, region.code.size(),
                            oldProtect, nullptr);

        if (result != NEXUS_OK) {
            SetError(ctx, NEXUS_ASM_ERROR_INJECTION_FAILED, 0, "Failed to write code to process", "");
            return result;
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerGetLastError(
    NexusAssemblerHandle assembler,
    NexusAssemblerErrorInfo* error)
{
    if (!assembler || !error) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    if (!ctx->hasError) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *error = ctx->lastError;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerAddSymbol(
    NexusAssemblerHandle assembler,
    const char* name,
    uint64_t address)
{
    if (!assembler || !name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    SymbolEntry sym;
    sym.name = name;
    sym.address = address;
    sym.type = NEXUS_SYM_ADDRESS;
    sym.size = 0;

    ctx->symbols[name] = sym;
    ctx->localLabels[name] = address;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerRemoveSymbol(
    NexusAssemblerHandle assembler,
    const char* name)
{
    if (!assembler || !name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    if (ctx->symbols.erase(name) == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }
    ctx->localLabels.erase(name);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerGetSymbol(
    NexusAssemblerHandle assembler,
    const char* name,
    NexusSymbol* symbol)
{
    if (!assembler || !name || !symbol) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    auto it = ctx->symbols.find(name);
    if (it == ctx->symbols.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    strncpy_s(symbol->name, it->second.name.c_str(), sizeof(symbol->name) - 1);
    symbol->address = it->second.address;
    symbol->type = it->second.type;
    symbol->size = it->second.size;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerGetSymbols(
    NexusAssemblerHandle assembler,
    NexusSymbol* buffer,
    size_t bufferCount,
    size_t* symbolCount)
{
    if (!assembler || !symbolCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    *symbolCount = ctx->symbols.size();

    if (!buffer) {
        return NEXUS_OK;
    }

    size_t i = 0;
    for (const auto& pair : ctx->symbols) {
        if (i >= bufferCount) break;

        strncpy_s(buffer[i].name, pair.second.name.c_str(), sizeof(buffer[i].name) - 1);
        buffer[i].address = pair.second.address;
        buffer[i].type = pair.second.type;
        buffer[i].size = pair.second.size;
        i++;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerGetAllocations(
    NexusAssemblerHandle assembler,
    NexusAllocEntry* buffer,
    size_t bufferCount,
    size_t* allocCount)
{
    if (!assembler || !allocCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);
    *allocCount = ctx->allocations.size();

    if (!buffer) {
        return NEXUS_OK;
    }

    for (size_t i = 0; i < ctx->allocations.size() && i < bufferCount; i++) {
        strncpy_s(buffer[i].name, ctx->allocations[i].name.c_str(), sizeof(buffer[i].name) - 1);
        buffer[i].address = ctx->allocations[i].address;
        buffer[i].size = ctx->allocations[i].size;
        buffer[i].protection = ctx->allocations[i].protection;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerFreeAllAllocations(NexusAssemblerHandle assembler) {
    if (!assembler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    for (const auto& alloc : ctx->allocations) {
        Nexus_FreeMemory(ctx->process, alloc.address, 0, MEM_RELEASE);
        ctx->symbols.erase(alloc.name);
        ctx->localLabels.erase(alloc.name);
    }

    ctx->allocations.clear();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AssemblerWriteCode(
    NexusAssemblerHandle assembler,
    uint64_t address,
    const uint8_t* code,
    size_t codeSize)
{
    if (!assembler || !code || codeSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    // Change protection
    uint32_t oldProtect;
    Nexus_ProtectMemory(ctx->process, address, codeSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Write code
    NexusResult result = Nexus_WriteMemory(ctx->process, address, code, codeSize, nullptr);

    // Restore protection
    Nexus_ProtectMemory(ctx->process, address, codeSize, oldProtect, nullptr);

    return result;
}

NEXUS_API NexusResult Nexus_AssemblerAllocCodeCave(
    NexusAssemblerHandle assembler,
    const char* name,
    size_t size,
    uint64_t nearAddress,
    uint64_t* address)
{
    if (!assembler || !name || size == 0 || !address) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    // Allocate memory (nearAddress hint is not fully implemented here)
    uint64_t addr = nearAddress;
    NexusResult result = Nexus_AllocateMemory(ctx->process, &addr, size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (result != NEXUS_OK) {
        // Try without address hint
        addr = 0;
        result = Nexus_AllocateMemory(ctx->process, &addr, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result != NEXUS_OK) {
            return result;
        }
    }

    // Record allocation
    ctx->allocations.push_back({name, addr, size, PAGE_EXECUTE_READWRITE});

    // Add to symbol table
    SymbolEntry sym;
    sym.name = name;
    sym.address = addr;
    sym.type = NEXUS_SYM_ALLOC;
    sym.size = static_cast<uint32_t>(size);
    ctx->symbols[name] = sym;
    ctx->localLabels[name] = addr;

    *address = addr;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_Disassemble(
    NexusAssemblerHandle assembler,
    uint64_t address,
    char* buffer,
    size_t bufferSize,
    size_t instructionCount,
    size_t* bytesDisassembled)
{
    if (!assembler || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    // Read code from process
    uint8_t code[256];
    size_t bytesRead;
    NexusResult result = Nexus_ReadMemory(ctx->process, address, code, sizeof(code), &bytesRead);
    if (result != NEXUS_OK) {
        return result;
    }

    // Simple disassembly output (hex dump for now)
    std::string output;
    size_t offset = 0;
    size_t count = 0;

    while (offset < bytesRead && count < instructionCount) {
        size_t len = GetInstructionLengthInternal(code + offset, ctx->is64Bit);

        char line[128];
        snprintf(line, sizeof(line), "%016llX: ", address + offset);
        output += line;

        for (size_t i = 0; i < len && i < 15; i++) {
            snprintf(line, sizeof(line), "%02X ", code[offset + i]);
            output += line;
        }
        output += "\n";

        offset += len;
        count++;
    }

    strncpy_s(buffer, bufferSize, output.c_str(), bufferSize - 1);
    if (bytesDisassembled) {
        *bytesDisassembled = offset;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetInstructionLength(
    NexusAssemblerHandle assembler,
    uint64_t address,
    size_t* length)
{
    if (!assembler || !length) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    // Read instruction bytes
    uint8_t code[16];
    size_t bytesRead;
    NexusResult result = Nexus_ReadMemory(ctx->process, address, code, sizeof(code), &bytesRead);
    if (result != NEXUS_OK) {
        return result;
    }

    *length = GetInstructionLengthInternal(code, ctx->is64Bit);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_CreateHook(
    NexusAssemblerHandle assembler,
    uint64_t hookAddress,
    uint64_t targetAddress,
    uint8_t* originalBytes,
    size_t originalBytesSize,
    size_t* bytesOverwritten)
{
    if (!assembler || !originalBytes || originalBytesSize < 5) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AssemblerContext* ctx = static_cast<AssemblerContext*>(assembler);

    // Calculate minimum bytes to overwrite (at least 5 for near jmp, 14 for far jmp in x64)
    size_t minBytes = ctx->is64Bit ? 14 : 5;  // Use 14 for guaranteed 64-bit jump

    // Read original bytes
    size_t totalLen = 0;
    uint8_t code[32];
    NexusResult result = Nexus_ReadMemory(ctx->process, hookAddress, code, sizeof(code), nullptr);
    if (result != NEXUS_OK) {
        return result;
    }

    // Find instruction boundary
    while (totalLen < minBytes) {
        size_t len = GetInstructionLengthInternal(code + totalLen, ctx->is64Bit);
        totalLen += len;
    }

    if (totalLen > originalBytesSize) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    // Save original bytes
    memcpy(originalBytes, code, totalLen);
    *bytesOverwritten = totalLen;

    // Create jump instruction
    std::vector<uint8_t> jump;

    if (ctx->is64Bit) {
        // FF 25 00 00 00 00 [8-byte address] - jmp qword ptr [rip]
        jump.push_back(0xFF);
        jump.push_back(0x25);
        jump.push_back(0x00);
        jump.push_back(0x00);
        jump.push_back(0x00);
        jump.push_back(0x00);
        for (int i = 0; i < 8; i++) {
            jump.push_back(static_cast<uint8_t>((targetAddress >> (i * 8)) & 0xFF));
        }
    } else {
        // E9 [4-byte relative offset] - jmp rel32
        int32_t relOffset = static_cast<int32_t>(targetAddress - hookAddress - 5);
        jump.push_back(0xE9);
        for (int i = 0; i < 4; i++) {
            jump.push_back(static_cast<uint8_t>((relOffset >> (i * 8)) & 0xFF));
        }
    }

    // Pad with NOPs
    while (jump.size() < totalLen) {
        jump.push_back(0x90);
    }

    // Write hook
    result = Nexus_AssemblerWriteCode(assembler, hookAddress, jump.data(), jump.size());

    return result;
}

NEXUS_API NexusResult Nexus_RemoveHook(
    NexusAssemblerHandle assembler,
    uint64_t hookAddress,
    const uint8_t* originalBytes,
    size_t bytesCount)
{
    if (!assembler || !originalBytes || bytesCount == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    return Nexus_AssemblerWriteCode(assembler, hookAddress, originalBytes, bytesCount);
}

} // extern "C"
