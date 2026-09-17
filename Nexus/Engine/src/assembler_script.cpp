/**
 * @file assembler_script.cpp
 * @brief Auto-Assembler (AA) script parser and high-level command execution.
 *
 * Implements the full Cheat Engine Auto-Assembler command set:
 *   alloc, dealloc, globalalloc, label, registersymbol, unregistersymbol,
 *   define, aobscan, aobscanmodule, assert, readmem, fullaccess,
 *   createthread, loadlibrary, reassemble
 *
 * Also handles define-expansion, module+offset resolution, multi-value db,
 * string literals in db, and the {$strict} directive.
 *
 * Instruction encoding tables are in assembler_engine.cpp.
 * Public NEXUS_API functions in assembler.cpp.
 */

#include "assembler_internal.h"

// ============================================================================
// Helper: Extract parenthesized arguments from a command
// Returns the content between ( and ), or empty string on failure.
// ============================================================================

static bool ExtractArgs(const std::string& line, const std::string& cmdLower,
                        size_t cmdLen, std::string& args, int lineNum, AssemblerContext* ctx) {
    size_t end = line.find(')', cmdLen);
    if (end == std::string::npos) {
        SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum,
                 ("Missing closing parenthesis in " + cmdLower).c_str(), line.c_str());
        return false;
    }
    args = line.substr(cmdLen, end - cmdLen);
    return true;
}

// ============================================================================
// Module+Offset Resolution: "game.exe+1234" -> absolute address
// ============================================================================

uint64_t ResolveModuleOffset(AssemblerContext* ctx, const std::string& expr) {
    // Check for module+offset format
    size_t plusPos = expr.find('+');
    if (plusPos == std::string::npos) {
        // Try as pure number
        int64_t val;
        if (ParseNumber(expr, val)) {
            return static_cast<uint64_t>(val);
        }
        // Try as symbol
        auto it = ctx->symbols.find(expr);
        if (it != ctx->symbols.end()) return it->second.address;
        auto lit = ctx->localLabels.find(expr);
        if (lit != ctx->localLabels.end()) return lit->second;
        return 0;
    }

    std::string moduleName = Trim(expr.substr(0, plusPos));
    std::string offsetStr = Trim(expr.substr(plusPos + 1));

    int64_t offset;
    if (!ParseNumber(offsetStr, offset)) {
        return 0;
    }

    // Enumerate modules to find base address
    NexusModuleInfo modules[512];
    size_t moduleCount = 0;
    if (Nexus_EnumerateModules(ctx->process, modules, 512, &moduleCount) != NEXUS_OK) {
        return 0;
    }

    // Convert module name to wide for comparison
    std::wstring wModuleName;
    for (char c : moduleName) wModuleName += static_cast<wchar_t>(c);

    // Case-insensitive module name comparison
    std::wstring wModuleLower = wModuleName;
    std::transform(wModuleLower.begin(), wModuleLower.end(), wModuleLower.begin(), ::towlower);

    for (size_t i = 0; i < moduleCount; i++) {
        std::wstring modName = modules[i].name;
        std::transform(modName.begin(), modName.end(), modName.begin(), ::towlower);
        if (modName == wModuleLower) {
            return modules[i].baseAddress + static_cast<uint64_t>(offset);
        }
    }

    return 0;
}

// ============================================================================
// Preprocessor: Define Expansion
// ============================================================================

std::string ExpandDefines(AssemblerContext* ctx, const std::string& line) {
    if (ctx->defines.empty()) return line;

    std::string result = line;
    // Iterate defines and replace occurrences
    // Use longest-match-first by sorting by length descending
    std::vector<std::pair<std::string, std::string>> sorted(ctx->defines.begin(), ctx->defines.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });

    for (const auto& [name, value] : sorted) {
        size_t pos = 0;
        while ((pos = result.find(name, pos)) != std::string::npos) {
            // Check word boundaries to avoid partial replacement
            bool leftOk = (pos == 0) || !std::isalnum(static_cast<unsigned char>(result[pos - 1])) && result[pos - 1] != '_';
            size_t endPos = pos + name.size();
            bool rightOk = (endPos >= result.size()) || !std::isalnum(static_cast<unsigned char>(result[endPos])) && result[endPos] != '_';

            if (leftOk && rightOk) {
                result.replace(pos, name.size(), value);
                pos += value.size();
            } else {
                pos += name.size();
            }
        }
    }
    return result;
}

// ============================================================================
// AOB Pattern Parsing: "48 8B ?? 0F 84" -> bytes + mask
// ============================================================================

static bool ParseAOBPattern(const std::string& pattern, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask) {
    auto parts = Split(pattern, ' ');
    for (const auto& part : parts) {
        if (part.empty()) continue;
        if (part == "?" || part == "??" || part == "*") {
            bytes.push_back(0);
            mask.push_back(0);  // Wildcard
        } else {
            try {
                uint8_t val = static_cast<uint8_t>(std::stoul(part, nullptr, 16));
                bytes.push_back(val);
                mask.push_back(0xFF);  // Exact match
            } catch (...) {
                return false;
            }
        }
    }
    return !bytes.empty();
}

// ============================================================================
// AOB Scan Implementation (uses ReadMemory directly for flexibility)
// ============================================================================

static bool ScanMemoryForAOB(AssemblerContext* ctx, uint64_t startAddr, uint64_t endAddr,
                              const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask,
                              uint64_t& resultAddr) {
    const size_t CHUNK_SIZE = 0x10000;  // 64KB chunks
    const size_t patLen = pattern.size();
    std::vector<uint8_t> buffer(CHUNK_SIZE + patLen - 1);

    for (uint64_t addr = startAddr; addr < endAddr; addr += CHUNK_SIZE) {
        uint64_t remaining = endAddr - addr;
        uint64_t bufSize = static_cast<uint64_t>(buffer.size());
        size_t readSize = static_cast<size_t>(remaining < bufSize ? remaining : bufSize);
        size_t bytesRead = 0;

        if (Nexus_ReadMemory(ctx->process, addr, buffer.data(), readSize, &bytesRead) != NEXUS_OK || bytesRead < patLen) {
            continue;
        }

        // Scan this chunk
        for (size_t i = 0; i <= bytesRead - patLen; i++) {
            bool found = true;
            for (size_t j = 0; j < patLen; j++) {
                if (mask[j] && (buffer[i + j] != pattern[j])) {
                    found = false;
                    break;
                }
            }
            if (found) {
                resultAddr = addr + i;
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// AA Script Parser
// ============================================================================

static bool ParseAACommand(AssemblerContext* ctx, const std::string& line, int lineNum) {
    std::string lower = ToLower(line);

    // ---- {$strict} directive ----
    if (lower == "{$strict}") {
        ctx->strictMode = true;
        return true;
    }

    // ---- define(name, value) ----
    if (lower.starts_with("define(")) {
        std::string args;
        if (!ExtractArgs(line, "define", 7, args, lineNum, ctx)) return false;

        auto parts = Split(args, ',');
        if (parts.size() < 2) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "define requires 2 arguments: define(name, value)", line.c_str());
            return false;
        }

        std::string name = parts[0];
        // Value may contain commas in some edge cases, rejoin remaining parts
        std::string value = parts[1];
        for (size_t i = 2; i < parts.size(); i++) {
            value += "," + parts[i];
        }

        ctx->defines[name] = value;
        return true;
    }

    // ---- alloc(name, size) or alloc(name, size, module) ----
    if (lower.starts_with("alloc(")) {
        std::string args;
        if (!ExtractArgs(line, "alloc", 6, args, lineNum, ctx)) return false;

        auto parts = Split(args, ',');
        if (parts.size() < 2) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "alloc requires at least 2 arguments", line.c_str());
            return false;
        }

        std::string name = parts[0];
        int64_t size;
        if (!ParseNumber(parts[1], size) || size <= 0) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid size in alloc", line.c_str());
            return false;
        }

        // Optional third argument: near address (module name for proximity allocation)
        uint64_t nearAddr = 0;
        if (parts.size() >= 3) {
            nearAddr = ResolveModuleOffset(ctx, parts[2]);
        }

        // Allocate memory in target process
        uint64_t addr = nearAddr;
        NexusResult result = Nexus_AllocateMemory(ctx->process, &addr, static_cast<size_t>(size),
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result != NEXUS_OK) {
            // Retry without hint
            addr = 0;
            result = Nexus_AllocateMemory(ctx->process, &addr, static_cast<size_t>(size),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (result != NEXUS_OK) {
                SetError(ctx, NEXUS_ASM_ERROR_ALLOC_FAILED, lineNum, "Memory allocation failed", line.c_str());
                return false;
            }
        }

        // Record allocation
        ctx->allocations.push_back({name, addr, static_cast<size_t>(size), PAGE_EXECUTE_READWRITE});

        // Add to symbol table
        SymbolEntry sym;
        sym.name = name;
        sym.address = addr;
        sym.type = NEXUS_SYM_ALLOC;
        sym.size = static_cast<uint32_t>(size);
        ctx->symbols[name] = sym;
        ctx->localLabels[name] = addr;

        return true;
    }

    // ---- globalalloc(name, size) ----
    if (lower.starts_with("globalalloc(")) {
        std::string args;
        if (!ExtractArgs(line, "globalalloc", 12, args, lineNum, ctx)) return false;

        auto parts = Split(args, ',');
        if (parts.size() < 2) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "globalalloc requires 2 arguments", line.c_str());
            return false;
        }

        std::string name = parts[0];
        int64_t size;
        if (!ParseNumber(parts[1], size) || size <= 0) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid size in globalalloc", line.c_str());
            return false;
        }

        // Check if already globally allocated (reuse)
        for (const auto& ga : ctx->globalAllocations) {
            if (ga.name == name) {
                // Already exists, just add to symbol table
                SymbolEntry sym;
                sym.name = name;
                sym.address = ga.address;
                sym.type = NEXUS_SYM_ALLOC;
                sym.size = static_cast<uint32_t>(ga.size);
                ctx->symbols[name] = sym;
                ctx->localLabels[name] = ga.address;
                return true;
            }
        }

        uint64_t addr = 0;
        NexusResult result = Nexus_AllocateMemory(ctx->process, &addr, static_cast<size_t>(size),
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result != NEXUS_OK) {
            SetError(ctx, NEXUS_ASM_ERROR_ALLOC_FAILED, lineNum, "globalalloc failed", line.c_str());
            return false;
        }

        // Record as global (not freed on destroy)
        ctx->globalAllocations.push_back({name, addr, static_cast<size_t>(size), PAGE_EXECUTE_READWRITE});

        SymbolEntry sym;
        sym.name = name;
        sym.address = addr;
        sym.type = NEXUS_SYM_ALLOC;
        sym.size = static_cast<uint32_t>(size);
        ctx->symbols[name] = sym;
        ctx->localLabels[name] = addr;

        return true;
    }

    // ---- dealloc(name) ----
    if (lower.starts_with("dealloc(")) {
        std::string args;
        if (!ExtractArgs(line, "dealloc", 8, args, lineNum, ctx)) return false;
        std::string name = Trim(args);

        for (auto it = ctx->allocations.begin(); it != ctx->allocations.end(); ++it) {
            if (it->name == name) {
                Nexus_FreeMemory(ctx->process, it->address, 0, MEM_RELEASE);
                ctx->allocations.erase(it);
                ctx->symbols.erase(name);
                ctx->localLabels.erase(name);
                return true;
            }
        }

        SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum, "Allocation not found for dealloc", line.c_str());
        return false;
    }

    // ---- label(name) ----
    if (lower.starts_with("label(")) {
        std::string args;
        if (!ExtractArgs(line, "label", 6, args, lineNum, ctx)) return false;
        std::string name = Trim(args);

        SymbolEntry sym;
        sym.name = name;
        sym.address = 0;
        sym.type = NEXUS_SYM_LABEL;
        sym.size = 0;
        ctx->symbols[name] = sym;

        return true;
    }

    // ---- registersymbol(name) ----
    if (lower.starts_with("registersymbol(")) {
        std::string args;
        if (!ExtractArgs(line, "registersymbol", 15, args, lineNum, ctx)) return false;
        std::string name = Trim(args);

        auto it = ctx->symbols.find(name);
        if (it != ctx->symbols.end()) {
            it->second.type = NEXUS_SYM_REGISTER;
        }
        return true;
    }

    // ---- unregistersymbol(name) ----
    if (lower.starts_with("unregistersymbol(")) {
        std::string args;
        if (!ExtractArgs(line, "unregistersymbol", 17, args, lineNum, ctx)) return false;
        std::string name = Trim(args);
        ctx->symbols.erase(name);
        return true;
    }

    // ---- aobscan(name, pattern) ----
    if (lower.starts_with("aobscan(")) {
        std::string args;
        if (!ExtractArgs(line, "aobscan", 8, args, lineNum, ctx)) return false;

        size_t firstComma = args.find(',');
        if (firstComma == std::string::npos) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "aobscan requires: aobscan(name, pattern)", line.c_str());
            return false;
        }

        std::string name = Trim(args.substr(0, firstComma));
        std::string pattern = Trim(args.substr(firstComma + 1));

        std::vector<uint8_t> patBytes, patMask;
        if (!ParseAOBPattern(pattern, patBytes, patMask)) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid AOB pattern", line.c_str());
            return false;
        }

        // Scan all readable memory regions
        // Use module enumeration to get typical address ranges
        NexusModuleInfo modules[512];
        size_t moduleCount = 0;
        Nexus_EnumerateModules(ctx->process, modules, 512, &moduleCount);

        uint64_t resultAddr = 0;
        bool found = false;

        for (size_t i = 0; i < moduleCount && !found; i++) {
            found = ScanMemoryForAOB(ctx, modules[i].baseAddress,
                                      modules[i].baseAddress + modules[i].size,
                                      patBytes, patMask, resultAddr);
        }

        if (!found) {
            SetError(ctx, NEXUS_ASM_ERROR_AOB_NOT_FOUND, lineNum,
                     ("AOB pattern not found: " + name).c_str(), line.c_str());
            return false;
        }

        SymbolEntry sym;
        sym.name = name;
        sym.address = resultAddr;
        sym.type = NEXUS_SYM_ADDRESS;
        sym.size = 0;
        ctx->symbols[name] = sym;
        ctx->localLabels[name] = resultAddr;

        return true;
    }

    // ---- aobscanmodule(name, module, pattern) ----
    if (lower.starts_with("aobscanmodule(")) {
        std::string args;
        if (!ExtractArgs(line, "aobscanmodule", 14, args, lineNum, ctx)) return false;

        // Split: name, module, pattern (pattern may contain commas in spaces)
        size_t firstComma = args.find(',');
        if (firstComma == std::string::npos) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "aobscanmodule requires: aobscanmodule(name, module, pattern)", line.c_str());
            return false;
        }
        std::string name = Trim(args.substr(0, firstComma));
        std::string rest = args.substr(firstComma + 1);

        size_t secondComma = rest.find(',');
        if (secondComma == std::string::npos) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "aobscanmodule requires 3 arguments", line.c_str());
            return false;
        }
        std::string moduleName = Trim(rest.substr(0, secondComma));
        std::string pattern = Trim(rest.substr(secondComma + 1));

        std::vector<uint8_t> patBytes, patMask;
        if (!ParseAOBPattern(pattern, patBytes, patMask)) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid AOB pattern", line.c_str());
            return false;
        }

        // Find module
        NexusModuleInfo modules[512];
        size_t moduleCount = 0;
        Nexus_EnumerateModules(ctx->process, modules, 512, &moduleCount);

        std::wstring wModuleName;
        for (char c : moduleName) wModuleName += static_cast<wchar_t>(c);
        std::wstring wModuleLower = wModuleName;
        std::transform(wModuleLower.begin(), wModuleLower.end(), wModuleLower.begin(), ::towlower);

        uint64_t resultAddr = 0;
        bool found = false;

        for (size_t i = 0; i < moduleCount; i++) {
            std::wstring modName = modules[i].name;
            std::transform(modName.begin(), modName.end(), modName.begin(), ::towlower);
            if (modName == wModuleLower) {
                found = ScanMemoryForAOB(ctx, modules[i].baseAddress,
                                          modules[i].baseAddress + modules[i].size,
                                          patBytes, patMask, resultAddr);
                break;
            }
        }

        if (!found) {
            SetError(ctx, NEXUS_ASM_ERROR_AOB_NOT_FOUND, lineNum,
                     ("AOB pattern not found in " + moduleName + ": " + name).c_str(), line.c_str());
            return false;
        }

        SymbolEntry sym;
        sym.name = name;
        sym.address = resultAddr;
        sym.type = NEXUS_SYM_ADDRESS;
        sym.size = 0;
        ctx->symbols[name] = sym;
        ctx->localLabels[name] = resultAddr;

        return true;
    }

    // ---- assert(address, bytes) ----
    if (lower.starts_with("assert(")) {
        std::string args;
        if (!ExtractArgs(line, "assert", 7, args, lineNum, ctx)) return false;

        size_t firstComma = args.find(',');
        if (firstComma == std::string::npos) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "assert requires: assert(address, bytes)", line.c_str());
            return false;
        }

        std::string addrStr = Trim(args.substr(0, firstComma));
        std::string bytesStr = Trim(args.substr(firstComma + 1));

        // Resolve address (supports module+offset and symbols)
        uint64_t addr = ResolveModuleOffset(ctx, addrStr);
        if (addr == 0) {
            auto it = ctx->symbols.find(addrStr);
            if (it != ctx->symbols.end()) addr = it->second.address;
        }
        if (addr == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum,
                     ("Cannot resolve address for assert: " + addrStr).c_str(), line.c_str());
            return false;
        }

        // Parse expected bytes
        std::vector<uint8_t> expected;
        auto byteParts = Split(bytesStr, ' ');
        for (const auto& bp : byteParts) {
            if (bp.empty()) continue;
            try {
                expected.push_back(static_cast<uint8_t>(std::stoul(bp, nullptr, 16)));
            } catch (...) {
                SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid byte in assert pattern", line.c_str());
                return false;
            }
        }

        // Read actual bytes
        std::vector<uint8_t> actual(expected.size());
        size_t bytesRead = 0;
        if (Nexus_ReadMemory(ctx->process, addr, actual.data(), expected.size(), &bytesRead) != NEXUS_OK
            || bytesRead != expected.size()) {
            SetError(ctx, NEXUS_ASM_ERROR_READ_FAILED, lineNum, "Failed to read memory for assert", line.c_str());
            return false;
        }

        // Compare
        if (memcmp(actual.data(), expected.data(), expected.size()) != 0) {
            SetError(ctx, NEXUS_ASM_ERROR_ASSERT_FAILED, lineNum,
                     "assert failed: memory does not match expected bytes", line.c_str());
            return false;
        }

        return true;
    }

    // ---- readmem(address, size) ----
    if (lower.starts_with("readmem(")) {
        std::string args;
        if (!ExtractArgs(line, "readmem", 8, args, lineNum, ctx)) return false;

        auto parts = Split(args, ',');
        if (parts.size() < 2) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "readmem requires: readmem(address, size)", line.c_str());
            return false;
        }

        uint64_t addr = ResolveModuleOffset(ctx, parts[0]);
        if (addr == 0) {
            auto it = ctx->symbols.find(parts[0]);
            if (it != ctx->symbols.end()) addr = it->second.address;
        }
        if (addr == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum,
                     ("Cannot resolve address for readmem: " + parts[0]).c_str(), line.c_str());
            return false;
        }

        int64_t size;
        if (!ParseNumber(parts[1], size) || size <= 0 || size > 0x10000) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid size in readmem", line.c_str());
            return false;
        }

        // Read bytes from target and append to output buffer
        std::vector<uint8_t> data(static_cast<size_t>(size));
        size_t bytesRead = 0;
        if (Nexus_ReadMemory(ctx->process, addr, data.data(), static_cast<size_t>(size), &bytesRead) != NEXUS_OK) {
            SetError(ctx, NEXUS_ASM_ERROR_READ_FAILED, lineNum, "Failed to read memory for readmem", line.c_str());
            return false;
        }

        ctx->outputBuffer.insert(ctx->outputBuffer.end(), data.begin(), data.begin() + bytesRead);
        return true;
    }

    // ---- fullaccess(address, size) ----
    if (lower.starts_with("fullaccess(")) {
        std::string args;
        if (!ExtractArgs(line, "fullaccess", 11, args, lineNum, ctx)) return false;

        auto parts = Split(args, ',');
        if (parts.size() < 2) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "fullaccess requires: fullaccess(address, size)", line.c_str());
            return false;
        }

        uint64_t addr = ResolveModuleOffset(ctx, parts[0]);
        if (addr == 0) {
            auto it = ctx->symbols.find(parts[0]);
            if (it != ctx->symbols.end()) addr = it->second.address;
        }
        if (addr == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum,
                     ("Cannot resolve address for fullaccess: " + parts[0]).c_str(), line.c_str());
            return false;
        }

        int64_t size;
        if (!ParseNumber(parts[1], size) || size <= 0) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, "Invalid size in fullaccess", line.c_str());
            return false;
        }

        uint32_t oldProtect;
        Nexus_ProtectMemory(ctx->process, addr, static_cast<size_t>(size),
                            PAGE_EXECUTE_READWRITE, &oldProtect);

        return true;
    }

    // ---- createthread(address) ----
    if (lower.starts_with("createthread(")) {
        std::string args;
        if (!ExtractArgs(line, "createthread", 13, args, lineNum, ctx)) return false;

        std::string addrStr = Trim(args);
        uint64_t addr = ResolveModuleOffset(ctx, addrStr);
        if (addr == 0) {
            auto it = ctx->symbols.find(addrStr);
            if (it != ctx->symbols.end()) addr = it->second.address;
        }
        if (addr == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum,
                     ("Cannot resolve address for createthread: " + addrStr).c_str(), line.c_str());
            return false;
        }

        // Get raw process handle for CreateRemoteThread
        void* rawHandle = nullptr;
        if (Nexus_GetRawHandle(ctx->process, &rawHandle) != NEXUS_OK || !rawHandle) {
            SetError(ctx, NEXUS_ASM_ERROR_THREAD_FAILED, lineNum, "Cannot get process handle for createthread", line.c_str());
            return false;
        }

        HANDLE hThread = CreateRemoteThread(static_cast<HANDLE>(rawHandle), nullptr, 0,
                                             reinterpret_cast<LPTHREAD_START_ROUTINE>(addr),
                                             nullptr, 0, nullptr);
        if (!hThread) {
            SetError(ctx, NEXUS_ASM_ERROR_THREAD_FAILED, lineNum, "CreateRemoteThread failed", line.c_str());
            return false;
        }
        CloseHandle(hThread);

        return true;
    }

    // ---- loadlibrary(path) ----
    if (lower.starts_with("loadlibrary(")) {
        std::string args;
        if (!ExtractArgs(line, "loadlibrary", 12, args, lineNum, ctx)) return false;

        std::string path = Trim(args);
        // Convert to wide string
        std::wstring wPath;
        for (char c : path) wPath += static_cast<wchar_t>(c);

        NexusInjectionResult injResult = {};
        NexusResult result = Nexus_InjectDll(ctx->process, wPath.c_str(),
                                              NEXUS_INJECT_FLAG_WAIT, &injResult);
        if (result != NEXUS_OK || !injResult.success) {
            SetError(ctx, NEXUS_ASM_ERROR_LOADLIB_FAILED, lineNum,
                     ("loadlibrary failed: " + path).c_str(), line.c_str());
            return false;
        }

        return true;
    }

    // ---- reassemble(address) ----
    if (lower.starts_with("reassemble(")) {
        std::string args;
        if (!ExtractArgs(line, "reassemble", 11, args, lineNum, ctx)) return false;

        std::string addrStr = Trim(args);
        uint64_t addr = ResolveModuleOffset(ctx, addrStr);
        if (addr == 0) {
            auto it = ctx->symbols.find(addrStr);
            if (it != ctx->symbols.end()) addr = it->second.address;
        }
        if (addr == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, lineNum,
                     ("Cannot resolve address for reassemble: " + addrStr).c_str(), line.c_str());
            return false;
        }

        // Read instruction bytes from target
        uint8_t instrBuf[16];
        size_t bytesRead = 0;
        if (Nexus_ReadMemory(ctx->process, addr, instrBuf, sizeof(instrBuf), &bytesRead) != NEXUS_OK || bytesRead == 0) {
            SetError(ctx, NEXUS_ASM_ERROR_READ_FAILED, lineNum, "Failed to read instruction for reassemble", line.c_str());
            return false;
        }

        int instrLen = GetInstructionLengthInternal(instrBuf, ctx->is64Bit);
        if (instrLen <= 0 || instrLen > 15) instrLen = 1;

        // Emit the instruction bytes directly
        ctx->outputBuffer.insert(ctx->outputBuffer.end(), instrBuf, instrBuf + instrLen);
        return true;
    }

    return false;  // Not a command, might be assembly
}

// ============================================================================
// Multi-Value db/dw/dd/dq Parser
// ============================================================================

static bool ParseDataDirective(AssemblerContext* ctx, const std::string& mnemonic,
                                const std::string& operandsStr, int lineNum, const std::string& line) {
    std::string mnemonicLower = ToLower(mnemonic);
    int unitSize = 0;
    if (mnemonicLower == "db") unitSize = 1;
    else if (mnemonicLower == "dw") unitSize = 2;
    else if (mnemonicLower == "dd") unitSize = 4;
    else if (mnemonicLower == "dq") unitSize = 8;
    else return false;

    std::string rest = operandsStr;

    size_t pos = 0;
    while (pos < rest.size()) {
        // Skip whitespace
        while (pos < rest.size() && (rest[pos] == ' ' || rest[pos] == '\t' || rest[pos] == ',')) pos++;
        if (pos >= rest.size()) break;

        // String literal: 'text' or "text"
        if (rest[pos] == '\'' || rest[pos] == '"') {
            char quote = rest[pos++];
            while (pos < rest.size() && rest[pos] != quote) {
                ctx->outputBuffer.push_back(static_cast<uint8_t>(rest[pos++]));
            }
            if (pos < rest.size()) pos++;  // Skip closing quote
            continue;
        }

        // Hex/decimal value
        size_t end = pos;
        while (end < rest.size() && rest[end] != ' ' && rest[end] != '\t' && rest[end] != ',') end++;
        std::string token = rest.substr(pos, end - pos);
        pos = end;

        if (token.empty()) continue;

        int64_t value;
        if (!ParseNumber(token, value)) {
            // Try as hex without prefix (CE style: "90" means 0x90 for db)
            try {
                value = std::stoll(token, nullptr, 16);
            } catch (...) {
                SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum,
                         ("Invalid value in " + mnemonicLower + ": " + token).c_str(), line.c_str());
                return false;
            }
        }

        // Emit value in little-endian
        for (int i = 0; i < unitSize; i++) {
            ctx->outputBuffer.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }

    return true;
}

// ============================================================================
// Main Line Parser
// ============================================================================

bool ParseAndAssembleLine(AssemblerContext* ctx, const std::string& line, int lineNum) {
    std::string trimmed = Trim(line);

    // Skip empty lines and comments
    if (trimmed.empty()) return true;
    if (trimmed[0] == ';') return true;
    if (trimmed.size() >= 2 && trimmed[0] == '/' && trimmed[1] == '/') return true;

    // Expand preprocessor defines
    trimmed = ExpandDefines(ctx, trimmed);

    // Check for {$strict} and other directives
    if (trimmed[0] == '{' && trimmed.back() == '}') {
        std::string lower = ToLower(trimmed);
        if (lower == "{$strict}") {
            ctx->strictMode = true;
            return true;
        }
        // Unknown directive - ignore in non-strict mode
        if (ctx->strictMode) {
            SetError(ctx, NEXUS_ASM_ERROR_SYNTAX, lineNum, ("Unknown directive: " + trimmed).c_str(), line.c_str());
            return false;
        }
        return true;
    }

    // Check for label definition (ends with : but NOT module+offset like game.exe+1234:)
    if (trimmed.back() == ':') {
        std::string labelCandidate = trimmed.substr(0, trimmed.size() - 1);
        // If it contains + it's likely a module+offset address, not a label
        if (labelCandidate.find('+') == std::string::npos) {
            uint64_t addr = ctx->currentAddress + ctx->outputBuffer.size();
            ctx->localLabels[labelCandidate] = addr;

            auto it = ctx->symbols.find(labelCandidate);
            if (it != ctx->symbols.end()) {
                it->second.address = addr;
            } else {
                SymbolEntry sym;
                sym.name = labelCandidate;
                sym.address = addr;
                sym.type = NEXUS_SYM_LABEL;
                sym.size = 0;
                ctx->symbols[labelCandidate] = sym;
            }
            return true;
        }
    }

    // Try AA commands
    if (ParseAACommand(ctx, trimmed, lineNum)) {
        return true;
    }

    // Parse as assembly instruction
    size_t spacePos = trimmed.find_first_of(" \t");
    std::string mnemonic;
    std::string operandsStr;

    if (spacePos != std::string::npos) {
        mnemonic = trimmed.substr(0, spacePos);
        operandsStr = Trim(trimmed.substr(spacePos));
    } else {
        mnemonic = trimmed;
    }

    // Handle multi-value data directives (db 90 90 90, db 'hello', etc.)
    std::string mnemonicLower = ToLower(mnemonic);
    if ((mnemonicLower == "db" || mnemonicLower == "dw" || mnemonicLower == "dd" || mnemonicLower == "dq")
        && !operandsStr.empty()) {
        // Check if this is a multi-value or string literal form
        bool isMultiValue = (operandsStr.find(' ') != std::string::npos && operandsStr.find(',') == std::string::npos && operandsStr.find('[') == std::string::npos)
                          || operandsStr[0] == '\'' || operandsStr[0] == '"'
                          || operandsStr.find(',') != std::string::npos;
        if (isMultiValue) {
            return ParseDataDirective(ctx, mnemonic, operandsStr, lineNum, line);
        }
    }

    // Parse operands
    Operand op1, op2;

    if (!operandsStr.empty()) {
        // Find comma separator (but not inside brackets or quotes)
        int bracketDepth = 0;
        bool inQuote = false;
        char quoteChar = 0;
        size_t commaPos = std::string::npos;
        for (size_t i = 0; i < operandsStr.size(); i++) {
            if (!inQuote) {
                if (operandsStr[i] == '[') bracketDepth++;
                else if (operandsStr[i] == ']') bracketDepth--;
                else if (operandsStr[i] == '\'' || operandsStr[i] == '"') {
                    inQuote = true;
                    quoteChar = operandsStr[i];
                }
                else if (operandsStr[i] == ',' && bracketDepth == 0) {
                    commaPos = i;
                    break;
                }
            } else if (operandsStr[i] == quoteChar) {
                inQuote = false;
            }
        }

        if (commaPos != std::string::npos) {
            std::string op1Str = Trim(operandsStr.substr(0, commaPos));
            std::string op2Str = Trim(operandsStr.substr(commaPos + 1));

            if (!ParseOperand(op1Str, op1, ctx)) {
                SetError(ctx, NEXUS_ASM_ERROR_INVALID_OPERAND, lineNum, "Invalid first operand", line.c_str());
                return false;
            }
            if (!ParseOperand(op2Str, op2, ctx)) {
                SetError(ctx, NEXUS_ASM_ERROR_INVALID_OPERAND, lineNum, "Invalid second operand", line.c_str());
                return false;
            }
        } else {
            if (!ParseOperand(operandsStr, op1, ctx)) {
                SetError(ctx, NEXUS_ASM_ERROR_INVALID_OPERAND, lineNum, "Invalid operand", line.c_str());
                return false;
            }
        }
    }

    // Handle unresolved labels
    if (op1.type == OperandType::Label) {
        PendingRelocation reloc;
        reloc.label = op1.label;
        reloc.instrAddr = ctx->currentAddress + ctx->outputBuffer.size();

        std::string mnLower = ToLower(mnemonic);
        if (mnLower == "jmp" || mnLower.starts_with("j") || mnLower == "call") {
            reloc.relocSize = 4;
            op1.type = OperandType::Rel32;
            op1.disp = 0;
        } else {
            reloc.relocSize = ctx->is64Bit ? 8 : 4;
            op1.type = ctx->is64Bit ? OperandType::Imm64 : OperandType::Imm32;
            op1.disp = 0;
        }

        reloc.offset = ctx->outputBuffer.size();
        ctx->pendingRelocations.push_back(reloc);
    }

    // Assemble
    std::vector<uint8_t> instrBytes;
    if (!AssembleInstruction(ctx, mnemonic, op1, op2, instrBytes)) {
        SetError(ctx, NEXUS_ASM_ERROR_UNKNOWN_OPCODE, lineNum,
                 ("Unknown instruction: " + mnemonic).c_str(), line.c_str());
        return false;
    }

    // Update relocation offsets
    for (auto& reloc : ctx->pendingRelocations) {
        if (reloc.offset == ctx->outputBuffer.size() - instrBytes.size() +
            (instrBytes.size() - reloc.relocSize)) {
            reloc.offset = ctx->outputBuffer.size() + instrBytes.size() - reloc.relocSize;
        }
    }

    ctx->outputBuffer.insert(ctx->outputBuffer.end(), instrBytes.begin(), instrBytes.end());
    return true;
}

// ============================================================================
// Relocation Resolution
// ============================================================================

bool ResolveRelocations(AssemblerContext* ctx) {
    for (const auto& reloc : ctx->pendingRelocations) {
        uint64_t targetAddr = 0;

        auto it = ctx->localLabels.find(reloc.label);
        if (it != ctx->localLabels.end()) {
            targetAddr = it->second;
        } else {
            auto sit = ctx->symbols.find(reloc.label);
            if (sit != ctx->symbols.end()) {
                targetAddr = sit->second.address;
            } else {
                SetError(ctx, NEXUS_ASM_ERROR_UNDEFINED_SYMBOL, 0,
                         ("Undefined symbol: " + reloc.label).c_str(), "");
                return false;
            }
        }

        int64_t offset = static_cast<int64_t>(targetAddr) -
                         static_cast<int64_t>(reloc.instrAddr + reloc.relocSize);

        if (reloc.relocSize == 1) {
            if (offset < -128 || offset > 127) {
                SetError(ctx, NEXUS_ASM_ERROR_RANGE, 0, "Relative jump out of range", "");
                return false;
            }
            ctx->outputBuffer[reloc.offset] = static_cast<uint8_t>(offset);
        } else if (reloc.relocSize == 4) {
            if (offset < INT32_MIN || offset > INT32_MAX) {
                SetError(ctx, NEXUS_ASM_ERROR_RANGE, 0, "Relative jump out of range", "");
                return false;
            }
            memcpy(&ctx->outputBuffer[reloc.offset], &offset, 4);
        } else {
            memcpy(&ctx->outputBuffer[reloc.offset], &targetAddr, 8);
        }
    }

    return true;
}

// ============================================================================
// Instruction Length Decoder
// ============================================================================

int GetInstructionLengthInternal(const uint8_t* code, bool is64Bit) {
    size_t len = 0;
    const uint8_t* p = code;

    // Prefixes
    while (*p == 0x66 || *p == 0x67 || *p == 0xF0 || *p == 0xF2 || *p == 0xF3 ||
           *p == 0x2E || *p == 0x36 || *p == 0x3E || *p == 0x26 || *p == 0x64 || *p == 0x65) {
        p++; len++;
    }

    // REX prefix (64-bit)
    if (is64Bit && (*p & 0xF0) == 0x40) {
        p++; len++;
    }

    // Opcode
    uint8_t opcode = *p++;
    len++;

    // Two-byte opcode
    if (opcode == 0x0F) {
        opcode = *p++;
        len++;

        // Check for three-byte opcodes
        if (opcode == 0x38 || opcode == 0x3A) {
            p++; len++;
        }
    }

    // Determine if ModR/M follows
    bool hasModRM = false;
    bool hasImm8 = false;
    bool hasImm16 = false;
    bool hasImm32 = false;

    if ((opcode & 0xC0) != 0xC0) {
        if ((opcode >= 0x00 && opcode <= 0x3F) ||
            (opcode >= 0x80 && opcode <= 0x8F) ||
            (opcode >= 0xC0 && opcode <= 0xC1) ||
            (opcode >= 0xC6 && opcode <= 0xC7) ||
            (opcode >= 0xD0 && opcode <= 0xD3) ||
            (opcode >= 0xF6 && opcode <= 0xF7) ||
            (opcode >= 0xFE && opcode <= 0xFF)) {
            hasModRM = true;
        }
    }

    // Check for immediate
    if (opcode >= 0xB0 && opcode <= 0xB7) hasImm8 = true;
    if (opcode >= 0xB8 && opcode <= 0xBF) hasImm32 = true;
    if (opcode == 0x68) hasImm32 = true;
    if (opcode == 0x6A) hasImm8 = true;
    if (opcode == 0xE8 || opcode == 0xE9) hasImm32 = true;
    if (opcode == 0xEB || opcode == 0xE0 || opcode == 0xE1 || opcode == 0xE2) hasImm8 = true;
    if (opcode >= 0x70 && opcode <= 0x7F) hasImm8 = true;
    if (opcode == 0xCD) hasImm8 = true;

    // ModR/M byte
    if (hasModRM) {
        uint8_t modrm = *p++;
        len++;

        uint8_t mod = (modrm >> 6) & 0x03;
        uint8_t rm = modrm & 0x07;

        // SIB byte
        if (mod != 0x03 && rm == 0x04) {
            p++; len++;
        }

        // Displacement
        if (mod == 0x01) {
            p++; len++;
        } else if (mod == 0x02 || (mod == 0x00 && rm == 0x05)) {
            p += 4; len += 4;
        }
    }

    // Immediate
    if (hasImm8) { p++; len++; }
    if (hasImm16) { p += 2; len += 2; }
    if (hasImm32) { p += 4; len += 4; }

    return len > 0 ? static_cast<int>(len) : 1;
}
