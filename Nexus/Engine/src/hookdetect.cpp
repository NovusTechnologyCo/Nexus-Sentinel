/**
 * @file hookdetect.cpp
 * @brief Hook detection: inline (JMP/hot-patch), IAT, and EAT hook scanning.
 *
 * Analyses module prologues for common inline hook patterns (relative JMP,
 * absolute JMP via register, hot-patch with short JMP), compares IAT entries
 * against expected export addresses, and checks EAT entries for forwarding
 * anomalies.  Uses Zydis for instruction-level prologue analysis.
 *
 * Bulk scanning, disk-image comparison, and restoration are in hookdetect_scan.cpp.
 */

#include "hookdetect_internal.h"
#include "../third_party/amalgamated-dist/Zydis.h"

/* ============================================================================
 * Global State
 * ============================================================================ */

HookScanContext g_scanContext;
std::mutex g_contextMutex;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

bool ReadProcessMem(HANDLE process, uint64_t address, void* buffer, size_t size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(process, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

static bool ReadProcessString(HANDLE process, uint64_t address, char* buffer, size_t bufferSize) {
    if (bufferSize == 0) return false;
    buffer[0] = '\0';

    size_t offset = 0;
    while (offset < bufferSize - 1) {
        size_t chunkSize = std::min((size_t)64, bufferSize - 1 - offset);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(process, (LPCVOID)(address + offset), buffer + offset, chunkSize, &bytesRead)) {
            break;
        }
        for (size_t i = 0; i < bytesRead; i++) {
            if (buffer[offset + i] == '\0') return true;
        }
        offset += bytesRead;
        if (bytesRead < chunkSize) break;
    }
    buffer[offset] = '\0';
    return offset > 0;
}

static bool GetPEHeaders(HANDLE process, uint64_t moduleBase, bool& is64Bit,
                         IMAGE_DOS_HEADER& dosHeader, IMAGE_NT_HEADERS64& ntHeaders64,
                         IMAGE_NT_HEADERS32& ntHeaders32) {
    if (!ReadProcessMem(process, moduleBase, &dosHeader, sizeof(dosHeader))) {
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (dosHeader.e_lfanew < 0 || dosHeader.e_lfanew > MAX_E_LFANEW) {
        return false;
    }

    uint64_t ntHeaderAddr = moduleBase + dosHeader.e_lfanew;
    DWORD signature;
    if (!ReadProcessMem(process, ntHeaderAddr, &signature, sizeof(signature))) {
        return false;
    }
    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!ReadProcessMem(process, ntHeaderAddr + sizeof(DWORD), &fileHeader, sizeof(fileHeader))) {
        return false;
    }

    is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

    if (is64Bit) {
        if (!ReadProcessMem(process, ntHeaderAddr, &ntHeaders64, sizeof(ntHeaders64))) {
            return false;
        }
    } else {
        if (!ReadProcessMem(process, ntHeaderAddr, &ntHeaders32, sizeof(ntHeaders32))) {
            return false;
        }
    }
    return true;
}

// Get module containing an address
bool GetModuleForAddress(HANDLE process, uint64_t address, wchar_t* moduleName, size_t nameLen, uint64_t* moduleBase) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }

    DWORD numMods = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < numMods; i++) {
        MODULEINFO modInfo;
        if (GetModuleInformation(process, hMods[i], &modInfo, sizeof(modInfo))) {
            uint64_t base = (uint64_t)modInfo.lpBaseOfDll;
            uint64_t end = base + modInfo.SizeOfImage;
            if (address >= base && address < end) {
                if (moduleName && nameLen > 0) {
                    GetModuleBaseNameW(process, hMods[i], moduleName, (DWORD)nameLen);
                }
                if (moduleBase) {
                    *moduleBase = base;
                }
                return true;
            }
        }
    }
    return false;
}

// Get module path for disk comparison
bool GetModulePath(HANDLE process, uint64_t moduleBase, wchar_t* path, size_t pathLen) {
    HMODULE hMod = (HMODULE)moduleBase;
    return GetModuleFileNameExW(process, hMod, path, (DWORD)pathLen) > 0;
}

// Read bytes from disk image at given RVA
bool ReadDiskBytes(const wchar_t* modulePath, uint64_t /*moduleBase*/, uint32_t rva,
                   uint8_t* buffer, size_t size, bool is64Bit) {
    HANDLE hFile = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead != sizeof(dosHeader)) {
        CloseHandle(hFile);
        return false;
    }

    // Seek to NT headers
    SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);

    // Read section headers to convert RVA to file offset
    DWORD sectionOffset;
    WORD numSections;

    if (is64Bit) {
        IMAGE_NT_HEADERS64 ntHeaders;
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL)) {
            CloseHandle(hFile);
            return false;
        }
        numSections = ntHeaders.FileHeader.NumberOfSections;
        sectionOffset = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    } else {
        IMAGE_NT_HEADERS32 ntHeaders;
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL)) {
            CloseHandle(hFile);
            return false;
        }
        numSections = ntHeaders.FileHeader.NumberOfSections;
        sectionOffset = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    }

    // Read sections to find the one containing our RVA
    SetFilePointer(hFile, sectionOffset, NULL, FILE_BEGIN);
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    if (!ReadFile(hFile, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL)) {
        CloseHandle(hFile);
        return false;
    }

    // Find section containing RVA
    DWORD fileOffset = 0;
    for (const auto& section : sections) {
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            fileOffset = section.PointerToRawData + (rva - section.VirtualAddress);
            break;
        }
    }

    if (fileOffset == 0) {
        CloseHandle(hFile);
        return false;
    }

    // Read the bytes
    SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);
    bool result = ReadFile(hFile, buffer, (DWORD)size, &bytesRead, NULL) && bytesRead == size;
    CloseHandle(hFile);
    return result;
}

// Calculate jump target from instruction bytes
static uint64_t CalculateJumpTarget(const uint8_t* bytes, uint64_t instrAddr, size_t instrLen, bool is64Bit) {
    if (instrLen == 0) return 0;

    // E9 xx xx xx xx - JMP rel32
    if (bytes[0] == 0xE9 && instrLen >= 5) {
        int32_t rel = *(int32_t*)(bytes + 1);
        return instrAddr + 5 + rel;
    }

    // EB xx - JMP rel8
    if (bytes[0] == 0xEB && instrLen >= 2) {
        int8_t rel = (int8_t)bytes[1];
        return instrAddr + 2 + rel;
    }

    // FF 25 xx xx xx xx - JMP [rip+disp32] (x64)
    if (bytes[0] == 0xFF && bytes[1] == 0x25 && instrLen >= 6 && is64Bit) {
        int32_t disp = *(int32_t*)(bytes + 2);
        uint64_t targetAddr = instrAddr + 6 + disp;
        // The target is an address that contains the actual jump destination
        return targetAddr; // Caller should dereference this
    }

    // 68 xx xx xx xx C3 - PUSH addr; RET
    if (bytes[0] == 0x68 && instrLen >= 6 && bytes[5] == 0xC3) {
        return *(uint32_t*)(bytes + 1);
    }

    // 48 B8 xx xx xx xx xx xx xx xx FF E0 - MOV RAX, imm64; JMP RAX
    if (is64Bit && bytes[0] == 0x48 && bytes[1] == 0xB8 && instrLen >= 12 &&
        bytes[10] == 0xFF && bytes[11] == 0xE0) {
        return *(uint64_t*)(bytes + 2);
    }

    return 0;
}

// Check if address is within a module's bounds
static bool IsAddressInModule(HANDLE process, uint64_t address, uint64_t moduleBase) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(process, (HMODULE)moduleBase, &modInfo, sizeof(modInfo))) {
        return false;
    }
    uint64_t end = moduleBase + modInfo.SizeOfImage;
    return address >= moduleBase && address < end;
}

/* ============================================================================
 * Inline Hook Detection
 * ============================================================================ */

static bool CheckForInlineHook(HANDLE process, uint64_t functionAddress, bool is64Bit,
                               NexusInlineHookInfo* info, uint64_t moduleBase) {
    if (!info) return false;

    memset(info, 0, sizeof(*info));
    info->functionAddress = functionAddress;

    // Read function prologue
    uint8_t prologue[32];
    if (!ReadProcessMem(process, functionAddress, prologue, sizeof(prologue))) {
        return false;
    }

    memcpy(info->prologueBytes, prologue, 16);

    // Check for hotpatch: 2-byte NOP sled (MOV EDI, EDI = 8B FF) with JMP before
    bool isHotpatch = false;
    if (prologue[0] == 0x8B && prologue[1] == 0xFF) {
        // Check for short jump at function-5
        uint8_t hotpatchArea[7];
        if (ReadProcessMem(process, functionAddress - 5, hotpatchArea, sizeof(hotpatchArea))) {
            if (hotpatchArea[0] == 0xE9 || hotpatchArea[0] == 0xEB) {
                isHotpatch = true;
                info->isHotpatch = 1;
                // Calculate jump target from hotpatch
                if (hotpatchArea[0] == 0xEB) {
                    int8_t rel = (int8_t)hotpatchArea[1];
                    info->jumpTarget = (functionAddress - 5) + 2 + rel;
                } else {
                    int32_t rel = *(int32_t*)(hotpatchArea + 1);
                    info->jumpTarget = (functionAddress - 5) + 5 + rel;
                }
                info->hookSize = 5;
                return true;
            }
        }
    }

    // Initialize Zydis decoder
    ZydisDecoder decoder;
    if (is64Bit) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }

    // Decode first instruction
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, prologue, sizeof(prologue),
                                              &instruction, operands))) {
        return false;
    }

    // Check for JMP instruction
    if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
        info->hookSize = instruction.length;

        // Calculate target
        uint64_t target = 0;

        if (instruction.operand_count > 0) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                // Relative jump
                if (operands[0].imm.is_relative) {
                    target = functionAddress + instruction.length + operands[0].imm.value.s;
                } else {
                    target = operands[0].imm.value.u;
                }
            } else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                // Indirect jump - [rip+disp] or [addr]
                if (is64Bit && operands[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t targetAddr = functionAddress + instruction.length + operands[0].mem.disp.value;
                    // Read the actual target from memory
                    ReadProcessMem(process, targetAddr, &target, sizeof(target));
                }
            }
        }

        if (target == 0) {
            target = CalculateJumpTarget(prologue, functionAddress, instruction.length, is64Bit);
        }

        info->jumpTarget = target;

        // Check if target is outside the module
        if (moduleBase != 0 && target != 0) {
            if (!IsAddressInModule(process, target, moduleBase)) {
                GetModuleForAddress(process, target, info->targetModule,
                                   sizeof(info->targetModule)/sizeof(wchar_t), nullptr);
                return true; // Hooked!
            }
        }
    }

    // Check for PUSH+RET pattern
    if (prologue[0] == 0x68 && prologue[5] == 0xC3) {
        info->hookSize = 6;
        info->jumpTarget = *(uint32_t*)(prologue + 1);
        if (moduleBase != 0 && !IsAddressInModule(process, info->jumpTarget, moduleBase)) {
            GetModuleForAddress(process, info->jumpTarget, info->targetModule,
                               sizeof(info->targetModule)/sizeof(wchar_t), nullptr);
            return true;
        }
    }

    // Check for MOV RAX, addr; JMP RAX (x64)
    if (is64Bit && prologue[0] == 0x48 && prologue[1] == 0xB8 &&
        prologue[10] == 0xFF && prologue[11] == 0xE0) {
        info->hookSize = 12;
        info->jumpTarget = *(uint64_t*)(prologue + 2);
        if (moduleBase != 0 && !IsAddressInModule(process, info->jumpTarget, moduleBase)) {
            GetModuleForAddress(process, info->jumpTarget, info->targetModule,
                               sizeof(info->targetModule)/sizeof(wchar_t), nullptr);
            return true;
        }
    }

    return false;
}

/* ============================================================================
 * Hook Detection API (Inline, IAT, EAT)
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_HookCheckInline(
    NexusProcessHandle process,
    uint64_t functionAddress,
    NexusInlineHookInfo* info)
{
    if (!process || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    bool is64Bit = !ctx->is32Bit;

    // Find module containing function
    uint64_t moduleBase = 0;
    wchar_t moduleName[260] = {0};
    GetModuleForAddress(ctx->hProcess, functionAddress, moduleName, 260, &moduleBase);

    if (CheckForInlineHook(ctx->hProcess, functionAddress, is64Bit, info, moduleBase)) {
        wcscpy_s(info->moduleName, moduleName);
        return NEXUS_OK;
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_HookScanInline(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusInlineHookInfo* buffer,
    size_t bufferCount,
    size_t* count)
{
    if (!process || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *count = 0;

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;
    bool is64Bit = !ctx->is32Bit;

    // Get module info
    wchar_t moduleName[260] = {0};
    GetModuleBaseNameW(hProcess, (HMODULE)moduleBase, moduleName, 260);

    // Parse PE to get exports
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders64;
    IMAGE_NT_HEADERS32 ntHeaders32;
    bool isPE64;

    if (!GetPEHeaders(hProcess, moduleBase, isPE64, dosHeader, ntHeaders64, ntHeaders32)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    DWORD exportDirRva;
    if (isPE64) {
        exportDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        exportDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }

    if (exportDirRva == 0) {
        return NEXUS_OK; // No exports
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMem(hProcess, moduleBase + exportDirRva, &exportDir, sizeof(exportDir))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (exportDir.NumberOfFunctions > MAX_EXPORTS) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Read function addresses
    std::vector<DWORD> functions(exportDir.NumberOfFunctions);
    if (!ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfFunctions,
                        functions.data(), exportDir.NumberOfFunctions * sizeof(DWORD))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Read names
    std::vector<DWORD> nameRvas(exportDir.NumberOfNames);
    std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
    if (exportDir.NumberOfNames > 0) {
        ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfNames,
                       nameRvas.data(), exportDir.NumberOfNames * sizeof(DWORD));
        ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfNameOrdinals,
                       nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD));
    }

    // Scan each export
    size_t found = 0;
    for (DWORD i = 0; i < exportDir.NumberOfFunctions && (buffer == nullptr || found < bufferCount); i++) {
        if (functions[i] == 0) continue;

        uint64_t funcAddr = moduleBase + functions[i];
        NexusInlineHookInfo tempInfo;

        if (CheckForInlineHook(hProcess, funcAddr, is64Bit, &tempInfo, moduleBase)) {
            wcscpy_s(tempInfo.moduleName, moduleName);

            // Find function name
            for (DWORD j = 0; j < exportDir.NumberOfNames; j++) {
                if (nameOrdinals[j] == i) {
                    ReadProcessString(hProcess, moduleBase + nameRvas[j],
                                     tempInfo.functionName, sizeof(tempInfo.functionName));
                    break;
                }
            }

            if (buffer && found < bufferCount) {
                buffer[found] = tempInfo;
            }
            found++;
        }
    }

    *count = found;
    return (buffer && found > bufferCount) ? NEXUS_ERROR_INSUFFICIENT_BUFFER : NEXUS_OK;
}

/* ============================================================================
 * IAT Hook Detection
 * ============================================================================ */

NEXUS_API NexusResult Nexus_HookScanIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusIatHookInfo* buffer,
    size_t bufferCount,
    size_t* count)
{
    if (!process || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *count = 0;

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;

    // Get module name
    wchar_t moduleName[260] = {0};
    GetModuleBaseNameW(hProcess, (HMODULE)moduleBase, moduleName, 260);

    // Parse PE headers
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders64;
    IMAGE_NT_HEADERS32 ntHeaders32;
    bool isPE64;

    if (!GetPEHeaders(hProcess, moduleBase, isPE64, dosHeader, ntHeaders64, ntHeaders32)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    DWORD importDirRva;
    if (isPE64) {
        importDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        importDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    if (importDirRva == 0) {
        return NEXUS_OK; // No imports
    }

    size_t found = 0;
    uint64_t importDescAddr = moduleBase + importDirRva;
    DWORD dllCount = 0;

    while (dllCount < 1000) { // Limit iterations
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        if (!ReadProcessMem(hProcess, importDescAddr, &importDesc, sizeof(importDesc))) {
            break;
        }

        if (importDesc.Name == 0) {
            break;
        }

        // Read DLL name
        char dllNameA[260];
        wchar_t dllNameW[260];
        ReadProcessString(hProcess, moduleBase + importDesc.Name, dllNameA, sizeof(dllNameA));
        MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, dllNameW, 260);

        // Try to get expected addresses by loading the DLL
        HMODULE hDll = GetModuleHandleA(dllNameA);
        if (!hDll) {
            hDll = LoadLibraryExA(dllNameA, NULL, DONT_RESOLVE_DLL_REFERENCES);
        }

        // Process thunks
        uint64_t thunkAddr = moduleBase + (importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk);
        uint64_t iatAddr = moduleBase + importDesc.FirstThunk;
        DWORD thunkCount = 0;

        while (thunkCount < MAX_IMPORTS) {
            uint64_t thunkValue;
            uint64_t actualAddr;

            if (isPE64) {
                if (!ReadProcessMem(hProcess, thunkAddr, &thunkValue, sizeof(uint64_t))) break;
                if (!ReadProcessMem(hProcess, iatAddr, &actualAddr, sizeof(uint64_t))) break;
                thunkAddr += sizeof(uint64_t);
            } else {
                DWORD thunk32, actual32;
                if (!ReadProcessMem(hProcess, thunkAddr, &thunk32, sizeof(DWORD))) break;
                if (!ReadProcessMem(hProcess, iatAddr, &actual32, sizeof(DWORD))) break;
                thunkValue = thunk32;
                actualAddr = actual32;
                thunkAddr += sizeof(DWORD);
            }

            if (thunkValue == 0) break;

            // Get function name
            char funcName[256] = {0};
            bool isOrdinal = isPE64 ?
                (thunkValue & IMAGE_ORDINAL_FLAG64) != 0 :
                (thunkValue & IMAGE_ORDINAL_FLAG32) != 0;

            WORD ordinal = 0;
            if (isOrdinal) {
                ordinal = (WORD)(thunkValue & 0xFFFF);
            } else {
                uint64_t rva = isPE64 ?
                    (thunkValue & 0x7FFFFFFFFFFFFFFFULL) :
                    (thunkValue & 0x7FFFFFFFULL);
                uint64_t hintNameAddr = moduleBase + rva;
                WORD hint;
                ReadProcessMem(hProcess, hintNameAddr, &hint, sizeof(hint));
                ReadProcessString(hProcess, hintNameAddr + sizeof(WORD), funcName, sizeof(funcName));
            }

            // Get expected address
            uint64_t expectedAddr = 0;
            if (hDll) {
                FARPROC proc = isOrdinal ?
                    GetProcAddress(hDll, MAKEINTRESOURCEA(ordinal)) :
                    GetProcAddress(hDll, funcName);
                expectedAddr = (uint64_t)proc;
            }

            // Check if hooked
            bool isHooked = false;
            if (expectedAddr != 0 && actualAddr != expectedAddr) {
                // Verify it's not just ASLR - check if it's in same module
                wchar_t expectedModule[260] = {0};
                wchar_t actualModule[260] = {0};
                GetModuleForAddress(hProcess, expectedAddr, expectedModule, 260, nullptr);
                GetModuleForAddress(hProcess, actualAddr, actualModule, 260, nullptr);

                if (_wcsicmp(expectedModule, actualModule) != 0) {
                    isHooked = true;
                }
            }

            if (isHooked) {
                if (buffer && found < bufferCount) {
                    NexusIatHookInfo& info = buffer[found];
                    wcscpy_s(info.importModule, moduleName);
                    wcscpy_s(info.dllName, dllNameW);
                    strncpy_s(info.functionName, funcName, sizeof(info.functionName) - 1);
                    info.thunkRva = (DWORD)(iatAddr - moduleBase);
                    info.expectedAddress = expectedAddr;
                    info.actualAddress = actualAddr;
                    info.hookTarget = actualAddr;
                    GetModuleForAddress(hProcess, actualAddr, info.targetModule, 260, nullptr);
                    info.isHooked = 1;
                }
                found++;
            }

            iatAddr += isPE64 ? sizeof(uint64_t) : sizeof(DWORD);
            thunkCount++;
        }

        importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        dllCount++;
    }

    *count = found;
    return (buffer && found > bufferCount) ? NEXUS_ERROR_INSUFFICIENT_BUFFER : NEXUS_OK;
}

NEXUS_API NexusResult Nexus_HookCheckIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const wchar_t* dllName,
    const char* functionName,
    NexusIatHookInfo* info)
{
    if (!process || !dllName || !functionName || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Scan IAT and find specific entry
    size_t count;
    NexusResult result = Nexus_HookScanIat(process, moduleBase, nullptr, 0, &count);
    if (result != NEXUS_OK || count == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    std::vector<NexusIatHookInfo> hooks(count);
    result = Nexus_HookScanIat(process, moduleBase, hooks.data(), count, &count);
    if (result != NEXUS_OK) {
        return result;
    }

    for (const auto& hook : hooks) {
        if (_wcsicmp(hook.dllName, dllName) == 0 &&
            _stricmp(hook.functionName, functionName) == 0) {
            *info = hook;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_HookVerifyIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    uint32_t* hookCount,
    uint32_t* totalEntries)
{
    if (!process) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t count;
    NexusResult result = Nexus_HookScanIat(process, moduleBase, nullptr, 0, &count);

    if (hookCount) *hookCount = (uint32_t)count;

    // Count total IAT entries (simplified - just get import count)
    if (totalEntries) {
        auto* ctx = static_cast<NexusProcessHandleData*>(process);

        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS64 ntHeaders64;
        IMAGE_NT_HEADERS32 ntHeaders32;
        bool is64Bit;

        if (GetPEHeaders(ctx->hProcess, moduleBase, is64Bit, dosHeader, ntHeaders64, ntHeaders32)) {
            // Parse imports to count total
            size_t total = 0;
            DWORD importDirRva = is64Bit ?
                ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
                ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

            if (importDirRva != 0) {
                uint64_t importDescAddr = moduleBase + importDirRva;
                for (DWORD i = 0; i < 1000; i++) {
                    IMAGE_IMPORT_DESCRIPTOR desc;
                    if (!ReadProcessMem(ctx->hProcess, importDescAddr, &desc, sizeof(desc))) break;
                    if (desc.Name == 0) break;

                    uint64_t thunkAddr = moduleBase + desc.FirstThunk;
                    for (DWORD j = 0; j < MAX_IMPORTS; j++) {
                        uint64_t thunk;
                        if (is64Bit) {
                            if (!ReadProcessMem(ctx->hProcess, thunkAddr, &thunk, 8)) break;
                            thunkAddr += 8;
                        } else {
                            DWORD t32;
                            if (!ReadProcessMem(ctx->hProcess, thunkAddr, &t32, 4)) break;
                            thunk = t32;
                            thunkAddr += 4;
                        }
                        if (thunk == 0) break;
                        total++;
                    }
                    importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            *totalEntries = (uint32_t)total;
        } else {
            *totalEntries = 0;
        }
    }

    return result;
}

/* ============================================================================
 * EAT Hook Detection
 * ============================================================================ */

NEXUS_API NexusResult Nexus_HookScanEat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count)
{
    if (!process || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *count = 0;

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;

    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, (HMODULE)moduleBase, &modInfo, sizeof(modInfo))) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    wchar_t moduleName[260] = {0};
    GetModuleBaseNameW(hProcess, (HMODULE)moduleBase, moduleName, 260);

    // Parse PE
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders64;
    IMAGE_NT_HEADERS32 ntHeaders32;
    bool is64Bit;

    if (!GetPEHeaders(hProcess, moduleBase, is64Bit, dosHeader, ntHeaders64, ntHeaders32)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    DWORD exportDirRva, exportDirSize;
    if (is64Bit) {
        exportDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        exportDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (exportDirRva == 0) {
        return NEXUS_OK;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMem(hProcess, moduleBase + exportDirRva, &exportDir, sizeof(exportDir))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (exportDir.NumberOfFunctions > MAX_EXPORTS) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::vector<DWORD> functions(exportDir.NumberOfFunctions);
    if (!ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfFunctions,
                        functions.data(), exportDir.NumberOfFunctions * sizeof(DWORD))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    std::vector<DWORD> nameRvas(exportDir.NumberOfNames);
    std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
    if (exportDir.NumberOfNames > 0) {
        ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfNames,
                       nameRvas.data(), exportDir.NumberOfNames * sizeof(DWORD));
        ReadProcessMem(hProcess, moduleBase + exportDir.AddressOfNameOrdinals,
                       nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD));
    }

    size_t found = 0;
    for (DWORD i = 0; i < exportDir.NumberOfFunctions; i++) {
        if (functions[i] == 0) continue;

        // Check if forwarded (legitimate, points inside export directory)
        bool isForwarded = functions[i] >= exportDirRva && functions[i] < exportDirRva + exportDirSize;
        if (isForwarded) continue;

        // Check if export points outside module
        uint64_t exportAddr = moduleBase + functions[i];
        if (exportAddr < moduleBase || exportAddr >= moduleBase + modInfo.SizeOfImage) {
            // EAT hook detected!
            if (buffer && found < bufferCount) {
                NexusHookInfo& info = buffer[found];
                memset(&info, 0, sizeof(info));
                info.hookAddress = moduleBase + exportDir.AddressOfFunctions + i * sizeof(DWORD);
                info.targetAddress = exportAddr;
                info.originalAddress = 0; // Unknown
                info.hookType = NEXUS_HOOK_EAT;
                info.hookSize = 4;
                wcscpy_s(info.moduleName, moduleName);
                GetModuleForAddress(hProcess, exportAddr, info.targetModule, 260, nullptr);
                info.confidence = 90;
                info.isSuspicious = 1;

                // Find name
                for (DWORD j = 0; j < exportDir.NumberOfNames; j++) {
                    if (nameOrdinals[j] == i) {
                        ReadProcessString(hProcess, moduleBase + nameRvas[j],
                                         info.functionName, sizeof(info.functionName));
                        break;
                    }
                }
            }
            found++;
        }
    }

    *count = found;
    return (buffer && found > bufferCount) ? NEXUS_ERROR_INSUFFICIENT_BUFFER : NEXUS_OK;
}

NEXUS_API NexusResult Nexus_HookCheckEat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const char* functionName,
    NexusHookInfo* info)
{
    if (!process || !functionName || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t count;
    NexusResult result = Nexus_HookScanEat(process, moduleBase, nullptr, 0, &count);
    if (result != NEXUS_OK || count == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    std::vector<NexusHookInfo> hooks(count);
    result = Nexus_HookScanEat(process, moduleBase, hooks.data(), count, &count);
    if (result != NEXUS_OK) {
        return result;
    }

    for (const auto& hook : hooks) {
        if (_stricmp(hook.functionName, functionName) == 0) {
            *info = hook;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

} // extern "C"
