/**
 * @file speedhack_hook.cpp
 * @brief Speedhack hook building: remote module resolution, stolen-byte relocation, and code gen.
 *
 * Resolves target-process module bases, parses PE exports to find
 * timing API addresses, relocates stolen prologue bytes for the
 * trampoline, and generates 32-bit or 64-bit hook stubs that
 * apply the speed multiplier.
 *
 * Public API functions are in speedhack.cpp.
 */

#include "speedhack_internal.h"

// ============================================================================
// Helper: Get module base address in target process
// ============================================================================

static uint64_t GetRemoteModuleBase(DWORD pid, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    uint64_t baseAddress = 0;

    if (Module32FirstW(snapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);
    return baseAddress;
}

// ============================================================================
// Helper: Get exported function RVA by parsing PE export table
// ============================================================================

static uint32_t GetExportRVAFromFile(const wchar_t* dllPath, const char* functionName) {
    HMODULE hMod = LoadLibraryExW(dllPath, nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!hMod) return 0;

    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary(hMod);
        return 0;
    }

    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(hMod) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary(hMod);
        return 0;
    }

    DWORD exportDirRVA;
    DWORD exportDirSize;
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&ntHeaders->OptionalHeader);
        exportDirRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        auto* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&ntHeaders->OptionalHeader);
        exportDirRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (!exportDirRVA) {
        FreeLibrary(hMod);
        return 0;
    }

    (void)exportDirSize;
    auto* baseAddr = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(hMod) & ~3);

    auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    uint8_t* exportDirPtr = nullptr;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (exportDirRVA >= sectionHeader[i].VirtualAddress &&
            exportDirRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
            DWORD offset = exportDirRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
            exportDirPtr = baseAddr + offset;
            break;
        }
    }

    if (!exportDirPtr) {
        FreeLibrary(hMod);
        return 0;
    }

    auto* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(exportDirPtr);

    auto RvaToPtr = [&](DWORD rva) -> uint8_t* {
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (rva >= sectionHeader[i].VirtualAddress &&
                rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                DWORD offset = rva - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
                return baseAddr + offset;
            }
        }
        return nullptr;
    };

    auto* names = reinterpret_cast<DWORD*>(RvaToPtr(exportDir->AddressOfNames));
    auto* ordinals = reinterpret_cast<WORD*>(RvaToPtr(exportDir->AddressOfNameOrdinals));
    auto* functions = reinterpret_cast<DWORD*>(RvaToPtr(exportDir->AddressOfFunctions));

    if (!names || !ordinals || !functions) {
        FreeLibrary(hMod);
        return 0;
    }

    uint32_t rva = 0;
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        auto* name = reinterpret_cast<const char*>(RvaToPtr(names[i]));
        if (name && strcmp(name, functionName) == 0) {
            WORD ordinal = ordinals[i];
            rva = functions[ordinal];
            break;
        }
    }

    FreeLibrary(hMod);
    return rva;
}

// ============================================================================
// Helper: Get function address in target process
// ============================================================================

uint64_t GetRemoteFunctionAddress(DWORD pid, const wchar_t* moduleName,
                                  const char* functionName, bool is32BitTarget) {
    uint64_t remoteBase = GetRemoteModuleBase(pid, moduleName);
    if (!remoteBase) return 0;

    wchar_t dllPath[MAX_PATH];
    if (is32BitTarget) {
        GetSystemWow64DirectoryW(dllPath, MAX_PATH);
    } else {
        GetSystemDirectoryW(dllPath, MAX_PATH);
    }
    wcscat_s(dllPath, L"\\");
    wcscat_s(dllPath, moduleName);

    uint32_t rva = GetExportRVAFromFile(dllPath, functionName);
    if (!rva) return 0;

    return remoteBase + rva;
}

// ============================================================================
// Relocate stolen bytes - fix relative jumps/calls
// ============================================================================

static bool RelocateStolenBytes(uint8_t* dest, const uint8_t* src, size_t count,
                                 uint64_t oldAddr, uint64_t newAddr, bool is32Bit) {
    memcpy(dest, src, count);

    size_t i = 0;
    while (i < count) {
        uint8_t* p = dest + i;
        uint8_t opcode = src[i];

        // E9: JMP rel32
        if (opcode == 0xE9 && i + 5 <= count) {
            int32_t oldRel;
            memcpy(&oldRel, src + i + 1, 4);
            uint64_t target = oldAddr + i + 5 + oldRel;
            int64_t newRel64 = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr + i + 5);
            if (is32Bit && (newRel64 < INT32_MIN || newRel64 > INT32_MAX)) {
                return false;
            }
            int32_t newRel = static_cast<int32_t>(newRel64);
            memcpy(p + 1, &newRel, 4);
            i += 5;
            continue;
        }

        // E8: CALL rel32
        if (opcode == 0xE8 && i + 5 <= count) {
            int32_t oldRel;
            memcpy(&oldRel, src + i + 1, 4);
            uint64_t target = oldAddr + i + 5 + oldRel;
            int64_t newRel64 = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr + i + 5);
            if (is32Bit && (newRel64 < INT32_MIN || newRel64 > INT32_MAX)) {
                return false;
            }
            int32_t newRel = static_cast<int32_t>(newRel64);
            memcpy(p + 1, &newRel, 4);
            i += 5;
            continue;
        }

        // EB: JMP rel8
        if (opcode == 0xEB && i + 2 <= count) {
            int8_t oldRel = static_cast<int8_t>(src[i + 1]);
            uint64_t target = oldAddr + i + 2 + oldRel;
            int64_t newRel64 = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr + i + 2);
            if (newRel64 < -128 || newRel64 > 127) {
                return false;
            }
            p[1] = static_cast<uint8_t>(static_cast<int8_t>(newRel64));
            i += 2;
            continue;
        }

        // 0F 8x: Jcc rel32
        if (opcode == 0x0F && i + 1 < count) {
            uint8_t opcode2 = src[i + 1];
            if (opcode2 >= 0x80 && opcode2 <= 0x8F && i + 6 <= count) {
                int32_t oldRel;
                memcpy(&oldRel, src + i + 2, 4);
                uint64_t target = oldAddr + i + 6 + oldRel;
                int64_t newRel64 = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr + i + 6);
                if (is32Bit && (newRel64 < INT32_MIN || newRel64 > INT32_MAX)) {
                    return false;
                }
                int32_t newRel = static_cast<int32_t>(newRel64);
                memcpy(p + 2, &newRel, 4);
                i += 6;
                continue;
            }
        }

        // 7x: Jcc rel8
        if (opcode >= 0x70 && opcode <= 0x7F && i + 2 <= count) {
            int8_t oldRel = static_cast<int8_t>(src[i + 1]);
            uint64_t target = oldAddr + i + 2 + oldRel;
            int64_t newRel64 = static_cast<int64_t>(target) - static_cast<int64_t>(newAddr + i + 2);
            if (newRel64 < -128 || newRel64 > 127) {
                return false;
            }
            p[1] = static_cast<uint8_t>(static_cast<int8_t>(newRel64));
            i += 2;
            continue;
        }

        size_t len = GetInstructionLength(src + i, !is32Bit);
        if (len == 0) {
            return false;
        }
        i += len;
    }

    return true;
}

// ============================================================================
// Build 32-bit Hook Code
// ============================================================================

size_t Build32BitHook(uint8_t* buffer, size_t bufferSize,
                      uint64_t hookBaseAddr, uint64_t sharedDataAddr,
                      uint64_t originalFuncAddr, const uint8_t* stolenBytes,
                      size_t stolenBytesCount) {
    if (bufferSize < 256) return 0;

    uint8_t* p = buffer;
    size_t trampolineOffset = 128;

    // Hook code
    *p++ = 0x55;
    *p++ = 0x89; *p++ = 0xE5;
    *p++ = 0x53;
    *p++ = 0x56;
    *p++ = 0x57;
    *p++ = 0x83; *p++ = 0xEC; *p++ = 0x10;

    *p++ = 0x8B; *p++ = 0x7D; *p++ = 0x08;

    *p++ = 0x57;
    *p++ = 0xB8;
    uint32_t trampolineAddr = static_cast<uint32_t>(hookBaseAddr + trampolineOffset);
    memcpy(p, &trampolineAddr, 4); p += 4;
    *p++ = 0xFF; *p++ = 0xD0;

    *p++ = 0xBB;
    uint32_t sharedAddr32 = static_cast<uint32_t>(sharedDataAddr);
    memcpy(p, &sharedAddr32, 4); p += 4;

    *p++ = 0x83; *p++ = 0x7B; *p++ = 0x08; *p++ = 0x00;

    *p++ = 0x74;
    uint8_t* jzPatch = p;
    *p++ = 0x00;

    *p++ = 0x83; *p++ = 0x43; *p++ = 0x20; *p++ = 0x01;
    *p++ = 0x83; *p++ = 0x53; *p++ = 0x24; *p++ = 0x00;

    *p++ = 0x8B; *p++ = 0x07;
    *p++ = 0x8B; *p++ = 0x57; *p++ = 0x04;

    *p++ = 0x2B; *p++ = 0x43; *p++ = 0x10;
    *p++ = 0x1B; *p++ = 0x53; *p++ = 0x14;

    *p++ = 0x89; *p++ = 0x45; *p++ = 0xF0;
    *p++ = 0x89; *p++ = 0x55; *p++ = 0xF4;

    *p++ = 0xDF; *p++ = 0x6D; *p++ = 0xF0;
    *p++ = 0xDC; *p++ = 0x0B;
    *p++ = 0xDF; *p++ = 0x7D; *p++ = 0xF0;

    *p++ = 0x8B; *p++ = 0x45; *p++ = 0xF0;
    *p++ = 0x8B; *p++ = 0x55; *p++ = 0xF4;

    *p++ = 0x03; *p++ = 0x43; *p++ = 0x10;
    *p++ = 0x13; *p++ = 0x53; *p++ = 0x14;

    *p++ = 0x89; *p++ = 0x07;
    *p++ = 0x89; *p++ = 0x57; *p++ = 0x04;

    *jzPatch = static_cast<uint8_t>(p - jzPatch - 1);

    *p++ = 0xB8; *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x83; *p++ = 0xC4; *p++ = 0x10;
    *p++ = 0x5F;
    *p++ = 0x5E;
    *p++ = 0x5B;
    *p++ = 0x5D;
    *p++ = 0xC2; *p++ = 0x04; *p++ = 0x00;

    // Trampoline
    p = buffer + trampolineOffset;
    uint64_t trampolineAddr32 = hookBaseAddr + trampolineOffset;

    if (!RelocateStolenBytes(p, stolenBytes, stolenBytesCount,
                             originalFuncAddr, trampolineAddr32, true)) {
        return 0;
    }
    p += stolenBytesCount;

    *p++ = 0xE9;
    uint32_t returnAddr = static_cast<uint32_t>(originalFuncAddr + stolenBytesCount);
    uint32_t jumpFrom = static_cast<uint32_t>(hookBaseAddr + trampolineOffset + stolenBytesCount + 5);
    int32_t relOffset = returnAddr - jumpFrom;
    memcpy(p, &relOffset, 4); p += 4;

    return p - buffer;
}

// ============================================================================
// Build 64-bit Hook Code
// ============================================================================

size_t Build64BitHook(uint8_t* buffer, size_t bufferSize,
                      uint64_t hookBaseAddr, uint64_t sharedDataAddr,
                      uint64_t originalFuncAddr, const uint8_t* stolenBytes,
                      size_t stolenBytesCount) {
    if (bufferSize < 512) return 0;

    uint8_t* p = buffer;
    size_t trampolineOffset = 256;

    // Hook code
    *p++ = 0x53;
    *p++ = 0x56;
    *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;

    *p++ = 0x48; *p++ = 0x89; *p++ = 0xCF;

    *p++ = 0x48; *p++ = 0xB8;
    uint64_t trampolineAddr64 = hookBaseAddr + trampolineOffset;
    memcpy(p, &trampolineAddr64, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xD0;

    *p++ = 0x48; *p++ = 0x89; *p++ = 0xC6;

    *p++ = 0x48; *p++ = 0xBB;
    memcpy(p, &sharedDataAddr, 8); p += 8;

    *p++ = 0x83; *p++ = 0x7B; *p++ = 0x08; *p++ = 0x00;

    *p++ = 0x74;
    uint8_t* jzPatch = p;
    *p++ = 0x00;

    *p++ = 0x48; *p++ = 0xFF; *p++ = 0x43; *p++ = 0x20;

    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x07;

    *p++ = 0x48; *p++ = 0x2B; *p++ = 0x43; *p++ = 0x10;

    *p++ = 0xF2; *p++ = 0x48; *p++ = 0x0F; *p++ = 0x2A; *p++ = 0xC0;
    *p++ = 0xF2; *p++ = 0x0F; *p++ = 0x59; *p++ = 0x03;
    *p++ = 0xF2; *p++ = 0x48; *p++ = 0x0F; *p++ = 0x2C; *p++ = 0xC0;

    *p++ = 0x48; *p++ = 0x03; *p++ = 0x43; *p++ = 0x10;

    *p++ = 0x48; *p++ = 0x89; *p++ = 0x07;

    *jzPatch = static_cast<uint8_t>(p - jzPatch - 1);

    *p++ = 0x48; *p++ = 0x89; *p++ = 0xF0;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;
    *p++ = 0x5F;
    *p++ = 0x5E;
    *p++ = 0x5B;
    *p++ = 0xC3;

    // Trampoline
    p = buffer + trampolineOffset;
    uint64_t trampolineAddrCalc = hookBaseAddr + trampolineOffset;

    if (!RelocateStolenBytes(p, stolenBytes, stolenBytesCount,
                             originalFuncAddr, trampolineAddrCalc, false)) {
        return 0;
    }
    p += stolenBytesCount;

    *p++ = 0x48; *p++ = 0xB8;
    uint64_t returnAddr = originalFuncAddr + stolenBytesCount;
    memcpy(p, &returnAddr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    return p - buffer;
}
