/**
 * @file pe.cpp
 * @brief PE parsing core: header reading, section enumeration, and import enumeration.
 *
 * Shared helper functions for reading DOS/NT headers, RVA-to-offset
 * conversion, section enumeration, and full import table parsing
 * (by name and by ordinal) from a remote process.
 *
 * Export enumeration is in pe_exports.cpp.
 */

#include "pe_internal.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

bool PeReadProcessMem(HANDLE process, uint64_t address, void* buffer, size_t size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(process, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool PeReadProcessString(HANDLE process, uint64_t address, char* buffer, size_t bufferSize) {
    if (bufferSize == 0) return false;

    buffer[0] = '\0';
    SIZE_T bytesRead;

    size_t offset = 0;
    while (offset < bufferSize - 1) {
        size_t chunkSize = min((size_t)64, bufferSize - 1 - offset);
        if (!ReadProcessMemory(process, (LPCVOID)(address + offset), buffer + offset, chunkSize, &bytesRead)) {
            break;
        }

        for (size_t i = 0; i < bytesRead; i++) {
            if (buffer[offset + i] == '\0') {
                return true;
            }
        }

        offset += bytesRead;
        if (bytesRead < chunkSize) break;
    }

    buffer[offset] = '\0';
    return offset > 0;
}

bool PeGetHeaders(HANDLE process, uint64_t moduleBase, bool& is64Bit,
                  IMAGE_DOS_HEADER& dosHeader, IMAGE_NT_HEADERS64& ntHeaders64,
                  IMAGE_NT_HEADERS32& ntHeaders32) {
    if (!PeReadProcessMem(process, moduleBase, &dosHeader, sizeof(dosHeader))) {
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
    if (!PeReadProcessMem(process, ntHeaderAddr, &signature, sizeof(signature))) {
        return false;
    }

    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!PeReadProcessMem(process, ntHeaderAddr + sizeof(DWORD), &fileHeader, sizeof(fileHeader))) {
        return false;
    }

    is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

    if (is64Bit) {
        if (!PeReadProcessMem(process, ntHeaderAddr, &ntHeaders64, sizeof(ntHeaders64))) {
            return false;
        }
    } else {
        if (!PeReadProcessMem(process, ntHeaderAddr, &ntHeaders32, sizeof(ntHeaders32))) {
            return false;
        }
    }

    return true;
}

/* ============================================================================
 * Section Enumeration
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetModuleSections(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusSectionInfo* buffer,
    size_t bufferCount,
    size_t* sectionCount
) {
    if (!handle || !sectionCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<NexusProcessHandleData*>(handle);
    HANDLE process = ctx->hProcess;

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders64;
    IMAGE_NT_HEADERS32 ntHeaders32;
    bool is64Bit;

    if (!PeGetHeaders(process, moduleBase, is64Bit, dosHeader, ntHeaders64, ntHeaders32)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    WORD numSections;
    uint64_t sectionTableAddr;

    if (is64Bit) {
        numSections = ntHeaders64.FileHeader.NumberOfSections;
        sectionTableAddr = moduleBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    } else {
        numSections = ntHeaders32.FileHeader.NumberOfSections;
        sectionTableAddr = moduleBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    }

    *sectionCount = numSections;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    size_t toRead = min((size_t)numSections, bufferCount);
    std::vector<IMAGE_SECTION_HEADER> sections(toRead);

    if (!PeReadProcessMem(process, sectionTableAddr, sections.data(), toRead * sizeof(IMAGE_SECTION_HEADER))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    for (size_t i = 0; i < toRead; i++) {
        NexusSectionInfo& info = buffer[i];
        info.virtualAddress = sections[i].VirtualAddress;
        info.virtualSize = sections[i].Misc.VirtualSize;
        info.rawAddress = sections[i].PointerToRawData;
        info.rawSize = sections[i].SizeOfRawData;
        info.characteristics = sections[i].Characteristics;

        memcpy(info.name, sections[i].Name, 8);
        info.name[8] = '\0';
    }

    if (bufferCount < numSections) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Import Enumeration
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetModuleImports(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusImportInfo* buffer,
    size_t bufferCount,
    size_t* importCount
) {
    if (!handle || !importCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<NexusProcessHandleData*>(handle);
    HANDLE process = ctx->hProcess;

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders64;
    IMAGE_NT_HEADERS32 ntHeaders32;
    bool is64Bit;

    if (!PeGetHeaders(process, moduleBase, is64Bit, dosHeader, ntHeaders64, ntHeaders32)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    DWORD importDirRva;
    if (is64Bit) {
        importDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        importDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    if (importDirRva == 0) {
        *importCount = 0;
        return NEXUS_OK;
    }

    /* First pass: count imports */
    size_t totalImports = 0;
    uint64_t importDescAddr = moduleBase + importDirRva;
    DWORD dllCount = 0;

    while (dllCount < MAX_IMPORT_DLLS) {
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        if (!PeReadProcessMem(process, importDescAddr, &importDesc, sizeof(importDesc))) {
            break;
        }

        if (importDesc.Name == 0) {
            break;
        }

        uint64_t thunkAddr = moduleBase + (importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk);
        uint64_t iatAddr = moduleBase + importDesc.FirstThunk;
        DWORD thunkCount = 0;

        while (thunkCount < MAX_IMPORTS && totalImports < MAX_IMPORTS) {
            uint64_t thunkValue;
            if (is64Bit) {
                if (!PeReadProcessMem(process, thunkAddr, &thunkValue, sizeof(uint64_t))) break;
                thunkAddr += sizeof(uint64_t);
                iatAddr += sizeof(uint64_t);
            } else {
                DWORD thunk32;
                if (!PeReadProcessMem(process, thunkAddr, &thunk32, sizeof(DWORD))) break;
                thunkValue = thunk32;
                thunkAddr += sizeof(DWORD);
                iatAddr += sizeof(DWORD);
            }

            if (thunkValue == 0) break;
            totalImports++;
            thunkCount++;
        }

        importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        dllCount++;
    }

    *importCount = totalImports;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    /* Second pass: fill buffer */
    size_t filled = 0;
    importDescAddr = moduleBase + importDirRva;
    dllCount = 0;

    while (filled < bufferCount && dllCount < MAX_IMPORT_DLLS) {
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        if (!PeReadProcessMem(process, importDescAddr, &importDesc, sizeof(importDesc))) {
            break;
        }

        if (importDesc.Name == 0) {
            break;
        }

        char moduleName[260];
        PeReadProcessString(process, moduleBase + importDesc.Name, moduleName, sizeof(moduleName));

        uint64_t thunkAddr = moduleBase + (importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk);
        uint64_t iatAddr = moduleBase + importDesc.FirstThunk;
        DWORD thunkCount = 0;

        while (filled < bufferCount && thunkCount < MAX_IMPORTS) {
            uint64_t thunkValue;
            uint64_t currentIatAddr = iatAddr;

            if (is64Bit) {
                if (!PeReadProcessMem(process, thunkAddr, &thunkValue, sizeof(uint64_t))) break;
                thunkAddr += sizeof(uint64_t);
                iatAddr += sizeof(uint64_t);
            } else {
                DWORD thunk32;
                if (!PeReadProcessMem(process, thunkAddr, &thunk32, sizeof(DWORD))) break;
                thunkValue = thunk32;
                thunkAddr += sizeof(DWORD);
                iatAddr += sizeof(DWORD);
            }

            if (thunkValue == 0) break;

            NexusImportInfo& info = buffer[filled];
            info.iatAddress = currentIatAddr;
            strncpy_s(info.moduleName, moduleName, sizeof(info.moduleName) - 1);

            bool isOrdinal = is64Bit ?
                (thunkValue & IMAGE_ORDINAL_FLAG64) != 0 :
                (thunkValue & IMAGE_ORDINAL_FLAG32) != 0;

            if (isOrdinal) {
                info.isOrdinal = 1;
                info.ordinal = (DWORD)(thunkValue & 0xFFFF);
                info.functionName[0] = '\0';
            } else {
                info.isOrdinal = 0;
                info.ordinal = 0;

                uint64_t rva = is64Bit ?
                    (thunkValue & 0x7FFFFFFFFFFFFFFFULL) :
                    (thunkValue & 0x7FFFFFFFULL);
                uint64_t hintNameAddr = moduleBase + rva;
                WORD hint;
                PeReadProcessMem(process, hintNameAddr, &hint, sizeof(hint));
                PeReadProcessString(process, hintNameAddr + sizeof(WORD), info.functionName, sizeof(info.functionName));
            }

            filled++;
            thunkCount++;
        }

        importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        dllCount++;
    }

    if (bufferCount < totalImports) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}
