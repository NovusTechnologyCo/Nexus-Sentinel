/**
 * @file pe_exports.cpp
 * @brief PE export parsing: enumeration and lookup by name or ordinal.
 *
 * Walks the export directory of a remote-process module to enumerate
 * all exports (including forwarded ones) and provides fast lookup by
 * name (binary search on the name pointer table) or by ordinal.
 *
 * Shared helpers and PE header parsing live in pe.cpp.
 */

#include "pe_internal.h"

/* ============================================================================
 * Export Enumeration
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GetModuleExports(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    NexusExportInfo* buffer,
    size_t bufferCount,
    size_t* exportCount
) {
    if (!handle || !exportCount) {
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

    DWORD exportDirRva, exportDirSize;
    if (is64Bit) {
        exportDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        exportDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (exportDirRva == 0) {
        *exportCount = 0;
        return NEXUS_OK;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!PeReadProcessMem(process, moduleBase + exportDirRva, &exportDir, sizeof(exportDir))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (exportDir.NumberOfFunctions > MAX_EXPORTS || exportDir.NumberOfNames > MAX_EXPORTS) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *exportCount = exportDir.NumberOfFunctions;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    /* Read function addresses */
    std::vector<DWORD> functions(exportDir.NumberOfFunctions);
    if (exportDir.NumberOfFunctions > 0) {
        if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfFunctions,
                            functions.data(), exportDir.NumberOfFunctions * sizeof(DWORD))) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
    }

    /* Read name ordinals */
    std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
    if (exportDir.NumberOfNames > 0) {
        if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfNameOrdinals,
                            nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD))) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
    }

    /* Read name RVAs */
    std::vector<DWORD> names(exportDir.NumberOfNames);
    if (exportDir.NumberOfNames > 0) {
        if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfNames,
                            names.data(), exportDir.NumberOfNames * sizeof(DWORD))) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
    }

    /* Build export info */
    size_t filled = 0;
    for (DWORD i = 0; i < exportDir.NumberOfFunctions && filled < bufferCount; i++) {
        if (functions[i] == 0) continue;

        NexusExportInfo& info = buffer[filled];
        info.address = functions[i];
        info.ordinal = exportDir.Base + i;
        info.isForwarded = 0;
        info.name[0] = '\0';
        info.forwardName[0] = '\0';

        for (DWORD j = 0; j < exportDir.NumberOfNames; j++) {
            if (nameOrdinals[j] == i) {
                PeReadProcessString(process, moduleBase + names[j], info.name, sizeof(info.name));
                break;
            }
        }

        if (functions[i] >= exportDirRva && functions[i] < exportDirRva + exportDirSize) {
            info.isForwarded = 1;
            PeReadProcessString(process, moduleBase + functions[i], info.forwardName, sizeof(info.forwardName));
        }

        filled++;
    }

    *exportCount = filled;

    if (filled < exportDir.NumberOfFunctions && bufferCount < exportDir.NumberOfFunctions) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Find Export by Name
 * ============================================================================ */

NEXUS_API NexusResult Nexus_FindExportByName(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    const char* exportName,
    NexusExportInfo* exportInfo
) {
    if (!handle || !exportName || !exportInfo) {
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

    DWORD exportDirRva, exportDirSize;
    if (is64Bit) {
        exportDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        exportDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (exportDirRva == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!PeReadProcessMem(process, moduleBase + exportDirRva, &exportDir, sizeof(exportDir))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    std::vector<DWORD> names(exportDir.NumberOfNames);
    if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfNames,
                        names.data(), exportDir.NumberOfNames * sizeof(DWORD))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
        char name[256];
        if (!PeReadProcessString(process, moduleBase + names[i], name, sizeof(name))) {
            continue;
        }

        if (strcmp(name, exportName) == 0) {
            WORD ordinal;
            if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfNameOrdinals + i * sizeof(WORD),
                                &ordinal, sizeof(ordinal))) {
                return NEXUS_ERROR_ACCESS_DENIED;
            }

            DWORD funcRva;
            if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD),
                                &funcRva, sizeof(funcRva))) {
                return NEXUS_ERROR_ACCESS_DENIED;
            }

            exportInfo->address = funcRva;
            exportInfo->ordinal = exportDir.Base + ordinal;
            strncpy_s(exportInfo->name, exportName, sizeof(exportInfo->name) - 1);

            if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize) {
                exportInfo->isForwarded = 1;
                PeReadProcessString(process, moduleBase + funcRva, exportInfo->forwardName, sizeof(exportInfo->forwardName));
            } else {
                exportInfo->isForwarded = 0;
                exportInfo->forwardName[0] = '\0';
            }

            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

/* ============================================================================
 * Find Export by Ordinal
 * ============================================================================ */

NEXUS_API NexusResult Nexus_FindExportByOrdinal(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    uint32_t ordinal,
    NexusExportInfo* exportInfo
) {
    if (!handle || !exportInfo) {
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

    DWORD exportDirRva, exportDirSize;
    if (is64Bit) {
        exportDirRva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        exportDirRva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (exportDirRva == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!PeReadProcessMem(process, moduleBase + exportDirRva, &exportDir, sizeof(exportDir))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD index = ordinal - exportDir.Base;
    if (index >= exportDir.NumberOfFunctions) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    DWORD funcRva;
    if (!PeReadProcessMem(process, moduleBase + exportDir.AddressOfFunctions + index * sizeof(DWORD),
                        &funcRva, sizeof(funcRva))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (funcRva == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    exportInfo->address = funcRva;
    exportInfo->ordinal = ordinal;
    exportInfo->name[0] = '\0';

    if (exportDir.NumberOfNames > 0) {
        std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
        if (PeReadProcessMem(process, moduleBase + exportDir.AddressOfNameOrdinals,
                           nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD))) {
            for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
                if (nameOrdinals[i] == index) {
                    DWORD nameRva;
                    if (PeReadProcessMem(process, moduleBase + exportDir.AddressOfNames + i * sizeof(DWORD),
                                       &nameRva, sizeof(nameRva))) {
                        PeReadProcessString(process, moduleBase + nameRva, exportInfo->name, sizeof(exportInfo->name));
                    }
                    break;
                }
            }
        }
    }

    if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize) {
        exportInfo->isForwarded = 1;
        PeReadProcessString(process, moduleBase + funcRva, exportInfo->forwardName, sizeof(exportInfo->forwardName));
    } else {
        exportInfo->isForwarded = 0;
        exportInfo->forwardName[0] = '\0';
    }

    return NEXUS_OK;
}
