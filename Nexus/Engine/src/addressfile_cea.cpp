/**
 * @file addressfile_cea.cpp
 * @brief Cheat Engine Address (.CEA) import and export for interoperability.
 *
 * Reads and writes the CE binary address-list format so that address
 * files can be exchanged with Cheat Engine users.
 */

#include "addressfile_internal.h"

/* ============================================================================
 * CEA Import
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AddressFileImportCEA(
    const char* path,
    NexusProcessHandle process,
    NexusAddressFileHandle* file
) {
    if (!path || !file) return NEXUS_ERROR_INVALID_PARAMETER;

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return NEXUS_ERROR_NOT_FOUND;

    AddressFile* af = new (std::nothrow) AddressFile();
    if (!af) return NEXUS_ERROR_OUT_OF_MEMORY;

    /* Read module count (WORD = 2 bytes) */
    uint16_t moduleCount = 0;
    ifs.read(reinterpret_cast<char*>(&moduleCount), 2);

    /* Read module names (AnsiString format: length-prefixed) */
    for (uint16_t i = 0; i < moduleCount; i++) {
        uint8_t len = 0;
        ifs.read(reinterpret_cast<char*>(&len), 1);

        if (len > 0) {
            std::string modName(len, '\0');
            ifs.read(&modName[0], len);
            af->modules.push_back(modName);
        } else {
            af->modules.push_back("");
        }
    }

    /* Read addresses */
    while (ifs.good() && ifs.peek() != EOF) {
        uint16_t index = 0;
        uint64_t addr = 0;

        ifs.read(reinterpret_cast<char*>(&index), 2);
        if (!ifs.good()) break;

        ifs.read(reinterpret_cast<char*>(&addr), 8);
        if (!ifs.good()) break;

        AddressEntry entry;
        entry.isValid = false;
        entry.resolvedAddress = 0;

        if (index == 0xFFFF) {
            entry.moduleIndex = -1;
            entry.offset = addr;
        } else if (index < af->modules.size()) {
            entry.moduleIndex = static_cast<int32_t>(index);
            entry.offset = addr;
            entry.moduleName = af->modules[index];
        } else {
            continue;
        }

        af->entries.push_back(entry);
    }

    ifs.close();

    /* Resolve if process provided */
    if (process) {
        for (auto& entry : af->entries) {
            if (entry.moduleIndex >= 0) {
                uint64_t base = AddrFileFindModuleBase(process, entry.moduleName);
                if (base != 0) {
                    entry.resolvedAddress = base + entry.offset;
                    entry.isValid = true;
                }
            } else {
                entry.resolvedAddress = entry.offset;
                entry.isValid = true;
            }
        }
    }

    *file = af;
    return NEXUS_OK;
}

/* ============================================================================
 * CEA Export
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AddressFileExportCEA(
    NexusAddressFileHandle file,
    const char* path
) {
    if (!file || !path) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return NEXUS_ERROR_ACCESS_DENIED;

    /* Write module count */
    uint16_t moduleCount = static_cast<uint16_t>(af->modules.size());
    ofs.write(reinterpret_cast<const char*>(&moduleCount), 2);

    /* Write module names (ShortString format) */
    for (const auto& mod : af->modules) {
        uint8_t len = static_cast<uint8_t>((std::min)(mod.size(), size_t(255)));
        ofs.write(reinterpret_cast<const char*>(&len), 1);
        ofs.write(mod.c_str(), len);
    }

    /* Write addresses */
    for (const auto& entry : af->entries) {
        uint16_t index;
        uint64_t addr;

        if (entry.moduleIndex == -1) {
            index = 0xFFFF;
            addr = entry.offset;
        } else {
            index = static_cast<uint16_t>(entry.moduleIndex);
            addr = entry.offset;
        }

        ofs.write(reinterpret_cast<const char*>(&index), 2);
        ofs.write(reinterpret_cast<const char*>(&addr), 8);
    }

    ofs.close();
    return NEXUS_OK;
}
