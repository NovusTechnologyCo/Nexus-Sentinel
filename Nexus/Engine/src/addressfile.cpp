/**
 * @file addressfile.cpp
 * @brief Address file (.nsa) API: CRUD, JSON persistence, and module-relative resolution.
 *
 * Implements the Nexus Sentinel Address (.nsa) file format for storing
 * module-relative address lists.  Provides create/destroy, module and
 * entry management, JSON serialization, and runtime address resolution
 * against a live process.
 *
 * Cheat Engine .CEA import/export is in addressfile_cea.cpp.
 */

#include "addressfile_internal.h"

/* ============================================================================
 * JSON Helper Functions
 * ============================================================================ */

static std::string EscapeJsonString(const std::string& str) {
    std::string result;
    result.reserve(str.size() + 10);
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

static std::string UnescapeJsonString(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '\\' && i + 1 < str.size()) {
            switch (str[i + 1]) {
                case '"': result += '"'; i++; break;
                case '\\': result += '\\'; i++; break;
                case 'b': result += '\b'; i++; break;
                case 'f': result += '\f'; i++; break;
                case 'n': result += '\n'; i++; break;
                case 'r': result += '\r'; i++; break;
                case 't': result += '\t'; i++; break;
                case 'u':
                    if (i + 5 < str.size()) {
                        int code = 0;
                        for (int j = 0; j < 4; j++) {
                            char ch = str[i + 2 + j];
                            code *= 16;
                            if (ch >= '0' && ch <= '9') code += ch - '0';
                            else if (ch >= 'a' && ch <= 'f') code += ch - 'a' + 10;
                            else if (ch >= 'A' && ch <= 'F') code += ch - 'A' + 10;
                        }
                        result += static_cast<char>(code);
                        i += 5;
                    }
                    break;
                default:
                    result += str[i];
            }
        } else {
            result += str[i];
        }
    }
    return result;
}

static void SkipWhitespace(const std::string& json, size_t& pos) {
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\n' || json[pos] == '\r')) {
        pos++;
    }
}

static std::string ParseString(const std::string& json, size_t& pos) {
    if (pos >= json.size() || json[pos] != '"') return "";
    pos++; /* skip opening quote */

    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            result += json[pos];
            result += json[pos + 1];
            pos += 2;
        } else {
            result += json[pos];
            pos++;
        }
    }
    if (pos < json.size()) pos++; /* skip closing quote */
    return UnescapeJsonString(result);
}

static int64_t ParseNumber(const std::string& json, size_t& pos) {
    SkipWhitespace(json, pos);

    bool negative = false;
    if (pos < json.size() && json[pos] == '-') {
        negative = true;
        pos++;
    }

    /* Check for hex */
    if (pos + 1 < json.size() && json[pos] == '0' &&
        (json[pos + 1] == 'x' || json[pos + 1] == 'X')) {
        pos += 2;
        uint64_t value = 0;
        while (pos < json.size()) {
            char c = json[pos];
            if (c >= '0' && c <= '9') {
                value = value * 16 + (c - '0');
                pos++;
            } else if (c >= 'a' && c <= 'f') {
                value = value * 16 + (c - 'a' + 10);
                pos++;
            } else if (c >= 'A' && c <= 'F') {
                value = value * 16 + (c - 'A' + 10);
                pos++;
            } else {
                break;
            }
        }
        return negative ? -static_cast<int64_t>(value) : static_cast<int64_t>(value);
    }

    /* Decimal */
    int64_t value = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        value = value * 10 + (json[pos] - '0');
        pos++;
    }
    return negative ? -value : value;
}

/* ============================================================================
 * Shared Helper (used by addressfile_cea.cpp too)
 * ============================================================================ */

uint64_t AddrFileFindModuleBase(NexusProcessHandle process, const std::string& moduleName) {
    if (!process) return 0;

    size_t count = 0;
    Nexus_EnumerateModules(process, nullptr, 0, &count);
    if (count == 0) return 0;

    std::vector<NexusModuleInfo> modules(count);
    Nexus_EnumerateModules(process, modules.data(), count, &count);

    std::wstring targetName(moduleName.begin(), moduleName.end());

    for (const auto& mod : modules) {
        if (_wcsicmp(mod.name, targetName.c_str()) == 0) {
            return mod.baseAddress;
        }
    }

    return 0;
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AddressFileCreate(NexusAddressFileHandle* file) {
    if (!file) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = new (std::nothrow) AddressFile();
    if (!af) return NEXUS_ERROR_OUT_OF_MEMORY;

    *file = af;
    return NEXUS_OK;
}

NEXUS_API void Nexus_AddressFileDestroy(NexusAddressFileHandle file) {
    if (file) {
        delete static_cast<AddressFile*>(file);
    }
}

NEXUS_API NexusResult Nexus_AddressFileLoad(
    const char* path,
    NexusProcessHandle process,
    NexusAddressFileHandle* file
) {
    if (!path || !file) return NEXUS_ERROR_INVALID_PARAMETER;

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return NEXUS_ERROR_NOT_FOUND;

    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string json = ss.str();
    ifs.close();

    AddressFile* af = new (std::nothrow) AddressFile();
    if (!af) return NEXUS_ERROR_OUT_OF_MEMORY;

    /* Simple JSON parsing */
    size_t pos = 0;
    SkipWhitespace(json, pos);

    if (pos >= json.size() || json[pos] != '{') {
        delete af;
        return NEXUS_ERROR_INVALID_PARAMETER;
    }
    pos++;

    while (pos < json.size()) {
        SkipWhitespace(json, pos);
        if (json[pos] == '}') break;
        if (json[pos] == ',') { pos++; continue; }

        std::string key = ParseString(json, pos);
        SkipWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ':') pos++;
        SkipWhitespace(json, pos);

        if (key == "version") {
            ParseNumber(json, pos);
        } else if (key == "modules") {
            if (pos < json.size() && json[pos] == '[') {
                pos++;
                while (pos < json.size()) {
                    SkipWhitespace(json, pos);
                    if (json[pos] == ']') { pos++; break; }
                    if (json[pos] == ',') { pos++; continue; }

                    std::string modName = ParseString(json, pos);
                    if (!modName.empty()) {
                        af->modules.push_back(modName);
                    }
                }
            }
        } else if (key == "addresses") {
            if (pos < json.size() && json[pos] == '[') {
                pos++;
                while (pos < json.size()) {
                    SkipWhitespace(json, pos);
                    if (json[pos] == ']') { pos++; break; }
                    if (json[pos] == ',') { pos++; continue; }

                    if (json[pos] == '{') {
                        pos++;
                        AddressEntry entry = {};
                        entry.moduleIndex = -1;
                        entry.isValid = false;

                        while (pos < json.size()) {
                            SkipWhitespace(json, pos);
                            if (json[pos] == '}') { pos++; break; }
                            if (json[pos] == ',') { pos++; continue; }

                            std::string entryKey = ParseString(json, pos);
                            SkipWhitespace(json, pos);
                            if (pos < json.size() && json[pos] == ':') pos++;
                            SkipWhitespace(json, pos);

                            if (entryKey == "module") {
                                entry.moduleIndex = static_cast<int32_t>(ParseNumber(json, pos));
                            } else if (entryKey == "offset" || entryKey == "address") {
                                entry.offset = static_cast<uint64_t>(ParseNumber(json, pos));
                            } else if (entryKey == "description") {
                                entry.description = ParseString(json, pos);
                            }
                        }

                        af->entries.push_back(entry);
                    }
                }
            }
        }
    }

    /* Resolve addresses if process provided */
    if (process) {
        for (auto& entry : af->entries) {
            if (entry.moduleIndex >= 0 &&
                entry.moduleIndex < static_cast<int32_t>(af->modules.size())) {
                entry.moduleName = af->modules[entry.moduleIndex];
                uint64_t base = AddrFileFindModuleBase(process, entry.moduleName);
                if (base != 0) {
                    entry.resolvedAddress = base + entry.offset;
                    entry.isValid = true;
                }
            } else if (entry.moduleIndex == -1) {
                entry.resolvedAddress = entry.offset;
                entry.isValid = true;
            }
        }
    }

    *file = af;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileSave(
    NexusAddressFileHandle file,
    const char* path
) {
    if (!file || !path) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return NEXUS_ERROR_ACCESS_DENIED;

    ofs << "{\n";
    ofs << "  \"version\": 1,\n";

    /* Modules */
    ofs << "  \"modules\": [";
    for (size_t i = 0; i < af->modules.size(); i++) {
        if (i > 0) ofs << ", ";
        ofs << "\"" << EscapeJsonString(af->modules[i]) << "\"";
    }
    ofs << "],\n";

    /* Addresses */
    ofs << "  \"addresses\": [\n";
    for (size_t i = 0; i < af->entries.size(); i++) {
        const auto& entry = af->entries[i];
        ofs << "    {";
        ofs << "\"module\": " << entry.moduleIndex << ", ";

        if (entry.moduleIndex == -1) {
            char hexBuf[32];
            snprintf(hexBuf, sizeof(hexBuf), "0x%llX", entry.offset);
            ofs << "\"address\": \"" << hexBuf << "\"";
        } else {
            char hexBuf[32];
            snprintf(hexBuf, sizeof(hexBuf), "0x%llX", entry.offset);
            ofs << "\"offset\": \"" << hexBuf << "\"";
        }

        if (!entry.description.empty()) {
            ofs << ", \"description\": \"" << EscapeJsonString(entry.description) << "\"";
        }

        ofs << "}";
        if (i + 1 < af->entries.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ]\n";

    ofs << "}\n";
    ofs.close();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileAddModule(
    NexusAddressFileHandle file,
    const char* moduleName,
    int32_t* moduleIndex
) {
    if (!file || !moduleName) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    /* Check if module already exists */
    for (size_t i = 0; i < af->modules.size(); i++) {
        if (_stricmp(af->modules[i].c_str(), moduleName) == 0) {
            if (moduleIndex) *moduleIndex = static_cast<int32_t>(i);
            return NEXUS_OK;
        }
    }

    int32_t idx = static_cast<int32_t>(af->modules.size());
    af->modules.push_back(moduleName);

    if (moduleIndex) *moduleIndex = idx;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileGetModuleCount(
    NexusAddressFileHandle file,
    size_t* count
) {
    if (!file || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);
    *count = af->modules.size();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileGetModule(
    NexusAddressFileHandle file,
    int32_t index,
    char* name,
    size_t nameSize
) {
    if (!file || !name || nameSize == 0) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    if (index < 0 || index >= static_cast<int32_t>(af->modules.size())) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    strncpy_s(name, nameSize, af->modules[index].c_str(), _TRUNCATE);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileAddEntry(
    NexusAddressFileHandle file,
    int32_t moduleIndex,
    uint64_t offset,
    const char* description
) {
    if (!file) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    if (moduleIndex >= 0 && moduleIndex >= static_cast<int32_t>(af->modules.size())) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    AddressEntry entry;
    entry.moduleIndex = moduleIndex;
    entry.offset = offset;
    entry.description = description ? description : "";
    entry.resolvedAddress = 0;
    entry.isValid = false;

    if (moduleIndex >= 0) {
        entry.moduleName = af->modules[moduleIndex];
    }

    af->entries.push_back(entry);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileGetEntryCount(
    NexusAddressFileHandle file,
    size_t* count
) {
    if (!file || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);
    *count = af->entries.size();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileGetEntry(
    NexusAddressFileHandle file,
    size_t index,
    NexusAddressFileEntry* entry
) {
    if (!file || !entry) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    if (index >= af->entries.size()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    const auto& e = af->entries[index];
    entry->moduleIndex = e.moduleIndex;
    entry->offset = e.offset;
    entry->resolvedAddress = e.resolvedAddress;
    entry->isValid = e.isValid ? 1 : 0;

    strncpy_s(entry->description, sizeof(entry->description),
              e.description.c_str(), _TRUNCATE);
    strncpy_s(entry->moduleName, sizeof(entry->moduleName),
              e.moduleName.c_str(), _TRUNCATE);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileRemoveEntry(
    NexusAddressFileHandle file,
    size_t index
) {
    if (!file) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    if (index >= af->entries.size()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    af->entries.erase(af->entries.begin() + index);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileClearEntries(NexusAddressFileHandle file) {
    if (!file) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);
    af->entries.clear();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AddressFileResolve(
    NexusAddressFileHandle file,
    NexusProcessHandle process
) {
    if (!file || !process) return NEXUS_ERROR_INVALID_PARAMETER;

    AddressFile* af = static_cast<AddressFile*>(file);

    for (auto& entry : af->entries) {
        entry.isValid = false;
        entry.resolvedAddress = 0;

        if (entry.moduleIndex >= 0 &&
            entry.moduleIndex < static_cast<int32_t>(af->modules.size())) {
            entry.moduleName = af->modules[entry.moduleIndex];
            uint64_t base = AddrFileFindModuleBase(process, entry.moduleName);
            if (base != 0) {
                entry.resolvedAddress = base + entry.offset;
                entry.isValid = true;
            }
        } else if (entry.moduleIndex == -1) {
            entry.resolvedAddress = entry.offset;
            entry.isValid = true;
        }
    }

    return NEXUS_OK;
}
