/**
 * @file table.cpp
 * @brief Cheat table (.nst) core: create/destroy/load/save, record CRUD, and script CRUD.
 *
 * Manages NexusSentinel Table (.nst) files that store memory records
 * (address, type, freeze value, hotkey) and Auto-Assembler scripts
 * with enable/disable sections.  Serialises to/from a JSON-based
 * file format.
 *
 * AA script section parsing is in table_script.cpp.
 */

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <memory>
#include <unordered_map>
#include <mutex>

/* Table schema version */
#define NEXUS_TABLE_SCHEMA_VERSION 1

/* Internal table data structure */
struct NexusTableData {
    NexusTableInfo info;

    /* Records indexed by ID */
    std::map<uint64_t, NexusTableRecord> records;

    /* Scripts indexed by ID, with content */
    struct ScriptData {
        NexusTableScript metadata;
        std::string content;
    };
    std::map<uint64_t, ScriptData> scripts;

    uint64_t nextRecordId;
    uint64_t nextScriptId;

    NexusTableData() : nextRecordId(1), nextScriptId(1) {
        memset(&info, 0, sizeof(info));
        info.schemaVersion = NEXUS_TABLE_SCHEMA_VERSION;
        info.createdTime = static_cast<uint64_t>(std::time(nullptr));
        info.modifiedTime = info.createdTime;
    }
};

/* ============================================================================
 * JSON Helpers
 * ============================================================================ */

static std::string WStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

static std::wstring Utf8ToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

static std::string EscapeJsonString(const std::string& s) {
    std::string result;
    result.reserve(s.length() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
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
                break;
        }
    }
    return result;
}

static std::string UnescapeJsonString(const std::string& s) {
    std::string result;
    result.reserve(s.length());
    for (size_t i = 0; i < s.length(); i++) {
        if (s[i] == '\\' && i + 1 < s.length()) {
            switch (s[i + 1]) {
                case '"':  result += '"'; i++; break;
                case '\\': result += '\\'; i++; break;
                case 'b':  result += '\b'; i++; break;
                case 'f':  result += '\f'; i++; break;
                case 'n':  result += '\n'; i++; break;
                case 'r':  result += '\r'; i++; break;
                case 't':  result += '\t'; i++; break;
                case 'u':
                    if (i + 5 < s.length()) {
                        char hex[5] = { s[i+2], s[i+3], s[i+4], s[i+5], 0 };
                        int val = strtol(hex, nullptr, 16);
                        if (val < 128) result += static_cast<char>(val);
                        i += 5;
                    }
                    break;
                default: result += s[i]; break;
            }
        } else {
            result += s[i];
        }
    }
    return result;
}

/* Simple JSON value extraction */
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++;

    size_t end = pos;
    while (end < json.length() && !(json[end] == '"' && json[end-1] != '\\')) {
        end++;
    }

    return UnescapeJsonString(json.substr(pos, end - pos));
}

static uint64_t ExtractJsonUint64(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return 0;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    pos++;

    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    return strtoull(&json[pos], nullptr, 10);
}

[[maybe_unused]] static int64_t ExtractJsonInt64(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return 0;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    pos++;

    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    return strtoll(&json[pos], nullptr, 10);
}

static uint32_t ExtractJsonUint32(const std::string& json, const std::string& key) {
    return static_cast<uint32_t>(ExtractJsonUint64(json, key));
}

/* Extract JSON array of objects */
static std::vector<std::string> ExtractJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;

    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;
    pos++;

    int depth = 0;
    size_t objStart = std::string::npos;

    while (pos < json.length()) {
        if (json[pos] == '{') {
            if (depth == 0) objStart = pos;
            depth++;
        } else if (json[pos] == '}') {
            depth--;
            if (depth == 0 && objStart != std::string::npos) {
                result.push_back(json.substr(objStart, pos - objStart + 1));
                objStart = std::string::npos;
            }
        } else if (json[pos] == ']' && depth == 0) {
            break;
        }
        pos++;
    }

    return result;
}

/* Extract JSON array of int64 */
static std::vector<int64_t> ExtractJsonInt64Array(const std::string& json, const std::string& key) {
    std::vector<int64_t> result;

    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;
    pos++;

    while (pos < json.length() && json[pos] != ']') {
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == ',' || json[pos] == '\n' || json[pos] == '\r' || json[pos] == '\t')) pos++;
        if (json[pos] == ']') break;

        char* end;
        int64_t val = strtoll(&json[pos], &end, 10);
        result.push_back(val);
        pos = end - json.c_str();
    }

    return result;
}

/* ============================================================================
 * Table Management
 * ============================================================================ */

// Global container to manage table ownership
static std::mutex g_tableMutex;
static std::unordered_map<void*, std::unique_ptr<NexusTableData>> g_tables;

/* ============================================================================
 * Table Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_TableCreate(NexusTableHandle* table) {
    if (!table) return NEXUS_ERROR_INVALID_PARAMETER;

    auto data = std::make_unique<NexusTableData>();
    if (!data) return NEXUS_ERROR_OUT_OF_MEMORY;

    // Store unique_ptr in global container and return raw pointer
    auto* rawPtr = data.get();
    {
        std::lock_guard<std::mutex> lock(g_tableMutex);
        g_tables[rawPtr] = std::move(data);
    }

    *table = rawPtr;
    return NEXUS_OK;
}

NEXUS_API void Nexus_TableDestroy(NexusTableHandle table) {
    if (table) {
        // Remove from global container (unique_ptr handles deletion)
        std::lock_guard<std::mutex> lock(g_tableMutex);
        g_tables.erase(table);
    }
}

NEXUS_API NexusResult Nexus_TableLoad(const wchar_t* path, NexusTableHandle* table) {
    if (!path || !table) return NEXUS_ERROR_INVALID_PARAMETER;

    /* Read file */
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return NEXUS_ERROR_NOT_FOUND;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();
    file.close();

    /* Create table using unique_ptr */
    auto data = std::make_unique<NexusTableData>();
    if (!data) return NEXUS_ERROR_OUT_OF_MEMORY;

    /* Parse metadata */
    std::wstring name = Utf8ToWString(ExtractJsonString(json, "name"));
    std::wstring author = Utf8ToWString(ExtractJsonString(json, "author"));
    std::wstring targetProcess = Utf8ToWString(ExtractJsonString(json, "targetProcess"));
    std::wstring gameVersion = Utf8ToWString(ExtractJsonString(json, "gameVersion"));

    wcsncpy_s(data->info.name, 128, name.c_str(), _TRUNCATE);
    wcsncpy_s(data->info.author, 64, author.c_str(), _TRUNCATE);
    wcsncpy_s(data->info.targetProcess, 260, targetProcess.c_str(), _TRUNCATE);
    wcsncpy_s(data->info.gameVersion, 32, gameVersion.c_str(), _TRUNCATE);

    data->info.schemaVersion = ExtractJsonUint32(json, "schemaVersion");
    data->info.createdTime = ExtractJsonUint64(json, "createdTime");
    data->info.modifiedTime = ExtractJsonUint64(json, "modifiedTime");

    /* Parse records */
    auto recordsJson = ExtractJsonArray(json, "records");
    for (const auto& recordJson : recordsJson) {
        NexusTableRecord record = {};

        record.id = ExtractJsonUint64(recordJson, "id");
        record.parentId = ExtractJsonUint64(recordJson, "parentId");
        record.recordType = ExtractJsonUint32(recordJson, "recordType");
        record.valueType = ExtractJsonUint32(recordJson, "valueType");
        record.flags = ExtractJsonUint32(recordJson, "flags");
        record.hotkey = ExtractJsonUint32(recordJson, "hotkey");
        record.address = ExtractJsonUint64(recordJson, "address");
        record.displayType = ExtractJsonUint32(recordJson, "displayType");
        record.frozenValueSize = ExtractJsonUint32(recordJson, "frozenValueSize");

        std::wstring desc = Utf8ToWString(ExtractJsonString(recordJson, "description"));
        std::wstring modName = Utf8ToWString(ExtractJsonString(recordJson, "moduleName"));
        std::wstring grpName = Utf8ToWString(ExtractJsonString(recordJson, "groupName"));

        wcsncpy_s(record.description, 128, desc.c_str(), _TRUNCATE);
        wcsncpy_s(record.moduleName, 64, modName.c_str(), _TRUNCATE);
        wcsncpy_s(record.groupName, 64, grpName.c_str(), _TRUNCATE);

        auto offsets = ExtractJsonInt64Array(recordJson, "offsets");
        record.offsetCount = static_cast<uint32_t>(std::min(offsets.size(), size_t(16)));
        for (uint32_t i = 0; i < record.offsetCount; i++) {
            record.offsets[i] = offsets[i];
        }

        /* Parse frozen value (base64 or hex would be better, using simple hex here) */
        std::string frozenHex = ExtractJsonString(recordJson, "frozenValue");
        size_t frozenLen = std::min(frozenHex.length() / 2, size_t(32));
        for (size_t i = 0; i < frozenLen; i++) {
            char hex[3] = { frozenHex[i*2], frozenHex[i*2+1], 0 };
            record.frozenValue[i] = static_cast<uint8_t>(strtol(hex, nullptr, 16));
        }

        data->records[record.id] = record;
        if (record.id >= data->nextRecordId) {
            data->nextRecordId = record.id + 1;
        }
    }

    /* Parse scripts */
    auto scriptsJson = ExtractJsonArray(json, "scripts");
    for (const auto& scriptJson : scriptsJson) {
        NexusTableData::ScriptData scriptData = {};

        scriptData.metadata.id = ExtractJsonUint64(scriptJson, "id");
        scriptData.metadata.parentId = ExtractJsonUint64(scriptJson, "parentId");
        scriptData.metadata.flags = ExtractJsonUint32(scriptJson, "flags");
        scriptData.metadata.hotkey = ExtractJsonUint32(scriptJson, "hotkey");

        std::wstring scriptName = Utf8ToWString(ExtractJsonString(scriptJson, "name"));
        wcsncpy_s(scriptData.metadata.name, 128, scriptName.c_str(), _TRUNCATE);

        scriptData.content = ExtractJsonString(scriptJson, "content");

        data->scripts[scriptData.metadata.id] = scriptData;
        if (scriptData.metadata.id >= data->nextScriptId) {
            data->nextScriptId = scriptData.metadata.id + 1;
        }
    }

    /* Update counts */
    data->info.recordCount = static_cast<uint32_t>(data->records.size());
    data->info.scriptCount = static_cast<uint32_t>(data->scripts.size());

    /* Count groups */
    uint32_t groupCount = 0;
    for (const auto& [id, record] : data->records) {
        if (record.recordType == NEXUS_RECORD_GROUP) groupCount++;
    }
    data->info.groupCount = groupCount;

    // Store unique_ptr in global container and return raw pointer
    auto* rawPtr = data.get();
    {
        std::lock_guard<std::mutex> lock(g_tableMutex);
        g_tables[rawPtr] = std::move(data);
    }

    *table = rawPtr;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableSave(NexusTableHandle table, const wchar_t* path) {
    if (!table || !path) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    /* Update modified time */
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    /* Build JSON */
    std::ostringstream json;
    json << "{\n";
    json << "  \"schemaVersion\": " << data->info.schemaVersion << ",\n";
    json << "  \"name\": \"" << EscapeJsonString(WStringToUtf8(data->info.name)) << "\",\n";
    json << "  \"author\": \"" << EscapeJsonString(WStringToUtf8(data->info.author)) << "\",\n";
    json << "  \"targetProcess\": \"" << EscapeJsonString(WStringToUtf8(data->info.targetProcess)) << "\",\n";
    json << "  \"gameVersion\": \"" << EscapeJsonString(WStringToUtf8(data->info.gameVersion)) << "\",\n";
    json << "  \"createdTime\": " << data->info.createdTime << ",\n";
    json << "  \"modifiedTime\": " << data->info.modifiedTime << ",\n";

    /* Write records */
    json << "  \"records\": [\n";
    bool firstRecord = true;
    for (const auto& [id, record] : data->records) {
        if (!firstRecord) json << ",\n";
        firstRecord = false;

        json << "    {\n";
        json << "      \"id\": " << record.id << ",\n";
        json << "      \"parentId\": " << record.parentId << ",\n";
        json << "      \"recordType\": " << record.recordType << ",\n";
        json << "      \"valueType\": " << record.valueType << ",\n";
        json << "      \"flags\": " << record.flags << ",\n";
        json << "      \"hotkey\": " << record.hotkey << ",\n";
        json << "      \"address\": " << record.address << ",\n";
        json << "      \"description\": \"" << EscapeJsonString(WStringToUtf8(record.description)) << "\",\n";
        json << "      \"moduleName\": \"" << EscapeJsonString(WStringToUtf8(record.moduleName)) << "\",\n";
        json << "      \"groupName\": \"" << EscapeJsonString(WStringToUtf8(record.groupName)) << "\",\n";
        json << "      \"displayType\": " << record.displayType << ",\n";
        json << "      \"frozenValueSize\": " << record.frozenValueSize << ",\n";

        /* Write frozen value as hex */
        json << "      \"frozenValue\": \"";
        for (uint32_t i = 0; i < record.frozenValueSize && i < 32; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02X", record.frozenValue[i]);
            json << hex;
        }
        json << "\",\n";

        /* Write offsets */
        json << "      \"offsets\": [";
        for (uint32_t i = 0; i < record.offsetCount; i++) {
            if (i > 0) json << ", ";
            json << record.offsets[i];
        }
        json << "]\n";
        json << "    }";
    }
    json << "\n  ],\n";

    /* Write scripts */
    json << "  \"scripts\": [\n";
    bool firstScript = true;
    for (const auto& [id, scriptData] : data->scripts) {
        if (!firstScript) json << ",\n";
        firstScript = false;

        json << "    {\n";
        json << "      \"id\": " << scriptData.metadata.id << ",\n";
        json << "      \"parentId\": " << scriptData.metadata.parentId << ",\n";
        json << "      \"flags\": " << scriptData.metadata.flags << ",\n";
        json << "      \"hotkey\": " << scriptData.metadata.hotkey << ",\n";
        json << "      \"name\": \"" << EscapeJsonString(WStringToUtf8(scriptData.metadata.name)) << "\",\n";
        json << "      \"content\": \"" << EscapeJsonString(scriptData.content) << "\"\n";
        json << "    }";
    }
    json << "\n  ]\n";

    json << "}\n";

    /* Write file */
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return NEXUS_ERROR_ACCESS_DENIED;

    std::string jsonStr = json.str();
    file.write(jsonStr.c_str(), jsonStr.length());

    /* CRITICAL FIX: Verify write succeeded to prevent silent data corruption */
    if (file.fail()) {
        file.close();
        return NEXUS_ERROR_UNKNOWN;
    }

    file.close();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableGetInfo(NexusTableHandle table, NexusTableInfo* info) {
    if (!table || !info) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    /* Update counts */
    data->info.recordCount = static_cast<uint32_t>(data->records.size());
    data->info.scriptCount = static_cast<uint32_t>(data->scripts.size());

    uint32_t groupCount = 0;
    for (const auto& [id, record] : data->records) {
        if (record.recordType == NEXUS_RECORD_GROUP) groupCount++;
    }
    data->info.groupCount = groupCount;

    *info = data->info;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableSetInfo(NexusTableHandle table, const NexusTableInfo* info) {
    if (!table || !info) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    /* Copy info but preserve counts (they're computed) */
    wcsncpy_s(data->info.name, 128, info->name, _TRUNCATE);
    wcsncpy_s(data->info.author, 64, info->author, _TRUNCATE);
    wcsncpy_s(data->info.targetProcess, 260, info->targetProcess, _TRUNCATE);
    wcsncpy_s(data->info.gameVersion, 32, info->gameVersion, _TRUNCATE);

    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

/* ============================================================================
 * Record Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_TableAddRecord(NexusTableHandle table, const NexusTableRecord* record, uint64_t* id) {
    if (!table || !record) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    NexusTableRecord newRecord = *record;
    newRecord.id = data->nextRecordId++;

    data->records[newRecord.id] = newRecord;
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    if (id) *id = newRecord.id;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableGetRecord(NexusTableHandle table, uint64_t id, NexusTableRecord* record) {
    if (!table || !record) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->records.find(id);
    if (it == data->records.end()) return NEXUS_ERROR_NOT_FOUND;

    *record = it->second;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableUpdateRecord(NexusTableHandle table, const NexusTableRecord* record) {
    if (!table || !record) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->records.find(record->id);
    if (it == data->records.end()) return NEXUS_ERROR_NOT_FOUND;

    it->second = *record;
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableRemoveRecord(NexusTableHandle table, uint64_t id) {
    if (!table) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->records.find(id);
    if (it == data->records.end()) return NEXUS_ERROR_NOT_FOUND;

    data->records.erase(it);
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableGetRecords(NexusTableHandle table, NexusTableRecord* buffer, size_t bufferCount, size_t* recordCount) {
    if (!table || !recordCount) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    *recordCount = data->records.size();

    if (buffer && bufferCount > 0) {
        size_t i = 0;
        for (const auto& [id, record] : data->records) {
            if (i >= bufferCount) break;
            buffer[i++] = record;
        }
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Script Operations
 * ============================================================================ */

NEXUS_API NexusResult Nexus_TableAddScript(NexusTableHandle table, const NexusTableScript* script, const char* content, uint64_t* id) {
    if (!table || !script) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    NexusTableData::ScriptData scriptData;
    scriptData.metadata = *script;
    scriptData.metadata.id = data->nextScriptId++;
    scriptData.content = content ? content : "";

    data->scripts[scriptData.metadata.id] = scriptData;
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    if (id) *id = scriptData.metadata.id;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableGetScriptContent(NexusTableHandle table, uint64_t id, char* buffer, size_t bufferSize, size_t* contentLength) {
    if (!table || !contentLength) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->scripts.find(id);
    if (it == data->scripts.end()) return NEXUS_ERROR_NOT_FOUND;

    *contentLength = it->second.content.length();

    if (buffer && bufferSize > 0) {
        size_t copyLen = std::min(bufferSize - 1, it->second.content.length());
        memcpy(buffer, it->second.content.c_str(), copyLen);
        buffer[copyLen] = '\0';
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableUpdateScriptContent(NexusTableHandle table, uint64_t id, const char* content) {
    if (!table) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->scripts.find(id);
    if (it == data->scripts.end()) return NEXUS_ERROR_NOT_FOUND;

    it->second.content = content ? content : "";
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableRemoveScript(NexusTableHandle table, uint64_t id) {
    if (!table) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    auto it = data->scripts.find(id);
    if (it == data->scripts.end()) return NEXUS_ERROR_NOT_FOUND;

    data->scripts.erase(it);
    data->info.modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TableGetScripts(NexusTableHandle table, NexusTableScript* buffer, size_t bufferCount, size_t* scriptCount) {
    if (!table || !scriptCount) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusTableData*>(table);

    *scriptCount = data->scripts.size();

    if (buffer && bufferCount > 0) {
        size_t i = 0;
        for (const auto& [id, scriptData] : data->scripts) {
            if (i >= bufferCount) break;
            buffer[i++] = scriptData.metadata;
        }
    }

    return NEXUS_OK;
}
