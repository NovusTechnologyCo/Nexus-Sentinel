/**
 * @file trainer_persist.cpp
 * @brief Trainer JSON deserialization (load) and .nst table import.
 *
 * Implements Nexus_TrainerLoad (parse JSON trainer file) and
 * Nexus_TrainerImportFromTable (convert .nst cheat-table records
 * into trainer cheat entries).
 */

#include "trainer_internal.h"
#include <cctype>

/* ============================================================================
 * Simple JSON Parser (internal to this file)
 * ============================================================================ */

class SimpleJsonParser {
public:
    SimpleJsonParser(const std::string& json) : m_json(json), m_pos(0) {}

    void skipWhitespace() {
        while (m_pos < m_json.size() && std::isspace(m_json[m_pos])) m_pos++;
    }

    bool expect(char c) {
        skipWhitespace();
        if (m_pos < m_json.size() && m_json[m_pos] == c) {
            m_pos++;
            return true;
        }
        return false;
    }

    std::string parseString() {
        skipWhitespace();
        if (m_pos >= m_json.size() || m_json[m_pos] != '"') return "";
        m_pos++; // skip opening quote

        std::string result;
        while (m_pos < m_json.size() && m_json[m_pos] != '"') {
            if (m_json[m_pos] == '\\' && m_pos + 1 < m_json.size()) {
                m_pos++;
                switch (m_json[m_pos]) {
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    default: result += m_json[m_pos]; break;
                }
            } else {
                result += m_json[m_pos];
            }
            m_pos++;
        }
        if (m_pos < m_json.size()) m_pos++; // skip closing quote
        return result;
    }

    int64_t parseNumber() {
        skipWhitespace();
        bool negative = false;
        if (m_pos < m_json.size() && m_json[m_pos] == '-') {
            negative = true;
            m_pos++;
        }
        int64_t value = 0;
        while (m_pos < m_json.size() && std::isdigit(m_json[m_pos])) {
            value = value * 10 + (m_json[m_pos] - '0');
            m_pos++;
        }
        return negative ? -value : value;
    }

    uint64_t parseHexString() {
        std::string s = parseString();
        if (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X") {
            return std::stoull(s, nullptr, 16);
        }
        return std::stoull(s);
    }

    bool parseBool() {
        skipWhitespace();
        if (m_json.substr(m_pos, 4) == "true") {
            m_pos += 4;
            return true;
        } else if (m_json.substr(m_pos, 5) == "false") {
            m_pos += 5;
            return false;
        }
        return false;
    }

    bool findKey(const std::string& key) {
        size_t searchPos = m_pos;
        std::string searchKey = "\"" + key + "\"";
        size_t found = m_json.find(searchKey, searchPos);
        if (found != std::string::npos) {
            m_pos = found + searchKey.size();
            skipWhitespace();
            expect(':');
            return true;
        }
        return false;
    }

    bool enterObject() { return expect('{'); }
    bool exitObject() { return expect('}'); }
    bool enterArray() { return expect('['); }
    bool exitArray() { return expect(']'); }
    bool hasMore() {
        skipWhitespace();
        return m_pos < m_json.size() && m_json[m_pos] != ']' && m_json[m_pos] != '}';
    }
    void skipComma() { expect(','); }
    size_t pos() const { return m_pos; }
    void setPos(size_t p) { m_pos = p; }
    const std::string& json() const { return m_json; }

private:
    std::string m_json;
    size_t m_pos;
};

/* ============================================================================
 * Static Helpers
 * ============================================================================ */

static NexusTrainerAction ParseActionName(const std::string& action) {
    if (action == "toggle") return NEXUS_TRAINER_TOGGLE;
    if (action == "set") return NEXUS_TRAINER_SET_VALUE;
    if (action == "freeze") return NEXUS_TRAINER_FREEZE;
    if (action == "increment") return NEXUS_TRAINER_INCREMENT;
    if (action == "decrement") return NEXUS_TRAINER_DECREMENT;
    if (action == "script") return NEXUS_TRAINER_EXECUTE_SCRIPT;
    return NEXUS_TRAINER_TOGGLE;
}

static int32_t ParseValueTypeName(const std::string& type) {
    if (type == "byte") return 0;
    if (type == "int16") return 1;
    if (type == "int32") return 2;
    if (type == "int64") return 3;
    if (type == "float") return 4;
    if (type == "double") return 5;
    return 2; // default to int32
}

// Helper to convert narrow string to wide string
static std::wstring Utf8ToWide(const char* str) {
    if (!str || !*str) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], len);
    return result;
}

// Helper to convert wide string to narrow string
static std::string WideToUtf8(const wchar_t* wstr) {
    if (!wstr || !*wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

// Map NexusRecordFlags to NexusTrainerAction
static NexusTrainerAction MapRecordFlagsToAction(uint32_t flags, uint32_t recordType) {
    if (recordType == NEXUS_RECORD_SCRIPT) {
        return NEXUS_TRAINER_EXECUTE_SCRIPT;
    }
    if (flags & NEXUS_RECORD_FLAG_FROZEN) {
        return NEXUS_TRAINER_FREEZE;
    }
    // Default to toggle for address records
    return NEXUS_TRAINER_TOGGLE;
}

/* ============================================================================
 * Load & Import API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_TrainerLoad(
    const char* path,
    NexusTrainerHandle* trainer
) {
    if (!path || !trainer) return NEXUS_ERROR_INVALID_PARAMETER;

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return NEXUS_ERROR_NOT_FOUND;

    // Read entire file
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string json = buffer.str();
    ifs.close();

    // Verify it's a JSON file
    if (json.find('{') == std::string::npos) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Create trainer
    NexusResult result = Nexus_TrainerCreate(trainer);
    if (result != NEXUS_OK) return result;

    TrainerContext* ctx = static_cast<TrainerContext*>(*trainer);
    SimpleJsonParser parser(json);

    // Parse config section
    if (parser.findKey("config")) {
        size_t configStart = parser.pos();

        if (parser.findKey("name")) {
            std::string name = parser.parseString();
            strncpy_s(ctx->config.name, sizeof(ctx->config.name), name.c_str(), _TRUNCATE);
        }
        parser.setPos(configStart);

        if (parser.findKey("author")) {
            std::string author = parser.parseString();
            strncpy_s(ctx->config.author, sizeof(ctx->config.author), author.c_str(), _TRUNCATE);
        }
        parser.setPos(configStart);

        if (parser.findKey("version")) {
            std::string version = parser.parseString();
            strncpy_s(ctx->config.version, sizeof(ctx->config.version), version.c_str(), _TRUNCATE);
        }
        parser.setPos(configStart);

        if (parser.findKey("targetProcess")) {
            std::string target = parser.parseString();
            strncpy_s(ctx->config.targetProcess, sizeof(ctx->config.targetProcess), target.c_str(), _TRUNCATE);
        }
        parser.setPos(configStart);

        if (parser.findKey("aboutText")) {
            std::string about = parser.parseString();
            strncpy_s(ctx->config.aboutText, sizeof(ctx->config.aboutText), about.c_str(), _TRUNCATE);
        }
        parser.setPos(configStart);

        if (parser.findKey("autoAttach")) {
            ctx->config.autoAttach = parser.parseBool() ? 1 : 0;
        }
        parser.setPos(configStart);

        if (parser.findKey("closeWithGame")) {
            ctx->config.closeWithGame = parser.parseBool() ? 1 : 0;
        }
        parser.setPos(configStart);

        if (parser.findKey("minimizeToTray")) {
            ctx->config.minimizeToTray = parser.parseBool() ? 1 : 0;
        }
        parser.setPos(configStart);

        if (parser.findKey("playSounds")) {
            ctx->config.playSounds = parser.parseBool() ? 1 : 0;
        }
    }

    // Parse modules array
    parser.setPos(0);
    if (parser.findKey("modules")) {
        if (parser.enterArray()) {
            while (parser.hasMore()) {
                std::string module = parser.parseString();
                if (!module.empty()) {
                    ctx->modules.push_back(module);
                }
                parser.skipComma();
            }
            parser.exitArray();
        }
    }

    // Parse cheats array
    parser.setPos(0);
    if (parser.findKey("cheats")) {
        if (parser.enterArray()) {
            while (parser.hasMore()) {
                if (parser.enterObject()) {
                    NexusTrainerCheat cheat = {};
                    size_t cheatStart = parser.pos();

                    if (parser.findKey("id")) {
                        cheat.id = static_cast<uint32_t>(parser.parseNumber());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("name")) {
                        std::string name = parser.parseString();
                        strncpy_s(cheat.name, sizeof(cheat.name), name.c_str(), _TRUNCATE);
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("action")) {
                        cheat.action = ParseActionName(parser.parseString());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("hotkey")) {
                        cheat.hotkey = static_cast<uint32_t>(parser.parseNumber());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("modifiers")) {
                        cheat.modifiers = static_cast<uint32_t>(parser.parseNumber());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("moduleIndex")) {
                        cheat.moduleIndex = static_cast<int32_t>(parser.parseNumber());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("offset")) {
                        cheat.offset = parser.parseHexString();
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("pointerOffsets")) {
                        if (parser.enterArray()) {
                            cheat.pointerCount = 0;
                            while (parser.hasMore() && cheat.pointerCount < 16) {
                                cheat.pointerOffsets[cheat.pointerCount++] =
                                    static_cast<int64_t>(parser.parseHexString());
                                parser.skipComma();
                            }
                            parser.exitArray();
                        }
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("valueType")) {
                        cheat.valueType = ParseValueTypeName(parser.parseString());
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("setValue")) {
                        cheat.setValue = parser.parseNumber();
                    }
                    parser.setPos(cheatStart);

                    if (parser.findKey("scriptName")) {
                        std::string scriptName = parser.parseString();
                        strncpy_s(cheat.scriptName, sizeof(cheat.scriptName), scriptName.c_str(), _TRUNCATE);
                    }

                    ctx->cheats.push_back(cheat);
                    ctx->nextCheatId = std::max(ctx->nextCheatId, cheat.id + 1);

                    // Skip to end of object
                    int depth = 1;
                    while (depth > 0 && parser.pos() < parser.json().size()) {
                        char c = parser.json()[parser.pos()];
                        if (c == '{') depth++;
                        else if (c == '}') depth--;
                        parser.setPos(parser.pos() + 1);
                    }
                }
                parser.skipComma();
            }
            parser.exitArray();
        }
    }

    // Parse scripts array
    parser.setPos(0);
    if (parser.findKey("scripts")) {
        if (parser.enterArray()) {
            while (parser.hasMore()) {
                if (parser.enterObject()) {
                    TrainerScript script;
                    size_t scriptStart = parser.pos();

                    if (parser.findKey("name")) {
                        script.name = parser.parseString();
                    }
                    parser.setPos(scriptStart);

                    if (parser.findKey("enable")) {
                        script.enableScript = parser.parseString();
                    }
                    parser.setPos(scriptStart);

                    if (parser.findKey("disable")) {
                        script.disableScript = parser.parseString();
                    }

                    if (!script.name.empty()) {
                        ctx->scripts.push_back(script);
                    }

                    // Skip to end of object
                    int depth = 1;
                    while (depth > 0 && parser.pos() < parser.json().size()) {
                        char c = parser.json()[parser.pos()];
                        if (c == '{') depth++;
                        else if (c == '}') depth--;
                        parser.setPos(parser.pos() + 1);
                    }
                }
                parser.skipComma();
            }
            parser.exitArray();
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerImportFromTable(
    NexusTrainerHandle trainer,
    const char* tablePath
) {
    if (!trainer || !tablePath) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    // Convert path to wide string for table API
    std::wstring widePath = Utf8ToWide(tablePath);
    if (widePath.empty()) return NEXUS_ERROR_INVALID_PARAMETER;

    // Load the .nst table file
    NexusTableHandle table = nullptr;
    NexusResult result = Nexus_TableLoad(widePath.c_str(), &table);
    if (result != NEXUS_OK || !table) {
        return result != NEXUS_OK ? result : NEXUS_ERROR_NOT_FOUND;
    }

    // Get table info and populate trainer config
    NexusTableInfo tableInfo = {};
    result = Nexus_TableGetInfo(table, &tableInfo);
    if (result == NEXUS_OK) {
        // Convert table info to trainer config
        std::string name = WideToUtf8(tableInfo.name);
        std::string author = WideToUtf8(tableInfo.author);
        std::string target = WideToUtf8(tableInfo.targetProcess);

        strncpy_s(ctx->config.name, sizeof(ctx->config.name), name.c_str(), _TRUNCATE);
        strncpy_s(ctx->config.author, sizeof(ctx->config.author), author.c_str(), _TRUNCATE);
        strncpy_s(ctx->config.targetProcess, sizeof(ctx->config.targetProcess), target.c_str(), _TRUNCATE);
        strncpy_s(ctx->config.version, sizeof(ctx->config.version), "1.0", _TRUNCATE);
    }

    // Build module list from records (collect unique module names)
    std::map<std::wstring, int32_t> moduleMap;

    // Get all records
    size_t recordCount = 0;
    result = Nexus_TableGetRecords(table, nullptr, 0, &recordCount);

    if (recordCount > 0) {
        std::vector<NexusTableRecord> records(recordCount);
        result = Nexus_TableGetRecords(table, records.data(), recordCount, &recordCount);

        if (result == NEXUS_OK) {
            // First pass: collect unique module names
            for (size_t i = 0; i < recordCount; i++) {
                const NexusTableRecord& rec = records[i];
                if (rec.moduleName[0] != L'\0' && moduleMap.find(rec.moduleName) == moduleMap.end()) {
                    std::string modName = WideToUtf8(rec.moduleName);
                    int32_t moduleIndex = static_cast<int32_t>(ctx->modules.size());
                    ctx->modules.push_back(modName);
                    moduleMap[rec.moduleName] = moduleIndex;
                }
            }

            // Second pass: convert records to cheats
            for (size_t i = 0; i < recordCount; i++) {
                const NexusTableRecord& rec = records[i];

                // Skip groups and headers - they're organizational only
                if (rec.recordType == NEXUS_RECORD_GROUP || rec.recordType == NEXUS_RECORD_HEADER) {
                    continue;
                }

                NexusTrainerCheat cheat = {};
                cheat.id = ctx->nextCheatId++;

                // Convert description to name
                std::string desc = WideToUtf8(rec.description);
                strncpy_s(cheat.name, sizeof(cheat.name), desc.c_str(), _TRUNCATE);

                // Set action based on record type and flags
                cheat.action = MapRecordFlagsToAction(rec.flags, rec.recordType);

                // Set hotkey
                cheat.hotkey = static_cast<NexusVirtualKey>(rec.hotkey);
                cheat.modifiers = 0; // Table doesn't store modifiers separately

                // Set module index
                if (rec.moduleName[0] != L'\0') {
                    auto it = moduleMap.find(rec.moduleName);
                    if (it != moduleMap.end()) {
                        cheat.moduleIndex = it->second;
                    } else {
                        cheat.moduleIndex = -1;
                    }
                } else {
                    cheat.moduleIndex = -1; // Absolute address
                }

                // Set address/offset
                cheat.offset = rec.address;

                // Copy pointer offsets
                cheat.pointerCount = std::min(rec.offsetCount, 16u);
                for (uint32_t j = 0; j < cheat.pointerCount; j++) {
                    cheat.pointerOffsets[j] = rec.offsets[j];
                }

                // Set value type
                cheat.valueType = static_cast<int32_t>(rec.valueType);

                // Extract frozen value as setValue if applicable
                if ((rec.flags & NEXUS_RECORD_FLAG_FROZEN) && rec.frozenValueSize > 0) {
                    // Interpret frozen value based on value type
                    switch (rec.valueType) {
                        case NEXUS_VALUE_INT8:
                            cheat.setValue = *reinterpret_cast<const int8_t*>(rec.frozenValue);
                            break;
                        case NEXUS_VALUE_INT16:
                            cheat.setValue = *reinterpret_cast<const int16_t*>(rec.frozenValue);
                            break;
                        case NEXUS_VALUE_INT32:
                            cheat.setValue = *reinterpret_cast<const int32_t*>(rec.frozenValue);
                            break;
                        case NEXUS_VALUE_INT64:
                            cheat.setValue = *reinterpret_cast<const int64_t*>(rec.frozenValue);
                            break;
                        case NEXUS_VALUE_FLOAT32:
                            cheat.setValue = static_cast<int64_t>(*reinterpret_cast<const float*>(rec.frozenValue));
                            break;
                        case NEXUS_VALUE_FLOAT64:
                            cheat.setValue = static_cast<int64_t>(*reinterpret_cast<const double*>(rec.frozenValue));
                            break;
                        default:
                            cheat.setValue = 0;
                            break;
                    }
                }

                cheat.isActive = (rec.flags & NEXUS_RECORD_FLAG_ACTIVE) ? 1 : 0;

                ctx->cheats.push_back(cheat);
            }
        }
    }

    // Get all scripts
    size_t scriptCount = 0;
    result = Nexus_TableGetScripts(table, nullptr, 0, &scriptCount);

    if (scriptCount > 0) {
        std::vector<NexusTableScript> scripts(scriptCount);
        result = Nexus_TableGetScripts(table, scripts.data(), scriptCount, &scriptCount);

        if (result == NEXUS_OK) {
            for (size_t i = 0; i < scriptCount; i++) {
                const NexusTableScript& script = scripts[i];

                // Get script content
                size_t contentLen = 0;
                Nexus_TableGetScriptContent(table, script.id, nullptr, 0, &contentLen);

                if (contentLen > 0) {
                    std::string content(contentLen, '\0');
                    Nexus_TableGetScriptContent(table, script.id, &content[0], contentLen + 1, &contentLen);

                    // Parse script content to extract [ENABLE] and [DISABLE] sections
                    std::string enableScript, disableScript;
                    std::string* currentSection = nullptr;

                    std::istringstream iss(content);
                    std::string line;
                    while (std::getline(iss, line)) {
                        // Trim whitespace
                        size_t start = line.find_first_not_of(" \t\r\n");
                        if (start == std::string::npos) continue;
                        line = line.substr(start);

                        if (line.find("[ENABLE]") == 0 || line.find("[enable]") == 0) {
                            currentSection = &enableScript;
                        } else if (line.find("[DISABLE]") == 0 || line.find("[disable]") == 0) {
                            currentSection = &disableScript;
                        } else if (currentSection) {
                            if (!currentSection->empty()) *currentSection += "\n";
                            *currentSection += line;
                        }
                    }

                    // Add script to trainer
                    std::string scriptName = WideToUtf8(script.name);
                    TrainerScript ts;
                    ts.name = scriptName;
                    ts.enableScript = enableScript;
                    ts.disableScript = disableScript;
                    ctx->scripts.push_back(ts);

                    // Also create a cheat entry for the script if it has a hotkey
                    if (script.hotkey != 0) {
                        NexusTrainerCheat cheat = {};
                        cheat.id = ctx->nextCheatId++;
                        strncpy_s(cheat.name, sizeof(cheat.name), scriptName.c_str(), _TRUNCATE);
                        cheat.action = NEXUS_TRAINER_EXECUTE_SCRIPT;
                        cheat.hotkey = static_cast<NexusVirtualKey>(script.hotkey);
                        strncpy_s(cheat.scriptName, sizeof(cheat.scriptName), scriptName.c_str(), _TRUNCATE);
                        cheat.isActive = (script.flags & NEXUS_RECORD_FLAG_ACTIVE) ? 1 : 0;
                        ctx->cheats.push_back(cheat);
                    }
                }
            }
        }
    }

    // Clean up table
    Nexus_TableDestroy(table);

    return NEXUS_OK;
}

} // extern "C"
