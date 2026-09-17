/**
 * @file project_json.cpp
 * @brief Project JSON serialization and deserialization.
 *
 * Lightweight JSON writer and parser (no external dependencies) used
 * for .nsp project files.  Handles Unicode escaping, address-entry
 * serialization (including pointer-chain offsets), and project
 * metadata round-tripping.
 */

#include "project_internal.h"

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

/* Simple JSON writer */
class JsonWriter {
public:
    std::ostringstream ss;
    int indent;
    bool needComma;

    JsonWriter() : indent(0), needComma(false) {}

    void BeginObject() {
        if (needComma) ss << ",";
        ss << "{\n";
        indent++;
        needComma = false;
    }

    void EndObject() {
        ss << "\n";
        indent--;
        WriteIndent();
        ss << "}";
        needComma = true;
    }

    void BeginArray(const char* name) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": [\n";
        indent++;
        needComma = false;
    }

    void EndArray() {
        ss << "\n";
        indent--;
        WriteIndent();
        ss << "]";
        needComma = true;
    }

    void WriteString(const char* name, const std::string& value) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": \"" << EscapeJsonString(value) << "\"";
        needComma = true;
    }

    void WriteWString(const char* name, const std::wstring& value) {
        WriteString(name, WStringToUtf8(value));
    }

    void WriteInt(const char* name, int64_t value) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": " << value;
        needComma = true;
    }

    void WriteUInt(const char* name, uint64_t value) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": " << value;
        needComma = true;
    }

    void WriteDouble(const char* name, double value) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": " << value;
        needComma = true;
    }

    void WriteBool(const char* name, bool value) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": " << (value ? "true" : "false");
        needComma = true;
    }

    void WriteIntArray(const char* name, const int64_t* arr, size_t count) {
        if (needComma) ss << ",\n";
        WriteIndent();
        ss << "\"" << name << "\": [";
        for (size_t i = 0; i < count; i++) {
            if (i > 0) ss << ", ";
            ss << arr[i];
        }
        ss << "]";
        needComma = true;
    }

    std::string ToString() { return ss.str(); }

private:
    void WriteIndent() {
        for (int i = 0; i < indent; i++) ss << "  ";
    }
};

/* Simple JSON parser (minimal implementation) */
class JsonParser {
public:
    const char* data;
    size_t pos;
    size_t len;

    JsonParser(const std::string& json) : data(json.c_str()), pos(0), len(json.length()) {}

    void SkipWhitespace() {
        while (pos < len && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\n' || data[pos] == '\r')) {
            pos++;
        }
    }

    bool Expect(char c) {
        SkipWhitespace();
        if (pos < len && data[pos] == c) {
            pos++;
            return true;
        }
        return false;
    }

    std::string ParseString() {
        SkipWhitespace();
        if (pos >= len || data[pos] != '"') return "";
        pos++;

        std::string result;
        while (pos < len && data[pos] != '"') {
            if (data[pos] == '\\' && pos + 1 < len) {
                pos++;
                switch (data[pos]) {
                    case '"':  result += '"'; break;
                    case '\\': result += '\\'; break;
                    case 'b':  result += '\b'; break;
                    case 'f':  result += '\f'; break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    default:   result += data[pos]; break;
                }
            } else {
                result += data[pos];
            }
            pos++;
        }
        if (pos < len) pos++;
        return result;
    }

    int64_t ParseInt() {
        SkipWhitespace();
        bool negative = false;
        if (pos < len && data[pos] == '-') {
            negative = true;
            pos++;
        }
        int64_t value = 0;
        while (pos < len && data[pos] >= '0' && data[pos] <= '9') {
            value = value * 10 + (data[pos] - '0');
            pos++;
        }
        return negative ? -value : value;
    }

    double ParseDouble() {
        SkipWhitespace();
        size_t start = pos;
        if (pos < len && data[pos] == '-') pos++;
        while (pos < len && data[pos] >= '0' && data[pos] <= '9') pos++;
        if (pos < len && data[pos] == '.') {
            pos++;
            while (pos < len && data[pos] >= '0' && data[pos] <= '9') pos++;
        }
        if (pos < len && (data[pos] == 'e' || data[pos] == 'E')) {
            pos++;
            if (pos < len && (data[pos] == '+' || data[pos] == '-')) pos++;
            while (pos < len && data[pos] >= '0' && data[pos] <= '9') pos++;
        }
        try {
            return std::stod(std::string(data + start, pos - start));
        } catch (...) {
            return 0.0;
        }
    }

    bool ParseBool() {
        SkipWhitespace();
        if (pos + 4 <= len && strncmp(data + pos, "true", 4) == 0) {
            pos += 4;
            return true;
        }
        if (pos + 5 <= len && strncmp(data + pos, "false", 5) == 0) {
            pos += 5;
            return false;
        }
        return false;
    }

    void SkipValue() {
        SkipWhitespace();
        if (pos >= len) return;

        if (data[pos] == '"') {
            ParseString();
        } else if (data[pos] == '{') {
            int depth = 1;
            pos++;
            while (pos < len && depth > 0) {
                if (data[pos] == '{') depth++;
                else if (data[pos] == '}') depth--;
                else if (data[pos] == '"') { ParseString(); continue; }
                pos++;
            }
        } else if (data[pos] == '[') {
            int depth = 1;
            pos++;
            while (pos < len && depth > 0) {
                if (data[pos] == '[') depth++;
                else if (data[pos] == ']') depth--;
                else if (data[pos] == '"') { ParseString(); continue; }
                pos++;
            }
        } else {
            while (pos < len && data[pos] != ',' && data[pos] != '}' && data[pos] != ']') {
                pos++;
            }
        }
    }
};

/* ============================================================================
 * Project Serialization
 * ============================================================================ */

std::string SerializeProject(NexusProjectData* project) {
    JsonWriter w;
    w.BeginObject();

    w.WriteInt("schemaVersion", NEXUS_PROJECT_SCHEMA_VERSION);
    w.WriteWString("name", project->name);
    w.WriteWString("targetProcess", project->targetProcess);
    w.WriteUInt("targetPid", project->targetPid);
    w.WriteUInt("createdTime", project->createdTime);
    w.WriteUInt("modifiedTime", static_cast<uint64_t>(std::time(nullptr)));
    w.WriteUInt("nextId", project->nextId);

    w.BeginArray("addresses");
    bool first = true;
    for (const auto& pair : project->addresses) {
        const NexusAddressEntry& entry = pair.second;

        if (!first) w.ss << ",";
        first = false;
        w.ss << "\n";
        w.indent++;
        w.needComma = false;

        w.BeginObject();
        w.WriteUInt("id", entry.id);
        w.WriteUInt("address", entry.address);
        w.WriteInt("valueType", static_cast<int>(entry.valueType));
        w.WriteUInt("flags", entry.flags);
        w.WriteWString("description", entry.description);
        w.WriteWString("groupName", entry.groupName);
        w.WriteUInt("offsetCount", entry.offsetCount);

        if (entry.offsetCount > 0) {
            w.WriteIntArray("offsets", entry.offsets, entry.offsetCount);
        }

        w.EndObject();
        w.indent--;
    }
    w.EndArray();

    w.EndObject();
    return w.ToString();
}

bool DeserializeProject(const std::string& json, NexusProjectData* project) {
    JsonParser p(json);

    if (!p.Expect('{')) return false;

    while (p.pos < p.len) {
        p.SkipWhitespace();
        if (p.pos >= p.len || p.data[p.pos] == '}') break;

        std::string key = p.ParseString();
        if (!p.Expect(':')) return false;

        if (key == "schemaVersion") {
            p.ParseInt();
        } else if (key == "name") {
            project->name = Utf8ToWString(p.ParseString());
        } else if (key == "targetProcess") {
            project->targetProcess = Utf8ToWString(p.ParseString());
        } else if (key == "targetPid") {
            project->targetPid = static_cast<uint32_t>(p.ParseInt());
        } else if (key == "createdTime") {
            project->createdTime = static_cast<uint64_t>(p.ParseInt());
        } else if (key == "modifiedTime") {
            project->modifiedTime = static_cast<uint64_t>(p.ParseInt());
        } else if (key == "nextId") {
            project->nextId = static_cast<uint64_t>(p.ParseInt());
        } else if (key == "addresses") {
            if (!p.Expect('[')) return false;

            while (p.pos < p.len) {
                p.SkipWhitespace();
                if (p.pos >= p.len || p.data[p.pos] == ']') break;

                if (!p.Expect('{')) {
                    p.SkipValue();
                    p.Expect(',');
                    continue;
                }

                NexusAddressEntry entry = {};

                while (p.pos < p.len) {
                    p.SkipWhitespace();
                    if (p.pos >= p.len || p.data[p.pos] == '}') break;

                    std::string entryKey = p.ParseString();
                    if (!p.Expect(':')) break;

                    if (entryKey == "id") {
                        entry.id = static_cast<uint64_t>(p.ParseInt());
                    } else if (entryKey == "address") {
                        entry.address = static_cast<uint64_t>(p.ParseInt());
                    } else if (entryKey == "valueType") {
                        entry.valueType = static_cast<NexusAddressValueType>(p.ParseInt());
                    } else if (entryKey == "flags") {
                        entry.flags = static_cast<uint32_t>(p.ParseInt());
                    } else if (entryKey == "description") {
                        std::wstring desc = Utf8ToWString(p.ParseString());
                        wcsncpy_s(entry.description, 256, desc.c_str(), _TRUNCATE);
                    } else if (entryKey == "groupName") {
                        std::wstring grp = Utf8ToWString(p.ParseString());
                        wcsncpy_s(entry.groupName, 64, grp.c_str(), _TRUNCATE);
                    } else if (entryKey == "offsetCount") {
                        entry.offsetCount = static_cast<uint32_t>(p.ParseInt());
                    } else if (entryKey == "offsets") {
                        if (p.Expect('[')) {
                            size_t i = 0;
                            while (i < 16 && p.pos < p.len && p.data[p.pos] != ']') {
                                entry.offsets[i++] = p.ParseInt();
                                p.Expect(',');
                            }
                            p.Expect(']');
                        }
                    } else {
                        p.SkipValue();
                    }

                    p.Expect(',');
                }
                p.Expect('}');

                if (entry.id > 0) {
                    project->addresses[entry.id] = entry;
                }

                p.Expect(',');
            }
            p.Expect(']');
        } else {
            p.SkipValue();
        }

        p.Expect(',');
    }

    return true;
}
