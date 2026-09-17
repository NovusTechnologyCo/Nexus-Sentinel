/**
 * @file dissect_persist.cpp
 * @brief Structure dissection persistence: XML save/load, CE import/export, and cloning.
 *
 * Serialises structure definitions to/from the .nxs XML format,
 * imports/exports CE-compatible .cs structure files, and provides
 * deep-clone functionality for structure handles.
 */

#include "dissect_internal.h"

/* ============================================================================
 * Static Helpers (used only by persistence)
 * ============================================================================ */

static int32_t SafeStoi(const std::string& str, int32_t defaultVal = 0, int base = 10) {
    if (str.empty()) return defaultVal;
    try {
        return std::stoi(str, nullptr, base);
    } catch (...) {
        return defaultVal;
    }
}

static uint32_t SafeStoul(const std::string& str, uint32_t defaultVal = 0, int base = 10) {
    if (str.empty()) return defaultVal;
    try {
        return std::stoul(str, nullptr, base);
    } catch (...) {
        return defaultVal;
    }
}

static std::string EscapeXML(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c; break;
        }
    }
    return result;
}

static std::string UnescapeXML(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '&') {
            if (str.compare(i, 5, "&amp;") == 0) { result += '&'; i += 4; }
            else if (str.compare(i, 4, "&lt;") == 0) { result += '<'; i += 3; }
            else if (str.compare(i, 4, "&gt;") == 0) { result += '>'; i += 3; }
            else if (str.compare(i, 6, "&quot;") == 0) { result += '"'; i += 5; }
            else if (str.compare(i, 6, "&apos;") == 0) { result += '\''; i += 5; }
            else result += str[i];
        } else {
            result += str[i];
        }
    }
    return result;
}

static const char* ElementTypeToString(NexusElementType type) {
    switch (type) {
        case NEXUS_ELEM_BYTE: return "Byte";
        case NEXUS_ELEM_WORD: return "Word";
        case NEXUS_ELEM_DWORD: return "Dword";
        case NEXUS_ELEM_QWORD: return "Qword";
        case NEXUS_ELEM_FLOAT: return "Float";
        case NEXUS_ELEM_DOUBLE: return "Double";
        case NEXUS_ELEM_STRING: return "String";
        case NEXUS_ELEM_UNICODE: return "Unicode";
        case NEXUS_ELEM_BYTE_ARRAY: return "ByteArray";
        case NEXUS_ELEM_BINARY: return "Binary";
        case NEXUS_ELEM_ENUMERATION: return "Enumeration";
        case NEXUS_ELEM_POINTER: return "Pointer";
        case NEXUS_ELEM_CUSTOM: return "Custom";
        case NEXUS_ELEM_INT8: return "Int8";
        case NEXUS_ELEM_INT16: return "Int16";
        case NEXUS_ELEM_INT32: return "Int32";
        case NEXUS_ELEM_INT64: return "Int64";
        default: return "Unknown";
    }
}

static NexusElementType StringToElementType(const std::string& str) {
    if (str == "Byte") return NEXUS_ELEM_BYTE;
    if (str == "Word") return NEXUS_ELEM_WORD;
    if (str == "Dword") return NEXUS_ELEM_DWORD;
    if (str == "Qword") return NEXUS_ELEM_QWORD;
    if (str == "Float") return NEXUS_ELEM_FLOAT;
    if (str == "Double") return NEXUS_ELEM_DOUBLE;
    if (str == "String") return NEXUS_ELEM_STRING;
    if (str == "Unicode") return NEXUS_ELEM_UNICODE;
    if (str == "ByteArray") return NEXUS_ELEM_BYTE_ARRAY;
    if (str == "Binary") return NEXUS_ELEM_BINARY;
    if (str == "Enumeration" || str == "Enum") return NEXUS_ELEM_ENUMERATION;
    if (str == "Pointer") return NEXUS_ELEM_POINTER;
    if (str == "Custom") return NEXUS_ELEM_CUSTOM;
    if (str == "Int8") return NEXUS_ELEM_INT8;
    if (str == "Int16") return NEXUS_ELEM_INT16;
    if (str == "Int32") return NEXUS_ELEM_INT32;
    if (str == "Int64") return NEXUS_ELEM_INT64;
    // CE compatibility
    if (str == "4 Bytes") return NEXUS_ELEM_DWORD;
    if (str == "8 Bytes") return NEXUS_ELEM_QWORD;
    if (str == "2 Bytes") return NEXUS_ELEM_WORD;
    return NEXUS_ELEM_DWORD;
}

static const char* DisplayMethodToString(NexusDisplayMethod method) {
    switch (method) {
        case NEXUS_DISPLAY_UNSIGNED: return "Unsigned";
        case NEXUS_DISPLAY_SIGNED: return "Signed";
        case NEXUS_DISPLAY_HEX: return "Hex";
        default: return "Unsigned";
    }
}

static NexusDisplayMethod StringToDisplayMethod(const std::string& str) {
    if (str == "Unsigned") return NEXUS_DISPLAY_UNSIGNED;
    if (str == "Signed") return NEXUS_DISPLAY_SIGNED;
    if (str == "Hex" || str == "Hexadecimal") return NEXUS_DISPLAY_HEX;
    return NEXUS_DISPLAY_UNSIGNED;
}

static std::string GetXMLAttribute(const std::string& line, const std::string& attr) {
    std::string search = attr + "=\"";
    size_t start = line.find(search);
    if (start == std::string::npos) return "";
    start += search.length();
    size_t end = line.find('"', start);
    if (end == std::string::npos) return "";
    return UnescapeXML(line.substr(start, end - start));
}

/* ============================================================================
 * Persistence API Implementation
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_StructureSave(
    NexusStructureHandle structure,
    const char* path)
{
    if (!structure || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    std::ofstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    file << "<NexusStructures version=\"1.0\">\n";
    file << "  <Structure Name=\"" << EscapeXML(s->name) << "\" "
         << "Size=\"" << s->size << "\" "
         << "Flags=\"" << s->flags << "\">\n";

    for (const auto& elem : s->elements) {
        file << "    <Element "
             << "Offset=\"" << elem.offset << "\" "
             << "Type=\"" << ElementTypeToString(elem.varType) << "\" "
             << "Size=\"" << elem.byteSize << "\" "
             << "Name=\"" << EscapeXML(elem.name) << "\" "
             << "Display=\"" << DisplayMethodToString(elem.displayMethod) << "\"";

        if (!elem.customTypeName.empty()) {
            file << " CustomType=\"" << EscapeXML(elem.customTypeName) << "\"";
        }
        if (elem.childStructId != 0) {
            file << " ChildStruct=\"" << elem.childStructId << "\""
                 << " ChildOffset=\"" << elem.childStructOffset << "\"";
        }
        if (elem.backgroundColor != 0) {
            file << " BgColor=\"" << std::hex << elem.backgroundColor << std::dec << "\"";
        }
        if (elem.arrayCount > 1) {
            file << " ArrayCount=\"" << elem.arrayCount << "\"";
        }
        if (elem.bitOffset != 0 || elem.bitSize != 0) {
            file << " BitOffset=\"" << elem.bitOffset << "\""
                 << " BitSize=\"" << elem.bitSize << "\"";
        }
        if (elem.flags != 0) {
            file << " Flags=\"" << elem.flags << "\"";
        }

        file << "/>\n";
    }

    file << "  </Structure>\n";
    file << "</NexusStructures>\n";

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureLoad(
    const char* path,
    NexusStructureHandle* structure)
{
    if (!path || !structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    auto* s = new DissectedStructure();
    s->id = g_nextStructId++;

    /* CRITICAL FIX: Use safe parsing to prevent exceptions on malformed XML */
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("<Structure ") != std::string::npos) {
            s->name = GetXMLAttribute(line, "Name");
            s->size = SafeStoi(GetXMLAttribute(line, "Size"));
            s->flags = SafeStoul(GetXMLAttribute(line, "Flags"));
        }
        else if (line.find("<Element ") != std::string::npos) {
            StructElement elem;
            elem.id = s->nextElementId++;
            elem.offset = SafeStoi(GetXMLAttribute(line, "Offset"));
            elem.varType = StringToElementType(GetXMLAttribute(line, "Type"));
            elem.byteSize = SafeStoi(GetXMLAttribute(line, "Size"), GetDefaultByteSize(elem.varType));
            elem.name = GetXMLAttribute(line, "Name");
            elem.displayMethod = StringToDisplayMethod(GetXMLAttribute(line, "Display"));
            elem.customTypeName = GetXMLAttribute(line, "CustomType");

            elem.childStructId = SafeStoul(GetXMLAttribute(line, "ChildStruct"));
            elem.childStructOffset = SafeStoi(GetXMLAttribute(line, "ChildOffset"));
            elem.backgroundColor = SafeStoul(GetXMLAttribute(line, "BgColor"), 0, 16);

            elem.arrayCount = SafeStoi(GetXMLAttribute(line, "ArrayCount"), 1);
            elem.bitOffset = SafeStoi(GetXMLAttribute(line, "BitOffset"));
            elem.bitSize = SafeStoi(GetXMLAttribute(line, "BitSize"));
            elem.flags = SafeStoul(GetXMLAttribute(line, "Flags"));

            s->elements.push_back(elem);
        }
    }

    std::lock_guard<std::mutex> lock(g_structMutex);
    *structure = static_cast<NexusStructureHandle>(s);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureSaveMultiple(
    NexusStructureHandle* structures,
    size_t count,
    const char* path)
{
    if (!structures || count == 0 || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::ofstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    file << "<NexusStructures version=\"1.0\">\n";

    for (size_t i = 0; i < count; ++i) {
        auto* s = static_cast<DissectedStructure*>(structures[i]);
        if (!s) continue;

        file << "  <Structure Name=\"" << EscapeXML(s->name) << "\" "
             << "Size=\"" << s->size << "\" "
             << "Flags=\"" << s->flags << "\">\n";

        for (const auto& elem : s->elements) {
            file << "    <Element "
                 << "Offset=\"" << elem.offset << "\" "
                 << "Type=\"" << ElementTypeToString(elem.varType) << "\" "
                 << "Size=\"" << elem.byteSize << "\" "
                 << "Name=\"" << EscapeXML(elem.name) << "\" "
                 << "Display=\"" << DisplayMethodToString(elem.displayMethod) << "\"/>\n";
        }

        file << "  </Structure>\n";
    }

    file << "</NexusStructures>\n";

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureLoadMultiple(
    const char* path,
    NexusStructureHandle* structures,
    size_t maxStructures,
    size_t* structuresLoaded)
{
    if (!path || !structures || !structuresLoaded) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *structuresLoaded = 0;
    DissectedStructure* current = nullptr;

    /* CRITICAL FIX: Use safe parsing to prevent exceptions on malformed XML */
    std::string line;
    while (std::getline(file, line) && *structuresLoaded < maxStructures) {
        if (line.find("<Structure ") != std::string::npos) {
            /* CRITICAL FIX: Clean up any orphaned structure before creating new one */
            if (current) {
                delete current;
            }
            current = new DissectedStructure();
            current->id = g_nextStructId++;
            current->name = GetXMLAttribute(line, "Name");
            current->size = SafeStoi(GetXMLAttribute(line, "Size"));
            current->flags = SafeStoul(GetXMLAttribute(line, "Flags"));
        }
        else if (line.find("</Structure>") != std::string::npos && current) {
            structures[*structuresLoaded] = static_cast<NexusStructureHandle>(current);
            (*structuresLoaded)++;
            current = nullptr;
        }
        else if (line.find("<Element ") != std::string::npos && current) {
            StructElement elem;
            elem.id = current->nextElementId++;
            elem.offset = SafeStoi(GetXMLAttribute(line, "Offset"));
            elem.varType = StringToElementType(GetXMLAttribute(line, "Type"));
            elem.byteSize = SafeStoi(GetXMLAttribute(line, "Size"), GetDefaultByteSize(elem.varType));
            elem.name = GetXMLAttribute(line, "Name");
            elem.displayMethod = StringToDisplayMethod(GetXMLAttribute(line, "Display"));
            elem.customTypeName = "";
            elem.childStructId = 0;
            elem.childStructOffset = 0;
            elem.backgroundColor = 0;
            elem.arrayCount = 1;
            elem.bitOffset = 0;
            elem.bitSize = 0;
            elem.flags = 0;
            current->elements.push_back(elem);
        }
    }

    /* CRITICAL FIX: Clean up if file ended without closing tag (memory leak fix) */
    if (current) {
        delete current;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureImportCE(
    const char* path,
    NexusStructureHandle* structure)
{
    if (!path || !structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // CE uses similar XML format, try to load
    std::ifstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    auto* s = new DissectedStructure();
    s->id = g_nextStructId++;

    std::string line;
    while (std::getline(file, line)) {
        // CE uses "Structures" root with child "Structure" elements
        if (line.find("<Structure ") != std::string::npos ||
            line.find("<Structure>") != std::string::npos) {
            std::string name = GetXMLAttribute(line, "Name");
            if (!name.empty()) {
                s->name = name;
            }
        }
        else if (line.find("<Element ") != std::string::npos) {
            StructElement elem;
            elem.id = s->nextElementId++;

            /* CRITICAL FIX: Use safe parsing for CE format attributes */
            std::string offset = GetXMLAttribute(line, "Offset");
            if (offset.empty()) offset = GetXMLAttribute(line, "OffsetHex");
            int base = (offset.find("0x") == 0 || offset.find("0X") == 0) ? 16 : 10;
            elem.offset = SafeStoi(offset, 0, base);

            std::string vartype = GetXMLAttribute(line, "Vartype");
            elem.varType = StringToElementType(vartype);

            elem.byteSize = SafeStoi(GetXMLAttribute(line, "Bytesize"), GetDefaultByteSize(elem.varType));

            elem.name = GetXMLAttribute(line, "Description");

            std::string displayMethod = GetXMLAttribute(line, "DisplayMethod");
            elem.displayMethod = StringToDisplayMethod(displayMethod);

            elem.customTypeName = GetXMLAttribute(line, "Customtype");

            std::string childStruct = GetXMLAttribute(line, "ChildStruct");
            elem.childStructId = 0; // Would need to resolve by name

            elem.childStructOffset = SafeStoi(GetXMLAttribute(line, "ChildStructStart"));
            elem.backgroundColor = SafeStoul(GetXMLAttribute(line, "BackgroundColor"), 0, 16);

            elem.arrayCount = 1;
            elem.bitOffset = 0;
            elem.bitSize = 0;
            elem.flags = 0;

            s->elements.push_back(elem);
        }
    }

    // Sort by offset
    std::sort(s->elements.begin(), s->elements.end(),
        [](const StructElement& a, const StructElement& b) {
            return a.offset < b.offset;
        });

    *structure = static_cast<NexusStructureHandle>(s);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureExportCE(
    NexusStructureHandle structure,
    const char* path)
{
    if (!structure || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    std::ofstream file(path);
    if (!file.is_open()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    file << "<?xml version=\"1.0\"?>\n";
    file << "<Structures>\n";
    file << "  <Structure Name=\"" << EscapeXML(s->name) << "\" "
         << "AutoCreate=\"0\" AutoDestroy=\"0\" "
         << "AutoFill=\"" << ((s->flags & NEXUS_STRUCT_FLAG_AUTOFILL) ? "1" : "0") << "\" "
         << "DefaultHex=\"" << ((s->flags & NEXUS_STRUCT_FLAG_HEXDEFAULT) ? "1" : "0") << "\">\n";

    for (const auto& elem : s->elements) {
        file << "    <Element "
             << "Offset=\"" << elem.offset << "\" "
             << "Vartype=\"" << ElementTypeToString(elem.varType) << "\" "
             << "Bytesize=\"" << elem.byteSize << "\" "
             << "Description=\"" << EscapeXML(elem.name) << "\"";

        if (elem.displayMethod != NEXUS_DISPLAY_UNSIGNED) {
            file << " DisplayMethod=\"" << DisplayMethodToString(elem.displayMethod) << "\"";
        }

        file << "/>\n";
    }

    file << "  </Structure>\n";
    file << "</Structures>\n";

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureClone(
    NexusStructureHandle source,
    const char* newName,
    NexusStructureHandle* clone)
{
    if (!source || !clone) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* src = static_cast<DissectedStructure*>(source);
    auto* dst = new DissectedStructure();

    dst->id = g_nextStructId++;
    dst->name = newName ? newName : src->name;
    dst->size = src->size;
    dst->flags = src->flags;
    dst->elements = src->elements;

    // Reassign element IDs
    for (auto& elem : dst->elements) {
        elem.id = dst->nextElementId++;
    }

    *clone = static_cast<NexusStructureHandle>(dst);
    return NEXUS_OK;
}

} // extern "C"
