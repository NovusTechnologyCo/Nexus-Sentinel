/**
 * @file table_script.cpp
 * @brief AA script section parsing, validation, combination, and CE import helpers.
 *
 * Parses Auto-Assembler scripts to locate [ENABLE] and [DISABLE] section
 * boundaries, validates script structure, and provides a combine function
 * to merge separate sections into a single script.  Also contains XML
 * helpers for importing Cheat Engine table files.
 *
 * Table CRUD operations are in table.cpp.
 */

#include "nexus_api.h"

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>

/* ============================================================================
 * AA Script Helpers
 * ============================================================================ */

static std::string TrimWhitespace(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string ToUpperCase(const std::string& s) {
    std::string result = s;
    for (char& c : result) {
        if (c >= 'a' && c <= 'z') c -= 32;
    }
    return result;
}

static std::vector<std::string> SplitLines(const std::string& script) {
    std::vector<std::string> lines;
    std::istringstream stream(script);
    std::string line;
    while (std::getline(stream, line)) {
        // Remove trailing \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

static bool IsEnableMarker(const std::string& line) {
    std::string trimmed = TrimWhitespace(line);
    // Remove comment portion
    size_t commentPos = trimmed.find("//");
    if (commentPos != std::string::npos) {
        trimmed = trimmed.substr(0, commentPos);
        trimmed = TrimWhitespace(trimmed);
    }
    return ToUpperCase(trimmed) == "[ENABLE]";
}

static bool IsDisableMarker(const std::string& line) {
    std::string trimmed = TrimWhitespace(line);
    // Remove comment portion
    size_t commentPos = trimmed.find("//");
    if (commentPos != std::string::npos) {
        trimmed = trimmed.substr(0, commentPos);
        trimmed = TrimWhitespace(trimmed);
    }
    return ToUpperCase(trimmed) == "[DISABLE]";
}

/* ============================================================================
 * AA Script Section Parsing
 * ============================================================================ */

NEXUS_API NexusResult Nexus_AAScriptParseSections(
    const char* script,
    NexusAAScriptSections* sections)
{
    if (!script || !sections) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(sections, 0, sizeof(NexusAAScriptSections));
    sections->enableStart = -1;
    sections->enableEnd = -1;
    sections->disableStart = -1;
    sections->disableEnd = -1;
    sections->globalEnd = -1;

    std::vector<std::string> lines = SplitLines(script);
    sections->totalLines = static_cast<int32_t>(lines.size());

    int enableCount = 0;
    int disableCount = 0;

    for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
        if (IsEnableMarker(lines[i])) {
            enableCount++;
            if (enableCount == 1) {
                sections->enableStart = i;
                sections->hasEnable = 1;
                // If global end not set, it's just before enable
                if (sections->globalEnd < 0) {
                    sections->globalEnd = i;
                }
            }
        } else if (IsDisableMarker(lines[i])) {
            disableCount++;
            if (disableCount == 1) {
                sections->disableStart = i;
                sections->hasDisable = 1;
                // End of enable section is just before disable
                if (sections->enableStart >= 0 && sections->enableEnd < 0) {
                    sections->enableEnd = i;
                }
                // If global end not set, it's just before disable
                if (sections->globalEnd < 0) {
                    sections->globalEnd = i;
                }
            }
        }
    }

    // Set end positions
    if (sections->enableStart >= 0 && sections->enableEnd < 0) {
        // Enable goes to end or to disable
        sections->enableEnd = sections->totalLines;
    }
    if (sections->disableStart >= 0) {
        sections->disableEnd = sections->totalLines;
    }

    // Validate
    if (enableCount > 1) {
        sections->isValid = 0;
        strncpy_s(sections->errorMessage, sizeof(sections->errorMessage),
                  "Multiple [ENABLE] sections found", _TRUNCATE);
    } else if (disableCount > 1) {
        sections->isValid = 0;
        strncpy_s(sections->errorMessage, sizeof(sections->errorMessage),
                  "Multiple [DISABLE] sections found", _TRUNCATE);
    } else {
        sections->isValid = 1;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AAScriptGetEnableSection(
    const char* script,
    char* buffer,
    size_t bufferSize,
    size_t* scriptLength)
{
    if (!script || !scriptLength) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusAAScriptSections sections;
    NexusResult result = Nexus_AAScriptParseSections(script, &sections);
    if (result != NEXUS_OK) return result;

    std::vector<std::string> lines = SplitLines(script);
    std::string output;

    // Add global code (before any section marker)
    for (int i = 0; i < sections.globalEnd && i < static_cast<int>(lines.size()); ++i) {
        output += lines[i] + "\n";
    }

    // Add enable section content (without the marker)
    if (sections.hasEnable && sections.enableStart >= 0) {
        for (int i = sections.enableStart + 1; i < sections.enableEnd && i < static_cast<int>(lines.size()); ++i) {
            output += lines[i] + "\n";
        }
    }

    *scriptLength = output.length();

    if (buffer && bufferSize > 0) {
        size_t copyLen = (std::min)(bufferSize - 1, output.length());
        memcpy(buffer, output.c_str(), copyLen);
        buffer[copyLen] = '\0';
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AAScriptGetDisableSection(
    const char* script,
    char* buffer,
    size_t bufferSize,
    size_t* scriptLength)
{
    if (!script || !scriptLength) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusAAScriptSections sections;
    NexusResult result = Nexus_AAScriptParseSections(script, &sections);
    if (result != NEXUS_OK) return result;

    std::vector<std::string> lines = SplitLines(script);
    std::string output;

    // Add global code (before any section marker)
    for (int i = 0; i < sections.globalEnd && i < static_cast<int>(lines.size()); ++i) {
        output += lines[i] + "\n";
    }

    // Add disable section content (without the marker)
    if (sections.hasDisable && sections.disableStart >= 0) {
        for (int i = sections.disableStart + 1; i < sections.disableEnd && i < static_cast<int>(lines.size()); ++i) {
            output += lines[i] + "\n";
        }
    }

    *scriptLength = output.length();

    if (buffer && bufferSize > 0) {
        size_t copyLen = (std::min)(bufferSize - 1, output.length());
        memcpy(buffer, output.c_str(), copyLen);
        buffer[copyLen] = '\0';
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AAScriptValidate(
    const char* script,
    int32_t* isValid,
    char* errorBuffer,
    size_t errorBufferSize)
{
    if (!script || !isValid) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusAAScriptSections sections;
    NexusResult result = Nexus_AAScriptParseSections(script, &sections);
    if (result != NEXUS_OK) return result;

    *isValid = sections.isValid;

    if (errorBuffer && errorBufferSize > 0) {
        if (!sections.isValid) {
            strncpy_s(errorBuffer, errorBufferSize, sections.errorMessage, _TRUNCATE);
        } else if (!sections.hasEnable && !sections.hasDisable) {
            strncpy_s(errorBuffer, errorBufferSize,
                      "Script has no [ENABLE] or [DISABLE] sections", _TRUNCATE);
            *isValid = 0;
        } else {
            errorBuffer[0] = '\0';
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AAScriptCombine(
    const char* enableCode,
    const char* disableCode,
    const char* globalCode,
    char* buffer,
    size_t bufferSize,
    size_t* scriptLength)
{
    if (!scriptLength) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::string output;

    // Add global code if provided
    if (globalCode && globalCode[0]) {
        output += globalCode;
        if (output.back() != '\n') output += '\n';
        output += '\n';
    }

    // Add enable section
    output += "[ENABLE]\n";
    if (enableCode && enableCode[0]) {
        output += enableCode;
        if (output.back() != '\n') output += '\n';
    }
    output += '\n';

    // Add disable section
    output += "[DISABLE]\n";
    if (disableCode && disableCode[0]) {
        output += disableCode;
        if (output.back() != '\n') output += '\n';
    }

    *scriptLength = output.length();

    if (buffer && bufferSize > 0) {
        size_t copyLen = (std::min)(bufferSize - 1, output.length());
        memcpy(buffer, output.c_str(), copyLen);
        buffer[copyLen] = '\0';
    }

    return NEXUS_OK;
}

/* ============================================================================
 * CE Cheat Table Import/Export (v0.22.0)
 * ============================================================================ */

// Simple XML attribute extraction
[[maybe_unused]] static std::string GetXMLAttr(const std::string& tag, const std::string& attr) {
    std::string search = attr + "=\"";
    size_t pos = tag.find(search);
    if (pos == std::string::npos) return "";
    pos += search.length();
    size_t end = tag.find('"', pos);
    if (end == std::string::npos) return "";
    return tag.substr(pos, end - pos);
}
