/**
 * @file utility.cpp
 * @brief Utility functions: type detection, address-expression resolution, memory dump, and fill.
 *
 * Implements heuristic value-type guessing (pointer, float, string, zero),
 * auto-structure analysis, address-expression parsing ("module+offset"
 * syntax), memory-region dumping to file, and memory fill with automatic
 * protection handling.
 *
 * Pattern scanning utilities are in utility_scan.cpp.
 */

#include "../include/nexus_api.h"
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

// Get module base by name
static uint64_t GetModuleBaseByName(HANDLE hProcess, const char* moduleName) {
    HMODULE modules[1024];
    DWORD needed;

    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return 0;
    }

    size_t moduleCount = needed / sizeof(HMODULE);
    for (size_t i = 0; i < moduleCount; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            if (_stricmp(name, moduleName) == 0) {
                MODULEINFO info;
                if (GetModuleInformation(hProcess, modules[i], &info, sizeof(info))) {
                    return (uint64_t)info.lpBaseOfDll;
                }
            }
        }
    }
    return 0;
}

// Parse hex address from string
static bool ParseHexAddress(const char* str, uint64_t& address) {
    const char* p = str;

    // Skip 0x prefix
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    // Skip $ prefix (Pascal notation)
    else if (p[0] == '$') {
        p++;
    }

    char* end;
    address = strtoull(p, &end, 16);
    return end != p && (*end == 0 || isspace(*end) || *end == '+' || *end == '-' || *end == ']');
}

/* ============================================================================
 * Type Detection Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_GuessValueType(
    NexusProcessHandle process,
    uint64_t address,
    NexusGuessedType* result)
{
    if (!process || !result) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(result, 0, sizeof(*result));

    HANDLE hProcess = (HANDLE)process;

    // Read 8 bytes
    uint8_t buffer[8];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 8, &bytesRead) || bytesRead < 8) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    uint64_t value = *(uint64_t*)buffer;
    float floatVal = *(float*)buffer;
    (void)floatVal;  // Used in float check below

    // Check for zero
    if (value == 0) {
        result->primaryType = NEXUS_SCAN_INT64;
        result->flags |= NEXUS_TYPE_IS_ZERO;
        result->confidence = 1.0f;
        return NEXUS_OK;
    }

    // Check if it looks like a pointer (x64 user-mode range)
    if (value > 0x10000 && value < 0x00007FFFFFFFFFFF) {
        // Verify it points to valid memory
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)value, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT) {
            result->flags |= NEXUS_TYPE_MIGHT_BE_POINTER;
            result->primaryType = NEXUS_SCAN_INT64;  // Pointer
            result->confidence = 0.8f;
            return NEXUS_OK;
        }
    }

    // Check if it looks like a reasonable float
    if (!std::isnan(floatVal) && !std::isinf(floatVal) &&
        floatVal > 0.0001f && floatVal < 100000.0f) {
        result->flags |= NEXUS_TYPE_MIGHT_BE_FLOAT;
        result->primaryType = NEXUS_SCAN_FLOAT;
        result->secondaryType = NEXUS_SCAN_INT32;
        result->confidence = 0.6f;
        return NEXUS_OK;
    }

    // Check if small integer
    if (value <= 0xFFFFFFFF) {
        uint32_t intVal = (uint32_t)value;
        if (intVal < 10000000) {
            result->primaryType = NEXUS_SCAN_INT32;
            result->confidence = 0.7f;
            return NEXUS_OK;
        }
    }

    // Default to 64-bit integer
    result->primaryType = NEXUS_SCAN_INT64;
    result->confidence = 0.5f;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_AutoAnalyzeStructure(
    NexusProcessHandle process,
    uint64_t baseAddress,
    size_t size,
    NexusGuessedField* fields,
    size_t maxFields,
    size_t* fieldCount)
{
    if (!process || !fieldCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *fieldCount = 0;

    HANDLE hProcess = (HANDLE)process;

    // Read memory
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddress, buffer.data(), size, &bytesRead)) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    // Analyze in 8-byte chunks
    for (size_t offset = 0; offset + 8 <= bytesRead && *fieldCount < maxFields; offset += 8) {
        NexusGuessedType guessedType;
        auto result = Nexus_GuessValueType(process, baseAddress + offset, &guessedType);
        if (result != NEXUS_OK) continue;

        if (fields) {
            NexusGuessedField& field = fields[*fieldCount];
            field.offset = (uint32_t)offset;
            field.type = guessedType.primaryType;
            field.confidence = guessedType.confidence;

            // Determine size based on type
            switch (guessedType.primaryType) {
                case NEXUS_SCAN_BYTE: field.size = 1; break;
                case NEXUS_SCAN_INT16: field.size = 2; break;
                case NEXUS_SCAN_INT32: field.size = 4; break;
                case NEXUS_SCAN_FLOAT: field.size = 4; break;
                case NEXUS_SCAN_DOUBLE: field.size = 8; break;
                default: field.size = 8; break;
            }

            // Add comment
            if (guessedType.flags & NEXUS_TYPE_IS_ZERO) {
                strcpy_s(field.comment, "Zero/null");
            } else if (guessedType.flags & NEXUS_TYPE_MIGHT_BE_POINTER) {
                strcpy_s(field.comment, "Possible pointer");
            } else if (guessedType.flags & NEXUS_TYPE_MIGHT_BE_FLOAT) {
                strcpy_s(field.comment, "Possible float");
            } else {
                sprintf_s(field.comment, "field_%02X", (uint32_t)offset);
            }
        }

        (*fieldCount)++;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Address Resolution Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ResolveAddressExpression(
    NexusProcessHandle handle,
    const char* expression,
    uint64_t* address)
{
    if (!handle || !expression || !address) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)handle;
    std::string expr(expression);

    // Trim whitespace
    while (!expr.empty() && isspace(expr.front())) expr.erase(0, 1);
    while (!expr.empty() && isspace(expr.back())) expr.pop_back();

    // Check for pointer dereference [...]
    if (expr.front() == '[' && expr.back() == ']') {
        std::string inner = expr.substr(1, expr.length() - 2);
        uint64_t innerAddr;
        auto result = Nexus_ResolveAddressExpression(handle, inner.c_str(), &innerAddr);
        if (result != NEXUS_OK) return result;

        // Dereference
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, (LPCVOID)innerAddr, address, 8, &bytesRead) || bytesRead < 8) {
            return NEXUS_ERROR_PARTIAL_READ;
        }
        return NEXUS_OK;
    }

    // Try to parse as hex address first
    if (ParseHexAddress(expr.c_str(), *address)) {
        return NEXUS_OK;
    }

    // Try module+offset format
    size_t plusPos = expr.find('+');
    size_t minusPos = expr.find('-');
    size_t opPos = std::min(plusPos, minusPos);

    if (opPos != std::string::npos) {
        std::string left = expr.substr(0, opPos);
        std::string right = expr.substr(opPos + 1);

        // Trim
        while (!left.empty() && isspace(left.back())) left.pop_back();
        while (!right.empty() && isspace(right.front())) right.erase(0, 1);

        // Try to resolve left side
        uint64_t leftVal;
        if (ParseHexAddress(left.c_str(), leftVal)) {
            // Left is hex
        } else {
            // Try as module name
            leftVal = GetModuleBaseByName(hProcess, left.c_str());
            if (leftVal == 0) return NEXUS_ERROR_NOT_FOUND;
        }

        // Parse right side as hex offset
        uint64_t rightVal;
        if (!ParseHexAddress(right.c_str(), rightVal)) {
            return NEXUS_ERROR_INVALID_PARAMETER;
        }

        *address = (expr[opPos] == '+') ? leftVal + rightVal : leftVal - rightVal;
        return NEXUS_OK;
    }

    // Try as module name only
    uint64_t moduleBase = GetModuleBaseByName(hProcess, expr.c_str());
    if (moduleBase != 0) {
        *address = moduleBase;
        return NEXUS_OK;
    }

    return NEXUS_ERROR_NOT_FOUND;
}

/* ============================================================================
 * Memory Dump Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_DumpMemoryRegion(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    const wchar_t* filePath)
{
    if (!handle || !filePath || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)handle;

    // Read memory
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead)) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    // Write to file
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        return NEXUS_ERROR_UNKNOWN;
    }

    file.write(reinterpret_cast<char*>(buffer.data()), bytesRead);
    return file ? NEXUS_OK : NEXUS_ERROR_UNKNOWN;
}

NEXUS_API NexusResult Nexus_DumpModule(
    NexusProcessHandle handle,
    uint64_t moduleBase,
    const wchar_t* filePath)
{
    if (!handle || !filePath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)handle;

    // Read DOS header to get module size
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Read NT headers to get image size
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return NEXUS_ERROR_PARTIAL_READ;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t imageSize = ntHeaders.OptionalHeader.SizeOfImage;
    return Nexus_DumpMemoryRegion(handle, moduleBase, imageSize, filePath);
}

/* ============================================================================
 * Fill Memory Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_FillMemory(
    NexusProcessHandle handle,
    uint64_t address,
    size_t size,
    uint8_t fillByte)
{
    if (!handle || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE hProcess = (HANDLE)handle;

    // Create fill buffer
    const size_t CHUNK_SIZE = 0x10000;  // 64KB
    std::vector<uint8_t> buffer(std::min(size, CHUNK_SIZE), fillByte);

    size_t remaining = size;
    uint64_t currentAddr = address;

    while (remaining > 0) {
        size_t toWrite = std::min(remaining, buffer.size());

        // Change protection
        DWORD oldProtect;
        bool protChanged = VirtualProtectEx(hProcess, (LPVOID)currentAddr, toWrite,
                                            PAGE_EXECUTE_READWRITE, &oldProtect);

        // Write memory
        SIZE_T bytesWritten;
        bool success = WriteProcessMemory(hProcess, (LPVOID)currentAddr, buffer.data(), toWrite, &bytesWritten);

        // Restore protection
        if (protChanged) {
            VirtualProtectEx(hProcess, (LPVOID)currentAddr, toWrite, oldProtect, &oldProtect);
        }

        if (!success || bytesWritten == 0) {
            return NEXUS_ERROR_PARTIAL_READ;
        }

        remaining -= bytesWritten;
        currentAddr += bytesWritten;
    }

    return NEXUS_OK;
}
