/**
 * @file dissect.cpp
 * @brief Structure dissection core: structure/element CRUD, instance binding, and read/write.
 *
 * Manages structure definitions (create, destroy, add/remove/update elements),
 * instance binding (map a structure to a base address), typed element reading
 * and writing, pointer following, auto-gap filling, and auto-guess from memory.
 *
 * Persistence (save/load/import/export) is in dissect_persist.cpp;
 * enumeration definitions are in dissect_enum.cpp.
 */

#include "dissect_internal.h"

/* ============================================================================
 * Global State Definitions
 * ============================================================================ */

std::atomic<uint32_t> g_nextStructId{1};
std::atomic<uint32_t> g_nextInstanceId{1};
std::mutex g_structMutex;

/* ============================================================================
 * Helper Functions (non-static — declared in dissect_internal.h)
 * ============================================================================ */

int32_t GetDefaultByteSize(NexusElementType varType) {
    switch (varType) {
        case NEXUS_ELEM_BYTE:
        case NEXUS_ELEM_INT8:
            return 1;
        case NEXUS_ELEM_WORD:
        case NEXUS_ELEM_INT16:
            return 2;
        case NEXUS_ELEM_DWORD:
        case NEXUS_ELEM_INT32:
        case NEXUS_ELEM_FLOAT:
            return 4;
        case NEXUS_ELEM_QWORD:
        case NEXUS_ELEM_INT64:
        case NEXUS_ELEM_DOUBLE:
        case NEXUS_ELEM_POINTER:
            return 8;
        case NEXUS_ELEM_STRING:
        case NEXUS_ELEM_UNICODE:
            return 64; // Default string length
        case NEXUS_ELEM_BYTE_ARRAY:
        case NEXUS_ELEM_BINARY:
            return 16; // Default array size
        case NEXUS_ELEM_ENUMERATION:
            return 4;  // Default to DWORD, actual size from linked enum
        default:
            return 4;
    }
}

void ElementToAPI(const StructElement& elem, NexusStructElement* out) {
    out->id = elem.id;
    out->offset = elem.offset;
    out->byteSize = elem.byteSize;
    out->varType = elem.varType;
    out->displayMethod = elem.displayMethod;
    strncpy_s(out->name, sizeof(out->name), elem.name.c_str(), _TRUNCATE);
    strncpy_s(out->customTypeName, sizeof(out->customTypeName),
              elem.customTypeName.c_str(), _TRUNCATE);
    out->childStructId = elem.childStructId;
    out->childStructOffset = elem.childStructOffset;
    out->backgroundColor = elem.backgroundColor;
    out->arrayCount = elem.arrayCount;
    out->bitOffset = elem.bitOffset;
    out->bitSize = elem.bitSize;
    out->flags = elem.flags;
    out->enumDefinitionId = elem.enumDefinitionId;
}

void APIToElement(const NexusStructElement* api, StructElement& elem) {
    elem.id = api->id;
    elem.offset = api->offset;
    elem.byteSize = api->byteSize;
    elem.varType = api->varType;
    elem.displayMethod = api->displayMethod;
    elem.name = api->name;
    elem.customTypeName = api->customTypeName;
    elem.childStructId = api->childStructId;
    elem.childStructOffset = api->childStructOffset;
    elem.backgroundColor = api->backgroundColor;
    elem.arrayCount = api->arrayCount;
    elem.bitOffset = api->bitOffset;
    elem.bitSize = api->bitSize;
    elem.flags = api->flags;
    elem.enumDefinitionId = api->enumDefinitionId;
}

/* ============================================================================
 * Structure Management & Instance Implementation
 * ============================================================================ */

extern "C" {

/* ----------------------------------------------------------------------------
 * Structure CRUD
 * -------------------------------------------------------------------------- */

NEXUS_API NexusResult Nexus_StructureCreate(
    const char* name,
    NexusStructureHandle* structure)
{
    if (!name || !structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = new DissectedStructure();
    s->id = g_nextStructId++;
    s->name = name;
    s->size = 0; // Auto-size
    s->flags = NEXUS_STRUCT_FLAG_NONE;

    *structure = static_cast<NexusStructureHandle>(s);
    return NEXUS_OK;
}

NEXUS_API void Nexus_StructureDestroy(NexusStructureHandle structure) {
    if (!structure) return;

    auto* s = static_cast<DissectedStructure*>(structure);

    // Clean up child structures marked as local
    for (auto& pair : s->childStructs) {
        delete pair.second;
    }

    delete s;
}

NEXUS_API NexusResult Nexus_StructureGetInfo(
    NexusStructureHandle structure,
    NexusStructInfo* info)
{
    if (!structure || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    info->id = s->id;
    strncpy_s(info->name, sizeof(info->name), s->name.c_str(), _TRUNCATE);
    info->size = s->size;
    info->elementCount = static_cast<uint32_t>(s->elements.size());
    info->flags = s->flags;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureSetProperties(
    NexusStructureHandle structure,
    const char* name,
    int32_t size,
    uint32_t flags)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    if (name) {
        s->name = name;
    }
    s->size = size;
    s->flags = flags;

    return NEXUS_OK;
}

/* ----------------------------------------------------------------------------
 * Element Management
 * -------------------------------------------------------------------------- */

NEXUS_API NexusResult Nexus_StructureAddElement(
    NexusStructureHandle structure,
    int32_t offset,
    NexusElementType varType,
    const char* name,
    int32_t byteSize,
    uint32_t* elementId)
{
    if (!structure || !name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    StructElement elem;
    elem.id = s->nextElementId++;
    elem.offset = offset;
    elem.varType = varType;
    elem.name = name;
    elem.byteSize = (byteSize > 0) ? byteSize : GetDefaultByteSize(varType);
    elem.displayMethod = NEXUS_DISPLAY_UNSIGNED;
    elem.childStructId = 0;
    elem.childStructOffset = 0;
    elem.backgroundColor = 0;
    elem.arrayCount = 1;
    elem.bitOffset = 0;
    elem.bitSize = 0;
    elem.flags = NEXUS_ELEM_FLAG_NONE;

    s->elements.push_back(elem);

    // Sort by offset
    std::sort(s->elements.begin(), s->elements.end(),
        [](const StructElement& a, const StructElement& b) {
            return a.offset < b.offset;
        });

    if (elementId) {
        *elementId = elem.id;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureRemoveElement(
    NexusStructureHandle structure,
    uint32_t elementId)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    s->elements.erase(it);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureGetElement(
    NexusStructureHandle structure,
    uint32_t elementId,
    NexusStructElement* element)
{
    if (!structure || !element) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    ElementToAPI(*it, element);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureGetElementByIndex(
    NexusStructureHandle structure,
    uint32_t index,
    NexusStructElement* element)
{
    if (!structure || !element) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    if (index >= s->elements.size()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    ElementToAPI(s->elements[index], element);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureGetElementByOffset(
    NexusStructureHandle structure,
    int32_t offset,
    NexusStructElement* element)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [offset](const StructElement& e) { return e.offset == offset; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (element) {
        ElementToAPI(*it, element);
    }
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureUpdateElement(
    NexusStructureHandle structure,
    const NexusStructElement* element)
{
    if (!structure || !element) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [element](const StructElement& e) { return e.id == element->id; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    APIToElement(element, *it);

    // Resort if offset changed
    std::sort(s->elements.begin(), s->elements.end(),
        [](const StructElement& a, const StructElement& b) {
            return a.offset < b.offset;
        });

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureGetElementCount(
    NexusStructureHandle structure,
    uint32_t* count)
{
    if (!structure || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);
    *count = static_cast<uint32_t>(s->elements.size());

    return NEXUS_OK;
}

/* ----------------------------------------------------------------------------
 * Child Structure
 * -------------------------------------------------------------------------- */

NEXUS_API NexusResult Nexus_StructureSetChildStruct(
    NexusStructureHandle structure,
    uint32_t elementId,
    NexusStructureHandle childStruct,
    int32_t childOffset)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (it->varType != NEXUS_ELEM_POINTER) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (childStruct) {
        auto* child = static_cast<DissectedStructure*>(childStruct);
        it->childStructId = child->id;
        s->childStructs[child->id] = child;
    } else {
        it->childStructId = 0;
    }
    it->childStructOffset = childOffset;

    return NEXUS_OK;
}

/* ----------------------------------------------------------------------------
 * Gap Filling & Auto-Guessing
 * -------------------------------------------------------------------------- */

NEXUS_API NexusResult Nexus_StructureFillGaps(
    NexusStructureHandle structure,
    NexusProcessHandle /*process*/,
    uint64_t /*baseAddress*/)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    if (s->elements.empty()) {
        return NEXUS_OK;
    }

    // Sort first
    std::sort(s->elements.begin(), s->elements.end(),
        [](const StructElement& a, const StructElement& b) {
            return a.offset < b.offset;
        });

    std::vector<StructElement> newElements;
    int32_t currentOffset = 0;

    for (const auto& elem : s->elements) {
        // Fill gap before this element
        while (currentOffset < elem.offset) {
            StructElement gap;
            gap.id = s->nextElementId++;
            gap.offset = currentOffset;
            gap.byteSize = 1;
            gap.varType = NEXUS_ELEM_BYTE;
            gap.displayMethod = NEXUS_DISPLAY_HEX;
            gap.name = "";
            gap.childStructId = 0;
            gap.childStructOffset = 0;
            gap.backgroundColor = 0;
            gap.arrayCount = 1;
            gap.bitOffset = 0;
            gap.bitSize = 0;
            gap.flags = NEXUS_ELEM_FLAG_NONE;

            newElements.push_back(gap);
            currentOffset++;
        }

        newElements.push_back(elem);
        currentOffset = elem.offset + elem.byteSize;
    }

    // Fill to structure size if defined
    if (s->size > 0) {
        while (currentOffset < s->size) {
            StructElement gap;
            gap.id = s->nextElementId++;
            gap.offset = currentOffset;
            gap.byteSize = 1;
            gap.varType = NEXUS_ELEM_BYTE;
            gap.displayMethod = NEXUS_DISPLAY_HEX;
            gap.name = "";
            gap.childStructId = 0;
            gap.childStructOffset = 0;
            gap.backgroundColor = 0;
            gap.arrayCount = 1;
            gap.bitOffset = 0;
            gap.bitSize = 0;
            gap.flags = NEXUS_ELEM_FLAG_NONE;

            newElements.push_back(gap);
            currentOffset++;
        }
    }

    s->elements = std::move(newElements);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureAutoGuess(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t address,
    size_t size)
{
    if (!structure || !process || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    // Clear existing elements
    s->elements.clear();
    s->nextElementId = 1;

    // Read memory
    std::vector<uint8_t> buffer(size);
    size_t bytesRead = 0;
    NexusResult result = Nexus_ReadMemory(process, address, buffer.data(), size, &bytesRead);
    if (result != NEXUS_OK && result != NEXUS_ERROR_PARTIAL_READ) {
        return result;
    }

    // Simple heuristics for type guessing
    size_t offset = 0;
    while (offset < bytesRead) {
        StructElement elem;
        elem.id = s->nextElementId++;
        elem.offset = static_cast<int32_t>(offset);
        elem.displayMethod = NEXUS_DISPLAY_UNSIGNED;
        elem.childStructId = 0;
        elem.childStructOffset = 0;
        elem.backgroundColor = 0;
        elem.arrayCount = 1;
        elem.bitOffset = 0;
        elem.bitSize = 0;
        elem.flags = NEXUS_ELEM_FLAG_NONE;

        // Check for pointer (aligned 8-byte value in valid range)
        if (offset + 8 <= bytesRead && (offset % 8) == 0) {
            uint64_t val = *reinterpret_cast<uint64_t*>(&buffer[offset]);
            // Check if it looks like a pointer (typical user-mode range)
            if (val >= 0x10000 && val < 0x00007FFFFFFFFFFF) {
                elem.varType = NEXUS_ELEM_POINTER;
                elem.byteSize = 8;
                elem.name = "ptr_" + std::to_string(offset);
                s->elements.push_back(elem);
                offset += 8;
                continue;
            }
        }

        // Check for float (4-byte aligned, reasonable value)
        if (offset + 4 <= bytesRead && (offset % 4) == 0) {
            float val = *reinterpret_cast<float*>(&buffer[offset]);
            if (val != 0.0f && std::isfinite(val) &&
                val > -1e10f && val < 1e10f && val != static_cast<float>(static_cast<int>(val))) {
                elem.varType = NEXUS_ELEM_FLOAT;
                elem.byteSize = 4;
                elem.name = "float_" + std::to_string(offset);
                s->elements.push_back(elem);
                offset += 4;
                continue;
            }
        }

        // Check for DWORD (4-byte aligned)
        if (offset + 4 <= bytesRead && (offset % 4) == 0) {
            uint32_t val = *reinterpret_cast<uint32_t*>(&buffer[offset]);
            if (val != 0) {
                elem.varType = NEXUS_ELEM_DWORD;
                elem.byteSize = 4;
                elem.name = "dword_" + std::to_string(offset);
                s->elements.push_back(elem);
                offset += 4;
                continue;
            }
        }

        // Default to byte
        elem.varType = NEXUS_ELEM_BYTE;
        elem.byteSize = 1;
        elem.name = "";
        s->elements.push_back(elem);
        offset += 1;
    }

    s->size = static_cast<int32_t>(size);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureSortElements(NexusStructureHandle structure) {
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    std::sort(s->elements.begin(), s->elements.end(),
        [](const StructElement& a, const StructElement& b) {
            return a.offset < b.offset;
        });

    return NEXUS_OK;
}

/* ----------------------------------------------------------------------------
 * Instance Management
 * -------------------------------------------------------------------------- */

NEXUS_API NexusResult Nexus_StructureCreateInstance(
    NexusStructureHandle structure,
    uint64_t baseAddress,
    const char* name,
    NexusStructInstance* instance)
{
    if (!structure || !instance) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    instance->id = g_nextInstanceId++;
    instance->structId = s->id;
    instance->baseAddress = baseAddress;
    if (name) {
        strncpy_s(instance->name, sizeof(instance->name), name, _TRUNCATE);
    } else {
        instance->name[0] = '\0';
    }
    instance->frozen = 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureReadElement(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    NexusElementValue* value)
{
    if (!structure || !process || !value) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    const StructElement& elem = *it;
    uint64_t addr = baseAddress + elem.offset;

    memset(value, 0, sizeof(NexusElementValue));
    value->elementId = elementId;
    value->address = addr;

    NexusResult result = NEXUS_OK;

    switch (elem.varType) {
        case NEXUS_ELEM_BYTE:
            result = Nexus_ReadU8(process, addr, &value->data.byteVal);
            value->dataSize = 1;
            break;
        case NEXUS_ELEM_INT8:
            result = Nexus_ReadMemory(process, addr, &value->data.int8Val, 1, nullptr);
            value->dataSize = 1;
            break;
        case NEXUS_ELEM_WORD:
            result = Nexus_ReadU16(process, addr, &value->data.wordVal);
            value->dataSize = 2;
            break;
        case NEXUS_ELEM_INT16:
            result = Nexus_ReadMemory(process, addr, &value->data.int16Val, 2, nullptr);
            value->dataSize = 2;
            break;
        case NEXUS_ELEM_DWORD:
            result = Nexus_ReadU32(process, addr, &value->data.dwordVal);
            value->dataSize = 4;
            break;
        case NEXUS_ELEM_INT32:
            result = Nexus_ReadMemory(process, addr, &value->data.int32Val, 4, nullptr);
            value->dataSize = 4;
            break;
        case NEXUS_ELEM_QWORD:
        case NEXUS_ELEM_POINTER:
            result = Nexus_ReadU64(process, addr, &value->data.qwordVal);
            value->dataSize = 8;
            break;
        case NEXUS_ELEM_INT64:
            result = Nexus_ReadMemory(process, addr, &value->data.int64Val, 8, nullptr);
            value->dataSize = 8;
            break;
        case NEXUS_ELEM_FLOAT:
            result = Nexus_ReadF32(process, addr, &value->data.floatVal);
            value->dataSize = 4;
            break;
        case NEXUS_ELEM_DOUBLE:
            result = Nexus_ReadF64(process, addr, &value->data.doubleVal);
            value->dataSize = 8;
            break;
        case NEXUS_ELEM_STRING:
            result = Nexus_ReadCString(process, addr, value->data.stringVal,
                                       sizeof(value->data.stringVal), nullptr);
            value->dataSize = static_cast<int32_t>(strlen(value->data.stringVal));
            break;
        case NEXUS_ELEM_UNICODE:
            result = Nexus_ReadWString(process, addr, value->data.unicodeVal,
                                       sizeof(value->data.unicodeVal)/sizeof(wchar_t), nullptr);
            value->dataSize = static_cast<int32_t>(wcslen(value->data.unicodeVal) * sizeof(wchar_t));
            break;
        case NEXUS_ELEM_BYTE_ARRAY:
        case NEXUS_ELEM_BINARY: {
            size_t toRead = (std::min)(static_cast<size_t>(elem.byteSize),
                                      sizeof(value->data.bytesVal));
            size_t bytesRead = 0;
            result = Nexus_ReadMemory(process, addr, value->data.bytesVal, toRead, &bytesRead);
            value->dataSize = static_cast<int32_t>(bytesRead);
            break;
        }
        default:
            return NEXUS_ERROR_INVALID_PARAMETER;
    }

    value->valid = (result == NEXUS_OK) ? 1 : 0;
    return result;
}

NEXUS_API NexusResult Nexus_StructureWriteElement(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    const NexusElementValue* value)
{
    if (!structure || !process || !value) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    const StructElement& elem = *it;
    uint64_t addr = baseAddress + elem.offset;

    switch (elem.varType) {
        case NEXUS_ELEM_BYTE:
            return Nexus_WriteMemory(process, addr, &value->data.byteVal, 1, nullptr);
        case NEXUS_ELEM_INT8:
            return Nexus_WriteMemory(process, addr, &value->data.int8Val, 1, nullptr);
        case NEXUS_ELEM_WORD:
            return Nexus_WriteMemory(process, addr, &value->data.wordVal, 2, nullptr);
        case NEXUS_ELEM_INT16:
            return Nexus_WriteMemory(process, addr, &value->data.int16Val, 2, nullptr);
        case NEXUS_ELEM_DWORD:
            return Nexus_WriteMemory(process, addr, &value->data.dwordVal, 4, nullptr);
        case NEXUS_ELEM_INT32:
            return Nexus_WriteMemory(process, addr, &value->data.int32Val, 4, nullptr);
        case NEXUS_ELEM_QWORD:
        case NEXUS_ELEM_POINTER:
            return Nexus_WriteMemory(process, addr, &value->data.qwordVal, 8, nullptr);
        case NEXUS_ELEM_INT64:
            return Nexus_WriteMemory(process, addr, &value->data.int64Val, 8, nullptr);
        case NEXUS_ELEM_FLOAT:
            return Nexus_WriteMemory(process, addr, &value->data.floatVal, 4, nullptr);
        case NEXUS_ELEM_DOUBLE:
            return Nexus_WriteMemory(process, addr, &value->data.doubleVal, 8, nullptr);
        case NEXUS_ELEM_STRING:
            return Nexus_WriteMemory(process, addr, value->data.stringVal,
                                     strlen(value->data.stringVal) + 1, nullptr);
        case NEXUS_ELEM_UNICODE:
            return Nexus_WriteMemory(process, addr, value->data.unicodeVal,
                                     (wcslen(value->data.unicodeVal) + 1) * sizeof(wchar_t), nullptr);
        case NEXUS_ELEM_BYTE_ARRAY:
        case NEXUS_ELEM_BINARY:
            return Nexus_WriteMemory(process, addr, value->data.bytesVal,
                                     value->dataSize, nullptr);
        default:
            return NEXUS_ERROR_INVALID_PARAMETER;
    }
}

NEXUS_API NexusResult Nexus_StructureReadAllElements(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    NexusElementValue* values,
    size_t maxValues,
    size_t* valuesRead)
{
    if (!structure || !process || !values || !valuesRead) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    size_t count = (std::min)(s->elements.size(), maxValues);
    *valuesRead = 0;

    for (size_t i = 0; i < count; ++i) {
        Nexus_StructureReadElement(structure, process, baseAddress,
                                   s->elements[i].id, &values[i]);
        (*valuesRead)++;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureFollowPointer(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    uint64_t* targetAddress)
{
    if (!structure || !process || !targetAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* s = static_cast<DissectedStructure*>(structure);

    auto it = std::find_if(s->elements.begin(), s->elements.end(),
        [elementId](const StructElement& e) { return e.id == elementId; });

    if (it == s->elements.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (it->varType != NEXUS_ELEM_POINTER) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    uint64_t ptrAddr = baseAddress + it->offset;
    uint64_t ptrValue = 0;

    NexusResult result = Nexus_ReadPointer(process, ptrAddr, &ptrValue);
    if (result != NEXUS_OK) {
        return result;
    }

    *targetAddress = ptrValue + it->childStructOffset;
    return NEXUS_OK;
}

} // extern "C"
