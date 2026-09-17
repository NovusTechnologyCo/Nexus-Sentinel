/**
 * @file dissect_enum.cpp
 * @brief Enumeration definition registry for structure elements.
 *
 * Manages a global registry of enum definitions that can be linked
 * to structure elements of type NEXUS_ELEM_ENUMERATION.  Supports
 * create/destroy, value add/remove, name/value lookup, bitmask
 * display mode, and whole-registry enumeration.
 */

#include "dissect_internal.h"

/* Global state definitions for enums */
std::map<uint32_t, EnumDefinitionInternal> g_enumRegistry;
std::atomic<uint32_t> g_nextEnumId{1};
std::mutex g_enumMutex;

/* Static helper */
static EnumDefinitionInternal* GetEnumById(uint32_t enumId) {
    auto it = g_enumRegistry.find(enumId);
    if (it != g_enumRegistry.end()) {
        return &it->second;
    }
    return nullptr;
}

extern "C" {

NEXUS_API NexusResult Nexus_EnumCreate(
    const char* name,
    NexusElementType baseType,
    uint32_t* enumId)
{
    if (!name || !enumId) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Validate base type is an integer type */
    switch (baseType) {
        case NEXUS_ELEM_BYTE:
        case NEXUS_ELEM_WORD:
        case NEXUS_ELEM_DWORD:
        case NEXUS_ELEM_QWORD:
        case NEXUS_ELEM_INT8:
        case NEXUS_ELEM_INT16:
        case NEXUS_ELEM_INT32:
        case NEXUS_ELEM_INT64:
            break;
        default:
            return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    EnumDefinitionInternal enumDef;
    enumDef.id = g_nextEnumId++;
    enumDef.name = name;
    enumDef.baseType = baseType;
    enumDef.flags = 0;

    g_enumRegistry[enumDef.id] = std::move(enumDef);
    *enumId = g_enumRegistry.rbegin()->second.id;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumDestroy(uint32_t enumId) {
    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto it = g_enumRegistry.find(enumId);
    if (it == g_enumRegistry.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    g_enumRegistry.erase(it);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumAddValue(
    uint32_t enumId,
    int64_t value,
    const char* name)
{
    if (!name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    /* Check if value already exists */
    for (const auto& v : enumDef->values) {
        if (v.numericValue == value) {
            return NEXUS_ERROR_ALREADY_EXISTS;
        }
    }

    NexusEnumValue newValue;
    newValue.numericValue = value;
    strncpy_s(newValue.name, sizeof(newValue.name), name, _TRUNCATE);

    enumDef->values.push_back(newValue);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumRemoveValue(
    uint32_t enumId,
    int64_t value)
{
    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    for (auto it = enumDef->values.begin(); it != enumDef->values.end(); ++it) {
        if (it->numericValue == value) {
            enumDef->values.erase(it);
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_EnumGetDefinition(
    uint32_t enumId,
    NexusEnumDefinition* definition)
{
    if (!definition) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    definition->id = enumDef->id;
    strncpy_s(definition->name, sizeof(definition->name), enumDef->name.c_str(), _TRUNCATE);
    definition->baseType = enumDef->baseType;
    definition->valueCount = static_cast<uint32_t>(enumDef->values.size());
    definition->flags = enumDef->flags;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumGetValues(
    uint32_t enumId,
    NexusEnumValue* values,
    size_t maxValues,
    size_t* valueCount)
{
    if (!valueCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *valueCount = enumDef->values.size();

    if (values && maxValues > 0) {
        size_t copyCount = (enumDef->values.size() < maxValues) ? enumDef->values.size() : maxValues;
        memcpy(values, enumDef->values.data(), copyCount * sizeof(NexusEnumValue));
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumValueToName(
    uint32_t enumId,
    int64_t value,
    char* name,
    size_t nameSize)
{
    if (!name || nameSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    for (const auto& v : enumDef->values) {
        if (v.numericValue == value) {
            strncpy_s(name, nameSize, v.name, _TRUNCATE);
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_EnumNameToValue(
    uint32_t enumId,
    const char* name,
    int64_t* value)
{
    if (!name || !value) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    for (const auto& v : enumDef->values) {
        if (_stricmp(v.name, name) == 0) {
            *value = v.numericValue;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_EnumGetAll(
    uint32_t* enumIds,
    size_t maxEnums,
    size_t* enumCount)
{
    if (!enumCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    *enumCount = g_enumRegistry.size();

    if (enumIds && maxEnums > 0) {
        size_t i = 0;
        for (const auto& pair : g_enumRegistry) {
            if (i >= maxEnums) break;
            enumIds[i++] = pair.first;
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnumFindByName(
    const char* name,
    uint32_t* enumId)
{
    if (!name || !enumId) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_enumMutex);

    for (const auto& pair : g_enumRegistry) {
        if (_stricmp(pair.second.name.c_str(), name) == 0) {
            *enumId = pair.first;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_EnumSetFlags(
    uint32_t enumId,
    uint32_t flags)
{
    std::lock_guard<std::mutex> lock(g_enumMutex);

    auto* enumDef = GetEnumById(enumId);
    if (!enumDef) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    enumDef->flags = flags;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StructureSetElementEnum(
    NexusStructureHandle structure,
    uint32_t elementId,
    uint32_t enumId)
{
    if (!structure) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_structMutex);

    auto* s = static_cast<DissectedStructure*>(structure);

    /* Find element by ID */
    for (auto& elem : s->elements) {
        if (elem.id == elementId) {
            elem.enumDefinitionId = enumId;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

} // extern "C"
