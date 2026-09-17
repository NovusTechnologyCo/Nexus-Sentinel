/**
 * @file project.cpp
 * @brief Project management API: create/destroy, address-list CRUD, info, and refresh.
 *
 * Implements the project (.nsp) lifecycle: creation, address entry
 * management (add/remove/update/get), metadata queries, and value
 * refresh against a live process via pointer resolution.
 *
 * JSON serialization/deserialization is in project_json.cpp.
 */

#include "project_internal.h"

/* ============================================================================
 * Project API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ProjectCreate(NexusProjectHandle* project) {
    if (!project) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = new NexusProjectData();
    *project = data;
    return NEXUS_OK;
}

NEXUS_API void Nexus_ProjectDestroy(NexusProjectHandle project) {
    if (project) {
        delete static_cast<NexusProjectData*>(project);
    }
}

NEXUS_API NexusResult Nexus_ProjectLoad(
    const wchar_t* path,
    NexusProjectHandle* project
) {
    if (!path || !project) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    std::string json = ss.str();
    file.close();

    auto* data = new NexusProjectData();
    if (!DeserializeProject(json, data)) {
        delete data;
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *project = data;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectSave(
    NexusProjectHandle project,
    const wchar_t* path
) {
    if (!project || !path) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    std::string json = SerializeProject(data);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    file.write(json.c_str(), json.length());

    if (file.fail()) {
        file.close();
        return NEXUS_ERROR_UNKNOWN;
    }

    file.close();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectGetInfo(
    NexusProjectHandle project,
    NexusProjectInfo* info
) {
    if (!project || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    wcsncpy_s(info->name, 256, data->name.c_str(), _TRUNCATE);
    wcsncpy_s(info->targetProcess, 260, data->targetProcess.c_str(), _TRUNCATE);
    info->targetPid = data->targetPid;
    info->schemaVersion = NEXUS_PROJECT_SCHEMA_VERSION;
    info->addressCount = data->addresses.size();
    info->createdTime = data->createdTime;
    info->modifiedTime = data->modifiedTime;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectSetName(
    NexusProjectHandle project,
    const wchar_t* name
) {
    if (!project || !name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);
    data->name = name;
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectSetTargetProcess(
    NexusProjectHandle project,
    const wchar_t* processName
) {
    if (!project || !processName) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);
    data->targetProcess = processName;
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectAddAddress(
    NexusProjectHandle project,
    const NexusAddressEntry* entry,
    uint64_t* id
) {
    if (!project || !entry) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    NexusAddressEntry newEntry = *entry;
    newEntry.id = data->nextId++;

    data->addresses[newEntry.id] = newEntry;
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    if (id) {
        *id = newEntry.id;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectRemoveAddress(
    NexusProjectHandle project,
    uint64_t id
) {
    if (!project) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    auto it = data->addresses.find(id);
    if (it == data->addresses.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    data->addresses.erase(it);
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectUpdateAddress(
    NexusProjectHandle project,
    const NexusAddressEntry* entry
) {
    if (!project || !entry) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    auto it = data->addresses.find(entry->id);
    if (it == data->addresses.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    it->second = *entry;
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectGetAddress(
    NexusProjectHandle project,
    uint64_t id,
    NexusAddressEntry* entry
) {
    if (!project || !entry) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    auto it = data->addresses.find(id);
    if (it == data->addresses.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *entry = it->second;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectGetAddressCount(
    NexusProjectHandle project,
    uint64_t* count
) {
    if (!project || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);
    *count = data->addresses.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectGetAddresses(
    NexusProjectHandle project,
    uint64_t startIndex,
    NexusAddressEntry* buffer,
    size_t bufferCount,
    size_t* entriesReturned
) {
    if (!project || !buffer || !entriesReturned || bufferCount == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    std::vector<const NexusAddressEntry*> entries;
    entries.reserve(data->addresses.size());
    for (const auto& pair : data->addresses) {
        entries.push_back(&pair.second);
    }

    if (startIndex >= entries.size()) {
        *entriesReturned = 0;
        return NEXUS_OK;
    }

    size_t available = entries.size() - static_cast<size_t>(startIndex);
    size_t toCopy = (available < bufferCount) ? available : bufferCount;

    for (size_t i = 0; i < toCopy; i++) {
        buffer[i] = *entries[static_cast<size_t>(startIndex) + i];
    }

    *entriesReturned = toCopy;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectRefreshValues(
    NexusProjectHandle project,
    NexusProcessHandle process
) {
    if (!project || !process) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);

    for (auto& pair : data->addresses) {
        NexusAddressEntry& entry = pair.second;

        uint64_t targetAddress = entry.address;

        if (entry.offsetCount > 0) {
            NexusResult res = Nexus_ResolvePointer(
                process,
                entry.address,
                entry.offsets,
                entry.offsetCount,
                &targetAddress
            );
            if (res != NEXUS_OK) {
                memset(&entry.currentValue, 0, sizeof(entry.currentValue));
                continue;
            }
        }

        size_t bytesRead = 0;
        size_t readSize = 0;

        switch (entry.valueType) {
            case NEXUS_ADDR_VALUE_INT8:    readSize = 1; break;
            case NEXUS_ADDR_VALUE_INT16:   readSize = 2; break;
            case NEXUS_ADDR_VALUE_INT32:   readSize = 4; break;
            case NEXUS_ADDR_VALUE_INT64:   readSize = 8; break;
            case NEXUS_ADDR_VALUE_FLOAT32: readSize = 4; break;
            case NEXUS_ADDR_VALUE_FLOAT64: readSize = 8; break;
            case NEXUS_ADDR_VALUE_POINTER: readSize = 8; break;
            default:                       readSize = 8; break;
        }

        NexusResult res = Nexus_ReadMemory(
            process,
            targetAddress,
            &entry.currentValue,
            readSize,
            &bytesRead
        );

        if (res != NEXUS_OK) {
            memset(&entry.currentValue, 0, sizeof(entry.currentValue));
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ProjectClearAddresses(NexusProjectHandle project) {
    if (!project) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* data = static_cast<NexusProjectData*>(project);
    data->addresses.clear();
    data->modifiedTime = static_cast<uint64_t>(std::time(nullptr));

    return NEXUS_OK;
}
