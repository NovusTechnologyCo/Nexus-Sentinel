/**
 * @file project_internal.h
 * @brief Internal header shared by project.cpp and project_json.cpp.
 */

#pragma once

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

/* Project schema version */
#define NEXUS_PROJECT_SCHEMA_VERSION 1

/* Internal project data structure */
struct NexusProjectData {
    std::wstring name;
    std::wstring targetProcess;
    uint32_t targetPid;
    uint64_t createdTime;
    uint64_t modifiedTime;

    /* Address entries indexed by ID */
    std::map<uint64_t, NexusAddressEntry> addresses;
    uint64_t nextId;

    NexusProjectData() :
        targetPid(0),
        createdTime(0),
        modifiedTime(0),
        nextId(1)
    {
        createdTime = static_cast<uint64_t>(std::time(nullptr));
        modifiedTime = createdTime;
    }
};

/* ============================================================================
 * Cross-File Function Prototypes (defined in project_json.cpp)
 * ============================================================================ */

std::string SerializeProject(NexusProjectData* project);
bool DeserializeProject(const std::string& json, NexusProjectData* project);
