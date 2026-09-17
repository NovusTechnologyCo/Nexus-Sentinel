/**
 * @file trainer_internal.h
 * @brief Internal header shared by trainer.cpp, trainer_persist.cpp, and trainer_codegen.cpp.
 *
 * Defines the TrainerContext structure (config, cheat list, modules,
 * scripts) and declares cross-file helper prototypes.
 */

#pragma once

#include "nexus_api.h"
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct TrainerScript {
    std::string name;
    std::string enableScript;
    std::string disableScript;
};

struct TrainerContext {
    NexusTrainerConfig config;
    std::vector<std::string> modules;
    std::vector<NexusTrainerCheat> cheats;
    std::vector<TrainerScript> scripts;
    uint32_t nextCheatId;
};

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- trainer.cpp --- */
std::string EscapeJsonString(const std::string& str);
std::string GetHotkeyString(uint32_t vk, uint32_t modifiers);
