/**
 * @file trainer.cpp
 * @brief Trainer core: creation/destruction, cheat CRUD, module/script management, and JSON save.
 *
 * Manages trainer projects that define a set of cheats (address-based
 * toggles, value sets, freezes, and AA scripts) with hotkey bindings.
 * Serializes to a JSON file format.
 *
 * JSON deserialization and table import are in trainer_persist.cpp;
 * standalone C code generation is in trainer_codegen.cpp.
 */

#include "trainer_internal.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

// Shared helpers (non-static, declared in trainer_internal.h)

std::string EscapeJsonString(const std::string& str) {
    std::string result;
    result.reserve(str.size() + 10);
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

std::string GetHotkeyString(uint32_t vk, uint32_t modifiers) {
    std::string result;

    if (modifiers & NEXUS_HOTKEY_CTRL) result += "Ctrl+";
    if (modifiers & NEXUS_HOTKEY_ALT) result += "Alt+";
    if (modifiers & NEXUS_HOTKEY_SHIFT) result += "Shift+";

    // Common VK codes
    if (vk >= 0x30 && vk <= 0x39) {
        result += static_cast<char>(vk); // 0-9
    } else if (vk >= 0x41 && vk <= 0x5A) {
        result += static_cast<char>(vk); // A-Z
    } else if (vk >= 0x70 && vk <= 0x7B) {
        result += "F" + std::to_string(vk - 0x6F); // F1-F12
    } else if (vk >= 0x60 && vk <= 0x69) {
        result += "Numpad" + std::to_string(vk - 0x60); // Numpad 0-9
    } else {
        switch (vk) {
            case 0x20: result += "Space"; break;
            case 0x2E: result += "Delete"; break;
            case 0x24: result += "Home"; break;
            case 0x23: result += "End"; break;
            case 0x21: result += "PageUp"; break;
            case 0x22: result += "PageDown"; break;
            case 0x6A: result += "Numpad*"; break;
            case 0x6B: result += "Numpad+"; break;
            case 0x6D: result += "Numpad-"; break;
            default: result += "VK_" + std::to_string(vk); break;
        }
    }

    return result;
}

// Static helpers (only used in this file)

static const char* GetActionName(NexusTrainerAction action) {
    switch (action) {
        case NEXUS_TRAINER_TOGGLE: return "toggle";
        case NEXUS_TRAINER_SET_VALUE: return "set";
        case NEXUS_TRAINER_FREEZE: return "freeze";
        case NEXUS_TRAINER_INCREMENT: return "increment";
        case NEXUS_TRAINER_DECREMENT: return "decrement";
        case NEXUS_TRAINER_EXECUTE_SCRIPT: return "script";
        default: return "unknown";
    }
}

static const char* GetValueTypeName(int32_t valueType) {
    switch (valueType) {
        case 0: return "byte";
        case 1: return "int16";
        case 2: return "int32";
        case 3: return "int64";
        case 4: return "float";
        case 5: return "double";
        default: return "int32";
    }
}

/* ============================================================================
 * Core Trainer API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_TrainerCreate(NexusTrainerHandle* trainer) {
    if (!trainer) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = new (std::nothrow) TrainerContext();
    if (!ctx) return NEXUS_ERROR_OUT_OF_MEMORY;

    memset(&ctx->config, 0, sizeof(ctx->config));
    strcpy_s(ctx->config.author, "Spontaneous");
    strcpy_s(ctx->config.version, "1.0");
    ctx->config.autoAttach = 1;
    ctx->config.closeWithGame = 1;
    ctx->nextCheatId = 1;

    *trainer = ctx;
    return NEXUS_OK;
}

NEXUS_API void Nexus_TrainerDestroy(NexusTrainerHandle trainer) {
    if (trainer) {
        delete static_cast<TrainerContext*>(trainer);
    }
}

NEXUS_API NexusResult Nexus_TrainerSetConfig(
    NexusTrainerHandle trainer,
    const NexusTrainerConfig* config
) {
    if (!trainer || !config) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);
    ctx->config = *config;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerGetConfig(
    NexusTrainerHandle trainer,
    NexusTrainerConfig* config
) {
    if (!trainer || !config) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);
    *config = ctx->config;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerAddCheat(
    NexusTrainerHandle trainer,
    const NexusTrainerCheat* cheat,
    uint32_t* id
) {
    if (!trainer || !cheat) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    NexusTrainerCheat newCheat = *cheat;
    newCheat.id = ctx->nextCheatId++;

    ctx->cheats.push_back(newCheat);

    if (id) *id = newCheat.id;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerRemoveCheat(
    NexusTrainerHandle trainer,
    uint32_t id
) {
    if (!trainer) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    auto it = std::find_if(ctx->cheats.begin(), ctx->cheats.end(),
        [id](const NexusTrainerCheat& c) { return c.id == id; });

    if (it == ctx->cheats.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    ctx->cheats.erase(it);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerGetCheatCount(
    NexusTrainerHandle trainer,
    size_t* count
) {
    if (!trainer || !count) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);
    *count = ctx->cheats.size();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerGetCheat(
    NexusTrainerHandle trainer,
    size_t index,
    NexusTrainerCheat* cheat
) {
    if (!trainer || !cheat) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    if (index >= ctx->cheats.size()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *cheat = ctx->cheats[index];
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerAddModule(
    NexusTrainerHandle trainer,
    const char* moduleName,
    int32_t* moduleIndex
) {
    if (!trainer || !moduleName) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    // Check if module already exists
    for (size_t i = 0; i < ctx->modules.size(); i++) {
        if (_stricmp(ctx->modules[i].c_str(), moduleName) == 0) {
            if (moduleIndex) *moduleIndex = static_cast<int32_t>(i);
            return NEXUS_OK;
        }
    }

    int32_t idx = static_cast<int32_t>(ctx->modules.size());
    ctx->modules.push_back(moduleName);

    if (moduleIndex) *moduleIndex = idx;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TrainerAddScript(
    NexusTrainerHandle trainer,
    const char* name,
    const char* enableScript,
    const char* disableScript
) {
    if (!trainer || !name) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    TrainerScript script;
    script.name = name;
    script.enableScript = enableScript ? enableScript : "";
    script.disableScript = disableScript ? disableScript : "";

    ctx->scripts.push_back(script);
    return NEXUS_OK;
}

/* ============================================================================
 * JSON Serialization (Save)
 * ============================================================================ */

NEXUS_API NexusResult Nexus_TrainerSave(
    NexusTrainerHandle trainer,
    const char* path
) {
    if (!trainer || !path) return NEXUS_ERROR_INVALID_PARAMETER;

    TrainerContext* ctx = static_cast<TrainerContext*>(trainer);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return NEXUS_ERROR_ACCESS_DENIED;

    // Write JSON format
    ofs << "{\n";
    ofs << "  \"version\": 1,\n";
    ofs << "  \"format\": \"NexusTrainer\",\n";

    // Config
    ofs << "  \"config\": {\n";
    ofs << "    \"name\": \"" << EscapeJsonString(ctx->config.name) << "\",\n";
    ofs << "    \"author\": \"" << EscapeJsonString(ctx->config.author) << "\",\n";
    ofs << "    \"version\": \"" << EscapeJsonString(ctx->config.version) << "\",\n";
    ofs << "    \"targetProcess\": \"" << EscapeJsonString(ctx->config.targetProcess) << "\",\n";
    ofs << "    \"aboutText\": \"" << EscapeJsonString(ctx->config.aboutText) << "\",\n";
    ofs << "    \"autoAttach\": " << (ctx->config.autoAttach ? "true" : "false") << ",\n";
    ofs << "    \"closeWithGame\": " << (ctx->config.closeWithGame ? "true" : "false") << ",\n";
    ofs << "    \"minimizeToTray\": " << (ctx->config.minimizeToTray ? "true" : "false") << ",\n";
    ofs << "    \"playSounds\": " << (ctx->config.playSounds ? "true" : "false") << "\n";
    ofs << "  },\n";

    // Modules
    ofs << "  \"modules\": [";
    for (size_t i = 0; i < ctx->modules.size(); i++) {
        if (i > 0) ofs << ", ";
        ofs << "\"" << EscapeJsonString(ctx->modules[i]) << "\"";
    }
    ofs << "],\n";

    // Cheats
    ofs << "  \"cheats\": [\n";
    for (size_t i = 0; i < ctx->cheats.size(); i++) {
        const auto& c = ctx->cheats[i];
        ofs << "    {\n";
        ofs << "      \"id\": " << c.id << ",\n";
        ofs << "      \"name\": \"" << EscapeJsonString(c.name) << "\",\n";
        ofs << "      \"action\": \"" << GetActionName(c.action) << "\",\n";
        ofs << "      \"hotkey\": " << c.hotkey << ",\n";
        ofs << "      \"modifiers\": " << c.modifiers << ",\n";
        ofs << "      \"hotkeyString\": \"" << GetHotkeyString(c.hotkey, c.modifiers) << "\",\n";
        ofs << "      \"moduleIndex\": " << c.moduleIndex << ",\n";

        char hexBuf[32];
        snprintf(hexBuf, sizeof(hexBuf), "0x%llX", c.offset);
        ofs << "      \"offset\": \"" << hexBuf << "\",\n";

        ofs << "      \"pointerOffsets\": [";
        for (uint32_t j = 0; j < c.pointerCount; j++) {
            if (j > 0) ofs << ", ";
            snprintf(hexBuf, sizeof(hexBuf), "0x%llX", c.pointerOffsets[j]);
            ofs << "\"" << hexBuf << "\"";
        }
        ofs << "],\n";

        ofs << "      \"valueType\": \"" << GetValueTypeName(c.valueType) << "\",\n";
        ofs << "      \"setValue\": " << c.setValue << ",\n";
        ofs << "      \"scriptName\": \"" << EscapeJsonString(c.scriptName) << "\"\n";
        ofs << "    }";
        if (i + 1 < ctx->cheats.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ],\n";

    // Scripts
    ofs << "  \"scripts\": [\n";
    for (size_t i = 0; i < ctx->scripts.size(); i++) {
        const auto& s = ctx->scripts[i];
        ofs << "    {\n";
        ofs << "      \"name\": \"" << EscapeJsonString(s.name) << "\",\n";
        ofs << "      \"enable\": \"" << EscapeJsonString(s.enableScript) << "\",\n";
        ofs << "      \"disable\": \"" << EscapeJsonString(s.disableScript) << "\"\n";
        ofs << "    }";
        if (i + 1 < ctx->scripts.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ]\n";

    ofs << "}\n";
    ofs.close();

    return NEXUS_OK;
}

} // extern "C"
