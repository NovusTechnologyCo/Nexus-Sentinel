/**
 * @file symbol_internal.h
 * @brief Internal header shared by symbol.cpp and symbol_user.cpp.
 */

#pragma once

#include "nexus_api.h"
#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/* User-defined symbol entry */
struct UserSymbol {
    std::string name;
    uint64_t address;
    uint64_t size;
};

struct NexusSymbolHandler {
    HANDLE processHandle;
    NexusProcessHandle nexusProcess;
    uint32_t options;
    bool initialized;
    std::string searchPath;
    std::mutex mutex;

    /* User-defined symbols - map by name and by address for fast lookup */
    std::map<std::string, UserSymbol> userSymbolsByName;
    std::map<uint64_t, std::string> userSymbolsByAddress;  /* Address -> name */
};

/* Global mutex for DbgHelp (it's not thread-safe for same process handle) */
extern std::mutex g_dbgHelpMutex;

/* ============================================================================
 * Cross-File Helper Prototypes (defined in symbol.cpp)
 * ============================================================================ */

NexusDbgSymbolType TranslateSymType(SYM_TYPE symType);
void FillSymbolInfo(const SYMBOL_INFO* symInfo, NexusSymbolInfo* nexusInfo, uint64_t moduleBase);
