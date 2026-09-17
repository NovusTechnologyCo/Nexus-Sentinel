/**
 * @file symbol.cpp
 * @brief Symbol handler core: create/destroy, search path, load/unload, and resolution.
 *
 * Wraps the DbgHelp library (SymInitialize, SymLoadModuleEx,
 * SymFromAddr, SymFromName, SymEnumSymbols) behind a thread-safe
 * mutex to provide PDB symbol loading, address-to-name and
 * name-to-address resolution, and symbol enumeration with pattern
 * matching.
 *
 * Line info, module info, undecorate, refresh, and user-defined
 * symbols are in symbol_user.cpp.
 */

#include "symbol_internal.h"

/* Global mutex definition */
std::mutex g_dbgHelpMutex;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static DWORD TranslateOptions(uint32_t nexusOptions) {
    DWORD symOptions = SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;

    if (nexusOptions & NEXUS_SYM_DEFERRED_LOADS)
        symOptions |= SYMOPT_DEFERRED_LOADS;
    if (nexusOptions & NEXUS_SYM_LOAD_ANYTHING)
        symOptions |= SYMOPT_LOAD_ANYTHING;
    if (nexusOptions & NEXUS_SYM_PUBLICS_ONLY)
        symOptions |= SYMOPT_PUBLICS_ONLY;
    if (nexusOptions & NEXUS_SYM_NO_PUBLICS)
        symOptions |= SYMOPT_NO_PUBLICS;
    if (nexusOptions & NEXUS_SYM_AUTO_PUBLICS)
        symOptions |= SYMOPT_AUTO_PUBLICS;
    if (nexusOptions & NEXUS_SYM_INCLUDE_32BIT)
        symOptions |= SYMOPT_INCLUDE_32BIT_MODULES;

    return symOptions;
}

NexusDbgSymbolType TranslateSymType(SYM_TYPE symType) {
    switch (symType) {
        case SymNone: return NEXUS_DBGSYM_NONE;
        case SymExport: return NEXUS_DBGSYM_EXPORT;
        case SymPdb: return NEXUS_DBGSYM_PDB;
        case SymCoff: return NEXUS_DBGSYM_COFF;
        case SymCv: return NEXUS_DBGSYM_CV;
        case SymSym: return NEXUS_DBGSYM_SYM;
        case SymVirtual: return NEXUS_DBGSYM_VIRTUAL;
        case SymDia: return NEXUS_DBGSYM_DIA;
        default: return NEXUS_DBGSYM_NONE;
    }
}

void FillSymbolInfo(const SYMBOL_INFO* symInfo, NexusSymbolInfo* nexusInfo, uint64_t moduleBase) {
    memset(nexusInfo, 0, sizeof(*nexusInfo));

    nexusInfo->address = symInfo->Address;
    nexusInfo->size = symInfo->Size;
    nexusInfo->flags = symInfo->Flags;
    nexusInfo->tag = symInfo->Tag;
    nexusInfo->type = NEXUS_DBGSYM_PDB;
    nexusInfo->moduleBase = moduleBase;

    strncpy_s(nexusInfo->name, sizeof(nexusInfo->name), symInfo->Name, _TRUNCATE);

    if (symInfo->Name[0] == '?' || symInfo->Name[0] == '@') {
        UnDecorateSymbolName(symInfo->Name, nexusInfo->undecoratedName,
                             sizeof(nexusInfo->undecoratedName), UNDNAME_COMPLETE);
    } else {
        strncpy_s(nexusInfo->undecoratedName, sizeof(nexusInfo->undecoratedName),
                  symInfo->Name, _TRUNCATE);
    }
}

/* ============================================================================
 * Symbol Enumeration Callback Context
 * ============================================================================ */

struct EnumContext {
    NexusSymbolInfo* symbols;
    size_t maxSymbols;
    size_t count;
    uint64_t moduleBase;
};

static BOOL CALLBACK EnumSymbolsCallback(PSYMBOL_INFO symInfo, ULONG symbolSize, PVOID userContext) {
    (void)symbolSize;
    EnumContext* ctx = static_cast<EnumContext*>(userContext);

    if (ctx->count >= ctx->maxSymbols) {
        return FALSE;
    }

    FillSymbolInfo(symInfo, &ctx->symbols[ctx->count], ctx->moduleBase);
    ctx->count++;

    return TRUE;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_SymbolCreate(
    NexusProcessHandle process,
    uint32_t options,
    NexusSymbolHandle* handler
) {
    if (!process || !handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    NexusSymbolHandler* sym = new (std::nothrow) NexusSymbolHandler();
    if (!sym) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }

    sym->nexusProcess = process;
    sym->options = options;
    sym->initialized = false;

    sym->processHandle = static_cast<HANDLE>(process);

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    DWORD symOptions = TranslateOptions(options);
    SymSetOptions(symOptions);

    if (!SymInitialize(sym->processHandle, nullptr, FALSE)) {
        delete sym;
        return NEXUS_ERROR_UNKNOWN;
    }

    sym->initialized = true;

    char defaultPath[1024];
    if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", defaultPath, sizeof(defaultPath)) == 0) {
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        snprintf(defaultPath, sizeof(defaultPath),
                 "srv*%ssymbols*https://msdl.microsoft.com/download/symbols",
                 tempPath);
        SymSetSearchPath(sym->processHandle, defaultPath);
    }

    *handler = sym;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolDestroy(NexusSymbolHandle handler) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    if (handler->initialized) {
        SymCleanup(handler->processHandle);
    }

    delete handler;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolSetSearchPath(
    NexusSymbolHandle handler,
    const char* searchPath
) {
    if (!handler || !searchPath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    if (!SymSetSearchPath(handler->processHandle, searchPath)) {
        return NEXUS_ERROR_UNKNOWN;
    }

    handler->searchPath = searchPath;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolGetSearchPath(
    NexusSymbolHandle handler,
    char* buffer,
    size_t bufferSize,
    size_t* length
) {
    if (!handler || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    if (!SymGetSearchPath(handler->processHandle, buffer, static_cast<DWORD>(bufferSize))) {
        return NEXUS_ERROR_UNKNOWN;
    }

    if (length) {
        *length = strlen(buffer);
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolAddServer(
    NexusSymbolHandle handler,
    const char* serverUrl,
    const char* cacheDir
) {
    if (!handler || !serverUrl) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    char currentPath[4096] = {0};
    SymGetSearchPath(handler->processHandle, currentPath, sizeof(currentPath));

    std::string newPath = currentPath;
    if (!newPath.empty()) {
        newPath += ";";
    }

    newPath += "srv*";
    if (cacheDir && cacheDir[0]) {
        newPath += cacheDir;
        newPath += "*";
    }
    newPath += serverUrl;

    if (!SymSetSearchPath(handler->processHandle, newPath.c_str())) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolLoadModule(
    NexusSymbolHandle handler,
    uint64_t moduleBase,
    uint32_t moduleSize,
    const char* moduleName,
    const char* imagePath
) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    DWORD64 result = SymLoadModuleEx(
        handler->processHandle,
        nullptr,
        imagePath,
        moduleName,
        moduleBase,
        moduleSize,
        nullptr,
        0
    );

    if (result == 0 && GetLastError() != ERROR_SUCCESS) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolUnloadModule(
    NexusSymbolHandle handler,
    uint64_t moduleBase
) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    if (!SymUnloadModule64(handler->processHandle, moduleBase)) {
        return NEXUS_ERROR_UNKNOWN;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolLoadAll(NexusSymbolHandle handler) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t modCount = 0;
    NexusResult result = Nexus_EnumerateModules(handler->nexusProcess, nullptr, 0, &modCount);
    if (result != NEXUS_OK || modCount == 0) {
        return NEXUS_ERROR_UNKNOWN;
    }

    std::vector<NexusModuleInfo> modules(modCount);
    result = Nexus_EnumerateModules(handler->nexusProcess, modules.data(), modCount, &modCount);
    if (result != NEXUS_OK) {
        return result;
    }

    for (size_t i = 0; i < modCount; i++) {
        char narrowName[260];
        WideCharToMultiByte(CP_UTF8, 0, modules[i].name, -1, narrowName, sizeof(narrowName), nullptr, nullptr);

        char narrowPath[260];
        WideCharToMultiByte(CP_UTF8, 0, modules[i].path, -1, narrowPath, sizeof(narrowPath), nullptr, nullptr);

        Nexus_SymbolLoadModule(handler, modules[i].baseAddress,
                               static_cast<uint32_t>(modules[i].size),
                               narrowName, narrowPath);
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolFromAddress(
    NexusSymbolHandle handler,
    uint64_t address,
    NexusSymbolInfo* symbol,
    uint64_t* displacement
) {
    if (!handler || !symbol) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Check user-defined symbols first (they take precedence) */
    {
        std::lock_guard<std::mutex> lock(handler->mutex);

        auto exactIt = handler->userSymbolsByAddress.find(address);
        if (exactIt != handler->userSymbolsByAddress.end()) {
            auto symIt = handler->userSymbolsByName.find(exactIt->second);
            if (symIt != handler->userSymbolsByName.end()) {
                const UserSymbol& userSym = symIt->second;
                memset(symbol, 0, sizeof(*symbol));
                symbol->address = userSym.address;
                symbol->size = userSym.size;
                symbol->type = NEXUS_DBGSYM_VIRTUAL;
                strncpy_s(symbol->name, sizeof(symbol->name), userSym.name.c_str(), _TRUNCATE);
                strncpy_s(symbol->undecoratedName, sizeof(symbol->undecoratedName),
                          userSym.name.c_str(), _TRUNCATE);
                if (displacement) *displacement = 0;
                return NEXUS_OK;
            }
        }

        if (!handler->userSymbolsByAddress.empty()) {
            auto it = handler->userSymbolsByAddress.upper_bound(address);
            if (it != handler->userSymbolsByAddress.begin()) {
                --it;
                auto symIt = handler->userSymbolsByName.find(it->second);
                if (symIt != handler->userSymbolsByName.end()) {
                    const UserSymbol& userSym = symIt->second;
                    uint64_t disp = address - userSym.address;
                    if (userSym.size == 0 || disp < userSym.size) {
                        memset(symbol, 0, sizeof(*symbol));
                        symbol->address = userSym.address;
                        symbol->size = userSym.size;
                        symbol->type = NEXUS_DBGSYM_VIRTUAL;
                        strncpy_s(symbol->name, sizeof(symbol->name),
                                  userSym.name.c_str(), _TRUNCATE);
                        strncpy_s(symbol->undecoratedName, sizeof(symbol->undecoratedName),
                                  userSym.name.c_str(), _TRUNCATE);
                        if (displacement) *displacement = disp;
                        return NEXUS_OK;
                    }
                }
            }
        }
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    SYMBOL_INFO* symInfo = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfo->MaxNameLen = MAX_SYM_NAME;

    DWORD64 disp64 = 0;
    if (!SymFromAddr(handler->processHandle, address, &disp64, symInfo)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    IMAGEHLP_MODULE64 modInfo;
    modInfo.SizeOfStruct = sizeof(modInfo);
    uint64_t moduleBase = 0;
    if (SymGetModuleInfo64(handler->processHandle, address, &modInfo)) {
        moduleBase = modInfo.BaseOfImage;
        strncpy_s(symbol->moduleName, sizeof(symbol->moduleName), modInfo.ModuleName, _TRUNCATE);
    }

    FillSymbolInfo(symInfo, symbol, moduleBase);

    if (displacement) {
        *displacement = disp64;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolFromName(
    NexusSymbolHandle handler,
    const char* name,
    NexusSymbolInfo* symbol
) {
    if (!handler || !name || !symbol) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    {
        std::lock_guard<std::mutex> lock(handler->mutex);

        auto it = handler->userSymbolsByName.find(name);
        if (it != handler->userSymbolsByName.end()) {
            const UserSymbol& userSym = it->second;
            memset(symbol, 0, sizeof(*symbol));
            symbol->address = userSym.address;
            symbol->size = userSym.size;
            symbol->type = NEXUS_DBGSYM_VIRTUAL;
            strncpy_s(symbol->name, sizeof(symbol->name), userSym.name.c_str(), _TRUNCATE);
            strncpy_s(symbol->undecoratedName, sizeof(symbol->undecoratedName),
                      userSym.name.c_str(), _TRUNCATE);
            return NEXUS_OK;
        }
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    SYMBOL_INFO* symInfo = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symInfo->MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(handler->processHandle, name, symInfo)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    IMAGEHLP_MODULE64 modInfo;
    modInfo.SizeOfStruct = sizeof(modInfo);
    uint64_t moduleBase = 0;
    if (SymGetModuleInfo64(handler->processHandle, symInfo->Address, &modInfo)) {
        moduleBase = modInfo.BaseOfImage;
        strncpy_s(symbol->moduleName, sizeof(symbol->moduleName), modInfo.ModuleName, _TRUNCATE);
    }

    FillSymbolInfo(symInfo, symbol, moduleBase);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolEnumerate(
    NexusSymbolHandle handler,
    const char* mask,
    NexusSymbolInfo* symbols,
    size_t maxSymbols,
    size_t* symbolCount
) {
    if (!handler || !mask || !symbols || !symbolCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    EnumContext ctx = {0};
    ctx.symbols = symbols;
    ctx.maxSymbols = maxSymbols;
    ctx.count = 0;
    ctx.moduleBase = 0;

    std::string maskStr = mask;
    size_t bangPos = maskStr.find('!');

    if (bangPos != std::string::npos) {
        std::string moduleName = maskStr.substr(0, bangPos);
        std::string pattern = maskStr.substr(bangPos + 1);

        IMAGEHLP_MODULE64 modInfo;
        modInfo.SizeOfStruct = sizeof(modInfo);

        size_t modCount = 0;
        Nexus_EnumerateModules(handler->nexusProcess, nullptr, 0, &modCount);
        std::vector<NexusModuleInfo> modules(modCount);
        Nexus_EnumerateModules(handler->nexusProcess, modules.data(), modCount, &modCount);

        for (size_t i = 0; i < modCount; i++) {
            char narrowName[260];
            WideCharToMultiByte(CP_UTF8, 0, modules[i].name, -1, narrowName, sizeof(narrowName), nullptr, nullptr);

            if (_stricmp(narrowName, moduleName.c_str()) == 0 ||
                (moduleName == "*")) {
                ctx.moduleBase = modules[i].baseAddress;
                SymEnumSymbols(handler->processHandle, modules[i].baseAddress,
                               pattern.c_str(), EnumSymbolsCallback, &ctx);

                if (moduleName != "*") {
                    break;
                }
            }
        }
    } else {
        SymEnumSymbols(handler->processHandle, 0, mask, EnumSymbolsCallback, &ctx);
    }

    *symbolCount = ctx.count;
    return NEXUS_OK;
}
