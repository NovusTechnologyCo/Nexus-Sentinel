/**
 * @file symbol_user.cpp
 * @brief Symbol line info, module info, name undecorating, refresh, and user-defined symbols.
 *
 * Extends the core symbol handler with source-line resolution
 * (SymGetLineFromAddr64), per-module symbol status, C++ name
 * undecorating (UnDecorateSymbolName), forced symbol reload, and a
 * user-defined symbol overlay that takes precedence over PDB symbols.
 */

#include "symbol_internal.h"

/* ============================================================================
 * Line and Module Info
 * ============================================================================ */

NEXUS_API NexusResult Nexus_SymbolGetLineFromAddress(
    NexusSymbolHandle handler,
    uint64_t address,
    NexusLineInfo* line,
    uint32_t* displacement
) {
    if (!handler || !line) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    IMAGEHLP_LINE64 lineInfo;
    lineInfo.SizeOfStruct = sizeof(lineInfo);
    DWORD disp = 0;

    if (!SymGetLineFromAddr64(handler->processHandle, address, &disp, &lineInfo)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    memset(line, 0, sizeof(*line));
    line->address = lineInfo.Address;
    line->lineNumber = lineInfo.LineNumber;
    if (lineInfo.FileName) {
        strncpy_s(line->fileName, sizeof(line->fileName), lineInfo.FileName, _TRUNCATE);
    }

    if (displacement) {
        *displacement = disp;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolGetAddressFromLine(
    NexusSymbolHandle handler,
    const char* fileName,
    uint32_t lineNumber,
    uint64_t* address
) {
    if (!handler || !fileName || !address) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    LONG displacement = 0;
    IMAGEHLP_LINE64 lineInfo;
    lineInfo.SizeOfStruct = sizeof(lineInfo);

    if (!SymGetLineFromName64(handler->processHandle, nullptr, fileName, lineNumber,
                               &displacement, &lineInfo)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *address = lineInfo.Address;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolGetModuleInfo(
    NexusSymbolHandle handler,
    uint64_t moduleBase,
    NexusModuleSymbolInfo* info
) {
    if (!handler || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    IMAGEHLP_MODULE64 modInfo;
    modInfo.SizeOfStruct = sizeof(modInfo);

    if (!SymGetModuleInfo64(handler->processHandle, moduleBase, &modInfo)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    memset(info, 0, sizeof(*info));
    info->baseAddress = modInfo.BaseOfImage;
    info->imageSize = modInfo.ImageSize;
    info->timeDateStamp = modInfo.TimeDateStamp;
    info->checkSum = modInfo.CheckSum;
    info->numSymbols = modInfo.NumSyms;
    info->symType = TranslateSymType(modInfo.SymType);

    strncpy_s(info->moduleName, sizeof(info->moduleName), modInfo.ModuleName, _TRUNCATE);
    strncpy_s(info->imageName, sizeof(info->imageName), modInfo.ImageName, _TRUNCATE);
    strncpy_s(info->loadedImageName, sizeof(info->loadedImageName), modInfo.LoadedImageName, _TRUNCATE);
    strncpy_s(info->loadedPdbName, sizeof(info->loadedPdbName), modInfo.LoadedPdbName, _TRUNCATE);

    info->pdbAge = modInfo.PdbAge;
    memcpy(info->pdbGuid, &modInfo.PdbSig70, sizeof(info->pdbGuid));
    info->symbolsLoaded = (modInfo.SymType != SymNone) ? 1 : 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolUndecorate(
    const char* decoratedName,
    char* buffer,
    size_t bufferSize,
    uint32_t flags
) {
    if (!decoratedName || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    DWORD undecoratFlags = flags ? flags : UNDNAME_COMPLETE;

    DWORD result = UnDecorateSymbolName(decoratedName, buffer,
                                        static_cast<DWORD>(bufferSize), undecoratFlags);

    if (result == 0) {
        strncpy_s(buffer, bufferSize, decoratedName, _TRUNCATE);
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolRefresh(
    NexusSymbolHandle handler,
    uint64_t moduleBase
) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_dbgHelpMutex);

    if (moduleBase != 0) {
        IMAGEHLP_MODULE64 modInfo;
        modInfo.SizeOfStruct = sizeof(modInfo);

        if (SymGetModuleInfo64(handler->processHandle, moduleBase, &modInfo)) {
            SymUnloadModule64(handler->processHandle, moduleBase);
            SymLoadModuleEx(handler->processHandle, nullptr, modInfo.ImageName, modInfo.ModuleName,
                           moduleBase, modInfo.ImageSize, nullptr, 0);
        }
    } else {
        SymRefreshModuleList(handler->processHandle);
    }

    return NEXUS_OK;
}

/* ============================================================================
 * User-Defined Symbols
 * ============================================================================ */

NEXUS_API NexusResult Nexus_SymbolAddUserDefined(
    NexusSymbolHandle handler,
    const char* name,
    uint64_t address,
    uint64_t size
) {
    if (!handler || !name || !name[0]) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(handler->mutex);

    auto existingIt = handler->userSymbolsByName.find(name);
    if (existingIt != handler->userSymbolsByName.end()) {
        handler->userSymbolsByAddress.erase(existingIt->second.address);
    }

    auto addrIt = handler->userSymbolsByAddress.find(address);
    if (addrIt != handler->userSymbolsByAddress.end()) {
        handler->userSymbolsByName.erase(addrIt->second);
    }

    UserSymbol sym;
    sym.name = name;
    sym.address = address;
    sym.size = size;

    handler->userSymbolsByName[name] = sym;
    handler->userSymbolsByAddress[address] = name;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolRemoveUserDefined(
    NexusSymbolHandle handler,
    const char* name
) {
    if (!handler || !name) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(handler->mutex);

    auto it = handler->userSymbolsByName.find(name);
    if (it == handler->userSymbolsByName.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    handler->userSymbolsByAddress.erase(it->second.address);
    handler->userSymbolsByName.erase(it);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolRemoveUserDefinedByAddress(
    NexusSymbolHandle handler,
    uint64_t address
) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(handler->mutex);

    auto it = handler->userSymbolsByAddress.find(address);
    if (it == handler->userSymbolsByAddress.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    handler->userSymbolsByName.erase(it->second);
    handler->userSymbolsByAddress.erase(it);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolClearUserDefined(NexusSymbolHandle handler) {
    if (!handler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(handler->mutex);

    handler->userSymbolsByName.clear();
    handler->userSymbolsByAddress.clear();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SymbolGetUserDefined(
    NexusSymbolHandle handler,
    NexusSymbolInfo* symbols,
    size_t maxSymbols,
    size_t* symbolCount
) {
    if (!handler || !symbols || !symbolCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(handler->mutex);

    size_t count = 0;
    for (const auto& pair : handler->userSymbolsByName) {
        if (count >= maxSymbols) break;

        const UserSymbol& sym = pair.second;
        NexusSymbolInfo* info = &symbols[count];

        memset(info, 0, sizeof(*info));
        info->address = sym.address;
        info->size = sym.size;
        info->type = NEXUS_DBGSYM_VIRTUAL;
        strncpy_s(info->name, sizeof(info->name), sym.name.c_str(), _TRUNCATE);
        strncpy_s(info->undecoratedName, sizeof(info->undecoratedName), sym.name.c_str(), _TRUNCATE);

        count++;
    }

    *symbolCount = count;
    return NEXUS_OK;
}
