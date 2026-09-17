/**
 * @file hookdetect_scan.cpp
 * @brief Bulk hook scanning, disk-image comparison, restoration, and kernel hook stubs.
 *
 * Scans all exports in all modules for hooks, compares in-memory code
 * against the on-disk PE image to identify patches, and provides
 * byte-level restoration of detected hooks.  Kernel-mode hook
 * detection is stubbed for future implementation.
 */

#include "hookdetect_internal.h"

/* ============================================================================
 * General Hook Scanning
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_HookScan(
    NexusProcessHandle process,
    uint32_t flags,
    NexusHookScanResult* result)
{
    if (!process || !result) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    memset(result, 0, sizeof(*result));
    DWORD startTime = GetTickCount();

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;

    // Clear previous scan
    {
        std::lock_guard<std::mutex> lock(g_contextMutex);
        g_scanContext.hooks.clear();
        g_scanContext.inlineHooks.clear();
        g_scanContext.iatHooks.clear();
    }

    // Enumerate modules
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD numMods = cbNeeded / sizeof(HMODULE);
    result->modulesScanned = numMods;

    for (DWORD i = 0; i < numMods; i++) {
        uint64_t moduleBase = (uint64_t)hMods[i];

        // Skip system modules unless requested
        if (!(flags & NEXUS_HOOK_FLAG_SCAN_SYSTEM)) {
            wchar_t modPath[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH)) {
                if (wcsstr(modPath, L"\\Windows\\System32\\") ||
                    wcsstr(modPath, L"\\Windows\\SysWOW64\\")) {
                    // Still scan ntdll and kernel32 for inline hooks
                    wchar_t modName[64];
                    GetModuleBaseNameW(hProcess, hMods[i], modName, 64);
                    if (_wcsicmp(modName, L"ntdll.dll") != 0 &&
                        _wcsicmp(modName, L"kernel32.dll") != 0 &&
                        _wcsicmp(modName, L"kernelbase.dll") != 0) {
                        continue;
                    }
                }
            }
        }

        // Scan for inline hooks
        size_t inlineCount;
        Nexus_HookScanInline(process, moduleBase, nullptr, 0, &inlineCount);
        if (inlineCount > 0) {
            std::vector<NexusInlineHookInfo> inlineHooks(inlineCount);
            Nexus_HookScanInline(process, moduleBase, inlineHooks.data(), inlineCount, &inlineCount);

            std::lock_guard<std::mutex> lock(g_contextMutex);
            for (const auto& hook : inlineHooks) {
                g_scanContext.inlineHooks.push_back(hook);

                // Convert to general hook info
                NexusHookInfo info;
                memset(&info, 0, sizeof(info));
                info.hookAddress = hook.functionAddress;
                info.targetAddress = hook.jumpTarget;
                info.hookType = hook.isHotpatch ? NEXUS_HOOK_HOTPATCH : NEXUS_HOOK_INLINE;
                info.hookSize = hook.hookSize;
                wcscpy_s(info.moduleName, hook.moduleName);
                wcscpy_s(info.targetModule, hook.targetModule);
                strncpy_s(info.functionName, hook.functionName, sizeof(info.functionName) - 1);
                memcpy(info.hookBytes, hook.prologueBytes, 16);
                info.confidence = 85;
                info.isSuspicious = 1;
                g_scanContext.hooks.push_back(info);
            }
            result->inlineHooks += (uint32_t)inlineCount;
        }

        // Scan IAT
        size_t iatCount;
        Nexus_HookScanIat(process, moduleBase, nullptr, 0, &iatCount);
        if (iatCount > 0) {
            std::vector<NexusIatHookInfo> iatHooks(iatCount);
            Nexus_HookScanIat(process, moduleBase, iatHooks.data(), iatCount, &iatCount);

            std::lock_guard<std::mutex> lock(g_contextMutex);
            for (const auto& hook : iatHooks) {
                g_scanContext.iatHooks.push_back(hook);

                NexusHookInfo info;
                memset(&info, 0, sizeof(info));
                info.hookAddress = moduleBase + hook.thunkRva;
                info.targetAddress = hook.actualAddress;
                info.originalAddress = hook.expectedAddress;
                info.hookType = NEXUS_HOOK_IAT;
                info.hookSize = ctx->is32Bit ? 4 : 8;
                wcscpy_s(info.moduleName, hook.importModule);
                wcscpy_s(info.targetModule, hook.targetModule);
                strncpy_s(info.functionName, hook.functionName, sizeof(info.functionName) - 1);
                info.confidence = 95;
                info.isSuspicious = 1;
                g_scanContext.hooks.push_back(info);
            }
            result->iatHooks += (uint32_t)iatCount;
        }

        // Scan EAT
        size_t eatCount;
        Nexus_HookScanEat(process, moduleBase, nullptr, 0, &eatCount);
        if (eatCount > 0) {
            std::vector<NexusHookInfo> eatHooks(eatCount);
            Nexus_HookScanEat(process, moduleBase, eatHooks.data(), eatCount, &eatCount);

            std::lock_guard<std::mutex> lock(g_contextMutex);
            for (const auto& hook : eatHooks) {
                g_scanContext.hooks.push_back(hook);
            }
            result->eatHooks += (uint32_t)eatCount;
        }
    }

    result->totalHooks = result->inlineHooks + result->iatHooks + result->eatHooks;
    result->suspiciousCount = result->totalHooks; // All detected hooks are suspicious
    result->scanTime = GetTickCount() - startTime;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_HookGetAll(
    NexusProcessHandle process,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count)
{
    if (!process || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_contextMutex);

    *count = g_scanContext.hooks.size();

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    size_t toCopy = std::min(bufferCount, g_scanContext.hooks.size());
    for (size_t i = 0; i < toCopy; i++) {
        buffer[i] = g_scanContext.hooks[i];
    }

    return (bufferCount < g_scanContext.hooks.size()) ?
           NEXUS_ERROR_INSUFFICIENT_BUFFER : NEXUS_OK;
}

NEXUS_API NexusResult Nexus_HookGetInModule(
    NexusProcessHandle process,
    const wchar_t* moduleName,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count)
{
    if (!process || !moduleName || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(g_contextMutex);

    std::vector<NexusHookInfo> matches;
    for (const auto& hook : g_scanContext.hooks) {
        if (_wcsicmp(hook.moduleName, moduleName) == 0) {
            matches.push_back(hook);
        }
    }

    *count = matches.size();

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    size_t toCopy = std::min(bufferCount, matches.size());
    for (size_t i = 0; i < toCopy; i++) {
        buffer[i] = matches[i];
    }

    return (bufferCount < matches.size()) ? NEXUS_ERROR_INSUFFICIENT_BUFFER : NEXUS_OK;
}

NEXUS_API NexusResult Nexus_HookCheck(
    NexusProcessHandle process,
    uint64_t address,
    NexusHookInfo* info)
{
    if (!process || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // First try inline hook check
    NexusInlineHookInfo inlineInfo;
    if (Nexus_HookCheckInline(process, address, &inlineInfo) == NEXUS_OK) {
        memset(info, 0, sizeof(*info));
        info->hookAddress = inlineInfo.functionAddress;
        info->targetAddress = inlineInfo.jumpTarget;
        info->hookType = inlineInfo.isHotpatch ? NEXUS_HOOK_HOTPATCH : NEXUS_HOOK_INLINE;
        info->hookSize = inlineInfo.hookSize;
        wcscpy_s(info->moduleName, inlineInfo.moduleName);
        wcscpy_s(info->targetModule, inlineInfo.targetModule);
        strncpy_s(info->functionName, inlineInfo.functionName, sizeof(info->functionName) - 1);
        memcpy(info->hookBytes, inlineInfo.prologueBytes, 16);
        info->confidence = 85;
        info->isSuspicious = 1;
        return NEXUS_OK;
    }

    return NEXUS_ERROR_NOT_FOUND;
}

/* ============================================================================
 * Disk Comparison
 * ============================================================================ */

NEXUS_API NexusResult Nexus_HookCompareWithDisk(
    NexusProcessHandle process,
    uint64_t functionAddress,
    uint32_t* isModified,
    uint8_t* diskBytes,
    size_t* byteCount)
{
    if (!process || !isModified) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    *isModified = 0;

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;
    bool is64Bit = !ctx->is32Bit;

    // Find module containing address
    uint64_t moduleBase = 0;
    wchar_t modulePath[MAX_PATH] = {0};

    if (!GetModuleForAddress(hProcess, functionAddress, nullptr, 0, &moduleBase)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (!GetModulePath(hProcess, moduleBase, modulePath, MAX_PATH)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    // Read memory bytes
    uint8_t memBytes[32];
    if (!ReadProcessMem(hProcess, functionAddress, memBytes, sizeof(memBytes))) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Read disk bytes
    uint32_t rva = (uint32_t)(functionAddress - moduleBase);
    uint8_t fileBytes[32];
    if (!ReadDiskBytes(modulePath, moduleBase, rva, fileBytes, sizeof(fileBytes), is64Bit)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Compare
    *isModified = memcmp(memBytes, fileBytes, sizeof(memBytes)) != 0 ? 1 : 0;

    if (diskBytes && byteCount && *byteCount >= sizeof(fileBytes)) {
        memcpy(diskBytes, fileBytes, sizeof(fileBytes));
        *byteCount = sizeof(fileBytes);
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Hook Restoration
 * ============================================================================ */

NEXUS_API NexusResult Nexus_HookRestore(
    NexusProcessHandle process,
    uint64_t functionAddress)
{
    if (!process) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;
    bool is64Bit = !ctx->is32Bit;

    // Find module
    uint64_t moduleBase = 0;
    wchar_t modulePath[MAX_PATH] = {0};

    if (!GetModuleForAddress(hProcess, functionAddress, nullptr, 0, &moduleBase)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (!GetModulePath(hProcess, moduleBase, modulePath, MAX_PATH)) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    // Read original bytes from disk
    uint32_t rva = (uint32_t)(functionAddress - moduleBase);
    uint8_t originalBytes[16];
    if (!ReadDiskBytes(modulePath, moduleBase, rva, originalBytes, sizeof(originalBytes), is64Bit)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Change protection and write
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)functionAddress, sizeof(originalBytes),
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    SIZE_T written;
    BOOL writeResult = WriteProcessMemory(hProcess, (LPVOID)functionAddress, originalBytes,
                                     sizeof(originalBytes), &written);

    // Restore protection
    VirtualProtectEx(hProcess, (LPVOID)functionAddress, sizeof(originalBytes), oldProtect, &oldProtect);

    return writeResult ? NEXUS_OK : NEXUS_ERROR_ACCESS_DENIED;
}

NEXUS_API NexusResult Nexus_HookRestoreModule(
    NexusProcessHandle process,
    uint64_t moduleBase)
{
    if (!process) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Scan for inline hooks and restore each
    size_t count;
    NexusResult result = Nexus_HookScanInline(process, moduleBase, nullptr, 0, &count);
    if (result != NEXUS_OK || count == 0) {
        return result;
    }

    std::vector<NexusInlineHookInfo> hooks(count);
    result = Nexus_HookScanInline(process, moduleBase, hooks.data(), count, &count);
    if (result != NEXUS_OK) {
        return result;
    }

    uint32_t restored = 0;
    for (const auto& hook : hooks) {
        if (Nexus_HookRestore(process, hook.functionAddress) == NEXUS_OK) {
            restored++;
        }
    }

    return restored > 0 ? NEXUS_OK : NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_HookRestoreIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const wchar_t* dllName,
    const char* functionName)
{
    if (!process || !dllName || !functionName) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<NexusProcessHandleData*>(process);
    HANDLE hProcess = ctx->hProcess;
    bool is64Bit = !ctx->is32Bit;

    // Find the IAT entry
    NexusIatHookInfo hookInfo;
    NexusResult result = Nexus_HookCheckIat(process, moduleBase, dllName, functionName, &hookInfo);
    if (result != NEXUS_OK) {
        return result;
    }

    // Get the correct address
    char dllNameA[260];
    WideCharToMultiByte(CP_ACP, 0, dllName, -1, dllNameA, sizeof(dllNameA), NULL, NULL);

    HMODULE hDll = GetModuleHandleA(dllNameA);
    if (!hDll) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    FARPROC proc = GetProcAddress(hDll, functionName);
    if (!proc) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    // Write the correct address to IAT
    uint64_t iatEntry = moduleBase + hookInfo.thunkRva;
    uint64_t correctAddr = (uint64_t)proc;

    DWORD oldProtect;
    SIZE_T entrySize = is64Bit ? 8 : 4;
    if (!VirtualProtectEx(hProcess, (LPVOID)iatEntry, entrySize, PAGE_READWRITE, &oldProtect)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    SIZE_T written;
    BOOL writeResult = WriteProcessMemory(hProcess, (LPVOID)iatEntry, &correctAddr, entrySize, &written);

    VirtualProtectEx(hProcess, (LPVOID)iatEntry, entrySize, oldProtect, &oldProtect);

    return writeResult ? NEXUS_OK : NEXUS_ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * System Hook Detection - Requires Kernel Driver
 * ============================================================================ */

NEXUS_API NexusResult Nexus_HookScanSsdt(
    NexusKernelHandle /*kernel*/,
    NexusHookInfo* /*buffer*/,
    size_t /*bufferCount*/,
    size_t* count)
{
    // Requires kernel driver implementation
    if (count) *count = 0;
    return NEXUS_ERROR_NOT_IMPLEMENTED;
}

NEXUS_API NexusResult Nexus_HookScanIdt(
    NexusKernelHandle /*kernel*/,
    NexusHookInfo* /*buffer*/,
    size_t /*bufferCount*/,
    size_t* count)
{
    // Requires kernel driver implementation
    if (count) *count = 0;
    return NEXUS_ERROR_NOT_IMPLEMENTED;
}

} // extern "C"
