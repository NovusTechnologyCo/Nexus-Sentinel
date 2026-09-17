/**
 * @file debugger_module.cpp
 * @brief Module-relative breakpoint management for ASLR-resilient debugging.
 *
 * Stores breakpoints as (module name, RVA) pairs so they survive
 * ASLR randomisation and DLL reload cycles.  Provides automatic
 * resolution on DLL_LOAD events, un-resolution on DLL_UNLOAD, and
 * symbol-based breakpoint setting (e.g. "ntdll!NtCreateFile").
 */

#include "debugger_internal.h"

// Activate a software breakpoint (write INT3)
static bool ActivateSoftwareBreakpoint(DebuggerContext* dbg, BreakpointData& bp) {
    if (bp.info.address == 0) return false;

    // Read original byte
    if (!ReadMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1)) {
        return false;
    }

    // Write INT3
    uint8_t int3 = 0xCC;
    if (!WriteMem(dbg->process->processHandle, bp.info.address, &int3, 1)) {
        return false;
    }

    bp.info.resolved = 1;
    bp.needsActivation = false;
    return true;
}

// Deactivate a software breakpoint (restore original byte)
[[maybe_unused]] static bool DeactivateSoftwareBreakpoint(DebuggerContext* dbg, BreakpointData& bp) {
    if (bp.info.address == 0 || !bp.info.resolved) return true;

    // Restore original byte
    WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1);
    bp.info.resolved = 0;
    bp.info.address = 0; // Clear resolved address
    return true;
}

// Try to resolve a module-relative breakpoint
static bool TryResolveModuleBreakpoint(DebuggerContext* dbg, BreakpointData& bp) {
    if (bp.info.mode != NEXUS_BP_MODE_MODULE_RELATIVE) return false;
    if (bp.info.resolved) return true; // Already resolved

    // Find module base
    uint64_t moduleBase = FindModuleBase(dbg->process->processHandle, dbg->processId, bp.info.moduleName);
    if (moduleBase == 0) return false;

    // Calculate absolute address
    bp.info.address = moduleBase + bp.info.rva;

    // Activate if enabled
    if (bp.info.enabled) {
        if (bp.info.type == NEXUS_BP_SOFTWARE) {
            return ActivateSoftwareBreakpoint(dbg, bp);
        } else if (bp.hwRegister >= 0) {
            ApplyHwBreakpointToAllThreads(dbg, bp, true);
            bp.info.resolved = 1;
            return true;
        }
    } else {
        // Just mark as resolved without activating
        bp.info.resolved = 1;
    }

    return true;
}

// Called when a module is loaded - resolve any matching breakpoints
void OnModuleLoad(DebuggerContext* dbg, uint64_t moduleBase, const wchar_t* modulePath) {
    wchar_t moduleName[64];
    ExtractModuleName(modulePath, moduleName, 64);

    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE &&
            !bp.info.resolved &&
            _wcsicmp(bp.info.moduleName, moduleName) == 0) {

            // Calculate absolute address from the provided base
            bp.info.address = moduleBase + bp.info.rva;

            // Activate if enabled
            if (bp.info.enabled) {
                if (bp.info.type == NEXUS_BP_SOFTWARE) {
                    ActivateSoftwareBreakpoint(dbg, bp);
                } else if (bp.hwRegister >= 0) {
                    ApplyHwBreakpointToAllThreads(dbg, bp, true);
                    bp.info.resolved = 1;
                }
            } else {
                bp.info.resolved = 1;
            }
        }
    }
}

// Called when a module is unloaded - unresolve matching breakpoints
void OnModuleUnload(DebuggerContext* dbg, uint64_t moduleBase) {
    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE && bp.info.resolved) {
            // Check if this BP was in the unloaded module
            // We stored the module name, so check if address matches
            uint64_t bpModuleBase = bp.info.address - bp.info.rva;
            if (bpModuleBase == moduleBase) {
                // Deactivate and mark as unresolved
                if (bp.info.enabled && bp.info.type == NEXUS_BP_SOFTWARE) {
                    // Note: Memory is gone, can't restore - just mark unresolved
                }
                if (bp.hwRegister >= 0) {
                    ApplyHwBreakpointToAllThreads(dbg, bp, false);
                }
                bp.info.resolved = 0;
                bp.info.address = 0;
            }
        }
    }
}

/* ============================================================================
 * Module-Relative Breakpoint API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_SetBreakpointModule(
    NexusDebuggerHandle debugger,
    const wchar_t* moduleName,
    uint64_t rva,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
) {
    if (!debugger || !moduleName || !breakpointId) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    BreakpointData bp = {};
    bp.info.type = type;
    bp.info.size = size;
    bp.info.enabled = 1;
    bp.info.hitCount = 0;
    bp.info.mode = NEXUS_BP_MODE_MODULE_RELATIVE;
    bp.info.resolved = 0;
    bp.info.rva = rva;
    bp.hwRegister = -1;
    bp.needsActivation = false;

    // Copy module name
    wcsncpy_s(bp.info.moduleName, sizeof(bp.info.moduleName) / sizeof(wchar_t), moduleName, _TRUNCATE);

    // For hardware breakpoints, allocate register now
    if (type == NEXUS_BP_HARDWARE_EXEC || type == NEXUS_BP_HARDWARE_WRITE || type == NEXUS_BP_HARDWARE_RW) {
        int reg = FindFreeHwRegister(dbg);
        if (reg < 0) {
            return NEXUS_ERROR_INSUFFICIENT_BUFFER;
        }
        bp.hwRegister = reg;
    }

    // Try to resolve immediately if module is loaded
    uint64_t moduleBase = FindModuleBase(dbg->process->processHandle, dbg->processId, moduleName);
    if (moduleBase != 0) {
        bp.info.address = moduleBase + rva;

        // Activate the breakpoint
        if (type == NEXUS_BP_SOFTWARE) {
            if (!ActivateSoftwareBreakpoint(dbg, bp)) {
                return NEXUS_ERROR_ACCESS_DENIED;
            }
        } else if (bp.hwRegister >= 0) {
            ApplyHwBreakpointToAllThreads(dbg, bp, true);
            bp.info.resolved = 1;
        }
    }
    // If module not loaded, breakpoint stays unresolved until module loads

    bp.info.id = dbg->nextBreakpointId++;
    *breakpointId = bp.info.id;

    dbg->breakpoints[bp.info.id] = bp;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SetBreakpointSymbol(
    NexusDebuggerHandle debugger,
    const char* symbol,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
) {
    if (!debugger || !symbol || !breakpointId) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Parse module!function format
    const char* bang = strchr(symbol, '!');
    if (!bang || bang == symbol) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    // Extract module name
    char moduleNameA[64];
    size_t moduleLen = bang - symbol;
    if (moduleLen >= sizeof(moduleNameA)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }
    memcpy(moduleNameA, symbol, moduleLen);
    moduleNameA[moduleLen] = '\0';

    // Add .dll if not present
    if (!strchr(moduleNameA, '.')) {
        strcat_s(moduleNameA, ".dll");
    }

    // Convert to wide string
    wchar_t moduleNameW[64];
    MultiByteToWideChar(CP_UTF8, 0, moduleNameA, -1, moduleNameW, 64);

    // Get function name
    const char* funcName = bang + 1;

    auto* dbg = static_cast<DebuggerContext*>(debugger);

    // Find module base
    uint64_t moduleBase = FindModuleBase(dbg->process->processHandle, dbg->processId, moduleNameW);
    if (moduleBase == 0) {
        return NEXUS_ERROR_NOT_FOUND; // Module not loaded
    }

    // Find export by name
    NexusExportInfo exportInfo;
    NexusResult result = Nexus_FindExportByName(dbg->process, moduleBase, funcName, &exportInfo);
    if (result != NEXUS_OK) {
        return result;
    }

    // exportInfo.address is already an RVA
    return Nexus_SetBreakpointModule(debugger, moduleNameW, exportInfo.address, type, size, breakpointId);
}

NEXUS_API NexusResult Nexus_ConvertBreakpointToModuleRelative(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId
) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    auto it = dbg->breakpoints.find(breakpointId);
    if (it == dbg->breakpoints.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    auto& bp = it->second;

    // Already module-relative?
    if (bp.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE) {
        return NEXUS_OK;
    }

    // Find which module contains this address
    wchar_t moduleName[64];
    uint64_t moduleBase;
    if (!FindModuleForAddress(dbg->processId, bp.info.address, moduleName, 64, &moduleBase)) {
        return NEXUS_ERROR_NOT_FOUND; // Address not in any module
    }

    // Convert to module-relative
    bp.info.mode = NEXUS_BP_MODE_MODULE_RELATIVE;
    bp.info.rva = bp.info.address - moduleBase;
    bp.info.resolved = 1;
    wcsncpy_s(bp.info.moduleName, sizeof(bp.info.moduleName) / sizeof(wchar_t), moduleName, _TRUNCATE);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ResolveModuleBreakpoints(
    NexusDebuggerHandle debugger,
    size_t* resolvedCount
) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    size_t count = 0;

    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE && !bp.info.resolved) {
            if (TryResolveModuleBreakpoint(dbg, bp)) {
                count++;
            }
        }
    }

    if (resolvedCount) {
        *resolvedCount = count;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetUnresolvedBreakpoints(
    NexusDebuggerHandle debugger,
    NexusBreakpoint* buffer,
    size_t bufferCount,
    size_t* count
) {
    if (!debugger || !count) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    // Count unresolved breakpoints
    size_t unresolvedCount = 0;
    for (auto& pair : dbg->breakpoints) {
        if (pair.second.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE &&
            !pair.second.info.resolved) {
            unresolvedCount++;
        }
    }

    *count = unresolvedCount;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    // Copy to buffer
    size_t i = 0;
    for (auto& pair : dbg->breakpoints) {
        if (i >= bufferCount) break;
        if (pair.second.info.mode == NEXUS_BP_MODE_MODULE_RELATIVE &&
            !pair.second.info.resolved) {
            buffer[i++] = pair.second.info;
        }
    }

    return NEXUS_OK;
}

} // extern "C"
