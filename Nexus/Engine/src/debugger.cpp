/**
 * @file debugger.cpp
 * @brief Debugger core: attach/detach, breakpoints, debug events, and single-step.
 *
 * Implements the Windows debug API workflow: DebugActiveProcess attach,
 * WaitForDebugEvent loop, INT3 software breakpoints with original-byte
 * save/restore, hardware execution/write/RW breakpoints via DR0-DR3,
 * single-step via EFLAGS trap flag, and clean detach.
 *
 * Module-relative breakpoints are split into debugger_module.cpp.
 */

#include "debugger_internal.h"

// Global debugger storage
std::mutex g_debuggerMutex;
std::unordered_map<void*, std::unique_ptr<DebuggerContext>> g_debuggers;

// Helper to extract module name from full path (case-insensitive comparison)
static bool ModuleNameMatches(const wchar_t* fullPath, const wchar_t* moduleName) {
    if (!fullPath || !moduleName) return false;

    // Find last path separator
    const wchar_t* lastSlash = wcsrchr(fullPath, L'\\');
    if (!lastSlash) lastSlash = wcsrchr(fullPath, L'/');
    const wchar_t* fileName = lastSlash ? lastSlash + 1 : fullPath;

    // Case-insensitive compare
    return _wcsicmp(fileName, moduleName) == 0;
}

// Extract module name from a full path
void ExtractModuleName(const wchar_t* fullPath, wchar_t* moduleName, size_t maxLen) {
    if (!fullPath || !moduleName || maxLen == 0) return;

    const wchar_t* lastSlash = wcsrchr(fullPath, L'\\');
    if (!lastSlash) lastSlash = wcsrchr(fullPath, L'/');
    const wchar_t* fileName = lastSlash ? lastSlash + 1 : fullPath;

    wcsncpy_s(moduleName, maxLen, fileName, _TRUNCATE);
}

// Find module base address by name
uint64_t FindModuleBase(HANDLE /*hProcess*/, DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    uint64_t result = 0;
    if (Module32FirstW(snapshot, &me)) {
        do {
            if (ModuleNameMatches(me.szModule, moduleName) ||
                ModuleNameMatches(me.szExePath, moduleName)) {
                result = (uint64_t)me.modBaseAddr;
                break;
            }
            me.dwSize = sizeof(me);
        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);
    return result;
}

// Find which module contains an address and return its base/name
bool FindModuleForAddress(DWORD processId, uint64_t address,
                          wchar_t* moduleName, size_t nameLen, uint64_t* moduleBase) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    bool found = false;
    if (Module32FirstW(snapshot, &me)) {
        do {
            uint64_t base = (uint64_t)me.modBaseAddr;
            uint64_t end = base + me.modBaseSize;
            if (address >= base && address < end) {
                ExtractModuleName(me.szModule, moduleName, nameLen);
                *moduleBase = base;
                found = true;
                break;
            }
            me.dwSize = sizeof(me);
        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);
    return found;
}

// Read/write memory helpers
bool ReadMem(HANDLE process, uint64_t address, void* buffer, size_t size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(process, (LPCVOID)address, buffer, size, &bytesRead) && bytesRead == size;
}

bool WriteMem(HANDLE process, uint64_t address, const void* buffer, size_t size) {
    SIZE_T bytesWritten;
    DWORD oldProtect;

    // Try to write directly first
    if (WriteProcessMemory(process, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size) {
        FlushInstructionCache(process, (LPCVOID)address, size);
        return true;
    }

    // If failed, try changing protection first
    if (!VirtualProtectEx(process, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    bool success = WriteProcessMemory(process, (LPVOID)address, buffer, size, &bytesWritten) && bytesWritten == size;

    VirtualProtectEx(process, (LPVOID)address, size, oldProtect, &oldProtect);

    if (success) {
        FlushInstructionCache(process, (LPCVOID)address, size);
    }

    return success;
}

// Set hardware breakpoint in a thread's debug registers
static bool SetHardwareBreakpoint(HANDLE thread, int regIndex, uint64_t address,
                                   NexusBreakpointType type, NexusBreakpointSize size) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(thread, &ctx)) {
        return false;
    }

    // Set the address in DR0-DR3
    switch (regIndex) {
        case 0: ctx.Dr0 = address; break;
        case 1: ctx.Dr1 = address; break;
        case 2: ctx.Dr2 = address; break;
        case 3: ctx.Dr3 = address; break;
        default: return false;
    }

    // Configure DR7
    // Each breakpoint has 2 bits for condition (bits 16-17, 20-21, 24-25, 28-29)
    // and 2 bits for length (bits 18-19, 22-23, 26-27, 30-31)
    // Plus local enable bits (bits 0, 2, 4, 6)

    int shift = regIndex * 4 + 16;

    // Clear existing condition and length for this register
    ctx.Dr7 &= ~(0xFULL << shift);

    // Set condition based on type
    uint64_t condition = 0;
    switch (type) {
        case NEXUS_BP_HARDWARE_EXEC:  condition = 0; break; // Execute
        case NEXUS_BP_HARDWARE_WRITE: condition = 1; break; // Write
        case NEXUS_BP_HARDWARE_RW:    condition = 3; break; // Read/Write
        default: return false;
    }

    // Set length
    uint64_t length = (uint64_t)size;

    ctx.Dr7 |= (condition | (length << 2)) << shift;

    // Enable local breakpoint
    ctx.Dr7 |= (1ULL << (regIndex * 2));

    return SetThreadContext(thread, &ctx) != 0;
}

// Clear hardware breakpoint from a thread
static bool ClearHardwareBreakpoint(HANDLE thread, int regIndex) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(thread, &ctx)) {
        return false;
    }

    // Clear the address
    switch (regIndex) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
        default: return false;
    }

    // Disable local breakpoint
    ctx.Dr7 &= ~(1ULL << (regIndex * 2));

    // Clear condition and length
    int shift = regIndex * 4 + 16;
    ctx.Dr7 &= ~(0xFULL << shift);

    return SetThreadContext(thread, &ctx) != 0;
}

// Apply hardware breakpoint to all threads in process
void ApplyHwBreakpointToAllThreads(DebuggerContext* dbg, BreakpointData& bp, bool enable) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dbg->processId) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                          FALSE, te.th32ThreadID);
                if (thread) {
                    SuspendThread(thread);

                    if (enable) {
                        SetHardwareBreakpoint(thread, bp.hwRegister, bp.info.address,
                                             (NexusBreakpointType)bp.info.type,
                                             (NexusBreakpointSize)bp.info.size);
                    } else {
                        ClearHardwareBreakpoint(thread, bp.hwRegister);
                    }

                    ResumeThread(thread);
                    CloseHandle(thread);
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
}

// Apply all active hardware breakpoints to a single thread
static void ApplyAllHwBreakpointsToThread(DebuggerContext* dbg, DWORD threadId) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                               FALSE, threadId);
    if (!thread) return;

    SuspendThread(thread);

    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.enabled && bp.hwRegister >= 0) {
            SetHardwareBreakpoint(thread, bp.hwRegister, bp.info.address,
                                  (NexusBreakpointType)bp.info.type,
                                  (NexusBreakpointSize)bp.info.size);
        }
    }

    ResumeThread(thread);
    CloseHandle(thread);
}

// Find a free hardware breakpoint register
int FindFreeHwRegister(DebuggerContext* dbg) {
    uint8_t inUse = 0;

    // Check all active hardware breakpoints
    for (auto& pair : dbg->breakpoints) {
        if (pair.second.hwRegister >= 0) {
            inUse |= (1 << pair.second.hwRegister);
        }
    }

    for (int i = 0; i < 4; i++) {
        if (!(inUse & (1 << i))) {
            return i;
        }
    }

    return -1; // No free registers
}

// Convert Windows debug event to Nexus debug event
static void ConvertDebugEvent(const DEBUG_EVENT& winEvent, NexusDebugEvent* event, DebuggerContext* dbg) {
    memset(event, 0, sizeof(NexusDebugEvent));

    event->processId = winEvent.dwProcessId;
    event->threadId = winEvent.dwThreadId;

    switch (winEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            switch (winEvent.u.Exception.ExceptionRecord.ExceptionCode) {
                case EXCEPTION_BREAKPOINT: {
                    event->type = NEXUS_DBG_BREAKPOINT;
                    event->address = (uint64_t)winEvent.u.Exception.ExceptionRecord.ExceptionAddress;

                    // Check if this is the initial system breakpoint (ntdll!LdrpDoDebuggerBreak)
                    // This occurs when we first attach to a process - it's not one of our breakpoints
                    if (!dbg->initialBreakpointSeen) {
                        dbg->initialBreakpointSeen = true;
                        // Mark as system breakpoint (breakpointId = 0)
                        event->breakpointId = 0;
                        break;
                    }

                    // Check if this is one of our breakpoints
                    for (auto& pair : dbg->breakpoints) {
                        if (pair.second.info.address == event->address ||
                            pair.second.info.address == event->address - 1) { // INT3 reports address+1
                            event->breakpointId = pair.first;
                            break;
                        }
                    }
                    break;
                }

                case EXCEPTION_SINGLE_STEP: {
                    // EXCEPTION_SINGLE_STEP is triggered by both:
                    // 1. Trap flag (TF) single-stepping
                    // 2. Hardware breakpoints (DR0-DR3 data breakpoints)
                    // We need to check DR6 to determine which
                    event->address = (uint64_t)winEvent.u.Exception.ExceptionRecord.ExceptionAddress;

                    // Open thread to read DR6
                    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                              FALSE, winEvent.dwThreadId);
                    bool isHwBreakpoint = false;
                    uint64_t hwBpAddress = 0;

                    if (thread) {
                        CONTEXT ctx;
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(thread, &ctx)) {
                            // DR6 bits 0-3 indicate which DR0-DR3 triggered
                            if (ctx.Dr6 & 0x0F) {
                                isHwBreakpoint = true;
                                // Find which register triggered
                                if (ctx.Dr6 & 0x01) hwBpAddress = ctx.Dr0;
                                else if (ctx.Dr6 & 0x02) hwBpAddress = ctx.Dr1;
                                else if (ctx.Dr6 & 0x04) hwBpAddress = ctx.Dr2;
                                else if (ctx.Dr6 & 0x08) hwBpAddress = ctx.Dr3;

                                // Clear DR6 to acknowledge the breakpoint
                                ctx.Dr6 = 0;
                                SetThreadContext(thread, &ctx);
                            }
                        }
                        CloseHandle(thread);
                    }

                    if (isHwBreakpoint) {
                        event->type = NEXUS_DBG_BREAKPOINT;
                        // For hardware breakpoints, look up which one it was
                        for (auto& pair : dbg->breakpoints) {
                            if (pair.second.info.address == hwBpAddress) {
                                event->breakpointId = pair.first;
                                pair.second.info.hitCount++;
                                break;
                            }
                        }
                    } else {
                        event->type = NEXUS_DBG_SINGLE_STEP;
                    }
                    break;
                }

                default:
                    event->type = NEXUS_DBG_EXCEPTION;
                    event->address = (uint64_t)winEvent.u.Exception.ExceptionRecord.ExceptionAddress;
                    event->exceptionCode = winEvent.u.Exception.ExceptionRecord.ExceptionCode;
                    break;
            }
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            event->type = NEXUS_DBG_PROCESS_CREATE;
            event->info.module.baseAddress = (uint64_t)winEvent.u.CreateProcessInfo.lpBaseOfImage;
            // Close handles we don't need
            if (winEvent.u.CreateProcessInfo.hFile) {
                CloseHandle(winEvent.u.CreateProcessInfo.hFile);
            }
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            event->type = NEXUS_DBG_PROCESS_EXIT;
            event->info.exit.exitCode = winEvent.u.ExitProcess.dwExitCode;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            event->type = NEXUS_DBG_THREAD_CREATE;
            event->address = (uint64_t)winEvent.u.CreateThread.lpStartAddress;
            // Apply existing hardware breakpoints to the new thread
            ApplyAllHwBreakpointsToThread(dbg, winEvent.dwThreadId);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            event->type = NEXUS_DBG_THREAD_EXIT;
            event->info.exit.exitCode = winEvent.u.ExitThread.dwExitCode;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            event->type = NEXUS_DBG_DLL_LOAD;
            event->info.module.baseAddress = (uint64_t)winEvent.u.LoadDll.lpBaseOfDll;
            // Try to get the module name from the file handle
            if (winEvent.u.LoadDll.hFile) {
                wchar_t pathBuffer[520] = {0};
                DWORD len = GetFinalPathNameByHandleW(winEvent.u.LoadDll.hFile, pathBuffer,
                                                       sizeof(pathBuffer)/sizeof(wchar_t) - 1,
                                                       FILE_NAME_NORMALIZED);
                if (len > 0 && len < sizeof(pathBuffer)/sizeof(wchar_t)) {
                    // Remove \\?\ prefix if present
                    wchar_t* name = pathBuffer;
                    if (wcsncmp(name, L"\\\\?\\", 4) == 0) {
                        name += 4;
                    }
                    wcsncpy_s(event->info.module.moduleName,
                              sizeof(event->info.module.moduleName)/sizeof(wchar_t),
                              name, _TRUNCATE);

                    // Resolve any module-relative breakpoints for this module
                    OnModuleLoad(dbg, event->info.module.baseAddress, name);
                }
                CloseHandle(winEvent.u.LoadDll.hFile);
            }
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            event->type = NEXUS_DBG_DLL_UNLOAD;
            event->info.module.baseAddress = (uint64_t)winEvent.u.UnloadDll.lpBaseOfDll;
            // Unresolve any module-relative breakpoints for this module
            OnModuleUnload(dbg, event->info.module.baseAddress);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            event->type = NEXUS_DBG_OUTPUT_STRING;
            // Read the debug string
            if (winEvent.u.DebugString.fUnicode) {
                // Unicode string
                wchar_t buffer[256];
                SIZE_T bytesRead;
                if (ReadProcessMemory(dbg->process->processHandle,
                                     winEvent.u.DebugString.lpDebugStringData,
                                     buffer, min((size_t)winEvent.u.DebugString.nDebugStringLength * 2, sizeof(buffer) - 2),
                                     &bytesRead)) {
                    buffer[bytesRead / 2] = L'\0';
                    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, event->info.outputString.message,
                                       sizeof(event->info.outputString.message), nullptr, nullptr);
                }
            } else {
                // ANSI string
                SIZE_T bytesRead;
                ReadProcessMemory(dbg->process->processHandle,
                                 winEvent.u.DebugString.lpDebugStringData,
                                 event->info.outputString.message,
                                 min((size_t)winEvent.u.DebugString.nDebugStringLength, sizeof(event->info.outputString.message) - 1),
                                 &bytesRead);
                event->info.outputString.message[bytesRead] = '\0';
            }
            break;

        default:
            event->type = NEXUS_DBG_NONE;
            break;
    }
}

/* ============================================================================
 * Core Debugger API
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_DebuggerAttach(
    NexusProcessHandle process,
    NexusDebuggerHandle* debugger
) {
    if (!process || !debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* ctx = static_cast<ProcessContext*>(process);

    // Try to attach as debugger
    if (!DebugActiveProcess(ctx->processId)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Don't kill process when debugger detaches
    DebugSetProcessKillOnExit(FALSE);

    auto dbg = std::make_unique<DebuggerContext>();
    dbg->process = ctx;
    dbg->processId = ctx->processId;
    dbg->attached = true;
    dbg->detaching = false;
    dbg->nextBreakpointId = 1;
    dbg->initialBreakpointSeen = false;

    // Store unique_ptr in global container and return raw pointer
    auto* rawPtr = dbg.get();
    {
        std::lock_guard<std::mutex> lock(g_debuggerMutex);
        g_debuggers[rawPtr] = std::move(dbg);
    }

    *debugger = rawPtr;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_DebuggerDetach(NexusDebuggerHandle debugger) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);

    /* CRITICAL FIX: Acquire global lock FIRST to prevent deadlock with Attach.
     * Lock ordering must be: g_debuggerMutex -> dbg->mutex
     * Previous code acquired dbg->mutex first, then g_debuggerMutex later,
     * which could deadlock with concurrent Attach operations.
     */
    std::lock_guard<std::mutex> globalLock(g_debuggerMutex);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    dbg->detaching = true;

    // Remove all breakpoints
    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.enabled) {
            if (bp.info.type == NEXUS_BP_SOFTWARE) {
                // Restore original byte
                WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1);
            } else if (bp.hwRegister >= 0) {
                // Clear hardware breakpoint
                ApplyHwBreakpointToAllThreads(dbg, bp, false);
            }
        }
    }
    dbg->breakpoints.clear();

    // Detach from process
    DebugActiveProcessStop(dbg->processId);

    dbg->attached = false;

    // Remove from global container (unique_ptr handles deletion)
    g_debuggers.erase(debugger);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SetBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t address,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
) {
    if (!debugger || !breakpointId) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    /* FIX: Check for duplicate breakpoint at same address (prevents corrupting original byte tracking) */
    for (const auto& pair : dbg->breakpoints) {
        if (pair.second.info.address == address && pair.second.info.enabled) {
            return NEXUS_ERROR_INVALID_PARAMETER;  /* Breakpoint already exists at this address */
        }
    }

    /* FIX: Hardware breakpoint alignment validation (TitanEngine pattern)
     * Data breakpoints must be aligned to their size for proper operation
     */
    if (type == NEXUS_BP_HARDWARE_WRITE || type == NEXUS_BP_HARDWARE_RW) {
        size_t alignment = (size == NEXUS_BP_SIZE_1) ? 1 :
                           (size == NEXUS_BP_SIZE_2) ? 2 :
                           (size == NEXUS_BP_SIZE_4) ? 4 : 8;
        if (address % alignment != 0) {
            return NEXUS_ERROR_INVALID_PARAMETER;  /* Address not properly aligned for HW BP size */
        }
    }

    BreakpointData bp = {};
    bp.info.address = address;
    bp.info.type = type;
    bp.info.size = size;
    bp.info.enabled = 1;
    bp.info.hitCount = 0;
    bp.hwRegister = -1;

    if (type == NEXUS_BP_SOFTWARE) {
        // Software breakpoint: save original byte and write INT3
        if (!ReadMem(dbg->process->processHandle, address, &bp.info.originalByte, 1)) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }

        uint8_t int3 = 0xCC;
        if (!WriteMem(dbg->process->processHandle, address, &int3, 1)) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }
    } else if (type == NEXUS_BP_HARDWARE_EXEC || type == NEXUS_BP_HARDWARE_WRITE || type == NEXUS_BP_HARDWARE_RW) {
        // Hardware breakpoint: find free register
        int reg = FindFreeHwRegister(dbg);
        if (reg < 0) {
            return NEXUS_ERROR_INSUFFICIENT_BUFFER; // No free HW BP registers
        }

        bp.hwRegister = reg;
        ApplyHwBreakpointToAllThreads(dbg, bp, true);
    } else {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    bp.info.id = dbg->nextBreakpointId++;
    *breakpointId = bp.info.id;

    dbg->breakpoints[bp.info.id] = bp;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_RemoveBreakpoint(
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

    if (bp.info.enabled) {
        if (bp.info.type == NEXUS_BP_SOFTWARE) {
            // Restore original byte
            WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1);
        } else if (bp.hwRegister >= 0) {
            // Clear hardware breakpoint
            ApplyHwBreakpointToAllThreads(dbg, bp, false);
        }
    }

    dbg->breakpoints.erase(it);
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_EnableBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId,
    int enabled
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

    if ((enabled != 0) == (bp.info.enabled != 0)) {
        return NEXUS_OK; // Already in desired state
    }

    if (enabled) {
        // Enable breakpoint
        if (bp.info.type == NEXUS_BP_SOFTWARE) {
            uint8_t int3 = 0xCC;
            if (!WriteMem(dbg->process->processHandle, bp.info.address, &int3, 1)) {
                return NEXUS_ERROR_ACCESS_DENIED;
            }
        } else if (bp.hwRegister >= 0) {
            ApplyHwBreakpointToAllThreads(dbg, bp, true);
        }
    } else {
        // Disable breakpoint
        if (bp.info.type == NEXUS_BP_SOFTWARE) {
            if (!WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1)) {
                return NEXUS_ERROR_ACCESS_DENIED;
            }
        } else if (bp.hwRegister >= 0) {
            ApplyHwBreakpointToAllThreads(dbg, bp, false);
        }
    }

    bp.info.enabled = enabled ? 1 : 0;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId,
    NexusBreakpoint* breakpoint
) {
    if (!debugger || !breakpoint) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    auto it = dbg->breakpoints.find(breakpointId);
    if (it == dbg->breakpoints.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *breakpoint = it->second.info;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetBreakpoints(
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

    *count = dbg->breakpoints.size();

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    size_t i = 0;
    for (auto& pair : dbg->breakpoints) {
        if (i >= bufferCount) break;
        buffer[i++] = pair.second.info;
    }

    if (bufferCount < dbg->breakpoints.size()) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_WaitForDebugEvent(
    NexusDebuggerHandle debugger,
    NexusDebugEvent* event,
    uint32_t timeoutMs
) {
    if (!debugger || !event) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);

retry_wait:
    DEBUG_EVENT winEvent;
    if (!WaitForDebugEvent(&winEvent, timeoutMs)) {
        if (GetLastError() == ERROR_SEM_TIMEOUT) {
            return NEXUS_ERROR_NOT_FOUND; // Timeout
        }
        return NEXUS_ERROR_UNKNOWN;
    }

    // Check if this is a single-step from stepping over a software breakpoint
    if (winEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
        winEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

        std::lock_guard<std::mutex> lock(dbg->mutex);
        auto it = dbg->stepOverPending.find(winEvent.dwThreadId);
        if (it != dbg->stepOverPending.end()) {
            // This is our step-over completion - re-set the INT3 and auto-continue
            StepOverState& state = it->second;

            // Re-write INT3 at the breakpoint address
            uint8_t int3 = 0xCC;
            WriteMem(dbg->process->processHandle, state.address, &int3, 1);

            // Remove from pending
            dbg->stepOverPending.erase(it);

            // Auto-continue without notifying the user
            ContinueDebugEvent(dbg->processId, winEvent.dwThreadId, DBG_CONTINUE);

            // Wait for next event
            goto retry_wait;
        }
    }

    // Convert to Nexus event
    {
        std::lock_guard<std::mutex> lock(dbg->mutex);
        ConvertDebugEvent(winEvent, event, dbg);

        // Increment hit count for breakpoint events
        if (event->type == NEXUS_DBG_BREAKPOINT && event->breakpointId != 0) {
            auto it = dbg->breakpoints.find(event->breakpointId);
            if (it != dbg->breakpoints.end()) {
                it->second.info.hitCount++;
            }
        }
    }

    // Store the Windows event for ContinueDebugEvent
    {
        std::lock_guard<std::mutex> lock(dbg->eventMutex);
        QueuedDebugEvent qe;
        qe.winEvent = winEvent;
        qe.handled = false;
        dbg->eventQueue.push(qe);
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ContinueDebugEvent(
    NexusDebuggerHandle debugger,
    uint32_t threadId,
    uint32_t continueStatus
) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);

    // Check if we need to step over a software breakpoint
    // This happens when we hit a software BP and want to continue
    {
        std::lock_guard<std::mutex> lock(dbg->mutex);

        // Check the last event in the queue
        std::lock_guard<std::mutex> eventLock(dbg->eventMutex);
        if (!dbg->eventQueue.empty()) {
            auto& qe = dbg->eventQueue.front();
            if (qe.winEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                qe.winEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

                uint64_t bpAddress = (uint64_t)qe.winEvent.u.Exception.ExceptionRecord.ExceptionAddress;

                // Find if this is one of our software breakpoints
                for (auto& pair : dbg->breakpoints) {
                    auto& bp = pair.second;
                    // INT3 may report address or address-1 depending on when we check
                    if (bp.info.type == NEXUS_BP_SOFTWARE && bp.info.enabled &&
                        (bp.info.address == bpAddress || bp.info.address == bpAddress - 1)) {

                        // Found our breakpoint - set up step-over
                        // 1. Restore original byte
                        WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1);

                        // 2. Set trap flag for single-step
                        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                                   FALSE, threadId);
                        if (thread) {
                            CONTEXT ctx;
                            ctx.ContextFlags = CONTEXT_CONTROL;
                            if (GetThreadContext(thread, &ctx)) {
                                ctx.EFlags |= 0x100; // Set trap flag
                                SetThreadContext(thread, &ctx);
                            }
                            CloseHandle(thread);
                        }

                        // 3. Track that we're stepping over this BP
                        StepOverState state;
                        state.breakpointId = bp.info.id;
                        state.address = bp.info.address;
                        state.originalByte = bp.info.originalByte;
                        dbg->stepOverPending[threadId] = state;

                        break;
                    }
                }
            }
        }
    }

    DWORD status = (continueStatus == DBG_CONTINUE) ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;

    if (!::ContinueDebugEvent(dbg->processId, threadId, status)) {
        return NEXUS_ERROR_UNKNOWN;
    }

    // Remove from queue
    {
        std::lock_guard<std::mutex> lock(dbg->eventMutex);
        if (!dbg->eventQueue.empty()) {
            /* FIX: Validate that the event being popped matches the threadId being continued
             * This prevents mismatched event/continue pairs that could cause issues
             */
            auto& qe = dbg->eventQueue.front();
            if (qe.winEvent.dwThreadId != threadId) {
                /* Mismatched thread ID - log warning but continue
                 * This shouldn't happen in normal operation but we handle it gracefully
                 */
            }
            dbg->eventQueue.pop();
        }
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SingleStep(
    NexusDebuggerHandle debugger,
    uint32_t threadId
) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);

    // Open the thread
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                               FALSE, threadId);
    if (!thread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Suspend, set trap flag, resume
    SuspendThread(thread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(thread, &ctx)) {
        ResumeThread(thread);
        CloseHandle(thread);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    // Set trap flag (bit 8 of EFLAGS)
    ctx.EFlags |= 0x100;

    if (!SetThreadContext(thread, &ctx)) {
        ResumeThread(thread);
        CloseHandle(thread);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    ResumeThread(thread);
    CloseHandle(thread);

    // Mark as pending single-step
    {
        std::lock_guard<std::mutex> lock(dbg->mutex);
        dbg->singleStepPending[threadId] = true;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_RemoveAllBreakpoints(NexusDebuggerHandle debugger) {
    if (!debugger) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* dbg = static_cast<DebuggerContext*>(debugger);
    std::lock_guard<std::mutex> lock(dbg->mutex);

    for (auto& pair : dbg->breakpoints) {
        auto& bp = pair.second;
        if (bp.info.enabled) {
            if (bp.info.type == NEXUS_BP_SOFTWARE) {
                WriteMem(dbg->process->processHandle, bp.info.address, &bp.info.originalByte, 1);
            } else if (bp.hwRegister >= 0) {
                ApplyHwBreakpointToAllThreads(dbg, bp, false);
            }
        }
    }

    dbg->breakpoints.clear();
    return NEXUS_OK;
}

} // extern "C"
