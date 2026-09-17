/**
 * @file speedhack.cpp
 * @brief Speedhack API: create/destroy, speed control, enable/disable, and status.
 *
 * Manages speedhack instances that intercept timing APIs (QPC,
 * GetTickCount, timeGetTime) in a target process to scale the
 * perceived passage of time.
 *
 * Hook building and PE helpers are in speedhack_hook.cpp.
 */

#include "speedhack_internal.h"

// ============================================================================
// Speedhack API Implementation
// ============================================================================

NEXUS_API NexusResult Nexus_SpeedhackCreate(
    NexusProcessHandle process,
    uint32_t method,
    NexusSpeedhackHandle* speedhack
) {
    if (!process || !speedhack) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(process);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    bool is32Bit = procData->is32Bit;

    uint64_t qpcAddr = GetRemoteFunctionAddress(
        procData->pid,
        L"kernel32.dll",
        "QueryPerformanceCounter",
        is32Bit
    );

    if (!qpcAddr) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    // Check if QPC is a jump thunk and follow it
    uint8_t thunkBytes[16];
    SIZE_T thunkRead;
    if (ReadProcessMemory(procData->hProcess, reinterpret_cast<void*>(qpcAddr),
                          thunkBytes, sizeof(thunkBytes), &thunkRead)) {
        bool isJmpThunk = false;
        int32_t disp32 = 0;
        size_t instrLen = 0;

        if (!is32Bit) {
            if (thunkBytes[0] == 0x48 && thunkBytes[1] == 0xFF && thunkBytes[2] == 0x25) {
                memcpy(&disp32, &thunkBytes[3], 4);
                instrLen = 7;
                isJmpThunk = true;
            } else if (thunkBytes[0] == 0xFF && thunkBytes[1] == 0x25) {
                memcpy(&disp32, &thunkBytes[2], 4);
                instrLen = 6;
                isJmpThunk = true;
            }
        } else {
            if (thunkBytes[0] == 0xFF && thunkBytes[1] == 0x25) {
                uint32_t absAddr;
                memcpy(&absAddr, &thunkBytes[2], 4);
                uint32_t target;
                if (ReadProcessMemory(procData->hProcess, reinterpret_cast<void*>(static_cast<uintptr_t>(absAddr)),
                                      &target, 4, &thunkRead)) {
                    qpcAddr = target;
                }
            }
        }

        if (isJmpThunk && !is32Bit) {
            uint64_t ptrAddr = qpcAddr + instrLen + disp32;
            uint64_t realTarget;
            if (ReadProcessMemory(procData->hProcess, reinterpret_cast<void*>(ptrAddr),
                                  &realTarget, 8, &thunkRead)) {
                qpcAddr = realTarget;
            }
        }
    }

    auto* state = new (std::nothrow) SpeedhackState();
    if (!state) {
        return NEXUS_ERROR_OUT_OF_MEMORY;
    }
    memset(state, 0, sizeof(SpeedhackState));
    state->process = procData;
    state->method = method;
    state->qpcAddressInTarget = qpcAddr;

    size_t minHookBytes = is32Bit ? 5 : 12;

    SIZE_T bytesRead;
    if (!ReadProcessMemory(procData->hProcess,
                          reinterpret_cast<void*>(qpcAddr),
                          state->originalBytes,
                          sizeof(state->originalBytes), &bytesRead)) {
        delete state;
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    state->stolenBytesCount = GetHookSize(state->originalBytes, minHookBytes, !is32Bit);

    if (state->stolenBytesCount == 0 || state->stolenBytesCount > 24) {
        delete state;
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    state->sharedMemory = VirtualAllocEx(
        procData->hProcess, nullptr,
        sizeof(SpeedhackSharedData),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!state->sharedMemory) {
        delete state;
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    SpeedhackSharedData sharedData = {};
    sharedData.speedMultiplier = 1.0;
    sharedData.enabled = 0;

    SIZE_T bytesWritten;
    WriteProcessMemory(procData->hProcess, state->sharedMemory,
                      &sharedData, sizeof(sharedData), &bytesWritten);

    size_t codeSize = is32Bit ? 256 : 512;
    state->hookCode = VirtualAllocEx(
        procData->hProcess, nullptr, codeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    if (!state->hookCode) {
        VirtualFreeEx(procData->hProcess, state->sharedMemory, 0, MEM_RELEASE);
        delete state;
        return NEXUS_ERROR_ACCESS_DENIED;
    }
    state->hookCodeSize = codeSize;

    uint8_t* codeBuffer = new uint8_t[codeSize];
    memset(codeBuffer, 0xCC, codeSize);

    uint64_t hookBaseAddr = reinterpret_cast<uint64_t>(state->hookCode);
    uint64_t sharedDataAddr = reinterpret_cast<uint64_t>(state->sharedMemory);

    size_t actualCodeSize;
    if (is32Bit) {
        actualCodeSize = Build32BitHook(codeBuffer, codeSize,
                                        hookBaseAddr, sharedDataAddr,
                                        qpcAddr, state->originalBytes,
                                        state->stolenBytesCount);
    } else {
        actualCodeSize = Build64BitHook(codeBuffer, codeSize,
                                        hookBaseAddr, sharedDataAddr,
                                        qpcAddr, state->originalBytes,
                                        state->stolenBytesCount);
    }

    if (actualCodeSize == 0) {
        delete[] codeBuffer;
        VirtualFreeEx(procData->hProcess, state->hookCode, 0, MEM_RELEASE);
        VirtualFreeEx(procData->hProcess, state->sharedMemory, 0, MEM_RELEASE);
        delete state;
        return NEXUS_ERROR_UNKNOWN;
    }

    if (!WriteProcessMemory(procData->hProcess, state->hookCode,
                           codeBuffer, codeSize, &bytesWritten)) {
        delete[] codeBuffer;
        VirtualFreeEx(procData->hProcess, state->hookCode, 0, MEM_RELEASE);
        VirtualFreeEx(procData->hProcess, state->sharedMemory, 0, MEM_RELEASE);
        delete state;
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    delete[] codeBuffer;
    FlushInstructionCache(procData->hProcess, state->hookCode, codeSize);

    state->initialized = true;
    state->isEnabled = false;
    *speedhack = state;

    return NEXUS_OK;
}

NEXUS_API void Nexus_SpeedhackDestroy(NexusSpeedhackHandle speedhack) {
    if (!speedhack) return;

    auto* state = static_cast<SpeedhackState*>(speedhack);

    if (state->isEnabled) {
        Nexus_SpeedhackSetEnabled(speedhack, 0);
    }

    if (state->hookCode && state->process && state->process->hProcess) {
        VirtualFreeEx(state->process->hProcess, state->hookCode, 0, MEM_RELEASE);
    }
    if (state->sharedMemory && state->process && state->process->hProcess) {
        VirtualFreeEx(state->process->hProcess, state->sharedMemory, 0, MEM_RELEASE);
    }

    delete state;
}

NEXUS_API NexusResult Nexus_SpeedhackSetSpeed(NexusSpeedhackHandle speedhack, double speed) {
    if (!speedhack) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* state = static_cast<SpeedhackState*>(speedhack);
    if (!state->initialized) return NEXUS_ERROR_INVALID_HANDLE;

    if (speed < 0.01) speed = 0.01;
    if (speed > 100.0) speed = 100.0;

    SIZE_T bytesWritten;
    WriteProcessMemory(state->process->hProcess, state->sharedMemory,
                      &speed, sizeof(speed), &bytesWritten);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SpeedhackGetSpeed(NexusSpeedhackHandle speedhack, double* speed) {
    if (!speedhack || !speed) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* state = static_cast<SpeedhackState*>(speedhack);
    if (!state->initialized) return NEXUS_ERROR_INVALID_HANDLE;

    SIZE_T bytesRead;
    ReadProcessMemory(state->process->hProcess, state->sharedMemory,
                     speed, sizeof(double), &bytesRead);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SpeedhackSetEnabled(NexusSpeedhackHandle speedhack, uint32_t enable) {
    if (!speedhack) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* state = static_cast<SpeedhackState*>(speedhack);
    if (!state->initialized) return NEXUS_ERROR_INVALID_HANDLE;

    bool is32Bit = state->process->is32Bit;
    SIZE_T bytesWritten;

    if (enable && !state->isEnabled) {
        LARGE_INTEGER currentQPC;
        QueryPerformanceCounter(&currentQPC);

        SpeedhackSharedData sharedData;
        SIZE_T bytesRead;
        ReadProcessMemory(state->process->hProcess, state->sharedMemory,
                         &sharedData, sizeof(sharedData), &bytesRead);

        sharedData.enabled = 1;
        sharedData.initialQPC = currentQPC.QuadPart;
        sharedData.virtualOffset = 0;

        WriteProcessMemory(state->process->hProcess, state->sharedMemory,
                          &sharedData, sizeof(sharedData), &bytesWritten);

        uint8_t hookJump[16];
        size_t jumpSize;

        if (is32Bit) {
            hookJump[0] = 0xE9;
            uint32_t hookAddr = static_cast<uint32_t>(reinterpret_cast<uint64_t>(state->hookCode));
            uint32_t jumpFrom = static_cast<uint32_t>(state->qpcAddressInTarget + 5);
            int32_t relOffset = hookAddr - jumpFrom;
            memcpy(&hookJump[1], &relOffset, 4);
            jumpSize = 5;
        } else {
            hookJump[0] = 0x48;
            hookJump[1] = 0xB8;
            uint64_t hookAddr = reinterpret_cast<uint64_t>(state->hookCode);
            memcpy(&hookJump[2], &hookAddr, 8);
            hookJump[10] = 0xFF;
            hookJump[11] = 0xE0;
            jumpSize = 12;
        }

        DWORD oldProtect;
        if (!VirtualProtectEx(state->process->hProcess,
                             reinterpret_cast<void*>(state->qpcAddressInTarget),
                             state->stolenBytesCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return NEXUS_ERROR_ACCESS_DENIED;
        }

        WriteProcessMemory(state->process->hProcess,
                          reinterpret_cast<void*>(state->qpcAddressInTarget),
                          hookJump, jumpSize, &bytesWritten);

        if (state->stolenBytesCount > jumpSize) {
            uint8_t nops[16];
            memset(nops, 0x90, sizeof(nops));
            WriteProcessMemory(state->process->hProcess,
                              reinterpret_cast<void*>(state->qpcAddressInTarget + jumpSize),
                              nops, state->stolenBytesCount - jumpSize, &bytesWritten);
        }

        VirtualProtectEx(state->process->hProcess,
                        reinterpret_cast<void*>(state->qpcAddressInTarget),
                        state->stolenBytesCount, oldProtect, &oldProtect);

        FlushInstructionCache(state->process->hProcess,
                             reinterpret_cast<void*>(state->qpcAddressInTarget),
                             state->stolenBytesCount);

        state->isEnabled = true;
    }
    else if (!enable && state->isEnabled) {
        DWORD oldProtect;
        VirtualProtectEx(state->process->hProcess,
                        reinterpret_cast<void*>(state->qpcAddressInTarget),
                        state->stolenBytesCount, PAGE_EXECUTE_READWRITE, &oldProtect);

        WriteProcessMemory(state->process->hProcess,
                          reinterpret_cast<void*>(state->qpcAddressInTarget),
                          state->originalBytes, state->stolenBytesCount, &bytesWritten);

        VirtualProtectEx(state->process->hProcess,
                        reinterpret_cast<void*>(state->qpcAddressInTarget),
                        state->stolenBytesCount, oldProtect, &oldProtect);

        FlushInstructionCache(state->process->hProcess,
                             reinterpret_cast<void*>(state->qpcAddressInTarget),
                             state->stolenBytesCount);

        uint32_t disabled = 0;
        void* enabledAddr = reinterpret_cast<uint8_t*>(state->sharedMemory) + 8;
        WriteProcessMemory(state->process->hProcess, enabledAddr,
                          &disabled, sizeof(disabled), &bytesWritten);

        state->isEnabled = false;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SpeedhackGetStatus(NexusSpeedhackHandle speedhack, NexusSpeedhackStatus* status) {
    if (!speedhack || !status) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* state = static_cast<SpeedhackState*>(speedhack);
    if (!state->initialized) return NEXUS_ERROR_INVALID_HANDLE;

    SpeedhackSharedData sharedData;
    SIZE_T bytesRead;
    ReadProcessMemory(state->process->hProcess, state->sharedMemory,
                     &sharedData, sizeof(sharedData), &bytesRead);

    status->isActive = state->isEnabled ? 1 : 0;
    status->method = state->method;
    status->currentSpeed = sharedData.speedMultiplier;
    status->hookCount = sharedData.hookCount;
    status->baseTime = sharedData.initialQPC;

    return NEXUS_OK;
}
