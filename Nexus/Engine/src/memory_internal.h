/**
 * @file memory_internal.h
 * @brief Internal header shared by memory.cpp, memory_typed.cpp, and memory_cache.cpp.
 *
 * Forward-declares the NexusProcessHandleData structure and includes
 * common Win32 headers needed by all memory operation source files.
 */

#pragma once

#include "nexus_api.h"

#include <Windows.h>
#include <Psapi.h>

/* Forward declaration of internal handle structure (must match process.cpp) */
struct NexusProcessHandleData {
    uint32_t magic;              /* Validation magic number */
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;  /* What was originally requested */
    NexusProcessAccess actualAccess;     /* What was actually granted */
};
