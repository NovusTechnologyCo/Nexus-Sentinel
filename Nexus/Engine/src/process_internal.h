/**
 * @file process_internal.h
 * @brief Internal header shared by process.cpp and process_thread.cpp.
 *
 * Defines the NexusProcessHandleData structure (opaque handle backing),
 * validation magic numbers, and common Win32/TlHelp32 includes used
 * by both the process and thread operation source files.
 */

#pragma once

#include "nexus_api.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <mutex>

/* Handle validation magic number */
#define NEXUS_PROCESS_HANDLE_MAGIC 0x4E585053  /* 'NXPS' */
#define NEXUS_PROCESS_HANDLE_FREED 0xDEADBEEF

/* Internal process handle structure */
struct NexusProcessHandleData {
    uint32_t magic;              /* Validation magic number */
    HANDLE hProcess;
    DWORD pid;
    BOOL is32Bit;
    NexusProcessAccess requestedAccess;  /* What was originally requested */
    NexusProcessAccess actualAccess;     /* What was actually granted */
};
