/**
 * @file pe_internal.h
 * @brief Internal header shared by pe.cpp and pe_exports.cpp.
 */

#pragma once

#include "nexus_api.h"
#include "process_internal.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <vector>
#include <string>
#include <cstring>

/* Maximum reasonable PE header offset (prevent integer overflow attacks) */
static const LONG MAX_E_LFANEW = 0x10000000;  /* 256MB */

/* Maximum number of exports/imports to process (prevent DoS) */
static const DWORD MAX_EXPORTS = 1000000;
static const DWORD MAX_IMPORTS = 1000000;
static const DWORD MAX_IMPORT_DLLS = 10000;

/* ============================================================================
 * Cross-File Function Prototypes (defined in pe.cpp)
 * ============================================================================ */

bool PeReadProcessMem(HANDLE process, uint64_t address, void* buffer, size_t size);
bool PeReadProcessString(HANDLE process, uint64_t address, char* buffer, size_t bufferSize);
bool PeGetHeaders(HANDLE process, uint64_t moduleBase, bool& is64Bit,
                  IMAGE_DOS_HEADER& dosHeader, IMAGE_NT_HEADERS64& ntHeaders64,
                  IMAGE_NT_HEADERS32& ntHeaders32);
