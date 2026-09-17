/**
 * @file nexus.cpp
 * @brief Engine lifecycle, version query, error strings, and heap utilities.
 *
 * Implements Nexus_Initialize / Nexus_Shutdown (idempotent via atomic flag),
 * Nexus_GetVersion, Nexus_Free, and Nexus_GetErrorString.
 * This is the entry point for the engine DLL; all subsystem init/teardown
 * will be wired in through this file.
 */

#include "nexus_api.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <atomic>

/* Internal state */
static std::atomic<bool> g_initialized{false};

/* ============================================================================
 * Version & Initialization
 * ============================================================================ */

NEXUS_API void Nexus_GetVersion(int* major, int* minor, int* patch) {
    if (major) *major = NEXUS_VERSION_MAJOR;
    if (minor) *minor = NEXUS_VERSION_MINOR;
    if (patch) *patch = NEXUS_VERSION_PATCH;
}

NEXUS_API NexusResult Nexus_Initialize(void) {
    if (g_initialized.exchange(true)) {
        return NEXUS_OK;  /* Already initialized */
    }

    /* Future: Initialize subsystems here */

    return NEXUS_OK;
}

NEXUS_API void Nexus_Shutdown(void) {
    if (!g_initialized.exchange(false)) {
        return;  /* Not initialized */
    }

    /* Future: Cleanup subsystems here */
}

/* ============================================================================
 * Utility
 * ============================================================================ */

NEXUS_API void Nexus_Free(void* ptr) {
    if (ptr) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }
}

NEXUS_API const char* Nexus_GetErrorString(NexusResult result) {
    switch (result) {
        case NEXUS_OK:                        return "Success";
        case NEXUS_ERROR_INVALID_HANDLE:      return "Invalid handle";
        case NEXUS_ERROR_INVALID_PARAMETER:   return "Invalid parameter";
        case NEXUS_ERROR_ACCESS_DENIED:       return "Access denied";
        case NEXUS_ERROR_NOT_FOUND:           return "Not found";
        case NEXUS_ERROR_INSUFFICIENT_BUFFER: return "Insufficient buffer";
        case NEXUS_ERROR_PARTIAL_READ:        return "Partial read";
        case NEXUS_ERROR_PARTIAL_WRITE:       return "Partial write";
        default:                              return "Unknown error";
    }
}
