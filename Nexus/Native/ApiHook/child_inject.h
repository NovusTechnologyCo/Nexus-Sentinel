/**
 * @file child_inject.h
 * @brief Child process hook propagation via NtCreateUserProcess interception
 *
 * Hooks NtCreateUserProcess to automatically inject the NexusApiHook DLL into
 * child processes using Early Bird APC injection. The DLL is loaded before
 * the child's entry point runs, ensuring API hooks are part of the process
 * baseline before any application or anti-cheat code initializes.
 *
 * Requires MinHook to be initialized (via HookEngine_Initialize) before
 * ChildInject_Initialize is called.
 *
 * @see child_inject.cpp  Implementation details and APC shellcode layout
 */
#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hook NtCreateUserProcess via MinHook. Must be called after HookEngine_Initialize
// (which calls MH_Initialize). Returns true on success.
bool ChildInject_Initialize(void);

// Unhook NtCreateUserProcess and clean up resources.
void ChildInject_Shutdown(void);

// Store the full path to the hook DLL for injection into child processes.
void ChildInject_SetDllPath(const wchar_t* path);

// Enable or disable child process injection.
void ChildInject_SetEnabled(bool enabled);

#ifdef __cplusplus
}
#endif
