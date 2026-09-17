/**
 * @file injection_internal.h
 * @brief Internal header shared by injection.cpp and injection_manualmap.cpp.
 */

#pragma once

#include "nexus_api.h"
#include "process_internal.h"
#include <Windows.h>
#include <winternl.h>
#include <cstring>
#include <vector>
#include <fstream>

/* ============================================================================
 * NT API Types for NtCreateThreadEx (TitanEngine pattern)
 * ============================================================================ */

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList
);

/* Thread creation flags for NtCreateThreadEx */
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED    0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESC   0x00000010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK        0x00000020
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040
