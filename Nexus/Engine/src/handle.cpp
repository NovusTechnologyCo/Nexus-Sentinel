/**
 * @file handle.cpp
 * @brief Handle enumeration via NtQuerySystemInformation and NtQueryObject.
 *
 * Enumerates all handles in the system, filters to the target process,
 * duplicates each handle into the engine process, and queries object
 * type/name information to populate NexusHandleInfo results.
 */

#include "nexus_api.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <string>

// Internal process context structure (must match process.cpp)
struct ProcessContext {
    HANDLE processHandle;
    DWORD processId;
    bool is32Bit;
};

// NT API definitions not in winternl.h
typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX_V2, *PSYSTEM_HANDLE_INFORMATION_EX_V2;

// Object information class values (match SDK definitions)
#define ObjBasicInfo 0
#define ObjNameInfo 1
#define ObjTypeInfo 2

// Function pointers for NT API
typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* PNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* PNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

// Static function pointers
static PNtQuerySystemInformation pNtQuerySystemInformation = nullptr;
static PNtQueryObject pNtQueryObject = nullptr;
static PNtDuplicateObject pNtDuplicateObject = nullptr;
static bool s_ntApiInitialized = false;

static bool InitNtApi() {
    if (s_ntApiInitialized) {
        return pNtQuerySystemInformation != nullptr;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        s_ntApiInitialized = true;
        return false;
    }

    pNtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQueryObject = (PNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    pNtDuplicateObject = (PNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");

    s_ntApiInitialized = true;
    return pNtQuerySystemInformation != nullptr;
}

// Get object type name for a duplicated handle
static bool GetObjectTypeName(HANDLE handle, wchar_t* typeName, size_t typeNameLen) {
    if (!pNtQueryObject) return false;

    ULONG size = 0;
    NTSTATUS status = pNtQueryObject(handle, ObjTypeInfo, nullptr, 0, &size);

    if (size == 0) {
        size = 256;
    }

    std::vector<uint8_t> buffer(size + 256);
    status = pNtQueryObject(handle, ObjTypeInfo, buffer.data(), (ULONG)buffer.size(), &size);

    if (status >= 0) {
        auto* typeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)buffer.data();
        if (typeInfo->TypeName.Length > 0 && typeInfo->TypeName.Buffer) {
            size_t copyLen = min((size_t)typeInfo->TypeName.Length / sizeof(wchar_t), typeNameLen - 1);
            wcsncpy_s(typeName, typeNameLen, typeInfo->TypeName.Buffer, copyLen);
            typeName[copyLen] = L'\0';
            return true;
        }
    }

    typeName[0] = L'\0';
    return false;
}

// Get object name for a duplicated handle
static bool GetObjectName(HANDLE handle, wchar_t* objectName, size_t objectNameLen) {
    if (!pNtQueryObject) return false;

    ULONG size = 0;
    NTSTATUS status = pNtQueryObject(handle, ObjNameInfo, nullptr, 0, &size);

    if (size == 0) {
        size = 1024;
    }

    std::vector<uint8_t> buffer(size + 512);
    status = pNtQueryObject(handle, ObjNameInfo, buffer.data(), (ULONG)buffer.size(), &size);

    if (status >= 0) {
        auto* nameInfo = (UNICODE_STRING*)buffer.data();
        if (nameInfo->Length > 0 && nameInfo->Buffer) {
            size_t copyLen = min((size_t)nameInfo->Length / sizeof(wchar_t), objectNameLen - 1);
            wcsncpy_s(objectName, objectNameLen, nameInfo->Buffer, copyLen);
            objectName[copyLen] = L'\0';
            return true;
        }
    }

    objectName[0] = L'\0';
    return false;
}

NEXUS_API NexusResult Nexus_EnumerateHandles(
    NexusProcessHandle handle,
    NexusHandleInfo* buffer,
    size_t bufferCount,
    size_t* handleCount
) {
    if (!handle || !handleCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (!InitNtApi()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    auto* ctx = static_cast<ProcessContext*>(handle);
    DWORD targetPid = ctx->processId;

    // Query system handle information
    ULONG bufferSize = 1024 * 1024; // Start with 1MB
    std::vector<uint8_t> sysInfoBuffer;
    NTSTATUS status;

    do {
        sysInfoBuffer.resize(bufferSize);
        status = pNtQuerySystemInformation(
            SystemExtendedHandleInformation,
            sysInfoBuffer.data(),
            bufferSize,
            &bufferSize
        );

        if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            bufferSize *= 2;
            if (bufferSize > 256 * 1024 * 1024) { // Max 256MB
                return NEXUS_ERROR_UNKNOWN;
            }
        }
    } while (status == 0xC0000004);

    if (status < 0) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    auto* handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX_V2)sysInfoBuffer.data();

    // Count handles for target process
    size_t count = 0;
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].UniqueProcessId == targetPid) {
            count++;
        }
    }

    *handleCount = count;

    if (!buffer || bufferCount == 0) {
        return NEXUS_OK;
    }

    if (bufferCount < count) {
        // Still fill what we can
    }

    // Fill buffer with handle information
    size_t filled = 0;
    HANDLE currentProcess = GetCurrentProcess();

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles && filled < bufferCount; i++) {
        if (handleInfo->Handles[i].UniqueProcessId != targetPid) {
            continue;
        }

        NexusHandleInfo& info = buffer[filled];
        info.handle = handleInfo->Handles[i].HandleValue;
        info.objectTypeIndex = handleInfo->Handles[i].ObjectTypeIndex;
        info.grantedAccess = handleInfo->Handles[i].GrantedAccess;
        info.typeName[0] = L'\0';
        info.objectName[0] = L'\0';

        // Try to duplicate handle to get type and name
        HANDLE dupHandle = nullptr;
        if (pNtDuplicateObject) {
            NTSTATUS dupStatus = pNtDuplicateObject(
                ctx->processHandle,
                (HANDLE)info.handle,
                currentProcess,
                &dupHandle,
                0,
                0,
                0 // DUPLICATE_SAME_ACCESS
            );

            if (dupStatus >= 0 && dupHandle) {
                GetObjectTypeName(dupHandle, info.typeName, sizeof(info.typeName) / sizeof(wchar_t));
                GetObjectName(dupHandle, info.objectName, sizeof(info.objectName) / sizeof(wchar_t));
                CloseHandle(dupHandle);
            }
        }

        filled++;
    }

    if (bufferCount < count) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_GetHandleInfo(
    NexusProcessHandle handle,
    uint64_t targetHandle,
    NexusHandleInfo* info
) {
    if (!handle || !info) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (!InitNtApi() || !pNtDuplicateObject) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    auto* ctx = static_cast<ProcessContext*>(handle);

    info->handle = targetHandle;
    info->objectTypeIndex = 0;
    info->grantedAccess = 0;
    info->typeName[0] = L'\0';
    info->objectName[0] = L'\0';

    // Duplicate the handle to query it
    HANDLE dupHandle = nullptr;
    NTSTATUS status = pNtDuplicateObject(
        ctx->processHandle,
        (HANDLE)targetHandle,
        GetCurrentProcess(),
        &dupHandle,
        0,
        0,
        0 // DUPLICATE_SAME_ACCESS
    );

    if (status < 0 || !dupHandle) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    GetObjectTypeName(dupHandle, info->typeName, sizeof(info->typeName) / sizeof(wchar_t));
    GetObjectName(dupHandle, info->objectName, sizeof(info->objectName) / sizeof(wchar_t));

    CloseHandle(dupHandle);

    return NEXUS_OK;
}
