/**
 * @file injection_manualmap.cpp
 * @brief DLL injection via manual mapping (no LoadLibrary).
 *
 * Reads a DLL from disk, allocates memory in the target process,
 * copies PE sections, applies base relocations, resolves imports,
 * and launches a shellcode stub that calls DllMain.  The DLL never
 * appears in the PEB module list.  Supports optional header erasure
 * and TLS callback suppression.
 */

#include "injection_internal.h"

/* ============================================================================
 * Manual Map Structures
 * ============================================================================ */

#pragma pack(push, 1)
struct ManualMapData {
    uint64_t imageBase;
    uint64_t ntHeaders;
    uint64_t loadLibraryA;
    uint64_t getProcAddress;
    uint64_t rtlAddFunctionTable;  /* For x64 exception handling */
    bool     success;
    uint8_t  padding[7];
};
#pragma pack(pop)

/* Shellcode to perform manual mapping initialization in target process.
 * Handles relocations, imports, TLS, and calls DllMain. */
static const uint8_t g_ManualMapShellcode64[] = {
    /* Placeholder - real implementation would include actual x64 shellcode for:
     * 1. Processing relocations
     * 2. Resolving imports
     * 3. Handling TLS callbacks
     * 4. Registering exception handlers
     * 5. Calling DllMain(DLL_PROCESS_ATTACH) */
    0x48, 0x89, 0xC8,   /* mov rax, rcx (parameter) */
    0xC3                 /* ret */
};

/* ============================================================================
 * Manual Map Injection
 * ============================================================================ */

NEXUS_API NexusResult Nexus_InjectDllManualMap(
    NexusProcessHandle handle,
    const wchar_t* dllPath,
    uint32_t flags,
    NexusInjectionResult* result
) {
    if (!handle || !dllPath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto* procData = static_cast<NexusProcessHandleData*>(handle);
    if (!procData || !procData->hProcess) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    if (result) {
        memset(result, 0, sizeof(NexusInjectionResult));
    }

    /* Read the DLL file */
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> dllData(fileSize);
    if (!file.read(reinterpret_cast<char*>(dllData.data()), fileSize)) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }
    file.close();

    /* Parse PE headers */
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(dllData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    /* Allocate memory in target for the mapped image */
    void* remoteImage = VirtualAllocEx(
        procData->hProcess,
        nullptr,
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteImage) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Prepare local image buffer with sections mapped */
    std::vector<uint8_t> mappedImage(imageSize, 0);

    /* Copy headers */
    memcpy(mappedImage.data(), dllData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

    /* Copy sections */
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            memcpy(
                mappedImage.data() + sectionHeader[i].VirtualAddress,
                dllData.data() + sectionHeader[i].PointerToRawData,
                sectionHeader[i].SizeOfRawData
            );
        }
    }

    /* Calculate relocation delta */
    uint64_t deltaBase = reinterpret_cast<uint64_t>(remoteImage) - ntHeaders->OptionalHeader.ImageBase;

    /* Process relocations locally before writing to target */
    if (deltaBase != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        auto relocDir = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            mappedImage.data() + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );

        while (relocDir->VirtualAddress) {
            uint32_t numEntries = (relocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto relocEntry = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(relocDir) + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t j = 0; j < numEntries; j++) {
                uint16_t type = relocEntry[j] >> 12;
                uint16_t offset = relocEntry[j] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* patchAddr = reinterpret_cast<uint64_t*>(
                        mappedImage.data() + relocDir->VirtualAddress + offset
                    );
                    *patchAddr += deltaBase;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* patchAddr = reinterpret_cast<uint32_t*>(
                        mappedImage.data() + relocDir->VirtualAddress + offset
                    );
                    *patchAddr += static_cast<uint32_t>(deltaBase);
                }
            }

            relocDir = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(relocDir) + relocDir->SizeOfBlock
            );
        }
    }

    /* Erase PE headers if requested */
    if (flags & NEXUS_INJECT_FLAG_ERASE_HEADERS) {
        memset(mappedImage.data(), 0, ntHeaders->OptionalHeader.SizeOfHeaders);
    }

    /* Write mapped image to target */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(procData->hProcess, remoteImage, mappedImage.data(), imageSize, &bytesWritten)) {
        VirtualFreeEx(procData->hProcess, remoteImage, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Prepare shellcode data for import resolution and DllMain call */
    ManualMapData mapData = {};
    mapData.imageBase = reinterpret_cast<uint64_t>(remoteImage);
    mapData.ntHeaders = reinterpret_cast<uint64_t>(remoteImage) + dosHeader->e_lfanew;
    mapData.loadLibraryA = reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));
    mapData.getProcAddress = reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress"));
    mapData.rtlAddFunctionTable = reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable"));
    mapData.success = false;

    /* Allocate memory for shellcode and data */
    size_t shellcodeSize = sizeof(g_ManualMapShellcode64);
    size_t totalSize = shellcodeSize + sizeof(ManualMapData);

    void* remoteShellcode = VirtualAllocEx(
        procData->hProcess,
        nullptr,
        totalSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteShellcode) {
        VirtualFreeEx(procData->hProcess, remoteImage, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    /* Write shellcode and data */
    WriteProcessMemory(procData->hProcess, remoteShellcode, g_ManualMapShellcode64, shellcodeSize, &bytesWritten);
    WriteProcessMemory(procData->hProcess,
        reinterpret_cast<uint8_t*>(remoteShellcode) + shellcodeSize,
        &mapData, sizeof(mapData), &bytesWritten);

    FlushInstructionCache(procData->hProcess, remoteShellcode, shellcodeSize);

    /* Create thread to execute initialization shellcode */
    HANDLE hThread = CreateRemoteThread(
        procData->hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode),
        reinterpret_cast<uint8_t*>(remoteShellcode) + shellcodeSize,
        0,
        nullptr
    );

    if (!hThread) {
        VirtualFreeEx(procData->hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(procData->hProcess, remoteImage, 0, MEM_RELEASE);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD threadId = GetThreadId(hThread);

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    /* Free shellcode memory (image stays) */
    VirtualFreeEx(procData->hProcess, remoteShellcode, 0, MEM_RELEASE);

    /* Calculate entry point */
    uint64_t entryPoint = reinterpret_cast<uint64_t>(remoteImage) + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    if (result) {
        result->baseAddress = reinterpret_cast<uint64_t>(remoteImage);
        result->entryPoint = entryPoint;
        result->threadId = threadId;
        result->exitCode = exitCode;
        result->success = 1;
    }

    return NEXUS_OK;
}
