/**
 * @file child_inject.cpp
 * @brief Child process propagation via NtCreateUserProcess hook and Early Bird APC
 *
 * Automatically injects the NexusApiHook DLL into child processes so that
 * API monitoring propagates to process trees. The mechanism:
 *
 * 1. Hooks ntdll!NtCreateUserProcess via MinHook (installed after the main
 *    hook engine is initialized)
 * 2. When a child process is created, forces the initial thread suspended
 *    (THREAD_CREATE_FLAGS_CREATE_SUSPENDED)
 * 3. Allocates RWX memory in the child and writes a custom APC shellcode
 *    that calls LoadLibraryW(dllPath), creates a NexusHookReady_{PID} event,
 *    and waits for it
 * 4. Queues the APC to the child's initial thread via NtQueueApcThread
 * 5. Resumes the thread if the original caller didn't request suspended
 *
 * The APC shellcode runs before the child's entry point. The DLL's worker
 * thread signals the ready event after hooks are installed, allowing the
 * entry point to proceed with all hooks active.
 *
 * @note kernel32.dll ASLR base is identical across all processes on the same
 *       boot, so LoadLibraryW/CreateEventW addresses resolved in the parent
 *       are valid in the child.
 *
 * @see child_inject.h  Public API
 */

#include "child_inject.h"
#include "protocol.h"
#include "pipe_client.h"
#include <MinHook.h>
#include <stdio.h>
#include <string.h>

// DbgLog is defined in dllmain.cpp
extern "C" void DbgLog(const char* fmt, ...);

// ---- NtCreateUserProcess typedef ----
// 11 parameters. We use void* for opaque kernel types since we just pass through.

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)

typedef NTSTATUS (NTAPI *PFN_NtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    void* ProcessObjectAttributes,
    void* ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    void* ProcessParameters,
    void* CreateInfo,
    void* AttributeList
);

// NtQueueApcThread — queues a user-mode APC to a thread
typedef NTSTATUS (NTAPI *PFN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    void* ApcRoutine,
    void* ApcArgument1,
    void* ApcArgument2,
    void* ApcArgument3
);

// ---- State ----

static PFN_NtCreateUserProcess g_pOrigNtCreateUserProcess = NULL;
static PFN_NtQueueApcThread g_pNtQueueApcThread = NULL;
static void* g_pNtCreateUserProcessTarget = NULL;  // For MH_DisableHook

static wchar_t g_dllPath[MAX_PATH] = {0};
static volatile bool g_enabled = false;
static bool g_initialized = false;

// ---- APC Shellcode Layout ----
// Memory layout in child process (1024 bytes total):
//   [0x000] shellcode (~105 bytes)
//   [0x100] dllPath (wchar_t[], null-terminated, up to MAX_PATH*2 bytes)
//   [0x300] eventName (wchar_t[], null-terminated, up to 256 bytes)
//
// APC routine signature: void ApcRoutine(arg1=dllPath, arg2=eventName, arg3=NULL)
//   rcx = &dllPath, rdx = &eventName, r8 = NULL
//
// The shellcode CREATES a named event (NexusHookReady_{pid}) in the CHILD process,
// then waits on it. The DLL's WorkerThread signals this event after hooks are installed.
// Key: the event is created by the child's APC (not the parent), so it survives
// even if the parent process exits before the child is ready.

#define CHILD_ALLOC_SIZE    0x400
#define DLLPATH_OFFSET      0x100
#define EVENTNAME_OFFSET    0x300

#ifdef _M_X64

// Shellcode bytes with placeholders for 4 function addresses.
static const uint8_t APC_SHELLCODE_TEMPLATE[] = {
    // sub rsp, 0x38
    0x48, 0x83, 0xEC, 0x38,
    // mov [rsp+0x30], rdx   (save eventName ptr)
    0x48, 0x89, 0x54, 0x24, 0x30,

    // --- LoadLibraryW(rcx=dllPath) ---
    // mov rax, <LoadLibraryW>       [addr at offset 11..18]
    0x48, 0xB8,  0,0,0,0, 0,0,0,0,
    // call rax
    0xFF, 0xD0,
    // test rax, rax  (if DLL load failed, skip wait entirely)
    0x48, 0x85, 0xC0,
    // jz .done                      [offset 25 = relative jump]
    0x74, 0x00,

    // --- CreateEventW(NULL, TRUE, FALSE, eventName) ---
    // xor ecx, ecx          (lpSecurityAttributes = NULL)
    0x31, 0xC9,
    // mov edx, 1             (bManualReset = TRUE)
    0xBA, 0x01, 0x00, 0x00, 0x00,
    // xor r8d, r8d           (bInitialState = FALSE)
    0x45, 0x31, 0xC0,
    // mov r9, [rsp+0x30]     (lpName = eventName)
    0x4C, 0x8B, 0x4C, 0x24, 0x30,
    // mov rax, <CreateEventW>       [addr at offset 43..50]
    0x48, 0xB8,  0,0,0,0, 0,0,0,0,
    // call rax
    0xFF, 0xD0,
    // test rax, rax
    0x48, 0x85, 0xC0,
    // jz .done                      [offset 57 = relative jump]
    0x74, 0x00,

    // --- WaitForSingleObject(hEvent, 30000) ---
    // mov [rsp+0x30], rax  (save hEvent)
    0x48, 0x89, 0x44, 0x24, 0x30,
    // mov rcx, rax
    0x48, 0x89, 0xC1,
    // mov edx, 30000  (0x7530)
    0xBA, 0x30, 0x75, 0x00, 0x00,
    // mov rax, <WaitForSingleObject> [addr at offset 73..80]
    0x48, 0xB8,  0,0,0,0, 0,0,0,0,
    // call rax
    0xFF, 0xD0,

    // --- CloseHandle(hEvent) ---
    // mov rcx, [rsp+0x30]
    0x48, 0x8B, 0x4C, 0x24, 0x30,
    // mov rax, <CloseHandle>        [addr at offset 90..97]
    0x48, 0xB8,  0,0,0,0, 0,0,0,0,
    // call rax
    0xFF, 0xD0,

    // .done:
    // add rsp, 0x38
    0x48, 0x83, 0xC4, 0x38,
    // ret
    0xC3,
};

// Offsets into APC_SHELLCODE_TEMPLATE for patching
#define SC_OFF_LOADLIBRARYW         11
#define SC_OFF_JZ_LOADFAIL          25
#define SC_OFF_CREATEEVENTW         43
#define SC_OFF_JZ_CREATEFAIL        57
#define SC_OFF_WAITFORSINGLEOBJECT  73
#define SC_OFF_CLOSEHANDLE          90
#define SC_DONE_OFFSET              100

static_assert(sizeof(APC_SHELLCODE_TEMPLATE) == 105, "Shellcode size mismatch");

#endif // _M_X64 (APC shellcode template and defines)

/**
 * @brief Inject the hook DLL into a child process via APC shellcode
 *
 * Allocates RWX memory in the child, writes the patched APC shellcode
 * along with the DLL path and event name, then queues the APC to the
 * child's initial thread.
 *
 * @param[in] hProcess  Handle to the child process
 * @param[in] hThread   Handle to the child's initial thread
 * @param[in] childPid  Child process ID (for event naming)
 * @return true if the APC was queued successfully
 */
static bool InjectIntoChild(HANDLE hProcess, HANDLE hThread, DWORD childPid)
{
#ifndef _M_X64
    // x86 APC shellcode is not implemented. Child injection requires x64.
    (void)hProcess; (void)hThread; (void)childPid;
    DbgLog("ChildInject: x86 APC shellcode not implemented, skipping injection for PID %u", childPid);
    return false;
#else
    // Step 1: Build wide-string event name for shellcode data.
    // The APC shellcode will CREATE this event in the child process (not the parent).
    wchar_t eventNameW[256];
    swprintf_s(eventNameW, 256, L"NexusHookReady_%u", childPid);
    int eventNameWLen = (int)wcslen(eventNameW) + 1; // include null terminator

    // Step 2: Resolve kernel32 function addresses (same ASLR base in all processes)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        DbgLog("ChildInject: GetModuleHandle(kernel32) failed");
        return false;
    }

    uintptr_t pLoadLibraryW = (uintptr_t)GetProcAddress(hKernel32, "LoadLibraryW");
    uintptr_t pCreateEventW = (uintptr_t)GetProcAddress(hKernel32, "CreateEventW");
    uintptr_t pWaitForSingleObject = (uintptr_t)GetProcAddress(hKernel32, "WaitForSingleObject");
    uintptr_t pCloseHandle = (uintptr_t)GetProcAddress(hKernel32, "CloseHandle");

    if (!pLoadLibraryW || !pCreateEventW || !pWaitForSingleObject || !pCloseHandle)
    {
        DbgLog("ChildInject: Failed to resolve kernel32 functions");
        return false;
    }

    // Step 3: Allocate RWX memory in child process
    void* remoteMem = VirtualAllocEx(hProcess, NULL, CHILD_ALLOC_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        DbgLog("ChildInject: VirtualAllocEx failed, err=%u", GetLastError());
        return false;
    }

    DbgLog("ChildInject: Allocated 0x%X bytes at %p in child PID %u",
        CHILD_ALLOC_SIZE, remoteMem, childPid);

    // Step 4: Build shellcode with patched addresses
    uint8_t shellcode[sizeof(APC_SHELLCODE_TEMPLATE)];
    memcpy(shellcode, APC_SHELLCODE_TEMPLATE, sizeof(shellcode));

    // Patch function addresses
    *(uintptr_t*)(shellcode + SC_OFF_LOADLIBRARYW) = pLoadLibraryW;
    *(uintptr_t*)(shellcode + SC_OFF_CREATEEVENTW) = pCreateEventW;
    *(uintptr_t*)(shellcode + SC_OFF_WAITFORSINGLEOBJECT) = pWaitForSingleObject;
    *(uintptr_t*)(shellcode + SC_OFF_CLOSEHANDLE) = pCloseHandle;

    // Patch jz offsets (relative to next instruction)
    shellcode[SC_OFF_JZ_LOADFAIL] = (uint8_t)(SC_DONE_OFFSET - (SC_OFF_JZ_LOADFAIL + 1));
    shellcode[SC_OFF_JZ_CREATEFAIL] = (uint8_t)(SC_DONE_OFFSET - (SC_OFF_JZ_CREATEFAIL + 1));

    // Step 5: Build the full memory block (shellcode + data)
    uint8_t block[CHILD_ALLOC_SIZE] = {0};
    memcpy(block, shellcode, sizeof(shellcode));

    // DLL path at DLLPATH_OFFSET (wide string, null-terminated)
    size_t dllPathBytes = (wcslen(g_dllPath) + 1) * sizeof(wchar_t);
    if (dllPathBytes > (EVENTNAME_OFFSET - DLLPATH_OFFSET))
    {
        DbgLog("ChildInject: DLL path too long");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    memcpy(block + DLLPATH_OFFSET, g_dllPath, dllPathBytes);

    // Event name at EVENTNAME_OFFSET (wide string, null-terminated)
    size_t eventNameBytes = eventNameWLen * sizeof(wchar_t);
    if (eventNameBytes > (CHILD_ALLOC_SIZE - EVENTNAME_OFFSET))
    {
        DbgLog("ChildInject: Event name too long");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    memcpy(block + EVENTNAME_OFFSET, eventNameW, eventNameBytes);

    // Step 6: Write the block to child process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, block, CHILD_ALLOC_SIZE, &written))
    {
        DbgLog("ChildInject: WriteProcessMemory failed, err=%u", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    FlushInstructionCache(hProcess, remoteMem, CHILD_ALLOC_SIZE);

    // Step 7: Queue APC to child's initial thread
    void* shellcodeAddr = remoteMem;
    void* dllPathAddr = (uint8_t*)remoteMem + DLLPATH_OFFSET;
    void* eventNameAddr = (uint8_t*)remoteMem + EVENTNAME_OFFSET;

    NTSTATUS apcStatus = g_pNtQueueApcThread(
        hThread, shellcodeAddr, dllPathAddr, eventNameAddr, NULL);

    if (apcStatus != STATUS_SUCCESS)
    {
        DbgLog("ChildInject: NtQueueApcThread failed, NTSTATUS=0x%08X", apcStatus);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    DbgLog("ChildInject: APC queued successfully for child PID %u", childPid);
    return true;
#endif // _M_X64
}

/**
 * @brief Hooked NtCreateUserProcess that injects hooks into child processes
 *
 * Forces the child thread suspended, calls the original NtCreateUserProcess,
 * injects the DLL via APC, notifies the host about the new child, and
 * resumes the thread if the caller didn't originally request suspended.
 * Pass-through when propagation is disabled or no DLL path is set.
 */
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

static NTSTATUS NTAPI HookedNtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    void* ProcessObjectAttributes,
    void* ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    void* ProcessParameters,
    void* CreateInfo,
    void* AttributeList)
{
    if (!g_enabled || g_dllPath[0] == L'\0')
    {
        // Propagation disabled — pass through
        return g_pOrigNtCreateUserProcess(
            ProcessHandle, ThreadHandle,
            ProcessDesiredAccess, ThreadDesiredAccess,
            ProcessObjectAttributes, ThreadObjectAttributes,
            ProcessFlags, ThreadFlags,
            ProcessParameters, CreateInfo, AttributeList);
    }

    // Save original thread flags and force suspended
    ULONG originalThreadFlags = ThreadFlags;
    ThreadFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    // Call original NtCreateUserProcess
    NTSTATUS status = g_pOrigNtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);

    if (status != STATUS_SUCCESS)
        return status;

    // Get child PID
    DWORD childPid = GetProcessId(*ProcessHandle);
    DbgLog("ChildInject: NtCreateUserProcess intercepted, child PID=%u", childPid);

    // Inject DLL into child via APC
    bool injected = InjectIntoChild(*ProcessHandle, *ThreadHandle, childPid);

    if (injected)
    {
        // Notify host about the new child
        MsgChildCreated msg;
        msg.childPid = childPid;
        PipeClient_SendMessage(MSG_CHILD_CREATED, &msg, sizeof(msg));
        DbgLog("ChildInject: MSG_CHILD_CREATED sent for PID %u", childPid);
    }
    else
    {
        DbgLog("ChildInject: Injection failed for PID %u, child will run without hooks", childPid);
    }

    // If the original caller didn't want suspended, resume the thread
    if (!(originalThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED))
    {
        ResumeThread(*ThreadHandle);
    }

    return status;
}

// ---- Public API ----

bool ChildInject_Initialize(void)
{
    if (g_initialized) return true;

    // Resolve NtQueueApcThread from ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        DbgLog("ChildInject: GetModuleHandle(ntdll) failed");
        return false;
    }

    g_pNtQueueApcThread = (PFN_NtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!g_pNtQueueApcThread)
    {
        DbgLog("ChildInject: NtQueueApcThread not found in ntdll");
        return false;
    }

    // Resolve NtCreateUserProcess for hooking
    g_pNtCreateUserProcessTarget = (void*)GetProcAddress(hNtdll, "NtCreateUserProcess");
    if (!g_pNtCreateUserProcessTarget)
    {
        DbgLog("ChildInject: NtCreateUserProcess not found in ntdll");
        return false;
    }

    // Install hook via MinHook (already initialized by HookEngine_Initialize)
    MH_STATUS mhStatus = MH_CreateHook(
        g_pNtCreateUserProcessTarget,
        (void*)HookedNtCreateUserProcess,
        (void**)&g_pOrigNtCreateUserProcess);

    if (mhStatus != MH_OK)
    {
        DbgLog("ChildInject: MH_CreateHook failed, status=%d", mhStatus);
        return false;
    }

    mhStatus = MH_EnableHook(g_pNtCreateUserProcessTarget);
    if (mhStatus != MH_OK)
    {
        DbgLog("ChildInject: MH_EnableHook failed, status=%d", mhStatus);
        MH_RemoveHook(g_pNtCreateUserProcessTarget);
        return false;
    }

    g_initialized = true;
    DbgLog("ChildInject: NtCreateUserProcess hooked successfully (enabled=%d, dllPath=%S)",
        (int)g_enabled, g_dllPath);
    return true;
}

void ChildInject_Shutdown(void)
{
    if (!g_initialized) return;

    // Disable and remove the hook
    if (g_pNtCreateUserProcessTarget)
    {
        MH_DisableHook(g_pNtCreateUserProcessTarget);
        MH_RemoveHook(g_pNtCreateUserProcessTarget);
    }

    g_pOrigNtCreateUserProcess = NULL;
    g_pNtCreateUserProcessTarget = NULL;
    g_enabled = false;
    g_initialized = false;

    DbgLog("ChildInject: Shutdown complete");
}

void ChildInject_SetDllPath(const wchar_t* path)
{
    if (!path)
    {
        g_dllPath[0] = L'\0';
        return;
    }
    wcsncpy_s(g_dllPath, MAX_PATH, path, _TRUNCATE);
    DbgLog("ChildInject: DLL path set to %S", g_dllPath);
}

void ChildInject_SetEnabled(bool enabled)
{
    g_enabled = enabled;
    DbgLog("ChildInject: Propagation %s", enabled ? "ENABLED" : "DISABLED");
}
