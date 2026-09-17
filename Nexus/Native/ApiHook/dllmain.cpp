/**
 * @file dllmain.cpp
 * @brief DLL entry point and worker thread for NexusApiHook
 *
 * NexusApiHook.dll is injected into a target process (via LoadLibrary or
 * manual mapping) to monitor Windows API calls in real time. The DLL
 * follows a strict initialization sequence to avoid loader-lock deadlocks:
 *
 * **DllMain** (DLL_PROCESS_ATTACH):
 * - Detects injection method (LoadLibrary vs manual-map) via PEB module list
 * - Erases PE headers for manual-mapped injection (anti-detection)
 * - Spawns a worker thread immediately (no heavy work on loader lock)
 *
 * **WorkerThread** (8-step lifecycle):
 * 1. Connect to host's named pipe (\\.\pipe\NexusApiMonitor_{PID})
 * 2. Receive MSG_CONFIGURE with API hook list and parameter metadata
 * 3. Initialize HookEngine with capacity from config
 * 4. Parse config and register hooks (armed immediately with INT3/JMP)
 * 5. Send MSG_READY to host, then enable full event capture
 * 6. Initialize child process injection (NtCreateUserProcess hook)
 * 7. Wait for stop event (NexusApiMonitorStop_{PID}) or pipe disconnect
 * 8. Cleanup: disable hooks, shutdown engine, disconnect pipe
 *
 * **Debug Logging**: Uses ntdll NtWriteFile/NtFlushBuffersFile directly
 * to write to %TEMP%\NexusApiHook_{PID}.log, bypassing hooked kernel32
 * functions. A crash handler (SetUnhandledExceptionFilter) logs exception
 * details on any thread crash.
 *
 * @see hook_engine.h  Core hooking engine
 * @see pipe_client.h  Named pipe IPC
 * @see child_inject.h Child process propagation
 * @see protocol.h     Wire protocol definitions
 */

#include "protocol.h"
#include "pipe_client.h"
#include "hook_engine.h"
#include "hook_engine_internal.h"
#include "child_inject.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HMODULE g_hModule = NULL;
static HANDLE g_hWorkerThread = NULL;
static volatile bool g_running = false;
static bool g_isManualMapped = false;

/*
 * Debug logging subsystem.
 * Uses raw ntdll NtWriteFile/NtFlushBuffersFile to avoid triggering hooked
 * kernel32!WriteFile/FlushFileBuffers. After hooks are enabled, any kernel32
 * call from DbgLog would fire GenericDispatch and create infinite recursion.
 */
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

// ntdll I/O typedefs are in hook_engine_internal.h (PFN_NtWriteFile, PFN_NtFlushBuffersFile)
static PFN_NtWriteFile g_pNtWriteFile = NULL;
static PFN_NtFlushBuffersFile g_pNtFlushBuffersFile = NULL;

/**
 * @brief Write a formatted debug message to the per-process log file
 *
 * Safe to call from hooked code paths -- uses ntdll direct I/O to bypass
 * all kernel32 hooks. Appends a newline automatically. No-op if the log
 * file is not open.
 *
 * @param[in] fmt  printf-style format string
 * @param[in] ...  Format arguments
 */
extern "C" void DbgLog(const char* fmt, ...)
{
    if (g_hLogFile == INVALID_HANDLE_VALUE) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int len = vsprintf_s(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (len > 0)
    {
        buf[len] = '\n';
        buf[len + 1] = '\0';

        // Use ntdll direct to avoid triggering hooked kernel32!WriteFile
        if (g_pNtWriteFile)
        {
            HOOK_IO_STATUS_BLOCK iosb = {};
            g_pNtWriteFile(g_hLogFile, NULL, NULL, NULL, &iosb,
                buf, (ULONG)(len + 1), NULL, NULL);
            if (g_pNtFlushBuffersFile)
            {
                HOOK_IO_STATUS_BLOCK iosb2 = {};
                g_pNtFlushBuffersFile(g_hLogFile, &iosb2);
            }
        }
        else
        {
            DWORD written;
            WriteFile(g_hLogFile, buf, (DWORD)(len + 1), &written, NULL);
            FlushFileBuffers(g_hLogFile);
        }
    }
}

/**
 * @brief Unhandled exception filter for crash diagnostics
 *
 * Installed via SetUnhandledExceptionFilter during log initialization.
 * Catches exceptions from any thread and logs the exception code, faulting
 * address, and thread ID before passing to the default handler.
 *
 * @param[in] ep  Exception information
 * @return EXCEPTION_CONTINUE_SEARCH (always chains to next handler)
 */
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        char msg[512];
        int n = sprintf_s(msg, sizeof(msg),
            "!!! CRASH: ExceptionCode=0x%08X Address=0x%p TID=%u\n",
            ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress,
            GetCurrentThreadId());
        if (n > 0 && g_pNtWriteFile)
        {
            HOOK_IO_STATUS_BLOCK iosb = {};
            g_pNtWriteFile(g_hLogFile, NULL, NULL, NULL, &iosb, msg, (ULONG)n, NULL, NULL);
            HOOK_IO_STATUS_BLOCK iosb2 = {};
            if (g_pNtFlushBuffersFile) g_pNtFlushBuffersFile(g_hLogFile, &iosb2);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void DbgLogOpen(void)
{
    // Resolve ntdll direct I/O functions (bypass kernel32 hooks)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        g_pNtWriteFile = (PFN_NtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
        g_pNtFlushBuffersFile = (PFN_NtFlushBuffersFile)GetProcAddress(hNtdll, "NtFlushBuffersFile");
    }

    char path[MAX_PATH];
    DWORD tmpLen = GetTempPathA(MAX_PATH, path);
    if (tmpLen == 0) return;
    sprintf_s(path + tmpLen, MAX_PATH - tmpLen, "NexusApiHook_%u.log", GetCurrentProcessId());
    g_hLogFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // Install crash handler to catch exceptions from hooked threads
    SetUnhandledExceptionFilter(CrashFilter);

    DbgLog("=== NexusApiHook loaded in PID %u ===", GetCurrentProcessId());
    DbgLog("Injection method: %s (hModule=%p)", g_isManualMapped ? "MANUAL-MAP" : "LOADLIBRARY", g_hModule);
}

/**
 * @brief Parse a MSG_CONFIGURE payload and register hooks
 *
 * Deserializes the binary configuration sent by the host, extracting
 * module name, function name, parameter count, and per-parameter metadata
 * for each API to hook. Calls HookEngine_RegisterHook for each entry.
 *
 * @param[in]  payload          Raw MSG_CONFIGURE payload bytes
 * @param[in]  payloadLen       Length of payload
 * @param[out] outSuccessCount  Number of hooks successfully registered
 * @param[out] outFailCount     Number of hooks that failed to register
 * @param[out] outTotalRequested Total number of APIs in the config
 * @param[out] outConsumedLen   Bytes consumed from payload (for appended data)
 * @return true if the header was parsed successfully
 */
static bool ParseConfigure(const uint8_t* payload, uint32_t payloadLen,
    uint16_t* outSuccessCount, uint16_t* outFailCount, uint16_t* outTotalRequested,
    uint32_t* outConsumedLen)
{
    if (payloadLen < 2) return false;

    uint32_t offset = 0;
    uint16_t apiCount = *(uint16_t*)(payload + offset); offset += 2;

    *outTotalRequested = apiCount;
    *outSuccessCount = 0;
    *outFailCount = 0;

    for (uint16_t i = 0; i < apiCount; i++)
    {
        // Read module name
        if (offset + 2 > payloadLen) break;
        uint16_t modLen = *(uint16_t*)(payload + offset); offset += 2;
        if (offset + modLen > payloadLen) break;

        char moduleName[MAX_MODULE_NAME] = {0};
        uint16_t copyLen = modLen < (MAX_MODULE_NAME - 1) ? modLen : (MAX_MODULE_NAME - 1);
        memcpy(moduleName, payload + offset, copyLen);
        moduleName[copyLen] = '\0';
        offset += modLen;

        // Read function name
        if (offset + 2 > payloadLen) break;
        uint16_t funcLen = *(uint16_t*)(payload + offset); offset += 2;
        if (offset + funcLen > payloadLen) break;

        char funcName[MAX_FUNC_NAME] = {0};
        copyLen = funcLen < (MAX_FUNC_NAME - 1) ? funcLen : (MAX_FUNC_NAME - 1);
        memcpy(funcName, payload + offset, copyLen);
        funcName[copyLen] = '\0';
        offset += funcLen;

        // Read param count
        if (offset + 1 > payloadLen) break;
        uint8_t paramCount = payload[offset]; offset += 1;
        if (paramCount > MAX_PARAMS) paramCount = MAX_PARAMS;

        // Read per-param metadata
        ParamMeta params[MAX_PARAMS] = {0};
        for (uint8_t p = 0; p < paramCount; p++)
        {
            // flags
            if (offset + 1 > payloadLen) break;
            params[p].flags = payload[offset]; offset += 1;

            // name
            if (offset + 2 > payloadLen) break;
            uint16_t nameLen = *(uint16_t*)(payload + offset); offset += 2;
            if (offset + nameLen > payloadLen) break;
            copyLen = nameLen < (MAX_PARAM_NAME - 1) ? nameLen : (MAX_PARAM_NAME - 1);
            memcpy(params[p].name, payload + offset, copyLen);
            params[p].name[copyLen] = '\0';
            offset += nameLen;

            // type
            if (offset + 2 > payloadLen) break;
            uint16_t typeLen = *(uint16_t*)(payload + offset); offset += 2;
            if (offset + typeLen > payloadLen) break;
            copyLen = typeLen < (MAX_PARAM_NAME - 1) ? typeLen : (MAX_PARAM_NAME - 1);
            memcpy(params[p].type, payload + offset, copyLen);
            params[p].type[copyLen] = '\0';
            offset += typeLen;
        }

        // Register the hook
        int slot = HookEngine_RegisterHook(moduleName, funcName, paramCount, params);
        if (slot >= 0)
        {
            // Store the config index so events report the correct API to the host
            HookRegistration* reg = HookEngine_GetRegistration(slot);
            if (reg) reg->configIndex = i;
            (*outSuccessCount)++;
        }
        else
        {
            (*outFailCount)++;
        }
    }

    if (outConsumedLen) *outConsumedLen = offset;
    return true;
}

/**
 * @brief Signal the NexusHookReady event to unblock the child's entry point
 *
 * For APC-injected (LoadLibrary) child processes, the APC shellcode creates
 * a NexusHookReady_{PID} event and waits on it. This function signals that
 * event after hooks are fully installed, allowing the child's entry point
 * to proceed. Must be called on every exit path to prevent permanent hangs.
 * No-op for manual-mapped injection (no ready event exists).
 */
static void SignalReadyEvent(void)
{
    // Only APC-injected processes (LoadLibrary method) have a NexusHookReady event.
    // Manual-mapped processes were injected by the host directly — no event to signal.
    if (g_isManualMapped) return;

    char readyEventName[256];
    sprintf_s(readyEventName, sizeof(readyEventName), "NexusHookReady_%u", GetCurrentProcessId());

    // Suppress VEH hook capture — OpenEventA/SetEvent may have INT3 hooks armed.
    void* savedGuard = HookEngine_SuppressGuard();

    // The APC shellcode creates the event concurrently (on the initial thread).
    // It should exist almost immediately after LoadLibraryW returns, but allow
    // a small retry window in case of scheduling delays.
    HANDLE hReadyEvent = NULL;
    for (int attempt = 0; attempt < 10 && !hReadyEvent; attempt++)
    {
        hReadyEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, readyEventName);
        if (!hReadyEvent && attempt < 9)
            Sleep(5);
    }

    DbgLog("SignalReady: OpenEventA(%s) = %p err=%u (attempts=%d)",
        readyEventName, hReadyEvent, GetLastError(),
        hReadyEvent ? 1 : 10);
    if (hReadyEvent)
    {
        SetEvent(hReadyEvent);
        CloseHandle(hReadyEvent);
        DbgLog("Signaled ready event: %s", readyEventName);
    }

    HookEngine_RestoreGuard(savedGuard);
}

/**
 * @brief Main worker thread: connects pipe, configures hooks, runs event loop
 *
 * Executes the full 8-step lifecycle described in the file header.
 * Runs entirely off the loader lock to avoid deadlocks. On exit, either
 * calls FreeLibraryAndExitThread (LoadLibrary injection) or ExitThread
 * (manual-map injection) to cleanly unload.
 *
 * @param[in] lpParam  Unused
 * @return 0 on clean shutdown, 1 on initialization failure
 */
static DWORD WINAPI WorkerThread(LPVOID lpParam)
{
    (void)lpParam;
    g_running = true;
    DbgLogOpen();

    // Build pipe name: \\.\pipe\NexusApiMonitor_{PID}
    char pipeName[256];
    sprintf_s(pipeName, sizeof(pipeName), "%s%u", PIPE_NAME_PREFIX, GetCurrentProcessId());
    DbgLog("Step 1: Connecting to pipe: %s", pipeName);

    // Step 1: Connect to host pipe
    if (!PipeClient_Connect(pipeName, 15000))
    {
        DWORD err = GetLastError();
        DbgLog("FAIL: PipeClient_Connect failed, GetLastError=%u (0x%X)", err, err);
        SignalReadyEvent(); // Unblock entry point if APC-injected
        g_running = false;
        if (g_isManualMapped) ExitThread(1); else FreeLibraryAndExitThread(g_hModule, 1);
        return 1;
    }
    DbgLog("Step 1: Pipe connected OK");

    // Step 2: Read MSG_CONFIGURE from host (before engine init, so we know how many hooks)
    DbgLog("Step 2: Waiting for MSG_CONFIGURE...");
    uint8_t msgType = 0;
    uint8_t* payload = NULL;
    uint32_t payloadLen = 0;

    if (!PipeClient_ReadMessage(&msgType, &payload, &payloadLen) || msgType != MSG_CONFIGURE)
    {
        DbgLog("FAIL: Expected MSG_CONFIGURE, got type=0x%02X len=%u", msgType, payloadLen);
        PipeClient_SendError("Expected MSG_CONFIGURE");
        PipeClient_Disconnect();
        SignalReadyEvent(); // Unblock entry point if APC-injected
        g_running = false;
        if (g_isManualMapped) ExitThread(1); else FreeLibraryAndExitThread(g_hModule, 1);
        return 1;
    }
    DbgLog("Step 2: MSG_CONFIGURE received, payloadLen=%u", payloadLen);

    // Extract apiCount from config header to size the engine
    uint16_t apiCount = 0;
    if (payloadLen >= 2)
        apiCount = *(uint16_t*)payload;
    DbgLog("Step 2b: apiCount=%u from config header", apiCount);

    // Step 3: Initialize hook engine with capacity from config
    int maxHooks = (int)apiCount + 16; // small headroom
    DbgLog("Step 3: Initializing hook engine (maxHooks=%d)...", maxHooks);
    if (!HookEngine_Initialize(maxHooks))
    {
        DbgLog("FAIL: HookEngine_Initialize(%d) failed", maxHooks);
        PipeClient_SendError("Failed to initialize hook engine");
        free(payload);
        PipeClient_Disconnect();
        SignalReadyEvent(); // Unblock entry point if APC-injected
        g_running = false;
        if (g_isManualMapped) ExitThread(1); else FreeLibraryAndExitThread(g_hModule, 1);
        return 1;
    }
    DbgLog("Step 3: Hook engine initialized OK");

    // Step 4: Parse configuration and register hooks.
    // Hooks are armed with INT3 during registration (arm-on-register mode).
    // The exception handler was installed during HookEngine_Initialize, so
    // INT3 breakpoints are immediately active. Suppress event capture during
    // registration to avoid noise from our own GetModuleHandle/GetProcAddress calls.
    DbgLog("Step 4: Parsing configuration (arm-on-register)...");
    void* savedGuard = HookEngine_SuppressGuard();
    uint16_t successCount = 0, failCount = 0, totalRequested = 0;
    uint32_t consumedLen = 0;
    ParseConfigure(payload, payloadLen, &successCount, &failCount, &totalRequested, &consumedLen);
    HookEngine_RestoreGuard(savedGuard);
    DbgLog("Step 4: Hooks registered+armed: %u requested, %u success, %u fail",
        totalRequested, successCount, failCount);

    // Step 4b: Parse propagation config (appended after API list in MSG_CONFIGURE)
    // Format: [uint8 flags][uint16 dllPathLenBytes][wchar_t[] dllPath]
    if (consumedLen + 1 <= payloadLen)
    {
        uint8_t propagationFlags = payload[consumedLen]; consumedLen++;
        if ((propagationFlags & 0x01) && consumedLen + 2 <= payloadLen)
        {
            uint16_t dllPathLen = *(uint16_t*)(payload + consumedLen); consumedLen += 2;
            if (dllPathLen > 0 && consumedLen + dllPathLen <= payloadLen)
            {
                const wchar_t* dllPath = (const wchar_t*)(payload + consumedLen);
                ChildInject_SetDllPath(dllPath);
                ChildInject_SetEnabled(true);
                DbgLog("Step 4b: Propagation enabled, DLL path len=%u", dllPathLen);
            }
        }
    }
    free(payload);
    payload = NULL;

    // Step 5: Send MSG_READY so the host knows we're connected.
    __try
    {
        DbgLog("Step 5: Sending MSG_READY...");
        void* savedGuard2 = HookEngine_SuppressGuard();
        bool readyOk = PipeClient_SendReady(totalRequested, successCount, failCount);
        HookEngine_RestoreGuard(savedGuard2);
        DbgLog("Step 5: MSG_READY sent (ok=%d).", (int)readyOk);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgLog("!!! Step 5 CRASHED: ExceptionCode=0x%08X", GetExceptionCode());
    }

    // Step 5b: VEH upgrade — enables full event capture (dispatching to ring buffer).
    // Must complete BEFORE SignalReadyEvent so hooks capture from the very first
    // API call after the entry point starts.
    if (successCount > 0)
    {
        DbgLog("Step 5b: VEH upgrade attempt...");
        HookEngine_EnableAll();
        DbgLog("Step 5b: Done");
    }
    else
    {
        DbgLog("Step 5b: No hooks to enable (0 success)");
    }

    // Step 5c: Signal NexusHookReady event — unblocks the child's entry point.
    // The APC shellcode CREATES this event in the child process and waits on it.
    // By signaling AFTER EnableAll, hooks are fully active before the entry point runs.
    // For manual-mapped processes (host-injected), this is a no-op.
    SignalReadyEvent();

    // Step 6: Initialize child inject (NtCreateUserProcess hook via MinHook).
    // Hooks process creation for grandchild propagation. Done LAST because it's
    // the least time-critical — if the process exits during this, hooks are already
    // fully active and events have been captured.
    DbgLog("Step 6: Initializing child inject...");
    ChildInject_Initialize();

    // Step 7: Wait for stop signal via named event.
    // CRITICAL: Do NOT read from the pipe here. The pipe handle is synchronous
    // (no FILE_FLAG_OVERLAPPED), so concurrent NtReadFile (this thread) and
    // NtWriteFile (drain thread) would serialize — the drain thread's writes
    // block until this read completes, creating a deadlock where no events flow.
    // Instead, the host signals a named event to tell us to stop.
    {
        char stopEventName[256];
        sprintf_s(stopEventName, sizeof(stopEventName),
            "NexusApiMonitorStop_%u", GetCurrentProcessId());
        HANDLE hStopEvent = OpenEventA(SYNCHRONIZE, FALSE, stopEventName);
        if (hStopEvent)
        {
            DbgLog("Step 7: Waiting for stop event: %s", stopEventName);
            WaitForSingleObject(hStopEvent, INFINITE);
            DbgLog("Step 7: Stop event signaled");
            CloseHandle(hStopEvent);
        }
        else
        {
            // Fallback: no stop event found, wait until pipe disconnects.
            // Use Sleep loop instead of pipe read to avoid handle serialization.
            DbgLog("Step 7: Stop event not found (err=%u), polling pipe status...",
                GetLastError());
            while (g_running && PipeClient_IsConnected())
                Sleep(100);
            DbgLog("Step 7: Pipe disconnected or stopped");
        }
    }

    // Step 8: Cleanup
    DbgLog("Step 8: Cleanup...");
    g_running = false;
    ChildInject_Shutdown();
    HookEngine_DisableAll();
    HookEngine_Shutdown();
    PipeClient_Disconnect();

    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }

    if (g_isManualMapped) ExitThread(0); else FreeLibraryAndExitThread(g_hModule, 0);
    return 0;
}

/**
 * @brief Standard DLL entry point
 *
 * On DLL_PROCESS_ATTACH: detects injection method, erases PE headers for
 * manual-mapped injection, disables thread library calls, and spawns the
 * worker thread. On DLL_PROCESS_DETACH: signals the worker to stop.
 *
 * @param[in] hModule            Module handle for this DLL
 * @param[in] ul_reason_for_call Attach/detach reason
 * @param[in] lpReserved         Reserved (non-NULL for static loads)
 * @return TRUE on success, FALSE to abort injection
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;

        // Detect injection method: if GetModuleHandleA finds us, we were LoadLibrary'd.
        // If NULL, we were manually mapped (not in PEB module list).
        {
            HMODULE hSelf64 = GetModuleHandleA("NexusApiHook.dll");
            HMODULE hSelf32 = GetModuleHandleA("NexusApiHook32.dll");
            bool isManualMapped = (hSelf64 != hModule && hSelf32 != hModule);

            if (isManualMapped)
            {
                // Erase PE headers immediately to avoid EAC memory scanning.
                // Must be done BEFORE EAC's periodic module/memory scan fires.
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
                if (dos->e_magic == 0x5A4D)
                {
                    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dos->e_lfanew);
                    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
                    DWORD oldProt;
                    if (VirtualProtect(hModule, headerSize, PAGE_READWRITE, &oldProt))
                    {
                        memset(hModule, 0, headerSize);
                        VirtualProtect(hModule, headerSize, oldProt, &oldProt);
                    }
                }
                // Don't call DisableThreadLibraryCalls — we're not in loader's list
            }
            else
            {
                DisableThreadLibraryCalls(hModule);
            }

            // Store injection method for worker thread to log
            g_isManualMapped = isManualMapped;
        }

        // Spawn worker thread - never do real work on the loader lock
        g_hWorkerThread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (!g_hWorkerThread)
            return FALSE;
        break;

    case DLL_PROCESS_DETACH:
        g_running = false;
        // Worker thread handles its own cleanup via FreeLibraryAndExitThread
        break;
    }

    return TRUE;
}
