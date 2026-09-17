/**
 * @file pipe_client.cpp
 * @brief Named pipe IPC client for communication with the NexusSentinel host
 *
 * Implements a framed binary protocol over Windows named pipes for sending
 * hook events from the injected DLL to the host application. Key design
 * decisions:
 *
 * **ntdll Direct I/O**: All pipe reads and writes use NtReadFile/NtWriteFile
 * from ntdll.dll directly, bypassing hooked kernel32!ReadFile/WriteFile.
 * This prevents infinite recursion when hooked APIs (e.g., WriteFile) try
 * to send events that would trigger another WriteFile call.
 *
 * **Frame Format**: Each message is framed as [uint32 length][uint8 type][payload].
 * The length field covers the type byte plus payload. This is compatible with
 * .NET's BinaryReader on the host side.
 *
 * **Thread Safety**: Writes are serialized via CRITICAL_SECTION. On the event
 * path the reentrancy guard is already set, so EnterCriticalSection (if hooked)
 * passes through to the original implementation without capturing events.
 *
 * **Connection**: Uses WaitNamedPipeA with retry loop for APC-injected children
 * where the host may not have created the pipe yet.
 *
 * @see pipe_client.h  Public API
 * @see protocol.h     Message type definitions and payload layouts
 */

#include "pipe_client.h"
#include "hook_engine_internal.h"
#include "protocol.h"
#include <string.h>
#include <stdlib.h>

// ---- ntdll direct I/O (bypasses hooked kernel32 ReadFile/WriteFile) ----
// Types (HOOK_HOOK_IO_STATUS_BLOCK, PFN_NtWriteFile, etc.) are in hook_engine_internal.h

static PFN_NtWriteFile g_pNtWriteFile = NULL;
static PFN_NtReadFile g_pNtReadFile = NULL;
static PFN_NtFlushBuffersFile g_pNtFlushBuffersFile = NULL;

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_writeLock;
static bool g_writeLockInit = false;

static void ResolveNtdllFunctions(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    g_pNtWriteFile = (PFN_NtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    g_pNtReadFile = (PFN_NtReadFile)GetProcAddress(hNtdll, "NtReadFile");
    g_pNtFlushBuffersFile = (PFN_NtFlushBuffersFile)GetProcAddress(hNtdll, "NtFlushBuffersFile");
}

/**
 * @brief Connect to the host's named pipe server
 *
 * Initializes the write lock and resolves ntdll I/O functions, then
 * retries WaitNamedPipeA until the pipe is available or the timeout
 * expires. Opens the pipe in GENERIC_READ | GENERIC_WRITE byte mode.
 *
 * @param[in] pipeName   Full pipe path (e.g., "\\\\.\\pipe\\NexusApiMonitor_1234")
 * @param[in] timeoutMs  Maximum wait for pipe availability in milliseconds
 * @return true if connected, false on timeout or error
 */
bool PipeClient_Connect(const char* pipeName, DWORD timeoutMs)
{
    if (!g_writeLockInit)
    {
        InitializeCriticalSection(&g_writeLock);
        g_writeLockInit = true;
    }

    ResolveNtdllFunctions();

    // Wait for the pipe to become available.
    // WaitNamedPipeA returns immediately with ERROR_FILE_NOT_FOUND if the pipe
    // server doesn't exist yet (timeout only applies when pipe exists but is busy).
    // For APC-injected children, the host may not have created the pipe yet,
    // so we retry in a loop.
    DWORD deadline = GetTickCount() + timeoutMs;
    for (;;)
    {
        if (WaitNamedPipeA(pipeName, 1000))
            break; // pipe available

        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_SEM_TIMEOUT)
            return false; // non-retryable error

        if (GetTickCount() >= deadline)
            return false; // timed out

        Sleep(50);
    }

    g_hPipe = CreateFileA(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (g_hPipe == INVALID_HANDLE_VALUE)
        return false;

    // Set pipe to byte mode
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(g_hPipe, &mode, NULL, NULL);

    return true;
}

/** @brief Flush, disconnect, and close the pipe handle. Releases the write lock. */
void PipeClient_Disconnect(void)
{
    if (g_hPipe != INVALID_HANDLE_VALUE)
    {
        if (g_pNtFlushBuffersFile)
        {
            HOOK_IO_STATUS_BLOCK iosb = {};
            g_pNtFlushBuffersFile(g_hPipe, &iosb);
        }
        else
        {
            FlushFileBuffers(g_hPipe);
        }
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }

    if (g_writeLockInit)
    {
        DeleteCriticalSection(&g_writeLock);
        g_writeLockInit = false;
    }
}

/** @brief Check if the pipe handle is currently valid (not disconnected). */
bool PipeClient_IsConnected(void)
{
    return g_hPipe != INVALID_HANDLE_VALUE;
}

/**
 * @brief Read exactly 'count' bytes from the pipe using ntdll NtReadFile
 *
 * Loops until all requested bytes are received or an error/disconnect occurs.
 * Uses ntdll directly to bypass any hooked kernel32!ReadFile.
 *
 * @param[out] buffer  Destination buffer
 * @param[in]  count   Number of bytes to read
 * @return true if all bytes were read, false on error or pipe close
 */
static bool NtReadExact(void* buffer, ULONG count)
{
    uint8_t* p = (uint8_t*)buffer;
    ULONG remaining = count;

    while (remaining > 0)
    {
        HOOK_IO_STATUS_BLOCK iosb = {};
        LONG status = g_pNtReadFile(g_hPipe, NULL, NULL, NULL, &iosb,
            p, remaining, NULL, NULL);
        if (status < 0) // NT_ERROR
            return false;
        ULONG bytesRead = (ULONG)iosb.Information;
        if (bytesRead == 0)
            return false; // pipe closed
        p += bytesRead;
        remaining -= bytesRead;
    }
    return true;
}

/**
 * @brief Write exactly 'count' bytes to the pipe using ntdll NtWriteFile
 *
 * @param[in] buffer  Source data
 * @param[in] count   Number of bytes to write
 * @return true if all bytes were written, false on error
 */
static bool NtWriteAll(const void* buffer, ULONG count)
{
    const uint8_t* p = (const uint8_t*)buffer;
    ULONG remaining = count;

    while (remaining > 0)
    {
        HOOK_IO_STATUS_BLOCK iosb = {};
        LONG status = g_pNtWriteFile(g_hPipe, NULL, NULL, NULL, &iosb,
            p, remaining, NULL, NULL);
        if (status < 0) // NT_ERROR
            return false;
        ULONG bytesWritten = (ULONG)iosb.Information;
        if (bytesWritten == 0)
            return false;
        p += bytesWritten;
        remaining -= bytesWritten;
    }
    return true;
}

/**
 * @brief Read a framed message from the pipe
 *
 * Reads the 4-byte length prefix, type byte, and payload. The caller
 * must free *outPayload with free() when done.
 *
 * @param[out] outType       Receives the message type byte
 * @param[out] outPayload    Receives a malloc'd payload buffer (or NULL if empty)
 * @param[out] outPayloadLen Receives the payload length (excluding type byte)
 * @return true on success, false on disconnect or protocol error
 */
bool PipeClient_ReadMessage(uint8_t* outType, uint8_t** outPayload, uint32_t* outPayloadLen)
{
    if (g_hPipe == INVALID_HANDLE_VALUE || !g_pNtReadFile)
        return false;

    // Read 4-byte length prefix (total frame size including type byte)
    uint32_t frameLen = 0;
    if (!NtReadExact(&frameLen, 4))
        return false;

    if (frameLen < 1)
        return false; // must have at least the type byte

    // Read type byte
    uint8_t type = 0;
    if (!NtReadExact(&type, 1))
        return false;

    uint32_t payloadLen = frameLen - 1;
    uint8_t* payload = NULL;

    if (payloadLen > 0)
    {
        payload = (uint8_t*)malloc(payloadLen);
        if (!payload)
            return false;

        if (!NtReadExact(payload, payloadLen))
        {
            free(payload);
            return false;
        }
    }

    *outType = type;
    *outPayload = payload;
    *outPayloadLen = payloadLen;
    return true;
}

/**
 * @brief Send a framed message to the host pipe (thread-safe)
 *
 * Writes [uint32 frameLen][uint8 type][payload] atomically under the
 * write lock. Uses ntdll direct I/O.
 *
 * @param[in] type        Message type byte (MSG_*)
 * @param[in] payload     Payload data (may be NULL if payloadLen == 0)
 * @param[in] payloadLen  Length of payload in bytes
 * @return true if the entire message was written
 */
bool PipeClient_SendMessage(uint8_t type, const void* payload, uint32_t payloadLen)
{
    if (g_hPipe == INVALID_HANDLE_VALUE || !g_pNtWriteFile)
        return false;

    uint32_t frameLen = 1 + payloadLen; // type byte + payload

    // CRITICAL_SECTION is fine here: on the event-send path the reentrancy guard
    // is already set, so hooked EnterCriticalSection just calls through to original.
    EnterCriticalSection(&g_writeLock);

    bool ok = false;

    // Write length prefix + type + payload using ntdll direct
    if (NtWriteAll(&frameLen, 4))
    {
        if (NtWriteAll(&type, 1))
        {
            if (payloadLen == 0)
            {
                ok = true;
            }
            else if (NtWriteAll(payload, payloadLen))
            {
                ok = true;
            }
        }
    }

    LeaveCriticalSection(&g_writeLock);
    return ok;
}

bool PipeClient_SendReady(uint16_t totalRequested, uint16_t successCount, uint16_t failCount)
{
    MsgReady msg;
    msg.totalRequested = totalRequested;
    msg.successCount = successCount;
    msg.failCount = failCount;
    return PipeClient_SendMessage(MSG_READY, &msg, sizeof(msg));
}

bool PipeClient_SendEvent(const void* eventData, uint32_t eventDataLen)
{
    return PipeClient_SendMessage(MSG_EVENT, eventData, eventDataLen);
}

bool PipeClient_SendError(const char* message)
{
    if (!message) return false;

    uint16_t len = (uint16_t)strlen(message);
    uint32_t totalLen = 2 + len;
    uint8_t* buf = (uint8_t*)malloc(totalLen);
    if (!buf) return false;

    memcpy(buf, &len, 2);
    memcpy(buf + 2, message, len);

    bool ok = PipeClient_SendMessage(MSG_ERROR, buf, totalLen);
    free(buf);
    return ok;
}
