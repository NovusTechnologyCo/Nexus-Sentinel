/**
 * @file pipe_client.h
 * @brief Named pipe IPC client for communicating with the NexusSentinel host
 *
 * Provides a simple framed message protocol over Windows named pipes.
 * All I/O uses ntdll direct calls (NtReadFile/NtWriteFile) to bypass
 * hooked kernel32 functions. Writes are thread-safe via CRITICAL_SECTION.
 *
 * Frame format: [uint32 length][uint8 type][payload...]
 * where length = 1 + payloadLen (type byte + payload).
 *
 * @see pipe_client.cpp  Implementation
 * @see protocol.h       Message types and payload structures
 */
#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Connect to the host pipe. Returns true on success.
// pipeName: full pipe path, e.g. "\\.\pipe\NexusApiMonitor_1234"
// timeoutMs: max wait for pipe availability
bool PipeClient_Connect(const char* pipeName, DWORD timeoutMs);

// Disconnect and close the pipe handle.
void PipeClient_Disconnect(void);

// Returns true if the pipe is currently connected.
bool PipeClient_IsConnected(void);

// Read a framed message (4-byte length prefix + payload).
// On success, *outType receives the message type byte,
// *outPayload receives a malloc'd buffer (caller must free),
// *outPayloadLen receives the payload length (excluding type byte).
// Returns true on success, false on disconnect/error.
bool PipeClient_ReadMessage(uint8_t* outType, uint8_t** outPayload, uint32_t* outPayloadLen);

// Send a framed message. Thread-safe (uses critical section internally).
// type: message type byte
// payload: message payload (may be NULL if payloadLen == 0)
// payloadLen: length of payload
// Returns true on success.
bool PipeClient_SendMessage(uint8_t type, const void* payload, uint32_t payloadLen);

// High-level: send MSG_READY with success/fail counts.
bool PipeClient_SendReady(uint16_t totalRequested, uint16_t successCount, uint16_t failCount);

// High-level: send a pre-serialized MSG_EVENT buffer.
bool PipeClient_SendEvent(const void* eventData, uint32_t eventDataLen);

// High-level: send MSG_ERROR with a UTF-8 message string.
bool PipeClient_SendError(const char* message);

#ifdef __cplusplus
}
#endif
