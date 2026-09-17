/**
 * @file protocol.h
 * @brief Wire protocol shared between NexusApiHook DLL (C++) and host UI (C#)
 *
 * Defines message types, parameter flags, size limits, and payload structures
 * for the named pipe IPC protocol. All messages are framed as:
 *
 *     [uint32 length][uint8 type][payload...]
 *
 * where length = 1 + payloadLen (includes the type byte).
 *
 * **Message Flow**:
 * - Host sends MSG_CONFIGURE after pipe connect (API list + param metadata)
 * - DLL sends MSG_READY after hooks are installed
 * - DLL sends MSG_EVENT for each captured API call
 * - DLL sends MSG_CHILD_CREATED when a child process is intercepted
 * - Host signals stop via named event (not pipe message)
 *
 * **Parameter Flags** (PARAM_FLAG_*): Bitmask controlling how each parameter
 * is captured. WIDE_STRING/ANSI_STRING cause string dereference and UTF-8
 * encoding. POINTER causes address logging. BUFFER is reserved for future use.
 *
 * @note This header must stay in sync with the C# MsgReady/MsgEvent/etc.
 *       structures in the Nexus.UI project.
 */
#pragma once

#include <stdint.h>

// ---- Message Types ----
#define MSG_CONFIGURE       0x01    // Host -> DLL: list of APIs to hook
#define MSG_STOP            0x02    // Host -> DLL: unhook and unload
#define MSG_READY           0x10    // DLL -> Host: hooks installed, ready
#define MSG_EVENT           0x11    // DLL -> Host: captured API call
#define MSG_ERROR           0x12    // DLL -> Host: error message
#define MSG_CHILD_CREATED   0x13    // DLL -> Host: child process was created

// ---- Parameter Flags (bitmask) ----
#define PARAM_FLAG_OUTPUT       0x01
#define PARAM_FLAG_POINTER      0x02
#define PARAM_FLAG_WIDE_STRING  0x04
#define PARAM_FLAG_ANSI_STRING  0x08
#define PARAM_FLAG_OPTIONAL     0x10
#define PARAM_FLAG_BUFFER       0x20
// PARAM_FLAG_OBJECT_ATTRIBUTES: parameter is a POBJECT_ATTRIBUTES pointer.
// The hook engine dereferences it and extracts ObjectName.Buffer (UTF-8).
// This enables NT* API calls (NtCreateFile, NtOpenKey, NtOpenSection, etc.)
// to expose the actual file/registry/section path as a string parameter
// instead of an opaque pointer. Required for Phase 2A SignatureManager
// correlation against the Phase 1C decrypted string vocabulary.
#define PARAM_FLAG_OBJECT_ATTRIBUTES 0x40

// ---- Limits ----
#define MAX_PARAMS          16
#define MAX_STACK_FRAMES    32
#define MAX_STRING_CAPTURE  4096
#define MAX_FUNC_NAME       256
#define MAX_MODULE_NAME     256
#define MAX_PARAM_NAME      64      // param name/type (shorter than function names)
#define PIPE_BUFFER_SIZE    65536
#define SEND_BUFFER_SIZE    65536

// ---- Pipe naming ----
// Format: \\.\pipe\NexusApiMonitor_{PID}
#define PIPE_NAME_PREFIX    "\\\\.\\pipe\\NexusApiMonitor_"

#pragma pack(push, 1)

// MSG_CONFIGURE payload: sent by host after pipe connects
// Layout:
//   uint16 apiCount
//   Per API:
//     uint16 moduleNameLen, char[moduleNameLen] moduleName (UTF-8)
//     uint16 funcNameLen,   char[funcNameLen]   funcName   (UTF-8)
//     uint8  paramCount
//     Per param:
//       uint8  flags
//       uint16 nameLen, char[nameLen] name (UTF-8)
//       uint16 typeLen, char[typeLen] type (UTF-8)

// MSG_READY payload
typedef struct {
    uint16_t totalRequested;
    uint16_t successCount;
    uint16_t failCount;
} MsgReady;

// MSG_EVENT payload (variable-length, serialized manually)
// Layout:
//   uint32 threadId
//   uint64 timestampQpc
//   uint16 hookIndex
//   uint64 durationQpc
//   uint64 returnValue
//   uint32 lastError
//   uint8  paramCount
//   Per param:
//     uint64 rawValue
//     uint16 stringDataLen
//     char[stringDataLen] stringData (UTF-8)
//   uint8  stackDepth
//   Per frame:
//     uint64 address

// MSG_CHILD_CREATED payload
typedef struct {
    uint32_t childPid;
} MsgChildCreated;

// MSG_ERROR payload
typedef struct {
    uint16_t messageLen;
    // followed by char[messageLen] (UTF-8)
} MsgErrorHeader;

#pragma pack(pop)
