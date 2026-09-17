/**
 * @file hook_events.cpp
 * @brief Event serialization, ring buffer, and drain thread
 *
 * Contains the event pipeline: CaptureStringParam, SerializeAndSendEvent,
 * EventQueue_Enqueue, and DrainThreadProc. Hooked threads serialize events
 * into a lock-free MPSC ring buffer; a dedicated drain thread reads from
 * the ring and writes to the host pipe.
 *
 * Extracted from hook_engine.cpp for maintainability.
 */

#include "hook_engine_internal.h"

// ============================================================
// String Parameter Capture
// ============================================================

// OBJECT_ATTRIBUTES layouts. Defined inline here to avoid pulling in the
// full DDK headers. Both x64 and x86 handled because EALauncher /
// EALaunchHelper may be 32-bit and call NT* APIs with the x86 OA layout.

#ifdef _WIN64
// x64: sizeof(OBJECT_ATTRIBUTES) = 0x30 (48 bytes)
struct OA_LAYOUT {
    uint32_t Length;                   // +0x00
    uint32_t _pad0;                    // +0x04 (alignment)
    uint64_t RootDirectory;            // +0x08
    uint64_t ObjectName;               // +0x10  -> PUNICODE_STRING
    uint32_t Attributes;               // +0x18
    uint32_t _pad1;                    // +0x1C
    uint64_t SecurityDescriptor;       // +0x20
    uint64_t SecurityQualityOfService; // +0x28
};
struct US_LAYOUT {
    uint16_t Length;        // +0x00 (in BYTES, not chars)
    uint16_t MaximumLength; // +0x02
    uint32_t _pad0;         // +0x04 (alignment)
    uint64_t Buffer;        // +0x08  -> PWSTR
};
#define OA_EXPECTED_LENGTH 0x30
#else
// x86: sizeof(OBJECT_ATTRIBUTES) = 0x18 (24 bytes)
struct OA_LAYOUT {
    uint32_t Length;                   // +0x00
    uint32_t RootDirectory;            // +0x04
    uint32_t ObjectName;               // +0x08  -> PUNICODE_STRING
    uint32_t Attributes;               // +0x0C
    uint32_t SecurityDescriptor;       // +0x10
    uint32_t SecurityQualityOfService; // +0x14
};
struct US_LAYOUT {
    uint16_t Length;        // +0x00 (in BYTES)
    uint16_t MaximumLength; // +0x02
    uint32_t Buffer;        // +0x04  -> PWSTR
};
#define OA_EXPECTED_LENGTH 0x18
#endif

static uint32_t CaptureStringParam(uint8_t flags, uint64_t rawValue, char* outBuf, uint32_t outBufSize)
{
    if (rawValue == 0 || outBufSize == 0)
        return 0;

    __try
    {
        if (flags & PARAM_FLAG_WIDE_STRING)
        {
            const wchar_t* ws = (const wchar_t*)rawValue;
            // Probe first byte
            volatile wchar_t probe = ws[0];
            (void)probe;

            int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, outBuf, (int)outBufSize - 1, NULL, NULL);
            if (len <= 0)
                return 0;
            outBuf[len] = '\0';
            return (uint32_t)(len - 1); // exclude null terminator
        }
        else if (flags & PARAM_FLAG_ANSI_STRING)
        {
            const char* s = (const char*)rawValue;
            // Probe first byte
            volatile char probe = s[0];
            (void)probe;

            size_t slen = strnlen(s, outBufSize - 1);
            memcpy(outBuf, s, slen);
            outBuf[slen] = '\0';
            return (uint32_t)slen;
        }
        else if (flags & PARAM_FLAG_OBJECT_ATTRIBUTES)
        {
            // Dereference POBJECT_ATTRIBUTES -> ObjectName.Buffer (PWSTR).
            // Walks: rawValue (POBJECT_ATTRIBUTES) -> ObjectName -> Buffer
            //        + Length (in bytes).
            // Each pointer hop is wrapped in __try so a torn / freed
            // OBJECT_ATTRIBUTES doesn't crash the hook.
            const OA_LAYOUT* oa = (const OA_LAYOUT*)(uintptr_t)rawValue;
            volatile uint32_t probeOaLen = oa->Length;
            (void)probeOaLen;

            // Sanity: must match this build's expected OBJECT_ATTRIBUTES size.
            // The x64 build uses 0x30, the x86 build uses 0x18.
            if (probeOaLen != OA_EXPECTED_LENGTH)
                return 0;

            const US_LAYOUT* uname = (const US_LAYOUT*)(uintptr_t)oa->ObjectName;
            if (uname == NULL)
                return 0;

            volatile uint16_t probeNameLen = uname->Length;
            (void)probeNameLen;

            const wchar_t* nbuf = (const wchar_t*)(uintptr_t)uname->Buffer;
            if (nbuf == NULL || probeNameLen == 0)
                return 0;

            // Length is in bytes; divide for char count
            int charCount = (int)(probeNameLen / sizeof(wchar_t));
            // Cap at a reasonable value to avoid wild pointers
            if (charCount <= 0 || charCount > 4096)
                return 0;

            // Probe the buffer's first char to verify the pointer is valid
            volatile wchar_t probeBuf = nbuf[0];
            (void)probeBuf;

            // Convert to UTF-8
            int len = WideCharToMultiByte(CP_UTF8, 0, nbuf, charCount,
                                          outBuf, (int)outBufSize - 1, NULL, NULL);
            if (len <= 0)
                return 0;
            outBuf[len] = '\0';
            return (uint32_t)len;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Invalid pointer - return empty
    }

    return 0;
}

// ============================================================
// Event Serialization
// ============================================================

void SerializeAndSendEvent(int slotIndex, uint32_t threadId,
    uint64_t timestampQpc, uint64_t durationQpc,
    uint64_t returnValue, uint32_t lastError,
    uint64_t* argValues, int paramCount,
    void* returnAddress)
{
    if (!PipeClient_IsConnected())
        return;
    if (g_tlsSendBuffer == TLS_OUT_OF_INDEXES)
        return;

    // Get or allocate per-thread send buffer via DirectTlsGet/Set.
    uint8_t* buf = (uint8_t*)DirectTlsGet(g_tlsSendBuffer);
    if (!buf)
    {
        buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, SEND_BUFFER_SIZE);
        if (!buf) return;
        DirectTlsSet(g_tlsSendBuffer, buf);
    }

    HookRegistration* reg = &g_hookSlots[slotIndex];

    uint32_t offset = 0;
    uint32_t maxLen = SEND_BUFFER_SIZE;

    // Helper macros for writing to buffer
    #define WRITE_U8(v)  do { if (offset + 1 <= maxLen) { buf[offset] = (uint8_t)(v); offset += 1; } } while(0)
    #define WRITE_U16(v) do { if (offset + 2 <= maxLen) { *(uint16_t*)(buf + offset) = (uint16_t)(v); offset += 2; } } while(0)
    #define WRITE_U32(v) do { if (offset + 4 <= maxLen) { *(uint32_t*)(buf + offset) = (uint32_t)(v); offset += 4; } } while(0)
    #define WRITE_U64(v) do { if (offset + 8 <= maxLen) { *(uint64_t*)(buf + offset) = (uint64_t)(v); offset += 8; } } while(0)

    // uint32 threadId
    WRITE_U32(threadId);
    // uint64 timestampQpc
    WRITE_U64(timestampQpc);
    // uint16 hookIndex (use configIndex so host can look up in its _configuredApis array)
    WRITE_U16(reg->configIndex);
    // uint64 durationQpc
    WRITE_U64(durationQpc);
    // uint64 returnValue
    WRITE_U64(returnValue);
    // uint32 lastError
    WRITE_U32(lastError);
    // uint8 paramCount
    WRITE_U8((uint8_t)paramCount);

    // Per param: uint64 rawValue, uint16 stringDataLen, char[] stringData
    for (int i = 0; i < paramCount && i < MAX_PARAMS; i++)
    {
        WRITE_U64(argValues[i]);

        char stringBuf[MAX_STRING_CAPTURE];
        uint32_t strLen = 0;

        if (reg->params[i].flags & (PARAM_FLAG_WIDE_STRING | PARAM_FLAG_ANSI_STRING | PARAM_FLAG_OBJECT_ATTRIBUTES))
        {
            strLen = CaptureStringParam(reg->params[i].flags, argValues[i], stringBuf, sizeof(stringBuf));
        }

        WRITE_U16((uint16_t)strLen);
        if (strLen > 0 && offset + strLen <= maxLen)
        {
            memcpy(buf + offset, stringBuf, strLen);
            offset += strLen;
        }
    }

    // Stack trace disabled -- CaptureStackBackTrace is ~1-5us per call and was
    // the primary cause of UI thread freezing when many hooks fire in rapid succession.
    // TODO: Re-enable with sampling (e.g. every Nth event) once base perf is confirmed.
    WRITE_U8(0); // frameCount = 0

    #undef WRITE_U8
    #undef WRITE_U16
    #undef WRITE_U32
    #undef WRITE_U64

    // Enqueue into ring buffer (fast memory copy, never blocks).
    // The drain thread handles actual pipe I/O on a separate thread.
    EventQueue_Enqueue(buf, offset);
}

// ============================================================
// Event Ring Buffer + Drain Thread
// ============================================================

void EventQueue_Enqueue(const uint8_t* data, uint32_t len)
{
    if (!g_eventRing || len == 0)
    {
        InterlockedIncrement(&g_dropCount);
        return;
    }
    if (len > EVENT_SLOT_SIZE)
    {
        LONG dropNum = InterlockedIncrement(&g_dropCount);
        if (dropNum <= 5)
            DbgLog("[ring] DROP oversized event: len=%u max=%u", len, EVENT_SLOT_SIZE);
        return;
    }

    // MPSC: claim a slot via atomic CAS on head
    LONG head, next;
    do
    {
        head = g_ringHead;
        next = (head + 1) % EVENT_RING_SLOTS;
        if (next == g_ringTail)
        {
            InterlockedIncrement(&g_dropCount);
            return; // ring full, drop event
        }
    } while (InterlockedCompareExchange(&g_ringHead, next, head) != head);

    // We own slot 'head'. Copy event data.
    memcpy(g_eventRing[head].data, data, len);
    g_eventRing[head].len = len;
    MemoryBarrier();
    InterlockedExchange(&g_eventRing[head].ready, 1);

    LONG enqNum = InterlockedIncrement(&g_enqueueCount);
    if (enqNum <= 5)
        DbgLog("[ring] enqueue #%d: len=%u slot=%d", enqNum, len, head);

    // Wake drain thread (auto-reset event, non-blocking SetEvent)
    if (g_hDrainEvent)
        SetEvent(g_hDrainEvent);
}

DWORD WINAPI DrainThreadProc(LPVOID)
{
    DbgLog("[drain] Drain thread started, TID=%u", GetCurrentThreadId());

    while (g_drainRunning)
    {
        WaitForSingleObject(g_hDrainEvent, 50); // wake on signal or 50ms poll

        // Set reentrancy guard so hooked functions called during pipe I/O
        // (EnterCriticalSection etc.) don't generate events back into the ring.
        if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
            DirectTlsSet(g_tlsReentrancy, (void*)1);

        while (g_ringTail != g_ringHead)
        {
            LONG tail = g_ringTail;
            if (!g_eventRing[tail].ready)
                break; // producer hasn't finished writing yet

            LONG drainNum = InterlockedIncrement(&g_drainCount);
            if (drainNum <= 5)
                DbgLog("[drain] sending #%d: len=%u slot=%d", drainNum,
                    g_eventRing[tail].len, tail);

            bool sendOk = PipeClient_SendEvent(g_eventRing[tail].data, g_eventRing[tail].len);
            if (!sendOk && drainNum <= 5)
                DbgLog("[drain] send FAILED for #%d", drainNum);

            g_eventRing[tail].ready = 0;
            MemoryBarrier();
            InterlockedExchange(&g_ringTail, (tail + 1) % EVENT_RING_SLOTS);
        }

        if (g_tlsReentrancy != TLS_OUT_OF_INDEXES)
            DirectTlsSet(g_tlsReentrancy, NULL);
    }

    DbgLog("[drain] Drain thread exiting. dispatched=%d enqueued=%d drained=%d dropped=%d",
        g_dispatchCount, g_enqueueCount, g_drainCount, g_dropCount);
    return 0;
}
