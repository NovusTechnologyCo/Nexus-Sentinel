/**
 * @file hook_blacklist.cpp
 * @brief Function blacklist for the hook engine
 *
 * Contains IsBlacklisted() which rejects functions that are dangerous to hook
 * (conflict with MinHook, cause infinite recursion, or are called so frequently
 * by Windows internals that they saturate the ring buffer).
 *
 * Extracted from hook_engine.cpp for maintainability.
 */

#include "hook_engine_internal.h"

// BLACKLIST approach: Hook whatever the host requests, EXCEPT functions that are
// dangerous to hook (conflict with MinHook, cause infinite recursion, or are
// called so frequently by Windows internals that they saturate the ring buffer).
// The UI tree controls what gets hooked; this is just a safety net.
bool IsBlacklisted(const char* funcName)
{
    static const char* blacklist[] = {
        // ---- MinHook internals ----
        // VirtualProtect is used by MH_EnableHook/MH_DisableHook to change page
        // permissions. Hooking it causes infinite recursion inside MinHook.
        "VirtualProtect", "VirtualProtectEx",
        "FlushInstructionCache",
        // MinHook allocates trampoline memory via VirtualAlloc/VirtualQuery.
        "VirtualAlloc", "VirtualAllocEx",
        "VirtualFree", "VirtualFreeEx",
        "VirtualQuery", "VirtualQueryEx",

        // ---- Functions used by RegisterHook internally ----
        "GetProcAddress", "GetProcAddressForCaller",
        "GetModuleHandleA", "GetModuleHandleW",
        "GetModuleHandleExA", "GetModuleHandleExW",
        "LdrGetDllHandle", "LdrGetProcedureAddress",
        "GetSystemInfo", "GetNativeSystemInfo",   // called by VirtualAlloc internally

        // ---- ntdll exception dispatch (infinite recursion if hooked) ----
        // These are called by Windows during exception delivery. If hooked with INT3,
        // the INT3 triggers another exception -> calls these again -> stack overflow.
        "RtlLookupFunctionEntry",
        "RtlVirtualUnwind",
        "RtlCaptureContext",
        "RtlUnwindEx", "RtlUnwind",
        "RtlRestoreContext",
        "RtlRaiseException",
        "RtlDispatchException",
        "RtlPcToFileHeader",
        "RtlImageNtHeader", "RtlImageNtHeaderEx",
        "KiUserExceptionDispatcher",
        "NtContinue",
        "NtRaiseException",
        // ntdll underpinnings of Virtual* functions
        "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueryVirtualMemory",

        // ---- Ultra-high-frequency noise (>1000 calls/sec in idle apps) ----
        "IsDebuggerPresent",        // Windows internal polling
        "CloseHandle",              // called millions of times by CRT/COM/GDI
        "ReleaseMutex",             // internal synchronization
        "WaitForSingleObject",      // internal synchronization
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",
        "WaitForMultipleObjectsEx",
        "SetWaitableTimer",         // internal timer management
        "CancelWaitableTimer",
        "Sleep", "SleepEx",
        "SetEvent", "ResetEvent", "PulseEvent",  // our drain thread uses SetEvent
        "SignalObjectAndWait",
        // Nt* synchronization -- kernel32 Wait* is blacklisted but ntdll Nt* was not,
        // causing our drain thread (SetEvent->NtSetEvent->NtWaitForSingleObject) to
        // generate 17M+ VEH hits per minute in an infinite feedback loop.
        "NtWaitForSingleObject", "NtWaitForMultipleObjects",
        "NtSignalAndWaitForSingleObject",
        "NtSetEvent", "NtResetEvent", "NtPulseEvent",
        "NtClearEvent",
        "NtReleaseSemaphore", "NtReleaseMutant",
        "NtCreateEvent", "NtOpenEvent",
        "NtCreateSemaphore", "NtOpenSemaphore",
        "NtCreateMutant", "NtOpenMutant",
        "NtCreateTimer", "NtOpenTimer", "NtSetTimer", "NtCancelTimer",
        "NtCreateKeyedEvent", "NtOpenKeyedEvent",
        "NtWaitForKeyedEvent", "NtReleaseKeyedEvent",
        "NtWaitForAlertByThreadId", "NtAlertThreadByThreadId",
        "GetTickCount", "GetTickCount64",
        "GetSystemTimeAsFileTime",
        "QueryPerformanceCounter",  // timing -- also used by our own capture code
        "GetLastError", "SetLastError",
        "GetCurrentThreadId", "GetCurrentProcessId",
        "GetCurrentThread", "GetCurrentProcess",
        "TlsGetValue", "TlsSetValue",  // TLS -- we use direct TEB access instead
        "EnterCriticalSection", "LeaveCriticalSection",
        "TryEnterCriticalSection",
        "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
        "InitializeCriticalSectionEx", "DeleteCriticalSection",
        "AcquireSRWLockExclusive", "AcquireSRWLockShared",
        "TryAcquireSRWLockExclusive", "TryAcquireSRWLockShared",
        "ReleaseSRWLockExclusive", "ReleaseSRWLockShared",
        "InitializeSRWLock",
        "SleepConditionVariableCS", "SleepConditionVariableSRW",
        "WakeConditionVariable", "WakeAllConditionVariable",
        "InitializeConditionVariable",
        "InterlockedIncrement", "InterlockedDecrement",
        "InterlockedExchange", "InterlockedCompareExchange",
        "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
        "RtlAllocateHeap", "RtlFreeHeap",
        "GetProcessHeap",

        // ---- ETW tracing noise ----
        "EventWriteTransfer", "EventEnabled", "EventWrite",
        "EventRegister", "EventUnregister",
        "EventActivityIdControl",
        "EtwEventWriteTransfer", "EtwEventEnabled", "EtwEventWrite",

        // ---- Pointer encoding used by VEH dispatcher ----
        // RtlDispatchException decodes VEH handler pointers via RtlDecodePointer.
        // If DecodePointer has INT3 -> recursive exception -> stack overflow.
        "DecodePointer", "EncodePointer",
        "DecodeSystemPointer", "EncodeSystemPointer",
        "RtlDecodePointer", "RtlEncodePointer",
        "RtlDecodeRemotePointer", "RtlEncodeRemotePointer",

        // ---- Delay-load resolution (called during critical DLL loading paths) ----
        "DelayLoadFailureHook",
        "ResolveDelayLoadedAPI", "ResolveDelayLoadsFromDll",
        "LdrResolveDelayLoadedAPI", "LdrResolveDelayLoadsFromDll",

        // ---- Functions used by VEH arm/disarm (WriteProcessMemory for INT3 patching) ----
        "WriteProcessMemory",
        "ReadProcessMemory",

        // ---- Functions called by CaptureStringParam inside VEH handler ----
        // Nested exceptions from string capture in VEH causes stack pressure over time.
        "WideCharToMultiByte", "MultiByteToWideChar",
        "CompareStringW", "CompareStringA",
        "CompareStringEx", "CompareStringOrdinal",

        // ---- Functions that break our pipe/logging infrastructure ----
        "NtWriteFile", "NtReadFile", "NtFlushBuffersFile",
        "NtClose",
        "FlushFileBuffers",         // called by our DbgLog

        // ---- Interlocked SList operations (heap free-list corruption) ----
        // The Windows heap uses SLIST_HEADER for lock-free free lists.
        // INT3 in the middle of a CMPXCHG16B-based SList operation corrupts
        // the list head -> heap corruption -> delayed silent crash.
        "InterlockedPopEntrySList", "InterlockedPushEntrySList",
        "InterlockedFlushSList",
        "InitializeSListHead", "QueryDepthSList",
        "RtlInterlockedPopEntrySList", "RtlInterlockedPushEntrySList",
        "RtlInterlockedFlushSList", "RtlFirstEntrySList",
        "RtlQueryDepthSList",

        // ---- Init-once primitives (one-time init state corruption) ----
        "InitOnceBeginInitialize", "InitOnceComplete",
        "InitOnceInitialize", "InitOnceExecuteOnce",

        // ---- Memory/string operations used internally everywhere ----
        "RtlMoveMemory", "RtlCopyMemory", "RtlFillMemory", "RtlZeroMemory",
        "RtlCompareMemory",
        "memcpy", "memmove", "memset", "memcmp",

        // ---- Loader notifications (called during DLL load, fragile state) ----
        "LdrRegisterDllNotification", "LdrUnregisterDllNotification",
        "LdrLockLoaderLock", "LdrUnlockLoaderLock",
        "LdrLoadDll", "LdrUnloadDll",

        // ---- NtQueryInformationProcess/Thread (used by CRT/debugger checks) ----
        "NtQueryInformationProcess", "NtQueryInformationThread",
        "NtSetInformationThread",

        // ---- Child inject infrastructure (hooked by ChildInject via MinHook) ----
        "NtCreateUserProcess",

        // ---- High-frequency message pump / UI noise ----
        // These fire hundreds/thousands of times per second in any GUI app.
        // Window queries
        "IsWindow", "IsWindowVisible", "IsWindowEnabled", "IsWindowUnicode",
        "IsIconic", "IsZoomed", "IsHungAppWindow",
        "GetClientRect", "GetWindowRect", "GetWindowInfo",
        "GetParent", "GetWindow", "GetTopWindow", "GetAncestor",
        "GetForegroundWindow", "GetActiveWindow", "GetFocus", "GetCapture",
        "GetDesktopWindow",
        "GetWindowLongA", "GetWindowLongW",
        "GetWindowLongPtrA", "GetWindowLongPtrW",
        "SetWindowLongA", "SetWindowLongW",
        "SetWindowLongPtrA", "SetWindowLongPtrW",
        "GetClassLongA", "GetClassLongW",
        "GetClassLongPtrA", "GetClassLongPtrW",
        "GetClassNameA", "GetClassNameW",
        "GetWindowTextA", "GetWindowTextW", "GetWindowTextLengthA", "GetWindowTextLengthW",
        "WindowFromPoint", "ChildWindowFromPoint", "ChildWindowFromPointEx",
        "RealChildWindowFromPoint",
        "GetTitleBarInfo",
        "GetWindowPlacement",
        "GetWindowThreadProcessId",
        // Message dispatch (the entire message pump loop)
        "GetMessageA", "GetMessageW",
        "PeekMessageA", "PeekMessageW",
        "TranslateMessage", "TranslateAcceleratorA", "TranslateAcceleratorW",
        "DispatchMessageA", "DispatchMessageW",
        "DefWindowProcA", "DefWindowProcW",
        "CallWindowProcA", "CallWindowProcW",
        "SendMessageA", "SendMessageW",
        "SendMessageTimeoutA", "SendMessageTimeoutW",
        "SendNotifyMessageA", "SendNotifyMessageW",
        "PostMessageA", "PostMessageW",
        "PostThreadMessageA", "PostThreadMessageW",
        "ReplyMessage", "InSendMessage", "InSendMessageEx",
        "MsgWaitForMultipleObjects", "MsgWaitForMultipleObjectsEx",
        "WaitMessage",
        // Mouse/cursor (spikes on mouse movement)
        "SetCursor", "GetCursorPos", "SetCursorPos", "GetCursorInfo",
        "ShowCursor", "ClipCursor", "GetClipCursor",
        "TrackMouseEvent",
        "ScreenToClient", "ClientToScreen", "MapWindowPoints",
        "GetMouseMovePointsEx",
        // Keyboard/input
        "GetKeyState", "GetAsyncKeyState", "GetKeyboardState",
        "GetKeyboardLayout", "GetKeyboardType",
        "GetKeyNameTextA", "GetKeyNameTextW",
        // Timer (notepad caret blink ~500ms)
        "SetTimer", "KillTimer",
        // Caret
        "CreateCaret", "DestroyCaret", "ShowCaret", "HideCaret",
        "GetCaretBlinkTime", "GetCaretPos", "SetCaretPos",
        // Rectangle math
        "OffsetRect", "IntersectRect", "UnionRect", "EqualRect",
        "PtInRect", "InflateRect", "SetRect", "SetRectEmpty",
        "CopyRect", "IsRectEmpty", "SubtractRect",
        // Paint/DC (drawing loop)
        "GetDC", "GetDCEx", "ReleaseDC", "GetWindowDC",
        "BeginPaint", "EndPaint",
        "InvalidateRect", "ValidateRect",
        "InvalidateRgn", "ValidateRgn",
        "UpdateWindow", "RedrawWindow",
        "GetUpdateRect", "GetUpdateRgn",
        // DWM/compositing
        "DwmDefWindowProc", "DwmFlush", "DwmIsCompositionEnabled",
        "DwmGetWindowAttribute", "DwmSetWindowAttribute",
        "DwmExtendFrameIntoClientArea",
        // comctl32 subclassing
        "DefSubclassProc", "SetWindowSubclass", "GetWindowSubclass",
        "RemoveWindowSubclass",
        // ScrollBar
        "GetScrollInfo", "SetScrollInfo", "GetScrollPos", "SetScrollPos",
        "GetScrollRange", "SetScrollRange", "ShowScrollBar", "EnableScrollBar",

        NULL
    };
    for (int i = 0; blacklist[i]; i++)
    {
        if (_stricmp(funcName, blacklist[i]) == 0)
            return true;
    }

    // ---- Prefix-based blacklisting ----
    // Zw* functions are ntdll syscall stubs identical to Nt* equivalents.
    // If NtContinue is blacklisted, ZwContinue at the SAME address must be too.
    // Hooking any Zw* function risks hitting an Nt* function used by exception dispatch.
    if (funcName[0] == 'Z' && funcName[1] == 'w')
        return true;

    // Rtl* are ntdll runtime library functions -- many are in the exception dispatch
    // chain (RtlDispatchException, RtlDecodePointer, RtlRaiseStatus, RtlVirtualUnwind,
    // RtlpCallVectoredHandlers, etc.). Block ALL Rtl* to prevent recursive INT3.
    // Users wanting ntdll monitoring should use Nt* syscall stubs instead.
    if (funcName[0] == 'R' && funcName[1] == 't' && funcName[2] == 'l')
        return true;

    // Ldr* are ntdll loader functions -- called during DLL load/unload with loader
    // lock held. INT3 here risks deadlock or loader state corruption.
    if (funcName[0] == 'L' && funcName[1] == 'd' && funcName[2] == 'r')
        return true;

    return false;
}
