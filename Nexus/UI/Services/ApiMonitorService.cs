// <file>
// <summary>
// API monitoring service managing the full lifecycle of API call interception.
// Injects NexusApiHook.dll (or NexusApiHook32.dll for WoW64 processes) into target
// processes, establishes a named pipe for bidirectional communication, sends API
// hook configuration (which functions to intercept), and receives real-time API call
// events including parameters, return values, and timestamps. Supports child process
// spawning notifications and automatic hook propagation to child processes.
// </summary>
// </file>

using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Nexus.UI.Core;
using Nexus.UI.Models;

namespace Nexus.UI.Services;

/// <summary>
/// Service for injecting API hook DLLs and receiving intercepted API call events via named pipes.
/// <para>
/// Lifecycle: Start() injects the hook DLL and opens a named pipe server. The DLL connects
/// back, receives configuration (list of APIs to hook), and begins streaming MSG_EVENT messages
/// for each intercepted call. Stop() signals the DLL to unhook and clean up.
/// </para>
/// <para>
/// Wire protocol constants (MSG_CONFIGURE, MSG_EVENT, etc.) must match the C definitions
/// in NexusApiHook's protocol.h header.
/// </para>
/// </summary>
public partial class ApiMonitorService : IDisposable
{
    private const string HookDllName64 = "NexusApiHook.dll";
    private const string HookDllName32 = "NexusApiHook32.dll";

    // Wire protocol constants (must match protocol.h)
    private const byte MSG_CONFIGURE = 0x01;
    private const byte MSG_STOP = 0x02;
    private const byte MSG_READY = 0x10;
    private const byte MSG_EVENT = 0x11;
    private const byte MSG_ERROR = 0x12;
    private const byte MSG_CHILD_CREATED = 0x13;

    // Parameter flags (must match protocol.h)
    private const byte PARAM_FLAG_OUTPUT = 0x01;
    private const byte PARAM_FLAG_POINTER = 0x02;
    private const byte PARAM_FLAG_WIDE_STRING = 0x04;
    private const byte PARAM_FLAG_ANSI_STRING = 0x08;
    private const byte PARAM_FLAG_OPTIONAL = 0x10;
    private const byte PARAM_FLAG_BUFFER = 0x20;
    // PARAM_FLAG_OBJECT_ATTRIBUTES: dereference POBJECT_ATTRIBUTES at hook
    // time and capture the embedded ObjectName.Buffer (UTF-8). Required for
    // NT* APIs like NtCreateFile/NtOpenKey to expose actual file/registry
    // paths instead of opaque pointers.
    private const byte PARAM_FLAG_OBJECT_ATTRIBUTES = 0x40;

    private bool _isMonitoring;
    private int _targetPid;
    private Thread? _pipeThread;
    private CancellationTokenSource? _cts;
    private NamedPipeServerStream? _pipeServer;
    private EventWaitHandle? _stopEvent;
    private ApiDefinition[]? _configuredApis;
    private volatile bool _pipeConnected;

    // For child services: deferred module filtering happens in PipeListenerThread
    // after the child connects, so the pipe exists immediately for the child to find.
    private List<ApiDefinition>? _deferredApiDefinitions;

    // QPC frequency for converting ticks to TimeSpan
    private static readonly long QpcFrequency;

    static ApiMonitorService()
    {
        QueryPerformanceFrequency(out QpcFrequency);
    }

    /// <summary>
    /// Fired when an API call is captured from the hook DLL.
    /// </summary>
    public event Action<ApiCallEvent>? OnApiCalled;

    /// <summary>
    /// Fired when the hook DLL reports an error.
    /// </summary>
    public event Action<string>? OnError;

    /// <summary>
    /// Fired when hook installation results are received.
    /// </summary>
    public event Action<int, int, int>? OnReady; // total, success, fail

    /// <summary>
    /// Fired when the hook DLL reports a child process was created.
    /// The DLL has already injected itself into the child via APC.
    /// </summary>
    public event Action<int>? OnChildCreated; // childPid

    /// <summary>
    /// Whether at least one hook DLL (x64 or x86) exists and can be used.
    /// </summary>
    public bool IsHookDllAvailable
    {
        get
        {
            var dll64 = FindHookDll(HookDllName64);
            var dll32 = FindHookDll(HookDllName32);
            return (dll64 != null && File.Exists(dll64)) ||
                   (dll32 != null && File.Exists(dll32));
        }
    }

    /// <summary>
    /// Starts monitoring the specified process using ProcessContext handle.
    /// </summary>
    public bool StartMonitoring(int pid, List<ApiDefinition> apiDefinitions)
    {
        return StartMonitoring(pid, IntPtr.Zero, apiDefinitions);
    }

    /// <summary>
    /// Starts monitoring with an explicit process handle.
    /// Use this overload when a handle is already open (e.g. from watchlist).
    /// </summary>
    /// <param name="pid">Target process ID.</param>
    /// <param name="processHandle">Open process handle. If Zero, uses ProcessContext.Current.</param>
    /// <param name="apiDefinitions">Resolved API definitions to hook.</param>
    /// <returns>True if monitoring started successfully.</returns>
    public bool StartMonitoring(int pid, IntPtr processHandle, List<ApiDefinition> apiDefinitions)
    {
        if (_isMonitoring) return true;

        var injectionHandle = processHandle != IntPtr.Zero
            ? processHandle
            : ProcessContext.Current.NativeProcessHandle;

        _targetPid = pid;

        // Pre-filter: only send APIs for modules actually loaded in the target process
        // AND that aren't blacklisted by the hook engine. This reduces the total from
        // ~12738 to ~5000 (module filter) and eliminates ~2000 blacklist failures.
        var loadedModules = EnumerateProcessModules((uint)pid);
        var filtered = loadedModules.Count > 0
            ? apiDefinitions.Where(a => loadedModules.Contains(a.Module.ToLowerInvariant())
                                     && !IsBlacklistedApi(a.Name)).ToList()
            : apiDefinitions.Where(a => !IsBlacklistedApi(a.Name)).ToList();

        _configuredApis = PrioritizeApiDefinitions(filtered);
        _cts = new CancellationTokenSource();
        _isMonitoring = true;
        _pipeConnected = false;

        if (injectionHandle == IntPtr.Zero)
        {
            OnError?.Invoke("Process handle is null - cannot inject");
            _isMonitoring = false;
            return false;
        }

        // Create pipe BEFORE injection so DLL can connect immediately.
        var pipeName = $"NexusApiMonitor_{pid}";
        try
        {
            var pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            _pipeServer = NamedPipeServerStreamAcl.Create(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.None,
                65536,
                65536,
                pipeSecurity);
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Pipe creation failed: {ex.Message}");
            _isMonitoring = false;
            return false;
        }

        var stopEventName = $"NexusApiMonitorStop_{pid}";
        _stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, stopEventName);

        _pipeThread = new Thread(PipeListenerThread)
        {
            Name = "ApiMonitor_PipeListener",
            IsBackground = true
        };
        _pipeThread.Start();

        // Injection runs on a background thread to avoid blocking the UI.
        // ManualMap's WaitForSingleObject and CreateRemoteThread can take seconds.
        var injectionThread = new Thread(() =>
        {
            PerformInjection(pid, injectionHandle);
        }) { Name = "ApiMonitor_Injection", IsBackground = true };
        injectionThread.Start();

        return true; // Monitoring started — injection happening in background
    }

    /// <summary>
    /// Performs DLL injection on a background thread. Reports errors via OnError.
    /// </summary>
    private void PerformInjection(int pid, IntPtr injectionHandle)
    {
        try
        {
            // Phase 1: Try x64 injection (all methods)
            string? x64Error = TryInjectDll(pid, injectionHandle, isTarget32Bit: false);
            if (x64Error == null)
                return; // Success — x64 target

            // Phase 2: Try x86 injection with WoW64-aware DirectInject
            string? wow64Error = null;
            var dll32Path = FindHookDll(HookDllName32);
            if (dll32Path != null)
            {
                wow64Error = DirectInjectDllWow64((uint)pid, dll32Path);
                if (wow64Error == null)
                    return; // Success — x86 target via WoW64 injection
            }

            // Phase 3: All injection methods reported failure, but the DLL may have
            // actually loaded (some engines return error even when LoadLibrary succeeds).
            // Wait briefly to see if the DLL connects to our pipe.
            for (int i = 0; i < 30 && !_pipeConnected; i++) // up to 3 seconds
                Thread.Sleep(100);

            if (_pipeConnected)
                return; // DLL loaded and connected despite injection "failure"

            if (dll32Path != null)
                OnError?.Invoke($"Injection failed: x64=[{x64Error}] x86=[{wow64Error}]");
            else
                OnError?.Invoke($"Injection failed (x64): {x64Error} — x86 DLL not available");

            StopMonitoring();
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Injection exception: {ex.Message}");
            StopMonitoring();
        }
    }

    /// <summary>
    /// Starts monitoring a child process that was already injected via APC by its parent.
    /// Only creates the pipe and listener — no injection needed.
    /// </summary>
    public bool StartMonitoringChild(int childPid, List<ApiDefinition> apiDefinitions)
    {
        if (_isMonitoring) return true;

        _targetPid = childPid;

        // CRITICAL: Create pipe FIRST, defer module filtering to PipeListenerThread.
        // Module enumeration can take up to 2s (retry loop for new processes), and
        // the child's DLL is already trying to connect. If the pipe doesn't exist
        // when the child connects, it dies before we can configure it.
        _deferredApiDefinitions = apiDefinitions;
        _configuredApis = null; // will be set in PipeListenerThread after filtering
        _cts = new CancellationTokenSource();
        _isMonitoring = true;
        _pipeConnected = false;

        var pipeName = $"NexusApiMonitor_{childPid}";
        try
        {
            var pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            _pipeServer = NamedPipeServerStreamAcl.Create(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.None,
                65536,
                65536,
                pipeSecurity);
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Child pipe creation failed (PID {childPid}): {ex.Message}");
            _isMonitoring = false;
            return false;
        }

        var stopEventName = $"NexusApiMonitorStop_{childPid}";
        _stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, stopEventName);

        _pipeThread = new Thread(PipeListenerThread)
        {
            Name = $"ApiMonitor_Child_{childPid}",
            IsBackground = true
        };
        _pipeThread.Start();

        return true; // No injection — DLL already loaded in child via APC
    }

    /// <summary>
    /// Stops monitoring and cleans up resources.
    /// Signals the stop event, waits for the DLL to drain remaining events
    /// and disconnect, then closes the pipe.
    /// </summary>
    public void StopMonitoring()
    {
        if (!_isMonitoring) return;
        _isMonitoring = false;

        // Signal the DLL to stop via the named event.
        // The DLL's worker thread waits on this event instead of reading MSG_STOP
        // from the pipe, because synchronous pipe handles serialize I/O — a
        // blocking NtReadFile on the worker thread would prevent the drain thread
        // from writing events via NtWriteFile.
        try { _stopEvent?.Set(); }
        catch { /* best effort */ }

        // Wait for the pipe listener thread to exit naturally.
        // The DLL will drain remaining events, then disconnect.
        _pipeThread?.Join(5000);

        _cts?.Cancel();
        try { _pipeServer?.Dispose(); } catch { }
        try { _stopEvent?.Dispose(); } catch { }
        _pipeServer = null;
        _pipeThread = null;
        _stopEvent = null;
        _configuredApis = null;
    }

    /// <summary>
    /// Pipe listener thread: waits for DLL connection, sends configuration,
    /// then reads events until stopped.
    /// </summary>
    private void PipeListenerThread()
    {
        var ct = _cts?.Token ?? CancellationToken.None;

        try
        {
            // Wait for the injected DLL to connect (15 second timeout).
            // Use a helper thread since synchronous WaitForConnection has no timeout.
            bool connected = false;
            var connectThread = new Thread(() =>
            {
                try { _pipeServer!.WaitForConnection(); connected = true; _pipeConnected = true; }
                catch { /* pipe disposed or error */ }
            }) { IsBackground = true };
            connectThread.Start();
            if (!connectThread.Join(15000) || !connected)
            {
                OnError?.Invoke("Hook DLL did not connect within 15 seconds - DLL may have crashed or failed to load");
                return;
            }

            // If this is a child service, do deferred module filtering now
            // (on the background thread, after pipe is connected).
            // CRITICAL: No retry loop — child processes in the EAC launcher chain
            // are extremely short-lived. The 2s retry loop was causing the child
            // to exit before MSG_CONFIGURE was sent. One instant attempt, then
            // fall back to blacklist-only filtering.
            if (_deferredApiDefinitions != null)
            {
                var deferred = _deferredApiDefinitions;
                _deferredApiDefinitions = null;

                var loadedModules = EnumerateProcessModules((uint)_targetPid);
                var filtered = loadedModules.Count > 0
                    ? deferred.Where(a => loadedModules.Contains(a.Module.ToLowerInvariant())
                                         && !IsBlacklistedApi(a.Name)).ToList()
                    : deferred.Where(a => !IsBlacklistedApi(a.Name)).ToList();
                _configuredApis = PrioritizeApiDefinitions(filtered);
            }

            // Send MSG_CONFIGURE with the list of APIs to hook
            SendConfigure();

            // Read message loop — keep reading until pipe disconnects.
            while (!ct.IsCancellationRequested && _pipeServer is { IsConnected: true })
            {
                var (type, payload) = ReadMessage();
                if (payload == null) break;

                switch (type)
                {
                    case MSG_READY:
                        HandleReady(payload);
                        break;
                    case MSG_EVENT:
                        HandleEvent(payload);
                        break;
                    case MSG_ERROR:
                        HandleError(payload);
                        break;
                    case MSG_CHILD_CREATED:
                        HandleChildCreated(payload);
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    #region Message I/O

    /// <summary>
    /// Sends a framed message: [uint32 length][uint8 type][payload].
    /// </summary>
    private void SendMessage(byte type, ReadOnlySpan<byte> payload)
    {
        if (_pipeServer == null || !_pipeServer.IsConnected) return;

        uint frameLen = (uint)(1 + payload.Length);
        Span<byte> header = stackalloc byte[5];
        BitConverter.TryWriteBytes(header, frameLen);
        header[4] = type;

        _pipeServer.Write(header);
        if (payload.Length > 0)
            _pipeServer.Write(payload);
        _pipeServer.Flush();
    }

    /// <summary>
    /// Reads a framed message. Returns (type, payload) or (0, null) on disconnect.
    /// </summary>
    private (byte type, byte[]? payload) ReadMessage()
    {
        if (_pipeServer == null) return (0, null);

        // Read 4-byte length prefix
        var lenBuf = new byte[4];
        if (!ReadExact(lenBuf, 4)) return (0, null);
        uint frameLen = BitConverter.ToUInt32(lenBuf, 0);
        if (frameLen < 1) return (0, null);

        // Read type byte
        var typeBuf = new byte[1];
        if (!ReadExact(typeBuf, 1)) return (0, null);

        uint payloadLen = frameLen - 1;
        byte[]? payload = null;
        if (payloadLen > 0)
        {
            payload = new byte[payloadLen];
            if (!ReadExact(payload, (int)payloadLen)) return (0, null);
        }
        else
        {
            payload = [];
        }

        return (typeBuf[0], payload);
    }

    private bool ReadExact(byte[] buffer, int count)
    {
        int offset = 0;
        while (offset < count)
        {
            int read = _pipeServer!.Read(buffer, offset, count - offset);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    #endregion

    // API Prioritization -> ApiMonitorService.Config.cs
    // MSG_CONFIGURE Serialization -> ApiMonitorService.Config.cs
    // Message Handlers -> ApiMonitorService.Messages.cs
    // Injection methods -> ApiMonitorService.Injection.cs
    // P/Invoke declarations -> ApiMonitorService.PInvoke.cs


    /// <summary>
    /// Mirrors the hook engine's IsBlacklisted() — filters out functions that the DLL
    /// would reject anyway (exception dispatch, sync primitives, message pump noise, etc.).
    /// Must stay in sync with hook_engine.cpp IsBlacklisted().
    /// </summary>
    private static bool IsBlacklistedApi(string funcName)
    {
        // Prefix-based blacklisting (matches hook_engine.cpp)
        if (funcName.StartsWith("Zw", StringComparison.Ordinal)) return true;
        if (funcName.StartsWith("Rtl", StringComparison.Ordinal)) return true;
        if (funcName.StartsWith("Ldr", StringComparison.Ordinal)) return true;

        // Exact-match blacklist — all entries from hook_engine.cpp IsBlacklisted()
        return BlacklistedFunctions.Contains(funcName);
    }

    private static readonly HashSet<string> BlacklistedFunctions = new(StringComparer.Ordinal)
    {
        // MinHook internals
        "VirtualProtect", "VirtualProtectEx", "FlushInstructionCache",
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
        "VirtualQuery", "VirtualQueryEx",
        // RegisterHook internals
        "GetProcAddress", "GetProcAddressForCaller",
        "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
        "LdrGetDllHandle", "LdrGetProcedureAddress",
        "GetSystemInfo", "GetNativeSystemInfo",
        // Exception dispatch
        "RtlLookupFunctionEntry", "RtlVirtualUnwind", "RtlCaptureContext",
        "RtlUnwindEx", "RtlUnwind", "RtlRestoreContext", "RtlRaiseException",
        "RtlDispatchException", "RtlPcToFileHeader", "RtlImageNtHeader", "RtlImageNtHeaderEx",
        "KiUserExceptionDispatcher", "NtContinue", "NtRaiseException",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",
        // Sync primitives
        "IsDebuggerPresent", "CloseHandle", "ReleaseMutex",
        "WaitForSingleObject", "WaitForSingleObjectEx",
        "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
        "SetWaitableTimer", "CancelWaitableTimer", "Sleep", "SleepEx",
        "SetEvent", "ResetEvent", "PulseEvent", "SignalObjectAndWait",
        "NtWaitForSingleObject", "NtWaitForMultipleObjects", "NtSignalAndWaitForSingleObject",
        "NtSetEvent", "NtResetEvent", "NtPulseEvent", "NtClearEvent",
        "NtReleaseSemaphore", "NtReleaseMutant",
        "NtCreateEvent", "NtOpenEvent", "NtCreateSemaphore", "NtOpenSemaphore",
        "NtCreateMutant", "NtOpenMutant",
        "NtCreateTimer", "NtOpenTimer", "NtSetTimer", "NtCancelTimer",
        "NtCreateKeyedEvent", "NtOpenKeyedEvent",
        "NtWaitForKeyedEvent", "NtReleaseKeyedEvent",
        "NtWaitForAlertByThreadId", "NtAlertThreadByThreadId",
        "GetTickCount", "GetTickCount64", "GetSystemTimeAsFileTime",
        "QueryPerformanceCounter", "GetLastError", "SetLastError",
        "GetCurrentThreadId", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentProcess",
        "TlsGetValue", "TlsSetValue",
        "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
        "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
        "InitializeCriticalSectionEx", "DeleteCriticalSection",
        "AcquireSRWLockExclusive", "AcquireSRWLockShared",
        "TryAcquireSRWLockExclusive", "TryAcquireSRWLockShared",
        "ReleaseSRWLockExclusive", "ReleaseSRWLockShared", "InitializeSRWLock",
        "SleepConditionVariableCS", "SleepConditionVariableSRW",
        "WakeConditionVariable", "WakeAllConditionVariable", "InitializeConditionVariable",
        "InterlockedIncrement", "InterlockedDecrement",
        "InterlockedExchange", "InterlockedCompareExchange",
        "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
        "RtlAllocateHeap", "RtlFreeHeap", "GetProcessHeap",
        // ETW
        "EventWriteTransfer", "EventEnabled", "EventWrite",
        "EventRegister", "EventUnregister", "EventActivityIdControl",
        "EtwEventWriteTransfer", "EtwEventEnabled", "EtwEventWrite",
        // Pointer encoding
        "DecodePointer", "EncodePointer", "DecodeSystemPointer", "EncodeSystemPointer",
        "RtlDecodePointer", "RtlEncodePointer", "RtlDecodeRemotePointer", "RtlEncodeRemotePointer",
        // Delay-load
        "DelayLoadFailureHook", "ResolveDelayLoadedAPI", "ResolveDelayLoadsFromDll",
        "LdrResolveDelayLoadedAPI", "LdrResolveDelayLoadsFromDll",
        // Pipe/logging
        "WriteProcessMemory", "ReadProcessMemory",
        "WideCharToMultiByte", "MultiByteToWideChar",
        "CompareStringW", "CompareStringA", "CompareStringEx", "CompareStringOrdinal",
        "NtWriteFile", "NtReadFile", "NtFlushBuffersFile", "NtClose", "FlushFileBuffers",
        // SList (heap corruption)
        "InterlockedPopEntrySList", "InterlockedPushEntrySList", "InterlockedFlushSList",
        "InitializeSListHead", "QueryDepthSList",
        "RtlInterlockedPopEntrySList", "RtlInterlockedPushEntrySList",
        "RtlInterlockedFlushSList", "RtlFirstEntrySList", "RtlQueryDepthSList",
        // Init-once
        "InitOnceBeginInitialize", "InitOnceComplete", "InitOnceInitialize", "InitOnceExecuteOnce",
        // Memory ops
        "RtlMoveMemory", "RtlCopyMemory", "RtlFillMemory", "RtlZeroMemory", "RtlCompareMemory",
        "memcpy", "memmove", "memset", "memcmp",
        // Loader
        "LdrRegisterDllNotification", "LdrUnregisterDllNotification",
        "LdrLockLoaderLock", "LdrUnlockLoaderLock", "LdrLoadDll", "LdrUnloadDll",
        // Query info
        "NtQueryInformationProcess", "NtQueryInformationThread", "NtSetInformationThread",
        // Child inject infrastructure (hooked by ChildInject via MinHook)
        "NtCreateUserProcess",
        // Message pump / UI noise
        "IsWindow", "IsWindowVisible", "IsWindowEnabled", "IsWindowUnicode",
        "IsIconic", "IsZoomed", "IsHungAppWindow",
        "GetClientRect", "GetWindowRect", "GetWindowInfo",
        "GetParent", "GetWindow", "GetTopWindow", "GetAncestor",
        "GetForegroundWindow", "GetActiveWindow", "GetFocus", "GetCapture", "GetDesktopWindow",
        "GetWindowLongA", "GetWindowLongW", "GetWindowLongPtrA", "GetWindowLongPtrW",
        "SetWindowLongA", "SetWindowLongW", "SetWindowLongPtrA", "SetWindowLongPtrW",
        "GetClassLongA", "GetClassLongW", "GetClassLongPtrA", "GetClassLongPtrW",
        "GetClassNameA", "GetClassNameW",
        "GetWindowTextA", "GetWindowTextW", "GetWindowTextLengthA", "GetWindowTextLengthW",
        "WindowFromPoint", "ChildWindowFromPoint", "ChildWindowFromPointEx", "RealChildWindowFromPoint",
        "GetTitleBarInfo", "GetWindowPlacement", "GetWindowThreadProcessId",
        "GetMessageA", "GetMessageW", "PeekMessageA", "PeekMessageW",
        "TranslateMessage", "TranslateAcceleratorA", "TranslateAcceleratorW",
        "DispatchMessageA", "DispatchMessageW",
        "DefWindowProcA", "DefWindowProcW", "CallWindowProcA", "CallWindowProcW",
        "SendMessageA", "SendMessageW", "SendMessageTimeoutA", "SendMessageTimeoutW",
        "SendNotifyMessageA", "SendNotifyMessageW",
        "PostMessageA", "PostMessageW", "PostThreadMessageA", "PostThreadMessageW",
        "ReplyMessage", "InSendMessage", "InSendMessageEx",
        "MsgWaitForMultipleObjects", "MsgWaitForMultipleObjectsEx", "WaitMessage",
        "SetCursor", "GetCursorPos", "SetCursorPos", "GetCursorInfo",
        "ShowCursor", "ClipCursor", "GetClipCursor", "TrackMouseEvent",
        "ScreenToClient", "ClientToScreen", "MapWindowPoints", "GetMouseMovePointsEx",
        "GetKeyState", "GetAsyncKeyState", "GetKeyboardState",
        "GetKeyboardLayout", "GetKeyboardType", "GetKeyNameTextA", "GetKeyNameTextW",
        "SetTimer", "KillTimer",
        "CreateCaret", "DestroyCaret", "ShowCaret", "HideCaret",
        "GetCaretBlinkTime", "GetCaretPos", "SetCaretPos",
        "OffsetRect", "IntersectRect", "UnionRect", "EqualRect",
        "PtInRect", "InflateRect", "SetRect", "SetRectEmpty", "CopyRect", "IsRectEmpty", "SubtractRect",
        "GetDC", "GetDCEx", "ReleaseDC", "GetWindowDC",
        "BeginPaint", "EndPaint", "InvalidateRect", "ValidateRect",
        "InvalidateRgn", "ValidateRgn", "UpdateWindow", "RedrawWindow",
        "GetUpdateRect", "GetUpdateRgn",
        "DwmDefWindowProc", "DwmFlush", "DwmIsCompositionEnabled",
        "DwmGetWindowAttribute", "DwmSetWindowAttribute", "DwmExtendFrameIntoClientArea",
        "DefSubclassProc", "SetWindowSubclass", "GetWindowSubclass", "RemoveWindowSubclass",
        "GetScrollInfo", "SetScrollInfo", "GetScrollPos", "SetScrollPos",
        "GetScrollRange", "SetScrollRange", "ShowScrollBar", "EnableScrollBar",
    };

    /// <summary>
    /// Enumerates loaded modules in the target process.
    /// Returns a HashSet of lowercase module filenames (e.g. "kernel32.dll").
    /// Used to pre-filter API definitions before sending to the hook DLL.
    /// </summary>
    private static HashSet<string> EnumerateProcessModules(uint pid)
    {
        var modules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 captures both x64 and WoW64 modules
        var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1))
            return modules;

        try
        {
            var me = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (Module32FirstW(hSnap, ref me))
            {
                do
                {
                    if (!string.IsNullOrEmpty(me.szModule))
                        modules.Add(me.szModule.ToLowerInvariant());
                } while (Module32NextW(hSnap, ref me));
            }
        }
        finally
        {
            CloseHandle(hSnap);
        }

        return modules;
    }

    /// <summary>
    /// Resolves the absolute path of the 64-bit hook DLL, or null if not found.
    /// Exposed so other components (e.g. ApiMonPanel kernel-APC inject path)
    /// can locate the same DLL the service would use.
    /// </summary>
    public static string? GetHookDll64Path() => FindHookDll(HookDllName64);

    /// <summary>
    /// Searches for the specified hook DLL in known locations.
    /// </summary>
    private static string? FindHookDll(string dllName)
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(baseDir, dllName),
            Path.Combine(baseDir, "hooks", dllName),
            Path.Combine(baseDir, "..", "hooks", dllName),
            // Dev-time: built by Native/ApiHook project
            Path.Combine(baseDir, "..", "Native", "ApiHook", "bin", "Release", dllName),
            Path.Combine(baseDir, "..", "Native", "ApiHook", "bin", "Debug", dllName),
        ];

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return Path.GetFullPath(path);
        }

        return null;
    }

    public void Dispose()
    {
        StopMonitoring();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
