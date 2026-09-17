// <file>
// <summary>
// User-mode debug provider using Windows Debug API (DebugActiveProcess, WaitForDebugEvent, etc.).
// Implements software/hardware breakpoints, single-stepping, and register access.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Providers;

/// <summary>
/// User-mode implementation of IDebugProvider using Windows Debug API.
/// </summary>
public class UserModeDebugProvider : IDebugProvider
{
    private int _processId;
    private int _currentThreadId;
    private bool _isDebugging;
    private bool _isPaused;
    private bool _disposed;
    private bool _singleStepping;
    private ulong _stepOverBreakpoint;
    private readonly Dictionary<ulong, SoftwareBreakpoint> _softwareBreakpoints = new();
    private readonly Dictionary<ulong, BreakpointInfo> _breakpoints = new();
    private readonly object _lock = new();
    private Thread? _debugThread;
    private CancellationTokenSource? _debugCts;

    // Breakpoint tracking for software breakpoints
    private class SoftwareBreakpoint
    {
        public ulong Address { get; init; }
        public byte OriginalByte { get; init; }
        public bool Enabled { get; set; } = true;
    }

    #region Win32 Debug API

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcess(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, int dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugBreakProcess(IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, int dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, int dwSize);

    // Constants
    private const uint DBG_CONTINUE = 0x00010002;
    private const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint THREAD_ALL_ACCESS = 0x001FFFFF;
    private const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    private const uint CONTEXT_AMD64 = 0x00100000;
    private const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x0001;
    private const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x0002;
    private const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x0004;
    private const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x0010;
    private const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    private const uint CONTEXT_ALL = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    // Debug event codes
    private const uint EXCEPTION_DEBUG_EVENT = 1;
    private const uint CREATE_THREAD_DEBUG_EVENT = 2;
    private const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    private const uint EXIT_THREAD_DEBUG_EVENT = 4;
    private const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    private const uint LOAD_DLL_DEBUG_EVENT = 6;
    private const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    private const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    private const uint RIP_EVENT = 9;

    // Exception codes
    private const uint EXCEPTION_BREAKPOINT = 0x80000003;
    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct DEBUG_EVENT
    {
        public uint dwDebugEventCode;
        public int dwProcessId;
        public int dwThreadId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 164)]
        public byte[] u; // Union of debug info structures
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EXCEPTION_RECORD
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecord;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
        public ulong[] ExceptionInformation;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    private struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        // XMM/FPU state follows but we don't need it for basic debugging
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] FltSave;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public ulong[] VectorRegister;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    #endregion

    public string Name => "User Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.UserMode;
    public bool IsAvailable => true;
    public bool IsDebugging => _isDebugging;
    public bool IsPaused => _isPaused;
    public int ProcessId => _processId;
    public int ThreadId => _currentThreadId;

    public event EventHandler<DebugEvent>? DebugEventOccurred;

    public bool Attach(int processId)
    {
        if (_isDebugging)
            Detach();

        // Attach to the process as a debugger
        if (!DebugActiveProcess(processId))
            return false;

        // Don't kill process when debugger exits
        DebugSetProcessKillOnExit(false);

        _processId = processId;
        _isDebugging = true;
        _isPaused = true; // Process stops on attach

        // Start debug event loop in background
        _debugCts = new CancellationTokenSource();
        _debugThread = new Thread(DebugEventLoop) { IsBackground = true, Name = "DebugEventLoop" };
        _debugThread.Start();

        return true;
    }

    public void Detach()
    {
        if (!_isDebugging)
            return;

        // Stop debug thread
        _debugCts?.Cancel();

        // Remove all software breakpoints (restore original bytes)
        var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
        if (processHandle != IntPtr.Zero)
        {
            foreach (var bp in _softwareBreakpoints.Values)
            {
                var buffer = new byte[] { bp.OriginalByte };
                WriteProcessMemory(processHandle, (IntPtr)(long)bp.Address, buffer, 1, out _);
            }
            CloseHandle(processHandle);
        }

        _softwareBreakpoints.Clear();
        _breakpoints.Clear();

        // Detach from process
        DebugActiveProcessStop(_processId);

        _isDebugging = false;
        _isPaused = false;
        _processId = 0;
        _currentThreadId = 0;

        _debugThread?.Join(1000);
        _debugThread = null;
        _debugCts?.Dispose();
        _debugCts = null;
    }

    private void DebugEventLoop()
    {
        while (!_debugCts!.Token.IsCancellationRequested)
        {
            // When paused, avoid tight-polling WaitForDebugEvent
            if (_isPaused)
            {
                Thread.Sleep(50);
                continue;
            }

            if (WaitForDebugEvent(out var debugEvent, 100))
            {
                _currentThreadId = debugEvent.dwThreadId;
                var handled = ProcessDebugEvent(debugEvent);

                if (!_isPaused)
                {
                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                        handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED);
                }
            }
        }
    }

    private bool ProcessDebugEvent(DEBUG_EVENT debugEvent)
    {
        DebugEvent? evt = null;

        switch (debugEvent.dwDebugEventCode)
        {
            case EXCEPTION_DEBUG_EVENT:
                var exRecord = MemoryMarshal.Read<EXCEPTION_RECORD>(debugEvent.u);
                var exAddress = (ulong)exRecord.ExceptionAddress;

                if (exRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                {
                    // Check if this is our breakpoint
                    if (_softwareBreakpoints.TryGetValue(exAddress - 1, out var bp))
                    {
                        _isPaused = true;
                        bp.Enabled = false; // Temporarily disable

                        // Restore original byte and back up RIP
                        var threadHandle = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);
                        if (threadHandle != IntPtr.Zero)
                        {
                            var ctx = new CONTEXT { ContextFlags = CONTEXT_ALL, FltSave = new byte[512], VectorRegister = new ulong[26] };
                            if (GetThreadContext(threadHandle, ref ctx))
                            {
                                ctx.Rip--; // Back up to breakpoint address
                                SetThreadContext(threadHandle, ref ctx);
                            }
                            CloseHandle(threadHandle);
                        }

                        // Restore original byte
                        var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
                        if (processHandle != IntPtr.Zero)
                        {
                            var buffer = new byte[] { bp.OriginalByte };
                            WriteProcessMemory(processHandle, (IntPtr)(long)bp.Address, buffer, 1, out _);
                            FlushInstructionCache(processHandle, (IntPtr)(long)bp.Address, 1);
                            CloseHandle(processHandle);
                        }

                        evt = new DebugEvent
                        {
                            Type = DebugEventType.Breakpoint,
                            ProcessId = debugEvent.dwProcessId,
                            ThreadId = debugEvent.dwThreadId,
                            Address = bp.Address,
                            ExceptionCode = exRecord.ExceptionCode
                        };

                        // Update hit count
                        if (_breakpoints.TryGetValue(bp.Address, out var bpInfo))
                            bpInfo.HitCount++;
                    }
                    else
                    {
                        // Initial breakpoint or other INT3
                        evt = new DebugEvent
                        {
                            Type = DebugEventType.Breakpoint,
                            ProcessId = debugEvent.dwProcessId,
                            ThreadId = debugEvent.dwThreadId,
                            Address = exAddress,
                            ExceptionCode = exRecord.ExceptionCode
                        };
                    }
                    DebugEventOccurred?.Invoke(this, evt);
                    return true;
                }
                else if (exRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
                {
                    if (_singleStepping)
                    {
                        _isPaused = true;
                        _singleStepping = false;

                        // Re-enable breakpoint if we stepped over one
                        if (_stepOverBreakpoint != 0 && _softwareBreakpoints.TryGetValue(_stepOverBreakpoint, out var bp))
                        {
                            bp.Enabled = true;
                            var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
                            if (processHandle != IntPtr.Zero)
                            {
                                var int3 = new byte[] { 0xCC };
                                WriteProcessMemory(processHandle, (IntPtr)(long)bp.Address, int3, 1, out _);
                                FlushInstructionCache(processHandle, (IntPtr)(long)bp.Address, 1);
                                CloseHandle(processHandle);
                            }
                            _stepOverBreakpoint = 0;
                        }

                        evt = new DebugEvent
                        {
                            Type = DebugEventType.SingleStep,
                            ProcessId = debugEvent.dwProcessId,
                            ThreadId = debugEvent.dwThreadId,
                            Address = exAddress,
                            ExceptionCode = exRecord.ExceptionCode
                        };
                        DebugEventOccurred?.Invoke(this, evt);
                    }
                    return true;
                }
                else
                {
                    evt = new DebugEvent
                    {
                        Type = DebugEventType.Exception,
                        ProcessId = debugEvent.dwProcessId,
                        ThreadId = debugEvent.dwThreadId,
                        Address = exAddress,
                        ExceptionCode = exRecord.ExceptionCode
                    };
                    DebugEventOccurred?.Invoke(this, evt);
                    return false; // Let the process handle it
                }

            case CREATE_PROCESS_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.ProcessCreate, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                return true;

            case EXIT_PROCESS_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.ProcessExit, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                _isDebugging = false;
                return true;

            case CREATE_THREAD_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.ThreadCreate, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                return true;

            case EXIT_THREAD_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.ThreadExit, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                return true;

            case LOAD_DLL_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.DllLoad, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                return true;

            case UNLOAD_DLL_DEBUG_EVENT:
                evt = new DebugEvent { Type = DebugEventType.DllUnload, ProcessId = debugEvent.dwProcessId, ThreadId = debugEvent.dwThreadId };
                DebugEventOccurred?.Invoke(this, evt);
                return true;

            default:
                return true;
        }
    }

    public bool SetBreakpoint(ulong address, BreakpointType type = BreakpointType.Software)
    {
        if (!_isDebugging)
            return false;

        lock (_lock)
        {
            if (_breakpoints.ContainsKey(address))
                return false; // Already exists

            if (type == BreakpointType.Software)
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
                if (processHandle == IntPtr.Zero)
                    return false;

                try
                {
                    // Read original byte
                    var originalByte = new byte[1];
                    if (!ReadProcessMemory(processHandle, (IntPtr)(long)address, originalByte, 1, out _))
                        return false;

                    // Write INT3
                    var int3 = new byte[] { 0xCC };
                    if (!WriteProcessMemory(processHandle, (IntPtr)(long)address, int3, 1, out _))
                        return false;

                    FlushInstructionCache(processHandle, (IntPtr)(long)address, 1);

                    _softwareBreakpoints[address] = new SoftwareBreakpoint
                    {
                        Address = address,
                        OriginalByte = originalByte[0]
                    };
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            else if (type == BreakpointType.HardwareExec || type == BreakpointType.HardwareWrite || type == BreakpointType.HardwareRW)
            {
                // Set hardware breakpoint via debug registers
                if (!SetHardwareBreakpoint(address, type))
                    return false;
            }
            else
            {
                return false; // Unsupported type
            }

            _breakpoints[address] = new BreakpointInfo
            {
                Address = address,
                Type = type,
                Enabled = true,
                HitCount = 0
            };

            return true;
        }
    }

    private bool SetHardwareBreakpoint(ulong address, BreakpointType type)
    {
        var threadHandle = OpenThread(THREAD_ALL_ACCESS, false, _currentThreadId);
        if (threadHandle == IntPtr.Zero)
            return false;

        try
        {
            var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS, FltSave = new byte[512], VectorRegister = new ulong[26] };
            if (!GetThreadContext(threadHandle, ref ctx))
                return false;

            // Find free debug register
            int regIndex = -1;
            if ((ctx.Dr7 & 0x01) == 0) regIndex = 0;
            else if ((ctx.Dr7 & 0x04) == 0) regIndex = 1;
            else if ((ctx.Dr7 & 0x10) == 0) regIndex = 2;
            else if ((ctx.Dr7 & 0x40) == 0) regIndex = 3;

            if (regIndex == -1)
                return false; // No free debug register

            // Set address
            switch (regIndex)
            {
                case 0: ctx.Dr0 = address; break;
                case 1: ctx.Dr1 = address; break;
                case 2: ctx.Dr2 = address; break;
                case 3: ctx.Dr3 = address; break;
            }

            // Set DR7 (enable and condition)
            uint condition = type switch
            {
                BreakpointType.HardwareExec => 0,   // Execute
                BreakpointType.HardwareWrite => 1,  // Write
                BreakpointType.HardwareRW => 3,     // Read/Write
                _ => 0
            };

            int shift = regIndex * 4 + 16;
            ctx.Dr7 &= ~(0xFUL << shift); // Clear condition/length
            ctx.Dr7 |= (ulong)condition << shift;
            ctx.Dr7 |= 1UL << (regIndex * 2); // Local enable

            return SetThreadContext(threadHandle, ref ctx);
        }
        finally
        {
            CloseHandle(threadHandle);
        }
    }

    public bool RemoveBreakpoint(ulong address)
    {
        if (!_isDebugging)
            return false;

        lock (_lock)
        {
            if (!_breakpoints.TryGetValue(address, out var bp))
                return false;

            if (bp.Type == BreakpointType.Software && _softwareBreakpoints.TryGetValue(address, out var sbp))
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
                if (processHandle != IntPtr.Zero)
                {
                    var buffer = new byte[] { sbp.OriginalByte };
                    WriteProcessMemory(processHandle, (IntPtr)(long)address, buffer, 1, out _);
                    FlushInstructionCache(processHandle, (IntPtr)(long)address, 1);
                    CloseHandle(processHandle);
                }
                _softwareBreakpoints.Remove(address);
            }

            _breakpoints.Remove(address);
            return true;
        }
    }

    public bool EnableBreakpoint(ulong address, bool enabled)
    {
        lock (_lock)
        {
            if (!_breakpoints.TryGetValue(address, out var bp))
                return false;

            bp.Enabled = enabled;

            if (bp.Type == BreakpointType.Software && _softwareBreakpoints.TryGetValue(address, out var sbp))
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
                if (processHandle != IntPtr.Zero)
                {
                    var buffer = enabled ? new byte[] { 0xCC } : new byte[] { sbp.OriginalByte };
                    WriteProcessMemory(processHandle, (IntPtr)(long)address, buffer, 1, out _);
                    FlushInstructionCache(processHandle, (IntPtr)(long)address, 1);
                    CloseHandle(processHandle);
                }
                sbp.Enabled = enabled;
            }

            return true;
        }
    }

    public IEnumerable<BreakpointInfo> GetBreakpoints()
    {
        lock (_lock)
        {
            return _breakpoints.Values.ToList();
        }
    }

    public void Continue()
    {
        if (!_isDebugging || !_isPaused)
            return;

        // Check if we need to re-enable a breakpoint after stepping over it
        var ctx = GetRegistersInternal(_currentThreadId);
        if (ctx != null && _softwareBreakpoints.TryGetValue(ctx.Rip, out var bp) && !bp.Enabled)
        {
            // Set single-step to step over the breakpoint, then re-enable it
            _stepOverBreakpoint = bp.Address;
            bp.Enabled = true;
            EnableSingleStep(true);
            _singleStepping = true;
        }

        _isPaused = false;
        ContinueDebugEvent(_processId, _currentThreadId, DBG_CONTINUE);
    }

    public void StepInto()
    {
        if (!_isDebugging || !_isPaused)
            return;

        _singleStepping = true;
        EnableSingleStep(true);
        _isPaused = false;
        ContinueDebugEvent(_processId, _currentThreadId, DBG_CONTINUE);
    }

    public void StepOver()
    {
        // For now, same as StepInto. Full implementation would check for CALL instruction
        // and set a temporary breakpoint after it.
        StepInto();
    }

    public void StepOut()
    {
        // Would need to set breakpoint at return address
        // For now, just continue
        Continue();
    }

    public void Pause()
    {
        if (!_isDebugging || _isPaused)
            return;

        var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _processId);
        if (processHandle != IntPtr.Zero)
        {
            DebugBreakProcess(processHandle);
            CloseHandle(processHandle);
        }
    }

    private void EnableSingleStep(bool enable)
    {
        var threadHandle = OpenThread(THREAD_ALL_ACCESS, false, _currentThreadId);
        if (threadHandle == IntPtr.Zero)
            return;

        try
        {
            var ctx = new CONTEXT { ContextFlags = CONTEXT_CONTROL, FltSave = new byte[512], VectorRegister = new ulong[26] };
            if (GetThreadContext(threadHandle, ref ctx))
            {
                if (enable)
                    ctx.EFlags |= 0x100; // Set TF
                else
                    ctx.EFlags &= ~0x100u; // Clear TF

                SetThreadContext(threadHandle, ref ctx);
            }
        }
        finally
        {
            CloseHandle(threadHandle);
        }
    }

    public RegisterContext GetRegisters() => GetRegisters(_currentThreadId);

    public RegisterContext GetRegisters(int threadId)
    {
        return GetRegistersInternal(threadId) ?? new RegisterContext();
    }

    private RegisterContext? GetRegistersInternal(int threadId)
    {
        var threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
        if (threadHandle == IntPtr.Zero)
            return null;

        try
        {
            var ctx = new CONTEXT { ContextFlags = CONTEXT_ALL, FltSave = new byte[512], VectorRegister = new ulong[26] };
            if (!GetThreadContext(threadHandle, ref ctx))
                return null;

            return new RegisterContext
            {
                Rax = ctx.Rax, Rbx = ctx.Rbx, Rcx = ctx.Rcx, Rdx = ctx.Rdx,
                Rsi = ctx.Rsi, Rdi = ctx.Rdi, Rbp = ctx.Rbp, Rsp = ctx.Rsp,
                R8 = ctx.R8, R9 = ctx.R9, R10 = ctx.R10, R11 = ctx.R11,
                R12 = ctx.R12, R13 = ctx.R13, R14 = ctx.R14, R15 = ctx.R15,
                Rip = ctx.Rip, EFlags = ctx.EFlags,
                Cs = ctx.SegCs, Ds = ctx.SegDs, Es = ctx.SegEs,
                Fs = ctx.SegFs, Gs = ctx.SegGs, Ss = ctx.SegSs,
                Dr0 = ctx.Dr0, Dr1 = ctx.Dr1, Dr2 = ctx.Dr2,
                Dr3 = ctx.Dr3, Dr6 = ctx.Dr6, Dr7 = ctx.Dr7
            };
        }
        finally
        {
            CloseHandle(threadHandle);
        }
    }

    public bool SetRegisters(RegisterContext context)
    {
        var threadHandle = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, _currentThreadId);
        if (threadHandle == IntPtr.Zero)
            return false;

        try
        {
            var ctx = new CONTEXT { ContextFlags = CONTEXT_ALL, FltSave = new byte[512], VectorRegister = new ulong[26] };
            if (!GetThreadContext(threadHandle, ref ctx))
                return false;

            ctx.Rax = context.Rax; ctx.Rbx = context.Rbx; ctx.Rcx = context.Rcx; ctx.Rdx = context.Rdx;
            ctx.Rsi = context.Rsi; ctx.Rdi = context.Rdi; ctx.Rbp = context.Rbp; ctx.Rsp = context.Rsp;
            ctx.R8 = context.R8; ctx.R9 = context.R9; ctx.R10 = context.R10; ctx.R11 = context.R11;
            ctx.R12 = context.R12; ctx.R13 = context.R13; ctx.R14 = context.R14; ctx.R15 = context.R15;
            ctx.Rip = context.Rip; ctx.EFlags = context.EFlags;
            ctx.SegCs = context.Cs; ctx.SegDs = context.Ds; ctx.SegEs = context.Es;
            ctx.SegFs = context.Fs; ctx.SegGs = context.Gs; ctx.SegSs = context.Ss;
            ctx.Dr0 = context.Dr0; ctx.Dr1 = context.Dr1; ctx.Dr2 = context.Dr2;
            ctx.Dr3 = context.Dr3; ctx.Dr6 = context.Dr6; ctx.Dr7 = context.Dr7;

            return SetThreadContext(threadHandle, ref ctx);
        }
        finally
        {
            CloseHandle(threadHandle);
        }
    }

    public DebugEvent? WaitForEvent(int timeoutMs = -1)
    {
        // Events are processed in background thread and delivered via event
        // This method could be used for synchronous waiting if needed
        return null;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Detach();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
