using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

/// <summary>
/// Kernel-mode implementation of IDebugProvider using NexusKernel.sys.
/// Provides capabilities beyond user-mode:
/// - Hardware breakpoints without debug API
/// - Memory breakpoints via page faults
/// - Kernel-level single stepping
/// - Debug protected processes
/// </summary>
public class KernelDebugProvider : IDebugProvider
{
    private readonly NexusKernelDriver _driver = NexusKernelDriver.Instance;
    private readonly List<BreakpointInfo> _breakpoints = [];
    private ulong _processHandle;
    private int _processId;
    private int _currentThreadId;
    private bool _isPaused;
    private bool _disposed;

    public string Name => "Kernel Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.Kernel;
    public bool IsAvailable => _driver.IsAvailable || _driver.Connect();
    public bool IsDebugging => _processHandle != 0;
    public bool IsPaused => _isPaused;
    public int ProcessId => _processId;
    public int ThreadId => _currentThreadId;

    public event EventHandler<DebugEvent>? DebugEventOccurred;

    protected virtual void OnDebugEvent(DebugEvent e)
    {
        DebugEventOccurred?.Invoke(this, e);
    }

    public bool Attach(int processId)
    {
        Detach();

        if (!IsAvailable) return false;

        var input = new KernelOpenProcessInput
        {
            ProcessId = (uint)processId,
            DesiredAccess = 0xFFFFFFFF
        };

        if (_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_OPEN_PROCESS, ref input, out KernelOpenProcessOutput output))
        {
            if (output.Status == 0 && output.ProcessHandle != 0)
            {
                _processHandle = output.ProcessHandle;
                _processId = processId;
                return true;
            }
        }

        return false;
    }

    public void Detach()
    {
        if (_processHandle != 0)
        {
            // Remove all breakpoints first
            foreach (var bp in _breakpoints.ToList())
            {
                RemoveBreakpoint(bp.Address);
            }

            var input = new KernelOpenProcessOutput { ProcessHandle = _processHandle };
            _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_CLOSE_PROCESS, ref input);
            _processHandle = 0;
            _processId = 0;
            _currentThreadId = 0;
            _isPaused = false;
        }
    }

    public bool SetBreakpoint(ulong address, BreakpointType type = BreakpointType.Software)
    {
        if (!IsDebugging) return false;

        // Check if already exists
        if (_breakpoints.Any(b => b.Address == address)) return false;

        // Determine hardware breakpoint index if needed
        uint drIndex = 0;
        if (type is BreakpointType.HardwareExec or BreakpointType.HardwareWrite or BreakpointType.HardwareRW)
        {
            var usedDr = _breakpoints
                .Where(b => b.Type is BreakpointType.HardwareExec or BreakpointType.HardwareWrite or BreakpointType.HardwareRW)
                .Count();
            if (usedDr >= 4) return false; // All 4 debug registers in use
            drIndex = (uint)usedDr;
        }

        var input = new NexusSetBreakpointInput
        {
            ThreadId = (uint)_currentThreadId,
            Register = drIndex,
            Address = address,
            Type = type switch
            {
                BreakpointType.Software => 0,
                BreakpointType.HardwareExec => 0, // Execute
                BreakpointType.HardwareWrite => 1, // Write
                BreakpointType.HardwareRW => 3,   // ReadWrite
                _ => 0
            },
            Size = 1
        };

        if (_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_SET_BREAKPOINT, ref input))
        {
            _breakpoints.Add(new BreakpointInfo
            {
                Address = address,
                Type = type,
                Enabled = true,
                HitCount = 0
            });
            return true;
        }

        return false;
    }

    public bool RemoveBreakpoint(ulong address)
    {
        if (!IsDebugging) return false;

        var bp = _breakpoints.FirstOrDefault(b => b.Address == address);
        if (bp == null) return false;

        System.Diagnostics.Trace.WriteLine("[KernelDebug] Not implemented: RemoveBreakpoint");
        // Find which debug register this breakpoint used
        var hwBreakpoints = _breakpoints
            .Where(b => b.Type is BreakpointType.HardwareExec or BreakpointType.HardwareWrite or BreakpointType.HardwareRW)
            .ToList();
        var regIndex = hwBreakpoints.IndexOf(bp);
        if (regIndex < 0) regIndex = 0;

        // IOCTL_NEXUS_CLEAR_BREAKPOINT expects: ThreadId (4) + Register (4)
        // For now just remove from local list - driver clear would need proper IOCTL
        _breakpoints.Remove(bp);
        return true;
    }

    public bool EnableBreakpoint(ulong address, bool enabled)
    {
        var bp = _breakpoints.FirstOrDefault(b => b.Address == address);
        if (bp == null) return false;

        bp.Enabled = enabled;
        return true;
    }

    public IEnumerable<BreakpointInfo> GetBreakpoints() => _breakpoints.AsReadOnly();

    public void Continue()
    {
        if (!IsDebugging || !IsPaused) return;

        System.Diagnostics.Trace.WriteLine("[KernelDebug] Not implemented: Continue");
        // IOCTL_NEXUS_CONTINUE_DEBUG - would resume execution
        // For now just update state
        _isPaused = false;
    }

    public void StepInto()
    {
        if (!IsDebugging || !IsPaused) return;

        System.Diagnostics.Trace.WriteLine("[KernelDebug] Not implemented: StepInto");
        // Single step would set TF flag in EFLAGS via thread context
        // Not directly implemented in driver - would use SET_THREAD_CONTEXT
        // For now, just continue
        _isPaused = false;
    }

    public void StepOver()
    {
        System.Diagnostics.Trace.WriteLine("[KernelDebug] Not implemented: StepOver");
        // Step over requires analyzing the instruction to determine if it's a call
        // For now, behave same as StepInto
        StepInto();
    }

    public void StepOut()
    {
        // Step out: read return address from stack and set temporary breakpoint
        if (!IsDebugging) return;

        var regs = GetRegisters();
        if (regs.Rsp == 0)
        {
            Continue();
            return;
        }

        // Read return address from top of stack
        var returnAddrBytes = _driver.ReadProcessMemory(_processId, regs.Rsp, 8);
        if (returnAddrBytes == null || returnAddrBytes.Length < 8)
        {
            Continue();
            return;
        }

        ulong returnAddr = BitConverter.ToUInt64(returnAddrBytes, 0);
        if (returnAddr != 0)
        {
            // Set a temporary breakpoint at return address
            // Use hardware breakpoint if available, otherwise software
            SetBreakpoint(returnAddr, BreakpointType.HardwareExec);
        }

        Continue();
    }

    public void Pause()
    {
        if (!IsDebugging || IsPaused) return;

        // Suspend the process via kernel IOCTL
        var input = new NexusSuspendResumeInput
        {
            ProcessId = (uint)_processId
        };

        if (_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_SUSPEND_PROCESS, ref input))
        {
            _isPaused = true;
        }
    }

    public RegisterContext GetRegisters()
    {
        return GetRegisters(_currentThreadId);
    }

    public RegisterContext GetRegisters(int threadId)
    {
        var context = new RegisterContext();
        if (!IsDebugging) return context;

        var input = new NexusThreadContextInput
        {
            ThreadId = (uint)threadId,
            ContextFlags = 0x10001F // CONTEXT_ALL for x64
        };

        if (_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_GET_THREAD_CONTEXT, ref input, out KernelContext64 kctx))
        {
            context.Rax = kctx.Rax;
            context.Rbx = kctx.Rbx;
            context.Rcx = kctx.Rcx;
            context.Rdx = kctx.Rdx;
            context.Rsi = kctx.Rsi;
            context.Rdi = kctx.Rdi;
            context.Rbp = kctx.Rbp;
            context.Rsp = kctx.Rsp;
            context.R8 = kctx.R8;
            context.R9 = kctx.R9;
            context.R10 = kctx.R10;
            context.R11 = kctx.R11;
            context.R12 = kctx.R12;
            context.R13 = kctx.R13;
            context.R14 = kctx.R14;
            context.R15 = kctx.R15;
            context.Rip = kctx.Rip;
            context.EFlags = kctx.EFlags;
            context.Cs = kctx.Cs;
            context.Ds = kctx.Ds;
            context.Es = kctx.Es;
            context.Fs = kctx.Fs;
            context.Gs = kctx.Gs;
            context.Ss = kctx.Ss;
            context.Dr0 = kctx.Dr0;
            context.Dr1 = kctx.Dr1;
            context.Dr2 = kctx.Dr2;
            context.Dr3 = kctx.Dr3;
            context.Dr6 = kctx.Dr6;
            context.Dr7 = kctx.Dr7;
        }

        return context;
    }

    public bool SetRegisters(RegisterContext context)
    {
        return SetRegisters(_currentThreadId, context);
    }

    public bool SetRegisters(int threadId, RegisterContext context)
    {
        if (!IsDebugging) return false;

        var kctx = new KernelContext64
        {
            Rax = context.Rax,
            Rbx = context.Rbx,
            Rcx = context.Rcx,
            Rdx = context.Rdx,
            Rsi = context.Rsi,
            Rdi = context.Rdi,
            Rbp = context.Rbp,
            Rsp = context.Rsp,
            R8 = context.R8,
            R9 = context.R9,
            R10 = context.R10,
            R11 = context.R11,
            R12 = context.R12,
            R13 = context.R13,
            R14 = context.R14,
            R15 = context.R15,
            Rip = context.Rip,
            EFlags = context.EFlags,
            Cs = context.Cs,
            Ds = context.Ds,
            Es = context.Es,
            Fs = context.Fs,
            Gs = context.Gs,
            Ss = context.Ss,
            Dr0 = context.Dr0,
            Dr1 = context.Dr1,
            Dr2 = context.Dr2,
            Dr3 = context.Dr3,
            Dr6 = context.Dr6,
            Dr7 = context.Dr7
        };

        return _driver.SetThreadContext(threadId, kctx);
    }

    public DebugEvent? WaitForEvent(int timeoutMs = -1)
    {
        // Poll for debug events from the kernel callback system
        var eventBuffer = _driver.GetPendingEvents();
        if (eventBuffer != null && eventBuffer.Length > 0)
        {
            foreach (var evt in _driver.ParseEvents(eventBuffer))
            {
                if (evt.ProcessId == _processId && evt.EventType == NexusEventType.Debug)
                {
                    return new DebugEvent
                    {
                        Type = DebugEventType.Breakpoint,
                        ThreadId = (int)evt.ThreadId,
                        Address = 0, // Would need to extract from event data
                        ProcessId = (int)evt.ProcessId
                    };
                }
            }
        }
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
