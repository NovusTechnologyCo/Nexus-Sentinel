// <file>
// <summary>
// Debug provider interface for debugger operations: attach/detach, breakpoints (software,
// hardware, memory, EPT), single-step, continue, thread context access, and debug event
// handling. Implementations span user-mode (Windows Debug API), kernel (NexusKernel.sys),
// and hypervisor (SentinelHV EPT breakpoints) backends.
// </summary>
// </file>

namespace Nexus.UI.Providers;

/// <summary>
/// Breakpoint types.
/// </summary>
public enum BreakpointType
{
    Software,       // INT3 software breakpoint
    HardwareExec,   // Hardware execution breakpoint (DR0-DR3)
    HardwareWrite,  // Hardware write watchpoint
    HardwareRW,     // Hardware read/write watchpoint
    Memory,         // Page guard memory breakpoint
    Ept             // EPT-based invisible breakpoint (hypervisor only)
}

/// <summary>
/// Debug event types.
/// </summary>
public enum DebugEventType
{
    None,
    Breakpoint,
    SingleStep,
    Exception,
    ProcessCreate,
    ProcessExit,
    ThreadCreate,
    ThreadExit,
    DllLoad,
    DllUnload
}

/// <summary>
/// Information about a breakpoint.
/// </summary>
public class BreakpointInfo
{
    public ulong Address { get; init; }
    public BreakpointType Type { get; init; }
    public bool Enabled { get; set; }
    public int HitCount { get; set; }
    public string? Condition { get; set; }
    public string? Name { get; set; }
}

/// <summary>
/// Debug event information.
/// </summary>
public class DebugEvent
{
    public DebugEventType Type { get; init; }
    public int ProcessId { get; init; }
    public int ThreadId { get; init; }
    public ulong Address { get; init; }
    public uint ExceptionCode { get; init; }
    public string? ModuleName { get; init; }
}

/// <summary>
/// CPU register context.
/// </summary>
public class RegisterContext
{
    // General purpose registers
    public ulong Rax { get; set; }
    public ulong Rbx { get; set; }
    public ulong Rcx { get; set; }
    public ulong Rdx { get; set; }
    public ulong Rsi { get; set; }
    public ulong Rdi { get; set; }
    public ulong Rbp { get; set; }
    public ulong Rsp { get; set; }
    public ulong R8 { get; set; }
    public ulong R9 { get; set; }
    public ulong R10 { get; set; }
    public ulong R11 { get; set; }
    public ulong R12 { get; set; }
    public ulong R13 { get; set; }
    public ulong R14 { get; set; }
    public ulong R15 { get; set; }

    // Instruction pointer and flags
    public ulong Rip { get; set; }
    public uint EFlags { get; set; }

    // Segment registers
    public ushort Cs { get; set; }
    public ushort Ds { get; set; }
    public ushort Es { get; set; }
    public ushort Fs { get; set; }
    public ushort Gs { get; set; }
    public ushort Ss { get; set; }

    // Debug registers
    public ulong Dr0 { get; set; }
    public ulong Dr1 { get; set; }
    public ulong Dr2 { get; set; }
    public ulong Dr3 { get; set; }
    public ulong Dr6 { get; set; }
    public ulong Dr7 { get; set; }

    // Flag helpers
    public bool CarryFlag => (EFlags & 0x0001) != 0;
    public bool ZeroFlag => (EFlags & 0x0040) != 0;
    public bool SignFlag => (EFlags & 0x0080) != 0;
    public bool TrapFlag => (EFlags & 0x0100) != 0;
    public bool DirectionFlag => (EFlags & 0x0400) != 0;
    public bool OverflowFlag => (EFlags & 0x0800) != 0;
}

/// <summary>
/// Abstraction for debugging operations.
/// Implementations can use user-mode Debug APIs, kernel driver, or hypervisor.
/// </summary>
public interface IDebugProvider : IDisposable
{
    /// <summary>
    /// Display name of this provider.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Privilege level of this provider.
    /// </summary>
    ProviderPrivilege Privilege { get; }

    /// <summary>
    /// Whether this provider is available.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Whether currently debugging a process.
    /// </summary>
    bool IsDebugging { get; }

    /// <summary>
    /// Whether the debugged process is currently paused.
    /// </summary>
    bool IsPaused { get; }

    /// <summary>
    /// Current process ID being debugged.
    /// </summary>
    int ProcessId { get; }

    /// <summary>
    /// Current thread ID (active thread context).
    /// </summary>
    int ThreadId { get; }

    /// <summary>
    /// Attach debugger to a process.
    /// </summary>
    bool Attach(int processId);

    /// <summary>
    /// Detach debugger from the process.
    /// </summary>
    void Detach();

    /// <summary>
    /// Set a breakpoint.
    /// </summary>
    bool SetBreakpoint(ulong address, BreakpointType type = BreakpointType.Software);

    /// <summary>
    /// Remove a breakpoint.
    /// </summary>
    bool RemoveBreakpoint(ulong address);

    /// <summary>
    /// Enable/disable a breakpoint.
    /// </summary>
    bool EnableBreakpoint(ulong address, bool enabled);

    /// <summary>
    /// Get all breakpoints.
    /// </summary>
    IEnumerable<BreakpointInfo> GetBreakpoints();

    /// <summary>
    /// Continue execution.
    /// </summary>
    void Continue();

    /// <summary>
    /// Single step (step into).
    /// </summary>
    void StepInto();

    /// <summary>
    /// Step over (execute until next instruction).
    /// </summary>
    void StepOver();

    /// <summary>
    /// Step out (execute until return).
    /// </summary>
    void StepOut();

    /// <summary>
    /// Pause execution.
    /// </summary>
    void Pause();

    /// <summary>
    /// Get current register context.
    /// </summary>
    RegisterContext GetRegisters();

    /// <summary>
    /// Set register context.
    /// </summary>
    bool SetRegisters(RegisterContext context);

    /// <summary>
    /// Get register context for a specific thread.
    /// </summary>
    RegisterContext GetRegisters(int threadId);

    /// <summary>
    /// Wait for a debug event.
    /// </summary>
    DebugEvent? WaitForEvent(int timeoutMs = -1);

    /// <summary>
    /// Event fired when a debug event occurs.
    /// </summary>
    event EventHandler<DebugEvent>? DebugEventOccurred;
}
