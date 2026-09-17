// <file>
// <summary>
// P/Invoke bindings for instruction tracing: start/stop trace recording, run-to-address,
// trace into (follow calls), trace over (skip calls), and retrieve recorded instruction
// traces with register snapshots.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Instruction Tracing Operations

    /// <summary>
    /// Create a trace recorder for a debugger session.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceCreate(
        IntPtr debuggerHandle,
        ref NexusTraceConfig config,
        out IntPtr traceHandle);

    /// <summary>
    /// Destroy a trace recorder and free resources.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_TraceDestroy(IntPtr traceHandle);

    /// <summary>
    /// Start recording instruction trace.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceStart(IntPtr traceHandle);

    /// <summary>
    /// Stop recording instruction trace.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceStop(IntPtr traceHandle);

    /// <summary>
    /// Check if tracing is active.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceIsRunning(
        IntPtr traceHandle,
        out uint isRunning);

    /// <summary>
    /// Get the number of recorded instructions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceGetCount(
        IntPtr traceHandle,
        out ulong count);

    /// <summary>
    /// Get recorded trace entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceGetEntries(
        IntPtr traceHandle,
        ulong startIndex,
        [In, Out] NexusTraceEntry[] entries,
        nuint maxEntries,
        out nuint entryCount);

    /// <summary>
    /// Clear all recorded trace data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceClear(IntPtr traceHandle);

    /// <summary>
    /// Save trace to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TraceSave(
        IntPtr traceHandle,
        string filePath,
        NexusTraceFileFormat format);

    /// <summary>
    /// Load trace from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TraceLoad(
        IntPtr traceHandle,
        string filePath);

    /// <summary>
    /// Get trace statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceGetStats(
        IntPtr traceHandle,
        out NexusTraceStats stats);

    /// <summary>
    /// Set a trace condition (stop when condition is met).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_TraceSetCondition(
        IntPtr traceHandle,
        NexusTraceConditionType type,
        string? condition);

    /// <summary>
    /// Step trace into - execute one instruction and record.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceStepInto(
        IntPtr traceHandle,
        uint threadId);

    /// <summary>
    /// Step trace over - execute one instruction (skip calls) and record.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceStepOver(
        IntPtr traceHandle,
        uint threadId);

    /// <summary>
    /// Run trace - trace until condition or breakpoint.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceRun(
        IntPtr traceHandle,
        uint threadId,
        NexusTraceMode mode);

    /// <summary>
    /// Get hit count for an address (how many times it was executed).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceGetHitCount(
        IntPtr traceHandle,
        ulong address,
        out uint hitCount);

    /// <summary>
    /// Find entries by address in the trace.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TraceFindByAddress(
        IntPtr traceHandle,
        ulong address,
        [In, Out] ulong[]? indices,
        nuint maxIndices,
        out nuint indexCount);

    #endregion

    #region Run-To Operations

    /// <summary>
    /// Run to a specific address (sets temporary breakpoint).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RunToAddress(
        IntPtr debuggerHandle,
        uint threadId,
        ulong address);

    /// <summary>
    /// Run to user code (skip system DLLs).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RunToUserCode(
        IntPtr debuggerHandle,
        uint threadId);

    /// <summary>
    /// Run to return (execute until current function returns).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RunToReturn(
        IntPtr debuggerHandle,
        uint threadId);

    #endregion
}

#region Trace Enums and Structs

/// <summary>
/// Trace recording mode.
/// </summary>
public enum NexusTraceMode : uint
{
    StepInto = 0,       // Trace into calls
    StepOver = 1,       // Trace over calls
    StepOut = 2         // Trace until return
}

/// <summary>
/// Trace condition types.
/// </summary>
public enum NexusTraceConditionType : uint
{
    None = 0,
    MaxInstructions = 1,    // Stop after N instructions
    Address = 2,            // Stop when reaching address
    Expression = 3,         // Stop when expression is true
    Module = 4              // Stop when entering/leaving module
}

/// <summary>
/// Trace file formats.
/// </summary>
public enum NexusTraceFileFormat : uint
{
    Binary = 0,         // Native binary format
    Json = 1,           // JSON format
    Text = 2            // Human-readable text
}

/// <summary>
/// Trace configuration.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTraceConfig
{
    public uint MaxInstructions;        // Maximum instructions to record (0 = unlimited)
    public uint RecordFlags;            // What to record (registers, memory, etc.)
    public uint BufferSizeKb;           // Buffer size in KB
    public ulong StartAddress;          // Start recording at this address (0 = immediate)
    public ulong StopAddress;           // Stop recording at this address (0 = never)
    public uint TraceIntoSystem;        // Trace into system DLLs (0/1)
}

/// <summary>
/// Flags for what to record in trace.
/// </summary>
[Flags]
public enum NexusTraceRecordFlags : uint
{
    None = 0,
    Registers = 1,          // Record register values
    Memory = 2,             // Record memory accesses
    Timestamps = 4,         // Record timestamps
    ThreadId = 8,           // Record thread ID
    All = 0xFFFFFFFF
}

/// <summary>
/// Single trace entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTraceEntry
{
    public ulong Index;             // Entry index in trace
    public ulong Address;           // Instruction address
    public uint ThreadId;           // Thread that executed
    public uint InstructionSize;    // Size of instruction
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Opcode;           // Instruction bytes
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Mnemonic;         // Disassembled instruction
    public ulong Timestamp;         // Timestamp (if recorded)

    // Key register values (always recorded)
    public ulong Rax, Rcx, Rdx, Rbx;
    public ulong Rsp, Rbp, Rsi, Rdi;
    public ulong Rip;
    public uint EFlags;
}

/// <summary>
/// Trace statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTraceStats
{
    public ulong TotalInstructions;     // Total instructions recorded
    public ulong UniqueAddresses;       // Number of unique addresses
    public ulong TotalCalls;            // Total call instructions
    public ulong TotalJumps;            // Total jump instructions
    public ulong TotalReturns;          // Total return instructions
    public ulong StartTime;             // Trace start timestamp
    public ulong EndTime;               // Trace end timestamp
    public ulong MemoryUsed;            // Memory used by trace buffer
}

#endregion
