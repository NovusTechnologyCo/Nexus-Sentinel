// <file>
// <summary>
// Interop structure definitions for the Nexus Engine P/Invoke layer. Mirrors the C struct
// definitions in nexus_api.h with matching field layouts and marshaling attributes.
// Includes process info, module info, memory region info, disassembly instructions,
// scan results, debug events, thread context (CONTEXT64), and other engine data types.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

/// <summary>
/// Process information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusProcessInfo
{
    public uint Pid;
    public uint ParentPid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string Path;
    public int Is32Bit;
}

/// <summary>
/// Module information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusModuleInfo
{
    public ulong BaseAddress;
    public ulong Size;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string Path;
}

/// <summary>
/// Thread information structure.
/// Must match native NexusThreadInfo from nexus_process.h
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusThreadInfo
{
    public uint ThreadId;
    public uint OwnerProcessId;
    public int BasePriority;
    public int DeltaPriority;
    public ulong StartAddress;
    public ulong TebAddress;
    public uint State;
    public uint WaitReason;
    public uint SuspendCount;
    public uint LastError;
    public int LastStatus;
    public ulong KernelTime;
    public ulong UserTime;
    public ulong CycleTime;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;
}

/// <summary>
/// Memory region information structure.
/// Must match native NexusMemoryRegion from nexus_api.h
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusMemoryRegion
{
    public ulong BaseAddress;
    public ulong AllocationBase;
    public ulong Size;
    public ulong AllocationSize;
    public uint Protection;
    public uint AllocationProtect;
    public uint State;
    public uint Type;
}

/// <summary>
/// Extended memory region information from snapshot.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusMemoryRegionEx
{
    public ulong BaseAddress;
    public ulong Size;
    public uint Protection;
    public uint State;
    public uint Type;
    public int IsExecutable;
    public int IsWritable;
    public int IsGuard;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModuleName;
}

/// <summary>
/// Breakpoint information structure.
/// Supports both absolute and module-relative addresses (x64dbg pattern).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusBreakpoint
{
    /// <summary>Unique breakpoint ID.</summary>
    public ulong Id;
    /// <summary>Resolved absolute address (0 if unresolved module-relative BP).</summary>
    public ulong Address;
    /// <summary>Breakpoint type (NexusBreakpointType).</summary>
    public uint Type;
    /// <summary>Breakpoint size (NexusBreakpointSize for hardware BP).</summary>
    public uint Size;
    /// <summary>1 if enabled, 0 if disabled.</summary>
    public uint Enabled;
    /// <summary>Number of times breakpoint was hit.</summary>
    public uint HitCount;
    /// <summary>Original byte (for software BP).</summary>
    public byte OriginalByte;
    /// <summary>Storage mode (NexusBreakpointMode).</summary>
    public byte Mode;
    /// <summary>1 if module-relative BP is resolved.</summary>
    public byte Resolved;
    /// <summary>Padding for alignment.</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
    public byte[] Reserved;
    /// <summary>RVA within module (if module-relative).</summary>
    public ulong Rva;
    /// <summary>Module name (if module-relative).</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;
}

/// <summary>
/// Debug event structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusDebugEvent
{
    public uint Type;
    public uint ProcessId;
    public uint ThreadId;
    public uint Reserved;
    public ulong Address;
    public ulong ExceptionCode;
    public ulong BreakpointId;
    // Union members - use largest variant
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 528)]
    public byte[] InfoBytes;
}

/// <summary>
/// Stack frame information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusStackFrame
{
    public ulong FrameAddress;
    public ulong ReturnAddress;
    public ulong StackPointer;
    public ulong InstructionPointer;
    public ulong ModuleBase;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] FunctionNameBytes;
    public uint FunctionOffset;
    public uint FrameIndex;
    public uint IsInline;
    public uint Reserved;

    public string FunctionName => System.Text.Encoding.UTF8.GetString(FunctionNameBytes).TrimEnd('\0');
}

/// <summary>
/// Pointer scan parameters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPointerScanParams
{
    public ulong TargetAddress;     // Address to find pointers to
    public ulong BaseStart;         // Start of base address range (0 for auto)
    public ulong BaseEnd;           // End of base address range (0 for auto)
    public uint MaxLevel;           // Maximum pointer chain depth (1-7)
    public uint MaxOffset;          // Maximum offset per level
    public uint Alignment;          // Pointer alignment (usually 4 or 8)
    public uint Is64Bit;            // 1 for 64-bit pointers, 0 for 32-bit
    public uint ScanWritable;       // 1 to only scan writable memory
    public uint ScanStatic;         // 1 to only find paths starting from static bases
    public uint MaxResults;         // Maximum results to find (0 for unlimited, default 10000)
    public uint IncludeSystemModules; // 0 to exclude system DLLs (default), 1 to include
    public uint MaxOffsetsPerNode;  // Max different offsets per node (0=unlimited, default 3 like CE)
    public uint AllowNegativeOffsets; // 1 to allow negative offsets (default), 0 to only use positive
    public uint MaxVisitsPerAddress; // Max times address can be visited (0=default 4, tuned to match CE)
    public uint ThreadStackCount;   // Number of thread stacks to use (0=default 2, CE default)
    public uint StackSize;          // Stack size for static detection (0=default 4096, CE default)
}

/// <summary>
/// Pointer path structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusPointerPath
{
    public ulong BaseAddress;       // Static base address (module base + offset)
    public ulong ModuleBase;        // Module base address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;       // Module name containing base
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public long[] Offsets;          // Offset chain
    public uint OffsetCount;        // Number of offsets in chain
    public uint Reserved;           // Padding

    /// <summary>
    /// Gets the offsets as a formatted string.
    /// </summary>
    public readonly string OffsetsString
    {
        get
        {
            if (OffsetCount == 0) return "";
            var parts = new string[OffsetCount];
            for (int i = 0; i < OffsetCount; i++)
            {
                parts[i] = Offsets[i] >= 0 ? $"+{Offsets[i]:X}" : $"-{Math.Abs(Offsets[i]):X}";
            }
            return string.Join(" -> ", parts);
        }
    }
}

/// <summary>
/// Pointer scan progress.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPointerScanProgress
{
    public ulong AddressesScanned;  // Addresses checked
    public ulong AddressesTotal;    // Total addresses to check
    public ulong PathsFound;        // Number of valid paths found
    public uint CurrentLevel;       // Current scan depth
    public uint IsComplete;         // 1 if scan is done
    public uint WasCancelled;       // 1 if scan was cancelled
    public uint Reserved;           // Padding

    /// <summary>
    /// Gets the progress as a percentage.
    /// </summary>
    public readonly double Progress => AddressesTotal > 0 ? (double)AddressesScanned / AddressesTotal : 0;
}

/// <summary>
/// Speedhack status information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusSpeedhackStatus
{
    public uint IsActive;           // 1 if speedhack is active
    public uint Method;             // Current method being used
    public double CurrentSpeed;     // Current speed multiplier
    public ulong HookCount;         // Number of times hooks were called
    public ulong BaseTime;          // Base time when speedhack started
}

/// <summary>
/// Injection result information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusInjectionResult
{
    public ulong BaseAddress;
    public ulong EntryPoint;
    public uint ThreadId;
    public uint ExitCode;
    public uint Success;
    public uint Reserved;
}

/// <summary>
/// Cheat table entry structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusTableEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;
    public ulong Address;
    public int ValueType;
    public int IsPointer;
    public int PointerOffsetCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public int[] PointerOffsets;
    public int IsFrozen;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] FrozenValueBytes;
    public nuint FrozenValueSize;
    public int IsGroupHeader;
    public int GroupId;
    public int Options;
    public int ShowAsHex;
}

/// <summary>
/// Disassembler instruction operand (matches native NexusDisasmOperand).
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 32)]
public struct NexusDisasmOperand
{
    [FieldOffset(0)]
    public uint Type;           // NexusOperandType
    [FieldOffset(4)]
    public uint Size;           // Operand size in bits

    // Union: register
    [FieldOffset(8)]
    public ushort RegId;

    // Union: memory
    [FieldOffset(8)]
    public ushort MemSegment;
    [FieldOffset(10)]
    public ushort MemBase;
    [FieldOffset(12)]
    public ushort MemIndex;
    [FieldOffset(14)]
    public byte MemScale;
    [FieldOffset(16)]
    public long MemDisp;
    [FieldOffset(24)]
    public byte MemHasDisp;

    // Union: immediate
    [FieldOffset(8)]
    public ulong ImmValue;
    [FieldOffset(16)]
    public byte ImmIsSigned;
    [FieldOffset(17)]
    public byte ImmIsRelative;
}

/// <summary>
/// Disassembler instruction structure (matches native NexusDisasmInstruction).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusDisasmInstruction
{
    public ulong Address;           // Runtime address
    public byte Length;             // Instruction length in bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
    public byte[] Bytes;            // Raw instruction bytes
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Mnemonic;         // Instruction mnemonic
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Text;             // Full formatted instruction text
    public byte OperandCount;       // Number of operands
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
    public NexusDisasmOperand[] Operands; // Operands (max 5)
    public ulong BranchTarget;      // Branch target address
    public uint IsBranch;
    public uint IsCall;
    public uint IsReturn;
    public uint IsConditional;
}

/// <summary>
/// Legacy disassembler instruction structure (deprecated, use NexusDisasmInstruction).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusInstruction
{
    public ulong Address;
    public nuint Length;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
    public byte[] Bytes;
    public byte ByteCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
    public byte[] MnemonicBytes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] OperandBytes;
    public int Category;
    public int OperandCount;
    public int IsCall;
    public int IsJump;
    public int IsConditional;
    public int IsReturn;
    public ulong BranchTarget;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public NexusOperand[] Operands;

    public string Mnemonic => System.Text.Encoding.UTF8.GetString(MnemonicBytes).TrimEnd('\0');
    public string OperandString => System.Text.Encoding.UTF8.GetString(OperandBytes).TrimEnd('\0');
}

/// <summary>
/// Legacy instruction operand structure (deprecated, use NexusDisasmOperand).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusOperand
{
    public int Type;
    public int Size;
    public ulong ImmediateValue;
    public ushort Register;
    public ushort BaseRegister;
    public ushort IndexRegister;
    public byte Scale;
    public byte Reserved;
    public long Displacement;
}

/// <summary>
/// Symbol information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSymbolInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string UndecoratedName;
    public ulong Address;
    public uint Size;
    public int Type;
    public uint Flags;
    public ulong ModuleBase;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModuleName;
}

/// <summary>
/// Scan configuration structure.
/// Matches NexusScanConfig in nexus_api.h
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusScanConfig
{
    public int ValueType;           // NexusScanValueType
    public int CompareType;         // NexusScanCompareType
    public uint Options;
    public uint Alignment;          // 0 = auto, 1 = byte-aligned
    public ulong StartAddress;      // 0 = process start
    public ulong EndAddress;        // 0 = process end
    public NexusScanValue Value1;   // Primary value
    public NexusScanValue Value2;   // Secondary value (for BETWEEN)
    public float FloatTolerance;    // Tolerance for float comparison
    public uint ThreadCount;        // 0 = auto
}

/// <summary>
/// Scan value union structure.
/// Matches NexusScanValue union in nexus_api.h
/// Size: 256 bytes (aob) + 256 bytes (mask) + size_t (length) = 520 bytes on x64
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 520)]
public unsafe struct NexusScanValue
{
    [FieldOffset(0)] public byte ByteVal;
    [FieldOffset(0)] public short Int16Val;
    [FieldOffset(0)] public int Int32Val;
    [FieldOffset(0)] public long Int64Val;
    [FieldOffset(0)] public float FloatVal;
    [FieldOffset(0)] public double DoubleVal;

    // stringVal: char data[256] at offset 0, size_t length at offset 256
    [FieldOffset(256)] public nuint StringLength;

    // aobVal: uint8_t bytes[256] at offset 0, uint8_t mask[256] at offset 256, size_t length at offset 512
    [FieldOffset(512)] public nuint AobLength;

    /// <summary>
    /// Set string value for string scanning.
    /// </summary>
    public void SetString(string value)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(value);
        int len = Math.Min(bytes.Length, 255);
        fixed (byte* ptr = &ByteVal)
        {
            for (int i = 0; i < len; i++)
                ptr[i] = bytes[i];
            ptr[len] = 0; // null terminate
        }
        StringLength = (nuint)len;
    }

    /// <summary>
    /// Get string value from scan result.
    /// </summary>
    public string GetString()
    {
        int len = (int)StringLength;
        if (len <= 0 || len > 255) len = 255;
        fixed (byte* ptr = &ByteVal)
        {
            return System.Text.Encoding.ASCII.GetString(ptr, len).TrimEnd('\0');
        }
    }

    /// <summary>
    /// Set AOB (Array of Bytes) pattern for scanning.
    /// Format: "DE AD BE EF" or "DE AD ?? EF" (wildcards: ??, **, or *)
    /// </summary>
    public void SetAob(string pattern)
    {
        // Split by spaces or no spaces (handle both "DEADBEEF" and "DE AD BE EF")
        var parts = pattern.Replace("  ", " ").Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // If no spaces, try to split every 2 characters
        if (parts.Length == 1 && pattern.Length > 2 && !pattern.Contains('?') && !pattern.Contains('*'))
        {
            var noSpaces = pattern.Replace(" ", "");
            parts = new string[(noSpaces.Length + 1) / 2];
            for (int i = 0; i < parts.Length; i++)
            {
                int start = i * 2;
                parts[i] = start + 2 <= noSpaces.Length ? noSpaces.Substring(start, 2) : noSpaces.Substring(start);
            }
        }

        int len = Math.Min(parts.Length, 255);
        fixed (byte* bytesPtr = &ByteVal)
        {
            byte* maskPtr = bytesPtr + 256;  // mask is at offset 256

            for (int i = 0; i < len; i++)
            {
                var part = parts[i].Trim();
                if (part == "??" || part == "**" || part == "?" || part == "*")
                {
                    // Wildcard - any value matches
                    bytesPtr[i] = 0;
                    maskPtr[i] = 0x00;  // mask 0 = don't care
                }
                else
                {
                    // Parse hex byte
                    bytesPtr[i] = Convert.ToByte(part, 16);
                    maskPtr[i] = 0xFF;  // mask FF = exact match
                }
            }
        }
        AobLength = (nuint)len;
    }

    /// <summary>
    /// Get AOB pattern as hex string from scan result.
    /// </summary>
    public string GetAob()
    {
        int len = (int)AobLength;
        if (len <= 0 || len > 255) return "";

        fixed (byte* bytesPtr = &ByteVal)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < len; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(bytesPtr[i].ToString("X2"));
            }
            return sb.ToString();
        }
    }
}

/// <summary>
/// Scan result entry structure.
/// Matches NexusScanResultEntry in nexus_api.h
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusScanResultEntry
{
    public ulong Address;                    // 8 bytes
    public NexusScanValue CurrentValue;      // 520 bytes
    public NexusScanValue PreviousValue;     // 520 bytes
    // Total: 1048 bytes
}

/// <summary>
/// Scan statistics structure.
/// Matches NexusScanStats in nexus_api.h
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusScanStats
{
    public ulong TotalBytes;        // Total bytes to scan
    public ulong BytesScanned;      // Bytes scanned so far
    public nuint RegionsScanned;    // Memory regions scanned (size_t)
    public nuint ResultsFound;      // Results found (size_t)
    public uint ThreadsUsed;        // Threads used
    public double ElapsedMs;        // Elapsed time in milliseconds
    public double ScanSpeedMBps;    // Scan speed in MB/s
    public int IsComplete;          // 1 if scan complete
    public int WasCancelled;        // 1 if scan was cancelled

    // Calculate progress (0.0 - 1.0)
    public readonly double Progress => TotalBytes > 0 ? (double)BytesScanned / TotalBytes : 0;
}

/// <summary>
/// Kernel driver status structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusKernelStatus
{
    public uint DriverLoaded;
    public uint HypervisorActive;
    public uint DseDisabled;
    public uint Capabilities;
    public uint TransportType;
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DriverPath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string DriverVersion;
}

/// <summary>
/// Physical memory region structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPhysicalRegion
{
    public ulong PhysicalAddress;
    public ulong VirtualAddress;
    public ulong Size;
    public uint Type;
    public uint Flags;
}

/// <summary>
/// ETW configuration structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusEtwConfig
{
    public uint Providers;          // Bitmask of NexusEtwProviders
    public uint TargetPid;          // Filter to specific PID (0 = all)
    public uint BufferSizeKb;       // Per-buffer size in KB (default: 64)
    public uint MinBuffers;         // Minimum buffer count (default: 8)
    public uint MaxBuffers;         // Maximum buffer count (default: 64)
    public uint FlushTimerMs;       // Flush timer in milliseconds (default: 1000)
    public uint MaxEventsPerSecond; // Rate limit (0 = unlimited)
    public uint Flags;              // Reserved for future use
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string SessionName;      // Custom session name (empty = auto)
}

/// <summary>
/// ETW event structure - returned by event polling.
/// Simplified for C# interop - full path and core data only.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusEtwEvent
{
    // Event identification
    public ulong SequenceNumber;    // Monotonic sequence number
    public ulong Timestamp;         // Timestamp in 100ns intervals since 1601

    // Classification
    public uint Category;           // NexusEtwEventCategory
    public uint Operation;          // NexusEtwOperation

    // Process/Thread context
    public uint ProcessId;
    public uint ThreadId;

    // Result/Status
    public int Status;              // NTSTATUS or Win32 error code
    public ulong Duration;          // Duration in 100ns intervals

    // Path/Name (520 wchars)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string Path;

    // Additional context-specific data (1024 bytes raw)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
    public byte[] Data;

    public uint DataSize;
    public uint Reserved;

    /// <summary>
    /// Converts timestamp to DateTime.
    /// </summary>
    public readonly DateTime Time => DateTime.FromFileTimeUtc((long)Timestamp);

    /// <summary>
    /// Gets the category name.
    /// </summary>
    public readonly string CategoryName => ((NexusEtwEventCategory)Category).ToString();

    /// <summary>
    /// Gets the operation name.
    /// </summary>
    public readonly string OperationName => ((NexusEtwOperation)Operation).ToString();
}

/// <summary>
/// ETW statistics structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusEtwStats
{
    public ulong EventsReceived;    // Total events received
    public ulong EventsDropped;     // Events dropped due to buffer overflow
    public ulong EventsFiltered;    // Events filtered out by PID filter
    public ulong BytesReceived;     // Total bytes processed
    public uint BuffersUsed;        // Current buffer count
    public uint BuffersLost;        // Buffers lost
    public uint IsRunning;          // 1 if trace is active
    public uint LastError;          // Last Win32 error code
}

#region CFG (Control Flow Graph) Structures

/// <summary>
/// CFG analysis result summary.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCFGResult
{
    public ulong EntryAddress;      // Entry point address
    public ulong FunctionStart;     // Function start address
    public ulong FunctionEnd;       // Function end address
    public uint BlockCount;         // Number of basic blocks
    public uint EdgeCount;          // Number of edges
    public uint InstructionCount;   // Total instructions
    public uint Flags;              // Analysis flags
}

/// <summary>
/// Basic block in a CFG.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusBasicBlock
{
    public uint Index;              // Block index
    public ulong StartAddress;      // Start address
    public ulong EndAddress;        // End address (exclusive)
    public uint InstructionCount;   // Number of instructions
    public uint PredecessorCount;   // Number of predecessors
    public uint SuccessorCount;     // Number of successors
    public uint Flags;              // Block flags (entry, exit, loop header, etc.)

    // Helper properties for flag interpretation
    public readonly uint BlockIndex => Index;
    public readonly bool IsEntry => (Flags & 0x01) != 0;
    public readonly bool IsExit => (Flags & 0x02) != 0;
    public readonly bool IsLoopHeader => (Flags & 0x04) != 0;
}

/// <summary>
/// Edge between basic blocks in a CFG.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCFGEdge
{
    public uint SourceIndex;        // Source block index
    public uint TargetIndex;        // Target block index
    public uint EdgeType;           // Edge type (fall-through, jump, call, etc.)
    public uint Flags;              // Edge flags

    // Helper properties
    public readonly uint SourceBlock => SourceIndex;
    public readonly uint TargetBlock => TargetIndex;
    public readonly bool IsFallthrough => EdgeType == 0;
    public readonly bool IsBackEdge => (Flags & 0x01) != 0;
}

#endregion

#region Structure Dissection Types

/// <summary>
/// Structure definition info.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusStructInfo
{
    public uint Id;                 // Structure ID
    public uint Size;               // Total structure size
    public uint ElementCount;       // Number of elements
    public uint Flags;              // Structure flags
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Name;             // Structure name
}

/// <summary>
/// Structure element definition.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusStructElement
{
    public uint Offset;             // Offset within structure
    public uint Size;               // Element size
    public uint ElementType;        // Element type (NexusElementType)
    public uint Flags;              // Element flags
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;             // Element name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TypeName;         // Type name (for custom types)
}

/// <summary>
/// Structure instance (bound to an address).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusStructInstance
{
    public uint StructId;           // Structure definition ID
    public ulong BaseAddress;       // Base address in memory
    public uint Flags;              // Instance flags
    public uint Reserved;           // Padding
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Description;      // User description
}

/// <summary>
/// Element value read from memory.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 272)]
public struct NexusElementValue
{
    [FieldOffset(0)] public byte ByteVal;
    [FieldOffset(0)] public short Int16Val;
    [FieldOffset(0)] public int Int32Val;
    [FieldOffset(0)] public long Int64Val;
    [FieldOffset(0)] public float FloatVal;
    [FieldOffset(0)] public double DoubleVal;
    [FieldOffset(0)] public ulong PointerVal;
    [FieldOffset(256)] public uint DataSize;
    [FieldOffset(260)] public uint IsValid;
    [FieldOffset(264)] public uint ElementType;
    [FieldOffset(268)] public uint Reserved;
}

#endregion
