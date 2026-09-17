// <file>
// <summary>
// Enumeration types for the Nexus Engine P/Invoke layer. Mirrors the C enum definitions
// in nexus_api.h. Includes result codes, process access levels, scan types, value types,
// memory protection flags, breakpoint types, debug event types, and other engine constants.
// </summary>
// </file>

namespace Nexus.UI.Interop;

/// <summary>
/// Result codes returned by Nexus Engine functions.
/// </summary>
public enum NexusResult : int
{
    OK = 0,
    Success = 0, // Alias for compatibility
    ErrorInvalidHandle = 1,
    ErrorInvalidParameter = 2,
    ErrorAccessDenied = 3,
    ErrorNotFound = 4,
    ErrorInsufficientBuffer = 5,
    ErrorPartialRead = 6,
    ErrorPartialWrite = 7,
    ErrorOutOfMemory = 8,
    ErrorUnknown = 255
}

/// <summary>
/// Process access level - determines which rights are requested when opening a process.
/// Using tiered access improves compatibility and reduces detection.
/// </summary>
/// <remarks>
/// Best practice: Request only the minimum access level needed for your operation.
/// Higher access levels are more likely to be blocked by security software.
/// </remarks>
public enum NexusProcessAccess : int
{
    /// <summary>Query-only: Get process info, no memory access.</summary>
    Query = 0,
    /// <summary>Read-only: Query + read process memory.</summary>
    Read = 1,
    /// <summary>Read-write: Query + read/write process memory (default).</summary>
    ReadWrite = 2,
    /// <summary>Full: Read-write + thread control (suspend/resume/inject).</summary>
    Full = 3,
    /// <summary>Debug: Full access + debug events (requires SeDebugPrivilege).</summary>
    Debug = 4
}

/// <summary>
/// Thread state flags.
/// </summary>
[Flags]
public enum NexusThreadState : uint
{
    Running = 0x0001,
    Suspended = 0x0002,
    Waiting = 0x0004,
    Terminated = 0x0008
}

/// <summary>
/// Breakpoint types.
/// </summary>
public enum NexusBreakpointType : int
{
    Software = 0,       // INT3 software breakpoint
    HardwareExec = 1,   // Hardware execution breakpoint (DR0-DR3)
    HardwareWrite = 2,  // Hardware write watchpoint
    HardwareRW = 3,     // Hardware read/write watchpoint
    Memory = 4          // Memory breakpoint (page guard)
}

/// <summary>
/// Breakpoint size (for hardware breakpoints).
/// </summary>
public enum NexusBreakpointSize : int
{
    Size1 = 0,  // 1 byte
    Size2 = 1,  // 2 bytes (word)
    Size4 = 3,  // 4 bytes (dword)
    Size8 = 2   // 8 bytes (qword, x64 only)
}

/// <summary>
/// Breakpoint storage mode (x64dbg pattern).
/// </summary>
public enum NexusBreakpointMode : byte
{
    /// <summary>Absolute address (legacy mode).</summary>
    Absolute = 0,
    /// <summary>Module name + RVA (survives module reload).</summary>
    ModuleRelative = 1
}

/// <summary>
/// Debug event types.
/// </summary>
public enum NexusDebugEventType : int
{
    None = 0,
    Breakpoint = 1,
    SingleStep = 2,
    Exception = 3,
    ProcessCreate = 4,
    ProcessExit = 5,
    ThreadCreate = 6,
    ThreadExit = 7,
    DllLoad = 8,
    DllUnload = 9,
    OutputString = 10
}

/// <summary>
/// Stack walk options.
/// </summary>
[Flags]
public enum NexusStackWalkFlags : uint
{
    Default = 0x0000,
    ResolveSymbols = 0x0001,
    ResolveModules = 0x0002,
    IncludeInline = 0x0004,
    Fast = 0x0008
}

/// <summary>
/// Injection method flags.
/// </summary>
public enum NexusInjectionMethod : int
{
    LoadLibrary = 0,
    ManualMap = 1,
    ThreadHijack = 2,
    Apc = 3
}

/// <summary>
/// Injection flags.
/// </summary>
[Flags]
public enum NexusInjectionFlags : uint
{
    None = 0,
    Wait = 0x0001,
    HideFromPeb = 0x0002,
    EraseHeaders = 0x0004,
    NoTls = 0x0008,
    Stealth = 0x0010,       // Use NtCreateThreadEx
    SkipAttach = 0x0020,    // Skip DLL_THREAD_ATTACH
    HideThread = 0x0040     // Hide thread from debugger
}

/// <summary>
/// ETW provider flags - which event categories to capture.
/// </summary>
[Flags]
public enum NexusEtwProviders : uint
{
    None = 0,
    Process = 0x0001,       // Process create/exit
    Thread = 0x0002,        // Thread create/exit
    ImageLoad = 0x0004,     // DLL/EXE load/unload
    FileIO = 0x0008,        // File operations
    Registry = 0x0010,      // Registry operations (high volume!)
    Network = 0x0020,       // TCP/UDP activity
    DiskIO = 0x0040,        // Low-level disk I/O
    VirtualAlloc = 0x0080,  // VirtualAlloc/Free
    ContextSwitch = 0x0100, // Thread context switches (very high volume!)
    SystemCall = 0x0200,    // System calls (high volume!)
    Alpc = 0x0400,          // Advanced Local Procedure Calls

    // Common presets
    Basic = Process | Thread | ImageLoad,
    Procmon = Basic | FileIO | Registry | Network,
    All = 0xFFFF
}

/// <summary>
/// ETW event categories.
/// </summary>
public enum NexusEtwEventCategory : uint
{
    Unknown = 0,
    Process = 1,
    Thread = 2,
    Image = 3,
    File = 4,
    Registry = 5,
    Network = 6,
    Disk = 7,
    Memory = 8,
    Syscall = 9,
    Alpc = 10
}

/// <summary>
/// ETW event operations (subcategories).
/// </summary>
public enum NexusEtwOperation : uint
{
    // Process
    ProcessStart = 100,
    ProcessExit = 101,

    // Thread
    ThreadStart = 200,
    ThreadExit = 201,

    // Image
    ImageLoad = 300,
    ImageUnload = 301,

    // File
    FileCreate = 400,
    FileRead = 401,
    FileWrite = 402,
    FileDelete = 403,
    FileRename = 404,
    FileClose = 405,
    FileQueryInfo = 406,
    FileSetInfo = 407,

    // Registry
    RegOpen = 500,
    RegCreate = 501,
    RegQuery = 502,
    RegSet = 503,
    RegDelete = 504,
    RegEnumKey = 505,
    RegEnumValue = 506,
    RegClose = 507,

    // Network
    TcpConnect = 600,
    TcpDisconnect = 601,
    TcpSend = 602,
    TcpRecv = 603,
    TcpAccept = 604,
    UdpSend = 610,
    UdpRecv = 611,

    // Memory
    MemAlloc = 700,
    MemFree = 701,
    MemProtect = 702,

    // Other
    Other = 999
}

/// <summary>
/// Speedhack timer types.
/// </summary>
public enum NexusSpeedHackTimer : int
{
    QueryPerformanceCounter = 0,
    GetTickCount = 1,
    GetTickCount64 = 2,
    TimeGetTime = 3,
    All = 255
}

/// <summary>
/// Assembler syntax modes.
/// </summary>
public enum NexusAssemblerSyntax : int
{
    Intel = 0,
    ATT = 1
}

/// <summary>
/// Assembler architecture modes.
/// </summary>
public enum NexusAssemblerMode : int
{
    Mode64 = 0,
    Mode32 = 1,
    Mode16 = 2
}

/// <summary>
/// Trace types.
/// </summary>
public enum NexusTraceType : int
{
    Into = 0,
    Over = 1,
    Until = 2
}

/// <summary>
/// Trace flags.
/// </summary>
[Flags]
public enum NexusTraceFlags : uint
{
    None = 0,
    IncludeSystem = 0x0001,
    IncludeJumps = 0x0002,
    IncludeCalls = 0x0004,
    SaveRegisters = 0x0008,
    SaveMemory = 0x0010
}

/// <summary>
/// Address entry types.
/// </summary>
public enum NexusAddressType : int
{
    Byte = 0,
    Word = 1,
    DWord = 2,
    QWord = 3,
    Float = 4,
    Double = 5,
    String = 6,
    ByteArray = 7,
    Pointer = 8,
    Custom = 255
}

/// <summary>
/// Trainer cheat types.
/// </summary>
public enum NexusCheatType : int
{
    WriteValue = 0,
    Freeze = 1,
    CodeInject = 2,
    Aob = 3,
    Pointer = 4
}

/// <summary>
/// Structure element types.
/// </summary>
public enum NexusElementType : int
{
    Byte = 0,
    Word = 1,
    DWord = 2,
    QWord = 3,
    Float = 4,
    Double = 5,
    String = 6,
    WString = 7,
    ByteArray = 8,
    Pointer = 9,
    Struct = 10,
    Padding = 11
}

/// <summary>
/// Disassembler instruction category.
/// </summary>
public enum NexusInsnCategory : int
{
    Unknown = 0,
    Arithmetic = 1,
    BitManip = 2,
    Branch = 3,
    Call = 4,
    Compare = 5,
    DataTransfer = 6,
    FloatingPoint = 7,
    Interrupt = 8,
    IO = 9,
    Logic = 10,
    Misc = 11,
    Nop = 12,
    Pop = 13,
    Push = 14,
    Ret = 15,
    Shift = 16,
    String = 17,
    System = 18,
    Cmov = 19,
    SetCC = 20,
    Xchg = 21,
    Simd = 22
}

/// <summary>
/// Symbol types.
/// </summary>
public enum NexusDbgSymbolType : int
{
    None = 0,
    Function = 1,
    Data = 2,
    PublicSymbol = 3,
    Parameter = 4,
    Local = 5,
    Block = 6,
    Label = 7,
    FuncDebug = 8,
    Constant = 9,
    UDT = 10,
    Export = 11
}

/// <summary>
/// Advanced scanner value types.
/// </summary>
public enum NexusScanValueType : int
{
    Byte = 0,
    Int16 = 1,
    Int32 = 2,
    Int64 = 3,
    Float = 4,
    Double = 5,
    String = 6,
    WString = 7,
    Aob = 8,
    All = 9
}

/// <summary>
/// Advanced scanner comparison types.
/// </summary>
public enum NexusScanCompareType : int
{
    Exact = 0,
    NotEqual = 1,
    Greater = 2,
    GreaterEqual = 3,
    Less = 4,
    LessEqual = 5,
    Between = 6,
    Increased = 7,
    IncreasedBy = 8,
    Decreased = 9,
    DecreasedBy = 10,
    Changed = 11,
    Unchanged = 12,
    Unknown = 13
}

/// <summary>
/// Advanced scanner options.
/// CE three-state behavior:
/// - Checked (Include): Only scan regions WITH property
/// - Unchecked (Exclude): Only scan regions WITHOUT property
/// - Indeterminate (DontCare): Don't filter by this property
/// </summary>
[Flags]
public enum NexusScanOptions : uint
{
    None = 0,
    // Include flags (Checked = must have property)
    Writable = 0x0001,
    Executable = 0x0002,
    CopyOnWrite = 0x0004,
    Mapped = 0x0008,
    Image = 0x0010,
    Private = 0x0020,
    Heap = 0x0040,
    Stack = 0x0080,
    // Other options
    CaseInsensitive = 0x0100,
    Unicode = 0x0200,
    HexString = 0x0400,
    Pause = 0x1000,
    FastScan = 0x2000,
    LastDigits = 0x4000,
    // Exclude flags (Unchecked = must NOT have property) - high bits
    WritableExclude = 0x010000,
    ExecutableExclude = 0x020000,
    CopyOnWriteExclude = 0x040000
}

/// <summary>
/// Kernel transport type.
/// </summary>
public enum NexusTransportType : int
{
    UserMode = 0,
    Kernel = 1,
    Hypervisor = 2
}

/// <summary>
/// Kernel capability flags.
/// </summary>
[Flags]
public enum NexusKernelCapability : uint
{
    ReadMemory = 0x0001,
    WriteMemory = 0x0002,
    PhysicalMemory = 0x0004,
    HideProcess = 0x0008,
    HideThread = 0x0010,
    HideHandle = 0x0020,
    BypassProtection = 0x0040,
    HookSyscall = 0x0080,
    EptHook = 0x0100,
    AntiDebug = 0x0200,
    TimingSpoof = 0x0400,
    KernelLoaded = 0x8000
}

/// <summary>
/// Hide types for kernel operations.
/// </summary>
public enum NexusHideType : int
{
    Process = 0,
    Thread = 1,
    Handle = 2,
    Module = 3,
    Memory = 4,
    Driver = 5
}

/// <summary>
/// Scan type for UI (maps to scanner compare type).
/// </summary>
public enum NexusScanType : int
{
    Exact = 0,
    BiggerThan = 2,
    SmallerThan = 4,
    Between = 6,
    UnknownInitial = 13,
    Increased = 7,
    IncreasedBy = 8,
    Decreased = 9,
    DecreasedBy = 10,
    Changed = 11,
    Unchanged = 12
}

/// <summary>
/// Value type for UI (matches CE value types).
/// </summary>
public enum NexusValueType : int
{
    Binary = 0,
    Byte = 1,
    TwoBytes = 2,
    FourBytes = 3,
    EightBytes = 4,
    Float = 5,
    Double = 6,
    String = 7,
    ArrayOfBytes = 8,
    All = 9,
    Custom = 255
}
