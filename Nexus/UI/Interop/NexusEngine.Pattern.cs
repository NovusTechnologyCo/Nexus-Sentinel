// <file>
// <summary>
// P/Invoke bindings for code pattern detection and analysis. Identifies function prologues,
// loop constructs, switch tables, vtable references, and common code idioms in disassembled
// instruction streams.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Pattern Scanner

    /// <summary>
    /// Create a pattern scanner for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternCreate(
        IntPtr processHandle,
        out IntPtr patternHandle);

    /// <summary>
    /// Destroy a pattern scanner.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_PatternDestroy(IntPtr patternHandle);

    /// <summary>
    /// Scan for a byte pattern with wildcards.
    /// Pattern format: "48 8B ?? 90 ??" where ?? is wildcard
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatternScan(
        IntPtr patternHandle,
        string pattern,
        ulong startAddress,
        ulong endAddress,
        [In, Out] ulong[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Scan for a pattern in a specific module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatternScanModule(
        IntPtr patternHandle,
        string pattern,
        [MarshalAs(UnmanagedType.LPWStr)] string moduleName,
        [In, Out] ulong[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Scan for multiple patterns simultaneously.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternScanMultiple(
        IntPtr patternHandle,
        [In] NexusPatternDef[] patterns,
        nuint patternCount,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusPatternMatch[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Create a pattern from bytes (auto-generate wildcards).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternFromBytes(
        IntPtr patternHandle,
        ulong address,
        nuint size,
        uint wildcardRelocations,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder pattern,
        nuint patternSize);

    #endregion

    #region Loop Detection

    /// <summary>
    /// Detect loops in a function's control flow.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LoopDetect(
        IntPtr patternHandle,
        ulong functionAddress,
        [In, Out] NexusLoop[]? loops,
        nuint maxLoops,
        out nuint loopCount);

    /// <summary>
    /// Analyze a loop structure.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LoopAnalyze(
        IntPtr patternHandle,
        ulong loopAddress,
        out NexusLoopInfo loopInfo);

    /// <summary>
    /// Find all back edges (loop indicators) in a range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LoopFindBackEdges(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusBackEdge[]? backEdges,
        nuint maxBackEdges,
        out nuint backEdgeCount);

    /// <summary>
    /// Estimate loop iteration count from runtime data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LoopEstimateIterations(
        IntPtr patternHandle,
        ulong loopAddress,
        uint threadId,
        out NexusLoopIterationInfo iterInfo);

    #endregion

    #region Code Pattern Recognition

    /// <summary>
    /// Detect known code patterns (encryption, obfuscation, etc.).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectCode(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        NexusCodePatternType patternTypes,
        [In, Out] NexusCodePattern[]? patterns,
        nuint maxPatterns,
        out nuint patternCount);

    /// <summary>
    /// Detect common crypto patterns (AES, RC4, XOR, etc.).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectCrypto(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusCryptoPattern[]? patterns,
        nuint maxPatterns,
        out nuint patternCount);

    /// <summary>
    /// Detect function prologues/epilogues.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectFunctions(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] ulong[]? functionStarts,
        nuint maxFunctions,
        out nuint functionCount);

    /// <summary>
    /// Detect switch/jump tables.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectSwitchTables(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusSwitchTable[]? tables,
        nuint maxTables,
        out nuint tableCount);

    #endregion

    #region Data Pattern Recognition

    /// <summary>
    /// Detect data structures (vtables, arrays, etc.).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectData(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        NexusDataPatternType patternTypes,
        [In, Out] NexusDataPattern[]? patterns,
        nuint maxPatterns,
        out nuint patternCount);

    /// <summary>
    /// Detect virtual tables (vtables).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectVtables(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusVtable[]? vtables,
        nuint maxVtables,
        out nuint vtableCount);

    /// <summary>
    /// Detect RTTI type information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternDetectRTTI(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusRttiInfo[]? rttiList,
        nuint maxRtti,
        out nuint rttiCount);

    #endregion

    #region Signature Generation

    /// <summary>
    /// Generate a unique signature for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternGenerateSignature(
        IntPtr patternHandle,
        ulong functionAddress,
        out NexusSignature signature);

    /// <summary>
    /// Find a function by its signature.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternFindBySignature(
        IntPtr patternHandle,
        ref NexusSignature signature,
        ulong startAddress,
        ulong endAddress,
        out ulong foundAddress);

    /// <summary>
    /// Compare two signatures for similarity.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternCompareSignatures(
        ref NexusSignature sig1,
        ref NexusSignature sig2,
        out double similarityScore);

    #endregion

    #region Entropy Analysis

    /// <summary>
    /// Calculate entropy of a memory region.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternCalculateEntropy(
        IntPtr patternHandle,
        ulong address,
        nuint size,
        out double entropy);

    /// <summary>
    /// Scan for high-entropy regions (possible encryption/compression).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatternFindHighEntropy(
        IntPtr patternHandle,
        ulong startAddress,
        ulong endAddress,
        double threshold,
        [In, Out] NexusEntropyRegion[]? regions,
        nuint maxRegions,
        out nuint regionCount);

    #endregion
}

#region Pattern Enums and Structs

/// <summary>
/// Code pattern types to detect.
/// </summary>
[Flags]
public enum NexusCodePatternType : uint
{
    None = 0,
    Prologue = 1,           // Function prologue
    Epilogue = 2,           // Function epilogue
    Loop = 4,               // Loop structure
    Switch = 8,             // Switch statement
    VirtualCall = 16,       // Virtual function call
    IndirectCall = 32,      // Indirect call
    Syscall = 64,           // System call
    Obfuscation = 128,      // Obfuscated code
    AntiDebug = 256,        // Anti-debug check
    Crypto = 512,           // Cryptographic operation
    All = 0xFFFFFFFF
}

/// <summary>
/// Data pattern types to detect.
/// </summary>
[Flags]
public enum NexusDataPatternType : uint
{
    None = 0,
    Vtable = 1,             // Virtual table
    Array = 2,              // Array of same-type elements
    String = 4,             // String data
    PointerArray = 8,       // Array of pointers
    Struct = 16,            // Structure
    RTTI = 32,              // Runtime type information
    ImportTable = 64,       // Import table
    ExportTable = 128,      // Export table
    All = 0xFFFFFFFF
}

/// <summary>
/// Pattern definition for multi-scan.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPatternDef
{
    public uint Id;                         // Pattern ID
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Pattern;                  // Pattern string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                     // Pattern name
}

/// <summary>
/// Pattern match result.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPatternMatch
{
    public uint PatternId;                  // Which pattern matched
    public ulong Address;                   // Match address
}

/// <summary>
/// Loop structure information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusLoop
{
    public ulong HeaderAddress;             // Loop header (entry point)
    public ulong BackEdgeAddress;           // Back edge (jump back)
    public ulong ExitAddress;               // Loop exit point
    public nuint BodySize;                  // Size of loop body
    public uint Depth;                      // Nesting depth
    public uint IsCountControlled;          // Has fixed iteration count
}

/// <summary>
/// Detailed loop analysis.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusLoopInfo
{
    public NexusLoop Basic;                 // Basic loop info
    public uint InstructionCount;           // Instructions in loop body
    public uint BasicBlockCount;            // Basic blocks in loop
    public uint NestedLoopCount;            // Number of nested loops
    public ulong InductionVariable;         // Address of loop counter (if any)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string InductionVarName;         // Name of induction variable
    public uint EstimatedIterations;        // Estimated iteration count
    public uint HasSideEffects;             // Loop has memory side effects
}

/// <summary>
/// Back edge information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusBackEdge
{
    public ulong FromAddress;               // Jump source
    public ulong ToAddress;                 // Jump target (header)
    public uint IsConditional;              // Conditional back edge
}

/// <summary>
/// Loop iteration information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusLoopIterationInfo
{
    public ulong LoopAddress;               // Loop header address
    public uint ObservedIterations;         // Iterations observed
    public uint MinIterations;              // Minimum observed
    public uint MaxIterations;              // Maximum observed
    public double AverageIterations;        // Average iterations
    public uint BreakCount;                 // Times exited early
}

/// <summary>
/// Detected code pattern.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCodePattern
{
    public NexusCodePatternType Type;       // Pattern type
    public ulong Address;                   // Pattern address
    public nuint Size;                      // Pattern size
    public uint Confidence;                 // Confidence (0-100)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Description;              // Pattern description
}

/// <summary>
/// Detected crypto pattern.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCryptoPattern
{
    public ulong Address;                   // Pattern address
    public nuint Size;                      // Pattern size
    public uint CryptoType;                 // 1=XOR, 2=AES, 3=RC4, 4=DES, etc.
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Algorithm;                // Algorithm name
    public uint Confidence;                 // Confidence (0-100)
    public ulong KeyAddress;                // Key address (if detected)
    public uint KeySize;                    // Key size (if detected)
}

/// <summary>
/// Switch/jump table.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusSwitchTable
{
    public ulong SwitchAddress;             // Switch instruction address
    public ulong TableAddress;              // Jump table address
    public uint EntryCount;                 // Number of entries
    public uint EntrySize;                  // Size of each entry
    public uint IsRelative;                 // Entries are relative offsets
    public ulong DefaultCase;               // Default case address
}

/// <summary>
/// Detected data pattern.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusDataPattern
{
    public NexusDataPatternType Type;       // Pattern type
    public ulong Address;                   // Pattern address
    public nuint Size;                      // Pattern size
    public uint ElementCount;               // Number of elements
    public uint ElementSize;                // Size of each element
    public uint Confidence;                 // Confidence (0-100)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Description;              // Pattern description
}

/// <summary>
/// Virtual table information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusVtable
{
    public ulong Address;                   // Vtable address
    public uint FunctionCount;              // Number of virtual functions
    public ulong RttiAddress;               // RTTI address (if present)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ClassName;                // Class name (from RTTI)
}

/// <summary>
/// RTTI information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusRttiInfo
{
    public ulong TypeDescriptorAddress;     // Type descriptor
    public ulong VtableAddress;             // Associated vtable
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ClassName;                // Class name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string DemangledName;            // Demangled name
    public uint BaseClassCount;             // Number of base classes
    public uint IsMultipleInheritance;      // Uses multiple inheritance
}

/// <summary>
/// Function signature for matching.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusSignature
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] Hash;                     // Signature hash
    public uint Length;                     // Original function length
    public uint InstructionCount;           // Number of instructions
    public uint UniqueOpcodes;              // Number of unique opcodes
    public uint CallCount;                  // Number of call instructions
    public uint JumpCount;                  // Number of jump instructions
}

/// <summary>
/// High-entropy region.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusEntropyRegion
{
    public ulong Address;                   // Region address
    public nuint Size;                      // Region size
    public double Entropy;                  // Entropy value (0-8)
    public uint LikelyEncrypted;            // Likely encrypted data
    public uint LikelyCompressed;           // Likely compressed data
}

#endregion
