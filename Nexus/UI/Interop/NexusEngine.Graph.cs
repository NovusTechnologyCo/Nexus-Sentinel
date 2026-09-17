// <file>
// <summary>
// P/Invoke bindings for control flow graph (CFG) and call graph analysis. Generates
// basic block graphs from function addresses, enumerates blocks and edges, and builds
// call graphs showing inter-function relationships.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region CFG Creation

    /// <summary>
    /// Create a control flow graph for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgCreate(
        IntPtr processHandle,
        ulong functionAddress,
        out IntPtr cfgHandle);

    /// <summary>
    /// Create a CFG with specific analysis options.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgCreateEx(
        IntPtr processHandle,
        ulong functionAddress,
        NexusCfgOptions options,
        out IntPtr cfgHandle);

    /// <summary>
    /// Destroy a CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CfgDestroy(IntPtr cfgHandle);

    /// <summary>
    /// Rebuild/refresh a CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgRebuild(IntPtr cfgHandle);

    #endregion

    #region Basic Blocks

    /// <summary>
    /// Get all basic blocks in the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetBlocks(
        IntPtr cfgHandle,
        [In, Out] NexusCfgBlock[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get a specific basic block by address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetBlockAt(
        IntPtr cfgHandle,
        ulong address,
        out NexusCfgBlock block);

    /// <summary>
    /// Get the entry block of the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetEntryBlock(
        IntPtr cfgHandle,
        out NexusCfgBlock block);

    /// <summary>
    /// Get exit blocks of the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetExitBlocks(
        IntPtr cfgHandle,
        [In, Out] NexusCfgBlock[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get instructions in a basic block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetBlockInstructions(
        IntPtr cfgHandle,
        ulong blockAddress,
        [In, Out] NexusCfgInstruction[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Edges

    /// <summary>
    /// Get all edges in the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetEdges(
        IntPtr cfgHandle,
        [In, Out] NexusCfgEdge[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get outgoing edges from a block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetSuccessors(
        IntPtr cfgHandle,
        ulong blockAddress,
        [In, Out] NexusCfgEdge[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get incoming edges to a block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetPredecessors(
        IntPtr cfgHandle,
        ulong blockAddress,
        [In, Out] NexusCfgEdge[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Dominators

    /// <summary>
    /// Get the immediate dominator of a block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetDominator(
        IntPtr cfgHandle,
        ulong blockAddress,
        out ulong dominatorAddress);

    /// <summary>
    /// Get all dominators of a block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetDominators(
        IntPtr cfgHandle,
        ulong blockAddress,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get blocks dominated by a block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetDominated(
        IntPtr cfgHandle,
        ulong blockAddress,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Check if block A dominates block B.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgDominates(
        IntPtr cfgHandle,
        ulong blockA,
        ulong blockB,
        out uint dominates);

    #endregion

    #region Paths

    /// <summary>
    /// Find all paths between two blocks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgFindPaths(
        IntPtr cfgHandle,
        ulong fromBlock,
        ulong toBlock,
        [In, Out] NexusCfgPath[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find the shortest path between two blocks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgFindShortestPath(
        IntPtr cfgHandle,
        ulong fromBlock,
        ulong toBlock,
        out NexusCfgPath path);

    /// <summary>
    /// Check if a path exists between two blocks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgPathExists(
        IntPtr cfgHandle,
        ulong fromBlock,
        ulong toBlock,
        out uint exists);

    #endregion

    #region Analysis

    /// <summary>
    /// Get CFG statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetStats(
        IntPtr cfgHandle,
        out NexusCfgStats stats);

    /// <summary>
    /// Detect unreachable code.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgFindUnreachable(
        IntPtr cfgHandle,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get cyclomatic complexity.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgGetComplexity(
        IntPtr cfgHandle,
        out uint complexity);

    /// <summary>
    /// Identify natural loops.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgFindLoops(
        IntPtr cfgHandle,
        [In, Out] NexusCfgLoop[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Export

    /// <summary>
    /// Export CFG to DOT format (Graphviz).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_CfgExportDot(
        IntPtr cfgHandle,
        string filePath);

    /// <summary>
    /// Export CFG to JSON.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_CfgExportJson(
        IntPtr cfgHandle,
        string filePath);

    /// <summary>
    /// Export CFG to custom format.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CfgExport(
        IntPtr cfgHandle,
        NexusCfgExportFormat format,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder output,
        nuint outputSize);

    #endregion

    #region Call Graph

    /// <summary>
    /// Create a call graph for a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallGraphCreate(
        IntPtr processHandle,
        ulong moduleBase,
        ulong moduleSize,
        out IntPtr callGraphHandle);

    /// <summary>
    /// Destroy a call graph.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CallGraphDestroy(IntPtr callGraphHandle);

    /// <summary>
    /// Get functions called by a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallGraphGetCallees(
        IntPtr callGraphHandle,
        ulong functionAddress,
        [In, Out] NexusCallGraphNode[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get functions that call a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallGraphGetCallers(
        IntPtr callGraphHandle,
        ulong functionAddress,
        [In, Out] NexusCallGraphNode[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find all paths in call graph between two functions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallGraphFindPaths(
        IntPtr callGraphHandle,
        ulong fromFunction,
        ulong toFunction,
        uint maxDepth,
        [In, Out] NexusCallPath[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region CFG Enums and Structs

/// <summary>
/// CFG analysis options.
/// </summary>
[Flags]
public enum NexusCfgOptions : uint
{
    None = 0,
    FollowCalls = 1,            // Include called functions
    ResolveIndirect = 2,        // Resolve indirect jumps
    DetectLoops = 4,            // Identify loop structures
    ComputeDominators = 8,      // Compute dominator tree
    TrackRegisters = 16,        // Track register values
    All = 0xFFFFFFFF
}

/// <summary>
/// CFG edge type.
/// </summary>
public enum NexusCfgEdgeType : uint
{
    Normal = 0,                 // Normal control flow
    ConditionalTrue = 1,        // Conditional true branch
    ConditionalFalse = 2,       // Conditional false branch
    Unconditional = 3,          // Unconditional jump
    Call = 4,                   // Function call
    Return = 5,                 // Function return
    Exception = 6,              // Exception handler
    BackEdge = 7                // Loop back edge
}

/// <summary>
/// CFG export format.
/// </summary>
public enum NexusCfgExportFormat : uint
{
    Dot = 0,                    // Graphviz DOT
    Json = 1,                   // JSON
    Xml = 2,                    // XML
    Text = 3                    // Plain text
}

/// <summary>
/// Basic block information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCfgBlock
{
    public ulong StartAddress;          // Block start address
    public ulong EndAddress;            // Block end address (last instruction)
    public nuint Size;                  // Block size in bytes
    public uint InstructionCount;       // Number of instructions
    public uint SuccessorCount;         // Number of outgoing edges
    public uint PredecessorCount;       // Number of incoming edges
    public uint IsEntry;                // Is function entry block
    public uint IsExit;                 // Is function exit block
    public uint LoopDepth;              // Nesting depth in loops
    public uint DominatorTreeLevel;     // Level in dominator tree
}

/// <summary>
/// CFG edge information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCfgEdge
{
    public ulong FromBlock;             // Source block address
    public ulong ToBlock;               // Target block address
    public NexusCfgEdgeType Type;       // Edge type
    public uint IsBackEdge;             // Is this a back edge (loop)
}

/// <summary>
/// CFG instruction information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCfgInstruction
{
    public ulong Address;               // Instruction address
    public uint Size;                   // Instruction size
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Mnemonic;             // Disassembled text
    public uint IsCall;                 // Is call instruction
    public uint IsJump;                 // Is jump instruction
    public uint IsReturn;               // Is return instruction
    public uint IsConditional;          // Is conditional
    public ulong TargetAddress;         // Jump/call target (if applicable)
}

/// <summary>
/// CFG path information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCfgPath
{
    public uint NodeCount;              // Number of nodes in path
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public ulong[] Nodes;               // Node addresses (first 64)
    public uint HasMore;                // Path has more than 64 nodes
}

/// <summary>
/// CFG statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCfgStats
{
    public uint BlockCount;             // Number of basic blocks
    public uint EdgeCount;              // Number of edges
    public uint InstructionCount;       // Total instructions
    public uint LoopCount;              // Number of loops
    public uint MaxLoopDepth;           // Maximum loop nesting
    public uint CyclomaticComplexity;   // McCabe complexity
    public uint UnreachableBlocks;      // Unreachable code blocks
    public uint ExitPoints;             // Number of exit points
}

/// <summary>
/// Natural loop information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCfgLoop
{
    public ulong HeaderAddress;         // Loop header block
    public ulong BackEdgeSource;        // Back edge source block
    public uint BodyBlockCount;         // Blocks in loop body
    public uint Depth;                  // Loop nesting depth
    public uint HasMultipleExits;       // Loop has multiple exits
    public uint IsReducible;            // Is a reducible loop
}

/// <summary>
/// Call graph node.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCallGraphNode
{
    public ulong Address;               // Function address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Function name
    public uint CallCount;              // Number of call sites
    public uint CallerCount;            // Number of callers
    public uint CalleeCount;            // Number of callees
    public uint IsImport;               // Is imported function
    public uint IsExport;               // Is exported function
}

/// <summary>
/// Call path information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCallPath
{
    public uint Depth;                  // Path depth
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public ulong[] Functions;           // Function addresses (first 32)
    public uint HasMore;                // Path has more than 32 functions
}

#endregion
