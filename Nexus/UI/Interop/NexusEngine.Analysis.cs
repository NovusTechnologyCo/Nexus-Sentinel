// <file>
// <summary>
// P/Invoke bindings for analysis operations: disassembly (x86/x64 via Zydis), symbol
// resolution and enumeration, control flow graph generation, structure definition and
// field management, and assembler (text-to-machine-code via Keystone).
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Disassembler Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DisasmDecode(
        IntPtr code,
        nuint codeSize,
        ulong address,
        int mode,
        out NexusInstruction instruction);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DisasmDecodeMultiple(
        IntPtr code,
        nuint codeSize,
        ulong address,
        int mode,
        [In, Out] NexusInstruction[] instructions,
        nuint maxInstructions,
        out nuint instructionCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DisasmDecodeProcess(
        IntPtr processHandle,
        ulong address,
        nuint maxInstructions,
        [In, Out] NexusDisasmInstruction[] instructions,
        out nuint instructionCount);

    #endregion

    #region Symbol Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SymbolCreate(
        IntPtr processHandle,
        uint options,
        out IntPtr symbolHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SymbolDestroy(IntPtr symbolHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SymbolFromAddress(
        IntPtr symbolHandle,
        ulong address,
        out NexusSymbolInfo info,
        out ulong displacement);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_SymbolFromName(
        IntPtr symbolHandle,
        string name,
        out NexusSymbolInfo info);

    // Symbol option flags
    public const uint NEXUS_SYM_UNDNAME = 0x00000002;
    public const uint NEXUS_SYM_DEFERRED_LOADS = 0x00000004;

    #endregion

    #region CFG (Control Flow Graph) Operations

    /// <summary>
    /// Analyze control flow and build CFG for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGAnalyze(
        IntPtr process,
        ulong entryAddress,
        nuint maxInstructions,
        out IntPtr cfg);

    /// <summary>
    /// Destroy a CFG handle and free associated resources.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CFGDestroy(IntPtr cfg);

    /// <summary>
    /// Get CFG analysis result summary.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetResult(
        IntPtr cfg,
        out NexusCFGResult result);

    /// <summary>
    /// Get all basic blocks in the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetBlocks(
        IntPtr cfg,
        [In, Out] NexusBasicBlock[]? blocks,
        nuint maxBlocks,
        out nuint blockCount);

    /// <summary>
    /// Get all edges in the CFG.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetEdges(
        IntPtr cfg,
        [In, Out] NexusCFGEdge[]? edges,
        nuint maxEdges,
        out nuint edgeCount);

    /// <summary>
    /// Get a specific basic block by address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetBlockByAddress(
        IntPtr cfg,
        ulong address,
        out NexusBasicBlock block);

    /// <summary>
    /// Get disassembly for a basic block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetBlockInstructions(
        IntPtr cfg,
        uint blockIndex,
        [In, Out] NexusDisasmInstruction[]? instructions,
        nuint maxInstructions,
        out nuint instructionCount);

    /// <summary>
    /// Get predecessors of a basic block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetPredecessors(
        IntPtr cfg,
        uint blockIndex,
        [In, Out] uint[]? predecessors,
        nuint maxPredecessors,
        out nuint predecessorCount);

    /// <summary>
    /// Get successors of a basic block.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CFGGetSuccessors(
        IntPtr cfg,
        uint blockIndex,
        [In, Out] uint[]? successors,
        nuint maxSuccessors,
        out nuint successorCount);

    #endregion

    #region Structure Dissection Operations

    /// <summary>
    /// Create a new empty structure definition.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureCreate(
        string name,
        out IntPtr structure);

    /// <summary>
    /// Destroy a structure and free all resources.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_StructureDestroy(IntPtr structure);

    /// <summary>
    /// Get structure information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureGetInfo(
        IntPtr structure,
        out NexusStructInfo info);

    /// <summary>
    /// Set structure properties.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureSetProperties(
        IntPtr structure,
        string? name,
        int size,
        uint flags);

    /// <summary>
    /// Add an element to the structure.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureAddElement(
        IntPtr structure,
        int offset,
        NexusElementType varType,
        string name,
        int byteSize,
        out uint elementId);

    /// <summary>
    /// Remove an element from the structure.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureRemoveElement(
        IntPtr structure,
        uint elementId);

    /// <summary>
    /// Get element by ID.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureGetElement(
        IntPtr structure,
        uint elementId,
        out NexusStructElement element);

    /// <summary>
    /// Get element by index (sorted by offset).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureGetElementByIndex(
        IntPtr structure,
        uint index,
        out NexusStructElement element);

    /// <summary>
    /// Get the number of elements in the structure.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureGetElementCount(
        IntPtr structure,
        out uint count);

    /// <summary>
    /// Auto-fill gaps in structure with byte elements.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureFillGaps(
        IntPtr structure,
        IntPtr process,
        ulong baseAddress);

    /// <summary>
    /// Auto-guess structure from memory using enhanced heuristics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureAutoGuess(
        IntPtr structure,
        IntPtr process,
        ulong address,
        nuint size);

    /// <summary>
    /// Sort elements by offset.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureSortElements(IntPtr structure);

    /// <summary>
    /// Create a structure instance at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureCreateInstance(
        IntPtr structure,
        ulong baseAddress,
        string? name,
        out NexusStructInstance instance);

    /// <summary>
    /// Read element value from a structure instance.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureReadElement(
        IntPtr structure,
        IntPtr process,
        ulong baseAddress,
        uint elementId,
        out NexusElementValue value);

    /// <summary>
    /// Read all element values from a structure instance.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StructureReadAllElements(
        IntPtr structure,
        IntPtr process,
        ulong baseAddress,
        [In, Out] NexusElementValue[] values,
        nuint maxValues,
        out nuint valuesRead);

    /// <summary>
    /// Save structure to XML file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureSave(
        IntPtr structure,
        string path);

    /// <summary>
    /// Load structure from XML file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureLoad(
        string path,
        out IntPtr structure);

    /// <summary>
    /// Import structure from CE structure file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureImportCE(
        string path,
        out IntPtr structure);

    /// <summary>
    /// Export structure to CE-compatible format.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureExportCE(
        IntPtr structure,
        string path);

    /// <summary>
    /// Clone a structure (deep copy).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_StructureClone(
        IntPtr source,
        string? newName,
        out IntPtr clone);

    #endregion

    #region Assembler Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AssemblerCreate(
        IntPtr processHandle,
        NexusAssemblerArch arch,
        out IntPtr assembler);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_AssemblerDestroy(IntPtr assembler);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_AssembleInstruction(
        IntPtr assembler,
        string instruction,
        ulong address,
        [Out] byte[] codeBuffer,
        nuint bufferSize,
        out nuint codeLength);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AssemblerGetLastError(
        IntPtr assembler,
        out NexusAssemblerErrorInfo error);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_AssemblerExecuteScript(
        IntPtr assembler,
        string script,
        [MarshalAs(UnmanagedType.Bool)] bool enableSection);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_AssemblerAddSymbol(
        IntPtr assembler,
        string name,
        ulong address);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AssemblerFreeAllAllocations(IntPtr assembler);

    /// <summary>
    /// Assembles a single instruction and returns the machine code bytes.
    /// </summary>
    public static NexusResult Nexus_Assemble(
        string instruction,
        ulong address,
        bool is64Bit,
        out byte[] bytes,
        out nuint length,
        out string? error)
    {
        bytes = new byte[16];
        length = 0;
        error = null;

        var arch = is64Bit ? NexusAssemblerArch.X64 : NexusAssemblerArch.X86;
        var result = Nexus_AssemblerCreate(IntPtr.Zero, arch, out var assembler);
        if (result != NexusResult.OK)
        {
            error = "Failed to create assembler";
            return result;
        }

        try
        {
            result = Nexus_AssembleInstruction(assembler, instruction, address, bytes, (nuint)bytes.Length, out length);
            if (result != NexusResult.OK)
            {
                if (Nexus_AssemblerGetLastError(assembler, out var errorInfo) == NexusResult.OK)
                {
                    error = errorInfo.Message;
                }
                else
                {
                    error = "Assembly failed";
                }
            }
            return result;
        }
        finally
        {
            Nexus_AssemblerDestroy(assembler);
        }
    }

    #endregion
}

/// <summary>
/// Assembler target architecture.
/// </summary>
public enum NexusAssemblerArch : uint
{
    X86 = 0,
    X64 = 1
}

/// <summary>
/// Assembler error information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusAssemblerErrorInfo
{
    public uint ErrorCode;
    public uint Line;
    public uint Column;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Message;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Context;
}
