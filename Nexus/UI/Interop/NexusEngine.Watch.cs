// <file>
// <summary>
// P/Invoke bindings for watch expressions: evaluate symbolic expressions (e.g., "[rax+0x10]",
// "module.dll+0x1234") against the current debug context, resolve symbols to addresses,
// and monitor expression values over time.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Expression Evaluation

    /// <summary>
    /// Create an expression evaluator for a debugger session.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExprCreate(
        IntPtr debuggerHandle,
        out IntPtr exprHandle);

    /// <summary>
    /// Destroy an expression evaluator.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ExprDestroy(IntPtr exprHandle);

    /// <summary>
    /// Evaluate an expression and get the result.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExprEvaluate(
        IntPtr exprHandle,
        string expression,
        uint threadId,
        out NexusExprResult result);

    /// <summary>
    /// Evaluate an expression and get a string result.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExprEvaluateString(
        IntPtr exprHandle,
        string expression,
        uint threadId,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder result,
        nuint resultSize);

    /// <summary>
    /// Validate an expression syntax without evaluating.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExprValidate(
        IntPtr exprHandle,
        string expression,
        out NexusExprValidation validation);

    /// <summary>
    /// Get expression autocomplete suggestions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExprAutocomplete(
        IntPtr exprHandle,
        string partialExpr,
        uint threadId,
        [In, Out] NexusExprSuggestion[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Watch Variables

    /// <summary>
    /// Add a watch expression.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_WatchAdd(
        IntPtr exprHandle,
        string expression,
        string? name,
        out uint watchId);

    /// <summary>
    /// Remove a watch expression.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchRemove(
        IntPtr exprHandle,
        uint watchId);

    /// <summary>
    /// Clear all watch expressions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchClear(IntPtr exprHandle);

    /// <summary>
    /// Modify a watch expression.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_WatchModify(
        IntPtr exprHandle,
        uint watchId,
        string expression);

    /// <summary>
    /// Get a watch entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchGet(
        IntPtr exprHandle,
        uint watchId,
        out NexusWatchEntry entry);

    /// <summary>
    /// Get all watch entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchGetAll(
        IntPtr exprHandle,
        [In, Out] NexusWatchEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Refresh all watch values.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchRefresh(
        IntPtr exprHandle,
        uint threadId);

    /// <summary>
    /// Set watch value (modify memory through expression).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_WatchSetValue(
        IntPtr exprHandle,
        uint watchId,
        string valueExpr,
        uint threadId);

    #endregion

    #region Variable/Symbol Resolution

    /// <summary>
    /// Resolve a symbol name to an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_SymbolResolve(
        IntPtr exprHandle,
        string symbolName,
        out ulong address);

    /// <summary>
    /// Get symbol information at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SymbolFromAddress(
        IntPtr exprHandle,
        ulong address,
        out NexusSymbolResult symbol);

    /// <summary>
    /// Search for symbols by pattern.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_SymbolSearch(
        IntPtr exprHandle,
        string pattern,
        [In, Out] NexusSymbolResult[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get local variables for current scope.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetLocalVariables(
        IntPtr exprHandle,
        uint threadId,
        [In, Out] NexusLocalVariable[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get function arguments for current scope.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetArguments(
        IntPtr exprHandle,
        uint threadId,
        [In, Out] NexusLocalVariable[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Memory Watch

    /// <summary>
    /// Add a memory watch (monitor memory region for changes).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemoryWatchAdd(
        IntPtr exprHandle,
        ulong address,
        nuint size,
        NexusMemoryDisplayType displayType,
        out uint watchId);

    /// <summary>
    /// Get memory watch data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemoryWatchGet(
        IntPtr exprHandle,
        uint watchId,
        [In, Out] byte[]? buffer,
        nuint bufferSize,
        out nuint bytesRead);

    /// <summary>
    /// Check if memory watch value changed since last read.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemoryWatchChanged(
        IntPtr exprHandle,
        uint watchId,
        out uint changed);

    #endregion

    #region Conditional Watch

    /// <summary>
    /// Set a condition for a watch (highlight when true).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_WatchSetCondition(
        IntPtr exprHandle,
        uint watchId,
        string? condition);

    /// <summary>
    /// Set break-on-change for a watch expression.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchSetBreakOnChange(
        IntPtr exprHandle,
        uint watchId,
        uint enable);

    /// <summary>
    /// Check if watch value changed since last evaluation.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WatchValueChanged(
        IntPtr exprHandle,
        uint watchId,
        out uint changed);

    #endregion

    #region Watch Persistence

    /// <summary>
    /// Save watch list to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_WatchSave(
        IntPtr exprHandle,
        string filePath);

    /// <summary>
    /// Load watch list from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_WatchLoad(
        IntPtr exprHandle,
        string filePath);

    #endregion
}

#region Watch Enums and Structs

/// <summary>
/// Expression result type.
/// </summary>
public enum NexusExprType : uint
{
    Invalid = 0,
    Integer = 1,            // 64-bit integer
    Float = 2,              // Double precision float
    String = 3,             // String value
    Address = 4,            // Memory address
    Boolean = 5,            // True/false
    Struct = 6,             // Structure (needs expansion)
    Array = 7               // Array (needs expansion)
}

/// <summary>
/// Memory display type for watch.
/// </summary>
public enum NexusMemoryDisplayType : uint
{
    Bytes = 0,              // Raw bytes
    Int8 = 1,               // Signed 8-bit
    UInt8 = 2,              // Unsigned 8-bit
    Int16 = 3,              // Signed 16-bit
    UInt16 = 4,             // Unsigned 16-bit
    Int32 = 5,              // Signed 32-bit
    UInt32 = 6,             // Unsigned 32-bit
    Int64 = 7,              // Signed 64-bit
    UInt64 = 8,             // Unsigned 64-bit
    Float = 9,              // 32-bit float
    Double = 10,            // 64-bit double
    Ascii = 11,             // ASCII string
    Unicode = 12,           // Unicode string
    Pointer = 13            // Pointer (platform size)
}

/// <summary>
/// Expression evaluation result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExprResult
{
    public NexusExprType Type;          // Result type
    public ulong IntValue;              // Integer/address value
    public double FloatValue;           // Float value
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string StringValue;          // String representation
    public uint IsValid;                // Evaluation succeeded
    public uint HasAddress;             // Result has memory address
    public ulong Address;               // Memory address (if applicable)
}

/// <summary>
/// Expression validation result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExprValidation
{
    public uint IsValid;                // Expression is syntactically valid
    public uint ErrorPosition;          // Position of error (if any)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ErrorMessage;         // Error description
    public NexusExprType ResultType;    // Expected result type
}

/// <summary>
/// Autocomplete suggestion.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExprSuggestion
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Text;                 // Suggestion text
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Type;                 // Type hint
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;          // Description
    public uint Priority;               // Sort priority
}

/// <summary>
/// Watch entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusWatchEntry
{
    public uint Id;                     // Watch ID
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Expression;           // Watch expression
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Display name
    public NexusExprResult Value;       // Current value
    public uint IsEnabled;              // Watch is enabled
    public uint ValueChanged;           // Value changed since last eval
    public uint ConditionMet;           // Condition (if any) is true
    public uint BreakOnChange;          // Break when value changes
}

/// <summary>
/// Symbol information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSymbolResult
{
    public ulong Address;               // Symbol address
    public ulong Size;                  // Symbol size (if known)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Symbol name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module containing symbol
    public uint SymbolType;             // Function, data, etc.
    public uint IsPublic;               // Is public/exported
}

/// <summary>
/// Local variable information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusLocalVariable
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Variable name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Type;                 // Variable type
    public ulong Address;               // Memory address
    public NexusExprResult Value;       // Current value
    public int StackOffset;             // Offset from RSP/RBP
    public uint Register;               // Register (if register var)
    public uint IsArgument;             // Is function argument
    public uint IsRegister;             // Stored in register
}

#endregion
