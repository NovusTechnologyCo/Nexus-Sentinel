// <file>
// <summary>
// P/Invoke bindings for the annotation database: address labels, inline comments,
// and bookmarks. Annotations persist across sessions via the engine's project file system.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Annotation Database

    /// <summary>
    /// Create an annotation database for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AnnotationCreate(
        IntPtr processHandle,
        out IntPtr annotationHandle);

    /// <summary>
    /// Destroy an annotation database.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_AnnotationDestroy(IntPtr annotationHandle);

    /// <summary>
    /// Save annotations to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_AnnotationSave(
        IntPtr annotationHandle,
        string filePath);

    /// <summary>
    /// Load annotations from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_AnnotationLoad(
        IntPtr annotationHandle,
        string filePath);

    /// <summary>
    /// Clear all annotations.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AnnotationClear(IntPtr annotationHandle);

    #endregion

    #region Labels

    /// <summary>
    /// Set a label at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_LabelSet(
        IntPtr annotationHandle,
        ulong address,
        string text,
        uint isManual);

    /// <summary>
    /// Set a temporary label (not saved to database).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_LabelSetTemporary(
        IntPtr annotationHandle,
        ulong address,
        string text);

    /// <summary>
    /// Get the label at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelGet(
        IntPtr annotationHandle,
        ulong address,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder text,
        nuint textSize);

    /// <summary>
    /// Get detailed label information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelGetInfo(
        IntPtr annotationHandle,
        ulong address,
        out NexusLabelInfo info);

    /// <summary>
    /// Delete a label.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelDelete(
        IntPtr annotationHandle,
        ulong address);

    /// <summary>
    /// Delete all labels in an address range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelDeleteRange(
        IntPtr annotationHandle,
        ulong startAddress,
        ulong endAddress);

    /// <summary>
    /// Find address by label text.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_LabelFromString(
        IntPtr annotationHandle,
        string label,
        out ulong address);

    /// <summary>
    /// Get all labels.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelGetList(
        IntPtr annotationHandle,
        [In, Out] NexusLabelInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Check if a label is temporary.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LabelIsTemporary(
        IntPtr annotationHandle,
        ulong address,
        out uint isTemporary);

    #endregion

    #region Comments

    /// <summary>
    /// Set a comment at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CommentSet(
        IntPtr annotationHandle,
        ulong address,
        string text,
        uint isManual);

    /// <summary>
    /// Get the comment at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommentGet(
        IntPtr annotationHandle,
        ulong address,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder text,
        nuint textSize);

    /// <summary>
    /// Get detailed comment information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommentGetInfo(
        IntPtr annotationHandle,
        ulong address,
        out NexusCommentInfo info);

    /// <summary>
    /// Delete a comment.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommentDelete(
        IntPtr annotationHandle,
        ulong address);

    /// <summary>
    /// Delete all comments in an address range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommentDeleteRange(
        IntPtr annotationHandle,
        ulong startAddress,
        ulong endAddress);

    /// <summary>
    /// Get all comments.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommentGetList(
        IntPtr annotationHandle,
        [In, Out] NexusCommentInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Bookmarks

    /// <summary>
    /// Set a bookmark at an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BookmarkSet(
        IntPtr annotationHandle,
        ulong address,
        string? description);

    /// <summary>
    /// Get bookmark information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkGet(
        IntPtr annotationHandle,
        ulong address,
        out NexusBookmarkInfo info);

    /// <summary>
    /// Check if an address is bookmarked.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkExists(
        IntPtr annotationHandle,
        ulong address,
        out uint exists);

    /// <summary>
    /// Delete a bookmark.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkDelete(
        IntPtr annotationHandle,
        ulong address);

    /// <summary>
    /// Get all bookmarks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkGetList(
        IntPtr annotationHandle,
        [In, Out] NexusBookmarkInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get the next bookmark after an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkGetNext(
        IntPtr annotationHandle,
        ulong address,
        out ulong nextAddress);

    /// <summary>
    /// Get the previous bookmark before an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BookmarkGetPrev(
        IntPtr annotationHandle,
        ulong address,
        out ulong prevAddress);

    #endregion

    #region Function Analysis Annotations

    /// <summary>
    /// Mark an address range as a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_FunctionSet(
        IntPtr annotationHandle,
        ulong startAddress,
        ulong endAddress,
        string? name);

    /// <summary>
    /// Get function bounds for an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FunctionGet(
        IntPtr annotationHandle,
        ulong address,
        out NexusFunctionInfo info);

    /// <summary>
    /// Delete a function annotation.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FunctionDelete(
        IntPtr annotationHandle,
        ulong address);

    /// <summary>
    /// Get all function annotations.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FunctionGetList(
        IntPtr annotationHandle,
        [In, Out] NexusFunctionInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Argument/Variable Annotations

    /// <summary>
    /// Set an argument name for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ArgumentSet(
        IntPtr annotationHandle,
        ulong functionAddress,
        uint argIndex,
        string name,
        string? type);

    /// <summary>
    /// Get argument information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ArgumentGet(
        IntPtr annotationHandle,
        ulong functionAddress,
        uint argIndex,
        out NexusArgumentInfo info);

    /// <summary>
    /// Delete an argument annotation.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ArgumentDelete(
        IntPtr annotationHandle,
        ulong functionAddress,
        uint argIndex);

    /// <summary>
    /// Get all arguments for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ArgumentGetList(
        IntPtr annotationHandle,
        ulong functionAddress,
        [In, Out] NexusArgumentInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region Annotation Structs

/// <summary>
/// Label information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusLabelInfo
{
    public ulong Address;               // Address of the label
    public ulong Rva;                   // RVA within module
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Text;                 // Label text
    public uint IsManual;               // User-defined (vs auto-generated)
    public uint IsTemporary;            // Temporary (not saved)
}

/// <summary>
/// Comment information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCommentInfo
{
    public ulong Address;               // Address of the comment
    public ulong Rva;                   // RVA within module
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Text;                 // Comment text
    public uint IsManual;               // User-defined (vs auto-generated)
}

/// <summary>
/// Bookmark information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusBookmarkInfo
{
    public ulong Address;               // Bookmarked address
    public ulong Rva;                   // RVA within module
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;          // Optional description
    public uint Index;                  // Bookmark index (for ordering)
}

/// <summary>
/// Function annotation information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusFunctionInfo
{
    public ulong StartAddress;          // Function start
    public ulong EndAddress;            // Function end
    public ulong Rva;                   // RVA within module
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Function name
    public uint IsManual;               // User-defined bounds
    public uint ArgumentCount;          // Number of arguments
    public uint LocalCount;             // Number of local variables
}

/// <summary>
/// Function argument information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusArgumentInfo
{
    public ulong FunctionAddress;       // Owning function
    public uint Index;                  // Argument index (0-based)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Argument name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Type;                 // Type name
    public int StackOffset;             // Offset from RSP (if stack arg)
    public uint Register;               // Register number (if register arg)
    public uint IsRegister;             // Is stored in register
}

#endregion
