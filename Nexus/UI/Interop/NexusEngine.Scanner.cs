// <file>
// <summary>
// P/Invoke bindings for memory scanner operations: first scan, next scan (refine), undo,
// result enumeration, pointer scanning, and advanced scanner configuration. Supports all
// value types (byte through double, string, AOB) and scan modes (exact, range, changed,
// unchanged, increased, decreased, unknown initial value).
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Scanner Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanCreate(
        IntPtr processHandle,
        out IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ScanDestroy(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanFirst(
        IntPtr scanHandle,
        IntPtr value,
        nuint valueSize,
        int valueType);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanNext(
        IntPtr scanHandle,
        IntPtr value,
        nuint valueSize,
        int compareType);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanGetResultCount(
        IntPtr scanHandle,
        out ulong count);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanGetResults(
        IntPtr scanHandle,
        ulong startIndex,
        [In, Out] ulong[] addresses,
        nuint maxResults,
        out nuint resultCount);

    #endregion

    #region Advanced Scanner Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanCreate(
        IntPtr processHandle,
        out IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_AdvScanDestroy(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanFirst(
        IntPtr scanHandle,
        ref NexusScanConfig config);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanNext(
        IntPtr scanHandle,
        ref NexusScanConfig config);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanGetResultCount(
        IntPtr scanHandle,
        out nuint count);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanGetResults(
        IntPtr scanHandle,
        ulong startIndex,
        [In, Out] NexusScanResultEntry[] results,
        nuint maxResults,
        out nuint resultCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanGetStats(
        IntPtr scanHandle,
        out NexusScanStats stats);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanUndo(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanCancel(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AdvScanRefreshValues(IntPtr scanHandle);

    #endregion

    #region Pointer Scanner Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanCreate(
        IntPtr processHandle,
        out IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_PointerScanDestroy(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanStart(
        IntPtr scanHandle,
        ref NexusPointerScanParams parameters);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_PointerScanCancel(IntPtr scanHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanGetProgress(
        IntPtr scanHandle,
        out NexusPointerScanProgress progress);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanGetResultCount(
        IntPtr scanHandle,
        out ulong count);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanGetResults(
        IntPtr scanHandle,
        ulong startIndex,
        [In, Out] NexusPointerPath[] results,
        nuint maxResults,
        out nuint resultCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PointerScanRescan(
        IntPtr scanHandle,
        ulong newTargetAddress);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PointerScanSave(
        IntPtr scanHandle,
        string path);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PointerScanLoad(
        IntPtr scanHandle,
        string path);

    #endregion
}
