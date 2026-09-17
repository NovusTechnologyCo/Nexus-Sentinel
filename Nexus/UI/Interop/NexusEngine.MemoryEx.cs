// <file>
// <summary>
// P/Invoke bindings for extended memory operations: memory caching for fast repeated reads,
// typed read/write helpers (ReadInt32, WriteFloat, etc.), memory fill, allocate-near for
// code caves, and dump memory regions to byte arrays.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Memory Cache (3x+ performance for repeated lookups)

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemCacheCreate(
        IntPtr processHandle,
        out IntPtr cache);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_MemCacheDestroy(IntPtr cache);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemCacheRefresh(IntPtr cache);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemCacheQuery(
        IntPtr cache,
        ulong address,
        out NexusMemoryRegionEx region);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemCacheGetAll(
        IntPtr cache,
        [In, Out] NexusMemoryRegionEx[]? regions,
        nuint maxRegions,
        out nuint regionCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_MemCacheInvalidate(
        IntPtr cache,
        ulong address,
        nuint size);

    #endregion

    #region Safe Memory Write

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteMemoryProtected(
        IntPtr handle,
        ulong address,
        IntPtr buffer,
        nuint size,
        out nuint bytesWritten);

    public static bool WriteMemoryProtected(IntPtr handle, ulong address, byte[] data)
    {
        var ptr = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, ptr, data.Length);
            return Nexus_WriteMemoryProtected(handle, address, ptr, (nuint)data.Length, out _) == NexusResult.OK;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    #endregion

    #region Near Allocation (for hooks/trampolines)

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AllocateNear(
        IntPtr handle,
        ulong nearAddress,
        nuint size,
        uint protection,
        out ulong allocatedAddress);

    #endregion

    #region Typed Memory Read Helpers

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadU8(IntPtr handle, ulong address, out byte value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadU16(IntPtr handle, ulong address, out ushort value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadU32(IntPtr handle, ulong address, out uint value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadU64(IntPtr handle, ulong address, out ulong value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadF32(IntPtr handle, ulong address, out float value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadF64(IntPtr handle, ulong address, out double value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadPointer(IntPtr handle, ulong address, out ulong value);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ReadCString(
        IntPtr handle,
        ulong address,
        [Out] byte[] buffer,
        nuint bufferSize,
        out nuint charsRead);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ReadWString(
        IntPtr handle,
        ulong address,
        [Out] char[] buffer,
        nuint bufferSize,
        out nuint charsRead);

    #endregion

    #region Typed Memory Write Helpers

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteU8(IntPtr handle, ulong address, byte value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteU16(IntPtr handle, ulong address, ushort value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteU32(IntPtr handle, ulong address, uint value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteU64(IntPtr handle, ulong address, ulong value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteF32(IntPtr handle, ulong address, float value);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteF64(IntPtr handle, ulong address, double value);

    #endregion

    // Note: Nexus_FillMemory, Nexus_DumpMemoryRegion, and Nexus_ResolveAddressExpression
    // are defined in NexusEngine.PE.cs

    #region Mapped File Name

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_GetMappedFileName(
        IntPtr handle,
        ulong address,
        [Out] char[] fileName,
        nuint fileNameSize);

    #endregion
}
