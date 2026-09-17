// <file>
// <summary>
// P/Invoke bindings for value operations: parse string representations into typed values,
// format typed values for display, batch-read multiple addresses, and perform value
// comparisons. Centralizes value handling in the engine for consistency and performance.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Value Parsing & Formatting

    /// <summary>
    /// Parse a string value into a scan value.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ParseValue(
        string text,
        uint valueType,
        int isHex,
        out NexusScanValue result);

    /// <summary>
    /// Format a value as a display string.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FormatValue(
        IntPtr value,
        uint valueType,
        uint displayFlags,
        IntPtr buffer,
        nuint bufferSize);

    /// <summary>
    /// Get the byte size for a value type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern nuint Nexus_GetTypeSize(uint valueType);

    /// <summary>
    /// Calculate float tolerance for CE-compatible comparison.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CalculateFloatTolerance(
        string text,
        out double tolerance);

    #endregion

    #region Batch Operations

    /// <summary>
    /// Batch read values from multiple addresses.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BatchReadValues(
        IntPtr processHandle,
        [In] NexusBatchEntry[] entries,
        nuint count,
        [Out] NexusBatchReadResult[] results);

    /// <summary>
    /// Batch write frozen values.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BatchWriteFrozen(
        IntPtr processHandle,
        [In] NexusBatchEntry[] entries,
        nuint count,
        out nuint successCount);

    #endregion

    #region Helper Methods

    /// <summary>
    /// Get the size of a value type.
    /// </summary>
    public static int GetTypeSize(NexusScanValueType valueType)
    {
        return (int)Nexus_GetTypeSize((uint)valueType);
    }

    /// <summary>
    /// Parse a value string into a NexusScanValue.
    /// </summary>
    public static bool TryParseValue(string text, NexusScanValueType valueType, bool isHex, out NexusScanValue result)
    {
        return Nexus_ParseValue(text, (uint)valueType, isHex ? 1 : 0, out result) == NexusResult.OK;
    }

    /// <summary>
    /// Format a value for display.
    /// </summary>
    public static string FormatValue(byte[] value, NexusScanValueType valueType, NexusValueFormatFlags flags = NexusValueFormatFlags.Default)
    {
        if (value == null || value.Length == 0)
            return string.Empty;

        var buffer = new byte[256];
        var valueHandle = GCHandle.Alloc(value, GCHandleType.Pinned);
        var bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

        try
        {
            var result = Nexus_FormatValue(
                valueHandle.AddrOfPinnedObject(),
                (uint)valueType,
                (uint)flags,
                bufferHandle.AddrOfPinnedObject(),
                (nuint)buffer.Length);

            if (result == NexusResult.OK)
            {
                int length = Array.IndexOf(buffer, (byte)0);
                if (length < 0) length = buffer.Length;
                return System.Text.Encoding.ASCII.GetString(buffer, 0, length);
            }

            return string.Empty;
        }
        finally
        {
            valueHandle.Free();
            bufferHandle.Free();
        }
    }

    /// <summary>
    /// Calculate float tolerance based on decimal places in input.
    /// </summary>
    public static double CalculateFloatTolerance(string text)
    {
        if (Nexus_CalculateFloatTolerance(text, out double tolerance) == NexusResult.OK)
            return tolerance;
        return 0.0;
    }

    /// <summary>
    /// Resolve a pointer chain using the engine.
    /// </summary>
    public static ulong ResolvePointerChain(IntPtr processHandle, ulong baseAddress, long[] offsets)
    {
        if (offsets == null || offsets.Length == 0)
            return baseAddress;

        var result = Nexus_ResolvePointer(
            processHandle,
            baseAddress,
            offsets,
            (nuint)offsets.Length,
            out ulong resolvedAddress);

        return result == NexusResult.OK ? resolvedAddress : 0;
    }

    #endregion
}

/// <summary>
/// Value format flags for Nexus_FormatValue.
/// </summary>
[Flags]
public enum NexusValueFormatFlags : uint
{
    Default = 0,
    Hex = 0x0001,
    Signed = 0x0002,
    Unsigned = 0x0004,
    Scientific = 0x0008,
    Truncate = 0x0010
}

/// <summary>
/// Batch operation entry for Nexus_BatchReadValues/WriteFrozen.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusBatchEntry
{
    public ulong BaseAddress;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public long[] Offsets;
    public uint OffsetCount;
    public uint ValueType;
    public uint IsFrozen;
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] FrozenValue;

    public NexusBatchEntry()
    {
        BaseAddress = 0;
        Offsets = new long[16];
        OffsetCount = 0;
        ValueType = 0;
        IsFrozen = 0;
        Reserved = 0;
        FrozenValue = new byte[32];
    }
}

/// <summary>
/// Result entry for batch read.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusBatchReadResult
{
    public ulong ResolvedAddress;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] Value;
    public uint ValueSize;
    public int Success;

    public NexusBatchReadResult()
    {
        ResolvedAddress = 0;
        Value = new byte[32];
        ValueSize = 0;
        Success = 0;
    }
}
