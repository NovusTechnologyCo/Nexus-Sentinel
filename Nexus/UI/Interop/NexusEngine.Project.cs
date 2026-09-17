// <file>
// <summary>
// P/Invoke bindings for project management: save and load address lists, annotations,
// breakpoints, and scan state to/from project files for session persistence.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Project Types

    public enum NexusAddressValueType : int
    {
        Int8 = 0,
        Int16 = 1,
        Int32 = 2,
        Int64 = 3,
        Float32 = 4,
        Float64 = 5,
        String = 6,
        Aob = 7,
        Pointer = 8
    }

    [Flags]
    public enum NexusAddressFlags : uint
    {
        None = 0,
        Frozen = 0x0001,
        Hidden = 0x0002,
        ReadOnly = 0x0004,
        IsPointer = 0x0008
    }

    #endregion

    #region Project Structures

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct NexusAddressEntry
    {
        [FieldOffset(0)] public ulong Id;
        [FieldOffset(8)] public ulong Address;
        [FieldOffset(16)] public NexusAddressValueType ValueType;
        [FieldOffset(20)] public uint Flags;
        [FieldOffset(24), MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        [FieldOffset(536), MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string GroupName;
        [FieldOffset(664), MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public long[] Offsets;
        [FieldOffset(792)] public uint OffsetCount;
        [FieldOffset(800)] public long CurrentIntValue;
        [FieldOffset(800)] public double CurrentFloatValue;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NexusProjectInfo
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string TargetProcess;
        public uint TargetPid;
        public uint SchemaVersion;
        public ulong AddressCount;
        public ulong CreatedTime;
        public ulong ModifiedTime;
    }

    #endregion

    #region Project Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectCreate(out IntPtr project);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ProjectDestroy(IntPtr project);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ProjectLoad(
        string path,
        out IntPtr project);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ProjectSave(
        IntPtr project,
        string path);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectGetInfo(
        IntPtr project,
        out NexusProjectInfo info);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ProjectSetName(
        IntPtr project,
        string name);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ProjectSetTargetProcess(
        IntPtr project,
        string processName);

    #endregion

    #region Address List Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectAddAddress(
        IntPtr project,
        ref NexusAddressEntry entry,
        out ulong id);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectRemoveAddress(
        IntPtr project,
        ulong id);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectUpdateAddress(
        IntPtr project,
        ref NexusAddressEntry entry);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectGetAddress(
        IntPtr project,
        ulong id,
        out NexusAddressEntry entry);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectGetAddressCount(
        IntPtr project,
        out ulong count);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectGetAddresses(
        IntPtr project,
        ulong startIndex,
        [In, Out] NexusAddressEntry[]? buffer,
        nuint bufferCount,
        out nuint entriesReturned);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectRefreshValues(
        IntPtr project,
        IntPtr process);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProjectClearAddresses(IntPtr project);

    #endregion
}
