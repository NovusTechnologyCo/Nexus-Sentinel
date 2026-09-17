// <file>
// <summary>
// P/Invoke bindings for extended dumper operations: Original Entry Point (OEP) detection,
// packer identification and signature matching, and automated unpacking support.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Dumper Types

    [Flags]
    public enum NexusDumpFlags : uint
    {
        None = 0,
        FixHeader = 0x0001,
        FixSections = 0x0002,
        FixImports = 0x0004,
        FixRelocations = 0x0008,
        RemoveOverlay = 0x0010,
        PreserveOverlay = 0x0020,
        UnmapFile = 0x0040,
        WipeHeader = 0x0080
    }

    public enum NexusOepFindMethod : uint
    {
        Auto = 0,
        TraceEntry = 1,
        ApiHook = 2,
        SectionJump = 3,
        MemoryBreakpoint = 4,
        HardwareBreakpoint = 5
    }

    public enum NexusUnpackerType : uint
    {
        Generic = 0,
        Upx = 1,
        Aspack = 2,
        PeCompact = 3,
        Themida = 4,
        VmProtect = 5
    }

    #endregion

    #region Dumper Structures

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NexusDumpInfo
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string OutputPath;
        public ulong BaseAddress;
        public ulong EntryPoint;
        public ulong ImageSize;
        public ulong FileSize;
        public uint SectionCount;
        public uint Flags;
        public uint WasRepaired;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct NexusOepSearchResult
    {
        public ulong OepAddress;
        public ulong OepRva;
        public uint Confidence;
        public uint Method;
        public ulong SearchTime;
        public uint InstructionsTraced;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string Signature;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NexusUnpackResult
    {
        public ulong OriginalBase;
        public ulong UnpackedBase;
        public ulong OriginalOep;
        public ulong RealOep;
        public ulong UnpackedSize;
        public uint PackerType;
        public uint Success;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string PackerName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string OutputPath;
    }

    #endregion

    #region Process Dumping

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpProcess(
        IntPtr handle,
        string outputPath,
        uint flags,
        out NexusDumpInfo info);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpModule(
        IntPtr handle,
        ulong moduleBase,
        string outputPath,
        uint flags,
        out NexusDumpInfo info);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpRegion(
        IntPtr handle,
        ulong startAddress,
        ulong size,
        string outputPath);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpToBuffer(
        IntPtr handle,
        ulong moduleBase,
        IntPtr buffer,
        nuint bufferSize,
        out nuint bytesWritten);

    #endregion

    #region OEP Finding

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FindOep(
        IntPtr debugger,
        uint method,
        uint timeout,
        out NexusOepSearchResult result);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FindOepByTrace(
        IntPtr debugger,
        uint maxInstructions,
        out NexusOepSearchResult result);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_FindOepByApiHook(
        IntPtr debugger,
        [In] string[] apiNames,
        nuint apiCount,
        out NexusOepSearchResult result);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CancelOepSearch(IntPtr debugger);

    #endregion

    #region Packer Detection & Unpacking

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DetectPacker(
        IntPtr handle,
        ulong moduleBase,
        out uint packerType,
        [Out] char[] packerName,
        nuint nameSize);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_Unpack(
        IntPtr debugger,
        ulong moduleBase,
        string outputPath,
        out NexusUnpackResult result);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_UnpackWith(
        IntPtr debugger,
        ulong moduleBase,
        uint unpackerType,
        string outputPath,
        out NexusUnpackResult result);

    #endregion

    #region Dump Repair

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RepairDump(string dumpPath, uint flags);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_FixDumpHeader(string dumpPath, ulong newEntryPoint);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RealignDumpSections(string dumpPath);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StripDumpOverlay(string dumpPath);

    #endregion

    #region Dumper Helpers

    public static string DetectPackerName(IntPtr handle, ulong moduleBase)
    {
        var name = new char[64];
        var result = Nexus_DetectPacker(handle, moduleBase, out _, name, 64);
        if (result != NexusResult.OK)
            return "Unknown";
        return new string(name).TrimEnd('\0');
    }

    #endregion
}
