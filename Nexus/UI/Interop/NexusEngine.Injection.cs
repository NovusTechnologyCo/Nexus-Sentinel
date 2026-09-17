// <file>
// <summary>
// P/Invoke bindings for code injection operations: DLL injection (LoadLibrary,
// LdrLoadDll, manual map), shellcode injection, and thread hijacking.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Injection Types

    [Flags]
    public enum NexusInjectFlags : uint
    {
        None = 0,
        Wait = 0x0001,               // Wait for injection to complete
        HideFromPeb = 0x0002,        // Unlink from PEB (manual map only)
        EraseHeaders = 0x0004,       // Erase PE headers after mapping
        NoTls = 0x0008,              // Skip TLS callbacks (manual map)
        Stealth = 0x0010,            // Use NtCreateThreadEx instead of CreateRemoteThread
        SkipAttach = 0x0020,         // Skip DLL_THREAD_ATTACH notifications (stealth)
        HideThread = 0x0040          // Hide thread from debugger (stealth)
    }

    public enum NexusInjectMethod : uint
    {
        LoadLibrary = 0,
        ManualMap = 1,
        ThreadHijack = 2,
        ApcQueue = 3,
        NtCreateThreadEx = 4
    }

    #endregion

    #region Injection Structures

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NexusInjectResult
    {
        public ulong ModuleBase;
        public ulong EntryPoint;
        public uint RemoteThreadId;
        public uint Success;
        public uint ErrorCode;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ErrorMessage;
    }

    #endregion

    #region DLL Injection

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_InjectDll(
        IntPtr process,
        string dllPath,
        uint flags,
        out NexusInjectResult result);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_InjectDllEx(
        IntPtr process,
        string dllPath,
        uint method,
        uint flags,
        uint timeout,
        out NexusInjectResult result);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_InjectDllManualMap(
        IntPtr process,
        string dllPath,
        uint flags,
        out NexusInjectResult result);

    #endregion

    #region Shellcode Injection

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_InjectShellcode(
        IntPtr process,
        IntPtr shellcode,
        nuint size,
        uint flags,
        out ulong executionAddress);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_InjectShellcodeEx(
        IntPtr process,
        IntPtr shellcode,
        nuint size,
        ulong parameter,
        uint flags,
        uint timeout,
        out ulong executionAddress,
        out ulong returnValue);

    #endregion

    #region Remote Function Calls

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallRemoteFunction(
        IntPtr process,
        ulong functionAddress,
        ulong parameter,
        uint timeout,
        out ulong returnValue);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CallRemoteFunctionEx(
        IntPtr process,
        ulong functionAddress,
        [In] ulong[]? parameters,
        nuint paramCount,
        uint callingConv,
        uint timeout,
        out ulong returnValue);

    #endregion

    #region Injection Cleanup

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FreeInjectedMemory(
        IntPtr process,
        ulong address);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EjectDll(
        IntPtr process,
        ulong moduleBase);

    #endregion

    #region Injection Helpers

    public static bool InjectDll(IntPtr process, string dllPath, out NexusInjectResult result)
    {
        return Nexus_InjectDll(process, dllPath, 0, out result) == NexusResult.OK && result.Success != 0;
    }

    public static bool InjectDllStealth(IntPtr process, string dllPath, out NexusInjectResult result)
    {
        var flags = (uint)(NexusInjectFlags.Stealth | NexusInjectFlags.HideFromPeb | NexusInjectFlags.EraseHeaders);
        return Nexus_InjectDll(process, dllPath, flags, out result) == NexusResult.OK && result.Success != 0;
    }

    #endregion
}
