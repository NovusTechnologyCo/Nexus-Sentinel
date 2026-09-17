// <file>
// <summary>
// Primary P/Invoke bindings for the Nexus Engine native DLL (engine.dll).
// This file contains core initialization, process operations, and memory operations.
//
// The NexusEngine class is split across many partial class files for maintainability.
// Each file covers a distinct engine subsystem:
//   - NexusEngine.cs (this file)      : Initialization, Process, Memory, Utility
//   - NexusEngine.Scanner.cs          : Value scanner, advanced scanner, pointer scanner
//   - NexusEngine.Debug.cs            : Debugger attach/detach, thread context, stack walker
//   - NexusEngine.Breakpoint.cs       : Enhanced breakpoints (conditional, memory, hardware, DLL)
//   - NexusEngine.Analysis.cs         : Disassembler, symbols, CFG, structures, assembler
//   - NexusEngine.Misc.cs             : Table, kernel, ETW, speedhack, injection
//   - NexusEngine.PE.cs               : PE parsing, imports/exports, module info
//   - NexusEngine.Xref.cs             : Cross-reference scanning
//   - NexusEngine.Trace.cs            : Instruction tracing and run-to operations
//   - NexusEngine.Annotations.cs      : Labels, comments, bookmarks
//   - NexusEngine.Handles.cs          : Handle enumeration
//   - NexusEngine.Patches.cs          : Patch manager
//   - NexusEngine.AntiDebug.cs        : Anti-debug bypass
//   - NexusEngine.Watch.cs            : Watch expressions and symbol resolution
//   - NexusEngine.Exception.cs        : Exception configuration
//   - NexusEngine.Thread.cs           : Thread operations and naming
//   - NexusEngine.Pattern.cs          : Pattern detection (function prologue, etc.)
//   - NexusEngine.Script.cs           : Scripting engine and command system
//   - NexusEngine.Graph.cs            : Control flow graph and call graph analysis
//   - NexusEngine.Dumper.cs           : Process dumping and import reconstruction
//   - NexusEngine.DumperEx.cs         : Extended dumping with OEP detection
//   - NexusEngine.PeManip.cs          : PE section manipulation and validation
//   - NexusEngine.Relocation.cs       : Relocation table management
//   - NexusEngine.Resource.cs         : PE resource handling
//   - NexusEngine.Tls.cs              : TLS callback manipulation
//   - NexusEngine.Import.cs           : Import/export reconstruction
//   - NexusEngine.Hook.cs             : Hook detection and installation
//   - NexusEngine.Static.cs           : Static analysis (decrypt, decompress, hash)
//   - NexusEngine.Avx512.cs           : AVX-512 extended register context
//   - NexusEngine.Injection.cs        : DLL injection methods
//   - NexusEngine.Network.cs          : TCP/UDP connection enumeration (implicit via Misc)
//   - NexusEngine.WindowHeap.cs       : Window and heap enumeration
//   - NexusEngine.SourceMap.cs        : Source file and line mapping
//   - NexusEngine.PageProtect.cs      : Page protection manipulation
//   - NexusEngine.Bootkit.cs          : UEFI bootkit communication (DSE, mapper, HWID)
//   - NexusEngine.Value.cs            : Value formatting and display
//   - NexusEngine.MemoryEx.cs         : Extended memory operations
//   - NexusEngine.Process.cs          : Extended process operations
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

/// <summary>
/// P/Invoke declarations for the Nexus Engine native DLL (engine.dll).
/// <para>
/// This static partial class provides managed wrappers around the C-exported functions
/// in engine.dll. All functions use Cdecl calling convention. Process handles obtained
/// via <see cref="Nexus_OpenProcess"/> must be closed with <see cref="Nexus_CloseProcess"/>.
/// The engine must be initialized with <see cref="Nexus_Initialize"/> before any other calls.
/// </para>
/// </summary>
public static partial class NexusEngine
{
    private const string DllName = "engine.dll";
    private const CallingConvention CallConv = CallingConvention.Cdecl;

    #region Initialization

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Initialize();

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_Shutdown();

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_GetVersion(out int major, out int minor, out int patch);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern IntPtr Nexus_GetErrorString(NexusResult result);

    #endregion

    #region Process Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EnumerateProcesses(
        [In, Out] NexusProcessInfo[]? buffer,
        nuint bufferCount,
        out nuint processCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_OpenProcess(
        uint pid,
        out IntPtr handle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_OpenProcessEx(
        uint pid,
        NexusProcessAccess access,
        out IntPtr handle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetProcessAccess(
        IntPtr handle,
        out NexusProcessAccess access);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CloseProcess(IntPtr handle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetProcessInfo(
        IntPtr handle,
        out NexusProcessInfo info);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EnumerateModules(
        IntPtr handle,
        [In, Out] NexusModuleInfo[]? buffer,
        nuint bufferCount,
        out nuint moduleCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EnumerateMemoryRegions(
        IntPtr handle,
        [In, Out] NexusMemoryRegion[]? buffer,
        nuint bufferCount,
        out nuint regionCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_QueryMemory(
        IntPtr handle,
        ulong address,
        out NexusMemoryRegion region);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EnumerateThreads(
        IntPtr handle,
        [In, Out] NexusThreadInfo[]? buffer,
        nuint bufferCount,
        out nuint threadCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SuspendThread(uint threadId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResumeThread(uint threadId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TerminateThread(uint threadId, uint exitCode);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetThreadPriority(uint threadId, int priority);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetThreadPriority(uint threadId, out int priority);

    #endregion

    #region Memory Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ReadMemory(
        IntPtr handle,
        ulong address,
        IntPtr buffer,
        nuint size,
        out nuint bytesRead);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WriteMemory(
        IntPtr handle,
        ulong address,
        IntPtr buffer,
        nuint size,
        out nuint bytesWritten);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AllocateMemory(
        IntPtr handle,
        nuint size,
        uint protect,
        out ulong allocatedAddress);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FreeMemory(
        IntPtr handle,
        ulong address);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ProtectMemory(
        IntPtr handle,
        ulong address,
        nuint size,
        uint newProtect,
        out uint oldProtect);

    // Aliases for compatibility
    public static NexusResult Nexus_ReadProcessMemory(
        IntPtr handle, ulong address, byte[] buffer, nuint size, out nuint bytesRead)
    {
        var ptr = Marshal.AllocHGlobal((int)size);
        try
        {
            var result = Nexus_ReadMemory(handle, address, ptr, size, out bytesRead);
            if (result == NexusResult.OK || result == NexusResult.Success)
                Marshal.Copy(ptr, buffer, 0, (int)bytesRead);
            return result;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static NexusResult Nexus_ProtectProcessMemory(
        IntPtr handle, ulong address, nuint size, uint newProtect, out uint oldProtect)
        => Nexus_ProtectMemory(handle, address, size, newProtect, out oldProtect);

    #endregion

    #region Memory Map Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CaptureMemoryMap(
        IntPtr processHandle,
        uint flags,
        out IntPtr snapshotId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetSnapshotRegionCount(
        IntPtr snapshotId,
        out nuint count);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetSnapshotRegions(
        IntPtr snapshotId,
        nuint startIndex,
        [In, Out] NexusMemoryRegionEx[] regions,
        nuint bufferCount,
        out nuint regionsReturned);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ReleaseSnapshot(IntPtr snapshotId);

    #endregion

    #region Pointer Resolution

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResolvePointer(
        IntPtr handle,
        ulong baseAddress,
        [In] long[] offsets,
        nuint offsetCount,
        out ulong resultAddress);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResolvePointerAndRead(
        IntPtr handle,
        ulong baseAddress,
        [In] long[] offsets,
        nuint offsetCount,
        IntPtr buffer,
        nuint size,
        out nuint bytesRead);

    #endregion

    #region Utility

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_Free(IntPtr ptr);

    #endregion

    #region Script Helper Methods

    public static byte ReadByte(IntPtr processHandle, ulong address)
    {
        byte value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 1, out _); }
        return value;
    }

    public static short ReadInt16(IntPtr processHandle, ulong address)
    {
        short value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 2, out _); }
        return value;
    }

    public static int ReadInt32(IntPtr processHandle, ulong address)
    {
        int value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 4, out _); }
        return value;
    }

    public static long ReadInt64(IntPtr processHandle, ulong address)
    {
        long value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 8, out _); }
        return value;
    }

    public static float ReadFloat(IntPtr processHandle, ulong address)
    {
        float value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 4, out _); }
        return value;
    }

    public static double ReadDouble(IntPtr processHandle, ulong address)
    {
        double value = 0;
        unsafe { Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), 8, out _); }
        return value;
    }

    public static string ReadString(IntPtr processHandle, ulong address, int maxLength = 256)
    {
        var buffer = new byte[maxLength];
        var ptr = Marshal.AllocHGlobal(maxLength);
        try
        {
            Nexus_ReadMemory(processHandle, address, ptr, (nuint)maxLength, out var bytesRead);
            Marshal.Copy(ptr, buffer, 0, (int)bytesRead);
            int length = 0;
            while (length < (int)bytesRead && buffer[length] != 0) length++;
            return System.Text.Encoding.UTF8.GetString(buffer, 0, length);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static byte[] ReadBytes(IntPtr processHandle, ulong address, int count)
    {
        var buffer = new byte[count];
        var ptr = Marshal.AllocHGlobal(count);
        try
        {
            Nexus_ReadMemory(processHandle, address, ptr, (nuint)count, out var bytesRead);
            Marshal.Copy(ptr, buffer, 0, (int)bytesRead);
            return buffer;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static bool WriteByte(IntPtr processHandle, ulong address, byte value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 1, out _) == NexusResult.OK; }
    }

    public static bool WriteInt16(IntPtr processHandle, ulong address, short value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 2, out _) == NexusResult.OK; }
    }

    public static bool WriteInt32(IntPtr processHandle, ulong address, int value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 4, out _) == NexusResult.OK; }
    }

    public static bool WriteInt64(IntPtr processHandle, ulong address, long value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 8, out _) == NexusResult.OK; }
    }

    public static bool WriteFloat(IntPtr processHandle, ulong address, float value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 4, out _) == NexusResult.OK; }
    }

    public static bool WriteDouble(IntPtr processHandle, ulong address, double value)
    {
        unsafe { return Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), 8, out _) == NexusResult.OK; }
    }

    public static bool WriteBytes(IntPtr processHandle, ulong address, byte[] data)
    {
        var ptr = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, ptr, data.Length);
            return Nexus_WriteMemory(processHandle, address, ptr, (nuint)data.Length, out _) == NexusResult.OK;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    #endregion
}

/// <summary>
/// x64 CONTEXT structure for thread context operations.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT64
{
    public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    public uint ContextFlags;
    public uint MxCsr;
    public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    public uint EFlags;
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    public ulong R8, R9, R10, R11, R12, R13, R14, R15;
    public ulong Rip;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] FltSave;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
    public M128A[] VectorRegister;
    public ulong VectorControl;
    public ulong DebugControl;
    public ulong LastBranchToRip, LastBranchFromRip;
    public ulong LastExceptionToRip, LastExceptionFromRip;
}

[StructLayout(LayoutKind.Sequential)]
public struct M128A
{
    public ulong Low;
    public long High;
}

/// <summary>
/// Helper methods for working with the Nexus Engine.
/// </summary>
public static class NexusHelper
{
    public static string GetErrorMessage(NexusResult result)
    {
        var ptr = NexusEngine.Nexus_GetErrorString(result);
        return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
    }

    public static string GetVersionString()
    {
        NexusEngine.Nexus_GetVersion(out int major, out int minor, out int patch);
        return $"{major}.{minor}.{patch}";
    }

    public static NexusProcessInfo[] EnumerateProcesses()
    {
        NexusEngine.Nexus_EnumerateProcesses(null, 0, out nuint count);
        if (count == 0) return [];
        var processes = new NexusProcessInfo[count];
        NexusEngine.Nexus_EnumerateProcesses(processes, count, out _);
        return processes;
    }

    public static T? ReadMemory<T>(IntPtr processHandle, ulong address) where T : unmanaged
    {
        unsafe
        {
            T value = default;
            var result = NexusEngine.Nexus_ReadMemory(processHandle, address, (IntPtr)(&value), (nuint)sizeof(T), out _);
            return result == NexusResult.OK ? value : null;
        }
    }

    public static bool WriteMemory<T>(IntPtr processHandle, ulong address, T value) where T : unmanaged
    {
        unsafe
        {
            return NexusEngine.Nexus_WriteMemory(processHandle, address, (IntPtr)(&value), (nuint)sizeof(T), out _) == NexusResult.OK;
        }
    }

    public static void Nexus_SuspendProcess(IntPtr processHandle)
    {
        NexusEngine.Nexus_EnumerateThreads(processHandle, null, 0, out nuint count);
        if (count == 0) return;
        var threads = new NexusThreadInfo[count];
        NexusEngine.Nexus_EnumerateThreads(processHandle, threads, count, out _);
        foreach (var thread in threads)
            NexusEngine.Nexus_SuspendThread(thread.ThreadId);
    }

    public static void Nexus_ResumeProcess(IntPtr processHandle)
    {
        NexusEngine.Nexus_EnumerateThreads(processHandle, null, 0, out nuint count);
        if (count == 0) return;
        var threads = new NexusThreadInfo[count];
        NexusEngine.Nexus_EnumerateThreads(processHandle, threads, count, out _);
        foreach (var thread in threads)
            NexusEngine.Nexus_ResumeThread(thread.ThreadId);
    }
}
