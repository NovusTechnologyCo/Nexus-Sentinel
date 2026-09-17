// <file>
// <summary>
// Kernel APC injection wrapper. Sends MAPPER_CMD_INJECT_DLL ('INJD') to NexusCore
// via the SetVariable backdoor (NtSetSystemEnvironmentValueEx). NexusCore opens
// a kernel handle to the target (OBJ_KERNEL_HANDLE bypasses ObCallbacks), allocates
// a shellcode page, resolves LdrLoadDll from the target's ntdll, and queues a
// user-mode APC. Requires no Win32 process handle on the host side, so it works
// against EAC-protected processes that block PROCESS_VM_OPERATION / CREATE_THREAD.
//
// Mirrors the protocol used by NexusDSEFix.exe --inject-dll (cmd_inject.cpp).
// </summary>
// </file>

using System.Runtime.InteropServices;
using System.Text;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region INJD Protocol

    private const uint MAPPER_CMD_INJECT_DLL_MAGIC = 0x494E4A44;  // 'INJD'
    private const int INJECT_DLL_PATH_MAX_L = 260;
    private const string InjectVariableName = "NexusCoreHwidQuery";

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct INJECT_REQUEST_L
    {
        public uint Magic;        // 'INJD'
        public uint Size;         // Total buffer size
        public ulong TargetPid;   // Target PID (0 = auto-find GameService.exe)
        // Followed by WCHAR DllPath[INJECT_DLL_PATH_MAX_L]
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct INJECT_RESPONSE_L
    {
        public int Status;        // NTSTATUS
        public uint TargetPid;
        public ulong ShellcodeVa;
        public ulong LdrLoadDllVa;
        public uint ApcQueued;
        public uint ThreadId;
    }

    #endregion

    /// <summary>
    /// Result of a kernel APC injection attempt.
    /// </summary>
    public struct KernelInjectResult
    {
        public int NtStatus;
        public uint TargetPid;
        public ulong ShellcodeVa;
        public ulong LdrLoadDllVa;
        public bool ApcQueued;
        public uint ThreadId;

        public bool Success => NtStatus == 0 && ApcQueued;
    }

    /// <summary>
    /// Injects a DLL into the target process via NexusCore kernel APC.
    /// Bypasses EAC's user-mode injection blocks because NexusCore opens its own
    /// kernel handle (OBJ_KERNEL_HANDLE → ObCallbacks skipped) and queues the APC
    /// from kernel mode. The DLL loads on the next alertable wait in the target.
    /// </summary>
    /// <param name="targetPid">Target process ID. Pass 0 to let NexusCore auto-find
    /// EAAntiCheat.GameService.exe by name.</param>
    /// <param name="dllPath">Full Win32 path to the DLL (NexusCore converts to NT path).</param>
    /// <param name="result">Detailed status fields from the kernel response.</param>
    /// <returns>BootkitResult.Success when the APC was queued; other codes for
    /// privilege/mapper-state failures.</returns>
    public static BootkitResult InjectDllViaKernelApc(uint targetPid, string dllPath, out KernelInjectResult result)
    {
        result = default;

        var priv = AcquireBootkitPrivileges();
        if (priv != BootkitResult.Success)
            return priv;

        // Build a single contiguous buffer matching the C struct + path tail
        // (request and response share the same buffer; SetVariable reuses it).
        const int reqHeaderSize = 4 + 4 + 8;                       // Magic + Size + TargetPid
        int pathBytes = INJECT_DLL_PATH_MAX_L * 2;                 // WCHAR[260]
        int totalSize = reqHeaderSize + pathBytes;

        IntPtr buffer = Marshal.AllocHGlobal(totalSize);
        try
        {
            // Zero
            for (int i = 0; i < totalSize; i++)
                Marshal.WriteByte(buffer, i, 0);

            // Header
            Marshal.WriteInt32(buffer, 0, (int)MAPPER_CMD_INJECT_DLL_MAGIC);
            Marshal.WriteInt32(buffer, 4, totalSize);
            Marshal.WriteInt64(buffer, 8, (long)(ulong)targetPid);

            // DllPath as null-terminated WCHARs (clamped to MAX-1)
            int charCap = INJECT_DLL_PATH_MAX_L - 1;
            string clamped = dllPath.Length > charCap ? dllPath.Substring(0, charCap) : dllPath;
            byte[] pathUtf16 = Encoding.Unicode.GetBytes(clamped);
            Marshal.Copy(pathUtf16, 0, buffer + reqHeaderSize, pathUtf16.Length);
            // Null-terminator already zeroed above

            // SetVariable (kernel reuses the buffer for the response)
            UNICODE_STRING varName = CreateUnicodeString(InjectVariableName);
            try
            {
                var guid = NexusMapperGuid;
                int status = NtSetSystemEnvironmentValueEx(
                    ref varName,
                    ref guid,
                    buffer,
                    (uint)totalSize,
                    NexusVariableAttributes);

                if (status != 0)
                {
                    result.NtStatus = status;
                    return BootkitResult.NtError;
                }
            }
            finally
            {
                FreeUnicodeString(ref varName);
            }

            // Read response (overlaid on the same buffer)
            result.NtStatus = Marshal.ReadInt32(buffer, 0);
            result.TargetPid = (uint)Marshal.ReadInt32(buffer, 4);
            result.ShellcodeVa = (ulong)Marshal.ReadInt64(buffer, 8);
            result.LdrLoadDllVa = (ulong)Marshal.ReadInt64(buffer, 16);
            result.ApcQueued = Marshal.ReadInt32(buffer, 24) != 0;
            result.ThreadId = (uint)Marshal.ReadInt32(buffer, 28);

            return result.Success ? BootkitResult.Success : BootkitResult.DriverError;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
