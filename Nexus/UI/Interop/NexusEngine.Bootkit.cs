// <file>
// <summary>
// Bootkit communication layer providing managed wrappers for UEFI bootkit operations.
// Communicates with NexusBootDxe.efi via UEFI runtime variable backdoor (SetVariable).
// Replaces the standalone NexusDSEFix.exe utility with integrated managed code.
//
// Capabilities:
//   - DSE (Driver Signature Enforcement) enable/disable
//   - NexusMapper: manual map kernel drivers into pool memory
//   - Kernel caller registration for trusted IOCTL access
//   - SecureBoot spoof status monitoring
//   - HWID configuration read/write via mapper commands
//
// Split into partial class files:
//   - NexusEngine.Bootkit.cs        (this file: shared types, constants, P/Invoke, helpers)
//   - NexusEngine.Bootkit.Mapper.cs (mapper operations, driver load/unload, comm channels)
//   - NexusEngine.Bootkit.Monitor.cs(SecureBoot monitor, obfuscation API)
//   - NexusEngine.KernelModules.cs  (loaded-driver lookup, via NtQuerySystemInformation)
// </summary>
// </file>

using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    /// <summary>
    /// Last NTSTATUS returned by the mapper during driver load.
    /// Check this value after MapDriver returns LoadFailed for detailed error info.
    /// Common values:
    /// - 0xC000007A: STATUS_PROCEDURE_NOT_FOUND (import resolution failed)
    /// - 0xC0000135: STATUS_DLL_NOT_FOUND (module not found for imports)
    /// - 0xC000007B: STATUS_INVALID_IMAGE_FORMAT (PE validation failed)
    /// </summary>
    public static uint LastMapperStatus { get; private set; }

    #region Native API Imports

    private const string NtDll = "ntdll.dll";
    private const uint SE_SYSTEM_ENVIRONMENT_PRIVILEGE = 22;
    private const uint SE_DEBUG_PRIVILEGE = 20;

    [DllImport(NtDll)]
    private static extern int NtSetSystemEnvironmentValueEx(
        ref UNICODE_STRING VariableName,
        ref Guid VendorGuid,
        IntPtr Value,
        uint ValueLength,
        uint Attributes);

    [DllImport(NtDll)]
    private static extern int NtQuerySystemEnvironmentValueEx(
        ref UNICODE_STRING VariableName,
        ref Guid VendorGuid,
        IntPtr Value,
        ref uint ValueLength,
        IntPtr Attributes);

    [DllImport(NtDll)]
    private static extern int RtlAdjustPrivilege(
        uint Privilege,
        bool Enable,
        bool CurrentThread,
        out bool WasEnabled);

    [DllImport(NtDll)]
    private static extern int NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    private const uint SystemModuleInformation = 11;

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RTL_PROCESS_MODULE_INFORMATION
    {
        public IntPtr Section;
        public IntPtr MappedBase;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RTL_PROCESS_MODULES
    {
        public uint NumberOfModules;
        // Followed by RTL_PROCESS_MODULE_INFORMATION array
    }

    #endregion

    #region Protocol Constants and Structures

    /// <summary>
    /// Global Variable GUID used by the backdoor
    /// </summary>
    private static readonly Guid EfiGlobalVariableGuid = new("8BE4DF61-93CA-11D2-AA0D-00E098032B8C");

    /// <summary>
    /// NexusMapper GUID for mapper commands
    /// </summary>
    private static readonly Guid NexusMapperGuid = new("7B3E4C5A-1234-5678-9ABC-DEF012345678");


    /// <summary>
    /// Mapper variable name
    /// </summary>
    private const string MapperVariableName = "NexusCore";

    /// <summary>
    /// GetVariable monitor variable name (reversed "NexusGetVariable")
    /// </summary>
    private const string GetVariableMonitorName = "noMraVteGsuxeN";


    /// <summary>
    /// EFI variable attributes
    /// </summary>
    private const uint EFI_VARIABLE_NON_VOLATILE = 0x00000001;
    private const uint EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002;
    private const uint EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004;
    private const uint NexusVariableAttributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;


    /// <summary>
    /// Mapper initialization request
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct NEXUS_MAPPER_INIT_REQUEST
    {
        public uint Command;
        public ulong NtoskrnlBase;
    }

    /// <summary>
    /// Mapper status response
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MapperStatusResponse
    {
        public uint Status;
        public uint MapperState;
        public ulong MapperBase;
        public ulong MapperSize;
        public uint LoadedDriverCount;
    }

    /// <summary>
    /// Mapper command header
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_CMD_HEADER
    {
        public uint Magic;
        public uint Size;
        public uint Flags;
        public uint Reserved;
    }

    /// <summary>
    /// Register caller request
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_REGISTER_REQUEST
    {
        public MAPPER_CMD_HEADER Header;
        public ulong CallerToken;
        public ulong CallerBase;
    }

    /// <summary>
    /// Simple load driver request header (matches bootkit protocol)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct NEXUS_MAPPER_LOAD_REQUEST_HEADER
    {
        public uint Command;        // NEXUS_MAPPER_CMD_LOAD_DRIVER (0x10)
        public uint Flags;          // LOAD_FLAG_*
        public ulong ImageSize;     // Size of driver image
        // ImageData follows
    }

    /// <summary>
    /// Simple load driver response (matches bootkit protocol)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MapperLoadResponse
    {
        public uint Status;         // NEXUS_MAPPER_STATUS_*
        public ulong DriverBase;    // Base address of mapped driver
        public ulong DriverSize;    // Size of mapped driver
        public ulong EntryPoint;    // Entry point address
    }

    /// <summary>
    /// Legacy load driver request (header only, data follows) - for direct mapper communication
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_LOAD_REQUEST_HEADER
    {
        public MAPPER_CMD_HEADER Header;
        public ulong ImageSize;
        public ulong Reserved1;
        public ulong Reserved2;
    }

    /// <summary>
    /// Full mapper status (from QUERY_STATUS command)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MapperFullStatus
    {
        public uint Version;
        public uint LoadedDriverCount;
        public ulong TotalMappedSize;
        public byte Operational;
        public byte KernelCallerRegistered;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Reserved;
    }

    /// <summary>
    /// Unload driver request (must match MAPPER_UNLOAD_REQUEST in mapper.h)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_UNLOAD_REQUEST
    {
        public MAPPER_CMD_HEADER Header;
        public ulong DriverBase;    // Base address to unload
    }

    /// <summary>
    /// Query driver comm request
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_QUERY_COMM_REQUEST
    {
        public MAPPER_CMD_HEADER Header;
        public ulong DriverBase;    // Base address of driver to query (0 = last loaded)
    }

    /// <summary>
    /// Driver communication channel info response
    /// Must match MAPPER_QUERY_COMM_RESPONSE in mapper.h exactly
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverCommInfo
    {
        public int Status;              // NTSTATUS - 4 bytes
        public uint Version;            // Comm protocol version - 4 bytes
        public uint Flags;              // Comm channel flags - 4 bytes
        public ulong PhysicalAddress;   // Physical address of shared memory - 8 bytes
        public ulong Size;              // Size of shared memory region - 8 bytes
        public ulong SessionId;         // Session ID for validation - 8 bytes
        // Total: 36 bytes with Pack=1
    }

    /// <summary>
    /// Map comm channel request
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MAPPER_MAP_COMM_REQUEST
    {
        public MAPPER_CMD_HEADER Header;
        public ulong DriverBase;    // Base address of driver (0 = last loaded)
    }

    /// <summary>
    /// Map comm channel response
    /// Must match MAPPER_MAP_COMM_RESPONSE in mapper.h exactly
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MapCommResponse
    {
        public int Status;              // NTSTATUS - 4 bytes
        public ulong MappedAddress;     // User-mode virtual address - 8 bytes
        public ulong Size;              // Size of mapped region - 8 bytes
        // Total: 20 bytes with Pack=1
    }

    /// <summary>
    /// GetVariable monitor statistics.
    /// NexusDSEFix uses UINT32 Counts[2] = { TotalHitCount, RuntimeHitCount }
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GetVariableMonitorStats
    {
        public uint TotalHits;      // Total GetVariable calls for "SecureBoot"
        public uint RuntimeHits;    // Calls after Windows booted (runtime)
    }

    // Simple mapper command codes (used by bootkit's HandleMapperCommand)
    private const uint NEXUS_MAPPER_CMD_INIT = 0x00;
    private const uint NEXUS_MAPPER_CMD_QUERY = 0x01;
    private const uint NEXUS_MAPPER_CMD_LOAD_DRIVER = 0x10;
    private const uint NEXUS_MAPPER_CMD_UNLOAD_DRIVER = 0x11;

    // Legacy magic command codes (for direct mapper communication - not currently used)
    private const uint MAPPER_CMD_LOAD_DRIVER = 0x4C4F4144;      // 'LOAD'
    private const uint MAPPER_CMD_UNLOAD_DRIVER = 0x554E4C44;   // 'UNLD'
    private const uint MAPPER_CMD_QUERY_STATUS = 0x51555259;    // 'QURY'
    private const uint MAPPER_CMD_GET_VERSION = 0x56455253;     // 'VERS'
    private const uint MAPPER_CMD_REGISTER_CALLER = 0x52454743; // 'REGC'
    private const uint MAPPER_CMD_UNREGISTER_CALLER = 0x55524547; // 'UREG'
    private const uint MAPPER_CMD_QUERY_DRIVER_COMM = 0x434F4D4D; // 'COMM'
    private const uint MAPPER_CMD_MAP_COMM = 0x4D415043;          // 'MAPC'

    // Load flags (must match mapper.h values)
    private const uint LOAD_FLAG_FROM_BUFFER = 0x00000001;
    private const uint LOAD_FLAG_FROM_PATH = 0x00000002;
    private const uint LOAD_FLAG_ERASE_HEADER = 0x00000010;
    private const uint LOAD_FLAG_RANDOMIZE_TAG = 0x00000020;

    // Mapper state values (must match NEXUS_CORE_STATE_* in NexusBootProtocol.h)
    public const uint MAPPER_STATE_NOT_MAPPED = 0;
    public const uint MAPPER_STATE_MAPPED = 1;
    public const uint MAPPER_STATE_IMPORTS_RESOLVED = 2;
    public const uint MAPPER_STATE_INITIALIZED = 3;

    // Obfuscation constants
    private const uint NEXUS_OBFUSCATION_MAGIC = 0x4F424653;  // 'OBFS'
    public const int NEXUS_OBFUSCATION_KEY_SIZE = 32;
    private const uint NEXUS_COMM_MAGIC_BASE = 0x4E584D43;  // 'NXMC'
    public const uint NEXUS_COMM_FLAG_OBFUSCATED = 0x00000100;

    /// <summary>
    /// Obfuscation key request structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBFUSCATION_KEY_REQUEST
    {
        public uint Magic;      // NEXUS_OBFUSCATION_MAGIC
        public uint Reserved;
    }

    /// <summary>
    /// Obfuscation key response structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBFUSCATION_KEY_RESPONSE
    {
        public uint Status;     // 0 = success
        public uint KeySize;    // Size of key (32)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = NEXUS_OBFUSCATION_KEY_SIZE)]
        public byte[] Key;
        public ulong BootId;    // Unique boot session ID
    }

    /// <summary>
    /// Obfuscation key data (public)
    /// </summary>
    public class ObfuscationKey
    {
        public byte[] Key { get; set; } = new byte[NEXUS_OBFUSCATION_KEY_SIZE];
        public ulong BootId { get; set; }
        public bool Valid { get; set; }
    }

    #endregion

    #region Bootkit Result Enum

    public enum BootkitResult
    {
        Success = 0,
        AccessDenied = 1,
        HookNotInstalled = 2,
        VbsEnabled = 3,
        InvalidParameter = 4,
        NotInitialized = 5,
        AlreadyInitialized = 6,
        MapperNotReady = 7,
        LoadFailed = 8,
        PrivilegeError = 9,
        NtError = 10,
        NotSupported = 11,
        DriverError = 12
    }

    #endregion

    #region Privilege Helpers

    private static bool _privilegesAcquired = false;

    /// <summary>
    /// Acquires the required privileges for bootkit operations.
    /// </summary>
    public static BootkitResult AcquireBootkitPrivileges()
    {
        if (_privilegesAcquired)
            return BootkitResult.Success;

        try
        {
            // Check if running as administrator
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return BootkitResult.AccessDenied;
            }

            // Acquire SE_SYSTEM_ENVIRONMENT_PRIVILEGE
            int status = RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, true, false, out _);
            if (status != 0)
            {
                return BootkitResult.PrivilegeError;
            }

            // Acquire SE_DEBUG_PRIVILEGE
            status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, out _);
            if (status != 0)
            {
                return BootkitResult.PrivilegeError;
            }

            _privilegesAcquired = true;
            return BootkitResult.Success;
        }
        catch
        {
            return BootkitResult.PrivilegeError;
        }
    }

    #endregion

    #region SetVariable Helpers

    private static UNICODE_STRING CreateUnicodeString(string str)
    {
        var us = new UNICODE_STRING
        {
            Length = (ushort)(str.Length * 2),
            MaximumLength = (ushort)((str.Length + 1) * 2),
            Buffer = Marshal.StringToHGlobalUni(str)
        };
        return us;
    }

    private static void FreeUnicodeString(ref UNICODE_STRING us)
    {
        if (us.Buffer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(us.Buffer);
            us.Buffer = IntPtr.Zero;
        }
    }

    #endregion
}
