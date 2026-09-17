// <file>
// <summary>
// Encrypted shared memory communication channel between user mode and NexusKernel.sys.
// Provides secure request/response communication using AES-encrypted shared memory regions.
// Supports three discovery methods for finding the kernel-side shared memory:
//   - Via IOCTL (when driver is loaded normally with a device object)
//   - Via mapper protocol (when driver is manually mapped without a device object)
//   - Via physical memory scan (fallback for when no other method is available)
//
// Split across partial class files:
//   NexusComm.cs              - Constants, structures, P/Invoke, fields, properties, IDisposable
//   NexusComm.Connection.cs   - Connection management (IOCTL, mapper, physical memory mapping)
//   NexusComm.Communication.cs - Ring buffer protocol, SendCommand, marshalling helpers
// </summary>
// </file>

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Cryptography;

namespace Nexus.UI.Interop;

/// <summary>
/// Encrypted shared memory communication client for NexusKernel.sys.
/// <para>
/// Establishes a shared memory region with the kernel driver and exchanges AES-encrypted
/// request/response messages. Used as the transport layer for kernel provider operations
/// when the driver is loaded via the bootkit mapper (no device object available for IOCTL).
/// </para>
/// </summary>
public sealed partial class NexusComm : IDisposable
{
    #region Constants

    private const uint NEXUS_COMM_MAGIC_BASE = 0x4E584D43;  // 'NXMC' - base magic (never stored directly when obfuscated)
    private const uint NEXUS_COMM_VERSION = 0x00010000;

    private const int NEXUS_COMM_REQUEST_SIZE = 64 * 1024;
    private const int NEXUS_COMM_RESPONSE_SIZE = 64 * 1024;
    private const int NEXUS_COMM_EVENT_SIZE = 256 * 1024;

    private const int NEXUS_COMM_KEY_SIZE = 32;
    private const int NEXUS_COMM_NONCE_SIZE = 24;
    private const int NEXUS_COMM_TAG_SIZE = 16;
    private const int NEXUS_COMM_MAX_MSG_SIZE = 32 * 1024;

    // Flags
    private const uint NEXUS_COMM_FLAG_INITIALIZED = 0x00000001;
    private const uint NEXUS_COMM_FLAG_ENCRYPTED = 0x00000002;
    private const uint NEXUS_COMM_FLAG_VALIDATED = 0x00000004;
    private const uint NEXUS_COMM_FLAG_KERNEL_READY = 0x00000008;
    private const uint NEXUS_COMM_FLAG_USER_READY = 0x00000010;
    private const uint NEXUS_COMM_FLAG_OBFUSCATED = 0x00000100;

    // Command codes
    public const uint CMD_PING = 0x0000;
    public const uint CMD_GET_VERSION = 0x0001;
    public const uint CMD_READ_MEMORY = 0x0220;
    public const uint CMD_WRITE_MEMORY = 0x0221;
    public const uint CMD_ENUM_PROCESSES = 0x0113;
    public const uint CMD_ENUM_MODULES = 0x0114;
    public const uint CMD_OPEN_PROCESS = 0x0110;
    public const uint CMD_ALLOC_MEMORY = 0x0225;
    public const uint CMD_FREE_MEMORY = 0x0226;
    public const uint CMD_PROTECT_MEMORY = 0x0227;
    public const uint CMD_QUERY_MEMORY = 0x0228;

    #endregion

    #region Native Structures

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct RingBufferHeader
    {
        public uint WriteIndex;
        public uint ReadIndex;
        public uint Size;
        public uint MessageCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct MsgHeader
    {
        public uint Magic;
        public uint Command;
        public uint Sequence;
        public uint DataSize;
        public uint Status;
        public uint Flags;
        public ulong Timestamp;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct CryptoState
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = NEXUS_COMM_KEY_SIZE)]
        public byte[] Key;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = NEXUS_COMM_KEY_SIZE)]
        public byte[] AuthKey;
        public ulong TxNonce;
        public ulong RxNonce;
        public ulong SessionId;
        public uint Flags;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct ClientInfo
    {
        public uint ProcessId;
        public uint ThreadId;
        public ulong ImageBase;
        public ulong ImageSize;
        public ulong ExpectedReturnRangeStart;
        public ulong ExpectedReturnRangeEnd;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ProcessHash;
        public ulong ValidationTime;
        public uint ValidationFlags;
        public uint Reserved;
    }

    #endregion

    #region P/Invoke

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess,
        uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern int NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        UIntPtr ZeroBits,
        UIntPtr CommitSize,
        ref long SectionOffset,
        ref UIntPtr ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect);

    [DllImport("ntdll.dll")]
    private static extern int NtOpenSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    private static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    private const uint FILE_MAP_ALL_ACCESS = 0xF001F;
    private const uint FILE_MAP_READ = 0x0004;
    private const uint FILE_MAP_WRITE = 0x0002;
    private const uint SECTION_ALL_ACCESS = 0xF001F;
    private const uint SECTION_MAP_READ = 0x0004;
    private const uint SECTION_MAP_WRITE = 0x0002;
    private const uint PAGE_READWRITE = 0x04;

    #endregion

    #region Fields

    private IntPtr _mappedMemory = IntPtr.Zero;
    private IntPtr _sectionHandle = IntPtr.Zero;
    private int _sharedMemorySize;
    private uint _sequenceNumber;
    private readonly object _lock = new();
    private bool _disposed;
    private bool _encryptionEnabled;
    private bool _mappedViaIoctl;
    private bool _mappedViaPhysical;

    // Obfuscation support
    private NexusEngine.ObfuscationKey? _obfuscationKey;
    private uint _obfuscatedMagic;
    private bool _obfuscationEnabled;

    // Cached offsets into shared memory
    private int _requestRingOffset;
    private int _responseRingOffset;
    private int _eventRingOffset;
    private int _requestBufferOffset;
    private int _responseBufferOffset;
    private int _eventBufferOffset;

    #endregion

    #region Properties

    /// <summary>
    /// Whether the communication channel is connected
    /// </summary>
    public bool IsConnected => _mappedMemory != IntPtr.Zero;

    /// <summary>
    /// Whether encryption is enabled
    /// </summary>
    public bool EncryptionEnabled
    {
        get => _encryptionEnabled;
        set
        {
            _encryptionEnabled = value;
            if (IsConnected)
            {
                UpdateFlags();
            }
        }
    }

    /// <summary>
    /// Session ID from kernel
    /// </summary>
    public ulong SessionId { get; private set; }

    /// <summary>
    /// Whether pre-boot obfuscation is active
    /// </summary>
    public bool ObfuscationEnabled => _obfuscationEnabled;

    /// <summary>
    /// Boot ID from the obfuscation key (unique per boot session)
    /// </summary>
    public ulong BootId => _obfuscationKey?.BootId ?? 0;

    #endregion

    #region IDisposable

    public void Dispose()
    {
        if (_disposed)
            return;

        Disconnect();
        _disposed = true;
    }

    #endregion
}

/// <summary>
/// Extension methods for NexusEngine to support shared memory communication
/// </summary>
public static partial class NexusEngine
{
    private static NexusComm? _commChannel;
    private static readonly object _commLock = new();

    /// <summary>
    /// Get or create the shared memory communication channel
    /// </summary>
    public static NexusComm GetCommChannel()
    {
        lock (_commLock)
        {
            if (_commChannel == null || !_commChannel.IsConnected)
            {
                _commChannel?.Dispose();
                _commChannel = new NexusComm();
                _commChannel.Connect();
            }
            return _commChannel;
        }
    }

    /// <summary>
    /// Check if shared memory communication is available
    /// </summary>
    public static bool IsCommChannelAvailable()
    {
        try
        {
            var comm = GetCommChannel();
            return comm.IsConnected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Map the comm channel shared memory into the calling process.
    /// Uses IOCTL to ask driver to map memory via MDL.
    /// </summary>
    internal static NexusEngine.BootkitResult MapCommChannel(out IntPtr mappedAddress, out ulong size)
    {
        mappedAddress = IntPtr.Zero;
        size = 0;

        try
        {
            // Use NexusKernelDriver to map comm channel
            var driver = Nexus.UI.Providers.NexusKernelDriver.Instance;
            if (!driver.IsLoaded)
                return NexusEngine.BootkitResult.NotSupported;

            bool success = driver.MapCommChannel(out mappedAddress, out size);
            return success ? NexusEngine.BootkitResult.Success : NexusEngine.BootkitResult.DriverError;
        }
        catch
        {
            return NexusEngine.BootkitResult.NotSupported;
        }
    }

    /// <summary>
    /// Unmap previously mapped comm channel memory.
    /// </summary>
    internal static void UnmapCommChannel(IntPtr mappedAddress)
    {
        try
        {
            var driver = Nexus.UI.Providers.NexusKernelDriver.Instance;
            if (driver.IsLoaded)
            {
                driver.UnmapCommChannel(mappedAddress);
            }
        }
        catch { }
    }

    /// <summary>
    /// Query mapper for comm channel physical address (for mapped driver mode).
    /// </summary>
    internal static NexusEngine.BootkitResult QueryMappedDriverComm(out ulong physicalAddress, out ulong size)
    {
        physicalAddress = 0;
        size = 0;

        try
        {
            // Query bootkit mapper for NexusKernel's comm info
            // This uses the mapper protocol via SetVariable
            var result = NexusEngine.QueryDriverCommInfo(out var info);
            if (result != NexusEngine.BootkitResult.Success)
                return result;

            physicalAddress = info.PhysicalAddress;
            size = info.Size;
            return NexusEngine.BootkitResult.Success;
        }
        catch
        {
            return NexusEngine.BootkitResult.NotSupported;
        }
    }
}
