// NexusComm.Connection.cs - Connection management (IOCTL, mapper, physical memory mapping)

using System;
using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public sealed partial class NexusComm
{
    #region Connection

    /// <summary>
    /// Connect to the kernel driver via shared memory.
    /// Tries multiple discovery methods.
    /// </summary>
    public bool Connect()
    {
        if (IsConnected)
            return true;

        // First, try to retrieve obfuscation key from bootkit
        // This tells us what magic value to expect in shared memory
        var keyResult = NexusEngine.GetObfuscationKey(out var key);
        if (keyResult == NexusEngine.BootkitResult.Success && key.Valid)
        {
            _obfuscationKey = key;
            _obfuscatedMagic = NexusEngine.GetObfuscatedMagic(key);
            _obfuscationEnabled = true;
        }
        else
        {
            // Fallback to base magic (bootkit not installed or key not available)
            _obfuscationKey = null;
            _obfuscatedMagic = NEXUS_COMM_MAGIC_BASE;
            _obfuscationEnabled = false;
        }

        // Method 1: Try via IOCTL to map shared memory (driver loaded normally)
        if (TryConnectViaIoctl())
            return true;

        // Method 2: Try via mapper protocol (driver manually mapped)
        if (TryConnectViaMapper())
            return true;

        return false;
    }

    private bool TryConnectViaIoctl()
    {
        try
        {
            // Ask driver to map shared memory into our process via IOCTL
            // This requires the driver to be loaded normally with device object
            var result = NexusEngine.MapCommChannel(out var mappedAddress, out var size);
            if (result != NexusEngine.BootkitResult.Success)
                return false;

            _mappedMemory = mappedAddress;
            _sharedMemorySize = (int)size;
            _mappedViaIoctl = true;

            return InitializeConnection();
        }
        catch
        {
            return false;
        }
    }

    private bool TryConnectViaMapper()
    {
        try
        {
            // Use the mapper's MAP_COMM command to map shared memory via kernel MDL
            // This is more reliable than trying to map physical memory directly
            var result = NexusEngine.MapDriverCommChannel(out var mappedAddress, out var size);
            if (result != NexusEngine.BootkitResult.Success || mappedAddress == IntPtr.Zero)
            {
                // Fallback: try physical memory mapping (less reliable)
                var queryResult = NexusEngine.QueryMappedDriverComm(out var physicalAddress, out var physSize);
                if (queryResult != NexusEngine.BootkitResult.Success)
                    return false;

                return MapPhysicalMemory(physicalAddress, (int)physSize);
            }

            _mappedMemory = mappedAddress;
            _sharedMemorySize = (int)size;
            _mappedViaIoctl = false;  // Mapped via mapper, not IOCTL

            return InitializeConnection();
        }
        catch
        {
            return false;
        }
    }

    private bool MapPhysicalMemory(ulong physicalAddress, int size)
    {
        // Map physical memory using NtMapViewOfSection with \Device\PhysicalMemory
        // This requires elevated privileges

        IntPtr sectionHandle = IntPtr.Zero;
        try
        {
            // Open \Device\PhysicalMemory
            var objectName = new UNICODE_STRING();
            RtlInitUnicodeString(ref objectName, "\\Device\\PhysicalMemory");

            var objAttr = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                RootDirectory = IntPtr.Zero,
                ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>()),
                Attributes = 0x40, // OBJ_CASE_INSENSITIVE
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            Marshal.StructureToPtr(objectName, objAttr.ObjectName, false);

            int status = NtOpenSection(out sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, ref objAttr);
            Marshal.FreeHGlobal(objAttr.ObjectName);

            if (status != 0)
                return false;

            // Map the physical address
            IntPtr baseAddress = IntPtr.Zero;
            long sectionOffset = (long)physicalAddress;
            UIntPtr viewSize = (UIntPtr)size;

            status = NtMapViewOfSection(
                sectionHandle,
                GetCurrentProcess(),
                ref baseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref viewSize,
                2, // ViewUnmap
                0,
                PAGE_READWRITE);

            if (status != 0)
            {
                CloseHandle(sectionHandle);
                return false;
            }

            _sectionHandle = sectionHandle;
            _mappedMemory = baseAddress;
            _sharedMemorySize = size;
            _mappedViaPhysical = true;

            return InitializeConnection();
        }
        catch
        {
            if (sectionHandle != IntPtr.Zero)
                CloseHandle(sectionHandle);
            return false;
        }
    }

    private bool InitializeConnection()
    {
        if (_mappedMemory == IntPtr.Zero)
            return false;

        // Verify magic - use obfuscated magic if available
        uint magic = (uint)Marshal.ReadInt32(_mappedMemory);
        if (magic != _obfuscatedMagic)
        {
            // Magic doesn't match - could be wrong key or not our shared memory
            // Try base magic as fallback (driver might not have obfuscation)
            if (magic != NEXUS_COMM_MAGIC_BASE)
            {
                Disconnect();
                return false;
            }
            // Using base magic - obfuscation not active
            _obfuscationEnabled = false;
        }

        // Check kernel is ready
        uint flags = (uint)Marshal.ReadInt32(_mappedMemory + 8);
        if ((flags & NEXUS_COMM_FLAG_KERNEL_READY) == 0)
        {
            Disconnect();
            return false;
        }

        // Verify obfuscation state matches
        bool kernelObfuscated = (flags & NEXUS_COMM_FLAG_OBFUSCATED) != 0;
        if (kernelObfuscated != _obfuscationEnabled)
        {
            // Mismatch - try to reconcile
            if (kernelObfuscated && !_obfuscationEnabled)
            {
                // Kernel has obfuscation but we don't have key - try to get it
                var keyResult = NexusEngine.GetObfuscationKey(out var key);
                if (keyResult == NexusEngine.BootkitResult.Success && key.Valid)
                {
                    _obfuscationKey = key;
                    _obfuscatedMagic = NexusEngine.GetObfuscatedMagic(key);
                    _obfuscationEnabled = true;
                }
                else
                {
                    // Can't get key - connection will likely fail
                    Disconnect();
                    return false;
                }
            }
        }

        // Calculate offsets
        CalculateOffsets();

        // Read session ID
        SessionId = (ulong)Marshal.ReadInt64(_mappedMemory + 128 + 40); // Crypto.SessionId offset

        // Register as client
        RegisterClient();

        // Set user ready flag
        UpdateFlags();

        return true;
    }

    private void CalculateOffsets()
    {
        // Based on NEXUS_COMM_SHARED_MEMORY structure layout
        int headerSize = 64;
        int cryptoSize = 64;
        int clientSize = 128;
        int syncSize = 64;
        int ringHeadersSize = 64;

        int baseOffset = headerSize + cryptoSize + clientSize + syncSize;

        _requestRingOffset = baseOffset;
        _responseRingOffset = baseOffset + 16;
        _eventRingOffset = baseOffset + 32;

        int bufferBase = baseOffset + ringHeadersSize;
        _requestBufferOffset = bufferBase;
        _responseBufferOffset = bufferBase + NEXUS_COMM_REQUEST_SIZE;
        _eventBufferOffset = bufferBase + NEXUS_COMM_REQUEST_SIZE + NEXUS_COMM_RESPONSE_SIZE;
    }

    private int CalculateSharedMemorySize()
    {
        return 64 + 64 + 128 + 64 + 64 +  // Headers
               NEXUS_COMM_REQUEST_SIZE +
               NEXUS_COMM_RESPONSE_SIZE +
               NEXUS_COMM_EVENT_SIZE;
    }

    private void RegisterClient()
    {
        if (_mappedMemory == IntPtr.Zero)
            return;

        // Write client info
        int clientOffset = 64 + 64; // After header and crypto

        uint pid = (uint)Environment.ProcessId;
        uint tid = (uint)Environment.CurrentManagedThreadId;

        Marshal.WriteInt32(_mappedMemory + clientOffset, (int)pid);
        Marshal.WriteInt32(_mappedMemory + clientOffset + 4, (int)tid);

        // Could also write ImageBase, hash, etc. for validation
    }

    private void UpdateFlags()
    {
        if (_mappedMemory == IntPtr.Zero)
            return;

        uint flags = (uint)Marshal.ReadInt32(_mappedMemory + 8);
        flags |= NEXUS_COMM_FLAG_USER_READY;

        if (_encryptionEnabled)
            flags |= NEXUS_COMM_FLAG_ENCRYPTED;
        else
            flags &= ~NEXUS_COMM_FLAG_ENCRYPTED;

        Marshal.WriteInt32(_mappedMemory + 8, (int)flags);
    }

    /// <summary>
    /// Disconnect from the kernel driver
    /// </summary>
    public void Disconnect()
    {
        if (_mappedMemory != IntPtr.Zero)
        {
            // Clear user ready flag
            try
            {
                uint flags = (uint)Marshal.ReadInt32(_mappedMemory + 8);
                flags &= ~NEXUS_COMM_FLAG_USER_READY;
                Marshal.WriteInt32(_mappedMemory + 8, (int)flags);
            }
            catch { }

            if (_mappedViaIoctl)
            {
                // Memory was mapped via IOCTL - ask driver to unmap
                NexusEngine.UnmapCommChannel(_mappedMemory);
            }
            else if (_mappedViaPhysical)
            {
                // Memory was mapped via physical memory
                UnmapViewOfFile(_mappedMemory);
            }
            else
            {
                // Generic unmap
                UnmapViewOfFile(_mappedMemory);
            }

            _mappedMemory = IntPtr.Zero;
            _mappedViaIoctl = false;
            _mappedViaPhysical = false;
        }

        if (_sectionHandle != IntPtr.Zero)
        {
            CloseHandle(_sectionHandle);
            _sectionHandle = IntPtr.Zero;
        }
    }

    #endregion
}
