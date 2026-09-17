// <file>
// <summary>
// NexusKernelDriver partial class — singleton for communicating with NexusKernel.sys
// via IOCTL or shared memory (mapped mode). Core driver interface: connect, disconnect,
// SendIoctl, ReadProcessMemory, WriteProcessMemory, ReadPhysicalMemory, QueryMemory,
// EnumModules, EnumThreads, EnumProcesses, thread/process operations, event monitoring.
//
// IOCTL codes:       see KernelProvider.Ioctls.cs
// Struct definitions: see KernelProvider.Ioctls.cs and KernelProvider.Structs.cs
// Process watch/CI:  see KernelProvider.Ioctl.cs (partial class extension)
// Memory provider:   see KernelProvider.Memory.cs
// Process provider:  see KernelProvider.Process.cs
// Debug provider:    see KernelProvider.Debug.cs
// </summary>
// </file>

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

#region Kernel Driver Interface

/// <summary>
/// Interface for communicating with NexusKernel.sys.
/// </summary>
public partial class NexusKernelDriver : IDisposable
{
    private const string DEVICE_NAME = @"\\.\NexusKernel";
    private SafeFileHandle? _deviceHandle;
    private NexusComm? _commChannel;
    private bool _useMappedMode;
    private bool _disposed;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    /// <summary>
    /// Singleton instance.
    /// </summary>
    public static NexusKernelDriver Instance { get; } = new();

    /// <summary>
    /// Whether the driver is loaded normally (with device object) and accessible via IOCTL.
    /// </summary>
    public bool IsLoaded => _deviceHandle is { IsInvalid: false, IsClosed: false };

    /// <summary>
    /// Whether the driver is mapped (via bootkit) and accessible via shared memory.
    /// </summary>
    public bool IsMapped
    {
        get
        {
            try
            {
                // Check if we can query comm info via the mapper
                var result = NexusEngine.QueryDriverCommInfo(out _);
                return result == NexusEngine.BootkitResult.Success;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Whether the driver is available via either IOCTL or shared memory.
    /// </summary>
    public bool IsAvailable => IsLoaded || IsMapped;

    /// <summary>
    /// Attempt to connect to the driver (IOCTL or shared memory mode).
    /// </summary>
    public bool Connect()
    {
        if (IsLoaded) return true;
        if (_useMappedMode && _commChannel?.IsConnected == true) return true;

        // Try IOCTL mode first (driver loaded via SC)
        try
        {
            _deviceHandle = CreateFile(
                DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (IsLoaded)
            {
                _useMappedMode = false;
                return true;
            }
        }
        catch
        {
            // IOCTL not available, try mapped mode
        }

        // Try mapped mode (driver loaded via bootkit)
        try
        {
            _commChannel ??= new NexusComm();
            if (_commChannel.Connect())
            {
                _useMappedMode = true;
                return true;
            }
        }
        catch
        {
            // Mapped mode also failed
        }

        return false;
    }

    /// <summary>
    /// Whether we're using mapped mode (shared memory) instead of IOCTL.
    /// </summary>
    public bool UsingMappedMode => _useMappedMode;

    /// <summary>
    /// Disconnect from the driver.
    /// </summary>
    public void Disconnect()
    {
        _deviceHandle?.Dispose();
        _deviceHandle = null;
        _commChannel?.Disconnect();
        _useMappedMode = false;
    }

    /// <summary>
    /// Send an IOCTL to the driver.
    /// </summary>
    public bool SendIoctl<TIn, TOut>(uint ioctlCode, ref TIn input, out TOut output)
        where TIn : struct
        where TOut : struct
    {
        output = default;

        if (!IsLoaded) return false;

        var inSize = Marshal.SizeOf<TIn>();
        var outSize = Marshal.SizeOf<TOut>();
        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(inSize);
            outPtr = Marshal.AllocHGlobal(outSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                ioctlCode,
                inPtr,
                (uint)inSize,
                outPtr,
                (uint)outSize,
                out _,
                IntPtr.Zero);

            if (result)
            {
                output = Marshal.PtrToStructure<TOut>(outPtr);
            }

            return result;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Send an IOCTL with input only.
    /// </summary>
    public bool SendIoctl<TIn>(uint ioctlCode, ref TIn input) where TIn : struct
    {
        if (!IsLoaded) return false;

        var inSize = Marshal.SizeOf<TIn>();
        var inPtr = Marshal.AllocHGlobal(inSize);

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);

            return DeviceIoControl(
                _deviceHandle!,
                ioctlCode,
                inPtr,
                (uint)inSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Read process memory via IOCTL or shared memory (mapped mode).
    /// </summary>
    public byte[] ReadProcessMemory(int processId, ulong address, int size)
    {
        if (size <= 0) return [];

        // Route through shared memory in mapped mode
        if (_useMappedMode && _commChannel?.IsConnected == true)
        {
            return ReadProcessMemoryViaMapped(processId, address, size);
        }

        // IOCTL mode
        if (!IsLoaded) return [];

        var input = new NexusReadMemoryInput
        {
            ProcessId = (uint)processId,
            Reserved = 0,
            Address = address,
            Size = (ulong)size
        };

        // Output buffer: header + data
        var headerSize = Marshal.SizeOf<NexusReadMemoryOutput>();
        var outputSize = headerSize + size;

        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusReadMemoryInput>());
            outPtr = Marshal.AllocHGlobal(outputSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_READ_MEMORY,
                inPtr,
                (uint)Marshal.SizeOf<NexusReadMemoryInput>(),
                outPtr,
                (uint)outputSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned <= headerSize) return [];

            // Parse the output header
            var output = Marshal.PtrToStructure<NexusReadMemoryOutput>(outPtr);
            if (output.Status != 0 || output.BytesRead == 0) return [];

            // Copy the data following the header
            var dataSize = (int)Math.Min(output.BytesRead, (ulong)(bytesReturned - headerSize));
            var buffer = new byte[dataSize];
            Marshal.Copy(outPtr + headerSize, buffer, 0, dataSize);
            return buffer;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Read process memory via shared memory (mapped mode).
    /// </summary>
    private byte[] ReadProcessMemoryViaMapped(int processId, ulong address, int size)
    {
        if (_commChannel == null) return [];

        // Build input matching kernel's expected format
        var input = new NexusReadMemoryInput
        {
            ProcessId = (uint)processId,
            Reserved = 0,
            Address = address,
            Size = (ulong)size
        };

        // Serialize input
        int inputSize = Marshal.SizeOf<NexusReadMemoryInput>();
        byte[] inputData = new byte[inputSize];
        IntPtr ptr = Marshal.AllocHGlobal(inputSize);
        try
        {
            Marshal.StructureToPtr(input, ptr, false);
            Marshal.Copy(ptr, inputData, 0, inputSize);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        // Send via shared memory
        if (!_commChannel.SendCommand(NexusComm.CMD_READ_MEMORY, inputData, out var outputData, out var status))
            return [];

        if (status != 0 || outputData.Length == 0)
            return [];

        // Output format: header (NexusReadMemoryOutput) + data
        var headerSize = Marshal.SizeOf<NexusReadMemoryOutput>();
        if (outputData.Length <= headerSize)
            return [];

        // Parse header to get actual bytes read
        ptr = Marshal.AllocHGlobal(headerSize);
        try
        {
            Marshal.Copy(outputData, 0, ptr, headerSize);
            var output = Marshal.PtrToStructure<NexusReadMemoryOutput>(ptr);

            if (output.Status != 0 || output.BytesRead == 0)
                return [];

            // Copy data after header
            var dataSize = (int)Math.Min(output.BytesRead, (ulong)(outputData.Length - headerSize));
            var buffer = new byte[dataSize];
            Array.Copy(outputData, headerSize, buffer, 0, dataSize);
            return buffer;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Write process memory via IOCTL or shared memory (mapped mode).
    /// </summary>
    public bool WriteProcessMemory(int processId, ulong address, byte[] data)
    {
        if (data == null || data.Length == 0) return false;

        // Route through shared memory in mapped mode
        if (_useMappedMode && _commChannel?.IsConnected == true)
        {
            return WriteProcessMemoryViaMapped(processId, address, data);
        }

        // IOCTL mode
        if (!IsLoaded) return false;

        // Input: header + data
        var headerSize = Marshal.SizeOf<NexusWriteMemoryInput>();
        var inSize = headerSize + data.Length;
        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(inSize);
            outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusWriteMemoryOutput>());

            var input = new NexusWriteMemoryInput
            {
                ProcessId = (uint)processId,
                Reserved = 0,
                Address = address,
                Size = (ulong)data.Length
            };

            // Copy header, then data
            Marshal.StructureToPtr(input, inPtr, false);
            Marshal.Copy(data, 0, inPtr + headerSize, data.Length);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_WRITE_MEMORY,
                inPtr,
                (uint)inSize,
                outPtr,
                (uint)Marshal.SizeOf<NexusWriteMemoryOutput>(),
                out var bytesReturned,
                IntPtr.Zero);

            if (!result) return false;

            if (bytesReturned >= Marshal.SizeOf<NexusWriteMemoryOutput>())
            {
                var output = Marshal.PtrToStructure<NexusWriteMemoryOutput>(outPtr);
                return output.Status == 0 && output.BytesWritten > 0;
            }

            return result;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Write process memory via shared memory (mapped mode).
    /// </summary>
    private bool WriteProcessMemoryViaMapped(int processId, ulong address, byte[] data)
    {
        if (_commChannel == null) return false;

        // Build input: header + data
        var header = new NexusWriteMemoryInput
        {
            ProcessId = (uint)processId,
            Reserved = 0,
            Address = address,
            Size = (ulong)data.Length
        };

        int headerSize = Marshal.SizeOf<NexusWriteMemoryInput>();
        byte[] inputData = new byte[headerSize + data.Length];

        // Serialize header
        IntPtr ptr = Marshal.AllocHGlobal(headerSize);
        try
        {
            Marshal.StructureToPtr(header, ptr, false);
            Marshal.Copy(ptr, inputData, 0, headerSize);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        // Copy data after header
        Array.Copy(data, 0, inputData, headerSize, data.Length);

        // Send via shared memory
        if (!_commChannel.SendCommand(NexusComm.CMD_WRITE_MEMORY, inputData, out var outputData, out var status))
            return false;

        if (status != 0)
            return false;

        // Parse output header if available
        if (outputData.Length >= Marshal.SizeOf<NexusWriteMemoryOutput>())
        {
            ptr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusWriteMemoryOutput>());
            try
            {
                Marshal.Copy(outputData, 0, ptr, Marshal.SizeOf<NexusWriteMemoryOutput>());
                var output = Marshal.PtrToStructure<NexusWriteMemoryOutput>(ptr);
                return output.Status == 0 && output.BytesWritten > 0;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        return true;  // No output header but status was 0
    }

    /// <summary>
    /// Read physical memory directly.
    /// </summary>
    public byte[] ReadPhysicalMemory(ulong physicalAddress, int size)
    {
        if (!IsLoaded || size <= 0) return [];

        var input = new NexusPhysicalMemoryInput
        {
            PhysicalAddress = physicalAddress,
            Size = (ulong)size
        };

        // Output: same format as kernel read (header + data)
        var headerSize = 16; // BytesTransferred(8) + Status(4) + Reserved(4)
        var outputSize = headerSize + size;

        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusPhysicalMemoryInput>());
            outPtr = Marshal.AllocHGlobal(outputSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_READ_PHYSICAL,
                inPtr,
                (uint)Marshal.SizeOf<NexusPhysicalMemoryInput>(),
                outPtr,
                (uint)outputSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned <= headerSize) return [];

            // Read bytes transferred from output header
            var bytesRead = (long)Marshal.ReadInt64(outPtr, 0);
            if (bytesRead <= 0) return [];

            var dataSize = (int)Math.Min(bytesRead, bytesReturned - headerSize);
            var buffer = new byte[dataSize];
            Marshal.Copy(outPtr + headerSize, buffer, 0, dataSize);
            return buffer;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Query memory region information.
    /// </summary>
    public bool QueryMemory(int processId, ulong address, out NexusQueryMemoryOutput output)
    {
        output = default;
        if (!IsLoaded) return false;

        var input = new NexusQueryMemoryInput
        {
            ProcessId = (uint)processId,
            Reserved = 0,
            Address = address
        };

        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_QUERY_MEMORY, ref input, out output);
    }

    /// <summary>
    /// Enumerate modules for a process.
    /// </summary>
    public KernelModuleInfo[] EnumModules(int processId)
    {
        if (!IsLoaded) return [];

        var input = new NexusEnumModulesInput
        {
            ProcessId = (uint)processId,
            Reserved = 0
        };

        // First call with small buffer to get required size
        const int initialBufferSize = 4096;
        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusEnumModulesInput>());
            outPtr = Marshal.AllocHGlobal(initialBufferSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_ENUM_MODULES,
                inPtr,
                (uint)Marshal.SizeOf<NexusEnumModulesInput>(),
                outPtr,
                initialBufferSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                // Check if buffer too small - the driver returns required size in first ULONG
                var lastError = Marshal.GetLastWin32Error();
                if (lastError == 234) // ERROR_MORE_DATA
                {
                    var requiredSize = Marshal.ReadInt32(outPtr);
                    Marshal.FreeHGlobal(outPtr);
                    outPtr = Marshal.AllocHGlobal(requiredSize);

                    result = DeviceIoControl(
                        _deviceHandle!,
                        NexusKernelIoctl.IOCTL_NEXUS_ENUM_MODULES,
                        inPtr,
                        (uint)Marshal.SizeOf<NexusEnumModulesInput>(),
                        outPtr,
                        (uint)requiredSize,
                        out bytesReturned,
                        IntPtr.Zero);
                }
            }

            if (!result || bytesReturned < 8) return [];

            // Parse output: first 8 bytes are count + reserved
            var moduleCount = Marshal.ReadInt32(outPtr);
            if (moduleCount <= 0) return [];

            var modules = new KernelModuleInfo[moduleCount];
            var moduleSize = Marshal.SizeOf<KernelModuleInfo>();
            var dataPtr = outPtr + 8; // Skip header

            for (int i = 0; i < moduleCount && (8 + (i + 1) * moduleSize) <= bytesReturned; i++)
            {
                modules[i] = Marshal.PtrToStructure<KernelModuleInfo>(dataPtr + (i * moduleSize));
            }

            return modules;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Enumerate threads for a process.
    /// </summary>
    public KernelThreadInfo[] EnumThreads(int processId)
    {
        if (!IsLoaded) return [];

        var input = new NexusEnumThreadsInput
        {
            ProcessId = (uint)processId,
            Reserved = 0
        };

        const int initialBufferSize = 4096;
        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusEnumThreadsInput>());
            outPtr = Marshal.AllocHGlobal(initialBufferSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_ENUM_THREADS,
                inPtr,
                (uint)Marshal.SizeOf<NexusEnumThreadsInput>(),
                outPtr,
                initialBufferSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                var lastError = Marshal.GetLastWin32Error();
                if (lastError == 234) // ERROR_MORE_DATA
                {
                    var requiredSize = Marshal.ReadInt32(outPtr);
                    Marshal.FreeHGlobal(outPtr);
                    outPtr = Marshal.AllocHGlobal(requiredSize);

                    result = DeviceIoControl(
                        _deviceHandle!,
                        NexusKernelIoctl.IOCTL_NEXUS_ENUM_THREADS,
                        inPtr,
                        (uint)Marshal.SizeOf<NexusEnumThreadsInput>(),
                        outPtr,
                        (uint)requiredSize,
                        out bytesReturned,
                        IntPtr.Zero);
                }
            }

            if (!result || bytesReturned < 8) return [];

            var threadCount = Marshal.ReadInt32(outPtr);
            if (threadCount <= 0) return [];

            var threads = new KernelThreadInfo[threadCount];
            var threadSize = Marshal.SizeOf<KernelThreadInfo>();
            var dataPtr = outPtr + 8;

            for (int i = 0; i < threadCount && (8 + (i + 1) * threadSize) <= bytesReturned; i++)
            {
                threads[i] = Marshal.PtrToStructure<KernelThreadInfo>(dataPtr + (i * threadSize));
            }

            return threads;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Enumerate all processes.
    /// </summary>
    public KernelProcessInfo[] EnumProcesses()
    {
        if (!IsLoaded) return [];

        const int initialBufferSize = 65536; // Processes can be large
        var outPtr = Marshal.AllocHGlobal(initialBufferSize);

        try
        {
            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_ENUM_PROCESSES,
                IntPtr.Zero,
                0,
                outPtr,
                initialBufferSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                var lastError = Marshal.GetLastWin32Error();
                if (lastError == 234) // ERROR_MORE_DATA
                {
                    var requiredSize = Marshal.ReadInt32(outPtr);
                    Marshal.FreeHGlobal(outPtr);
                    outPtr = Marshal.AllocHGlobal(requiredSize);

                    result = DeviceIoControl(
                        _deviceHandle!,
                        NexusKernelIoctl.IOCTL_NEXUS_ENUM_PROCESSES,
                        IntPtr.Zero,
                        0,
                        outPtr,
                        (uint)requiredSize,
                        out bytesReturned,
                        IntPtr.Zero);
                }
            }

            if (!result || bytesReturned < 8) return [];

            var processCount = Marshal.ReadInt32(outPtr);
            if (processCount <= 0) return [];

            var processes = new KernelProcessInfo[processCount];
            var processSize = Marshal.SizeOf<KernelProcessInfo>();
            var dataPtr = outPtr + 8;

            for (int i = 0; i < processCount && (8 + (i + 1) * processSize) <= bytesReturned; i++)
            {
                processes[i] = Marshal.PtrToStructure<KernelProcessInfo>(dataPtr + (i * processSize));
            }

            return processes;
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Suspend a thread.
    /// </summary>
    public bool SuspendThread(int threadId)
    {
        if (!IsLoaded) return false;

        var input = new KernelThreadIdInput { ThreadId = (uint)threadId };
        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_SUSPEND_THREAD, ref input);
    }

    /// <summary>
    /// Resume a thread.
    /// </summary>
    public bool ResumeThread(int threadId)
    {
        if (!IsLoaded) return false;

        var input = new KernelThreadIdInput { ThreadId = (uint)threadId };
        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_RESUME_THREAD, ref input);
    }

    /// <summary>
    /// Terminate a process.
    /// </summary>
    public bool TerminateProcess(int processId, uint exitCode = 0)
    {
        if (!IsLoaded) return false;

        var input = new KernelTerminateProcessInput
        {
            ProcessId = (uint)processId,
            ExitCode = exitCode
        };
        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_TERMINATE_PROCESS, ref input);
    }

    /// <summary>
    /// Terminate a thread.
    /// </summary>
    public bool TerminateThread(int threadId, uint exitCode = 0)
    {
        if (!IsLoaded) return false;

        var input = new KernelTerminateThreadInput
        {
            ThreadId = (uint)threadId,
            ExitCode = exitCode
        };
        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_TERMINATE_THREAD, ref input);
    }

    /// <summary>
    /// Close a handle in a target process.
    /// </summary>
    public bool CloseRemoteHandle(int processId, IntPtr handle)
    {
        if (!IsLoaded) return false;

        var input = new KernelCloseHandleInput
        {
            ProcessId = (uint)processId,
            Reserved = 0,
            Handle = (ulong)handle
        };
        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_CLOSE_HANDLE, ref input);
    }

    /// <summary>
    /// Enumerate handles for a process.
    /// </summary>
    public KernelHandleInfo[] EnumHandles(int processId)
    {
        if (!IsLoaded) return [];

        var input = new KernelEnumHandlesInput
        {
            ProcessId = (uint)processId,
            Reserved = 0
        };

        const int initialBufferSize = 65536; // Handles can be many
        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<KernelEnumHandlesInput>());
            outPtr = Marshal.AllocHGlobal(initialBufferSize);

            Marshal.StructureToPtr(input, inPtr, false);

            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_ENUM_HANDLES,
                inPtr,
                (uint)Marshal.SizeOf<KernelEnumHandlesInput>(),
                outPtr,
                initialBufferSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result)
            {
                var lastError = Marshal.GetLastWin32Error();
                if (lastError == 234) // ERROR_MORE_DATA
                {
                    var requiredSize = Marshal.ReadInt32(outPtr);
                    Marshal.FreeHGlobal(outPtr);
                    outPtr = Marshal.AllocHGlobal(requiredSize);

                    result = DeviceIoControl(
                        _deviceHandle!,
                        NexusKernelIoctl.IOCTL_NEXUS_ENUM_HANDLES,
                        inPtr,
                        (uint)Marshal.SizeOf<KernelEnumHandlesInput>(),
                        outPtr,
                        (uint)requiredSize,
                        out bytesReturned,
                        IntPtr.Zero);
                }
            }

            if (!result || bytesReturned < 8) return [];

            var handleCount = Marshal.ReadInt32(outPtr);
            if (handleCount <= 0) return [];

            var handles = new KernelHandleInfo[handleCount];
            var handleSize = Marshal.SizeOf<KernelHandleInfo>();
            var dataPtr = outPtr + 8;

            for (int i = 0; i < handleCount && (8 + (i + 1) * handleSize) <= bytesReturned; i++)
            {
                handles[i] = Marshal.PtrToStructure<KernelHandleInfo>(dataPtr + (i * handleSize));
            }

            return handles;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Configure kernel event callbacks (registry, handle, memory monitoring).
    /// </summary>
    /// <param name="eventMask">Bitmask of enabled event types (1 &lt;&lt; NEXUS_EVENT_*)</param>
    /// <param name="processFilter">PID to filter (0 = all processes)</param>
    public bool ConfigureCallbacks(uint eventMask, uint processFilter)
    {
        if (!IsLoaded) return false;

        var config = new KernelCallbackConfig
        {
            EventMask = eventMask,
            ProcessFilter = processFilter
        };

        return SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_REGISTER_CALLBACK, ref config);
    }

    /// <summary>
    /// Enable all ProcMon-like monitoring events.
    /// </summary>
    public bool EnableAllMonitoring(uint processFilter = 0)
    {
        uint mask = (1u << (int)NexusEventType.RegistryOp) |
                    (1u << (int)NexusEventType.HandleOp) |
                    (1u << (int)NexusEventType.MemoryOp) |
                    (1u << (int)NexusEventType.ProcessCreate) |
                    (1u << (int)NexusEventType.ProcessExit) |
                    (1u << (int)NexusEventType.ThreadCreate) |
                    (1u << (int)NexusEventType.ThreadExit) |
                    (1u << (int)NexusEventType.ImageLoad) |
                    (1u << (int)NexusEventType.Syscall);
        return ConfigureCallbacks(mask, processFilter);
    }

    /// <summary>
    /// Disable all event monitoring.
    /// </summary>
    public bool DisableMonitoring()
    {
        return ConfigureCallbacks(0, 0);
    }


    /// <summary>
    /// Set thread context (registers) for a thread.
    /// </summary>
    public bool SetThreadContext(int threadId, KernelContext64 context)
    {
        if (!IsLoaded) return false;

        var headerSize = Marshal.SizeOf<NexusThreadContextInput>();
        var contextSize = Marshal.SizeOf<KernelContext64>();
        var totalSize = headerSize + contextSize;

        var inPtr = Marshal.AllocHGlobal(totalSize);
        try
        {
            var input = new NexusThreadContextInput
            {
                ThreadId = (uint)threadId,
                ContextFlags = 0x10001F // CONTEXT_ALL for x64
            };

            Marshal.StructureToPtr(input, inPtr, false);
            Marshal.StructureToPtr(context, inPtr + headerSize, false);

            return DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_SET_THREAD_CONTEXT,
                inPtr,
                (uint)totalSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Shut down the singleton instance, releasing the driver handle.
    /// Call this at application exit to ensure proper cleanup.
    /// </summary>
    public static void Shutdown()
    {
        Instance.Dispose();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Disconnect();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}

#endregion
