// NexusComm.Communication.cs - Ring buffer protocol, SendCommand, marshalling helpers

using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Nexus.UI.Interop;

public sealed partial class NexusComm
{
    #region Communication

    /// <summary>
    /// Send a command and wait for response
    /// </summary>
    public bool SendCommand(uint command, byte[]? inputData, out byte[] outputData, out uint status, int timeoutMs = 5000)
    {
        outputData = Array.Empty<byte>();
        status = 0;

        if (!IsConnected)
            return false;

        lock (_lock)
        {
            uint sequence = ++_sequenceNumber;

            // Build message header - use obfuscated magic
            var header = new MsgHeader
            {
                Magic = _obfuscatedMagic,
                Command = command,
                Sequence = sequence,
                DataSize = (uint)(inputData?.Length ?? 0),
                Status = 0,
                Flags = 0,
                Timestamp = (ulong)DateTime.UtcNow.Ticks
            };

            // Write to request ring buffer
            if (!WriteToRing(_requestRingOffset, _requestBufferOffset, NEXUS_COMM_REQUEST_SIZE, header, inputData))
                return false;

            // Wait for response
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                if (TryReadResponse(sequence, out var responseHeader, out outputData))
                {
                    status = responseHeader.Status;
                    return true;
                }

                Thread.Sleep(1);
            }

            return false; // Timeout
        }
    }

    /// <summary>
    /// Simplified command with typed input/output
    /// </summary>
    public bool SendCommand<TInput, TOutput>(uint command, TInput input, out TOutput output, out uint status, int timeoutMs = 5000)
        where TInput : struct
        where TOutput : struct
    {
        output = default;
        status = 0;

        int inputSize = Marshal.SizeOf<TInput>();
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

        if (!SendCommand(command, inputData, out var outputData, out status, timeoutMs))
            return false;

        if (outputData.Length >= Marshal.SizeOf<TOutput>())
        {
            ptr = Marshal.AllocHGlobal(outputData.Length);
            try
            {
                Marshal.Copy(outputData, 0, ptr, outputData.Length);
                output = Marshal.PtrToStructure<TOutput>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        return true;
    }

    private bool WriteToRing(int ringOffset, int bufferOffset, int bufferSize, MsgHeader header, byte[]? data)
    {
        // Read ring state
        uint writeIndex = (uint)Marshal.ReadInt32(_mappedMemory + ringOffset);
        uint readIndex = (uint)Marshal.ReadInt32(_mappedMemory + ringOffset + 4);
        uint size = (uint)bufferSize;

        int totalSize = Marshal.SizeOf<MsgHeader>() + (data?.Length ?? 0);

        // Check space
        uint freeSpace;
        if (writeIndex >= readIndex)
            freeSpace = size - (writeIndex - readIndex) - 1;
        else
            freeSpace = readIndex - writeIndex - 1;

        if (freeSpace < totalSize)
            return false;

        // Write header
        byte[] headerBytes = StructToBytes(header);
        WriteRingData(bufferOffset, bufferSize, ref writeIndex, headerBytes);

        // Write data
        if (data != null && data.Length > 0)
        {
            WriteRingData(bufferOffset, bufferSize, ref writeIndex, data);
        }

        // Update write index
        Marshal.WriteInt32(_mappedMemory + ringOffset, (int)writeIndex);

        // Increment message count
        int msgCount = Marshal.ReadInt32(_mappedMemory + ringOffset + 12);
        Marshal.WriteInt32(_mappedMemory + ringOffset + 12, msgCount + 1);

        return true;
    }

    private void WriteRingData(int bufferOffset, int bufferSize, ref uint writeIndex, byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            int offset = bufferOffset + (int)(writeIndex & (bufferSize - 1));
            Marshal.WriteByte(_mappedMemory + offset, data[i]);
            writeIndex = (writeIndex + 1) & ((uint)bufferSize - 1);
        }
    }

    private bool TryReadResponse(uint expectedSequence, out MsgHeader header, out byte[] data)
    {
        header = default;
        data = Array.Empty<byte>();

        // Check message count
        int msgCount = Marshal.ReadInt32(_mappedMemory + _responseRingOffset + 12);
        if (msgCount <= 0)
            return false;

        uint readIndex = (uint)Marshal.ReadInt32(_mappedMemory + _responseRingOffset + 4);

        // Read header
        byte[] headerBytes = ReadRingData(_responseBufferOffset, NEXUS_COMM_RESPONSE_SIZE, ref readIndex, Marshal.SizeOf<MsgHeader>());
        header = BytesToStruct<MsgHeader>(headerBytes);

        // Validate magic using obfuscated value
        if (header.Magic != _obfuscatedMagic)
            return false;

        // Read data
        if (header.DataSize > 0)
        {
            data = ReadRingData(_responseBufferOffset, NEXUS_COMM_RESPONSE_SIZE, ref readIndex, (int)header.DataSize);
        }

        // Check sequence
        if (header.Sequence != expectedSequence)
        {
            // Not our response, put it back (or this is a bug)
            return false;
        }

        // Update read index
        Marshal.WriteInt32(_mappedMemory + _responseRingOffset + 4, (int)readIndex);

        // Decrement message count
        msgCount = Marshal.ReadInt32(_mappedMemory + _responseRingOffset + 12);
        Marshal.WriteInt32(_mappedMemory + _responseRingOffset + 12, msgCount - 1);

        return true;
    }

    private byte[] ReadRingData(int bufferOffset, int bufferSize, ref uint readIndex, int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            int offset = bufferOffset + (int)(readIndex & (bufferSize - 1));
            data[i] = Marshal.ReadByte(_mappedMemory + offset);
            readIndex = (readIndex + 1) & ((uint)bufferSize - 1);
        }
        return data;
    }

    #endregion

    #region Helpers

    private static byte[] StructToBytes<T>(T value) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        byte[] bytes = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
        return bytes;
    }

    private static T BytesToStruct<T>(byte[] bytes) where T : struct
    {
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            return Marshal.PtrToStructure<T>(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    #endregion
}
