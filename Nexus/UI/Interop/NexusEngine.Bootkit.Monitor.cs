// Bootkit SecureBoot monitoring and obfuscation API.
// Split from NexusEngine.Bootkit.cs for maintainability.

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region SecureBoot Monitor

    /// <summary>
    /// Queries the GetVariable monitor for SecureBoot read statistics.
    /// </summary>
    public static BootkitResult QuerySecureBootMonitor(out GetVariableMonitorStats stats)
    {
        stats = default;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var varName = CreateUnicodeString(GetVariableMonitorName);
        var guid = EfiGlobalVariableGuid;
        var dataSize = (uint)Marshal.SizeOf<GetVariableMonitorStats>();
        var dataPtr = Marshal.AllocHGlobal((int)dataSize);

        try
        {
            // Use SetVariable to query (the hook handles this specially)
            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                dataSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            stats = Marshal.PtrToStructure<GetVariableMonitorStats>(dataPtr);
            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    #endregion

    #region Obfuscation API

    // Cached obfuscation key
    private static ObfuscationKey? _cachedObfuscationKey = null;

    /// <summary>
    /// Retrieves the obfuscation key from the UEFI bootkit.
    /// The key is generated at boot time and used to XOR shared memory structures.
    /// </summary>
    public static BootkitResult GetObfuscationKey(out ObfuscationKey key)
    {
        key = new ObfuscationKey();

        // Return cached key if available
        if (_cachedObfuscationKey != null && _cachedObfuscationKey.Valid)
        {
            key = _cachedObfuscationKey;
            return BootkitResult.Success;
        }

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        // Build request
        var response = new OBFUSCATION_KEY_RESPONSE
        {
            Status = 0,
            KeySize = 0,
            Key = new byte[NEXUS_OBFUSCATION_KEY_SIZE],
            BootId = 0
        };

        // We'll reuse the buffer for request then response
        var varName = CreateUnicodeString("NexusObfsKey");
        var guid = NexusMapperGuid;
        var bufferSize = Marshal.SizeOf<OBFUSCATION_KEY_RESPONSE>();
        var dataPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            // Write request magic at start of buffer
            Marshal.WriteInt32(dataPtr, (int)NEXUS_OBFUSCATION_MAGIC);
            Marshal.WriteInt32(dataPtr + 4, 0);  // Reserved

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)bufferSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.HookNotInstalled;
            }

            // Read response
            response = Marshal.PtrToStructure<OBFUSCATION_KEY_RESPONSE>(dataPtr);

            if (response.Status != 0 || response.KeySize != NEXUS_OBFUSCATION_KEY_SIZE)
            {
                return BootkitResult.NtError;
            }

            // Build key object
            key.Key = response.Key ?? new byte[NEXUS_OBFUSCATION_KEY_SIZE];
            key.BootId = response.BootId;
            key.Valid = true;

            // Cache for future use
            _cachedObfuscationKey = key;

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Gets the obfuscated magic value for the current boot session.
    /// </summary>
    public static uint GetObfuscatedMagic(ObfuscationKey? key = null)
    {
        if (key == null || !key.Valid)
        {
            // Try to get cached key
            if (_cachedObfuscationKey != null && _cachedObfuscationKey.Valid)
            {
                key = _cachedObfuscationKey;
            }
            else
            {
                // Fallback to base magic
                return NEXUS_COMM_MAGIC_BASE;
            }
        }

        // XOR base magic with first 4 bytes of key
        uint keyPart = BitConverter.ToUInt32(key.Key, 0);
        return NEXUS_COMM_MAGIC_BASE ^ keyPart;
    }

    /// <summary>
    /// Obfuscates/de-obfuscates data in place using XOR with the key.
    /// Since XOR is symmetric, this works for both operations.
    /// </summary>
    public static void Obfuscate(byte[] data, ObfuscationKey key)
    {
        if (data == null || data.Length == 0 || key == null || !key.Valid)
            return;

        for (int i = 0; i < data.Length; i++)
        {
            data[i] ^= key.Key[i % NEXUS_OBFUSCATION_KEY_SIZE];
        }
    }

    /// <summary>
    /// Obfuscates/de-obfuscates data in place using XOR with the key.
    /// Operates on a span within a larger buffer.
    /// </summary>
    public static void Obfuscate(byte[] data, int offset, int length, ObfuscationKey key)
    {
        if (data == null || length == 0 || key == null || !key.Valid)
            return;

        for (int i = 0; i < length; i++)
        {
            data[offset + i] ^= key.Key[i % NEXUS_OBFUSCATION_KEY_SIZE];
        }
    }

    /// <summary>
    /// Alias for Obfuscate (XOR is symmetric)
    /// </summary>
    public static void Deobfuscate(byte[] data, ObfuscationKey key) => Obfuscate(data, key);

    /// <summary>
    /// Alias for Obfuscate (XOR is symmetric)
    /// </summary>
    public static void Deobfuscate(byte[] data, int offset, int length, ObfuscationKey key)
        => Obfuscate(data, offset, length, key);

    /// <summary>
    /// Checks if obfuscation is available (bootkit is loaded and key can be retrieved).
    /// </summary>
    public static bool IsObfuscationAvailable()
    {
        if (_cachedObfuscationKey != null && _cachedObfuscationKey.Valid)
            return true;

        var result = GetObfuscationKey(out _);
        return result == BootkitResult.Success;
    }

    /// <summary>
    /// Clears the cached obfuscation key (useful for testing or after reboot detection).
    /// </summary>
    public static void ClearObfuscationKeyCache()
    {
        _cachedObfuscationKey = null;
    }

    #endregion
}
