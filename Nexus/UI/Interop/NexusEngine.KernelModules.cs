// Kernel module lookup.
//
// Split out of the former DSE interop file, which was deleted with the DSE feature. This has
// nothing to do with that: it asks Windows for the loaded-driver list through
// NtQuerySystemInformation and needs no firmware hook, no bootkit and no elevation beyond what
// the query itself requires.

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Kernel Module Helpers

    // RTL_PROCESS_MODULE_INFORMATION structure size on x64
    // Layout: Section(8) + MappedBase(8) + ImageBase(8) + ImageSize(4) + Flags(4) +
    //         LoadOrderIndex(2) + InitOrderIndex(2) + LoadCount(2) + OffsetToFileName(2) + FullPathName(256) = 296
    private const int RTL_PROCESS_MODULE_INFO_SIZE = 296;

    /// <summary>
    /// Finds a kernel module by name and returns its base address.
    /// Uses direct memory reading to avoid struct marshalling issues.
    /// </summary>
    public static bool FindKernelModule(string moduleName, out ulong moduleBase)
    {
        moduleBase = 0;

        // First call to get required size
        int status = NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out uint returnLength);
        if (returnLength == 0)
            return false;

        // Allocate buffer with extra space
        IntPtr buffer = Marshal.AllocHGlobal((int)(returnLength + 4096));

        try
        {
            status = NtQuerySystemInformation(SystemModuleInformation, buffer, returnLength + 4096, out _);
            if (status != 0)
                return false;

            // Read number of modules (ULONG at offset 0)
            uint numberOfModules = (uint)Marshal.ReadInt32(buffer);

            // Module array starts at offset 8 (4 bytes ULONG + 4 bytes padding on x64)
            IntPtr moduleArrayPtr = buffer + 8;

            for (uint i = 0; i < numberOfModules; i++)
            {
                IntPtr currentModule = moduleArrayPtr + (int)(i * RTL_PROCESS_MODULE_INFO_SIZE);

                // Read ImageBase at offset 16 (after Section + MappedBase)
                IntPtr imageBase = Marshal.ReadIntPtr(currentModule + 16);

                // Read OffsetToFileName at offset 38 (USHORT)
                ushort offsetToFileName = (ushort)Marshal.ReadInt16(currentModule + 38);

                // FullPathName starts at offset 40, get filename pointer using offset
                IntPtr fileNamePtr = currentModule + 40 + offsetToFileName;

                // Read the filename as ASCII string
                string? fileName = Marshal.PtrToStringAnsi(fileNamePtr);

                if (!string.IsNullOrEmpty(fileName) &&
                    fileName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    moduleBase = (ulong)imageBase;
                    return moduleBase != 0;
                }
            }

            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    #endregion
}
