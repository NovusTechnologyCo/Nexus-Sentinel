// <file>
// <summary>
// P/Invoke bindings for static binary analysis: XOR/RC4/AES decryption, zlib/LZMA
// decompression, hash computation (MD5, SHA1, SHA256, CRC32), entropy calculation,
// and binary data classification.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Decryption

    /// <summary>
    /// Decrypt memory region with XOR key.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecryptXor(
        [In, Out] byte[] data,
        nuint dataSize,
        [In] byte[] key,
        nuint keySize);

    /// <summary>
    /// Decrypt memory with XOR (in target process).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecryptXorMem(
        IntPtr processHandle,
        ulong address,
        nuint size,
        [In] byte[] key,
        nuint keySize);

    /// <summary>
    /// Decrypt with rolling XOR.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecryptRollingXor(
        [In, Out] byte[] data,
        nuint dataSize,
        byte initialKey);

    /// <summary>
    /// Decrypt with ADD/SUB key.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecryptAddSub(
        [In, Out] byte[] data,
        nuint dataSize,
        [In] byte[] key,
        nuint keySize,
        uint isAdd);

    /// <summary>
    /// Decrypt with ROT/ROL.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecryptRotate(
        [In, Out] byte[] data,
        nuint dataSize,
        uint rotateCount,
        uint isLeft);

    /// <summary>
    /// Auto-detect and decrypt simple encryption.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticAutoDecrypt(
        [In, Out] byte[] data,
        nuint dataSize,
        out NexusDecryptInfo decryptInfo);

    #endregion

    #region Decompression

    /// <summary>
    /// Decompress data (auto-detect algorithm).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompress(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Decompress LZMA data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompressLzma(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Decompress zlib data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompressZlib(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Decompress APLib data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompressAplib(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Decompress LZO data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompressLzo(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Decompress LZSS data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDecompressLzss(
        [In] byte[] compressedData,
        nuint compressedSize,
        [In, Out] byte[]? outputBuffer,
        nuint outputSize,
        out nuint decompressedSize);

    /// <summary>
    /// Detect compression algorithm.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticDetectCompression(
        [In] byte[] data,
        nuint dataSize,
        out NexusCompressionType type,
        out nuint estimatedSize);

    #endregion

    #region Hashing

    /// <summary>
    /// Calculate CRC32.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashCrc32(
        [In] byte[] data,
        nuint dataSize,
        out uint crc32);

    /// <summary>
    /// Calculate MD5.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashMd5(
        [In] byte[] data,
        nuint dataSize,
        [Out] byte[] hash);

    /// <summary>
    /// Calculate SHA1.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashSha1(
        [In] byte[] data,
        nuint dataSize,
        [Out] byte[] hash);

    /// <summary>
    /// Calculate SHA256.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashSha256(
        [In] byte[] data,
        nuint dataSize,
        [Out] byte[] hash);

    /// <summary>
    /// Calculate SHA512.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashSha512(
        [In] byte[] data,
        nuint dataSize,
        [Out] byte[] hash);

    /// <summary>
    /// Calculate file hash.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticHashFile(
        string filePath,
        NexusHashType hashType,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder hashString,
        nuint hashStringSize);

    /// <summary>
    /// Calculate memory region hash.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticHashMemory(
        IntPtr processHandle,
        ulong address,
        nuint size,
        NexusHashType hashType,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder hashString,
        nuint hashStringSize);

    /// <summary>
    /// Calculate import hash (imphash).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticHashImports(
        string filePath,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder imphash,
        nuint imphashSize);

    /// <summary>
    /// Calculate section hashes.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticHashSections(
        string filePath,
        NexusHashType hashType,
        [In, Out] NexusSectionHash[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Entropy Analysis

    /// <summary>
    /// Calculate entropy of data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticEntropy(
        [In] byte[] data,
        nuint dataSize,
        out double entropy);

    /// <summary>
    /// Calculate entropy of file sections.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticEntropyFile(
        string filePath,
        [In, Out] NexusSectionEntropy[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Calculate sliding window entropy.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticEntropyScan(
        [In] byte[] data,
        nuint dataSize,
        nuint windowSize,
        [In, Out] double[]? entropyBuffer,
        nuint bufferCount,
        out nuint sampleCount);

    /// <summary>
    /// Find high entropy regions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticFindHighEntropy(
        [In] byte[] data,
        nuint dataSize,
        double threshold,
        [In, Out] NexusEntropyRegion[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region String Extraction

    /// <summary>
    /// Extract ASCII strings from data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticExtractStringsA(
        [In] byte[] data,
        nuint dataSize,
        uint minLength,
        [In, Out] NexusExtractedString[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Extract Unicode strings from data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticExtractStringsW(
        [In] byte[] data,
        nuint dataSize,
        uint minLength,
        [In, Out] NexusExtractedString[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Extract all strings from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticExtractStringsFile(
        string filePath,
        uint minLength,
        NexusStringType stringType,
        [In, Out] NexusExtractedString[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Extract URLs and paths from data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StaticExtractUrls(
        [In] byte[] data,
        nuint dataSize,
        [In, Out] NexusExtractedString[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Signature Detection

    /// <summary>
    /// Match YARA rules against data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticYaraScan(
        [In] byte[] data,
        nuint dataSize,
        string rulesPath,
        [In, Out] NexusYaraMatch[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Match YARA rules against file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticYaraScanFile(
        string filePath,
        string rulesPath,
        [In, Out] NexusYaraMatch[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Detect packer/protector signatures.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticDetectPacker(
        string filePath,
        [In, Out] NexusPackerDetection[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Detect compiler signatures.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_StaticDetectCompiler(
        string filePath,
        out NexusCompilerInfo compilerInfo);

    #endregion
}

#region Static Analysis Enums and Structs

/// <summary>
/// Compression type.
/// </summary>
public enum NexusCompressionType : uint
{
    Unknown = 0,
    None = 1,
    Zlib = 2,
    Gzip = 3,
    Lzma = 4,
    Lzma2 = 5,
    Aplib = 6,
    Lzo = 7,
    Lzss = 8,
    Lzw = 9,
    Bzip2 = 10,
    Deflate = 11,
    Upx = 12
}

/// <summary>
/// Hash type.
/// </summary>
public enum NexusHashType : uint
{
    Crc32 = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
    Sha512 = 4,
    Imphash = 5
}

/// <summary>
/// String type for extraction.
/// </summary>
[Flags]
public enum NexusStringType : uint
{
    Ascii = 1,
    Unicode = 2,
    Both = 3
}

/// <summary>
/// Decryption information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusDecryptInfo
{
    public uint WasEncrypted;           // Data was encrypted
    public uint Algorithm;              // Detected algorithm (0=XOR, 1=ADD, etc)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Key;                  // Detected key
    public uint KeyLength;              // Key length
    public uint Confidence;             // Detection confidence
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string AlgorithmName;        // Algorithm name
}

/// <summary>
/// Section hash result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSectionHash
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 9)]
    public string SectionName;          // Section name
    public uint SectionIndex;           // Section index
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
    public string Hash;                 // Hash string
    public nuint Size;                  // Section size
}

/// <summary>
/// Section entropy result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSectionEntropy
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 9)]
    public string SectionName;          // Section name
    public uint SectionIndex;           // Section index
    public double Entropy;              // Entropy value (0-8)
    public nuint Size;                  // Section size
    public uint IsPacked;               // Likely packed (entropy > 7.0)
}

// NexusEntropyRegion is defined in NexusEngine.Pattern.cs

/// <summary>
/// Extracted string.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusExtractedString
{
    public nuint Offset;                // Offset in data
    public uint Length;                 // String length
    public uint IsUnicode;              // Unicode string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Value;                // String value (truncated if longer)
    public uint StringType;             // Classification (path, url, etc)
}

/// <summary>
/// YARA match result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusYaraMatch
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string RuleName;             // Rule name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Namespace;            // Rule namespace
    public nuint Offset;                // Match offset
    public nuint Length;                // Match length
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string StringId;             // Matching string identifier
}

/// <summary>
/// Packer detection result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPackerDetection
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Packer name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Version;              // Version (if detected)
    public uint Confidence;             // Detection confidence (0-100)
    public nuint SignatureOffset;       // Signature location
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Details;              // Additional details
}

/// <summary>
/// Compiler detection result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCompilerInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Compiler;             // Compiler name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Version;              // Compiler version
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Language;             // Source language
    public uint LinkerVersion;          // Linker version
    public uint Confidence;             // Detection confidence
    public uint IsDebugBuild;           // Debug build detected
    public uint HasPdb;                 // Has PDB info
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string PdbPath;              // PDB path (if present)
}

#endregion
