// <file>
// <summary>
// P/Invoke bindings for AVX-512 extended register context. Provides access to ZMM0-ZMM31
// registers and opmask registers (K0-K7) for processors that support AVX-512 extensions.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region AVX-512 Support Detection

    /// <summary>
    /// Check if CPU supports AVX-512.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512IsSupported(
        out uint isSupported);

    /// <summary>
    /// Get AVX-512 feature flags.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetFeatures(
        out NexusAvx512Features features);

    /// <summary>
    /// Check if target process uses AVX-512.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512ProcessSupported(
        IntPtr processHandle,
        out uint isSupported);

    #endregion

    #region AVX-512 Context Access

    /// <summary>
    /// Get full AVX-512 context for thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetContext(
        IntPtr processHandle,
        uint threadId,
        out NexusAvx512Context context);

    /// <summary>
    /// Set full AVX-512 context for thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetContext(
        IntPtr processHandle,
        uint threadId,
        ref NexusAvx512Context context);

    /// <summary>
    /// Get single ZMM register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetZmm(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        out NexusZmmRegister value);

    /// <summary>
    /// Set single ZMM register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetZmm(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        ref NexusZmmRegister value);

    /// <summary>
    /// Get opmask register (k0-k7).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetOpmask(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        out ulong value);

    /// <summary>
    /// Set opmask register (k0-k7).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetOpmask(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        ulong value);

    #endregion

    #region YMM Access (AVX-256 high portions)

    /// <summary>
    /// Get YMM register high portion (upper 128 bits).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetYmmHigh(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        out NexusXmmRegister value);

    /// <summary>
    /// Set YMM register high portion.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetYmmHigh(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        ref NexusXmmRegister value);

    /// <summary>
    /// Get full YMM register (256 bits).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetYmm(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        out NexusYmmRegister value);

    /// <summary>
    /// Set full YMM register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetYmm(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        ref NexusYmmRegister value);

    #endregion

    #region ZMM High Registers (ZMM16-ZMM31)

    /// <summary>
    /// Get ZMM16-ZMM31 register (x64 only).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetZmmHi(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        out NexusZmmRegister value);

    /// <summary>
    /// Set ZMM16-ZMM31 register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetZmmHi(
        IntPtr processHandle,
        uint threadId,
        uint registerIndex,
        ref NexusZmmRegister value);

    #endregion

    #region MXCSR and Control

    /// <summary>
    /// Get MXCSR register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetMxcsr(
        IntPtr processHandle,
        uint threadId,
        out uint mxcsr);

    /// <summary>
    /// Set MXCSR register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetMxcsr(
        IntPtr processHandle,
        uint threadId,
        uint mxcsr);

    /// <summary>
    /// Get XCR0 (Extended Control Register).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetXcr0(
        out ulong xcr0);

    #endregion

    #region Register Display

    /// <summary>
    /// Format ZMM register as string.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512FormatZmm(
        ref NexusZmmRegister reg,
        NexusAvx512DisplayFormat format,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder output,
        nuint outputSize);

    /// <summary>
    /// Parse string to ZMM register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_Avx512ParseZmm(
        string input,
        NexusAvx512DisplayFormat format,
        out NexusZmmRegister reg);

    /// <summary>
    /// Compare two ZMM registers.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512CompareZmm(
        ref NexusZmmRegister reg1,
        ref NexusZmmRegister reg2,
        out uint areEqual,
        out uint diffMask);

    #endregion

    #region Bulk Operations

    /// <summary>
    /// Get all ZMM registers at once.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetAllZmm(
        IntPtr processHandle,
        uint threadId,
        [In, Out, MarshalAs(UnmanagedType.LPArray, SizeConst = 32)] NexusZmmRegister[] registers,
        out uint registerCount);

    /// <summary>
    /// Set all ZMM registers at once.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetAllZmm(
        IntPtr processHandle,
        uint threadId,
        [In, MarshalAs(UnmanagedType.LPArray, SizeConst = 32)] NexusZmmRegister[] registers,
        uint registerCount);

    /// <summary>
    /// Get all opmask registers.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512GetAllOpmask(
        IntPtr processHandle,
        uint threadId,
        [In, Out, MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] ulong[] masks);

    /// <summary>
    /// Set all opmask registers.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512SetAllOpmask(
        IntPtr processHandle,
        uint threadId,
        [In, MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] ulong[] masks);

    /// <summary>
    /// Clear all AVX-512 registers.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_Avx512ClearAll(
        IntPtr processHandle,
        uint threadId);

    #endregion
}

#region AVX-512 Enums and Structs

/// <summary>
/// AVX-512 feature flags.
/// </summary>
[Flags]
public enum NexusAvx512Features : uint
{
    None = 0,
    Avx512F = 1,                // Foundation
    Avx512Cd = 2,               // Conflict Detection
    Avx512Er = 4,               // Exponential and Reciprocal
    Avx512Pf = 8,               // Prefetch
    Avx512Bw = 16,              // Byte and Word
    Avx512Dq = 32,              // Doubleword and Quadword
    Avx512Vl = 64,              // Vector Length Extensions
    Avx512Ifma = 128,           // Integer Fused Multiply-Add
    Avx512Vbmi = 256,           // Vector Bit Manipulation Instructions
    Avx512Vbmi2 = 512,          // VBMI2
    Avx512Vnni = 1024,          // Vector Neural Network Instructions
    Avx512Bitalg = 2048,        // Bit Algorithms
    Avx512Vpopcntdq = 4096,     // VPOPCNTDQ
    Avx512Bf16 = 8192,          // BFloat16
    Avx512Vp2Intersect = 16384, // VP2INTERSECT
    Avx512Fp16 = 32768          // FP16
}

/// <summary>
/// Display format for AVX-512 registers.
/// </summary>
public enum NexusAvx512DisplayFormat : uint
{
    Hex = 0,                    // Hexadecimal
    Float32 = 1,                // 16 x float
    Float64 = 2,                // 8 x double
    Int8 = 3,                   // 64 x int8
    Int16 = 4,                  // 32 x int16
    Int32 = 5,                  // 16 x int32
    Int64 = 6,                  // 8 x int64
    UInt8 = 7,                  // 64 x uint8
    UInt16 = 8,                 // 32 x uint16
    UInt32 = 9,                 // 16 x uint32
    UInt64 = 10                 // 8 x uint64
}

/// <summary>
/// XMM register (128 bits).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusXmmRegister
{
    public ulong Low;                   // Bits 0-63
    public ulong High;                  // Bits 64-127
}

/// <summary>
/// YMM register (256 bits).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusYmmRegister
{
    public NexusXmmRegister Low;        // Bits 0-127 (XMM)
    public NexusXmmRegister High;       // Bits 128-255
}

/// <summary>
/// ZMM register (512 bits).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusZmmRegister
{
    public NexusYmmRegister Low;        // Bits 0-255 (YMM)
    public NexusYmmRegister High;       // Bits 256-511

    // Helper accessors for different data types
    public ulong GetQword(int index) => index switch
    {
        0 => Low.Low.Low,
        1 => Low.Low.High,
        2 => Low.High.Low,
        3 => Low.High.High,
        4 => High.Low.Low,
        5 => High.Low.High,
        6 => High.High.Low,
        7 => High.High.High,
        _ => 0
    };
}

/// <summary>
/// Full AVX-512 context.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusAvx512Context
{
    // ZMM0-ZMM15 (or ZMM0-ZMM7 on x86)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public NexusZmmRegister[] Zmm;

    // ZMM16-ZMM31 (x64 only)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public NexusZmmRegister[] ZmmHi;

    // Opmask registers k0-k7
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public ulong[] Opmask;

    // Control and status
    public uint Mxcsr;                  // MXCSR register
    public uint MxcsrMask;              // MXCSR mask
    public ulong Xcr0;                  // XCR0 register

    // Feature flags
    public uint Is64Bit;                // 64-bit context
    public uint HasZmmHi;               // Has ZMM16-31
    public NexusAvx512Features Features; // Supported features
}

#endregion
