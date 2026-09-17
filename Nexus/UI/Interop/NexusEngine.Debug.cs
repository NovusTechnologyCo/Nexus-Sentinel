// <file>
// <summary>
// P/Invoke bindings for debugger operations: attach/detach debugger, wait for debug events,
// continue execution, get/set thread context (CONTEXT64), stack walking, and step operations.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Debugger Operations

    /// <summary>
    /// Attach debugger to process. Creates debugger context and attaches.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DebuggerAttach(
        IntPtr processHandle,
        out IntPtr debuggerHandle);

    /// <summary>
    /// Detach debugger from process. Removes breakpoints and destroys context.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DebuggerDetach(IntPtr debuggerHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetBreakpoint(
        IntPtr debuggerHandle,
        ulong address,
        int type,
        int size,
        out ulong breakpointId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WaitForDebugEvent(
        IntPtr debuggerHandle,
        out NexusDebugEvent debugEvent,
        uint timeoutMs);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ContinueDebugEvent(
        IntPtr debuggerHandle,
        uint threadId,
        int continueStatus);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SingleStep(
        IntPtr debuggerHandle,
        uint threadId);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveAllBreakpoints(
        IntPtr debuggerHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EnableBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId,
        int enabled);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId,
        out NexusBreakpoint breakpoint);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetBreakpoints(
        IntPtr debuggerHandle,
        [In, Out] NexusBreakpoint[] buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Module-Relative Breakpoints

    /// <summary>
    /// Set a module-relative breakpoint.
    /// The breakpoint is stored as module + RVA and will survive module reloading.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SetBreakpointModule(
        IntPtr debuggerHandle,
        [MarshalAs(UnmanagedType.LPWStr)] string moduleName,
        ulong rva,
        int type,
        int size,
        out ulong breakpointId);

    /// <summary>
    /// Set a breakpoint by symbol name (module!function pattern).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetBreakpointSymbol(
        IntPtr debuggerHandle,
        [MarshalAs(UnmanagedType.LPStr)] string symbol,
        int type,
        int size,
        out ulong breakpointId);

    /// <summary>
    /// Convert an absolute breakpoint to module-relative.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ConvertBreakpointToModuleRelative(
        IntPtr debuggerHandle,
        ulong breakpointId);

    /// <summary>
    /// Resolve all unresolved module-relative breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResolveModuleBreakpoints(
        IntPtr debuggerHandle,
        out nuint resolvedCount);

    /// <summary>
    /// Get list of unresolved module-relative breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetUnresolvedBreakpoints(
        IntPtr debuggerHandle,
        [In, Out] NexusBreakpoint[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Thread Context Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetThreadContext(
        uint threadId,
        IntPtr context,
        nuint contextSize);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetThreadContext(
        uint threadId,
        IntPtr context,
        nuint contextSize);

    /// <summary>
    /// Gets thread context into a CONTEXT64 structure.
    /// </summary>
    public static NexusResult Nexus_GetThreadContext(uint threadId, out CONTEXT64 context)
    {
        const int CONTEXT64_SIZE = 1232;
        IntPtr ptr = Marshal.AllocHGlobal(CONTEXT64_SIZE);
        try
        {
            Marshal.WriteInt32(ptr, 48, (int)CONTEXT_ALL);
            var result = Nexus_GetThreadContext(threadId, ptr, (nuint)CONTEXT64_SIZE);
            if (result == NexusResult.OK)
            {
                context = Marshal.PtrToStructure<CONTEXT64>(ptr);
            }
            else
            {
                context = default;
            }
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Sets thread context from a CONTEXT64 structure.
    /// </summary>
    public static NexusResult Nexus_SetThreadContext(uint threadId, CONTEXT64 context)
    {
        const int CONTEXT64_SIZE = 1232;
        IntPtr ptr = Marshal.AllocHGlobal(CONTEXT64_SIZE);
        try
        {
            Marshal.StructureToPtr(context, ptr, false);
            return Nexus_SetThreadContext(threadId, ptr, (nuint)CONTEXT64_SIZE);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    // Context flags
    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x0001;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x0002;
    public const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x0004;
    public const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x0008;
    public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x0010;
    public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    public const uint CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

    #endregion

    #region Stack Walker Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StackWalkerCreate(
        IntPtr processHandle,
        out IntPtr walkerHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_StackWalkerDestroy(IntPtr walkerHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_StackWalk(
        IntPtr walkerHandle,
        uint threadId,
        [In, Out] NexusStackFrame[] frames,
        nuint maxFrames,
        out nuint frameCount);

    #endregion
}
