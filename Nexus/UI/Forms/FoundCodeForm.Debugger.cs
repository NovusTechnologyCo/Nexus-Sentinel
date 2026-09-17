// <file>
// <summary>
// Debugger attachment, breakpoint monitoring, and instruction capture logic for FoundCodeForm.
// </summary>
// </file>
using Nexus.UI.Interop;
using System.Text;


namespace Nexus.UI.Forms;

public partial class FoundCodeForm
{
    private void StartMonitoring()
    {
        if (_monitoring) return;
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process handle available.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // IMPORTANT: Windows requires DebugActiveProcess and WaitForDebugEvent
        // to be called from the SAME thread. So we do ALL debug operations
        // on the background thread.
        _monitoring = true;
        _capturing = true;
        _debugThread = new Thread(DebugThreadMain)
        {
            IsBackground = true,
            Name = "FoundCodeDebugThread"
        };
        _debugThread.Start();

        // Update UI
        btnOK.Text = "Stop";
        string typeText = _breakpointType == NexusBreakpointType.HardwareWrite ? "writes" : "accesses";
        memoInfo.Text = $"Monitoring {typeText} to address {_watchedAddress:X}...\r\n" +
            "Trigger the value change in the target application.";
    }

    private void StopMonitoring()
    {
        // Stop capturing new hits
        _capturing = false;

        // Remove the breakpoint so we don't get more hits
        // But keep the debug loop running to drain events
        var handle = _debuggerHandle;
        var bpId = _breakpointId;
        if (handle != IntPtr.Zero && bpId != 0)
        {
            _breakpointId = 0;  // Clear first to prevent double-remove
            try
            {
                NexusEngine.Nexus_RemoveBreakpoint(handle, bpId);
            }
            catch { /* Ignore */ }
        }

        // Start grace period countdown (like CE's deletecountdown)
        // The debug loop will continue draining events during this period
        _cleanupCountdown = CleanupGracePeriodIterations;

        // Update UI
        try
        {
            if (!IsDisposed && !Disposing)
            {
                btnOK.Text = "Close";
                memoInfo.Text += "\r\n\r\nMonitoring stopped.";
            }
        }
        catch { /* Ignore */ }
    }

    private void DebugThreadMain()
    {
        const uint DBG_CONTINUE = 0x00010002;

        try
        {
            // Phase 1: Attach debugger (MUST be on same thread as WaitForDebugEvent)
            var result = NexusEngine.Nexus_DebuggerAttach(_processHandle, out _debuggerHandle);
            if (result != NexusResult.OK && result != NexusResult.Success)
            {
                try
                {
                    BeginInvoke(() =>
                    {
                        try
                        {
                            if (!IsDisposed)
                            {
                                MessageBox.Show($"Failed to attach debugger: {result}\n\n" +
                                    "Only one breakpoint monitor can be active at a time.\n" +
                                    "Please close any existing 'Find out what accesses/writes' windows first.",
                                    "Debugger Already Attached", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                memoInfo.Text = "Failed to attach - close other breakpoint monitors first.";
                            }
                        }
                        catch { /* Form may be disposing */ }
                    });
                }
                catch { /* Form may be disposed */ }
                _debuggerHandle = IntPtr.Zero;
                _monitoring = false;
                return;
            }

            // Phase 2: Drain initial debug events (CREATE_PROCESS, LOAD_DLL, etc.)
            // These must be handled before we can set breakpoints
            int initEvents = 0;
            while (_monitoring && _debuggerHandle != IntPtr.Zero && initEvents < 500)
            {
                var waitResult = NexusEngine.Nexus_WaitForDebugEvent(
                    _debuggerHandle,
                    out NexusDebugEvent evt,
                    10); // Very short timeout

                if (waitResult != NexusResult.OK && waitResult != NexusResult.Success)
                {
                    // No more pending events - process is ready
                    break;
                }

                // Continue this event immediately
                NexusEngine.Nexus_ContinueDebugEvent(_debuggerHandle, evt.ThreadId, (int)DBG_CONTINUE);
                initEvents++;
            }

            // Phase 3: Now set the breakpoint
            var bpSize = NexusBreakpointSize.Size4;
            var bpResult = NexusEngine.Nexus_SetBreakpoint(
                _debuggerHandle,
                _watchedAddress,
                (int)_breakpointType,
                (int)bpSize,
                out _breakpointId);

            if (bpResult != NexusResult.OK && bpResult != NexusResult.Success)
            {
                try
                {
                    BeginInvoke(() =>
                    {
                        try
                        {
                            if (!IsDisposed)
                            {
                                MessageBox.Show($"Failed to set breakpoint: {bpResult}\n\n" +
                                    "All hardware breakpoint slots may be in use.",
                                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                        }
                        catch { /* Form may be disposing */ }
                    });
                }
                catch { /* Form may be disposed */ }
                // Still need to detach before returning
                CleanupDebugger();
                return;
            }

            // Phase 4: Normal debug event loop - monitor for breakpoint hits
            DebugEventLoop();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"DebugThreadMain exception: {ex}");
        }
        finally
        {
            // IMPORTANT: Cleanup must happen on the same thread that attached
            CleanupDebugger();
        }
    }

    private void CleanupDebugger()
    {
        // Atomic check-and-set to prevent double cleanup (thread-safe)
        if (Interlocked.Exchange(ref _cleanupDone, 1) == 1)
            return; // Already cleaned up

        _monitoring = false;
        _debuggerHandle = IntPtr.Zero;
        _breakpointId = 0;

        // Actual cleanup is done in DoCleanup called from DebugEventLoop
        // This just marks that cleanup has been initiated
    }

    private void DebugEventLoop()
    {
        const uint DBG_CONTINUE = 0x00010002;
        const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        // Capture handle at start - use this throughout the loop
        var handle = _debuggerHandle;
        if (handle == IntPtr.Zero) return;

        NexusDebugEvent lastEvent = default;
        bool hasUnhandledEvent = false;

        // Loop continues while:
        // 1. _monitoring is true (form not closing), OR
        // 2. _cleanupCountdown > 0 (grace period to drain events after stop)
        while (_monitoring || _cleanupCountdown > 0)
        {
            try
            {
                // Decrement grace period countdown if active
                if (!_capturing && _cleanupCountdown > 0)
                {
                    _cleanupCountdown--;
                }

                var waitResult = NexusEngine.Nexus_WaitForDebugEvent(
                    handle,
                    out NexusDebugEvent evt,
                    100); // 100ms timeout

                if (waitResult != NexusResult.OK && waitResult != NexusResult.Success)
                {
                    // Timeout - check if we should exit
                    if (!_monitoring && _cleanupCountdown <= 0) break;
                    continue;
                }

                // Check if we should stop BEFORE continuing
                // This leaves the target suspended so we can safely cleanup
                if (!_monitoring && _cleanupCountdown <= 0)
                {
                    lastEvent = evt;
                    hasUnhandledEvent = true;
                    break;
                }

                uint continueStatus = DBG_CONTINUE;

                // Handle the event
                try
                {
                    var eventType = (NexusDebugEventType)evt.Type;

                    if (eventType == NexusDebugEventType.Breakpoint ||
                        eventType == NexusDebugEventType.SingleStep)
                    {
                        // Only capture if still capturing (not stopped)
                        if (_capturing)
                        {
                            CaptureAccessingInstruction(evt);
                        }
                        // Otherwise we're in grace period - just drain the event
                    }
                    else if (eventType == NexusDebugEventType.Exception)
                    {
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Event handling error: {ex.Message}");
                }

                // Continue the debug event
                try
                {
                    NexusEngine.Nexus_ContinueDebugEvent(handle, evt.ThreadId, (int)continueStatus);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"ContinueDebugEvent error: {ex.Message}");
                    break;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"DebugEventLoop error: {ex.Message}");
            }
        }

        // Continue any pending event before cleanup
        if (hasUnhandledEvent)
        {
            try
            {
                NexusEngine.Nexus_ContinueDebugEvent(handle, lastEvent.ThreadId, (int)DBG_CONTINUE);
            }
            catch { /* Ignore */ }
        }

        // Now do proper cleanup - remove breakpoint if still set, then detach
        var bpId = _breakpointId;
        if (bpId != 0)
        {
            _breakpointId = 0;
            try
            {
                NexusEngine.Nexus_RemoveBreakpoint(handle, bpId);
            }
            catch { /* Ignore */ }
        }

        // Detach debugger
        try
        {
            NexusEngine.Nexus_DebuggerDetach(handle);
        }
        catch { /* Ignore */ }
    }

    private void CaptureAccessingInstruction(NexusDebugEvent evt)
    {
        // For hardware breakpoints, evt.Address is the instruction pointer (RIP/EIP)
        // that triggered the breakpoint. For hardware WRITE breakpoints, this is the
        // address of the instruction that performed the write.

        ulong instructionAddress = evt.Address;

        // Safety check - if address is 0 or looks invalid, skip
        if (instructionAddress == 0 || instructionAddress < 0x10000)
        {
            System.Diagnostics.Debug.WriteLine($"CaptureAccessingInstruction: Invalid address {instructionAddress:X}");
            return;
        }

        // Get thread context for register display
        string registersText = "";
        var ctxResult = NexusEngine.Nexus_GetThreadContext(evt.ThreadId, out CONTEXT64 ctx);
        if (ctxResult == NexusResult.OK || ctxResult == NexusResult.Success)
        {
            registersText = FormatRegisters(ctx);
        }

        try
        {
            // Try to disassemble the instruction
            var instructions = new NexusDisasmInstruction[1];
            var result = NexusEngine.Nexus_DisasmDecodeProcess(
                _processHandle,
                instructionAddress,
                1,
                instructions,
                out nuint count);

            if ((result == NexusResult.OK || result == NexusResult.Success) && count > 0)
            {
                var instr = instructions[0];
                string instrText = !string.IsNullOrEmpty(instr.Text) ? instr.Text : instr.Mnemonic;

                // Get original bytes
                int byteCount = Math.Min(instr.Length, (byte)(instr.Bytes?.Length ?? 0));
                byte[] originalBytes = new byte[byteCount];
                if (byteCount > 0 && instr.Bytes != null)
                {
                    Array.Copy(instr.Bytes, originalBytes, byteCount);
                }

                AddEntryThreadSafe(instr.Address, instrText, originalBytes, "", registersText);
                return;
            }

            // Fallback: read raw bytes if disassembly fails
            byte[] rawBytes = new byte[15];
            nuint bytesRead;

            unsafe
            {
                fixed (byte* ptr = rawBytes)
                {
                    var readResult = NexusEngine.Nexus_ReadMemory(
                        _processHandle,
                        instructionAddress,
                        (IntPtr)ptr,
                        (nuint)rawBytes.Length,
                        out bytesRead);

                    if (readResult != NexusResult.OK && readResult != NexusResult.Success)
                    {
                        AddEntryThreadSafe(instructionAddress, "???", [], "Could not read memory", registersText);
                        return;
                    }
                }
            }

            int showBytes = Math.Min(8, (int)bytesRead);
            byte[] instrBytes = new byte[showBytes];
            Array.Copy(rawBytes, instrBytes, showBytes);

            string bytesHex = BitConverter.ToString(instrBytes).Replace("-", " ");
            AddEntryThreadSafe(instructionAddress, bytesHex, instrBytes, "", registersText);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"CaptureAccessingInstruction exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Formats register values from CONTEXT64 into a readable string.
    /// </summary>
    private static string FormatRegisters(CONTEXT64 ctx)
    {
        var sb = new StringBuilder();

        // General purpose registers (one per line for clarity)
        sb.AppendLine("=== General Purpose Registers ===");
        sb.AppendLine($"RAX = {ctx.Rax:X16}");
        sb.AppendLine($"RBX = {ctx.Rbx:X16}");
        sb.AppendLine($"RCX = {ctx.Rcx:X16}");
        sb.AppendLine($"RDX = {ctx.Rdx:X16}");
        sb.AppendLine($"RSI = {ctx.Rsi:X16}");
        sb.AppendLine($"RDI = {ctx.Rdi:X16}");
        sb.AppendLine($"RBP = {ctx.Rbp:X16}");
        sb.AppendLine($"RSP = {ctx.Rsp:X16}");
        sb.AppendLine($"R8  = {ctx.R8:X16}");
        sb.AppendLine($"R9  = {ctx.R9:X16}");
        sb.AppendLine($"R10 = {ctx.R10:X16}");
        sb.AppendLine($"R11 = {ctx.R11:X16}");
        sb.AppendLine($"R12 = {ctx.R12:X16}");
        sb.AppendLine($"R13 = {ctx.R13:X16}");
        sb.AppendLine($"R14 = {ctx.R14:X16}");
        sb.AppendLine($"R15 = {ctx.R15:X16}");
        sb.AppendLine();

        // Instruction pointer and flags
        sb.AppendLine("=== Instruction Pointer & Flags ===");
        sb.AppendLine($"RIP    = {ctx.Rip:X16}");
        sb.AppendLine($"EFLAGS = {ctx.EFlags:X8}  [{FormatEFlags(ctx.EFlags)}]");

        return sb.ToString();
    }

    /// <summary>
    /// Formats EFLAGS into readable flag names.
    /// </summary>
    private static string FormatEFlags(uint eflags)
    {
        var flags = new List<string>();
        if ((eflags & 0x0001) != 0) flags.Add("CF");
        if ((eflags & 0x0004) != 0) flags.Add("PF");
        if ((eflags & 0x0010) != 0) flags.Add("AF");
        if ((eflags & 0x0040) != 0) flags.Add("ZF");
        if ((eflags & 0x0080) != 0) flags.Add("SF");
        if ((eflags & 0x0100) != 0) flags.Add("TF");
        if ((eflags & 0x0200) != 0) flags.Add("IF");
        if ((eflags & 0x0400) != 0) flags.Add("DF");
        if ((eflags & 0x0800) != 0) flags.Add("OF");
        return flags.Count > 0 ? string.Join(" ", flags) : "none";
    }

    private static string GetNullTerminatedString(byte[] bytes)
    {
        if (bytes == null) return "";
        int len = Array.IndexOf(bytes, (byte)0);
        if (len < 0) len = bytes.Length;
        return System.Text.Encoding.ASCII.GetString(bytes, 0, len);
    }

    private void AddEntryThreadSafe(ulong address, string instruction, byte[] originalBytes, string extraInfo = "", string registersText = "")
    {
        if (IsDisposed || !_monitoring) return;

        try
        {
            BeginInvoke(() =>
            {
                try
                {
                    if (!IsDisposed && _monitoring)
                    {
                        AddEntry(address, instruction, originalBytes, extraInfo, registersText);
                    }
                }
                catch { /* Form may be disposing */ }
            });
        }
        catch { /* Form may be disposed */ }
    }
}
