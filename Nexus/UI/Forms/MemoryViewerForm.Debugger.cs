using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Breakpoint Management

    private void MnuSetBreakpoint_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Get the address to set breakpoint on (use disasm selection if in disasm view, otherwise hex selection)
        ulong breakpointAddress = _lastActiveViewIsHex ? _hexSelectedAddress : _disasmSelectedAddress;
        if (breakpointAddress == 0)
            breakpointAddress = _baseAddress;

        // Toggle breakpoint
        if (_breakpoints.ContainsKey(breakpointAddress))
        {
            // Remove breakpoint
            RemoveBreakpoint(breakpointAddress);
        }
        else
        {
            // Add breakpoint
            AddBreakpoint(breakpointAddress);
        }

        // Refresh disassembly to show/hide breakpoint marker
        pnlDisasm.Invalidate();
    }

    private void AddBreakpoint(ulong address)
    {
        if (_breakpoints.ContainsKey(address)) return;

        // Ensure debugger is attached and ready
        if (!EnsureDebuggerAttached()) return;

        // Queue the breakpoint to be set by the debug thread
        _pendingAddBp.Enqueue(address);

        // Mark as pending in the UI (will be confirmed by debug thread)
        _breakpoints[address] = 0;  // 0 = pending
        System.Diagnostics.Debug.WriteLine($"Breakpoint queued at {address:X}");
    }

    private void RemoveBreakpoint(ulong address)
    {
        if (!_breakpoints.ContainsKey(address)) return;

        // Queue for removal
        _pendingRemoveBp.Enqueue(address);
        _breakpoints.Remove(address);
        System.Diagnostics.Debug.WriteLine($"Breakpoint removal queued at {address:X}");

        // If no more breakpoints and debug ready, signal stop
        if (_breakpoints.Count == 0 && _debugReady)
        {
            // Don't detach here - let the debug thread handle it
            _debugging = false;
        }
    }

    #endregion

    #region Debugger Attach/Detach

    private bool EnsureDebuggerAttached()
    {
        if (_debugThread != null && _debugThread.IsAlive) return true;

        // Clear any stale state
        _debugReady = false;
        _debugging = true;
        _isPaused = false;

        // Start debug thread - it will attach the debugger
        _debugThread = new Thread(DebugThreadLoop)
        {
            IsBackground = true,
            Name = "MemoryViewerDebugThread"
        };
        _debugThread.Start();

        // Wait for debugger to be ready (with timeout)
        int waitCount = 0;
        while (!_debugReady && _debugging && waitCount < 50)
        {
            Thread.Sleep(20);
            waitCount++;
        }

        if (!_debugReady)
        {
            _debugging = false;
            return false;
        }

        return true;
    }

    private void DetachDebugger()
    {
        _debugging = false;
        _isPaused = false;
        _debugReady = false;

        // Wait for thread to exit
        _debugThread?.Join(1000);
        _debugThread = null;
        _debuggerHandle = IntPtr.Zero;
    }

    #endregion

    #region Debug Thread Loop

    private void DebugThreadLoop()
    {
        const uint DBG_CONTINUE = 0x00010002;
        const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        IntPtr handle = IntPtr.Zero;

        try
        {
            // Attach debugger on THIS thread (required by Windows)
            var attachResult = NexusEngine.Nexus_DebuggerAttach(_processHandle, out handle);
            if (attachResult != NexusResult.OK && attachResult != NexusResult.Success)
            {
                try
                {
                    BeginInvoke(() =>
                    {
                        MessageBox.Show($"Failed to attach debugger: {attachResult}\n\n" +
                            "Only one debugger can be attached at a time.\n" +
                            "Close any 'Find what accesses/writes' windows first.",
                            "Debugger Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    });
                }
                catch { }
                _debugging = false;
                return;
            }

            _debuggerHandle = handle;

            // Drain initial events (CREATE_PROCESS, LOAD_DLL, etc.)
            int initEvents = 0;
            while (_debugging && initEvents < 500)
            {
                var waitResult = NexusEngine.Nexus_WaitForDebugEvent(handle, out NexusDebugEvent evt, 10);
                if (waitResult != NexusResult.OK && waitResult != NexusResult.Success) break;
                NexusEngine.Nexus_ContinueDebugEvent(handle, evt.ThreadId, (int)DBG_CONTINUE);
                initEvents++;
            }

            // Now ready for breakpoints
            _debugReady = true;

            // Main debug loop
            while (_debugging)
            {
                try
                {
                    // Process pending breakpoint additions
                    while (_pendingAddBp.TryDequeue(out ulong addAddr))
                    {
                        var bpResult = NexusEngine.Nexus_SetBreakpoint(
                            handle,
                            addAddr,
                            (int)NexusBreakpointType.HardwareExec,
                            (int)NexusBreakpointSize.Size1,
                            out ulong bpId);

                        if (bpResult == NexusResult.OK || bpResult == NexusResult.Success)
                        {
                            _breakpoints[addAddr] = bpId;
                            System.Diagnostics.Debug.WriteLine($"Breakpoint set at {addAddr:X}, id={bpId}");
                        }
                        else
                        {
                            _breakpoints.Remove(addAddr);
                            try
                            {
                                BeginInvoke(() =>
                                {
                                    MessageBox.Show($"Failed to set breakpoint at {addAddr:X}: {bpResult}",
                                        "Breakpoint Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    pnlDisasm.Invalidate();
                                });
                            }
                            catch { }
                        }
                    }

                    // Process pending breakpoint removals
                    while (_pendingRemoveBp.TryDequeue(out ulong removeAddr))
                    {
                        // Find and remove the breakpoint
                        foreach (var kvp in _breakpoints.ToList())
                        {
                            if (kvp.Key == removeAddr && kvp.Value != 0)
                            {
                                NexusEngine.Nexus_RemoveBreakpoint(handle, kvp.Value);
                                _breakpoints.Remove(removeAddr);
                                break;
                            }
                        }
                    }

                    // Wait for debug event
                    var result = NexusEngine.Nexus_WaitForDebugEvent(handle, out NexusDebugEvent evt, 50);
                    if (result != NexusResult.OK && result != NexusResult.Success) continue;

                    uint continueStatus = DBG_CONTINUE;
                    var eventType = (NexusDebugEventType)evt.Type;

                    if (eventType == NexusDebugEventType.Breakpoint || eventType == NexusDebugEventType.SingleStep)
                    {
                        ulong hitAddress = evt.Address;

                        // Check if we're completing a step-over-breakpoint
                        if (_steppingOverBp)
                        {
                            _steppingOverBp = false;

                            // Re-arm the breakpoint we stepped over
                            if (_stepOverBpAddress != 0 && _breakpoints.ContainsKey(_stepOverBpAddress))
                            {
                                var bpResult = NexusEngine.Nexus_SetBreakpoint(
                                    handle, _stepOverBpAddress,
                                    (int)NexusBreakpointType.HardwareExec,
                                    (int)NexusBreakpointSize.Size1,
                                    out ulong newBpId);
                                if (bpResult == NexusResult.OK || bpResult == NexusResult.Success)
                                {
                                    _breakpoints[_stepOverBpAddress] = newBpId;
                                }
                            }

                            // If in single-step mode, show the dialog at new location
                            if (_singleStepMode)
                            {
                                ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                            }
                            // Otherwise just continue running
                        }
                        // Check if this is the step-out breakpoint (return address)
                        else if (_stepOutBreakpointAddress != 0 && hitAddress == _stepOutBreakpointAddress)
                        {
                            // Remove the step-out breakpoint
                            NexusEngine.Nexus_RemoveBreakpoint(handle, _stepOutBreakpointId);
                            System.Diagnostics.Debug.WriteLine($"Step-out complete at {hitAddress:X}");
                            _stepOutBreakpointAddress = 0;
                            _stepOutBreakpointId = 0;
                            ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                        }
                        // Check if this is one of our breakpoints
                        else if (_breakpoints.ContainsKey(hitAddress) && _breakpoints[hitAddress] != 0)
                        {
                            ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                        }
                        // Check if in single-step mode (user stepping through code)
                        else if (_singleStepMode)
                        {
                            ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                        }
                    }
                    else if (eventType == NexusDebugEventType.Exception)
                    {
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }

                    NexusEngine.Nexus_ContinueDebugEvent(handle, evt.ThreadId, (int)continueStatus);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"DebugThreadLoop error: {ex.Message}");
                }
            }
        }
        finally
        {
            // Cleanup - remove all breakpoints and detach
            foreach (var kvp in _breakpoints.ToList())
            {
                if (kvp.Value != 0)
                {
                    try { NexusEngine.Nexus_RemoveBreakpoint(handle, kvp.Value); } catch { }
                }
            }
            _breakpoints.Clear();

            if (handle != IntPtr.Zero)
            {
                try { NexusEngine.Nexus_DebuggerDetach(handle); } catch { }
            }
            _debuggerHandle = IntPtr.Zero;
            _debugReady = false;
        }
    }

    #endregion

    #region Breakpoint Dialog & Stepping

    private void ShowBreakpointDialog(IntPtr debugHandle, uint threadId, ulong hitAddress)
    {
        _isPaused = true;
        _pausedAtAddress = hitAddress;
        _continueAction = 0;

        // Get thread context for register display
        string registerText = "";
        var ctxResult = NexusEngine.Nexus_GetThreadContext(threadId, out CONTEXT64 ctx);
        if (ctxResult == NexusResult.OK || ctxResult == NexusResult.Success)
        {
            registerText = FormatRegisters(ctx);
        }
        else
        {
            registerText = $"(Could not get registers: {ctxResult})";
        }

        // Show dialog on UI thread
        try
        {
            BeginInvoke(() =>
            {
                try
                {
                    // Navigate to the hit address
                    GoToAddress(hitAddress);
                    pnlDisasm.Invalidate();

                    // Create custom dialog with registers and buttons
                    using var dialog = new Form
                    {
                        Text = "Breakpoint Hit",
                        Size = new Size(500, 440),
                        StartPosition = FormStartPosition.CenterParent,
                        FormBorderStyle = FormBorderStyle.Sizable,
                        MaximizeBox = true,
                        MinimizeBox = false
                    };

                    var lblInfo = new Label
                    {
                        Text = $"Breakpoint hit at {hitAddress:X}",
                        Location = new Point(20, 15),
                        AutoSize = true,
                        Font = new Font(Font.FontFamily, 10, FontStyle.Bold)
                    };

                    var txtRegisters = new TextBox
                    {
                        Location = new Point(20, 45),
                        Size = new Size(445, 260),
                        Multiline = true,
                        ReadOnly = true,
                        ScrollBars = ScrollBars.Vertical,
                        Font = new Font("Consolas", 9.5F),
                        Text = registerText,
                        Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
                    };
                    NexusTheme.StyleTextBox(txtRegisters);

                    // Row 1: Continue and Remove
                    var btnContinue = new Button
                    {
                        Text = "Continue (F5)",
                        Location = new Point(20, 315),
                        Size = new Size(110, 32),
                        Anchor = AnchorStyles.Bottom | AnchorStyles.Left
                    };
                    btnContinue.Click += (s, e) => { _continueAction = 1; dialog.Close(); };

                    var btnRemove = new Button
                    {
                        Text = "Remove BP",
                        Location = new Point(140, 315),
                        Size = new Size(110, 32),
                        Anchor = AnchorStyles.Bottom | AnchorStyles.Left
                    };
                    btnRemove.Click += (s, e) => { _continueAction = 3; dialog.Close(); };

                    // Row 2: Step Into, Step Over, Step Out
                    var btnStepInto = new Button
                    {
                        Text = "Step Into (F7)",
                        Location = new Point(20, 355),
                        Size = new Size(110, 32),
                        Anchor = AnchorStyles.Bottom | AnchorStyles.Left
                    };
                    btnStepInto.Click += (s, e) => { _continueAction = 2; dialog.Close(); };

                    var btnStepOver = new Button
                    {
                        Text = "Step Over (F8)",
                        Location = new Point(140, 355),
                        Size = new Size(110, 32),
                        Anchor = AnchorStyles.Bottom | AnchorStyles.Left
                    };
                    btnStepOver.Click += (s, e) => { _continueAction = 4; dialog.Close(); };

                    var btnStepOut = new Button
                    {
                        Text = "Step Out",
                        Location = new Point(260, 355),
                        Size = new Size(110, 32),
                        Anchor = AnchorStyles.Bottom | AnchorStyles.Left
                    };
                    btnStepOut.Click += (s, e) => { _continueAction = 5; dialog.Close(); };

                    dialog.Controls.AddRange([lblInfo, txtRegisters, btnContinue, btnRemove,
                        btnStepInto, btnStepOver, btnStepOut]);
                    dialog.AcceptButton = btnContinue;
                    dialog.ShowDialog(this);
                }
                catch { }
                finally
                {
                    _isPaused = false;
                }
            });
        }
        catch { _isPaused = false; }

        // Wait for user response
        while (_isPaused && _debugging)
        {
            Thread.Sleep(50);
        }

        // Process user's choice
        // Actions: 1=Continue, 2=Step Into, 3=Remove BP, 4=Step Over, 5=Step Out
        bool isAtBreakpoint = _breakpoints.ContainsKey(hitAddress) && _breakpoints[hitAddress] != 0;

        if (_continueAction == 3) // Remove breakpoint
        {
            if (isAtBreakpoint)
            {
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints.Remove(hitAddress);
                try { BeginInvoke(() => pnlDisasm.Invalidate()); } catch { }
            }
            _singleStepMode = false;
        }
        else if (_continueAction == 1) // Continue
        {
            _singleStepMode = false;

            // If at a breakpoint, we need to step over it first
            if (isAtBreakpoint)
            {
                // Remove the breakpoint temporarily
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints[hitAddress] = 0; // Mark as pending re-arm

                // Set up step-over state
                _steppingOverBp = true;
                _stepOverBpAddress = hitAddress;
                _stepOverBpId = bpId;

                // Enable single-step via trap flag
                NexusEngine.Nexus_SingleStep(debugHandle, threadId);
            }
        }
        else if (_continueAction == 5) // Step Out - set breakpoint at return address
        {
            _singleStepMode = false;

            // Get thread context to read RSP (return address is at [RSP])
            var stepOutCtxResult = NexusEngine.Nexus_GetThreadContext(threadId, out CONTEXT64 stepOutCtx);
            if (stepOutCtxResult == NexusResult.OK || stepOutCtxResult == NexusResult.Success)
            {
                // Read return address from [RSP]
                byte[] retAddrBytes = new byte[8];
                NexusResult readResult;
                nuint bytesRead;
                unsafe
                {
                    fixed (byte* ptr = retAddrBytes)
                    {
                        readResult = NexusEngine.Nexus_ReadMemory(
                            _processHandle, stepOutCtx.Rsp, (IntPtr)ptr, 8, out bytesRead);
                    }
                }

                if ((readResult == NexusResult.OK || readResult == NexusResult.Success) && bytesRead >= 8)
                {
                    ulong returnAddress = BitConverter.ToUInt64(retAddrBytes, 0);

                    // Set a temporary breakpoint at the return address
                    var bpResult = NexusEngine.Nexus_SetBreakpoint(
                        debugHandle,
                        returnAddress,
                        (int)NexusBreakpointType.HardwareExec,
                        (int)NexusBreakpointSize.Size1,
                        out ulong stepOutBpId);

                    if (bpResult == NexusResult.OK || bpResult == NexusResult.Success)
                    {
                        _stepOutBreakpointAddress = returnAddress;
                        _stepOutBreakpointId = stepOutBpId;
                        System.Diagnostics.Debug.WriteLine($"Step-out breakpoint set at return address {returnAddress:X}");
                    }
                }
            }

            // If at a breakpoint, we need to step over it first
            if (isAtBreakpoint)
            {
                // Remove the breakpoint temporarily
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints[hitAddress] = 0; // Mark as pending re-arm

                // Set up step-over state
                _steppingOverBp = true;
                _stepOverBpAddress = hitAddress;
                _stepOverBpId = bpId;

                // Enable single-step via trap flag
                NexusEngine.Nexus_SingleStep(debugHandle, threadId);
            }
        }
        else if (_continueAction == 2 || _continueAction == 4) // Step Into or Step Over
        {
            // For now both behave as single-step (true step-over requires call detection)
            _singleStepMode = true;

            // If at a breakpoint, we need to step over it
            if (isAtBreakpoint)
            {
                // Remove the breakpoint temporarily
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints[hitAddress] = 0; // Mark as pending re-arm

                // Set up step-over state
                _steppingOverBp = true;
                _stepOverBpAddress = hitAddress;
                _stepOverBpId = bpId;
            }

            // Enable single-step via trap flag
            NexusEngine.Nexus_SingleStep(debugHandle, threadId);
        }
    }

    #endregion

    #region Register Formatting

    /// <summary>
    /// Formats register values from CONTEXT64 into a readable string.
    /// </summary>
    private static string FormatRegisters(CONTEXT64 ctx)
    {
        var sb = new System.Text.StringBuilder();

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
        sb.AppendLine();

        // Segment registers
        sb.AppendLine("=== Segment Registers ===");
        sb.AppendLine($"CS = {ctx.SegCs:X4}  DS = {ctx.SegDs:X4}  ES = {ctx.SegEs:X4}");
        sb.AppendLine($"FS = {ctx.SegFs:X4}  GS = {ctx.SegGs:X4}  SS = {ctx.SegSs:X4}");
        sb.AppendLine();

        // Debug registers (if relevant)
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        {
            sb.AppendLine("=== Debug Registers ===");
            sb.AppendLine($"DR0 = {ctx.Dr0:X16}");
            sb.AppendLine($"DR1 = {ctx.Dr1:X16}");
            sb.AppendLine($"DR2 = {ctx.Dr2:X16}");
            sb.AppendLine($"DR3 = {ctx.Dr3:X16}");
            sb.AppendLine($"DR6 = {ctx.Dr6:X16}");
            sb.AppendLine($"DR7 = {ctx.Dr7:X16}");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Formats EFLAGS into readable flag names.
    /// </summary>
    private static string FormatEFlags(uint eflags)
    {
        var flags = new List<string>();
        if ((eflags & 0x0001) != 0) flags.Add("CF");  // Carry
        if ((eflags & 0x0004) != 0) flags.Add("PF");  // Parity
        if ((eflags & 0x0010) != 0) flags.Add("AF");  // Auxiliary
        if ((eflags & 0x0040) != 0) flags.Add("ZF");  // Zero
        if ((eflags & 0x0080) != 0) flags.Add("SF");  // Sign
        if ((eflags & 0x0100) != 0) flags.Add("TF");  // Trap
        if ((eflags & 0x0200) != 0) flags.Add("IF");  // Interrupt
        if ((eflags & 0x0400) != 0) flags.Add("DF");  // Direction
        if ((eflags & 0x0800) != 0) flags.Add("OF");  // Overflow
        return flags.Count > 0 ? string.Join(" ", flags) : "none";
    }

    #endregion
}
