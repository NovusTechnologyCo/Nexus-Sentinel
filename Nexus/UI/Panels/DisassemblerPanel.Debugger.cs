// <file>
// <summary>
// Partial class for DisassemblerPanel containing debugger operations: breakpoint
// toggle, debug thread lifecycle, continue/step-into/step-over/step-out logic,
// debug event processing loop, and breakpoint-over-breakpoint stepping state machine.
// </summary>
// </file>

using System.Collections.Concurrent;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class DisassemblerPanel
{
    #region Breakpoints & Debugging

    private void ToggleBreakpoint()
    {
        ulong address = _disasmSelectedAddress;
        if (address == 0) address = _disasmAddress;

        if (_breakpoints.ContainsKey(address))
            RemoveBreakpoint(address);
        else
            AddBreakpoint(address);

        _disasmPanel.Invalidate();
    }

    private void AddBreakpoint(ulong address)
    {
        if (_breakpoints.ContainsKey(address)) return;

        if (!EnsureDebuggerAttached()) return;

        _pendingAddBp.Enqueue(address);
        _breakpoints[address] = 0;
        UpdateLocalStatus($"Breakpoint queued at 0x{address:X}");
    }

    private void RemoveBreakpoint(ulong address)
    {
        if (!_breakpoints.ContainsKey(address)) return;

        _pendingRemoveBp.Enqueue(address);
        _breakpoints.TryRemove(address, out _);
        UpdateLocalStatus($"Breakpoint removal queued at 0x{address:X}");

        if (_breakpoints.Count == 0 && _debugReady)
            _debugging = false;
    }

    private bool EnsureDebuggerAttached()
    {
        if (_debugThread != null && _debugThread.IsAlive) return true;

        _debugReady = false;
        _debugging = true;
        _isPaused = false;

        _debugThread = new Thread(DebugThreadLoop)
        {
            IsBackground = true,
            Name = "DisassemblerDebugThread"
        };
        _debugThread.Start();

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

        _debugThread?.Join(1000);
        _debugThread = null;
        _debuggerHandle = IntPtr.Zero;
    }

    private void DebugThreadLoop()
    {
        const uint DBG_CONTINUE = 0x00010002;
        const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        IntPtr handle = IntPtr.Zero;

        try
        {
            var attachResult = NexusEngine.Nexus_DebuggerAttach(_processHandle, out handle);
            if (attachResult != NexusResult.OK && attachResult != NexusResult.Success)
            {
                try
                {
                    BeginInvoke(() =>
                    {
                        MessageBox.Show($"Failed to attach debugger: {attachResult}\n\nOnly one debugger can be attached at a time.",
                            "Debugger Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    });
                }
                catch { }
                _debugging = false;
                return;
            }

            _debuggerHandle = handle;

            // Drain initial events
            int initEvents = 0;
            while (_debugging && initEvents < 500)
            {
                var waitResult = NexusEngine.Nexus_WaitForDebugEvent(handle, out NexusDebugEvent evt, 10);
                if (waitResult != NexusResult.OK && waitResult != NexusResult.Success) break;
                NexusEngine.Nexus_ContinueDebugEvent(handle, evt.ThreadId, (int)DBG_CONTINUE);
                initEvents++;
            }

            _debugReady = true;

            // Main debug loop
            while (_debugging)
            {
                try
                {
                    // Process pending breakpoint additions
                    while (_pendingAddBp.TryDequeue(out ulong addAddr))
                    {
                        var bpResult = NexusEngine.Nexus_SetBreakpoint(handle, addAddr,
                            (int)NexusBreakpointType.HardwareExec, (int)NexusBreakpointSize.Size1, out ulong bpId);

                        if (bpResult == NexusResult.OK || bpResult == NexusResult.Success)
                        {
                            _breakpoints[addAddr] = bpId;
                        }
                        else
                        {
                            _breakpoints.TryRemove(addAddr, out _);
                            try
                            {
                                BeginInvoke(() =>
                                {
                                    MessageBox.Show($"Failed to set breakpoint at 0x{addAddr:X}", "Breakpoint Error",
                                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    _disasmPanel.Invalidate();
                                });
                            }
                            catch { }
                        }
                    }

                    // Process pending breakpoint removals
                    while (_pendingRemoveBp.TryDequeue(out ulong removeAddr))
                    {
                        foreach (var kvp in _breakpoints.ToList())
                        {
                            if (kvp.Key == removeAddr && kvp.Value != 0)
                            {
                                NexusEngine.Nexus_RemoveBreakpoint(handle, kvp.Value);
                                _breakpoints.TryRemove(removeAddr, out _);
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

                        if (_steppingOverBp)
                        {
                            _steppingOverBp = false;

                            if (_stepOverBpAddress != 0 && _breakpoints.ContainsKey(_stepOverBpAddress))
                            {
                                var bpResult = NexusEngine.Nexus_SetBreakpoint(handle, _stepOverBpAddress,
                                    (int)NexusBreakpointType.HardwareExec, (int)NexusBreakpointSize.Size1, out ulong newBpId);
                                if (bpResult == NexusResult.OK || bpResult == NexusResult.Success)
                                    _breakpoints[_stepOverBpAddress] = newBpId;
                            }

                            if (_singleStepMode)
                                ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                        }
                        else if (_breakpoints.ContainsKey(hitAddress) && _breakpoints[hitAddress] != 0)
                        {
                            ShowBreakpointDialog(handle, evt.ThreadId, hitAddress);
                        }
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

    private void ShowBreakpointDialog(IntPtr debugHandle, uint threadId, ulong hitAddress)
    {
        _isPaused = true;
        _pausedAtAddress = hitAddress;
        _continueAction = 0;

        // Notify parent that we paused at this thread
        OnDebugPaused?.Invoke(this, threadId);

        string registerText = "";
        var ctxResult = NexusEngine.Nexus_GetThreadContext(threadId, out CONTEXT64 ctx);
        if (ctxResult == NexusResult.OK || ctxResult == NexusResult.Success)
            registerText = FormatRegisters(ctx);
        else
            registerText = $"(Could not get registers: {ctxResult})";

        try
        {
            BeginInvoke(() =>
            {
                try
                {
                    GoToAddressDisasm(hitAddress);
                    _disasmPanel.Invalidate();

                    using var dialog = new Form
                    {
                        Text = "Breakpoint Hit",
                        Size = new Size(500, 440),
                        StartPosition = FormStartPosition.CenterParent,
                        FormBorderStyle = FormBorderStyle.Sizable,
                        BackColor = NexusTheme.BackgroundPanel
                    };

                    var lblInfo = new Label
                    {
                        Text = $"Breakpoint hit at 0x{hitAddress:X}",
                        Location = new Point(20, 15),
                        AutoSize = true,
                        ForeColor = NexusTheme.TextPrimary,
                        Font = new Font(Font.FontFamily, 10, FontStyle.Bold)
                    };

                    var txtRegisters = new TextBox
                    {
                        Location = new Point(20, 45),
                        Size = new Size(445, 260),
                        Multiline = true,
                        ReadOnly = true,
                        ScrollBars = ScrollBars.Vertical,
                        Font = NexusTheme.FontMono,
                        Text = registerText,
                        Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
                    };
                    NexusTheme.StyleTextBox(txtRegisters);

                    var btnContinue = new Button { Text = "Continue (F5)", Location = new Point(20, 315), Size = new Size(110, 32), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
                    var btnRemove = new Button { Text = "Remove BP", Location = new Point(140, 315), Size = new Size(110, 32), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
                    var btnStepInto = new Button { Text = "Step Into (F7)", Location = new Point(20, 355), Size = new Size(110, 32), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
                    var btnStepOver = new Button { Text = "Step Over (F8)", Location = new Point(140, 355), Size = new Size(110, 32), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };

                    NexusTheme.StylePrimaryButton(btnContinue);
                    NexusTheme.StyleButton(btnRemove);
                    NexusTheme.StyleButton(btnStepInto);
                    NexusTheme.StyleButton(btnStepOver);

                    btnContinue.Click += (s, e) => { _continueAction = 1; dialog.Close(); };
                    btnRemove.Click += (s, e) => { _continueAction = 3; dialog.Close(); };
                    btnStepInto.Click += (s, e) => { _continueAction = 2; dialog.Close(); };
                    btnStepOver.Click += (s, e) => { _continueAction = 4; dialog.Close(); };

                    dialog.Controls.AddRange([lblInfo, txtRegisters, btnContinue, btnRemove, btnStepInto, btnStepOver]);
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

        while (_isPaused && _debugging)
        {
            Thread.Sleep(50);
        }

        bool isAtBreakpoint = _breakpoints.ContainsKey(hitAddress) && _breakpoints[hitAddress] != 0;

        if (_continueAction == 3)
        {
            if (isAtBreakpoint)
            {
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints.TryRemove(hitAddress, out _);
                try { BeginInvoke(() => _disasmPanel.Invalidate()); } catch { }
            }
            _singleStepMode = false;
        }
        else if (_continueAction == 1)
        {
            _singleStepMode = false;

            if (isAtBreakpoint)
            {
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints[hitAddress] = 0;

                _steppingOverBp = true;
                _stepOverBpAddress = hitAddress;
                _stepOverBpId = bpId;

                NexusEngine.Nexus_SingleStep(debugHandle, threadId);
            }
        }
        else if (_continueAction == 2 || _continueAction == 4)
        {
            _singleStepMode = true;

            if (isAtBreakpoint)
            {
                var bpId = _breakpoints[hitAddress];
                NexusEngine.Nexus_RemoveBreakpoint(debugHandle, bpId);
                _breakpoints[hitAddress] = 0;

                _steppingOverBp = true;
                _stepOverBpAddress = hitAddress;
                _stepOverBpId = bpId;
            }

            NexusEngine.Nexus_SingleStep(debugHandle, threadId);
        }
    }

    private static string FormatRegisters(CONTEXT64 ctx)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=== General Purpose Registers ===");
        sb.AppendLine($"RAX = {ctx.Rax:X16}    RBX = {ctx.Rbx:X16}");
        sb.AppendLine($"RCX = {ctx.Rcx:X16}    RDX = {ctx.Rdx:X16}");
        sb.AppendLine($"RSI = {ctx.Rsi:X16}    RDI = {ctx.Rdi:X16}");
        sb.AppendLine($"RBP = {ctx.Rbp:X16}    RSP = {ctx.Rsp:X16}");
        sb.AppendLine($"R8  = {ctx.R8:X16}    R9  = {ctx.R9:X16}");
        sb.AppendLine($"R10 = {ctx.R10:X16}    R11 = {ctx.R11:X16}");
        sb.AppendLine($"R12 = {ctx.R12:X16}    R13 = {ctx.R13:X16}");
        sb.AppendLine($"R14 = {ctx.R14:X16}    R15 = {ctx.R15:X16}");
        sb.AppendLine();

        sb.AppendLine("=== Instruction Pointer & Flags ===");
        sb.AppendLine($"RIP    = {ctx.Rip:X16}");
        sb.AppendLine($"EFLAGS = {ctx.EFlags:X8}  [{FormatEFlags(ctx.EFlags)}]");
        sb.AppendLine();

        sb.AppendLine("=== Segment Registers ===");
        sb.AppendLine($"CS = {ctx.SegCs:X4}  DS = {ctx.SegDs:X4}  ES = {ctx.SegEs:X4}");
        sb.AppendLine($"FS = {ctx.SegFs:X4}  GS = {ctx.SegGs:X4}  SS = {ctx.SegSs:X4}");

        return sb.ToString();
    }

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

    #endregion
}
