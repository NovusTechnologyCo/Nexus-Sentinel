using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Fill / Allocate / Protect Dialogs

    private void MnuFillBytes_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var dialog = new FillMemoryForm(_processHandle, _selectedAddress, _selectedAddress + 0x100);
        dialog.ShowDialog(this);
        RefreshMemory();
    }

    private void ShowAllocateDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var dialog = new AllocateMemoryForm(_processHandle);
        dialog.ShowDialog(this);

        // If allocation succeeded, navigate to the allocated address
        if (dialog.AllocatedAddress != 0)
        {
            GoToAddress(dialog.AllocatedAddress);
        }
    }

    private void ShowProtectionDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var dialog = new Form
        {
            Text = "Change Memory Protection",
            Size = new Size(350, 210),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var lblAddress = new Label { Text = "Address:", Location = new Point(10, 15), AutoSize = true };
        var txtAddr = new TextBox { Location = new Point(110, 12), Width = 200, Text = $"{_selectedAddress:X}" };
        NexusTheme.StyleTextBox(txtAddr);

        var lblSize = new Label { Text = "Size:", Location = new Point(10, 45), AutoSize = true };
        var txtSize = new TextBox { Location = new Point(110, 42), Width = 200, Text = "4096" };
        NexusTheme.StyleTextBox(txtSize);

        var lblProt = new Label { Text = "Protection:", Location = new Point(10, 75), AutoSize = true };
        var cboProt = new ComboBox { Location = new Point(110, 72), Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
        cboProt.Items.AddRange(new object[] {
            "PAGE_EXECUTE_READWRITE (0x40)",
            "PAGE_EXECUTE_READ (0x20)",
            "PAGE_READWRITE (0x04)",
            "PAGE_READONLY (0x02)"
        });
        cboProt.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cboProt);

        var btnOk = new Button { Text = "OK", Location = new Point(145, 115), Size = new Size(80, 32), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(235, 115), Size = new Size(80, 32), DialogResult = DialogResult.Cancel };

        dialog.Controls.AddRange(new Control[] { lblAddress, txtAddr, lblSize, txtSize, lblProt, cboProt, btnOk, btnCancel });
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            if (!ulong.TryParse(txtAddr.Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                return;
            if (!ulong.TryParse(txtSize.Text, out ulong size))
                return;

            uint newProtect = cboProt.SelectedIndex switch
            {
                0 => 0x40, // PAGE_EXECUTE_READWRITE
                1 => 0x20, // PAGE_EXECUTE_READ
                2 => 0x04, // PAGE_READWRITE
                3 => 0x02, // PAGE_READONLY
                _ => 0x04
            };

            var result = NexusEngine.Nexus_ProtectMemory(
                _processHandle,
                addr,
                (nuint)size,
                newProtect,
                out uint oldProtect);

            if (result == NexusResult.OK)
            {
                MessageBox.Show($"Protection changed from 0x{oldProtect:X} to 0x{newProtect:X}",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show($"Protection change failed: {NexusHelper.GetErrorMessage(result)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    #endregion

    #region Symbol Lookup

    private void MnuShowSymbols_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Try to resolve symbol at selected address
        IntPtr symbolHandle;
        uint options = NexusEngine.NEXUS_SYM_UNDNAME | NexusEngine.NEXUS_SYM_DEFERRED_LOADS;
        var result = NexusEngine.Nexus_SymbolCreate(_processHandle, options, out symbolHandle);
        if (result != NexusResult.OK)
        {
            MessageBox.Show($"Failed to create symbol handler: {NexusHelper.GetErrorMessage(result)}",
                "Symbol Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            result = NexusEngine.Nexus_SymbolFromAddress(symbolHandle, _selectedAddress, out var info, out var displacement);
            if (result == NexusResult.OK)
            {
                string dispStr = displacement != 0 ? $"+0x{displacement:X}" : "";
                MessageBox.Show(
                    $"Address: {_selectedAddress:X16}\n" +
                    $"Symbol: {info.Name}{dispStr}\n" +
                    $"Module: {info.ModuleName}",
                    "Symbol Info",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("No symbol found at this address", "Symbol Info",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        finally
        {
            NexusEngine.Nexus_SymbolDestroy(symbolHandle);
        }
    }

    #endregion

    #region GoTo / Navigation

    private void ShowGoToDialog()
    {
        // Called from menu bar - goes to address in both views
        ShowGoToDialogInternal(addr => GoToAddress(addr), _selectedAddress);
    }

    private void ShowGoToDialogHex()
    {
        // Called from hex view context menu - only affects hex view
        ShowGoToDialogInternal(GoToAddressHex, _hexSelectedAddress);
    }

    private void ShowGoToDialogDisasm()
    {
        // Called from disasm view context menu - only affects disasm view
        ShowGoToDialogInternal(GoToAddressDisasm, _disasmSelectedAddress);
    }

    private void ShowGoToDialogInternal(Action<ulong> goToAction, ulong defaultAddress)
    {
        using var dialog = new Form
        {
            Text = "Go to Address",
            Size = new Size(300, 150),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var textBox = new TextBox
        {
            Location = new Point(10, 15),
            Size = new Size(265, 23),
            Text = $"{defaultAddress:X}"
        };
        NexusTheme.StyleTextBox(textBox);

        var okButton = new Button
        {
            Text = "OK",
            Location = new Point(105, 50),
            Size = new Size(80, 28),
            DialogResult = DialogResult.OK
        };

        dialog.Controls.AddRange([textBox, okButton]);
        dialog.AcceptButton = okButton;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var hexText = textBox.Text.Trim();
            if (hexText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hexText = hexText[2..];
            if (ulong.TryParse(hexText,
                System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                goToAction(address);
            }
        }
    }

    private void FollowSelectedAddress()
    {
        // Follow the address/pointer at the selected location
        // Read the pointer value at the selected address
        ulong address = _lastActiveViewIsHex ? _hexSelectedAddress : _disasmSelectedAddress;
        if (address == 0) address = _selectedAddress;

        if (address == 0 || _processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No address selected", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Read pointer-sized value (8 bytes for 64-bit)
        var buffer = new byte[8];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, address, buffer, 8, out nuint bytesRead);

        if ((result != NexusResult.OK && result != NexusResult.Success) || bytesRead < 8)
        {
            MessageBox.Show($"Failed to read pointer at 0x{address:X}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Convert to pointer value
        ulong pointerValue = BitConverter.ToUInt64(buffer, 0);

        if (pointerValue == 0)
        {
            MessageBox.Show("Pointer value is NULL (0)", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        // Navigate to the pointer target
        GoToAddress(pointerValue);
    }

    private void BtnGo_Click(object? sender, EventArgs e)
    {
        var addrText = txtAddress.Text.Trim();
        if (addrText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addrText = addrText[2..];
        if (ulong.TryParse(addrText,
            System.Globalization.NumberStyles.HexNumber, null, out ulong address))
        {
            GoToAddress(address);
        }
    }

    private void TxtAddress_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            BtnGo_Click(sender, e);
            e.Handled = true;
            e.SuppressKeyPress = true;
        }
    }

    #endregion

    #region Find What Accesses / Writes

    private void FindWhatAccesses()
    {
        ulong address = _lastActiveViewIsHex ? _hexSelectedAddress : _disasmSelectedAddress;
        if (address == 0) address = _selectedAddress;
        if (address == 0) address = _baseAddress;

        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process handle available.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Open FoundCodeForm for hardware read/write access monitoring
        var form = new FoundCodeForm(_processHandle, address, NexusBreakpointType.HardwareRW, _processId);
        form.Show(this);
    }

    private void FindWhatWrites()
    {
        ulong address = _lastActiveViewIsHex ? _hexSelectedAddress : _disasmSelectedAddress;
        if (address == 0) address = _selectedAddress;
        if (address == 0) address = _baseAddress;

        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process handle available.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Open FoundCodeForm for hardware write monitoring
        var form = new FoundCodeForm(_processHandle, address, NexusBreakpointType.HardwareWrite, _processId);
        form.Show(this);
    }

    #endregion

    #region UI Events / Form Lifecycle

    private void UpdateTitle()
    {
        if (_dumpFileData != null && !string.IsNullOrEmpty(_dumpFileName))
        {
            Text = $"Memory Viewer - [Dump: {_dumpFileName}]";
        }
        else if (_processHandle == IntPtr.Zero)
        {
            Text = "Memory Viewer";
        }
        else
        {
            NexusEngine.Nexus_GetProcessInfo(_processHandle, out var info);
            Text = $"Memory Viewer - {info.Name}";
        }
    }

    private void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        RefreshMemory();
    }

    private void ChkAutoRefresh_CheckedChanged(object? sender, EventArgs e)
    {
        if (chkAutoRefresh.Checked)
            refreshTimer.Start();
        else
            refreshTimer.Stop();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        // Start auto-refresh timer if enabled by default
        if (chkAutoRefresh.Checked)
            refreshTimer.Start();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        refreshTimer.Stop();

        // Cleanup debugger and breakpoints
        _debugging = false;
        _isPaused = false;
        try
        {
            _debugThread?.Join(500);
        }
        catch { }
        _debugThread = null;

        // Remove all breakpoints
        if (_debuggerHandle != IntPtr.Zero)
        {
            foreach (var kvp in _breakpoints)
            {
                try { NexusEngine.Nexus_RemoveBreakpoint(_debuggerHandle, kvp.Value); } catch { }
            }
            _breakpoints.Clear();

            try { NexusEngine.Nexus_DebuggerDetach(_debuggerHandle); } catch { }
            _debuggerHandle = IntPtr.Zero;
        }

        base.OnFormClosing(e);
    }

    #endregion

    #region View Toggle

    private void MnuHexView_Click(object? sender, EventArgs e)
    {
        // CheckOnClick already toggled the state, so read current values
        bool showHex = mnuHexView.Checked;
        bool showDisasm = mnuDisasmView.Checked;

        // Don't allow hiding both
        if (!showHex && !showDisasm)
        {
            mnuHexView.Checked = true;
            return;
        }

        UpdatePanelVisibility();
    }

    private void MnuDisasmView_Click(object? sender, EventArgs e)
    {
        // CheckOnClick already toggled the state, so read current values
        bool showHex = mnuHexView.Checked;
        bool showDisasm = mnuDisasmView.Checked;

        // Don't allow hiding both
        if (!showHex && !showDisasm)
        {
            mnuDisasmView.Checked = true;
            return;
        }

        UpdatePanelVisibility();
    }

    private void UpdatePanelVisibility()
    {
        bool showHex = mnuHexView.Checked;
        bool showDisasm = mnuDisasmView.Checked;

        // Use SplitterDistance to show/hide panels
        // Panel1 = disasm (top), Panel2 = hex view (bottom)
        if (showHex && showDisasm)
        {
            // Show both - set splitter to middle
            splitContainer.Panel1Collapsed = false;
            splitContainer.Panel2Collapsed = false;
            splitContainer.SplitterDistance = splitContainer.Height / 2;
        }
        else if (showDisasm && !showHex)
        {
            // Show only disasm - expand Panel1 to full height
            splitContainer.Panel2Collapsed = true;
            splitContainer.Panel1Collapsed = false;
        }
        else if (!showDisasm && showHex)
        {
            // Show only hex view - expand Panel2 to full height
            splitContainer.Panel1Collapsed = true;
            splitContainer.Panel2Collapsed = false;
        }

        // Force refresh
        splitContainer.Invalidate(true);
        pnlHexView.Invalidate();
        pnlDisasm.Invalidate();
    }

    #endregion
}
