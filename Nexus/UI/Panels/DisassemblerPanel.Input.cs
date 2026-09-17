// <file>
// <summary>
// Partial class for DisassemblerPanel handling user input: keyboard shortcuts,
// mouse clicks for selection and navigation, scroll wheel, goto-address, and
// address bar interaction.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;

namespace Nexus.UI.Panels;

public partial class DisassemblerPanel
{
    #region Navigation & Events

    private void GotoBtn_Click(object? sender, EventArgs e)
    {
        if (!ProcessContext.Current.IsAttached)
        {
            UpdateLocalStatus("No process attached", StatusType.Warning);
            return;
        }

        var text = _addressBox.Text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var address))
        {
            GoToAddress(address);
        }
        else
        {
            UpdateLocalStatus("Invalid address format", StatusType.Warning);
        }
    }

    private void AddressBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            e.SuppressKeyPress = true;
            GotoBtn_Click(sender, e);
        }
    }

    /// <summary>
    /// Navigates the disassembler view to the specified address.
    /// </summary>
    public void NavigateTo(ulong address) => GoToAddress(address);

    public void GoToAddress(ulong address)
    {
        _disasmAddress = address;
        _disasmSelectedAddress = address;
        _disasmSelectionEnd = address + 1;
        _disasmSelectionAnchor = address;

        _addressBox.Text = $"{address:X}";
        RefreshViews();
        UpdateLocalStatus($"Navigated to 0x{address:X}");

        // Update info panel
        _infoPanel.SetCurrentAddress(address);
    }

    private void GoToAddressDisasm(ulong address)
    {
        _disasmAddress = address;
        _disasmSelectedAddress = address;
        _disasmSelectionEnd = address + 1;
        _disasmSelectionAnchor = address;
        _addressBox.Text = $"{address:X}";
        RefreshDisasmView();

        // Update info panel
        _infoPanel.SetCurrentAddress(address);
    }

    private void OnNavigateToAddress(NavigateToAddressEvent evt)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnNavigateToAddress(evt));
            return;
        }

        GoToAddress(evt.Address);
    }

    private void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        RefreshViews();
    }

    private void AutoRefreshCheck_CheckedChanged(object? sender, EventArgs e)
    {
        if (_autoRefreshCheck.Checked && _processHandle != IntPtr.Zero)
            _refreshTimer.Start();
        else
            _refreshTimer.Stop();
    }

    #endregion

    #region Disasm View Input

    private void DisasmPanel_MouseWheel(object? sender, MouseEventArgs e)
    {
        int linesToScroll = e.Delta > 0 ? -3 : 3;
        ScrollDisasmByInstructions(linesToScroll);
    }

    private void DisasmScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        int delta = e.NewValue - (_disasmScrollBar.Maximum / 2);
        if (delta == 0) return;
        ScrollDisasmByInstructions(delta);
        _disasmScrollBar.Value = _disasmScrollBar.Maximum / 2;
    }

    private void ScrollDisasmByInstructions(int instructionCount)
    {
        if (instructionCount == 0) return;

        long scrollDelta;

        if (instructionCount > 0 && _cachedDisasmCount > 0)
        {
            int skipCount = Math.Min(instructionCount, _cachedDisasmCount - 1);
            if (skipCount > 0 && skipCount < _cachedDisasmCount)
                scrollDelta = (long)(_cachedDisasm[skipCount].Address - _disasmAddress);
            else
                scrollDelta = instructionCount * 4;
        }
        else if (instructionCount < 0)
        {
            int backupBytes = Math.Abs(instructionCount) * 8;
            ulong scanStart = _disasmAddress > (ulong)backupBytes ? _disasmAddress - (ulong)backupBytes : 0;

            var tempDisasm = new NexusDisasmInstruction[64];
            var result = NexusEngine.Nexus_DisasmDecodeProcess(_processHandle, scanStart, 64, tempDisasm, out nuint count);

            if (result == NexusResult.OK && count > 0)
            {
                int targetIdx = -1;
                for (int i = 0; i < (int)count; i++)
                {
                    if (tempDisasm[i].Address >= _disasmAddress)
                    {
                        targetIdx = Math.Max(0, i + instructionCount);
                        break;
                    }
                }

                if (targetIdx >= 0 && targetIdx < (int)count)
                    scrollDelta = (long)tempDisasm[targetIdx].Address - (long)_disasmAddress;
                else
                    scrollDelta = instructionCount * 4;
            }
            else
            {
                scrollDelta = instructionCount * 4;
            }
        }
        else
        {
            scrollDelta = instructionCount * 4;
        }

        long newAddress = (long)_disasmAddress + scrollDelta;
        if (newAddress < 0) newAddress = 0;
        _disasmAddress = (ulong)newAddress;

        _disasmScrollBar.Value = _disasmScrollBar.Maximum / 2;
        RefreshDisasmView();
    }

    private void DisasmPanel_MouseDown(object? sender, MouseEventArgs e)
    {
        if (_cachedDisasmCount == 0 || _disasmLineHeight == 0) return;

        int row = (e.Y - 2) / _disasmLineHeight;

        if (row >= 0 && row < _cachedDisasmCount)
        {
            ulong clickedAddress = _cachedDisasm[row].Address;

            if ((Control.ModifierKeys & Keys.Shift) != 0 && _disasmSelectionAnchor != 0)
            {
                if (clickedAddress >= _disasmSelectionAnchor)
                {
                    _disasmSelectedAddress = _disasmSelectionAnchor;
                    _disasmSelectionEnd = clickedAddress + _cachedDisasm[row].Length;
                }
                else
                {
                    _disasmSelectedAddress = clickedAddress;
                    for (int i = 0; i < _cachedDisasmCount; i++)
                    {
                        if (_cachedDisasm[i].Address == _disasmSelectionAnchor)
                        {
                            _disasmSelectionEnd = _cachedDisasm[i].Address + _cachedDisasm[i].Length;
                            break;
                        }
                    }
                }
            }
            else
            {
                _disasmSelectedAddress = clickedAddress;
                _disasmSelectionEnd = clickedAddress + _cachedDisasm[row].Length;
                _disasmSelectionAnchor = clickedAddress;
            }

            UpdateLocalStatus($"Selected: 0x{_disasmSelectedAddress:X}");
            _disasmPanel.Invalidate();
        }

        _disasmPanel.Focus();
    }

    private void DisasmPanel_MouseDoubleClick(object? sender, MouseEventArgs e)
    {
        if (_cachedDisasmCount == 0 || _disasmLineHeight == 0) return;

        int row = (e.Y - 2) / _disasmLineHeight;

        if (row >= 0 && row < _cachedDisasmCount)
        {
            var insn = _cachedDisasm[row];
            ShowAssembleDialog(insn.Address, insn.Text ?? insn.Mnemonic);
        }
    }

    private void DisasmPanel_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Control && e.KeyCode == Keys.Z)
        {
            UndoLastChange();
            e.Handled = true;
        }
        else if (e.Control && e.KeyCode == Keys.G)
        {
            ShowGotoAddressDialog();
            e.Handled = true;
        }
        else if (e.KeyCode == Keys.F2)
        {
            ToggleBreakpoint();
            e.Handled = true;
        }
    }

    private void ShowGotoAddressDialog()
    {
        var address = Forms.GotoAddressForm.ShowGoto(this, _processHandle, _disasmSelectedAddress);
        if (address.HasValue)
        {
            GoToAddress(address.Value);
        }
    }

    #endregion
}
