// <file>
// <summary>
// Breakpoints tab logic for the debugger form: refresh, add, remove, toggle, enable/disable.
// </summary>
// </file>
using System.Text;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class DebuggerForm
{
    #region Breakpoints Tab

    private void RefreshBreakpoints()
    {
        ulong? selectedAddress = null;
        if (_lvBreakpoints.SelectedItems.Count > 0 && _lvBreakpoints.SelectedItems[0].Tag is BreakpointInfo selectedBp)
            selectedAddress = selectedBp.Address;

        _lvBreakpoints.BeginUpdate();
        _lvBreakpoints.Items.Clear();

        if (_debuggerHandle != IntPtr.Zero)
        {
            _breakpoints.Clear();
            var buffer = new NexusBreakpoint[64];
            var result = NexusEngine.Nexus_GetBreakpoints(_debuggerHandle, buffer, (nuint)buffer.Length, out nuint count);

            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                for (int i = 0; i < (int)count; i++)
                {
                    var nxBp = buffer[i];
                    _breakpoints.Add(new BreakpointInfo
                    {
                        Id = nxBp.Id,
                        Address = nxBp.Address,
                        Type = (NexusBreakpointType)nxBp.Type,
                        Size = (int)nxBp.Size switch { 0 => 1, 1 => 2, 3 => 4, 2 => 8, _ => 1 },
                        HitCount = (int)nxBp.HitCount,
                        Enabled = nxBp.Enabled != 0
                    });
                }
            }
        }

        foreach (var bp in _breakpoints)
        {
            if (!_showShadowBreakpoints && bp.IsShadow) continue;

            var item = new ListViewItem($"0x{bp.Address:X}");
            item.SubItems.Add(GetBreakpointTypeName(bp.Type));
            item.SubItems.Add($"{bp.Size}");
            item.SubItems.Add($"{bp.HitCount}");
            item.SubItems.Add(bp.Condition ?? "");
            item.SubItems.Add(bp.Enabled ? "Yes" : "No");
            item.SubItems.Add(bp.Description ?? "");
            item.Tag = bp;
            if (!bp.Enabled) item.ForeColor = Color.Gray;
            _lvBreakpoints.Items.Add(item);
        }

        if (selectedAddress.HasValue)
        {
            foreach (ListViewItem item in _lvBreakpoints.Items)
            {
                if (item.Tag is BreakpointInfo bp && bp.Address == selectedAddress.Value)
                {
                    item.Selected = true;
                    item.EnsureVisible();
                    break;
                }
            }
        }

        _lvBreakpoints.EndUpdate();
    }

    private static string GetBreakpointTypeName(NexusBreakpointType type) => type switch
    {
        NexusBreakpointType.Software => "Software (INT3)",
        NexusBreakpointType.HardwareExec => "HW Execute",
        NexusBreakpointType.HardwareWrite => "HW Write",
        NexusBreakpointType.HardwareRW => "HW Access",
        NexusBreakpointType.Memory => "Memory (Guard)",
        _ => type.ToString()
    };

    private void DeleteSelectedBreakpoint()
    {
        if (_lvBreakpoints.SelectedItems.Count == 0) return;
        if (_lvBreakpoints.SelectedItems[0].Tag is not BreakpointInfo bp) return;

        var result = NexusEngine.Nexus_RemoveBreakpoint(_debuggerHandle, bp.Id);
        if (result == NexusResult.OK)
        {
            _breakpoints.Remove(bp);
            RefreshBreakpoints();
        }
        else
        {
            MessageBox.Show($"Failed to remove breakpoint: {NexusHelper.GetErrorMessage(result)}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SetBreakpointCondition()
    {
        if (_lvBreakpoints.SelectedItems.Count == 0) return;
        if (_lvBreakpoints.SelectedItems[0].Tag is not BreakpointInfo bp) return;

        var conditionForm = BreakpointConditionForm.ShowCondition(this);
        if (conditionForm != null)
        {
            bp.Condition = conditionForm.ConditionType switch
            {
                BreakConditionType.Always => null,
                BreakConditionType.Expression => conditionForm.Expression,
                BreakConditionType.HitCount => $"hitcount >= {conditionForm.HitCount}",
                BreakConditionType.RegisterEquals => $"{conditionForm.Register} == 0x{conditionForm.CompareValue:X}",
                BreakConditionType.RegisterNotEquals => $"{conditionForm.Register} != 0x{conditionForm.CompareValue:X}",
                BreakConditionType.RegisterGreater => $"{conditionForm.Register} > 0x{conditionForm.CompareValue:X}",
                BreakConditionType.RegisterLess => $"{conditionForm.Register} < 0x{conditionForm.CompareValue:X}",
                BreakConditionType.MemoryEquals => $"readInteger(0x{conditionForm.MemoryAddress:X}) == target",
                BreakConditionType.MemoryChanged => $"memoryChanged(0x{conditionForm.MemoryAddress:X})",
                _ => null
            };
            bp.IsEasyCondition = conditionForm.ConditionType != BreakConditionType.Expression;
            RefreshBreakpoints();
        }
    }

    private void ToggleBreakpoint()
    {
        if (_lvBreakpoints.SelectedItems.Count == 0) return;
        if (_lvBreakpoints.SelectedItems[0].Tag is not BreakpointInfo bp) return;

        bool newState = !bp.Enabled;
        var result = NexusEngine.Nexus_EnableBreakpoint(_debuggerHandle, bp.Id, newState ? 1 : 0);

        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            bp.Enabled = newState;
            RefreshBreakpoints();
        }
        else
        {
            MessageBox.Show($"Failed to {(newState ? "enable" : "disable")} breakpoint: {NexusHelper.GetErrorMessage(result)}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BtnAddBreakpoint_Click(object? sender, EventArgs e)
    {
        using var inputForm = new Form
        {
            Text = "Add Breakpoint",
            Size = new Size(380, 280),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false
        };

        int y = NexusTheme.Space16;
        var lblAddress = new Label { Text = "Address:", Location = new Point(NexusTheme.Space16, y), AutoSize = true };
        var txtAddress = new TextBox { Location = new Point(120, y - 3), Width = 220 };
        y += 35;

        var lblType = new Label { Text = "Type:", Location = new Point(NexusTheme.Space16, y), AutoSize = true };
        var cmbType = new ComboBox { Location = new Point(120, y - 3), Width = 220, DropDownStyle = ComboBoxStyle.DropDownList };
        cmbType.Items.AddRange(new[] { "Software (INT3)", "HW Execute", "HW Write", "HW Access", "Memory (Guard)" });
        cmbType.SelectedIndex = 0;
        y += 35;

        var lblSize = new Label { Text = "Size:", Location = new Point(NexusTheme.Space16, y), AutoSize = true };
        var cmbSize = new ComboBox { Location = new Point(120, y - 3), Width = 100, DropDownStyle = ComboBoxStyle.DropDownList };
        cmbSize.Items.AddRange(new[] { "1 byte", "2 bytes", "4 bytes", "8 bytes" });
        cmbSize.SelectedIndex = 0;
        y += 35;

        var lblDesc = new Label { Text = "Description:", Location = new Point(NexusTheme.Space16, y), AutoSize = true };
        var txtDesc = new TextBox { Location = new Point(120, y - 3), Width = 220 };
        y += 45;

        var btnOk = new Button { Text = "OK", Location = new Point(160, y), Size = new Size(80, NexusTheme.ControlHeight), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(250, y), Size = new Size(80, NexusTheme.ControlHeight), DialogResult = DialogResult.Cancel };

        inputForm.Controls.AddRange(new Control[] { lblAddress, txtAddress, lblType, cmbType, lblSize, cmbSize, lblDesc, txtDesc, btnOk, btnCancel });
        inputForm.AcceptButton = btnOk;
        inputForm.CancelButton = btnCancel;
        NexusTheme.ApplyTo(inputForm);

        if (inputForm.ShowDialog(this) == DialogResult.OK)
        {
            var addressText = txtAddress.Text.Trim();
            if (addressText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                addressText = addressText[2..];

            if (ulong.TryParse(addressText, System.Globalization.NumberStyles.HexNumber, null, out var address))
            {
                var bpType = cmbType.SelectedIndex switch
                {
                    0 => NexusBreakpointType.Software,
                    1 => NexusBreakpointType.HardwareExec,
                    2 => NexusBreakpointType.HardwareWrite,
                    3 => NexusBreakpointType.HardwareRW,
                    4 => NexusBreakpointType.Memory,
                    _ => NexusBreakpointType.Software
                };
                var size = cmbSize.SelectedIndex switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, _ => 1 };

                var bp = new BreakpointInfo
                {
                    Id = (ulong)_breakpoints.Count + 1,
                    Address = address,
                    Type = bpType,
                    Size = size,
                    Enabled = true,
                    Description = txtDesc.Text
                };
                _breakpoints.Add(bp);
                RefreshBreakpoints();
            }
            else
            {
                MessageBox.Show("Invalid address format. Use hex (e.g., 00401000 or 0x00401000)", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void BtnRemoveAllBreakpoints_Click(object? sender, EventArgs e)
    {
        if (_breakpoints.Count == 0) return;
        if (MessageBox.Show($"Remove all {_breakpoints.Count} breakpoints?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

        foreach (var bp in _breakpoints.ToList())
            NexusEngine.Nexus_RemoveBreakpoint(_debuggerHandle, bp.Id);
        _breakpoints.Clear();
        RefreshBreakpoints();
    }

    private void BtnEnableAllBreakpoints_Click(object? sender, EventArgs e)
    {
        foreach (var bp in _breakpoints.Where(b => !b.Enabled))
        {
            NexusEngine.Nexus_EnableBreakpoint(_debuggerHandle, bp.Id, 1);
            bp.Enabled = true;
        }
        RefreshBreakpoints();
    }

    private void BtnDisableAllBreakpoints_Click(object? sender, EventArgs e)
    {
        foreach (var bp in _breakpoints.Where(b => b.Enabled))
        {
            NexusEngine.Nexus_EnableBreakpoint(_debuggerHandle, bp.Id, 0);
            bp.Enabled = false;
        }
        RefreshBreakpoints();
    }

    #endregion
}
