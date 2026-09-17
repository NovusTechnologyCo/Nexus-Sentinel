// <file>
// <summary>
// Breakpoints management panel listing all active breakpoints with their addresses,
// types (software/hardware/memory/conditional/DLL), hit counts, and enable/disable state.
// Provides add/remove/enable/disable controls and double-click navigation to breakpoint
// addresses in the disassembler view.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Breakpoints panel displaying a list of all active breakpoints with management controls.
/// Supports adding, removing, enabling/disabling breakpoints, and navigating to breakpoint
/// addresses. Shows breakpoint type, address, module, condition, and hit count.
/// </summary>
public class BreakpointsPanel : UserControl
{
    private readonly ListView _listView;
    private readonly ContextMenuStrip _contextMenu;
    private readonly List<BreakpointInfo> _breakpoints = new();
    private IntPtr _debuggerHandle = IntPtr.Zero;
    private bool _showShadowBreakpoints;

    public event EventHandler<ulong>? OnNavigateToAddress;

    public BreakpointsPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Compact toolbar (no header - saves space in split context)
        var toolbar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 26,
            Padding = new Padding(2),
            BackColor = NexusTheme.BackgroundDark
        };

        var btnAdd = new Button { Text = "+", Size = new Size(24, 20), Location = new Point(2, 2) };
        btnAdd.Click += BtnAdd_Click;
        NexusTheme.StyleButton(btnAdd);
        var ttAdd = new ToolTip();
        ttAdd.SetToolTip(btnAdd, "Add breakpoint");

        var btnRemove = new Button { Text = "-", Size = new Size(24, 20), Location = new Point(28, 2) };
        btnRemove.Click += (s, e) => DeleteSelectedBreakpoint();
        NexusTheme.StyleButton(btnRemove);
        var ttRemove = new ToolTip();
        ttRemove.SetToolTip(btnRemove, "Remove breakpoint");

        var btnClear = new Button { Text = "Cle", Size = new Size(32, 20), Location = new Point(54, 2) };
        btnClear.Click += BtnClearAll_Click;
        NexusTheme.StyleButton(btnClear);

        toolbar.Controls.AddRange(new Control[] { btnAdd, btnRemove, btnClear });

        // ListView
        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            CheckBoxes = true,
            SmallImageList = CreateImageList(),
            Font = new Font("Consolas", 9f)
        };
        _listView.Columns.Add("Address", 100);
        _listView.Columns.Add("Type", 60);
        _listView.Columns.Add("Hits", 35);
        _listView.Columns.Add("Cond", 60);
        NexusTheme.StyleListView(_listView);

        _listView.ItemCheck += ListView_ItemCheck;
        _listView.DoubleClick += ListView_DoubleClick;

        // Context menu
        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Go to Address", null, (s, e) => GoToSelectedAddress());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Set Condition...", null, (s, e) => SetCondition());
        _contextMenu.Items.Add("Toggle Enabled", null, (s, e) => ToggleSelectedBreakpoint());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Delete", null, (s, e) => DeleteSelectedBreakpoint());
        _contextMenu.Items.Add("Delete All", null, (s, e) => BtnClearAll_Click(null, EventArgs.Empty));
        _contextMenu.Items.Add(new ToolStripSeparator());
        var miShowShadow = new ToolStripMenuItem("Show Shadow Breakpoints") { CheckOnClick = true };
        miShowShadow.Click += (s, e) => { _showShadowBreakpoints = miShowShadow.Checked; RefreshBreakpoints(); };
        _contextMenu.Items.Add(miShowShadow);
        _listView.ContextMenuStrip = _contextMenu;

        Controls.Add(_listView);
        Controls.Add(toolbar);
    }

    private static ImageList CreateImageList()
    {
        var imageList = new ImageList { ImageSize = new Size(16, 16) };
        // Add breakpoint icon (red circle)
        var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.FillEllipse(Brushes.Red, 2, 2, 12, 12);
        }
        imageList.Images.Add("bp", bmp);
        return imageList;
    }

    public void SetDebuggerHandle(IntPtr handle)
    {
        _debuggerHandle = handle;
        RefreshBreakpoints();
    }

    public void RefreshBreakpoints()
    {
        ulong? selectedAddress = null;
        if (_listView.SelectedItems.Count > 0 && _listView.SelectedItems[0].Tag is BreakpointInfo selectedBp)
            selectedAddress = selectedBp.Address;

        _listView.BeginUpdate();
        _listView.Items.Clear();

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

            var item = new ListViewItem($"0x{bp.Address:X}")
            {
                Checked = bp.Enabled,
                Tag = bp,
                ImageKey = "bp"
            };
            item.SubItems.Add(GetBreakpointTypeName(bp.Type));
            item.SubItems.Add($"{bp.HitCount}");
            item.SubItems.Add(bp.Condition ?? "");
            if (!bp.Enabled) item.ForeColor = Color.Gray;
            _listView.Items.Add(item);
        }

        if (selectedAddress.HasValue)
        {
            foreach (ListViewItem item in _listView.Items)
            {
                if (item.Tag is BreakpointInfo bp && bp.Address == selectedAddress.Value)
                {
                    item.Selected = true;
                    item.EnsureVisible();
                    break;
                }
            }
        }

        _listView.EndUpdate();
    }

    private static string GetBreakpointTypeName(NexusBreakpointType type) => type switch
    {
        NexusBreakpointType.Software => "SW",
        NexusBreakpointType.HardwareExec => "HW Exec",
        NexusBreakpointType.HardwareWrite => "HW Write",
        NexusBreakpointType.HardwareRW => "HW R/W",
        NexusBreakpointType.Memory => "Memory",
        _ => type.ToString()
    };

    private void ListView_ItemCheck(object? sender, ItemCheckEventArgs e)
    {
        if (_listView.Items[e.Index].Tag is not BreakpointInfo bp) return;
        bool newState = e.NewValue == CheckState.Checked;

        if (_debuggerHandle != IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_EnableBreakpoint(_debuggerHandle, bp.Id, newState ? 1 : 0);
            if (result == NexusResult.OK || result == NexusResult.Success)
                bp.Enabled = newState;
            else
                e.NewValue = e.CurrentValue; // Revert
        }
    }

    private void ListView_DoubleClick(object? sender, EventArgs e)
    {
        GoToSelectedAddress();
    }

    private void GoToSelectedAddress()
    {
        if (_listView.SelectedItems.Count == 0) return;
        if (_listView.SelectedItems[0].Tag is not BreakpointInfo bp) return;

        OnNavigateToAddress?.Invoke(this, bp.Address);
        EventBus.Instance.Publish(new NavigateToAddressEvent(bp.Address, "Disassembler"));
    }

    private void SetCondition()
    {
        if (_listView.SelectedItems.Count == 0) return;
        if (_listView.SelectedItems[0].Tag is not BreakpointInfo bp) return;

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
                BreakConditionType.MemoryEquals => $"mem[0x{conditionForm.MemoryAddress:X}] == target",
                BreakConditionType.MemoryChanged => $"memChanged(0x{conditionForm.MemoryAddress:X})",
                _ => null
            };
            RefreshBreakpoints();
        }
    }

    private void ToggleSelectedBreakpoint()
    {
        if (_listView.SelectedItems.Count == 0) return;
        var item = _listView.SelectedItems[0];
        item.Checked = !item.Checked;
    }

    private void DeleteSelectedBreakpoint()
    {
        if (_listView.SelectedItems.Count == 0) return;
        if (_listView.SelectedItems[0].Tag is not BreakpointInfo bp) return;

        if (_debuggerHandle != IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_RemoveBreakpoint(_debuggerHandle, bp.Id);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                _breakpoints.Remove(bp);
                RefreshBreakpoints();
            }
        }
        else
        {
            _breakpoints.Remove(bp);
            RefreshBreakpoints();
        }
    }

    private void BtnAdd_Click(object? sender, EventArgs e)
    {
        using var input = new InputBoxForm("Add Breakpoint", "Enter address (hex):");
        if (input.ShowDialog(this) != DialogResult.OK) return;

        var addressText = input.Value.Trim();
        if (addressText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addressText = addressText[2..];

        if (!ulong.TryParse(addressText, System.Globalization.NumberStyles.HexNumber, null, out var address))
        {
            MessageBox.Show("Invalid address format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var bp = new BreakpointInfo
        {
            Id = (ulong)_breakpoints.Count + 1,
            Address = address,
            Type = NexusBreakpointType.Software,
            Size = 1,
            Enabled = true
        };
        _breakpoints.Add(bp);
        RefreshBreakpoints();
    }

    private void BtnClearAll_Click(object? sender, EventArgs e)
    {
        if (_breakpoints.Count == 0) return;
        if (MessageBox.Show($"Remove all {_breakpoints.Count} breakpoints?", "Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

        if (_debuggerHandle != IntPtr.Zero)
        {
            foreach (var bp in _breakpoints.ToList())
                NexusEngine.Nexus_RemoveBreakpoint(_debuggerHandle, bp.Id);
        }
        _breakpoints.Clear();
        RefreshBreakpoints();
    }

    public void AddBreakpoint(BreakpointInfo bp)
    {
        _breakpoints.Add(bp);
        RefreshBreakpoints();
    }
}
