// <file>
// <summary>
// Partial class for MemoryScannerPanel containing top-level menu action handlers
// exposed to the shell menu bar, including first scan, reset scan, and panel-specific
// menu items returned via GetPanelMenus().
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class MemoryScannerPanel
{
    #region Menu Actions

    private void DoFirstScan()
    {
        if (_isFirstScan)
            _firstScanBtn.PerformClick();
        else
        {
            ResetScan();
            _firstScanBtn.PerformClick();
        }
    }

    private void DoNextScan()
    {
        if (!_isFirstScan)
            _nextScanBtn.PerformClick();
    }

    private void UndoScan()
    {
        _undoBtn.PerformClick();
    }

    private void ClearFoundList()
    {
        _foundItems.Clear();
        _foundList.VirtualListSize = 0;
        _foundLabel.Text = "Found: 0";
    }

    private void AddAddressManually()
    {
        using var dialog = new Form
        {
            Text = "Add Address",
            Size = new Size(350, 180),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblAddr = new Label { Text = "Address:", Location = new Point(10, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtAddr = new TextBox { Location = new Point(100, 12), Width = 200 };
        NexusTheme.StyleTextBox(txtAddr);

        var lblDesc = new Label { Text = "Description:", Location = new Point(10, 45), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtDesc = new TextBox { Location = new Point(100, 42), Width = 200 };
        NexusTheme.StyleTextBox(txtDesc);

        var btnOk = new Button { Text = "Add", Location = new Point(130, 85), Size = new Size(80, 28), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(220, 85), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblAddr, txtAddr, lblDesc, txtDesc, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            if (ulong.TryParse(txtAddr.Text.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                _savedAddresses.Add(new SavedAddress { Address = addr, Description = txtDesc.Text, ValueType = _valueTypeCombo.SelectedIndex });
                RefreshSavedList();
            }
        }
    }

    private void ChangeSelectedValue()
    {
        if (_savedList.SelectedIndices.Count == 0) return;
        var idx = _savedList.SelectedIndices[0];
        if (idx < 0 || idx >= _savedAddresses.Count) return;
        // Trigger the double-click edit action
        _savedList.Items[idx].BeginEdit();
    }

    private void ToggleFreezeSelected()
    {
        if (_savedList.SelectedIndices.Count == 0) return;
        var idx = _savedList.SelectedIndices[0];
        if (idx < 0 || idx >= _savedAddresses.Count) return;
        _savedAddresses[idx].IsFrozen = !_savedAddresses[idx].IsFrozen;
        RefreshSavedList();
    }

    private void BrowseInDisassembler()
    {
        ulong address = 0;
        if (_savedList.SelectedIndices.Count > 0)
        {
            var idx = _savedList.SelectedIndices[0];
            if (idx >= 0 && idx < _savedAddresses.Count)
                address = _savedAddresses[idx].Address;
        }
        else if (_foundList.SelectedIndices.Count > 0)
        {
            var idx = _foundList.SelectedIndices[0];
            if (idx >= 0 && idx < _foundItems.Count)
                address = _foundItems[idx].Address;
        }

        if (address != 0)
            EventBus.Instance.Publish(new NavigateToAddressEvent(address));
    }

    private void FindWhatAccessesSelected()
    {
        var address = GetSelectedSavedAddress();
        if (address == 0)
        {
            PublishStatus("No address selected", StatusType.Warning);
            return;
        }

        if (!ProcessContext.Current.IsAttached)
        {
            PublishStatus("No process attached", StatusType.Warning);
            return;
        }

        var form = new Forms.FoundCodeForm(
            ProcessContext.Current.NativeProcessHandle,
            address,
            Interop.NexusBreakpointType.HardwareRW,
            ProcessContext.Current.ProcessId);
        form.Show();
    }

    private void FindWhatWritesSelected()
    {
        var address = GetSelectedSavedAddress();
        if (address == 0)
        {
            PublishStatus("No address selected", StatusType.Warning);
            return;
        }

        if (!ProcessContext.Current.IsAttached)
        {
            PublishStatus("No process attached", StatusType.Warning);
            return;
        }

        var form = new Forms.FoundCodeForm(
            ProcessContext.Current.NativeProcessHandle,
            address,
            Interop.NexusBreakpointType.HardwareWrite,
            ProcessContext.Current.ProcessId);
        form.Show();
    }

    private ulong GetSelectedSavedAddress()
    {
        if (_savedList.SelectedIndices.Count == 0) return 0;
        var idx = _savedList.SelectedIndices[0];
        if (idx < 0 || idx >= _savedAddresses.Count) return 0;
        return _savedAddresses[idx].Address;
    }

    private void DeleteSelectedSaved()
    {
        if (_savedList.SelectedIndices.Count == 0) return;
        var indices = _savedList.SelectedIndices.Cast<int>().OrderByDescending(i => i).ToList();
        foreach (var idx in indices)
        {
            if (idx >= 0 && idx < _savedAddresses.Count)
                _savedAddresses.RemoveAt(idx);
        }
        RefreshSavedList();
    }

    #endregion
}
