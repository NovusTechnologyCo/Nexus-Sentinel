// <file>
// <summary>
// Partial class for MemoryScannerPanel defining right-click context menus
// for the Found List (scan results) and Saved Addresses table.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Helpers;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class MemoryScannerPanel
{
    #region Found List Context Menu

    private ContextMenuStrip CreateFoundListContextMenu()
    {
        var menu = new ContextMenuStrip();
        ThemeManager.ApplyThemeToToolStrip(menu);

        menu.Items.Add("Add to list", null, (s, e) => AddToList_Click(s, e));
        menu.Items.Add("Change value", null, (s, e) => ChangeFoundValue());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Disassemble this memory region", null, (s, e) => DisassembleFoundMemory());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Find out what writes to this address", null, (s, e) => FindWhatWritesToFoundAddress());
        menu.Items.Add("Find out what accesses this address", null, (s, e) => FindWhatAccessesFoundAddress());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Copy selected addresses", null, (s, e) => CopyFoundAddresses());

        menu.Opening += (s, e) =>
        {
            bool hasSelection = _foundList.SelectedIndices.Count > 0;
            foreach (ToolStripItem item in menu.Items)
            {
                if (item is ToolStripMenuItem menuItem)
                    menuItem.Enabled = hasSelection;
            }
        };

        return menu;
    }

    /// <summary>
    /// Gets the scan result entry for a selected index from the native engine.
    /// Returns null if the fetch fails.
    /// </summary>
    private Interop.NexusScanResultEntry? GetFoundResultAt(int index)
    {
        if (_scanHandle == IntPtr.Zero) return null;

        var results = new Interop.NexusScanResultEntry[1];
        var fetchResult = Interop.NexusEngine.Nexus_AdvScanGetResults(
            _scanHandle,
            (ulong)index,
            results,
            1,
            out var actualCount);

        if (fetchResult != Interop.NexusResult.OK || actualCount == 0)
            return null;

        return results[0];
    }

    private void ChangeFoundValue()
    {
        if (_foundList.SelectedIndices.Count == 0) return;

        int index = _foundList.SelectedIndices[0];
        var entry = GetFoundResultAt(index);
        if (entry == null) return;

        var currentValue = FormatScanValue(entry.Value.CurrentValue, _scanValueType);
        using var inputForm = new InputBoxForm("Change Value", "Enter new value:", currentValue);
        if (inputForm.ShowDialog(this) == DialogResult.OK)
        {
            if (TryWriteFoundValue(entry.Value.Address, inputForm.Value))
            {
                PublishStatus($"Value changed at {entry.Value.Address:X}", StatusType.Success);
                _foundList.Invalidate();
            }
            else
            {
                PublishStatus("Failed to write value", StatusType.Error);
            }
        }
    }

    private static string FormatScanValue(Interop.NexusScanValue val, int valueType)
    {
        return valueType switch
        {
            0 => val.ByteVal.ToString(),
            1 => val.Int16Val.ToString(),
            2 => val.Int32Val.ToString(),
            3 => val.Int64Val.ToString(),
            4 => val.FloatVal.ToString("G"),
            5 => val.DoubleVal.ToString("G"),
            _ => val.Int32Val.ToString()
        };
    }

    private bool TryWriteFoundValue(ulong address, string valueStr)
    {
        if (!ProcessContext.Current.IsAttached) return false;

        try
        {
            var buffer = _scanValueType switch
            {
                0 => [byte.Parse(valueStr)],
                1 => BitConverter.GetBytes(short.Parse(valueStr)),
                2 => BitConverter.GetBytes(int.Parse(valueStr)),
                3 => BitConverter.GetBytes(long.Parse(valueStr)),
                4 => BitConverter.GetBytes(float.Parse(valueStr)),
                5 => BitConverter.GetBytes(double.Parse(valueStr)),
                _ => BitConverter.GetBytes(int.Parse(valueStr))
            };

            return Interop.NexusEngine.WriteBytes(
                ProcessContext.Current.NativeProcessHandle, address, buffer);
        }
        catch
        {
            return false;
        }
    }

    private void DisassembleFoundMemory()
    {
        if (_foundList.SelectedIndices.Count == 0) return;

        int index = _foundList.SelectedIndices[0];
        var entry = GetFoundResultAt(index);
        if (entry == null) return;

        EventBus.Instance.Publish(new NavigateToAddressEvent(entry.Value.Address, "Disassembler"));
    }

    private void FindWhatWritesToFoundAddress()
    {
        if (_foundList.SelectedIndices.Count == 0) return;

        int index = _foundList.SelectedIndices[0];
        var entry = GetFoundResultAt(index);
        if (entry == null) return;

        if (!ProcessContext.Current.IsAttached)
        {
            PublishStatus("No process attached", StatusType.Warning);
            return;
        }

        var form = new FoundCodeForm(
            ProcessContext.Current.NativeProcessHandle,
            entry.Value.Address,
            Interop.NexusBreakpointType.HardwareWrite,
            ProcessContext.Current.ProcessId);
        form.Show();
    }

    private void FindWhatAccessesFoundAddress()
    {
        if (_foundList.SelectedIndices.Count == 0) return;

        int index = _foundList.SelectedIndices[0];
        var entry = GetFoundResultAt(index);
        if (entry == null) return;

        if (!ProcessContext.Current.IsAttached)
        {
            PublishStatus("No process attached", StatusType.Warning);
            return;
        }

        var form = new FoundCodeForm(
            ProcessContext.Current.NativeProcessHandle,
            entry.Value.Address,
            Interop.NexusBreakpointType.HardwareRW,
            ProcessContext.Current.ProcessId);
        form.Show();
    }

    private void CopyFoundAddresses()
    {
        if (_foundList.SelectedIndices.Count == 0) return;

        var addresses = new System.Text.StringBuilder();
        foreach (int index in _foundList.SelectedIndices)
        {
            var entry = GetFoundResultAt(index);
            if (entry != null)
            {
                addresses.AppendLine($"{entry.Value.Address:X}");
            }
        }

        if (addresses.Length > 0)
        {
            Clipboard.SetText(addresses.ToString().TrimEnd());
            PublishStatus($"Copied {_foundList.SelectedIndices.Count} address(es) to clipboard", StatusType.Success);
        }
    }

    #endregion

    #region Saved Addresses Context Menu

    private ContextMenuStrip CreateSavedListContextMenu()
    {
        var menu = new ContextMenuStrip();
        ThemeManager.ApplyThemeToToolStrip(menu);

        menu.Items.Add("Change value (Enter)", null, (s, e) => ChangeSelectedSavedValue());
        menu.Items.Add("Toggle freeze (Space)", null, (s, e) => ToggleFreezeSelected());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Find out what writes to this address", null, (s, e) => FindWhatWritesSelected());
        menu.Items.Add("Find out what accesses this address", null, (s, e) => FindWhatAccessesSelected());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Change description", null, (s, e) => ChangeSelectedDescription());
        menu.Items.Add("Change address", null, (s, e) => ChangeSelectedAddress());
        menu.Items.Add("Browse this memory region", null, (s, e) => BrowseSavedMemory());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Copy address (Ctrl+C)", null, (s, e) => CopySavedAddresses());
        menu.Items.Add("Paste address (Ctrl+V)", null, (s, e) => PasteSavedAddresses());
        menu.Items.Add("Add address manually...", null, (s, e) => ShowAddAddressManually());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Delete selected (Del)", null, (s, e) => DeleteSelectedSaved());

        menu.Opening += (s, e) =>
        {
            bool hasSelection = _savedList.SelectedItems.Count > 0;
            foreach (ToolStripItem item in menu.Items)
            {
                if (item is ToolStripMenuItem menuItem)
                {
                    // Paste is always enabled if clipboard has text
                    if (menuItem.Text?.Contains("Paste") == true)
                        menuItem.Enabled = Clipboard.ContainsText();
                    else
                        menuItem.Enabled = hasSelection;
                }
            }
        };

        return menu;
    }

    private void ChangeSelectedSavedValue()
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var item = _savedList.SelectedItems[0];
        if (item.Tag is SavedAddress saved)
        {
            EditSavedValue(saved, item);
        }
    }

    private void ChangeSelectedDescription()
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var item = _savedList.SelectedItems[0];
        if (item.Tag is SavedAddress saved)
        {
            EditSavedDescription(saved, item);
        }
    }

    private void ChangeSelectedAddress()
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var item = _savedList.SelectedItems[0];
        if (item.Tag is SavedAddress saved)
        {
            using var inputForm = new InputBoxForm("Change Address", "Enter new address (hex):", saved.Address.ToString("X"));
            if (inputForm.ShowDialog(this) == DialogResult.OK)
            {
                var addressStr = inputForm.Value.Trim();
                if (addressStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    addressStr = addressStr[2..];

                if (ulong.TryParse(addressStr, System.Globalization.NumberStyles.HexNumber, null, out ulong newAddress))
                {
                    saved.Address = newAddress;
                    item.SubItems[1].Text = newAddress.ToString("X");
                    PublishStatus("Address updated", StatusType.Success);
                }
                else
                {
                    PublishStatus("Invalid address format", StatusType.Error);
                }
            }
        }
    }

    private void BrowseSavedMemory()
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var item = _savedList.SelectedItems[0];
        if (item.Tag is SavedAddress saved)
        {
            var viewer = new MemoryViewerForm(
                ProcessContext.Current.NativeProcessHandle,
                saved.Address,
                ProcessContext.Current.ProcessId);
            viewer.Show(this);
        }
    }

    private void CopySavedAddresses()
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var text = new System.Text.StringBuilder();
        foreach (ListViewItem item in _savedList.SelectedItems)
        {
            if (item.Tag is SavedAddress saved)
            {
                text.AppendLine($"{saved.Address:X}");
            }
        }

        if (text.Length > 0)
        {
            Clipboard.SetText(text.ToString().TrimEnd());
            PublishStatus($"Copied {_savedList.SelectedItems.Count} address(es) to clipboard", StatusType.Success);
        }
    }

    private void PasteSavedAddresses()
    {
        if (!Clipboard.ContainsText()) return;

        var text = Clipboard.GetText();
        var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int addedCount = 0;

        foreach (var line in lines)
        {
            var addressStr = line.Trim();
            if (addressStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                addressStr = addressStr[2..];

            if (ulong.TryParse(addressStr, System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                var saved = new SavedAddress
                {
                    Address = address,
                    Description = $"Address_{address:X}",
                    ValueType = _valueTypeCombo.SelectedIndex,
                    IsFrozen = false
                };
                _savedAddresses.Add(saved);
                AddSavedAddressToList(saved);
                addedCount++;
            }
        }

        if (addedCount > 0)
        {
            PublishStatus($"Pasted {addedCount} address(es)", StatusType.Success);
        }
    }

    private void ShowAddAddressManually()
    {
        using var form = new WatchListAddEntryForm();
        if (form.ShowDialog(this) == DialogResult.OK)
        {
            var expression = form.Expression;
            if (string.IsNullOrWhiteSpace(expression)) return;

            // Parse the address
            var addrStr = expression.Trim();
            if (addrStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                addrStr = addrStr[2..];

            if (ulong.TryParse(addrStr, System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                // Map WatchEntryType to ValueType int
                var valueType = form.EntryType switch
                {
                    WatchEntryType.Byte => 0,
                    WatchEntryType.TwoBytes => 1,
                    WatchEntryType.FourBytes => 2,
                    WatchEntryType.EightBytes => 3,
                    WatchEntryType.Float => 4,
                    WatchEntryType.Double => 5,
                    WatchEntryType.String => 6,
                    _ => 2 // Default to 4 bytes
                };

                var saved = new SavedAddress
                {
                    Address = address,
                    Description = expression,
                    ValueType = valueType,
                    IsFrozen = false
                };
                _savedAddresses.Add(saved);
                AddSavedAddressToList(saved);
                PublishStatus($"Added address 0x{address:X}", StatusType.Success);
            }
            else
            {
                MessageBox.Show("Invalid address format", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    #endregion
}
