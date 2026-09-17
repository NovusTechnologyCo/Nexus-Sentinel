// <file>
// <summary>
// Partial class for MemoryScannerPanel managing the saved address table.
// Handles adding addresses from scan results, removing entries, changing descriptions,
// freezing/unfreezing values, changing value types, and periodic value refresh.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class MemoryScannerPanel
{
    #region Saved Address Operations

    private void AddToList_Click(object? sender, EventArgs e)
    {
        AddSelectedToList();
    }

    private void Clear_Click(object? sender, EventArgs e)
    {
        ResetScan();
    }

    private void AddSelectedToList()
    {
        if (_foundList.SelectedIndices.Count == 0)
            return;

        var addedCount = 0;
        foreach (int index in _foundList.SelectedIndices)
        {
            // Fetch the result from native engine
            var results = new NexusScanResultEntry[1];
            var fetchResult = NexusEngine.Nexus_AdvScanGetResults(
                _scanHandle,
                (ulong)index,
                results,
                1,
                out var actualCount);

            if (fetchResult != NexusResult.OK || actualCount == 0)
                continue;

            var entry = results[0];
            var saved = new SavedAddress
            {
                Address = entry.Address,
                Description = $"Address_{entry.Address:X}",
                ValueType = _scanValueType,
                IsFrozen = false
            };

            _savedAddresses.Add(saved);
            AddSavedAddressToList(saved);
            addedCount++;
        }

        PublishStatus($"Added {addedCount} address(es) to list", StatusType.Success);
    }

    private void AddSavedAddressToList(SavedAddress saved)
    {
        var lvi = new ListViewItem(saved.Description)
        {
            Tag = saved,
            Checked = saved.IsFrozen
        };
        lvi.SubItems.Add(saved.Address.ToString("X"));
        lvi.SubItems.Add(GetValueTypeName(saved.ValueType));
        lvi.SubItems.Add(ReadCurrentValue(saved));
        _savedList.Items.Add(lvi);
        AutoSizeSavedListColumns();
    }

    private void AutoSizeSavedListColumns()
    {
        if (_savedList.Columns.Count < 4) return;

        // Fixed widths for Address, Type, Value columns
        const int addressWidth = 140;
        const int typeWidth = 100;
        const int valueWidth = 80;

        // Give Description all remaining space
        int availableWidth = _savedList.ClientSize.Width - addressWidth - typeWidth - valueWidth - 4;
        if (availableWidth < 80) availableWidth = 80;  // Minimum width

        _savedList.Columns[0].Width = availableWidth;  // Description
        _savedList.Columns[1].Width = addressWidth;    // Address
        _savedList.Columns[2].Width = typeWidth;       // Type
        _savedList.Columns[3].Width = valueWidth;      // Value
    }

    private string ReadCurrentValue(SavedAddress saved)
    {
        if (!ProcessContext.Current.IsAttached)
            return "???";

        // Read current value from memory using byte array
        var size = GetValueSize(saved.ValueType);
        var buffer = new byte[size];
        var result = NexusEngine.Nexus_ReadProcessMemory(
            ProcessContext.Current.NativeProcessHandle,
            saved.Address,
            buffer,
            (nuint)size,
            out var bytesRead);

        if (result != NexusResult.OK || bytesRead == 0)
            return "???";

        return FormatBytes(buffer, saved.ValueType);
    }

    private static string FormatBytes(byte[] buffer, int valueType)
    {
        return valueType switch
        {
            0 => buffer[0].ToString(),
            1 => BitConverter.ToInt16(buffer, 0).ToString(),
            2 => BitConverter.ToInt32(buffer, 0).ToString(),
            3 => BitConverter.ToInt64(buffer, 0).ToString(),
            4 => BitConverter.ToSingle(buffer, 0).ToString("G"),
            5 => BitConverter.ToDouble(buffer, 0).ToString("G"),
            _ => BitConverter.ToInt32(buffer, 0).ToString()
        };
    }

    private static int GetValueSize(int valueType)
    {
        return valueType switch
        {
            0 => 1,  // Byte
            1 => 2,  // 2 Bytes
            2 => 4,  // 4 Bytes
            3 => 8,  // 8 Bytes
            4 => 4,  // Float
            5 => 8,  // Double
            _ => 4
        };
    }

    private void SavedList_DoubleClick(object? sender, EventArgs e)
    {
        if (_savedList.SelectedItems.Count == 0) return;

        var item = _savedList.SelectedItems[0];
        if (item.Tag is not SavedAddress saved) return;

        // Determine which column was clicked based on mouse position
        var mousePos = _savedList.PointToClient(Cursor.Position);
        var hitInfo = _savedList.HitTest(mousePos);

        if (hitInfo.SubItem != null)
        {
            int columnIndex = item.SubItems.IndexOf(hitInfo.SubItem);
            if (columnIndex == 0)
            {
                // Description column - edit description
                EditSavedDescription(saved, item);
                return;
            }
        }

        // Default: edit value (Value column or any other)
        EditSavedValue(saved, item);
    }

    private void EditSavedDescription(SavedAddress saved, ListViewItem item)
    {
        using var form = new Forms.MemoryRecordDescriptionForm(saved.Description);
        if (form.ShowDialog(this) == DialogResult.OK)
        {
            var newDescription = form.Description.Trim();
            if (!string.IsNullOrEmpty(newDescription))
            {
                saved.Description = newDescription;
                item.SubItems[0].Text = newDescription;
                // Additional display settings from the form can be applied here
                // form.ShowAsHex, form.ShowAsSigned, form.DisplayType, form.TextColor
                PublishStatus("Description updated", StatusType.Success);
            }
        }
    }

    private void SavedList_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Delete && _savedList.SelectedItems.Count > 0)
        {
            foreach (ListViewItem item in _savedList.SelectedItems)
            {
                if (item.Tag is SavedAddress saved)
                    _savedAddresses.Remove(saved);
                _savedList.Items.Remove(item);
            }
            e.Handled = true;
        }
    }

    private void SavedList_ItemChecked(object? sender, ItemCheckedEventArgs e)
    {
        if (e.Item.Tag is SavedAddress saved)
        {
            saved.IsFrozen = e.Item.Checked;

            if (saved.IsFrozen)
            {
                // Capture the current value to freeze
                saved.FrozenValue = ReadCurrentValueBytes(saved);
                StartFreezeTimer();
            }
            else
            {
                saved.FrozenValue = null;
                // Stop timer if no more frozen addresses
                if (!_savedAddresses.Any(a => a.IsFrozen))
                    StopFreezeTimer();
            }
        }
    }

    private System.Windows.Forms.Timer? _freezeTimer;

    private void StartFreezeTimer()
    {
        if (_freezeTimer != null) return;

        _freezeTimer = new System.Windows.Forms.Timer { Interval = 50 };
        _freezeTimer.Tick += FreezeTimer_Tick;
        _freezeTimer.Start();
    }

    private void StopFreezeTimer()
    {
        if (_freezeTimer == null) return;

        _freezeTimer.Stop();
        _freezeTimer.Dispose();
        _freezeTimer = null;
    }

    private void FreezeTimer_Tick(object? sender, EventArgs e)
    {
        if (!ProcessContext.Current.IsAttached) return;

        foreach (var saved in _savedAddresses.Where(a => a.IsFrozen && a.FrozenValue != null))
        {
            NexusEngine.WriteBytes(
                ProcessContext.Current.NativeProcessHandle,
                saved.Address,
                saved.FrozenValue!);
        }
    }

    private byte[]? ReadCurrentValueBytes(SavedAddress saved)
    {
        if (!ProcessContext.Current.IsAttached)
            return null;

        var size = GetValueSize(saved.ValueType);
        var buffer = new byte[size];
        var result = NexusEngine.Nexus_ReadProcessMemory(
            ProcessContext.Current.NativeProcessHandle,
            saved.Address,
            buffer,
            (nuint)size,
            out var bytesRead);

        if (result != NexusResult.OK || bytesRead == 0)
            return null;

        return buffer;
    }

    private void EditSavedValue(SavedAddress saved, ListViewItem item)
    {
        var currentValue = ReadCurrentValue(saved);
        using var inputForm = new Forms.InputBoxForm("Edit Value", "Enter new value:", currentValue);
        if (inputForm.ShowDialog(this) == DialogResult.OK)
        {
            var newValueStr = inputForm.Value;
            if (TryWriteValue(saved, newValueStr))
            {
                item.SubItems[3].Text = ReadCurrentValue(saved);
                PublishStatus($"Value updated at {saved.Address:X}", StatusType.Success);
            }
            else
            {
                PublishStatus("Failed to write value", StatusType.Error);
            }
        }
    }

    private bool TryWriteValue(SavedAddress saved, string valueStr)
    {
        if (!ProcessContext.Current.IsAttached)
            return false;

        try
        {
            var buffer = saved.ValueType switch
            {
                0 => [byte.Parse(valueStr)],
                1 => BitConverter.GetBytes(short.Parse(valueStr)),
                2 => BitConverter.GetBytes(int.Parse(valueStr)),
                3 => BitConverter.GetBytes(long.Parse(valueStr)),
                4 => BitConverter.GetBytes(float.Parse(valueStr)),
                5 => BitConverter.GetBytes(double.Parse(valueStr)),
                _ => BitConverter.GetBytes(int.Parse(valueStr))
            };

            return NexusEngine.WriteBytes(
                ProcessContext.Current.NativeProcessHandle,
                saved.Address,
                buffer);
        }
        catch
        {
            return false;
        }
    }

    private void RefreshSavedList()
    {
        _savedList.Items.Clear();
        foreach (var addr in _savedAddresses)
        {
            var item = new ListViewItem(addr.IsFrozen ? "❄" : "");
            item.SubItems.Add(addr.Description);
            item.SubItems.Add($"0x{addr.Address:X}");
            item.SubItems.Add(GetValueTypeName(addr.ValueType));
            item.SubItems.Add("?");
            _savedList.Items.Add(item);
        }
        _savedLabel.Text = $"Saved: {_savedAddresses.Count}";
        AutoSizeSavedListColumns();
    }

    #endregion

    #region Helper Types

    private record FoundItem
    {
        public ulong Address { get; init; }
        public string Value { get; init; } = "";
        public string Previous { get; init; } = "";
    }

    private static string GetValueTypeName(int valueType)
    {
        return valueType switch
        {
            0 => "Byte",
            1 => "2 Bytes",
            2 => "4 Bytes",
            3 => "8 Bytes",
            4 => "Float",
            5 => "Double",
            6 => "String",
            7 => "AOB",
            _ => "4 Bytes"
        };
    }

    private class SavedAddress
    {
        public ulong Address { get; set; }
        public string Description { get; set; } = "";
        public int ValueType { get; set; }
        public bool IsFrozen { get; set; }
        public byte[]? FrozenValue { get; set; }
    }

    #endregion
}
