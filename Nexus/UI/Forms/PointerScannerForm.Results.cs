// <file>
// <summary>
// Pointer scanner form - results display, sorting, and value reading.
// </summary>
// </file>
using Nexus.UI.Interop;

namespace Nexus.UI.Forms;

public partial class PointerScannerForm
{
    private void LvResults_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        if (e.ItemIndex < 0 || e.ItemIndex >= _engineResults.Count)
        {
            e.Item = new ListViewItem("???");
            return;
        }

        var path = _engineResults[e.ItemIndex];
        // Calculate base offset - can be negative if pointer is before module base
        long baseOffset = (long)path.BaseAddress - (long)path.ModuleBase;
        string baseOffsetStr = baseOffset >= 0 ? $"+{baseOffset:X}" : $"-{Math.Abs(baseOffset):X}";
        var item = new ListViewItem($"{path.ModuleName}{baseOffsetStr}");
        item.SubItems.Add(path.OffsetsString);

        // Resolve the pointer path to get the final address
        ulong finalAddress = ResolvePointerPath(path);
        item.SubItems.Add($"{finalAddress:X}");

        // Read value at final address
        string value = ReadValueAtAddress(finalAddress);
        item.SubItems.Add(value);

        e.Item = item;
    }

    private ulong ResolvePointerPath(NexusPointerPath path)
    {
        if (_processHandle == IntPtr.Zero || path.OffsetCount == 0)
            return path.BaseAddress;

        // Extract the active offsets from the fixed-size array
        var offsets = new long[path.OffsetCount];
        Array.Copy(path.Offsets, offsets, path.OffsetCount);

        return NexusEngine.ResolvePointerChain(_processHandle, path.BaseAddress, offsets);
    }

    private string ReadValueAtAddress(ulong address)
    {
        if (_processHandle == IntPtr.Zero || address == 0) return "???";

        int typeIndex = _cbType.SelectedIndex;
        return typeIndex switch
        {
            0 => (NexusHelper.ReadMemory<byte>(_processHandle, address) ?? 0).ToString(),
            1 => (NexusHelper.ReadMemory<short>(_processHandle, address) ?? 0).ToString(),
            2 => (NexusHelper.ReadMemory<int>(_processHandle, address) ?? 0).ToString(),
            3 => (NexusHelper.ReadMemory<long>(_processHandle, address) ?? 0).ToString(),
            4 => (NexusHelper.ReadMemory<float>(_processHandle, address) ?? 0).ToString("G"),
            5 => (NexusHelper.ReadMemory<double>(_processHandle, address) ?? 0).ToString("G"),
            _ => (NexusHelper.ReadMemory<int>(_processHandle, address) ?? 0).ToString()
        };
    }

    private void LvResults_DoubleClick(object? sender, EventArgs e)
    {
        AddSelectedToAddressList();
    }

    private void LvResults_ColumnClick(object? sender, ColumnClickEventArgs e)
    {
        // Toggle sort direction if clicking the same column
        if (e.Column == _sortColumn)
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _sortColumn = e.Column;
            _sortAscending = true;
        }

        // Sort the results
        SortResults();
    }

    private void SortResults()
    {
        if (_engineResults.Count == 0) return;

        _engineResults.Sort((a, b) =>
        {
            int result = _sortColumn switch
            {
                0 => // Base Address - sort by module name then offset
                    string.Compare(a.ModuleName, b.ModuleName, StringComparison.OrdinalIgnoreCase) != 0
                        ? string.Compare(a.ModuleName, b.ModuleName, StringComparison.OrdinalIgnoreCase)
                        : (a.BaseAddress - a.ModuleBase).CompareTo(b.BaseAddress - b.ModuleBase),
                1 => // Offsets - sort by offset count then first offset
                    a.OffsetCount != b.OffsetCount
                        ? a.OffsetCount.CompareTo(b.OffsetCount)
                        : (a.OffsetCount > 0 ? a.Offsets[0].CompareTo(b.Offsets[0]) : 0),
                2 => // Points to - sort by resolved address
                    ResolvePointerPath(a).CompareTo(ResolvePointerPath(b)),
                3 => // Value - handled separately as it requires reading memory
                    0,
                _ => 0
            };
            return _sortAscending ? result : -result;
        });

        _lvResults.Refresh();
    }

    private void AutoSizeColumns()
    {
        if (_lvResults.Columns.Count == 0) return;

        // Auto-size each column to fit content
        _lvResults.BeginUpdate();
        foreach (ColumnHeader col in _lvResults.Columns)
        {
            col.Width = -2; // Auto-size to content + header
        }
        _lvResults.EndUpdate();
    }

    private void LoadResultsFromEngine()
    {
        if (_scanHandle == IntPtr.Zero) return;

        // Get result count
        var result = NexusEngine.Nexus_PointerScanGetResultCount(_scanHandle, out ulong count);
        if (result != NexusResult.OK) return;

        _engineResults.Clear();

        // Load results in batches
        const int batchSize = 1000;
        ulong offset = 0;
        while (offset < count)
        {
            var batch = new NexusPointerPath[batchSize];
            result = NexusEngine.Nexus_PointerScanGetResults(
                _scanHandle,
                offset,
                batch,
                (nuint)batchSize,
                out nuint actualCount);

            if (result != NexusResult.OK) break;

            for (int i = 0; i < (int)actualCount; i++)
            {
                _engineResults.Add(batch[i]);
            }

            offset += actualCount;
            if (actualCount < batchSize) break;
        }

        _lvResults.VirtualListSize = _engineResults.Count;
        _lvResults.Refresh();

        // Auto-size columns to fit content
        AutoSizeColumns();

        _lblProgress.Text = $"Loaded {_engineResults.Count:N0} pointer paths";
    }

    #region Results Actions

    private void AddSelectedToAddressList()
    {
        if (_lvResults.SelectedIndices.Count == 0)
            return;

        // Add selected pointer paths to saved addresses via EventBus
        int addedCount = 0;
        foreach (int index in _lvResults.SelectedIndices)
        {
            if (index >= 0 && index < _engineResults.Count)
            {
                var result = _engineResults[index];
                var offsets = result.Offsets.Take((int)result.OffsetCount).Select(o => o.ToString("X"));
                var description = $"Pointer: {result.ModuleName}+{string.Join("->", offsets)}";

                // Publish event to add to watch list
                Core.EventBus.Instance.Publish(new Core.AddToWatchListEvent(
                    result.BaseAddress,
                    "Pointer",
                    description));
                addedCount++;
            }
        }

        if (addedCount > 0)
            MessageBox.Show($"Added {addedCount} pointer path(s) to the address list.",
                "Added", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ResyncModuleList()
    {
        // Module list is refreshed automatically when results are displayed
        // This triggers a refresh of the results view which will re-resolve module names
        RefreshResults();
    }

    private void RefreshResults()
    {
        _lvResults.Refresh();
    }

    private void ToggleSigned()
    {
        _showSigned = !_showSigned;
        RefreshResults();
    }

    private void ToggleHexadecimal()
    {
        _showHexadecimal = !_showHexadecimal;
        RefreshResults();
    }

    #endregion
}
