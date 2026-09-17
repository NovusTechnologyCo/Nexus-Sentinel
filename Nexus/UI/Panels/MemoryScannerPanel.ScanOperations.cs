// <file>
// <summary>
// Partial class for MemoryScannerPanel containing scan execution logic.
// Handles first scan, next scan, undo scan, value type parsing, scan progress,
// result population, and scan state management.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;

namespace Nexus.UI.Panels;

public partial class MemoryScannerPanel
{
    #region Scan Operations

    private void NewScan_Click(object? sender, EventArgs e)
    {
        // Reset scan state for a new first scan - do NOT perform the scan
        _isFirstScan = true;
        _valueTypeCombo.Enabled = true; // Unlock value type for new scan
        _originalValues.Clear(); // Clear stored original values
        _foundList.VirtualListSize = 0;
        _foundLabel.Text = "Found: 0";
        UpdateButtonStates();
        PublishStatus("Ready for new scan", StatusType.Info);
    }

    private void FirstScan_Click(object? sender, EventArgs e)
    {
        if (!ProcessContext.Current.IsAttached)
        {
            PublishStatus("No process attached", StatusType.Warning);
            return;
        }

        if (_scanHandle == IntPtr.Zero)
        {
            PublishStatus("Scanner not initialized", StatusType.Error);
            return;
        }

        var value = _scanValue.Text.Trim();
        bool needsValue = _scanTypeCombo.SelectedIndex < 4; // Exact, Bigger, Smaller, Between
        if (needsValue && string.IsNullOrEmpty(value))
        {
            PublishStatus("Enter a value to scan for", StatusType.Warning);
            return;
        }

        // Build scan configuration
        _scanValueType = MapValueType(_valueTypeCombo.SelectedIndex);
        var config = new NexusScanConfig
        {
            ValueType = _scanValueType,
            CompareType = MapCompareType(_scanTypeCombo.SelectedIndex),
            Options = GetScanOptions(),
            Alignment = 4,
            StartAddress = ParseAddress(_startAddress.Text),
            EndAddress = ParseAddress(_stopAddress.Text),
            ThreadCount = 0 // Auto
        };

        // Parse value
        if (needsValue && !TryParseValue(value, config.ValueType, _hexCheckBox.Checked, ref config.Value1))
        {
            PublishStatus("Invalid value format", StatusType.Warning);
            return;
        }

        // Parse second value for "between" scan
        if (_scanTypeCombo.SelectedIndex == 3 && _scanValue2.Visible)
        {
            if (!TryParseValue(_scanValue2.Text.Trim(), config.ValueType, _hexCheckBox.Checked, ref config.Value2))
            {
                PublishStatus("Invalid second value format", StatusType.Warning);
                return;
            }
        }

        // Perform scan
        Cursor = Cursors.WaitCursor;
        PublishStatus($"Scanning for {value} (type={config.ValueType}, compare={config.CompareType})...", StatusType.Info);
        try
        {
            var result = NexusEngine.Nexus_AdvScanFirst(_scanHandle, ref config);
            if (result != NexusResult.OK)
            {
                PublishStatus($"Scan failed: {NexusHelper.GetErrorMessage(result)} (code {(int)result})", StatusType.Error);
                return;
            }

            _isFirstScan = false;
            _valueTypeCombo.Enabled = false; // Lock value type after first scan

            // Store original values from first scan
            StoreOriginalValues();

            UpdateFoundList();
            UpdateButtonStates();

            // Get result count for status
            NexusEngine.Nexus_AdvScanGetResultCount(_scanHandle, out var count);
            PublishStatus($"Scan complete: found {count:N0} results", StatusType.Success);
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    private void NextScan_Click(object? sender, EventArgs e)
    {
        if (_scanHandle == IntPtr.Zero)
        {
            PublishStatus("No active scan", StatusType.Warning);
            return;
        }

        var value = _scanValue.Text.Trim();
        bool needsValue = _scanTypeCombo.SelectedIndex < 4;

        var config = new NexusScanConfig
        {
            ValueType = _scanValueType,
            CompareType = MapCompareType(_scanTypeCombo.SelectedIndex),
            Options = GetScanOptions()
        };

        if (needsValue && !string.IsNullOrEmpty(value))
        {
            TryParseValue(value, config.ValueType, _hexCheckBox.Checked, ref config.Value1);
        }

        Cursor = Cursors.WaitCursor;
        try
        {
            var result = NexusEngine.Nexus_AdvScanNext(_scanHandle, ref config);
            if (result != NexusResult.OK)
            {
                PublishStatus($"Next scan failed: {NexusHelper.GetErrorMessage(result)}", StatusType.Error);
                return;
            }

            UpdateFoundList();
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    private void Undo_Click(object? sender, EventArgs e)
    {
        if (_scanHandle == IntPtr.Zero) return;

        var result = NexusEngine.Nexus_AdvScanUndo(_scanHandle);
        if (result == NexusResult.OK)
        {
            UpdateFoundList();
            PublishStatus("Scan undone", StatusType.Info);
        }
        else
        {
            PublishStatus($"Undo failed: {NexusHelper.GetErrorMessage(result)}", StatusType.Warning);
        }
    }

    private void ResetScan()
    {
        _foundItems.Clear();
        _foundList.VirtualListSize = 0;
        _foundLabel.Text = "Found: 0";
        _isFirstScan = true;
        UpdateButtonStates();
    }

    private void UpdateFoundList()
    {
        if (_scanHandle == IntPtr.Zero)
        {
            _foundLabel.Text = "Found: 0";
            _foundList.VirtualListSize = 0;
            return;
        }

        var result = NexusEngine.Nexus_AdvScanGetResultCount(_scanHandle, out _resultCount);
        if (result != NexusResult.OK)
        {
            _foundLabel.Text = $"Found: (error)";
            return;
        }

        _foundLabel.Text = $"Found: {_resultCount:N0}";

        // Only show addresses when count is manageable
        const int MaxDisplayCount = 50000;
        if (_resultCount <= MaxDisplayCount)
        {
            _foundList.VirtualListSize = (int)_resultCount;
            _foundList.Invalidate();
        }
        else
        {
            _foundList.VirtualListSize = 0;
            PublishStatus($"Found {_resultCount:N0} addresses - narrow down your search", StatusType.Info);
        }
    }

    private void StoreOriginalValues()
    {
        if (_scanHandle == IntPtr.Zero) return;

        _originalValues.Clear();
        NexusEngine.Nexus_AdvScanGetResultCount(_scanHandle, out var count);

        // Only store if count is manageable (avoid memory issues)
        const int MaxStoreCount = 100000;
        if (count > MaxStoreCount) return;

        // Fetch results in batches
        const int BatchSize = 1000;
        var results = new NexusScanResultEntry[BatchSize];

        for (ulong offset = 0; offset < count; offset += BatchSize)
        {
            var toFetch = (nuint)Math.Min(BatchSize, (int)(count - offset));
            var fetchResult = NexusEngine.Nexus_AdvScanGetResults(
                _scanHandle, offset, results, toFetch, out var fetched);

            if (fetchResult != NexusResult.OK) break;

            for (nuint i = 0; i < fetched; i++)
            {
                _originalValues[results[i].Address] = results[i].CurrentValue;
            }
        }
    }

    #endregion

    #region Value Type Mapping

    private int MapValueType(int index)
    {
        // Map UI combo index to NexusScanValueType
        return index switch
        {
            0 => 0, // Byte
            1 => 1, // 2 Bytes (Int16)
            2 => 2, // 4 Bytes (Int32)
            3 => 3, // 8 Bytes (Int64)
            4 => 4, // Float
            5 => 5, // Double
            6 => 6, // String
            7 => 8, // Array of Bytes
            _ => 2  // Default to 4 Bytes
        };
    }

    private int MapCompareType(int index)
    {
        // Map UI combo index to NexusScanCompareType
        return index switch
        {
            0 => 0,  // Exact Value
            1 => 1,  // Bigger than
            2 => 2,  // Smaller than
            3 => 6,  // Value Between
            4 => 13, // Unknown Initial Value
            5 => 7,  // Increased Value
            6 => 9,  // Decreased Value
            7 => 11, // Changed Value
            8 => 12, // Unchanged Value
            9 => 8,  // Increased by
            10 => 10, // Decreased by
            _ => 0
        };
    }

    private uint GetScanOptions()
    {
        // Option flags from nexus_scanner.h:
        // NEXUS_SCANOPT_WRITABLE = 0x0001 (must be writable)
        // NEXUS_SCANOPT_EXECUTABLE = 0x0002 (must be executable)
        // NEXUS_SCANOPT_FAST_SCAN = 0x2000
        // When unchecked, we DON'T add the flag (don't care), not exclude
        uint options = 0;
        if (_writableCheck.Checked) options |= 0x0001; // Must be writable
        if (_executableCheck.Checked) options |= 0x0002; // Must be executable
        if (_fastScanCheck?.Checked == true) options |= 0x2000; // Fast scan
        return options;
    }

    private static ulong ParseAddress(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var addr) ? addr : 0;
    }

    private static bool TryParseValue(string text, int valueType, bool isHex, ref NexusScanValue scanValue)
    {
        // Use the engine's value parsing
        if (NexusEngine.TryParseValue(text, (NexusScanValueType)valueType, isHex, out var result))
        {
            scanValue = result;
            return true;
        }
        return false;
    }

    #endregion
}
