// <file>
// <summary>
// Exceptions and tracer tab logic for the debugger form.
// </summary>
// </file>
using System.Text;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class DebuggerForm
{
    #region Exceptions Tab

    private void LoadDefaultExceptions()
    {
        _exceptions.AddRange(new[]
        {
            new ExceptionEntry { ExceptionCode = 0x80000001, Name = "EXCEPTION_GUARD_PAGE", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0x80000002, Name = "EXCEPTION_DATATYPE_MISALIGNMENT", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0x80000003, Name = "EXCEPTION_BREAKPOINT", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0x80000004, Name = "EXCEPTION_SINGLE_STEP", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC0000005, Name = "EXCEPTION_ACCESS_VIOLATION", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC0000006, Name = "EXCEPTION_IN_PAGE_ERROR", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC000001D, Name = "EXCEPTION_ILLEGAL_INSTRUCTION", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC0000094, Name = "EXCEPTION_INT_DIVIDE_BY_ZERO", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC00000FD, Name = "EXCEPTION_STACK_OVERFLOW", Ignore = false },
            new ExceptionEntry { ExceptionCode = 0xC0000135, Name = "STATUS_DLL_NOT_FOUND", Ignore = true },
            new ExceptionEntry { ExceptionCode = 0xE06D7363, Name = "C++ Exception (MS)", Ignore = true },
            new ExceptionEntry { ExceptionCode = 0x0EEDFADE, Name = "Delphi Exception", Ignore = true }
        });
        RefreshExceptions();
    }

    private void RefreshExceptions()
    {
        _lvExceptions.Items.Clear();
        foreach (var ex in _exceptions)
        {
            var item = new ListViewItem($"0x{ex.ExceptionCode:X8}") { Checked = ex.Ignore, Tag = ex };
            item.SubItems.Add(ex.Name);
            item.SubItems.Add(ex.PassToApplication ? "Yes" : "No");
            _lvExceptions.Items.Add(item);
        }
    }

    private void LvExceptions_ItemCheck(object? sender, ItemCheckEventArgs e)
    {
        if (_lvExceptions.Items[e.Index].Tag is ExceptionEntry entry)
            entry.Ignore = e.NewValue == CheckState.Checked;
    }

    private void BtnAddException_Click(object? sender, EventArgs e)
    {
        if (!InputBoxForm.Show(this, "Add Exception", "Enter exception code (hex):", out var codeStr, "C0000000", InputType.Hex))
            return;

        if (codeStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            codeStr = codeStr[2..];

        if (!uint.TryParse(codeStr, System.Globalization.NumberStyles.HexNumber, null, out var code))
        {
            MessageBox.Show("Invalid exception code.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (!InputBoxForm.Show(this, "Add Exception", "Enter exception name:", out var name, $"Custom_{code:X8}"))
            return;

        _exceptions.Add(new ExceptionEntry { ExceptionCode = code, Name = name, Ignore = true });
        RefreshExceptions();
    }

    public uint[] GetIgnoredExceptions() => _exceptions.Where(e => e.Ignore).Select(e => e.ExceptionCode).ToArray();

    #endregion

    #region Tracer Tab

    private void BtnStartTrace_Click(object? sender, EventArgs e)
    {
        if (!ulong.TryParse(_txtStartAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out var startAddress))
        {
            MessageBox.Show("Invalid start address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ulong endAddress = 0;
        if (!string.IsNullOrEmpty(_txtEndAddress.Text))
        {
            if (!ulong.TryParse(_txtEndAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out endAddress))
            {
                MessageBox.Show("Invalid end address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        var maxInstructions = (int)_nudMaxInstructions.Value;
        lock (_traceEntriesLock) { _traceEntries.Clear(); }
        _lvTrace.VirtualListSize = 0;

        _isTracing = true;
        _btnStartTrace.Enabled = false;
        _btnStopTrace.Enabled = true;
        _lblTraceStatus.Text = "Tracing...";

        Task.Run(() => PerformTrace(startAddress, endAddress, maxInstructions));
    }

    private void PerformTrace(ulong startAddress, ulong endAddress, int maxInstructions)
    {
        try
        {
            UpdateTraceStatus("Disassembling instructions...");

            int maxInstr = Math.Min(maxInstructions, 1000);
            var instructions = new NexusDisasmInstruction[maxInstr];
            var result = NexusEngine.Nexus_DisasmDecodeProcess(_processHandle, startAddress, (nuint)maxInstr, instructions, out nuint count);

            if (result == NexusResult.OK && count > 0)
            {
                for (int i = 0; i < (int)count && _isTracing; i++)
                {
                    var entry = new TraceEntry
                    {
                        Index = i + 1,
                        Address = instructions[i].Address,
                        Instruction = instructions[i].Text ?? instructions[i].Mnemonic ?? "???",
                        Registers = "",
                        ThreadId = 0
                    };
                    lock (_traceEntriesLock) { _traceEntries.Add(entry); }

                    if (endAddress != 0 && instructions[i].Address >= endAddress) break;

                    if (i % 100 == 0)
                    {
                        int cnt = i;
                        Invoke(() => { _lvTrace.VirtualListSize = cnt; _lblTraceCount.Text = $"{cnt} instructions"; });
                    }
                }
            }

            Invoke(() =>
            {
                _lvTrace.VirtualListSize = _traceEntries.Count;
                _lblTraceCount.Text = $"{_traceEntries.Count} instructions";
                _lblTraceStatus.Text = $"Trace complete - {_traceEntries.Count} instructions";
                _isTracing = false;
                _btnStartTrace.Enabled = true;
                _btnStopTrace.Enabled = false;
            });
        }
        catch (Exception ex)
        {
            Invoke(() =>
            {
                _lblTraceStatus.Text = $"Error: {ex.Message}";
                _isTracing = false;
                _btnStartTrace.Enabled = true;
                _btnStopTrace.Enabled = false;
            });
        }
    }

    private void UpdateTraceStatus(string status)
    {
        if (InvokeRequired) Invoke(() => _lblTraceStatus.Text = status);
        else _lblTraceStatus.Text = status;
    }

    private void BtnStopTrace_Click(object? sender, EventArgs e)
    {
        _isTracing = false;
        _btnStartTrace.Enabled = true;
        _btnStopTrace.Enabled = false;
        _lblTraceStatus.Text = "Trace stopped";
    }

    private void LvTrace_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        lock (_traceEntriesLock)
        {
            if (e.ItemIndex >= 0 && e.ItemIndex < _traceEntries.Count)
            {
                var entry = _traceEntries[e.ItemIndex];
                var item = new ListViewItem(entry.Index.ToString());
                item.SubItems.Add($"0x{entry.Address:X}");
                item.SubItems.Add(entry.Instruction);
                item.SubItems.Add(entry.Registers);
                item.SubItems.Add(entry.ThreadId > 0 ? entry.ThreadId.ToString() : "");
                e.Item = item;
            }
            else
            {
                e.Item = new ListViewItem("");
            }
        }
    }

    private void SaveTraceToFile(object? sender, EventArgs e)
    {
        using var saveDialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".txt"
        };

        if (saveDialog.ShowDialog() != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine("Nexus Instruction Trace");
        sb.AppendLine($"Instructions: {_traceEntries.Count}");
        sb.AppendLine(new string('=', 80));
        sb.AppendLine();

        foreach (var entry in _traceEntries)
            sb.AppendLine($"{entry.Index,6}  {entry.Address:X16}  {entry.Instruction,-40}  {entry.Registers}");

        File.WriteAllText(saveDialog.FileName, sb.ToString());
        MessageBox.Show($"Trace saved to {saveDialog.FileName}", "Save Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    #endregion

    #region Common

    private void RefreshCurrentTab()
    {
        switch (_selectedTab)
        {
            case 0: RefreshBreakpoints(); break;
            case 1: RefreshExceptions(); break;
            case 2: break; // Tracer doesn't auto-refresh
        }
    }

    #endregion
}
