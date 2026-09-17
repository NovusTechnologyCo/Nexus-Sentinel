// <file>
// <summary>
// UI event handlers and actions for FoundCodeForm (replace, disassembly, code list, clipboard, etc.).
// </summary>
// </file>
using Nexus.UI.Core;
using Nexus.UI.Interop;
using System.Text;


namespace Nexus.UI.Forms;

public partial class FoundCodeForm
{
    private void LvFoundCode_SelectedIndexChanged(object? sender, EventArgs e)
    {
        bool hasSelection = lvFoundCode.SelectedItems.Count > 0;
        btnReplace.Enabled = hasSelection;
        btnShowDisasm.Enabled = hasSelection;
        btnAddToCodeList.Enabled = hasSelection;
        btnMoreInfo.Enabled = hasSelection;

        UpdateDescription();
        UpdateInfoMemo();
    }

    private void UpdateDescription()
    {
        if (lvFoundCode.SelectedItems.Count == 0)
        {
            lblDescription.Text = "";
            return;
        }

        var item = lvFoundCode.SelectedItems[0];
        if (item.Tag is not FoundCodeEntry entry) return;

        var sb = new StringBuilder();
        sb.AppendLine($"Address: {entry.Address:X}");
        sb.AppendLine($"Hit count: {entry.Count}");
        sb.AppendLine($"Size: {entry.OpcodeSize} bytes");
        sb.AppendLine();
        sb.AppendLine("Original bytes:");
        sb.AppendLine(BitConverter.ToString(entry.OriginalBytes).Replace("-", " "));

        lblDescription.Text = sb.ToString();
    }

    private void UpdateInfoMemo()
    {
        if (lvFoundCode.SelectedItems.Count == 0)
        {
            memoInfo.Text = "";
            return;
        }

        var item = lvFoundCode.SelectedItems[0];
        if (item.Tag is not FoundCodeEntry entry) return;

        // Show registers if available, otherwise show extra info
        if (!string.IsNullOrEmpty(entry.RegistersText))
        {
            memoInfo.Text = entry.RegistersText;
        }
        else if (!string.IsNullOrEmpty(entry.ExtraInfo))
        {
            memoInfo.Text = entry.ExtraInfo;
        }
        else
        {
            memoInfo.Text = "";
        }
    }

    private void LvFoundCode_DoubleClick(object? sender, EventArgs e)
    {
        BtnMoreInfo_Click(sender, e);
    }

    private void BtnReplace_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero) return;

        int replaced = 0;
        int failed = 0;

        foreach (ListViewItem item in lvFoundCode.SelectedItems)
        {
            if (item.Tag is not FoundCodeEntry entry) continue;

            // Create NOP bytes
            var nops = new byte[entry.OpcodeSize];
            Array.Fill(nops, (byte)0x90);

            unsafe
            {
                fixed (byte* ptr = nops)
                {
                    var result = NexusEngine.Nexus_WriteMemory(
                        _processHandle, entry.Address, (IntPtr)ptr, (nuint)nops.Length, out _);

                    if (result == NexusResult.OK || result == NexusResult.Success)
                    {
                        replaced++;
                    }
                    else
                    {
                        failed++;
                    }
                }
            }
        }

        if (replaced > 0)
        {
            MessageBox.Show($"Replaced {replaced} instruction(s) with NOPs.",
                "Replace Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else if (failed > 0)
        {
            // All writes failed - offer admin restart
            if (!Helpers.AdminHelper.IsRunningAsAdmin())
            {
                Helpers.AdminHelper.PromptAndRestartAsAdmin(
                    this,
                    "Failed to replace instruction(s). The memory region may be protected.",
                    _processId);
            }
            else
            {
                MessageBox.Show(
                    "Failed to replace instruction(s). The memory region may be protected.",
                    "Replace Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
    }

    private void BtnShowDisasm_Click(object? sender, EventArgs e)
    {
        if (lvFoundCode.SelectedItems.Count == 0) return;
        var item = lvFoundCode.SelectedItems[0];
        if (item.Tag is not FoundCodeEntry entry) return;

        // Navigate to address in the Disassembler panel
        EventBus.Instance.Publish(new NavigateToAddressEvent(entry.Address, "Disassembler"));
    }

    private void BtnAddToCodeList_Click(object? sender, EventArgs e)
    {
        // Note: "Code list" refers to Cheat Engine's Advanced Options feature where you can track
        // specific code locations. This would require implementing an AdvancedOptionsForm with
        // a list of tracked code addresses and their hit counts. For now, add to watch list instead.
        int added = 0;
        foreach (ListViewItem item in lvFoundCode.SelectedItems)
        {
            if (item.Tag is FoundCodeEntry entry)
            {
                // Add to watch list via EventBus
                Core.EventBus.Instance.Publish(new Core.AddToWatchListEvent(
                    entry.Address,
                    "Int64",
                    $"Code: {entry.Instruction}"));
                added++;
            }
        }

        if (added > 0)
            MessageBox.Show($"Added {added} instruction address(es) to the address list.",
                "Add to Code List", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void BtnMoreInfo_Click(object? sender, EventArgs e)
    {
        if (lvFoundCode.SelectedItems.Count == 0) return;
        var item = lvFoundCode.SelectedItems[0];
        if (item.Tag is not FoundCodeEntry entry) return;

        var sb = new StringBuilder();
        sb.AppendLine($"Address: {entry.Address:X}");
        sb.AppendLine($"Instruction: {entry.Instruction}");
        sb.AppendLine($"Hit count: {entry.Count}");
        sb.AppendLine($"Original bytes: {BitConverter.ToString(entry.OriginalBytes)}");
        sb.AppendLine();

        if (!string.IsNullOrEmpty(entry.RegistersText))
        {
            sb.AppendLine(entry.RegistersText);
        }
        else if (!string.IsNullOrEmpty(entry.ExtraInfo))
        {
            sb.AppendLine("Extra information:");
            sb.AppendLine(entry.ExtraInfo);
        }

        // Show in a larger dialog with scrollable text
        using var dialog = new Form
        {
            Text = "Instruction Details",
            Size = new Size(500, 450),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.Sizable,
            MaximizeBox = true,
            MinimizeBox = false
        };

        var txtDetails = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            Font = new Font("Consolas", 9.5F),
            Text = sb.ToString()
        };

        var btnClose = new Button
        {
            Text = "Close",
            Dock = DockStyle.Bottom,
            Height = 35,
            DialogResult = DialogResult.OK
        };

        dialog.Controls.Add(txtDetails);
        dialog.Controls.Add(btnClose);
        dialog.AcceptButton = btnClose;
        dialog.ShowDialog(this);
    }

    private void CtxSelectAll_Click(object? sender, EventArgs e)
    {
        foreach (ListViewItem item in lvFoundCode.Items)
        {
            item.Selected = true;
        }
    }

    private void CtxCopyToClipboard_Click(object? sender, EventArgs e)
    {
        var sb = new StringBuilder();
        foreach (ListViewItem item in lvFoundCode.SelectedItems)
        {
            if (item.Tag is FoundCodeEntry entry)
            {
                sb.AppendLine($"{entry.Address:X} ({entry.Count}x) - {entry.Instruction}");
            }
        }

        if (sb.Length > 0)
        {
            Clipboard.SetText(sb.ToString());
        }
    }

    private void CtxSaveToFile_Click(object? sender, EventArgs e)
    {
        using var saveDialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            DefaultExt = ".txt"
        };

        if (saveDialog.ShowDialog(this) != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine($"Found code accessing address {_watchedAddress:X}");
        sb.AppendLine(new string('=', 50));
        sb.AppendLine();

        foreach (ListViewItem item in lvFoundCode.SelectedItems)
        {
            if (item.Tag is FoundCodeEntry entry)
            {
                sb.AppendLine($"Address: {entry.Address:X}");
                sb.AppendLine($"Instruction: {entry.Instruction}");
                sb.AppendLine($"Count: {entry.Count}");
                sb.AppendLine($"Bytes: {BitConverter.ToString(entry.OriginalBytes)}");
                sb.AppendLine();
            }
        }

        File.WriteAllText(saveDialog.FileName, sb.ToString());
    }
}
