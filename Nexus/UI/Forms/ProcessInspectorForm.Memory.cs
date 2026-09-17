using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Providers;
using Nexus.UI.Styles;
using static Nexus.UI.UIHelpers;

namespace Nexus.UI.Forms;

public partial class ProcessInspectorForm
{
    #region Memory Tab

    private void RefreshMemoryRegions()
    {
        _memoryRegions.Clear();
        _lvMemory.Items.Clear();

        var result = NexusEngine.Nexus_CaptureMemoryMap(_processHandle, 0, out var snapshotId);
        if (result != NexusResult.Success) { MessageBox.Show($"Failed: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }

        result = NexusEngine.Nexus_GetSnapshotRegionCount(snapshotId, out var count);
        if (result != NexusResult.Success || count == 0) { NexusEngine.Nexus_ReleaseSnapshot(snapshotId); return; }

        var regions = new NexusMemoryRegionEx[count];
        NexusEngine.Nexus_GetSnapshotRegions(snapshotId, 0, regions, count, out _);
        NexusEngine.Nexus_ReleaseSnapshot(snapshotId);

        ulong totalSize = 0;
        _lvMemory.BeginUpdate();

        foreach (var region in regions)
        {
            if (!_chkShowFreeRegions.Checked && region.State == 0x10000) continue;

            _memoryRegions.Add(new MemoryRegion
            {
                BaseAddress = region.BaseAddress, Size = region.Size, Protection = region.Protection,
                State = region.State, Type = region.Type
            });

            var item = new ListViewItem($"0x{region.BaseAddress:X16}");
            item.SubItems.Add(FormatSize(region.Size));
            item.SubItems.Add(FormatProtection(region.Protection));
            item.SubItems.Add(FormatState(region.State));
            item.SubItems.Add(FormatType(region.Type));
            item.SubItems.Add(region.ModuleName ?? "");
            item.Tag = _memoryRegions[^1];

            if (region.State == 0x10000) item.ForeColor = Color.Gray;
            else if (region.State == 0x2000) item.ForeColor = Color.DarkGray;
            else if ((region.Protection & 0x10) != 0) item.BackColor = Color.FromArgb(255, 240, 240);
            else if ((region.Protection & 0x20) != 0) item.BackColor = Color.FromArgb(255, 245, 245);
            else if ((region.Protection & 0x40) != 0) item.BackColor = Color.FromArgb(255, 230, 230);

            _lvMemory.Items.Add(item);
            if (region.State == 0x1000) totalSize += region.Size;
        }
        _lvMemory.EndUpdate();
        _lblMemoryTotal.Text = $"Total committed: {FormatSize(totalSize)} ({_memoryRegions.Count} regions)";
    }

    private string FormatProtection(uint p)
    {
        var parts = new List<string>();
        if ((p & 0x01) != 0) parts.Add("NA"); if ((p & 0x02) != 0) parts.Add("R"); if ((p & 0x04) != 0) parts.Add("RW");
        if ((p & 0x08) != 0) parts.Add("WC"); if ((p & 0x10) != 0) parts.Add("X"); if ((p & 0x20) != 0) parts.Add("RX");
        if ((p & 0x40) != 0) parts.Add("RWX"); if ((p & 0x80) != 0) parts.Add("WCX");
        if ((p & 0x100) != 0) parts.Add("+G"); if ((p & 0x200) != 0) parts.Add("+NC"); if ((p & 0x400) != 0) parts.Add("+WC");
        return parts.Count > 0 ? string.Join("", parts) : $"0x{p:X}";
    }

    private string FormatState(uint s) => s switch { 0x1000 => "Commit", 0x2000 => "Reserve", 0x10000 => "Free", _ => $"0x{s:X}" };
    private string FormatType(uint t) => t switch { 0x20000 => "Private", 0x40000 => "Mapped", 0x1000000 => "Image", _ => t == 0 ? "" : $"0x{t:X}" };

    private MemoryRegion? GetSelectedMemoryRegion() =>
        _lvMemory.SelectedItems.Count > 0 ? _lvMemory.SelectedItems[0].Tag as MemoryRegion : null;

    private void BrowseMemoryRegion() { var r = GetSelectedMemoryRegion(); if (r != null) OnNavigateToAddress?.Invoke(this, r.BaseAddress); }
    private void CopyMemoryAddress() { var r = GetSelectedMemoryRegion(); if (r != null) Clipboard.SetText($"0x{r.BaseAddress:X16}"); }
    private void CopyMemoryRow()
    {
        if (_lvMemory.SelectedItems.Count == 0) return;
        var item = _lvMemory.SelectedItems[0];
        Clipboard.SetText(string.Join("\t", Enumerable.Range(0, item.SubItems.Count).Select(i => item.SubItems[i].Text)));
    }

    private void DumpMemoryRegion()
    {
        var r = GetSelectedMemoryRegion(); if (r == null) return;
        using var dlg = new SaveFileDialog { Filter = "Binary (*.bin)|*.bin|All (*.*)|*.*", FileName = $"dump_{r.BaseAddress:X16}.bin" };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        var buffer = new byte[r.Size];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, r.BaseAddress, buffer, (nuint)r.Size, out _);
        if (result == NexusResult.Success) { File.WriteAllBytes(dlg.FileName, buffer); MessageBox.Show($"Dumped to {dlg.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information); }
        else MessageBox.Show($"Failed: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private void SetMemoryProtection()
    {
        var r = GetSelectedMemoryRegion(); if (r == null) return;

        // Simple protection selection dialog
        using var dialog = new Form
        {
            Text = "Set Memory Protection", Size = new Size(300, 200), FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent, MaximizeBox = false, MinimizeBox = false
        };
        var protections = new[] {
            ("No Access", 0x01u), ("Read Only", 0x02u), ("Read/Write", 0x04u),
            ("Execute", 0x10u), ("Execute/Read", 0x20u), ("Execute/Read/Write", 0x40u)
        };
        var cbo = new ComboBox { Location = new Point(20, 30), Width = 240, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var (name, _) in protections) cbo.Items.Add(name);
        cbo.SelectedIndex = 2;
        var lblCurrent = new Label { Text = $"Current: {FormatProtection(r.Protection)}", Location = new Point(20, 10), AutoSize = true };
        var btnOk = new Button { Text = "OK", Location = new Point(100, 80), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(190, 80), DialogResult = DialogResult.Cancel };
        dialog.Controls.AddRange(new Control[] { lblCurrent, cbo, btnOk, btnCancel });
        dialog.AcceptButton = btnOk; dialog.CancelButton = btnCancel;
        NexusTheme.ApplyTo(dialog);

        if (dialog.ShowDialog(this) == DialogResult.OK && cbo.SelectedIndex >= 0)
        {
            var result = NexusEngine.Nexus_ProtectProcessMemory(_processHandle, r.BaseAddress, (nuint)r.Size, protections[cbo.SelectedIndex].Item2, out _);
            if (result == NexusResult.Success) RefreshMemoryRegions();
            else MessageBox.Show($"Failed: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    #endregion
}
