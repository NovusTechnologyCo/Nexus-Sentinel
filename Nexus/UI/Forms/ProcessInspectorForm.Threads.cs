// <file>
// <summary>
// Process inspector: threads tab and modules tab logic.
// </summary>
// </file>
using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Providers;
using Nexus.UI.Styles;
using static Nexus.UI.UIHelpers;

namespace Nexus.UI.Forms;

public partial class ProcessInspectorForm
{
    #region Threads Tab

    private void RefreshThreads()
    {
        NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out nuint count);
        if (count == 0) { _lvThreads.Items.Clear(); return; }

        var threads = new NexusThreadInfo[count];
        NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, count, out _);

        _lvThreads.BeginUpdate();
        _lvThreads.Items.Clear();
        _threads.Clear();

        foreach (var t in threads)
        {
            var info = new ThreadInfo
            {
                ThreadId = (int)t.ThreadId,
                StartAddress = t.StartAddress,
                Priority = t.BasePriority + t.DeltaPriority,
                State = (uint)t.State
            };
            _threads.Add(info);

            var item = new ListViewItem($"{t.ThreadId}");
            item.SubItems.Add($"0x{t.StartAddress:X}");
            item.SubItems.Add($"{t.BasePriority + t.DeltaPriority}");
            item.SubItems.Add(GetThreadStateString((NexusThreadState)t.State));
            item.SubItems.Add($"{t.BasePriority}");
            item.SubItems.Add($"{t.WaitReason}");
            item.Tag = info;
            _lvThreads.Items.Add(item);
        }
        _lvThreads.EndUpdate();
    }

    private string GetThreadStateString(NexusThreadState state)
    {
        if (state.HasFlag(NexusThreadState.Suspended)) return "Suspended";
        if (state.HasFlag(NexusThreadState.Waiting)) return "Waiting";
        if (state.HasFlag(NexusThreadState.Running)) return "Running";
        if (state.HasFlag(NexusThreadState.Terminated)) return "Terminated";
        return "Unknown";
    }

    private ThreadInfo? GetSelectedThread() =>
        _lvThreads.SelectedItems.Count > 0 ? _lvThreads.SelectedItems[0].Tag as ThreadInfo : null;

    private void SuspendThread()
    {
        var t = GetSelectedThread(); if (t == null) return;
        NexusEngine.Nexus_SuspendThread((uint)t.ThreadId);
        RefreshThreads();
    }

    private void ResumeThread()
    {
        var t = GetSelectedThread(); if (t == null) return;
        NexusEngine.Nexus_ResumeThread((uint)t.ThreadId);
        RefreshThreads();
    }

    private void SetThreadPriority()
    {
        var t = GetSelectedThread(); if (t == null) return;
        var priorities = new[] { ("Idle", -15), ("Lowest", -2), ("Below Normal", -1), ("Normal", 0), ("Above Normal", 1), ("Highest", 2), ("Time Critical", 15) };

        using var dialog = new Form
        {
            Text = "Set Thread Priority", Size = new Size(300, 180), FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent, MaximizeBox = false, MinimizeBox = false
        };
        var cbo = new ComboBox { Location = new Point(20, 20), Width = 240, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var (name, _) in priorities) cbo.Items.Add(name);
        cbo.SelectedIndex = 3;
        var btnOk = new Button { Text = "OK", Location = new Point(100, 70), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(190, 70), DialogResult = DialogResult.Cancel };
        dialog.Controls.AddRange(new Control[] { cbo, btnOk, btnCancel });
        dialog.AcceptButton = btnOk; dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && cbo.SelectedIndex >= 0)
        {
            var result = NexusEngine.Nexus_SetThreadPriority((uint)t.ThreadId, priorities[cbo.SelectedIndex].Item2);
            if (result == NexusResult.OK || result == NexusResult.Success) RefreshThreads();
            else MessageBox.Show($"Failed: {NexusHelper.GetErrorMessage(result)}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ViewThreadContext()
    {
        var t = GetSelectedThread(); if (t == null) return;

        // Suspend thread to get consistent context
        NexusEngine.Nexus_SuspendThread((uint)t.ThreadId);
        try
        {
            var result = NexusEngine.Nexus_GetThreadContext((uint)t.ThreadId, out var ctx);
            if (result != NexusResult.OK && result != NexusResult.Success)
            {
                MessageBox.Show($"Failed to get thread context: {NexusHelper.GetErrorMessage(result)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Thread {t.ThreadId} Context");
            sb.AppendLine(new string('=', 40));
            sb.AppendLine();
            sb.AppendLine("General Purpose Registers:");
            sb.AppendLine($"  RAX = {ctx.Rax:X16}    RBX = {ctx.Rbx:X16}");
            sb.AppendLine($"  RCX = {ctx.Rcx:X16}    RDX = {ctx.Rdx:X16}");
            sb.AppendLine($"  RSI = {ctx.Rsi:X16}    RDI = {ctx.Rdi:X16}");
            sb.AppendLine($"  RBP = {ctx.Rbp:X16}    RSP = {ctx.Rsp:X16}");
            sb.AppendLine($"  R8  = {ctx.R8:X16}    R9  = {ctx.R9:X16}");
            sb.AppendLine($"  R10 = {ctx.R10:X16}    R11 = {ctx.R11:X16}");
            sb.AppendLine($"  R12 = {ctx.R12:X16}    R13 = {ctx.R13:X16}");
            sb.AppendLine($"  R14 = {ctx.R14:X16}    R15 = {ctx.R15:X16}");
            sb.AppendLine();
            sb.AppendLine("Instruction Pointer:");
            sb.AppendLine($"  RIP = {ctx.Rip:X16}");
            sb.AppendLine();
            sb.AppendLine("Flags:");
            sb.AppendLine($"  EFLAGS = {ctx.EFlags:X8}");
            sb.AppendLine();
            sb.AppendLine("Segment Registers:");
            sb.AppendLine($"  CS={ctx.SegCs:X4}  DS={ctx.SegDs:X4}  ES={ctx.SegEs:X4}  FS={ctx.SegFs:X4}  GS={ctx.SegGs:X4}  SS={ctx.SegSs:X4}");
            sb.AppendLine();
            sb.AppendLine("Debug Registers:");
            sb.AppendLine($"  DR0 = {ctx.Dr0:X16}    DR1 = {ctx.Dr1:X16}");
            sb.AppendLine($"  DR2 = {ctx.Dr2:X16}    DR3 = {ctx.Dr3:X16}");
            sb.AppendLine($"  DR6 = {ctx.Dr6:X16}    DR7 = {ctx.Dr7:X16}");

            using var dlg = new Form
            {
                Text = $"Thread {t.ThreadId} Context",
                Size = new Size(500, 500),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = NexusTheme.BackgroundDark
            };
            var txt = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                Dock = DockStyle.Fill,
                Font = new Font("Consolas", 9f),
                BackColor = NexusTheme.BackgroundDark,
                ForeColor = NexusTheme.TextPrimary,
                Text = sb.ToString(),
                ScrollBars = ScrollBars.Both,
                WordWrap = false
            };
            dlg.Controls.Add(txt);
            dlg.ShowDialog(this);
        }
        finally
        {
            NexusEngine.Nexus_ResumeThread((uint)t.ThreadId);
        }
    }

    private void ViewThreadStack()
    {
        var t = GetSelectedThread(); if (t == null) return;
        using var form = new StackViewForm(_processHandle, (uint)t.ThreadId);
        form.ShowDialog(this);
    }

    private void GoToThreadStartAddress()
    {
        var t = GetSelectedThread(); if (t == null) return;
        OnNavigateToAddress?.Invoke(this, t.StartAddress);
    }

    private void TerminateSelectedThread()
    {
        var t = GetSelectedThread(); if (t == null) return;
        if (MessageBox.Show($"WARNING: Terminating thread {t.ThreadId} may crash the target.\n\nContinue?",
            "Terminate Thread", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        var result = NexusEngine.Nexus_TerminateThread((uint)t.ThreadId, 0);
        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            MessageBox.Show($"Thread {t.ThreadId} terminated.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            RefreshThreads();
        }
        else MessageBox.Show($"Failed: {NexusHelper.GetErrorMessage(result)}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    #endregion

    #region Modules Tab

    private void RefreshModules()
    {
        _allModules.Clear();
        NexusEngine.Nexus_EnumerateModules(_processHandle, null, 0, out nuint count);
        if (count == 0) { _lvModules.Items.Clear(); _lblModuleCount.Text = "0 modules"; return; }

        var modules = new NexusModuleInfo[count];
        NexusEngine.Nexus_EnumerateModules(_processHandle, modules, count, out _);

        foreach (var mod in modules)
        {
            _allModules.Add(new ModuleEntry
            {
                BaseAddress = mod.BaseAddress, Size = mod.Size,
                Name = mod.Name, Path = mod.Path,
                IsSystemModule = IsSystemPath(mod.Path)
            });
        }
        _allModules.Sort((a, b) => a.BaseAddress.CompareTo(b.BaseAddress));
        ApplyModuleFilter();
    }

    private bool IsSystemPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\windows\") || lower.Contains(@"\system32\") ||
               lower.Contains(@"\syswow64\") || lower.Contains(@"\winsxs\");
    }

    private void ApplyModuleFilter()
    {
        var filter = _txtModuleFilter.Text.ToLowerInvariant();
        var showSystem = _chkShowSystemModules.Checked;

        _lvModules.BeginUpdate();
        _lvModules.Items.Clear();
        var displayed = 0;

        foreach (var mod in _allModules)
        {
            if (!showSystem && mod.IsSystemModule) continue;
            if (!string.IsNullOrEmpty(filter) &&
                !mod.Name.ToLowerInvariant().Contains(filter) &&
                !mod.Path.ToLowerInvariant().Contains(filter)) continue;

            var item = new ListViewItem($"0x{mod.BaseAddress:X16}");
            item.SubItems.Add(FormatSize(mod.Size));
            item.SubItems.Add(mod.Name);
            item.SubItems.Add(mod.Path);
            item.Tag = mod;
            if (mod.IsSystemModule) item.ForeColor = Color.Gray;
            _lvModules.Items.Add(item);
            displayed++;
        }
        _lvModules.EndUpdate();
        _lblModuleCount.Text = displayed != _allModules.Count ? $"{displayed} modules (of {_allModules.Count})" : $"{displayed} modules";
    }

    private ModuleEntry? GetSelectedModule() =>
        _lvModules.SelectedItems.Count > 0 ? _lvModules.SelectedItems[0].Tag as ModuleEntry : null;

    private void BrowseModule() { var m = GetSelectedModule(); if (m != null) OnNavigateToAddress?.Invoke(this, m.BaseAddress); }
    private void DisassembleModuleEntry() { var m = GetSelectedModule(); if (m != null) OnNavigateToAddress?.Invoke(this, m.BaseAddress); }
    private void CopyModuleAddress() { var m = GetSelectedModule(); if (m != null) Clipboard.SetText($"0x{m.BaseAddress:X}"); }
    private void CopyModuleName() { var m = GetSelectedModule(); if (m != null) Clipboard.SetText(m.Name); }
    private void CopyModulePath() { var m = GetSelectedModule(); if (m != null) Clipboard.SetText(m.Path); }

    private void DumpModule()
    {
        var mod = GetSelectedModule(); if (mod == null) return;
        using var dlg = new SaveFileDialog { Filter = "All files (*.*)|*.*", FileName = mod.Name };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        var buffer = new byte[mod.Size];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, mod.BaseAddress, buffer, (nuint)mod.Size, out var read);
        if (result == NexusResult.Success || result == NexusResult.OK)
        {
            using var fs = new FileStream(dlg.FileName, FileMode.Create);
            fs.Write(buffer, 0, (int)read);
            MessageBox.Show($"Dumped {read} bytes to {dlg.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else MessageBox.Show($"Failed to read memory: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private void ViewModuleExports()
    {
        var m = GetSelectedModule(); if (m == null) return;

        var exports = NexusEngine.GetModuleExports(_processHandle, m.BaseAddress);
        if (exports.Length == 0)
        {
            MessageBox.Show($"No exports found in {m.Name}", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dlg = new Form
        {
            Text = $"Exports - {m.Name} ({exports.Length})",
            Size = new Size(800, 500),
            StartPosition = FormStartPosition.CenterParent,
            BackColor = NexusTheme.BackgroundDark
        };

        var lv = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            BackColor = NexusTheme.BackgroundDark,
            ForeColor = NexusTheme.TextPrimary,
            Font = new Font("Consolas", 9f)
        };
        lv.Columns.Add("Address", 140);
        lv.Columns.Add("Ordinal", 60);
        lv.Columns.Add("Name", 300);
        lv.Columns.Add("Forward", 250);
        NexusTheme.StyleListView(lv);

        foreach (var exp in exports.OrderBy(e => e.Ordinal))
        {
            var item = new ListViewItem($"0x{m.BaseAddress + exp.Address:X16}");
            item.SubItems.Add(exp.Ordinal.ToString());
            item.SubItems.Add(exp.Name ?? $"(ordinal {exp.Ordinal})");
            item.SubItems.Add(exp.IsForwarded != 0 ? exp.ForwardName : "");
            lv.Items.Add(item);
        }

        dlg.Controls.Add(lv);
        dlg.ShowDialog(this);
    }

    private void ViewModuleImports()
    {
        var m = GetSelectedModule(); if (m == null) return;

        var imports = NexusEngine.GetModuleImports(_processHandle, m.BaseAddress);
        if (imports.Length == 0)
        {
            MessageBox.Show($"No imports found in {m.Name}", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dlg = new Form
        {
            Text = $"Imports - {m.Name} ({imports.Length})",
            Size = new Size(900, 500),
            StartPosition = FormStartPosition.CenterParent,
            BackColor = NexusTheme.BackgroundDark
        };

        var lv = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            BackColor = NexusTheme.BackgroundDark,
            ForeColor = NexusTheme.TextPrimary,
            Font = new Font("Consolas", 9f)
        };
        lv.Columns.Add("IAT Address", 140);
        lv.Columns.Add("Module", 150);
        lv.Columns.Add("Function", 300);
        lv.Columns.Add("Ordinal", 70);
        NexusTheme.StyleListView(lv);

        foreach (var imp in imports.OrderBy(i => i.ModuleName).ThenBy(i => i.FunctionName))
        {
            var item = new ListViewItem($"0x{imp.IatAddress:X16}");
            item.SubItems.Add(imp.ModuleName ?? "");
            item.SubItems.Add(imp.IsOrdinal != 0 ? $"(ordinal {imp.Ordinal})" : imp.FunctionName ?? "");
            item.SubItems.Add(imp.IsOrdinal != 0 ? imp.Ordinal.ToString() : "");
            lv.Items.Add(item);
        }

        dlg.Controls.Add(lv);
        dlg.ShowDialog(this);
    }

    #endregion
}
