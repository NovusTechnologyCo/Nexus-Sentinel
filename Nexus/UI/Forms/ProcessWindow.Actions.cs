// <file>
// <summary>
// Event handlers, context menu actions, menu actions, and auto-attach logic for ProcessWindow.
// </summary>
// </file>
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class ProcessWindow
{
    #region Event Handlers

    private void TxtFilter_TextChanged(object? sender, EventArgs e)
    {
        _filter = txtFilter.Text;
        RefreshAll();
    }

    private void BtnRefresh_Click(object? sender, EventArgs e)
    {
        RefreshAll();
    }

    private void RefreshAll()
    {
        RefreshProcessList();
        RefreshWindowList();
        RefreshApplicationList();
    }

    private void SwitchTab(int tabIndex)
    {
        _selectedTab = tabIndex;

        // Update button appearance using standard helper
        NexusTheme.UpdateTabSelection(_tabButtons, tabIndex);

        // Show/hide ListViews
        lvApplications.Visible = tabIndex == 0;
        lvProcesses.Visible = tabIndex == 1;
        lvWindows.Visible = tabIndex == 2;
        pnlAutoAttach.Visible = tabIndex == 3;

        // Bring visible one to front
        if (tabIndex == 0) lvApplications.BringToFront();
        else if (tabIndex == 1) lvProcesses.BringToFront();
        else if (tabIndex == 2) lvWindows.BringToFront();
        else if (tabIndex == 3) pnlAutoAttach.BringToFront();

        // Show/hide "Add to Auto-Attach" button (visible on tabs 0-2)
        btnAddToAutoAttach.Visible = tabIndex < 3;

        // Show/hide "Open" button (hidden on Auto Attach tab)
        btnOK.Visible = tabIndex < 3;
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        // Check which tab is active and get selection from there
        ListView? activeListView = _selectedTab switch
        {
            0 => lvApplications,
            1 => lvProcesses,
            2 => lvWindows,
            _ => null
        };

        if (activeListView?.SelectedItems.Count > 0)
        {
            SelectedPid = (uint)activeListView.SelectedItems[0].Tag!;
            DialogResult = DialogResult.OK;
            Close();
        }
        else
        {
            MessageBox.Show("Please select a process.", "Selection Required",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private void LvProcesses_DoubleClick(object? sender, EventArgs e)
    {
        BtnOK_Click(sender, e);
    }

    private void LvProcesses_KeyPress(object? sender, KeyPressEventArgs e)
    {
        // Accumulate filter on keypress
        if (char.IsLetterOrDigit(e.KeyChar) || e.KeyChar == ' ')
        {
            txtFilter.Text += e.KeyChar;
            txtFilter.SelectionStart = txtFilter.Text.Length;
            txtFilter.Focus();
            e.Handled = true;
        }
        else if (e.KeyChar == '\b' && txtFilter.Text.Length > 0)
        {
            txtFilter.Text = txtFilter.Text[..^1];
            e.Handled = true;
        }
    }

    private void BtnAttachDebugger_Click(object? sender, EventArgs e)
    {
        if (lvProcesses.SelectedItems.Count > 0)
        {
            SelectedPid = (uint)lvProcesses.SelectedItems[0].Tag!;
            AttachDebuggerRequested = true;  // Signal caller to attach debugger after opening process
            DialogResult = DialogResult.OK;
            Close();
        }
        else
        {
            MessageBox.Show("Please select a process to attach debugger.", "Selection Required",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void BtnNetwork_Click(object? sender, EventArgs e)
    {
        if (lvProcesses.SelectedItems.Count > 0)
        {
            var lvi = lvProcesses.SelectedItems[0];
            if (lvi.Tag is uint pid)
            {
                var form = new NetworkConnectionsForm(pid);
                form.Show();
            }
        }
        else
        {
            MessageBox.Show("Please select a process to view network connections.", "Selection Required",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    #region Auto Attach Tab

    private void RefreshAutoAttachList()
    {
        _isLoadingAutoAttach = true;
        lvAutoAttach.BeginUpdate();
        try
        {
            lvAutoAttach.Items.Clear();
            foreach (var entry in NexusSettings.Instance.AutoAttachEntries)
            {
                var text = entry.ByWindow ? entry.WindowTitle : entry.ProcessName;
                var lvi = new ListViewItem(text)
                {
                    Checked = entry.Enabled
                };
                lvi.SubItems.Add(entry.ByWindow ? "Window" : "Process");
                lvi.SubItems.Add(entry.Enabled ? "Yes" : "No");
                lvAutoAttach.Items.Add(lvi);
            }
        }
        finally
        {
            lvAutoAttach.EndUpdate();
            _isLoadingAutoAttach = false;
        }
    }

    private void BtnAutoAttachAdd_Click(object? sender, EventArgs e)
    {
        var text = txtAutoAttachName.Text.Trim();
        if (string.IsNullOrEmpty(text))
        {
            MessageBox.Show("Please enter a process name.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var entry = new AutoAttachEntry
        {
            ProcessName = text,
            WindowTitle = "",
            ByWindow = false,
            Enabled = true
        };

        NexusSettings.Instance.AutoAttachEntries.Add(entry);
        NexusSettings.Instance.Save();
        RefreshAutoAttachList();
        txtAutoAttachName.Clear();
    }

    private void BtnAutoAttachRemove_Click(object? sender, EventArgs e)
    {
        if (lvAutoAttach.SelectedItems.Count > 0)
        {
            var index = lvAutoAttach.SelectedIndices[0];
            NexusSettings.Instance.AutoAttachEntries.RemoveAt(index);
            NexusSettings.Instance.Save();
            RefreshAutoAttachList();
        }
    }

    private void BtnAutoAttachBrowse_Click(object? sender, EventArgs e)
    {
        using var openFileDialog = new OpenFileDialog
        {
            Title = "Select Executable",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            FilterIndex = 1,
            CheckFileExists = true
        };

        if (openFileDialog.ShowDialog(this) == DialogResult.OK)
        {
            txtAutoAttachName.Text = Path.GetFileName(openFileDialog.FileName);
        }
    }

    private void LvAutoAttach_ItemChecked(object? sender, ItemCheckedEventArgs e)
    {
        if (_isLoadingAutoAttach) return;
        var entries = NexusSettings.Instance.AutoAttachEntries;
        if (e.Item.Index >= 0 && e.Item.Index < entries.Count)
        {
            entries[e.Item.Index].Enabled = e.Item.Checked;
            // Update the "Enabled" column text
            e.Item.SubItems[2].Text = e.Item.Checked ? "Yes" : "No";
            NexusSettings.Instance.Save();
        }
    }

    private void NudCheckInterval_ValueChanged(object? sender, EventArgs e)
    {
        if (_isLoadingAutoAttach) return;
        NexusSettings.Instance.AutoAttachCheckInterval = (int)nudCheckInterval.Value;
        NexusSettings.Instance.Save();
    }

    private void BtnAddToAutoAttach_Click(object? sender, EventArgs e)
    {
        // Get selected process name from current tab's ListView
        ListView? activeListView = _selectedTab switch
        {
            0 => lvApplications,
            1 => lvProcesses,
            2 => lvWindows,
            _ => null
        };

        if (activeListView?.SelectedItems.Count > 0)
        {
            string processName;
            if (_selectedTab == 0) // Applications - get from window title, need to find process name
            {
                var pid = (uint)activeListView.SelectedItems[0].Tag!;
                var proc = _processes.FirstOrDefault(p => p.Pid == pid);
                processName = proc.Name ?? $"PID:{pid}";
            }
            else if (_selectedTab == 1) // Processes
            {
                processName = activeListView.SelectedItems[0].SubItems[1].Text;
            }
            else // Windows - need to find process name from PID
            {
                var pid = (uint)activeListView.SelectedItems[0].Tag!;
                var proc = _processes.FirstOrDefault(p => p.Pid == pid);
                processName = proc.Name ?? $"PID:{pid}";
            }

            // Check if already exists
            if (NexusSettings.Instance.AutoAttachEntries.Any(e =>
                e.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase)))
            {
                MessageBox.Show($"\"{processName}\" is already in the auto-attach list.", "Info",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var entry = new AutoAttachEntry
            {
                ProcessName = processName,
                WindowTitle = "",
                ByWindow = false,
                Enabled = true
            };

            NexusSettings.Instance.AutoAttachEntries.Add(entry);
            NexusSettings.Instance.Save();
            RefreshAutoAttachList();

            MessageBox.Show($"Added \"{processName}\" to auto-attach list.", "Added",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            MessageBox.Show("Please select a process first.", "Selection Required",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    #endregion

    private void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        // Auto-refresh the list periodically (only if no filter active for performance)
        if (string.IsNullOrEmpty(_filter))
        {
            RefreshProcessList();
        }
    }

    #endregion

    #region Context Menu Handlers

    private void MiInputPidManually_Click(object? sender, EventArgs e)
    {
        using var dialog = new Form
        {
            Text = "Input PID",
            Size = new Size(300, 120),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var lblPid = new Label { Text = "PID (hex or decimal):", Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 3), AutoSize = true };
        var txtPid = new TextBox { Location = new Point(140, NexusTheme.DialogPadding), Size = new Size(130, NexusTheme.TextBoxHeight) };
        var btnOK = new Button { Text = "OK", Location = new Point(130, NexusTheme.DialogPadding + NexusTheme.TextBoxHeight + NexusTheme.Space16), Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(130 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, NexusTheme.DialogPadding + NexusTheme.TextBoxHeight + NexusTheme.Space16), Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight), DialogResult = DialogResult.Cancel };

        NexusTheme.StylePrimaryButton(btnOK);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblPid, txtPid, btnOK, btnCancel]);
        dialog.AcceptButton = btnOK;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            string pidText = txtPid.Text.Trim();
            uint pid = 0;

            // Try hex first (with or without 0x prefix)
            if (pidText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                uint.TryParse(pidText[2..], System.Globalization.NumberStyles.HexNumber, null, out pid);
            }
            else if (uint.TryParse(pidText, System.Globalization.NumberStyles.HexNumber, null, out uint hexPid))
            {
                pid = hexPid;
            }
            else
            {
                uint.TryParse(pidText, out pid);
            }

            if (pid > 0)
            {
                SelectedPid = pid;
                DialogResult = DialogResult.OK;
                Close();
            }
            else
            {
                MessageBox.Show("Invalid PID format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void MiShowInvisible_Click(object? sender, EventArgs e)
    {
        _showInvisibleWindows = !_showInvisibleWindows;
        miShowInvisible.Checked = _showInvisibleWindows;
        RefreshAll();
    }

    private void MiOwnProcessesOnly_Click(object? sender, EventArgs e)
    {
        _ownProcessesOnly = !_ownProcessesOnly;
        miOwnProcessesOnly.Checked = _ownProcessesOnly;
        RefreshAll();
    }

    private void MiConvertPidToDecimal_Click(object? sender, EventArgs e)
    {
        _showPidAsDecimal = !_showPidAsDecimal;
        miConvertPidToDecimal.Checked = _showPidAsDecimal;
        RefreshAll();
    }

    #endregion

    #region Menu Handlers

    private void MiCreateProcess_Click(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            Title = "Select executable to run"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dialog.FileName,
                    UseShellExecute = true
                };
                var process = System.Diagnostics.Process.Start(startInfo);
                if (process != null)
                {
                    // Wait for process to finish launching (non-blocking idle wait)
                    try { process.WaitForInputIdle(2000); } catch { }
                    SelectedPid = (uint)process.Id;
                    DialogResult = DialogResult.OK;
                    Close();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start process: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void MiOpenFile_Click(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "All files (*.*)|*.*",
            Title = "Open file with default application"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dialog.FileName,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open file: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    #endregion
}
