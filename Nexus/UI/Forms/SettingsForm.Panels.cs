// <file>
// <summary>
// Partial class for SettingsForm containing individual settings panel construction.
// </summary>
// </file>
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class SettingsForm
{
    #region General Settings Panel

    private Panel CreateGeneralSettingsPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Visible = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        int y = 10;
        const int lineHeight = 25;
        const int indent = 10;

        // Title
        panel.Controls.Add(new Label
        {
            Text = "General Settings",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 30;

        // Appearance section
        panel.Controls.Add(new Label
        {
            Text = "Appearance",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 25;

        // Dark mode
        chkDarkMode = new CheckBox
        {
            Text = "Dark mode",
            Location = new Point(indent, y),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkDarkMode);
        panel.Controls.Add(chkDarkMode);
        y += lineHeight;

        // Note about restart
        var lblDarkModeNote = new Label
        {
            Text = "Requires restart to fully apply",
            Location = new Point(indent + 15, y),
            AutoSize = true,
            ForeColor = Color.Gray
        };
        panel.Controls.Add(lblDarkModeNote);
        y += lineHeight + 10;

        // Save window positions
        chkSaveWindowPos = new CheckBox
        {
            Text = "Save window positions",
            Location = new Point(indent, y),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkSaveWindowPos);
        panel.Controls.Add(chkSaveWindowPos);
        y += lineHeight;

        // Show all windows in taskbar
        chkShowAllWindows = new CheckBox
        {
            Text = "Show all windows in the taskbar",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkShowAllWindows);
        panel.Controls.Add(chkShowAllWindows);
        y += lineHeight + 10;

        // Elevation section
        panel.Controls.Add(new Label
        {
            Text = "Elevation",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 25;

        // Run as administrator
        chkRunAsAdmin = new CheckBox
        {
            Text = "Always run as Administrator",
            Location = new Point(indent, y),
            AutoSize = true,
            Checked = Helpers.ElevationHelper.GetPreference() == Helpers.ElevationPreference.Administrator
        };
        NexusTheme.StyleCheckBox(chkRunAsAdmin);
        panel.Controls.Add(chkRunAsAdmin);
        y += lineHeight;

        // Note about elevation
        var lblElevationNote = new Label
        {
            Text = "Administrator privileges are required for ETW monitoring, debugging protected\nprocesses, and accessing elevated applications.",
            Location = new Point(indent + 15, y),
            AutoSize = true,
            ForeColor = Color.Gray
        };
        panel.Controls.Add(lblElevationNote);
        y += 40;

        // Separator
        panel.Controls.Add(new Label
        {
            Text = "Address List Specific",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 25;

        // Show as signed
        chkShowAsSigned = new CheckBox
        {
            Text = "Show values as if they are signed",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkShowAsSigned);
        panel.Controls.Add(chkShowAsSigned);
        y += lineHeight;

        // Simple paste
        chkSimplePaste = new CheckBox
        {
            Text = "Simple paste",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkSimplePaste);
        panel.Controls.Add(chkSimplePaste);
        y += lineHeight + 10;

        // Auto attach
        btnAutoAttachConfig = new Button
        {
            Text = "Configure Auto Attach...",
            Location = new Point(indent, y),
            Size = new Size(180, 28)
        };
        NexusTheme.StyleButton(btnAutoAttachConfig);
        btnAutoAttachConfig.Click += BtnAutoAttachConfig_Click;
        panel.Controls.Add(btnAutoAttachConfig);
        y += lineHeight + 10;

        // Intervals section
        y += 10;
        panel.Controls.Add(new Label
        {
            Text = "Intervals",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 20;

        // Update interval
        panel.Controls.Add(new Label
        {
            Text = "Update interval:",
            Location = new Point(indent + 10, y + 3),
            AutoSize = true
        });
        txtUpdateInterval = new TextBox
        {
            Location = new Point(235, y),
            Size = new Size(60, 23),
            Text = "500"
        };
        NexusTheme.StyleTextBox(txtUpdateInterval);
        panel.Controls.Add(txtUpdateInterval);
        panel.Controls.Add(new Label
        {
            Text = "ms",
            Location = new Point(300, y + 3),
            AutoSize = true
        });
        y += lineHeight;

        // Freeze interval
        panel.Controls.Add(new Label
        {
            Text = "Freeze interval:",
            Location = new Point(indent + 10, y + 3),
            AutoSize = true
        });
        txtFreezeInterval = new TextBox
        {
            Location = new Point(235, y),
            Size = new Size(60, 23),
            Text = "100"
        };
        NexusTheme.StyleTextBox(txtFreezeInterval);
        panel.Controls.Add(txtFreezeInterval);
        panel.Controls.Add(new Label
        {
            Text = "ms",
            Location = new Point(300, y + 3),
            AutoSize = true
        });
        y += lineHeight;

        // Found list update interval
        panel.Controls.Add(new Label
        {
            Text = "Found list update interval:",
            Location = new Point(indent + 10, y + 3),
            AutoSize = true
        });
        txtFoundListInterval = new TextBox
        {
            Location = new Point(235, y),
            Size = new Size(60, 23),
            Text = "1000"
        };
        NexusTheme.StyleTextBox(txtFoundListInterval);
        panel.Controls.Add(txtFoundListInterval);
        panel.Controls.Add(new Label
        {
            Text = "ms",
            Location = new Point(300, y + 3),
            AutoSize = true
        });

        return panel;
    }

    #endregion

    #region Scan Settings Panel

    private Panel CreateScanSettingsPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Visible = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        int y = 10;
        const int lineHeight = 25;
        const int indent = 10;

        // Title
        panel.Controls.Add(new Label
        {
            Text = "Scan Settings",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 30;

        // MEM_MAPPED
        chkScanMemMapped = new CheckBox
        {
            Text = "Scan MEM_MAPPED memory regions",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkScanMemMapped);
        panel.Controls.Add(chkScanMemMapped);
        y += lineHeight;

        // MEM_IMAGE
        chkScanMemImage = new CheckBox
        {
            Text = "Scan MEM_IMAGE memory regions",
            Location = new Point(indent, y),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkScanMemImage);
        panel.Controls.Add(chkScanMemImage);
        y += lineHeight;

        // Pause while scanning
        chkPauseWhileScanning = new CheckBox
        {
            Text = "Pause the game while scanning",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkPauseWhileScanning);
        panel.Controls.Add(chkPauseWhileScanning);
        y += lineHeight;

        // Skip page-file backed memory
        chkSkipPageFile = new CheckBox
        {
            Text = "Skip page-file backed memory",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkSkipPageFile);
        panel.Controls.Add(chkSkipPageFile);
        y += lineHeight + 10;

        // Thread count
        panel.Controls.Add(new Label
        {
            Text = "Scanner thread count (0 = auto):",
            Location = new Point(indent, y + 3),
            AutoSize = true
        });
        txtScanThreads = new TextBox
        {
            Location = new Point(280, y),
            Size = new Size(50, 23),
            Text = "0"
        };
        NexusTheme.StyleTextBox(txtScanThreads);
        panel.Controls.Add(txtScanThreads);
        y += lineHeight + 10;

        // Float settings
        panel.Controls.Add(new Label
        {
            Text = "Float/Double Settings",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 23;

        chkTruncateFloat = new CheckBox
        {
            Text = "Use truncated floating point comparison",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkTruncateFloat);
        panel.Controls.Add(chkTruncateFloat);
        y += lineHeight;

        chkSimpleFloat = new CheckBox
        {
            Text = "Use simple floating point comparison",
            Location = new Point(indent + 10, y),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkSimpleFloat);
        panel.Controls.Add(chkSimpleFloat);
        y += lineHeight + 10;

        // String settings
        panel.Controls.Add(new Label
        {
            Text = "String Settings",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 23;

        chkCaseSensitive = new CheckBox
        {
            Text = "Case sensitive string scanning",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkCaseSensitive);
        panel.Controls.Add(chkCaseSensitive);
        y += lineHeight;

        chkUnicode = new CheckBox
        {
            Text = "Scan for Unicode strings by default",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkUnicode);
        panel.Controls.Add(chkUnicode);

        return panel;
    }

    #endregion

    #region Debugger Panel

    private Panel CreateDebuggerPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Visible = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        int y = 10;
        const int lineHeight = 25;
        const int indent = 10;

        // Title
        panel.Controls.Add(new Label
        {
            Text = "Debugger Options",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 30;

        // Debugger interface selection
        panel.Controls.Add(new Label
        {
            Text = "Debugger interface:",
            Location = new Point(indent, y + 3),
            AutoSize = true
        });
        cboDebuggerInterface = new ComboBox
        {
            Location = new Point(180, y),
            Size = new Size(200, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cboDebuggerInterface.Items.AddRange(new object[]
        {
            "Windows Debugger",
            "VEH Debugger",
            "Kernel Debugger"
        });
        cboDebuggerInterface.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cboDebuggerInterface);
        panel.Controls.Add(cboDebuggerInterface);
        y += lineHeight + 10;

        // Breakpoint options
        panel.Controls.Add(new Label
        {
            Text = "Breakpoint Options",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 23;

        chkBreakOnAttach = new CheckBox
        {
            Text = "Break on process attach",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkBreakOnAttach);
        panel.Controls.Add(chkBreakOnAttach);
        y += lineHeight;

        chkHandleBreakpoints = new CheckBox
        {
            Text = "Handle unhandled breakpoints",
            Location = new Point(indent + 10, y),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkHandleBreakpoints);
        panel.Controls.Add(chkHandleBreakpoints);
        y += lineHeight + 10;

        // VEH options
        panel.Controls.Add(new Label
        {
            Text = "VEH Debugger Options",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 23;

        chkVEHGlobalHook = new CheckBox
        {
            Text = "Use global debug hook (affects all threads)",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkVEHGlobalHook);
        panel.Controls.Add(chkVEHGlobalHook);
        y += lineHeight;

        chkVEHPageExceptions = new CheckBox
        {
            Text = "Handle page exceptions as breakpoints",
            Location = new Point(indent + 10, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkVEHPageExceptions);
        panel.Controls.Add(chkVEHPageExceptions);

        return panel;
    }

    #endregion

    #region Extra Panel

    private Panel CreateExtraPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Visible = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        int y = 10;
        const int lineHeight = 25;
        const int indent = 10;

        // Title
        panel.Controls.Add(new Label
        {
            Text = "Extra Options",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 30;

        // Query memory region routines
        chkQueryMemoryRegion = new CheckBox
        {
            Text = "Query memory region routines",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkQueryMemoryRegion);
        panel.Controls.Add(chkQueryMemoryRegion);
        y += lineHeight;

        // Read/write process memory
        chkReadWriteProcessMemory = new CheckBox
        {
            Text = "Read/Write process memory",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkReadWriteProcessMemory);
        panel.Controls.Add(chkReadWriteProcessMemory);
        y += lineHeight + 10;

        // Anti-debug bypass
        panel.Controls.Add(new Label
        {
            Text = "Anti-Debug Bypass",
            Font = new Font(Font.FontFamily, 9, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 23;

        chkHideDebugger = new CheckBox
        {
            Text = "Try to hide debugger from process",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkHideDebugger);
        panel.Controls.Add(chkHideDebugger);
        y += lineHeight;

        chkPatchNtQuery = new CheckBox
        {
            Text = "Patch NtQueryInformationProcess",
            Location = new Point(indent, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkPatchNtQuery);
        panel.Controls.Add(chkPatchNtQuery);

        return panel;
    }

    #endregion

    #region Event Handlers

    private void BtnAutoAttachConfig_Click(object? sender, EventArgs e)
    {
        // Open ProcessWindow on the Auto Attach tab
        using var processWindow = new ProcessWindow();
        processWindow.SwitchToAutoAttachTab();
        processWindow.ShowDialog(this);
    }

    #endregion
}
