// <file>
// <summary>
// Control panel for UEFI bootkit operations including DSE control and driver mapping.
// </summary>
// </file>
using Nexus.UI.Interop;
using Nexus.UI.Styles;
using static Nexus.UI.Interop.NexusEngine;

namespace Nexus.UI.Forms;

/// <summary>
/// Form for controlling bootkit operations including DSE, mapper, and SecureBoot monitoring.
/// </summary>
public class BootkitControlForm : Form
{
    // Status section
    private GroupBox _grpStatus = null!;
    private Label _lblHookStatus = null!;
    private Label _lblMapperStatus = null!;
    private Button _btnRefreshStatus = null!;

    // DSE control section

    // Mapper section
    private GroupBox _grpMapper = null!;
    private Label _lblMapperInfo = null!;
    private Label _lblLoadedDrivers = null!;
    private Label _lblMappedSize = null!;
    private Button _btnMapDriver = null!;
    private Button _btnUnmapDriver = null!;

    // SecureBoot monitor section
    private GroupBox _grpSecureBoot = null!;
    private Label _lblSecureBootHits = null!;
    private Button _btnRefreshSecureBoot = null!;

    // Bottom buttons
    private Button _btnClose = null!;

    // State
    private bool _privilegesAcquired;

    public BootkitControlForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        AcquirePrivileges();
        RefreshAllStatus();
    }

    private void InitializeComponent()
    {
        Text = "Bootkit Control";
        Size = new Size(480, 550);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        const int margin = NexusTheme.Space16;
        const int contentWidth = 480 - margin * 2 - 15;

        int yPos = margin;

        // Status group
        _grpStatus = new GroupBox
        {
            Text = "Bootkit Status",
            Location = new Point(margin, yPos),
            Size = new Size(contentWidth, 100)
        };

        _lblHookStatus = new Label
        {
            Text = "Hook: Checking...",
            Location = new Point(15, 25),
            AutoSize = true
        };


        _lblMapperStatus = new Label
        {
            Text = "Mapper: Unknown",
            Location = new Point(15, 65),
            AutoSize = true
        };

        _btnRefreshStatus = new Button
        {
            Text = "Refresh",
            Location = new Point(contentWidth - 95, 25),
            Size = new Size(80, 60)
        };
        _btnRefreshStatus.Click += (s, e) => RefreshAllStatus();

        _grpStatus.Controls.Add(_lblHookStatus);
        _grpStatus.Controls.Add(_lblMapperStatus);
        _grpStatus.Controls.Add(_btnRefreshStatus);

        yPos += 110;

        // DSE control group

        yPos += 70;

        // Mapper group
        _grpMapper = new GroupBox
        {
            Text = "Driver Mapper",
            Location = new Point(margin, yPos),
            Size = new Size(contentWidth, 115)
        };

        _lblMapperInfo = new Label
        {
            Text = "Status: Not queried",
            Location = new Point(15, 25),
            AutoSize = true
        };

        _lblLoadedDrivers = new Label
        {
            Text = "Base: -",
            Location = new Point(15, 45),
            AutoSize = true
        };

        _lblMappedSize = new Label
        {
            Text = "Size: -",
            Location = new Point(15, 65),
            AutoSize = true
        };

        _btnMapDriver = new Button
        {
            Text = "Map",
            Location = new Point(15, 85),
            Size = new Size(70, 25)
        };
        _btnMapDriver.Click += BtnMapDriver_Click;

        _btnUnmapDriver = new Button
        {
            Text = "Unmap",
            Location = new Point(95, 85),
            Size = new Size(70, 25)
        };
        _btnUnmapDriver.Click += BtnUnmapDriver_Click;


        _grpMapper.Controls.Add(_lblMapperInfo);
        _grpMapper.Controls.Add(_lblLoadedDrivers);
        _grpMapper.Controls.Add(_lblMappedSize);
        _grpMapper.Controls.Add(_btnMapDriver);
        _grpMapper.Controls.Add(_btnUnmapDriver);

        yPos += 125;

        // SecureBoot monitor group
        _grpSecureBoot = new GroupBox
        {
            Text = "SecureBoot Monitor",
            Location = new Point(margin, yPos),
            Size = new Size(contentWidth, 70)
        };

        _lblSecureBootHits = new Label
        {
            Text = "GetVariable Spoofs: - total, - at runtime",
            Location = new Point(15, 30),
            AutoSize = true
        };

        _btnRefreshSecureBoot = new Button
        {
            Text = "Refresh",
            Location = new Point(contentWidth - 95, 25),
            Size = new Size(80, 30)
        };
        _btnRefreshSecureBoot.Click += (s, e) => RefreshSecureBootStatus();

        _grpSecureBoot.Controls.Add(_lblSecureBootHits);
        _grpSecureBoot.Controls.Add(_btnRefreshSecureBoot);

        yPos += 80;

        // Close button
        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(contentWidth + margin - 95, yPos),
            Size = new Size(95, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_grpStatus);
        Controls.Add(_grpMapper);
        Controls.Add(_grpSecureBoot);
        Controls.Add(_btnClose);
        CancelButton = _btnClose;
    }

    private void AcquirePrivileges()
    {
        var result = NexusEngine.AcquireBootkitPrivileges();
        _privilegesAcquired = (result == BootkitResult.Success);

        if (!_privilegesAcquired)
        {
            _lblHookStatus.Text = "Hook: Privilege error - run as Administrator";
            _lblHookStatus.ForeColor = Color.Red;
        }
    }


    private void RefreshAllStatus()
    {
        RefreshHookStatus();
        RefreshMapperStatus();
        RefreshSecureBootStatus();
    }

    private void RefreshHookStatus()
    {
        if (!_privilegesAcquired)
        {
            _lblHookStatus.Text = "Hook: Requires Administrator";
            _lblHookStatus.ForeColor = Color.Red;
            return;
        }

        // The probe this used read two bytes of hal.dll through the kernel read/write backdoor,
        // which has been removed. `PlatformCtl status` answers the same question better: it
        // distinguishes "the hook is not there" from "the hook answered but the driver never
        // ran", which the two-byte read could not.
        _lblHookStatus.Text = "Hook: check with `PlatformCtl status`";
        _lblHookStatus.ForeColor = NexusTheme.TextSecondary;

    }


    private void RefreshMapperStatus()
    {
        var result = NexusEngine.QueryMapperStatus(out var status);

        if (result == BootkitResult.Success)
        {
            // Auto-initialize if mapped but not initialized
            if (status.MapperState == NexusEngine.MAPPER_STATE_MAPPED)
            {
                AutoInitializeMapper();
                // Re-query after init attempt
                result = NexusEngine.QueryMapperStatus(out status);
                if (result != BootkitResult.Success)
                {
                    _lblMapperStatus.Text = $"Mapper: Query failed after init ({result})";
                    _lblMapperStatus.ForeColor = Color.Red;
                    return;
                }
            }

            bool operational = status.MapperState == NexusEngine.MAPPER_STATE_INITIALIZED;
            _lblMapperStatus.Text = operational ? "Mapper: Operational" : "Mapper: Not initialized";
            _lblMapperStatus.ForeColor = operational ? Color.Green : Color.Orange;

            string stateStr = status.MapperState switch
            {
                NexusEngine.MAPPER_STATE_NOT_MAPPED => "Not mapped",
                NexusEngine.MAPPER_STATE_MAPPED => "Mapped (not initialized)",
                NexusEngine.MAPPER_STATE_IMPORTS_RESOLVED => "Imports resolved",
                NexusEngine.MAPPER_STATE_INITIALIZED => "Ready",
                _ => "Unknown"
            };
            _lblMapperInfo.Text = $"Status: {stateStr}";
            _lblLoadedDrivers.Text = $"Base: 0x{status.MapperBase:X}";
            _lblMappedSize.Text = $"Size: {FormatSize(status.MapperSize)}";
        }
        else if (result == BootkitResult.HookNotInstalled)
        {
            _lblMapperStatus.Text = "Mapper: Hook not active";
            _lblMapperStatus.ForeColor = Color.Red;
            _lblMapperInfo.Text = "Status: Bootkit not loaded";
        }
        else
        {
            _lblMapperStatus.Text = $"Mapper: Query failed ({result})";
            _lblMapperStatus.ForeColor = Color.Red;
        }
    }

    private void AutoInitializeMapper()
    {
        // Find ntoskrnl base and initialize silently
        if (!NexusEngine.FindKernelModule("ntoskrnl.exe", out ulong ntoskrnlBase) || ntoskrnlBase == 0)
            return;

        NexusEngine.InitializeMapper(ntoskrnlBase);
    }

    private void RefreshSecureBootStatus()
    {
        var result = NexusEngine.QuerySecureBootMonitor(out var stats);

        if (result == BootkitResult.Success)
        {
            _lblSecureBootHits.Text = $"GetVariable Spoofs: {stats.TotalHits} total, {stats.RuntimeHits} at runtime";
        }
        else if (result == BootkitResult.HookNotInstalled)
        {
            _lblSecureBootHits.Text = "GetVariable Spoofs: Hook not active";
        }
        else if (result == BootkitResult.NtError)
        {
            // The monitor query isn't implemented in the bootkit yet
            // The GetVariable hook spoofs SecureBoot but doesn't track hit counts
            _lblSecureBootHits.Text = "GetVariable Spoof: Active (monitor not implemented)";
        }
        else
        {
            _lblSecureBootHits.Text = $"GetVariable Spoofs: Query failed ({result})";
        }
    }




    private void BtnMapDriver_Click(object? sender, EventArgs e)
    {
        // Check mapper status first
        var queryResult = NexusEngine.QueryMapperStatus(out var status);
        if (queryResult != BootkitResult.Success)
        {
            MessageBox.Show(
                $"Cannot access mapper: {NexusEngine.GetBootkitResultString(queryResult)}\n\n" +
                "Ensure the bootkit is loaded and the mapper feature is enabled.",
                "Mapper Not Available",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        // Auto-initialize if mapped but not initialized
        if (status.MapperState == NexusEngine.MAPPER_STATE_MAPPED)
        {
            AutoInitializeMapper();
            // Re-query
            queryResult = NexusEngine.QueryMapperStatus(out status);
        }

        if (status.MapperState == NexusEngine.MAPPER_STATE_NOT_MAPPED)
        {
            MessageBox.Show(
                "Mapper driver is not mapped.\n\n" +
                "The bootkit must map NexusMapper at boot time.\n" +
                "Ensure mapper is enabled in bootkit config and reboot.",
                "Mapper Not Available",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (status.MapperState != NexusEngine.MAPPER_STATE_INITIALIZED)
        {
            MessageBox.Show(
                "Failed to initialize mapper.\n\n" +
                "The mapper could not resolve kernel imports.",
                "Mapper Not Ready",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        // Open file dialog
        using var openDialog = new OpenFileDialog
        {
            Title = "Select Driver to Map",
            Filter = "Driver Files (*.sys)|*.sys|All Files (*.*)|*.*",
            FilterIndex = 1
        };

        if (openDialog.ShowDialog() != DialogResult.OK)
            return;

        string driverPath = openDialog.FileName;

        // Map the driver
        var mapResult = NexusEngine.MapDriverFromFile(driverPath, eraseHeader: true, randomizePoolTag: true, out var response);

        if (mapResult == BootkitResult.Success)
        {
            RefreshMapperStatus();
            MessageBox.Show(
                $"Driver mapped successfully!\n\n" +
                $"Base Address: 0x{response.DriverBase:X16}\n" +
                $"Size: {FormatSize(response.DriverSize)}\n" +
                $"Entry Point: 0x{response.EntryPoint:X16}",
                "Success",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        else
        {
            var statusInfo = mapResult == BootkitResult.LoadFailed
                ? $"\n\nMapper Status: 0x{NexusEngine.LastMapperStatus:X8}"
                : "";
            MessageBox.Show(
                $"Failed to map driver: {NexusEngine.GetBootkitResultString(mapResult)}{statusInfo}\n\n" +
                "This may occur if:\n" +
                "- The mapper command handler is not implemented\n" +
                "- The driver file is invalid\n" +
                "- There was a communication error",
                "Mapping Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    private void BtnUnmapDriver_Click(object? sender, EventArgs e)
    {
        // Check mapper status first
        var queryResult = NexusEngine.QueryMapperStatus(out var status);
        if (queryResult != BootkitResult.Success)
        {
            MessageBox.Show(
                $"Cannot access mapper: {NexusEngine.GetBootkitResultString(queryResult)}",
                "Mapper Not Available",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (status.LoadedDriverCount == 0)
        {
            MessageBox.Show(
                "No drivers are currently mapped.",
                "Nothing to Unmap",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        // Ask user for driver base address
        if (!InputBoxForm.ShowAddress(this,
            "Unmap Driver",
            $"Enter the base address of the driver to unmap.\n" +
            $"Currently {status.LoadedDriverCount} driver(s) loaded.\n\n" +
            "WARNING: If the driver does not export NexusDriverUnload,\n" +
            "the memory will be force-freed which may BSOD if\n" +
            "the driver has active hooks or threads.",
            out ulong driverBase))
        {
            return;
        }

        if (driverBase == 0)
        {
            MessageBox.Show(
                "Invalid address.",
                "Invalid Input",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        // Confirm
        var confirm = MessageBox.Show(
            $"Unmap driver at 0x{driverBase:X16}?\n\n" +
            "This will call NexusDriverUnload (if exported) then free the memory.",
            "Confirm Unmap",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (confirm != DialogResult.Yes)
            return;

        var unloadResult = NexusEngine.UnloadDriver(driverBase);

        if (unloadResult == BootkitResult.Success)
        {
            RefreshMapperStatus();
            MessageBox.Show(
                $"Driver at 0x{driverBase:X16} unmapped successfully.",
                "Success",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        else
        {
            var statusInfo = unloadResult == BootkitResult.DriverError
                ? $"\n\nMapper Status: 0x{NexusEngine.LastMapperStatus:X8}"
                : "";
            MessageBox.Show(
                $"Failed to unmap driver: {NexusEngine.GetBootkitResultString(unloadResult)}{statusInfo}\n\n" +
                "The driver may not exist at that address.",
                "Unmap Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    /// <summary>
    /// Maps a driver file using the UEFI bootkit mapper.
    /// Can be called from external code (e.g., menu items).
    /// </summary>
    public static bool MapDriverFile(string driverPath, out string resultMessage)
    {
        resultMessage = "";

        var queryResult = NexusEngine.QueryMapperStatus(out var status);
        if (queryResult != BootkitResult.Success)
        {
            resultMessage = $"Cannot access mapper: {NexusEngine.GetBootkitResultString(queryResult)}";
            return false;
        }

        if (status.MapperState != NexusEngine.MAPPER_STATE_INITIALIZED)
        {
            resultMessage = "Mapper not initialized. Load the kernel driver first.";
            return false;
        }

        var mapResult = NexusEngine.MapDriverFromFile(driverPath, eraseHeader: true, randomizePoolTag: true, out var response);

        if (mapResult == BootkitResult.Success)
        {
            resultMessage = $"Driver mapped at 0x{response.DriverBase:X16} (Size: {response.DriverSize} bytes)";
            return true;
        }

        resultMessage = $"Mapping failed: {NexusEngine.GetBootkitResultString(mapResult)}";
        return false;
    }

    private static string FormatSize(ulong bytes)
    {
        if (bytes == 0) return "0 B";
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F2} MB";
    }
}
