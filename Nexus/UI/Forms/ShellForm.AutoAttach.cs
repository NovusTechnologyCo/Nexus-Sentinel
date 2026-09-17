using System.Runtime.InteropServices;
using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Panels;
using Nexus.UI.Plugins;
using Nexus.UI.Providers;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class ShellForm
{
    #region Auto-Attach

    private System.Windows.Forms.Timer? _autoAttachTimer;

    private void InitializeAutoAttach()
    {
        // Subscribe to settings changes to start/stop timer as needed
        NexusSettings.SettingsChanged += OnSettingsChanged_AutoAttach;

        // Start timer if there are entries
        UpdateAutoAttachTimer();
    }

    private void OnSettingsChanged_AutoAttach(object? sender, EventArgs e)
    {
        UpdateAutoAttachTimer();
    }

    private void UpdateAutoAttachTimer()
    {
        var settings = NexusSettings.Instance;
        bool hasEntries = settings.AutoAttachEntries.Count > 0;

        if (hasEntries && _autoAttachTimer == null)
        {
            // Start timer - entries were added
            _autoAttachTimer = new System.Windows.Forms.Timer
            {
                Interval = settings.AutoAttachCheckInterval
            };
            _autoAttachTimer.Tick += AutoAttachTimer_Tick;
            _autoAttachTimer.Start();

            // Check immediately
            CheckAutoAttach();
        }
        else if (!hasEntries && _autoAttachTimer != null)
        {
            // Stop timer - all entries removed
            _autoAttachTimer.Stop();
            _autoAttachTimer.Dispose();
            _autoAttachTimer = null;
        }
        else if (hasEntries && _autoAttachTimer != null)
        {
            // Update interval if changed
            _autoAttachTimer.Interval = settings.AutoAttachCheckInterval;
        }
    }

    private void AutoAttachTimer_Tick(object? sender, EventArgs e)
    {
        // Don't check if already attached or if paused by user
        if (_processHandle != IntPtr.Zero) return;
        if (_autoAttachPaused) return;

        CheckAutoAttach();
    }

    private void CheckAutoAttach()
    {
        var entries = NexusSettings.Instance.AutoAttachEntries;
        if (entries.Count == 0) return;

        // Get list of running processes
        var processes = NexusHelper.EnumerateProcesses();

        foreach (var entry in entries.Where(e => e.Enabled))
        {
            if (entry.ByWindow)
            {
                // Match by window title - enumerate windows and find matching title
                uint matchedPid = 0;
                string? matchedTitle = null;

                EnumWindows((hWnd, lParam) =>
                {
                    if (!IsWindowVisible(hWnd))
                        return true;

                    int length = GetWindowTextLength(hWnd);
                    if (length == 0)
                        return true;

                    var sb = new StringBuilder(length + 1);
                    GetWindowText(hWnd, sb, sb.Capacity);
                    string title = sb.ToString();

                    // Check if title contains the window title from entry
                    if (title.Contains(entry.ProcessName, StringComparison.OrdinalIgnoreCase))
                    {
                        GetWindowThreadProcessId(hWnd, out matchedPid);
                        matchedTitle = title;
                        return false; // Stop enumeration
                    }
                    return true;
                }, IntPtr.Zero);

                if (matchedPid != 0)
                {
                    AttachToProcess(matchedPid);
                    UpdateStatus($"Auto-attached to window '{matchedTitle}' (PID: {matchedPid})", StatusType.Success);
                    return;
                }
            }
            else
            {
                // Match by process name
                var match = processes.FirstOrDefault(p =>
                    p.Name.Equals(entry.ProcessName, StringComparison.OrdinalIgnoreCase));

                if (match.Pid != 0)
                {
                    // Found a matching process - attach to it
                    AttachToProcess(match.Pid);
                    UpdateStatus($"Auto-attached to {entry.ProcessName} (PID: {match.Pid})", StatusType.Success);
                    return;
                }
            }
        }
    }

    #endregion
    #region Provider Switching

    /// <summary>
    /// Switches the active memory/debug provider to the specified privilege level.
    /// Creates appropriate provider instances and re-attaches to the current process if one is attached.
    /// </summary>
    /// <param name="privilege">The provider privilege level (UserMode, Kernel, or Hypervisor).</param>
    private void SetProvider(ProviderPrivilege privilege)
    {
        // Check availability first - check both IOCTL and mapped modes
        if (privilege == ProviderPrivilege.Kernel && !NexusKernelDriver.Instance.IsAvailable)
        {
            if (!NexusKernelDriver.Instance.Connect())
            {
                // Also check if driver is available via mapper (mapped mode)
                if (!NexusKernelDriver.Instance.IsMapped)
                {
                    var result = MessageBox.Show(
                        "Kernel driver is not available.\n\n" +
                        "The NexusKernel.sys driver must be loaded (normally or via mapper) to use kernel-level features.\n\n" +
                        "Would you like to attempt to load the driver now?",
                        "Kernel Driver Not Available",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);

                    if (result == DialogResult.Yes)
                    {
                        LoadKernelDriver();
                    }
                    return;
                }
                // Driver is mapped - proceed with shared memory mode
            }
        }

        if (privilege == ProviderPrivilege.Hypervisor)
        {
            UpdateStatus("Hypervisor provider not yet implemented - requires SentinelHV", StatusType.Warning);
            return;
        }

        // Create and set providers based on privilege level
        IMemoryProvider? memoryProvider = null;
        IProcessProvider? processProvider = null;
        IDebugProvider? debugProvider = null;

        switch (privilege)
        {
            case ProviderPrivilege.UserMode:
                memoryProvider = new UserModeMemoryProvider();
                processProvider = new UserModeProcessProvider();
                debugProvider = new UserModeDebugProvider();
                break;

            case ProviderPrivilege.Kernel:
                var kernelMemory = new KernelMemoryProvider();
                var kernelProcess = new KernelProcessProvider();
                var kernelDebug = new KernelDebugProvider();

                if (!kernelMemory.IsAvailable)
                {
                    UpdateStatus("Kernel provider failed to connect to driver", StatusType.Error);
                    return;
                }

                memoryProvider = kernelMemory;
                processProvider = kernelProcess;
                debugProvider = kernelDebug;
                break;

            case ProviderPrivilege.Hypervisor:
                // Future: HypervisorMemoryProvider, etc.
                return;
        }

        // Update providers in ProcessContext
        if (memoryProvider != null)
            ProcessContext.Current.SetMemoryProvider(memoryProvider);
        if (processProvider != null)
            ProcessContext.Current.SetProcessProvider(processProvider);
        if (debugProvider != null)
            ProcessContext.Current.SetDebugProvider(debugProvider);

        // Update current level and UI
        _currentProviderLevel = privilege;
        UpdateProviderUI();

        // Re-attach to process if one was attached
        if (ProcessContext.Current.IsAttached)
        {
            var pid = ProcessContext.Current.ProcessId;
            ProcessContext.Current.Detach();
            ProcessContext.Current.Attach(pid, _processHandle);
        }

        UpdateStatus($"Switched to {privilege} provider", StatusType.Success);
    }

    private void RefreshProviderAvailability()
    {
        // User mode is always available
        _menuProviderUserMode.Enabled = true;

        // Check kernel driver availability
        var kernelAvailable = NexusKernelDriver.Instance.IsLoaded || NexusKernelDriver.Instance.Connect();
        _menuProviderKernel.Enabled = true; // Always enabled - clicking prompts to load driver
        _menuProviderKernel.Text = kernelAvailable
            ? "&Kernel Mode"
            : "&Kernel Mode (Driver not loaded)";

        // Hypervisor - check for SentinelHV (not implemented yet)
        _menuProviderHypervisor.Enabled = false;
        _menuProviderHypervisor.Text = "&Hypervisor (Not available)";

        // Update toolbar dropdown
        UpdateProviderDropdownAvailability(kernelAvailable);
    }

    private void UpdateProviderDropdownAvailability(bool kernelAvailable)
    {
        if (_providerDropdown?.DropDownItems.Count >= 3)
        {
            _providerDropdown.DropDownItems[1].Enabled = true; // Always enabled - clicking prompts to load
            _providerDropdown.DropDownItems[1].Text = kernelAvailable
                ? "Kernel Mode"
                : "Kernel Mode (Not loaded)";

            _providerDropdown.DropDownItems[2].Enabled = false;
            _providerDropdown.DropDownItems[2].Text = "Hypervisor (Not available)";
        }
    }

    private void UpdateProviderUI()
    {
        // Update menu checkmarks
        _menuProviderUserMode.Checked = _currentProviderLevel == ProviderPrivilege.UserMode;
        _menuProviderKernel.Checked = _currentProviderLevel == ProviderPrivilege.Kernel;
        _menuProviderHypervisor.Checked = _currentProviderLevel == ProviderPrivilege.Hypervisor;

        // Update toolbar dropdown text
        var (text, color) = _currentProviderLevel switch
        {
            ProviderPrivilege.UserMode => ("⚙ User Mode", NexusTheme.Accent),
            ProviderPrivilege.Kernel => ("⚙ Kernel Mode", NexusTheme.Success),
            ProviderPrivilege.Hypervisor => ("⚙ Hypervisor", NexusTheme.Warning),
            _ => ("⚙ User Mode", NexusTheme.Accent)
        };
        _providerDropdown.Text = text;
        _providerDropdown.ForeColor = color;

        // Update status bar
        UpdateProviderStatus();
    }

    private void LoadKernelDriver()
    {
        // Check if running as admin
        if (!ElevationHelper.IsElevated)
        {
            var result = MessageBox.Show(
                "Loading a kernel driver requires administrator privileges.\n\n" +
                "Would you like to restart as Administrator?",
                "Administrator Required",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                ElevationHelper.SetPreference(ElevationPreference.Administrator);
                if (ElevationHelper.RelaunchAsAdministrator())
                {
                    Application.Exit();
                }
            }
            return;
        }

        // Try to find the driver file
        var driverPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "NexusKernel.sys");
        if (!File.Exists(driverPath))
        {
            MessageBox.Show(
                $"Driver file not found:\n{driverPath}\n\n" +
                "Please ensure NexusKernel.sys is in the application directory.",
                "Driver Not Found",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        // First, try to map via UEFI bootkit if available
        if (TryMapDriverViaBootkit(driverPath))
        {
            return; // Success via mapping
        }

        // Fall back to SC method
        LoadKernelDriverViaSC(driverPath);
    }

    /// <summary>
    /// Attempts to map the driver via UEFI bootkit's manual mapper.
    /// Returns true if successful, false if mapping not available or failed.
    /// </summary>
    private bool TryMapDriverViaBootkit(string driverPath)
    {
        try
        {
            // Check if UEFI mapper is available
            var queryResult = NexusEngine.QueryMapperStatus(out var mapperStatus);
            if (queryResult != NexusEngine.BootkitResult.Success)
            {
                return false; // Mapper not available
            }

            if (mapperStatus.MapperState != NexusEngine.MAPPER_STATE_INITIALIZED)
            {
                return false; // Mapper not initialized
            }

            UpdateStatus("Attempting to map driver via UEFI bootkit...", StatusType.Info);

            // Try to map the driver
            var mapResult = NexusEngine.MapDriverFromFile(
                driverPath,
                eraseHeader: true,
                randomizePoolTag: true,
                out var response);

            if (mapResult == NexusEngine.BootkitResult.Success)
            {
                UpdateStatus($"Driver mapped at 0x{response.DriverBase:X}", StatusType.Success);

                // TODO: move to async — Thread.Sleep on UI thread blocks message pump
                System.Threading.Thread.Sleep(500);

                if (NexusKernelDriver.Instance.Connect())
                {
                    UpdateStatus("Kernel driver mapped and connected successfully", StatusType.Success);
                    RefreshProviderAvailability();
                    return true;
                }
                else
                {
                    UpdateStatus("Driver mapped but connection failed", StatusType.Warning);
                    return true; // Mapping succeeded even if connection failed
                }
            }

            // Mapping failed - will fall back to SC method
            return false;
        }
        catch
        {
            return false; // Any error means fall back to SC
        }
    }

    /// <summary>
    /// Loads the kernel driver via SC (Service Control Manager).
    /// </summary>
    private void LoadKernelDriverViaSC(string driverPath)
    {
        UpdateStatus("Loading kernel driver via service...", StatusType.Info);

        try
        {
            var serviceName = "NexusKernel";

            // First try to delete any existing service
            var deleteProcess = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"delete {serviceName}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            deleteProcess?.WaitForExit(5000);

            // Create the service
            var createProcess = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"create {serviceName} type= kernel binPath= \"{driverPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (createProcess == null)
            {
                UpdateStatus("Failed to start sc.exe", StatusType.Error);
                return;
            }

            createProcess.WaitForExit(10000);
            var createOutput = createProcess.StandardOutput.ReadToEnd();
            var createError = createProcess.StandardError.ReadToEnd();

            if (createProcess.ExitCode != 0 && !createOutput.Contains("exists"))
            {
                UpdateStatus($"Failed to create driver service: {createError}", StatusType.Error);
                return;
            }

            // Start the service
            var startProcess = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"start {serviceName}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (startProcess == null)
            {
                UpdateStatus("Failed to start sc.exe", StatusType.Error);
                return;
            }

            startProcess.WaitForExit(10000);
            var startOutput = startProcess.StandardOutput.ReadToEnd();
            var startError = startProcess.StandardError.ReadToEnd();

            if (startProcess.ExitCode != 0 && !startOutput.Contains("RUNNING"))
            {
                UpdateStatus($"Failed to start driver: {startError}", StatusType.Error);
                MessageBox.Show(
                    $"Failed to load kernel driver.\n\n" +
                    $"Error: {startError}\n\n" +
                    "To load unsigned drivers, you need to either:\n\n" +
                    "1. Disable DSE via Tools > Bootkit Control > Disable\n" +
                    "2. Enable UEFI mapper in boot menu to manually map drivers\n\n" +
                    "Both options require booting with the NexusBoot UEFI module.",
                    "Driver Load Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            // Try to connect
            // TODO: move to async — Thread.Sleep on UI thread blocks message pump
            System.Threading.Thread.Sleep(500);
            if (NexusKernelDriver.Instance.Connect())
            {
                UpdateStatus("Kernel driver loaded successfully", StatusType.Success);
                RefreshProviderAvailability();
            }
            else
            {
                UpdateStatus("Driver loaded but connection failed", StatusType.Warning);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Error loading driver: {ex.Message}", StatusType.Error);
        }
    }

    #endregion
    #region Auto Attach and Launch

    private void LaunchAndAttach()
    {
        using var openFileDialog = new OpenFileDialog
        {
            Title = "Select Executable to Launch",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            FilterIndex = 1,
            CheckFileExists = true
        };

        if (openFileDialog.ShowDialog(this) == DialogResult.OK)
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = openFileDialog.FileName,
                    UseShellExecute = true,
                    WorkingDirectory = System.IO.Path.GetDirectoryName(openFileDialog.FileName)
                };

                var process = System.Diagnostics.Process.Start(startInfo);
                if (process != null)
                {
                    // Wait briefly for process to initialize
                    process.WaitForInputIdle(1000);
                    AttachToProcess((uint)process.Id);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to launch process: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void ShowAutoAttach()
    {
        using var processWindow = new ProcessWindow();
        processWindow.SwitchToAutoAttachTab();
        if (processWindow.ShowDialog(this) == DialogResult.OK && processWindow.SelectedPid > 0)
        {
            AttachToProcess(processWindow.SelectedPid);
        }
    }

    private void ResumeAutoAttach()
    {
        _autoAttachPaused = false;
        _menuResumeAutoAttach.Enabled = false;
        UpdateStatus("Auto-attach resumed", StatusType.Info);
    }

    #endregion
}
