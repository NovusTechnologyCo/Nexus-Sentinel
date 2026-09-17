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
    #region Process Management

    private void OpenProcess()
    {
        using var processWindow = new ProcessWindow();
        if (processWindow.ShowDialog(this) == DialogResult.OK && processWindow.SelectedPid > 0)
        {
            AttachToProcess(processWindow.SelectedPid);

            // If user clicked "Attach Debugger" button, also attach debugger
            if (processWindow.AttachDebuggerRequested)
            {
                AttachDebugger();
            }
        }
    }

    /// <summary>
    /// Attaches to a target process by PID. Closes any existing attachment first,
    /// opens the process via the engine, and notifies the <see cref="ProcessContext"/>.
    /// </summary>
    /// <param name="pid">Process ID to attach to.</param>
    private void AttachToProcess(uint pid)
    {
        CloseProcess();

        var result = NexusEngine.Nexus_OpenProcess(pid, out _processHandle);
        if (result != NexusResult.OK)
        {
            MessageBox.Show($"Failed to open process: {NexusHelper.GetErrorMessage(result)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _attachedPid = pid;
        ProcessContext.Current.Attach((int)pid, _processHandle);
    }

    /// <summary>
    /// Detaches from the currently attached process, closes the engine handle,
    /// and pauses auto-attach to prevent immediate re-attachment.
    /// </summary>
    private void CloseProcess()
    {
        if (_processHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_CloseProcess(_processHandle);
            _processHandle = IntPtr.Zero;
            _attachedPid = 0;

            // Pause auto-attach when user manually detaches
            if (NexusSettings.Instance.AutoAttachEntries.Count > 0)
            {
                _autoAttachPaused = true;
                _menuResumeAutoAttach.Enabled = true;
            }
        }
        ProcessContext.Current.Detach();
    }

    private void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        UpdateTitle();
        UpdateProcessStatus();
        UpdateToolbarState();
        UpdateStatus($"Attached to {e.ProcessName} (PID: {e.ProcessId})", StatusType.Success);

        // Notify plugin host
        _pluginHost?.SetProcess(e.ProcessHandle, e.ProcessId, e.ProcessName);

        // Auto-scan for g_CiOptions references when attaching to EA/anti-cheat related processes
        TryAutoScanForSecureBootReferences(e.ProcessName);
    }

    /// <summary>
    /// Automatically triggers a static scan for g_CiOptions references when
    /// attaching to processes that might have anti-cheat drivers loaded.
    /// </summary>
    private void TryAutoScanForSecureBootReferences(string processName)
    {
        // Process names that indicate an EA Anti-Cheat runtime may be loaded
        string[] triggerProcesses = {
            "EADesktop", "EALauncher", "Origin", "EAAntiCheat",
            "EABackgroundService", "link2ea"
        };

        bool shouldScan = triggerProcesses.Any(p =>
            processName.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (!shouldScan) return;

        // Run the scan on a background thread to not block UI
        Task.Run(() =>
        {
            try
            {
                var kernelDriver = NexusKernelDriver.Instance;
                if (!kernelDriver.IsLoaded)
                {
                    this.BeginInvoke(() => UpdateStatus("Kernel driver not loaded - cannot scan for SecureBoot references", StatusType.Warning));
                    return;
                }

                // Get CI info to find g_CiOptions address
                var ciInfo = kernelDriver.GetCiInfo();
                if (ciInfo == null)
                {
                    this.BeginInvoke(() => UpdateStatus("Could not get CI info from kernel driver", StatusType.Warning));
                    return;
                }

                var info = ciInfo.Value;
                if (info.CiOptionsAddress == 0)
                {
                    this.BeginInvoke(() => UpdateStatus("Could not find g_CiOptions address", StatusType.Warning));
                    return;
                }

                this.BeginInvoke(() => UpdateStatus($"Auto-scanning kernel modules for SecureBoot references (g_CiOptions @ 0x{info.CiOptionsAddress:X})...", StatusType.Info));

                // Start the static scan
                var monitorIndex = kernelDriver.StartMemoryMonitor(
                    info.CiOptionsAddress,
                    4,  // DWORD size
                    Providers.MemoryMonitorType.ReadWrite,
                    "g_CiOptions (auto-scan)");

                if (monitorIndex >= 0)
                {
                    // Get the results
                    var status = kernelDriver.GetMemoryMonitorStatus();
                    var entries = kernelDriver.GetMemoryAccessLog(256);

                    this.BeginInvoke(() =>
                    {
                        if (status != null && status.Value.TotalHits > 0)
                        {
                            UpdateStatus($"SecureBoot scan complete: Found {status.Value.TotalHits} references in non-Windows modules!", StatusType.Warning);

                            // Show a message box with details if references were found
                            var moduleNames = entries
                                .Where(e => !string.IsNullOrEmpty(e.ModuleNameString) && e.ModuleNameString != "UNKNOWN")
                                .Select(e => e.ModuleNameString)
                                .Distinct()
                                .ToList();

                            if (moduleNames.Count > 0)
                            {
                                MessageBox.Show(
                                    $"Found code referencing g_CiOptions in the following modules:\n\n" +
                                    string.Join("\n", moduleNames.Select(m => $"  • {m}")) +
                                    $"\n\nThese modules may be checking SecureBoot status.",
                                    "SecureBoot Reference Scan",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Information);
                            }
                        }
                        else
                        {
                            UpdateStatus("SecureBoot scan complete: No suspicious references found in loaded modules", StatusType.Success);
                        }
                    });

                    // Stop the monitor (it was just a one-time scan)
                    kernelDriver.StopMemoryMonitor((uint)monitorIndex);
                }
                else
                {
                    this.BeginInvoke(() => UpdateStatus("Failed to start SecureBoot reference scan", StatusType.Error));
                }
            }
            catch (Exception ex)
            {
                this.BeginInvoke(() => UpdateStatus($"SecureBoot scan error: {ex.Message}", StatusType.Error));
            }
        });
    }

    private void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        UpdateTitle();
        UpdateProcessStatus();
        UpdateToolbarState();
        UpdateStatus("Process detached", StatusType.Info);

        // Notify plugin host
        _pluginHost?.SetProcess(IntPtr.Zero, 0, string.Empty);
    }

    private void OnProviderChanged(object? sender, ProviderChangedEventArgs e)
    {
        UpdateProviderStatus();
        UpdateStatus($"Switched to {e.ProviderName} provider", StatusType.Info);
    }

    private void UpdateTitle()
    {
        var adminSuffix = AdminHelper.IsRunningAsAdmin() ? " (Admin)" : "";
        var ctx = ProcessContext.Current;

        Text = ctx.IsAttached
            ? $"Nexus Sentinel - {ctx.ProcessName}{adminSuffix}"
            : $"Nexus Sentinel{adminSuffix}";
    }

    private void UpdateProcessStatus()
    {
        var ctx = ProcessContext.Current;
        _processLabel.Text = ctx.IsAttached
            ? $"{ctx.ProcessName} (PID: {ctx.ProcessId}) - {(ctx.Is64Bit ? "64-bit" : "32-bit")}"
            : "No process";
    }

    private void UpdateProviderStatus()
    {
        var ctx = ProcessContext.Current;
        var providerName = ctx.MemoryProvider?.Name ?? "User Mode";
        _providerLabel.Text = providerName;

        // Color code based on privilege level
        _providerLabel.ForeColor = _currentProviderLevel switch
        {
            ProviderPrivilege.UserMode => NexusTheme.Accent,
            ProviderPrivilege.Kernel => NexusTheme.Success,
            ProviderPrivilege.Hypervisor => NexusTheme.Warning,
            _ => NexusTheme.Accent
        };

        // Update tooltip with more info
        _providerLabel.ToolTipText = _currentProviderLevel switch
        {
            ProviderPrivilege.UserMode => "User Mode - Standard Windows API access (Ring 3)",
            ProviderPrivilege.Kernel => "Kernel Mode - Driver-based access (Ring 0)",
            ProviderPrivilege.Hypervisor => "Hypervisor - VMX Root mode access (Ring -1)",
            _ => ""
        };
    }

    #endregion
    #region View Operations

    private void ShowMemoryViewer()
    {
        if (!CheckProcessAttached()) return;
        var viewer = new MemoryViewerForm();
        viewer.Show(this);
    }

    private void ShowProcessInspector(int tab = 0)
    {
        if (!CheckProcessAttached()) return;
        var form = new ProcessInspectorForm(_processHandle, _attachedPid, tab);
        form.Show(this);
    }

    private void ShowSaveMemory()
    {
        if (!CheckProcessAttached()) return;
        // Default to a reasonable starting address and size
        var form = new SaveMemoryForm(_processHandle, 0, 0x1000);
        form.ShowDialog(this);
    }

    private void ShowLoadMemory()
    {
        if (!CheckProcessAttached()) return;
        var form = new LoadMemoryForm(_processHandle);
        form.ShowDialog(this);
    }

    private void ShowMemoryMap()
    {
        if (!CheckProcessAttached()) return;
        var form = new ProcessMemoryMapForm();
        form.Show(this);
    }

    private void ShowStackView()
    {
        if (!CheckProcessAttached()) return;
        var form = new StackViewForm(_processHandle, 0);
        form.Show(this);
    }

    private void ShowDebugger(int tab = 0)
    {
        if (!CheckProcessAttached()) return;
        var form = new DebuggerForm(_processHandle, IntPtr.Zero, tab);
        form.Show(this);
    }

    private void ShowScanHistory()
    {
        var form = new ScanHistoryForm();
        form.Show(this);
    }

    private void ShowValueHistory()
    {
        var form = new ValueHistoryForm();
        form.Show(this);
    }

    private void ShowScanSettings()
    {
        using var form = new ScanSettingsForm();
        form.ShowDialog(this);
    }

    private bool CheckProcessAttached()
    {
        if (_processHandle == IntPtr.Zero)
        {
            UpdateStatus("No process attached - use File > Open Process first", StatusType.Warning);
            return false;
        }
        return true;
    }

    #endregion
    #region Debug Operations

    private void AttachDebugger()
    {
        if (!CheckProcessAttached()) return;

        var result = MessageBox.Show(
            "This will attach the debugger of Nexus Sentinel to the current process. Continue?",
            "Confirmation",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result != DialogResult.Yes) return;

        // Switch to the Debugger tab where debugging features are available
        SwitchToModule(1); // Debugger tab index (1 = Debugger)

        // The DisassemblerPanel handles debugger attachment when setting breakpoints
        // via EnsureDebuggerAttached(). Inform the user.
        UpdateStatus("Use F2 to set breakpoints in the Debugger view. The debugger will attach automatically.", StatusType.Info);
    }

    private void DetachDebugger()
    {
        // Detach from process completely (same as toolbar Detach button)
        CloseProcess();
    }

    private void ShowBreakThread()
    {
        if (!CheckProcessAttached()) return;
        if (BreakThreadForm.Show(this, _processHandle, out uint threadId))
        {
            // Suspend the selected thread
            var result = NexusEngine.Nexus_SuspendThread(threadId);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                UpdateStatus($"Thread {threadId:X8} suspended", StatusType.Success);
            }
            else
            {
                UpdateStatus($"Failed to suspend thread {threadId:X8}: {result}", StatusType.Error);
            }
        }
    }

    private void DebugContinue() => ProcessContext.Current.DebugProvider?.Continue();
    private void DebugStepInto() => ProcessContext.Current.DebugProvider?.StepInto();
    private void DebugStepOver() => ProcessContext.Current.DebugProvider?.StepOver();
    private void DebugStepOut() => ProcessContext.Current.DebugProvider?.StepOut();
    private void DebugPause() => ProcessContext.Current.DebugProvider?.Pause();

    #endregion
    #region Tools

    private void ShowPointerScanner()
    {
        if (!CheckProcessAttached()) return;
        var form = new PointerScannerForm(_processHandle);
        form.Show(this);
    }

    private void ShowStructureDissector()
    {
        // StructuresForm removed - use Structures panel instead
        SwitchToModule(2); // Structures tab index (0=Scanner, 1=Debugger, 2=Structures)
    }

    private void ShowCodeCaveScanner()
    {
        if (!CheckProcessAttached()) return;
        var form = new CodeCaveScannerForm(_processHandle);
        form.Show(this);
    }

    private void ShowScriptEditor()
    {
        if (!CheckProcessAttached()) return;
        var form = new ScriptEditorForm(_processHandle, (int)_attachedPid);
        form.Show(this);
    }

    private void ShowSpeedhack()
    {
        if (!CheckProcessAttached()) return;
        var form = new SpeedhackForm(_processHandle);
        form.Show(this);
    }

    private void ShowCodeInjection()
    {
        if (!CheckProcessAttached()) return;
        var form = new CodeInjectForm(_processHandle);
        form.Show(this);
    }

    private void ShowDotNetInfo()
    {
        if (!CheckProcessAttached()) return;
        var form = new DotNetInfoForm(_processHandle, (uint)_attachedPid);
        form.Show(this);
    }

    private void ShowEnumerateDLLs()
    {
        var form = new EnumerateDLLsForm(_processHandle);
        form.Show(this);
    }

    private void ShowFindStatics()
    {
        var form = new FindStaticsForm();
        form.Show(this);
    }

    private void ShowWindowSpy()
    {
        var form = new WindowSpyForm();
        form.Show(this);
    }

    private void ShowProcessWatchlist()
    {
        using var form = new ProcessWatchlistForm();
        form.ShowDialog(this);
    }

    private void ShowBootkitControl()
    {
        var form = new BootkitControlForm();
        form.Show(this);
    }

    private void ShowMapDriver()
    {
        // Check if bootkit is available
        var queryResult = NexusEngine.QueryMapperStatus(out var status);
        if (queryResult != NexusEngine.BootkitResult.Success)
        {
            MessageBox.Show(
                $"Cannot access mapper: {NexusEngine.GetBootkitResultString(queryResult)}\n\n" +
                "Ensure the bootkit is loaded and the mapper feature is enabled.",
                "Mapper Not Available",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (status.MapperState != NexusEngine.MAPPER_STATE_INITIALIZED)
        {
            MessageBox.Show(
                "The mapper is not initialized.\n\n" +
                "The mapper must be initialized before drivers can be mapped.\n" +
                "This requires loading the kernel driver first.",
                "Mapper Not Ready",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        // Show user mode warning
        var warnResult = MessageBox.Show(
            "You are about to map a driver from USER MODE.\n\n" +
            "For better stealth and kernel-mode mapping capabilities,\n" +
            "load the NexusKernel driver first and register it as a\n" +
            "trusted caller.\n\n" +
            "Do you want to continue with user-mode mapping?",
            "User Mode Mapping",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Information);

        if (warnResult != DialogResult.Yes)
            return;

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

        if (mapResult == NexusEngine.BootkitResult.Success)
        {
            MessageBox.Show(
                $"Driver mapped successfully!\n\n" +
                $"Base Address: 0x{response.DriverBase:X16}\n" +
                $"Size: {response.DriverSize} bytes\n" +
                $"Entry Point: 0x{response.EntryPoint:X16}",
                "Success",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        else
        {
            var statusInfo = mapResult == NexusEngine.BootkitResult.LoadFailed
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

    #endregion
}
