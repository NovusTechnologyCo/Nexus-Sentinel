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
    #region Settings and Help

    private void ShowSettings()
    {
        using var form = new SettingsForm();
        form.ShowDialog(this);
    }

    private void ShowHotkeys()
    {
        using var form = new HotkeyConfigForm();
        form.ShowDialog(this);
    }

    private void ShowDocumentation()
    {
        UpdateStatus("Documentation not yet available", StatusType.Info);
    }

    private void ShowAbout()
    {
        using var form = new AboutForm();
        form.ShowDialog(this);
    }

    private void ShowNotImplemented(string feature)
    {
        UpdateStatus($"{feature} not yet implemented", StatusType.Warning);
    }

    private void ElevationLabel_Click(object? sender, EventArgs e)
    {
        if (ElevationHelper.IsElevated)
        {
            // Already admin - offer to switch to user mode
            var result = MessageBox.Show(
                this,
                "You are currently running as Administrator.\n\n" +
                "Would you like to restart as a standard user?\n\n" +
                "Note: Some features may be limited without administrator privileges.",
                "Restart as User",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                ElevationHelper.SetPreference(ElevationPreference.User);
                if (ElevationHelper.RelaunchAsUser())
                {
                    Application.Exit();
                }
            }
        }
        else
        {
            // Not admin - offer to elevate
            var result = MessageBox.Show(
                this,
                "You are currently running as a standard user.\n\n" +
                "Would you like to restart as Administrator?\n\n" +
                "Administrator privileges are required for:\n" +
                "• ETW system-wide process monitoring\n" +
                "• Debugging protected processes\n" +
                "• Reading memory of elevated applications",
                "Restart as Administrator",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                ElevationHelper.SetPreference(ElevationPreference.Administrator);
                if (ElevationHelper.RelaunchAsAdministrator())
                {
                    Application.Exit();
                }
            }
        }
    }

    #endregion
    #region Status Updates

    private void OnStatusUpdate(StatusUpdateEvent evt)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnStatusUpdate(evt));
            return;
        }

        _statusLabel.Text = evt.Message;
        _statusLabel.ForeColor = evt.Type switch
        {
            StatusType.Warning => NexusTheme.Warning,
            StatusType.Error => NexusTheme.Error,
            StatusType.Success => NexusTheme.Success,
            _ => NexusTheme.TextSecondary
        };
    }

    /// <summary>
    /// Publishes a status update to the status bar via the event bus.
    /// </summary>
    /// <param name="message">Status message text.</param>
    /// <param name="type">Status severity (Info, Warning, Error, Success).</param>
    private void UpdateStatus(string message, StatusType type = StatusType.Info)
    {
        EventBus.Instance.Publish(new StatusUpdateEvent(message, type));
    }

    private void OnNavigateToAddress(NavigateToAddressEvent evt)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnNavigateToAddress(evt));
            return;
        }

        // Switch to the appropriate module based on target
        switch (evt.TargetModule)
        {
            case "Debugger":
            case "Disassembler": // Legacy support
                SwitchToModule(1);
                _debuggerLayoutPanel?.DisassemblerPanel.NavigateTo(evt.Address);
                break;
            case "Structures":
                SwitchToModule(2);
                break;
            case "MemoryViewer":
            default:
                // For MemoryViewer, open a separate form or stay on current panel
                break;
        }
    }

    #endregion
    #region Plugin System

    private void InitializePluginSystem()
    {
        var pluginsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "plugins");
        var settingsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NexusSentinel");
        var trustSettingsPath = Path.Combine(settingsDir, "plugin_trust.json");
        var pluginSettingsPath = Path.Combine(settingsDir, "plugin_settings.json");

        // Create plugin host
        _pluginHost = new PluginHost(this, _pluginsMenu, pluginSettingsPath);

        // Create plugin loader
        _pluginLoader = new PluginLoader(pluginsDir, trustSettingsPath);
        _pluginLoader.ApprovalRequired += OnPluginApprovalRequired;
        _pluginLoader.PluginLoaded += OnPluginLoaded;
        _pluginLoader.PluginLoadFailed += OnPluginLoadFailed;

        // Discover and load plugins
        _pluginLoader.DiscoverPlugins();
        _ = LoadPluginsAsync();
    }

    private async Task LoadPluginsAsync()
    {
        if (_pluginLoader == null || _pluginHost == null)
            return;

        await _pluginLoader.LoadPluginsAsync(_pluginHost, promptForApproval: true);
    }

    private void OnPluginApprovalRequired(object? sender, PluginApprovalEventArgs e)
    {
        // Show approval dialog on UI thread
        if (InvokeRequired)
        {
            Invoke(() => OnPluginApprovalRequired(sender, e));
            return;
        }

        using var dialog = new PluginApprovalDialog(e.Plugin);
        var result = dialog.ShowDialog(this);

        if (result == DialogResult.OK)
        {
            if (dialog.Approved)
                e.Approve();
            else if (dialog.Blocked)
                e.Block();
            else
                e.Skip();
        }
        else
        {
            e.Skip();
        }
    }

    private void OnPluginLoaded(object? sender, PluginInfo plugin)
    {
        UpdateStatus($"Plugin loaded: {plugin.Name}", StatusType.Success);
    }

    private void OnPluginLoadFailed(object? sender, PluginInfo plugin)
    {
        UpdateStatus($"Plugin failed to load: {plugin.FileName} - {plugin.LoadError}", StatusType.Warning);
    }

    private void ShowPluginManager()
    {
        if (_pluginLoader == null)
        {
            MessageBox.Show("Plugin system not initialized.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var form = new PluginManagerForm(_pluginLoader);
        form.ShowDialog(this);
    }

    #endregion
}
