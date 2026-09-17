// <file>
// <summary>
// Partial class for SettingsForm containing settings load/save logic.
// </summary>
// </file>
using Nexus.UI.Helpers;

namespace Nexus.UI.Forms;

public partial class SettingsForm
{
    #region Settings Load/Save

    private void LoadSettings()
    {
        _isLoading = true;
        var settings = NexusSettings.Instance;

        // General settings
        chkDarkMode.Checked = settings.DarkMode;
        chkSaveWindowPos.Checked = settings.SaveWindowPositions;
        chkShowAllWindows.Checked = settings.ShowAllWindowsInTaskbar;
        chkShowAsSigned.Checked = settings.ShowValuesAsSigned;
        chkSimplePaste.Checked = settings.SimplePaste;
        txtUpdateInterval.Text = settings.UpdateInterval.ToString();
        txtFreezeInterval.Text = settings.FreezeInterval.ToString();
        txtFoundListInterval.Text = settings.FoundListUpdateInterval.ToString();

        // Scan settings
        chkScanMemMapped.Checked = settings.ScanMemMapped;
        chkScanMemImage.Checked = settings.ScanMemImage;
        chkPauseWhileScanning.Checked = settings.PauseWhileScanning;
        chkSkipPageFile.Checked = settings.SkipPageFile;
        txtScanThreads.Text = settings.ScanThreadCount.ToString();
        chkTruncateFloat.Checked = settings.TruncateFloat;
        chkSimpleFloat.Checked = settings.SimpleFloatComparison;
        chkCaseSensitive.Checked = settings.CaseSensitiveStrings;
        chkUnicode.Checked = settings.ScanUnicodeByDefault;

        // Debugger settings
        cboDebuggerInterface.SelectedIndex = Math.Clamp(settings.DebuggerInterface, 0, 2);
        chkBreakOnAttach.Checked = settings.BreakOnAttach;
        chkHandleBreakpoints.Checked = settings.HandleUnhandledBreakpoints;
        chkVEHGlobalHook.Checked = settings.VEHGlobalHook;
        chkVEHPageExceptions.Checked = settings.VEHPageExceptions;

        // Extra settings
        chkQueryMemoryRegion.Checked = settings.QueryMemoryRegion;
        chkReadWriteProcessMemory.Checked = settings.ReadWriteProcessMemory;
        chkHideDebugger.Checked = settings.HideDebugger;
        chkPatchNtQuery.Checked = settings.PatchNtQueryInformationProcess;

        // Hotkeys
        lvHotkeys.Items.Clear();
        foreach (var hotkey in settings.Hotkeys)
        {
            lvHotkeys.Items.Add(new ListViewItem([hotkey.Action, hotkey.Key, hotkey.Behavior]));
        }

        _isLoading = false;
    }

    private void SaveSettings()
    {
        var settings = NexusSettings.Instance;

        // General settings
        settings.DarkMode = chkDarkMode.Checked;
        settings.SaveWindowPositions = chkSaveWindowPos.Checked;
        settings.ShowAllWindowsInTaskbar = chkShowAllWindows.Checked;
        settings.ShowValuesAsSigned = chkShowAsSigned.Checked;

        // Elevation preference (stored separately from NexusSettings)
        var newElevationPref = chkRunAsAdmin.Checked ? ElevationPreference.Administrator : ElevationPreference.User;
        var currentElevationPref = ElevationHelper.GetPreference();
        if (newElevationPref != currentElevationPref)
        {
            ElevationHelper.SetPreference(newElevationPref);
        }
        settings.SimplePaste = chkSimplePaste.Checked;
        if (int.TryParse(txtUpdateInterval.Text, out int updateInterval))
            settings.UpdateInterval = Math.Max(100, updateInterval);
        if (int.TryParse(txtFreezeInterval.Text, out int freezeInterval))
            settings.FreezeInterval = Math.Max(10, freezeInterval);
        if (int.TryParse(txtFoundListInterval.Text, out int foundInterval))
            settings.FoundListUpdateInterval = Math.Max(100, foundInterval);

        // Scan settings
        settings.ScanMemMapped = chkScanMemMapped.Checked;
        settings.ScanMemImage = chkScanMemImage.Checked;
        settings.PauseWhileScanning = chkPauseWhileScanning.Checked;
        settings.SkipPageFile = chkSkipPageFile.Checked;
        if (int.TryParse(txtScanThreads.Text, out int threads))
            settings.ScanThreadCount = Math.Max(0, threads);
        settings.TruncateFloat = chkTruncateFloat.Checked;
        settings.SimpleFloatComparison = chkSimpleFloat.Checked;
        settings.CaseSensitiveStrings = chkCaseSensitive.Checked;
        settings.ScanUnicodeByDefault = chkUnicode.Checked;

        // Debugger settings
        settings.DebuggerInterface = cboDebuggerInterface.SelectedIndex;
        settings.BreakOnAttach = chkBreakOnAttach.Checked;
        settings.HandleUnhandledBreakpoints = chkHandleBreakpoints.Checked;
        settings.VEHGlobalHook = chkVEHGlobalHook.Checked;
        settings.VEHPageExceptions = chkVEHPageExceptions.Checked;

        // Extra settings
        settings.QueryMemoryRegion = chkQueryMemoryRegion.Checked;
        settings.ReadWriteProcessMemory = chkReadWriteProcessMemory.Checked;
        settings.HideDebugger = chkHideDebugger.Checked;
        settings.PatchNtQueryInformationProcess = chkPatchNtQuery.Checked;

        // Hotkeys
        settings.Hotkeys.Clear();
        foreach (ListViewItem item in lvHotkeys.Items)
        {
            settings.Hotkeys.Add(new HotkeySetting
            {
                Action = item.Text,
                Key = item.SubItems[1].Text,
                Behavior = item.SubItems[2].Text
            });
        }

        // Save to disk and notify listeners
        settings.Save();
        settings.NotifySettingsChanged();
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        SaveSettings();
        DialogResult = DialogResult.OK;
        Close();
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private void BtnApply_Click(object? sender, EventArgs e)
    {
        SaveSettings();
        SetHasChanges(false);
    }

    #endregion
}
