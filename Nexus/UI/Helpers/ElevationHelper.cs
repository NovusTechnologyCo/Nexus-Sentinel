// <file>
// <summary>
// Elevation preference manager handling whether Nexus Sentinel should run as administrator
// or standard user. Persists the user's choice to AppData, detects current elevation state,
// and provides methods to relaunch the application at a different privilege level.
// </summary>
// </file>

using System.Diagnostics;
using System.Text.Json;

namespace Nexus.UI.Helpers;

/// <summary>
/// Elevation preference for application startup.
/// </summary>
public enum ElevationPreference
{
    /// <summary>No preference set - show prompt on first launch.</summary>
    NotSet,
    /// <summary>Always run as administrator.</summary>
    Administrator,
    /// <summary>Always run as standard user.</summary>
    User
}

/// <summary>
/// Manages administrator elevation detection, preferences, and relaunch.
/// </summary>
public static class ElevationHelper
{
    private static readonly string SettingsFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Nexus Sentinel");

    private static readonly string SettingsFile = Path.Combine(SettingsFolder, "elevation.json");

    private static ElevationPreference? _cachedPreference;

    /// <summary>
    /// Check if the current process is running with administrator privileges.
    /// </summary>
    public static bool IsElevated => AdminHelper.IsRunningAsAdmin();

    /// <summary>
    /// Get the saved elevation preference.
    /// </summary>
    public static ElevationPreference GetPreference()
    {
        if (_cachedPreference.HasValue)
            return _cachedPreference.Value;

        try
        {
            if (File.Exists(SettingsFile))
            {
                var json = File.ReadAllText(SettingsFile);
                var settings = JsonSerializer.Deserialize<ElevationSettings>(json);
                _cachedPreference = settings?.Preference ?? ElevationPreference.NotSet;
                return _cachedPreference.Value;
            }
        }
        catch
        {
            // If we can't read settings, treat as not set
        }

        _cachedPreference = ElevationPreference.NotSet;
        return ElevationPreference.NotSet;
    }

    /// <summary>
    /// Save the elevation preference.
    /// </summary>
    public static void SetPreference(ElevationPreference preference)
    {
        _cachedPreference = preference;

        try
        {
            Directory.CreateDirectory(SettingsFolder);

            var settings = new ElevationSettings { Preference = preference };
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsFile, json);
        }
        catch
        {
            // Best effort - if we can't save, we'll just prompt again next time
        }
    }

    /// <summary>
    /// Clear the saved preference (will prompt again on next launch).
    /// </summary>
    public static void ClearPreference()
    {
        _cachedPreference = null;

        try
        {
            if (File.Exists(SettingsFile))
                File.Delete(SettingsFile);
        }
        catch
        {
            // Best effort
        }
    }

    /// <summary>
    /// Relaunch the application with administrator privileges.
    /// </summary>
    /// <returns>True if relaunch was initiated, false if it failed or was cancelled.</returns>
    public static bool RelaunchAsAdministrator()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
                return false;

            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.CurrentDirectory
            };

            // Pass command line arguments
            var args = Environment.GetCommandLineArgs();
            if (args.Length > 1)
            {
                startInfo.Arguments = string.Join(" ", args.Skip(1).Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
            }

            Process.Start(startInfo);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC prompt
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Relaunch the application without administrator privileges.
    /// This is done by using explorer.exe to launch the process.
    /// </summary>
    /// <returns>True if relaunch was initiated.</returns>
    public static bool RelaunchAsUser()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
                return false;

            // Use explorer.exe to launch without elevation
            var startInfo = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{exePath}\"",
                UseShellExecute = true
            };

            Process.Start(startInfo);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Check elevation status and handle according to saved preference.
    /// Call this early in Program.Main before Application.Run.
    /// </summary>
    /// <returns>True if the application should continue, false if it should exit (relaunch initiated).</returns>
    public static bool HandleStartupElevation()
    {
        var preference = GetPreference();
        var isElevated = IsElevated;

        // If preference is Administrator and we're not elevated, relaunch
        if (preference == ElevationPreference.Administrator && !isElevated)
        {
            if (RelaunchAsAdministrator())
            {
                return false; // Exit current instance
            }
            // If relaunch failed (user cancelled UAC), continue as user
        }

        // If preference is not set, we need to show the prompt
        // Return true to continue - the prompt will be shown by the caller
        return true;
    }

    /// <summary>
    /// Check if we need to show the elevation prompt (preference not set and not elevated).
    /// </summary>
    public static bool ShouldShowElevationPrompt()
    {
        return GetPreference() == ElevationPreference.NotSet && !IsElevated;
    }

    private class ElevationSettings
    {
        public ElevationPreference Preference { get; set; } = ElevationPreference.NotSet;
    }
}
