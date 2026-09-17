// <file>
// <summary>
// Administrator privilege helper for detecting elevation state, prompting for UAC
// elevation, restarting the application as administrator, and restoring session state
// (attached process, window position) across elevation-triggered restarts.
// </summary>
// </file>

using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;

namespace Nexus.UI.Helpers;

/// <summary>
/// Helper class for administrator elevation and state restoration.
/// </summary>
public static class AdminHelper
{
    private static readonly string StateFilePath = Path.Combine(
        Path.GetTempPath(),
        "nexus_elevation_state.json");

    /// <summary>
    /// Checks if the current process is running with administrator privileges.
    /// </summary>
    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Shows a prompt asking if the user wants to restart as admin.
    /// If yes, restarts the application with elevation.
    /// </summary>
    /// <param name="owner">Parent window for the dialog</param>
    /// <param name="reason">Reason why admin is required</param>
    /// <param name="processId">Process ID to reattach to (0 if none)</param>
    /// <returns>True if restarting, false if user declined</returns>
    public static bool PromptAndRestartAsAdmin(
        IWin32Window? owner,
        string reason,
        int processId = 0)
    {
        var result = MessageBox.Show(
            owner,
            $"{reason}\n\n" +
            "Nexus needs to run as Administrator to perform this operation.\n\n" +
            "Would you like to restart Nexus as Administrator now?\n\n" +
            "(You will need to re-attach to the process after restart)",
            "Administrator Required",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result != DialogResult.Yes)
        {
            return false;
        }

        return RestartAsAdmin(processId);
    }

    /// <summary>
    /// Restarts the application as administrator with optional process ID to reattach.
    /// </summary>
    public static bool RestartAsAdmin(int processId = 0)
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Application.ExecutablePath;

            // Save state to temp file (more reliable than command line args with UAC)
            var state = new StartupState
            {
                AttachProcessId = processId
            };

            SaveStateToFile(state);

            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = "--restore-session",
                UseShellExecute = true,
                Verb = "runas" // This triggers the UAC prompt
            };

            Process.Start(startInfo);

            // Exit current instance
            Application.Exit();
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC prompt
            DeleteStateFile();
            return false;
        }
        catch (Exception ex)
        {
            DeleteStateFile();
            MessageBox.Show(
                $"Failed to restart as Administrator:\n\n{ex.Message}",
                "Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return false;
        }
    }

    private static void SaveStateToFile(StartupState state)
    {
        try
        {
            var json = JsonSerializer.Serialize(state);
            File.WriteAllText(StateFilePath, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"SaveStateToFile failed: {ex.Message}");
        }
    }

    private static void DeleteStateFile()
    {
        try
        {
            if (File.Exists(StateFilePath))
            {
                File.Delete(StateFilePath);
            }
        }
        catch { }
    }

    /// <summary>
    /// Parses command line arguments for state restoration.
    /// Also checks for state file if --restore-session is present.
    /// </summary>
    public static StartupState ParseCommandLine(string[] args)
    {
        // Check if we should restore from file
        if (args.Any(a => a.Equals("--restore-session", StringComparison.OrdinalIgnoreCase)))
        {
            var state = LoadStateFromFile();
            if (state != null)
            {
                return state;
            }
        }

        // Parse command line args as fallback
        var parsedState = new StartupState();

        foreach (var arg in args)
        {
            if (arg.StartsWith("--attach=", StringComparison.OrdinalIgnoreCase))
            {
                var value = arg[9..];
                if (int.TryParse(value, out int pid))
                {
                    parsedState.AttachProcessId = pid;
                }
            }
        }

        return parsedState;
    }

    private static StartupState? LoadStateFromFile()
    {
        try
        {
            if (!File.Exists(StateFilePath))
            {
                return null;
            }

            var json = File.ReadAllText(StateFilePath);
            var state = JsonSerializer.Deserialize<StartupState>(json);

            // Delete the file after reading (one-time use)
            DeleteStateFile();

            return state;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Represents startup state to restore after elevation.
/// Only stores process ID - addresses are not stored because they change with ASLR.
/// </summary>
public class StartupState
{
    public int AttachProcessId { get; set; }

    public bool HasState => AttachProcessId > 0;
}
