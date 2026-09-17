// <file>
// <summary>
// Application entry point for Nexus Sentinel. Handles elevation preference prompting,
// engine.dll initialization, global exception handling, command-line parsing for session
// state restoration after UAC elevation, and browser history safety check.
// </summary>
// </file>

using Nexus.UI.Forms;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;

namespace Nexus.UI;

static class Program
{
    /// <summary>
    /// Startup state for restoring session after elevation.
    /// </summary>
    public static StartupState? StartupState { get; private set; }

    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        // Initialize application configuration first (required for any UI)
        ApplicationConfiguration.Initialize();
        _applicationInitialized = true;

        // Handle elevation preference before anything else
        if (!HandleElevationPreference())
        {
            return; // Relaunching as admin or user closed dialog, exit this instance
        }


        // Parse command line arguments for state restoration
        // Use Environment.GetCommandLineArgs() as fallback since UAC may handle args differently
        var effectiveArgs = args.Length > 0 ? args : Environment.GetCommandLineArgs().Skip(1).ToArray();
        System.Diagnostics.Debug.WriteLine($"Main: args.Length={args.Length}, Environment.GetCommandLineArgs().Length={Environment.GetCommandLineArgs().Length}");
        StartupState = AdminHelper.ParseCommandLine(effectiveArgs);

        // Set up global exception handlers - skip if application already started message loop
        try
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        }
        catch (InvalidOperationException)
        {
            // Already started - ignore
        }
        Application.ThreadException += (s, e) =>
        {
            MessageBox.Show(
                $"Unhandled thread exception:\n\n{e.Exception.Message}\n\n{e.Exception.StackTrace}",
                "Nexus Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        };
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            var ex = e.ExceptionObject as Exception;
            MessageBox.Show(
                $"Unhandled exception:\n\n{ex?.Message}\n\n{ex?.StackTrace}",
                "Nexus Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        };

        try
        {
            // Configure application first (needed for MessageBox styling)
            EnsureApplicationInitialized();

            // Try to initialize Nexus Engine
            NexusResult result;
            try
            {
                result = NexusEngine.Nexus_Initialize();
            }
            catch (DllNotFoundException ex)
            {
                MessageBox.Show(
                    $"Failed to load engine.dll:\n\n{ex.Message}\n\nMake sure engine.dll is in the same directory as Nexus.exe",
                    "Nexus Error - DLL Not Found",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }
            catch (BadImageFormatException ex)
            {
                MessageBox.Show(
                    $"engine.dll architecture mismatch:\n\n{ex.Message}\n\nMake sure you're using the x64 version of engine.dll with x64 Nexus.exe",
                    "Nexus Error - Architecture Mismatch",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to load engine.dll:\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                    "Nexus Error - DLL Load Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            if (result != NexusResult.OK)
            {
                MessageBox.Show(
                    $"Failed to initialize Nexus Engine: {NexusHelper.GetErrorMessage(result)}",
                    "Nexus Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            try
            {
                // Show version info
                var version = NexusHelper.GetVersionString();
                Console.WriteLine($"Nexus Engine v{version} initialized");

                // Run the shell form
                Console.WriteLine("Starting Nexus Sentinel...");
                Application.Run(new ShellForm());
            }
            finally
            {
                // Cleanup
                NexusEngine.Nexus_Shutdown();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Fatal error during startup:\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                "Nexus Fatal Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    private static bool _applicationInitialized;

    /// <summary>
    /// Ensure ApplicationConfiguration.Initialize() is called only once.
    /// </summary>
    private static void EnsureApplicationInitialized()
    {
        if (!_applicationInitialized)
        {
            ApplicationConfiguration.Initialize();
            _applicationInitialized = true;
        }
    }

    /// <summary>
    /// Copy a file to temp and scan for a byte pattern. Handles locked files.
    /// </summary>
    private static bool ScanFileForBytes(string filePath, byte[] pattern)
    {
        string? tempCopy = null;
        try
        {
            tempCopy = Path.Combine(Path.GetTempPath(), $"nx_hist_{Guid.NewGuid():N}.tmp");
            File.Copy(filePath, tempCopy, overwrite: true);

            var data = File.ReadAllBytes(tempCopy);
            return IndexOf(data, pattern) >= 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (tempCopy != null)
            {
                try { File.Delete(tempCopy); } catch { /* best effort cleanup */ }
            }
        }
    }

    /// <summary>
    /// Simple byte pattern search.
    /// </summary>
    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        int end = haystack.Length - needle.Length;
        for (int i = 0; i <= end; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }
        return -1;
    }

    /// <summary>
    /// Handle elevation preference check at startup.
    /// </summary>
    /// <returns>True to continue, false if relaunching (exit current instance).</returns>
    private static bool HandleElevationPreference()
    {
        var preference = ElevationHelper.GetPreference();
        var isElevated = ElevationHelper.IsElevated;

        // If preference is Administrator and we're not elevated, auto-relaunch
        if (preference == ElevationPreference.Administrator && !isElevated)
        {
            if (ElevationHelper.RelaunchAsAdministrator())
            {
                return false; // Exit this instance
            }
            // If relaunch failed (user cancelled UAC), continue anyway
        }

        // If no preference set and not elevated, show the prompt
        if (preference == ElevationPreference.NotSet && !isElevated)
        {
            using var dialog = new ElevationPromptForm();
            var dialogResult = dialog.ShowDialog();
            System.Diagnostics.Debug.WriteLine($"ElevationPrompt: DialogResult={dialogResult}, SelectedPreference={dialog.SelectedPreference}, RememberChoice={dialog.RememberChoice}");

            if (dialogResult == DialogResult.OK)
            {
                // Save preference if user chose to remember
                if (dialog.RememberChoice)
                {
                    ElevationHelper.SetPreference(dialog.SelectedPreference);
                }

                // If they chose admin, relaunch
                if (dialog.SelectedPreference == ElevationPreference.Administrator)
                {
                    if (ElevationHelper.RelaunchAsAdministrator())
                    {
                        return false; // Exit this instance
                    }
                    // If relaunch failed, continue as user
                }

                // User chose User mode - continue with normal startup
            }
            else
            {
                // User closed dialog (X button) - exit the app
                return false;
            }
        }

        return true; // Continue with normal startup
    }
}
