// <file>
// <summary>
// Application settings singleton persisted as JSON in %AppData%/NexusSentinel/settings.json.
// Contains all user-configurable options: appearance (dark mode), scan parameters, debugger
// preferences, auto-attach entries, hotkey bindings, update intervals, and extra options
// like hiding the debugger. Fires SettingsChanged event on save.
// </summary>
// </file>

using System.Text.Json;

namespace Nexus.UI;

/// <summary>
/// Application settings that persist between sessions.
/// </summary>
public class NexusSettings
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "NexusSentinel",
        "settings.json");

    private static NexusSettings? _instance;
    private static readonly object _lock = new();

    /// <summary>
    /// Gets the singleton settings instance.
    /// </summary>
    public static NexusSettings Instance
    {
        get
        {
            if (_instance == null)
            {
                lock (_lock)
                {
                    _instance ??= Load();
                }
            }
            return _instance;
        }
    }

    // Appearance
    public bool DarkMode { get; set; } = true;  // Default to dark mode

    // General Settings
    public bool SaveWindowPositions { get; set; } = true;
    public bool ShowAllWindowsInTaskbar { get; set; } = false;  // Default: child windows hidden from taskbar
    public bool ShowValuesAsSigned { get; set; } = false;
    public bool SimplePaste { get; set; } = false;
    public List<AutoAttachEntry> AutoAttachEntries { get; set; } = new();
    public int AutoAttachCheckInterval { get; set; } = 1000;
    public int UpdateInterval { get; set; } = 500;
    public int FreezeInterval { get; set; } = 100;
    public int FoundListUpdateInterval { get; set; } = 1000;

    // Scan Settings
    public bool ScanMemMapped { get; set; } = false;
    public bool ScanMemImage { get; set; } = true;
    public bool PauseWhileScanning { get; set; } = false;
    public bool SkipPageFile { get; set; } = false;
    public int ScanThreadCount { get; set; } = 0;
    public bool TruncateFloat { get; set; } = false;
    public bool SimpleFloatComparison { get; set; } = true;
    public bool CaseSensitiveStrings { get; set; } = false;
    public bool ScanUnicodeByDefault { get; set; } = false;

    // Debugger Settings
    public int DebuggerInterface { get; set; } = 0; // 0=Windows, 1=VEH, 2=Kernel
    public bool BreakOnAttach { get; set; } = false;
    public bool HandleUnhandledBreakpoints { get; set; } = true;
    public bool VEHGlobalHook { get; set; } = false;
    public bool VEHPageExceptions { get; set; } = false;

    // Extra Settings
    public bool QueryMemoryRegion { get; set; } = false;
    public bool ReadWriteProcessMemory { get; set; } = false;
    public bool HideDebugger { get; set; } = false;
    public bool PatchNtQueryInformationProcess { get; set; } = false;

    // Hotkey Settings
    public List<HotkeySetting> Hotkeys { get; set; } = new()
    {
        new HotkeySetting { Action = "Speedhack speed 1", Key = "Numpad 1", Behavior = "Set" },
        new HotkeySetting { Action = "Speedhack speed 2", Key = "Numpad 2", Behavior = "Set" },
        new HotkeySetting { Action = "Speedhack speed 3", Key = "Numpad 3", Behavior = "Set" },
        new HotkeySetting { Action = "Speedhack speed 4", Key = "Numpad 4", Behavior = "Set" },
        new HotkeySetting { Action = "Speedhack speed 5", Key = "Numpad 5", Behavior = "Set" },
        new HotkeySetting { Action = "Pause process", Key = "Pause", Behavior = "Toggle" },
        new HotkeySetting { Action = "Toggle speedhack", Key = "~", Behavior = "Toggle" }
    };

    // Watchlist Settings
    public List<string> WatchlistProcessNames { get; set; } = [];
    public List<string> WatchlistDriverNames { get; set; } = [];
    public bool WatchlistFollowChildren { get; set; } = true;
    public bool WatchlistPassiveMode { get; set; } = true;
    public bool WatchlistAutoStart { get; set; }

    // Window positions (optional future use)
    public Dictionary<string, WindowPosition> WindowPositions { get; set; } = new();

    /// <summary>
    /// Loads settings from disk or returns defaults.
    /// </summary>
    private static NexusSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var settings = JsonSerializer.Deserialize<NexusSettings>(json);
                if (settings != null)
                    return settings;
            }
        }
        catch
        {
            // If loading fails, return defaults
        }
        return new NexusSettings();
    }

    /// <summary>
    /// Saves current settings to disk.
    /// </summary>
    public void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);

            // Notify listeners that settings have changed
            NotifySettingsChanged();
        }
        catch
        {
            // Silently fail if we can't save settings
        }
    }

    /// <summary>
    /// Event raised when settings change.
    /// </summary>
    public static event EventHandler? SettingsChanged;

    /// <summary>
    /// Raises the SettingsChanged event.
    /// </summary>
    public void NotifySettingsChanged()
    {
        SettingsChanged?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>
/// Represents a window position for persistence.
/// </summary>
public class WindowPosition
{
    public int X { get; set; }
    public int Y { get; set; }
    public int Width { get; set; }
    public int Height { get; set; }
}

/// <summary>
/// Represents a hotkey configuration.
/// </summary>
public class HotkeySetting
{
    public string Action { get; set; } = "";
    public string Key { get; set; } = "(None)";
    public string Behavior { get; set; } = "Toggle";
}

/// <summary>
/// Represents an auto-attach entry configuration.
/// </summary>
public class AutoAttachEntry
{
    public string ProcessName { get; set; } = "";
    public string WindowTitle { get; set; } = "";
    public bool ByWindow { get; set; }
    public bool Enabled { get; set; } = true;
}
