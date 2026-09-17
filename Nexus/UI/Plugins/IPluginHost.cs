// <file>
// <summary>
// Plugin host interface exposing Nexus Sentinel functionality to loaded plugins. Provides
// access to the attached process handle, memory read/write, module enumeration, status bar
// updates, menu registration, and event notification callbacks.
// </summary>
// </file>

using Nexus.UI.Interop;

namespace Nexus.UI.Plugins;

/// <summary>
/// Host interface providing plugins access to Nexus functionality.
/// </summary>
public interface IPluginHost
{
    #region Process Information

    /// <summary>
    /// Handle to the currently attached process, or IntPtr.Zero if none.
    /// </summary>
    IntPtr ProcessHandle { get; }

    /// <summary>
    /// Process ID of the currently attached process, or 0 if none.
    /// </summary>
    int ProcessId { get; }

    /// <summary>
    /// Whether a process is currently attached.
    /// </summary>
    bool IsProcessAttached { get; }

    #endregion

    #region Memory Operations

    /// <summary>
    /// Memory read/write operations for the attached process.
    /// </summary>
    IMemoryOperations Memory { get; }

    #endregion

    #region UI Integration

    /// <summary>
    /// Add a menu item to the Plugins menu.
    /// </summary>
    /// <param name="text">Menu item text (use &amp; for accelerator key).</param>
    /// <param name="onClick">Click handler.</param>
    /// <returns>The created menu item for further customization.</returns>
    ToolStripMenuItem AddMenuItem(string text, EventHandler onClick);

    /// <summary>
    /// Add a submenu to the Plugins menu.
    /// </summary>
    /// <param name="text">Submenu text.</param>
    /// <returns>The submenu item to add children to.</returns>
    ToolStripMenuItem AddSubMenu(string text);

    /// <summary>
    /// Show a form as a dialog.
    /// </summary>
    /// <param name="form">The form to show.</param>
    /// <returns>Dialog result.</returns>
    DialogResult ShowDialog(Form form);

    /// <summary>
    /// Show a form non-modally.
    /// </summary>
    /// <param name="form">The form to show.</param>
    void ShowForm(Form form);

    /// <summary>
    /// Get the main form for parenting dialogs.
    /// </summary>
    Form MainForm { get; }

    #endregion

    #region Logging

    /// <summary>
    /// Log an informational message.
    /// </summary>
    void LogInfo(string message);

    /// <summary>
    /// Log a warning message.
    /// </summary>
    void LogWarning(string message);

    /// <summary>
    /// Log an error message.
    /// </summary>
    void LogError(string message);

    /// <summary>
    /// Log an exception.
    /// </summary>
    void LogException(Exception ex, string context = "");

    #endregion

    #region Settings

    /// <summary>
    /// Get a plugin-specific setting.
    /// </summary>
    /// <typeparam name="T">Type of the setting value.</typeparam>
    /// <param name="pluginId">Plugin identifier.</param>
    /// <param name="key">Setting key.</param>
    /// <param name="defaultValue">Default value if not found.</param>
    T GetSetting<T>(string pluginId, string key, T defaultValue);

    /// <summary>
    /// Set a plugin-specific setting.
    /// </summary>
    /// <typeparam name="T">Type of the setting value.</typeparam>
    /// <param name="pluginId">Plugin identifier.</param>
    /// <param name="key">Setting key.</param>
    /// <param name="value">Setting value.</param>
    void SetSetting<T>(string pluginId, string key, T value);

    /// <summary>
    /// Save all plugin settings to disk.
    /// </summary>
    void SaveSettings();

    #endregion

    #region Events

    /// <summary>
    /// Fired when a process is attached.
    /// </summary>
    event EventHandler<ProcessEventArgs>? ProcessAttached;

    /// <summary>
    /// Fired when the process is detached.
    /// </summary>
    event EventHandler? ProcessDetached;

    #endregion
}

/// <summary>
/// Event args for process-related events.
/// </summary>
public class ProcessEventArgs : EventArgs
{
    public int ProcessId { get; }
    public IntPtr ProcessHandle { get; }
    public string ProcessName { get; }

    public ProcessEventArgs(int processId, IntPtr processHandle, string processName)
    {
        ProcessId = processId;
        ProcessHandle = processHandle;
        ProcessName = processName;
    }
}

/// <summary>
/// Memory operations interface for plugins.
/// </summary>
public interface IMemoryOperations
{
    // Read operations
    byte ReadByte(ulong address);
    short ReadInt16(ulong address);
    int ReadInt32(ulong address);
    long ReadInt64(ulong address);
    float ReadFloat(ulong address);
    double ReadDouble(ulong address);
    string ReadString(ulong address, int maxLength = 256);
    byte[] ReadBytes(ulong address, int count);

    // Write operations
    bool WriteByte(ulong address, byte value);
    bool WriteInt16(ulong address, short value);
    bool WriteInt32(ulong address, int value);
    bool WriteInt64(ulong address, long value);
    bool WriteFloat(ulong address, float value);
    bool WriteDouble(ulong address, double value);
    bool WriteBytes(ulong address, byte[] data);

    // Utility
    bool IsValidAddress(ulong address);
}
