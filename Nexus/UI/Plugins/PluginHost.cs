// <file>
// <summary>
// Concrete implementation of IPluginHost providing plugins with access to the main form,
// engine P/Invoke wrappers, process state, memory operations, menu bar integration,
// per-plugin settings persistence, and status bar updates.
// </summary>
// </file>

using System.Text.Json;
using Nexus.UI.Interop;

namespace Nexus.UI.Plugins;

/// <summary>
/// Implementation of IPluginHost that provides plugins access to Nexus functionality.
/// </summary>
public class PluginHost : IPluginHost, IMemoryOperations
{
    private readonly Form _mainForm;
    private readonly ToolStripMenuItem _pluginsMenu;
    private readonly Dictionary<string, Dictionary<string, object>> _pluginSettings = new();
    private readonly string _settingsPath;
    private IntPtr _processHandle;
    private int _processId;

    public PluginHost(Form mainForm, ToolStripMenuItem pluginsMenu, string settingsPath)
    {
        _mainForm = mainForm;
        _pluginsMenu = pluginsMenu;
        _settingsPath = settingsPath;
        LoadSettings();
    }

    #region Process Information

    public IntPtr ProcessHandle => _processHandle;
    public int ProcessId => _processId;
    public bool IsProcessAttached => _processHandle != IntPtr.Zero && _processId != 0;

    /// <summary>
    /// Update the attached process (called by ShellForm).
    /// </summary>
    public void SetProcess(IntPtr handle, int pid, string processName)
    {
        var wasAttached = IsProcessAttached;
        _processHandle = handle;
        _processId = pid;

        if (handle != IntPtr.Zero && pid != 0)
        {
            ProcessAttached?.Invoke(this, new ProcessEventArgs(pid, handle, processName));
        }
        else if (wasAttached)
        {
            ProcessDetached?.Invoke(this, EventArgs.Empty);
        }
    }

    #endregion

    #region Memory Operations

    public IMemoryOperations Memory => this;

    byte IMemoryOperations.ReadByte(ulong address) => NexusEngine.ReadByte(_processHandle, address);
    short IMemoryOperations.ReadInt16(ulong address) => NexusEngine.ReadInt16(_processHandle, address);
    int IMemoryOperations.ReadInt32(ulong address) => NexusEngine.ReadInt32(_processHandle, address);
    long IMemoryOperations.ReadInt64(ulong address) => NexusEngine.ReadInt64(_processHandle, address);
    float IMemoryOperations.ReadFloat(ulong address) => NexusEngine.ReadFloat(_processHandle, address);
    double IMemoryOperations.ReadDouble(ulong address) => NexusEngine.ReadDouble(_processHandle, address);
    string IMemoryOperations.ReadString(ulong address, int maxLength) => NexusEngine.ReadString(_processHandle, address, maxLength);
    byte[] IMemoryOperations.ReadBytes(ulong address, int count) => NexusEngine.ReadBytes(_processHandle, address, count);

    bool IMemoryOperations.WriteByte(ulong address, byte value) => NexusEngine.WriteByte(_processHandle, address, value);
    bool IMemoryOperations.WriteInt16(ulong address, short value) => NexusEngine.WriteInt16(_processHandle, address, value);
    bool IMemoryOperations.WriteInt32(ulong address, int value) => NexusEngine.WriteInt32(_processHandle, address, value);
    bool IMemoryOperations.WriteInt64(ulong address, long value) => NexusEngine.WriteInt64(_processHandle, address, value);
    bool IMemoryOperations.WriteFloat(ulong address, float value) => NexusEngine.WriteFloat(_processHandle, address, value);
    bool IMemoryOperations.WriteDouble(ulong address, double value) => NexusEngine.WriteDouble(_processHandle, address, value);
    bool IMemoryOperations.WriteBytes(ulong address, byte[] data) => NexusEngine.WriteBytes(_processHandle, address, data);

    bool IMemoryOperations.IsValidAddress(ulong address)
    {
        if (!IsProcessAttached) return false;
        var result = NexusEngine.Nexus_QueryMemory(_processHandle, address, out var region);
        return result == NexusResult.OK && region.State == 0x1000; // MEM_COMMIT
    }

    #endregion

    #region UI Integration

    public Form MainForm => _mainForm;

    public ToolStripMenuItem AddMenuItem(string text, EventHandler onClick)
    {
        var item = new ToolStripMenuItem(text);
        item.Click += onClick;

        if (_mainForm.InvokeRequired)
        {
            _mainForm.Invoke(() => _pluginsMenu.DropDownItems.Add(item));
        }
        else
        {
            _pluginsMenu.DropDownItems.Add(item);
        }

        return item;
    }

    public ToolStripMenuItem AddSubMenu(string text)
    {
        var item = new ToolStripMenuItem(text);

        if (_mainForm.InvokeRequired)
        {
            _mainForm.Invoke(() => _pluginsMenu.DropDownItems.Add(item));
        }
        else
        {
            _pluginsMenu.DropDownItems.Add(item);
        }

        return item;
    }

    public DialogResult ShowDialog(Form form)
    {
        if (_mainForm.InvokeRequired)
        {
            return (DialogResult)_mainForm.Invoke(() => form.ShowDialog(_mainForm));
        }
        return form.ShowDialog(_mainForm);
    }

    public void ShowForm(Form form)
    {
        if (_mainForm.InvokeRequired)
        {
            _mainForm.Invoke(() => form.Show(_mainForm));
        }
        else
        {
            form.Show(_mainForm);
        }
    }

    #endregion

    #region Logging

    public void LogInfo(string message)
    {
        System.Diagnostics.Debug.WriteLine($"[Plugin Info] {message}");
    }

    public void LogWarning(string message)
    {
        System.Diagnostics.Debug.WriteLine($"[Plugin Warning] {message}");
    }

    public void LogError(string message)
    {
        System.Diagnostics.Debug.WriteLine($"[Plugin Error] {message}");
    }

    public void LogException(Exception ex, string context = "")
    {
        var msg = string.IsNullOrEmpty(context)
            ? $"[Plugin Exception] {ex.Message}"
            : $"[Plugin Exception] {context}: {ex.Message}";
        System.Diagnostics.Debug.WriteLine(msg);
        System.Diagnostics.Debug.WriteLine(ex.StackTrace);
    }

    #endregion

    #region Settings

    public T GetSetting<T>(string pluginId, string key, T defaultValue)
    {
        if (_pluginSettings.TryGetValue(pluginId, out var settings))
        {
            if (settings.TryGetValue(key, out var value))
            {
                try
                {
                    if (value is JsonElement element)
                    {
                        return JsonSerializer.Deserialize<T>(element.GetRawText()) ?? defaultValue;
                    }
                    return (T)Convert.ChangeType(value, typeof(T));
                }
                catch
                {
                    return defaultValue;
                }
            }
        }
        return defaultValue;
    }

    public void SetSetting<T>(string pluginId, string key, T value)
    {
        if (!_pluginSettings.ContainsKey(pluginId))
        {
            _pluginSettings[pluginId] = new Dictionary<string, object>();
        }
        _pluginSettings[pluginId][key] = value!;
    }

    public void SaveSettings()
    {
        try
        {
            var json = JsonSerializer.Serialize(_pluginSettings, new JsonSerializerOptions { WriteIndented = true });
            var dir = Path.GetDirectoryName(_settingsPath);
            if (dir != null && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(_settingsPath, json);
        }
        catch (Exception ex)
        {
            LogException(ex, "Failed to save plugin settings");
        }
    }

    private void LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = File.ReadAllText(_settingsPath);
                var settings = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, object>>>(json);
                if (settings != null)
                {
                    foreach (var kvp in settings)
                    {
                        _pluginSettings[kvp.Key] = kvp.Value;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LogException(ex, "Failed to load plugin settings");
        }
    }

    #endregion

    #region Events

    public event EventHandler<ProcessEventArgs>? ProcessAttached;
    public event EventHandler? ProcessDetached;

    #endregion
}
