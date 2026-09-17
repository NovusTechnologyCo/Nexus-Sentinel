// <file>
// <summary>
// Process and kernel driver watchlist service. Polls the system at regular intervals
// to detect when target processes start/stop or kernel drivers load/unload. Fires
// events for discovered/exited processes and loaded/unloaded drivers. Used by the
// Kernel Monitor panel and API Monitor panel to automatically begin monitoring
// when target applications or anti-cheat drivers appear.
// </summary>
// </file>

using System.Runtime.InteropServices;
using System.Text.Json;
using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Models;

namespace Nexus.UI.Services;

/// <summary>
/// Runtime state for a watched entry.
/// </summary>
public class WatchlistEntry
{
    public string Name { get; set; } = "";
    public WatchlistEntryType Type { get; set; }
    public bool Enabled { get; set; } = true;
    public List<int> ActivePids { get; set; } = [];
    public ulong DriverBase { get; set; }
    public ulong DriverSize { get; set; }
    public bool IsActive { get; set; }
}

/// <summary>
/// Event args for process discovery/exit.
/// </summary>
public class WatchlistProcessEventArgs : EventArgs
{
    public int ProcessId { get; }
    public string ProcessName { get; }
    public WatchlistEntry Entry { get; }

    public WatchlistProcessEventArgs(int pid, string name, WatchlistEntry entry)
    {
        ProcessId = pid;
        ProcessName = name;
        Entry = entry;
    }
}

/// <summary>
/// Event args for driver load/unload.
/// </summary>
public class WatchlistDriverEventArgs : EventArgs
{
    public WatchlistEntry Entry { get; }

    public WatchlistDriverEventArgs(WatchlistEntry entry)
    {
        Entry = entry;
    }
}

/// <summary>
/// Singleton service that watches for processes and kernel drivers by name.
/// Uses timer-based polling to detect when targets appear or disappear.
/// </summary>
public class ProcessWatchlist : IDisposable
{
    private static ProcessWatchlist? _instance;
    private static readonly object _instanceLock = new();

    public static ProcessWatchlist Instance
    {
        get
        {
            if (_instance == null)
            {
                lock (_instanceLock)
                {
                    _instance ??= new ProcessWatchlist();
                }
            }
            return _instance;
        }
    }

    private readonly List<WatchlistEntry> _entries = [];
    private readonly Dictionary<int, WatchlistEntry> _activePids = [];
    private readonly object _lock = new();
    private System.Threading.Timer? _pollTimer;
    private bool _isRunning;

    /// <summary>
    /// Poll interval in milliseconds. Default is 1000ms for general watchlist use.
    /// Set to a lower value (e.g. 100ms) for fast process detection when racing
    /// against anti-cheat initialization.
    /// </summary>
    public int PollIntervalMs { get; set; } = 1000;

    public bool FollowChildProcesses { get; set; } = true;

    /// <summary>
    /// When true, watchlist only enables ETW observation — no OpenProcess, no DLL injection.
    /// Safe for monitoring anti-cheat protected processes.
    /// </summary>
    public bool PassiveMode { get; set; } = true;

    // Events
    public event EventHandler<WatchlistProcessEventArgs>? ProcessDiscovered;
    public event EventHandler<WatchlistProcessEventArgs>? ProcessExited;
    public event EventHandler<WatchlistDriverEventArgs>? DriverLoaded;
    public event EventHandler<WatchlistDriverEventArgs>? DriverUnloaded;
    public event EventHandler? WatchlistChanged;

    public IReadOnlyList<WatchlistEntry> Entries
    {
        get
        {
            lock (_lock)
            {
                return [.. _entries];
            }
        }
    }

    public bool IsRunning => _isRunning;

    /// <summary>
    /// Returns all currently tracked process PIDs.
    /// </summary>
    public IReadOnlyDictionary<int, WatchlistEntry> ActivePids
    {
        get
        {
            lock (_lock)
            {
                return new Dictionary<int, WatchlistEntry>(_activePids);
            }
        }
    }

    /// <summary>
    /// Checks if the given PID is being tracked by the watchlist.
    /// </summary>
    public bool IsTrackedPid(int pid)
    {
        lock (_lock)
        {
            return _activePids.ContainsKey(pid);
        }
    }

    public void AddEntry(string name, WatchlistEntryType type)
    {
        lock (_lock)
        {
            if (_entries.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && e.Type == type))
                return;

            _entries.Add(new WatchlistEntry
            {
                Name = name,
                Type = type,
                Enabled = true
            });
        }
        WatchlistChanged?.Invoke(this, EventArgs.Empty);
        EventBus.Instance.Publish(new ProcessWatchlistChangedEvent());
    }

    public void RemoveEntry(WatchlistEntry entry)
    {
        lock (_lock)
        {
            _entries.Remove(entry);

            // Clean up active PIDs for this entry
            if (entry.Type == WatchlistEntryType.Process)
            {
                var pidsToRemove = _activePids.Where(kv => kv.Value == entry).Select(kv => kv.Key).ToList();
                foreach (var pid in pidsToRemove)
                {
                    _activePids.Remove(pid);
                }
            }
        }
        WatchlistChanged?.Invoke(this, EventArgs.Empty);
        EventBus.Instance.Publish(new ProcessWatchlistChangedEvent());
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;

        // Use non-periodic timer to prevent re-entrant callbacks
        _pollTimer = new System.Threading.Timer(PollCallback, null, 0, Timeout.Infinite);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        _pollTimer?.Dispose();
        _pollTimer = null;
    }

    private void PollCallback(object? state)
    {
        if (!_isRunning) return;

        try
        {
            PollProcesses();
            PollDrivers();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProcessWatchlist] Poll error: {ex.Message}");
        }
        finally
        {
            // Re-arm the timer for next poll (prevents re-entrant callbacks)
            if (_isRunning)
            {
                try { _pollTimer?.Change(PollIntervalMs, Timeout.Infinite); }
                catch (ObjectDisposedException) { }
            }
        }
    }

    private void PollProcesses()
    {
        List<WatchlistEntry> processEntries;
        lock (_lock)
        {
            processEntries = _entries
                .Where(e => e.Type == WatchlistEntryType.Process && e.Enabled)
                .ToList();
        }

        if (processEntries.Count == 0) return;

        // Use native CreateToolhelp32Snapshot for fast enumeration.
        // Process.GetProcesses() creates ~200 managed Process objects per poll,
        // causing GC pressure. Native toolhelp is a single snapshot with no allocations.
        Dictionary<string, List<int>> runningProcesses;
        IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1))
            return;

        try
        {
            runningProcesses = new(StringComparer.OrdinalIgnoreCase);
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(hSnap, ref pe))
            {
                do
                {
                    if (string.IsNullOrEmpty(pe.szExeFile)) continue;

                    // Store with full exe name (e.g. "target.exe")
                    if (!runningProcesses.TryGetValue(pe.szExeFile, out var list))
                    {
                        list = [];
                        runningProcesses[pe.szExeFile] = list;
                    }
                    list.Add((int)pe.th32ProcessID);

                    // Also store without .exe extension for matching
                    var nameNoExt = Path.GetFileNameWithoutExtension(pe.szExeFile);
                    if (!runningProcesses.TryGetValue(nameNoExt, out var list2))
                    {
                        list2 = [];
                        runningProcesses[nameNoExt] = list2;
                    }
                    list2.Add((int)pe.th32ProcessID);
                } while (Process32NextW(hSnap, ref pe));
            }
        }
        catch { return; }
        finally
        {
            CloseHandle(hSnap);
        }

        // Collect events to fire OUTSIDE the lock
        var discovered = new List<WatchlistProcessEventArgs>();
        var exited = new List<WatchlistProcessEventArgs>();

        lock (_lock)
        {
            foreach (var entry in processEntries)
            {
                if (!runningProcesses.TryGetValue(entry.Name, out var pids))
                    pids = [];

                // Detect new PIDs
                foreach (var pid in pids)
                {
                    if (!entry.ActivePids.Contains(pid))
                    {
                        entry.ActivePids.Add(pid);
                        entry.IsActive = true;
                        _activePids[pid] = entry;
                        discovered.Add(new WatchlistProcessEventArgs(pid, entry.Name, entry));
                    }
                }

                // Detect exited PIDs
                var exitedPids = entry.ActivePids.Where(p => !pids.Contains(p)).ToList();
                foreach (var pid in exitedPids)
                {
                    entry.ActivePids.Remove(pid);
                    _activePids.Remove(pid);
                    exited.Add(new WatchlistProcessEventArgs(pid, entry.Name, entry));
                }

                entry.IsActive = entry.ActivePids.Count > 0;
            }
        }

        // Fire events outside the lock so subscribers can safely access watchlist state
        foreach (var args in discovered)
        {
            try { ProcessDiscovered?.Invoke(this, args); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ProcessWatchlist] ProcessDiscovered handler error: {ex.Message}"); }
        }
        foreach (var args in exited)
        {
            try { ProcessExited?.Invoke(this, args); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ProcessWatchlist] ProcessExited handler error: {ex.Message}"); }
        }
    }

    private void PollDrivers()
    {
        List<WatchlistEntry> driverEntries;
        lock (_lock)
        {
            driverEntries = _entries
                .Where(e => e.Type == WatchlistEntryType.Driver && e.Enabled)
                .ToList();
        }

        if (driverEntries.Count == 0) return;

        // Collect events to fire outside the lock
        var loaded = new List<WatchlistDriverEventArgs>();
        var unloaded = new List<WatchlistDriverEventArgs>();

        foreach (var entry in driverEntries)
        {
            bool found;
            ulong moduleBase;
            try
            {
                found = NexusEngine.FindKernelModule(entry.Name, out moduleBase);
            }
            catch
            {
                continue; // Skip this entry if kernel query fails
            }

            lock (_lock)
            {
                if (found && moduleBase != 0)
                {
                    if (!entry.IsActive)
                    {
                        entry.IsActive = true;
                        entry.DriverBase = moduleBase;
                        entry.DriverSize = GetKernelModuleSize(entry.Name);
                        loaded.Add(new WatchlistDriverEventArgs(entry));
                    }
                    else
                    {
                        entry.DriverBase = moduleBase;
                    }
                }
                else if (entry.IsActive)
                {
                    entry.IsActive = false;
                    entry.DriverBase = 0;
                    entry.DriverSize = 0;
                    unloaded.Add(new WatchlistDriverEventArgs(entry));
                }
            }
        }

        // Fire events outside the lock
        foreach (var args in loaded)
        {
            try { DriverLoaded?.Invoke(this, args); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ProcessWatchlist] DriverLoaded handler error: {ex.Message}"); }
        }
        foreach (var args in unloaded)
        {
            try { DriverUnloaded?.Invoke(this, args); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ProcessWatchlist] DriverUnloaded handler error: {ex.Message}"); }
        }
    }

    /// <summary>
    /// Attempts to get the size of a kernel module using NtQuerySystemInformation.
    /// </summary>
    private static ulong GetKernelModuleSize(string moduleName)
    {
        const int SystemModuleInformation = 11;
        const int RTL_PROCESS_MODULE_INFO_SIZE = 296;

        int status = NtQuerySystemInformation(SystemModuleInformation, IntPtr.Zero, 0, out uint returnLength);
        if (returnLength == 0) return 0;

        IntPtr buffer = Marshal.AllocHGlobal((int)(returnLength + 4096));
        try
        {
            status = NtQuerySystemInformation(SystemModuleInformation, buffer, returnLength + 4096, out _);
            if (status != 0) return 0;

            uint numberOfModules = (uint)Marshal.ReadInt32(buffer);
            IntPtr moduleArrayPtr = buffer + 8;

            for (uint i = 0; i < numberOfModules; i++)
            {
                IntPtr currentModule = moduleArrayPtr + (int)(i * RTL_PROCESS_MODULE_INFO_SIZE);

                ushort offsetToFileName = (ushort)Marshal.ReadInt16(currentModule + 38);
                IntPtr fileNamePtr = currentModule + 40 + offsetToFileName;
                string? fileName = Marshal.PtrToStringAnsi(fileNamePtr);

                if (!string.IsNullOrEmpty(fileName) &&
                    fileName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    // ImageSize is at offset 24 (after Section=IntPtr + MappedBase=IntPtr + ImageBase=IntPtr)
                    return (ulong)Marshal.ReadInt32(currentModule + 24);
                }
            }
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, uint bufferLength, out uint returnLength);

    // Native process enumeration — much faster than Process.GetProcesses()
    // (no managed Process objects created, no GC pressure)
    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }


    /// <summary>
    /// Saves entries to a JSON profile file.
    /// </summary>
    public void SaveProfile(string filePath)
    {
        List<WatchlistEntry> snapshot;
        lock (_lock)
        {
            snapshot = [.. _entries];
        }

        var profile = new WatchlistProfile
        {
            Name = Path.GetFileNameWithoutExtension(filePath),
            Entries = snapshot.Select(e => new WatchlistProfileEntry
            {
                ProcessName = e.Name,
                Type = e.Type,
                Enabled = e.Enabled
            }).ToList(),
            FollowChildProcesses = FollowChildProcesses
        };

        var options = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(filePath, JsonSerializer.Serialize(profile, options));
    }

    /// <summary>
    /// Loads entries from a JSON profile file.
    /// </summary>
    public void LoadProfile(string filePath)
    {
        var json = File.ReadAllText(filePath);
        var profile = JsonSerializer.Deserialize<WatchlistProfile>(json);
        if (profile?.Entries == null) return;

        lock (_lock)
        {
            _entries.Clear();
            _activePids.Clear();

            foreach (var pe in profile.Entries)
            {
                _entries.Add(new WatchlistEntry
                {
                    Name = pe.ProcessName,
                    Type = pe.Type,
                    Enabled = pe.Enabled
                });
            }

            FollowChildProcesses = profile.FollowChildProcesses;
        }

        WatchlistChanged?.Invoke(this, EventArgs.Empty);
        EventBus.Instance.Publish(new ProcessWatchlistChangedEvent());
    }

    /// <summary>
    /// Restores watchlist from NexusSettings persistence.
    /// </summary>
    public void RestoreFromSettings()
    {
        var settings = NexusSettings.Instance;
        if (settings.WatchlistProcessNames.Count == 0 && settings.WatchlistDriverNames.Count == 0) return;

        lock (_lock)
        {
            foreach (var name in settings.WatchlistProcessNames)
            {
                if (!_entries.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && e.Type == WatchlistEntryType.Process))
                {
                    _entries.Add(new WatchlistEntry { Name = name, Type = WatchlistEntryType.Process });
                }
            }
            foreach (var name in settings.WatchlistDriverNames)
            {
                if (!_entries.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && e.Type == WatchlistEntryType.Driver))
                {
                    _entries.Add(new WatchlistEntry { Name = name, Type = WatchlistEntryType.Driver });
                }
            }
            FollowChildProcesses = settings.WatchlistFollowChildren;
            PassiveMode = settings.WatchlistPassiveMode;
        }

        if (settings.WatchlistAutoStart)
            Start();
    }

    /// <summary>
    /// Persists current watchlist to NexusSettings.
    /// </summary>
    public void SaveToSettings()
    {
        var settings = NexusSettings.Instance;
        lock (_lock)
        {
            settings.WatchlistProcessNames = _entries
                .Where(e => e.Type == WatchlistEntryType.Process)
                .Select(e => e.Name)
                .ToList();
            settings.WatchlistDriverNames = _entries
                .Where(e => e.Type == WatchlistEntryType.Driver)
                .Select(e => e.Name)
                .ToList();
            settings.WatchlistFollowChildren = FollowChildProcesses;
            settings.WatchlistPassiveMode = PassiveMode;
            settings.WatchlistAutoStart = _isRunning;
        }
        settings.Save();
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
