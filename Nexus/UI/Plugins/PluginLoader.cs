// <file>
// <summary>
// Plugin discovery, verification, and loading engine. Scans the plugins/ directory for
// DLL assemblies, verifies signatures and trust status, prompts for user approval of
// unsigned/untrusted plugins, and loads approved plugins into isolated AssemblyLoadContexts.
// Persists trust decisions to a JSON settings file.
// </summary>
// </file>

using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;

namespace Nexus.UI.Plugins;

/// <summary>
/// Manages discovery, verification, and loading of plugins.
/// </summary>
public class PluginLoader : IDisposable
{
    private readonly string _pluginsDirectory;
    private readonly string _settingsPath;
    private readonly List<PluginInfo> _plugins = new();
    private readonly List<PluginLoadContext> _loadContexts = new();
    private PluginTrustSettings _trustSettings = new();
    private bool _disposed;

    /// <summary>
    /// All discovered plugins.
    /// </summary>
    public IReadOnlyList<PluginInfo> Plugins => _plugins.AsReadOnly();

    /// <summary>
    /// Trust settings for plugin verification.
    /// </summary>
    public PluginTrustSettings TrustSettings => _trustSettings;

    /// <summary>
    /// Event fired when a plugin requires user approval.
    /// </summary>
    public event EventHandler<PluginApprovalEventArgs>? ApprovalRequired;

    /// <summary>
    /// Event fired when a plugin is loaded.
    /// </summary>
    public event EventHandler<PluginInfo>? PluginLoaded;

    /// <summary>
    /// Event fired when a plugin fails to load.
    /// </summary>
    public event EventHandler<PluginInfo>? PluginLoadFailed;

    public PluginLoader(string pluginsDirectory, string settingsPath)
    {
        _pluginsDirectory = pluginsDirectory;
        _settingsPath = settingsPath;

        // Ensure plugins directory exists
        if (!Directory.Exists(_pluginsDirectory))
        {
            Directory.CreateDirectory(_pluginsDirectory);
        }

        LoadTrustSettings();
    }

    /// <summary>
    /// Discover all plugin DLLs in the plugins directory.
    /// </summary>
    public void DiscoverPlugins()
    {
        _plugins.Clear();

        if (!Directory.Exists(_pluginsDirectory))
            return;

        foreach (var dllPath in Directory.GetFiles(_pluginsDirectory, "*.dll", SearchOption.TopDirectoryOnly))
        {
            var pluginInfo = AnalyzePlugin(dllPath);
            _plugins.Add(pluginInfo);
        }
    }

    /// <summary>
    /// Analyze a plugin DLL without loading it.
    /// </summary>
    private PluginInfo AnalyzePlugin(string dllPath)
    {
        var fileHash = PluginInfo.CalculateFileHash(dllPath);
        var (sigStatus, signerName, thumbprint) = PluginInfo.CheckSignature(
            dllPath,
            PluginTrustSettings.NexusCertificateThumbprint);

        var trustStatus = DetermineTrustStatus(sigStatus, fileHash);

        return new PluginInfo
        {
            FilePath = dllPath,
            FileHash = fileHash,
            SignatureStatus = sigStatus,
            SignerName = signerName,
            CertificateThumbprint = thumbprint,
            TrustStatus = trustStatus
        };
    }

    /// <summary>
    /// Determine trust status based on signature and whitelist.
    /// </summary>
    private PluginTrustStatus DetermineTrustStatus(PluginSignatureStatus sigStatus, string fileHash)
    {
        // Official Nexus signature = always trusted
        if (sigStatus == PluginSignatureStatus.TrustedNexus)
        {
            return PluginTrustStatus.Trusted;
        }

        // Invalid signature = always blocked (tampered)
        if (sigStatus == PluginSignatureStatus.Invalid)
        {
            return PluginTrustStatus.Blocked;
        }

        // Check blocklist
        if (_trustSettings.IsBlocked(fileHash))
        {
            return PluginTrustStatus.Blocked;
        }

        // Check whitelist
        if (_trustSettings.IsApproved(fileHash))
        {
            return PluginTrustStatus.UserApproved;
        }

        // Unknown plugin
        return PluginTrustStatus.RequiresApproval;
    }

    /// <summary>
    /// Load all trusted and approved plugins.
    /// </summary>
    /// <param name="host">Plugin host to provide to plugins.</param>
    /// <param name="promptForApproval">Whether to prompt for unknown plugins.</param>
    public async Task LoadPluginsAsync(IPluginHost host, bool promptForApproval = true)
    {
        foreach (var plugin in _plugins)
        {
            // Skip already loaded
            if (plugin.IsLoaded)
                continue;

            // Handle based on trust status
            switch (plugin.TrustStatus)
            {
                case PluginTrustStatus.Trusted:
                case PluginTrustStatus.UserApproved:
                    LoadPlugin(plugin, host);
                    break;

                case PluginTrustStatus.RequiresApproval:
                    if (promptForApproval && _trustSettings.PromptForUnknown)
                    {
                        var args = new PluginApprovalEventArgs(plugin);
                        ApprovalRequired?.Invoke(this, args);

                        // Wait for approval decision
                        await args.WaitForDecisionAsync();

                        if (args.Approved)
                        {
                            _trustSettings.Approve(plugin.FileHash, plugin.FileName);
                            plugin.TrustStatus = PluginTrustStatus.UserApproved;
                            SaveTrustSettings();
                            LoadPlugin(plugin, host);
                        }
                        else if (args.Blocked)
                        {
                            _trustSettings.Block(plugin.FileHash);
                            plugin.TrustStatus = PluginTrustStatus.Blocked;
                            SaveTrustSettings();
                        }
                    }
                    break;

                case PluginTrustStatus.Blocked:
                    // Don't load blocked plugins
                    break;
            }
        }
    }

    /// <summary>
    /// Load a single plugin.
    /// </summary>
    private void LoadPlugin(PluginInfo pluginInfo, IPluginHost host)
    {
        try
        {
            // Create isolated load context
            var loadContext = new PluginLoadContext(pluginInfo.FilePath);
            _loadContexts.Add(loadContext);

            // Load the assembly
            var assembly = loadContext.LoadFromAssemblyPath(pluginInfo.FilePath);

            // Find IPlugin implementation
            var pluginType = assembly.GetTypes()
                .FirstOrDefault(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

            if (pluginType == null)
            {
                pluginInfo.LoadError = "No IPlugin implementation found";
                PluginLoadFailed?.Invoke(this, pluginInfo);
                return;
            }

            // Create instance
            var instance = (IPlugin?)Activator.CreateInstance(pluginType);
            if (instance == null)
            {
                pluginInfo.LoadError = "Failed to create plugin instance";
                PluginLoadFailed?.Invoke(this, pluginInfo);
                return;
            }

            // Initialize
            instance.Initialize(host);
            pluginInfo.Instance = instance;

            // Register menu items if applicable
            if (instance is IPluginWithMenu menuPlugin)
            {
                menuPlugin.RegisterMenuItems(host);
            }

            // Update approved plugin name if we now know it
            if (pluginInfo.TrustStatus == PluginTrustStatus.UserApproved)
            {
                var approved = _trustSettings.ApprovedPlugins
                    .FirstOrDefault(p => string.Equals(p.Hash, pluginInfo.FileHash, StringComparison.OrdinalIgnoreCase));
                if (approved != null && approved.PluginName == null)
                {
                    approved.PluginName = instance.Name;
                    SaveTrustSettings();
                }
            }

            PluginLoaded?.Invoke(this, pluginInfo);
        }
        catch (Exception ex)
        {
            pluginInfo.LoadError = ex.Message;
            PluginLoadFailed?.Invoke(this, pluginInfo);
        }
    }

    /// <summary>
    /// Unload all plugins.
    /// </summary>
    public void UnloadAll()
    {
        foreach (var plugin in _plugins.Where(p => p.IsLoaded))
        {
            try
            {
                plugin.Instance?.Shutdown();
            }
            catch
            {
                // Ignore shutdown errors
            }
            plugin.Instance = null;
        }

        // Unload contexts
        foreach (var context in _loadContexts)
        {
            context.Unload();
        }
        _loadContexts.Clear();
    }

    /// <summary>
    /// Refresh the plugin list (rescan directory).
    /// </summary>
    public void Refresh()
    {
        UnloadAll();
        DiscoverPlugins();
    }

    /// <summary>
    /// Load trust settings from disk.
    /// </summary>
    private void LoadTrustSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = File.ReadAllText(_settingsPath);
                _trustSettings = JsonSerializer.Deserialize<PluginTrustSettings>(json) ?? new();
            }
        }
        catch
        {
            _trustSettings = new PluginTrustSettings();
        }
    }

    /// <summary>
    /// Save trust settings to disk.
    /// </summary>
    public void SaveTrustSettings()
    {
        try
        {
            var json = JsonSerializer.Serialize(_trustSettings, new JsonSerializerOptions { WriteIndented = true });
            var dir = Path.GetDirectoryName(_settingsPath);
            if (dir != null && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(_settingsPath, json);
        }
        catch
        {
            // Ignore save errors
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            UnloadAll();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Isolated assembly load context for plugins.
/// </summary>
internal class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;

    public PluginLoadContext(string pluginPath) : base(isCollectible: true)
    {
        _resolver = new AssemblyDependencyResolver(pluginPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        var assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        if (assemblyPath != null)
        {
            return LoadFromAssemblyPath(assemblyPath);
        }

        return null;
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        var libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (libraryPath != null)
        {
            return LoadUnmanagedDllFromPath(libraryPath);
        }

        return IntPtr.Zero;
    }
}

/// <summary>
/// Event args for plugin approval requests.
/// </summary>
public class PluginApprovalEventArgs : EventArgs
{
    private readonly TaskCompletionSource<bool> _tcs = new();

    public PluginInfo Plugin { get; }
    public bool Approved { get; private set; }
    public bool Blocked { get; private set; }

    public PluginApprovalEventArgs(PluginInfo plugin)
    {
        Plugin = plugin;
    }

    /// <summary>
    /// Approve the plugin for loading.
    /// </summary>
    public void Approve()
    {
        Approved = true;
        Blocked = false;
        _tcs.TrySetResult(true);
    }

    /// <summary>
    /// Block the plugin from loading.
    /// </summary>
    public void Block()
    {
        Approved = false;
        Blocked = true;
        _tcs.TrySetResult(true);
    }

    /// <summary>
    /// Skip the plugin for now (don't load, don't block).
    /// </summary>
    public void Skip()
    {
        Approved = false;
        Blocked = false;
        _tcs.TrySetResult(true);
    }

    /// <summary>
    /// Wait for the user to make a decision.
    /// </summary>
    internal Task WaitForDecisionAsync() => _tcs.Task;
}
