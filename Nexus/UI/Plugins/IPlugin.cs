// <file>
// <summary>
// Core plugin interface that all Nexus Sentinel plugins must implement. Defines the
// contract for plugin identity (Id, Name, Version, Author, Description), lifecycle
// (Initialize, Shutdown), and optional capabilities (menu items, panel creation).
// </summary>
// </file>

namespace Nexus.UI.Plugins;

/// <summary>
/// Base interface that all Nexus plugins must implement.
/// </summary>
public interface IPlugin
{
    /// <summary>
    /// Unique identifier for this plugin.
    /// </summary>
    string Id { get; }

    /// <summary>
    /// Display name of the plugin.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Plugin version string (e.g., "1.0.0").
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Plugin author/developer name.
    /// </summary>
    string Author { get; }

    /// <summary>
    /// Brief description of what the plugin does.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Called when the plugin is loaded and initialized.
    /// </summary>
    /// <param name="host">The plugin host providing access to Nexus functionality.</param>
    void Initialize(IPluginHost host);

    /// <summary>
    /// Called when the plugin is being unloaded.
    /// Clean up any resources here.
    /// </summary>
    void Shutdown();
}

/// <summary>
/// Optional interface for plugins that want to add menu items.
/// </summary>
public interface IPluginWithMenu : IPlugin
{
    /// <summary>
    /// Called to register menu items. Use host.AddMenuItem().
    /// </summary>
    void RegisterMenuItems(IPluginHost host);
}

/// <summary>
/// Optional interface for plugins that want to respond to process events.
/// </summary>
public interface IPluginWithProcessEvents : IPlugin
{
    /// <summary>
    /// Called when a process is attached.
    /// </summary>
    void OnProcessAttached(int processId, IntPtr processHandle);

    /// <summary>
    /// Called when the current process is detached.
    /// </summary>
    void OnProcessDetached();
}

/// <summary>
/// Optional interface for plugins that run background tasks.
/// </summary>
public interface IPluginWithBackgroundTask : IPlugin
{
    /// <summary>
    /// Called on a background thread after initialization.
    /// Use the cancellation token to stop when shutdown is requested.
    /// </summary>
    Task RunAsync(CancellationToken cancellationToken);
}
