// <file>
// <summary>
// Base class for all shell module panels. Provides shared access to ProcessContext and
// EventBus, auto-subscribes to process attach/detach/provider-change events, and defines
// the panel menu integration point for contributing menus to the shell's menu bar.
// </summary>
// </file>

namespace Nexus.UI.Core;

/// <summary>
/// Base class for all module panels.
/// Provides common functionality and access to shared context.
/// </summary>
public class ShellPanel : UserControl
{
    /// <summary>
    /// Access to the shared process context.
    /// </summary>
    protected ProcessContext Context => ProcessContext.Current;

    /// <summary>
    /// Access to the event bus for cross-module communication.
    /// </summary>
    protected new EventBus Events => EventBus.Instance;

    /// <summary>
    /// Unique identifier for this panel type.
    /// Override in derived classes.
    /// </summary>
    public virtual string PanelId => GetType().Name;

    /// <summary>
    /// Display name for this panel.
    /// Override in derived classes.
    /// </summary>
    public virtual string PanelDisplayName => "Panel";

    protected ShellPanel()
    {
        // Subscribe to context events
        Context.ProcessAttached += OnProcessAttached;
        Context.ProcessDetached += OnProcessDetached;
        Context.ProviderChanged += OnProviderChanged;
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        // Unsubscribe from events
        Context.ProcessAttached -= OnProcessAttached;
        Context.ProcessDetached -= OnProcessDetached;
        Context.ProviderChanged -= OnProviderChanged;

        base.OnHandleDestroyed(e);
    }

    /// <summary>
    /// Called when a process is attached.
    /// Override to handle process attachment.
    /// </summary>
    protected virtual void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        // Override in derived classes
    }

    /// <summary>
    /// Called when a process is detached.
    /// Override to handle process detachment.
    /// </summary>
    protected virtual void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        // Override in derived classes
    }

    /// <summary>
    /// Called when a provider changes (e.g., switching from user mode to kernel).
    /// Override to handle provider changes.
    /// </summary>
    protected virtual void OnProviderChanged(object? sender, ProviderChangedEventArgs e)
    {
        // Override in derived classes
    }

    /// <summary>
    /// Publish an event to the event bus.
    /// </summary>
    protected void PublishEvent<TEvent>(TEvent evt) where TEvent : IEvent
    {
        Events.Publish(evt);
    }

    /// <summary>
    /// Subscribe to an event type.
    /// </summary>
    protected void SubscribeEvent<TEvent>(Action<TEvent> handler) where TEvent : IEvent
    {
        Events.Subscribe(handler);
    }

    /// <summary>
    /// Update the status bar with a message.
    /// </summary>
    protected void UpdateStatus(string message, StatusType type = StatusType.Info)
    {
        Events.Publish(new StatusUpdateEvent(message, type));
    }

    /// <summary>
    /// Returns panel-specific menus to be shown in the main menu bar.
    /// Override in derived classes to provide custom menus.
    /// These menus appear between the common menus (File, Edit, View) and Help.
    /// </summary>
    /// <returns>Array of menu items, or null/empty if no panel-specific menus.</returns>
    public virtual ToolStripMenuItem[]? GetPanelMenus() => null;
}
