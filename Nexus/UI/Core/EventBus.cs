// <file>
// <summary>
// Publish-subscribe event bus for decoupled cross-module communication. Modules publish
// and subscribe to typed events without direct references to each other. Also defines
// the IEvent marker interface and common application events (StatusUpdate, AddressSelected,
// NavigateToAddress, MemoryChanged, ProcessListRefresh, ScanComplete, ValueChanged).
// </summary>
// </file>

namespace Nexus.UI.Core;

/// <summary>
/// Event bus for loosely-coupled communication between modules.
/// Modules can publish and subscribe to events without knowing about each other.
/// </summary>
public class EventBus
{
    private static EventBus? _instance;
    private readonly Dictionary<Type, List<Delegate>> _handlers = [];
    private readonly object _lock = new();

    /// <summary>
    /// Global event bus instance.
    /// </summary>
    public static EventBus Instance => _instance ??= new EventBus();

    /// <summary>
    /// Subscribe to an event type.
    /// </summary>
    public void Subscribe<TEvent>(Action<TEvent> handler) where TEvent : IEvent
    {
        lock (_lock)
        {
            var type = typeof(TEvent);
            if (!_handlers.TryGetValue(type, out var handlers))
            {
                handlers = [];
                _handlers[type] = handlers;
            }
            handlers.Add(handler);
        }
    }

    /// <summary>
    /// Unsubscribe from an event type.
    /// </summary>
    public void Unsubscribe<TEvent>(Action<TEvent> handler) where TEvent : IEvent
    {
        lock (_lock)
        {
            var type = typeof(TEvent);
            if (_handlers.TryGetValue(type, out var handlers))
            {
                handlers.Remove(handler);
            }
        }
    }

    /// <summary>
    /// Publish an event to all subscribers.
    /// </summary>
    public void Publish<TEvent>(TEvent evt) where TEvent : IEvent
    {
        List<Delegate> handlersCopy;
        lock (_lock)
        {
            var type = typeof(TEvent);
            if (!_handlers.TryGetValue(type, out var handlers))
                return;
            handlersCopy = [.. handlers];
        }

        foreach (var handler in handlersCopy)
        {
            try
            {
                ((Action<TEvent>)handler)(evt);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"EventBus handler error: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Clear all subscriptions.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _handlers.Clear();
        }
    }
}

/// <summary>
/// Marker interface for events.
/// </summary>
public interface IEvent { }

// Common events used across modules

/// <summary>
/// Event when an address is selected (e.g., from scan results).
/// </summary>
public class AddressSelectedEvent : IEvent
{
    public ulong Address { get; }
    public string? Description { get; }

    public AddressSelectedEvent(ulong address, string? description = null)
    {
        Address = address;
        Description = description;
    }
}

/// <summary>
/// Event to navigate to an address in a viewer.
/// </summary>
public class NavigateToAddressEvent : IEvent
{
    public ulong Address { get; }
    public string TargetModule { get; }

    public NavigateToAddressEvent(ulong address, string targetModule = "MemoryViewer")
    {
        Address = address;
        TargetModule = targetModule;
    }
}

/// <summary>
/// Event when a breakpoint is hit.
/// </summary>
public class BreakpointHitEvent : IEvent
{
    public ulong Address { get; }
    public int ThreadId { get; }

    public BreakpointHitEvent(ulong address, int threadId)
    {
        Address = address;
        ThreadId = threadId;
    }
}

/// <summary>
/// Event when memory is modified.
/// </summary>
public class MemoryModifiedEvent : IEvent
{
    public ulong Address { get; }
    public int Size { get; }

    public MemoryModifiedEvent(ulong address, int size)
    {
        Address = address;
        Size = size;
    }
}

/// <summary>
/// Event to add an address to the watch list.
/// </summary>
public class AddToWatchListEvent : IEvent
{
    public ulong Address { get; }
    public string ValueType { get; }
    public string? Description { get; }

    public AddToWatchListEvent(ulong address, string valueType, string? description = null)
    {
        Address = address;
        ValueType = valueType;
        Description = description;
    }
}

/// <summary>
/// Event when a module/DLL is loaded or unloaded.
/// </summary>
public class ModuleLoadEvent : IEvent
{
    public string ModuleName { get; }
    public ulong BaseAddress { get; }
    public ulong Size { get; }
    public bool IsLoad { get; }

    public ModuleLoadEvent(string name, ulong baseAddress, ulong size, bool isLoad)
    {
        ModuleName = name;
        BaseAddress = baseAddress;
        Size = size;
        IsLoad = isLoad;
    }
}

/// <summary>
/// Event for status bar updates.
/// </summary>
public class StatusUpdateEvent : IEvent
{
    public string Message { get; }
    public StatusType Type { get; }

    public StatusUpdateEvent(string message, StatusType type = StatusType.Info)
    {
        Message = message;
        Type = type;
    }
}

public enum StatusType
{
    Info,
    Warning,
    Error,
    Success
}

/// <summary>
/// Event when the process/driver watchlist changes.
/// </summary>
public class ProcessWatchlistChangedEvent : IEvent { }
