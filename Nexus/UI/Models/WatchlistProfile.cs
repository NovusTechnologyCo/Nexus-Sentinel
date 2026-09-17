// <file>
// <summary>
// Serializable data models for the process and driver watchlist. Defines WatchlistEntryType
// (Process/Driver), WatchlistProfileEntry (a single watched item), and WatchlistProfile
// (a named collection of entries that can be saved/loaded as JSON).
// </summary>
// </file>

namespace Nexus.UI.Models;

/// <summary>
/// Type of watchlist entry.
/// </summary>
public enum WatchlistEntryType
{
    Process,
    Driver
}

/// <summary>
/// A single entry in a watchlist profile (serializable).
/// </summary>
public class WatchlistProfileEntry
{
    public string ProcessName { get; set; } = "";
    public WatchlistEntryType Type { get; set; }
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// A saveable/loadable watchlist profile containing process and driver targets.
/// </summary>
public class WatchlistProfile
{
    public string Name { get; set; } = "Default";
    public DateTime Created { get; set; } = DateTime.Now;
    public List<WatchlistProfileEntry> Entries { get; set; } = [];
    public bool FollowChildProcesses { get; set; } = true;
}
