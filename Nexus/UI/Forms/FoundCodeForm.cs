// <file>
// <summary>
// Found code dialog showing instructions that accessed a specific memory address.
// </summary>
// </file>
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using System.Text;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

public partial class FoundCodeForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly int _processId;
    private readonly ulong _watchedAddress;
    private readonly List<FoundCodeEntry> _entries = [];
    private readonly NexusBreakpointType _breakpointType;

    // Debugger state
    private IntPtr _debuggerHandle = IntPtr.Zero;
    private ulong _breakpointId;
    private Thread? _debugThread;
    private volatile bool _monitoring;       // True while debug loop should run
    private volatile bool _capturing;        // True while we should capture breakpoint hits
    private volatile int _cleanupCountdown;  // Grace period after breakpoint removal (like CE's deletecountdown)
    private int _cleanupDone; // 0 = not done, 1 = done (use Interlocked)

    private const int CleanupGracePeriodIterations = 10; // Number of loop iterations to drain events after stop

    // Static tracking of all open FoundCodeForm instances (for auto-cleanup of conflicting debuggers)
    private static readonly List<FoundCodeForm> _activeInstances = [];
    private static readonly object _instanceLock = new();

    public class FoundCodeEntry
    {
        public ulong Address { get; set; }
        public int Count { get; set; }
        public string Instruction { get; set; } = "";
        public byte[] OriginalBytes { get; set; } = [];
        public int OpcodeSize { get; set; }
        public string ExtraInfo { get; set; } = "";
        public string RegistersText { get; set; } = "";  // Formatted register state at time of access
    }

    public FoundCodeForm(IntPtr processHandle, ulong watchedAddress,
        NexusBreakpointType breakpointType = NexusBreakpointType.HardwareWrite,
        int processId = 0)
    {
        _processHandle = processHandle;
        _processId = processId;
        _watchedAddress = watchedAddress;
        _breakpointType = breakpointType;
        InitializeComponent();
        NexusTheme.StyleForm(this);

        string typeText = breakpointType == NexusBreakpointType.HardwareWrite ? "writes to" : "accesses";
        Text = $"Find out what {typeText} {watchedAddress:X}";

        // Handle resize to keep instruction column filling available space
        lvFoundCode.Resize += (s, e) => ResizeInstructionColumn();
        ResizeInstructionColumn();

        // Stop any existing breakpoint monitors for the same process
        // Windows only allows one debugger per process (keeps windows open for reference)
        StopExistingMonitorsForProcess(processId);

        // Track this instance
        lock (_instanceLock)
        {
            _activeInstances.Add(this);
        }

        // Start monitoring automatically
        StartMonitoring();
    }

    /// <summary>
    /// Stop monitoring on all existing FoundCodeForm instances for the same process.
    /// This detaches the debugger but keeps the window open so results can still be viewed.
    /// Required because Windows only allows one debugger per process.
    /// </summary>
    private static void StopExistingMonitorsForProcess(int processId)
    {
        if (processId == 0) return;

        List<FoundCodeForm> toStop;
        lock (_instanceLock)
        {
            toStop = _activeInstances
                .Where(f => f._processId == processId && f._monitoring)
                .ToList();
        }

        foreach (var form in toStop)
        {
            try
            {
                // Stop monitoring (removes breakpoint and detaches debugger)
                // but keep the window open so user can still view results
                form._capturing = false;
                form._monitoring = false;

                // Wait briefly for the debug thread to exit and detach
                form._debugThread?.Join(500);

                // Update UI to show monitoring was stopped
                if (!form.IsDisposed)
                {
                    if (form.InvokeRequired)
                    {
                        form.BeginInvoke(() => form.UpdateUIAfterExternalStop());
                    }
                    else
                    {
                        form.UpdateUIAfterExternalStop();
                    }
                }
            }
            catch
            {
                // Ignore errors during cleanup
            }
        }

        // Give a moment for cleanup to complete
        if (toStop.Count > 0)
        {
            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Updates UI when monitoring is stopped externally (by another FoundCodeForm opening).
    /// </summary>
    private void UpdateUIAfterExternalStop()
    {
        try
        {
            btnOK.Text = "Close";
            memoInfo.Text += "\r\n\r\nMonitoring stopped (new breakpoint monitor opened).";
        }
        catch { /* Ignore */ }
    }

    private void ResizeInstructionColumn()
    {
        // Calculate available width for instruction column
        int availableWidth = lvFoundCode.ClientSize.Width - colCount.Width - 4;
        if (availableWidth > 100)
        {
            colInstruction.Width = availableWidth;
        }
    }

    #region Public Methods

    /// <summary>
    /// Add a found opcode to the list.
    /// </summary>
    public void AddEntry(ulong address, string instruction, byte[] originalBytes, string extraInfo = "", string registersText = "")
    {
        // Check if already in list
        var existing = _entries.FirstOrDefault(e => e.Address == address);
        if (existing != null)
        {
            existing.Count++;
            // Update registers to most recent capture
            if (!string.IsNullOrEmpty(registersText))
                existing.RegistersText = registersText;
            UpdateListItem(existing);
            return;
        }

        var entry = new FoundCodeEntry
        {
            Address = address,
            Count = 1,
            Instruction = instruction,
            OriginalBytes = originalBytes,
            OpcodeSize = originalBytes.Length,
            ExtraInfo = extraInfo,
            RegistersText = registersText
        };
        _entries.Add(entry);

        var item = new ListViewItem(entry.Count.ToString());
        item.SubItems.Add($"{address:X} - {instruction}");
        item.Tag = entry;
        lvFoundCode.Items.Add(item);
    }

    private void UpdateListItem(FoundCodeEntry entry)
    {
        foreach (ListViewItem item in lvFoundCode.Items)
        {
            if (item.Tag == entry)
            {
                item.SubItems[0].Text = entry.Count.ToString();
                break;
            }
        }
    }

    #endregion

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Remove from tracking
        lock (_instanceLock)
        {
            _activeInstances.Remove(this);
        }

        // Stop capturing and remove breakpoint
        _capturing = false;

        // Stop the debug loop
        _monitoring = false;

        // Wait briefly for the loop to exit and cleanup
        try
        {
            _debugThread?.Join(1000);
        }
        catch { /* Ignore */ }

        base.OnFormClosing(e);
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        try
        {
            if (_capturing)
            {
                // Still capturing - stop monitoring (removes breakpoint)
                StopMonitoring();
            }
            else
            {
                // Already stopped - close the form (this will stop the loop and detach)
                Close();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"BtnOK_Click exception: {ex}");
            try { Close(); } catch { /* Ignore */ }
        }
    }
}
