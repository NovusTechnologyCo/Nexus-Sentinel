// <file>
// <summary>
// Debugger layout panel composing all debugging sub-panels into an x64dbg-style arrangement.
// Hosts the disassembly view, registers, arguments, call stack, breakpoints, trace log,
// debug log, hex dump, and raw stack dump in a nested split container layout.
// Acts as the container for the shell's "Debugger" tab.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Main debugger layout panel arranging all debugging sub-panels in an x64dbg-style grid.
/// <para>
/// Layout:
/// <code>
/// +------------------------------------------+------------------+
/// |                                          |    Registers     |
/// |           Disassembly View               |                  |
/// |                                          +------------------+
/// |           (with hex view below)          |   Arguments      |
/// +------------------------------------------+------------------+
/// | [Call Stack] [Breakpoints] [Trace] [Log] |   Stack Dump     |
/// | (Tabbed)                                 |   (raw stack)    |
/// +------------------------------------------+------------------+
/// </code>
/// Coordinates debug events between sub-panels: when a breakpoint is hit, the disassembler
/// notifies registers, stack, and hex dump panels to refresh with the paused thread context.
/// </para>
/// </summary>
public class DebuggerLayoutPanel : ShellPanel
{
    // Sub-panels
    private readonly DisassemblerPanel _disassemblerPanel;
    private readonly RegistersPanel _registersPanel;
    private readonly ArgumentsPanel _argumentsPanel;
    private readonly BreakpointsPanel _breakpointsPanel;
    private readonly StackPanel _stackPanel;
    private readonly TracePanel _tracePanel;
    private readonly LogPanel _logPanel;
    private readonly StackDumpPanel _stackDumpPanel;
    private readonly HexDumpPanel _hexDumpPanel;

    // Layout containers (x64dbg style nesting)
    private readonly SplitContainer _mainSplit;        // Top | Bottom (horizontal ~65:35)
    private readonly SplitContainer _topSplit;         // Disasm | Right sidebar (vertical ~77:23)
    private readonly SplitContainer _topRightSplit;    // Registers | Arguments (horizontal)
    private readonly SplitContainer _bottomSplit;      // Tabs | Stack Dump (vertical ~50:50)
    private readonly TabControl _bottomTabs;           // Tabs for Call Stack, Breakpoints, Trace, Log

    public override string PanelId => "Debugger";
    public override string PanelDisplayName => "Debugger";

    public DebuggerLayoutPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Create sub-panels
        _disassemblerPanel = new DisassemblerPanel { Dock = DockStyle.Fill };
        _registersPanel = new RegistersPanel { Dock = DockStyle.Fill };
        _argumentsPanel = new ArgumentsPanel { Dock = DockStyle.Fill };
        _breakpointsPanel = new BreakpointsPanel { Dock = DockStyle.Fill };
        _stackPanel = new StackPanel { Dock = DockStyle.Fill };
        _tracePanel = new TracePanel { Dock = DockStyle.Fill };
        _logPanel = new LogPanel { Dock = DockStyle.Fill };
        _stackDumpPanel = new StackDumpPanel { Dock = DockStyle.Fill };
        _hexDumpPanel = new HexDumpPanel { Dock = DockStyle.Fill };

        // Wire up navigation events
        _breakpointsPanel.OnNavigateToAddress += (s, addr) => NavigateToAddress(addr);
        _stackPanel.OnNavigateToAddress += (s, addr) => NavigateToAddress(addr);
        _tracePanel.OnNavigateToAddress += (s, addr) => NavigateToAddress(addr);

        // Wire up debug events - when disassembler pauses, update all panels
        _disassemblerPanel.OnDebugPaused += (s, threadId) => SetThreadId(threadId);

        // Top Right split: Registers (top) | Arguments (bottom)
        _topRightSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 50,
            Panel2MinSize = 50,
            SplitterWidth = 4
        };
        _topRightSplit.Panel1.Controls.Add(_registersPanel);
        _topRightSplit.Panel2.Controls.Add(_argumentsPanel);

        // Top split: Disassembler (left) | Right sidebar (right) - x64dbg 77:23 ratio
        _topSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 50,
            Panel2MinSize = 50,
            SplitterWidth = 4
        };
        _topSplit.Panel1.Controls.Add(_disassemblerPanel);
        _topSplit.Panel2.Controls.Add(_topRightSplit);

        // Bottom tabs (x64dbg style - like CPUMultiDump)
        _bottomTabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Alignment = TabAlignment.Top,
            SizeMode = TabSizeMode.Fixed,
            ItemSize = new Size(80, 20),
            Padding = new Point(0, 0)
        };
        StyleTabControl(_bottomTabs);

        // Add tab pages
        var stackTab = new TabPage("Call Stack") { Padding = new Padding(0) };
        stackTab.Controls.Add(_stackPanel);
        _bottomTabs.TabPages.Add(stackTab);

        var breakpointsTab = new TabPage("Breakpoints") { Padding = new Padding(0) };
        breakpointsTab.Controls.Add(_breakpointsPanel);
        _bottomTabs.TabPages.Add(breakpointsTab);

        var traceTab = new TabPage("Trace") { Padding = new Padding(0) };
        traceTab.Controls.Add(_tracePanel);
        _bottomTabs.TabPages.Add(traceTab);

        var logTab = new TabPage("Log") { Padding = new Padding(0) };
        logTab.Controls.Add(_logPanel);
        _bottomTabs.TabPages.Add(logTab);

        var hexDumpTab = new TabPage("Dump") { Padding = new Padding(0) };
        hexDumpTab.Controls.Add(_hexDumpPanel);
        _bottomTabs.TabPages.Add(hexDumpTab);

        // Bottom split: Tabs (left) | Stack Dump (right)
        _bottomSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 50,
            Panel2MinSize = 50,
            SplitterWidth = 4
        };
        _bottomSplit.Panel1.Controls.Add(_bottomTabs);
        _bottomSplit.Panel2.Controls.Add(_stackDumpPanel);

        // Main split: Top | Bottom - x64dbg 48:62 ratio (we'll use ~65:35)
        _mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 50,
            Panel2MinSize = 50,
            SplitterWidth = 4
        };
        _mainSplit.Panel1.Controls.Add(_topSplit);
        _mainSplit.Panel2.Controls.Add(_bottomSplit);

        Controls.Add(_mainSplit);

        // Set initial splitter positions after load (deferred to ensure layout is complete)
        Load += (s, e) => BeginInvoke(SetInitialSplitterPositions);

        // Style splitters
        StyleSplitter(_mainSplit);
        StyleSplitter(_topSplit);
        StyleSplitter(_topRightSplit);
        StyleSplitter(_bottomSplit);

        // Log startup message
        _logPanel.AppendLog("Debugger initialized", LogType.Info);
    }

    private void StyleTabControl(TabControl tabs)
    {
        tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
        tabs.DrawItem += TabControl_DrawItem;
        tabs.BackColor = NexusTheme.BackgroundDark;

        foreach (TabPage page in tabs.TabPages)
        {
            page.BackColor = NexusTheme.BackgroundPanel;
            page.ForeColor = NexusTheme.TextPrimary;
        }
    }

    private void TabControl_DrawItem(object? sender, DrawItemEventArgs e)
    {
        var tabs = sender as TabControl;
        if (tabs == null) return;

        var page = tabs.TabPages[e.Index];
        var bounds = e.Bounds;
        bool selected = tabs.SelectedIndex == e.Index;

        // Background
        using var backBrush = new SolidBrush(selected ? NexusTheme.BackgroundPanel : NexusTheme.BackgroundDark);
        e.Graphics.FillRectangle(backBrush, bounds);

        // Text
        using var textBrush = new SolidBrush(selected ? NexusTheme.TextPrimary : NexusTheme.TextSecondary);
        var textSize = e.Graphics.MeasureString(page.Text, tabs.Font);
        var textX = bounds.X + (bounds.Width - textSize.Width) / 2;
        var textY = bounds.Y + (bounds.Height - textSize.Height) / 2;
        e.Graphics.DrawString(page.Text, tabs.Font, textBrush, textX, textY);

        // Bottom border for selected tab
        if (selected)
        {
            using var pen = new Pen(NexusTheme.Accent, 2);
            e.Graphics.DrawLine(pen, bounds.Left, bounds.Bottom - 1, bounds.Right, bounds.Bottom - 1);
        }
    }

    private void SetInitialSplitterPositions()
    {
        try
        {
            // Main split: ~65:35 -> top:bottom
            if (_mainSplit.Height > 0)
                _mainSplit.SplitterDistance = (int)(_mainSplit.Height * 0.65);

            // Top horizontal: 74:26 -> disasm:right sidebar
            if (_topSplit.Width > 0)
                _topSplit.SplitterDistance = (int)(_topSplit.Width * 0.74);

            // Top right: registers get most space, arguments area at bottom (~275px)
            if (_topRightSplit.Height > 275)
                _topRightSplit.SplitterDistance = _topRightSplit.Height - 275;

            // Bottom split: 70:30 -> tabs:stack dump
            if (_bottomSplit.Width > 0)
                _bottomSplit.SplitterDistance = (int)(_bottomSplit.Width * 0.70);
        }
        catch
        {
            // Ignore layout exceptions during initialization
        }
    }

    private static void StyleSplitter(SplitContainer split)
    {
        split.BackColor = NexusTheme.BackgroundDark;
        split.Panel1.BackColor = NexusTheme.BackgroundPanel;
        split.Panel2.BackColor = NexusTheme.BackgroundPanel;
    }

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        base.OnProcessAttached(sender, e);

        var handle = Context.NativeProcessHandle;
        _stackPanel.SetProcessHandle(handle);
        _tracePanel.SetProcessHandle(handle);
        _stackDumpPanel.SetProcessHandle(handle);
        _argumentsPanel.SetProcessHandle(handle);
        _hexDumpPanel.SetProcessHandle(handle);

        // Try to get first thread and update all panels
        TryGetFirstThread(handle);

        _logPanel.AppendLog($"Attached to {e.ProcessName} (PID: {e.ProcessId})", LogType.Success);
    }

    private void TryGetFirstThread(IntPtr processHandle)
    {
        if (processHandle == IntPtr.Zero) return;

        var threads = new NexusThreadInfo[64];
        var result = NexusEngine.Nexus_EnumerateThreads(processHandle, threads, 64, out nuint count);
        if ((result == NexusResult.OK || result == NexusResult.Success) && count > 0)
        {
            SetThreadId(threads[0].ThreadId);
        }
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        base.OnProcessDetached(sender, e);

        _registersPanel.ClearRegisters();
        _stackPanel.SetProcessHandle(IntPtr.Zero);
        _tracePanel.SetProcessHandle(IntPtr.Zero);

        _logPanel.AppendLog("Process detached", LogType.Info);
    }

    private void NavigateToAddress(ulong address)
    {
        _disassemblerPanel.NavigateTo(address);
    }

    /// <summary>
    /// Gets the embedded disassembler panel for direct access.
    /// </summary>
    public DisassemblerPanel DisassemblerPanel => _disassemblerPanel;

    /// <summary>
    /// Gets the log panel for external logging.
    /// </summary>
    public LogPanel LogPanel => _logPanel;

    /// <summary>
    /// Sets the debugger handle for breakpoint management.
    /// </summary>
    public void SetDebuggerHandle(IntPtr handle)
    {
        _breakpointsPanel.SetDebuggerHandle(handle);
    }

    /// <summary>
    /// Refreshes all panels.
    /// </summary>
    public void RefreshAll()
    {
        _breakpointsPanel.RefreshBreakpoints();
        _stackPanel.RefreshStack();
        _registersPanel.RefreshRegisters();
        _argumentsPanel.RefreshArguments();
    }

    /// <summary>
    /// Sets the thread ID for panels that need thread context.
    /// </summary>
    public void SetThreadId(uint threadId)
    {
        _registersPanel.SetThreadId(threadId);
        _argumentsPanel.SetThreadId(threadId);
        _stackDumpPanel.SetThreadContext(threadId, 0); // RSP will be fetched internally
    }

    /// <summary>
    /// Logs a message to the Log panel.
    /// </summary>
    public void Log(string message, LogType type = LogType.Info)
    {
        _logPanel.AppendLog(message, type);
    }
}
