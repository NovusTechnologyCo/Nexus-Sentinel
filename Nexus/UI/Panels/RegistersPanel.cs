// <file>
// <summary>
// CPU registers display panel in x64dbg style. Shows general-purpose registers (RAX-R15),
// segment registers, flags (RFLAGS with individual flag bits), XMM/YMM SIMD registers,
// and debug registers. Highlights changed values in red when stepping through code.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// CPU registers display panel showing all x64 register groups with change highlighting.
/// Renders general-purpose, segment, flags, XMM/YMM, and debug registers. Values that
/// changed since the last update are highlighted in red. Supports context menu for copying
/// register values and navigating to addresses held in registers.
/// </summary>
public partial class RegistersPanel : UserControl
{
    private readonly DoubleBufferedPanel _renderPanel;
    private readonly VScrollBar _scrollBar;
    private readonly ContextMenuStrip _contextMenu;
    private readonly Font _font = new("Consolas", 9f);

    // Register values
    private CONTEXT64 _context;
    private CONTEXT64 _previousContext;
    private bool _hasContext;
    private uint _threadId;

    // Colors (x64dbg style)
    private readonly Color _backColor = Color.FromArgb(30, 30, 30);
    private readonly Color _labelColor = Color.FromArgb(200, 200, 200);
    private readonly Color _valueColor = Color.FromArgb(200, 200, 200);
    private readonly Color _changedColor = Color.FromArgb(255, 0, 0);
    private readonly Color _zeroColor = Color.FromArgb(128, 128, 128);
    private readonly Color _sectionColor = Color.FromArgb(0, 150, 200);

    // Layout
    private const int RowHeight = 16;
    private const int LabelWidth = 60;
    private const int XmmLabelWidth = 60;
    private int _selectedRegister = -1;
    private int _scrollOffset;
    private int _totalContentHeight;

    // Register definitions
    private readonly List<RegisterEntry> _gpRegisters = new();
    private readonly List<RegisterEntry> _extRegisters = new();

    private record RegisterEntry(string Name, Func<CONTEXT64, ulong> GetValue);

    public RegistersPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Scroll bar
        _scrollBar = new VScrollBar
        {
            Dock = DockStyle.Right,
            Minimum = 0,
            Maximum = 100,
            LargeChange = 10,
            SmallChange = RowHeight
        };
        _scrollBar.Scroll += (s, e) =>
        {
            _scrollOffset = e.NewValue;
            _renderPanel?.Invalidate();
        };

        // Render panel (no header - x64dbg style)
        _renderPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = _backColor
        };
        _renderPanel.Paint += RenderPanel_Paint;
        _renderPanel.MouseClick += RenderPanel_MouseClick;
        _renderPanel.MouseDoubleClick += RenderPanel_MouseDoubleClick;
        _renderPanel.MouseWheel += RenderPanel_MouseWheel;
        _renderPanel.Resize += (s, e) => UpdateScrollBar();

        // Context menu
        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Copy Value", null, (s, e) => CopySelectedValue());
        _contextMenu.Items.Add("Copy All", null, (s, e) => CopyAllRegisters());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Follow in Disassembler", null, (s, e) => FollowInDisassembler());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Modify...", null, (s, e) => EditRegister());
        _renderPanel.ContextMenuStrip = _contextMenu;

        Controls.Add(_renderPanel);
        Controls.Add(_scrollBar);

        InitializeRegisters();

        // Subscribe to events
        EventBus.Instance.Subscribe<BreakpointHitEvent>(OnBreakpointHit);
    }

    private void InitializeRegisters()
    {
        // General purpose registers (like x64dbg order)
        _gpRegisters.Add(new("RAX", c => c.Rax));
        _gpRegisters.Add(new("RBX", c => c.Rbx));
        _gpRegisters.Add(new("RCX", c => c.Rcx));
        _gpRegisters.Add(new("RDX", c => c.Rdx));
        _gpRegisters.Add(new("RBP", c => c.Rbp));
        _gpRegisters.Add(new("RSP", c => c.Rsp));
        _gpRegisters.Add(new("RSI", c => c.Rsi));
        _gpRegisters.Add(new("RDI", c => c.Rdi));

        // Extended registers
        _extRegisters.Add(new("R8", c => c.R8));
        _extRegisters.Add(new("R9", c => c.R9));
        _extRegisters.Add(new("R10", c => c.R10));
        _extRegisters.Add(new("R11", c => c.R11));
        _extRegisters.Add(new("R12", c => c.R12));
        _extRegisters.Add(new("R13", c => c.R13));
        _extRegisters.Add(new("R14", c => c.R14));
        _extRegisters.Add(new("R15", c => c.R15));
    }

    private void OnBreakpointHit(BreakpointHitEvent evt)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => OnBreakpointHit(evt));
            return;
        }

        _threadId = (uint)evt.ThreadId;
        RefreshRegisters();
    }

    public void RefreshRegisters()
    {
        if (_threadId == 0) return;

        _previousContext = _context;
        var result = NexusEngine.Nexus_GetThreadContext(_threadId, out _context);
        _hasContext = result == NexusResult.OK || result == NexusResult.Success;
        UpdateScrollBar();
        _renderPanel.Invalidate();
    }

    public void SetThreadId(uint threadId)
    {
        _threadId = threadId;
        RefreshRegisters();
    }

    public void ClearRegisters()
    {
        _hasContext = false;
        _threadId = 0;
        _context = default;
        _previousContext = default;
        _renderPanel.Invalidate();
    }

    private void UpdateScrollBar()
    {
        if (_totalContentHeight > _renderPanel.Height)
        {
            _scrollBar.Maximum = _totalContentHeight - _renderPanel.Height + _scrollBar.LargeChange;
            _scrollBar.Visible = true;
        }
        else
        {
            _scrollBar.Visible = false;
            _scrollOffset = 0;
        }
    }

    private void RenderPanel_MouseWheel(object? sender, MouseEventArgs e)
    {
        int delta = e.Delta > 0 ? -RowHeight * 3 : RowHeight * 3;
        _scrollOffset = Math.Max(0, Math.Min(_scrollOffset + delta, _scrollBar.Maximum - _scrollBar.LargeChange));
        _scrollBar.Value = _scrollOffset;
        _renderPanel.Invalidate();
    }

    private void RenderPanel_MouseClick(object? sender, MouseEventArgs e)
    {
        _selectedRegister = GetRegisterAtPoint(e.Location);
        _renderPanel.Invalidate();
    }

    private void RenderPanel_MouseDoubleClick(object? sender, MouseEventArgs e)
    {
        _selectedRegister = GetRegisterAtPoint(e.Location);
        if (_selectedRegister >= 0)
            EditRegister();
    }

    private int GetRegisterAtPoint(Point pt)
    {
        int y = 4 - _scrollOffset;
        int index = 0;

        // GP registers
        foreach (var _ in _gpRegisters)
        {
            if (pt.Y >= y && pt.Y < y + RowHeight)
                return index;
            y += RowHeight;
            index++;
        }

        y += 4; // gap

        // Extended registers
        foreach (var _ in _extRegisters)
        {
            if (pt.Y >= y && pt.Y < y + RowHeight)
                return index;
            y += RowHeight;
            index++;
        }

        y += 4; // gap

        // RIP
        if (pt.Y >= y && pt.Y < y + RowHeight)
            return index;
        y += RowHeight;
        index++;

        y += 4; // gap

        // RFLAGS
        if (pt.Y >= y && pt.Y < y + RowHeight * 2)
            return index;

        return -1;
    }

    private ulong GetSelectedRegisterValue()
    {
        if (_selectedRegister < 0 || !_hasContext) return 0;

        int index = _selectedRegister;

        if (index < _gpRegisters.Count)
            return _gpRegisters[index].GetValue(_context);

        index -= _gpRegisters.Count;

        if (index < _extRegisters.Count)
            return _extRegisters[index].GetValue(_context);

        index -= _extRegisters.Count;

        if (index == 0) return _context.Rip;
        if (index == 1) return _context.EFlags;

        return 0;
    }

    private void CopySelectedValue()
    {
        var value = GetSelectedRegisterValue();
        Clipboard.SetText($"{value:X16}");
    }

    private void CopyAllRegisters()
    {
        if (!_hasContext) return;
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=== General Purpose ===");
        foreach (var reg in _gpRegisters)
            sb.AppendLine($"{reg.Name,-4} {reg.GetValue(_context):X16}");
        sb.AppendLine();
        foreach (var reg in _extRegisters)
            sb.AppendLine($"{reg.Name,-4} {reg.GetValue(_context):X16}");
        sb.AppendLine();
        sb.AppendLine($"RIP  {_context.Rip:X16}");
        sb.AppendLine($"RFLAGS {_context.EFlags:X16}");
        sb.AppendLine();

        sb.AppendLine("=== Segment Registers ===");
        sb.AppendLine($"GS {_context.SegGs:X4}  FS {_context.SegFs:X4}  ES {_context.SegEs:X4}");
        sb.AppendLine($"DS {_context.SegDs:X4}  CS {_context.SegCs:X4}  SS {_context.SegSs:X4}");
        sb.AppendLine();

        sb.AppendLine("=== Debug Registers ===");
        sb.AppendLine($"DR0 {_context.Dr0:X16}");
        sb.AppendLine($"DR1 {_context.Dr1:X16}");
        sb.AppendLine($"DR2 {_context.Dr2:X16}");
        sb.AppendLine($"DR3 {_context.Dr3:X16}");
        sb.AppendLine($"DR6 {_context.Dr6:X16}");
        sb.AppendLine($"DR7 {_context.Dr7:X16}");
        sb.AppendLine();

        sb.AppendLine("=== SIMD Control ===");
        sb.AppendLine($"MxCsr {_context.MxCsr:X8}");

        Clipboard.SetText(sb.ToString());
    }

    private void FollowInDisassembler()
    {
        var address = GetSelectedRegisterValue();
        if (address != 0)
            EventBus.Instance.Publish(new NavigateToAddressEvent(address, "Disassembler"));
    }

    private void EditRegister()
    {
        if (_selectedRegister < 0 || !_hasContext) return;

        var regName = GetSelectedRegisterName();
        var value = GetSelectedRegisterValue();
        using var input = new Forms.InputBoxForm($"Edit {regName}", "Enter new value (hex):", $"{value:X}");
        if (input.ShowDialog(this) == DialogResult.OK)
        {
            if (ulong.TryParse(input.Value, System.Globalization.NumberStyles.HexNumber, null, out ulong newValue))
            {
                // Update the context with the new value
                var newContext = _context;
                if (!SetRegisterInContext(ref newContext, _selectedRegister, newValue))
                {
                    MessageBox.Show("Cannot modify this register.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Apply the modified context
                var result = NexusEngine.Nexus_SetThreadContext(_threadId, newContext);
                if (result == NexusResult.OK || result == NexusResult.Success)
                {
                    RefreshRegisters();
                }
                else
                {
                    MessageBox.Show($"Failed to set register: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                MessageBox.Show("Invalid hexadecimal value.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    private string GetSelectedRegisterName()
    {
        if (_selectedRegister < 0) return "";

        int index = _selectedRegister;

        if (index < _gpRegisters.Count)
            return _gpRegisters[index].Name;

        index -= _gpRegisters.Count;

        if (index < _extRegisters.Count)
            return _extRegisters[index].Name;

        index -= _extRegisters.Count;

        if (index == 0) return "RIP";
        if (index == 1) return "RFLAGS";

        return "";
    }

    private bool SetRegisterInContext(ref CONTEXT64 context, int registerIndex, ulong value)
    {
        int index = registerIndex;

        // GP registers
        if (index < _gpRegisters.Count)
        {
            var name = _gpRegisters[index].Name;
            switch (name)
            {
                case "RAX": context.Rax = value; return true;
                case "RBX": context.Rbx = value; return true;
                case "RCX": context.Rcx = value; return true;
                case "RDX": context.Rdx = value; return true;
                case "RBP": context.Rbp = value; return true;
                case "RSP": context.Rsp = value; return true;
                case "RSI": context.Rsi = value; return true;
                case "RDI": context.Rdi = value; return true;
            }
            return false;
        }

        index -= _gpRegisters.Count;

        // Extended registers
        if (index < _extRegisters.Count)
        {
            var name = _extRegisters[index].Name;
            switch (name)
            {
                case "R8": context.R8 = value; return true;
                case "R9": context.R9 = value; return true;
                case "R10": context.R10 = value; return true;
                case "R11": context.R11 = value; return true;
                case "R12": context.R12 = value; return true;
                case "R13": context.R13 = value; return true;
                case "R14": context.R14 = value; return true;
                case "R15": context.R15 = value; return true;
            }
            return false;
        }

        index -= _extRegisters.Count;

        // Special registers
        if (index == 0) { context.Rip = value; return true; }
        if (index == 1) { context.EFlags = (uint)value; return true; }

        return false;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<BreakpointHitEvent>(OnBreakpointHit);
            _font.Dispose();
            _contextMenu.Dispose();
        }
        base.Dispose(disposing);
    }
}
