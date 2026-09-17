// <file>
// <summary>
// Raw stack memory dump panel in x64dbg style. Reads contiguous stack memory and displays
// each QWORD/DWORD with its stack address, value, and a comment column resolving values
// to module+function names (if they point into known modules). Color-coded: return addresses
// in green, valid pointers in yellow, current stack pointer highlighted.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Raw stack memory dump panel showing stack address, QWORD value, and resolved symbol
/// comments. Values pointing into loaded modules are color-coded (return addresses in
/// green, other pointers in yellow). Renders via custom double-buffered painting.
/// </summary>
public class StackDumpPanel : UserControl
{
    private readonly DoubleBufferedPanel _renderPanel;
    private readonly VScrollBar _scrollBar;
    private readonly ContextMenuStrip _contextMenu;
    private readonly Font _font = new("Consolas", 9f);

    private IntPtr _processHandle;
    private ulong _stackPointer;
    private ulong _stackBase;
    private uint _threadId;
    private readonly byte[] _stackBuffer = new byte[4096];
    private bool _readSuccess;
    private int _scrollOffset;
    private int _selectedRow = -1;

    // Cached module list to avoid per-row allocation in paint
    private readonly NexusModuleInfo[] _cachedModules = new NexusModuleInfo[256];
    private nuint _cachedModuleCount;
    private bool _moduleCacheDirty = true;

    // Colors (x64dbg style)
    private readonly Color _backColor = Color.FromArgb(30, 30, 30);
    private readonly Color _addressColor = Color.FromArgb(128, 128, 128);
    private readonly Color _valueColor = Color.FromArgb(200, 200, 200);
    private readonly Color _returnColor = Color.FromArgb(0, 200, 0);
    private readonly Color _pointerColor = Color.FromArgb(200, 200, 0);
    private readonly Color _selectionColor = Color.FromArgb(60, 60, 80);

    private const int RowHeight = 16;
    private const int BytesPerRow = 8; // 64-bit values

    public StackDumpPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        _scrollBar = new VScrollBar
        {
            Dock = DockStyle.Right,
            Minimum = 0,
            Maximum = 1000,
            Value = 0,
            LargeChange = 100,
            SmallChange = 10
        };
        _scrollBar.Scroll += ScrollBar_Scroll;

        _renderPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = _backColor
        };
        _renderPanel.Paint += RenderPanel_Paint;
        _renderPanel.MouseWheel += RenderPanel_MouseWheel;
        _renderPanel.MouseClick += RenderPanel_MouseClick;
        _renderPanel.MouseDoubleClick += RenderPanel_MouseDoubleClick;

        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Follow in Disassembler", null, (s, e) => FollowInDisassembler());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Copy Address", null, (s, e) => CopyAddress());
        _contextMenu.Items.Add("Copy Value", null, (s, e) => CopyValue());
        _contextMenu.Items.Add("Copy Line", null, (s, e) => CopyLine());
        _renderPanel.ContextMenuStrip = _contextMenu;

        Controls.Add(_renderPanel);
        Controls.Add(_scrollBar);

        // Subscribe to events
        EventBus.Instance.Subscribe<BreakpointHitEvent>(OnBreakpointHit);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;
    }

    public void SetThreadContext(uint threadId, ulong rsp)
    {
        _threadId = threadId;
        _stackPointer = rsp;
        _stackBase = rsp;
        _scrollOffset = 0;
        RefreshStack();
    }

    private void OnBreakpointHit(BreakpointHitEvent evt)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => OnBreakpointHit(evt));
            return;
        }

        _threadId = (uint)evt.ThreadId;

        // Get RSP from thread context
        if (_threadId != 0)
        {
            var result = NexusEngine.Nexus_GetThreadContext(_threadId, out var context);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                _stackPointer = context.Rsp;
                _stackBase = context.Rsp;
                _scrollOffset = 0;
                RefreshStack();
            }
        }
    }

    public void RefreshStack()
    {
        if (_processHandle == IntPtr.Zero || _stackPointer == 0)
        {
            _readSuccess = false;
            _renderPanel.Invalidate();
            return;
        }

        _moduleCacheDirty = true;

        ulong readAddress = _stackBase + (ulong)(_scrollOffset * BytesPerRow);

        unsafe
        {
            fixed (byte* ptr = _stackBuffer)
            {
                var result = NexusEngine.Nexus_ReadMemory(
                    _processHandle, readAddress, (IntPtr)ptr,
                    (nuint)_stackBuffer.Length, out var bytesRead);
                _readSuccess = (result == NexusResult.OK || result == NexusResult.Success) && bytesRead > 0;
            }
        }

        _renderPanel.Invalidate();
    }

    private void RenderPanel_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        g.Clear(_backColor);

        if (_processHandle == IntPtr.Zero || _stackPointer == 0)
        {
            g.DrawString("No stack context", _font, Brushes.Gray, 4, 4);
            return;
        }

        if (!_readSuccess)
        {
            g.DrawString("Failed to read stack", _font, Brushes.Gray, 4, 4);
            return;
        }

        using var addressBrush = new SolidBrush(_addressColor);
        using var valueBrush = new SolidBrush(_valueColor);
        using var returnBrush = new SolidBrush(_returnColor);
        using var pointerBrush = new SolidBrush(_pointerColor);
        using var selectionBrush = new SolidBrush(_selectionColor);

        int charWidth = (int)g.MeasureString("0", _font).Width - 3;
        int addressWidth = charWidth * 17;
        int valueWidth = charWidth * 18;

        int y = 2;
        int rowIndex = 0;
        ulong baseAddr = _stackBase + (ulong)(_scrollOffset * BytesPerRow);

        while (y < _renderPanel.Height && rowIndex * BytesPerRow < _stackBuffer.Length)
        {
            ulong stackAddr = baseAddr + (ulong)(rowIndex * BytesPerRow);
            int bufferOffset = rowIndex * BytesPerRow;

            if (bufferOffset + BytesPerRow > _stackBuffer.Length)
                break;

            // Read 64-bit value
            ulong value = BitConverter.ToUInt64(_stackBuffer, bufferOffset);

            // Selection highlight
            if (rowIndex == _selectedRow)
            {
                g.FillRectangle(selectionBrush, 0, y - 1, _renderPanel.Width, RowHeight);
            }

            // Highlight current RSP
            if (stackAddr == _stackPointer)
            {
                using var rspBrush = new SolidBrush(Color.FromArgb(40, 60, 40));
                g.FillRectangle(rspBrush, 0, y - 1, _renderPanel.Width, RowHeight);
            }

            // Draw address
            g.DrawString($"{stackAddr:X16}", _font, addressBrush, 4, y);

            // Draw value with color indicator
            string valueStr = $"{value:X16}";
            g.DrawString(valueStr, _font, valueBrush, 4 + addressWidth, y);

            // Try to resolve the value as an address (return address, pointer, etc.)
            string comment = ResolveStackValue(value);
            if (!string.IsNullOrEmpty(comment))
            {
                var commentBrush = comment.StartsWith("return to") ? returnBrush : pointerBrush;
                g.DrawString(comment, _font, commentBrush, 4 + addressWidth + valueWidth, y);
            }

            y += RowHeight;
            rowIndex++;
        }
    }

    private void RefreshModuleCache()
    {
        if (!_moduleCacheDirty) return;

        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, _cachedModules, 256, out _cachedModuleCount);
        if (result != NexusResult.OK && result != NexusResult.Success)
            _cachedModuleCount = 0;

        _moduleCacheDirty = false;
    }

    private string ResolveStackValue(ulong value)
    {
        if (value == 0) return "";
        if (_processHandle == IntPtr.Zero) return "";

        // Check if value looks like a valid address (in user space)
        if (value < 0x10000 || value > 0x7FFFFFFFFFFF)
            return "";

        // Use cached module list (refreshed once per paint cycle)
        RefreshModuleCache();
        var moduleCount = (int)Math.Min(_cachedModuleCount, (nuint)_cachedModules.Length);
        if (moduleCount > 0)
        {
            for (int i = 0; i < moduleCount; i++)
            {
                var mod = _cachedModules[i];
                if (value >= mod.BaseAddress && value < mod.BaseAddress + mod.Size)
                {
                    string moduleName = Path.GetFileNameWithoutExtension(mod.Name ?? "");
                    ulong offset = value - mod.BaseAddress;

                    if (!string.IsNullOrEmpty(moduleName))
                    {
                        return $"return to {moduleName}.+{offset:X}";
                    }
                }
            }
        }

        // Check if it's a valid readable address (might be a pointer)
        var result = NexusEngine.Nexus_QueryMemory(_processHandle, value, out var memInfo);
        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            if (memInfo.Protection != 0)
                return ""; // Valid address but no symbol
        }

        return "";
    }

    private void ScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        _scrollOffset = e.NewValue;
        RefreshStack();
    }

    private void RenderPanel_MouseWheel(object? sender, MouseEventArgs e)
    {
        int delta = e.Delta > 0 ? -3 : 3;
        _scrollOffset = Math.Max(0, _scrollOffset + delta);
        _scrollBar.Value = Math.Min(_scrollBar.Maximum, Math.Max(_scrollBar.Minimum, _scrollOffset));
        RefreshStack();
    }

    private void RenderPanel_MouseClick(object? sender, MouseEventArgs e)
    {
        int row = (e.Y - 2) / RowHeight;
        if (row >= 0)
        {
            _selectedRow = row;
            _renderPanel.Invalidate();
        }
    }

    private void RenderPanel_MouseDoubleClick(object? sender, MouseEventArgs e)
    {
        FollowInDisassembler();
    }

    private ulong GetSelectedValue()
    {
        if (_selectedRow < 0 || !_readSuccess) return 0;

        int bufferOffset = _selectedRow * BytesPerRow;
        if (bufferOffset + BytesPerRow > _stackBuffer.Length) return 0;

        return BitConverter.ToUInt64(_stackBuffer, bufferOffset);
    }

    private ulong GetSelectedAddress()
    {
        if (_selectedRow < 0) return 0;
        return _stackBase + (ulong)((_scrollOffset + _selectedRow) * BytesPerRow);
    }

    private void FollowInDisassembler()
    {
        ulong value = GetSelectedValue();
        if (value != 0 && value > 0x10000 && value < 0x7FFFFFFFFFFF)
        {
            EventBus.Instance.Publish(new NavigateToAddressEvent(value, "Disassembler"));
        }
    }

    private void CopyAddress()
    {
        ulong addr = GetSelectedAddress();
        if (addr != 0)
            Clipboard.SetText($"{addr:X16}");
    }

    private void CopyValue()
    {
        ulong value = GetSelectedValue();
        Clipboard.SetText($"{value:X16}");
    }

    private void CopyLine()
    {
        ulong addr = GetSelectedAddress();
        ulong value = GetSelectedValue();
        string comment = ResolveStackValue(value);
        Clipboard.SetText($"{addr:X16}\t{value:X16}\t{comment}");
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
