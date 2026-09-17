// <file>
// <summary>
// Hex memory dump panel providing an x64dbg Dump-tab-style view of raw process memory.
// Renders address column, hex bytes (16 per row), and ASCII representation with scrollbar
// navigation. Integrated into the debugger layout as a companion view to disassembly.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Hex memory dump panel displaying raw bytes at a given address with address, hex, and ASCII columns.
/// Supports address navigation, selection highlighting, and scroll-based memory paging.
/// </summary>
public class HexDumpPanel : UserControl
{
    private readonly DoubleBufferedPanel _renderPanel;
    private readonly TextBox _addressBox;
    private readonly VScrollBar _scrollBar;
    private readonly Font _font = new("Consolas", 9f);

    private IntPtr _processHandle;
    private ulong _baseAddress;
    private ulong _selectedAddress;
    private int _selectionLength = 1;
    private readonly byte[] _buffer = new byte[4096];
    private bool _readSuccess;

    // Colors
    private readonly Color _backColor = Color.FromArgb(30, 30, 30);
    private readonly Color _addressColor = Color.FromArgb(86, 156, 214);
    private readonly Color _hexColor = Color.FromArgb(220, 220, 220);
    private readonly Color _asciiColor = Color.FromArgb(206, 145, 120);
    private readonly Color _selectionBackColor = Color.FromArgb(38, 79, 120);
    private readonly Color _selectionForeColor = Color.White;

    private const int BytesPerRow = 16;
    private const int RowCount = 32;

    public HexDumpPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Toolbar
        var toolbar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 26,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblAddress = new Label
        {
            Text = "Address:",
            Location = new Point(4, 5),
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary
        };

        _addressBox = new TextBox
        {
            Location = new Point(60, 2),
            Width = 140,
            Font = new Font("Consolas", 9f),
            Text = "0"
        };
        _addressBox.KeyDown += AddressBox_KeyDown;
        NexusTheme.StyleTextBox(_addressBox);

        var btnGo = new Button
        {
            Text = "Go",
            Location = new Point(206, 1),
            Size = new Size(40, 22)
        };
        btnGo.Click += (s, e) => GoToAddress();
        NexusTheme.StyleButton(btnGo);

        toolbar.Controls.AddRange(new Control[] { lblAddress, _addressBox, btnGo });

        // Scroll bar
        _scrollBar = new VScrollBar
        {
            Dock = DockStyle.Right,
            Minimum = 0,
            Maximum = 10000,
            LargeChange = 100
        };
        _scrollBar.Scroll += ScrollBar_Scroll;

        // Render panel
        _renderPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = _backColor
        };
        _renderPanel.Paint += RenderPanel_Paint;
        _renderPanel.MouseWheel += RenderPanel_MouseWheel;
        _renderPanel.MouseClick += RenderPanel_MouseClick;

        Controls.Add(_renderPanel);
        Controls.Add(_scrollBar);
        Controls.Add(toolbar);

        // Subscribe to navigation events
        EventBus.Instance.Subscribe<NavigateToAddressEvent>(OnNavigateToAddress);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;
        RefreshView();
    }

    public void NavigateTo(ulong address)
    {
        _baseAddress = address;
        _addressBox.Text = $"{address:X}";
        RefreshView();
    }

    private void OnNavigateToAddress(NavigateToAddressEvent evt)
    {
        if (evt.TargetModule == "HexDump" || evt.TargetModule == "Dump")
        {
            if (InvokeRequired)
                BeginInvoke(() => NavigateTo(evt.Address));
            else
                NavigateTo(evt.Address);
        }
    }

    private void GoToAddress()
    {
        var text = _addressBox.Text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var address))
        {
            NavigateTo(address);
        }
    }

    private void AddressBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            GoToAddress();
            e.Handled = true;
            e.SuppressKeyPress = true;
        }
    }

    private void RefreshView()
    {
        if (_processHandle == IntPtr.Zero)
        {
            _readSuccess = false;
            _renderPanel.Invalidate();
            return;
        }

        unsafe
        {
            fixed (byte* ptr = _buffer)
            {
                var result = NexusEngine.Nexus_ReadMemory(
                    _processHandle, _baseAddress, (IntPtr)ptr,
                    (nuint)_buffer.Length, out var bytesRead);
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

        if (_processHandle == IntPtr.Zero)
        {
            g.DrawString("Attach to a process to view memory", _font, Brushes.Gray, 10, 10);
            return;
        }

        int lineHeight = (int)_font.GetHeight(g) + 2;
        int charWidth = (int)g.MeasureString("0", _font).Width;
        int addressWidth = charWidth * 17;
        int hexWidth = charWidth * 3;
        int asciiStart = addressWidth + (BytesPerRow * hexWidth) + charWidth * 2;

        using var addressBrush = new SolidBrush(_addressColor);
        using var hexBrush = new SolidBrush(_hexColor);
        using var asciiBrush = new SolidBrush(_asciiColor);
        using var selBackBrush = new SolidBrush(_selectionBackColor);
        using var selForeBrush = new SolidBrush(_selectionForeColor);

        // Header
        g.DrawString("address", _font, Brushes.Gray, 2, 2);
        int hx = addressWidth;
        for (int col = 0; col < BytesPerRow; col++)
        {
            g.DrawString($"{col:X2}", _font, Brushes.Gray, hx, 2);
            hx += hexWidth;
            if (col == 7) hx += charWidth;
        }

        // Data
        int dataStartY = lineHeight + 4;
        for (int row = 0; row < RowCount && row * BytesPerRow < _buffer.Length; row++)
        {
            int y = row * lineHeight + dataStartY;
            ulong rowAddress = _baseAddress + (ulong)(row * BytesPerRow);

            // Address
            g.DrawString($"{rowAddress:X16}", _font, addressBrush, 2, y);

            // Hex bytes
            int x = addressWidth;
            for (int col = 0; col < BytesPerRow; col++)
            {
                int idx = row * BytesPerRow + col;
                if (idx >= _buffer.Length) break;

                ulong byteAddr = rowAddress + (ulong)col;
                bool isSelected = byteAddr >= _selectedAddress &&
                                  byteAddr < _selectedAddress + (ulong)Math.Max(1, _selectionLength);

                string byteStr = _readSuccess ? $"{_buffer[idx]:X2}" : "??";

                if (isSelected)
                {
                    g.FillRectangle(selBackBrush, x - 1, y - 1, hexWidth, lineHeight);
                    g.DrawString(byteStr, _font, selForeBrush, x, y);
                }
                else
                {
                    g.DrawString(byteStr, _font, hexBrush, x, y);
                }

                x += hexWidth;
                if (col == 7) x += charWidth;
            }

            // ASCII
            x = asciiStart;
            for (int col = 0; col < BytesPerRow; col++)
            {
                int idx = row * BytesPerRow + col;
                if (idx >= _buffer.Length) break;

                char c = _readSuccess && _buffer[idx] >= 32 && _buffer[idx] < 127
                    ? (char)_buffer[idx] : '.';

                ulong byteAddr = rowAddress + (ulong)col;
                bool isSelected = byteAddr >= _selectedAddress &&
                                  byteAddr < _selectedAddress + (ulong)Math.Max(1, _selectionLength);

                if (isSelected)
                {
                    g.FillRectangle(selBackBrush, x - 1, y - 1, charWidth - 2, lineHeight);
                    g.DrawString(c.ToString(), _font, selForeBrush, x, y);
                }
                else
                {
                    g.DrawString(c.ToString(), _font, asciiBrush, x, y);
                }

                x += charWidth - 3;
            }
        }
    }

    private void ScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        _baseAddress = (ulong)(e.NewValue * BytesPerRow);
        RefreshView();
    }

    private void RenderPanel_MouseWheel(object? sender, MouseEventArgs e)
    {
        int delta = e.Delta > 0 ? -3 : 3;
        long newAddr = (long)_baseAddress + delta * BytesPerRow;
        if (newAddr < 0) newAddr = 0;
        _baseAddress = (ulong)newAddr;
        RefreshView();
    }

    private void RenderPanel_MouseClick(object? sender, MouseEventArgs e)
    {
        using var g = _renderPanel.CreateGraphics();
        int lineHeight = (int)_font.GetHeight(g) + 2;
        int charWidth = (int)g.MeasureString("0", _font).Width;
        int addressWidth = charWidth * 17;
        int hexWidth = charWidth * 3;

        int dataStartY = lineHeight + 4;
        int row = (e.Y - dataStartY) / lineHeight;

        if (row >= 0 && row < RowCount)
        {
            int hexX = e.X - addressWidth;
            if (hexX >= 0)
            {
                if (hexX >= hexWidth * 8 + charWidth)
                    hexX -= charWidth;

                int col = hexX / hexWidth;
                if (col >= 0 && col < BytesPerRow)
                {
                    _selectedAddress = _baseAddress + (ulong)(row * BytesPerRow + col);
                    _selectionLength = 1;
                    _renderPanel.Invalidate();
                }
            }
        }

        _renderPanel.Focus();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<NavigateToAddressEvent>(OnNavigateToAddress);
            _font.Dispose();
        }
        base.Dispose(disposing);
    }
}
