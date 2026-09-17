// <file>
// <summary>
// Control flow graph (CFG) visualization panel rendering function basic blocks as boxes
// with disassembled instructions and edges as directional arrows between blocks.
// Supports pan/scroll navigation, block selection, and visual distinction between
// conditional jumps, unconditional jumps, and fall-through edges.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Control flow graph visualization panel rendering function CFGs as a node-edge diagram.
/// Basic blocks are drawn as boxes containing disassembled instructions. Edges are drawn as
/// arrows: conditional branches in green/red (taken/not-taken), unconditional jumps in blue,
/// and fall-through in gray. Supports scrolling, block selection, and hover highlighting.
/// </summary>
public class CFGPanel : ShellPanel
{
    #region Fields

    // CFG data
    private IntPtr _cfgHandle = IntPtr.Zero;
    private NexusCFGResult _cfgResult;
    private NexusBasicBlock[] _blocks = [];
    private NexusCFGEdge[] _edges = [];
    private Dictionary<uint, List<NexusDisasmInstruction>> _blockInstructions = [];

    // Layout data
    private Dictionary<uint, Rectangle> _blockBounds = [];
    private Point _scrollOffset = Point.Empty;
    private Size _contentSize = Size.Empty;

    // Selection
    private uint? _selectedBlock;
    private uint? _hoveredBlock;

    // Layout constants
    private const int BlockPadding = 10;
    private const int BlockMargin = 40;
    private const int InstructionHeight = 16;
    private const int BlockMinWidth = 250;
    private const int BlockHeaderHeight = 24;

    // Colors
    private readonly Color _blockBackColor = Color.FromArgb(40, 40, 45);
    private readonly Color _blockBorderColor = Color.FromArgb(80, 80, 85);
    private readonly Color _blockSelectedColor = Color.FromArgb(51, 153, 255);
    private readonly Color _blockHoveredColor = Color.FromArgb(60, 60, 65);
    private readonly Color _entryBlockColor = Color.FromArgb(50, 80, 50);
    private readonly Color _exitBlockColor = Color.FromArgb(80, 50, 50);
    private readonly Color _loopHeaderColor = Color.FromArgb(80, 70, 40);

    private readonly Color _edgeFallthroughColor = Color.FromArgb(100, 100, 100);
    private readonly Color _edgeBranchColor = Color.FromArgb(78, 201, 176);
    private readonly Color _edgeBackEdgeColor = Color.FromArgb(214, 157, 133);

    private readonly Color _addressColor = Color.FromArgb(86, 156, 214);
    private readonly Color _mnemonicColor = Color.FromArgb(220, 220, 220);
    private readonly Color _callColor = Color.FromArgb(78, 201, 176);
    private readonly Color _jumpColor = Color.FromArgb(184, 215, 163);
    private readonly Color _retColor = Color.FromArgb(214, 157, 133);

    // Fonts
    private readonly Font _codeFont = new("Consolas", 9f);
    private readonly Font _headerFont = new("Segoe UI", 9f, FontStyle.Bold);

    // UI Controls
    private DoubleBufferedPanel _graphPanel = null!;
    private VScrollBar _vScrollBar = null!;
    private HScrollBar _hScrollBar = null!;
    private Label _statusLabel = null!;
    private TextBox _addressBox = null!;

    // Dragging
    private bool _isDragging;
    private Point _dragStart;
    private Point _scrollStart;

    #endregion

    #region Constructor

    public CFGPanel()
    {
        Text = "Control Flow Graph";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Create toolbar
        var toolbar = CreateToolbar();

        // Create graph panel with scrollbars
        _vScrollBar = new VScrollBar
        {
            Dock = DockStyle.Right,
            Minimum = 0,
            Maximum = 100,
            Value = 0
        };
        _vScrollBar.Scroll += (s, e) =>
        {
            _scrollOffset.Y = e.NewValue;
            _graphPanel.Invalidate();
        };

        _hScrollBar = new HScrollBar
        {
            Dock = DockStyle.Bottom,
            Minimum = 0,
            Maximum = 100,
            Value = 0
        };
        _hScrollBar.Scroll += (s, e) =>
        {
            _scrollOffset.X = e.NewValue;
            _graphPanel.Invalidate();
        };

        _graphPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundDark
        };
        _graphPanel.Paint += GraphPanel_Paint;
        _graphPanel.MouseDown += GraphPanel_MouseDown;
        _graphPanel.MouseMove += GraphPanel_MouseMove;
        _graphPanel.MouseUp += GraphPanel_MouseUp;
        _graphPanel.MouseWheel += GraphPanel_MouseWheel;
        _graphPanel.Resize += (s, e) => UpdateScrollbars();

        // Status bar
        var statusPanel = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 24,
            BackColor = NexusTheme.BackgroundDark
        };
        _statusLabel = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = NexusTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(8, 0, 0, 0),
            Text = "Enter a function address to analyze"
        };
        statusPanel.Controls.Add(_statusLabel);

        // Add controls
        Controls.Add(_graphPanel);
        Controls.Add(_vScrollBar);
        Controls.Add(_hScrollBar);
        Controls.Add(toolbar);
        Controls.Add(statusPanel);

        // Subscribe to process events
        SubscribeEvent<NavigateToAddressEvent>(OnNavigateToAddress);
    }

    #endregion

    #region UI Creation

    private Panel CreateToolbar()
    {
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = new Padding(NexusTheme.Space4, NexusTheme.Space8, NexusTheme.Space4, NexusTheme.Space4)
        };

        var addrLabel = new Label
        {
            Text = "Function Address:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, NexusTheme.Space8, NexusTheme.Space8, 0)
        };

        _addressBox = new TextBox
        {
            Width = 150,
            Font = NexusTheme.FontMono,
            Text = ""
        };
        _addressBox.KeyDown += AddressBox_KeyDown;
        NexusTheme.StyleTextBox(_addressBox);
        _addressBox.Margin = new Padding(0, NexusTheme.Space4, NexusTheme.ButtonGap, 0);

        var analyzeBtn = new Button { Text = "Analyze" };
        NexusTheme.StylePrimaryButton(analyzeBtn);
        analyzeBtn.Size = new Size(100, NexusTheme.ButtonHeight);
        analyzeBtn.Margin = new Padding(0, 0, NexusTheme.ButtonGap, 0);
        analyzeBtn.Click += (s, e) => AnalyzeFunction();

        var clearBtn = new Button { Text = "Clear" };
        NexusTheme.StyleButton(clearBtn);
        clearBtn.Click += (s, e) => ClearCFG();

        var zoomLabel = new Label
        {
            Text = "Drag to pan, scroll to zoom",
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary,
            Margin = new Padding(NexusTheme.Space16, NexusTheme.Space8, 0, 0)
        };

        toolbar.Controls.Add(addrLabel);
        toolbar.Controls.Add(_addressBox);
        toolbar.Controls.Add(analyzeBtn);
        toolbar.Controls.Add(clearBtn);
        toolbar.Controls.Add(zoomLabel);

        return toolbar;
    }

    #endregion

    #region Event Handlers

    private void AddressBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;
            AnalyzeFunction();
        }
    }

    private void OnNavigateToAddress(NavigateToAddressEvent evt)
    {
        _addressBox.Text = $"0x{evt.Address:X}";
        AnalyzeFunction();
    }

    private void GraphPanel_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        // Apply scroll offset
        g.TranslateTransform(-_scrollOffset.X, -_scrollOffset.Y);

        if (_blocks.Length == 0)
        {
            g.TranslateTransform(_scrollOffset.X, _scrollOffset.Y);
            using var brush = new SolidBrush(NexusTheme.TextSecondary);
            var msg = "No CFG loaded. Enter a function address and click Analyze.";
            var size = g.MeasureString(msg, Font);
            g.DrawString(msg, Font, brush, (_graphPanel.Width - size.Width) / 2, (_graphPanel.Height - size.Height) / 2);
            return;
        }

        // Draw edges first (behind blocks)
        DrawEdges(g);

        // Draw blocks
        DrawBlocks(g);
    }

    private void GraphPanel_MouseDown(object? sender, MouseEventArgs e)
    {
        _graphPanel.Focus();

        if (e.Button == MouseButtons.Left)
        {
            // Check for block click
            var clickPoint = new Point(e.X + _scrollOffset.X, e.Y + _scrollOffset.Y);
            uint? clickedBlock = null;

            foreach (var kvp in _blockBounds)
            {
                if (kvp.Value.Contains(clickPoint))
                {
                    clickedBlock = kvp.Key;
                    break;
                }
            }

            if (clickedBlock.HasValue)
            {
                _selectedBlock = clickedBlock;
                _graphPanel.Invalidate();
                UpdateStatus();
            }
            else
            {
                // Start drag to pan
                _isDragging = true;
                _dragStart = e.Location;
                _scrollStart = _scrollOffset;
                _graphPanel.Cursor = Cursors.SizeAll;
            }
        }
    }

    private void GraphPanel_MouseMove(object? sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            int dx = _dragStart.X - e.X;
            int dy = _dragStart.Y - e.Y;
            _scrollOffset = new Point(
                Math.Clamp(_scrollStart.X + dx, 0, Math.Max(0, _contentSize.Width - _graphPanel.Width)),
                Math.Clamp(_scrollStart.Y + dy, 0, Math.Max(0, _contentSize.Height - _graphPanel.Height))
            );
            UpdateScrollbars();
            _graphPanel.Invalidate();
        }
        else
        {
            // Check for hover
            var hoverPoint = new Point(e.X + _scrollOffset.X, e.Y + _scrollOffset.Y);
            uint? newHover = null;

            foreach (var kvp in _blockBounds)
            {
                if (kvp.Value.Contains(hoverPoint))
                {
                    newHover = kvp.Key;
                    break;
                }
            }

            if (newHover != _hoveredBlock)
            {
                _hoveredBlock = newHover;
                _graphPanel.Cursor = newHover.HasValue ? Cursors.Hand : Cursors.Default;
                _graphPanel.Invalidate();
            }
        }
    }

    private void GraphPanel_MouseUp(object? sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            _isDragging = false;
            _graphPanel.Cursor = Cursors.Default;
        }
    }

    private void GraphPanel_MouseWheel(object? sender, MouseEventArgs e)
    {
        int delta = e.Delta > 0 ? -50 : 50;
        _scrollOffset.Y = Math.Clamp(_scrollOffset.Y + delta, 0, Math.Max(0, _contentSize.Height - _graphPanel.Height));
        UpdateScrollbars();
        _graphPanel.Invalidate();
    }

    #endregion

    #region CFG Analysis

    private void AnalyzeFunction()
    {
        if (!ProcessContext.Current.IsAttached)
        {
            _statusLabel.Text = "No process attached";
            return;
        }

        if (!TryParseAddress(_addressBox.Text, out ulong address))
        {
            _statusLabel.Text = "Invalid address format";
            return;
        }

        ClearCFG();

        _statusLabel.Text = $"Analyzing function at 0x{address:X}...";
        _graphPanel.Refresh();

        var result = NexusEngine.Nexus_CFGAnalyze(
            ProcessContext.Current.NativeProcessHandle,
            address,
            0, // Use default max instructions
            out _cfgHandle);

        if (result != NexusResult.OK)
        {
            _statusLabel.Text = $"CFG analysis failed: {result}";
            return;
        }

        // Get result summary
        result = NexusEngine.Nexus_CFGGetResult(_cfgHandle, out _cfgResult);
        if (result != NexusResult.OK)
        {
            _statusLabel.Text = $"Failed to get CFG result: {result}";
            return;
        }

        // Get blocks
        _blocks = new NexusBasicBlock[_cfgResult.BlockCount];
        result = NexusEngine.Nexus_CFGGetBlocks(_cfgHandle, _blocks, _cfgResult.BlockCount, out _);
        if (result != NexusResult.OK)
        {
            _statusLabel.Text = $"Failed to get blocks: {result}";
            return;
        }

        // Get edges
        _edges = new NexusCFGEdge[_cfgResult.EdgeCount];
        result = NexusEngine.Nexus_CFGGetEdges(_cfgHandle, _edges, _cfgResult.EdgeCount, out _);
        if (result != NexusResult.OK)
        {
            _statusLabel.Text = $"Failed to get edges: {result}";
            return;
        }

        // Get instructions for each block
        _blockInstructions.Clear();
        foreach (var block in _blocks)
        {
            var instructions = new NexusDisasmInstruction[block.InstructionCount];
            result = NexusEngine.Nexus_CFGGetBlockInstructions(_cfgHandle, block.BlockIndex, instructions, block.InstructionCount, out var count);
            if (result == NexusResult.OK)
            {
                _blockInstructions[block.BlockIndex] = new List<NexusDisasmInstruction>(instructions.Take((int)count));
            }
        }

        // Calculate layout
        CalculateLayout();

        _statusLabel.Text = $"Analyzed: {_cfgResult.BlockCount} blocks, {_cfgResult.EdgeCount} edges, {_cfgResult.InstructionCount} instructions";
        _graphPanel.Invalidate();
    }

    private void ClearCFG()
    {
        if (_cfgHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_CFGDestroy(_cfgHandle);
            _cfgHandle = IntPtr.Zero;
        }

        _blocks = [];
        _edges = [];
        _blockInstructions.Clear();
        _blockBounds.Clear();
        _selectedBlock = null;
        _hoveredBlock = null;
        _scrollOffset = Point.Empty;
        _graphPanel.Invalidate();
    }

    private static bool TryParseAddress(string text, out ulong address)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out address);
    }

    #endregion

    #region Layout

    private void CalculateLayout()
    {
        _blockBounds.Clear();

        if (_blocks.Length == 0)
        {
            _contentSize = Size.Empty;
            return;
        }

        // Simple hierarchical layout - sort by address and place in rows
        // More sophisticated layouts (Sugiyama algorithm) could be added later

        var sortedBlocks = _blocks.OrderBy(b => b.StartAddress).ToList();
        int x = BlockMargin;
        int y = BlockMargin;
        int rowMaxHeight = 0;
        int maxX = 0;

        using var g = _graphPanel.CreateGraphics();

        foreach (var block in sortedBlocks)
        {
            // Calculate block size
            int instructionCount = (int)block.InstructionCount;
            int blockHeight = BlockHeaderHeight + (instructionCount * InstructionHeight) + (BlockPadding * 2);
            int blockWidth = BlockMinWidth;

            // Measure instruction widths
            if (_blockInstructions.TryGetValue(block.BlockIndex, out var instructions))
            {
                foreach (var inst in instructions)
                {
                    var text = $"  {inst.Address:X8}  {inst.Text}";
                    var size = g.MeasureString(text, _codeFont);
                    blockWidth = Math.Max(blockWidth, (int)size.Width + BlockPadding * 2);
                }
            }

            // Check if we need to start a new row (simple heuristic)
            if (x + blockWidth + BlockMargin > 1200 && x > BlockMargin)
            {
                x = BlockMargin;
                y += rowMaxHeight + BlockMargin;
                rowMaxHeight = 0;
            }

            _blockBounds[block.BlockIndex] = new Rectangle(x, y, blockWidth, blockHeight);

            x += blockWidth + BlockMargin;
            maxX = Math.Max(maxX, x);
            rowMaxHeight = Math.Max(rowMaxHeight, blockHeight);
        }

        _contentSize = new Size(maxX, y + rowMaxHeight + BlockMargin);
        UpdateScrollbars();
    }

    private void UpdateScrollbars()
    {
        if (_contentSize.Width > _graphPanel.Width)
        {
            _hScrollBar.Maximum = _contentSize.Width - _graphPanel.Width + _hScrollBar.LargeChange;
            _hScrollBar.LargeChange = _graphPanel.Width / 4;
            _hScrollBar.Value = Math.Min(_hScrollBar.Value, Math.Max(0, _hScrollBar.Maximum - _hScrollBar.LargeChange));
            _hScrollBar.Visible = true;
        }
        else
        {
            _hScrollBar.Visible = false;
            _scrollOffset.X = 0;
        }

        if (_contentSize.Height > _graphPanel.Height)
        {
            _vScrollBar.Maximum = _contentSize.Height - _graphPanel.Height + _vScrollBar.LargeChange;
            _vScrollBar.LargeChange = _graphPanel.Height / 4;
            _vScrollBar.Value = Math.Min(_vScrollBar.Value, Math.Max(0, _vScrollBar.Maximum - _vScrollBar.LargeChange));
            _vScrollBar.Visible = true;
        }
        else
        {
            _vScrollBar.Visible = false;
            _scrollOffset.Y = 0;
        }
    }

    private void UpdateStatus()
    {
        if (_selectedBlock.HasValue && _selectedBlock.Value < _blocks.Length)
        {
            var block = _blocks[_selectedBlock.Value];
            _statusLabel.Text = $"Block {block.BlockIndex}: 0x{block.StartAddress:X} - 0x{block.EndAddress:X} ({block.InstructionCount} instructions)";
        }
    }

    #endregion

    #region Drawing

    private void DrawBlocks(Graphics g)
    {
        foreach (var block in _blocks)
        {
            if (!_blockBounds.TryGetValue(block.BlockIndex, out var bounds))
                continue;

            // Determine block color
            Color bgColor = _blockBackColor;
            Color borderColor = _blockBorderColor;

            if (block.IsEntry)
                bgColor = _entryBlockColor;
            else if (block.IsExit)
                bgColor = _exitBlockColor;
            else if (block.IsLoopHeader)
                bgColor = _loopHeaderColor;

            if (_selectedBlock == block.BlockIndex)
                borderColor = _blockSelectedColor;
            else if (_hoveredBlock == block.BlockIndex)
                bgColor = _blockHoveredColor;

            // Draw block background
            using (var brush = new SolidBrush(bgColor))
            {
                g.FillRectangle(brush, bounds);
            }

            // Draw border
            using (var pen = new Pen(borderColor, _selectedBlock == block.BlockIndex ? 2 : 1))
            {
                g.DrawRectangle(pen, bounds);
            }

            // Draw header
            using (var brush = new SolidBrush(Color.White))
            {
                string header = $"Block {block.BlockIndex}";
                if (block.IsEntry) header += " [ENTRY]";
                if (block.IsExit) header += " [EXIT]";
                if (block.IsLoopHeader) header += " [LOOP]";
                g.DrawString(header, _headerFont, brush, bounds.X + BlockPadding, bounds.Y + 4);
            }

            // Draw instructions
            if (_blockInstructions.TryGetValue(block.BlockIndex, out var instructions))
            {
                int instY = bounds.Y + BlockHeaderHeight + BlockPadding;

                foreach (var inst in instructions)
                {
                    // Address
                    using (var brush = new SolidBrush(_addressColor))
                    {
                        g.DrawString($"{inst.Address:X8}", _codeFont, brush, bounds.X + BlockPadding, instY);
                    }

                    // Instruction text (colored by type)
                    Color textColor = _mnemonicColor;
                    if (inst.IsCall != 0) textColor = _callColor;
                    else if (inst.IsBranch != 0) textColor = _jumpColor;
                    else if (inst.IsReturn != 0) textColor = _retColor;

                    using (var brush = new SolidBrush(textColor))
                    {
                        g.DrawString(inst.Text, _codeFont, brush, bounds.X + BlockPadding + 80, instY);
                    }

                    instY += InstructionHeight;
                }
            }
        }
    }

    private void DrawEdges(Graphics g)
    {
        using var fallthroughPen = new Pen(_edgeFallthroughColor, 1);
        using var branchPen = new Pen(_edgeBranchColor, 1.5f);
        using var backEdgePen = new Pen(_edgeBackEdgeColor, 2) { DashStyle = System.Drawing.Drawing2D.DashStyle.Dash };

        branchPen.CustomEndCap = new System.Drawing.Drawing2D.AdjustableArrowCap(5, 5);
        fallthroughPen.CustomEndCap = new System.Drawing.Drawing2D.AdjustableArrowCap(4, 4);
        backEdgePen.CustomEndCap = new System.Drawing.Drawing2D.AdjustableArrowCap(6, 6);

        foreach (var edge in _edges)
        {
            if (!_blockBounds.TryGetValue(edge.SourceBlock, out var sourceBounds) ||
                !_blockBounds.TryGetValue(edge.TargetBlock, out var targetBounds))
                continue;

            // Calculate connection points
            Point start, end;

            if (edge.IsBackEdge)
            {
                // Back edge - draw on the left side
                start = new Point(sourceBounds.Left, sourceBounds.Top + sourceBounds.Height / 2);
                end = new Point(targetBounds.Left, targetBounds.Top + targetBounds.Height / 2);

                // Draw curved back edge
                int curveOffset = -30;
                var points = new PointF[]
                {
                    start,
                    new PointF(start.X + curveOffset, start.Y),
                    new PointF(end.X + curveOffset, end.Y),
                    end
                };
                g.DrawBeziers(backEdgePen, points);
            }
            else
            {
                // Normal edges - draw from bottom to top
                start = new Point(sourceBounds.Left + sourceBounds.Width / 2, sourceBounds.Bottom);
                end = new Point(targetBounds.Left + targetBounds.Width / 2, targetBounds.Top);

                Pen pen = edge.IsFallthrough ? fallthroughPen : branchPen;

                // Draw a simple line or bezier curve
                if (Math.Abs(start.X - end.X) < 20)
                {
                    g.DrawLine(pen, start, end);
                }
                else
                {
                    int midY = (start.Y + end.Y) / 2;
                    var points = new PointF[]
                    {
                        start,
                        new PointF(start.X, midY),
                        new PointF(end.X, midY),
                        end
                    };
                    g.DrawBeziers(pen, points);
                }
            }
        }
    }

    #endregion

    #region Cleanup

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ClearCFG();
            _codeFont.Dispose();
            _headerFont.Dispose();
        }
        base.Dispose(disposing);
    }

    #endregion
}
