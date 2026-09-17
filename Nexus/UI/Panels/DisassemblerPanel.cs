// <file>
// <summary>
// Integrated disassembler and debugger panel embedded in the shell's Debugger tab.
// Provides x64dbg-style disassembly view with instruction-level debugging, software
// breakpoints, single-step/step-over/step-out, inline assembly patching, NOP filling,
// undo stack, cross-reference navigation, and syntax-highlighted instruction rendering.
// Coordinates with DebuggerLayoutPanel and companion panels (Registers, Stack, Hex Dump).
// </summary>
// </file>

using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Disassembler panel providing an x64dbg-style interactive debugger view.
/// <para>
/// Renders disassembled instructions with syntax highlighting (calls in teal, jumps in green,
/// returns in orange, bytes in gray). Supports software breakpoints (F2), continue (F5),
/// step into (F7), step over (F8), step out (Shift+F8), inline assembly (Enter on selection),
/// NOP fill, and a full undo stack for byte modifications.
/// </para>
/// <para>
/// The debug thread runs on a background thread and communicates state changes back to the
/// UI thread via Invoke. Breakpoints are tracked in a concurrent dictionary keyed by address.
/// </para>
/// </summary>
public partial class DisassemblerPanel : ShellPanel
{
    #region Fields

    // Process state
    private IntPtr _processHandle;
    private int _processId;
    private bool _is64Bit = true;

    // View addresses
    private ulong _disasmAddress;      // Disasm view start address

    // Memory buffers
    private byte[] _disasmBuffer = new byte[512];
    private bool _disasmReadSuccess = true;

    // Selection state
    private ulong _disasmSelectedAddress;
    private ulong _disasmSelectionEnd;
    private ulong _disasmSelectionAnchor;

    // Cached disassembly
    private NexusDisasmInstruction[] _cachedDisasm = new NexusDisasmInstruction[64];
    private int _cachedDisasmCount;
    private int _disasmLineHeight;

    // Undo stack for assembly/NOP operations
    private readonly Stack<UndoEntry> _undoStack = new();
    private record UndoEntry(ulong Address, byte[] OriginalBytes, string Description);

    // Events
    /// <summary>Event fired when debugger pauses (breakpoint hit, single step complete).</summary>
    public event EventHandler<uint>? OnDebugPaused;

    // Breakpoint tracking
    private readonly ConcurrentDictionary<ulong, ulong> _breakpoints = new(); // Address -> BreakpointId
    private readonly ConcurrentQueue<ulong> _pendingAddBp = new();
    private readonly ConcurrentQueue<ulong> _pendingRemoveBp = new();
    private IntPtr _debuggerHandle = IntPtr.Zero;
    private Thread? _debugThread;
    private volatile bool _debugging;
    private volatile bool _isPaused;
    private volatile bool _debugReady;
    private ulong _pausedAtAddress;
    private volatile bool _steppingOverBp;
    private ulong _stepOverBpAddress;
    private ulong _stepOverBpId;
    private volatile bool _singleStepMode;
    private volatile int _continueAction;

    // Fonts
    private readonly Font _disasmFont = new("Consolas", 9f);

    // Colors
    private readonly Color _viewBackColor = Color.FromArgb(30, 30, 30);
    private readonly Color _addressColor = Color.FromArgb(86, 156, 214);
    private readonly Color _hexColor = Color.FromArgb(220, 220, 220);
    private readonly Color _selectionBackColor = Color.FromArgb(51, 153, 255);
    private readonly Color _selectionForeColor = Color.White;
    private readonly Color _breakpointBackColor = Color.FromArgb(100, 40, 40);
    private readonly Color _breakpointMarkerColor = Color.Red;
    private readonly Color _callColor = Color.FromArgb(78, 201, 176);
    private readonly Color _jumpColor = Color.FromArgb(184, 215, 163);
    private readonly Color _retColor = Color.FromArgb(214, 157, 133);
    private readonly Color _bytesColor = Color.FromArgb(128, 128, 128);  // Gray for instruction bytes

    // UI Controls
    private readonly SplitContainer _mainSplit;
    private readonly DoubleBufferedPanel _disasmPanel;
    private readonly InfoPanel _infoPanel;
    private readonly VScrollBar _disasmScrollBar;
    private TextBox _addressBox = null!;
    private Button _gotoBtn = null!;
    private ComboBox _displayTypeCombo = null!;
    private CheckBox _autoRefreshCheck = null!;
    private readonly System.Windows.Forms.Timer _refreshTimer;

    // Context menus
    private readonly ContextMenuStrip _disasmContextMenu;

    #endregion

    #region Constructor

    public DisassemblerPanel()
    {
        Text = "Disassembler";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Create toolbar
        var toolbar = CreateToolbar();

        // Create main split container (disasm top, hex bottom)
        _mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 100,
            Panel2MinSize = 25
        };

        // Disasm panel (top)
        _disasmScrollBar = new VScrollBar
        {
            Dock = DockStyle.Right,
            Minimum = 0,
            Maximum = 1000,
            Value = 500,
            LargeChange = 50,
            SmallChange = 10
        };
        _disasmScrollBar.Scroll += DisasmScrollBar_Scroll;

        _disasmPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = _viewBackColor
        };
        _disasmPanel.Paint += DisasmPanel_Paint;
        _disasmPanel.MouseWheel += DisasmPanel_MouseWheel;
        _disasmPanel.MouseDown += DisasmPanel_MouseDown;
        _disasmPanel.MouseDoubleClick += DisasmPanel_MouseDoubleClick;
        _disasmPanel.KeyDown += DisasmPanel_KeyDown;

        _disasmContextMenu = CreateDisasmContextMenu();
        _disasmPanel.ContextMenuStrip = _disasmContextMenu;

        _mainSplit.Panel1.Controls.Add(_disasmPanel);
        _mainSplit.Panel1.Controls.Add(_disasmScrollBar);

        // Info panel (bottom) - shows reference info like x64dbg
        _infoPanel = new InfoPanel
        {
            Dock = DockStyle.Fill
        };
        _mainSplit.Panel2.Controls.Add(_infoPanel);

        // Add controls in correct order
        Controls.Add(_mainSplit);
        Controls.Add(toolbar);

        // Refresh timer
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _refreshTimer.Tick += RefreshTimer_Tick;

        // Set splitter distance after load - info panel is small (like x64dbg reference bar)
        Load += (s, e) => BeginInvoke(() =>
        {
            if (_mainSplit.Height > 50)
                _mainSplit.SplitterDistance = _mainSplit.Height - 75; // Info panel gets ~75px
        });

        // Subscribe to process events
        SubscribeEvent<NavigateToAddressEvent>(OnNavigateToAddress);

        ShowPlaceholder();
    }

    #endregion

    #region UI Creation

    private Panel CreateToolbar()
    {
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 34,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = new Padding(4, 4, 0, 0)
        };

        var addrLabel = new Label
        {
            Text = "Address:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, 6, 4, 0)
        };

        _addressBox = new TextBox
        {
            Width = 150,
            Font = NexusTheme.FontMono,
            Text = "0"
        };
        _addressBox.KeyDown += AddressBox_KeyDown;
        NexusTheme.StyleTextBox(_addressBox);

        _gotoBtn = new Button { Text = "Go", Width = 50 };
        NexusTheme.StylePrimaryButton(_gotoBtn);
        _gotoBtn.Click += GotoBtn_Click;

        var separator1 = new Label { Text = "|", AutoSize = true, ForeColor = NexusTheme.TextSecondary, Margin = new Padding(8, 6, 8, 0) };

        var typeLabel = new Label
        {
            Text = "Display:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, 6, 4, 0)
        };

        _displayTypeCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 80
        };
        _displayTypeCombo.Items.AddRange(["Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"]);
        _displayTypeCombo.SelectedIndex = 0;
        NexusTheme.StyleComboBox(_displayTypeCombo);

        var separator2 = new Label { Text = "|", AutoSize = true, ForeColor = NexusTheme.TextSecondary, Margin = new Padding(8, 6, 8, 0) };

        _autoRefreshCheck = new CheckBox
        {
            Text = "Auto Refresh",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(0, 4, 0, 0)
        };
        _autoRefreshCheck.CheckedChanged += AutoRefreshCheck_CheckedChanged;

        toolbar.Controls.AddRange([addrLabel, _addressBox, _gotoBtn, separator1, typeLabel, _displayTypeCombo, separator2, _autoRefreshCheck]);

        return toolbar;
    }

    private ContextMenuStrip CreateDisasmContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.AddRange([
            new ToolStripMenuItem("&Undo last change", null, (s, e) => UndoLastChange()) { ShortcutKeys = Keys.Control | Keys.Z },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Go to address...", null, (s, e) => ShowGoToDialog(false)) { ShortcutKeys = Keys.Control | Keys.G },
            new ToolStripMenuItem("&Find bytes...", null, (s, e) => ShowFindBytesDialog()) { ShortcutKeys = Keys.Control | Keys.F },
            new ToolStripMenuItem("Follow", null, (s, e) => FollowSelectedAddress()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Replace with NOP", null, (s, e) => ReplaceWithNop()),
            new ToolStripMenuItem("Assemble...", null, (s, e) => ShowAssembleDialog()),
            new ToolStripMenuItem("Fill memory...", null, (s, e) => ShowFillMemoryDialog()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Toggle &breakpoint", null, (s, e) => ToggleBreakpoint()) { ShortcutKeys = Keys.F2 },
            new ToolStripMenuItem("Find what accesses this address", null, (s, e) => FindWhatAccesses()),
            new ToolStripMenuItem("Find what writes to this address", null, (s, e) => FindWhatWrites()),
            new ToolStripMenuItem("Show &symbol info", null, (s, e) => ShowSymbolInfo()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Open in dissect data...", null, (s, e) => OpenInDissectData(false)),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Copy &address", null, (s, e) => CopyDisasmAddress()),
            new ToolStripMenuItem("Copy &bytes", null, (s, e) => CopyDisasmBytes()),
            new ToolStripMenuItem("Copy &disassembly", null, (s, e) => CopyDisassembly())
        ]);
        return menu;
    }


    #endregion

    #region Panel Overrides

    public override string PanelId => "Disassembler";
    public override string PanelDisplayName => "Disassembler";

    public override ToolStripMenuItem[]? GetPanelMenus()
    {
        // Disassembly menu
        var disasmMenu = new ToolStripMenuItem("&Disassembly");
        disasmMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Go to address...", null, (s, e) => ShowGoToDialog(false)) { ShortcutKeys = Keys.Control | Keys.G },
            new ToolStripMenuItem("&Find bytes...", null, (s, e) => ShowFindBytesDialog()) { ShortcutKeys = Keys.Control | Keys.F },
            new ToolStripMenuItem("&Follow", null, (s, e) => FollowSelectedAddress()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Assemble...", null, (s, e) => ShowAssembleDialog()),
            new ToolStripMenuItem("Auto &Assemble...", null, (s, e) => ShowAutoAssembleDialog()),
            new ToolStripMenuItem("Replace with &NOP", null, (s, e) => ReplaceWithNop()),
            new ToolStripMenuItem("Fill &memory...", null, (s, e) => ShowFillMemoryDialog()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Undo last change", null, (s, e) => UndoLastChange()) { ShortcutKeys = Keys.Control | Keys.Z },
            new ToolStripSeparator(),
            new ToolStripMenuItem("Toggle &breakpoint", null, (s, e) => ToggleBreakpoint()) { ShortcutKeys = Keys.F2 },
            new ToolStripMenuItem("Find what &accesses this address", null, (s, e) => FindWhatAccesses()),
            new ToolStripMenuItem("Find what &writes to this address", null, (s, e) => FindWhatWrites()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Show &symbol info", null, (s, e) => ShowSymbolInfo())
        ]);

        // Memory menu
        var memoryMenu = new ToolStripMenuItem("&Memory");
        memoryMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Fill memory...", null, (s, e) => ShowFillMemoryDialog()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Dump memory...", null, (s, e) => ShowDumpMemoryDialog()),
            new ToolStripMenuItem("&Allocate memory...", null, (s, e) => ShowAllocateMemoryDialog()),
            new ToolStripMenuItem("Change &protection...", null, (s, e) => ShowProtectionDialog())
        ]);

        return [disasmMenu, memoryMenu];
    }

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnProcessAttached(sender, e));
            return;
        }

        _processHandle = e.ProcessHandle;
        _processId = e.ProcessId;
        _is64Bit = e.Is64Bit;

        // Wire up info panel
        _infoPanel.SetProcessHandle(_processHandle);

        // Navigate to entry point
        InitializeForProcess();

        // Update info panel with initial address
        _infoPanel.SetCurrentAddress(_disasmAddress);

        if (_autoRefreshCheck.Checked)
            _refreshTimer.Start();
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnProcessDetached(sender, e));
            return;
        }

        _refreshTimer.Stop();
        DetachDebugger();

        _processHandle = IntPtr.Zero;
        _processId = 0;
        _cachedDisasmCount = 0;
        _breakpoints.Clear();

        ShowPlaceholder();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            DetachDebugger();
            _disasmFont.Dispose();
        }
        base.Dispose(disposing);
    }

    #endregion

    #region Initialization

    private void InitializeForProcess()
    {
        if (_processHandle == IntPtr.Zero) return;

        // Get main module base and entry point
        var modules = new NexusModuleInfo[256];
        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 256, out var count);

        ulong baseAddr = 0x00400000;
        if (result == NexusResult.OK && count > 0)
        {
            baseAddr = modules[0].BaseAddress;
            for (int i = 0; i < (int)count; i++)
            {
                if (modules[i].Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    baseAddr = modules[i].BaseAddress;
                    break;
                }
            }
        }

        // Get entry point for disasm view
        ulong entryPoint = GetModuleEntryPoint(baseAddr);
        _disasmAddress = entryPoint > 0 ? entryPoint : baseAddr;
        _disasmSelectedAddress = _disasmAddress;
        _disasmSelectionEnd = _disasmAddress + 1;
        _disasmSelectionAnchor = _disasmAddress;

        _addressBox.Text = $"{_disasmAddress:X}";

        RefreshViews();
    }

    private ulong GetModuleEntryPoint(ulong moduleBase)
    {
        if (_processHandle == IntPtr.Zero) return 0;

        try
        {
            var buffer = new byte[64];
            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    var result = NexusEngine.Nexus_ReadMemory(_processHandle, moduleBase, (IntPtr)ptr, 64, out var bytesRead);
                    if (result != NexusResult.OK || bytesRead < 64) return 0;
                }
            }

            // Check DOS signature
            if (buffer[0] != 'M' || buffer[1] != 'Z') return 0;

            uint peOffset = BitConverter.ToUInt32(buffer, 0x3C);

            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    var result = NexusEngine.Nexus_ReadMemory(_processHandle, moduleBase + peOffset, (IntPtr)ptr, 64, out var bytesRead);
                    if (result != NexusResult.OK || bytesRead < 64) return 0;
                }
            }

            // Check PE signature
            if (buffer[0] != 'P' || buffer[1] != 'E' || buffer[2] != 0 || buffer[3] != 0) return 0;

            uint entryPointRVA = BitConverter.ToUInt32(buffer, 40);
            return moduleBase + entryPointRVA;
        }
        catch
        {
            return 0;
        }
    }

    private void ShowPlaceholder()
    {
        _cachedDisasmCount = 0;
        _disasmReadSuccess = false;
        _disasmPanel.Invalidate();
    }

    #endregion

    #region Memory Operations

    private void RefreshViews()
    {
        RefreshDisasmView();
    }

    private void RefreshDisasmView()
    {
        if (_processHandle == IntPtr.Zero)
        {
            _disasmReadSuccess = false;
            _disasmPanel.Invalidate();
            return;
        }

        // Read memory for fallback display
        if (_disasmBuffer.Length < 512)
            _disasmBuffer = new byte[512];

        unsafe
        {
            fixed (byte* ptr = _disasmBuffer)
            {
                var result = NexusEngine.Nexus_ReadMemory(_processHandle, _disasmAddress, (IntPtr)ptr, 512, out var bytesRead);
                _disasmReadSuccess = (result == NexusResult.OK || result == NexusResult.Success) && bytesRead > 0;
            }
        }

        _disasmPanel.Invalidate();
    }


    #endregion

    #region Helper Methods

    private void ShowGoToDialog(bool _)
    {
        using var dialog = new Form
        {
            Text = "Go to Address",
            Size = new Size(300, 130),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var textBox = new TextBox
        {
            Location = new Point(10, 15),
            Size = new Size(265, 23),
            Text = $"{_disasmSelectedAddress:X}"
        };
        NexusTheme.StyleTextBox(textBox);

        var okButton = new Button
        {
            Text = "OK",
            Location = new Point(105, 50),
            Size = new Size(80, 28),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(okButton);

        dialog.Controls.AddRange([textBox, okButton]);
        dialog.AcceptButton = okButton;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var hexText = textBox.Text.Trim();
            if (hexText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hexText = hexText[2..];
            if (ulong.TryParse(hexText,
                System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                GoToAddressDisasm(address);
            }
        }
    }

    private void FollowSelectedAddress()
    {
        ulong address = _disasmSelectedAddress;
        if (address == 0 || _processHandle == IntPtr.Zero) return;

        var buffer = new byte[8];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, address, buffer, 8, out nuint bytesRead);

        if ((result != NexusResult.OK && result != NexusResult.Success) || bytesRead < 8)
        {
            MessageBox.Show($"Failed to read pointer at 0x{address:X}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ulong pointerValue = BitConverter.ToUInt64(buffer, 0);

        if (pointerValue == 0)
        {
            MessageBox.Show("Pointer value is NULL (0)", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        GoToAddress(pointerValue);
    }

    private void FindWhatAccesses()
    {
        ulong address = _disasmSelectedAddress;
        if (address == 0) address = _disasmAddress;

        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var form = new FoundCodeForm(_processHandle, address, NexusBreakpointType.HardwareRW, _processId);
        form.Show(this);
    }

    private void FindWhatWrites()
    {
        ulong address = _disasmSelectedAddress;
        if (address == 0) address = _disasmAddress;

        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var form = new FoundCodeForm(_processHandle, address, NexusBreakpointType.HardwareWrite, _processId);
        form.Show(this);
    }

    private void CopyDisasmAddress()
    {
        if (_disasmSelectedAddress != 0)
            Clipboard.SetText($"{_disasmSelectedAddress:X}");
    }

    private void CopyDisasmBytes()
    {
        if (_processHandle == IntPtr.Zero || _disasmSelectedAddress == 0) return;

        int length = (int)(_disasmSelectionEnd - _disasmSelectedAddress);
        if (length <= 0 || length > 0x1000) return;

        var bytes = new byte[length];
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, _disasmSelectedAddress, (IntPtr)ptr, (nuint)length, out _);
            }
        }

        Clipboard.SetText(BitConverter.ToString(bytes).Replace("-", " "));
    }

    private void CopyDisassembly()
    {
        if (_cachedDisasmCount == 0 || _disasmSelectedAddress == 0) return;

        var lines = new List<string>();
        for (int i = 0; i < _cachedDisasmCount; i++)
        {
            var insn = _cachedDisasm[i];
            if (insn.Address >= _disasmSelectedAddress && insn.Address < _disasmSelectionEnd)
            {
                string instrText = !string.IsNullOrEmpty(insn.Text) ? insn.Text : insn.Mnemonic;
                lines.Add($"{insn.Address:X16}  {instrText}");
            }
        }

        if (lines.Count > 0)
            Clipboard.SetText(string.Join(Environment.NewLine, lines));
    }


    private void UpdateLocalStatus(string message, StatusType type = StatusType.Info)
    {
        // Publish to shell status bar instead of local status label
        EventBus.Instance.Publish(new StatusUpdateEvent(message, type));
    }

    #endregion
}

/// <summary>
/// Panel with double buffering enabled for flicker-free rendering.
/// </summary>
internal class DoubleBufferedPanel : Panel
{
    public DoubleBufferedPanel()
    {
        SetStyle(ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.UserPaint |
                 ControlStyles.Selectable, true);
        UpdateStyles();
    }
}
