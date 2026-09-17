// <file>
// <summary>
// Standalone memory viewer form with dual-pane hex dump and disassembly display.
// Provides interactive hex editing, x86/x64 disassembly, inline assembly patching,
// breakpoint management, integrated debugging (continue/step/step-over/step-out),
// dump file loading, copy/paste operations, and undo support for byte modifications.
// This form can operate on live process memory or loaded binary dump files.
// </summary>
// </file>

using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Memory viewer form with side-by-side hex dump and disassembly views.
/// <para>
/// Features include:
/// <list type="bullet">
///   <item>Hex view with address column, hex bytes, and ASCII representation</item>
///   <item>Disassembly view with x86/x64 instruction decoding via the Nexus engine</item>
///   <item>Inline assembly: select an instruction and type new assembly to patch it</item>
///   <item>Breakpoint toggle (F2), with visual markers in the disassembly gutter</item>
///   <item>Integrated debugger: Continue (F5), Step Into (F7), Step Over (F8), Step Out (Shift+F8)</item>
///   <item>Undo stack for all assembly and NOP operations (Ctrl+Z)</item>
///   <item>Dump file mode for offline analysis of binary files</item>
///   <item>Selection-aware context menus for copy, paste, fill, goto, and data inspection</item>
/// </list>
/// </para>
/// </summary>
public partial class MemoryViewerForm : Form
{
    private IntPtr _processHandle;
    private int _processId;
    private ulong _baseAddress;           // Disasm view address (independent)
    private ulong _scrollAddress;         // Hex view address (independent)
    private byte[] _memoryBuffer = new byte[4096];        // Hex view buffer
    private byte[] _disasmMemoryBuffer = new byte[512];   // Disasm view buffer (for fallback)
    private int _bytesPerRow = 16;
    private int _rowCount = 32;
    private bool _hexReadSuccess = true;    // Track if last hex memory read succeeded
    private bool _disasmReadSuccess = true; // Track if last disasm memory read succeeded

    // Separate selections for each view
    private ulong _hexSelectedAddress;
    private int _hexSelectionLength = 1;
    private ulong _disasmSelectedAddress;
    private ulong _disasmSelectionEnd;        // For range selection
    private ulong _disasmSelectionAnchor;     // Anchor point for shift+click
    private int _disasmSelectionLength = 1;
    private bool _lastActiveViewIsHex = true;  // Track which view was last clicked

    // Undo stack for assembly/NOP operations
    private readonly Stack<UndoEntry> _undoStack = new();
    private record UndoEntry(ulong Address, byte[] OriginalBytes, string Description);

    // Convenience property for "current" selection (from last active view)
    private ulong _selectedAddress => _lastActiveViewIsHex ? _hexSelectedAddress : _disasmSelectedAddress;
    private int _selectionLength => _lastActiveViewIsHex ? _hexSelectionLength : _disasmSelectionLength;

    private readonly Font _hexFont = new("Consolas", 10f);
    private readonly Font _disasmFont = new("Consolas", 9f);

    // Scrollbar constants
    private const int ScrollPageSize = 16; // Rows to scroll per page
    private const int ScrollLineSize = 1;  // Rows to scroll per line

    // Cached disassembly for click detection
    private NexusDisasmInstruction[] _cachedDisasm = [];
    private int _cachedDisasmCount;
    private int _disasmLineHeight;

    // Colors matching CE
    private readonly Color _backgroundColor = Color.White;
    private readonly Color _addressColor = Color.FromArgb(0, 0, 128);
    private readonly Color _hexColor = Color.Black;
    private readonly Color _asciiColor = Color.FromArgb(128, 0, 0);
    private readonly Color _selectionBackColor = Color.FromArgb(51, 153, 255);
    private readonly Color _selectionForeColor = Color.White;
    private readonly Color _modifiedColor = Color.Red;

    // Breakpoint tracking
    private readonly Dictionary<ulong, ulong> _breakpoints = []; // Address -> BreakpointId
    private readonly System.Collections.Concurrent.ConcurrentQueue<ulong> _pendingAddBp = new();
    private readonly System.Collections.Concurrent.ConcurrentQueue<ulong> _pendingRemoveBp = new();
    private IntPtr _debuggerHandle = IntPtr.Zero;
    private Thread? _debugThread;
    private volatile bool _debugging;
    private volatile bool _isPaused;
    private volatile bool _debugReady;  // True when debug thread has finished init
    private ulong _pausedAtAddress;  // Access via UI thread Invoke
    private readonly Color _breakpointBackColor = Color.FromArgb(255, 200, 200);
    private readonly Color _breakpointMarkerColor = Color.Red;

    // Step-over-breakpoint state
    private volatile bool _steppingOverBp;      // True when stepping over a breakpoint
    private ulong _stepOverBpAddress;           // Address of breakpoint we're stepping over
    private ulong _stepOverBpId;                // ID of breakpoint we're stepping over
    private volatile bool _singleStepMode;      // True when user wants to single-step
    private volatile int _continueAction;       // 0=none, 1=continue, 2=step, 3=remove bp, 4=step over, 5=step out

    // Step-out state
    private ulong _stepOutBreakpointAddress;    // Return address where step-out breakpoint is set
    private ulong _stepOutBreakpointId;         // ID of the step-out breakpoint

    // Dump file mode
    private byte[]? _dumpFileData;              // Loaded dump file data (null = live memory)
    private ulong _dumpFileBaseAddress;         // Base address for dump file display
    private string? _dumpFileName;              // Name of loaded dump file

    public MemoryViewerForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupDefaultState();
    }

    public MemoryViewerForm(IntPtr processHandle, ulong address, int processId = 0) : this()
    {
        _processHandle = processHandle;
        _processId = processId;
        GoToAddress(address);
    }

    private void SetupDefaultState()
    {
        UpdateTitle();
        pnlHexView.Paint += PnlHexView_Paint;
        pnlHexView.MouseWheel += PnlHexView_MouseWheel;
        pnlHexView.MouseDown += PnlHexView_MouseDown;
        pnlHexView.MouseDoubleClick += PnlHexView_MouseDoubleClick;
        pnlHexView.KeyDown += PnlHexView_KeyDown;

        pnlDisasm.Paint += PnlDisasm_Paint;
        pnlDisasm.MouseWheel += PnlDisasm_MouseWheel;
        pnlDisasm.MouseDown += PnlDisasm_MouseDown;
        pnlDisasm.MouseDoubleClick += PnlDisasm_MouseDoubleClick;
        pnlDisasm.KeyDown += PnlDisasm_KeyDown;
    }

    #region Public Methods

    public void SetProcess(IntPtr processHandle, int processId = 0)
    {
        _processHandle = processHandle;
        _processId = processId;
        UpdateTitle();

        if (_processHandle != IntPtr.Zero)
        {
            // Get the main module's base address to display
            var modules = new NexusModuleInfo[256];
            var result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 256, out var count);
            if (result == NexusResult.OK && count > 0)
            {
                // Find the main executable module (usually first, but verify by name)
                ulong baseAddr = modules[0].BaseAddress;

                // Try to find .exe module specifically
                for (int i = 0; i < (int)count; i++)
                {
                    if (modules[i].Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        baseAddr = modules[i].BaseAddress;
                        break;
                    }
                }

                // Like CE: Hex view at module base, disasm at entry point
                ulong entryPoint = GetModuleEntryPoint(baseAddr);

                // Set disasm to entry point (code)
                _baseAddress = entryPoint > 0 ? entryPoint : baseAddr;
                _disasmSelectedAddress = _baseAddress;
                _disasmSelectionEnd = _baseAddress + 1;
                _disasmSelectionAnchor = _baseAddress;

                // Set hex view to module base (data/headers)
                _scrollAddress = baseAddr;
                _hexSelectedAddress = baseAddr;

                txtAddress.Text = $"{_baseAddress:X}";
                lblSelectedAddress.Text = $"Selected: 0x{_disasmSelectedAddress:X}";
            }
            else
            {
                // If we can't get modules, try to find a readable memory region
                var regions = new NexusMemoryRegion[1];
                result = NexusEngine.Nexus_EnumerateMemoryRegions(_processHandle, regions, 1, out var regionCount);
                if (result == NexusResult.OK && regionCount > 0)
                {
                    _baseAddress = regions[0].BaseAddress;
                    _scrollAddress = regions[0].BaseAddress;
                    _hexSelectedAddress = _baseAddress;
                    _disasmSelectedAddress = _baseAddress;
                    _disasmSelectionEnd = _baseAddress + 1;
                    _disasmSelectionAnchor = _baseAddress;
                }
                else
                {
                    _baseAddress = 0x00400000;
                    _scrollAddress = 0x00400000;
                    _hexSelectedAddress = _baseAddress;
                    _disasmSelectedAddress = _baseAddress;
                    _disasmSelectionEnd = _baseAddress + 1;
                    _disasmSelectionAnchor = _baseAddress;
                }
                txtAddress.Text = $"{_baseAddress:X}";
                lblSelectedAddress.Text = $"Selected: 0x{_disasmSelectedAddress:X}";
            }
        }

        // Refresh both views
        RefreshMemory();
    }

    /// <summary>
    /// Reads the PE header to find the entry point address.
    /// Like CE, we want to open to actual code, not the PE header.
    /// </summary>
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
                    // Read DOS header
                    var result = NexusEngine.Nexus_ReadMemory(
                        _processHandle, moduleBase, (IntPtr)ptr, 64, out var bytesRead);
                    if (result != NexusResult.OK || bytesRead < 64) return 0;
                }
            }

            // Check DOS signature "MZ"
            if (buffer[0] != 'M' || buffer[1] != 'Z') return 0;

            // Get offset to PE header (e_lfanew at offset 0x3C)
            uint peOffset = BitConverter.ToUInt32(buffer, 0x3C);

            // Read PE header
            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    var result = NexusEngine.Nexus_ReadMemory(
                        _processHandle, moduleBase + peOffset, (IntPtr)ptr, 64, out var bytesRead);
                    if (result != NexusResult.OK || bytesRead < 64) return 0;
                }
            }

            // Check PE signature "PE\0\0"
            if (buffer[0] != 'P' || buffer[1] != 'E' || buffer[2] != 0 || buffer[3] != 0) return 0;

            // AddressOfEntryPoint is at PE + 4 (sig) + 20 (COFF header) + 16 (offset in optional header)
            // = PE + 40
            uint entryPointRVA = BitConverter.ToUInt32(buffer, 40);

            return moduleBase + entryPointRVA;
        }
        catch
        {
            return 0;
        }
    }

    public void GoToAddress(ulong address, bool centerInView = true)
    {
        // Update both views (used for initial load and toolbar)
        GoToAddressHex(address);
        GoToAddressDisasm(address);
    }

    private void GoToAddressHex(ulong address)
    {
        _hexSelectedAddress = address;
        // Position address at first byte of view
        _scrollAddress = address;
        RefreshHexMemory();
        lblSelectedAddress.Text = $"Selected: 0x{address:X}";
    }

    private void GoToAddressDisasm(ulong address)
    {
        _disasmSelectedAddress = address;
        _disasmSelectionEnd = address + 1;
        _disasmSelectionAnchor = address;
        _baseAddress = address;
        RefreshDisasmMemory();
        txtAddress.Text = $"{address:X}";
        lblSelectedAddress.Text = $"Selected: 0x{address:X}";
    }

    #endregion

    // Hex view, disassembly, editing, and navigation methods are in partial class files:
    // - MemoryViewerForm.HexView.cs
    // - MemoryViewerForm.Search.cs
    // - MemoryViewerForm.Edit.cs
    // - MemoryViewerForm.Navigation.cs
}

partial class MemoryViewerForm
{
    private System.ComponentModel.IContainer? components = null;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hexFont.Dispose();
            _disasmFont.Dispose();
            components?.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        this.components = new System.ComponentModel.Container();

        this.menuStrip = new MenuStrip();
        this.fileMenu = new ToolStripMenuItem();
        this.viewMenu = new ToolStripMenuItem();
        this.searchMenu = new ToolStripMenuItem();
        this.debugMenu = new ToolStripMenuItem();
        this.toolsMenu = new ToolStripMenuItem();

        this.toolStrip = new ToolStrip();
        this.lblAddress = new ToolStripLabel();
        this.txtAddress = new ToolStripTextBox();
        this.btnGo = new ToolStripButton();
        this.toolStripSeparator1 = new ToolStripSeparator();
        this.cboDisplayType = new ToolStripComboBox();
        this.chkAutoRefresh = new ToolStripButton();

        this.splitContainer = new SplitContainer();

        this.statusStrip = new StatusStrip();
        this.lblStatus = new ToolStripStatusLabel();
        this.lblSelectedAddress = new ToolStripStatusLabel();

        this.refreshTimer = new System.Windows.Forms.Timer(this.components);

        ((System.ComponentModel.ISupportInitialize)this.splitContainer).BeginInit();
        this.splitContainer.Panel1.SuspendLayout();
        this.splitContainer.Panel2.SuspendLayout();
        this.splitContainer.SuspendLayout();
        this.menuStrip.SuspendLayout();
        this.toolStrip.SuspendLayout();
        this.statusStrip.SuspendLayout();
        this.SuspendLayout();

        //
        // menuStrip
        //
        this.menuStrip.Items.AddRange(new ToolStripItem[] {
            this.fileMenu,
            this.viewMenu,
            this.searchMenu,
            this.debugMenu,
            this.toolsMenu
        });
        this.menuStrip.Location = new Point(0, 0);
        this.menuStrip.Name = "menuStrip";
        this.menuStrip.Size = new Size(900, 24);

        //
        // fileMenu
        //
        this.fileMenu.Name = "fileMenu";
        this.fileMenu.Text = "&File";
        this.fileMenu.DropDownItems.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("&Open dump...", null, (s, e) => OpenDump()),
            new ToolStripMenuItem("&Save dump...", null, new EventHandler(this.MnuDump_Click!)),
            new ToolStripSeparator(),
            new ToolStripMenuItem("E&xit", null, (s, e) => Close())
        });

        //
        // viewMenu
        //
        this.viewMenu.Name = "viewMenu";
        this.viewMenu.Text = "&View";
        this.mnuHexView = new ToolStripMenuItem("&Hex View", null, MnuHexView_Click) { Checked = true, CheckOnClick = true };
        this.mnuDisasmView = new ToolStripMenuItem("&Disassembly", null, MnuDisasmView_Click) { Checked = true, CheckOnClick = true };
        this.viewMenu.DropDownItems.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("&Go to address...", null, (s, e) => ShowGoToDialog()) { ShortcutKeys = Keys.Control | Keys.G },
            new ToolStripSeparator(),
            this.mnuHexView,
            this.mnuDisasmView,
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Refresh", null, (s, e) => RefreshMemory()) { ShortcutKeys = Keys.F5 }
        });

        //
        // searchMenu
        //
        this.searchMenu.Name = "searchMenu";
        this.searchMenu.Text = "&Search";
        this.searchMenu.DropDownItems.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("&Find bytes...", null, new EventHandler(this.MnuFindBytes_Click!)) { ShortcutKeys = Keys.Control | Keys.F },
            new ToolStripMenuItem("Find &next", null, (s, e) => { }) { ShortcutKeys = Keys.F3 },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Copy", null, new EventHandler(this.MnuCopy_Click!)) { ShortcutKeys = Keys.Control | Keys.C },
            new ToolStripMenuItem("&Paste", null, new EventHandler(this.MnuPaste_Click!)) { ShortcutKeys = Keys.Control | Keys.V },
            new ToolStripMenuItem("&Fill...", null, new EventHandler(this.MnuFillBytes_Click!))
        });

        //
        // debugMenu
        //
        this.debugMenu.Name = "debugMenu";
        this.debugMenu.Text = "&Debug";
        this.debugMenu.DropDownItems.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("Toggle &breakpoint", null, new EventHandler(this.MnuSetBreakpoint_Click!)) { ShortcutKeys = Keys.F2 },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Step into", null, (s, e) => { }) { ShortcutKeys = Keys.F7 },
            new ToolStripMenuItem("Step &over", null, (s, e) => { }) { ShortcutKeys = Keys.F8 },
            new ToolStripMenuItem("Step o&ut", null, (s, e) => { }) { ShortcutKeys = Keys.Control | Keys.F8 }
        });

        //
        // toolsMenu
        //
        this.toolsMenu.Name = "toolsMenu";
        this.toolsMenu.Text = "&Tools";
        this.toolsMenu.DropDownItems.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("Show &symbols...", null, new EventHandler(this.MnuShowSymbols_Click!)),
            new ToolStripMenuItem("&Edit value...", null, (s, e) => ShowEditValueDialog()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Allocate memory...", null, (s, e) => ShowAllocateDialog()),
            new ToolStripMenuItem("&Change protection...", null, (s, e) => ShowProtectionDialog())
        });

        //
        // toolStrip
        //
        this.toolStrip.Items.AddRange(new ToolStripItem[] {
            this.lblAddress,
            this.txtAddress,
            this.btnGo,
            this.toolStripSeparator1,
            this.cboDisplayType,
            this.chkAutoRefresh
        });
        this.toolStrip.Location = new Point(0, 24);
        this.toolStrip.Name = "toolStrip";
        this.toolStrip.Size = new Size(900, 25);

        //
        // lblAddress
        //
        this.lblAddress.Name = "lblAddress";
        this.lblAddress.Text = "Address:";

        //
        // txtAddress
        //
        this.txtAddress.Name = "txtAddress";
        this.txtAddress.Size = new Size(150, 25);
        this.txtAddress.KeyDown += new KeyEventHandler(this.TxtAddress_KeyDown!);

        //
        // btnGo
        //
        this.btnGo.DisplayStyle = ToolStripItemDisplayStyle.Text;
        this.btnGo.Name = "btnGo";
        this.btnGo.Text = "Go";
        this.btnGo.Click += new EventHandler(this.BtnGo_Click!);

        //
        // cboDisplayType
        //
        this.cboDisplayType.DropDownStyle = ComboBoxStyle.DropDownList;
        this.cboDisplayType.Items.AddRange(new object[] {
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double"
        });
        this.cboDisplayType.Name = "cboDisplayType";
        this.cboDisplayType.SelectedIndex = 0;
        this.cboDisplayType.Size = new Size(80, 25);

        //
        // chkAutoRefresh
        //
        this.chkAutoRefresh.CheckOnClick = true;
        this.chkAutoRefresh.Checked = true;
        this.chkAutoRefresh.DisplayStyle = ToolStripItemDisplayStyle.Text;
        this.chkAutoRefresh.Name = "chkAutoRefresh";
        this.chkAutoRefresh.Text = "Auto Refresh";
        this.chkAutoRefresh.CheckedChanged += new EventHandler(this.ChkAutoRefresh_CheckedChanged!);

        //
        // splitContainer
        //
        this.splitContainer.Dock = DockStyle.Fill;
        this.splitContainer.Location = new Point(0, 49);
        this.splitContainer.Name = "splitContainer";
        this.splitContainer.Orientation = Orientation.Horizontal;
        this.splitContainer.Size = new Size(900, 500);
        this.splitContainer.SplitterDistance = 300;
        this.splitContainer.Panel1MinSize = 50;
        this.splitContainer.Panel2MinSize = 50;

        //
        // disasmScrollBar (top panel)
        //
        this.disasmScrollBar = new VScrollBar();
        this.disasmScrollBar.Dock = DockStyle.Right;
        this.disasmScrollBar.Name = "disasmScrollBar";
        this.disasmScrollBar.Minimum = 0;
        this.disasmScrollBar.Maximum = 1000;
        this.disasmScrollBar.Value = 500;
        this.disasmScrollBar.LargeChange = 50;
        this.disasmScrollBar.SmallChange = 10;
        this.disasmScrollBar.Scroll += new ScrollEventHandler(this.DisasmScrollBar_Scroll!);

        //
        // pnlDisasm (top panel)
        //
        this.pnlDisasm = new DoubleBufferedPanel();
        this.pnlDisasm.BackColor = Color.White;
        this.pnlDisasm.Dock = DockStyle.Fill;
        this.pnlDisasm.Name = "pnlDisasm";

        // Disasm context menu
        this.disasmContextMenu = new ContextMenuStrip();
        this.disasmContextMenu.Items.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("&Undo last change", null, (s, e) => UndoLastChange()) { ShortcutKeys = Keys.Control | Keys.Z },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Go to address...", null, (s, e) => ShowGoToDialogDisasm()) { ShortcutKeys = Keys.Control | Keys.G },
            new ToolStripMenuItem("Follow", null, (s, e) => FollowSelectedAddress()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Replace with code that does nothing (NOP)", null, (s, e) => ReplaceWithNop()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Toggle &breakpoint", null, new EventHandler(this.MnuSetBreakpoint_Click!)) { ShortcutKeys = Keys.F2 },
            new ToolStripMenuItem("Find out what accesses this address", null, (s, e) => FindWhatAccesses()),
            new ToolStripMenuItem("Find out what writes to this address", null, (s, e) => FindWhatWrites()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Copy address", null, (s, e) => CopyDisasmAddress()),
            new ToolStripMenuItem("Copy &bytes", null, (s, e) => CopyDisasmBytes()),
            new ToolStripMenuItem("Copy &disassembly", null, (s, e) => CopyDisassembly()),
        });
        this.pnlDisasm.ContextMenuStrip = this.disasmContextMenu;

        this.splitContainer.Panel1.Controls.Add(this.disasmScrollBar);
        this.splitContainer.Panel1.Controls.Add(this.pnlDisasm);

        //
        // lblHexHeader (bottom panel - header showing region info)
        //
        this.lblHexHeader = new Label();
        this.lblHexHeader.BackColor = Color.FromArgb(240, 240, 240);
        this.lblHexHeader.Dock = DockStyle.Top;
        this.lblHexHeader.Font = new Font("Consolas", 9F);
        this.lblHexHeader.Name = "lblHexHeader";
        this.lblHexHeader.Height = 20;
        this.lblHexHeader.Padding = new Padding(2, 2, 2, 0);
        this.lblHexHeader.Text = "";

        //
        // hexScrollBar (bottom panel)
        //
        this.hexScrollBar = new VScrollBar();
        this.hexScrollBar.Dock = DockStyle.Right;
        this.hexScrollBar.Name = "hexScrollBar";
        this.hexScrollBar.Minimum = 0;
        this.hexScrollBar.Maximum = 1000;
        this.hexScrollBar.Value = 500;
        this.hexScrollBar.LargeChange = 50;
        this.hexScrollBar.SmallChange = 10;
        this.hexScrollBar.Scroll += new ScrollEventHandler(this.HexScrollBar_Scroll!);

        //
        // pnlHexView (bottom panel)
        //
        this.pnlHexView = new DoubleBufferedPanel();
        this.pnlHexView.BackColor = Color.White;
        this.pnlHexView.Dock = DockStyle.Fill;
        this.pnlHexView.Name = "pnlHexView";

        // Hex view context menu
        this.hexContextMenu = new ContextMenuStrip();
        this.hexContextMenu.Items.AddRange(new ToolStripItem[] {
            new ToolStripMenuItem("&Go to address...", null, (s, e) => ShowGoToDialogHex()) { ShortcutKeys = Keys.Control | Keys.G },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Edit value...", null, (s, e) => ShowEditValueDialog()),
            new ToolStripMenuItem("&Fill memory...", null, new EventHandler(this.MnuFillBytes_Click!)),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Find out what accesses this address", null, (s, e) => FindWhatAccesses()),
            new ToolStripMenuItem("Find out what writes to this address", null, (s, e) => FindWhatWrites()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Copy address", null, (s, e) => CopySelectedAddress()),
            new ToolStripMenuItem("Copy bytes", null, new EventHandler(this.MnuCopy_Click!)) { ShortcutKeys = Keys.Control | Keys.C },
            new ToolStripMenuItem("&Paste bytes", null, new EventHandler(this.MnuPaste_Click!)) { ShortcutKeys = Keys.Control | Keys.V },
        });
        this.pnlHexView.ContextMenuStrip = this.hexContextMenu;

        this.splitContainer.Panel2.Controls.Add(this.hexScrollBar);
        this.splitContainer.Panel2.Controls.Add(this.pnlHexView);
        this.splitContainer.Panel2.Controls.Add(this.lblHexHeader);

        //
        // statusStrip
        //
        this.statusStrip.Items.AddRange(new ToolStripItem[] {
            this.lblStatus,
            this.lblSelectedAddress
        });
        this.statusStrip.Location = new Point(0, 549);
        this.statusStrip.Name = "statusStrip";
        this.statusStrip.Size = new Size(900, 22);

        //
        // lblStatus
        //
        this.lblStatus.Name = "lblStatus";
        this.lblStatus.Text = "Ready";
        this.lblStatus.Spring = true;
        this.lblStatus.TextAlign = ContentAlignment.MiddleLeft;

        //
        // lblSelectedAddress
        //
        this.lblSelectedAddress.Name = "lblSelectedAddress";
        this.lblSelectedAddress.Size = new Size(150, 17);
        this.lblSelectedAddress.Text = "Selected: 0x0";

        //
        // refreshTimer
        //
        this.refreshTimer.Interval = 100;
        this.refreshTimer.Tick += new EventHandler(this.RefreshTimer_Tick!);

        //
        // MemoryViewerForm
        //
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.ClientSize = new Size(960, 571);
        this.Controls.Add(this.splitContainer);
        this.Controls.Add(this.toolStrip);
        this.Controls.Add(this.menuStrip);
        this.Controls.Add(this.statusStrip);
        this.MainMenuStrip = this.menuStrip;
        this.MinimumSize = new Size(600, 400);
        this.Name = "MemoryViewerForm";
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "Memory Viewer";

        ((System.ComponentModel.ISupportInitialize)this.splitContainer).EndInit();
        this.splitContainer.Panel1.ResumeLayout(false);
        this.splitContainer.Panel2.ResumeLayout(false);
        this.splitContainer.ResumeLayout(false);
        this.menuStrip.ResumeLayout(false);
        this.menuStrip.PerformLayout();
        this.toolStrip.ResumeLayout(false);
        this.toolStrip.PerformLayout();
        this.statusStrip.ResumeLayout(false);
        this.statusStrip.PerformLayout();
        this.ResumeLayout(false);
        this.PerformLayout();
    }

    private MenuStrip menuStrip = null!;
    private ToolStripMenuItem fileMenu = null!;
    private ToolStripMenuItem viewMenu = null!;
    private ToolStripMenuItem searchMenu = null!;
    private ToolStripMenuItem debugMenu = null!;
    private ToolStripMenuItem toolsMenu = null!;
    private ToolStripMenuItem mnuHexView = null!;
    private ToolStripMenuItem mnuDisasmView = null!;

    private ToolStrip toolStrip = null!;
    private ToolStripLabel lblAddress = null!;
    private ToolStripTextBox txtAddress = null!;
    private ToolStripButton btnGo = null!;
    private ToolStripSeparator toolStripSeparator1 = null!;
    private ToolStripComboBox cboDisplayType = null!;
    private ToolStripButton chkAutoRefresh = null!;

    private SplitContainer splitContainer = null!;
    private Panel pnlHexView = null!;
    private Panel pnlDisasm = null!;
    private VScrollBar hexScrollBar = null!;
    private VScrollBar disasmScrollBar = null!;
    private Label lblHexHeader = null!;

    private StatusStrip statusStrip = null!;
    private ToolStripStatusLabel lblStatus = null!;
    private ToolStripStatusLabel lblSelectedAddress = null!;

    private ContextMenuStrip disasmContextMenu = null!;
    private ContextMenuStrip hexContextMenu = null!;

    private System.Windows.Forms.Timer refreshTimer = null!;
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
                 ControlStyles.UserPaint, true);
        UpdateStyles();
    }
}
