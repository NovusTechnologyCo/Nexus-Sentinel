// <file>
// <summary>
// Static address finder scanning code sections for references to data addresses.
// </summary>
// </file>
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Represents a found static address entry.
/// </summary>
public class StaticEntry
{
    public ulong Address { get; set; }
    public bool IsStruct { get; set; }
    public uint ReferenceCount { get; set; }
}

/// <summary>
/// Form to find static addresses referenced in executable code.
/// </summary>
public partial class FindStaticsForm : Form
{
    private CancellationTokenSource? _cts;
    private readonly List<StaticEntry> _staticList = new();
    private int _lastSortedColumn = -1;
    private bool _ascending = true;
    private bool _is64Bit;

    public FindStaticsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Find static addresses";
        Size = new Size(720, 550);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(450, 350);
        Padding = new Padding(NexusTheme.Space16, NexusTheme.Space8, NexusTheme.Space16, NexusTheme.Space8);

        // Progress bar at bottom
        progressBar = new ProgressBar
        {
            Dock = DockStyle.Bottom,
            Height = 18
        };

        // Checkbox panel
        pnlCheckbox = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = NexusTheme.ControlHeight + NexusTheme.Space8
        };

        chkExecutableOnly = new CheckBox
        {
            Text = "Only disassemble and check executable code",
            Checked = true,
            AutoSize = true,
            Location = new Point(0, NexusTheme.Space4)
        };
        pnlCheckbox.Controls.Add(chkExecutableOnly);

        // Right panel with controls
        pnlRight = new Panel
        {
            Dock = DockStyle.Right,
            Width = 180,
            Padding = new Padding(NexusTheme.Space8, 0, 0, 0)
        };

        int y = 0;

        btnScan = new Button
        {
            Text = "Scan",
            Size = new Size(160, NexusTheme.ControlHeight),
            Location = new Point(NexusTheme.Space8, y)
        };
        btnScan.Click += BtnScan_Click;

        y += NexusTheme.ControlHeight + NexusTheme.Space16 + NexusTheme.Space8;

        lblFrom = new Label { Text = "From:", Location = new Point(NexusTheme.Space8, y), AutoSize = true };
        y += 22;
        txtStartAddress = new TextBox
        {
            Location = new Point(NexusTheme.Space8, y),
            Size = new Size(160, NexusTheme.ControlHeight),
            CharacterCasing = CharacterCasing.Upper,
            MaxLength = 16,
            Text = "00401000"
        };

        y += NexusTheme.ControlHeight + NexusTheme.Space16;

        lblTo = new Label { Text = "To:", Location = new Point(NexusTheme.Space8, y), AutoSize = true };
        y += 22;
        txtStopAddress = new TextBox
        {
            Location = new Point(NexusTheme.Space8, y),
            Size = new Size(160, NexusTheme.ControlHeight),
            CharacterCasing = CharacterCasing.Upper,
            MaxLength = 16,
            Text = "00700000"
        };

        y += NexusTheme.ControlHeight + NexusTheme.Space16 + NexusTheme.Space8;

        lblFilter = new Label { Text = "Filter addresses", Location = new Point(NexusTheme.Space8, y), AutoSize = true };
        y += 24;

        lblFilterFrom = new Label { Text = "From:", Location = new Point(NexusTheme.Space8, y), AutoSize = true };
        y += 22;
        txtFilterStart = new TextBox
        {
            Location = new Point(NexusTheme.Space8, y),
            Size = new Size(160, NexusTheme.ControlHeight),
            CharacterCasing = CharacterCasing.Upper,
            MaxLength = 16,
            Text = "00400000"
        };

        y += NexusTheme.ControlHeight + NexusTheme.Space16;

        lblFilterTo = new Label { Text = "To:", Location = new Point(NexusTheme.Space8, y), AutoSize = true };
        y += 22;
        txtFilterStop = new TextBox
        {
            Location = new Point(NexusTheme.Space8, y),
            Size = new Size(160, NexusTheme.ControlHeight),
            CharacterCasing = CharacterCasing.Upper,
            MaxLength = 16,
            Text = "7FFFFFFF"
        };

        pnlRight.Controls.AddRange([
            btnScan, lblFrom, txtStartAddress, lblTo, txtStopAddress,
            lblFilter, lblFilterFrom, txtFilterStart, lblFilterTo, txtFilterStop
        ]);

        // ListView for results
        lvResults = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        lvResults.Columns.Add("Address", 150);
        lvResults.Columns.Add("Pointer?", 120);
        lvResults.Columns.Add("References", 130);
        lvResults.ColumnClick += LvResults_ColumnClick;
        lvResults.DoubleClick += LvResults_DoubleClick;
        lvResults.Resize += (s, e) => ResizeColumns();

        Controls.AddRange([lvResults, pnlRight, pnlCheckbox, progressBar]);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        ResizeColumns();
        LoadInitialAddresses();
    }

    private void ResizeColumns()
    {
        if (lvResults == null || lvResults.Columns.Count < 3) return;

        const int pointerWidth = 120;
        const int referencesWidth = 130;

        lvResults.Columns[1].Width = pointerWidth;
        lvResults.Columns[2].Width = referencesWidth;

        int addressWidth = lvResults.ClientSize.Width - pointerWidth - referencesWidth;
        if (addressWidth < 100) addressWidth = 100;
        lvResults.Columns[0].Width = addressWidth;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        base.OnFormClosing(e);
        StopScan();
    }

    private void LoadInitialAddresses()
    {
        // Get main module base address from engine
        var ctx = ProcessContext.Current;
        if (ctx.NativeProcessHandle != IntPtr.Zero)
        {
            // Get module count first
            var result = NexusEngine.Nexus_EnumerateModules(
                ctx.NativeProcessHandle, null, 0, out nuint moduleCount);

            if (result == NexusResult.Success && moduleCount > 0)
            {
                // Get modules
                var modules = new NexusModuleInfo[moduleCount];
                result = NexusEngine.Nexus_EnumerateModules(
                    ctx.NativeProcessHandle, modules, moduleCount, out _);

                if (result == NexusResult.Success && modules.Length > 0)
                {
                    // First module is usually the main executable
                    var mainModule = modules[0];
                    txtStartAddress.Text = mainModule.BaseAddress.ToString("X");
                    txtStopAddress.Text = (mainModule.BaseAddress + mainModule.Size).ToString("X");

                    // Detect 64-bit mode from module base address
                    _is64Bit = mainModule.BaseAddress > uint.MaxValue;
                }
            }
        }

        // Detect 64-bit mode if not already set
        if (!_is64Bit)
            _is64Bit = Environment.Is64BitProcess;

        if (_is64Bit)
        {
            txtStartAddress.MaxLength = 16;
            txtStopAddress.MaxLength = 16;
            txtFilterStart.MaxLength = 16;
            txtFilterStop.MaxLength = 16;
            txtFilterStart.Text = "0000000000000000";
            txtFilterStop.Text = "7FFFFFFFFFFFFFFF";
        }
    }

    private void BtnScan_Click(object? sender, EventArgs e)
    {
        if (btnScan.Text == "Stopping...")
            return;

        if (btnScan.Text == "Stop")
        {
            btnScan.Text = "Stopping...";
            StopScan();
        }
        else
        {
            StartScan();
        }
    }

    private void StartScan()
    {
        lvResults.Items.Clear();
        _staticList.Clear();

        if (!ulong.TryParse(txtStartAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out ulong startAddr) ||
            !ulong.TryParse(txtStopAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out ulong stopAddr) ||
            !ulong.TryParse(txtFilterStart.Text, System.Globalization.NumberStyles.HexNumber, null, out ulong filterStart) ||
            !ulong.TryParse(txtFilterStop.Text, System.Globalization.NumberStyles.HexNumber, null, out ulong filterStop))
        {
            MessageBox.Show("Invalid address format", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _cts = new CancellationTokenSource();
        btnScan.Text = "Stop";

        progressBar.Value = 0;
        progressBar.Maximum = 100;

        Task.Run(async () =>
        {
            try
            {
                await ScanForStaticsAsync(startAddr, stopAddr, filterStart, filterStop,
                    chkExecutableOnly.Checked, _cts.Token);
            }
            finally
            {
                if (!IsDisposed)
                {
                    Invoke(() =>
                    {
                        progressBar.Value = 0;
                        btnScan.Text = "Scan";
                    });
                }
            }
        });
    }

    private void StopScan()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    // Memory protection flags
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    // Operand types (Zydis convention)
    private const uint OPERAND_TYPE_MEMORY = 2;

    // RIP register ID (varies by disassembler, common values)
    private const ushort REG_RIP = 48;  // Zydis ZydisRegister_RIP

    private async Task ScanForStaticsAsync(ulong startAddress, ulong stopAddress,
        ulong filterStart, ulong filterStop, bool onlyExecutable, CancellationToken ct)
    {
        var ctx = ProcessContext.Current;
        if (ctx.NativeProcessHandle == IntPtr.Zero)
        {
            Invoke(() =>
            {
                var item = lvResults.Items.Add("No process attached");
                item.SubItems.Add("-");
                item.SubItems.Add("0");
            });
            return;
        }

        // Get memory region count first
        var result = NexusEngine.Nexus_EnumerateMemoryRegions(
            ctx.NativeProcessHandle, null, 0, out nuint regionCount);

        if (result != NexusResult.Success || regionCount == 0)
        {
            Invoke(() =>
            {
                var item = lvResults.Items.Add("Failed to enumerate memory regions");
                item.SubItems.Add("-");
                item.SubItems.Add("0");
            });
            return;
        }

        // Get all memory regions
        var regions = new NexusMemoryRegion[regionCount];
        result = NexusEngine.Nexus_EnumerateMemoryRegions(
            ctx.NativeProcessHandle, regions, regionCount, out _);

        if (result != NexusResult.Success)
            return;

        // Filter regions to scan range
        var regionsToScan = regions
            .Where(r => r.BaseAddress >= startAddress && r.BaseAddress < stopAddress)
            .Where(r => !onlyExecutable || IsExecutable(r.Protection))
            .ToList();

        if (regionsToScan.Count == 0)
        {
            Invoke(() =>
            {
                var item = lvResults.Items.Add("No regions found in scan range");
                item.SubItems.Add("-");
                item.SubItems.Add("0");
            });
            return;
        }

        ulong totalSize = (ulong)regionsToScan.Sum(r => (long)r.Size);
        ulong processedSize = 0;

        var foundStatics = new Dictionary<ulong, (bool IsStruct, uint RefCount, ulong PointerValue)>();

        foreach (var region in regionsToScan)
        {
            if (ct.IsCancellationRequested)
                break;

            // Disassemble instructions in this region
            await ScanRegionForStaticsAsync(ctx.NativeProcessHandle, region,
                filterStart, filterStop, foundStatics, ct);

            processedSize += region.Size;
            int progress = (int)(processedSize * 100 / totalSize);
            Invoke(() => progressBar.Value = Math.Min(progress, 100));
        }

        // Update ListView with results
        Invoke(() =>
        {
            lvResults.BeginUpdate();
            foreach (var kvp in foundStatics.OrderByDescending(x => x.Value.RefCount))
            {
                var entry = new StaticEntry
                {
                    Address = kvp.Key,
                    IsStruct = kvp.Value.IsStruct,
                    ReferenceCount = kvp.Value.RefCount
                };
                _staticList.Add(entry);

                var item = lvResults.Items.Add(kvp.Key.ToString(_is64Bit ? "X16" : "X8"));
                if (kvp.Value.IsStruct)
                    item.SubItems.Add("struct or array");
                else
                    item.SubItems.Add(kvp.Value.PointerValue.ToString(_is64Bit ? "X16" : "X8"));
                item.SubItems.Add(kvp.Value.RefCount.ToString());
            }
            lvResults.EndUpdate();

            if (_staticList.Count == 0)
            {
                var item = lvResults.Items.Add("No static addresses found");
                item.SubItems.Add("-");
                item.SubItems.Add("0");
            }
        });
    }

    private static bool IsExecutable(uint protection)
    {
        return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    private async Task ScanRegionForStaticsAsync(IntPtr processHandle, NexusMemoryRegion region,
        ulong filterStart, ulong filterStop,
        Dictionary<ulong, (bool IsStruct, uint RefCount, ulong PointerValue)> foundStatics,
        CancellationToken ct)
    {
        const int BATCH_SIZE = 1000;
        var instructions = new NexusDisasmInstruction[BATCH_SIZE];

        ulong currentAddress = region.BaseAddress;
        ulong endAddress = region.BaseAddress + region.Size;

        while (currentAddress < endAddress && !ct.IsCancellationRequested)
        {
            var result = NexusEngine.Nexus_DisasmDecodeProcess(
                processHandle, currentAddress, BATCH_SIZE, instructions, out nuint count);

            if (result != NexusResult.Success || count == 0)
                break;

            for (nuint i = 0; i < count; i++)
            {
                var instr = instructions[i];
                if (instr.Length == 0) break;

                // Check each operand for memory references
                for (int op = 0; op < instr.OperandCount && op < 5; op++)
                {
                    var operand = instr.Operands[op];

                    // Check if this is a memory operand
                    if (operand.Type == OPERAND_TYPE_MEMORY && operand.MemHasDisp != 0)
                    {
                        ulong staticAddr = 0;
                        bool isAbsolute = false;

                        if (operand.MemBase == 0 && operand.MemIndex == 0)
                        {
                            // Direct absolute address (common in 32-bit)
                            staticAddr = (ulong)operand.MemDisp;
                            isAbsolute = true;
                        }
                        else if (operand.MemBase == REG_RIP && operand.MemIndex == 0)
                        {
                            // RIP-relative addressing (common in 64-bit)
                            staticAddr = (ulong)((long)instr.Address + instr.Length + operand.MemDisp);
                            isAbsolute = true;
                        }

                        // Check if address is in filter range
                        if (isAbsolute && staticAddr >= filterStart && staticAddr <= filterStop)
                        {
                            if (foundStatics.TryGetValue(staticAddr, out var existing))
                            {
                                foundStatics[staticAddr] = (existing.IsStruct, existing.RefCount + 1, existing.PointerValue);
                            }
                            else
                            {
                                // Try to read the value at this address to determine if pointer
                                ulong pointerValue = 0;
                                bool isStruct = false;

                                int ptrSize = _is64Bit ? 8 : 4;
                                byte[] buffer = new byte[ptrSize];
                                unsafe
                                {
                                    fixed (byte* ptr = buffer)
                                    {
                                        var readResult = NexusEngine.Nexus_ReadMemory(
                                            processHandle, staticAddr, (IntPtr)ptr, (nuint)ptrSize, out _);
                                        if (readResult == NexusResult.Success)
                                        {
                                            pointerValue = _is64Bit
                                                ? BitConverter.ToUInt64(buffer, 0)
                                                : BitConverter.ToUInt32(buffer, 0);

                                            // Simple heuristic: if the value looks like a valid pointer, it's a pointer
                                            // If it's outside typical pointer range or zero, might be struct data
                                            isStruct = pointerValue == 0 ||
                                                (pointerValue < 0x10000) ||
                                                (_is64Bit && pointerValue > 0x7FFFFFFFFFFF);
                                        }
                                        else
                                        {
                                            isStruct = true; // Couldn't read, assume struct
                                        }
                                    }
                                }

                                foundStatics[staticAddr] = (isStruct, 1, pointerValue);
                            }
                        }
                    }
                }

                currentAddress = instr.Address + instr.Length;
            }

            // Small delay to prevent UI lockup
            await Task.Delay(1, ct);
        }
    }

    private void AddStaticEntry(ulong address, bool isStruct, ulong pointerValue)
    {
        // Check if already exists
        for (int i = 0; i < _staticList.Count; i++)
        {
            if (_staticList[i].Address == address)
            {
                _staticList[i].ReferenceCount++;
                UpdateListViewEntry(i);
                return;
            }
        }

        // Add new entry
        var entry = new StaticEntry
        {
            Address = address,
            IsStruct = isStruct,
            ReferenceCount = 1
        };
        _staticList.Add(entry);

        Invoke(() =>
        {
            var item = lvResults.Items.Add(address.ToString("X8"));
            if (isStruct)
                item.SubItems.Add("struct or array");
            else
                item.SubItems.Add(pointerValue.ToString("X8"));
            item.SubItems.Add("1");
        });
    }

    private void UpdateListViewEntry(int index)
    {
        if (index < 0 || index >= lvResults.Items.Count) return;

        Invoke(() =>
        {
            var item = lvResults.Items[index];
            if (_staticList[index].IsStruct)
                item.SubItems[0].Text = "struct or array";
            item.SubItems[1].Text = _staticList[index].ReferenceCount.ToString();
        });
    }

    private void LvResults_ColumnClick(object? sender, ColumnClickEventArgs e)
    {
        if (_cts != null) return; // Don't sort while scanning

        if (e.Column == _lastSortedColumn)
            _ascending = !_ascending;
        else
            _lastSortedColumn = e.Column;

        lvResults.ListViewItemSorter = new ListViewItemComparer(e.Column, _ascending);
        lvResults.Sort();
    }

    private void LvResults_DoubleClick(object? sender, EventArgs e)
    {
        if (lvResults.SelectedItems.Count > 0)
        {
            string addrStr = lvResults.SelectedItems[0].Text;
            if (ulong.TryParse(addrStr, System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                // Open memory browser at this address
                var ctx = ProcessContext.Current;
                if (ctx.NativeProcessHandle != IntPtr.Zero)
                {
                    var viewer = new MemoryViewerForm(
                        ctx.NativeProcessHandle,
                        address,
                        ctx.ProcessId);
                    viewer.Show(this);
                }
            }
        }
    }

    /// <summary>
    /// Shows the find statics form.
    /// </summary>
    public static void ShowForm(IWin32Window? owner = null)
    {
        var form = new FindStaticsForm();
        if (owner != null)
            form.Show(owner);
        else
            form.Show();
    }

    // Controls
    private ProgressBar progressBar = null!;
    private Panel pnlCheckbox = null!;
    private Panel pnlRight = null!;
    private CheckBox chkExecutableOnly = null!;
    private Button btnScan = null!;
    private Label lblFrom = null!;
    private Label lblTo = null!;
    private Label lblFilter = null!;
    private Label lblFilterFrom = null!;
    private Label lblFilterTo = null!;
    private TextBox txtStartAddress = null!;
    private TextBox txtStopAddress = null!;
    private TextBox txtFilterStart = null!;
    private TextBox txtFilterStop = null!;
    private ListView lvResults = null!;

    /// <summary>
    /// ListView item comparer for sorting.
    /// </summary>
    private class ListViewItemComparer : System.Collections.IComparer
    {
        private readonly int _column;
        private readonly bool _ascending;

        public ListViewItemComparer(int column, bool ascending)
        {
            _column = column;
            _ascending = ascending;
        }

        public int Compare(object? x, object? y)
        {
            if (x is not ListViewItem item1 || y is not ListViewItem item2)
                return 0;

            string text1 = _column == 0 ? item1.Text : item1.SubItems[_column].Text;
            string text2 = _column == 0 ? item2.Text : item2.SubItems[_column].Text;

            int result;
            if (_column == 2) // Reference count - numeric sort
            {
                uint.TryParse(text1, out uint val1);
                uint.TryParse(text2, out uint val2);
                result = val1.CompareTo(val2);
            }
            else
            {
                result = string.Compare(text1, text2, StringComparison.OrdinalIgnoreCase);
            }

            return _ascending ? result : -result;
        }
    }
}
