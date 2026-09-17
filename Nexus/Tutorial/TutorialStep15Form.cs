// Tutorial Step 15 - Memory Viewer / Hex Editing
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 15 - Memory Viewer / Hex Editing.
/// Tests hex editor and direct memory manipulation.
/// </summary>
public class TutorialStep15Form : Form
{
    private readonly byte[] _memoryBlock = new byte[32];
    private readonly GCHandle _pinnedHandle;
    private readonly IntPtr _memoryAddress;
    private readonly Label _lblHexView;
    private readonly Label _lblTarget;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step15Text = @"Step 15: Memory Viewer

The Memory Viewer shows raw bytes in memory. You can:
- View memory as hex bytes
- Edit bytes directly
- See ASCII representation
- Navigate to addresses

Below is a 32-byte memory block. Change the 4 bytes at offset +16 (0x10) to 0xDEADBEEF.

Steps:
1. Copy the address shown below
2. In CE: Memory View -> Ctrl+G (Go to address)
3. Paste the address and press Enter
4. Navigate to offset +10 from the base
5. Edit the 4 bytes to: EF BE AD DE (little-endian for DEADBEEF)

Or: Right-click the address in your table -> Browse this memory region";

    public TutorialStep15Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 15";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize memory block with pattern
        var rng = new Random(42);
        rng.NextBytes(_memoryBlock);
        _memoryBlock[16] = 0x00;
        _memoryBlock[17] = 0x00;
        _memoryBlock[18] = 0x00;
        _memoryBlock[19] = 0x00;

        // Pin the array so it doesn't move in memory
        _pinnedHandle = GCHandle.Alloc(_memoryBlock, GCHandleType.Pinned);
        _memoryAddress = _pinnedHandle.AddrOfPinnedObject();

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 180),
            Text = Step15Text
        };
        Controls.Add(instructions);

        // Show the actual memory address
        var lblAddress = new Label
        {
            Text = $"Memory Address: {_memoryAddress:X} (offset +10 for target bytes)",
            Location = new Point(10, 195),
            Size = new Size(560, 25),
            Font = new Font("Consolas", 11, FontStyle.Bold),
            ForeColor = Color.DarkRed
        };
        Controls.Add(lblAddress);

        var lblHexTitle = new Label { Text = "Memory Block (32 bytes):", Location = new Point(10, 225), AutoSize = true };
        Controls.Add(lblHexTitle);

        _lblHexView = new Label
        {
            Text = GetHexView(),
            Location = new Point(10, 250),
            Size = new Size(560, 80),
            Font = new Font("Consolas", 10),
            BackColor = Color.Black,
            ForeColor = Color.Lime
        };
        Controls.Add(_lblHexView);

        _lblTarget = new Label
        {
            Text = $"Value at offset +16: 0x{BitConverter.ToUInt32(_memoryBlock, 16):X8}",
            Location = new Point(10, 340),
            Size = new Size(400, 30),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblTarget);

        var lblExpected = new Label
        {
            Text = "Target: 0xDEADBEEF",
            Location = new Point(10, 375),
            AutoSize = true,
            ForeColor = Color.DarkBlue
        };
        Controls.Add(lblExpected);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep17Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            uint value = BitConverter.ToUInt32(_memoryBlock, 16);
            _lblTarget.Text = $"Value at offset +16: 0x{value:X8}";
            _lblHexView.Text = GetHexView();

            if (value == 0xDEADBEEF)
            {
                _btnNext.Enabled = true;
                _lblTarget.ForeColor = Color.Green;
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 15);
        FormClosing += (s, e) =>
        {
            _checkTimer.Stop();
            if (_pinnedHandle.IsAllocated)
                _pinnedHandle.Free();
            Environment.Exit(0);
        };
    }

    private string GetHexView()
    {
        var sb = new System.Text.StringBuilder();
        for (int row = 0; row < 2; row++)
        {
            sb.Append($"{row * 16:X4}: ");
            for (int col = 0; col < 16; col++)
            {
                int idx = row * 16 + col;
                sb.Append($"{_memoryBlock[idx]:X2} ");
                if (col == 7) sb.Append(" ");
            }
            sb.Append(" | ");
            for (int col = 0; col < 16; col++)
            {
                int idx = row * 16 + col;
                char c = (char)_memoryBlock[idx];
                sb.Append(char.IsControl(c) ? '.' : c);
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
