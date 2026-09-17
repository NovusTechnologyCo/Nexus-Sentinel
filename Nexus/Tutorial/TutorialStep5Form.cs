// Tutorial Step 5 - Code Finder
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 5 - Code Finder.
/// Tests "Find what writes to this address".
/// Uses native DLL for write operation so the instruction can be NOP'd.
/// </summary>
public class TutorialStep5Form : Form
{
    // P/Invoke to native DLL - the WriteValue function contains NOP-able code
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void WriteValue(int newValue);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int ReadValue();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr GetValuePtr();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    private readonly Label _lblValue;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private int _lastValue;
    private IntPtr _valuePtr;

    private const string Step5Text = @"Step 5: Code Finder (Introduction to Breakpoints)

WHAT ARE BREAKPOINTS?
Breakpoints let you find WHICH CODE modifies a memory address. When you set a breakpoint, the debugger pauses whenever that address is read or written, showing you the exact assembly instruction responsible.

Two key types:
- 'Find what WRITES' - Shows code that changes the value
- 'Find what ACCESSES' - Shows code that reads OR writes the value

WHY USE THEM?
Instead of just changing a value (which the game overwrites), you can find and disable the code that changes it. This is more powerful than freezing.

YOUR TASK:
The value below changes location each restart, so a normal address won't work.
1. Find the current address of the value
2. Right-click it -> 'Find out what writes to this address'
3. Click 'Change value' in this tutorial - you'll see the instruction appear
4. Select the instruction and click 'Replace with NOPs' (No Operation)
5. Click Stop, then Close the window
6. Click 'Change value' again - it should no longer change!

Note: Freezing fast enough might also work, but NOP is the proper solution.";

    public TutorialStep5Form()
    {
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize value using native DLL
        IntPtr valuePtr = IntPtr.Zero;
        try
        {
            // First call to WriteValue will load the DLL
            WriteValue(new Random().Next(1000));
            _lastValue = ReadValue();

            // Get where the value is stored
            valuePtr = GetValuePtr();
        }
        catch (DllNotFoundException ex)
        {
            MessageBox.Show($"Failed to load tutorial_native.dll:\n{ex.Message}\n\nMake sure the DLL is in the same folder as NexusTutorial.exe",
                "DLL Not Found", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _lastValue = 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error calling native DLL:\n{ex.GetType().Name}: {ex.Message}",
                "Native DLL Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _lastValue = 0;
        }

        // Store for display
        _valuePtr = valuePtr;
        Text = "Nexus Sentinel Tutorial - Step 5";

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 350),
            Text = Step5Text
        };
        Controls.Add(instructions);

        var lblTitle = new Label
        {
            Text = "Value:",
            Location = new Point(10, 375),
            AutoSize = true
        };
        Controls.Add(lblTitle);

        _lblValue = new Label
        {
            Text = ReadValue().ToString(),
            Location = new Point(70, 375),
            Size = new Size(150, 31),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblValue);

        var btnChangeValue = new Button
        {
            Text = "Change value",
            Location = new Point(230, 370),
            Size = new Size(120, 36)
        };
        btnChangeValue.Click += BtnChangeValue_Click;
        Controls.Add(btnChangeValue);

        _btnNext = new Button
        {
            Text = "Next",
            Location = new Point(480, 435),
            Size = new Size(80, 36),
            Enabled = false
        };
        _btnNext.Click += (s, e) =>
        {
            Hide();
            new TutorialStep6Form { Location = Location }.Show();
        };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _checkTimer.Tick += CheckTimer_Tick;
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 5);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void BtnChangeValue_Click(object? sender, EventArgs e)
    {
        _lastValue = ReadValue();
        // This write goes through tutorial_native.dll - can be NOP'd!
        WriteValue(new Random().Next(1000));
        int newValue = ReadValue();
        _lblValue.Text = newValue.ToString();

        // If the write was NOPed, value won't change
        if (newValue == _lastValue)
        {
            // Value stayed the same - code was replaced!
            _btnNext.Enabled = true;
        }
    }

    private void CheckTimer_Tick(object? sender, EventArgs e)
    {
        // Just update the display
        _lblValue.Text = ReadValue().ToString();
    }
}
