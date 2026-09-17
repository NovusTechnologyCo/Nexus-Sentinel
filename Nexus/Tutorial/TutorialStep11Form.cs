// Tutorial Step 11 - AOB (Array of Bytes) Scanning
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 11 - AOB (Array of Bytes) Scanning.
/// Teaches signature scanning with wildcards.
/// </summary>
public class TutorialStep11Form : Form
{
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int Step11_GetValue();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step11_GetAddress();

    private readonly Label _lblStatus;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private bool _nativeLoaded = false;

    private const string Step11Text = @"Step 11: AOB/Signature Scanning

Array of Bytes (AOB) scanning finds data patterns in memory. This is useful when you know a unique byte sequence near your target value.

There's a hidden value stored after a unique byte signature. Your task:

Steps:
1. Select 'Array of bytes' as the scan type
2. Search for: DE AD BE EF CA FE BA BE
3. You'll find one result - that's the signature location
4. The hidden value (4 bytes) is at offset +8 from that address
5. Add that address+8 manually, set type to 4 Bytes
6. Change the value to 99999

Signature: DE AD BE EF CA FE BA BE
Value offset: +8 (add 8 to the address you find)
Target value: 99999

This technique helps find values when you know nearby patterns!";

    public TutorialStep11Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 11";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize native DLL
        try
        {
            int val = Step11_GetValue(); // Just to load the DLL
            _nativeLoaded = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load tutorial_native.dll:\n{ex.Message}", "DLL Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 280),
            Text = Step11Text
        };
        Controls.Add(instructions);

        _lblStatus = new Label
        {
            Text = "Hidden Value: ?????",
            Location = new Point(10, 300),
            Size = new Size(300, 30),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblStatus);

        var btnReveal = new Button { Text = "Reveal", Location = new Point(10, 340), Size = new Size(80, 35) };
        btnReveal.Click += (s, e) =>
        {
            if (_nativeLoaded)
                _lblStatus.Text = $"Hidden Value: {Step11_GetValue()}";
        };
        Controls.Add(btnReveal);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep12Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (!_nativeLoaded) return;
            int currentValue = Step11_GetValue();
            if (currentValue == 99999)
            {
                _btnNext.Enabled = true;
                _lblStatus.Text = $"Hidden Value: {currentValue}";
                _lblStatus.ForeColor = Color.Green;
                _checkTimer.Stop();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 11);
        FormClosing += (s, e) => { _checkTimer.Stop(); Environment.Exit(0); };
    }
}
