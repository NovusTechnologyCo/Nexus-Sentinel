// Tutorial Step 10 - String Scanning
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 10 - String Scanning.
/// Teaches ASCII and Unicode string searches.
/// </summary>
public class TutorialStep10Form : Form
{
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private static extern void Step10_SetName(string name);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step10_GetName();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step10_GetNameAddress();

    private readonly TextBox _txtPlayerName;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private bool _nativeLoaded = false;

    private const string Step10Text = @"Step 10: String Scanning

So far you've only searched for numeric values. But games also store text strings like player names, item names, etc.

Below you see a player name stored in native memory. Your task is to change it to 'YOURNAME'.

Steps:
1. Search for the player name as String type
2. IMPORTANT: Uncheck 'UTF-16' - use ASCII (1 byte per char)
3. You should find exactly one result
4. Change it to exactly 'YOURNAME' (all caps, 8 chars)

Tips:
- UTF-16 uses 2 bytes per char, ASCII uses 1 byte
- The native string is ASCII - uncheck UTF-16!

Change the name to 'YOURNAME' to proceed.";

    public TutorialStep10Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 10";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize native DLL with unique name
        try
        {
            Step10_SetName("Player" + DateTime.Now.Ticks % 10000);
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
            Size = new Size(560, 250),
            Text = Step10Text
        };
        Controls.Add(instructions);

        var lblTitle = new Label
        {
            Text = "Player Name:",
            Location = new Point(10, 280),
            AutoSize = true
        };
        Controls.Add(lblTitle);

        _txtPlayerName = new TextBox
        {
            Text = "", // Don't store the name here - read directly from native
            Location = new Point(140, 277),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ReadOnly = true,
            BackColor = Color.White
        };
        // Only update TextBox when explicitly needed
        if (_nativeLoaded)
        {
            IntPtr ptr = Step10_GetName();
            _txtPlayerName.Text = Marshal.PtrToStringAnsi(ptr) ?? "";
        }
        Controls.Add(_txtPlayerName);

        var btnRandomize = new Button { Text = "New", Location = new Point(350, 273), Size = new Size(70, 35) };
        btnRandomize.Click += (s, e) =>
        {
            if (!_nativeLoaded) return;
            Step10_SetName("Player" + DateTime.Now.Ticks % 10000);
            _txtPlayerName.Text = GetPlayerName();
        };
        Controls.Add(btnRandomize);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep11Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        // Timer to check for name change
        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (!_nativeLoaded) return;
            string currentName = GetPlayerName();
            _txtPlayerName.Text = currentName;
            if (currentName == "YOURNAME")
            {
                _btnNext.Enabled = true;
                _checkTimer.Stop();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 10);
        FormClosing += (s, e) => { _checkTimer.Stop(); Environment.Exit(0); };
    }

    private string GetPlayerName()
    {
        if (!_nativeLoaded) return "[DLL not loaded]";
        try
        {
            IntPtr ptr = Step10_GetName();
            return Marshal.PtrToStringAnsi(ptr) ?? "";
        }
        catch
        {
            return "[Error]";
        }
    }
}
