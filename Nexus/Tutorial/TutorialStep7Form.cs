// Tutorial Step 7 - Code Injection
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 7 - Code Injection.
/// Uses native DLL for SUB instruction that can be injected.
/// </summary>
public class TutorialStep7Form : Form
{
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step7_Init(int initialHealth);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step7_GetHealthPtr();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int Step7_ReadHealth();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step7_Hit();

    private readonly Label _lblHealth;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private bool _dllLoaded = false;
    private int _healthBeforeHit = 0;

    private const string Step7Text = @"Step 7: Code Injection

Code injection is a technique where you inject a piece of code into the target process, and then reroute the execution of code to go through your own written code.

In this step you'll have a health value that will decrease when you click 'Hit me'.

Your task is to use code injection to make the code ADD 2 to your health instead of subtracting 1.
Find the address, find what writes, show disassembler, use Tools->Auto Assemble, and use the 'Code injection' template.

The disassembly will show something like: sub dword ptr [rax], 01
Write code that adds instead of subtracting. Click 'Hit me' and if health increases, Next becomes enabled.";

    public TutorialStep7Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 7";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize using native DLL
        try
        {
            Step7_Init(100);
            _dllLoaded = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load native DLL: {ex.Message}", "DLL Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 230),
            Text = Step7Text
        };
        Controls.Add(instructions);

        _lblHealth = new Label
        {
            Text = $"Health: {(_dllLoaded ? Step7_ReadHealth() : 0)}",
            Location = new Point(10, 260),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep8Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        var btnHitMe = new Button { Text = "Hit me", Location = new Point(10, 300), Size = new Size(100, 35) };
        btnHitMe.Click += (s, e) =>
        {
            if (_dllLoaded)
            {
                _healthBeforeHit = Step7_ReadHealth();
                Step7_Hit(); // This calls the native SUB instruction (or injected ADD)
                int healthAfterHit = Step7_ReadHealth();

                // If health increased, the code injection worked!
                if (healthAfterHit > _healthBeforeHit)
                {
                    _btnNext.Enabled = true;
                }
                UpdateLabel();
            }
        };
        Controls.Add(btnHitMe);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_dllLoaded)
            {
                UpdateLabel();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 7);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void UpdateLabel()
    {
        if (_dllLoaded)
            _lblHealth.Text = $"Health: {Step7_ReadHealth()}";
    }
}
