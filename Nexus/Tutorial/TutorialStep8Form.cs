// Tutorial Step 8 - Multilevel Pointers
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 8 - Multilevel Pointers.
/// Uses native DLL with 4-level pointer chain matching CE Tutorial offsets: +10, +18, +0, +18
/// </summary>
public class TutorialStep8Form : Form
{
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step8_Init(int initialHealth);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int Step8_ReadHealth();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step8_Hit();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step8_ChangePointer();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step8_Cleanup();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    private readonly Label _lblHealth;
    private readonly Label _lblInfo;
    private readonly Button _btnNext;
    private System.Windows.Forms.Timer? _checkTimer;
    private bool _nativeLoaded = false;
    private const int PointerCheckWindowSeconds = 3; // Must have 5000 within 3 seconds of clicking Change pointer

    private const string Step8Text = @"Step 8: Multilevel Pointers

In step 6 your trainer used a pointer but it was only a simple 1-level pointer.
This trainer however uses a 4-level pointer. It has a static base pointer, plus 3 offsets to finally get to the health.

Pointer chain: [[[[tutorial_native.dll+XXXXX]+20]+0]+10]+18

You can manually trace back each pointer level using 'Find what accesses', or use the Pointer Scanner.

Manual method:
1. Find the health value (starts at 100)
2. Use 'Find what writes' - note the instruction shows [reg+offset]
3. Subtract offset from reg, search for result as 8-byte hex
4. Set breakpoint, trigger access, note new offset
5. Repeat until you reach a static address (dll+XXXXX)
6. Offsets from value to base: +18, +10, +0, +20
   (Note: +0 means [reg] with no offset shown)

Using pointer scanner:
1. Find the health address, do a pointer scan
2. Click 'Change pointer' (reallocates chain)
3. Find health again, rescan with new address
4. Look for tutorial_native.dll base results

When your pointer shows 5000 after clicking 'Change pointer', Next enables.";

    public TutorialStep8Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 8";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 250),
            Text = Step8Text
        };
        Controls.Add(instructions);

        _lblHealth = new Label
        {
            Text = "Health: ---",
            Location = new Point(10, 270),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        _lblInfo = new Label
        {
            Text = "",
            Location = new Point(10, 305),
            Size = new Size(560, 55),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblInfo);

        var btnHitMe = new Button { Text = "Hit me", Location = new Point(10, 370), Size = new Size(100, 35) };
        btnHitMe.Click += BtnHitMe_Click;
        Controls.Add(btnHitMe);

        var btnChangePointer = new Button { Text = "Change pointer", Location = new Point(120, 370), Size = new Size(130, 35) };
        btnChangePointer.Click += BtnChangePointer_Click;
        Controls.Add(btnChangePointer);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep9Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        // Initialize native pointer chain
        try
        {
            Step8_Init(100);
            _nativeLoaded = true;

            // Show initial health synchronously (safe at startup, no breakpoints yet)
            int initialHealth = Step8_ReadHealth();
            _lblHealth.Text = $"Health: {initialHealth}";

            // Show DLL base address for reference
            IntPtr hModule = GetModuleHandle("tutorial_native.dll");
            if (hModule != IntPtr.Zero)
            {
                _lblInfo.Text = $"Base: tutorial_native.dll @ 0x{hModule.ToInt64():X}";
            }
        }
        catch (DllNotFoundException ex)
        {
            MessageBox.Show($"Failed to load tutorial_native.dll:\n{ex.Message}\n\nMake sure the DLL is in the same folder as NexusTutorial.exe",
                "DLL Not Found", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error initializing Step 8:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        TutorialNavigation.AddNavigationControls(this, 8);
        FormClosing += (s, e) => { _checkTimer?.Stop(); if (_nativeLoaded) Step8_Cleanup(); Environment.Exit(0); };

        UpdateLabel();
    }

    private void BtnHitMe_Click(object? sender, EventArgs e)
    {
        if (!_nativeLoaded) return;
        // Run on background thread so CE breakpoints don't freeze the UI
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                Step8_Hit(); // Uses SUB instruction - can be found with "find what writes"
            }
            catch { }
        }).ContinueWith(_ =>
        {
            // Update UI on main thread after hit completes (or CE releases breakpoint)
            BeginInvoke(new Action(UpdateLabel));
        });
    }

    private void BtnChangePointer_Click(object? sender, EventArgs e)
    {
        if (!_nativeLoaded) return;
        try
        {
            Step8_ChangePointer(); // Reallocates entire pointer chain
            UpdateLabel();
            _lblInfo.Text = $"Pointer chain reallocated! Checking for {PointerCheckWindowSeconds} seconds...";
            _lblInfo.ForeColor = Color.Blue;

            // Start a temporary timer that only runs for the check window
            _checkTimer?.Stop();
            int ticksRemaining = PointerCheckWindowSeconds * 10; // 100ms intervals
            _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
            _checkTimer.Tick += (s2, e2) =>
            {
                ticksRemaining--;
                // Run health read on background thread to avoid CE breakpoint crashes
                System.Threading.Tasks.Task.Run(() =>
                {
                    try { return Step8_ReadHealth(); }
                    catch { return -1; }
                }).ContinueWith(t =>
                {
                    BeginInvoke(new Action(() =>
                    {
                        int health = t.Result;
                        _lblHealth.Text = $"Health: {health}";

                        if (health >= 5000)
                        {
                            // Success!
                            _checkTimer?.Stop();
                            _btnNext.Enabled = true;
                            _lblInfo.Text = "Pointer working! Address updated correctly.";
                            _lblInfo.ForeColor = Color.Green;
                        }
                        else if (ticksRemaining <= 0)
                        {
                            // Time expired
                            _checkTimer?.Stop();
                            _lblInfo.Text = "Time expired. Set health to 5000, freeze it, then try again.";
                            _lblInfo.ForeColor = Color.Red;
                        }
                    }));
                });
            };
            _checkTimer.Start();
        }
        catch { }
    }

    private void UpdateLabel()
    {
        if (!_nativeLoaded)
        {
            _lblHealth.Text = "Health: [DLL not loaded]";
            return;
        }
        // Run on background thread so CE breakpoints don't crash the app
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                return Step8_ReadHealth();
            }
            catch
            {
                return -1;
            }
        }).ContinueWith(t =>
        {
            BeginInvoke(new Action(() =>
            {
                if (t.Result >= 0)
                    _lblHealth.Text = $"Health: {t.Result}";
                else
                    _lblHealth.Text = "Health: [Error]";
            }));
        });
    }
}
