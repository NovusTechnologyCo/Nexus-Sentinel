// Tutorial Step 6 - Pointers
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 6 - Pointers.
/// </summary>
public class TutorialStep6Form : Form
{
    // P/Invoke to native DLL for clean pointer operations
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step6_Init(int initialValue);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step6_GetPointerAddress();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step6_GetValuePtr();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int Step6_ReadValue();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step6_WriteValue(int newValue);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step6_ChangePointer();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step6_Cleanup();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    private readonly Label _lblValue;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private bool _dllLoaded = false;
    private bool _pointerChanged = false; // User must click "Change pointer" for Next to enable

    private const string Step6Text = @"Step 6: Pointers

In the previous step I explained how to use the Code finder to handle changing locations. But that method alone makes it difficult to find the address to set the values you want.
That's why there are pointers:

At the bottom you'll find 2 buttons. One will change the value, and the other changes the value AND the location of the value.
For this step you don't really need to know assembler, but it helps a lot if you do.

First find the address of the value. When you've found it use the function to find out what accesses this address.
Change the value again, and an item will show up in the list. Double click that item and a new window will open with detailed information.

If the assembler instruction has something between '[' and ']' it will show the pointer value.
Do a 4 byte hex scan for that value. Add the address manually with the pointer checkbox enabled.

Fill in the pointer address and offset. Click OK and the address should show P->xxxxxxx.
Now change the value to 5000, freeze it, then click 'Change pointer'. If correct, Next will enable.";

    public TutorialStep6Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 6";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Initialize using native DLL
        try
        {
            Step6_Init(new Random().Next(100, 1000));
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
            Size = new Size(560, 280),
            Text = Step6Text
        };
        Controls.Add(instructions);

        _lblValue = new Label
        {
            Text = $"Value: {(_dllLoaded ? Step6_ReadValue() : 0)}",
            Location = new Point(10, 300),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblValue);

        var btnChangeValue = new Button { Text = "Change value", Location = new Point(10, 350), Size = new Size(120, 70) };
        btnChangeValue.Click += (s, e) =>
        {
            if (_dllLoaded)
            {
                Step6_WriteValue(new Random().Next(100, 1000));
                UpdateLabel();
            }
        };
        Controls.Add(btnChangeValue);

        var btnChangePointer = new Button { Text = "Change pointer", Location = new Point(140, 350), Size = new Size(130, 70) };
        btnChangePointer.Click += (s, e) =>
        {
            if (_dllLoaded)
            {
                // Change pointer moves data to new location, then set a random value
                // If user has a working pointer with freeze, it will write 5000 back
                Step6_ChangePointer();
                Step6_WriteValue(new Random().Next(100, 999)); // Set to random value
                _pointerChanged = true;
                UpdateLabel();
            }
        };
        Controls.Add(btnChangePointer);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep7Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_dllLoaded)
            {
                int val = Step6_ReadValue();
                // Value must be 5000 AND user must have clicked "Change pointer"
                if (val == 5000 && _pointerChanged) { _btnNext.Enabled = true; }
                UpdateLabel();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 6);
        FormClosing += (s, e) =>
        {
            if (_dllLoaded) Step6_Cleanup();
            Environment.Exit(0);
        };
    }

    private void UpdateLabel()
    {
        if (_dllLoaded)
            _lblValue.Text = $"Value: {Step6_ReadValue()}";
    }
}
