// Tutorial Step 18 - Hotkeys
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 18 - Hotkeys.
/// Tests hotkey configuration and usage.
/// </summary>
public class TutorialStep21Form : Form
{
    private int _energy = 50;
    private int _hotkeyPresses;
    private readonly Label _lblEnergy;
    private readonly Label _lblHotkey;
    private readonly Label _lblStatus;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _drainTimer;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step18Text = @"Step 18: Hotkeys

Hotkeys let you toggle cheats while in-game without switching windows.

Below, energy drains over time. Your task:
1. Find the energy address
2. Add it to your list and set value to 100
3. Right-click the entry -> Set Hotkey
4. Configure a hotkey (e.g., F5) to set value to 100
5. Press the hotkey 5 times to demonstrate it works

Hotkey options:
- Toggle freeze
- Set value
- Increase/decrease by X
- Toggle script

The counter tracks simulated hotkey presses. Press the button 5 times (or use actual hotkey).";

    public TutorialStep21Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 18";
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
            Size = new Size(560, 220),
            Text = Step18Text
        };
        Controls.Add(instructions);

        _lblEnergy = new Label
        {
            Text = $"Energy: {_energy}",
            Location = new Point(10, 250),
            Size = new Size(200, 35),
            Font = new Font("Segoe UI", 16, FontStyle.Bold)
        };
        Controls.Add(_lblEnergy);

        var progressBar = new ProgressBar
        {
            Location = new Point(220, 255),
            Size = new Size(200, 25),
            Minimum = 0,
            Maximum = 100,
            Value = _energy
        };
        Controls.Add(progressBar);

        _lblHotkey = new Label
        {
            Text = $"Hotkey presses: {_hotkeyPresses}/5",
            Location = new Point(10, 300),
            Size = new Size(200, 25)
        };
        Controls.Add(_lblHotkey);

        var btnSimulateHotkey = new Button { Text = "Simulate Hotkey (F5)", Location = new Point(10, 330), Size = new Size(150, 35) };
        btnSimulateHotkey.Click += (s, e) =>
        {
            _energy = 100;
            progressBar.Value = 100;
            _hotkeyPresses++;
            _lblHotkey.Text = $"Hotkey presses: {_hotkeyPresses}/5";
            _lblEnergy.Text = $"Energy: {_energy}";
        };
        Controls.Add(btnSimulateHotkey);

        _lblStatus = new Label
        {
            Text = "Press hotkey 5 times to proceed",
            Location = new Point(10, 380),
            Size = new Size(300, 25),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblStatus);

        _btnNext = new Button { Text = "Finish", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialCompleteForm { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _drainTimer = new System.Windows.Forms.Timer { Interval = 500 };
        _drainTimer.Tick += (s, e) =>
        {
            _energy -= 2;
            if (_energy < 0) _energy = 0;
            progressBar.Value = Math.Max(0, _energy);
            _lblEnergy.Text = $"Energy: {_energy}";
        };
        _drainTimer.Start();

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_hotkeyPresses >= 5)
            {
                _btnNext.Enabled = true;
                _lblStatus.Text = "Hotkeys mastered!";
                _lblStatus.ForeColor = Color.Green;
                _drainTimer.Stop();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 18);
        FormClosing += (s, e) => Environment.Exit(0);
    }
}
