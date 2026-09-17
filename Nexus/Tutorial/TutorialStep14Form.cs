// Tutorial Step 14 - Freeze Values
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 14 - Freeze Values.
/// Tests the freeze/lock functionality.
/// </summary>
public class TutorialStep14Form : Form
{
    private int _health = 100;
    private int _decreaseCount;
    private readonly Label _lblHealth;
    private readonly Label _lblStatus;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _damageTimer;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step14Text = @"Step 14: Freeze Values

Freezing (or locking) a value keeps it constant even when the game tries to change it.

Below is a health value that automatically decreases every second (simulating damage over time). Your task is to:

1. Find the health address
2. Add it to the address list
3. Check the 'Freeze' checkbox (or Active column)
4. The value should stay frozen even as damage is applied

The health must stay at exactly 500 for 10 consecutive damage ticks to proceed.

Tips:
- Freeze writes the value repeatedly (default: every 100ms)
- You can also right-click and choose 'Freeze' type (freeze, allow increase, allow decrease)
- Some anti-cheats detect rapid memory writes";

    public TutorialStep14Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 14";
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
            Text = Step14Text
        };
        Controls.Add(instructions);

        _lblHealth = new Label
        {
            Text = $"Health: {_health}",
            Location = new Point(10, 250),
            Size = new Size(200, 35),
            Font = new Font("Segoe UI", 16, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        _lblStatus = new Label
        {
            Text = "Freeze at 500 for 10 ticks: 0/10",
            Location = new Point(10, 295),
            Size = new Size(300, 25),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblStatus);

        var progressBar = new ProgressBar
        {
            Location = new Point(10, 325),
            Size = new Size(300, 20),
            Minimum = 0,
            Maximum = 10,
            Value = 0
        };
        Controls.Add(progressBar);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep15Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        // Damage timer - decreases health every second
        _damageTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _damageTimer.Tick += (s, e) =>
        {
            // Check if value is frozen at 500 BEFORE applying damage
            // If CE is freezing the value, it will still be 500 from the previous tick
            if (_health == 500)
            {
                _decreaseCount++;
                progressBar.Value = Math.Min(_decreaseCount, 10);
                _lblStatus.Text = $"Freeze at 500 for 10 ticks: {_decreaseCount}/10";
                _lblStatus.ForeColor = Color.Blue;
            }
            else
            {
                _decreaseCount = 0;
                progressBar.Value = 0;
                _lblStatus.Text = "Freeze at 500 for 10 ticks: 0/10";
                _lblStatus.ForeColor = Color.Gray;
            }

            // Apply damage after checking
            _health -= 5;
            if (_health < 0) _health = 100;

            _lblHealth.Text = $"Health: {_health}";
        };
        _damageTimer.Start();

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            _lblHealth.Text = $"Health: {_health}";
            if (_decreaseCount >= 10)
            {
                _btnNext.Enabled = true;
                _lblStatus.Text = "Freeze successful!";
                _lblStatus.ForeColor = Color.Green;
                _damageTimer.Stop();
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 14);
        FormClosing += (s, e) => Environment.Exit(0);
    }
}
