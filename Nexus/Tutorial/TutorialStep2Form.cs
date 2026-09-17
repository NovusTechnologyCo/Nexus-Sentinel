// Tutorial Step 2 - Exact Value Scanning
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 2 - Find a value.
/// </summary>
public class TutorialStep2Form : Form
{
    private int _health = 100;
    private readonly Label _lblHealth;
    private readonly Button _btnHitMe;
    private readonly Button _btnNext;

    public TutorialStep2Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 2";
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
            Size = new Size(560, 350),
            Text = @"Step 2: Exact Value Scanning

Now that you have opened the process, let's find the health value.

Health: The value displayed below is the current health. Try to find this value using NS's memory scanner. When found, change it to 1000 to advance.

Note: The value is stored as a 4 byte integer."
        };
        Controls.Add(instructions);

        _lblHealth = new Label
        {
            Text = $"Health: {_health}",
            Location = new Point(10, 390),
            Size = new Size(200, 40),
            Font = new Font("Segoe UI", 14, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        _btnHitMe = new Button
        {
            Text = "Hit me",
            Location = new Point(220, 390),
            Size = new Size(80, 36)
        };
        _btnHitMe.Click += (s, e) =>
        {
            _health -= new Random().Next(1, 10);
            UpdateHealth();
        };
        Controls.Add(_btnHitMe);

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
            new TutorialStep3Form { Location = Location }.Show();
        };
        Controls.Add(_btnNext);

        var timer = new System.Windows.Forms.Timer { Interval = 100 };
        timer.Tick += (s, e) =>
        {
            if (_health >= 1000)
            {
                _btnNext.Enabled = true;
            }
            UpdateHealth();
        };
        timer.Start();

        TutorialNavigation.AddNavigationControls(this, 2);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void UpdateHealth()
    {
        _lblHealth.Text = $"Health: {_health}";
    }
}
