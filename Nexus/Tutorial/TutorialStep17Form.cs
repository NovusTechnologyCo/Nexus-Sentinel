// Tutorial Step 16 - Cheat Table (.CT) Files
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 16 - Cheat Table (.CT) Files.
/// Tests saving and loading CT format.
/// </summary>
public class TutorialStep17Form : Form
{
    private int _health = 100;
    private int _ammo = 50;
    private int _score;
    private readonly Label _lblHealth;
    private readonly Label _lblAmmo;
    private readonly Label _lblScore;
    private readonly Label _lblStatus;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step16Text = @"Step 16: Nexus Sentinel Tables (.NST)

Nexus Sentinel Tables store your addresses, scripts, and settings for reuse.

Below are three game values. Your task:
1. Find all three addresses (Health, Ammo, Score)
2. Add them to your address list with descriptions
3. Save as a .NST file (File -> Save As)
4. Close NS, then reopen and load the .NST file
5. Verify the addresses still work

NST files contain:
- Address entries with descriptions
- Scripts and Auto Assembler code
- Memory records and groups
- Form definitions

Set all three values to 9999 to proceed.";

    public TutorialStep17Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 16";
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
            Size = new Size(560, 200),
            Text = Step16Text
        };
        Controls.Add(instructions);

        // Health
        _lblHealth = new Label
        {
            Text = $"Health: {_health}",
            Location = new Point(10, 225),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        var btnHit = new Button { Text = "Hit", Location = new Point(220, 220), Size = new Size(80, 35) };
        btnHit.Click += (s, e) => { _health -= 10; UpdateLabels(); };
        Controls.Add(btnHit);

        // Ammo
        _lblAmmo = new Label
        {
            Text = $"Ammo: {_ammo}",
            Location = new Point(10, 265),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblAmmo);

        var btnShoot = new Button { Text = "Shoot", Location = new Point(220, 260), Size = new Size(80, 35) };
        btnShoot.Click += (s, e) => { _ammo--; UpdateLabels(); };
        Controls.Add(btnShoot);

        // Score
        _lblScore = new Label
        {
            Text = $"Score: {_score}",
            Location = new Point(10, 305),
            Size = new Size(200, 30),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblScore);

        var btnAddScore = new Button { Text = "+100", Location = new Point(220, 300), Size = new Size(80, 35) };
        btnAddScore.Click += (s, e) => { _score += 100; UpdateLabels(); };
        Controls.Add(btnAddScore);

        _lblStatus = new Label
        {
            Text = "Set all values to 9999 to proceed.",
            Location = new Point(10, 350),
            Size = new Size(400, 25),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblStatus);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep19Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            UpdateLabels();
            if (_health == 9999 && _ammo == 9999 && _score == 9999)
            {
                _btnNext.Enabled = true;
                _lblStatus.Text = "All values set! Table saved successfully.";
                _lblStatus.ForeColor = Color.Green;
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 16);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void UpdateLabels()
    {
        _lblHealth.Text = $"Health: {_health}";
        _lblAmmo.Text = $"Ammo: {_ammo}";
        _lblScore.Text = $"Score: {_score}";
    }
}
