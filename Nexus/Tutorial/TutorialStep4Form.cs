// Tutorial Step 4 - Floating Points
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 4 - Floating Points (health=float, ammo=double).
/// </summary>
public class TutorialStep4Form : Form
{
    private float _health = 100.0f;
    private double _ammo = 100.0;
    private readonly Label _lblHealth;
    private readonly Label _lblAmmo;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step4Text = @"Step 4: Floating Points

In the previous tutorial we used bytes to scan, but some games store information in so called 'floating point' notations. (probably to prevent simple memory scanners from finding it the easy way)
A floating point is a value with some digits behind the point. (like 5.12 or 11321.1)

Below you see your health and ammo. Both are stored as Floating point notations, but health is stored as a float and ammo is stored as a double.
Click on Hit me to lose some health, and on Shoot to decrease your ammo with 0.5

You have to set BOTH values to 5000 or higher to proceed.

Exact value scan will work fine here, but you may want to experiment with other types too.

Hint: It is recommended to disable ""Fast Scan"" for type double";

    public TutorialStep4Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 4";
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
            Size = new Size(560, 300),
            Text = Step4Text
        };
        Controls.Add(instructions);

        // Health (float)
        var lblHealthTitle = new Label
        {
            Text = "Health (Float):",
            Location = new Point(10, 325),
            AutoSize = true
        };
        Controls.Add(lblHealthTitle);

        _lblHealth = new Label
        {
            Text = _health.ToString("F2"),
            Location = new Point(170, 325),
            Size = new Size(100, 28),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblHealth);

        var btnHitMe = new Button
        {
            Text = "Hit me",
            Location = new Point(280, 320),
            Size = new Size(80, 33)
        };
        btnHitMe.Click += BtnHitMe_Click;
        Controls.Add(btnHitMe);

        // Ammo (double)
        var lblAmmoTitle = new Label
        {
            Text = "Ammo (Double):",
            Location = new Point(10, 370),
            AutoSize = true
        };
        Controls.Add(lblAmmoTitle);

        _lblAmmo = new Label
        {
            Text = _ammo.ToString("F2"),
            Location = new Point(170, 370),
            Size = new Size(100, 28),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblAmmo);

        var btnShoot = new Button
        {
            Text = "Shoot",
            Location = new Point(280, 365),
            Size = new Size(80, 33)
        };
        btnShoot.Click += BtnShoot_Click;
        Controls.Add(btnShoot);

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
            new TutorialStep5Form { Location = Location }.Show();
        };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_health >= 5000 && _ammo >= 5000)
            {
                _btnNext.Enabled = true;
                _checkTimer.Stop();
            }
            UpdateLabels();
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 4);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void BtnHitMe_Click(object? sender, EventArgs e)
    {
        float loss = new Random().Next(4) + (1 + new Random().Next(10) / 10.0f);
        _health -= loss;

        if (_health <= 0)
        {
            MessageBox.Show("I think you're dead!\nPress OK to become a brain eating zombie",
                "Dead!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _health = 100.0f;
        }
        UpdateLabels();
    }

    private void BtnShoot_Click(object? sender, EventArgs e)
    {
        _ammo -= 0.5;

        if (_ammo <= 0)
        {
            MessageBox.Show("Out of ammo!\nPress OK to stock up on some ammo",
                "Empty!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _ammo = 100.0;
        }
        UpdateLabels();
    }

    private void UpdateLabels()
    {
        _lblHealth.Text = _health.ToString("F2");
        _lblAmmo.Text = _ammo.ToString("F2");
    }
}
