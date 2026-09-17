// Tutorial Step 3 - Unknown Initial Value
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 3 - Unknown Initial Value.
/// </summary>
public class TutorialStep3Form : Form
{
    private int _health;
    private readonly ProgressBar _progressBar;
    private readonly Label _lblDamage;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;
    private readonly System.Windows.Forms.Timer _damageTimer;

    private const string Step3Text = @"Step 3: Unknown Initial Value

Ok, seeing that you've figured out how to find a value using exact value let's move on to the next step.

First things first though. Since you are doing a new scan, you have to click on New Scan first, to start a new scan. (You may think this is straightforward, but you'd be surprised how many people get stuck on that step) I won't be explaining this step again, so keep this in mind.

In the previous test we knew the initial value so we could do an exact value search, but now we have a status bar where we don't know the starting value.
We only know that the value is between 0 and 500. And each time you click 'Hit me' you lose some health. The amount you lose each time is shown above the status bar.

Again there are several different ways to find the value. (like doing a decreased value by... scan), but I'll only explain the easiest. ""Unknown initial value"", and decreased value.

Because you don't know the value it is right now, exact value won't do any good, so choose as scantype 'Unknown initial value', again, the value type is 4-bytes. (Most windows apps use 4-bytes.) Click First scan and wait till it's done.

When it is done click 'Hit me'. You'll lose some of your health. (the amount you lost shows for a few seconds and then disappears, but you don't need that)
Now go to Nexus Sentinel, and choose 'Decreased Value' and click 'Next Scan'
When that scan is done, click 'Hit me' again, and repeat the above till you only find a few.

We know the value is between 0 and 500, so pick the one that is most likely the address we need, and add it to the list.
Now change the health to 5000, to proceed to the next step.";

    public TutorialStep3Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 3";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        _health = 100 + new Random().Next(401);  // 100-500

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 300),
            Text = Step3Text
        };
        Controls.Add(instructions);

        _lblDamage = new Label
        {
            Text = "",
            Location = new Point(10, 320),
            Size = new Size(100, 25),
            ForeColor = Color.Red,
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblDamage);

        _progressBar = new ProgressBar
        {
            Location = new Point(10, 350),
            Size = new Size(400, 25),
            Minimum = 0,
            Maximum = 500,
            Value = Math.Min(_health, 500)
        };
        Controls.Add(_progressBar);

        var btnHitMe = new Button
        {
            Text = "Hit me",
            Location = new Point(420, 345),
            Size = new Size(80, 35)
        };
        btnHitMe.Click += BtnHitMe_Click;
        Controls.Add(btnHitMe);

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
            new TutorialStep4Form { Location = Location }.Show();
        };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_health >= 5000)
            {
                _btnNext.Enabled = true;
                _checkTimer.Stop();
            }
            UpdateProgress();
        };
        _checkTimer.Start();

        _damageTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _damageTimer.Tick += (s, e) =>
        {
            _lblDamage.Text = "";
            _damageTimer.Stop();
        };

        TutorialNavigation.AddNavigationControls(this, 3);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void BtnHitMe_Click(object? sender, EventArgs e)
    {
        int loss = 1 + new Random().Next(10);
        _health -= loss;

        if (_health < 0)
        {
            MessageBox.Show("Seems you've done it again! Let me get a replacement! (And restart your scan!)",
                "Dead!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _health = 100 + new Random().Next(401);  // 100-500
        }
        else
        {
            _lblDamage.Text = $"-{loss}";
            _damageTimer.Stop();
            _damageTimer.Start();
        }
        UpdateProgress();
    }

    private void UpdateProgress()
    {
        _progressBar.Value = Math.Max(0, Math.Min(_health, 500));
    }
}
