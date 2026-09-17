// Tutorial Step 9 - Shared Code
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 9 - Shared Code.
/// Teaches identifying shared code between different game entities.
/// </summary>
public class TutorialStep9Form : Form
{
    private const string NativeDll = "tutorial_native.dll";

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step9_Init();

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr Step9_GetActor(int index);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern float Step9_GetHealth(int index);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern int Step9_GetTeam(int index);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step9_Attack(int actorIndex);

    [DllImport(NativeDll, CallingConvention = CallingConvention.StdCall)]
    private static extern void Step9_Cleanup();

    private readonly Label[] _lblActors = new Label[4];
    private readonly Button[] _btnAttacks = new Button[4];
    private readonly Button _btnNext;
    private readonly Button _btnAttackAll;
    private bool _nativeLoaded = false;

    // Actor names for display
    private static readonly string[] ActorNames = { "Dave", "Eric", "HAL", "Killbot" };

    private const string Step9Text = @"Step 9: Shared Code

This step explains how to deal with code that is shared by multiple objects.

Often when you've found health of a unit or your own player, you'll find that if you
remove the code, it affects enemies as well. This is because the game uses the SAME
function to deal damage to ALL actors.

Below are 4 actors: Dave & Eric (your team), HAL & Killbot (enemies).
All use the SAME damage function in tutorial_native.dll.

Your task:
1. Find Dave's health (float, starts at 100)
2. Use 'Find what writes' to locate the shared damage code
3. Notice ALL actors use the same instruction!
4. Use 'More information' to compare register values between actors
5. Find the team ID at offset +10 from the actor pointer (1=ally, 2=enemy)
6. Inject code to skip damage when team == 1 (your team)

Structure: [actor+08] = health (float), [actor+10] = team (int)

When both enemies are dead and your team still has health, Next enables.";

    public TutorialStep9Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 9";
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
            Text = Step9Text
        };
        Controls.Add(instructions);

        // Create labels and buttons for each actor
        // Layout: Left column = allies (Dave, Eric), Right column = enemies (HAL, Killbot)
        // Actor indices: 0=Dave, 1=Eric, 2=HAL, 3=Killbot
        int yPos = 230;
        int[] layoutOrder = { 0, 2, 1, 3 }; // Row 0: Dave, HAL; Row 1: Eric, Killbot

        for (int pos = 0; pos < 4; pos++)
        {
            int actorIndex = layoutOrder[pos];
            bool isAlly = (actorIndex < 2);
            int col = pos % 2;  // 0 = left (allies), 1 = right (enemies)
            int row = pos / 2;  // 0 = first row, 1 = second row

            _lblActors[actorIndex] = new Label
            {
                Text = $"{ActorNames[actorIndex]}: ---",
                Location = new Point(10 + col * 280, yPos + row * 50),
                Size = new Size(150, 25),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = isAlly ? Color.Green : Color.Red
            };
            Controls.Add(_lblActors[actorIndex]);

            _btnAttacks[actorIndex] = new Button
            {
                Text = "Attack",
                Location = new Point(160 + col * 280, yPos + row * 50 - 5),
                Size = new Size(80, 35)
            };
            _btnAttacks[actorIndex].Click += (s, e) => AttackActor(actorIndex);
            Controls.Add(_btnAttacks[actorIndex]);
        }

        // Team labels
        var lblTeam1 = new Label { Text = "Your Team (1)", Location = new Point(10, yPos - 25), AutoSize = true, ForeColor = Color.Green };
        var lblTeam2 = new Label { Text = "Enemies (2)", Location = new Point(290, yPos - 25), AutoSize = true, ForeColor = Color.Red };
        Controls.Add(lblTeam1);
        Controls.Add(lblTeam2);

        // Attack All button
        _btnAttackAll = new Button
        {
            Text = "Attack All",
            Location = new Point(10, 370),
            Size = new Size(100, 35)
        };
        _btnAttackAll.Click += (s, e) =>
        {
            for (int i = 0; i < 4; i++)
                AttackActor(i);
        };
        Controls.Add(_btnAttackAll);

        // Restart button
        var btnRestart = new Button
        {
            Text = "Restart",
            Location = new Point(120, 370),
            Size = new Size(80, 35)
        };
        btnRestart.Click += (s, e) =>
        {
            if (!_nativeLoaded) return;
            // Run on background thread so CE breakpoints don't crash the app
            System.Threading.Tasks.Task.Run(() =>
            {
                try { Step9_Init(); } catch { }
            }).ContinueWith(_ => BeginInvoke(new Action(UpdateLabels)));
        };
        Controls.Add(btnRestart);

        // Auto Attack button - attacks all until one team is dead
        var btnAutoAttack = new Button
        {
            Text = "Auto Attack",
            Location = new Point(210, 370),
            Size = new Size(100, 35)
        };
        btnAutoAttack.Click += (s, e) =>
        {
            if (!_nativeLoaded) return;

            // Run on background thread so CE breakpoints don't crash the app
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    // Attack all until one team is wiped out
                    while (true)
                    {
                        // Check if allies are all dead (Dave and Eric)
                        float daveHealth = Step9_GetHealth(0);
                        float ericHealth = Step9_GetHealth(1);
                        if (daveHealth <= 0 && ericHealth <= 0)
                            break;

                        // Check if enemies are all dead (HAL and Killbot)
                        float halHealth = Step9_GetHealth(2);
                        float killbotHealth = Step9_GetHealth(3);
                        if (halHealth <= 0 && killbotHealth <= 0)
                            break;

                        // Attack all actors
                        for (int i = 0; i < 4; i++)
                            Step9_Attack(i);
                    }
                }
                catch { }
            }).ContinueWith(_ => BeginInvoke(new Action(UpdateLabels)));
        };
        Controls.Add(btnAutoAttack);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep10Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        // Initialize native
        try
        {
            Step9_Init();
            _nativeLoaded = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load tutorial_native.dll:\n{ex.Message}", "DLL Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        TutorialNavigation.AddNavigationControls(this, 9);
        FormClosing += (s, e) => { if (_nativeLoaded) Step9_Cleanup(); Environment.Exit(0); };

        UpdateLabels();
    }

    private void AttackActor(int index)
    {
        if (!_nativeLoaded) return;

        // Run on background thread so CE breakpoints don't freeze UI
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                Step9_Attack(index);
            }
            catch { }
        }).ContinueWith(_ =>
        {
            BeginInvoke(new Action(UpdateLabels));
        });
    }

    private void UpdateLabels()
    {
        if (!_nativeLoaded) return;

        try
        {
            for (int i = 0; i < 4; i++)
            {
                float health = Step9_GetHealth(i);
                _lblActors[i].Text = $"{ActorNames[i]}: {health:F0}";
            }
            CheckWinCondition();
        }
        catch { }
    }

    private void CheckWinCondition()
    {
        if (!_nativeLoaded) return;

        // Win condition: Both enemies at 0 AND at least one ally still has health
        float daveHealth = Step9_GetHealth(0);
        float ericHealth = Step9_GetHealth(1);
        float halHealth = Step9_GetHealth(2);
        float killbotHealth = Step9_GetHealth(3);

        bool enemiesDead = halHealth <= 0 && killbotHealth <= 0;
        bool alliesAlive = daveHealth > 0 || ericHealth > 0;

        if (enemiesDead && alliesAlive)
        {
            _btnNext.Enabled = true;
        }
    }
}
