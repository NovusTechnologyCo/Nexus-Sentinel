// Tutorial Step 17 - Structure/Group Scanning
// Split from TutorialForms.cs for maintainability

using System.Drawing;
using System.Runtime.InteropServices;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 17 - Structure/Group Scanning.
/// Tests finding related values in structures.
/// </summary>
public class TutorialStep19Form : Form
{
    // Player structure in pinned memory (20 bytes total):
    // Offset +0: X (float), +4: Y (float), +8: Z (float), +12: Health (int), +16: Armor (int)
    private readonly byte[] _playerStruct = new byte[20];
    private GCHandle _pinnedHandle;
    private IntPtr _structAddress;
    private readonly Label _lblAddress;
    private readonly Label _lblCoords;
    private readonly Label _lblStats;
    private readonly Label _lblStatus;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step17Text = @"Step 17: Structure Dissection

Game data is often stored in structures - sequential memory containing related values. In 3D games, player structures typically contain position, health, ammo, team ID, etc.

Below is a player structure with 5 consecutive values:
  Offset +0: X position (float)
  Offset +4: Y position (float)
  Offset +8: Z position (float)
  Offset +12: Health (4 bytes)
  Offset +16: Armor (4 bytes)

Your task:
1. Use the structure address shown below
2. In Memory Viewer: Tools -> 'Dissect data/structures'
3. Enter the address, then: Structures -> 'Define new structure'
4. Name it 'Player', size 20 bytes
5. Identify all 5 fields at their offsets
6. Set: X=999, Y=999, Z=999, Health=999, Armor=999";

    // Property accessors for structure fields
    private float PlayerX
    {
        get => BitConverter.ToSingle(_playerStruct, 0);
        set => Array.Copy(BitConverter.GetBytes(value), 0, _playerStruct, 0, 4);
    }
    private float PlayerY
    {
        get => BitConverter.ToSingle(_playerStruct, 4);
        set => Array.Copy(BitConverter.GetBytes(value), 0, _playerStruct, 4, 4);
    }
    private float PlayerZ
    {
        get => BitConverter.ToSingle(_playerStruct, 8);
        set => Array.Copy(BitConverter.GetBytes(value), 0, _playerStruct, 8, 4);
    }
    private int PlayerHealth
    {
        get => BitConverter.ToInt32(_playerStruct, 12);
        set => Array.Copy(BitConverter.GetBytes(value), 0, _playerStruct, 12, 4);
    }
    private int PlayerArmor
    {
        get => BitConverter.ToInt32(_playerStruct, 16);
        set => Array.Copy(BitConverter.GetBytes(value), 0, _playerStruct, 16, 4);
    }

    public TutorialStep19Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 17";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        // Pin the structure in memory
        _pinnedHandle = GCHandle.Alloc(_playerStruct, GCHandleType.Pinned);
        _structAddress = _pinnedHandle.AddrOfPinnedObject();

        // Initialize structure values
        PlayerX = 100.0f;
        PlayerY = 50.0f;
        PlayerZ = 0.0f;
        PlayerHealth = 100;
        PlayerArmor = 50;

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(580, 200),
            Text = Step17Text
        };
        Controls.Add(instructions);

        _lblAddress = new Label
        {
            Text = $"Structure Address: {_structAddress:X}",
            Location = new Point(10, 220),
            Size = new Size(400, 25),
            Font = new Font("Consolas", 11, FontStyle.Bold),
            ForeColor = Color.Blue
        };
        Controls.Add(_lblAddress);

        _lblCoords = new Label
        {
            Text = $"Position: X={PlayerX:F1}, Y={PlayerY:F1}, Z={PlayerZ:F1}",
            Location = new Point(10, 255),
            Size = new Size(400, 30),
            Font = new Font("Segoe UI", 11, FontStyle.Bold)
        };
        Controls.Add(_lblCoords);

        var btnMove = new Button { Text = "Move", Location = new Point(420, 252), Size = new Size(80, 35) };
        btnMove.Click += (s, e) =>
        {
            PlayerX += new Random().Next(-10, 10);
            PlayerY += new Random().Next(-10, 10);
            PlayerZ += new Random().Next(-5, 5);
            UpdateLabels();
        };
        Controls.Add(btnMove);

        _lblStats = new Label
        {
            Text = $"Health: {PlayerHealth}  |  Armor: {PlayerArmor}",
            Location = new Point(10, 295),
            Size = new Size(350, 30),
            Font = new Font("Segoe UI", 11, FontStyle.Bold)
        };
        Controls.Add(_lblStats);

        var btnDamage = new Button { Text = "Damage", Location = new Point(370, 292), Size = new Size(100, 35) };
        btnDamage.Click += (s, e) =>
        {
            int dmg = new Random().Next(5, 15);
            int armor = PlayerArmor;
            int health = PlayerHealth;
            if (armor > 0)
            {
                armor -= dmg;
                if (armor < 0)
                {
                    health += armor;
                    armor = 0;
                }
            }
            else
            {
                health -= dmg;
            }
            if (health < 0) health = 0;
            PlayerArmor = armor;
            PlayerHealth = health;
            UpdateLabels();
        };
        Controls.Add(btnDamage);

        _lblStatus = new Label
        {
            Text = "Set all 5 structure values to 999",
            Location = new Point(10, 345),
            Size = new Size(400, 25),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblStatus);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep21Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            UpdateLabels();
            if (Math.Abs(PlayerX - 999) < 1 && Math.Abs(PlayerY - 999) < 1 && Math.Abs(PlayerZ - 999) < 1 &&
                PlayerHealth == 999 && PlayerArmor == 999)
            {
                _btnNext.Enabled = true;
                _lblStatus.Text = "Structure fully mapped!";
                _lblStatus.ForeColor = Color.Green;
            }
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 17);
        FormClosing += (s, e) =>
        {
            if (_pinnedHandle.IsAllocated) _pinnedHandle.Free();
            Environment.Exit(0);
        };
    }

    private void UpdateLabels()
    {
        _lblCoords.Text = $"Position: X={PlayerX:F1}, Y={PlayerY:F1}, Z={PlayerZ:F1}";
        _lblStats.Text = $"Health: {PlayerHealth}  |  Armor: {PlayerArmor}";
    }
}
