// Nexus Tutorial - Native Win32 Application
// A CE-style tutorial for learning memory scanning techniques
// Compile: cl /O2 /W3 tutorial.c /link user32.lib gdi32.lib comctl32.lib /OUT:NexusTutorial.exe

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Window dimensions
#define WINDOW_WIDTH 550
#define WINDOW_HEIGHT 480

// Control IDs
#define ID_NEXT_BUTTON 1001
#define ID_CHANGE_VALUE 1002
#define ID_VALUE_LABEL 1003
#define ID_INSTRUCTIONS 1004
#define ID_PASSWORD_EDIT 1005
#define ID_PASSWORD_OK 1006
#define ID_HEALTH_BAR 1007
#define ID_HIT_ME 1008
#define ID_AMMO_LABEL 1009
#define ID_FIRE 1010
#define ID_CHANGE_POINTER 1011

// Current step (1-9)
static int g_currentStep = 1;

// Step 1: Simple value to find
static volatile int g_step1Value = 100;

// Step 2: Unknown initial value (decreases)
static volatile int g_step2Health = 100;

// Step 3: Float and double values
static volatile float g_step3Float = 100.0f;
static volatile double g_step3Double = 5000.0;

// Step 4: Multiple values (health + ammo)
static volatile int g_step4Health = 100;
static volatile int g_step4Ammo = 500;

// Step 5: Code finder - value that changes via code
static volatile int g_step5Value = 100;

// Step 6: Pointer - dynamically allocated value
typedef struct {
    int padding[128];  // Random offset
    int value;
    int padding2[64];
} Step6Data;
static Step6Data* g_step6Ptr = NULL;
static volatile int** g_step6BasePtr = NULL;  // Static pointer to the dynamic allocation

// Step 7: Code injection (placeholder)
static volatile int g_step7Health = 100;
static volatile int g_step7Ammo = 500;

// Step 8: Multi-level pointers
typedef struct {
    int padding[32];
    int* valuePtr;
} Level1;
typedef struct {
    int padding[16];
    Level1* level1;
} Level2;
typedef struct {
    int padding[8];
    Level2* level2;
} Level3;
static Level3* g_step8Base = NULL;
static int g_step8Value = 5000;

// Window handles
static HWND g_hWnd = NULL;
static HWND g_hInstructions = NULL;
static HWND g_hValueLabel = NULL;
static HWND g_hNextButton = NULL;
static HWND g_hChangeButton = NULL;
static HWND g_hPasswordLabel = NULL;
static HWND g_hPasswordEdit = NULL;
static HWND g_hPasswordOK = NULL;
static HWND g_hHealthBar = NULL;
static HWND g_hHitMe = NULL;
static HWND g_hAmmoLabel = NULL;
static HWND g_hFire = NULL;
static HWND g_hChangePointer = NULL;
static HFONT g_hFont = NULL;

// Passwords for each step
static const char* g_passwords[] = {
    "",         // Step 0 (unused)
    "090453",   // Step 1
    "419482",   // Step 2
    "890124",   // Step 3
    "525927",   // Step 4
    "888899",   // Step 5
    "098712",   // Step 6
    "013370",   // Step 7
    "525824",   // Step 8
    ""          // Step 9 (final)
};

// Forward declarations
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
void SetupStep(int step);
void UpdateDisplay(void);
void HideAllControls(void);

// Step 5: The function that writes to the value - CAN BE NOP'd
__declspec(noinline) void Step5_WriteValue(int newValue)
{
    // This MOV instruction can be found and NOP'd
    g_step5Value = newValue;
}

// Step 6: Initialize pointer structure
void Step6_Init(void)
{
    if (g_step6Ptr) {
        free(g_step6Ptr);
    }
    g_step6Ptr = (Step6Data*)malloc(sizeof(Step6Data));
    if (g_step6Ptr) {
        memset(g_step6Ptr, 0, sizeof(Step6Data));
        g_step6Ptr->value = 100 + (rand() % 5000);
        // Set up the static pointer
        g_step6BasePtr = (volatile int**)&g_step6Ptr->value;
    }
}

// Step 8: Initialize multi-level pointer
void Step8_Init(void)
{
    g_step8Base = (Level3*)malloc(sizeof(Level3));
    g_step8Base->level2 = (Level2*)malloc(sizeof(Level2));
    g_step8Base->level2->level1 = (Level1*)malloc(sizeof(Level1));
    g_step8Base->level2->level1->valuePtr = &g_step8Value;
}

// Get instruction text for each step
const char* GetStepInstructions(int step)
{
    switch (step) {
    case 1:
        return "Step 1: Exact Value (PW=090453)\r\n\r\n"
               "Welcome to the Nexus Tutorial!\r\n\r\n"
               "This tutorial will teach you the basics of memory scanning.\r\n\r\n"
               "The value below is your health. It starts at 100.\r\n"
               "Use Nexus to find this exact value in memory.\r\n\r\n"
               "Steps:\r\n"
               "1. Open Nexus and attach to this process\r\n"
               "2. Scan for '100' (Exact Value, 4 Bytes)\r\n"
               "3. Click 'Hit me' to change the value\r\n"
               "4. Scan for the new value\r\n"
               "5. Repeat until one address remains\r\n"
               "6. Change it to 1000 to enable Next";

    case 2:
        return "Step 2: Unknown Initial Value (PW=419482)\r\n\r\n"
               "Now you have a status bar. The bar shows your health.\r\n"
               "You don't know the exact value, but you know it decreases.\r\n\r\n"
               "Steps:\r\n"
               "1. Do an 'Unknown initial value' scan\r\n"
               "2. Click 'Hit me' to decrease health\r\n"
               "3. Do a 'Decreased value' scan\r\n"
               "4. Repeat until one address remains\r\n"
               "5. Set health above 5000 to enable Next";

    case 3:
        return "Step 3: Floating Point (PW=890124)\r\n\r\n"
               "Some games use floating point values.\r\n"
               "Here are two values: a float and a double.\r\n\r\n"
               "Health (float): Starts at 100.0\r\n"
               "Ammo (double): Starts at 5000.0\r\n\r\n"
               "Find both values and set:\r\n"
               "- Health to 5000 or more\r\n"
               "- Ammo to exactly 5000\r\n\r\n"
               "Remember to select the correct value type!";

    case 4:
        return "Step 4: Multiple Values (PW=525927)\r\n\r\n"
               "Games often have multiple values to track.\r\n"
               "Here you have Health and Ammo (both integers).\r\n\r\n"
               "Health: 100 (decreases when hit)\r\n"
               "Ammo: 500 (decreases when firing)\r\n\r\n"
               "Find both values. To proceed:\r\n"
               "- Set Health to 5000 or more\r\n"
               "- Set Ammo to 5000 or more";

    case 5:
        return "Step 5: Code Finder (PW=888899)\r\n\r\n"
               "Sometimes the value's address changes when you\r\n"
               "restart the game. The Code Finder helps with this.\r\n\r\n"
               "Steps:\r\n"
               "1. Find the value's address (starts at 100)\r\n"
               "2. Right-click and select 'Find out what writes'\r\n"
               "3. Click 'Change value' to trigger the write\r\n"
               "4. An instruction address should appear\r\n"
               "5. Click 'Replace' to NOP the instruction\r\n"
               "6. Click 'Change value' again - it should NOT change\r\n"
               "7. If the value stays the same, Next will enable";

    case 6:
        return "Step 6: Pointers (PW=098712)\r\n\r\n"
               "The value is stored at a dynamically allocated address.\r\n"
               "A pointer points to this address.\r\n\r\n"
               "Steps:\r\n"
               "1. Find the current value\r\n"
               "2. Use 'Find what writes' to see the instruction\r\n"
               "3. Look at the instruction - it shows [reg+offset]\r\n"
               "4. Scan for the base pointer value (shown in Extra Info)\r\n"
               "5. Add the address as a pointer with the offset\r\n"
               "6. Change value to 5000 and freeze it\r\n"
               "7. Click 'Change pointer' - if it stays 5000, Next enables";

    case 7:
        return "Step 7: Code Injection (PW=013370)\r\n\r\n"
               "Code injection lets you run your own code.\r\n\r\n"
               "Health decreases when hit, Ammo decreases when firing.\r\n"
               "Your goal: Make both INCREASE instead of decrease!\r\n\r\n"
               "Steps:\r\n"
               "1. Find what writes to Health\r\n"
               "2. Use 'Show disassembler'\r\n"
               "3. Use Auto Assemble -> Template -> AOB Injection\r\n"
               "4. Change SUB to ADD in your script\r\n"
               "5. Do the same for Ammo\r\n"
               "6. When both increase instead of decrease, Next enables";

    case 8:
        return "Step 8: Multi-level Pointers (PW=525824)\r\n\r\n"
               "Some games use multiple pointer levels.\r\n"
               "The value is: [[[[base]+offset1]+offset2]+offset3]\r\n\r\n"
               "Steps:\r\n"
               "1. Find the value (5000)\r\n"
               "2. Do a pointer scan for this address\r\n"
               "3. Find the pointer path starting with the exe\r\n"
               "4. Add it as a multi-level pointer\r\n"
               "5. Click 'Change pointer' - value will change\r\n"
               "6. If your pointer still shows correct value, Next enables";

    case 9:
        return "Congratulations!\r\n\r\n"
               "You have completed the Nexus Tutorial!\r\n\r\n"
               "You've learned:\r\n"
               "- Exact value scanning\r\n"
               "- Unknown value scanning\r\n"
               "- Float and double scanning\r\n"
               "- Code finding and NOPing\r\n"
               "- Basic pointers\r\n"
               "- Code injection concepts\r\n"
               "- Multi-level pointers\r\n\r\n"
               "Now go forth and explore real applications!\r\n\r\n"
               "Remember: Only use these techniques on\r\n"
               "software you own or have permission to modify.";

    default:
        return "Unknown step";
    }
}

void HideAllControls(void)
{
    ShowWindow(g_hValueLabel, SW_HIDE);
    ShowWindow(g_hChangeButton, SW_HIDE);
    ShowWindow(g_hPasswordEdit, SW_HIDE);
    ShowWindow(g_hPasswordOK, SW_HIDE);
    ShowWindow(g_hHealthBar, SW_HIDE);
    ShowWindow(g_hHitMe, SW_HIDE);
    ShowWindow(g_hAmmoLabel, SW_HIDE);
    ShowWindow(g_hFire, SW_HIDE);
    ShowWindow(g_hChangePointer, SW_HIDE);
}

void SetupStep(int step)
{
    char title[64];
    sprintf(title, "Nexus Tutorial - Step %d", step);
    SetWindowTextA(g_hWnd, title);

    HideAllControls();
    EnableWindow(g_hNextButton, FALSE);

    // Set instructions
    SetWindowTextA(g_hInstructions, GetStepInstructions(step));

    switch (step) {
    case 1:
        g_step1Value = 100;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hHitMe, SW_SHOW);
        break;

    case 2:
        g_step2Health = 100;
        ShowWindow(g_hHealthBar, SW_SHOW);
        ShowWindow(g_hHitMe, SW_SHOW);
        SendMessage(g_hHealthBar, PBM_SETPOS, g_step2Health, 0);
        break;

    case 3:
        g_step3Float = 100.0f;
        g_step3Double = 5000.0;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hHitMe, SW_SHOW);
        ShowWindow(g_hAmmoLabel, SW_SHOW);
        ShowWindow(g_hFire, SW_SHOW);
        break;

    case 4:
        g_step4Health = 100;
        g_step4Ammo = 500;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hHitMe, SW_SHOW);
        ShowWindow(g_hAmmoLabel, SW_SHOW);
        ShowWindow(g_hFire, SW_SHOW);
        break;

    case 5:
        g_step5Value = 100;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hChangeButton, SW_SHOW);
        break;

    case 6:
        Step6_Init();
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hChangePointer, SW_SHOW);
        break;

    case 7:
        g_step7Health = 100;
        g_step7Ammo = 500;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hHitMe, SW_SHOW);
        ShowWindow(g_hAmmoLabel, SW_SHOW);
        ShowWindow(g_hFire, SW_SHOW);
        break;

    case 8:
        if (!g_step8Base) Step8_Init();
        g_step8Value = 5000;
        ShowWindow(g_hValueLabel, SW_SHOW);
        ShowWindow(g_hChangePointer, SW_SHOW);
        break;

    case 9:
        // Final step - just show congrats
        break;
    }

    UpdateDisplay();
}

void UpdateDisplay(void)
{
    char buf[128];

    switch (g_currentStep) {
    case 1:
        sprintf(buf, "Value: %d", g_step1Value);
        SetWindowTextA(g_hValueLabel, buf);
        if (g_step1Value == 1000) EnableWindow(g_hNextButton, TRUE);
        break;

    case 2:
        SendMessage(g_hHealthBar, PBM_SETPOS, g_step2Health > 0 ? g_step2Health : 0, 0);
        if (g_step2Health > 5000) EnableWindow(g_hNextButton, TRUE);
        break;

    case 3:
        sprintf(buf, "Health: %.2f", g_step3Float);
        SetWindowTextA(g_hValueLabel, buf);
        sprintf(buf, "Ammo: %.2f", g_step3Double);
        SetWindowTextA(g_hAmmoLabel, buf);
        if (g_step3Float >= 5000.0f && g_step3Double == 5000.0)
            EnableWindow(g_hNextButton, TRUE);
        break;

    case 4:
        sprintf(buf, "Health: %d", g_step4Health);
        SetWindowTextA(g_hValueLabel, buf);
        sprintf(buf, "Ammo: %d", g_step4Ammo);
        SetWindowTextA(g_hAmmoLabel, buf);
        if (g_step4Health >= 5000 && g_step4Ammo >= 5000)
            EnableWindow(g_hNextButton, TRUE);
        break;

    case 5:
        sprintf(buf, "Value: %d", g_step5Value);
        SetWindowTextA(g_hValueLabel, buf);
        break;

    case 6:
        if (g_step6Ptr) {
            sprintf(buf, "Value: %d", g_step6Ptr->value);
            SetWindowTextA(g_hValueLabel, buf);
        }
        break;

    case 7:
        sprintf(buf, "Health: %d", g_step7Health);
        SetWindowTextA(g_hValueLabel, buf);
        sprintf(buf, "Ammo: %d", g_step7Ammo);
        SetWindowTextA(g_hAmmoLabel, buf);
        break;

    case 8:
        sprintf(buf, "Value: %d", g_step8Value);
        SetWindowTextA(g_hValueLabel, buf);
        break;

    case 9:
        EnableWindow(g_hNextButton, FALSE);
        break;
    }
}

// Timer callback for continuous value checking
void CALLBACK TimerProc(HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    UpdateDisplay();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static int step5_lastValue = 0;

    switch (message) {
    case WM_CREATE:
        {
            // Initialize common controls
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(icex);
            icex.dwICC = ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);

            // Create a nice font
            g_hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

            // Create instructions text box (read-only multiline edit for scrolling)
            g_hInstructions = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                15, 15, WINDOW_WIDTH - 45, 220,
                hWnd, (HMENU)ID_INSTRUCTIONS, NULL, NULL);
            SendMessage(g_hInstructions, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // === Step controls (below instructions) ===
            int ctrlY = 250;  // Starting Y position for step controls

            // Value label (Health/Value display)
            g_hValueLabel = CreateWindowExA(0, "STATIC", "Value: 100",
                WS_CHILD | SS_LEFT,
                20, ctrlY, 180, 25,
                hWnd, (HMENU)ID_VALUE_LABEL, NULL, NULL);
            SendMessage(g_hValueLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Change value button (Step 5)
            g_hChangeButton = CreateWindowExA(0, "BUTTON", "Change value",
                WS_CHILD | BS_PUSHBUTTON,
                210, ctrlY - 3, 110, 28,
                hWnd, (HMENU)ID_CHANGE_VALUE, NULL, NULL);
            SendMessage(g_hChangeButton, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Hit me button
            g_hHitMe = CreateWindowExA(0, "BUTTON", "Hit me",
                WS_CHILD | BS_PUSHBUTTON,
                210, ctrlY - 3, 90, 28,
                hWnd, (HMENU)ID_HIT_ME, NULL, NULL);
            SendMessage(g_hHitMe, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Change pointer button (Step 6, 8)
            g_hChangePointer = CreateWindowExA(0, "BUTTON", "Change pointer",
                WS_CHILD | BS_PUSHBUTTON,
                210, ctrlY - 3, 130, 28,
                hWnd, (HMENU)ID_CHANGE_POINTER, NULL, NULL);
            SendMessage(g_hChangePointer, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Health bar (Step 2)
            g_hHealthBar = CreateWindowExA(0, PROGRESS_CLASSA, "",
                WS_CHILD | PBS_SMOOTH,
                20, ctrlY + 30, 280, 22,
                hWnd, (HMENU)ID_HEALTH_BAR, NULL, NULL);
            SendMessage(g_hHealthBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

            // Ammo label (second value row)
            g_hAmmoLabel = CreateWindowExA(0, "STATIC", "Ammo: 500",
                WS_CHILD | SS_LEFT,
                20, ctrlY + 35, 180, 25,
                hWnd, (HMENU)ID_AMMO_LABEL, NULL, NULL);
            SendMessage(g_hAmmoLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Fire button
            g_hFire = CreateWindowExA(0, "BUTTON", "Fire",
                WS_CHILD | BS_PUSHBUTTON,
                210, ctrlY + 32, 90, 28,
                hWnd, (HMENU)ID_FIRE, NULL, NULL);
            SendMessage(g_hFire, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // === Password section (bottom of window) ===
            int pwY = WINDOW_HEIGHT - 80;

            // Password label
            g_hPasswordLabel = CreateWindowExA(0, "STATIC", "Password:",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                20, pwY + 5, 70, 20,
                hWnd, (HMENU)0, NULL, NULL);
            SendMessage(g_hPasswordLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Password edit
            g_hPasswordEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                95, pwY, 100, 26,
                hWnd, (HMENU)ID_PASSWORD_EDIT, NULL, NULL);
            SendMessage(g_hPasswordEdit, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Password OK button
            g_hPasswordOK = CreateWindowExA(0, "BUTTON", "OK",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                205, pwY, 55, 26,
                hWnd, (HMENU)ID_PASSWORD_OK, NULL, NULL);
            SendMessage(g_hPasswordOK, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Next button (bottom right)
            g_hNextButton = CreateWindowExA(0, "BUTTON", "Next",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                WINDOW_WIDTH - 110, pwY, 85, 30,
                hWnd, (HMENU)ID_NEXT_BUTTON, NULL, NULL);
            SendMessage(g_hNextButton, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            EnableWindow(g_hNextButton, FALSE);

            // Set up timer for value checking
            SetTimer(hWnd, 1, 100, TimerProc);

            // Initialize step 1
            SetupStep(1);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_NEXT_BUTTON:
            if (g_currentStep < 9) {
                g_currentStep++;
                SetupStep(g_currentStep);
            }
            break;

        case ID_CHANGE_VALUE:
            if (g_currentStep == 5) {
                step5_lastValue = g_step5Value;
                Step5_WriteValue(g_step5Value + (rand() % 10) + 1);
                // Check if the value actually changed
                if (g_step5Value == step5_lastValue) {
                    // Code was NOP'd! Enable next
                    EnableWindow(g_hNextButton, TRUE);
                }
                UpdateDisplay();
            }
            break;

        case ID_HIT_ME:
            switch (g_currentStep) {
            case 1:
                g_step1Value -= (rand() % 5) + 1;
                break;
            case 2:
                g_step2Health -= (rand() % 10) + 5;
                if (g_step2Health < 0) g_step2Health = 0;
                break;
            case 3:
                g_step3Float -= (float)((rand() % 10) + 1) / 2.0f;
                break;
            case 4:
                g_step4Health -= (rand() % 10) + 5;
                break;
            case 7:
                g_step7Health -= 5;
                if (g_step7Health > 100) EnableWindow(g_hNextButton, TRUE); // Increased instead
                break;
            }
            UpdateDisplay();
            break;

        case ID_FIRE:
            switch (g_currentStep) {
            case 3:
                g_step3Double -= (rand() % 100) + 10;
                break;
            case 4:
                g_step4Ammo -= (rand() % 5) + 1;
                break;
            case 7:
                g_step7Ammo -= 5;
                if (g_step7Ammo > 500) EnableWindow(g_hNextButton, TRUE); // Increased instead
                break;
            }
            UpdateDisplay();
            break;

        case ID_CHANGE_POINTER:
            if (g_currentStep == 6) {
                // Reallocate to new address
                int oldValue = g_step6Ptr ? g_step6Ptr->value : 0;
                Step6_Init();
                // Check if user's frozen value persisted
                if (g_step6Ptr->value == 5000) {
                    EnableWindow(g_hNextButton, TRUE);
                }
                UpdateDisplay();
            } else if (g_currentStep == 8) {
                // Change the pointed value
                g_step8Value = rand() % 5000 + 1000;
                UpdateDisplay();
            }
            break;

        case ID_PASSWORD_OK:
            // Check password
            {
                char pw[32];
                GetWindowTextA(g_hPasswordEdit, pw, sizeof(pw));
                for (int i = 1; i <= 8; i++) {
                    if (strcmp(pw, g_passwords[i]) == 0) {
                        g_currentStep = i;
                        SetupStep(g_currentStep);
                        break;
                    }
                }
            }
            break;
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hWnd, 1);
        if (g_hFont) DeleteObject(g_hFont);
        if (g_step6Ptr) free(g_step6Ptr);
        if (g_step8Base) {
            if (g_step8Base->level2) {
                if (g_step8Base->level2->level1) free(g_step8Base->level2->level1);
                free(g_step8Base->level2);
            }
            free(g_step8Base);
        }
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    srand((unsigned int)time(NULL));

    // Register window class
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "NexusTutorialClass";

    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class", "Error", MB_ICONERROR);
        return 1;
    }

    // Create window
    g_hWnd = CreateWindowExA(
        0, "NexusTutorialClass", "Nexus Tutorial - Step 1",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInstance, NULL);

    if (!g_hWnd) {
        MessageBoxA(NULL, "Failed to create window", "Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
