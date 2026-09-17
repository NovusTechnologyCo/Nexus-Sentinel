// Tutorial Native Helper
// Provides native functions that write to memory, creating NOP-able code
// in the tutorial's address space.

#include <windows.h>
#include <stdlib.h>

// ============================================================================
// STEP 5: Code Finder - Static value with NOP-able write
// ============================================================================

// Global value storage - address will be stable
static volatile int g_tutorialValue = 0;

// Export: Get pointer to the value
__declspec(dllexport) int* __stdcall GetValuePtr(void)
{
    return (int*)&g_tutorialValue;
}

// Export: Write value - THIS is the function that can be NOP'd
// The MOV instruction in this function will be in the DLL's code section
__declspec(dllexport) void __stdcall WriteValue(int newValue)
{
    // The actual write - this creates a MOV instruction that can be NOP'd
    *(volatile int*)&g_tutorialValue = newValue;
}

// Export: Read value
__declspec(dllexport) int __stdcall ReadValue(void)
{
    return g_tutorialValue;
}

// ============================================================================
// STEP 6: Pointers - Dynamic allocation with static pointer
// ============================================================================

// Static pointer variable - users will find this at [tutorial_native.dll+xxxxx]
// It points to dynamically allocated memory
// NOT exported so CE shows dll+offset format instead of symbol name
static int* g_step6Pointer = NULL;

// Export: Initialize Step 6 - allocates memory and sets up pointer
__declspec(dllexport) void __stdcall Step6_Init(int initialValue)
{
    if (g_step6Pointer != NULL)
    {
        free(g_step6Pointer);
    }
    g_step6Pointer = (int*)malloc(sizeof(int));
    if (g_step6Pointer != NULL)
    {
        *g_step6Pointer = initialValue;
    }
}

// Export: Get the address of the static pointer (for finding "Tutorial+xxxxx")
__declspec(dllexport) int** __stdcall Step6_GetPointerAddress(void)
{
    return &g_step6Pointer;
}

// Export: Get the current value address (what the pointer points to)
__declspec(dllexport) int* __stdcall Step6_GetValuePtr(void)
{
    return g_step6Pointer;
}

// Export: Read the value through the pointer
__declspec(dllexport) int __stdcall Step6_ReadValue(void)
{
    if (g_step6Pointer != NULL)
    {
        return *g_step6Pointer;
    }
    return 0;
}

// Export: Write value through pointer - shows [tutorial_native.dll+xxxxx] in disasm
// This generates: mov rax,[tutorial_native.g_step6Pointer] ; mov [rax],ecx
__declspec(dllexport) __declspec(noinline) void __stdcall Step6_WriteValue(int newValue)
{
    *g_step6Pointer = newValue;
}

// Export: Change pointer - reallocates to new address (simulates game restart)
__declspec(dllexport) int* __stdcall Step6_ChangePointer(void)
{
    int oldValue = 0;
    if (g_step6Pointer != NULL)
    {
        oldValue = *g_step6Pointer;
        free(g_step6Pointer);
    }

    // Allocate at a new address
    g_step6Pointer = (int*)malloc(sizeof(int));
    if (g_step6Pointer != NULL)
    {
        *g_step6Pointer = oldValue;
    }

    return g_step6Pointer;
}

// Export: Cleanup
__declspec(dllexport) void __stdcall Step6_Cleanup(void)
{
    if (g_step6Pointer != NULL)
    {
        free(g_step6Pointer);
        g_step6Pointer = NULL;
    }
}

// ============================================================================
// STEP 7: Code Injection - Health with SUB instruction
// ============================================================================

// Static health value for Step 7
static volatile int g_step7Health = 100;

// Export: Initialize Step 7
__declspec(dllexport) void __stdcall Step7_Init(int initialHealth)
{
    g_step7Health = initialHealth;
}

// Export: Get health pointer
__declspec(dllexport) int* __stdcall Step7_GetHealthPtr(void)
{
    return (int*)&g_step7Health;
}

// Export: Read health
__declspec(dllexport) int __stdcall Step7_ReadHealth(void)
{
    return g_step7Health;
}

// Export: Get health pointer for assembly routine
__declspec(dllexport) volatile int* __stdcall Step7_GetHealthPtrInternal(void)
{
    return &g_step7Health;
}

// Implemented in step7_hit.asm - uses SUB instruction
// __declspec(dllexport) void __stdcall Step7_Hit(void);

// ============================================================================
// STEP 8: Multi-level Pointers
// ============================================================================

// Multi-level pointer structure with offsets: +20, +0, +10, +18 (unique to Nexus)
// Level 4 (innermost): Contains padding + the actual value
typedef struct {
    char padding[0x18];        // 0x18 bytes padding
    int health;                // at offset +0x18, THE ACTUAL VALUE
} Step8_Level4;

// Level 3: Contains padding + pointer to Level4
typedef struct {
    char padding[0x10];        // 0x10 bytes padding
    Step8_Level4* level4;      // at offset +0x10
} Step8_Level3;

// Level 2: Pointer to Level3 at offset +0 (no padding)
typedef struct {
    Step8_Level3* level3;      // at offset +0x0
} Step8_Level2;

// Level 1 (base): Contains padding + pointer to Level2
typedef struct {
    char padding[0x20];        // 0x20 bytes padding
    Step8_Level2* level2;      // at offset +0x20
} Step8_Level1;

// Static base pointer - this will be at tutorial_native.dll+XXXXX
static Step8_Level1* g_step8Base = NULL;

// Export: Initialize Step 8 pointer chain
__declspec(dllexport) void __stdcall Step8_Init(int initialHealth)
{
    // Clean up any existing chain
    if (g_step8Base != NULL)
    {
        if (g_step8Base->level2 != NULL)
        {
            if (g_step8Base->level2->level3 != NULL)
            {
                if (g_step8Base->level2->level3->level4 != NULL)
                {
                    free(g_step8Base->level2->level3->level4);
                }
                free(g_step8Base->level2->level3);
            }
            free(g_step8Base->level2);
        }
        free(g_step8Base);
    }

    // Allocate new chain
    g_step8Base = (Step8_Level1*)malloc(sizeof(Step8_Level1));
    memset(g_step8Base, 0, sizeof(Step8_Level1));

    g_step8Base->level2 = (Step8_Level2*)malloc(sizeof(Step8_Level2));
    memset(g_step8Base->level2, 0, sizeof(Step8_Level2));

    g_step8Base->level2->level3 = (Step8_Level3*)malloc(sizeof(Step8_Level3));
    memset(g_step8Base->level2->level3, 0, sizeof(Step8_Level3));

    g_step8Base->level2->level3->level4 = (Step8_Level4*)malloc(sizeof(Step8_Level4));
    memset(g_step8Base->level2->level3->level4, 0, sizeof(Step8_Level4));

    // Set the health value directly in the structure
    g_step8Base->level2->level3->level4->health = initialHealth;
}

// Export: Get address of the static base pointer (for finding dll+offset)
__declspec(dllexport) Step8_Level1** __stdcall Step8_GetBaseAddress(void)
{
    return &g_step8Base;
}

// Export: Read health value through pointer chain (C version - fast, not breakpoint-friendly)
__declspec(dllexport) int __stdcall Step8_ReadHealth(void)
{
    if (g_step8Base != NULL &&
        g_step8Base->level2 != NULL &&
        g_step8Base->level2->level3 != NULL &&
        g_step8Base->level2->level3->level4 != NULL)
    {
        return g_step8Base->level2->level3->level4->health;
    }
    return 0;
}

// Export: Read health through pointer chain with visible instructions
// NOTE: This is now implemented in step8_hit.asm as Step8_ReadHealthSlow
// to avoid stack variables that create duplicate pointer values in memory scans
// The ASM version uses only registers, ensuring clean pointer chain traversal

// Export: Get Level4 pointer (for ASM routine) - returns pointer to Level4 struct
// The ASM will then use [rax+18] to access health, showing the offset
__declspec(dllexport) Step8_Level4* __stdcall Step8_GetHealthPtrInternal(void)
{
    if (g_step8Base != NULL &&
        g_step8Base->level2 != NULL &&
        g_step8Base->level2->level3 != NULL)
    {
        return g_step8Base->level2->level3->level4;
    }
    return NULL;
}

// Export: Change pointer - reallocates entire chain (simulates game restart)
__declspec(dllexport) void __stdcall Step8_ChangePointer(void)
{
    int currentHealth = Step8_ReadHealth();
    if (currentHealth == 0) currentHealth = 5000;

    // Reinitialize with same value - but all addresses will change
    Step8_Init(currentHealth);
}

// Export: Cleanup
__declspec(dllexport) void __stdcall Step8_Cleanup(void)
{
    if (g_step8Base != NULL)
    {
        if (g_step8Base->level2 != NULL)
        {
            if (g_step8Base->level2->level3 != NULL)
            {
                if (g_step8Base->level2->level3->level4 != NULL)
                {
                    free(g_step8Base->level2->level3->level4);
                }
                free(g_step8Base->level2->level3);
            }
            free(g_step8Base->level2);
        }
        free(g_step8Base);
        g_step8Base = NULL;
    }
}

// Implemented in step8_hit.asm - uses SUB instruction
// __declspec(dllexport) void __stdcall Step8_Hit(void);

// ============================================================================
// STEP 9: Shared Code - Multiple actors with same damage function
// ============================================================================

// Actor structure - health at +0x08, team at +0x10
// This layout makes it easy to find via "compare registers"
typedef struct {
    int id;                     // +0x00: Actor ID (1-4)
    int padding1;               // +0x04: Padding for alignment
    float health;               // +0x08: Health value (float like CE tutorial)
    int padding2;               // +0x0C: Padding
    int team;                   // +0x10: Team ID (1 = player team, 2 = enemy team)
    char name[16];              // +0x14: Actor name
} Step9_Actor;

// 4 actors: 2 players (team 1), 2 enemies (team 2)
#define STEP9_NUM_ACTORS 4
static Step9_Actor* g_step9Actors[STEP9_NUM_ACTORS] = { NULL, NULL, NULL, NULL };

// Export: Initialize Step 9
__declspec(dllexport) void __stdcall Step9_Init(void)
{
    const char* names[] = { "Dave", "Eric", "HAL", "Killbot" };
    const int teams[] = { 1, 1, 2, 2 };           // First two are allies, last two are enemies
    const float healths[] = { 100.0f, 100.0f, 500.0f, 500.0f };

    for (int i = 0; i < STEP9_NUM_ACTORS; i++)
    {
        if (g_step9Actors[i] != NULL)
        {
            free(g_step9Actors[i]);
        }
        g_step9Actors[i] = (Step9_Actor*)malloc(sizeof(Step9_Actor));
        if (g_step9Actors[i] != NULL)
        {
            memset(g_step9Actors[i], 0, sizeof(Step9_Actor));
            g_step9Actors[i]->id = i + 1;
            g_step9Actors[i]->health = healths[i];
            g_step9Actors[i]->team = teams[i];
            strncpy(g_step9Actors[i]->name, names[i], 15);
            g_step9Actors[i]->name[15] = '\0';
        }
    }
}

// Export: Get actor pointer by index (0-3)
__declspec(dllexport) Step9_Actor* __stdcall Step9_GetActor(int index)
{
    if (index >= 0 && index < STEP9_NUM_ACTORS)
    {
        return g_step9Actors[index];
    }
    return NULL;
}

// Export: Get actor health
__declspec(dllexport) float __stdcall Step9_GetHealth(int index)
{
    if (index >= 0 && index < STEP9_NUM_ACTORS && g_step9Actors[index] != NULL)
    {
        return g_step9Actors[index]->health;
    }
    return 0.0f;
}

// Export: Get actor team
__declspec(dllexport) int __stdcall Step9_GetTeam(int index)
{
    if (index >= 0 && index < STEP9_NUM_ACTORS && g_step9Actors[index] != NULL)
    {
        return g_step9Actors[index]->team;
    }
    return 0;
}

// Export: Get actor name
__declspec(dllexport) const char* __stdcall Step9_GetName(int index)
{
    if (index >= 0 && index < STEP9_NUM_ACTORS && g_step9Actors[index] != NULL)
    {
        return g_step9Actors[index]->name;
    }
    return "";
}

// Export: Cleanup
__declspec(dllexport) void __stdcall Step9_Cleanup(void)
{
    for (int i = 0; i < STEP9_NUM_ACTORS; i++)
    {
        if (g_step9Actors[i] != NULL)
        {
            free(g_step9Actors[i]);
            g_step9Actors[i] = NULL;
        }
    }
}

// The actual damage function is in step9_damage.asm
// It uses: sub dword ptr [rcx+08h], edx  (or similar for float)
// Where RCX = actor pointer, health is at +0x08, team is at +0x10
// Users must inject code to check [rcx+10] for team ID

// ============================================================================
// STEP 10: String Scanning - Player name in native memory
// ============================================================================

// ============================================================================
// STEP 11: AOB/Signature Scanning
// Structure with recognizable byte pattern followed by a value
// Users search for the pattern, then find the value at offset +8
// ============================================================================

// The signature bytes - a unique pattern to search for
// Pattern: DE AD BE EF CA FE BA BE (easy to recognize)
// Value is at offset +8 from the start of the signature
static struct {
    unsigned char signature[8];
    int secretValue;
} g_step11Data = {
    { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE },
    12345
};

// Export: Get the secret value
__declspec(dllexport) int __stdcall Step11_GetValue(void)
{
    return g_step11Data.secretValue;
}

// Export: Get address of the structure (for verification)
__declspec(dllexport) void* __stdcall Step11_GetAddress(void)
{
    return (void*)&g_step11Data;
}

// Static buffer for player name - THIS is the only copy users should find
static char g_step10PlayerName[16] = "Player0000";

// Export: Set player name
__declspec(dllexport) void __stdcall Step10_SetName(const char* name)
{
    memset(g_step10PlayerName, 0, sizeof(g_step10PlayerName));
    strncpy(g_step10PlayerName, name, sizeof(g_step10PlayerName) - 1);
}

// Export: Get player name pointer (for reading)
__declspec(dllexport) const char* __stdcall Step10_GetName(void)
{
    return g_step10PlayerName;
}

// Export: Get address of the buffer (for display)
__declspec(dllexport) void* __stdcall Step10_GetNameAddress(void)
{
    return (void*)g_step10PlayerName;
}

// ============================================================================
// STEP 16: Breakpoints - NOP-able damage function
// ============================================================================

// Pointer to external health value (set by C#)
static volatile int* g_step16HealthPtr = NULL;

// Export: Set the health pointer
__declspec(dllexport) void __stdcall Step16_SetHealthPtr(int* ptr)
{
    g_step16HealthPtr = ptr;
}

// Export: Deal damage - THIS INSTRUCTION CAN BE NOPPED
// Users will find this with "Find what writes" and NOP the SUB
__declspec(dllexport) __declspec(noinline) void __stdcall Step16_DealDamage(int amount)
{
    if (g_step16HealthPtr != NULL)
    {
        // THE WRITE INSTRUCTION - this is what users need to NOP
        *g_step16HealthPtr -= amount;
    }
}

// Export: Read current health
__declspec(dllexport) int __stdcall Step16_ReadHealth(void)
{
    if (g_step16HealthPtr != NULL)
    {
        return *g_step16HealthPtr;
    }
    return 0;
}

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_DETACH:
        // Cleanup on unload
        if (g_step6Pointer != NULL)
        {
            free((void*)g_step6Pointer);
            g_step6Pointer = NULL;
        }
        // Cleanup Step 8
        Step8_Cleanup();
        // Cleanup Step 9
        Step9_Cleanup();
        break;
    }
    return TRUE;
}
