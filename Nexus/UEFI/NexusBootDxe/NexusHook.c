//
// NexusHook -- inline hooks on boot-time code. See NexusHook.h.
//

#include "NexusBootDxe.h"
#include "NexusHook.h"
#include "NexusUtil.h"

#include <Library/BaseMemoryLib.h>

//
// (!) NO UefiBootServicesTableLib, AND THAT IS THE POINT. See NexusHookWrite below.
//

//
// The trampoline, with a zeroed address field. NexusHookWrite patches the address in.
//
STATIC CONST UINT8 mTrampoline[NEXUS_HOOK_SIZE] =
{
	0x48, 0xB8,                                     // mov rax, imm64
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x50,                                           // push rax
	0xC3                                            // ret
};

#define TRAMPOLINE_ADDRESS_OFFSET   2


//
// Write the trampoline over the target.
//
// The whole 12 bytes go down with interrupts masked, so no handler can be dispatched between
// the opcode bytes landing and the address landing -- one that reached this code mid-write
// would execute `mov rax, <half-written address>` and jump somewhere arbitrary.
//
// (!) MASKED WITH CLI/STI, NOT WITH gBS->RaiseTPL. THIS IS NOT A STYLE CHOICE.
//
// Restore and re-arm are called from INSIDE the detours, and
// HookedOslFwpKernelSetupPhase1 runs in WINLOAD'S PROTECTED-MODE CONTEXT, on winload's own
// page tables. gBS is a firmware pointer that is not mapped there, so touching boot services
// from a detour hangs the machine at a black screen before Windows reaches its boot spinner.
//
// That is not a hypothesis. PatchWinload.c carries a comment about the identical failure from
// When the Tier 3 log transform was called from this hook and died the same way:
// "anything reached through a firmware-physical address does not belong in this context".
// The code this replaced knew it too -- its in-hook restore was a bare CopyWpMem with no TPL
// raise, and only the INSTALL path (which runs in the DXE, where gBS is fine) raised TPL.
// Adding a raise to the shared helper put the firmware call back on the winload path and
// reproduced the hang exactly.
//
// SaveAndDisableInterrupts/SetInterruptState are BaseLib -- CLI and STI compiled into this
// image. Same atomicity, no firmware pointer, correct in every context a hook can run in.
//
STATIC
VOID
EFIAPI
NexusHookWrite(
	IN UINT8* Target,
	IN VOID* Detour
	)
{
	CONST BOOLEAN Interrupts = SaveAndDisableInterrupts();

	CopyWpMem(Target, mTrampoline, sizeof(mTrampoline));
	CopyWpMem(Target + TRAMPOLINE_ADDRESS_OFFSET, &Detour, sizeof(Detour));

	SetInterruptState(Interrupts);
}


EFI_STATUS
EFIAPI
NexusHookInstall(
	IN OUT NEXUS_HOOK* Hook,
	IN VOID* Target,
	IN VOID* Detour
	)
{
	if (Hook == NULL || Target == NULL || Detour == NULL)
		return EFI_INVALID_PARAMETER;

	//
	// (!) CAPTURE ONCE, AND ONLY WHILE THE TARGET IS STILL ITS ORIGINAL SELF.
	//
	// If this ran again with the hook already armed it would store the trampoline as
	// Original, and the real instructions would be gone for good -- every later restore would
	// write a jump back into the detour. Guarding on Captured makes a second install a
	// re-arm, which is what a caller asking to install an already-installed hook means.
	//
	if (!Hook->Captured)
	{
		CopyMem(Hook->Original, Target, sizeof(Hook->Original));
		Hook->Captured = TRUE;
		Hook->Target = (UINT8*)Target;
		Hook->Detour = Detour;
	}
	else if (Hook->Target != (UINT8*)Target || Hook->Detour != Detour)
	{
		//
		// Reusing one NEXUS_HOOK for a different target would restore the first target's
		// bytes over the second. Refuse rather than corrupt.
		//
		return EFI_ALREADY_STARTED;
	}

	NexusHookWrite(Hook->Target, Hook->Detour);
	Hook->Armed = TRUE;
	return EFI_SUCCESS;
}


VOID
EFIAPI
NexusHookRestore(
	IN OUT NEXUS_HOOK* Hook
	)
{
	if (Hook == NULL || !Hook->Captured || !Hook->Armed)
		return;

	CONST BOOLEAN Interrupts = SaveAndDisableInterrupts();
	CopyWpMem(Hook->Target, Hook->Original, sizeof(Hook->Original));
	SetInterruptState(Interrupts);

	Hook->Armed = FALSE;
}


VOID
EFIAPI
NexusHookRearm(
	IN OUT NEXUS_HOOK* Hook
	)
{
	if (Hook == NULL || !Hook->Captured || Hook->Armed)
		return;

	NexusHookWrite(Hook->Target, Hook->Detour);
	Hook->Armed = TRUE;
}
