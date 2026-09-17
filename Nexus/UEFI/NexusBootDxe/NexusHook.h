#pragma once

//
// NexusHook -- inline hooks on boot-time code. Replaces the open-coded gHookTemplate dance
// that PatchBootmgr.c and PatchWinload.c each carried a copy of.
//
// Three call sites installed the same 12-byte trampoline by hand, and each one re-implemented
// capture, install, re-arm and restore. That is three chances to get the ordering wrong on
// code that runs before Windows exists, with no console left to say what happened.
//

#include <Uefi.h>

//
// mov rax, imm64 ; push rax ; ret
//
// (!) WHY THIS FORM. An absolute 64-bit jump has no single-instruction encoding on x64, so it
// is either this or `jmp qword ptr [rip+0]` followed by the address. This one is 12 bytes
// against 14, which matters because every byte is overwritten in the target function.
//
// It clobbers RAX, which is safe HERE and only here: the trampoline sits at a function's first
// instruction, where RAX is caller-scratch under the Microsoft x64 ABI and carries no argument
// (those are RCX, RDX, R8, R9). Installing this anywhere other than an entry point would be a
// register corruption bug.
//
// ⚠ AND ONE REASON TO PREFER THE OTHER FORM, RECORDED RATHER THAN ACTED ON. `push rax; ret`
// returns to an address that no `call` pushed, so with a CET shadow stack enforced it raises
// #CP. It evidently is not enforced where these hooks run -- this mechanism boots -- but that
// is an observation about today's firmware, not a guarantee. `jmp [rip+0]` needs no shadow
// stack entry and clobbers nothing. It was NOT switched to, because changing the trampoline in
// boot-critical code that cannot be tested short of a reboot buys a hypothetical at the cost
// of a known-good path.
//
#define NEXUS_HOOK_SIZE     12

typedef struct _NEXUS_HOOK
{
	UINT8* Target;                      // first byte of the hooked function
	VOID* Detour;                       // where the trampoline sends it
	UINT8 Original[NEXUS_HOOK_SIZE];    // bytes displaced by the trampoline
	BOOLEAN Captured;                   // Original is valid
	BOOLEAN Armed;                      // the trampoline is currently written
} NEXUS_HOOK;

//
// Capture `Target`'s first NEXUS_HOOK_SIZE bytes and write the trampoline over them.
//
// (!) THE ORIGINAL BYTES ARE CAPTURED EXACTLY ONCE, on the first install. Capturing again
// while the hook is armed would store the TRAMPOLINE as the original and lose the real
// instructions permanently -- restore would then write a hook that jumps to a detour that
// restores a hook, forever. That is not a hypothetical shape of bug: install/restore/re-arm
// cycles are exactly what these hooks do.
//
EFI_STATUS
EFIAPI
NexusHookInstall(
	IN OUT NEXUS_HOOK* Hook,
	IN VOID* Target,
	IN VOID* Detour
	);

//
// Put the displaced bytes back. Safe to call when not armed.
//
VOID
EFIAPI
NexusHookRestore(
	IN OUT NEXUS_HOOK* Hook
	);

//
// Write the trampoline again after a restore.
//
// ⚠ ONLY AFTER THE ORIGINAL FUNCTION HAS RETURNED. Re-arming before calling through sends our
// own call straight back into the detour -- unbounded recursion in the boot path, which
// presents as a hang with no output.
//
VOID
EFIAPI
NexusHookRearm(
	IN OUT NEXUS_HOOK* Hook
	);
