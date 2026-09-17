#pragma once

//
// NexusBootLocate -- find the hook targets in bootmgfw.efi and winload.efi.
//
// The counterpart to NexusPgLocate, for the two boot files rather than the kernel. Same
// principle: identify code by what it MEANS, and refuse when the answer is not unique.
//
// (!) THE SIGNATURE THIS REPLACES WAS ALREADY AMBIGUOUS, on this machine, today.
// `41 B8 09 00 00 D0` (mov r8d, 0D0000009h) matches TWICE in bootmgfw 10.0.28000.367.
// FindPattern returns the first match and reports nothing, so the ambiguity was invisible:
// the right function happened to come first. A build that ordered them the other way would
// have hooked a 321-byte routine taking one argument, with a five-argument prototype.
//
// Measured, and the basis for the predicates below:
//
//   0x001CF264  1341 B, 35 calls, homes RCX/RDX/R8   <- ImgArchEfiStartBootApplication
//   0x0027ED00   321 B,  7 calls, homes RCX only
//
// The discriminator is the function's ARITY, read from the home-space spills in its
// prologue. That is the function's signature, not an encoding detail.
//

#include "NexusPe.h"

//
// bootmgfw!ImgArchEfiStartBootApplication.
//
// Identified by loading 0xD0000009 into R8D -- passing it as a third argument -- within a
// function that itself takes at least three arguments. Searching for the constant alone
// finds six functions in bootmgfw; requiring R8D takes it to two; requiring the arity takes
// it to one.
//
EFI_STATUS
EFIAPI
NexusBootLocateImgArchStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	);

//
// winload!OslFwpKernelSetupPhase1.
//
// Identified by a store to [REG+0x124] immediately followed by a call to the EXPORTED
// BlBdStop. Nine functions in winload call BlBdStop; exactly one does it straight after that
// store. Anchoring on an export is worth more than any instruction pattern -- export names
// are a contract, instruction encodings are not.
//
EFI_STATUS
EFIAPI
NexusBootLocateOslFwpKernelSetupPhase1(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	);

//
// bootmgfw!BuildPcrSnapshotData.
//
// Identified by the 0xADF01995 snapshot magic as an immediate. Occurs once in the whole
// image, which is why this target was always the least fragile of the three.
//
EFI_STATUS
EFIAPI
NexusBootLocateBuildPcrSnapshotData(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT UINT8** Found
	);
