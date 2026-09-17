/**
 * @file NexusLoaderBlock.h
 * @brief Boot-loader-block helpers: module lookup and boot-debugger output.
 *
 * The Windows boot loader hands the kernel a LOADER_PARAMETER_BLOCK whose LoadOrderList links
 * every image it has loaded. Between the loader's handoff hook and the kernel's first
 * instruction, that list is the only directory of what is in memory and where -- there is no
 * API to call and no allocator to use.
 *
 * Two things are needed there, and both live here:
 *
 *   - finding a loaded image by name, which is how the kernel and the boot drivers are located
 *   - printing, because the UEFI console is gone by then and the boot debugger is all that is
 *     left
 */

#pragma once

#include "NexusNt.h"
#include "NexusArc.h"

/**
 * Signature of the boot loader's debug printer, which takes a printf-style wide format string.
 */
typedef
NTSTATUS
(EFIAPI*
NEXUS_BOOT_PRINT)(
	IN CONST CHAR16* Format,
	...
	);

/**
 * The boot loader's debug printer, or a sink when the loader does not export one.
 *
 * NEVER NULL. It is initialised to the sink and only ever replaced by a resolved export, so
 * callers do not test it -- a print that silently does nothing is correct behaviour on a machine
 * with no debugger attached, and a NULL check at every call site would be noise guarding against
 * a state that cannot occur.
 */
extern NEXUS_BOOT_PRINT gNexusBootPrint;

/**
 * Point boot-debugger output at the loader's printer, or back at the sink.
 *
 * @param Printer  resolved export, or NULL to restore the sink.
 * @retval TRUE    a real printer is now installed.
 */
BOOLEAN
EFIAPI
NexusBootPrintSetTarget(
	IN NEXUS_BOOT_PRINT Printer OPTIONAL
	);

/**
 * Find an image in the boot loader's load-order list by name.
 *
 * The comparison is case-insensitive and bounded by the entry's own recorded length, so a
 * non-terminated name cannot run off the end of its buffer.
 *
 * @param ListHead    LoadOrderList head from the loader parameter block.
 * @param ModuleName  image name to match, e.g. L"ntoskrnl.exe".
 * @return the matching entry, or NULL.
 *
 * (!) THE WALK IS BOUNDED. A circular or corrupted list would otherwise spin forever inside the
 * loader handoff, where there is no watchdog, no console and no way to interrupt -- the machine
 * would simply stop with a black screen and no indication of why. The bound costs one comparison
 * per entry and converts that into an ordinary NULL return.
 */
PKLDR_DATA_TABLE_ENTRY
EFIAPI
NexusFindBootModule(
	IN CONST LIST_ENTRY* ListHead,
	IN CONST CHAR16* ModuleName
	);

/**
 * Upper bound on load-order list entries. Measured boot-driver counts on this class of machine
 * are in the low hundreds; 4096 is far above any plausible real list and far below a number that
 * would take noticeable time to walk.
 */
#define NEXUS_MAX_BOOT_MODULES  4096u
