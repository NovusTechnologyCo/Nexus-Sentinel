/**
 * @file NexusLoaderBlock.c
 * @brief Boot-loader-block helpers. See NexusLoaderBlock.h.
 */

#include "NexusBootDxe.h"
#include "NexusLoaderBlock.h"
#include "NexusUtil.h"

/** STATUS_NOT_SUPPORTED. Defined here because it is the only NTSTATUS this file produces. */
#define NEXUS_STATUS_NOT_SUPPORTED  ((NTSTATUS)0xC00000BBL)

/**
 * The sink. Returns STATUS_NOT_SUPPORTED so a caller that does check gets a truthful answer
 * rather than a fabricated success.
 */
STATIC
NTSTATUS
EFIAPI
NexusBootPrintSink(
	IN CONST CHAR16* Format,
	...
	)
{
	(VOID)Format;
	return NEXUS_STATUS_NOT_SUPPORTED;
}

NEXUS_BOOT_PRINT gNexusBootPrint = NexusBootPrintSink;

BOOLEAN
EFIAPI
NexusBootPrintSetTarget(
	IN NEXUS_BOOT_PRINT Printer OPTIONAL
	)
{
	gNexusBootPrint = (Printer != NULL) ? Printer : NexusBootPrintSink;
	return (Printer != NULL);
}

PKLDR_DATA_TABLE_ENTRY
EFIAPI
NexusFindBootModule(
	IN CONST LIST_ENTRY* ListHead,
	IN CONST CHAR16* ModuleName
	)
{
	if (ListHead == NULL || ModuleName == NULL)
		return NULL;

	CONST LIST_ENTRY* Node = ListHead->ForwardLink;

	for (UINT32 Seen = 0; Node != NULL && Node != ListHead; Node = Node->ForwardLink, ++Seen)
	{
		if (Seen >= NEXUS_MAX_BOOT_MODULES)
			return NULL;

		/*
		 * InLoadOrderLinks is the first member of the entry, so the link address IS the entry
		 * address (C99 6.7.2.1p13). BASE_CR states that relationship rather than assuming it.
		 */
		PKLDR_DATA_TABLE_ENTRY CONST Entry =
			BASE_CR(Node, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		CONST UNICODE_STRING* CONST Name = &Entry->BaseDllName;
		if (Name->Buffer == NULL || Name->Length == 0)
			continue;

		/*
		 * (!) LENGTHS MUST MATCH BEFORE CONTENT IS COMPARED, OR SHORT NAMES PREFIX-MATCH.
		 *
		 * The comparison is bounded by the entry's own Length because the loader is not obliged
		 * to null-terminate these, and a plain string compare would read past a name that is
		 * not. But bounding ALONE is wrong: an entry named "nt" compared over its own two
		 * characters matches a query for "ntoskrnl.exe", and this function would hand back the
		 * wrong image for the caller to patch.
		 *
		 * Requiring the character counts to be equal first makes the bounded compare exact.
		 */
		CONST UINTN NameChars = Name->Length / sizeof(CHAR16);
		if (NameChars != StrLen(ModuleName))
			continue;

		if (StrniCmp(Name->Buffer, ModuleName, NameChars) == 0)
			return Entry;
	}

	return NULL;
}
