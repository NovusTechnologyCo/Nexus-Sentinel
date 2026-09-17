/**
 * @file TpmCrb.h
 * @brief G1: service the RAM CRB after ExitBootServices, so Windows' TPM driver gets an answer.
 *
 * THE MEASUREMENT THAT MADE THIS NECESSARY (spec rev 9.25):
 *
 *     CTRL_REQ = 0x00000001      <-- cmdReady, written by tpm.sys. STILL SET.
 *
 * With the ACPI TPM2 table at revision 5, `tpm.sys` accepts the platform and writes
 * `TPM_CRB_CTRL_REQ.cmdReady` asking the TPM to leave Idle. Nothing answered, so it polled,
 * timed out, and logged *"non-recoverable error in the TPM hardware"*. Everything upstream --
 * ACPI table, device node, interface register, control area, buffer addressing -- is thereby
 * validated BY WINDOWS. The only missing piece is something that answers.
 *
 * ⚠ WHY THE KERNEL AND NOT THE DXE. A RAM CRB has no hardware doorbell: the DXE stops executing at
 * ExitBootServices, and the CRB is just memory afterwards. NexusCore is already resident, already
 * able to map the published regions, and can run a timer. It is the only thing we control that is
 * alive when tpm.sys is.
 *
 * ⚠ POLLING, AND THE MARGIN IS STATED RATHER THAN HOPED. PTP Table 27 gives TIMEOUT_C = 200 ms for
 * the Idle-to-Ready transition. A 10 ms period has a 20x margin. Earlier revisions of the spec
 * rejected polling as a matter of project architecture, but that objection was about an
 * UNSPECIFIED poll with no stated latency; this one is specified, bounded and measured.
 *
 * ⚠ IT RUNS THE REAL TPM CORE, NOT A SECOND ONE. `Tpm2Dispatch` compiles into this driver via
 * `uefi_shim/Uefi.h`, so the OS and the boot loader are answered by the same code. Two
 * implementations would eventually disagree, and a TPM caught contradicting itself is worse than
 * one that never answered.
 *
 * ⚠ EVERY COMMAND IS RECORDED. We do not know which commands Windows sends once the TPM leaves
 * Idle, and guessing that list is how this project has spent reboots. The trace is published in
 * region B where `readphys` can reach it; the next build implements exactly what shows up.
 */

#pragma once

#include <ntddk.h>

/*
 * A recorded command. Fixed size so the ring can be walked from outside with no allocator and no
 * knowledge of our internals -- PlatformCtl reads this out of physical memory.
 */
#pragma pack(push, 1)
typedef struct _NXC_TPM_CRB_RECORD {
	ULONG64 Tsc;              // when, by TSC -- ordering across a boot with no clock assumptions
	ULONG   Sequence;         // monotonic; a gap means the ring wrapped
	ULONG   CommandCode;      // TPM_CC as parsed from the request
	ULONG   CommandSize;      // as DECLARED by the command header
	ULONG   InputSize;        // as actually present in the buffer -- the two disagreeing is itself
	                          // a finding, so both are kept
	ULONG   ResponseCode;     // the TPM_RC we answered
	ULONG   ResponseSize;     // bytes we wrote back
	USHORT  Tag;
	USHORT  Reserved;
	UCHAR   Head[32];         // first bytes of the request, for commands we do not yet decode
	//
	// The first bytes of what we ANSWERED. Added after a boot in which every surviving record
	// said SUCCESS and Windows gave up anyway: an RC alone cannot distinguish a correct answer
	// from a well-formed response carrying wrong content, and the content is what the peer acts
	// on. 32 bytes covers the 10-byte header plus the first fields of every response we emit.
	//
	UCHAR   Rsp[32];
} NXC_TPM_CRB_RECORD;
#pragma pack(pop)

C_ASSERT(sizeof(NXC_TPM_CRB_RECORD) == 100);

#define NXC_TPM_CRB_TRACE_MAGIC   0x43425254504D5854ull   /* 'TXMPTRBC' */
/*
 * (!) THE RING WAS THE INSTRUMENT AND THE INSTRUMENT WAS TOO SMALL. One boot produced 265
 * commands against 64 slots, so sequences 0..200 were overwritten -- and the conclusion drawn
 * from the survivors ("nothing was refused") was a statement about the last quarter of the boot
 * dressed up as a statement about the boot. Region B is 64 KB with the trace at 0x1000, so the
 * old size was a guess, never a constraint.
 */
#define NXC_TPM_CRB_TRACE_SLOTS   192

/*
 * A SECOND RING, WRITTEN ONLY FOR TPM_RC_COMMAND_CODE -- AND IT KEEPS THE WHOLE COMMAND.
 *
 * This is the "implement this" ring, and the filter is deliberately narrow. In v2 it took every
 * non-SUCCESS answer, and one boot later 70 correct TPM_RC_HANDLE answers had evicted most of
 * the TPM_RC_COMMAND_CODE records that actually scoped the next build.
 *
 * ⚠ 32 BYTES WAS ENOUGH TO NAME THE COMMAND AND NOT ENOUGH TO IMPLEMENT IT.
 * TPM2_CreatePrimary arrives at 343 and 375 bytes; the header and first handle fit in 32, and
 * the inPublic template -- the part that says WHAT to create -- is the entire remainder.
 * Reconstructing it from a published document and hoping Windows sends that exact one is the
 * guessing this project has repeatedly paid for, so the bytes are captured instead.
 *
 * Commands we do not implement are rare BY CONSTRUCTION: each one is a gap, and gaps get
 * closed. So the ring trades slots for completeness -- 8 records of 2 KB rather than 48 of 100
 * bytes. Captured vs CommandSize says explicitly when a command was longer than the window.
 */
#define NXC_TPM_CRB_FULL_SLOTS    8
#define NXC_TPM_CRB_FULL_BYTES    2048

#pragma pack(push, 1)
typedef struct _NXC_TPM_CRB_FULL {
	ULONG64 Tsc;
	ULONG   Sequence;         // the MAIN ring sequence, so it can be located in the traffic
	ULONG   CommandCode;
	ULONG   CommandSize;      // as DECLARED by the command header
	ULONG   Captured;         // bytes actually stored; < CommandSize means the window was short
	ULONG   ResponseCode;
	ULONG   Reserved;
	UCHAR   Command[NXC_TPM_CRB_FULL_BYTES];
} NXC_TPM_CRB_FULL;
#pragma pack(pop)

C_ASSERT(sizeof(NXC_TPM_CRB_FULL) == 32 + NXC_TPM_CRB_FULL_BYTES);

/*
 * THE CENSUS: one bucket per command code, independent of both rings.
 *
 * (!) THIS IS THE PART THAT CANNOT BE LOST. A ring answers "what happened recently"; the census
 * answers "what happened at all", which is the question that scopes the next phase. Indexed by
 * TPM_CC directly so a reader needs no table, with the final bucket collecting anything outside
 * the range -- vendor commands included -- so an out-of-range code is counted rather than
 * silently dropped.
 *
 * 0x11F is TPM_CC_FIRST in Part 2. The window runs to 0x1CD, comfortably past TPM_CC_LAST in
 * revision 185, so a command landing in the catch-all means something genuinely unusual.
 */
#define NXC_TPM_CRB_CENSUS_FIRST  0x0000011Fu
#define NXC_TPM_CRB_CENSUS_SLOTS  176            /* 0x11F..0x1CD, plus a catch-all at the end */
#define NXC_TPM_CRB_CENSUS_OTHER  (NXC_TPM_CRB_CENSUS_SLOTS - 1)

#pragma pack(push, 1)
typedef struct _NXC_TPM_CRB_CENSUS {
	ULONG Count;         // times this command code arrived
	//
	// (!) TWO COUNTERS, BECAUSE THESE ARE DIFFERENT FACTS AND ONE OF THEM SCOPES THE NEXT BUILD.
	//
	// Unimplemented means we answered TPM_RC_COMMAND_CODE: the command is missing from this TPM.
	// Errored means we answered some other non-SUCCESS code, which is frequently CORRECT --
	// TPM_RC_HANDLE for an object that does not exist is the right answer, not a shortfall.
	//
	// v2 had a single Refused counter, and once ReadPublic began answering TPM_RC_HANDLE it
	// reported 74 refusals of which 70 were correct answers, and listed two implemented
	// commands as work to do.
	//
	ULONG Unimplemented; // answered TPM_RC_COMMAND_CODE
	ULONG Errored;       // answered any other non-SUCCESS code
	ULONG FirstRc;       // the first answer, kept because a command can succeed once then fail
	ULONG LastRc;        // the most recent answer
} NXC_TPM_CRB_CENSUS;
#pragma pack(pop)

C_ASSERT(sizeof(NXC_TPM_CRB_CENSUS) == 20);

/*
 * The trace header, written at a fixed offset inside region B so a reader needs only the region
 * base -- which the boot block already publishes -- and nothing from this driver.
 */
#pragma pack(push, 1)
typedef struct _NXC_TPM_CRB_TRACE {
	ULONG64 Magic;
	ULONG   Version;
	ULONG   SlotCount;
	ULONG   Written;          // total records ever written; > SlotCount means it wrapped
	ULONG   Serviced;         // cmdReady/goIdle/locality transitions handled
	ULONG   Polls;            // timer ticks, so a silent trace can be told from a dead timer
	ULONG   LastError;        // NXC_TPM_CRB_ERR_*
	ULONG   FullSlotCount;
	ULONG   FullWritten;      // total COMMAND_CODE records; > FullSlotCount means this wrapped
	ULONG   FullBytes;        // capture window, published so the reader does not assume it
	//
	// The ring-independent headline figures. Unimplemented is the one that means WORK; Errored
	// is mostly correct answers and is reported separately so it cannot inflate the other.
	//
	ULONG   Unimplemented;
	ULONG   Errored;
	ULONG   CensusFirst;      // command code of census bucket 0
	ULONG   CensusSlots;
	//
	// (!) PUBLISHED, NOT ASSUMED. A reader outside this driver would otherwise have to agree with
	// us about sizeof() to walk the arrays, and that agreement is exactly what breaks silently
	// when one side is rebuilt and the other is not.
	//
	ULONG   RecordSize;
	ULONG   CensusSize;
	ULONG   Reserved0;
	NXC_TPM_CRB_CENSUS Census[NXC_TPM_CRB_CENSUS_SLOTS];
	NXC_TPM_CRB_RECORD Slot[NXC_TPM_CRB_TRACE_SLOTS];
	NXC_TPM_CRB_FULL   Full[NXC_TPM_CRB_FULL_SLOTS];
} NXC_TPM_CRB_TRACE;
#pragma pack(pop)

/*
 * ⚠ PLACED ON THE SECOND PAGE OF REGION B, leaving the first page to the state header and the PCR
 * bank. Region B is 64 KB, so the trace cannot collide with the payload -- and the offset is fixed
 * rather than computed so a reader never has to agree with us about sizeof().
 */
#define NXC_TPM_CRB_TRACE_OFFSET  0x1000

/*
 * (!) VERSION 2 IS A BREAKING CHANGE, AND DELIBERATELY SO. Every offset moved. A reader built
 * for version 1 that tried to be tolerant here would decode garbage as data, which is worse
 * than refusing -- so the version is checked by the reader, not negotiated.
 */
#define NXC_TPM_CRB_TRACE_VERSION 4

/*
 * Region B is 16 pages and the trace begins one page in, so this is the whole budget. Asserted
 * rather than commented: growing a ring is a one-line edit, and the failure it would otherwise
 * cause is a driver writing past the region into whatever the firmware placed next.
 */
C_ASSERT(NXC_TPM_CRB_TRACE_OFFSET + sizeof(NXC_TPM_CRB_TRACE) <= 16 * 4096);

#define NXC_TPM_CRB_ERR_NONE          0
#define NXC_TPM_CRB_ERR_NO_BLOCK      1   /* boot block absent */
#define NXC_TPM_CRB_ERR_NO_REGION     2   /* DXE published no transport/state this boot */
#define NXC_TPM_CRB_ERR_MAP_FAILED    3
#define NXC_TPM_CRB_ERR_BAD_STATE     4   /* region B header is not ours */
#define NXC_TPM_CRB_ERR_NO_BANK       5   /* PayloadLength 0: nothing to serve commands from */
#define NXC_TPM_CRB_ERR_TOO_SMALL     6   /* region B cannot hold header + bank + trace */

/**
 * Map the published regions and start servicing. Safe to call more than once.
 *
 * ⚠ MUST be called at PASSIVE_LEVEL: MmMapIoSpace cannot run at DISPATCH_LEVEL, and the servicing
 * DPC that follows depends on the mapping already existing.
 */
NTSTATUS NxcTpmCrbStart(void);

/** Stop servicing and release the mappings. Idempotent. */
void NxcTpmCrbStop(void);

/** Where the trace lives, so PlatformCtl can be told rather than have to guess. 0 if not running. */
ULONG64 NxcTpmCrbTracePhys(void);
