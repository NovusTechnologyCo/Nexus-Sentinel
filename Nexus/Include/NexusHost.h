/**
 * @file NexusHost.h
 * @brief What NexusCore hands a mapped module so the module can do anything at all.
 *
 * ============================================================================================
 * THE PROBLEM THIS SOLVES
 * ============================================================================================
 *
 * A module mapped by NexusCore is in the same position NexusCore itself is in, and worse:
 *
 *   - It has NO IMPORT TABLE it can rely on. NexusCore's own payload deliberately carries none
 *     (see NexusNtApi.h -- the FF-25 IAT scan is a published detection), and a module that ships a
 *     normal import table hands back exactly the signature we removed.
 *   - It MUST NOT call ExAllocatePool2. The arena exists precisely so mapped code does not appear in
 *     pool enumeration with a tag, and so unmap can be "mark the extent free" instead of "return
 *     pages to the kernel". A module allocating from pool defeats both.
 *   - Its allocations MUST BE ATTRIBUTABLE. NxcArenaAllocFor tags every extent with an owner so
 *     teardown can reclaim ALL of a module's memory; an untagged allocation is a leak that survives
 *     unmap. That was already built and, until this header, was unreachable from a module -- arena
 *     ownership without a way to allocate is bookkeeping for something nobody can do.
 *
 * So the host passes ONE pointer, and everything a module legitimately needs hangs off it.
 *
 * ============================================================================================
 * HOW IT REACHES THE MODULE, and why it is written into the descriptor
 * ============================================================================================
 *
 * There is no argument channel. A mapped entry is called as DriverEntry(NULL, NULL), so the host
 * writes the pointer INTO THE MODULE'S OWN DESCRIPTOR before calling the entry -- the same mechanism
 * as NexusCoreBootSlot, and proven on hardware.
 *
 * ⚠ CONSEQUENCE FOR MODULE AUTHORS: NEXUS_MODULE_DESCRIPTOR must live in WRITABLE data. Declaring
 * it `const` puts it in .rdata, which the mapper now protects read-only before the entry runs
 * (task 7), and the host's write would fault. The mapper writes Host BEFORE applying protections
 * so the ordering is safe either way, but a const descriptor is still wrong: the ActiveCount field
 * is written by the module itself on every call.
 *
 * ============================================================================================
 * WHY A VERSIONED STRUCT RATHER THAN A PILE OF EXPORTS
 * ============================================================================================
 *
 * Exports would mean each module resolving names out of NexusCore's export directory -- more
 * machinery, and it makes NexusCore's capability surface enumerable from any module image. One
 * pointer to one versioned struct means a module validates Magic/Abi/StructSize exactly the way the
 * boot block is validated, and a host/module mismatch fails closed instead of calling through a
 * pointer that means something else now.
 */

#pragma once

typedef unsigned char      NXH_U8;
typedef unsigned int       NXH_U32;
typedef unsigned long long NXH_U64;

/* 'NXHA' -- validated by the module before it trusts a single function pointer. */
#define NEXUS_HOST_MAGIC   0x4148584EULL

/*
 * BUMP when a field is appended. A module built against ABI 1 must refuse an ABI 2 host it does not
 * understand rather than calling through a slot that has since been repurposed -- the same fail-closed
 * rule as NEXUS_CORE_BOOT_ABI, for the same reason: a wrong call here is a wild jump in kernel mode.
 */
#define NEXUS_HOST_ABI     2u   /* 2: RegisterCommand -- modules can own opcodes, so a feature
                                 *    no longer has to live in Core just to be reachable. */

/*
 * Allocate from the runtime arena, tagged with this module's OWNER ID.
 *
 * Owner tagging is not bookkeeping for its own sake: teardown reclaims by owner, so an allocation
 * made without one is memory that survives unmap and is handed to whoever maps next. The host
 * supplies the id -- a module cannot choose or forge its own, which is what makes the guarantee
 * hold even for a module that is careless or hostile.
 */
typedef void* (*NXH_ALLOC_FN)(NXH_U64 Owner, NXH_U32 Bytes);

/* Free one extent. Freeing by owner (all of them) is the HOST's job during teardown, not a module's. */
typedef void  (*NXH_FREE_FN)(NXH_U64 Owner, void* Block);

/* The single logging path, so a module's diagnostics do not require its own nt import. */
typedef void  (*NXH_LOG_FN)(const char* Format, ...);

/*
 * A module's command handler. Receives NEXUS_COMMAND* (opaque here -- this header is included by
 * code with no kernel types) and returns an NXCMD_RESULT_* code.
 *
 * Runs on the CALLING usermode thread, in the caller's process context, at PASSIVE_LEVEL, under the
 * command channel's reentrancy guard. Everything Command.c's header says about that context applies
 * verbatim, including: the caller's buffers are HOSTILE, and there is NO SEH.
 */
typedef NXH_U32 (*NXH_COMMAND_FN)(void* Command);

typedef struct _NEXUS_HOST_API
{
	NXH_U64      Magic;        /* NEXUS_HOST_MAGIC, checked FIRST                       */
	NXH_U32      Abi;          /* NEXUS_HOST_ABI                                        */
	NXH_U32      StructSize;   /* sizeof(*this) as the HOST built it                    */

	/*
	 * This module's owner id, assigned by the host at map time. Pass it back to Alloc/Free. It is
	 * handed over rather than chosen so that ownership cannot be spoofed into another module's
	 * extents, and so teardown's "reclaim everything owned by X" is exactly true.
	 */
	NXH_U64      Owner;

	NXH_ALLOC_FN Alloc;
	NXH_FREE_FN  Free;
	NXH_LOG_FN   Log;

	/*
	 * The host's resolved nt call table (NXC_NT_API), so a module reaches the kernel WITHOUT an
	 * import table of its own. Typed as an opaque pointer here because this header is included by
	 * code that has no kernel types; a module casts it to NXC_NT_API* after checking Magic.
	 *
	 * Sharing the host's table rather than resolving a second one per module is deliberate: one
	 * resolved surface means one place to audit what we depend on, and no per-module name list to
	 * appear in a module image.
	 */
	void*        NtApi;

	NXH_U64      KernelBase;   /* ntoskrnl image base, already validated by the host    */
	NXH_U32      KernelSize;
	NXH_U32      Reserved0;

	/*
	 * ============================================================================================
	 * ABI 2 -- REGISTER A COMMAND HANDLER, so a module can be driven from usermode.
	 * ============================================================================================
	 *
	 * Without this, NexusCore's dispatch is a fixed switch and a mapped module has no way to be
	 * asked to do anything. That makes "features live in modules, primitives live in Core" a
	 * statement rather than a design -- the first feature module would have had to be folded into
	 * Core purely to reach the channel, which is exactly how v1 ended up with 1698 lines of
	 * target-specific code inside its foothold.
	 *
	 * Opcode must be >= NXCMD_OP_MODULE_FIRST. Core's own opcodes are refused outright, so a module
	 * cannot shadow `map`, `unmap` or `read` -- deliberately, since a module that could intercept
	 * unmap could refuse its own teardown.
	 *
	 * ⚠ THE HANDLER POINTER MUST LIE INSIDE THE REGISTERING MODULE'S OWN IMAGE, and the host CHECKS
	 * that rather than trusting it. A handler pointing into Core, into another module, or into
	 * arbitrary kernel memory would turn this into a way to call anywhere with kernel privileges
	 * using a usermode-supplied opcode.
	 *
	 * ⚠ REGISTRATIONS DIE WITH THE MODULE. The host clears every handler owned by a module during
	 * unmap, immediately after PREPARE succeeds -- before COMMIT, before the barrier, and long
	 * before the extent is poisoned. A stale handler here would not merely dangle: it would point
	 * into arena memory that gets handed to the NEXT module, so a usermode command would execute
	 * whatever that module put there.
	 *
	 * WHY NO RUNDOWN PROTECTION, which is what a normal driver would use here: every command,
	 * INCLUDING unmap, is serialised by a single interlocked guard at NxcCommandHandler. A module's
	 * handler therefore cannot be executing while its own teardown runs -- the in-flight race that
	 * EX_RUNDOWN_REF exists to solve cannot occur. That guarantee holds ONLY while the command
	 * channel is the sole caller of module handlers. If a handler is ever invoked from a DPC, a
	 * kernel callback or a worker thread, THIS ARGUMENT COLLAPSES and real rundown protection
	 * becomes mandatory. Do not add such a caller without revisiting this.
	 *
	 * @param Owner    the module's own owner id, as handed to it in this struct
	 * @param Opcode   NXCMD_OP_MODULE_FIRST or above
	 * @param Handler  a function inside the module, taking NEXUS_COMMAND*, returning NXCMD_RESULT_*
	 * @return 0 on success, non-zero on refusal
	 */
	NXH_U32 (*RegisterCommand)(NXH_U64 Owner, NXH_U32 Opcode, NXH_COMMAND_FN Handler);
} NEXUS_HOST_API;

#define NXH_OFFSETOF(type, field)     ((NXH_U64)(NXH_U64*)&(((type*)0)->field))
#define NXH_ASSERT_LAYOUT(name, expr) typedef char nxh_assert_##name[(expr) ? 1 : -1]

NXH_ASSERT_LAYOUT(host_size,  sizeof(NEXUS_HOST_API) == 80);  /* 72@1 80@2 */
NXH_ASSERT_LAYOUT(off_regcmd, NXH_OFFSETOF(NEXUS_HOST_API, RegisterCommand) == 72);
NXH_ASSERT_LAYOUT(off_magic,  NXH_OFFSETOF(NEXUS_HOST_API, Magic)      ==  0);
NXH_ASSERT_LAYOUT(off_abi,    NXH_OFFSETOF(NEXUS_HOST_API, Abi)        ==  8);
NXH_ASSERT_LAYOUT(off_size,   NXH_OFFSETOF(NEXUS_HOST_API, StructSize) == 12);
NXH_ASSERT_LAYOUT(off_owner,  NXH_OFFSETOF(NEXUS_HOST_API, Owner)      == 16);
NXH_ASSERT_LAYOUT(off_alloc,  NXH_OFFSETOF(NEXUS_HOST_API, Alloc)      == 24);
NXH_ASSERT_LAYOUT(off_free,   NXH_OFFSETOF(NEXUS_HOST_API, Free)       == 32);
NXH_ASSERT_LAYOUT(off_log,    NXH_OFFSETOF(NEXUS_HOST_API, Log)        == 40);
NXH_ASSERT_LAYOUT(off_ntapi,  NXH_OFFSETOF(NEXUS_HOST_API, NtApi)      == 48);
NXH_ASSERT_LAYOUT(off_kbase,  NXH_OFFSETOF(NEXUS_HOST_API, KernelBase) == 56);
NXH_ASSERT_LAYOUT(off_ksize,  NXH_OFFSETOF(NEXUS_HOST_API, KernelSize) == 64);
/* (review) The only unpinned field here, same as Reserved1 in the boot block. Explicit
 * padding, but pinned deliberately: a trailing reserved word is the natural place a future field
 * gets "reused" into, and in a table handed to a SEPARATELY COMPILED module that reuse must be an
 * ABI decision rather than a silent one. Every field in this header is now checkable at a glance. */
NXH_ASSERT_LAYOUT(off_rsvd0,  NXH_OFFSETOF(NEXUS_HOST_API, Reserved0)  == 68);
