/**
 * @file Tpm2Primary.h
 * @brief `TPM2_CreatePrimary`, the transient object store, and the primary-seed interface.
 *
 * WHY THIS IS THE COMMAND THAT MATTERS. Windows sends exactly two of these at boot — the SRK
 * under `TPM_RH_OWNER` and the EK under `TPM_RH_ENDORSEMENT` — and everything downstream of a
 * provisioned TPM waits on them.
 *
 * ✅ measured ON HARDWARE: twelve calls, three SUCCESS, three real RSA primary keys.
 * Windows then immediately sent `EvictControl`, `FlushContext` and `ContextSave` — commands it had
 * never sent before, because it had never got this far.
 *
 * ⚠ AND IT SETTLED A QUESTION THIS COMMENT USED TO GET WRONG. It said the surviving hypothesis was
 * that `tpm.sys`'s filter opens on PROVISIONING. It does not. Adding this one command to
 * `TPM_CAP_COMMANDS` moved exactly one sweep code from blocked to reachable, and across hardware
 * and ours, in 268 measurements, **no code has ever reached a TPM without being advertised**. The
 * filter is the advertised list, minus the four the Resource Manager reserves. See spec 9.42.
 *
 * ⚠ THE SEED IS SUPPLIED BY THE PLATFORM, AND ITS ABSENCE IS AN HONEST FAILURE. Same shape as the
 * entropy and time sources in Tpm2Dispatch: this layer knows how to *derive* from a seed, and
 * nothing about where one is kept. Without a source, `TPM2_CreatePrimary` answers
 * `TPM_RC_FAILURE`. It does not invent a seed, because a primary key from a fabricated seed is a
 * key nobody can reproduce — which is the exact failure the whole KDFa layer exists to remove.
 */

#pragma once

#include "Tpm2Object.h"
#include "Tpm2Session.h"
#include "Tpm2Nv.h"

//
// The two codes this command produces that no other layer needed. Both cross-checked against
// EDK2's Tpm20.h by `check_tpm2_core`.
//
// ⚠ OBJECT_MEMORY IS A *WARNING*, NOT AN ERROR, and the difference is the whole point of the code.
// RC_WARN means "try again later": the object store is full now, and the caller can flush
// something and retry. Answering an RC_FMT1 failure would tell it the command is wrong when the
// only problem is that three slots are in use.
//
#define TPM2_RC_AUTH_MISSING        (TPM2_RC_VER1 + 0x025)
//
// ⚠ AUTH_CONTEXT IS THE ANSWER TO A *TAG*, NOT TO A BAD PASSWORD. Part 3 clause 28.4.1:
// TPM2_FlushContext takes "no sessions of any type", so a caller that sends TPM_ST_SESSIONS gets
// this rather than an authorisation failure -- the session area is not wrong, it is not allowed.
//
#define TPM2_RC_AUTH_CONTEXT        (TPM2_RC_VER1 + 0x045)
#define TPM2_RC_OBJECT_MEMORY       (TPM2_RC_WARN + 0x002)

//
// TPM2_EvictControl's own codes, Part 3 clause 28.5.1. Cross-checked against EDK2.
//
// (!) IT ALSO USES TPM_RC_NV_DEFINED AND TPM_RC_NV_SPACE, WHICH NOW LIVE IN Tpm2Nv.h. They were
// declared here because EvictControl reached them first; an NV layer exists now and a constant
// belongs with the subsystem it describes rather than with its first caller. Both are RC_VER1,
// so neither carries a field number -- right, because neither is a complaint about something the
// caller sent: one says the destination is occupied, the other says the TPM is full.
//
#define TPM2_RC_HIERARCHY           (TPM2_RC_FMT1 + 0x005)
#define TPM2_RC_RANGE               (TPM2_RC_FMT1 + 0x00D)

/**
 * The platform's primary-seed provider.
 *
 * ⚠ THE SAME HIERARCHY MUST YIELD THE SAME SEED ACROSS REBOOTS, or the SRK changes and Windows
 * logs event 519 exactly as it does today. That durability is the provider's problem, not this
 * file's — which is why it is an interface and not a constant.
 *
 * @param Hierarchy  `TPM_RH_OWNER` (SPS), `TPM_RH_ENDORSEMENT` (EPS), `TPM_RH_PLATFORM` (PPS),
 *                   or `TPM_RH_NULL` (regenerated every reset, by design).
 * @param Seed       receives exactly `SeedLen` octets.
 * @return FALSE if this hierarchy has no seed. Never a partial fill.
 */
typedef BOOLEAN (*TPM2_SEED_FN)(IN UINT32 Hierarchy, OUT UINT8* Seed, IN UINT32 SeedLen);

/** Install the seed provider. NULL removes it, and CreatePrimary then fails honestly. */
VOID Tpm2SetSeedSource(IN TPM2_SEED_FN Fn);

/** Whether a provider is installed. Lets a caller report the reason before a command fails. */
BOOLEAN Tpm2HaveSeedSource(VOID);

//
// The seed size we ask for. Part 1 §11.5: "A proof value of 256 bits is required for a SHA256
// ticket", and every hash we implement is at least that. 32 octets is the smallest size that is
// sufficient for the whole algorithm set.
//
#define TPM2_PRIMARY_SEED_BYTES     32

//
// How many transient objects can be loaded at once.
//
// ⚠ THIS NUMBER IS ALREADY ADVERTISED. `TPM_PT_HR_LOADED_AVAIL` and `TPM_PT_HR_TRANSIENT_AVAIL`
// both report 3 in Tpm2Dispatch, and they were 3 before anything could be loaded. Changing it here
// without changing them there would make the TPM lie about its own capacity in a property any
// caller can read.
//
#define TPM2_MAX_LOADED_OBJECTS     3

//
// TPM_HT_TRANSIENT << 24, Part 2 clause 7.4. Transient handles are 0x80000000 upward.
//
#define TPM2_TRANSIENT_FIRST        0x80000000u

//
// Persistent object handles, Part 2 clause 7.4 and Part 3 clause 28.5.1 rule 3. The range is
// SPLIT BY WHO AUTHORISED THE COMMAND, and the split is not cosmetic: it is what keeps the
// platform OEM's indices from colliding with the owner's.
//
//   TPM_RH_OWNER     0x81000000 .. 0x817FFFFF
//   TPM_RH_PLATFORM  0x81800000 .. 0x81FFFFFF
//
// Windows asks for 0x81000001 (the SRK) and 0x81010001 (the EK), both under OWNER auth — which
// is legal because Part 3 rule 2 says owner auth covers the Storage *and* Endorsement
// hierarchies. Measured, not assumed: both EvictControl commands captured this boot carry
// authHandle 0x40000001.
//
#define TPM2_PERSISTENT_FIRST       0x81000000u
#define TPM2_PERSISTENT_OWNER_LAST  0x817FFFFFu
#define TPM2_PERSISTENT_LAST        0x81FFFFFFu

//
// How many persistent objects fit.
//
// ⚠ SEVEN, BECAUSE `TPM_PT_HR_PERSISTENT_AVAIL` HAS ADVERTISED SEVEN SINCE BEFORE ANY EXISTED.
// Hardware reports 4 used and 17 available, so 21 — and matching that would cost 21 slots of
// ~3.4 KB, about 71 KB of BSS in both images, to hold RSA keys for objects nothing has asked for
// yet. The capacity difference is a KNOWN, EXISTING distinguisher; closing it by advertising 21
// while holding 7 would be the self-contradiction this project refuses everywhere else.
//
#define TPM2_MAX_PERSISTENT_OBJECTS 7

/** One loaded transient object. */
typedef struct _TPM2_OBJECT_SLOT {
	BOOLEAN      Loaded;
	UINT32       Handle;
	UINT32       Hierarchy;
	TPM2_PUBLIC  Public;
	TPM2_RSA_KEY Key;
	UINT16       NameLen;
	UINT8        Name[2 + TPM2_MAX_DIGEST_SIZE];
	UINT16       AuthLen;
	UINT8        Auth[TPM2_MAX_DIGEST_SIZE];    /* the object's authValue, trailing zeros kept */
} TPM2_OBJECT_SLOT;

/**
 * Empty the object store.
 *
 * ⚠ CALLED FROM TPM2_Startup(CLEAR), because Part 1 is explicit that transient objects do not
 * survive a TPM Reset. Leaving them loaded across a startup would hand out handles to objects the
 * caller believes were destroyed.
 */
VOID Tpm2ObjectStoreReset(VOID);

/** How many slots are in use. Answers `TPM_PT_HR_LOADED` truthfully. */
UINT32 Tpm2ObjectStoreLoaded(VOID);

/** The slot a handle refers to, or NULL. */
CONST TPM2_OBJECT_SLOT* Tpm2ObjectFind(IN UINT32 Handle);

/**
 * Release one loaded object. FALSE if no slot holds that handle.
 *
 * ⚠ THE SLOT IS ZEROED, NOT MARKED FREE. It holds an RSA private key, and a "free" slot that
 * still contains P and Q is a key the caller believes was destroyed sitting in the driver's BSS.
 */
BOOLEAN Tpm2ObjectFlush(IN UINT32 Handle);

/**
 * How many non-zero octets remain in slots that are NOT loaded. **Always zero on a correct
 * implementation**, and that is the whole point of it existing.
 *
 * ⚠ THIS EXISTS BECAUSE A FLUSH THAT ONLY CLEARS A FLAG PASSES EVERY BEHAVIOURAL TEST. The
 * handle stops resolving, the count drops, the next CreatePrimary succeeds and overwrites the
 * slot — so nothing observable through the command interface ever differs, while an RSA private
 * key sits in the driver's BSS until something happens to reuse that slot. Proven by writing the
 * flag-only version deliberately and watching the suite stay green.
 *
 * Same guarantee, and the same shape of check, as the event log's "the tail past Used must be
 * ZERO": a property about memory that no amount of asking the interface politely can reach.
 */
UINT32 Tpm2ObjectStoreResidue(VOID);

/** How many persistent objects exist. Answers `TPM_PT_HR_PERSISTENT` truthfully. */
UINT32 Tpm2PersistentCount(VOID);

/**
 * Enumerate loaded handles of one type, ASCENDING, for `TPM_CAP_HANDLES`.
 *
 * Part 3 clause 30.2: the capability returns *"a list of all of the handles within the range of
 * handles of the type indicated in property"*. The TYPE is the high octet of `First`, so
 * `0x80000000` asks for transient objects and `0x81000000` for persistent ones — the same
 * question about two different stores.
 *
 * ⚠ ASCENDING IS PART OF THE ANSWER, NOT A COURTESY. `property` is a *starting* handle so a
 * caller can page through a list longer than one response, and paging is only meaningful if the
 * order is stable and increasing. Hardware returns `81000001 81000002 81000009 81010001`, sorted;
 * our slots are in allocation order, which is not.
 *
 * @param First    the first handle to report, inclusive. Its high octet selects the type.
 * @param Max      how many `Handles` can hold.
 * @return how many were written.
 */
UINT32 Tpm2ObjectEnumerate(
	IN  UINT32  First,
	IN  UINT32  Max,
	OUT UINT32* Handles
	);

/**
 * Empty the PERSISTENT store.
 *
 * ⚠ NOT CALLED FROM TPM2_Startup, AND THAT IS THE ENTIRE POINT OF THE WORD "PERSISTENT". Part 3
 * clause 28.5.1: *"A transient object is one that may be removed from TPM memory using either
 * TPM2_FlushContext() or TPM2_Startup(). A persistent object is not removed from TPM memory by
 * TPM2_FlushContext() or TPM2_Startup()."* This exists for `TPM2_Clear`, which is the command
 * that is actually allowed to do it.
 */
VOID Tpm2PersistentReset(VOID);

/** Non-zero octets in unused persistent slots. Always zero; see Tpm2ObjectStoreResidue. */
UINT32 Tpm2PersistentResidue(VOID);

/**
 * The object's Qualified Name, Part 1 §23.5.
 *
 * ⚠ A PRIMARY OBJECT'S PARENT HAS NO NAME OF ITS OWN, AND THE SPEC SAYS WHAT TO USE INSTEAD:
 * *"Both the Name and Qualified Name for a Primary Seed are the handle of the Primary Seed ...
 * This makes the QN of a Primary Object equal to* `QN = H_nameAlg(hierarchy handle ‖ Primary
 * Object Name)`*"*. So the hash covers four octets of handle followed by the object's whole Name
 * — algorithm prefix included — and the result is itself Name-formatted, `nameAlg ‖ digest`.
 */
BOOLEAN Tpm2ObjectQualifiedName(
	IN  CONST TPM2_OBJECT_SLOT* Slot,
	OUT UINT8*                  Qn,
	OUT UINT16*                 QnLen
	);

/**
 * `TPM2_EvictControl`, Part 3 clause 28.5 — make a transient object persistent, or evict one.
 *
 * ⚠ THE TRANSIENT OBJECT SURVIVES. Part 3 rule 7: *"the object referenced by objectHandle will
 * not be flushed and both objectHandle and persistentHandle may be used to access the object."*
 * Persisting is a COPY. Windows relies on it: it persists, then flushes the transient handle
 * separately, and a TPM that consumed the object would leave it flushing a handle that is
 * already gone.
 *
 * ⚠ AND EVICTION DOES NOT PRODUCE A TRANSIENT OBJECT EITHER — Part 3 says why: *"this would
 * prevent the immediate revocation of an object by removing it from persistent memory."*
 */
UINT32 Tpm2DoEvictControl(
	IN     CONST UINT8* In,
	IN     UINT32       Size,
	OUT    UINT8*       Out,
	IN     UINT32       OutSize,
	OUT    UINT32*      Written
	);

/**
 * `TPM2_FlushContext`, Part 3 clause 28.4 — given the already-unmarshalled `flushHandle`.
 *
 * ⚠ `flushHandle` IS A PARAMETER, NOT A HANDLE, and Part 3 says why: *"If it were in the handle
 * area, the TPM would validate that the context for the referenced entity is in the TPM. When a
 * TPM2_FlushContext() references a saved session context, it is not necessary for the context to
 * be in the TPM."* Hardware confirms it independently — its `TPMA_CC` for this command is
 * `0x00000165`, **cHandles = 0**. So every error here is numbered as a PARAMETER.
 *
 * @return TPM_RC_SUCCESS, or a parameter-numbered response code.
 */
UINT32 Tpm2DoFlushContext(IN UINT32 FlushHandle);

/**
 * `TPM2_CreatePrimary`, Part 3 clause 24.1.
 *
 *     primaryHandle          the hierarchy, authorised with a session
 *     inSensitive            TPM2B_SENSITIVE_CREATE
 *     inPublic               TPM2B_PUBLIC — the template
 *     outsideInfo            TPM2B_DATA
 *     creationPCR            TPML_PCR_SELECTION
 *  -> objectHandle, outPublic, creationData, creationHash, creationTicket, name
 *
 * @param Written  receives the response length. Zero means nothing was written.
 * @return the response code, which is also written into the response header.
 */
UINT32 Tpm2DoCreatePrimary(
	IN     CONST TPM2_PCR_BANK* Bank,
	IN     CONST UINT8*         In,
	IN     UINT32               Size,
	OUT    UINT8*               Out,
	IN     UINT32               OutSize,
	OUT    UINT32*              Written
	);
