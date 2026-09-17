/**
 * @file Tpm2Dispatch.c
 * @brief The shared TPM command dispatcher. See Tpm2Dispatch.h for why it exists.
 *
 * ⚠ THE COMMAND SET HERE IS DELIBERATELY SMALL AND HONEST ABOUT IT. Anything not implemented
 * answers TPM_RC_COMMAND_CODE, which is what a real TPM returns for a command it does not
 * support -- not a fabricated success. The list grows from MEASURED demand: the servicer traces
 * what Windows actually asks for, and the next build implements exactly that.
 */

#include "Tpm2Dispatch.h"
#include "Tpm2Profile.h"
#include "Tpm2Primary.h"

//
// TPM_CAP values, Part 2 Table 21. Only the one we answer is named.
//
#define TPM2_CAP_ALGS               0x00000000
#define TPM2_CAP_HANDLES            0x00000001
#define TPM2_CAP_COMMANDS           0x00000002
#define TPM2_CAP_PCRS               0x00000005
#define TPM2_CAP_TPM_PROPERTIES     0x00000006

//
// TPM_PT constants, Part 2 Table 23. PT_FIXED is the first group.
//
#define TPM2_PT_FIXED               0x00000100
#define TPM2_PT_FAMILY_INDICATOR    (TPM2_PT_FIXED + 0)
#define TPM2_PT_LEVEL               (TPM2_PT_FIXED + 1)
#define TPM2_PT_REVISION            (TPM2_PT_FIXED + 2)
#define TPM2_PT_DAY_OF_YEAR         (TPM2_PT_FIXED + 3)
#define TPM2_PT_YEAR                (TPM2_PT_FIXED + 4)
#define TPM2_PT_MANUFACTURER        (TPM2_PT_FIXED + 5)
#define TPM2_PT_VENDOR_STRING_1     (TPM2_PT_FIXED + 6)
#define TPM2_PT_VENDOR_STRING_2     (TPM2_PT_FIXED + 7)
#define TPM2_PT_VENDOR_STRING_3     (TPM2_PT_FIXED + 8)
#define TPM2_PT_VENDOR_STRING_4     (TPM2_PT_FIXED + 9)
#define TPM2_PT_VENDOR_TPM_TYPE     (TPM2_PT_FIXED + 10)
#define TPM2_PT_FIRMWARE_VERSION_1  (TPM2_PT_FIXED + 11)
#define TPM2_PT_FIRMWARE_VERSION_2  (TPM2_PT_FIXED + 12)
#define TPM2_PT_INPUT_BUFFER        (TPM2_PT_FIXED + 13)
#define TPM2_PT_PCR_COUNT           (TPM2_PT_FIXED + 18)
#define TPM2_PT_PCR_SELECT_MIN      (TPM2_PT_FIXED + 19)
#define TPM2_PT_MAX_COMMAND_SIZE    (TPM2_PT_FIXED + 30)
#define TPM2_PT_MAX_RESPONSE_SIZE   (TPM2_PT_FIXED + 31)
#define TPM2_PT_HR_TRANSIENT_MIN    (TPM2_PT_FIXED + 14)
#define TPM2_PT_HR_PERSISTENT_MIN   (TPM2_PT_FIXED + 15)
#define TPM2_PT_HR_LOADED_MIN       (TPM2_PT_FIXED + 16)
#define TPM2_PT_ACTIVE_SESSIONS_MAX (TPM2_PT_FIXED + 17)
#define TPM2_PT_CONTEXT_GAP_MAX     (TPM2_PT_FIXED + 20)
#define TPM2_PT_NV_COUNTERS_MAX     (TPM2_PT_FIXED + 22)
#define TPM2_PT_NV_INDEX_MAX        (TPM2_PT_FIXED + 23)
#define TPM2_PT_MEMORY              (TPM2_PT_FIXED + 24)
#define TPM2_PT_CLOCK_UPDATE        (TPM2_PT_FIXED + 25)
#define TPM2_PT_CONTEXT_HASH        (TPM2_PT_FIXED + 26)
#define TPM2_PT_CONTEXT_SYM         (TPM2_PT_FIXED + 27)
#define TPM2_PT_CONTEXT_SYM_SIZE    (TPM2_PT_FIXED + 28)
#define TPM2_PT_ORDERLY_COUNT       (TPM2_PT_FIXED + 29)
#define TPM2_PT_MAX_DIGEST          (TPM2_PT_FIXED + 32)
#define TPM2_PT_MAX_OBJECT_CONTEXT  (TPM2_PT_FIXED + 33)
#define TPM2_PT_MAX_SESSION_CONTEXT (TPM2_PT_FIXED + 34)
#define TPM2_PT_PS_FAMILY_INDICATOR (TPM2_PT_FIXED + 35)
#define TPM2_PT_PS_LEVEL            (TPM2_PT_FIXED + 36)
#define TPM2_PT_PS_REVISION         (TPM2_PT_FIXED + 37)
#define TPM2_PT_PS_DAY_OF_YEAR      (TPM2_PT_FIXED + 38)
#define TPM2_PT_PS_YEAR             (TPM2_PT_FIXED + 39)
#define TPM2_PT_SPLIT_MAX           (TPM2_PT_FIXED + 40)
#define TPM2_PT_TOTAL_COMMANDS      (TPM2_PT_FIXED + 41)
#define TPM2_PT_LIBRARY_COMMANDS    (TPM2_PT_FIXED + 42)
#define TPM2_PT_VENDOR_COMMANDS     (TPM2_PT_FIXED + 43)
#define TPM2_PT_NV_BUFFER_MAX       (TPM2_PT_FIXED + 44)
#define TPM2_PT_MODES               (TPM2_PT_FIXED + 45)
#define TPM2_PT_MAX_CAP_BUFFER      (TPM2_PT_FIXED + 46)

//
// PT_VAR, Part 2 Table 23 -- the TPM's CURRENT state rather than its fixed dimensions.
// Windows asked for 0x200 and 0x20E and got empty lists; these are all things we know exactly.
//
#define TPM2_PT_VAR                 0x00000200
#define TPM2_PT_PERMANENT           (TPM2_PT_VAR + 0)
#define TPM2_PT_STARTUP_CLEAR       (TPM2_PT_VAR + 1)
#define TPM2_PT_HR_NV_INDEX         (TPM2_PT_VAR + 2)
#define TPM2_PT_HR_LOADED           (TPM2_PT_VAR + 3)
#define TPM2_PT_HR_LOADED_AVAIL     (TPM2_PT_VAR + 4)
#define TPM2_PT_HR_ACTIVE           (TPM2_PT_VAR + 5)
#define TPM2_PT_HR_ACTIVE_AVAIL     (TPM2_PT_VAR + 6)
#define TPM2_PT_HR_TRANSIENT_AVAIL  (TPM2_PT_VAR + 7)
#define TPM2_PT_HR_PERSISTENT       (TPM2_PT_VAR + 8)
#define TPM2_PT_HR_PERSISTENT_AVAIL (TPM2_PT_VAR + 9)
#define TPM2_PT_NV_COUNTERS         (TPM2_PT_VAR + 10)
#define TPM2_PT_NV_COUNTERS_AVAIL   (TPM2_PT_VAR + 11)
#define TPM2_PT_ALGORITHM_SET       (TPM2_PT_VAR + 12)
#define TPM2_PT_LOADED_CURVES       (TPM2_PT_VAR + 13)
#define TPM2_PT_LOCKOUT_COUNTER     (TPM2_PT_VAR + 14)
#define TPM2_PT_MAX_AUTH_FAIL       (TPM2_PT_VAR + 15)
#define TPM2_PT_LOCKOUT_INTERVAL    (TPM2_PT_VAR + 16)
#define TPM2_PT_LOCKOUT_RECOVERY    (TPM2_PT_VAR + 17)
#define TPM2_PT_NV_WRITE_RECOVERY   (TPM2_PT_VAR + 18)
#define TPM2_PT_AUDIT_COUNTER_0     (TPM2_PT_VAR + 19)
#define TPM2_PT_AUDIT_COUNTER_1     (TPM2_PT_VAR + 20)

//
// TPMA_STARTUP_CLEAR after TPM2_Startup(CLEAR): all four hierarchies enabled.
// phEnable(0) | shEnable(1) | ehEnable(2) | phEnableNV(3).
//
#define TPM2_STARTUP_CLEAR_ENABLED  0x0000000Fu

#define TPM2_CC_GET_RANDOM_LOCAL    0x0000017B

//
// The PC Client platform we present as, from PTP 1.07. PS_* describe the PLATFORM spec, not
// the TPM library spec -- a different document with a different date, and conflating them is
// an inconsistency a verifier can check.
//
#define TPM2_PS_FAMILY_PC_CLIENT    1
#define TPM2_PS_REVISION_1_07       TPM2_PROFILE_PS_REVISION
#define TPM2_PS_YEAR                TPM2_PROFILE_PS_YEAR
#define TPM2_PS_DAY_OF_YEAR         TPM2_PROFILE_PS_DAY_OF_YEAR

//
// (!) THE NUMBER OF COMMANDS WE ACTUALLY IMPLEMENT. Claiming more would look more like a real
// TPM right up until someone asks TPM_CAP_COMMANDS and gets a shorter list -- a
// self-contradiction, which is worse than a small number. Update this when the dispatcher grows.
//
#define TPM2_OUR_COMMAND_COUNT      14        /* EvictControl, CreatePrimary, SelfTest,
                                                 Startup, Shutdown, FlushContext,
                                                 NV_ReadPublic, ReadPublic, GetCapability,
                                                 GetRandom, GetTestResult, PCR_Read,
                                                 ReadClock, PCR_Extend */

//
// TPM_CC, Part 2 Table 12. GetTestResult is here because the CRB trace recorded Windows asking
// for it and us refusing -- not because a list said it might.
//
#define TPM2_CC_GET_TEST_RESULT     0x0000017C

//
// Added on MEASURED demand: the v2 trace census recorded Windows sending these and us
// refusing with TPM_RC_COMMAND_CODE. All three arrived at sequences 6-15 of a 166-command
// boot -- inside the window the OLD 64-slot ring had already overwritten, which is why they
// went unseen for two builds.
//
#define TPM2_CC_NV_READ_PUBLIC      0x00000169
#define TPM2_CC_READ_PUBLIC         0x00000173
#define TPM2_CC_READ_CLOCK          0x00000181
#define TPM2_CC_CREATE_PRIMARY      0x00000131
#define TPM2_CC_FLUSH_CONTEXT       0x00000165
#define TPM2_CC_EVICT_CONTROL       0x00000120
#define TPM2_CC_SHUTDOWN_LOCAL      0x00000145
#define TPM2_CC_PCR_READ_LOCAL      0x0000017E
#define TPM2_CC_PCR_EXTEND_LOCAL    0x00000182

//
// Handle ranges, Part 2 Table 28 (TPM_HT). Only the two an object handle may name are
// needed here; the rest of the space is a TPMI_DH_OBJECT type error, not a missing object.
//
#define TPM2_HT_TRANSIENT_BASE      0x80000000u
#define TPM2_HT_PERSISTENT_BASE     0x81000000u
#define TPM2_HT_PERSISTENT_END      0x81FFFFFFu
#define TPM2_HT_NV_INDEX_BASE       0x01000000u
#define TPM2_HT_NV_INDEX_END        0x01FFFFFFu

//
// TPMS_TIME_INFO on the wire, Part 2 Tables 142 and 143:
//   time (UINT64) | clock (UINT64) | resetCount (UINT32) | restartCount (UINT32) | safe (1)
//
#define TPM2_TIME_INFO_SIZE         25

//
// Our own dimensions. The command/response buffer is the CRB data buffer, PTP's maximum for a
// single 4 KB locality page: 0x1000 - 0x80 = 0xF80 = 3968.
//
#define TPM2_OUR_BUFFER_SIZE        3968

//
// ⚠ THE IDENTITY WE PRESENT. `INTC` matches what the TCG2 protocol already reports, and the two
// MUST agree: a boot loader that reads INTC over TCG2 and an OS that reads something else over the
// CRB have caught us in a contradiction that no real TPM could produce.
//
#define TPM2_MANUFACTURER_INTC      0x494E5443u   /* 'I','N','T','C' */
#define TPM2_FAMILY_2_0             0x322E3000u   /* "2.0\0" */

/*
 * Family indicator is "2.0" as four ASCII bytes, level 0, and revision is the Library revision
 * times 100 -- Library 185 is spelled 1.85, so the field reads 185.
 */
#define TPM2_SPEC_LEVEL             0
//
// ⚠ THESE ARE NO LONGER OURS TO CHOOSE. They come from Tpm2Profile.h, which holds what a
// REAL Intel PTT on this machine reports. We used to publish revision 185 with the PTP 1.07
// date -- accurate about the documents we implement against, and unlike any shipping TPM,
// which is exactly the kind of diligence that fingerprints you.
//
#define TPM2_SPEC_REVISION          TPM2_PROFILE_REVISION
#define TPM2_SPEC_YEAR              TPM2_PROFILE_YEAR
#define TPM2_SPEC_DAY_OF_YEAR       TPM2_PROFILE_DAY_OF_YEAR

/*
 * THE COMMANDS WE IMPLEMENT, in ascending command-code order because TPM_CAP_COMMANDS is
 * defined to return them that way and a caller pages through by code.
 *
 * ⚠ THIS TABLE AND TPM2_OUR_COMMAND_COUNT MUST AGREE, and a C_ASSERT below enforces it. They
 * disagreed once already -- the count said 4 while TPM_CAP_COMMANDS returned nothing -- and
 * Windows caught it. A compile-time check is cheaper than another reboot.
 */
//
// ⚠ THESE ARE TPMA_CC VALUES, NOT COMMAND CODES, AND THE DIFFERENCE WAS A REAL BUG.
//
// Part 2 Table 43: TPM_CAP_COMMANDS returns TPML_CCA -- a list of TPMA_CC, which packs the
// command index into bits 15:0 and carries attributes above it: nv at 22, extensive 23,
// flushed 24, cHandles 27:25, rHandle 28, V 29. cHandles is how the Resource Manager learns
// how many handles a command takes.
//
// We used to emit bare command codes with every attribute zero, and the comment here asserted
// that zero was correct "for all four of ours". It was not. Genuine Intel PTT on this machine
// reports nv on Startup and SelfTest, and cHandles=1 on both ReadPublic commands.
//
// ⚠ THE VALUES ARE MEASURED, NOT DERIVED. Each one is what real hardware returned for
// that exact command -- a PTT capture taken, TPM_CAP_COMMANDS. Deriving them
// from Part 3 by hand would have been another table to get 34/46 wrong.
//
// Ascending by command index, because TPM_CAP_COMMANDS pages from a starting index.
//
STATIC CONST UINT32 mOurCommands[] = {
	//
	// (!) nv IS SET, AND IT IS THE ONLY COMMAND WE ADVERTISE THAT SETS IT. TPMA_CC bit 22 says
	// the command may write NV, which EvictControl does by definition -- persisting an object
	// is the write. The Resource Manager uses it to know a command can fail for NV reasons and
	// may need retrying, so clearing it would be a promise we cannot keep.
	//
	0x04400120u,  /* 0x120 */   /* EvictControl   nv | cHandles=2   */
	0x12000131u,  /* 0x131 */   /* CreatePrimary  cHandles=1 rHandle */
	0x00400143u,  /* 0x143 */   /* SelfTest       nv                */
	0x00400144u,  /* 0x144 */   /* Startup        nv                */
	//
	// (!) SHUTDOWN IS ADVERTISED AND CAN NEVER BE REACHED THROUGH A SWEEP, and that is not a
	// contradiction. It is one of the four the Resource Manager reserves for itself -- with
	// Startup, ContextLoad and ContextSave -- so tpm.sys answers it rather than forwarding it.
	// Hardware advertises it on exactly the same terms. Advertising what we implement is the
	// rule; whether a user can reach it is Windows' business, not ours.
	//
	0x00400145u,  /* 0x145 */   /* Shutdown       nv                */
	//
	// (!) 0x00000165 -- NO ATTRIBUTES AT ALL, AND cHandles = 0 IS THE INTERESTING ZERO.
	// FlushContext takes its handle as a PARAMETER, so it declares no command handles, which
	// is what Part 3 clause 28.4.1 says in prose and what hardware reports in one word.
	//
	0x00000165u,  /* 0x165 */   /* FlushContext   cHandles=0        */
	0x02000169u,  /* 0x169 */   /* NV_ReadPublic  cHandles=1        */
	0x02000173u,  /* 0x173 */   /* ReadPublic     cHandles=1        */
	0x0000017Au,  /* 0x17A */   /* GetCapability                    */
	0x0000017Bu,  /* 0x17B */   /* GetRandom                        */
	0x0000017Cu,  /* 0x17C */   /* GetTestResult                    */
	//
	// (!) PCR_Read IS THE ONLY ONE OF THESE WITH NO ATTRIBUTES AT ALL. It takes no handle and
	// writes no NV, because Part 3 clause 22.4.1 says so outright: "No authorization is required
	// to read a PCR and any implemented PCR may be read from any locality." PCR_Extend, two lines
	// down, carries both -- the asymmetry is the whole difference between reading and extending.
	//
	0x0000017Eu,  /* 0x17E */   /* PCR_Read                         */
	0x00000181u,  /* 0x181 */   /* ReadClock                        */
	0x02400182u,  /* 0x182 */   /* PCR_Extend     nv | cHandles=1   */
};

//
// The command index out of a TPMA_CC. Bits 15:0, per Part 2 Table 43.
//
#define TPM2_CCA_INDEX(V)           ((V) & 0xFFFFu)

//
// (!) A NEGATIVE-ARRAY-SIZE ASSERT, NOT C_ASSERT. This file must compile under the UEFI
// toolchain, the WDK (via uefi_shim) AND a host compiler with only tools/tpm2_host_test/Uefi.h,
// which has no C_ASSERT -- the same reason NexusCoreBoot.h uses this idiom for its layout locks.
// A construct that depends on any one of those headers breaks the other two.
//
#define TPM2_ASSERT(name, expr) typedef char tpm2_assert_##name[(expr) ? 1 : -1]

TPM2_ASSERT(command_count,
            sizeof(mOurCommands) / sizeof(mOurCommands[0]) == TPM2_OUR_COMMAND_COUNT);

/*
 * The hashes Tpm2Hash actually implements. TPMA_ALGORITHM bit 2 is `hash`.
 *
 * ⚠ SHA-384 AND SHA-512 ARE LISTED EVEN THOUGH THE PCR BANK IS SHA-256 ONLY, and the two are
 * consistent: a TPM may implement a hash without allocating a PCR bank for it, and
 * TPM_CAP_PCRS below reports exactly one bank. What would be inconsistent is listing an
 * algorithm Tpm2Hash cannot compute.
 */
#define TPMA_ALGORITHM_HASH   0x00000004u

STATIC CONST UINT16 mOurHashes[] = {
	TPM2_ALG_SHA256,
	0x000C,   /* SHA-384 */
	0x000D,   /* SHA-512 */
};

//
// (!) NULL UNTIL A PLATFORM INSTALLS ONE, and GetRandom fails while it is. See the header: a
// fallback here would be a TPM handing out predictable bytes labelled random.
//
STATIC TPM2_ENTROPY_FN mEntropy = NULL;

//
// The platform clock. NULL until a platform installs one, and ReadClock says so rather than
// inventing a value -- the same rule entropy follows, for the same reason.
//
STATIC TPM2_TIME_FN mTime = NULL;

VOID
Tpm2SetEntropySource(
	IN TPM2_ENTROPY_FN Fn
	)
{
	mEntropy = Fn;
}

VOID
Tpm2SetTimeSource(
	IN TPM2_TIME_FN Fn
	)
{
	mTime = Fn;
}

/*
 * The response code for a parameter area that is not the size the command needs.
 *
 * ⚠ TOO FEW AND TOO MANY ARE DIFFERENT ERRORS, and we answered both with
 * TPM_RC_COMMAND_SIZE. Real Intel PTT answers a bare header with TPM_RC_INSUFFICIENT, and it
 * is right: TPM_RC_COMMAND_SIZE means the DECLARED commandSize disagrees with the octets
 * received, which is a framing error. Running out of octets while unmarshalling a parameter is
 * TPM_RC_INSUFFICIENT; having octets left over afterwards is TPM_RC_SIZE.
 *
 * Found by comparing against hardware: 90 command codes where PTT said 0x09A and we said
 * 0x142. Fixing it is spec-correctness, not mimicry -- the specification already said this.
 */
STATIC
UINT32
ParamSizeRc(
	IN UINT32 Have,
	IN UINT32 Want
	)
{
	return (Have < Want) ? TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1)
	                     : TPM2_RC_P(TPM2_RC_SIZE, 1);
}
STATIC
UINT32
ShortResponse(
	OUT UINT8*  Out,
	IN  UINT32  OutSize,
	IN  UINT32  ResponseCode
	)
{
	if (Out == NULL || OutSize < TPM2_HEADER_SIZE)
		return 0;
	Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, TPM2_HEADER_SIZE, ResponseCode);
	return TPM2_HEADER_SIZE;
}

/*
 * One TPMS_TAGGED_PROPERTY. Returns the value for a property, or FALSE if we do not publish it --
 * a TPM answers only the properties it has, and inventing one would be a lie a verifier can check
 * against the others.
 */
/*
 * The TPM's CURRENT state. Every one of these is a fact we can state exactly, because we know
 * what we have: no owner, nothing loaded, no NV, no lockout.
 *
 * ⚠ THE ZEROES HERE ARE NOT PLACEHOLDERS. HR_LOADED = 0 because nothing is loaded;
 * NV_COUNTERS = 0 because there is no NV. They will change when those subsystems exist, which
 * is the difference between an honest zero and an unimplemented one.
 */
STATIC
BOOLEAN
VarProperty(
	IN  UINT32  Property,
	IN  CONST TPM2_PCR_BANK* Bank,
	OUT UINT32* Value
	)
{
	switch (Property)
	{
	//
	// TPMA_PERMANENT: no authorisation has been set, nothing is in lockout. All zero is the
	// truthful description of a TPM nobody has taken ownership of.
	//
	case TPM2_PT_PERMANENT:          *Value = 0;                      return TRUE;
	//
	// TPMA_STARTUP_CLEAR: the hierarchies are enabled once Startup has run. Reporting them
	// enabled before that would claim a state the TPM is not in, so this follows Bank->Started.
	//
	case TPM2_PT_STARTUP_CLEAR:
		*Value = (Bank != NULL && Bank->Started) ? TPM2_STARTUP_CLEAR_ENABLED : 0;
		return TRUE;

	case TPM2_PT_HR_NV_INDEX:        *Value = 0;                      return TRUE;
	//
	// (!) THESE WERE HONEST ZEROES AND ARE NOW HONEST COUNTS. Before CreatePrimary nothing
	// could be loaded, so 0 was a fact; leaving it at 0 now would be a lie a caller can catch
	// by loading an object and reading the property back.
	//
	case TPM2_PT_HR_LOADED:          *Value = Tpm2ObjectStoreLoaded(); return TRUE;
	case TPM2_PT_HR_LOADED_AVAIL:
		*Value = TPM2_MAX_LOADED_OBJECTS - Tpm2ObjectStoreLoaded();
		return TRUE;
	case TPM2_PT_HR_ACTIVE:          *Value = 0;                      return TRUE;
	case TPM2_PT_HR_ACTIVE_AVAIL:    *Value = 64;                     return TRUE;
	case TPM2_PT_HR_TRANSIENT_AVAIL:
		*Value = TPM2_MAX_LOADED_OBJECTS - Tpm2ObjectStoreLoaded();
		return TRUE;
	//
	// Honest zeroes when nothing could be persisted; honest counts now that something can.
	//
	case TPM2_PT_HR_PERSISTENT:      *Value = Tpm2PersistentCount(); return TRUE;
	case TPM2_PT_HR_PERSISTENT_AVAIL:
		*Value = TPM2_MAX_PERSISTENT_OBJECTS - Tpm2PersistentCount();
		return TRUE;
	case TPM2_PT_NV_COUNTERS:        *Value = 0;                      return TRUE;
	case TPM2_PT_NV_COUNTERS_AVAIL:  *Value = 0;                      return TRUE;
	case TPM2_PT_ALGORITHM_SET:      *Value = 0;                      return TRUE;
	case TPM2_PT_LOADED_CURVES:      *Value = 0;   /* no ECC yet */   return TRUE;
	//
	// Dictionary-attack state. Nothing has failed, and the thresholds are the PC Client
	// defaults -- 32 failures, 2 hours to recover one, 24 hours for lockout.
	//
	case TPM2_PT_LOCKOUT_COUNTER:    *Value = 0;                      return TRUE;
	case TPM2_PT_MAX_AUTH_FAIL:      *Value = 32;                     return TRUE;
	case TPM2_PT_LOCKOUT_INTERVAL:   *Value = 7200;                   return TRUE;
	case TPM2_PT_LOCKOUT_RECOVERY:   *Value = 86400;                  return TRUE;
	case TPM2_PT_NV_WRITE_RECOVERY:  *Value = 0;                      return TRUE;
	case TPM2_PT_AUDIT_COUNTER_0:    *Value = 0;                      return TRUE;
	case TPM2_PT_AUDIT_COUNTER_1:    *Value = 0;                      return TRUE;
	default:                                                          return FALSE;
	}
}

STATIC
BOOLEAN
FixedProperty(
	IN  UINT32  Property,
	OUT UINT32* Value
	)
{
	switch (Property)
	{
	case TPM2_PT_FAMILY_INDICATOR:   *Value = TPM2_FAMILY_2_0;        return TRUE;
	case TPM2_PT_LEVEL:              *Value = TPM2_SPEC_LEVEL;        return TRUE;
	case TPM2_PT_REVISION:           *Value = TPM2_SPEC_REVISION;     return TRUE;
	case TPM2_PT_DAY_OF_YEAR:        *Value = TPM2_SPEC_DAY_OF_YEAR;  return TRUE;
	case TPM2_PT_YEAR:               *Value = TPM2_SPEC_YEAR;         return TRUE;
	case TPM2_PT_MANUFACTURER:       *Value = TPM2_MANUFACTURER_INTC; return TRUE;
	case TPM2_PT_VENDOR_STRING_1:    *Value = TPM2_PROFILE_VENDOR_STRING_1; return TRUE;
	case TPM2_PT_VENDOR_STRING_2:    *Value = 0;                      return TRUE;
	case TPM2_PT_VENDOR_STRING_3:    *Value = 0;                      return TRUE;
	case TPM2_PT_VENDOR_STRING_4:    *Value = 0;                      return TRUE;
	case TPM2_PT_VENDOR_TPM_TYPE:    *Value = TPM2_PROFILE_VENDOR_TPM_TYPE; return TRUE;
	case TPM2_PT_FIRMWARE_VERSION_1: *Value = TPM2_PROFILE_FIRMWARE_VERSION_1; return TRUE;
	case TPM2_PT_FIRMWARE_VERSION_2: *Value = TPM2_PROFILE_FIRMWARE_VERSION_2; return TRUE;

	//
	// (!) THESE DESCRIBE US, AND WE KNOW THEM EXACTLY. Windows asked for the whole PT_FIXED run
	// and accepted their absence, so adding them is not chasing a requirement -- it is reporting
	// dimensions of our own implementation that we were failing to state.
	//
	case TPM2_PT_INPUT_BUFFER:       *Value = TPM2_OUR_BUFFER_SIZE;   return TRUE;
	case TPM2_PT_MAX_COMMAND_SIZE:   *Value = TPM2_OUR_BUFFER_SIZE;   return TRUE;
	case TPM2_PT_MAX_RESPONSE_SIZE:  *Value = TPM2_OUR_BUFFER_SIZE;   return TRUE;
	case TPM2_PT_PCR_COUNT:          *Value = TPM2_PCR_COUNT;         return TRUE;
	case TPM2_PT_PCR_SELECT_MIN:     *Value = 3;                      return TRUE;
	//
	// (!) 32, NOT 64, AND THE REASON IS HONESTY ABOUT WHAT IS REACHABLE. Tpm2Hash implements
	// SHA-384 and SHA-512, so the crypto could produce a 64-byte digest -- but no COMMAND exposes
	// them: the PCR bank is SHA-256 and PCR_Extend/PCR_Read are what exist. Reporting 64 would
	// advertise a capability a caller cannot actually reach.
	//
	case TPM2_PT_MAX_DIGEST:         *Value = TPM2_SHA256_DIGEST_SIZE; return TRUE;

	//
	// ---- CAPACITIES WE CLAIM BUT DO NOT YET IMPLEMENT ------------------------------------
	//
	// (!) A TPM REPORTING ZERO SESSIONS IS NOT A TPM. These are the smallest PC-Client-plausible
	// figures rather than the literal truth, and that is a deliberate crossing of the line this
	// file otherwise holds.
	//
	// It is safe ONLY because nothing reachable depends on them: a caller that acts on these by
	// calling TPM2_StartAuthSession or TPM2_ContextSave gets TPM_RC_COMMAND_CODE either way.
	// Contrast MAX_DIGEST above, which stays 32 -- reporting 64 would make a caller ASK for
	// SHA-512 and receive a wrong answer. The test is not "is it true" but "can a caller catch
	// us out by acting on it".
	//
	case TPM2_PT_HR_TRANSIENT_MIN:   *Value = 3;                      return TRUE;
	case TPM2_PT_HR_PERSISTENT_MIN:  *Value = 7;                      return TRUE;
	case TPM2_PT_HR_LOADED_MIN:      *Value = 3;                      return TRUE;
	case TPM2_PT_ACTIVE_SESSIONS_MAX:*Value = 64;                     return TRUE;
	case TPM2_PT_CONTEXT_GAP_MAX:    *Value = 0x0000FFFFu;            return TRUE;
	case TPM2_PT_MAX_OBJECT_CONTEXT: *Value = 2048;                   return TRUE;
	case TPM2_PT_MAX_SESSION_CONTEXT:*Value = 2048;                   return TRUE;
	case TPM2_PT_ORDERLY_COUNT:      *Value = 255;                    return TRUE;
	case TPM2_PT_CLOCK_UPDATE:       *Value = 0x00040000u;            return TRUE;
	case TPM2_PT_MEMORY:             *Value = 6;   /* shared RAM + NV, object copied to RAM */
	                                                                  return TRUE;

	//
	// ---- FACTS, and a genuine zero ---------------------------------------------------------
	//
	// CONTEXT_HASH is SHA-256 because that is the hash we HAVE. CONTEXT_SYM says AES-128, which
	// we do not implement -- but context blobs are produced only by TPM2_ContextSave, which
	// answers COMMAND_CODE, so no caller can obtain one to check.
	//
	case TPM2_PT_CONTEXT_HASH:       *Value = TPM2_ALG_SHA256;        return TRUE;
	case TPM2_PT_CONTEXT_SYM:        *Value = 0x0006;  /* TPM_ALG_AES */ return TRUE;
	case TPM2_PT_CONTEXT_SYM_SIZE:   *Value = 128;                    return TRUE;
	case TPM2_PT_NV_BUFFER_MAX:      *Value = TPM2_OUR_BUFFER_SIZE;   return TRUE;
	case TPM2_PT_MAX_CAP_BUFFER:     *Value = TPM2_OUR_BUFFER_SIZE;   return TRUE;
	case TPM2_PT_MODES:              *Value = 0;   /* not FIPS_140_2 -- claiming it would be a
	                                                  certification claim, not a capability */
	                                                                  return TRUE;
	//
	// We have no NV at all yet, and zero is both true and confirmable.
	//
	case TPM2_PT_NV_COUNTERS_MAX:    *Value = 0;                      return TRUE;
	case TPM2_PT_NV_INDEX_MAX:       *Value = 0;                      return TRUE;
	case TPM2_PT_SPLIT_MAX:          *Value = 0;                      return TRUE;
	case TPM2_PT_VENDOR_COMMANDS:    *Value = 0;                      return TRUE;
	case TPM2_PT_TOTAL_COMMANDS:     *Value = TPM2_OUR_COMMAND_COUNT; return TRUE;
	case TPM2_PT_LIBRARY_COMMANDS:   *Value = TPM2_OUR_COMMAND_COUNT; return TRUE;

	//
	// ---- the PLATFORM specification, which is PTP and not the Library --------------------
	//
	case TPM2_PT_PS_FAMILY_INDICATOR:*Value = TPM2_PS_FAMILY_PC_CLIENT; return TRUE;
	case TPM2_PT_PS_LEVEL:           *Value = 0;                      return TRUE;
	case TPM2_PT_PS_REVISION:        *Value = TPM2_PS_REVISION_1_07;  return TRUE;
	case TPM2_PT_PS_DAY_OF_YEAR:     *Value = TPM2_PS_DAY_OF_YEAR;    return TRUE;
	case TPM2_PT_PS_YEAR:            *Value = TPM2_PS_YEAR;           return TRUE;
	default:                                                          return FALSE;
	}
}

/*
 * One property lookup across both groups.
 *
 * (!) THE GROUP IS PART OF THE PROPERTY NUMBER, not a separate argument. PT_FIXED is 0x100 and
 * PT_VAR is 0x200, and a caller walking upward from 0x100 must not silently fall into the VAR
 * table -- so each lookup is tried on its own range and nothing bridges the gap between them.
 */
STATIC
BOOLEAN
AnyProperty(
	IN  UINT32  Property,
	IN  CONST TPM2_PCR_BANK* Bank,
	OUT UINT32* Value
	)
{
	if (Property >= TPM2_PT_VAR)
		return VarProperty(Property, Bank, Value);
	return FixedProperty(Property, Value);
}

/*
 * TPM2_GetCapability(capability, property, propertyCount).
 *
 * Only TPM_CAP_TPM_PROPERTIES is answered. Everything else reports moreData = NO and an EMPTY
 * list of the requested capability, which is the truthful answer for a TPM that has none of that
 * kind -- as opposed to TPM_RC_VALUE, which would say the request itself was malformed.
 */
STATIC
UINT32
DoGetCapability(
	IN  CONST TPM2_PCR_BANK* Bank,
	IN  CONST UINT8* In,
	IN  UINT32       Size,
	OUT UINT8*       Out,
	IN  UINT32       OutSize
	)
{
	UINT32 Capability;
	UINT32 Property;
	UINT32 Count;
	UINT32 Written;
	UINT32 Emitted = 0;
	UINT32 i;

	if (Size != TPM2_HEADER_SIZE + 12)
		return ShortResponse(Out, OutSize,
		                     ParamSizeRc(Size - TPM2_HEADER_SIZE, 12));

	Capability = Tpm2ReadBe32(In + TPM2_HEADER_SIZE + 0);
	Property   = Tpm2ReadBe32(In + TPM2_HEADER_SIZE + 4);
	Count      = Tpm2ReadBe32(In + TPM2_HEADER_SIZE + 8);

	//
	// Response: header | moreData(1) | capability(4) | count(4) | count * (property(4) value(4))
	//
	// The header is written LAST, because its size field is not known until the properties have
	// been emitted. Writing it first with a guessed length is how a response ends up describing
	// itself incorrectly.
	//
	Written = TPM2_HEADER_SIZE + 1 + 4 + 4;
	if (OutSize < Written)
		return ShortResponse(Out, OutSize, TPM2_RC_SIZE);

	if (Capability == TPM2_CAP_TPM_PROPERTIES)
	{
		for (i = 0; i < Count && Emitted < 64; i++)
		{
			UINT32 Value;
			if (!AnyProperty(Property + i, Bank, &Value))
			{
				//
				// Omit rather than invent. A TPM answers only the properties it has, and a
				// fabricated value is checkable against the others.
				//
				// (!) BUT A GAP IS ALSO EVIDENCE. Every real TPM 2.0 publishes the whole PT_FIXED
				// run; a list missing two entries in the middle says as much as a wrong value
				// would. That is why YEAR and DAY_OF_YEAR are published above -- not to pad the
				// list, but because a TPM that genuinely lacked them would be the anomaly.
				//
				continue;
			}
			if (OutSize < Written + 8)
				break;                         /* out of room: moreData stays NO, list truncates */
			Tpm2WriteBe32(Out + Written + 0, Property + i);
			Tpm2WriteBe32(Out + Written + 4, Value);
			Written += 8;
			Emitted++;
		}
	}

	else if (Capability == TPM2_CAP_COMMANDS)
	{
		//
		// TPML_CCA: count, then one TPMA_CC per command, straight out of mOurCommands --
		// which holds the measured attribute values rather than bare codes.
		//
		// `Property` is the command code to start FROM, so a caller can page through.
		//
		for (i = 0; i < sizeof(mOurCommands) / sizeof(mOurCommands[0]); i++)
		{
			//
			// Paging compares the INDEX; the wire carries the whole TPMA_CC.
			//
			if (TPM2_CCA_INDEX(mOurCommands[i]) < Property)
				continue;
			if (Emitted >= Count || OutSize < Written + 4)
				break;
			Tpm2WriteBe32(Out + Written, mOurCommands[i]);
			Written += 4;
			Emitted++;
		}
	}
	else if (Capability == TPM2_CAP_HANDLES)
	{
		//
		// TPML_HANDLE: count, then one TPM_HANDLE per entry.
		//
		// (!) THIS BRANCH DID NOT EXIST, and its absence was invisible for a reason worth writing
		// down: with no objects to report, falling through emitted an EMPTY list -- which was the
		// correct answer, so nothing ever looked wrong. EvictControl made it wrong on the same
		// boot it made objects real, and the profile showed persistent handles as absent while
		// TPM_PT_HR_PERSISTENT said 2. Two of our own answers disagreeing is exactly the
		// self-contradiction this dispatcher is built to avoid.
		//
		// `Property` is a STARTING handle whose high octet selects the type, per Part 3 30.2.
		//
		UINT32 Found[TPM2_MAX_PERSISTENT_OBJECTS > TPM2_MAX_LOADED_OBJECTS
		              ? TPM2_MAX_PERSISTENT_OBJECTS : TPM2_MAX_LOADED_OBJECTS];
		UINT32 Have = Tpm2ObjectEnumerate(Property,
		                                  sizeof(Found) / sizeof(Found[0]), Found);

		for (i = 0; i < Have; i++)
		{
			if (Emitted >= Count || OutSize < Written + 4)
				break;
			Tpm2WriteBe32(Out + Written, Found[i]);
			Written += 4;
			Emitted++;
		}
	}
	else if (Capability == TPM2_CAP_ALGS)
	{
		//
		// TPML_ALG_PROPERTY: count, then { alg (UINT16), algProperties (UINT32) } per algorithm.
		//
		for (i = 0; i < sizeof(mOurHashes) / sizeof(mOurHashes[0]); i++)
		{
			if (mOurHashes[i] < Property)
				continue;
			if (Emitted >= Count || OutSize < Written + 6)
				break;
			Tpm2WriteBe16(Out + Written, mOurHashes[i]);
			Tpm2WriteBe32(Out + Written + 2, TPMA_ALGORITHM_HASH);
			Written += 6;
			Emitted++;
		}
	}
	else if (Capability == TPM2_CAP_PCRS)
	{
		//
		// TPML_PCR_SELECTION: count, then { hash (UINT16), sizeOfSelect (UINT8), select[] }.
		//
		// ⚠ ONE BANK, AND IT MUST MATCH EVERYTHING ELSE WE HAVE SAID. PCR_COUNT reports 24 and
		// PCR_SELECT_MIN reports 3, so the selection is 3 bytes with all 24 bits set. The event
		// log we publish is SHA-256-only for the same reason. Three answers, one fact.
		//
		if (Count > 0 && OutSize >= Written + 2 + 1 + 3)
		{
			Tpm2WriteBe16(Out + Written, TPM2_ALG_SHA256);
			Out[Written + 2] = 3;                       /* sizeOfSelect */
			Out[Written + 3] = 0xFF;                    /* PCR  0..7  allocated */
			Out[Written + 4] = 0xFF;                    /* PCR  8..15 */
			Out[Written + 5] = 0xFF;                    /* PCR 16..23 */
			Written += 6;
			Emitted++;
		}
	}

	Out[TPM2_HEADER_SIZE] = 0;                                     /* moreData = NO */
	Tpm2WriteBe32(Out + TPM2_HEADER_SIZE + 1, Capability);
	Tpm2WriteBe32(Out + TPM2_HEADER_SIZE + 5, Emitted);
	Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
	return Written;
}

UINT32
Tpm2Dispatch(
	IN OUT TPM2_PCR_BANK*      Bank,
	IN     CONST UINT8*        In,
	IN     UINT32              InSize,
	OUT    UINT8*              Out,
	IN     UINT32              OutSize,
	OUT    TPM2_DISPATCH_INFO* Info
	)
{
	UINT16 Tag  = 0;
	UINT32 Size = 0;
	UINT32 Code = 0;
	UINT32 Rc;
	UINT32 Written = 0;

	if (Info != NULL)
	{
		Info->Tag = 0; Info->CommandSize = 0; Info->CommandCode = 0;
		Info->ResponseCode = 0; Info->ResponseSize = 0; Info->InputSize = InSize;
	}

	if (Out == NULL || OutSize < TPM2_HEADER_SIZE)
		return 0;

	if (In == NULL)
	{
		Written = ShortResponse(Out, OutSize, TPM2_RC_FAILURE);
		Rc = TPM2_RC_FAILURE;
		goto done;
	}

	Rc = Tpm2ParseCommandHeader(In, InSize, &Tag, &Size, &Code);
	if (Rc != TPM2_RC_SUCCESS)
	{
		Written = ShortResponse(Out, OutSize, Rc);
		goto done;
	}

	switch (Code)
	{
	case TPM2_CC_STARTUP:
	{
		UINT16 SuType;

		if (Size != TPM2_HEADER_SIZE + 2)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 2);
			break;
		}
		SuType = Tpm2ReadBe16(In + TPM2_HEADER_SIZE);
		if (SuType != TPM2_SU_CLEAR && SuType != TPM2_SU_STATE)
		{
			Rc = TPM2_RC_VALUE;
			break;
		}
		//
		// ⚠ TPM_SU_STATE IS REFUSED RATHER THAN TREATED AS CLEAR. Startup(STATE) means "restore
		// what Shutdown(STATE) saved". We save nothing, so silently clearing would answer success
		// and hand back PCRs that are not the ones the caller asked to have restored.
		//
		if (SuType == TPM2_SU_STATE)
		{
			Rc = TPM2_RC_VALUE;
			break;
		}
		if (Bank == NULL)
		{
			Rc = TPM2_RC_FAILURE;
			break;
		}
		Tpm2PcrStartupClear(Bank, 0);      /* locality 0: this implementation is locality-0-only */
		//
		// (!) TRANSIENT OBJECTS DO NOT SURVIVE A TPM RESET. Part 1: they are flushed on
		// Startup(CLEAR). Leaving them loaded would hand out handles to objects the caller
		// believes were destroyed -- and would leave RSA private keys in the driver's BSS.
		//
		Tpm2ObjectStoreReset();
		Rc = TPM2_RC_SUCCESS;
		break;
	}

	case TPM2_CC_SELF_TEST:
		//
		// One BYTE, fullTest. Our algorithms are validated against independent oracles on the host
		// before they ship, so there is nothing to defer and nothing that can newly fail here.
		//
		Rc = (Size == TPM2_HEADER_SIZE + 1)
		     ? TPM2_RC_SUCCESS
		     : ParamSizeRc(Size - TPM2_HEADER_SIZE, 1);
		break;

	case TPM2_CC_GET_RANDOM_LOCAL:
	{
		//
		// TPM2_GetRandom(bytesRequested: UINT16) -> randomBytes: TPM2B_DIGEST.
		//
		// Part 3: the TPM returns no more than the size of the largest digest it implements, and
		// a request for more is answered with that maximum rather than refused -- so a caller
		// asking for 128 bytes legitimately receives 32.
		//
		UINT16 Want;
		UINT8  Rnd[TPM2_SHA256_DIGEST_SIZE];
		UINT32 k;

		if (Size != TPM2_HEADER_SIZE + 2)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 2);
			break;
		}
		Want = Tpm2ReadBe16(In + TPM2_HEADER_SIZE);
		if (Want > TPM2_SHA256_DIGEST_SIZE)
			Want = TPM2_SHA256_DIGEST_SIZE;

		//
		// ⚠ NO SOURCE, NO RANDOM. TPM_RC_FAILURE rather than a counter, a TSC hash or a zero
		// buffer. A caller cannot distinguish predictable bytes from random ones, so every key
		// derived from a fabricated answer would be compromised with no error anywhere.
		//
		if (mEntropy == NULL || !mEntropy(Rnd, Want))
		{
			Rc = TPM2_RC_FAILURE;
			break;
		}

		if (OutSize < TPM2_HEADER_SIZE + 2 + (UINT32)Want)
		{
			Rc = TPM2_RC_SIZE;
			break;
		}
		Tpm2WriteBe16(Out + TPM2_HEADER_SIZE, Want);
		for (k = 0; k < (UINT32)Want; k++)
			Out[TPM2_HEADER_SIZE + 2 + k] = Rnd[k];
		Written = TPM2_HEADER_SIZE + 2 + (UINT32)Want;
		Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
		Rc = TPM2_RC_SUCCESS;
		goto done;
	}

	case TPM2_CC_READ_PUBLIC:
	{
		//
		// TPM2_ReadPublic(objectHandle: TPMI_DH_OBJECT).
		//
		// (!) WE HAVE NO OBJECTS, AND THAT IS AN ANSWER RATHER THAN A GAP. Part 3 clause 5.4
		// (Handle Area Validation) rule 2.2: a handle referencing a persistent object must
		// reference one "currently in TPM non-volatile memory", and TPM_RC_HANDLE is the code when
		// it does not. Rule 1: a TRANSIENT handle must reference a LOADED object, and that failure
		// is the warning TPM_RC_REFERENCE_H0 + N instead -- a warning because a transient object
		// CAN be loaded, where a persistent one is simply absent.
		//
		// So every input this command can receive is answered correctly for the state we are in.
		// What is missing is objects, not this command; when they exist it grows a success branch.
		//
		// Windows asks this for 0x81000001 (the SRK) and 0x81010001 (the EK) before trying to
		// create them. TPM_RC_COMMAND_CODE told it the TPM was broken; TPM_RC_HANDLE tells it the
		// object is not there yet, which is true and is a state it knows how to proceed from.
		//
		UINT32 Handle;

		if (Size != TPM2_HEADER_SIZE + 4)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 4);
			break;
		}
		Handle = Tpm2ReadBe32(In + TPM2_HEADER_SIZE);

		//
		// (!) THE SUCCESS BRANCH THE COMMENT ABOVE PROMISED. Objects exist now, so the lookup
		// comes first and the refusals below are what is left when it misses.
		//
		// Part 3 clause 12.5: outPublic, name, qualifiedName -- no handles, and the command
		// carries no session, so the response is NO_SESSIONS with no parameterSize.
		//
		{
			CONST TPM2_OBJECT_SLOT* Obj = Tpm2ObjectFind(Handle);

			if (Obj != NULL)
			{
				UINT8  Qn[2 + TPM2_MAX_DIGEST_SIZE];
				UINT16 QnLen = 0;
				UINT32 q = TPM2_HEADER_SIZE;
				UINT32 wrote = 0;
				UINT32 k;

				if (!Tpm2ObjectQualifiedName(Obj, Qn, &QnLen))
				{
					Rc = TPM2_RC_FAILURE;
					break;
				}

				if (OutSize < q + 2)
				{
					Rc = TPM2_RC_SIZE;
					break;
				}
				Rc = Tpm2PublicMarshal(&Obj->Public, Out + q + 2, OutSize - (q + 2), &wrote);
				if (Rc != TPM2_RC_SUCCESS)
					break;
				Tpm2WriteBe16(Out + q, (UINT16)wrote);
				q += 2 + wrote;

				if (OutSize < q + 2 + Obj->NameLen + 2 + QnLen)
				{
					Rc = TPM2_RC_SIZE;
					break;
				}
				Tpm2WriteBe16(Out + q, Obj->NameLen); q += 2;
				for (k = 0; k < Obj->NameLen; k++)
					Out[q + k] = Obj->Name[k];
				q += Obj->NameLen;

				Tpm2WriteBe16(Out + q, QnLen); q += 2;
				for (k = 0; k < QnLen; k++)
					Out[q + k] = Qn[k];
				q += QnLen;

				Written = q;
				Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
				Rc = TPM2_RC_SUCCESS;
				goto done;
			}
		}

		if (Handle >= TPM2_HT_PERSISTENT_BASE && Handle <= TPM2_HT_PERSISTENT_END)
			Rc = TPM2_RC_H(TPM2_RC_HANDLE, 1);
		else if (Handle >= TPM2_HT_TRANSIENT_BASE && Handle < TPM2_HT_PERSISTENT_BASE)
			Rc = TPM2_RC_REFERENCE_H0;
		else
			//
			// Not an object handle at all. This is a TYPE error on TPMI_DH_OBJECT, which the
			// reference implementation reports from its unmarshalling code as TPM_RC_VALUE --
			// distinct from "the object is missing", and the caller acts on the difference.
			//
			Rc = TPM2_RC_H(TPM2_RC_VALUE, 1);
		break;
	}

	case TPM2_CC_NV_READ_PUBLIC:
	{
		//
		// TPM2_NV_ReadPublic(nvIndex: TPMI_RH_NV_INDEX).
		//
		// Part 3 clause 5.4 rule 3.1: "an Index exists that corresponds to the handle
		// (TPM_RC_HANDLE)". We define no NV Indices -- NV is Phase 3 and gate G2 -- so the correct
		// answer for every index is that it does not exist.
		//
		// (!) THE INDICES WINDOWS ASKS FOR NAME THE ONE THING THIS PROJECT ALREADY PLANS TO LIE
		// ABOUT. 0x01C00003 and 0x01C00004 are the RSA-2048 EK nonce and EK template from the TCG
		// EK Credential Profile. When NV lands, THIS is where the EK spoof lives, and answering
		// truthfully today keeps that decision in one place instead of scattering it.
		//
		UINT32 Index;

		if (Size != TPM2_HEADER_SIZE + 4)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 4);
			break;
		}
		Index = Tpm2ReadBe32(In + TPM2_HEADER_SIZE);

		if (Index >= TPM2_HT_NV_INDEX_BASE && Index <= TPM2_HT_NV_INDEX_END)
			Rc = TPM2_RC_H(TPM2_RC_HANDLE, 1);
		else
			Rc = TPM2_RC_H(TPM2_RC_VALUE, 1);
		break;
	}

	case TPM2_CC_READ_CLOCK:
	{
		//
		// TPM2_ReadClock() -> currentTime: TPMS_TIME_INFO.
		//
		//   time         UINT64  ms since the Time circuit was last reset
		//   clock        UINT64  ms advancing while powered; zeroed by TPM2_Clear
		//   resetCount   UINT32  TPM Resets since the last TPM2_Clear
		//   restartCount UINT32  Shutdowns/_TPM_Hash_Start since the last Reset or Clear
		//   safe         BYTE    no greater Clock value has previously been reported
		//
		// (!) time == clock, AND THAT IS A CONSEQUENCE OF HAVING NO NV RATHER THAN A SHORTCUT.
		// Clock is defined to survive power cycles in non-volatile storage and to be zeroed by
		// TPM2_Clear. We have no NV yet (Phase 3, gate G2), so nothing carries Clock across a
		// reboot: every power-on IS a fresh TPM after a Clear, which is exactly what Windows event
		// 519 already observes. Both counters therefore start together and stay equal. When NV
		// lands they diverge, and this branch is where that shows up.
		//
		// resetCount and restartCount are 0 for the same reason: they count since the last Clear,
		// and the last Clear was this power-on. safe is YES because Clock has only ever increased
		// within this power cycle and TPM2_Clear sets it YES.
		//
		UINT64 Ms = 0;

		if (Size != TPM2_HEADER_SIZE)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 0);
			break;
		}

		//
		// ⚠ NO CLOCK, NO TIME. Clock appears inside signed attestation structures, so a
		// fabricated value is a wrong signature that verifies -- the worst shape of failure
		// available here. TPM_RC_FAILURE instead, exactly as GetRandom refuses without entropy.
		//
		if (mTime == NULL || !mTime(&Ms))
		{
			Rc = TPM2_RC_FAILURE;
			break;
		}

		if (OutSize < TPM2_HEADER_SIZE + TPM2_TIME_INFO_SIZE)
		{
			Rc = TPM2_RC_SIZE;
			break;
		}
		Tpm2WriteBe64(Out + TPM2_HEADER_SIZE + 0,  Ms);   /* time         */
		Tpm2WriteBe64(Out + TPM2_HEADER_SIZE + 8,  Ms);   /* clock        */
		Tpm2WriteBe32(Out + TPM2_HEADER_SIZE + 16, 0);    /* resetCount   */
		Tpm2WriteBe32(Out + TPM2_HEADER_SIZE + 20, 0);    /* restartCount */
		Out[TPM2_HEADER_SIZE + 24] = 1;                   /* safe = YES   */

		Written = TPM2_HEADER_SIZE + TPM2_TIME_INFO_SIZE;
		Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
		Rc = TPM2_RC_SUCCESS;
		goto done;
	}

	case TPM2_CC_GET_TEST_RESULT:
	{
		//
		// TPM2_GetTestResult -> outData (TPM2B_MAX_BUFFER) + testResult (TPM_RC).
		//
		// (!) EMPTY outData IS THE CORRECT ANSWER, NOT A PLACEHOLDER. Part 3: outData is
		// "manufacturer-specific information regarding the results of a self-test", and a TPM with
		// nothing to report returns an empty buffer. Inventing diagnostic bytes would be
		// fabricating a vendor blob that means nothing.
		//
		// (!) testResult IS TPM_RC_SUCCESS BECAUSE OUR ALGORITHMS ARE VALIDATED BEFORE THEY SHIP,
		// against hashlib and Python hmac on the host. There is no deferred test that could still
		// fail, so SUCCESS is a true statement rather than an optimistic one.
		//
		if (Size != TPM2_HEADER_SIZE)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 0);
			break;
		}
		if (OutSize < TPM2_HEADER_SIZE + 2 + 4)
		{
			Rc = TPM2_RC_SIZE;
			break;
		}
		Tpm2WriteBe16(Out + TPM2_HEADER_SIZE, 0);              /* outData: empty */
		Tpm2WriteBe32(Out + TPM2_HEADER_SIZE + 2, TPM2_RC_SUCCESS);   /* testResult */
		Written = TPM2_HEADER_SIZE + 2 + 4;
		Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
		Rc = TPM2_RC_SUCCESS;
		goto done;
	}

	case TPM2_CC_GET_CAPABILITY:
		Written = DoGetCapability(Bank, In, Size, Out, OutSize);
		Rc = (Written >= TPM2_HEADER_SIZE) ? Tpm2ReadBe32(Out + 6) : TPM2_RC_FAILURE;
		goto done;

	case TPM2_CC_SHUTDOWN_LOCAL:
	{
		//
		// TPM2_Shutdown(shutdownType: TPM_SU) -> nothing but the header.
		//
		// ⚠ TPM_SU_STATE IS REFUSED, FOR THE SAME REASON TPM2_Startup(STATE) IS. Shutdown(STATE)
		// is a promise to save state that a later Startup(STATE) can restore. We save nothing --
		// region B does not survive power loss -- so accepting it would be a promise kept by
		// nobody, and the failure would surface one boot later as PCRs that are not the ones the
		// caller asked to have restored.
		//
		// ⚠ THIS IS A DELIBERATE, VISIBLE DIFFERENCE FROM HARDWARE, which accepts both. It is the
		// consistent choice: refusing to save exactly as we refuse to restore. The alternative is
		// a TPM that agrees to remember and then does not, which is the failure this project keeps
		// refusing everywhere else.
		//
		UINT16 SuType;

		if (Size != TPM2_HEADER_SIZE + 2)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 2);
			break;
		}
		SuType = Tpm2ReadBe16(In + TPM2_HEADER_SIZE);
		if (SuType != TPM2_SU_CLEAR && SuType != TPM2_SU_STATE)
		{
			Rc = TPM2_RC_P(TPM2_RC_VALUE, 1);
			break;
		}
		Rc = (SuType == TPM2_SU_STATE) ? TPM2_RC_P(TPM2_RC_VALUE, 1) : TPM2_RC_SUCCESS;
		break;
	}

	case TPM2_CC_PCR_READ_LOCAL:
	{
		//
		// TPM2_PCR_Read(pcrSelectionIn) -> pcrUpdateCounter, pcrSelectionOut, pcrValues.
		//
		// ⚠ THE BANK HAS BEEN IMPLEMENTED AND TESTED SINCE THE EVENT LOG LANDED, AND NOTHING COULD
		// CALL IT. Tpm2PcrStartupClear, Tpm2PcrExtend and Tpm2PcrRead all existed, with the log
		// replay exercising them, while the two commands that expose a PCR bank to the outside
		// world had no case in this switch. That is a different failure from a missing feature and
		// it hides better: every unit test passes.
		//
		UINT32 Count;
		UINT32 q = TPM2_HEADER_SIZE;
		UINT8  SelOut[3];
		UINT32 Returned = 0;
		UINT32 Bit;
		UINT32 d;
		UINT16 Alg = 0;
		UINT8  SelSize = 0;
		CONST UINT8* Sel = NULL;

		if (Bank == NULL)
		{
			Rc = TPM2_RC_FAILURE;
			break;
		}
		if (Size < q + 4)
		{
			Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
			break;
		}
		Count = Tpm2ReadBe32(In + q); q += 4;
		if (Count > 1)
		{
			Rc = TPM2_RC_P(TPM2_RC_VALUE, 1);
			break;
		}
		if (Count == 1)
		{
			if (Size < q + 3)
			{
				Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
				break;
			}
			Alg     = Tpm2ReadBe16(In + q); q += 2;
			SelSize = In[q]; q += 1;
			if (SelSize != (TPM2_PCR_COUNT + 7) / 8)
			{
				Rc = TPM2_RC_P(TPM2_RC_VALUE, 1);
				break;
			}
			if (Size < q + SelSize)
			{
				Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
				break;
			}
			Sel = In + q; q += SelSize;
		}
		if (q != Size)
		{
			Rc = TPM2_RC_P(TPM2_RC_SIZE, 1);
			break;
		}

		SelOut[0] = 0; SelOut[1] = 0; SelOut[2] = 0;
		Written = TPM2_HEADER_SIZE + 4 + 4 + 2 + 1 + 3 + 4;
		if (OutSize < Written)
		{
			Rc = TPM2_RC_SIZE;
			break;
		}

		//
		// ⚠ AT MOST EIGHT, AND pcrSelectionOut SAYS WHICH EIGHT. Part 2 Table 126 caps TPML_DIGEST
		// at eight entries; Part 3 clause 22.4.1 says the TPM stops "until pcrValues would be too
		// large to fit into the output buffer" and that the returned selection has a bit set "for
		// each value present in pcrValues".
		//
		// So a caller asking for all 24 PCRs legitimately gets 8 and re-asks for the rest. A TPM
		// that echoed the REQUESTED selection while sending fewer digests would desynchronise every
		// caller that trusted the pairing -- and would look right in any test that asked for eight
		// or fewer.
		//
		if (Count == 1 && Alg == TPM2_ALG_SHA256)
		{
			for (Bit = 0; Bit < TPM2_PCR_COUNT; Bit++)
			{
				UINT8 Pcr[TPM2_SHA256_DIGEST_SIZE];

				if ((Sel[Bit / 8] & (1u << (Bit % 8))) == 0)
					continue;
				if (Returned >= 8)
					break;
				if (OutSize < Written + 2 + TPM2_SHA256_DIGEST_SIZE)
					break;
				if (Tpm2PcrRead(Bank, Bit, Pcr) != TPM2_RC_SUCCESS)
					continue;

				Tpm2WriteBe16(Out + Written, TPM2_SHA256_DIGEST_SIZE);
				Written += 2;
				for (d = 0; d < TPM2_SHA256_DIGEST_SIZE; d++)
					Out[Written + d] = Pcr[d];
				Written += TPM2_SHA256_DIGEST_SIZE;
				SelOut[Bit / 8] |= (UINT8)(1u << (Bit % 8));
				Returned++;
			}
		}

		q = TPM2_HEADER_SIZE;
		Tpm2WriteBe32(Out + q, Bank->UpdateCounter); q += 4;
		//
		// pcrSelectionOut carries the bank even when nothing came back -- Part 3: "If no PCR are
		// returned from a bank, the selector for the bank will be present in pcrSelectionOut."
		//
		Tpm2WriteBe32(Out + q, 1); q += 4;
		Tpm2WriteBe16(Out + q, TPM2_ALG_SHA256); q += 2;
		Out[q++] = 3;
		Out[q++] = SelOut[0];
		Out[q++] = SelOut[1];
		Out[q++] = SelOut[2];
		Tpm2WriteBe32(Out + q, Returned);

		Tpm2WriteResponseHeader(Out, TPM2_ST_NO_SESSIONS, Written, TPM2_RC_SUCCESS);
		Rc = TPM2_RC_SUCCESS;
		goto done;
	}

	case TPM2_CC_EVICT_CONTROL:
		//
		// (!) DELEGATED, like CreatePrimary and for the same reason. Tpm2Primary owns the
		// persistent store; this case owns the routing and nothing else.
		//
		Rc = Tpm2DoEvictControl(In, Size, Out, OutSize, &Written);
		if (Rc == TPM2_RC_SUCCESS)
			goto done;
		Written = 0;
		break;

	case TPM2_CC_PCR_EXTEND_LOCAL:
	{
		//
		// TPM2_PCR_Extend(@pcrHandle, digests: TPML_DIGEST_VALUES) -> nothing but the header.
		//
		// ⚠ EXTENDING NEEDS AUTHORISATION AND READING DOES NOT, which is why this case carries a
		// session area and PCR_Read does not. Hardware says the same thing in its attributes:
		// 0x02400182 has nv and cHandles=1; 0x0000017E has neither.
		//
		TPM2_SESSION_AREA Sessions;
		UINT32 PcrHandle;
		UINT32 Count;
		UINT32 q;
		UINT32 Used = 0;
		UINT32 Extended = 0;
		UINT32 i;
		UINT32 w;
		BOOLEAN Probe = FALSE;

		if (Bank == NULL)
		{
			Rc = TPM2_RC_FAILURE;
			break;
		}
		if (Tag != TPM2_ST_SESSIONS)
		{
			Rc = TPM2_RC_AUTH_MISSING;
			break;
		}

		q = TPM2_HEADER_SIZE;
		if (Size < q + 4)
		{
			Rc = TPM2_RC_INSUFFICIENT;
			break;
		}
		PcrHandle = Tpm2ReadBe32(In + q); q += 4;
		//
		// TPMI_DH_PCR: a PCR handle is 0x00000000 upward, and ours run to 23. Part 2 Table 53
		// gives the type as {PCR_FIRST:PCR_LAST}, +TPM_RH_NULL, #TPM_RC_VALUE.
		//
		// ⚠ THE `+` IS NOT DECORATION -- TPM_RH_NULL IS A LEGAL pcrHandle, AND REFUSING IT WAS A
		// DISTINGUISHER. Part 3 clause 22.2.1: "The pcrHandle parameter is allowed to reference
		// TPM_RH_NULL. If so, the input parameters are processed but no action is taken by the
		// TPM. This permits the caller to probe for implemented hash algorithms as an alternative
		// to TPM2_GetCapability()."
		//
		// So this is a documented PROFILING PROBE written into the specification: extend nothing,
		// into nowhere, and read the response code -- SUCCESS means "I implement that hash",
		// TPM_RC_HASH means "I do not". Hardware answers it. We answered TPM_RC_VALUE, which is
		// the answer for a handle that is out of range, and no genuine TPM gives it here.
		//
		if (PcrHandle == TPM2_RH_NULL_HIERARCHY)
		{
			Probe = TRUE;
		}
		else if (PcrHandle >= TPM2_PCR_COUNT)
		{
			Rc = TPM2_RC_H(TPM2_RC_VALUE, 1);
			break;
		}

		Rc = Tpm2SessionParse(In + q, Size - q, &Sessions, &Used);
		if (Rc != TPM2_RC_SUCCESS)
			break;
		q += Used;
		if (Sessions.Count != 1)
		{
			Rc = TPM2_RC_AUTHSIZE;
			break;
		}
		//
		// A PCR's authValue is empty on a TPM where nothing has set one, exactly as the hierarchy
		// authValues are. When TPM2_PCR_SetAuthValue exists this reads the stored value instead.
		//
		Rc = Tpm2SessionAuthorize(&Sessions.S[0], 0, NULL, 0);
		if (Rc != TPM2_RC_SUCCESS)
			break;

		if (Size < q + 4)
		{
			Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
			break;
		}
		Count = Tpm2ReadBe32(In + q); q += 4;

		//
		// TPML_DIGEST_VALUES: count, then that many TPMT_HA -- an algorithm ID and a digest of
		// whatever size that algorithm produces.
		//
		// ⚠ TWO DIFFERENT "WE DO NOT HAVE THAT" CASES, AND THEY GET OPPOSITE ANSWERS. The comment
		// that stood here said an unimplemented bank is skipped rather than refused, and a test
		// that sent SHA-1 ahead of SHA-256 showed the code doing the opposite. The code was right
		// and the comment was wrong. Part 3 clause 22.2.1, verbatim:
		//
		//     "If the caller includes digests for algorithms that are not implemented, then the
		//      TPM will fail the call because the unmarshaling of digests will fail. [...] If the
		//      algorithm is not implemented, unmarshaling of the hashAlg will fail and the TPM
		//      will return TPM_RC_HASH."
		//
		//     "If a digest is present and the PCR in that bank is not implemented, the digest
		//      value is not used."
		//
		// So: an unimplemented ALGORITHM fails the whole command. An implemented algorithm whose
		// PCR is not allocated in that bank is silently not used. For us that line falls between
		// SHA-1 -- which Tpm2Hash cannot compute and TPM_CAP_ALGS does not advertise, so it is
		// TPM_RC_HASH -- and SHA-384/SHA-512, which we compute and advertise but have no PCR bank
		// for, so their digests are consumed and dropped. Three answers, one fact, again.
		//
		// The octets of a dropped entry still have to be COUNTED to find the next entry, which is
		// why the length comes from the algorithm rather than from a constant.
		//
		for (i = 0; i < Count; i++)
		{
			UINT16 Alg;
			UINT16 DigLen;

			if (Size < q + 2)
			{
				Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
				goto pcr_extend_done;
			}
			Alg = Tpm2ReadBe16(In + q); q += 2;
			DigLen = Tpm2HashSize(Alg);
			if (DigLen == 0)
			{
				//
				// We cannot know how many octets an algorithm we do not implement occupies, so the
				// list cannot be walked past it. That is TPM_RC_HASH, and it is a different answer
				// from "a bank we do not have": one is unparseable, the other merely absent.
				//
				Rc = TPM2_RC_P(TPM2_RC_HASH_FMT1, 1);
				goto pcr_extend_done;
			}
			if (Size < q + DigLen)
			{
				Rc = TPM2_RC_P(TPM2_RC_INSUFFICIENT, 1);
				goto pcr_extend_done;
			}
			//
			// Probe is the TPM_RH_NULL case: the entry has been unmarshalled, which is the whole
			// of what the caller asked for, and nothing is extended. Note where the test sits --
			// AFTER the TPM_RC_HASH check above, because a probe that accepted an algorithm we do
			// not implement would answer SUCCESS and report a bank we do not have.
			//
			if (Alg == TPM2_ALG_SHA256 && !Probe)
			{
				Rc = Tpm2PcrExtend(Bank, PcrHandle, In + q);
				if (Rc != TPM2_RC_SUCCESS)
					goto pcr_extend_done;
				Extended++;
			}
			q += DigLen;
		}

		if (q != Size)
		{
			Rc = TPM2_RC_P(TPM2_RC_SIZE, 1);
			break;
		}

		//
		// parameterSize present and zero, then the session acknowledgement -- the same shape as
		// TPM2_EvictControl's response, and for the same Part 1 clause 18.3 reason.
		//
		q = TPM2_HEADER_SIZE;
		if (OutSize < q + 4)
		{
			Rc = TPM2_RC_SIZE;
			break;
		}
		Tpm2WriteBe32(Out + q, 0);
		q += 4;
		Rc = Tpm2SessionWriteResponse(&Sessions, Out + q, OutSize - q, &w);
		if (Rc != TPM2_RC_SUCCESS)
			break;
		q += w;

		Written = q;
		Tpm2WriteResponseHeader(Out, TPM2_ST_SESSIONS, Written, TPM2_RC_SUCCESS);
		Rc = TPM2_RC_SUCCESS;
		goto done;

	pcr_extend_done:
		break;
	}

	case TPM2_CC_FLUSH_CONTEXT:
	{
		//
		// TPM2_FlushContext(flushHandle: TPMI_DH_CONTEXT) -> nothing but the header.
		//
		// (!) THE TAG IS PART OF THE COMMAND'S DEFINITION HERE. Part 3 clause 28.4.1: "No
		// sessions of any type are allowed with this command and tag is required to be
		// TPM_ST_NO_SESSIONS." A caller that sends a session area is not failing to authorise,
		// it is sending something the command does not take -- so TPM_RC_AUTH_CONTEXT, which
		// says exactly that, rather than an authorisation failure that would send it looking
		// for a password.
		//
		if (Tag != TPM2_ST_NO_SESSIONS)
		{
			Rc = TPM2_RC_AUTH_CONTEXT;
			break;
		}
		if (Size != TPM2_HEADER_SIZE + 4)
		{
			Rc = ParamSizeRc(Size - TPM2_HEADER_SIZE, 4);
			break;
		}
		Rc = Tpm2DoFlushContext(Tpm2ReadBe32(In + TPM2_HEADER_SIZE));
		break;
	}

	case TPM2_CC_CREATE_PRIMARY:
		//
		// (!) DELEGATED, LIKE GetCapability, AND FOR THE SAME REASON: the command is large
		// enough that inlining it here would bury the dispatch table it belongs to. Tpm2Primary
		// owns the object store and the seed interface; this case owns nothing but the routing.
		//
		// (!) IT WRITES ITS OWN RESPONSE HEADER ON SUCCESS, because the response carries
		// SESSIONS rather than NO_SESSIONS and only the command knows the length. On failure it
		// writes nothing and falls through to ShortResponse below, which is the same shape every
		// other refusal in this file has.
		//
		Rc = Tpm2DoCreatePrimary(Bank, In, Size, Out, OutSize, &Written);
		if (Rc == TPM2_RC_SUCCESS)
			goto done;
		Written = 0;
		break;

	default:
		//
		// ⚠ NOT A STUB, AND NOT A LIE. TPM_RC_COMMAND_CODE is exactly what a TPM answers for a
		// command it does not implement. A fabricated success here would be undetectable by the
		// caller and would corrupt whatever it went on to do with the "result".
		//
		Rc = TPM2_RC_COMMAND_CODE;
		break;
	}

	Written = ShortResponse(Out, OutSize, Rc);

done:
	if (Info != NULL)
	{
		Info->Tag = Tag;
		Info->CommandSize = Size;
		Info->CommandCode = Code;
		Info->ResponseCode = Rc;
		Info->ResponseSize = Written;
	}
	return Written;
}
