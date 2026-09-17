/**
 * @file Tpm2Object.h
 * @brief TPMT_PUBLIC marshalling, object Names, and primary-key derivation.
 *
 * WHY THIS EXISTS. `TPM2_CreatePrimary` is the one command standing between us and a provisioned
 * TPM, and 90 of the 125 remaining distinguishers are downstream of it. The two templates Windows
 * sends on this machine were captured byte-exact (spec §12), so everything here is
 * built against real bytes rather than a reconstruction:
 *
 *   SRK  TPM_RH_OWNER        RSA-2048 restricted decrypt, AES-128-CFB, attrs 0x00030472, no policy
 *   EK   TPM_RH_ENDORSEMENT  the same, attrs 0x000300B2, with TCG "Policy A" as authPolicy
 *
 * ⚠ A PRIMARY KEY IS A DETERMINISTIC FUNCTION OF (SEED, TEMPLATE), AND THAT IS THE WHOLE POINT.
 * Part 1 §24.6.3: *"the DRBG is seeded with a primary seed, a template hash, and a use string ...
 * the DRBG state can be reinstantiated each time the same Primary Object is created."* Without
 * that property the SRK differs on every boot, which is exactly what Windows reports as event 519,
 * *"The TPM has been cleared. Reason: SRK has changed"*.
 *
 * ⚠ AND IT IS WHERE A SPOOF LIVES. Both keys are `fixedTPM | fixedParent | sensitiveDataOrigin` —
 * derived by the TPM, never supplied. So whoever controls the Storage and Endorsement Primary
 * Seeds controls the SRK and the EK, and no part of the key generator has to be special: it has to
 * be *deterministic from a seed we choose*, which is what the specification demands anyway.
 */

#pragma once

#include "Tpm2Kdf.h"
#include "Tpm2Prime.h"

//
// TPM_ALG_ID values this file needs beyond the hashes in Tpm2Hash.h. Part 2 Table 9.
//
#define TPM2_ALG_RSA                0x0001
#define TPM2_ALG_AES                0x0006
#define TPM2_ALG_KEYEDHASH          0x0008
#define TPM2_ALG_SYMCIPHER          0x0025
#define TPM2_ALG_ECC                0x0023
#define TPM2_ALG_NULL_ID            0x0010
#define TPM2_ALG_CFB                0x0043

//
// TPMA_OBJECT bits, Part 2 Table 33. Named because a hex literal in a template check is a comment
// that cannot be verified.
//
#define TPM2_OBJ_FIXED_TPM              (1u << 1)
#define TPM2_OBJ_ST_CLEAR               (1u << 2)
#define TPM2_OBJ_FIXED_PARENT           (1u << 4)
#define TPM2_OBJ_SENSITIVE_DATA_ORIGIN  (1u << 5)
#define TPM2_OBJ_USER_WITH_AUTH         (1u << 6)
#define TPM2_OBJ_ADMIN_WITH_POLICY      (1u << 7)
#define TPM2_OBJ_NO_DA                  (1u << 10)
#define TPM2_OBJ_ENCRYPTED_DUPLICATION  (1u << 11)
#define TPM2_OBJ_RESTRICTED             (1u << 16)
#define TPM2_OBJ_DECRYPT                (1u << 17)
#define TPM2_OBJ_SIGN_ENCRYPT           (1u << 18)

//
// Response codes this layer produces that Tpm2Core.h does not already name. Part 2 Table 17.
//
// ⚠ TWO OF THESE WERE WRONG WHEN FIRST WRITTEN, AND THE TESTS PASSED ANYWAY, because I had typed
// the same wrong number into the checker. TYPE was 0x024 and SYMMETRIC was 0x01B; the real values
// are below. The specification's text extraction interleaves the name and value columns, which is
// how the command-name table once got 34 of 46 wrong -- reading it by hand a second time was the
// same mistake with a different table.
//
// They are now cross-checked against EDK2's IndustryStandard/Tpm20.h by `check_tpm2_core`, which
// is a source that is not ours. Agreement with yourself is not evidence.
//
#define TPM2_RC_ASYMMETRIC          (TPM2_RC_FMT1 + 0x001)
#define TPM2_RC_ATTRIBUTES          (TPM2_RC_FMT1 + 0x002)
#define TPM2_RC_HASH_FMT1           (TPM2_RC_FMT1 + 0x003)
#define TPM2_RC_KEY_SIZE            (TPM2_RC_FMT1 + 0x007)
#define TPM2_RC_TYPE                (TPM2_RC_FMT1 + 0x00A)
#define TPM2_RC_SCHEME              (TPM2_RC_FMT1 + 0x012)
#define TPM2_RC_SYMMETRIC           (TPM2_RC_FMT1 + 0x016)

//
// The largest RSA modulus this build will hold. 2048 bits is what both captured templates ask for;
// 4096 is the largest a TPM 2.0 profile commonly permits, and Tpm2Bn is sized for it.
//
#define TPM2_MAX_RSA_KEY_BYTES      512

/**
 * A parsed TPMT_PUBLIC, Part 2 Table 235.
 *
 *     type | nameAlg | objectAttributes | authPolicy | [type]parameters | [type]unique
 *
 * ⚠ FIXED BUFFERS, NO ALLOCATION, like everything else in this tree — a DXE and a kernel driver
 * share this code and neither has a heap it should be using here.
 *
 * ⚠ ONLY `TPM_ALG_RSA` IS ACCEPTED, AND UNMARSHALLING SAYS SO RATHER THAN GUESSING. Part 2
 * Table 225 assigns `TPM_RC_TYPE` to *"response code when a public type is not supported"*, so an
 * ECC or KEYEDHASH template gets the answer a real TPM gives for an unimplemented type. When ECC
 * lands, it lands here and the refusal narrows.
 */
typedef struct _TPM2_PUBLIC {
	UINT16 Type;                                /* TPMI_ALG_PUBLIC                              */
	UINT16 NameAlg;                             /* TPMI_ALG_HASH                                */
	UINT32 ObjectAttributes;                    /* TPMA_OBJECT                                  */
	UINT16 AuthPolicyLen;
	UINT8  AuthPolicy[TPM2_MAX_DIGEST_SIZE];

	/* TPMS_RSA_PARMS, Part 2 Table 228 */
	UINT16 SymAlg;                              /* TPM_ALG_NULL, or AES for a storage key       */
	UINT16 SymKeyBits;                          /* present only when SymAlg != NULL             */
	UINT16 SymMode;                             /* present only when SymAlg != NULL             */
	UINT16 Scheme;                              /* TPMT_RSA_SCHEME.scheme                       */
	UINT16 KeyBits;
	UINT32 Exponent;                            /* 0 means the default; see Tpm2PublicExponent  */

	UINT16 UniqueLen;                           /* TPM2B_PUBLIC_KEY_RSA size                    */
	UINT8  Unique[TPM2_MAX_RSA_KEY_BYTES];
} TPM2_PUBLIC;

/**
 * Part 2 Table 228: the exponent field is *"an odd number greater than 2"*, and **zero means the
 * default**, which Part 1 fixes at 65537. Both captured templates send zero.
 *
 * ⚠ THE ZERO MUST SURVIVE MARSHALLING UNCHANGED. Substituting 65537 into the public area would
 * change the object's Name, because the Name is a hash of these very bytes — so the caller's key
 * handle would refer to an object it cannot recompute. The substitution happens at key generation
 * and nowhere else.
 */
UINT32 Tpm2PublicExponent(IN CONST TPM2_PUBLIC* Pub);

/**
 * Unmarshal a TPMT_PUBLIC.
 *
 * @param In,InLen  the octets available. Not a TPM2B: the caller has already consumed the size.
 * @param Pub       receives the parsed area.
 * @param Used      receives how many octets were consumed, so a TPM2B's declared size can be
 *                  checked against what actually parsed — Part 2 Table 236 requires exactly that.
 * @return TPM_RC_SUCCESS, or the response code a real TPM gives for this input.
 */
UINT32 Tpm2PublicUnmarshal(
	IN  CONST UINT8*  In,
	IN  UINT32        InLen,
	OUT TPM2_PUBLIC*  Pub,
	OUT UINT32*       Used
	);

/**
 * Marshal a TPMT_PUBLIC. Round-trips `Tpm2PublicUnmarshal` byte for byte, which is not a
 * convenience: the object Name is the hash of these octets, so a marshaller that normalises
 * anything produces a Name no other TPM would compute.
 */
UINT32 Tpm2PublicMarshal(
	IN  CONST TPM2_PUBLIC* Pub,
	OUT UINT8*             Out,
	IN  UINT32             OutLen,
	OUT UINT32*            Written
	);

/**
 * The object's Name, Part 1 §16: `nameAlg || H_nameAlg(TPMT_PUBLIC)`, big-endian algorithm ID.
 *
 * ⚠ THE ALGORITHM ID IS PART OF THE NAME, not a label on it. A bare digest is not a Name, and the
 * two-octet prefix is what lets a verifier know which hash to recompute.
 *
 * @param Name    receives 2 + digest size octets.
 * @param NameLen receives that length.
 */
BOOLEAN Tpm2ObjectName(
	IN  CONST TPM2_PUBLIC* Pub,
	OUT UINT8*             Name,
	OUT UINT16*            NameLen
	);

/**
 * Derive a primary RSA key from a seed and a template, and fill in the resulting public area.
 *
 * Part 1 §24.6.3 names the three inputs — *"a primary seed, a template hash, and a use string"* —
 * and then says plainly: **"Choice of the entropy generation for Primary Objects is a vendor
 * option. The Reference Code uses a DRBG based on SP 800-90A in order to minimize compliance
 * issues."**
 *
 * ⚠ SO THE CONSTRUCTION BELOW IS OURS, DELIBERATELY, AND IS WRITTEN DOWN RATHER THAN LEFT TO BE
 * REVERSE-ENGINEERED FROM THE CODE:
 *
 *     stream = KDFa(nameAlg, seed, "PRIMARY OBJECT CREATION", H_nameAlg(template), <block>, 8*len)
 *
 * It supplies all three inputs the clause requires and is reinstantiable, which is the property
 * the clause is actually about. It is **not** an SP800-90A DRBG and `TPM_PT_MODES` continues not
 * to claim FIPS — see Tpm2Kdf.h.
 *
 * ⚠ THE TEMPLATE IS HASHED AS RECEIVED, INCLUDING ITS `unique` FIELD. Both captured templates
 * carry 256 zero octets there. Stripping it first would be defensible and would produce different
 * keys, so the choice is recorded: hash what arrived.
 *
 * ⚠ PERSONALIZATION DATA IS HASHED WITH THE TEMPLATE, NOT BESIDE IT. Part 3 clause 24.1: for a
 * primary key `inSensitive.data` *"permits personalization of the object"*, and *"if this command
 * is called multiple times with the same inPublic parameter, inSensitive.data, and Primary Seed,
 * the TPM shall produce the same Primary Object."* So the context is
 *
 *     H_nameAlg( marshalled template ‖ inSensitive.data )
 *
 * which reduces to the plain template hash when the data is empty — the case both captured
 * commands send, since `sensitiveDataOrigin` is SET in both templates. Concatenating the data
 * into the KDF context instead would have capped it at whatever the context buffer holds.
 *
 * @param Seed         the hierarchy's primary seed (SPS for owner, EPS for endorsement).
 * @param Templ        the template as it arrived. Not modified.
 * @param Personal     `inSensitive.data`; NULL/0 for the ordinary case.
 * @param Key          receives the generated key, private parts included.
 * @param OutPub       receives `Templ` with `unique` replaced by the public modulus.
 * @return TPM_RC_SUCCESS, or a response code. Never a fabricated success.
 */
UINT32 Tpm2CreatePrimaryRsa(
	IN  CONST UINT8*       Seed,
	IN  UINT32             SeedLen,
	IN  CONST TPM2_PUBLIC* Templ,
	IN  CONST UINT8*       Personal,
	IN  UINT32             PersonalLen,
	OUT TPM2_RSA_KEY*      Key,
	OUT TPM2_PUBLIC*       OutPub
	);

/**
 * Derive a hierarchy's `proof` value from its primary seed.
 *
 * Part 1 §11.5 gives every hierarchy a proof value used as the HMAC key for its tickets. Real
 * TPMs keep it as a separate persistent secret, regenerated together with the seed by
 * `TPM2_Clear` / `TPM2_ChangeEPS`.
 *
 * ⚠ WE DERIVE IT FROM THE SEED INSTEAD, DELIBERATELY, and the consequence is the point: one
 * persisted secret per hierarchy rather than two, and the proof necessarily changes whenever the
 * seed does — which is exactly the behaviour `TPM2_Clear` is required to produce. Nothing outside
 * the TPM can observe a proof value, so no caller can tell the difference.
 *
 *     proof = KDFa(hashAlg, seed, "HIERARCHY PROOF", <hierarchy handle, 4 octets BE>, NULL, bits)
 */
UINT32 Tpm2HierarchyProof(
	IN  CONST UINT8* Seed,
	IN  UINT32       SeedLen,
	IN  UINT16       HashAlg,
	IN  UINT32       Hierarchy,
	OUT UINT8*       Proof,
	OUT UINT16*      ProofLen
	);

/* ============================================================================================
 * Creation data, creation hash, and the creation ticket.
 *
 * TPM2_CreatePrimary returns four things besides the key: outPublic, creationData, creationHash
 * and creationTicket. The last three exist so that TPM2_CertifyCreation can later prove THIS TPM
 * created THAT object under THOSE conditions, without the creation data having to live inside the
 * object forever.
 * ============================================================================================ */

//
// TPM_ST_CREATION, and the hierarchy handles. Values taken from EDK2's Tpm20.h and cross-checked
// by `check_tpm2_core`, after two hand-read constants shipped wrong.
//
#define TPM2_ST_CREATION            0x8021
#define TPM2_RH_OWNER               0x40000001u
#define TPM2_RH_NULL_HIERARCHY      0x40000007u
#define TPM2_RH_ENDORSEMENT         0x4000000Bu
#define TPM2_RH_PLATFORM            0x4000000Cu

//
// TPMA_LOCALITY, Part 2 Table 39: bit 0 is locZero. This implementation is locality-0-only, so
// the byte is 1 and not 0 -- an all-zero TPMA_LOCALITY asserts NO locality, which is not a thing
// that can have happened.
//
#define TPM2_LOCALITY_ZERO          0x01u

//
// A marshalled TPML_PCR_SELECTION for the banks we could ever have: count, then per bank a hash
// ID, a size octet, and the selection. Three banks would be 4 + 3*6 = 22; 64 is room to spare.
//
#define TPM2_MAX_PCR_SELECT_BYTES   64

//
// TPM2B_DATA holds outsideInfo. Part 2 sizes its buffer by the largest TPMT_HA, which is 2 + 64.
//
#define TPM2_MAX_OUTSIDE_INFO       66

/**
 * TPMS_CREATION_DATA, Part 2 Table 261.
 *
 * ⚠ `pcrSelect` AND `pcrDigest` ARRIVE ALREADY MARSHALLED, from the caller who owns the PCR bank.
 * Keeping PCR knowledge out of this file is deliberate: the dispatcher has the bank, and a second
 * copy of the selection logic here would be a second thing to keep in step.
 */
typedef struct _TPM2_CREATION_DATA {
	UINT16 PcrSelectLen;
	UINT8  PcrSelect[TPM2_MAX_PCR_SELECT_BYTES];    /* a whole TPML_PCR_SELECTION       */
	UINT16 PcrDigestLen;
	UINT8  PcrDigest[TPM2_MAX_DIGEST_SIZE];
	UINT8  Locality;
	UINT16 ParentNameAlg;
	UINT16 ParentNameLen;
	UINT8  ParentName[2 + TPM2_MAX_DIGEST_SIZE];
	UINT16 ParentQualifiedNameLen;
	UINT8  ParentQualifiedName[2 + TPM2_MAX_DIGEST_SIZE];
	UINT16 OutsideInfoLen;
	UINT8  OutsideInfo[TPM2_MAX_OUTSIDE_INFO];
} TPM2_CREATION_DATA;

/**
 * Fill in the parts of a TPMS_CREATION_DATA that a PRIMARY object determines.
 *
 * ⚠ A PRIMARY OBJECT HAS NO PARENT KEY, AND THE STRUCTURE SAYS SO IN A SPECIFIC WAY. Part 2
 * Table 261: *"The size will match digest size associated with parentNameAlg unless it is
 * TPM_ALG_NULL, in which case the size will be 4 and parentName will be the hierarchy handle."*
 * So `parentNameAlg` is `TPM_ALG_NULL` and both Names are the four octets of the hierarchy handle.
 * Writing a digest there instead would be a creation blob no verifier could reproduce.
 *
 * `pcrSelect`, `pcrDigest` and `outsideInfo` are left for the caller to supply.
 */
UINT32 Tpm2CreationDataForPrimary(
	OUT TPM2_CREATION_DATA* Data,
	IN  UINT32              Hierarchy,
	IN  UINT8               Locality
	);

/** Marshal a TPMS_CREATION_DATA in Part 2 Table 261 field order. */
UINT32 Tpm2CreationDataMarshal(
	IN  CONST TPM2_CREATION_DATA* Data,
	OUT UINT8*                    Out,
	IN  UINT32                    OutLen,
	OUT UINT32*                   Written
	);

/** creationHash = H_HashAlg(marshalled TPMS_CREATION_DATA). Part 3: nameAlg of outPublic. */
UINT32 Tpm2CreationHash(
	IN  CONST TPM2_CREATION_DATA* Data,
	IN  UINT16                    HashAlg,
	OUT UINT8*                    Digest,
	OUT UINT16*                   DigestLen
	);

/**
 * Marshal a TPMT_TK_CREATION: tag, hierarchy, and an HMAC under the hierarchy's proof.
 *
 * ⚠ THE HMAC'S MESSAGE IS NOT SPECIFIED BY THE LIBRARY, AND THAT IS NOT AN OVERSIGHT. Part 2
 * Table 110 says only *"This shall be the HMAC produced using a proof value of hierarchy"*: the
 * ticket is validated by the same TPM that produced it, so the message is an internal matter. Ours
 * is written down here rather than left to be recovered from the code:
 *
 *     digest = HMAC_HashAlg(proof, TPM_ST_CREATION ‖ name ‖ creationHash)
 *
 * with `TPM_ST_CREATION` as two big-endian octets and the Names and digests as bare octets, no
 * size prefixes. It is the construction the reference implementation uses, chosen so that anything
 * built against a conventional TPM behaves the same way here.
 *
 * ⚠ NO PROOF, NO TICKET. A ticket with a fabricated or empty HMAC key would validate against
 * nothing and would be indistinguishable from a real one until the day it mattered.
 */
UINT32 Tpm2CreationTicket(
	IN  CONST UINT8* Proof,
	IN  UINT32       ProofLen,
	IN  UINT16       HashAlg,
	IN  UINT32       Hierarchy,
	IN  CONST UINT8* Name,
	IN  UINT16       NameLen,
	IN  CONST UINT8* CreationHash,
	IN  UINT16       CreationHashLen,
	OUT UINT8*       Out,
	IN  UINT32       OutLen,
	OUT UINT32*      Written
	);
