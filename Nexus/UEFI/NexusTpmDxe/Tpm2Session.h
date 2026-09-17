/**
 * @file Tpm2Session.h
 * @brief The command authorization area, and password authorization.
 *
 * WHY THIS EXISTS. Every command with an `@` on a handle in Part 3 carries an authorization area,
 * and `TPM2_CreatePrimary` is the first such command we implement. Until now the dispatcher has
 * only handled `TPM_ST_NO_SESSIONS`, which is why the eight commands it answers are exactly the
 * eight that need no authorization.
 *
 * ⚠ THE VECTOR IS THE REAL ONE. Both captured `TPM2_CreatePrimary` calls carry `tag 0x8002`,
 * `authorizationSize 29`, session handle `TPM_RS_PW` (`0x40000009`), an empty nonce, zero
 * attributes, and **a 20-octet authValue that is entirely zero** (spec §12).
 *
 * ⚠ THOSE 20 ZERO OCTETS *ARE* THE EMPTY AUTHORISATION, and Part 1 says so twice:
 *
 *   §16.6.4.3  *"Trailing octets of zero are to be removed from any string before it is used as an
 *              authValue."*
 *   §16.6.5    *"Trailing zeros are always removed from an authValue before it is used in an
 *              authorization computation."*
 *
 * And §16.4: *"A password authorization lets the caller send more or fewer octets than are present
 * in the object's authorization field. The TPM truncates any octets of zero on either of the two
 * values before they are compared."* **Both sides**, not just the caller's. So Windows is
 * authorising against an unowned hierarchy exactly as a freshly-cleared TPM expects: there is no
 * password to discover and no ownership problem.
 */

#pragma once

#include "Tpm2Hash.h"
#include "Tpm2Core.h"

//
// Part 2 Table 17 and clause 6.6.2: for a format-one code, a SESSION error sets N to 8 + the
// session number. TPM_RC_S is that 8, and TPM_RC_1..7 supply the number in bits 11:8.
//
// (!) Tpm2Core.h already has TPM2_RC_H (handles) and TPM2_RC_P (parameters). This is the third
// case, and the three are not interchangeable: N is one 4-bit field whose meaning depends on P.
//
#define TPM2_RC_S(Rc, N)            ((Rc) | 0x800u | ((UINT32)(N) << 8))

//
// The two codes this layer produces. Both are cross-checked against EDK2's Tpm20.h by
// `check_tpm2_core`, after two hand-read constants shipped wrong in Tpm2Object.h.
//
// ⚠ AUTHSIZE IS RC_VER1, NOT RC_FMT1, and that is not a detail. A format-zero code carries no
// parameter or session number, which is right: authorizationSize is the field that says where the
// sessions ARE, so a bad one means no session can be identified to blame.
//
#define TPM2_RC_AUTHSIZE            (TPM2_RC_VER1 + 0x044)
#define TPM2_RC_AUTH_FAIL           (TPM2_RC_FMT1 + 0x00E)

//
// TPM_RS_PW, Part 2 Table 40. The one session handle that always exists and needs no
// TPM2_StartAuthSession.
//
#define TPM2_RS_PW                  0x40000009u

//
// TPMA_SESSION bits, Part 2 Table 34. Only continueSession is meaningful for a password session.
//
#define TPM2_SESSION_CONTINUE       0x01u

//
// Part 1 §16.4: at most three sessions may appear in one command.
//
#define TPM2_MAX_SESSIONS           3

/** One parsed authorization. */
typedef struct _TPM2_AUTH_SESSION {
	UINT32 Handle;
	UINT16 NonceLen;
	UINT8  Nonce[TPM2_MAX_DIGEST_SIZE];
	UINT8  Attributes;
	UINT16 AuthLen;                             /* as sent, trailing zeros NOT yet trimmed */
	UINT8  Auth[TPM2_MAX_DIGEST_SIZE];
} TPM2_AUTH_SESSION;

/** The whole authorization area of one command. */
typedef struct _TPM2_SESSION_AREA {
	UINT32            Count;
	UINT32            AreaSize;                 /* authorizationSize, as declared */
	TPM2_AUTH_SESSION S[TPM2_MAX_SESSIONS];
} TPM2_SESSION_AREA;

/**
 * Parse the authorization area that follows the handle area.
 *
 * @param In,InLen  the octets from `authorizationSize` onward.
 * @param Used      receives 4 + authorizationSize, so the caller can find the parameters.
 * @return TPM_RC_SUCCESS, or a session-numbered response code.
 */
UINT32 Tpm2SessionParse(
	IN  CONST UINT8*        In,
	IN  UINT32              InLen,
	OUT TPM2_SESSION_AREA*  Area,
	OUT UINT32*             Used
	);

/**
 * The length of `Auth` once trailing zero octets are removed.
 *
 * ⚠ THIS IS NOT A TIDYING STEP. It is the rule that makes 20 zero octets equal to no octets at
 * all, which is the only reason the captured commands authorise against an unowned hierarchy.
 */
UINT16 Tpm2AuthTrim(IN CONST UINT8* Auth, IN UINT16 Len);

/**
 * Compare two authValues the way Part 1 §16.4 requires: **trailing zeros removed from BOTH**, then
 * an octet-for-octet comparison.
 *
 * ⚠ TRIMMING ONLY THE CALLER'S SIDE WOULD BE A SECURITY BUG, not a cosmetic one: an entity whose
 * stored authValue ends in a zero octet would reject the very password that set it.
 */
BOOLEAN Tpm2AuthEqual(
	IN CONST UINT8* A, IN UINT16 ALen,
	IN CONST UINT8* B, IN UINT16 BLen
	);

/**
 * Authorise one password session against an entity's authValue.
 *
 * @param Index  zero-based session index, used only to number the response code.
 * @return TPM_RC_SUCCESS, or `TPM_RC_AUTH_FAIL` / `TPM_RC_VALUE` numbered with the session.
 */
UINT32 Tpm2SessionAuthorize(
	IN CONST TPM2_AUTH_SESSION* Session,
	IN UINT32                   Index,
	IN CONST UINT8*             AuthValue,
	IN UINT16                   AuthValueLen
	);

/**
 * Write the response session area, Part 1 Table 21: an empty nonce, the command's flags **with
 * continueSession SET**, and an empty hmac — one acknowledgement per command session, in order.
 *
 * ⚠ THE ONE-TO-ONE CORRESPONDENCE IS THE POINT. Part 1: *"This structure is provided to ensure a
 * one-to-one correspondence between the sessions in the command and in the response."* A response
 * that omits it after a `TPM_ST_SESSIONS` command is malformed however correct its parameters are.
 */
UINT32 Tpm2SessionWriteResponse(
	IN  CONST TPM2_SESSION_AREA* Area,
	OUT UINT8*                   Out,
	IN  UINT32                   OutLen,
	OUT UINT32*                  Written
	);
