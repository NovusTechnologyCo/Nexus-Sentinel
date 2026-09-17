/**
 * @file Tpm2Nv.h
 * @brief NV indices — the public area, the Name, and the store that holds them.
 *
 * WHY, AND MEASURED RATHER THAN PLANNED. The boot answered `TPM_RC_HANDLE` to **ten**
 * `TPM2_NV_ReadPublic` calls, for exactly two indices:
 *
 * | index | what it is |
 * |---|---|
 * | `0x01C00002` | the **RSA EK certificate**. On a real TPM this is factory-provisioned |
 * | `0x01880011` | one of the two Windows uses; hardware has it too |
 *
 * Hardware holds thirteen. We hold none, and `TPM_RC_HANDLE` is the correct answer to a question
 * about an index that does not exist — so this is not a bug being fixed, it is a subsystem that
 * does not exist yet being built.
 *
 * ⚠ "FACTORY-PROVISIONED" MEANS *US*, AND THAT IS THE WHOLE POINT. Nobody else can put a
 * certificate in `0x01C00002` on this TPM. Which certificate goes there is the EK spoof this
 * project exists for, and it is why the NV layer is a prerequisite rather than a side quest.
 *
 * ⚠ THE INDEX IS NOT DEFINED UNTIL THERE IS SOMETHING REAL TO PUT IN IT. Hardware reports
 * `dataSize` 911 with `TPMA_NV_WRITTEN` SET, because it holds an Intel-signed certificate.
 * Declaring the same size over nothing would be *"copying a capacity claim before the capacity
 * exists"* — the self-contradiction the profile header already refuses for `MODES` and
 * `NV_INDEX_MAX`. This header is the substrate; provisioning waits for a certificate.
 */

#pragma once

#include "Tpm2Object.h"

//
// The NV codes this layer produces. Both RC_VER1, so neither carries a field number -- and both
// cross-checked against EDK2 by `check_tpm2_core`, after two hand-read constants shipped wrong.
//
// (!) NV_UNINITIALIZED IS THE ANSWER FOR A DEFINED-BUT-UNWRITTEN INDEX, and it is the reason the
// EK certificate index can be created honestly before a certificate exists: a TPM whose
// 0x01C00002 is defined and unwritten is in a state the specification names, where one whose
// index claims WRITTEN over nothing is simply lying.
//
#define TPM2_RC_NV_RANGE            (TPM2_RC_VER1 + 0x046)
#define TPM2_RC_NV_UNINITIALIZED    (TPM2_RC_VER1 + 0x04A)
#define TPM2_RC_NV_SPACE            (TPM2_RC_VER1 + 0x04B)
#define TPM2_RC_NV_DEFINED          (TPM2_RC_VER1 + 0x04C)

//
// TPMA_NV bits, Part 2 Table 249. Named because a hex literal is a comment that cannot be checked,
// and because hardware's value for the EK index is one we DECODED rather than guessed:
//
//   0x62070408 = POLICYWRITE | POLICY_DELETE | PPREAD | OWNERREAD | AUTHREAD
//                | NO_DA | WRITTEN | PLATFORMCREATE
//
#define TPM2_NVA_PPWRITE            (1u << 0)
#define TPM2_NVA_OWNERWRITE         (1u << 1)
#define TPM2_NVA_AUTHWRITE          (1u << 2)
#define TPM2_NVA_POLICYWRITE        (1u << 3)
#define TPM2_NVA_POLICY_DELETE      (1u << 10)
#define TPM2_NVA_WRITELOCKED        (1u << 11)
#define TPM2_NVA_WRITEALL           (1u << 12)
#define TPM2_NVA_WRITEDEFINE        (1u << 13)
#define TPM2_NVA_WRITE_STCLEAR      (1u << 14)
#define TPM2_NVA_GLOBALLOCK         (1u << 15)
#define TPM2_NVA_PPREAD             (1u << 16)
#define TPM2_NVA_OWNERREAD          (1u << 17)
#define TPM2_NVA_AUTHREAD           (1u << 18)
#define TPM2_NVA_POLICYREAD         (1u << 19)
#define TPM2_NVA_NO_DA              (1u << 25)
#define TPM2_NVA_ORDERLY            (1u << 26)
#define TPM2_NVA_CLEAR_STCLEAR      (1u << 27)
#define TPM2_NVA_READLOCKED         (1u << 28)
#define TPM2_NVA_WRITTEN            (1u << 29)
#define TPM2_NVA_PLATFORMCREATE     (1u << 30)
#define TPM2_NVA_READ_STCLEAR       (1u << 31)

/** TPM_NT, Part 2 Table 247 — the index TYPE, in TPMA_NV bits 7:4. */
#define TPM2_NVA_TYPE_SHIFT         4
#define TPM2_NVA_TYPE_MASK          0xFu
#define TPM2_NT_ORDINARY            0x0
#define TPM2_NT_COUNTER             0x1
#define TPM2_NT_BITS                0x2
#define TPM2_NT_EXTEND              0x4
#define TPM2_NT_PIN_FAIL            0x8
#define TPM2_NT_PIN_PASS            0x9

//
// NV index handles are 0x01xxxxxx, Part 2 clause 7.4.
//
#define TPM2_NV_INDEX_FIRST         0x01000000u
#define TPM2_NV_INDEX_LAST          0x01FFFFFFu

//
// How many indices the store holds, and how big one may be.
//
// ⚠ NEITHER NUMBER IS ADVERTISED YET, and that is deliberate. `TPM_PT_NV_INDEX_MAX` and
// `TPM_PT_NV_BUFFER_MAX` are among the values `Tpm2Profile.h` records as MEASURED BUT NOT ADOPTED,
// for the reason that applies here too: a capacity claim has to be one we can meet. These are set
// from what the EK certificate will actually need, and the properties change when they are met.
//
#define TPM2_MAX_NV_INDICES         8
#define TPM2_MAX_NV_DATA            1024

/**
 * TPMS_NV_PUBLIC, Part 2 Table 251.
 *
 *     nvIndex | nameAlg | attributes | authPolicy | dataSize
 *
 * ⚠ `dataSize` DESCRIBES THE INDEX, NOT THE CONTENT PRESENT. An index is defined at a size and
 * only later written; `TPMA_NV_WRITTEN` is the bit that says which. Conflating them is how a TPM
 * ends up reporting a certificate it does not have.
 */
typedef struct _TPM2_NV_PUBLIC {
	UINT32 NvIndex;
	UINT16 NameAlg;
	UINT32 Attributes;
	UINT16 AuthPolicyLen;
	UINT8  AuthPolicy[TPM2_MAX_DIGEST_SIZE];
	UINT16 DataSize;
} TPM2_NV_PUBLIC;

/** One defined index, and whatever has been written to it. */
typedef struct _TPM2_NV_INDEX {
	BOOLEAN        Defined;
	TPM2_NV_PUBLIC Public;
	UINT16         Written;                     /* octets actually written */
	UINT8          Data[TPM2_MAX_NV_DATA];
} TPM2_NV_INDEX;

/** Marshal a TPMS_NV_PUBLIC in Table 251 field order. */
UINT32 Tpm2NvPublicMarshal(
	IN  CONST TPM2_NV_PUBLIC* Pub,
	OUT UINT8*                Out,
	IN  UINT32                OutLen,
	OUT UINT32*               Written
	);

/**
 * The Index's Name: `nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)` — the same construction as an object's
 * Name, over a different structure.
 *
 * ✅ **VERIFIED AGAINST HARDWARE BEFORE THIS FILE EXISTED.** Hardware's `TPM2_NV_ReadPublic`
 * response for `0x01C00002` carries both the public area and the Name, and
 * `SHA-384(that public area)` reproduces that Name exactly. The rule is not read off the
 * specification and hoped for — it is confirmed by a TPM that is not ours.
 */
BOOLEAN Tpm2NvName(
	IN  CONST TPM2_NV_PUBLIC* Pub,
	OUT UINT8*                Name,
	OUT UINT16*               NameLen
	);

/** Empty the NV store. */
VOID Tpm2NvReset(VOID);

/** How many indices are defined. Answers `TPM_PT_HR_NV_INDEX` truthfully. */
UINT32 Tpm2NvCount(VOID);

/** The index with that handle, or NULL. */
CONST TPM2_NV_INDEX* Tpm2NvFind(IN UINT32 NvIndex);

/**
 * Enumerate defined NV handles, ASCENDING, for `TPM_CAP_HANDLES`.
 *
 * ⚠ SORTED FOR THE SAME REASON THE OBJECT ENUMERATION IS: `property` is a starting handle, paging
 * only works on an increasing sequence, and slot order is allocation order. An unsorted version of
 * that function passed every test until one was written where the two orders could not coincide.
 */
UINT32 Tpm2NvEnumerate(
	IN  UINT32  First,
	IN  UINT32  Max,
	OUT UINT32* Handles
	);

/**
 * Define an index. The platform calls this at boot for the indices a real TPM would have been
 * shipped with.
 *
 * ⚠ `TPMA_NV_WRITTEN` IS CLEARED HERE NO MATTER WHAT THE CALLER ASKS FOR. Part 2 Table 249 makes
 * it a status bit the TPM maintains, not an attribute the definer chooses, and a defined-but-unwritten
 * index is a legitimate state that `TPM2_NV_Read` reports as `TPM_RC_NV_UNINITIALIZED`. Letting a
 * caller assert it would let the TPM claim content it does not hold.
 */
UINT32 Tpm2NvDefine(IN CONST TPM2_NV_PUBLIC* Pub);

/**
 * Write an index's data, setting `TPMA_NV_WRITTEN`.
 *
 * @return TPM_RC_SUCCESS, `TPM_RC_HANDLE` if undefined, or `TPM_RC_NV_RANGE` if the write does not
 *         fit the size the index was defined at.
 */
UINT32 Tpm2NvWrite(
	IN UINT32       NvIndex,
	IN CONST UINT8* Data,
	IN UINT16       Len
	);
