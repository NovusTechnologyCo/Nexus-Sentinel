/**
 * @file Tpm2Profile.h
 * @brief The identity we present, taken from a REAL TPM rather than invented.
 *
 * WHY THIS FILE EXISTS. The standard set by the owner,: *"I want all our response in
 * TBS to be as normal hardware would respond, so if we have to go past the TPM spec to do so,
 * then we do so."* Indistinguishability cannot be reasoned to; it needs a reference measured from
 * hardware. Every value below was read off genuine Intel PTT on this machine and is recorded with
 * where it came from.
 *
 * ⚠ SOURCE OF TRUTH: a hardware PTT capture taken, with PTT enabled in the
 * BIOS and our DXE absent from the boot (verified twice: PlatformCtl found no NexusCore boot
 * block, and tpmtool reported firmware 700.19.1011.2289, which ours cannot produce). Anything
 * here that is not in that file is a guess and should say so.
 *
 * ⚠ IDENTITY ONLY. This header carries values that describe WHO the TPM claims to be. It
 * deliberately does NOT carry values that describe what it can DO -- buffer sizes, digest sizes,
 * NV capacity, resource counts. Copying those from hardware while the capability is absent is the
 * self-contradiction this project has already shipped once, when TPM_PT_TOTAL_COMMANDS claimed
 * more commands than TPM_CAP_COMMANDS listed and Windows caught it. A capacity claim moves here
 * only when the capacity is real.
 */

#pragma once

//
// ------------------------------------------------------------------------------------------
// Library specification the TPM claims to implement
// ------------------------------------------------------------------------------------------
//
// ⚠ THE HARDWARE CLAIMS REVISION 159, AND WE IMPLEMENT AGAINST 185. That is deliberate and it
// has a consequence worth stating: revision 159 predates the whole 0x199-0x1AA command block
// (ECC_Encrypt/Decrypt, PolicyCapability, NV_DefineSpace2, SetCapability, PolicyTransportSPDM,
// SignDigest, the Sign/Verify sequences, Encapsulate/Decapsulate). A TPM claiming 159 while
// advertising those commands is contradicting itself in a way anyone can check.
//
// So this constant and the ADVERTISED command set are coupled. Implement all of them by all
// means -- the objective in spec §1 is the whole specification -- but what we ADVERTISE has to
// stay consistent with the revision we claim.
//
#define TPM2_PROFILE_REVISION           159         /* 0x0000009F */
#define TPM2_PROFILE_YEAR               2026        /* 0x000007EA -- matches ours already */
#define TPM2_PROFILE_DAY_OF_YEAR        32          /* 0x00000020 */
#define TPM2_PROFILE_LEVEL              0

//
// ------------------------------------------------------------------------------------------
// Vendor identity
// ------------------------------------------------------------------------------------------
//
#define TPM2_PROFILE_MANUFACTURER       0x494E5443u /* "INTC" -- already matched */
#define TPM2_PROFILE_VENDOR_STRING_1    0x4D545000u /* "MTP\0" */
#define TPM2_PROFILE_VENDOR_STRING_2    0x00000000u
#define TPM2_PROFILE_VENDOR_STRING_3    0x00000000u
#define TPM2_PROFILE_VENDOR_STRING_4    0x00000000u
#define TPM2_PROFILE_VENDOR_TPM_TYPE    0x00000000u

//
// Firmware version. tpmtool renders these as "700.19.1011.2289", which is exactly
// (0x02BC << 16 | 0x0013) and (0x03F3 << 16 | 0x08F1) -- so the two halves reconstruct the string
// Windows prints, and that is the cross-check that the capture was read correctly.
//
#define TPM2_PROFILE_FIRMWARE_VERSION_1 0x02BC0013u /* 700.19   */
#define TPM2_PROFILE_FIRMWARE_VERSION_2 0x03F308F1u /* 1011.2289 */

//
// ------------------------------------------------------------------------------------------
// Platform specification (PC Client)
// ------------------------------------------------------------------------------------------
//
// ⚠ THE HARDWARE LEAVES PS_DAY_OF_YEAR AND PS_YEAR AT ZERO. We used to fill them with the real
// PTP 1.07 date, which is *more* correct per the specification and is precisely why it stood out:
// no shipping PTT populates them. Being more diligent than the thing you are imitating is a
// fingerprint.
//
#define TPM2_PROFILE_PS_FAMILY          1
#define TPM2_PROFILE_PS_LEVEL           0
#define TPM2_PROFILE_PS_REVISION        260         /* 0x00000104 */
#define TPM2_PROFILE_PS_DAY_OF_YEAR     0
#define TPM2_PROFILE_PS_YEAR            0

//
// ------------------------------------------------------------------------------------------
// ACPI TPM2 table identity
// ------------------------------------------------------------------------------------------
//
// ⚠ THIS IS THE LOUDEST THING WE WERE GETTING WRONG. We published OEM ID "NEXUS ", OEM table ID
// "NXTPM2  " and creator "NXUS". The TPM2 ACPI table is one GetSystemFirmwareTable call away from
// any process on the machine, so our own name was sitting in plain sight of anything that looked.
//
// Hardware on this machine: 'ALWARE' / 'Dell Inc' / four spaces, revision 4, OEM revision 2,
// creator revision 0x01000013.
//
#define TPM2_PROFILE_ACPI_REVISION      4
#define TPM2_PROFILE_ACPI_OEM_ID        "ALWARE"    /* exactly 6 bytes, no terminator */
#define TPM2_PROFILE_ACPI_OEM_TABLE_ID  "Dell Inc"  /* exactly 8 bytes, no terminator */
#define TPM2_PROFILE_ACPI_OEM_REVISION  2
#define TPM2_PROFILE_ACPI_CREATOR_ID    "    "      /* exactly 4 bytes: four spaces */
#define TPM2_PROFILE_ACPI_CREATOR_REV   0x01000013u

//
// ------------------------------------------------------------------------------------------
// MEASURED BUT NOT YET ADOPTED -- and why
// ------------------------------------------------------------------------------------------
//
// These are in the reference and are NOT applied, because each is a claim about a capability we
// do not have. Adopting a capability claim before the capability exists is how a TPM becomes
// detectable by the thing it says it can do:
//
//   TPM_PT_MODES              1        hardware asserts FIPS_140_2. We have entropy without an
//                                      SP800-90A DRBG (see Tpm2Entropy.c), so the claim is false
//                                      and FIPS mode is behaviourally checkable.
//   TPM_PT_MAX_DIGEST         0x30     48 bytes = SHA-384. Ties to PCR banks and CONTEXT_HASH;
//                                      adopt when the SHA-384 bank exists.
//   TPM_PT_CONTEXT_HASH       0x0C     SHA-384, same coupling.
//   TPM_PT_INPUT_BUFFER       0x400    1024. Ours is the 3968-byte CRB data buffer. Adopting the
//                                      smaller figure means enforcing it.
//   TPM_PT_NV_INDEX_MAX       0x800    NV does not exist yet (Phase 3, gate G2).
//   TPM_PT_NV_COUNTERS_MAX    0x80     same.
//   TPM_PT_SPLIT_MAX          0x80     ECC does not exist yet.
//   TPM_PT_MAX_OBJECT_CONTEXT 0x6AC    objects do not exist yet.
//   TPM_PT_MAX_SESSION_CONTEXT 0x14C   sessions do not exist yet.
//
// The full capture is kept with the development material, so nothing is lost by deferring it.
//
