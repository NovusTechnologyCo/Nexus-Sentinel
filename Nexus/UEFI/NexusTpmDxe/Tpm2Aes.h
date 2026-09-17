/**
 * @file Tpm2Aes.h
 *
 * AES and CFB mode, per **FIPS-197** and **NIST SP 800-38A**.
 *
 * ⚠ **WHY THIS EXISTS AT ALL**, since every other algorithm here arrived from a demand trace and
 * this one did not. The design §5 has to cache derived primary objects on the ESP, and
 * §5's own confidentiality argument forbids putting key material there in the clear. Part 1
 * §8.4.7 settles what protects it:
 *
 *     "The TPM uses symmetric encryption to encrypt some command parameters (typically,
 *      authentication information) and to encrypt Protected Objects stored outside it. Cipher
 *      Feedback mode (CFB) is the only block cipher mode required by this specification."
 *
 * and §8.4.7.2:
 *
 *     "CFB is also used for symmetric encryption of the sensitive area of an object when the
 *      object is not stored in a Shielded Location. When used in this way, the key and IV are
 *      derived from a secret."
 *
 * An object cached on the ESP is a Protected Object outside a Shielded Location, word for word.
 *
 * ⚠ **XOR OBFUSCATION IS NOT AN OPTION HERE, THOUGH WE ALREADY HAVE KDFa.** The same clause:
 * *"XOR obfuscation can be used **only** for confidential parameter passing."* That was the first
 * design I reached for and Part 1 forbids it.
 *
 * ⚠ **THIS IS ALSO OWED INDEPENDENTLY.** A TPM cannot protect a child object without a symmetric
 * cipher, and the SRK template we already answer declares `TPM_ALG_AES` / 128 / `TPM_ALG_CFB` in
 * its `TPMT_SYM_DEF_OBJECT`. Advertising a template whose symmetric algorithm we could not
 * compute was a contradiction waiting for the first `TPM2_Create`.
 */

#ifndef NEXUS_TPM2_AES_H
#define NEXUS_TPM2_AES_H

#include "Tpm2Core.h"

#define TPM2_AES_BLOCK_SIZE   16
#define TPM2_AES_MAX_ROUNDS   14
#define TPM2_AES_MAX_KEY_BYTES 32

/**
 * An expanded AES key schedule.
 *
 * `Rounds` is 10, 12 or 14 for 128, 192 and 256 bits (FIPS-197 Figure 4). The schedule holds
 * `4 * (Rounds + 1)` words, so a 128-bit key leaves the tail unused rather than being a separate
 * type.
 */
typedef struct _TPM2_AES_KEY {
	UINT32  RoundKey[4 * (TPM2_AES_MAX_ROUNDS + 1)];
	UINT32  Rounds;
	BOOLEAN Valid;
} TPM2_AES_KEY;

/**
 * Expand a cipher key into a round-key schedule.
 *
 * ⚠ **AN UNSUPPORTED KEY LENGTH IS REFUSED, NOT ROUNDED.** FIPS-197 defines exactly three, and a
 * caller asking for 512 bits has a bug that must surface here rather than as a silently weaker
 * key. `Valid` is cleared so a refused schedule cannot be used by a caller that ignored the
 * return.
 *
 * @param Key      the expanded schedule
 * @param KeyBytes the cipher key
 * @param KeyBits  128, 192 or 256
 *
 * @retval TRUE   expanded
 * @retval FALSE  KeyBits is not 128, 192 or 256, or a pointer was NULL
 */
BOOLEAN
Tpm2AesSetKey(
	OUT TPM2_AES_KEY* Key,
	IN  CONST UINT8*  KeyBytes,
	IN  UINT32        KeyBits
	);

/**
 * The AES forward cipher on one 16-octet block: FIPS-197 §5.1 `Cipher()`.
 *
 * ⚠ **THERE IS NO INVERSE CIPHER IN THIS FILE, AND THAT IS NOT AN OMISSION.** CFB uses the
 * FORWARD cipher function in BOTH directions — SP 800-38A §6.3 defines decryption as
 * `P_j = C_j XOR CIPH_K(...)`, never `CIPH-1`. Since CFB is the only mode TPM 2.0 requires, an
 * `InvSubBytes`/`InvMixColumns` path would be code that nothing calls and no test could
 * meaningfully cover. If a mode that needs it ever lands, it lands with that mode.
 *
 * `In` and `Out` may be the same buffer.
 */
VOID
Tpm2AesEncryptBlock(
	IN  CONST TPM2_AES_KEY* Key,
	IN  CONST UINT8         In[TPM2_AES_BLOCK_SIZE],
	OUT UINT8               Out[TPM2_AES_BLOCK_SIZE]
	);

/**
 * CFB mode encryption, full-block feedback (CFB128), per SP 800-38A §6.3.
 *
 * ⚠ **THE IV IS UPDATED IN PLACE, AND THE CHAINING CONTRACT HAS A CONDITION I FIRST GOT WRONG.**
 * This comment used to say that a caller encrypting an object in one call and a caller encrypting
 * it in three get the same ciphertext, full stop. A test with chunks of 7, 9, 16 and 68 showed
 * they do not, and the code was right rather than the claim.
 *
 * The real contract: **every chunk but the last must be a whole number of blocks.** CFB128 feeds
 * back a complete ciphertext BLOCK, so a short chunk ends the stream — there is no 16-octet
 * feedback value to carry into the next call, only a fragment of one. Chunks of 16/32/16/36 chain
 * exactly; chunks of 7/9/16/68 do not, and the suite pins BOTH directions so that a later change
 * to buffer the keystream remainder has to be a deliberate contract change rather than a silent
 * one.
 *
 * ⚠ **THIS IS NOT A LIMITATION TPM 2.0 FEELS.** Part 1 applies CFB to a whole sensitive area or a
 * whole parameter buffer — one buffer, one call. Making short chunks resumable would mean carrying
 * a keystream remainder and an offset, which is a general-purpose crypto library's problem and not
 * this TPM's.
 *
 * ⚠ **A PARTIAL FINAL BLOCK IS NOT PADDED.** CFB is a stream mode: `Len` octets in, `Len` octets
 * out. Padding would change the length of a stored object and desynchronise every offset computed
 * over it.
 *
 * @param Key  an expanded schedule
 * @param Iv   16 octets in, advanced in place
 * @param In   plaintext
 * @param Len  octets; may be any length including zero
 * @param Out  ciphertext; may alias `In` exactly, but must not otherwise overlap
 *
 * @retval TRUE   done
 * @retval FALSE  a NULL pointer, or a schedule that was never validly expanded
 */
BOOLEAN
Tpm2AesCfbEncrypt(
	IN     CONST TPM2_AES_KEY* Key,
	IN OUT UINT8               Iv[TPM2_AES_BLOCK_SIZE],
	IN     CONST UINT8*        In,
	IN     UINT32              Len,
	OUT    UINT8*              Out
	);

/**
 * CFB mode decryption, per SP 800-38A §6.3.
 *
 * ⚠ **THE FEEDBACK IS THE CIPHERTEXT, WHICH IS THE ONLY THING SEPARATING THIS FROM ENCRYPT.**
 * Both call the forward cipher on the previous ciphertext block; encryption produces that block
 * as it goes, decryption already has it. Getting this backwards yields a routine that round-trips
 * correctly against itself and matches no other implementation on earth — which is exactly why
 * the tests below pin against OpenSSL and against published vectors rather than against a
 * round-trip.
 */
BOOLEAN
Tpm2AesCfbDecrypt(
	IN     CONST TPM2_AES_KEY* Key,
	IN OUT UINT8               Iv[TPM2_AES_BLOCK_SIZE],
	IN     CONST UINT8*        In,
	IN     UINT32              Len,
	OUT    UINT8*              Out
	);

/**
 * The S-box, exposed ONLY so the test suite can verify it against the value computed from the
 * FIPS-197 definition. Nothing else should read it.
 */
CONST UINT8* Tpm2AesSbox(VOID);

#endif /* NEXUS_TPM2_AES_H */
