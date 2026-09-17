/**
 * @file Tpm2Entropy.c
 * @brief The platform entropy source: RDRAND.
 *
 * WHY IT IS SEPARATE FROM THE DISPATCHER. `Tpm2Dispatch.c` includes nothing but its own headers,
 * which is what lets one dispatcher serve the DXE, the Windows kernel driver and the host harness.
 * RDRAND needs a compiler intrinsic, so the source is injected through `Tpm2SetEntropySource`
 * rather than reached for directly.
 *
 * ⚠ AN INTRINSIC IS NOT A DEPENDENCY. `_rdrand64_step` compiles to a single instruction; there is
 * no library, no EFI service and no WDK call behind it. That is why this file can be shared by
 * both environments while the rule that keeps the dispatcher portable stays intact.
 *
 * ⚠ KNOWN SHORTFALL, RECORDED RATHER THAN GLOSSED. Part 1 wants a TPM's RNG to be a DRBG per
 * SP800-90A, seeded from an entropy source and reseeded on a schedule. This is the entropy
 * WITHOUT the DRBG: the bytes come straight from the CPU's hardware random generator. They are
 * genuinely unpredictable, so nothing here is fabricated -- but the construction is not yet what
 * the specification asks for, and `TPM_PT_MODES` correctly does not claim FIPS.
 *
 * ⚠ RDRAND CAN FAIL, AND FAILURE IS REPORTED. The instruction clears CF when the hardware entropy
 * pool is momentarily exhausted. Intel's guidance is a short retry loop; after that we return
 * FALSE and the caller answers TPM_RC_FAILURE. Spinning forever would hang a DPC, and returning
 * whatever was in the buffer would be the fabrication this whole design refuses.
 */

#include "Tpm2Entropy.h"

#include <immintrin.h>

//
// Intel's Digital Random Number Generator guide recommends 10 retries before declaring the
// generator unavailable. The figure is theirs, not a guess.
//
#define RDRAND_RETRIES  10

STATIC
BOOLEAN
Rdrand64(
	OUT UINT64* Out
	)
{
	UINT32 i;

	for (i = 0; i < RDRAND_RETRIES; i++)
	{
		unsigned __int64 V = 0;
		if (_rdrand64_step(&V) == 1)
		{
			*Out = (UINT64)V;
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN
Tpm2RdrandEntropy(
	OUT UINT8*  Out,
	IN  UINT32  Bytes
	)
{
	UINT32 Done = 0;

	if (Out == NULL)
		return FALSE;
	if (Bytes == 0)
		return TRUE;

	while (Done < Bytes)
	{
		UINT64 V;
		UINT32 k;

		if (!Rdrand64(&V))
		{
			//
			// ⚠ WIPE WHAT WAS WRITTEN. A partial fill is a fully predictable buffer for the
			// remaining bytes, and a caller that ignores our FALSE would otherwise find plausible
			// data sitting there. Leave nothing usable behind.
			//
			for (k = 0; k < Done; k++)
				Out[k] = 0;
			return FALSE;
		}

		for (k = 0; k < 8 && Done < Bytes; k++, Done++)
			Out[Done] = (UINT8)(V >> (k * 8));
	}
	return TRUE;
}
