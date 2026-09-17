/**
 * @file TpmPlatformAuthProbe.c
 * @brief Is platformAuth still the EMPTY buffer at DXE time?
 *
 * WHY
 * ----------------
 * The EK certificate NV indices (0x01C00002 RSA, 0x01C0000A ECC) are NOT write-locked on this
 * unit -- MEASURED: POLICYWRITE | POLICY_DELETE | PPREAD | OWNERREAD | AUTHREAD | NO_DA | WRITTEN |
 * PLATFORMCREATE, with no WRITELOCKED and no WRITEDEFINE -- and phEnable is SET. So rewriting the
 * EK certificate is architecturally possible IF the platform hierarchy can be authorised.
 *
 * ⚠ WHY THE DATA AND NOT THE READS. Intercepting TPM reads was tried in v1 (PatchTpmCrb.c hooking
 * MmMapIoSpace, plus IRP hooks) and FAILED; only hypervisor/EPT interception ever worked. The
 * reason is architectural: a reader holding ring 0 need not call ANY kernel mapping API -- it can
 * build its own page tables to reach the physical page, and no ring-0 hook can see that. Changing
 * the DATA has no such ceiling: every reader, custom page tables included, sees the new bytes.
 *
 * ⚠ FROM WINDOWS THIS IS CLOSED. measured via TBS:
 *     TPM2_PolicySecret(TPM_RH_PLATFORM, empty auth) -> rc 0x0A2 = TPM_RC_BAD_AUTH
 * Firmware randomises platformAuth before handing off to the OS, as the TCG PC Client firmware
 * profile recommends. But it does that LATE -- at or near the handoff -- and THIS CODE RUNS
 * BEFORE IT. That is the entire point of asking the question from here.
 *
 * WHAT THIS DOES -- AND DOES NOT DO
 * ---------------------------------
 * It only ASKS. A trial session computes a policy digest and can never authorise anything, so the
 * probe creates nothing, writes nothing, and leaves no state:
 *
 *     TPM2_StartAuthSession(TPM_SE_TRIAL) -> TPM2_PolicySecret(TPM_RH_PLATFORM) -> TPM2_FlushContext
 *
 * ⚠ A REFUSAL COSTS NOTHING EITHER. TPM_RC_BAD_AUTH is the DA-EXEMPT failure ("authorization
 * failure without DA implications"); TPM_RC_AUTH_FAIL (0x08E) is the one that increments the
 * dictionary-attack counter. Verified from Windows: LOCKOUT_COUNTER 0 before, 0 after.
 *
 * The answer is one number, and it decides the whole approach:
 *     rc == 0      -> platformAuth is usable HERE. The EK certificate can be rewritten at boot,
 *                     with no interception and no hypervisor.
 *     rc == 0x0A2  -> randomised before us too. Interception is the only non-HV route, and v1
 *                     proved that route does not hold. Phase 6.
 */

#include "NexusBootDxe.h"
#include "TpmPlatformAuthProbe.h"

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include "TcgLogSanitize.h"   // local EFI_TCG2_PROTOCOL declaration + gEfiTcg2ProtocolGuid

//
// TPM 2.0 wire constants. The TPM speaks BIG-ENDIAN on every field; x64 does not, so every
// multi-byte value below goes through Be16/Be32. Getting one of these backwards produces a
// TPM_RC_COMMAND_SIZE or a silent misparse rather than an obvious failure.
//
#define TPM_ST_NO_SESSIONS   0x8001
#define TPM_ST_SESSIONS      0x8002
#define TPM_RH_PLATFORM      0x4000000C
#define TPM_RH_NULL          0x40000007
#define TPM_RS_PW            0x40000009
#define TPM_SE_TRIAL         0x03
#define TPM_ALG_NULL         0x0010
#define TPM_ALG_SHA256       0x000B
#define CC_STARTAUTHSESSION  0x00000176
#define CC_POLICYSECRET      0x00000151
#define CC_FLUSHCONTEXT      0x00000165

//
// ⚠ CLASSIFY BY THE ERROR NUMBER, NEVER BY EQUALITY WITH A WHOLE RESPONSE CODE.
//
// TPM 2.0 Part 2 Table 17: a format-1 code carries bits 0-5 = the error number, bit 7 = the format
// selector, and bits 8-11 = WHICH handle / parameter / session was at fault. The same failure
// therefore arrives as DIFFERENT 32-bit values depending on where it was raised.
//
// measured -- the same refusal, two encodings:
//     via TBS from Windows   rc = 0x0A2   BAD_AUTH, no qualifier
//     via TCG2 from the DXE  rc = 0x9A2   BAD_AUTH on SESSION 1  (N=9 -> session 9-8 = 1)
//
// The first version compared `Rc == 0x0A2` and so printed "INCONCLUSIVE" for a completely
// conclusive answer -- the worst possible outcome for a probe whose entire job is to return one
// trustworthy number.
//
#define TPM_RC_FMT1          0x080
#define TPM_RC_E_BAD_AUTH    0x022
#define TPM_RC_E_AUTH_FAIL   0x00E

#define TPM_RC_IS_FMT1(rc)   (((rc) & TPM_RC_FMT1) != 0)
#define TPM_RC_ERRNUM(rc)    ((rc) & 0x3F)

STATIC UINT8 mCmd[512];
STATIC UINT8 mRsp[512];

STATIC VOID Be16(UINT8* P, UINT16 V) { P[0] = (UINT8)(V >> 8); P[1] = (UINT8)V; }
STATIC VOID Be32(UINT8* P, UINT32 V)
{
	P[0] = (UINT8)(V >> 24); P[1] = (UINT8)(V >> 16);
	P[2] = (UINT8)(V >> 8);  P[3] = (UINT8)V;
}
STATIC UINT32 Rd32(CONST UINT8* P)
{
	return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | (UINT32)P[3];
}

/**
 * Submit one command. Returns the TPM response code, or 0xFFFFFFFF if the transport itself failed
 * -- deliberately distinct, because "the TPM said no" and "we never reached the TPM" call for
 * completely different conclusions and must never be conflated.
 */
STATIC
UINT32
Submit(
	IN EFI_TCG2_PROTOCOL* Tcg2,
	IN UINT32 Length
	)
{
	ZeroMem(mRsp, sizeof(mRsp));
	CONST EFI_STATUS Status = Tcg2->SubmitCommand(Tcg2, Length, mCmd, sizeof(mRsp), mRsp);
	if (EFI_ERROR(Status))
		return 0xFFFFFFFFu;
	if (Rd32(&mRsp[2]) < 10)          // responseSize must cover at least the header
		return 0xFFFFFFFFu;
	return Rd32(&mRsp[6]);
}

EFI_STATUS
NexusTpmPlatformAuthProbe(
	OUT UINT32* OutRc
	)
{
	EFI_TCG2_PROTOCOL* Tcg2 = NULL;
	UINT32 Len;

	if (OutRc != NULL)
		*OutRc = 0xFFFFFFFFu;

	if (EFI_ERROR(gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2)) || Tcg2 == NULL)
	{
		Print(L"[TPM] platformAuth probe: TCG2 protocol not available.\r\n");
		return EFI_NOT_FOUND;
	}

	//
	// TPM2_StartAuthSession -- tpmKey = NULL, bind = NULL, TRIAL session, no symmetric, SHA-256.
	// A trial session can NEVER authorise anything; it exists only to accumulate a policy digest.
	//
	ZeroMem(mCmd, sizeof(mCmd));
	Len = 0;
	Be16(&mCmd[Len], TPM_ST_NO_SESSIONS);          Len += 2;
	Be32(&mCmd[Len], 0);                           Len += 4;   // commandSize, patched below
	Be32(&mCmd[Len], CC_STARTAUTHSESSION);         Len += 4;
	Be32(&mCmd[Len], TPM_RH_NULL);                 Len += 4;   // tpmKey
	Be32(&mCmd[Len], TPM_RH_NULL);                 Len += 4;   // bind
	Be16(&mCmd[Len], 16);                          Len += 2;   // nonceCaller size
	ZeroMem(&mCmd[Len], 16);                       Len += 16;  // nonceCaller (zeros are fine here)
	Be16(&mCmd[Len], 0);                           Len += 2;   // encryptedSalt (empty)
	mCmd[Len] = TPM_SE_TRIAL;                      Len += 1;
	Be16(&mCmd[Len], TPM_ALG_NULL);                Len += 2;   // symmetric.algorithm
	Be16(&mCmd[Len], TPM_ALG_SHA256);              Len += 2;   // authHash
	Be32(&mCmd[2], Len);

	CONST UINT32 StartRc = Submit(Tcg2, Len);
	if (StartRc != 0)
	{
		Print(L"[TPM] platformAuth probe: StartAuthSession rc=0x%08x -- probe INCONCLUSIVE.\r\n",
			  StartRc);
		return EFI_DEVICE_ERROR;
	}
	CONST UINT32 Session = Rd32(&mRsp[10]);

	//
	// TPM2_PolicySecret(authHandle = TPM_RH_PLATFORM, policySession = trial), EMPTY password.
	// The password session is the whole question: if platformAuth is still the empty buffer this
	// succeeds, and if firmware has already randomised it we get TPM_RC_BAD_AUTH.
	//
	ZeroMem(mCmd, sizeof(mCmd));
	Len = 0;
	Be16(&mCmd[Len], TPM_ST_SESSIONS);             Len += 2;
	Be32(&mCmd[Len], 0);                           Len += 4;   // commandSize, patched below
	Be32(&mCmd[Len], CC_POLICYSECRET);             Len += 4;
	Be32(&mCmd[Len], TPM_RH_PLATFORM);             Len += 4;   // authHandle
	Be32(&mCmd[Len], Session);                     Len += 4;   // policySession
	Be32(&mCmd[Len], 9);                           Len += 4;   // authorizationSize
	Be32(&mCmd[Len], TPM_RS_PW);                   Len += 4;   // sessionHandle = password
	Be16(&mCmd[Len], 0);                           Len += 2;   // nonce (empty)
	mCmd[Len] = 0;                                 Len += 1;   // sessionAttributes
	Be16(&mCmd[Len], 0);                           Len += 2;   // hmac == the EMPTY auth value
	Be16(&mCmd[Len], 0);                           Len += 2;   // nonceTPM
	Be16(&mCmd[Len], 0);                           Len += 2;   // cpHashA
	Be16(&mCmd[Len], 0);                           Len += 2;   // policyRef
	Be32(&mCmd[Len], 0);                           Len += 4;   // expiration
	Be32(&mCmd[2], Len);

	CONST UINT32 Rc = Submit(Tcg2, Len);

	//
	// Flush the trial session unconditionally -- including on failure. A leaked session handle
	// consumes one of the TPM's few session slots for the rest of the boot.
	//
	ZeroMem(mCmd, sizeof(mCmd));
	Len = 0;
	Be16(&mCmd[Len], TPM_ST_NO_SESSIONS);          Len += 2;
	Be32(&mCmd[Len], 0);                           Len += 4;
	Be32(&mCmd[Len], CC_FLUSHCONTEXT);             Len += 4;
	Be32(&mCmd[Len], Session);                     Len += 4;
	Be32(&mCmd[2], Len);
	(VOID)Submit(Tcg2, Len);

	if (OutRc != NULL)
		*OutRc = Rc;

	Print(L"\r\n[TPM] ==================== platformAuth probe ====================\r\n");
	Print(L"[TPM] TPM2_PolicySecret(TPM_RH_PLATFORM, empty auth) -> rc=0x%08x\r\n", Rc);
	if (Rc == 0)
	{
		Print(L"[TPM] ** platformAuth IS EMPTY AT DXE TIME **\r\n");
		Print(L"[TPM] The EK certificate NV index can be rewritten from here --\r\n");
		Print(L"[TPM] no interception, no hypervisor.\r\n");
	}
	else if (TPM_RC_IS_FMT1(Rc) && TPM_RC_ERRNUM(Rc) == TPM_RC_E_BAD_AUTH)
	{
		Print(L"[TPM] BAD_AUTH -- already randomised before our DXE runs.\r\n");
		Print(L"[TPM] Interception is the only non-HV route, and v1 proved it does not hold.\r\n");
	}
	else
	{
		Print(L"[TPM] Unexpected rc -- INCONCLUSIVE, do not read it as either answer.\r\n");
	}
	Print(L"[TPM] ============================================================\r\n\r\n");

	return EFI_SUCCESS;
}
