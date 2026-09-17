#ifndef __NEXUSBOOT_GUID_H__
#define __NEXUSBOOT_GUID_H__

#include <Guid/GlobalVariable.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// The driver protocol this DXE publishes, and the Loader locates.
//
// (!) REISSUED, and it must not be reverted. A protocol GUID is an IDENTITY, so the
// cleanroom is not finished while the tree publishes an inherited one -- whatever the code behind
// it now says. Reissuing costs nothing except that the DXE and the Loader must be deployed
// TOGETHER: they agree on this value symbolically, but they are separate images built from
// separate targets, and a Loader carrying the old value simply fails to find the protocol.
//
#define EFI_NEXUSBOOT_DRIVER_PROTOCOL_GUID \
	{ \
	0x0479c5e7, 0xe97d, 0x41c6, { 0x99, 0x37, 0x09, 0xf5, 0xb6, 0x14, 0xf1, 0x68 } \
	}

//
// THE COMMAND CHANNEL VARIABLE.
//
// The DXE hooks gRT->SetVariable and gRT->GetVariable, and recognises this one name under this
// one GUID as the transport for NEXUS_COMMAND (see Include/NexusCommand.h). Commands are written,
// results are read back, and the same name serves both directions so exactly one non-standard
// variable exists rather than two.
//
// (!) IT NEVER REACHES FIRMWARE. The hook answers it and returns without calling through, which
// is what makes an arbitrary name workable here: this GUID is the UEFI-reserved global namespace,
// and firmware refuses to CREATE an unrecognised name in it. measured -- a write under
// this GUID that DOES reach firmware fails with EFI_INVALID_PARAMETER. Anything that must survive
// a reboot therefore needs a private vendor GUID; see NXCMD_BOOTCTL_VAR_GUID_STR.
//
// The name is deliberately unremarkable. Variable names are readable by anything with the
// privilege to enumerate them, so it does not announce the project.
//
#define NEXUS_CHANNEL_VARIABLE_NAME     L"BootOrderCacheV2"
#define NEXUS_CHANNEL_VARIABLE_GUID     &gEfiGlobalVariableGuid

//
// Main driver configuration data, optionally sent to the driver through the protocol's
// Configure() pointer.
//
typedef struct _NEXUSBOOT_CONFIGURATION_DATA {
	//
	// Whether to wait for a keypress at the end of each patch stage, regardless of success or failure.
	// Recommended for debugging purposes only.
	// Default: FALSE
	//
	BOOLEAN WaitForKeyPress;

	//
	// Whether to force VBS (Virtualization-Based Security) off for this boot, by writing the
	// `VbsPolicyDisabled` UEFI variable that winload consumes.
	// Default: TRUE
	//
	// WHY THIS IS A FLAG (added): the DisableVbs call in PatchWinload.c was
	// UNCONDITIONAL, which made VBS-off an invisible, non-negotiable property of the whole
	// driver. That matters because VBS-off is a PRECONDITION for essentially everything
	// NexusBootDxe and NexusCore do -- every technique they use (PatchGuard disable, DSE
	// patching, CR0.WP code writes, unsigned manual-mapped drivers) assumes VTL0 is the
	// highest authority on the machine, which is exactly what VBS makes false. See:
	//   - HVCI's EPT W^X blocks manual mapping regardless of DSE (a memory permission, not a
	//     signature check), so the hypervisor cannot load either -- SentinelHV.sys is itself
	//     PE subsystem 1, i.e. an unsigned kernel driver
	//   - HyperGuard (VTL1) is untouched by our VTL0 PatchGuard patches
	//   - securekernel re-checks code integrity independently of g_CiOptions
	//   - KDP (MmProtectDriverSection) blocks the g_CiOptions write outright, and the
	//     SetVariable DSE path bugchecks (SECURE_KERNEL_ERROR) under HVCI
	//
	// So do NOT set this FALSE expecting things to keep working -- it is here so that
	// experimenting with VBS/HVCI enabled is a config toggle rather than a code edit, and so
	// that the dependency is DOCUMENTED rather than implicit.
	//
	// Motivation: integrity-checking software classifies machines on exactly these axes --
	// no HVCI, no Secure Boot, no TPM, a vulnerable driver present -- and some now gate their
	// less-invasive modes on VBS and HVCI being up. That is tracked, so the
	// option to test with it enabled is worth keeping cheap.
	//
	BOOLEAN DisableVbs;

	//
	// Whether to present Secure Boot as ENABLED to anything that reads the `SecureBoot` UEFI
	// variable, by hooking gRT->GetVariable. This is Tier 1 of the SB spoof.
	// Default: TRUE
	//
	// SCOPE -- ONE BYTE. This flips `SecureBoot` 0 -> 1 and touches NOTHING else. That is not a
	// simplification; it is the whole job on a provisioned platform, and it is worth
	// understanding why before anyone "improves" it into something broader.
	//
	// measured (baseline a committed baseline, three platform states):
	// this machine keeps PK/KEK/db/dbx enrolled and sits in Deployed Mode at all times. The BIOS
	// gates only ENFORCEMENT, not provisioning (see an earlier finding).
	// So with SB switched off in firmware the variable set already reads:
	//
	//     SetupMode=00  AuditMode=00  DeployedMode=01  VendorKeys=01  PK/KEK/db/dbx present
	//
	// which is EXACTLY spec Deployed Mode. The single variable differing from a genuinely
	// SB-on boot is `SecureBoot` itself. One byte lands the entire set in a coherent state.
	//
	// WHY THAT MATTERS: the original design (the design notes, written before
	// measurement) assumed an unprovisioned box and scoped Tier 1 as "synthesise plausible
	// PK/KEK/db/dbx contents". Fake key material has to survive a caller that parses
	// EFI_SIGNATURE_LIST and walks certificate chains -- trivially detectable, and the single
	// largest detection risk in the whole layer. Measurement deleted that entire problem. The
	// real Microsoft-signed databases are already present and pass through untouched.
	//
	// DESIGN RULE, therefore: narrow pass-through. Modify only `SecureBoot`, only when the
	// firmware's real value is 0. Do not enumerate, do not synthesise, do not "complete" the
	// set -- dbt/dbr are legitimately absent here, and a hook that invents them creates an
	// inconsistency the unspoofed machine does not have. The platform already provides
	// coherence; the job is to avoid breaking it.
	//
	// COHERENCE GATE (spec-derived, so it generalises for free): per UEFI Table 32-1,
	// SecureBoot=1 is only meaningful outside Setup and Audit mode. HookedGetVariable therefore
	// re-reads the platform's real SetupMode/AuditMode and spoofs ONLY when both are 0. On a
	// box sitting in Setup Mode this fails closed rather than manufacturing the "impossible
	// machine" combination that is more detectable than not spoofing at all.
	//
	// WHAT THIS REACHES -- measured on a real boot, firmware Secure Boot OFF:
	//   - rung A, the `SecureBoot` UEFI variable itself. Confirm-SecureBootUEFI returns True and
	//     the full variable set is byte-identical to the committed SB-ON baseline.
	//   - rung A', KUSER_SHARED_DATA.DbgSecureBootEnabled -- FOR FREE, and this was not designed.
	//     That flag is populated by winload from the loader block, and this hook is already live
	//     when winload runs, so winload consumed the spoofed value and the belief propagated into
	//     the kernel: NtQuerySystemInformation(SystemSecureBootInformation) reports
	//     SecureBootEnabled=1. A separate "Tier 2" patch was planned and turned out to be
	//     unnecessary -- do not add one, it would write a value that is already correct.
	//     Generalises: a GetVariable hook installed before BDS reaches anything winload DERIVES
	//     from UEFI variables, not merely code that reads those variables directly.
	//
	// WHAT THIS DOES NOT REACH -- accepted limits, not TODOs (the design notes):
	//   - a checker that walks the TCG log needs Tier 3 (WBCL patch at handoff). Note this is a
	//     WIDER hole than the variable was: UEFI measures every loaded image's device path in
	//     PLAINTEXT, so \EFI\NexusBoot\Loader.efi and NexusBootDxe.efi appear BY NAME in a log
	//     Windows serves to any caller via TBS, WMI and MeasuredBoot\*.log. Such a checker never
	//     has to defeat this hook at all -- it can just read our filenames. PCR[1]'s `Setup`
	//     blob separately records the firmware's real Secure Boot toggle, which is setup data
	//     rather than a UEFI variable and so is unreachable from here by construction.
	//   - a checker that recomputes the log hash chain against the TPM's real PCR[7] defeats
	//     this, structurally: PCR[7] events 18-22 are extended during DXE dispatch, before any
	//     ESP-loaded image runs, and extends are one-way. MEASURED, not merely reasoned: a
	//     Tier-1 boot still logs SecureBoot=00 at PCR[7] event 18.
	//   - TPM2_Quote over PCR[7] is the attestation ceiling (the design notes)
	//
	BOOLEAN SpoofSecureBoot;

	//
	// TRUE when the Loader MANUALLY MAPPED this driver instead of using gBS->LoadImage
	// (scope item 4c). Set by the Loader; never set it by hand.
	// Default: FALSE
	//
	// WHY THE DRIVER MUST KNOW: the firmware relocates REGISTERED runtime images at
	// SetVirtualAddressMap. A manually-mapped image is not registered, so it must relocate ITSELF --
	// and a LoadImage'd image must NOT, because relocating twice corrupts every absolute address in
	// the image. The two cases are indistinguishable from inside the driver (there is no API to ask
	// "will the firmware relocate me?"), so the Loader states it explicitly.
	//
	// Getting this wrong in either direction produces the same symptom: the first runtime
	// GetVariable call after Windows switches to virtual addressing jumps somewhere that is not our
	// code. Which is to say, it is not observable until it is fatal.
	//
	BOOLEAN ManuallyMapped;

	//
	// TRUE to leave PatchGuard ALIVE for this boot -- i.e. run everything else and skip only the
	// defusal. Set from the one-shot boot-control variable; see NXCMD_BOOTCTL_SKIP_PG in
	// Include/NexusCommand.h for the mechanism and why it self-clears.
	// Default: FALSE
	//
	// (!) THE SENSE IS DELIBERATELY NEGATIVE, and that is worth one sentence because the obvious
	// spelling is the dangerous one. A `DefusePatchGuard` field defaulting to TRUE would mean
	// that any initializer which forgot it -- gDriverConfig is POSITIONAL, and already omits
	// ManuallyMapped -- would zero-init to FALSE and silently stop defusing PatchGuard on every
	// boot. Phrased this way, zero means the historical behaviour, so the failure mode of
	// forgetting it is "nothing changes".
	//
	// WHAT THIS IS FOR: pgscan (NXCMD_OP_PG_SCAN) reports whether a PatchGuard context is
	// resident, and an empty result from it proves nothing until the same detector has been seen
	// to FIND one. This flag produces the boot where a context MUST exist. It is a measurement
	// instrument, not a feature.
	//
	// ⚠ ON SUCH A BOOT PATCHGUARD IS REAL. NexusCore is still manually mapped, so a bugcheck
	// 0x109 some minutes or hours in is a POSSIBLE and ACCEPTABLE outcome of the control -- run
	// pgscan early, and do not leave the machine doing work it cares about.
	//
	BOOLEAN SkipPatchGuardDefusal;
} NEXUSBOOT_CONFIGURATION_DATA;


//
// Sends configuration data to the driver.
//
typedef
EFI_STATUS
(EFIAPI*
NEXUSBOOT_CONFIGURE)(
	IN CONST NEXUSBOOT_CONFIGURATION_DATA* ConfigurationData
	);


//
// The NexusBoot bootkit driver protocol.
//
typedef struct _NEXUSBOOT_DRIVER_PROTOCOL {
	NEXUSBOOT_CONFIGURE Configure;
} NEXUSBOOT_DRIVER_PROTOCOL;


extern EFI_GUID gNexusBootDriverProtocolGuid;

#ifdef __cplusplus
}
#endif

#endif
