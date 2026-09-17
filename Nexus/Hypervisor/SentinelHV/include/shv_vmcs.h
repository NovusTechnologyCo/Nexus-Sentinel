/**
 * @file shv_vmcs.h
 * @brief VMCS field configuration function declarations.
 *
 * Declares the interface for configuring the Virtual Machine Control Structure
 * (VMCS) for each logical processor. The VMCS defines the complete guest and
 * host CPU state, execution controls (what triggers VM-exits), and entry/exit
 * behavior.
 *
 * ShvAdjustControls applies the mandatory fixed-bit constraints from VMX
 * capability MSRs to ensure requested control bits are valid for the hardware.
 *
 * ShvSetupVmcs performs the full VMCS field initialization including guest
 * state (captured registers, segments, descriptor tables, MSRs), host state
 * (exit entry point, stack, segments), and all execution control fields.
 */

#pragma once

#include "shv_arch.h"

/**
 * @brief Adjust VMX execution controls per hardware capability MSRs.
 *
 * Applies the mandatory fixed-bit constraints from a VMX capability MSR
 * to the requested control value. Bits in the low 32 bits of the capability
 * MSR must be set to 1; bits not in the high 32 bits must be cleared.
 * This ensures the resulting control word is valid for VMWRITE.
 *
 * @param Requested      Desired control bits (e.g., CPU_BASED_USE_MSR_BITMAPS).
 * @param CapabilityMsr  MSR index to read (e.g., IA32_VMX_TRUE_PROCBASED_CTLS).
 * @return Adjusted control value with mandatory bits applied.
 */
ULONG32
ShvAdjustControls(
    _In_ ULONG32 Requested,
    _In_ ULONG32 CapabilityMsr
    );

/**
 * @brief Configure all VMCS fields for a given VCPU.
 *
 * Initializes the complete Virtual Machine Control Structure including:
 *   - Guest state area: CR0-CR4, segment registers (selector, base, limit,
 *     access rights), descriptor tables (GDTR, IDTR), MSRs (SYSENTER, EFER,
 *     DEBUGCTL), RIP/RSP/RFLAGS from the captured context.
 *   - Host state area: Control registers, segment selectors (RPL cleared),
 *     FS/GS/TR bases, HOST_RIP (ShvVmExitStub), HOST_RSP (top of host stack
 *     with pre-stored VCPU pointer).
 *   - Execution controls: Pin-based, primary/secondary processor-based
 *     (MSR bitmaps, EPT, RDTSCP, XSAVES, INVPCID), VM-exit/entry controls,
 *     CR0/CR4 guest-host masks (hiding VMXE), exception bitmap.
 *
 * The VMCS must already be active (VMCLEAR + VMPTRLD completed).
 *
 * @param Vcpu           Per-CPU data with VMCS physical address and host stack.
 * @param CapturedState  Guest register state from ShvCaptureContext.
 * @return STATUS_SUCCESS on successful configuration.
 */
NTSTATUS
ShvSetupVmcs(
    _In_ PVCPU_DATA Vcpu,
    _In_ PGUEST_CONTEXT CapturedState
    );
