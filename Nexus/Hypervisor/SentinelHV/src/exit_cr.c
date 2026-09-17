/**
 * @file exit_cr.c
 * @brief Control register access VM-exit handler (MOV to/from CR, CLTS, LMSW).
 *
 * Handles EXIT_REASON_CR_ACCESS (28), which fires when the guest modifies
 * or reads a control register that the hypervisor has masked via the
 * CR0/CR4 guest-host mask VMCS fields.
 *
 * Primary responsibilities:
 *
 *   - **Hide CR4.VMXE**: The guest must not see that CR4.VMXE is set
 *     (which would reveal hypervisor presence). The CR4 read shadow
 *     always has VMXE cleared. Writes to CR4 are intercepted to maintain
 *     VMXE=1 in the actual register while showing VMXE=0 to the guest.
 *
 *   - **Enforce VMX fixed bits**: Both CR0 and CR4 have mandatory bits
 *     that must be set/cleared for VMX operation. When the guest writes
 *     to CR0/CR4, the handler applies the fixed-bit masks from
 *     IA32_VMX_CR{0,4}_FIXED{0,1} MSRs.
 *
 *   - **CLTS/LMSW**: Special CR0 modification instructions are handled
 *     by directly updating the VMCS guest CR0 and read shadow.
 *
 * The exit qualification is decoded using the CR_ACCESS_* macros from
 * shv_vmx.h to determine the CR number, access type, and GPR index.
 */

#include "shv.h"

/* ── GPR Access Helper ────────────────────────────────────────────── */

/**
 * @brief Get a pointer to the specified GPR within the guest context.
 *
 * Maps a GPR index (0-15 from the exit qualification) to the corresponding
 * field in the GUEST_CONTEXT structure. Used for MOV to/from CR instructions
 * where the exit qualification specifies which register holds the source or
 * destination value.
 *
 * @param GuestContext  The saved guest register context.
 * @param GprIndex      Register index (0=RAX, 1=RCX, ..., 15=R15).
 * @return Pointer to the 64-bit register value in the context structure.
 */
static ULONG64*
ShvGetGprPointer(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_ ULONG GprIndex
    )
{
    switch (GprIndex) {
    case 0:  return &GuestContext->Rax;
    case 1:  return &GuestContext->Rcx;
    case 2:  return &GuestContext->Rdx;
    case 3:  return &GuestContext->Rbx;
    case 4:  return &GuestContext->Rsp;  /* Technically from VMCS */
    case 5:  return &GuestContext->Rbp;
    case 6:  return &GuestContext->Rsi;
    case 7:  return &GuestContext->Rdi;
    case 8:  return &GuestContext->R8;
    case 9:  return &GuestContext->R9;
    case 10: return &GuestContext->R10;
    case 11: return &GuestContext->R11;
    case 12: return &GuestContext->R12;
    case 13: return &GuestContext->R13;
    case 14: return &GuestContext->R14;
    case 15: return &GuestContext->R15;
    default: return &GuestContext->Rax;
    }
}

/* ── CR Access Handler ────────────────────────────────────────────── */

/**
 * @brief Handle control register access VM-exit.
 *
 * Decodes the exit qualification to determine the operation type and
 * dispatches accordingly:
 *
 *   - **MOV to CR0**: Apply VMX CR0 fixed bits, update VMCS guest CR0
 *     and CR0 read shadow.
 *   - **MOV to CR4**: Apply VMX CR4 fixed bits, force VMXE=1, update
 *     VMCS guest CR4 and CR4 read shadow (with VMXE cleared in shadow).
 *   - **MOV from CR0/CR4**: Return the read shadow value to the GPR.
 *   - **CLTS**: Clear the TS bit (bit 3) in both guest CR0 and shadow.
 *   - **LMSW**: Load the low 16 bits of CR0 with PE preservation, apply
 *     VMX fixed bits.
 *
 * @param GuestContext  Guest registers; the GPR from the exit qualification
 *                      is read (MOV to CR) or written (MOV from CR).
 */
void
ShvHandleCrAccess(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    SIZE_T qualification = 0;
    __vmx_vmread(VMCS_RO_EXIT_QUALIFICATION, &qualification);

    ULONG crNumber = CR_ACCESS_CR_NUMBER(qualification);
    ULONG accessType = CR_ACCESS_TYPE(qualification);
    ULONG gprIndex = CR_ACCESS_REG(qualification);

    ULONG64* gprValue = ShvGetGprPointer(GuestContext, gprIndex);

    switch (accessType) {

    case CR_ACCESS_TYPE_MOV_TO_CR:
        if (crNumber == 0) {
            /*
             * MOV to CR0: apply VMX fixed bits, update VMCS.
             */
            ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
            ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);

            ULONG64 newCr0 = (*gprValue | cr0Fixed0) & cr0Fixed1;
            __vmx_vmwrite(VMCS_GUEST_CR0, newCr0);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, *gprValue);
        }
        else if (crNumber == 4) {
            /*
             * MOV to CR4: guest wants to set CR4.
             * Actual CR4 must have VMXE=1 (VMX requirement).
             * Shadow shows what guest expects (VMXE=0).
             */
            ULONG64 cr4Fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
            ULONG64 cr4Fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

            ULONG64 newCr4 = (*gprValue | cr4Fixed0) & cr4Fixed1;
            newCr4 |= CR4_VMXE;  /* Always keep VMXE set */

            __vmx_vmwrite(VMCS_GUEST_CR4, newCr4);
            __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, *gprValue & ~CR4_VMXE);
        }
        break;

    case CR_ACCESS_TYPE_MOV_FROM_CR:
        if (crNumber == 0) {
            /* Return CR0 shadow (what guest thinks CR0 is) */
            SIZE_T shadow = 0;
            __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);
            *gprValue = shadow;
        }
        else if (crNumber == 4) {
            /* Return CR4 shadow (VMXE hidden) */
            SIZE_T shadow = 0;
            __vmx_vmread(VMCS_CTRL_CR4_READ_SHADOW, &shadow);
            *gprValue = shadow;
        }
        break;

    case CR_ACCESS_TYPE_CLTS:
        /* Clear TS bit in CR0 */
        {
            SIZE_T cr0 = 0;
            __vmx_vmread(VMCS_GUEST_CR0, &cr0);
            cr0 &= ~(1ULL << 3);  /* Clear TS (bit 3) */
            __vmx_vmwrite(VMCS_GUEST_CR0, cr0);

            SIZE_T shadow = 0;
            __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);
            shadow &= ~(1ULL << 3);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        }
        break;

    case CR_ACCESS_TYPE_LMSW:
        /* LMSW: load lower 16 bits of CR0 (PE cannot be cleared) */
        {
            USHORT source = (USHORT)CR_ACCESS_LMSW_SOURCE(qualification);
            SIZE_T cr0 = 0;
            __vmx_vmread(VMCS_GUEST_CR0, &cr0);

            cr0 = (cr0 & 0xFFFFFFFFFFFF0000ULL) | source;
            /* PE (bit 0) cannot be cleared by LMSW */
            SIZE_T oldCr0 = 0;
            __vmx_vmread(VMCS_GUEST_CR0, &oldCr0);
            if (oldCr0 & 1) cr0 |= 1;

            ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
            ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
            cr0 = (cr0 | cr0Fixed0) & cr0Fixed1;

            __vmx_vmwrite(VMCS_GUEST_CR0, cr0);
        }
        break;
    }
}
