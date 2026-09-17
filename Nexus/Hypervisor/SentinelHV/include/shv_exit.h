/**
 * @file shv_exit.h
 * @brief VM-exit handler function declarations.
 *
 * Declares the main VM-exit dispatcher and all individual exit reason handlers
 * invoked during VMX non-root operation. The dispatcher (ShvHandleVmExit) is
 * called from the assembly exit stub on every VM-exit and routes to the
 * appropriate handler based on the basic exit reason.
 *
 * Handler categories:
 *   - **CPUID**: Hides VMX capability bit, reports hypervisor vendor leaf.
 *   - **MSR Read/Write**: Passthrough for intercepted MSR accesses.
 *   - **CR Access**: Enforces VMX fixed bits, hides CR4.VMXE from guest.
 *   - **VMCALL**: Dispatches hypercall commands (ping, devirtualize).
 *   - **XSETBV / INVD**: Passthrough with safety (INVD upgraded to WBINVD).
 *   - **EPT Violation/Misconfig**: Diagnostic handlers for EPT faults.
 *   - **Triple Fault**: Fatal error logging and bugcheck.
 *
 * ShvAdvanceGuestRip is a shared utility that increments the guest instruction
 * pointer past the instruction that caused the exit, used by most handlers
 * before returning to VMRESUME.
 */

#pragma once

#include "shv_arch.h"

/* Forward declaration */
typedef struct _VCPU_DATA VCPU_DATA, *PVCPU_DATA;

/**
 * @brief Main VM-exit dispatcher, called from the ASM exit stub.
 *
 * Reads the exit reason from VMCS, logs it to CMOS diagnostics, and routes
 * to the appropriate handler. Unhandled exit reasons trigger a bugcheck.
 *
 * @param GuestContext  Saved guest GPR state (modifiable by handlers).
 * @param Vcpu          Per-CPU VCPU data for the current processor.
 * @return TRUE if devirtualization was requested (skip VMRESUME), FALSE for normal resume.
 */
BOOLEAN
ShvHandleVmExit(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    );

/**
 * @brief Handle CPUID VM-exit by executing real CPUID with selective modifications.
 *
 * Sets the hypervisor-present bit (ECX.31) on leaf 1 and returns a custom
 * vendor signature on the hypervisor leaf (0x40000000). All other leaves
 * are passed through unmodified.
 *
 * @param GuestContext  Guest registers; RAX=leaf, RCX=subleaf on entry;
 *                      RAX/RBX/RCX/RDX set to CPUID results on return.
 */
void ShvHandleCpuid(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle RDMSR VM-exit by executing the MSR read on the host CPU.
 *
 * Returns the 64-bit MSR value in the guest's EDX:EAX registers per the
 * standard x64 MSR read convention.
 *
 * @param GuestContext  Guest registers; RCX=MSR index on entry.
 */
void ShvHandleMsrRead(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle WRMSR VM-exit by executing the MSR write on the host CPU.
 *
 * Writes the value from the guest's EDX:EAX to the MSR specified in RCX.
 *
 * @param GuestContext  Guest registers; RCX=MSR index, EDX:EAX=value.
 */
void ShvHandleMsrWrite(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle control register access VM-exit (MOV to/from CR, CLTS, LMSW).
 *
 * Enforces VMX fixed bits on CR0/CR4 writes, maintains CR4.VMXE=1 while
 * hiding it from the guest via the read shadow. Decodes the exit
 * qualification to determine the CR number, access type, and GPR involved.
 *
 * @param GuestContext  Guest registers; the GPR involved is read/written.
 */
void ShvHandleCrAccess(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle XSETBV VM-exit by executing XSETBV on the host CPU.
 *
 * Passes through the guest's XCR index (RCX) and value (EDX:EAX)
 * to the real XSETBV instruction.
 *
 * @param GuestContext  Guest registers with XCR index and value.
 */
void ShvHandleXsetbv(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle INVD VM-exit by executing WBINVD instead.
 *
 * INVD discards dirty cache lines without writeback, which could corrupt
 * data. We upgrade it to WBINVD (writeback + invalidate) for safety.
 */
void ShvHandleInvd(void);

/**
 * @brief Handle VMCALL VM-exit by dispatching hypercall commands.
 *
 * Supported commands:
 *   - VMCALL_PING: Returns VMCALL_PING_RESPONSE in RAX (health check).
 *   - VMCALL_DEVIRTUALIZE: Validates magic cookie, then calls
 *     ShvVmxOffAndRestore to exit VMX operation (does not return).
 *
 * Unknown commands return STATUS_INVALID_PARAMETER in RAX.
 *
 * @param GuestContext  Guest registers; RCX=command, RDX=cookie.
 * @param Vcpu          Per-CPU data for logging.
 * @return TRUE if devirtualization was performed, FALSE otherwise.
 */
BOOLEAN
ShvHandleVmcall(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    );

/**
 * @brief Handle triple fault VM-exit (fatal, does not return).
 *
 * Logs guest RIP, RSP, and CR3 to debug output and CMOS diagnostics,
 * then triggers a bugcheck.
 */
void ShvHandleTripleFault(void);

/** Handle UMWAIT (67) / TPAUSE (68) exits — Arrow Lake+ power-wait instructions. */
void ShvHandleUmwaitTpause(void);

/**
 * @brief Handle EPT violation VM-exit.
 *
 * In Phase 1 (identity map with RWX on all pages), EPT violations are
 * unexpected. Logs full diagnostic information (GPA, GLA, RIP, access type
 * vs. entry permissions) and injects #GP(0) into the guest.
 *
 * Future phases will use this handler for execute-only hooks, read/write
 * logging, and memory isolation.
 *
 * @param GuestContext  Guest registers (unused in Phase 1).
 * @param Vcpu          Per-CPU data (unused in Phase 1).
 */
void ShvHandleEptViolation(_Inout_ PGUEST_CONTEXT GuestContext, _In_ PVCPU_DATA Vcpu);

/**
 * @brief Handle EPT misconfiguration VM-exit (fatal, does not return).
 *
 * An EPT misconfiguration indicates an illegal EPT entry (invalid memory
 * type, reserved bits set, write-only without read). This always represents
 * a bug in EPT construction. Logs the faulting GPA and guest RIP, then
 * triggers a bugcheck.
 *
 * @param GuestContext  Guest registers (unused).
 */
void ShvHandleEptMisconfig(_Inout_ PGUEST_CONTEXT GuestContext);

/**
 * @brief Handle Monitor Trap Flag (MTF) VM-exit.
 *
 * Fires after a single guest instruction completes when MTF was enabled.
 * Used by the FIFO EPT read-trap: disables MTF in VMCS proc-based controls,
 * then re-removes the Read bit from the FIFO EPT PTE to re-arm the trap.
 *
 * Does NOT advance guest RIP (MTF fires after the instruction completes,
 * and the guest should continue at the next instruction naturally).
 *
 * @param GuestContext  Guest registers (unused).
 * @param Vcpu          Per-CPU data containing MtfFifoRearmPending flag.
 */
void ShvHandleMtfExit(_Inout_ PGUEST_CONTEXT GuestContext, _In_ PVCPU_DATA Vcpu);

/**
 * @brief Advance guest RIP past the instruction that caused the VM-exit.
 *
 * Reads VMCS_RO_VMEXIT_INSTRUCTION_LEN and adds it to VMCS_GUEST_RIP.
 * Called by most exit handlers before returning to VMRESUME so the guest
 * does not re-execute the intercepted instruction in a loop.
 */
void ShvAdvanceGuestRip(void);

/**
 * @brief Inject a hardware exception into the guest on VM-entry.
 *
 * Builds the VM-entry interruption-information field per Intel SDM Vol 3
 * Sec 25.8.3, writes the optional error code, copies the VM-exit instruction
 * length to VM-entry instruction length (so re-injection of #BP/#OF/etc.
 * advances correctly), and does NOT advance guest RIP — the exception
 * delivery semantics handle that. Use for #UD/#GP injection from probes
 * we want to look bare-metal-equivalent (XSETBV with bad ECX, VMXOFF from
 * non-root guest, etc.).
 *
 * @param vector       Exception vector (VECTOR_GP, VECTOR_UD, VECTOR_VE, ...)
 * @param error_code   Error code; ignored when vector doesn't deliver one.
 *                     For #GP/#PF/#NP/#SS/#TS/#DF/#AC use 0 unless specific
 *                     error required.
 */
void ShvInjectException(ULONG vector, ULONG error_code);
