;; @file vmx_asm.asm
;; @brief VMX assembly stubs for MASM x64 (SentinelHV).
;;
;; Implements low-level VMX operations that cannot be expressed in C:
;;
;;   ShvCaptureContext   - Save all GPRs, RSP, RIP, RFLAGS into GUEST_CONTEXT.
;;                         Uses a setjmp-like dual-return mechanism: returns 0
;;                         on first call, 1 when resumed as VMX guest.
;;
;;   ShvVmxLaunch        - Load guest GPRs from GUEST_CONTEXT and execute
;;                         VMLAUNCH. Does not return on success.
;;
;;   ShvVmExitStub       - HOST_RIP entry point for all VM-exits. Saves guest
;;                         GPRs, calls ShvHandleVmExit (C), restores GPRs,
;;                         and executes VMRESUME.
;;
;;   ShvVmxOffAndRestore - Execute VMXOFF, clear CR4.VMXE, restore guest RSP
;;                         and RFLAGS, set return value in RAX, JMP to guest RIP.
;;                         Called during devirtualization; does not return.
;;
;;   ShvDoVmcall         - Execute VMCALL with command (RCX) and cookie (RDX).
;;                         Returns the exit handler's RAX value.
;;
;;   Segment readers     - ShvReadCs/Ss/Ds/Es/Fs/Gs/Tr/Ldtr: read segment
;;                         selectors that MSVC x64 lacks intrinsics for.
;;
;;   Descriptor table    - ShvSgdt/ShvSidt: execute SGDT/SIDT instructions.
;;   readers
;;
;;   ShvReadDr7          - Read the DR7 debug control register.
;;
;;   ShvInvept/ShvInvvpid - Execute INVEPT/INVVPID for TLB invalidation.
;;

; ksamd64.inc is WDK-only; skip for UEFI builds.
; All needed constants are defined inline below.
IFNDEF SHV_PLATFORM_EFI
INCLUDE ksamd64.inc
ENDIF

; GUEST_CONTEXT field offsets (must match shv_arch.h)
GUEST_RAX           EQU 000h
GUEST_RCX           EQU 008h
GUEST_RDX           EQU 010h
GUEST_RBX           EQU 018h
GUEST_RSP_FIELD     EQU 020h
GUEST_RBP           EQU 028h
GUEST_RSI           EQU 030h
GUEST_RDI           EQU 038h
GUEST_R8            EQU 040h
GUEST_R9            EQU 048h
GUEST_R10           EQU 050h
GUEST_R11           EQU 058h
GUEST_R12           EQU 060h
GUEST_R13           EQU 068h
GUEST_R14           EQU 070h
GUEST_R15           EQU 078h
GUEST_RFLAGS        EQU 080h
GUEST_RIP_FIELD     EQU 088h

GUEST_CONTEXT_SIZE  EQU 090h

EXTERN ShvHandleVmExit:PROC

.CODE

;; ---------------------------------------------------------------------------
;; ULONG64 ShvCaptureContext(PGUEST_CONTEXT Context)
;;
;; Captures the current CPU register state into a GUEST_CONTEXT structure
;; for use as VMCS guest state. Saves all 16 GPRs, the caller's RSP
;; (current RSP + 8 to account for the return address on the stack),
;; the return address as RIP, and RFLAGS.
;;
;; Returns 0 on first call. After VMLAUNCH, the CPU resumes execution at
;; the captured RIP (this function's return address). The VMCS setup code
;; sets guest RAX=1, so the caller of ShvCaptureContext sees a non-zero
;; return and knows it is running as a VMX guest.
;;
;; Input:  RCX = pointer to GUEST_CONTEXT
;; Output: RAX = 0 (first call), 1 (resumed as guest)
;; ---------------------------------------------------------------------------
ShvCaptureContext PROC

    mov     [rcx + GUEST_RAX], rax
    mov     [rcx + GUEST_RCX], rcx
    mov     [rcx + GUEST_RDX], rdx
    mov     [rcx + GUEST_RBX], rbx
    mov     [rcx + GUEST_RBP], rbp
    mov     [rcx + GUEST_RSI], rsi
    mov     [rcx + GUEST_RDI], rdi
    mov     [rcx + GUEST_R8],  r8
    mov     [rcx + GUEST_R9],  r9
    mov     [rcx + GUEST_R10], r10
    mov     [rcx + GUEST_R11], r11
    mov     [rcx + GUEST_R12], r12
    mov     [rcx + GUEST_R13], r13
    mov     [rcx + GUEST_R14], r14
    mov     [rcx + GUEST_R15], r15

    ; Caller's RSP = current RSP + 8 (return address on stack)
    lea     rax, [rsp + 8]
    mov     [rcx + GUEST_RSP_FIELD], rax

    ; Caller's RIP = return address
    mov     rax, [rsp]
    mov     [rcx + GUEST_RIP_FIELD], rax

    pushfq
    pop     rax
    mov     [rcx + GUEST_RFLAGS], rax

    xor     eax, eax
    ret

ShvCaptureContext ENDP

;; ---------------------------------------------------------------------------
;; ULONG64 ShvVmxLaunch(PGUEST_CONTEXT Context)
;;
;; Loads all guest GPRs from the provided GUEST_CONTEXT structure and
;; executes VMLAUNCH. On success, the CPU transitions to VMX non-root
;; operation at VMCS_GUEST_RIP and this function never returns.
;;
;; On failure (CF or ZF set by VMLAUNCH), pushes RFLAGS and returns the
;; value in RAX for error diagnosis. The caller should read
;; VMCS_RO_VM_INSTRUCTION_ERROR for the specific error code.
;;
;; Note: Guest RIP, RSP, and RFLAGS come from VMCS fields set during
;; ShvSetupVmcs, not from the Context parameter.
;;
;; Input:  RCX = pointer to GUEST_CONTEXT
;; Output: RAX = RFLAGS on failure; does not return on success
;; ---------------------------------------------------------------------------
ShvVmxLaunch PROC

    mov     rax, rcx

    mov     r15, [rax + GUEST_R15]
    mov     r14, [rax + GUEST_R14]
    mov     r13, [rax + GUEST_R13]
    mov     r12, [rax + GUEST_R12]
    mov     r11, [rax + GUEST_R11]
    mov     r10, [rax + GUEST_R10]
    mov     r9,  [rax + GUEST_R9]
    mov     r8,  [rax + GUEST_R8]
    mov     rdi, [rax + GUEST_RDI]
    mov     rsi, [rax + GUEST_RSI]
    mov     rbp, [rax + GUEST_RBP]
    mov     rbx, [rax + GUEST_RBX]
    mov     rdx, [rax + GUEST_RDX]
    mov     rcx, [rax + GUEST_RCX]
    mov     rax, [rax + GUEST_RAX]

    vmlaunch

    ; VMLAUNCH failed
    pushfq
    pop     rax
    ret

ShvVmxLaunch ENDP

;; ---------------------------------------------------------------------------
;; ShvVmExitStub
;;
;; Assembly entry point for ALL VM-exits (address written to VMCS HOST_RIP).
;;
;; On every VM-exit, the CPU atomically:
;;   1. Loads HOST_RSP from VMCS into RSP.
;;   2. Loads HOST_RIP from VMCS into RIP (jumps here).
;;   3. Leaves all guest GPRs in the actual CPU registers.
;;
;; Stack layout (configured by ShvSetupVmcs in vmcs.c):
;;   HOST_RSP ----> [PVCPU_DATA pointer]  (8 bytes, pre-stored)
;;                  ... 16KB host stack space (grows downward) ...
;;
;; Algorithm:
;;   1. Save guest RAX, load VCPU pointer from [HOST_RSP].
;;   2. Push VCPU pointer for later retrieval.
;;   3. Allocate GUEST_CONTEXT on the stack and save all guest GPRs.
;;   4. Call ShvHandleVmExit(&context, vcpu) with x64 calling convention.
;;   5. If handler returns FALSE: restore GPRs and execute VMRESUME.
;;      If handler returns TRUE: devirtualization occurred (ShvVmxOffAndRestore
;;      already jumped to guest code; reaching here is a bug -> INT 3).
;; ---------------------------------------------------------------------------
ShvVmExitStub PROC

    ; RSP = HOST_RSP. [RSP] = VCPU pointer (pre-stored in vmcs.c).
    ;
    ; Strategy: push all guest GPRs onto the host stack to form a
    ; GUEST_CONTEXT. Then call ShvHandleVmExit(&context, vcpu).
    ;
    ; But we need to read [RSP] (VCPU ptr) before pushing overwrites it.
    ; We use a push-based approach: push GPRs in reverse order so that
    ; the struct is at the top of stack when done.

    ; First, stash the VCPU pointer. We'll use it after saving regs.
    ; Push it further down - save in a callee-saved slot after context.
    ;
    ; Actually simplest: exchange RSP content with a register.
    ; On VM-exit, guest registers are in the actual CPU registers.
    ; We must save them all. Use the trick: save RAX first, load VCPU
    ; into RAX, push VCPU, restore RAX, then save everything.

    ; Step 1: Save guest RAX to scratch, load VCPU pointer
    push    rax                     ; [RSP-8] = guest RAX (pushed below VCPU ptr slot)
    mov     rax, [rsp + 8]         ; RAX = VCPU pointer (original [HOST_RSP])

    ; Step 2: Push VCPU pointer as a "hidden" frame element
    push    rax                     ; [RSP-16] = VCPU pointer (saved for later)

    ; Step 3: Recover guest RAX
    ; After two pushes: RSP = HOST_RSP - 16
    ;   [rsp + 10h] = [HOST_RSP]   = VCPU pointer (pre-stored)
    ;   [rsp + 08h] = [HOST_RSP-8] = guest RAX (pushed at step 1)
    ;   [rsp + 00h] = [HOST_RSP-16]= VCPU pointer (pushed at step 2)
    mov     rax, [rsp + 8]         ; RAX = original guest RAX (pushed at step 1)

    ; Step 4: Allocate GUEST_CONTEXT on stack
    sub     rsp, GUEST_CONTEXT_SIZE

    ; Step 5: Save all guest GPRs
    mov     [rsp + GUEST_RAX], rax
    mov     [rsp + GUEST_RCX], rcx
    mov     [rsp + GUEST_RDX], rdx
    mov     [rsp + GUEST_RBX], rbx
    mov     [rsp + GUEST_RBP], rbp
    mov     [rsp + GUEST_RSI], rsi
    mov     [rsp + GUEST_RDI], rdi
    mov     [rsp + GUEST_R8],  r8
    mov     [rsp + GUEST_R9],  r9
    mov     [rsp + GUEST_R10], r10
    mov     [rsp + GUEST_R11], r11
    mov     [rsp + GUEST_R12], r12
    mov     [rsp + GUEST_R13], r13
    mov     [rsp + GUEST_R14], r14
    mov     [rsp + GUEST_R15], r15
    ; GUEST_RSP_FIELD and GUEST_RFLAGS/GUEST_RIP are unused by exit handler
    ; (they come from VMCS reads instead)

    ; Step 6: Call ShvHandleVmExit(PGUEST_CONTEXT, PVCPU_DATA)
    mov     rcx, rsp                                ; arg1 = &GUEST_CONTEXT
    mov     rdx, [rsp + GUEST_CONTEXT_SIZE]         ; arg2 = VCPU pointer

    ; x64 calling convention: 32-byte shadow space
    sub     rsp, 28h
    call    ShvHandleVmExit
    add     rsp, 28h

    ; Step 7: Check if devirtualize was requested
    test    al, al
    jnz     ExitDevirt

    ; Step 8: Restore guest GPRs
    mov     rax, [rsp + GUEST_RAX]
    mov     rcx, [rsp + GUEST_RCX]
    mov     rdx, [rsp + GUEST_RDX]
    mov     rbx, [rsp + GUEST_RBX]
    mov     rbp, [rsp + GUEST_RBP]
    mov     rsi, [rsp + GUEST_RSI]
    mov     rdi, [rsp + GUEST_RDI]
    mov     r8,  [rsp + GUEST_R8]
    mov     r9,  [rsp + GUEST_R9]
    mov     r10, [rsp + GUEST_R10]
    mov     r11, [rsp + GUEST_R11]
    mov     r12, [rsp + GUEST_R12]
    mov     r13, [rsp + GUEST_R13]
    mov     r14, [rsp + GUEST_R14]
    mov     r15, [rsp + GUEST_R15]

    ; Deallocate context + VCPU ptr + saved RAX
    add     rsp, GUEST_CONTEXT_SIZE + 10h

    vmresume

    ; VMRESUME failed - fatal
    int     3

ExitDevirt:
    ; ShvVmxOffAndRestore already jumped to guest code.
    ; We should never reach here.
    int     3

ShvVmExitStub ENDP

;; ---------------------------------------------------------------------------
;; void ShvVmxOffAndRestore(GuestRip, GuestRsp, GuestRflags, ReturnValue)
;;                          RCX       RDX       R8           R9
;;
;; Permanently exits VMX root operation on the current CPU.
;;
;; Sequence:
;;   1. VMXOFF - Leave VMX root operation.
;;   2. Clear CR4.VMXE (bit 13) - Remove VMX enable flag.
;;   3. MOV RSP, RDX - Restore guest stack pointer.
;;   4. PUSH R8; POPFQ - Restore guest RFLAGS.
;;   5. MOV RAX, R9 - Set return value (typically STATUS_SUCCESS).
;;   6. JMP RCX - Jump to guest RIP (past the VMCALL instruction).
;;
;; This function does NOT return. After execution, the CPU is no longer
;; in VMX operation and continues executing as a normal unprivileged CPU
;; at the guest's original instruction stream.
;; ---------------------------------------------------------------------------
ShvVmxOffAndRestore PROC

    vmxoff

    ; Clear CR4.VMXE (bit 13)
    mov     rax, cr4
    and     rax, NOT (1 SHL 13)
    mov     cr4, rax

    ; Restore guest stack
    mov     rsp, rdx

    ; Restore RFLAGS
    push    r8
    popfq

    ; Return value in RAX
    mov     rax, r9

    ; Jump to guest RIP (past the VMCALL instruction)
    jmp     rcx

    int     3

ShvVmxOffAndRestore ENDP

;; ---------------------------------------------------------------------------
;; NTSTATUS ShvDoVmcall(ULONG64 Command, ULONG64 Cookie)
;;                      RCX              RDX
;;
;; Executes the VMCALL instruction from VMX non-root (guest) mode.
;; The VM-exit handler reads the command from guest RCX and the
;; authentication cookie from guest RDX, processes the hypercall,
;; and sets guest RAX as the return value.
;;
;; For VMCALL_DEVIRTUALIZE: ShvVmxOffAndRestore executes VMXOFF and
;; returns here with STATUS_SUCCESS in RAX as if VMCALL returned normally.
;;
;; Input:  RCX = command code, RDX = authentication cookie
;; Output: RAX = NTSTATUS result from the exit handler
;; ---------------------------------------------------------------------------
ShvDoVmcall PROC

    ; Save callee-saved registers before VMCALL.
    ; For VMCALL_DEVIRTUALIZE, ShvVmxOffAndRestore does VMXOFF then
    ; JMPs past the VMCALL to the pops below — restoring all regs
    ; before returning to the caller.
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    vmcall

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

ShvDoVmcall ENDP

;; ---------------------------------------------------------------------------
;; Segment Register Readers
;;
;; MSVC x64 does not provide intrinsics for reading segment selectors
;; (no __readcs, __readss, etc.). These trivial functions read the
;; segment register into AX and return it as a USHORT.
;; ---------------------------------------------------------------------------
ShvReadCs PROC
    mov     ax, cs
    ret
ShvReadCs ENDP

ShvReadSs PROC
    mov     ax, ss
    ret
ShvReadSs ENDP

ShvReadDs PROC
    mov     ax, ds
    ret
ShvReadDs ENDP

ShvReadEs PROC
    mov     ax, es
    ret
ShvReadEs ENDP

ShvReadFs PROC
    mov     ax, fs
    ret
ShvReadFs ENDP

ShvReadGs PROC
    mov     ax, gs
    ret
ShvReadGs ENDP

ShvReadTr PROC
    str     ax
    ret
ShvReadTr ENDP

ShvReadLdtr PROC
    sldt    ax
    ret
ShvReadLdtr ENDP

;; ---------------------------------------------------------------------------
;; Descriptor Table Readers
;;
;; Execute SGDT/SIDT and store the result (2-byte limit + 8-byte base)
;; at the address in RCX. The output matches the DESCRIPTOR_TABLE_REG
;; structure defined in shv_arch.h.
;;
;; void ShvSgdt(PDESCRIPTOR_TABLE_REG Out)  ; RCX = output pointer
;; void ShvSidt(PDESCRIPTOR_TABLE_REG Out)  ; RCX = output pointer
;; ---------------------------------------------------------------------------
ShvSgdt PROC
    sgdt    [rcx]
    ret
ShvSgdt ENDP

ShvSidt PROC
    sidt    [rcx]
    ret
ShvSidt ENDP

;; ---------------------------------------------------------------------------
;; ULONG64 ShvReadDr7(void)
;;
;; Reads the DR7 (Debug Control) register and returns it in RAX.
;; Used during VMCS guest state initialization to capture the current
;; debug register configuration.
;; ---------------------------------------------------------------------------
ShvReadDr7 PROC
    mov     rax, dr7
    ret
ShvReadDr7 ENDP

;; ---------------------------------------------------------------------------
;; UCHAR ShvInvept(ULONG64 Type, INVEPT_DESCRIPTOR* Descriptor)
;;                 RCX            RDX
;;
;; Executes the INVEPT instruction to invalidate EPT-derived TLB entries.
;; Type selects single-context (1) or all-contexts (2) invalidation.
;; The descriptor contains the EPTP value for single-context mode.
;;
;; Returns 0 on success. Returns 1 if either ZF or CF was set by the
;; instruction (indicating an invalid operand or VMX error).
;; ---------------------------------------------------------------------------
ShvInvept PROC
    invept  rcx, OWORD PTR [rdx]
    jz      short inveptFail
    jc      short inveptFail
    xor     eax, eax
    ret
inveptFail:
    mov     eax, 1
    ret
ShvInvept ENDP

;; ---------------------------------------------------------------------------
;; UCHAR ShvInvvpid(ULONG64 Type, INVVPID_DESCRIPTOR* Descriptor)
;;                  RCX            RDX
;;
;; Executes the INVVPID instruction to invalidate VPID-tagged TLB entries.
;; Type selects the invalidation scope: individual address (0),
;; single-context (1), all-contexts (2), or single-context retaining
;; global translations (3).
;;
;; Returns 0 on success. Returns 1 if either ZF or CF was set by the
;; instruction (indicating an invalid operand or VMX error).
;; ---------------------------------------------------------------------------
ShvInvvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    jz      short invvpidFail
    jc      short invvpidFail
    xor     eax, eax
    ret
invvpidFail:
    mov     eax, 1
    ret
ShvInvvpid ENDP

END
