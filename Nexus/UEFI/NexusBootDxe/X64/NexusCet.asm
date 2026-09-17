;
; NexusCet -- turn CR4.CET off and back on from C. Replaces X64/Cet.asm.
;
; This is assembly because it cannot be anything else. Two of the instructions below have no
; C expression at all, and the control flow has to be wrong on purpose:
;
;   * Clearing CR4.CET while the shadow stack still holds the return address pushed by our
;     own CALL leaves that entry stranded. INCSSPQ pops it. There is no intrinsic for it.
;
;   * Setting CR4.CET arms shadow-stack enforcement immediately, so the RET that would
;     normally end this function has no matching shadow-stack entry and faults. The return
;     address is taken off the data stack and jumped to instead.
;
; Facts from the Intel SDM: IA32_S_CET is MSR 0x6A2, bit 0 (SH_STK_EN) enables the supervisor
; shadow stack, and CR4.CET is bit 23.
;
; Callers: DisableWriteProtect / EnableWriteProtect in NexusUtil.c, which must bring CET down
; BEFORE clearing CR0.WP and put it back AFTER restoring CR0.WP.
;

NEXUS_MSR_S_CET             EQU 6A2h
NEXUS_S_CET_SH_STK_EN       EQU 1
NEXUS_CR4_CET_BIT           EQU 23

.code

align 16
AsmDisableCet PROC
        ;
        ; Only unwind the shadow stack if the supervisor shadow stack is actually enabled.
        ; INCSSPQ on a machine without it raises #UD.
        ;
        mov     ecx, NEXUS_MSR_S_CET
        rdmsr
        test    al, NEXUS_S_CET_SH_STK_EN
        jz      NexusCetNotArmed

        ;
        ; Discard the shadow-stack copy of our own return address. Without this the RET at
        ; the end mismatches and faults the moment enforcement is re-armed.
        ;
        mov     rax, 1
        incsspq rax

NexusCetNotArmed:
        mov     rax, cr4
        btr     eax, NEXUS_CR4_CET_BIT
        mov     cr4, rax
        ret
AsmDisableCet ENDP

align 16
AsmEnableCet PROC
        mov     rax, cr4
        bts     eax, NEXUS_CR4_CET_BIT
        mov     cr4, rax

        ;
        ; (!) DELIBERATELY NOT A RET. Enforcement is live as of the write above, and the
        ; shadow stack has no entry for this frame -- we removed it in AsmDisableCet. Take
        ; the return address off the data stack and jump.
        ;
        pop     rax
        jmp     rax
AsmEnableCet ENDP

end
