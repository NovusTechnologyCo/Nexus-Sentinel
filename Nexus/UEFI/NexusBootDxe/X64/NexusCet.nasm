;
; NexusCet -- turn CR4.CET off and back on from C. Replaces X64/Cet.nasm.
;
; NASM twin of NexusCet.asm, for the EDK2 (.inf) build; the MSVC (.vcxproj) build assembles
; the MASM one. Keep the two in step -- they are the same routine for two assemblers.
;
; Assembly is forced here, not chosen. INCSSPQ has no C expression, and AsmEnableCet must not
; end in a RET: enforcement is live the instant CR4.CET is set, and this frame has no
; shadow-stack entry because AsmDisableCet removed it.
;
; Intel SDM: IA32_S_CET is MSR 0x6A2, bit 0 (SH_STK_EN) enables the supervisor shadow stack,
; CR4.CET is bit 23.
;

%define NEXUS_MSR_S_CET             0x6A2
%define NEXUS_S_CET_SH_STK_EN       0x1
%define NEXUS_CR4_CET_BIT           23

DEFAULT REL
SECTION .text

align 16
global ASM_PFX(AsmDisableCet)
ASM_PFX(AsmDisableCet):
	;
	; Only unwind the shadow stack if the supervisor shadow stack is actually enabled --
	; INCSSPQ raises #UD on a machine without it.
	;
	mov     ecx, NEXUS_MSR_S_CET
	rdmsr
	test    al, NEXUS_S_CET_SH_STK_EN
	jz      .NexusCetNotArmed

	;
	; Discard the shadow-stack copy of our own return address, or the RET below mismatches
	; as soon as enforcement comes back.
	;
	mov     rax, 1
	incsspq rax

.NexusCetNotArmed:
	mov     rax, cr4
	btr     eax, NEXUS_CR4_CET_BIT
	mov     cr4, rax
	ret

align 16
global ASM_PFX(AsmEnableCet)
ASM_PFX(AsmEnableCet):
	mov     rax, cr4
	bts     eax, NEXUS_CR4_CET_BIT
	mov     cr4, rax

	;
	; (!) DELIBERATELY NOT A RET -- see the header comment.
	;
	pop     rax
	jmp     rax
