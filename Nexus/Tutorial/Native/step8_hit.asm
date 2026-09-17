; Step 8 functions - traverses 4-level pointer chain with visible offsets
; Compile with: ml64 /c step8_hit.asm
; Pointer chain: [[[[base+20]+0]+10]+18] = health
; Offsets from value to base: +18, +10, +0, +20

.code

; External: returns address of g_step8Base (the static pointer variable)
extern Step8_GetBaseAddress:proc

; ============================================================================
; int __stdcall Step8_ReadHealthSlow(void)
; Traverses the pointer chain using only registers (no stack variables)
; This ensures no duplicate pointer values appear in memory scans
; ============================================================================
Step8_ReadHealthSlow proc
    ; Get address of g_step8Base into RAX
    sub rsp, 28h
    call Step8_GetBaseAddress
    add rsp, 28h

    ; RAX = &g_step8Base (address of the static pointer)
    test rax, rax
    jz read_zero

    ; Level 1: Load g_step8Base (the pointer value itself)
    mov rax, [rax]          ; RAX = g_step8Base (Level1 struct pointer)
    test rax, rax
    jz read_zero

    ; Level 1 -> Level 2: [rax+20h] = level2 pointer
    mov rax, [rax+20h]      ; RAX = Level2 struct pointer (offset +20)
    test rax, rax
    jz read_zero

    ; Level 2 -> Level 3: [rax+0] = level3 pointer
    mov rax, [rax]          ; RAX = Level3 struct pointer (offset +0)
    test rax, rax
    jz read_zero

    ; Level 3 -> Level 4: [rax+10h] = level4 pointer
    mov rax, [rax+10h]      ; RAX = Level4 struct pointer (offset +10)
    test rax, rax
    jz read_zero

    ; Level 4 -> Health: [rax+18h] = health value
    mov eax, dword ptr [rax+18h]    ; Return health in EAX
    ret

read_zero:
    xor eax, eax            ; Return 0
    ret
Step8_ReadHealthSlow endp

; ============================================================================
; void __stdcall Step8_Hit(void)
; Traverses the pointer chain with visible offsets at each level
; ============================================================================
Step8_Hit proc
    ; Get address of g_step8Base into RAX
    sub rsp, 28h
    call Step8_GetBaseAddress
    add rsp, 28h

    ; RAX = &g_step8Base (address of the static pointer)
    test rax, rax
    jz skip_hit

    ; Level 1: Load g_step8Base (the pointer value itself)
    mov rax, [rax]          ; RAX = g_step8Base (Level1 struct pointer)
    test rax, rax
    jz skip_hit

    ; Level 1 -> Level 2: [rax+20h] = level2 pointer
    mov rax, [rax+20h]      ; RAX = Level2 struct pointer (offset +20)
    test rax, rax
    jz skip_hit

    ; Level 2 -> Level 3: [rax+0] = level3 pointer (offset +0, shows as [rax])
    mov rax, [rax]          ; RAX = Level3 struct pointer (offset +0)
    test rax, rax
    jz skip_hit

    ; Level 3 -> Level 4: [rax+10h] = level4 pointer
    mov rax, [rax+10h]      ; RAX = Level4 struct pointer (offset +10)
    test rax, rax
    jz skip_hit

    ; Level 4 -> Health: [rax+18h] = health value
    ; SUB dword ptr [rax+18h], 1
    ; This is the final instruction users will find with "what writes"
    sub dword ptr [rax+18h], 1

skip_hit:
    ret
Step8_Hit endp

end
