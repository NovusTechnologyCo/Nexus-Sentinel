; Step 9 Shared Code - Damage function used by all actors
; Compile with: ml64 /c step9_damage.asm
;
; Actor structure layout:
;   +0x00: id (int)
;   +0x04: padding
;   +0x08: health (float)
;   +0x0C: padding
;   +0x10: team (int) - 1 = player team, 2 = enemy team
;   +0x14: name (char[16])
;
; Users must inject code to check [rcx+10] (team) and conditionally skip damage
; for their team (team == 1)

.data
    ; Damage amount as float (will subtract this from health)
    damage_amount REAL4 5.0
    ; Zero constant for clamping
    zero_val REAL4 0.0

.code

; External: Get actor pointer by index
extern Step9_GetActor:proc

; ============================================================================
; void __stdcall Step9_DealDamage(int actorIndex)
; Deals damage to an actor - THIS IS THE SHARED CODE
; All actors use this same function, users must inject to differentiate
; ============================================================================
Step9_DealDamage proc
    ; Save actorIndex (in ECX on entry per Windows x64 calling convention)
    push rbx
    sub rsp, 20h

    mov ebx, ecx                ; Save actor index in EBX

    ; Get actor pointer: Step9_GetActor(actorIndex)
    ; ECX already has actorIndex
    call Step9_GetActor

    ; RAX now contains actor pointer (or NULL)
    test rax, rax
    jz done

    ; RAX = actor pointer
    ; [RAX+08h] = health (float)
    ; [RAX+10h] = team (int)
    ;
    ; THE DAMAGE INSTRUCTION - users will find this with "find what writes"
    ; They need to inject code here to check team before applying damage
    ;
    ; Load current health
    movss xmm0, dword ptr [rax+08h]     ; xmm0 = current health

    ; Load damage amount
    movss xmm1, dword ptr [damage_amount]

    ; Subtract damage: health = health - damage
    subss xmm0, xmm1

    ; Clamp to zero (don't allow negative health)
    movss xmm2, dword ptr [zero_val]
    maxss xmm0, xmm2                    ; xmm0 = max(health, 0)

    ; Store new health - THIS IS THE WRITE INSTRUCTION TO FIND
    movss dword ptr [rax+08h], xmm0     ; Write health back

done:
    add rsp, 20h
    pop rbx
    ret
Step9_DealDamage endp

; ============================================================================
; void __stdcall Step9_Attack(int actorIndex)
; Wrapper that can be called from C# - attacks a specific actor
; ============================================================================
Step9_Attack proc
    ; Just call DealDamage with the actor index
    jmp Step9_DealDamage
Step9_Attack endp

end
