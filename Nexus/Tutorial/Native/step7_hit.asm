; Step 7 Hit function - uses SUB instruction for code injection tutorial
; Compile with: ml64 /c step7_hit.asm

.code

; External function to get the health pointer
extern Step7_GetHealthPtrInternal:proc

; void __stdcall Step7_Hit(void)
; Exported function that subtracts 1 from health using SUB instruction
Step7_Hit proc
    ; Get address of health into RAX
    sub rsp, 28h          ; Shadow space for call
    call Step7_GetHealthPtrInternal
    add rsp, 28h

    ; RAX now contains pointer to health
    ; SUB dword ptr [rax], 1
    ; This is the instruction users need to find and inject code to change to ADD
    sub dword ptr [rax], 1
    ret
Step7_Hit endp

end
