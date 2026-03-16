OPTION CASEMAP:NONE

.code

__int2d PROC
    int 2Dh
    int 3
    jmp qword ptr [rsp]
__int2d ENDP

__readcr0_rax PROC
    mov rax, cr0
    jmp qword ptr [rsp]
__readcr0_rax ENDP

__readcr2_rax PROC
    mov rax, cr2
    jmp qword ptr [rsp]
__readcr2_rax ENDP

__readcr3_rax PROC
    mov rax, cr3
    jmp qword ptr [rsp]
__readcr3_rax ENDP

__readcr4_rax PROC
    mov rax, cr4
    jmp qword ptr [rsp]
__readcr4_rax ENDP

__readcr8_rax PROC
    mov rax, cr8
    jmp qword ptr [rsp]
__readcr8_rax ENDP

__writecr0_rax PROC
    mov cr0, rax
    jmp qword ptr [rsp]
__writecr0_rax ENDP

__writecr2_rax PROC
    mov cr2, rax
    jmp qword ptr [rsp]
__writecr2_rax ENDP

__writecr3_rax PROC
    mov cr3, rax
    jmp qword ptr [rsp]
__writecr3_rax ENDP

__writecr4_rax PROC
    mov cr4, rax
    jmp qword ptr [rsp]
__writecr4_rax ENDP

__writecr8_rax PROC
    mov cr8, rax
    jmp qword ptr [rsp]
__writecr8_rax ENDP

END
