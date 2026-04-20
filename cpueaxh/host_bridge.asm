OPTION CASEMAP:NONE

CTX_RAX    EQU 0
CTX_RCX    EQU 8
CTX_RDX    EQU 16
CTX_RBX    EQU 24
CTX_RSP    EQU 32
CTX_RBP    EQU 40
CTX_RSI    EQU 48
CTX_RDI    EQU 56
CTX_R8     EQU 64
CTX_R9     EQU 72
CTX_R10    EQU 80
CTX_R11    EQU 88
CTX_R12    EQU 96
CTX_R13    EQU 104
CTX_R14    EQU 112
CTX_R15    EQU 120
CTX_RIP    EQU 128
CTX_RFLAGS EQU 136
CTX_XMM0   EQU 144
CTX_XMM1   EQU 160
CTX_XMM2   EQU 176
CTX_XMM3   EQU 192
CTX_XMM4   EQU 208
CTX_XMM5   EQU 224
CTX_XMM6   EQU 240
CTX_XMM7   EQU 256
CTX_XMM8   EQU 272
CTX_XMM9   EQU 288
CTX_XMM10  EQU 304
CTX_XMM11  EQU 320
CTX_XMM12  EQU 336
CTX_XMM13  EQU 352
CTX_XMM14  EQU 368
CTX_XMM15  EQU 384
; mxcsr lives after xmm[16] (144..400), ymm_upper[16] (400..656),
; zmm_upper[16] (656..1168), opmask[8] (1168..1232) and mm[8]
; (1232..1296) in cpueaxh_x86_context. The previous value (720)
; pointed inside ymm_upper, which silently fed garbage YMM bits to
; ldmxcsr and unmasked FP exceptions in the host on return.
CTX_MXCSR  EQU 1296

BLOCK_HOST_RSP     EQU 0
BLOCK_CTXPTR       EQU 8
BLOCK_GUEST_RSP    EQU 16
BLOCK_SAVED_STACK0 EQU 24
BLOCK_SAVED_STACK1 EQU 32
BLOCK_SAVED_STACK2 EQU 40
BLOCK_SAVED_RAX    EQU 48

LOCAL_XMM0   EQU 0
LOCAL_XMM1   EQU 16
LOCAL_XMM2   EQU 32
LOCAL_XMM3   EQU 48
LOCAL_XMM4   EQU 64
LOCAL_XMM5   EQU 80
LOCAL_XMM6   EQU 96
LOCAL_XMM7   EQU 112
LOCAL_XMM8   EQU 128
LOCAL_XMM9   EQU 144
LOCAL_XMM10  EQU 160
LOCAL_XMM11  EQU 176
LOCAL_XMM12  EQU 192
LOCAL_XMM13  EQU 208
LOCAL_XMM14  EQU 224
LOCAL_XMM15  EQU 240
LOCAL_MXCSR  EQU 256
LOCAL_SIZE   EQU 272

.code

cpueaxh_host_call_asm PROC
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, LOCAL_SIZE

    movdqu xmmword ptr [rsp + LOCAL_XMM0], xmm0
    movdqu xmmword ptr [rsp + LOCAL_XMM1], xmm1
    movdqu xmmword ptr [rsp + LOCAL_XMM2], xmm2
    movdqu xmmword ptr [rsp + LOCAL_XMM3], xmm3
    movdqu xmmword ptr [rsp + LOCAL_XMM4], xmm4
    movdqu xmmword ptr [rsp + LOCAL_XMM5], xmm5
    movdqu xmmword ptr [rsp + LOCAL_XMM6], xmm6
    movdqu xmmword ptr [rsp + LOCAL_XMM7], xmm7
    movdqu xmmword ptr [rsp + LOCAL_XMM8], xmm8
    movdqu xmmword ptr [rsp + LOCAL_XMM9], xmm9
    movdqu xmmword ptr [rsp + LOCAL_XMM10], xmm10
    movdqu xmmword ptr [rsp + LOCAL_XMM11], xmm11
    movdqu xmmword ptr [rsp + LOCAL_XMM12], xmm12
    movdqu xmmword ptr [rsp + LOCAL_XMM13], xmm13
    movdqu xmmword ptr [rsp + LOCAL_XMM14], xmm14
    movdqu xmmword ptr [rsp + LOCAL_XMM15], xmm15
    stmxcsr dword ptr [rsp + LOCAL_MXCSR]

    mov qword ptr [r8 + BLOCK_HOST_RSP], rsp
    mov qword ptr [r8 + BLOCK_CTXPTR], rcx
    mov r9, qword ptr [rcx + CTX_RSP]
    mov qword ptr [r8 + BLOCK_GUEST_RSP], r9
    mov r10, qword ptr [r9]
    mov qword ptr [r8 + BLOCK_SAVED_STACK0], r10
    mov r10, qword ptr [r9 + 8]
    mov qword ptr [r8 + BLOCK_SAVED_STACK1], r10
    mov r10, qword ptr [r9 + 16]
    mov qword ptr [r8 + BLOCK_SAVED_STACK2], r10
    lea r10, cpueaxh_host_bridge_resume
    mov qword ptr [r9], r10
    mov qword ptr [r9 + 8], r8
    mov qword ptr [r9 + 16], rdx

    ldmxcsr dword ptr [rcx + CTX_MXCSR]
    movdqu xmm0, xmmword ptr [rcx + CTX_XMM0]
    movdqu xmm1, xmmword ptr [rcx + CTX_XMM1]
    movdqu xmm2, xmmword ptr [rcx + CTX_XMM2]
    movdqu xmm3, xmmword ptr [rcx + CTX_XMM3]
    movdqu xmm4, xmmword ptr [rcx + CTX_XMM4]
    movdqu xmm5, xmmword ptr [rcx + CTX_XMM5]
    movdqu xmm6, xmmword ptr [rcx + CTX_XMM6]
    movdqu xmm7, xmmword ptr [rcx + CTX_XMM7]
    movdqu xmm8, xmmword ptr [rcx + CTX_XMM8]
    movdqu xmm9, xmmword ptr [rcx + CTX_XMM9]
    movdqu xmm10, xmmword ptr [rcx + CTX_XMM10]
    movdqu xmm11, xmmword ptr [rcx + CTX_XMM11]
    movdqu xmm12, xmmword ptr [rcx + CTX_XMM12]
    movdqu xmm13, xmmword ptr [rcx + CTX_XMM13]
    movdqu xmm14, xmmword ptr [rcx + CTX_XMM14]
    movdqu xmm15, xmmword ptr [rcx + CTX_XMM15]

    mov rax, qword ptr [rcx + CTX_RFLAGS]
    push rax
    popfq

    mov r10, rcx

    mov rax, qword ptr [r10 + CTX_RAX]
    mov rcx, qword ptr [r10 + CTX_RCX]
    mov rdx, qword ptr [r10 + CTX_RDX]
    mov rbx, qword ptr [r10 + CTX_RBX]
    mov rbp, qword ptr [r10 + CTX_RBP]
    mov rsi, qword ptr [r10 + CTX_RSI]
    mov rdi, qword ptr [r10 + CTX_RDI]
    mov r8, qword ptr [r10 + CTX_R8]
    mov r9, qword ptr [r10 + CTX_R9]
    mov r11, qword ptr [r10 + CTX_R11]
    mov r12, qword ptr [r10 + CTX_R12]
    mov r13, qword ptr [r10 + CTX_R13]
    mov r14, qword ptr [r10 + CTX_R14]
    mov r15, qword ptr [r10 + CTX_R15]
    mov rsp, qword ptr [r10 + CTX_RSP]
    mov r10, qword ptr [r10 + CTX_R10]
    jmp qword ptr [rsp + 16]

cpueaxh_host_bridge_resume LABEL PROC
    xchg r11, qword ptr [rsp + 8]
    mov qword ptr [r11 + BLOCK_SAVED_RAX], rax
    mov rax, r10
    mov r10, qword ptr [r11 + BLOCK_CTXPTR]

    mov qword ptr [r10 + CTX_RCX], rcx
    mov qword ptr [r10 + CTX_RDX], rdx
    mov qword ptr [r10 + CTX_RBX], rbx
    mov qword ptr [r10 + CTX_RSP], rsp
    mov qword ptr [r10 + CTX_RBP], rbp
    mov qword ptr [r10 + CTX_RSI], rsi
    mov qword ptr [r10 + CTX_RDI], rdi
    mov qword ptr [r10 + CTX_R8], r8
    mov qword ptr [r10 + CTX_R9], r9
    mov qword ptr [r10 + CTX_R10], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [r10 + CTX_R11], rax
    mov qword ptr [r10 + CTX_R12], r12
    mov qword ptr [r10 + CTX_R13], r13
    mov qword ptr [r10 + CTX_R14], r14
    mov qword ptr [r10 + CTX_R15], r15

    pushfq
    pop rax
    mov qword ptr [r10 + CTX_RFLAGS], rax
    mov rax, qword ptr [r11 + BLOCK_SAVED_RAX]
    mov qword ptr [r10 + CTX_RAX], rax
    stmxcsr dword ptr [r10 + CTX_MXCSR]
    movdqu xmmword ptr [r10 + CTX_XMM0], xmm0
    movdqu xmmword ptr [r10 + CTX_XMM1], xmm1
    movdqu xmmword ptr [r10 + CTX_XMM2], xmm2
    movdqu xmmword ptr [r10 + CTX_XMM3], xmm3
    movdqu xmmword ptr [r10 + CTX_XMM4], xmm4
    movdqu xmmword ptr [r10 + CTX_XMM5], xmm5
    movdqu xmmword ptr [r10 + CTX_XMM6], xmm6
    movdqu xmmword ptr [r10 + CTX_XMM7], xmm7
    movdqu xmmword ptr [r10 + CTX_XMM8], xmm8
    movdqu xmmword ptr [r10 + CTX_XMM9], xmm9
    movdqu xmmword ptr [r10 + CTX_XMM10], xmm10
    movdqu xmmword ptr [r10 + CTX_XMM11], xmm11
    movdqu xmmword ptr [r10 + CTX_XMM12], xmm12
    movdqu xmmword ptr [r10 + CTX_XMM13], xmm13
    movdqu xmmword ptr [r10 + CTX_XMM14], xmm14
    movdqu xmmword ptr [r10 + CTX_XMM15], xmm15

    mov rax, qword ptr [r11 + BLOCK_SAVED_STACK0]
    mov qword ptr [rsp], rax
    mov rax, qword ptr [r11 + BLOCK_SAVED_STACK1]
    mov qword ptr [rsp + 8], rax
    mov rax, qword ptr [r11 + BLOCK_SAVED_STACK2]
    mov qword ptr [rsp + 16], rax

    mov rsp, qword ptr [r11 + BLOCK_HOST_RSP]

    ldmxcsr dword ptr [rsp + LOCAL_MXCSR]
    movdqu xmm0, xmmword ptr [rsp + LOCAL_XMM0]
    movdqu xmm1, xmmword ptr [rsp + LOCAL_XMM1]
    movdqu xmm2, xmmword ptr [rsp + LOCAL_XMM2]
    movdqu xmm3, xmmword ptr [rsp + LOCAL_XMM3]
    movdqu xmm4, xmmword ptr [rsp + LOCAL_XMM4]
    movdqu xmm5, xmmword ptr [rsp + LOCAL_XMM5]
    movdqu xmm6, xmmword ptr [rsp + LOCAL_XMM6]
    movdqu xmm7, xmmword ptr [rsp + LOCAL_XMM7]
    movdqu xmm8, xmmword ptr [rsp + LOCAL_XMM8]
    movdqu xmm9, xmmword ptr [rsp + LOCAL_XMM9]
    movdqu xmm10, xmmword ptr [rsp + LOCAL_XMM10]
    movdqu xmm11, xmmword ptr [rsp + LOCAL_XMM11]
    movdqu xmm12, xmmword ptr [rsp + LOCAL_XMM12]
    movdqu xmm13, xmmword ptr [rsp + LOCAL_XMM13]
    movdqu xmm14, xmmword ptr [rsp + LOCAL_XMM14]
    movdqu xmm15, xmmword ptr [rsp + LOCAL_XMM15]

    add rsp, LOCAL_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    xor eax, eax
    ret
cpueaxh_host_call_asm ENDP

END
