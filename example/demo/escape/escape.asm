OPTION CASEMAP:NONE

.code

cpueaxh_example_execute_syscall PROC
    syscall
    jmp qword ptr [rsp]
cpueaxh_example_execute_syscall ENDP

cpueaxh_example_execute_cpuid PROC
    cpuid
    jmp qword ptr [rsp]
cpueaxh_example_execute_cpuid ENDP

cpueaxh_example_execute_xgetbv PROC
    xgetbv
    jmp qword ptr [rsp]
cpueaxh_example_execute_xgetbv ENDP

END
