// asm escape examples
extern "C" void cpueaxh_example_execute_syscall();
extern "C" void cpueaxh_example_execute_cpuid();
extern "C" void cpueaxh_example_execute_xgetbv();

cpueaxh_err syscall_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    return cpueaxh_host_call(context, cpueaxh_example_execute_syscall);
}

cpueaxh_err cpuid_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    return cpueaxh_host_call(context, cpueaxh_example_execute_cpuid);
}

cpueaxh_err xgetbv_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    return cpueaxh_host_call(context, cpueaxh_example_execute_xgetbv);
}

// function escape examples
cpueaxh_err rdtsc_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    const unsigned __int64 tsc = __rdtsc();
    context->regs[CPUEAXH_X86_REG_RAX] = static_cast<uint32_t>(tsc);
    context->regs[CPUEAXH_X86_REG_RDX] = static_cast<uint32_t>(tsc >> 32);
    return CPUEAXH_ERR_OK;
}

cpueaxh_err rdtscp_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    unsigned int aux = 0;
    const unsigned __int64 tsc = __rdtscp(&aux);
    context->regs[CPUEAXH_X86_REG_RAX] = static_cast<uint32_t>(tsc);
    context->regs[CPUEAXH_X86_REG_RDX] = static_cast<uint32_t>(tsc >> 32);
    context->regs[CPUEAXH_X86_REG_RCX] = aux;
    return CPUEAXH_ERR_OK;
}

cpueaxh_err rdrand_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    unsigned __int64 value = 0;
    const unsigned char ok = _rdrand64_step(&value);
    context->regs[CPUEAXH_X86_REG_RAX] = value;
    if (ok != 0) context->rflags |= 0x1ull;
    else context->rflags &= ~0x1ull;
    return CPUEAXH_ERR_OK;
}

// custom escape examples
cpueaxh_err hlt_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_GP;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}

cpueaxh_err sysenter_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_UD;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}

cpueaxh_err int_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_UD;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}

cpueaxh_err int3_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_UD;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}
cpueaxh_err in_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_UD;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}

cpueaxh_err out_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
    context->code_exception = CPUEAXH_EXCEPTION_UD;
    context->error_code_exception = 0;
    return CPUEAXH_ERR_OK;
}