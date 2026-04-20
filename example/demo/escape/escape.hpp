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
    // RDRAND encoding: [REX] 0F C7 /6  (modrm.mod==3, modrm.reg==6, modrm.rm==target)
    // Operand size: REX.W => 64, 0x66 => 16, otherwise 32.
    // The callback gets raw instruction bytes; we have to re-decode the
    // prefix block ourselves because cpueaxh's escape framework just hands
    // back the byte stream and expects the host to honor the ModRM target.
    bool rex_w = false;
    bool rex_b = false;
    bool operand_size_override = false;
    int offset = 0;
    while (true) {
        const uint8_t prefix = instruction[offset];
        if (prefix == 0x66) { operand_size_override = true; ++offset; continue; }
        if (prefix == 0x67) { ++offset; continue; }
        if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3) { ++offset; continue; }
        if (prefix == 0x26 || prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
            prefix == 0x64 || prefix == 0x65) { ++offset; continue; }
        if (prefix >= 0x40 && prefix <= 0x4F) {
            rex_w = (prefix & 0x08) != 0;
            rex_b = (prefix & 0x01) != 0;
            ++offset;
            continue;
        }
        break;
    }
    // Skip the 0F C7 escape; ModRM follows immediately.
    const uint8_t modrm = instruction[offset + 2];
    const int target_reg = (modrm & 0x07) | (rex_b ? 0x08 : 0x00);

    unsigned char ok = 0;
    if (rex_w) {
        unsigned __int64 value = 0;
        ok = _rdrand64_step(&value);
        context->regs[target_reg] = ok ? value : 0ull;
    } else if (operand_size_override) {
        unsigned short value = 0;
        ok = _rdrand16_step(&value);
        // Writes to 16-bit subregister preserve the upper bits per AMD64
        // ABI; for our purposes overwriting the low 16 bits suffices.
        context->regs[target_reg] = (context->regs[target_reg] & ~0xffffull) | (ok ? value : 0u);
    } else {
        unsigned int value = 0;
        ok = _rdrand32_step(&value);
        // 32-bit dest in long mode zero-extends to 64.
        context->regs[target_reg] = ok ? (uint64_t)value : 0ull;
    }
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