#include "cpueaxh.hpp"
#include "cpueaxh_internal.hpp"

#define CPUEAXH_MAX_HOOKS 64

#if defined(CPUEAXH_PLATFORM_KERNEL) || defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_WDM_INCLUDED_) || defined(_NTIFS_)
extern "C" int _fltused = 0;
#endif

extern "C" cpueaxh_err cpueaxh_host_call_asm(cpueaxh_x86_context* context, cpueaxh_cb_host_bridge_t bridge, void* bridge_block);

struct CPUEAXH_HOST_BRIDGE_BLOCK {
    uint64_t host_rsp;
    uint64_t context_ptr;
    uint64_t guest_rsp;
    uint64_t saved_stack0;
    uint64_t saved_stack1;
    uint64_t saved_stack2;
    uint64_t saved_rax;
};

struct CPUEAXH_HOOK_ENTRY {
    bool used;
    cpueaxh_hook handle;
    uint32_t type;
    cpueaxh_cb_hookcode_t code_callback;
    void* user_data;
    uint64_t begin;
    uint64_t end;
};

struct CPUEAXH_ESCAPE_ENTRY {
    cpueaxh_hook handle;
    cpueaxh_escape_insn_id instruction_id;
    cpueaxh_cb_escape_t callback;
    void* user_data;
    uint64_t begin;
    uint64_t end;
};

struct cpueaxh_engine {
    MEMORY_MANAGER memory_manager;
    CPU_CONTEXT context;
    CPUEAXH_HOOK_ENTRY hooks[CPUEAXH_MAX_HOOKS];
    CPUEAXH_ESCAPE_ENTRY* escapes;
    size_t escape_count;
    size_t escape_capacity;
    cpueaxh_hook next_hook;
    uint32_t memory_mode;
    int stop_requested;
    cpueaxh_err last_error;
};

static void cpueaxh_copy_segment_out(cpueaxh_x86_segment* out_segment, const SegmentRegister* in_segment) {
    out_segment->selector = in_segment->selector;
    out_segment->reserved0 = 0;
    out_segment->descriptor.base = in_segment->descriptor.base;
    out_segment->descriptor.limit = in_segment->descriptor.limit;
    out_segment->descriptor.type = in_segment->descriptor.type;
    out_segment->descriptor.dpl = in_segment->descriptor.dpl;
    out_segment->descriptor.present = in_segment->descriptor.present ? 1u : 0u;
    out_segment->descriptor.granularity = in_segment->descriptor.granularity ? 1u : 0u;
    out_segment->descriptor.db = in_segment->descriptor.db ? 1u : 0u;
    out_segment->descriptor.long_mode = in_segment->descriptor.long_mode ? 1u : 0u;
}

static void cpueaxh_copy_segment_in(SegmentRegister* out_segment, const cpueaxh_x86_segment* in_segment) {
    out_segment->selector = in_segment->selector;
    out_segment->descriptor.base = in_segment->descriptor.base;
    out_segment->descriptor.limit = in_segment->descriptor.limit;
    out_segment->descriptor.type = in_segment->descriptor.type;
    out_segment->descriptor.dpl = in_segment->descriptor.dpl;
    out_segment->descriptor.present = in_segment->descriptor.present != 0;
    out_segment->descriptor.granularity = in_segment->descriptor.granularity != 0;
    out_segment->descriptor.db = in_segment->descriptor.db != 0;
    out_segment->descriptor.long_mode = in_segment->descriptor.long_mode != 0;
}

static void cpueaxh_context_out(cpueaxh_x86_context* out_context, const CPU_CONTEXT* in_context) {
    CPUEAXH_MEMSET(out_context, 0, sizeof(*out_context));
    CPUEAXH_MEMCPY(out_context->regs, in_context->regs, sizeof(out_context->regs));
    CPUEAXH_MEMCPY(out_context->xmm, in_context->xmm, sizeof(out_context->xmm));
    CPUEAXH_MEMCPY(out_context->ymm_upper, in_context->ymm_upper, sizeof(out_context->ymm_upper));
    CPUEAXH_MEMCPY(out_context->mm, in_context->mm, sizeof(out_context->mm));
    out_context->rip = in_context->rip;
    out_context->rflags = in_context->rflags;
    out_context->mxcsr = in_context->mxcsr;
    cpueaxh_copy_segment_out(&out_context->es, &in_context->es);
    cpueaxh_copy_segment_out(&out_context->cs, &in_context->cs);
    cpueaxh_copy_segment_out(&out_context->ss, &in_context->ss);
    cpueaxh_copy_segment_out(&out_context->ds, &in_context->ds);
    cpueaxh_copy_segment_out(&out_context->fs, &in_context->fs);
    cpueaxh_copy_segment_out(&out_context->gs, &in_context->gs);
    out_context->gdtr_base = in_context->gdtr_base;
    out_context->gdtr_limit = in_context->gdtr_limit;
    out_context->ldtr_base = in_context->ldtr_base;
    out_context->ldtr_limit = in_context->ldtr_limit;
    out_context->cpl = in_context->cpl;
    out_context->code_exception = in_context->exception.code;
    out_context->error_code_exception = in_context->exception.error_code;
    CPUEAXH_MEMCPY(out_context->control_regs, in_context->control_regs, sizeof(out_context->control_regs));
}

static void cpueaxh_context_in(CPU_CONTEXT* out_context, const cpueaxh_x86_context* in_context) {
    CPUEAXH_MEMCPY(out_context->regs, in_context->regs, sizeof(out_context->regs));
    CPUEAXH_MEMCPY(out_context->xmm, in_context->xmm, sizeof(out_context->xmm));
    CPUEAXH_MEMCPY(out_context->ymm_upper, in_context->ymm_upper, sizeof(out_context->ymm_upper));
    CPUEAXH_MEMCPY(out_context->mm, in_context->mm, sizeof(out_context->mm));
    out_context->rip = in_context->rip;
    out_context->rflags = in_context->rflags;
    out_context->mxcsr = in_context->mxcsr;
    cpueaxh_copy_segment_in(&out_context->es, &in_context->es);
    cpueaxh_copy_segment_in(&out_context->cs, &in_context->cs);
    cpueaxh_copy_segment_in(&out_context->ss, &in_context->ss);
    cpueaxh_copy_segment_in(&out_context->ds, &in_context->ds);
    cpueaxh_copy_segment_in(&out_context->fs, &in_context->fs);
    cpueaxh_copy_segment_in(&out_context->gs, &in_context->gs);
    out_context->gdtr_base = in_context->gdtr_base;
    out_context->gdtr_limit = in_context->gdtr_limit;
    out_context->ldtr_base = in_context->ldtr_base;
    out_context->ldtr_limit = in_context->ldtr_limit;
    out_context->cpl = in_context->cpl;
    out_context->exception.code = in_context->code_exception;
    out_context->exception.error_code = in_context->error_code_exception;
    CPUEAXH_MEMCPY(out_context->control_regs, in_context->control_regs, sizeof(out_context->control_regs));
}

static bool cpueaxh_range_contains(uint64_t begin, uint64_t end, uint64_t address) {
    if (begin == 0 && end == 0) {
        return true;
    }
    if (end == 0) {
        return address >= begin;
    }
    return address >= begin && address <= end;
}

static bool cpueaxh_is_supported_hook_type(uint32_t type) {
    return type == CPUEAXH_HOOK_CODE_PRE || type == CPUEAXH_HOOK_CODE_POST;
}

static cpueaxh_escape_insn_id cpueaxh_classify_escape_instruction(const uint8_t* bytes, int fetched, uint32_t* instruction_size) {
    if (!bytes || !instruction_size || fetched <= 0) {
        return CPUEAXH_ESCAPE_INSN_NONE;
    }

    *instruction_size = 0;

    int prefix_len = 0;
    uint16_t opc = peek_opcode(bytes, fetched, &prefix_len);
    if (opc == 0xFFFF) {
        return CPUEAXH_ESCAPE_INSN_NONE;
    }

    if (opc == 0x00CC) {
        *instruction_size = (uint32_t)(prefix_len + 1);
        return CPUEAXH_ESCAPE_INSN_INT3;
    }
    if (opc == 0x00CD && fetched >= (prefix_len + 2)) {
        *instruction_size = (uint32_t)(prefix_len + 2);
        return CPUEAXH_ESCAPE_INSN_INT;
    }
    if (opc == 0x00F4) {
        *instruction_size = (uint32_t)(prefix_len + 1);
        return CPUEAXH_ESCAPE_INSN_HLT;
    }

    if (opc == 0x00E4 || opc == 0x00E5) {
        if (fetched >= (prefix_len + 2)) {
            *instruction_size = (uint32_t)(prefix_len + 2);
            return CPUEAXH_ESCAPE_INSN_IN;
        }
        return CPUEAXH_ESCAPE_INSN_NONE;
    }
    if (opc == 0x00EC || opc == 0x00ED) {
        *instruction_size = (uint32_t)(prefix_len + 1);
        return CPUEAXH_ESCAPE_INSN_IN;
    }
    if (opc == 0x00E6 || opc == 0x00E7) {
        if (fetched >= (prefix_len + 2)) {
            *instruction_size = (uint32_t)(prefix_len + 2);
            return CPUEAXH_ESCAPE_INSN_OUT;
        }
        return CPUEAXH_ESCAPE_INSN_NONE;
    }
    if (opc == 0x00EE || opc == 0x00EF) {
        *instruction_size = (uint32_t)(prefix_len + 1);
        return CPUEAXH_ESCAPE_INSN_OUT;
    }

    if (opc == 0x0F05) {
        *instruction_size = (uint32_t)(prefix_len + 2);
        return CPUEAXH_ESCAPE_INSN_SYSCALL;
    }
    if (opc == 0x0F34) {
        *instruction_size = (uint32_t)(prefix_len + 2);
        return CPUEAXH_ESCAPE_INSN_SYSENTER;
    }
    if (opc == 0x0FA2) {
        *instruction_size = (uint32_t)(prefix_len + 2);
        return CPUEAXH_ESCAPE_INSN_CPUID;
    }
    if (opc == 0x0F31) {
        *instruction_size = (uint32_t)(prefix_len + 2);
        return CPUEAXH_ESCAPE_INSN_RDTSC;
    }
    if (opc == 0x0F01 && (prefix_len + 2) < fetched && bytes[prefix_len + 2] == 0xD0) {
        *instruction_size = (uint32_t)(prefix_len + 3);
        return CPUEAXH_ESCAPE_INSN_XGETBV;
    }
    if (opc == 0x0F01 && (prefix_len + 2) < fetched && bytes[prefix_len + 2] == 0xF9) {
        *instruction_size = (uint32_t)(prefix_len + 3);
        return CPUEAXH_ESCAPE_INSN_RDTSCP;
    }
    if (opc == 0x0FC7 && is_rdrand_instruction(bytes, (size_t)fetched)) {
        *instruction_size = (uint32_t)(prefix_len + 3);
        return CPUEAXH_ESCAPE_INSN_RDRAND;
    }
    if (opc == 0x0F20 && fetched >= (prefix_len + 3)) {
        *instruction_size = (uint32_t)(prefix_len + 3);
        return CPUEAXH_ESCAPE_INSN_READCRX;
    }
    if (opc == 0x0F22 && fetched >= (prefix_len + 3)) {
        *instruction_size = (uint32_t)(prefix_len + 3);
        return CPUEAXH_ESCAPE_INSN_WRITECRX;
    }
    return CPUEAXH_ESCAPE_INSN_NONE;
}

static cpueaxh_err cpueaxh_ensure_escape_capacity(cpueaxh_engine* engine, size_t required_count) {
    if (!engine) {
        return CPUEAXH_ERR_ARG;
    }
    if (required_count <= engine->escape_capacity) {
        return CPUEAXH_ERR_OK;
    }

    size_t new_capacity = engine->escape_capacity == 0 ? 8 : engine->escape_capacity;
    while (new_capacity < required_count) {
        new_capacity *= 2;
    }

    CPUEAXH_ESCAPE_ENTRY* new_entries = reinterpret_cast<CPUEAXH_ESCAPE_ENTRY*>(
        CPUEAXH_ALLOC_ZEROED(new_capacity * sizeof(CPUEAXH_ESCAPE_ENTRY)));
    if (!new_entries) {
        return CPUEAXH_ERR_NOMEM;
    }

    if (engine->escapes && engine->escape_count != 0) {
        CPUEAXH_MEMCPY(new_entries, engine->escapes, engine->escape_count * sizeof(CPUEAXH_ESCAPE_ENTRY));
        CPUEAXH_FREE(engine->escapes);
    }

    engine->escapes = new_entries;
    engine->escape_capacity = new_capacity;
    return CPUEAXH_ERR_OK;
}

static cpueaxh_err cpueaxh_validate_engine(cpueaxh_engine* engine) {
    return engine ? CPUEAXH_ERR_OK : CPUEAXH_ERR_ARG;
}

static cpueaxh_err cpueaxh_apply_memory_mode(cpueaxh_engine* engine, uint32_t memory_mode) {
    if (!engine) {
        return CPUEAXH_ERR_ARG;
    }

    if (memory_mode != CPUEAXH_MEMORY_MODE_GUEST && memory_mode != CPUEAXH_MEMORY_MODE_HOST) {
        return CPUEAXH_ERR_MODE;
    }

    engine->memory_mode = memory_mode;
    mm_set_host_passthrough(
        &engine->memory_manager,
        MM_PROT_READ | MM_PROT_WRITE | MM_PROT_EXEC,
        memory_mode == CPUEAXH_MEMORY_MODE_HOST);
    return CPUEAXH_ERR_OK;
}

static cpueaxh_err cpueaxh_translate_access_error(MM_ACCESS_STATUS status, uint32_t perm) {
    if (status == MM_ACCESS_PROT) {
        switch (perm) {
        case MM_PROT_WRITE:
            return CPUEAXH_ERR_WRITE_PROT;
        case MM_PROT_EXEC:
            return CPUEAXH_ERR_FETCH_PROT;
        case MM_PROT_READ:
        default:
            return CPUEAXH_ERR_READ_PROT;
        }
    }

    switch (perm) {
    case MM_PROT_WRITE:
        return CPUEAXH_ERR_WRITE_UNMAPPED;
    case MM_PROT_EXEC:
        return CPUEAXH_ERR_FETCH_UNMAPPED;
    case MM_PROT_READ:
    default:
        return CPUEAXH_ERR_READ_UNMAPPED;
    }
}

static cpueaxh_err cpueaxh_mem_write_raw(cpueaxh_engine* engine, uint64_t address, const void* bytes, size_t size) {
    const uint8_t* source = reinterpret_cast<const uint8_t*>(bytes);
    for (size_t index = 0; index < size; index++) {
        MM_ACCESS_STATUS status = mm_write_byte_checked(&engine->memory_manager, address + index, source[index]);
        if (status != MM_ACCESS_OK) {
            return cpueaxh_translate_access_error(status, MM_PROT_WRITE);
        }
    }
    return CPUEAXH_ERR_OK;
}

static cpueaxh_err cpueaxh_mem_read_raw(cpueaxh_engine* engine, uint64_t address, void* bytes, size_t size) {
    uint8_t* target = reinterpret_cast<uint8_t*>(bytes);
    for (size_t index = 0; index < size; index++) {
        MM_ACCESS_STATUS status = mm_read_byte_checked(&engine->memory_manager, address + index, &target[index], MM_PROT_READ);
        if (status != MM_ACCESS_OK) {
            return cpueaxh_translate_access_error(status, MM_PROT_READ);
        }
    }
    return CPUEAXH_ERR_OK;
}

static cpueaxh_err cpueaxh_translate_patch_error(MM_PATCH_STATUS status) {
    switch (status) {
    case MM_PATCH_OK:
        return CPUEAXH_ERR_OK;
    case MM_PATCH_ARG:
        return CPUEAXH_ERR_ARG;
    case MM_PATCH_NOMEM:
        return CPUEAXH_ERR_NOMEM;
    case MM_PATCH_CONFLICT:
    case MM_PATCH_NOT_FOUND:
    default:
        return CPUEAXH_ERR_PATCH;
    }
}

static cpueaxh_err cpueaxh_reg_read_raw(const CPU_CONTEXT* context, int regid, void* value) {
    uint64_t* output = reinterpret_cast<uint64_t*>(value);
    if (!output) {
        return CPUEAXH_ERR_ARG;
    }

    switch (regid) {
    case CPUEAXH_X86_REG_RAX:
    case CPUEAXH_X86_REG_RCX:
    case CPUEAXH_X86_REG_RDX:
    case CPUEAXH_X86_REG_RBX:
    case CPUEAXH_X86_REG_RSP:
    case CPUEAXH_X86_REG_RBP:
    case CPUEAXH_X86_REG_RSI:
    case CPUEAXH_X86_REG_RDI:
    case CPUEAXH_X86_REG_R8:
    case CPUEAXH_X86_REG_R9:
    case CPUEAXH_X86_REG_R10:
    case CPUEAXH_X86_REG_R11:
    case CPUEAXH_X86_REG_R12:
    case CPUEAXH_X86_REG_R13:
    case CPUEAXH_X86_REG_R14:
    case CPUEAXH_X86_REG_R15:
        *output = context->regs[regid];
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_RIP:
        *output = context->rip;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_EFLAGS:
        *output = context->rflags;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_GS_SELECTOR:
        *output = context->gs.selector;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_GS_BASE:
        *output = context->gs.descriptor.base;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CPL:
        *output = context->cpl;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR0:
        *output = context->control_regs[REG_CR0];
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR2:
        *output = context->control_regs[REG_CR2];
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR3:
        *output = context->control_regs[REG_CR3];
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR4:
        *output = context->control_regs[REG_CR4];
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR8:
        *output = context->control_regs[REG_CR8];
        return CPUEAXH_ERR_OK;
    default:
        return CPUEAXH_ERR_ARG;
    }
}

static cpueaxh_err cpueaxh_reg_write_raw(CPU_CONTEXT* context, int regid, const void* value) {
    const uint64_t* input = reinterpret_cast<const uint64_t*>(value);
    if (!input) {
        return CPUEAXH_ERR_ARG;
    }

    switch (regid) {
    case CPUEAXH_X86_REG_RAX:
    case CPUEAXH_X86_REG_RCX:
    case CPUEAXH_X86_REG_RDX:
    case CPUEAXH_X86_REG_RBX:
    case CPUEAXH_X86_REG_RSP:
    case CPUEAXH_X86_REG_RBP:
    case CPUEAXH_X86_REG_RSI:
    case CPUEAXH_X86_REG_RDI:
    case CPUEAXH_X86_REG_R8:
    case CPUEAXH_X86_REG_R9:
    case CPUEAXH_X86_REG_R10:
    case CPUEAXH_X86_REG_R11:
    case CPUEAXH_X86_REG_R12:
    case CPUEAXH_X86_REG_R13:
    case CPUEAXH_X86_REG_R14:
    case CPUEAXH_X86_REG_R15:
        context->regs[regid] = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_RIP:
        context->rip = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_EFLAGS:
        context->rflags = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_GS_SELECTOR:
        context->gs.selector = (uint16_t)(*input & 0xFFFFu);
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_GS_BASE:
        context->gs.descriptor.base = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CPL:
        context->cpl = (uint8_t)(*input & 0x3u);
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR0:
        context->control_regs[REG_CR0] = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR2:
        context->control_regs[REG_CR2] = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR3:
        context->control_regs[REG_CR3] = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR4:
        context->control_regs[REG_CR4] = *input;
        return CPUEAXH_ERR_OK;
    case CPUEAXH_X86_REG_CR8:
        context->control_regs[REG_CR8] = *input;
        return CPUEAXH_ERR_OK;
    default:
        return CPUEAXH_ERR_ARG;
    }
}

static void cpueaxh_dispatch_code_hooks(cpueaxh_engine* engine, uint32_t type, uint64_t address) {
    for (int index = 0; index < CPUEAXH_MAX_HOOKS; index++) {
        CPUEAXH_HOOK_ENTRY* hook = &engine->hooks[index];
        if (!hook->used || hook->type != type || !hook->code_callback) {
            continue;
        }

        if (!cpueaxh_range_contains(hook->begin, hook->end, address)) {
            continue;
        }

        hook->code_callback(engine, address, hook->user_data);
    }
}

static bool cpueaxh_try_dispatch_escape(cpueaxh_engine* engine, uint64_t address, uint32_t* escaped_size, cpueaxh_err* callback_error, CPUEAXH_HOST_BRIDGE_BLOCK* bridge_block) {
    if (!engine || !escaped_size || !callback_error) {
        return false;
    }

    uint8_t bytes[MAX_INST_FETCH] = {};
    int fetched = fetch_instruction_bytes(&engine->context, address, bytes);
    if (fetched <= 0 || cpu_has_exception(&engine->context)) {
        return false;
    }

    uint32_t instruction_size = 0;
    cpueaxh_escape_insn_id instruction_id = cpueaxh_classify_escape_instruction(bytes, fetched, &instruction_size);
    if (instruction_id == CPUEAXH_ESCAPE_INSN_NONE || instruction_size == 0) {
        return false;
    }

    for (size_t index = 0; index < engine->escape_count; index++) {
        CPUEAXH_ESCAPE_ENTRY* escape = &engine->escapes[index];
        if (!escape->callback || escape->instruction_id != instruction_id) {
            continue;
        }
        if (!cpueaxh_range_contains(escape->begin, escape->end, address)) {
            continue;
        }

        cpueaxh_x86_context context = {};
        uint64_t rip_before = engine->context.rip;
        cpueaxh_context_out(&context, &engine->context);
        context.internal_bridge_block = reinterpret_cast<uint64_t>(bridge_block);

        cpueaxh_err error = escape->callback(engine, &context, bytes, escape->user_data);
        if (error != CPUEAXH_ERR_OK) {
            *callback_error = error;
            return true;
        }

        cpueaxh_context_in(&engine->context, &context);
        if (engine->context.rip == rip_before) {
            engine->context.rip = rip_before + (uint64_t)instruction_size;
        }
        engine->context.last_inst_size = (int)instruction_size;
        *escaped_size = instruction_size;
        if (cpu_has_exception(&engine->context)) {
            *callback_error = CPUEAXH_ERR_EXCEPTION;
        }
        else {
            *callback_error = CPUEAXH_ERR_OK;
        }
        return true;
    }

    cpu_raise_exception(&engine->context, CPU_EXCEPTION_UD, 0);
    *callback_error = CPUEAXH_ERR_EXCEPTION;
    return true;
}

static cpueaxh_err cpueaxh_translate_step_error(cpueaxh_engine* engine, int status) {
    switch (status) {
    case CPU_STEP_OK:
    case CPU_STEP_HALT:
        return CPUEAXH_ERR_OK;
    case CPU_STEP_FETCH_ERR:
        return CPUEAXH_ERR_FETCH_UNMAPPED;
    case CPU_STEP_UD:
        return CPUEAXH_ERR_EXCEPTION;
    case CPU_STEP_EXCEPTION:
        if (engine->context.exception.code == CPU_EXCEPTION_PF) {
            const uint32_t error_code = engine->context.exception.error_code;
            const bool protection_violation = (error_code & 0x1u) != 0;
            const bool write_access = (error_code & 0x2u) != 0;
            const bool exec_access = (error_code & 0x10u) != 0;

            if (exec_access) {
                return protection_violation ? CPUEAXH_ERR_FETCH_PROT : CPUEAXH_ERR_FETCH_UNMAPPED;
            }
            if (write_access) {
                return protection_violation ? CPUEAXH_ERR_WRITE_PROT : CPUEAXH_ERR_WRITE_UNMAPPED;
            }
            return protection_violation ? CPUEAXH_ERR_READ_PROT : CPUEAXH_ERR_READ_UNMAPPED;
        }
        return CPUEAXH_ERR_EXCEPTION;
    default:
        return CPUEAXH_ERR_EXCEPTION;
    }
}

extern "C" cpueaxh_err cpueaxh_open(uint32_t arch, uint32_t mode, cpueaxh_engine** out_engine) {
    if (!out_engine) {
        return CPUEAXH_ERR_ARG;
    }
    if (arch != CPUEAXH_ARCH_X86) {
        *out_engine = NULL;
        return CPUEAXH_ERR_ARCH;
    }
    if (mode != CPUEAXH_MODE_64) {
        *out_engine = NULL;
        return CPUEAXH_ERR_MODE;
    }

    cpueaxh_engine* engine = (cpueaxh_engine*)CPUEAXH_ALLOC_ZEROED(sizeof(cpueaxh_engine));
    if (!engine) {
        *out_engine = NULL;
        return CPUEAXH_ERR_NOMEM;
    }

    mm_init(&engine->memory_manager);
    init_cpu_context(&engine->context, &engine->memory_manager);
    engine->next_hook = 1;
    engine->memory_mode = CPUEAXH_MEMORY_MODE_GUEST;
    cpueaxh_apply_memory_mode(engine, CPUEAXH_MEMORY_MODE_GUEST);
    engine->last_error = CPUEAXH_ERR_OK;
    *out_engine = engine;
    return CPUEAXH_ERR_OK;
}

extern "C" void cpueaxh_close(cpueaxh_engine* engine) {
    if (!engine) {
        return;
    }
    mm_destroy(&engine->memory_manager);
    CPUEAXH_FREE(engine->escapes);
    CPUEAXH_FREE(engine);
}

extern "C" cpueaxh_err cpueaxh_set_memory_mode(cpueaxh_engine* engine, uint32_t memory_mode) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    return cpueaxh_apply_memory_mode(engine, memory_mode);
}

extern "C" cpueaxh_err cpueaxh_mem_map(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || size == 0) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }

    if (!mm_is_page_aligned(address) || !mm_is_page_aligned((uint64_t)size) ||
        mm_range_overflows(address, (uint64_t)size) || !mm_is_valid_perms(perms)) {
        return CPUEAXH_ERR_ARG;
    }

    if (!mm_map_internal(&engine->memory_manager, address, (uint64_t)size, perms)) {
        return CPUEAXH_ERR_MAP;
    }
    return CPUEAXH_ERR_OK;
}

extern "C" cpueaxh_err cpueaxh_mem_map_ptr(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms, void* host_ptr) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || size == 0 || !host_ptr) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }

    if (!mm_is_page_aligned(address) || !mm_is_page_aligned((uint64_t)size) ||
        mm_range_overflows(address, (uint64_t)size) || !mm_is_valid_perms(perms)) {
        return CPUEAXH_ERR_ARG;
    }

    if (!mm_map_host(&engine->memory_manager, address, (uint64_t)size, perms, host_ptr)) {
        return CPUEAXH_ERR_MAP;
    }
    return CPUEAXH_ERR_OK;
}

extern "C" cpueaxh_err cpueaxh_mem_unmap(cpueaxh_engine* engine, uint64_t address, size_t size) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    if (size == 0) {
        return CPUEAXH_ERR_OK;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned((uint64_t)size) || mm_range_overflows(address, (uint64_t)size)) {
        return CPUEAXH_ERR_ARG;
    }
    if (!mm_check_range_mapped(&engine->memory_manager, address, (uint64_t)size)) {
        return CPUEAXH_ERR_MAP;
    }

    return mm_unmap(&engine->memory_manager, address, (uint64_t)size) ? CPUEAXH_ERR_OK : CPUEAXH_ERR_MAP;
}

extern "C" cpueaxh_err cpueaxh_mem_protect(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    if (size == 0) {
        return CPUEAXH_ERR_OK;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned((uint64_t)size) ||
        mm_range_overflows(address, (uint64_t)size) || !mm_is_valid_perms(perms)) {
        return CPUEAXH_ERR_ARG;
    }
    if (!mm_check_range_mapped(&engine->memory_manager, address, (uint64_t)size)) {
        return CPUEAXH_ERR_MAP;
    }

    return mm_protect(&engine->memory_manager, address, (uint64_t)size, perms) ? CPUEAXH_ERR_OK : CPUEAXH_ERR_MAP;
}

extern "C" cpueaxh_err cpueaxh_mem_set_cpu_attrs(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t attrs) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    if (size == 0) {
        return CPUEAXH_ERR_OK;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned((uint64_t)size) ||
        mm_range_overflows(address, (uint64_t)size) || !mm_is_valid_cpu_attrs(attrs)) {
        return CPUEAXH_ERR_ARG;
    }
    if (!mm_check_range_mapped(&engine->memory_manager, address, (uint64_t)size)) {
        return CPUEAXH_ERR_MAP;
    }

    return mm_set_cpu_attrs(&engine->memory_manager, address, (uint64_t)size, attrs) ? CPUEAXH_ERR_OK : CPUEAXH_ERR_MAP;
}

extern "C" cpueaxh_err cpueaxh_mem_regions(const cpueaxh_engine* engine, cpueaxh_mem_region** regions, uint32_t* count) {
    if (!regions || !count) {
        return CPUEAXH_ERR_ARG;
    }

    *regions = NULL;
    *count = 0;

    if (!engine) {
        return CPUEAXH_ERR_ARG;
    }

    const size_t region_count = engine->memory_manager.region_count;
    if (region_count == 0) {
        return CPUEAXH_ERR_OK;
    }

    if (region_count > 0xFFFFFFFFu) {
        return CPUEAXH_ERR_NOMEM;
    }

    cpueaxh_mem_region* result = reinterpret_cast<cpueaxh_mem_region*>(
        CPUEAXH_ALLOC_ZEROED(region_count * sizeof(cpueaxh_mem_region)));
    if (!result) {
        return CPUEAXH_ERR_NOMEM;
    }

    for (size_t i = 0; i < region_count; i++) {
        const MEMORY_REGION* source = &engine->memory_manager.regions[i];
        result[i].begin = source->base;
        result[i].end = source->base + source->size - 1;
        result[i].perms = source->perms;
        result[i].cpu_attrs = source->cpu_attrs;
    }

    *regions = result;
    *count = (uint32_t)region_count;
    return CPUEAXH_ERR_OK;
}

extern "C" cpueaxh_err cpueaxh_mem_write(cpueaxh_engine* engine, uint64_t address, const void* bytes, size_t size) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || (!bytes && size != 0)) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }
    return cpueaxh_mem_write_raw(engine, address, bytes, size);
}

extern "C" cpueaxh_err cpueaxh_mem_read(cpueaxh_engine* engine, uint64_t address, void* bytes, size_t size) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || (!bytes && size != 0)) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }
    return cpueaxh_mem_read_raw(engine, address, bytes, size);
}

extern "C" cpueaxh_err cpueaxh_mem_patch_add(cpueaxh_engine* engine, cpueaxh_mem_patch_handle* out_patch, uint64_t address, const void* bytes, size_t size) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || !out_patch || (!bytes && size != 0)) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }
    if (engine->memory_mode != CPUEAXH_MEMORY_MODE_HOST) {
        return CPUEAXH_ERR_MODE;
    }

    return cpueaxh_translate_patch_error(mm_add_patch(&engine->memory_manager, out_patch, address, bytes, (uint64_t)size));
}

extern "C" cpueaxh_err cpueaxh_mem_patch_del(cpueaxh_engine* engine, cpueaxh_mem_patch_handle patch) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    return cpueaxh_translate_patch_error(mm_del_patch(&engine->memory_manager, patch));
}

extern "C" cpueaxh_err cpueaxh_reg_write(cpueaxh_engine* engine, int regid, const void* value) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }
    return cpueaxh_reg_write_raw(&engine->context, regid, value);
}

extern "C" cpueaxh_err cpueaxh_reg_read(cpueaxh_engine* engine, int regid, void* value) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }
    return cpueaxh_reg_read_raw(&engine->context, regid, value);
}

extern "C" cpueaxh_err cpueaxh_emu_start(cpueaxh_engine* engine, uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
    (void)timeout;
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    if (begin != 0) {
        engine->context.rip = begin;
    }

    engine->stop_requested = 0;
    cpu_clear_exception(&engine->context);
    CPUEAXH_HOST_BRIDGE_BLOCK host_bridge_block = {};

    size_t executed = 0;
    for (;;) {
        if (count != 0 && executed >= count) {
            break;
        }
        if (until != 0 && engine->context.rip == until) {
            break;
        }
        if (engine->stop_requested) {
            break;
        }

        uint64_t address = engine->context.rip;
        cpueaxh_dispatch_code_hooks(engine, CPUEAXH_HOOK_CODE_PRE, address);
        if (engine->stop_requested) {
            break;
        }

        uint32_t escaped_size = 0;
        if (cpueaxh_try_dispatch_escape(engine, address, &escaped_size, &error, &host_bridge_block)) {
            if (error != CPUEAXH_ERR_OK) {
                engine->last_error = error;
                return error;
            }

            executed++;
            cpueaxh_dispatch_code_hooks(engine, CPUEAXH_HOOK_CODE_POST, address);
            continue;
        }

        int status = cpu_step(&engine->context);
        if (status == CPU_STEP_OK) {
            executed++;
            cpueaxh_dispatch_code_hooks(engine, CPUEAXH_HOOK_CODE_POST, address);
            continue;
        }
        if (status == CPU_STEP_HALT) {
            cpueaxh_dispatch_code_hooks(engine, CPUEAXH_HOOK_CODE_POST, address);
            return CPUEAXH_ERR_OK;
        }

        error = cpueaxh_translate_step_error(engine, status);
        engine->last_error = error;
        return error;
    }

    engine->last_error = CPUEAXH_ERR_OK;
    return CPUEAXH_ERR_OK;
}

extern "C" cpueaxh_err cpueaxh_emu_start_function(cpueaxh_engine* engine, uint64_t begin, uint64_t timeout, size_t count) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    uint64_t stack_address = 0;
    error = cpueaxh_reg_read_raw(&engine->context, CPUEAXH_X86_REG_RSP, &stack_address);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    uint64_t original_return = 0;
    error = cpueaxh_mem_read_raw(engine, stack_address, &original_return, sizeof(original_return));
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    const uint64_t magic_return = CPUEAXH_EMU_RETURN_MAGIC;
    error = cpueaxh_mem_write_raw(engine, stack_address, &magic_return, sizeof(magic_return));
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    cpueaxh_err run_error = cpueaxh_emu_start(engine, begin, magic_return, timeout, count);

    cpueaxh_err restore_error = cpueaxh_mem_write_raw(engine, stack_address, &original_return, sizeof(original_return));
    if (run_error != CPUEAXH_ERR_OK) {
        return run_error;
    }
    if (restore_error != CPUEAXH_ERR_OK) {
        return restore_error;
    }

    return CPUEAXH_ERR_OK;
}

extern "C" void cpueaxh_emu_stop(cpueaxh_engine* engine) {
    if (!engine) {
        return;
    }
    engine->stop_requested = 1;
}

extern "C" cpueaxh_err cpueaxh_host_call(cpueaxh_x86_context* context, cpueaxh_cb_host_bridge_t bridge) {
    if (!context || !bridge || context->internal_bridge_block == 0) {
        return CPUEAXH_ERR_ARG;
    }

    return cpueaxh_host_call_asm(context, bridge, reinterpret_cast<void*>(context->internal_bridge_block));
}

extern "C" cpueaxh_err cpueaxh_hook_add(cpueaxh_engine* engine, cpueaxh_hook* out_hook, uint32_t type, void* callback, void* user_data, uint64_t begin, uint64_t end) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || !out_hook || !callback) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }
    if (!cpueaxh_is_supported_hook_type(type)) {
        return CPUEAXH_ERR_HOOK;
    }

    for (int index = 0; index < CPUEAXH_MAX_HOOKS; index++) {
        if (engine->hooks[index].used) {
            continue;
        }

        engine->hooks[index].used = true;
        engine->hooks[index].handle = engine->next_hook++;
        engine->hooks[index].type = type;
        engine->hooks[index].code_callback = (cpueaxh_cb_hookcode_t)callback;
        engine->hooks[index].user_data = user_data;
        engine->hooks[index].begin = begin;
        engine->hooks[index].end = end;
        *out_hook = engine->hooks[index].handle;
        return CPUEAXH_ERR_OK;
    }

    return CPUEAXH_ERR_HOOK;
}

extern "C" cpueaxh_err cpueaxh_hook_add_address(cpueaxh_engine* engine, cpueaxh_hook* out_hook, uint32_t type, void* callback, void* user_data, uint64_t address) {
    return cpueaxh_hook_add(engine, out_hook, type, callback, user_data, address, address);
}

extern "C" cpueaxh_err cpueaxh_hook_del(cpueaxh_engine* engine, cpueaxh_hook hook) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    for (int index = 0; index < CPUEAXH_MAX_HOOKS; index++) {
        if (engine->hooks[index].used && engine->hooks[index].handle == hook) {
            CPUEAXH_MEMSET(&engine->hooks[index], 0, sizeof(engine->hooks[index]));
            return CPUEAXH_ERR_OK;
        }
    }

    for (size_t index = 0; index < engine->escape_count; index++) {
        if (engine->escapes[index].handle == hook) {
            if (index + 1 < engine->escape_count) {
                CPUEAXH_MEMMOVE(
                    &engine->escapes[index],
                    &engine->escapes[index + 1],
                    (engine->escape_count - index - 1) * sizeof(engine->escapes[index]));
            }
            engine->escape_count--;
            if (engine->escape_count < engine->escape_capacity) {
                CPUEAXH_MEMSET(&engine->escapes[engine->escape_count], 0, sizeof(engine->escapes[engine->escape_count]));
            }
            return CPUEAXH_ERR_OK;
        }
    }

    return CPUEAXH_ERR_HOOK;
}

extern "C" cpueaxh_err cpueaxh_escape_add(cpueaxh_engine* engine, cpueaxh_escape_handle* out_hook, cpueaxh_escape_insn_id instruction_id, void* callback, void* user_data, uint64_t begin, uint64_t end) {
    cpueaxh_err error = cpueaxh_validate_engine(engine);
    if (error != CPUEAXH_ERR_OK || !out_hook || !callback || instruction_id == CPUEAXH_ESCAPE_INSN_NONE) {
        return error != CPUEAXH_ERR_OK ? error : CPUEAXH_ERR_ARG;
    }

    for (size_t index = 0; index < engine->escape_count; index++) {
        if (engine->escapes[index].instruction_id == instruction_id) {
            return CPUEAXH_ERR_HOOK;
        }
    }

    error = cpueaxh_ensure_escape_capacity(engine, engine->escape_count + 1);
    if (error != CPUEAXH_ERR_OK) {
        return error;
    }

    CPUEAXH_ESCAPE_ENTRY* escape = &engine->escapes[engine->escape_count++];
    escape->handle = engine->next_hook++;
    escape->callback = (cpueaxh_cb_escape_t)callback;
    escape->user_data = user_data;
    escape->begin = begin;
    escape->end = end;
    escape->instruction_id = instruction_id;
    *out_hook = escape->handle;
    return CPUEAXH_ERR_OK;
}

extern "C" cpueaxh_err cpueaxh_escape_del(cpueaxh_engine* engine, cpueaxh_escape_handle hook) {
    return cpueaxh_hook_del(engine, hook);
}

extern "C" uint32_t cpueaxh_code_exception(const cpueaxh_engine* engine) {
    return engine ? engine->context.exception.code : CPU_EXCEPTION_NONE;
}

extern "C" uint32_t cpueaxh_error_code_exception(const cpueaxh_engine* engine) {
    return engine ? engine->context.exception.error_code : 0;
}

extern "C" void cpueaxh_free(void* ptr) {
    if (!ptr) {
        return;
    }
    CPUEAXH_FREE(ptr);
}