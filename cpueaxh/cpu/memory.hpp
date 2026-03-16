// cpu/memory.hpp - CPU memory access functions

inline uint32_t cpu_make_page_fault_error(const CPU_CONTEXT* ctx, uint32_t access, bool protection_violation) {
    uint32_t error_code = protection_violation ? 0x1u : 0x0u;

    if (access == MM_PROT_WRITE) {
        error_code |= 0x2u;
    }
    if (ctx && ctx->cpl == 3) {
        error_code |= 0x4u;
    }
    if (access == MM_PROT_EXEC) {
        error_code |= 0x10u;
    }

    return error_code;
}

inline void cpu_raise_page_fault(CPU_CONTEXT* ctx, uint32_t access, bool protection_violation) {
    cpu_raise_exception(ctx, CPU_EXCEPTION_PF, cpu_make_page_fault_error(ctx, access, protection_violation));
}

inline MM_ACCESS_STATUS cpu_resolve_memory_access(CPU_CONTEXT* ctx, uint64_t address, uint32_t access, uint8_t** out_ptr) {
    if (!ctx || cpu_has_exception(ctx)) {
        if (out_ptr) {
            *out_ptr = NULL;
        }
        return MM_ACCESS_UNMAPPED;
    }

    uint32_t cpu_attrs = 0;
    MM_ACCESS_STATUS status = mm_get_ptr_checked(ctx->mem_mgr, address, access, out_ptr, &cpu_attrs);
    if (status == MM_ACCESS_UNMAPPED) {
        cpu_raise_page_fault(ctx, access, false);
        return status;
    }
    if (status == MM_ACCESS_PROT) {
        cpu_raise_page_fault(ctx, access, true);
        return status;
    }

    if (ctx->cpl == 3 && (cpu_attrs & MM_CPU_ATTR_USER) == 0) {
        if (out_ptr) {
            *out_ptr = NULL;
        }
        cpu_raise_page_fault(ctx, access, true);
        return MM_ACCESS_PROT;
    }

    return MM_ACCESS_OK;
}

inline uint8_t read_memory_byte(CPU_CONTEXT* ctx, uint64_t address) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_READ, &ptr) != MM_ACCESS_OK) {
        return 0;
    }
    return *ptr;
}

inline uint8_t read_memory_exec_byte(CPU_CONTEXT* ctx, uint64_t address) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_EXEC, &ptr) != MM_ACCESS_OK) {
        return 0;
    }
    return *ptr;
}

inline void write_memory_byte(CPU_CONTEXT* ctx, uint64_t address, uint8_t value) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_WRITE, &ptr) != MM_ACCESS_OK) {
        return;
    }
    *ptr = value;
}

inline uint8_t* get_memory_write_ptr(CPU_CONTEXT* ctx, uint64_t address, size_t size) {
    if (!ctx || size == 0 || cpu_has_exception(ctx)) {
        return NULL;
    }

    uint8_t* base_ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_WRITE, &base_ptr) != MM_ACCESS_OK) {
        return NULL;
    }

    for (size_t offset = 1; offset < size; offset++) {
        uint8_t* next_ptr = NULL;
        if (cpu_resolve_memory_access(ctx, address + offset, MM_PROT_WRITE, &next_ptr) != MM_ACCESS_OK) {
            return NULL;
        }
        if (next_ptr != base_ptr + offset) {
            cpu_raise_page_fault(ctx, MM_PROT_WRITE, true);
            return NULL;
        }
    }

    return base_ptr;
}

inline bool cpu_is_host_write_passthrough(CPU_CONTEXT* ctx) {
    return ctx && ctx->mem_mgr && mm_has_host_passthrough(ctx->mem_mgr, MM_PROT_WRITE);
}

inline uint16_t read_memory_word(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint16_t value = 0;
    for (int i = 0; i < 2; i++) {
        value |= ((uint16_t)read_memory_byte(ctx, address + i)) << (i * 8);
    }
    return value;
}

inline void write_memory_word(CPU_CONTEXT* ctx, uint64_t address, uint16_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    for (int i = 0; i < 2; i++) {
        write_memory_byte(ctx, address + i, (uint8_t)((value >> (i * 8)) & 0xFF));
    }
}

inline uint32_t read_memory_dword(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint32_t value = 0;
    for (int i = 0; i < 4; i++) {
        value |= ((uint32_t)read_memory_byte(ctx, address + i)) << (i * 8);
    }
    return value;
}

inline void write_memory_dword(CPU_CONTEXT* ctx, uint64_t address, uint32_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    for (int i = 0; i < 4; i++) {
        write_memory_byte(ctx, address + i, (uint8_t)((value >> (i * 8)) & 0xFF));
    }
}

inline uint64_t read_memory_qword(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t)read_memory_byte(ctx, address + i)) << (i * 8);
    }
    return value;
}

inline void write_memory_qword(CPU_CONTEXT* ctx, uint64_t address, uint64_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    for (int i = 0; i < 8; i++) {
        write_memory_byte(ctx, address + i, (uint8_t)((value >> (i * 8)) & 0xFF));
    }
}

inline uint64_t cpu_memory_operand_mask(int operand_size) {
    switch (operand_size) {
    case 8:  return 0xFFULL;
    case 16: return 0xFFFFULL;
    case 32: return 0xFFFFFFFFULL;
    case 64: return 0xFFFFFFFFFFFFFFFFULL;
    default: raise_ud(); return 0;
    }
}

inline uint64_t read_memory_operand(CPU_CONTEXT* ctx, uint64_t address, int operand_size) {
    switch (operand_size) {
    case 8:  return read_memory_byte(ctx, address);
    case 16: return read_memory_word(ctx, address);
    case 32: return read_memory_dword(ctx, address);
    case 64: return read_memory_qword(ctx, address);
    default: raise_ud(); return 0;
    }
}

inline void write_memory_operand(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t value) {
    switch (operand_size) {
    case 8:  write_memory_byte(ctx, address, (uint8_t)value); break;
    case 16: write_memory_word(ctx, address, (uint16_t)value); break;
    case 32: write_memory_dword(ctx, address, (uint32_t)value); break;
    case 64: write_memory_qword(ctx, address, value); break;
    default: raise_ud(); break;
    }
}

inline bool cpu_atomic_compare_exchange_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size,
                                               uint64_t expected_value, uint64_t desired_value,
                                               uint64_t* previous_value) {
    uint8_t* ptr = get_memory_write_ptr(ctx, address, (size_t)(operand_size / 8));
    if (!ptr) {
        return false;
    }

    uint64_t old_value = 0;
    switch (operand_size) {
    case 8:
        old_value = (uint8_t)_InterlockedCompareExchange8((volatile char*)ptr, (char)desired_value, (char)expected_value);
        break;
    case 16:
        old_value = (uint16_t)_InterlockedCompareExchange16((volatile short*)ptr, (short)desired_value, (short)expected_value);
        break;
    case 32:
        old_value = (uint32_t)_InterlockedCompareExchange((volatile long*)ptr, (long)desired_value, (long)expected_value);
        break;
    case 64:
        old_value = (uint64_t)_InterlockedCompareExchange64((volatile long long*)ptr, (long long)desired_value, (long long)expected_value);
        break;
    default:
        raise_ud();
        return false;
    }

    old_value &= cpu_memory_operand_mask(operand_size);
    if (previous_value) {
        *previous_value = old_value;
    }
    return old_value == (expected_value & cpu_memory_operand_mask(operand_size));
}

typedef uint64_t(*cpu_atomic_rmw_callback)(uint64_t current_value, void* user_data);

inline bool cpu_atomic_rmw_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size,
                                  cpu_atomic_rmw_callback callback, void* user_data,
                                  uint64_t* old_value_out, uint64_t* new_value_out) {
    uint64_t mask = cpu_memory_operand_mask(operand_size);
    uint64_t current_value = read_memory_operand(ctx, address, operand_size) & mask;
    if (cpu_has_exception(ctx)) {
        return false;
    }

    for (;;) {
        uint64_t desired_value = callback(current_value, user_data) & mask;
        uint64_t observed_value = 0;
        if (!cpu_atomic_compare_exchange_memory(ctx, address, operand_size, current_value, desired_value, &observed_value)) {
            if (cpu_has_exception(ctx)) {
                return false;
            }
            current_value = observed_value & mask;
            continue;
        }

        if (old_value_out) {
            *old_value_out = current_value;
        }
        if (new_value_out) {
            *new_value_out = desired_value;
        }
        return true;
    }
}

struct cpu_atomic_binary_op_data {
    uint64_t operand;
};

inline uint64_t cpu_atomic_add_callback(uint64_t current_value, void* user_data) {
    return current_value + ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline uint64_t cpu_atomic_sub_callback(uint64_t current_value, void* user_data) {
    return current_value - ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline uint64_t cpu_atomic_and_callback(uint64_t current_value, void* user_data) {
    return current_value & ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline uint64_t cpu_atomic_or_callback(uint64_t current_value, void* user_data) {
    return current_value | ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline uint64_t cpu_atomic_xor_callback(uint64_t current_value, void* user_data) {
    return current_value ^ ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline uint64_t cpu_atomic_exchange_callback(uint64_t current_value, void* user_data) {
    (void)current_value;
    return ((cpu_atomic_binary_op_data*)user_data)->operand;
}

inline bool cpu_atomic_add_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t operand,
                                  uint64_t* old_value_out, uint64_t* new_value_out) {
    cpu_atomic_binary_op_data data = { operand };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_add_callback, &data, old_value_out, new_value_out);
}

inline bool cpu_atomic_sub_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t operand,
                                  uint64_t* old_value_out, uint64_t* new_value_out) {
    cpu_atomic_binary_op_data data = { operand };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_sub_callback, &data, old_value_out, new_value_out);
}

inline bool cpu_atomic_and_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t operand,
                                  uint64_t* old_value_out, uint64_t* new_value_out) {
    cpu_atomic_binary_op_data data = { operand };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_and_callback, &data, old_value_out, new_value_out);
}

inline bool cpu_atomic_or_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t operand,
                                 uint64_t* old_value_out, uint64_t* new_value_out) {
    cpu_atomic_binary_op_data data = { operand };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_or_callback, &data, old_value_out, new_value_out);
}

inline bool cpu_atomic_xor_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t operand,
                                  uint64_t* old_value_out, uint64_t* new_value_out) {
    cpu_atomic_binary_op_data data = { operand };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_xor_callback, &data, old_value_out, new_value_out);
}

inline bool cpu_atomic_exchange_memory(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t desired_value,
                                       uint64_t* old_value_out) {
    cpu_atomic_binary_op_data data = { desired_value };
    return cpu_atomic_rmw_memory(ctx, address, operand_size, cpu_atomic_exchange_callback, &data, old_value_out, NULL);
}
