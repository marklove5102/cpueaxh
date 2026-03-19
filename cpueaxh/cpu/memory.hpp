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

inline uint32_t cpu_get_invalid_memory_hook_type(uint32_t access, bool protection_violation) {
    if (protection_violation) {
        if (access == MM_PROT_WRITE) {
            return CPUEAXH_HOOK_MEM_WRITE_PROT;
        }
        if (access == MM_PROT_EXEC) {
            return CPUEAXH_HOOK_MEM_FETCH_PROT;
        }
        return CPUEAXH_HOOK_MEM_READ_PROT;
    }

    if (access == MM_PROT_WRITE) {
        return CPUEAXH_HOOK_MEM_WRITE_UNMAPPED;
    }
    if (access == MM_PROT_EXEC) {
        return CPUEAXH_HOOK_MEM_FETCH_UNMAPPED;
    }
    return CPUEAXH_HOOK_MEM_READ_UNMAPPED;
}

inline bool cpu_try_handle_invalid_memory_access(CPU_CONTEXT* ctx, uint64_t address, uint32_t access, bool protection_violation, size_t size, uint64_t value) {
    return cpu_notify_invalid_memory_hook(ctx, cpu_get_invalid_memory_hook_type(access, protection_violation), address, size, value);
}

inline MM_ACCESS_STATUS cpu_resolve_memory_access(CPU_CONTEXT* ctx, uint64_t address, uint32_t access, uint8_t** out_ptr,
    uint64_t reported_address = 0, size_t reported_size = 1, uint64_t reported_value = 0) {
    if (!ctx || cpu_has_exception(ctx)) {
        if (out_ptr) {
            *out_ptr = NULL;
        }
        return MM_ACCESS_UNMAPPED;
    }

    if (reported_address == 0) {
        reported_address = address;
    }

    for (int attempt = 0; attempt < 4; attempt++) {
        uint32_t cpu_attrs = 0;
        MM_ACCESS_STATUS status = mm_get_ptr_checked_ex(ctx->mem_mgr, address, access, out_ptr, &cpu_attrs, access == MM_PROT_WRITE);
        if (status == MM_ACCESS_UNMAPPED) {
            if (out_ptr) {
                *out_ptr = NULL;
            }
            if (cpu_try_handle_invalid_memory_access(ctx, reported_address, access, false, reported_size, reported_value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, false);
            return status;
        }
        if (status == MM_ACCESS_PROT) {
            if (out_ptr) {
                *out_ptr = NULL;
            }
            if (cpu_try_handle_invalid_memory_access(ctx, reported_address, access, true, reported_size, reported_value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, true);
            return status;
        }

        if (ctx->cpl == 3 && (cpu_attrs & MM_CPU_ATTR_USER) == 0) {
            if (out_ptr) {
                *out_ptr = NULL;
            }
            if (cpu_try_handle_invalid_memory_access(ctx, reported_address, access, true, reported_size, reported_value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, true);
            return MM_ACCESS_PROT;
        }

        return MM_ACCESS_OK;
    }

    if (out_ptr) {
        *out_ptr = NULL;
    }
    cpu_raise_page_fault(ctx, access, true);
    return MM_ACCESS_PROT;
}

inline uint8_t read_memory_byte(CPU_CONTEXT* ctx, uint64_t address) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_READ, &ptr, address, 1, 0) != MM_ACCESS_OK) {
        return 0;
    }
    uint8_t value = *ptr;
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_READ, address, 1, value);
    return value;
}

inline uint8_t read_memory_exec_byte(CPU_CONTEXT* ctx, uint64_t address) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_EXEC, &ptr, address, 1, 0) != MM_ACCESS_OK) {
        return 0;
    }
    uint8_t value = *ptr;
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_FETCH, address, 1, value);
    return value;
}

inline void write_memory_byte(CPU_CONTEXT* ctx, uint64_t address, uint8_t value) {
    uint8_t* ptr = NULL;
    if (cpu_resolve_memory_access(ctx, address, MM_PROT_WRITE, &ptr, address, 1, value) != MM_ACCESS_OK) {
        return;
    }
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_WRITE, address, 1, value);
    *ptr = value;
}

inline uint8_t* cpu_get_contiguous_ptr(CPU_CONTEXT* ctx, uint64_t address, size_t size, uint32_t access, uint64_t value = 0) {
    if (!ctx || size == 0 || cpu_has_exception(ctx)) {
        return NULL;
    }

    for (int attempt = 0; attempt < 4; ++attempt) {
        uint8_t* base_ptr = NULL;
        uint32_t cpu_attrs = 0;
        MM_ACCESS_STATUS status = mm_get_contiguous_ptr_checked(ctx->mem_mgr, address, (uint64_t)size, access, &base_ptr, &cpu_attrs, access == MM_PROT_WRITE);
        if (status == MM_ACCESS_UNMAPPED) {
            if (cpu_try_handle_invalid_memory_access(ctx, address, access, false, size, value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, false);
            return NULL;
        }
        if (status == MM_ACCESS_PROT) {
            if (cpu_try_handle_invalid_memory_access(ctx, address, access, true, size, value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, true);
            return NULL;
        }
        if (ctx->cpl == 3 && (cpu_attrs & MM_CPU_ATTR_USER) == 0) {
            if (cpu_try_handle_invalid_memory_access(ctx, address, access, true, size, value)) {
                continue;
            }
            cpu_raise_page_fault(ctx, access, true);
            return NULL;
        }
        return base_ptr;
    }

    cpu_raise_page_fault(ctx, access, true);
    return NULL;
}

inline uint8_t* get_memory_write_ptr(CPU_CONTEXT* ctx, uint64_t address, size_t size, uint64_t value = 0) {
    return cpu_get_contiguous_ptr(ctx, address, size, MM_PROT_WRITE, value);
}

inline bool cpu_is_host_write_passthrough(CPU_CONTEXT* ctx) {
    return ctx && ctx->mem_mgr && mm_has_host_passthrough(ctx->mem_mgr, MM_PROT_WRITE) && !ctx->mem_mgr->host_write_isolation_enabled;
}

inline uint16_t read_memory_word(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint8_t* ptr = cpu_get_contiguous_ptr(ctx, address, 2, MM_PROT_READ);
    if (!ptr) {
        return 0;
    }
    uint16_t value = (uint16_t)ptr[0] | ((uint16_t)ptr[1] << 8);
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_READ, address, 2, value);
    return value;
}

inline void write_memory_word(CPU_CONTEXT* ctx, uint64_t address, uint16_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    uint8_t* ptr = get_memory_write_ptr(ctx, address, 2, value);
    if (!ptr) {
        return;
    }
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_WRITE, address, 2, value);
    ptr[0] = (uint8_t)(value & 0xFF);
    ptr[1] = (uint8_t)((value >> 8) & 0xFF);
}

inline uint32_t read_memory_dword(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint8_t* ptr = cpu_get_contiguous_ptr(ctx, address, 4, MM_PROT_READ);
    if (!ptr) {
        return 0;
    }
    uint32_t value = (uint32_t)ptr[0] |
        ((uint32_t)ptr[1] << 8) |
        ((uint32_t)ptr[2] << 16) |
        ((uint32_t)ptr[3] << 24);
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_READ, address, 4, value);
    return value;
}

inline void write_memory_dword(CPU_CONTEXT* ctx, uint64_t address, uint32_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    uint8_t* ptr = get_memory_write_ptr(ctx, address, 4, value);
    if (!ptr) {
        return;
    }
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_WRITE, address, 4, value);
    ptr[0] = (uint8_t)(value & 0xFF);
    ptr[1] = (uint8_t)((value >> 8) & 0xFF);
    ptr[2] = (uint8_t)((value >> 16) & 0xFF);
    ptr[3] = (uint8_t)((value >> 24) & 0xFF);
}

inline uint64_t read_memory_qword(CPU_CONTEXT* ctx, uint64_t address) {
    if (cpu_has_exception(ctx)) {
        return 0;
    }

    uint8_t* ptr = cpu_get_contiguous_ptr(ctx, address, 8, MM_PROT_READ);
    if (!ptr) {
        return 0;
    }
    uint64_t value = (uint64_t)ptr[0] |
        ((uint64_t)ptr[1] << 8) |
        ((uint64_t)ptr[2] << 16) |
        ((uint64_t)ptr[3] << 24) |
        ((uint64_t)ptr[4] << 32) |
        ((uint64_t)ptr[5] << 40) |
        ((uint64_t)ptr[6] << 48) |
        ((uint64_t)ptr[7] << 56);
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_READ, address, 8, value);
    return value;
}

inline void write_memory_qword(CPU_CONTEXT* ctx, uint64_t address, uint64_t value) {
    if (cpu_has_exception(ctx)) {
        return;
    }

    uint8_t* ptr = get_memory_write_ptr(ctx, address, 8, value);
    if (!ptr) {
        return;
    }
    cpu_notify_memory_hook(ctx, CPUEAXH_HOOK_MEM_WRITE, address, 8, value);
    ptr[0] = (uint8_t)(value & 0xFF);
    ptr[1] = (uint8_t)((value >> 8) & 0xFF);
    ptr[2] = (uint8_t)((value >> 16) & 0xFF);
    ptr[3] = (uint8_t)((value >> 24) & 0xFF);
    ptr[4] = (uint8_t)((value >> 32) & 0xFF);
    ptr[5] = (uint8_t)((value >> 40) & 0xFF);
    ptr[6] = (uint8_t)((value >> 48) & 0xFF);
    ptr[7] = (uint8_t)((value >> 56) & 0xFF);
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
