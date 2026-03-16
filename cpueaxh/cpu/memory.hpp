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
