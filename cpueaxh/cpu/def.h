// cpu/def.h - CPU definitions: enums, structs, status-based exceptions

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef CPUEAXH_MEMSET
#include <string.h>
#define CPUEAXH_MEMSET memset
#endif

#ifndef CPUEAXH_MEMCPY
#include <string.h>
#define CPUEAXH_MEMCPY memcpy
#endif

#ifndef CPUEAXH_ALLOC_ZEROED
#include <stdlib.h>
#define CPUEAXH_ALLOC_ZEROED(size) calloc(1, (size))
#endif

#ifndef CPUEAXH_FREE
#include <stdlib.h>
#define CPUEAXH_FREE(ptr) free((ptr))
#endif

struct MEMORY_MANAGER;
struct CPU_CONTEXT;

// RFLAGS bit definitions
#define RFLAGS_CF  (1ULL << 0)
#define RFLAGS_PF  (1ULL << 2)
#define RFLAGS_AF  (1ULL << 4)
#define RFLAGS_ZF  (1ULL << 6)
#define RFLAGS_SF  (1ULL << 7)
#define RFLAGS_DF  (1ULL << 10)
#define RFLAGS_OF  (1ULL << 11)

enum CPU_EXCEPTION_CODE : uint32_t {
    CPU_EXCEPTION_NONE = 0,
    CPU_EXCEPTION_DE   = 0xE0000000,
    CPU_EXCEPTION_GP   = 0xE0000001,
    CPU_EXCEPTION_SS   = 0xE0000002,
    CPU_EXCEPTION_NP   = 0xE0000003,
    CPU_EXCEPTION_UD   = 0xE0000004,
    CPU_EXCEPTION_PF   = 0xE0000005,
    CPU_EXCEPTION_AC   = 0xE0000006,
};

struct CPU_EXCEPTION_STATE {
    uint32_t code;
    uint32_t error_code;
};

inline bool cpu_is_exception_code(uint32_t code) {
    return code >= CPU_EXCEPTION_DE && code <= CPU_EXCEPTION_AC;
}

inline void cpu_exception_reset(CPU_EXCEPTION_STATE* state) {
    state->code = CPU_EXCEPTION_NONE;
    state->error_code = 0;
}

inline CPU_CONTEXT*& cpu_active_context_slot() {
    static thread_local CPU_CONTEXT* current_ctx = nullptr;
    return current_ctx;
}

inline CPU_CONTEXT* cpu_get_active_context() {
    return cpu_active_context_slot();
}

inline CPU_CONTEXT* cpu_set_active_context(CPU_CONTEXT* ctx) {
    CPU_CONTEXT* previous = cpu_active_context_slot();
    cpu_active_context_slot() = ctx;
    return previous;
}

enum SegmentRegisterIndex {
    SEG_ES = 0,
    SEG_CS = 1,
    SEG_SS = 2,
    SEG_DS = 3,
    SEG_FS = 4,
    SEG_GS = 5
};

enum RegisterIndex {
    REG_RAX = 0,
    REG_RCX = 1,
    REG_RDX = 2,
    REG_RBX = 3,
    REG_RSP = 4,
    REG_RBP = 5,
    REG_RSI = 6,
    REG_RDI = 7,
    REG_R8 = 8,
    REG_R9 = 9,
    REG_R10 = 10,
    REG_R11 = 11,
    REG_R12 = 12,
    REG_R13 = 13,
    REG_R14 = 14,
    REG_R15 = 15
};

struct SegmentDescriptor {
    uint64_t base;
    uint32_t limit;
    uint8_t type;
    uint8_t dpl;
    bool present;
    bool granularity;
    bool db;
    bool long_mode;
};

struct SegmentRegister {
    uint16_t selector;
    SegmentDescriptor descriptor;
};

struct XMMRegister {
    uint64_t low;
    uint64_t high;
};

struct CPU_CONTEXT {
    uint64_t regs[16];
    XMMRegister xmm[16];
    XMMRegister ymm_upper[16];
    uint64_t mm[8];
    uint32_t mxcsr;
    SegmentRegister es;
    SegmentRegister cs;
    SegmentRegister ss;
    SegmentRegister ds;
    SegmentRegister fs;
    SegmentRegister gs;

    uint64_t rip;
    uint64_t rflags;

    uint8_t cpl;

    uint64_t gdtr_base;
    uint16_t gdtr_limit;
    uint64_t ldtr_base;
    uint16_t ldtr_limit;

    MEMORY_MANAGER* mem_mgr;

    bool rex_present;
    bool rex_w;
    bool rex_r;
    bool rex_x;
    bool rex_b;

    bool operand_size_override;
    bool address_size_override;

    // Set by every decoder to the byte-length of the decoded instruction.
    // cpu_step uses this to advance RIP for non-branch instructions.
    int last_inst_size;

    CPU_EXCEPTION_STATE exception;
};

inline bool cpu_has_exception(const CPU_CONTEXT* ctx) {
    return ctx && ctx->exception.code != CPU_EXCEPTION_NONE;
}

inline void cpu_clear_exception(CPU_CONTEXT* ctx) {
    cpu_exception_reset(&ctx->exception);
}

inline void cpu_raise_exception(CPU_CONTEXT* ctx, uint32_t code, uint32_t error_code = 0) {
    if (!ctx || cpu_has_exception(ctx)) {
        return;
    }

    ctx->exception.code = code;
    ctx->exception.error_code = error_code;
}

#define raise_de()    cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_DE, 0)
#define raise_gp(ec)  cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_GP, (uint32_t)(ec))
#define raise_ss(ec)  cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_SS, (uint32_t)(ec))
#define raise_np(ec)  cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_NP, (uint32_t)(ec))
#define raise_ud()    cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_UD, 0)
#define raise_pf(ec)  cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_PF, (uint32_t)(ec))
#define raise_ac()    cpu_raise_exception(cpu_get_active_context(), CPU_EXCEPTION_AC, 0)

struct DecodedInstruction {
    uint8_t opcode;
    uint8_t mandatory_prefix;
    uint8_t modrm;
    uint8_t sib;
    int32_t displacement;
    uint64_t immediate;
    uint64_t mem_address;
    int operand_size;
    int address_size;
    bool has_modrm;
    bool has_sib;
    bool has_lock_prefix;
    int disp_size;
    int imm_size;
    int inst_size;  // total instruction size in bytes (used by CALL/JMP for return address calculation)
};
