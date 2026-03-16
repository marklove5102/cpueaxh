#pragma once

#include <stdint.h>
#include <stddef.h>

typedef int cpueaxh_err;
typedef struct cpueaxh_engine cpueaxh_engine;
typedef uint64_t cpueaxh_hook;
typedef uint64_t cpueaxh_mem_patch_handle;
typedef uint64_t cpueaxh_escape_handle;
typedef uint32_t cpueaxh_escape_insn_id;
typedef cpueaxh_escape_insn_id cpueaxh_insn_id;
typedef void (*cpueaxh_cb_hookcode_t)(cpueaxh_engine* engine, uint64_t address, void* user_data);
typedef void (*cpueaxh_cb_host_bridge_t)(void);

typedef struct cpueaxh_x86_xmm {
	uint64_t low;
	uint64_t high;
} cpueaxh_x86_xmm;

typedef struct cpueaxh_x86_segment_descriptor {
	uint64_t base;
	uint32_t limit;
	uint8_t type;
	uint8_t dpl;
	uint8_t present;
	uint8_t granularity;
	uint8_t db;
	uint8_t long_mode;
} cpueaxh_x86_segment_descriptor;

typedef struct cpueaxh_x86_segment {
	uint16_t selector;
	uint16_t reserved0;
	cpueaxh_x86_segment_descriptor descriptor;
} cpueaxh_x86_segment;

typedef struct cpueaxh_x86_context {
	uint64_t regs[16];
	uint64_t rip;
	uint64_t rflags;
	cpueaxh_x86_xmm xmm[16];
	cpueaxh_x86_xmm ymm_upper[16];
	uint64_t mm[8];
	uint32_t mxcsr;
	uint32_t reserved0;
	cpueaxh_x86_segment es;
	cpueaxh_x86_segment cs;
	cpueaxh_x86_segment ss;
	cpueaxh_x86_segment ds;
	cpueaxh_x86_segment fs;
	cpueaxh_x86_segment gs;
	uint64_t gdtr_base;
	uint16_t gdtr_limit;
	uint16_t reserved1;
	uint64_t ldtr_base;
	uint16_t ldtr_limit;
	uint16_t reserved2;
	uint8_t cpl;
	uint8_t reserved3[7];
	uint32_t code_exception;
	uint32_t error_code_exception;
	uint64_t internal_bridge_block;
} cpueaxh_x86_context;

typedef struct cpueaxh_mem_region {
	uint64_t begin;
	uint64_t end;
	uint32_t perms;
	uint32_t cpu_attrs;
} cpueaxh_mem_region;

typedef cpueaxh_err (*cpueaxh_cb_escape_t)(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data);

#define CPUEAXH_ERR_OK 0
#define CPUEAXH_ERR_NOMEM 1
#define CPUEAXH_ERR_ARG 2
#define CPUEAXH_ERR_ARCH 3
#define CPUEAXH_ERR_MODE 4
#define CPUEAXH_ERR_MAP 5
#define CPUEAXH_ERR_READ_UNMAPPED 6
#define CPUEAXH_ERR_WRITE_UNMAPPED 7
#define CPUEAXH_ERR_FETCH_UNMAPPED 8
#define CPUEAXH_ERR_EXCEPTION 9
#define CPUEAXH_ERR_HOOK 10
#define CPUEAXH_ERR_READ_PROT 11
#define CPUEAXH_ERR_WRITE_PROT 12
#define CPUEAXH_ERR_FETCH_PROT 13
#define CPUEAXH_ERR_PATCH 14

#define CPUEAXH_ARCH_X86 1u
#define CPUEAXH_MODE_64 8u

#define CPUEAXH_MEMORY_MODE_GUEST 0u
#define CPUEAXH_MEMORY_MODE_HOST 1u

#define CPUEAXH_PROT_READ 1u
#define CPUEAXH_PROT_WRITE 2u
#define CPUEAXH_PROT_EXEC 4u

#define CPUEAXH_MEM_ATTR_USER 1u

#define CPUEAXH_EMU_RETURN_MAGIC 0x4350554541584841ull

#define CPUEAXH_HOOK_CODE_PRE 1u
#define CPUEAXH_HOOK_CODE_POST 2u

#define CPUEAXH_ESCAPE_INSN_NONE 0u
#define CPUEAXH_ESCAPE_INSN_SYSCALL 1u
#define CPUEAXH_ESCAPE_INSN_SYSENTER 2u
#define CPUEAXH_ESCAPE_INSN_INT 3u
#define CPUEAXH_ESCAPE_INSN_INT3 4u
#define CPUEAXH_ESCAPE_INSN_CPUID 5u
#define CPUEAXH_ESCAPE_INSN_XGETBV 6u
#define CPUEAXH_ESCAPE_INSN_RDTSC 7u
#define CPUEAXH_ESCAPE_INSN_RDTSCP 8u
#define CPUEAXH_ESCAPE_INSN_RDRAND 9u
#define CPUEAXH_ESCAPE_INSN_HLT 10u
#define CPUEAXH_ESCAPE_INSN_IN 11u
#define CPUEAXH_ESCAPE_INSN_OUT 12u

#define CPUEAXH_EXCEPTION_NONE ((uint32_t)0u)
#define CPUEAXH_EXCEPTION_DE ((uint32_t)0xE0000000u)
#define CPUEAXH_EXCEPTION_GP ((uint32_t)0xE0000001u)
#define CPUEAXH_EXCEPTION_SS ((uint32_t)0xE0000002u)
#define CPUEAXH_EXCEPTION_NP ((uint32_t)0xE0000003u)
#define CPUEAXH_EXCEPTION_UD ((uint32_t)0xE0000004u)
#define CPUEAXH_EXCEPTION_PF ((uint32_t)0xE0000005u)
#define CPUEAXH_EXCEPTION_AC ((uint32_t)0xE0000006u)

#define CPUEAXH_X86_REG_RAX 0
#define CPUEAXH_X86_REG_RCX 1
#define CPUEAXH_X86_REG_RDX 2
#define CPUEAXH_X86_REG_RBX 3
#define CPUEAXH_X86_REG_RSP 4
#define CPUEAXH_X86_REG_RBP 5
#define CPUEAXH_X86_REG_RSI 6
#define CPUEAXH_X86_REG_RDI 7
#define CPUEAXH_X86_REG_R8 8
#define CPUEAXH_X86_REG_R9 9
#define CPUEAXH_X86_REG_R10 10
#define CPUEAXH_X86_REG_R11 11
#define CPUEAXH_X86_REG_R12 12
#define CPUEAXH_X86_REG_R13 13
#define CPUEAXH_X86_REG_R14 14
#define CPUEAXH_X86_REG_R15 15
#define CPUEAXH_X86_REG_RIP 16
#define CPUEAXH_X86_REG_EFLAGS 17
#define CPUEAXH_X86_REG_GS_SELECTOR 18
#define CPUEAXH_X86_REG_GS_BASE 19
#define CPUEAXH_X86_REG_CPL 20

#ifdef __cplusplus
extern "C" {
#endif

cpueaxh_err cpueaxh_open(uint32_t arch, uint32_t mode, cpueaxh_engine** out_engine);
void cpueaxh_close(cpueaxh_engine* engine);

cpueaxh_err cpueaxh_set_memory_mode(cpueaxh_engine* engine, uint32_t memory_mode);

cpueaxh_err cpueaxh_mem_map(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms);
cpueaxh_err cpueaxh_mem_map_ptr(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms, void* host_ptr);
cpueaxh_err cpueaxh_mem_unmap(cpueaxh_engine* engine, uint64_t address, size_t size);
cpueaxh_err cpueaxh_mem_protect(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t perms);
cpueaxh_err cpueaxh_mem_set_cpu_attrs(cpueaxh_engine* engine, uint64_t address, size_t size, uint32_t attrs);
cpueaxh_err cpueaxh_mem_regions(const cpueaxh_engine* engine, cpueaxh_mem_region** regions, uint32_t* count);
cpueaxh_err cpueaxh_mem_write(cpueaxh_engine* engine, uint64_t address, const void* bytes, size_t size);
cpueaxh_err cpueaxh_mem_read(cpueaxh_engine* engine, uint64_t address, void* bytes, size_t size);
cpueaxh_err cpueaxh_mem_patch_add(cpueaxh_engine* engine, cpueaxh_mem_patch_handle* out_patch, uint64_t address, const void* bytes, size_t size);
cpueaxh_err cpueaxh_mem_patch_del(cpueaxh_engine* engine, cpueaxh_mem_patch_handle patch);

cpueaxh_err cpueaxh_reg_write(cpueaxh_engine* engine, int regid, const void* value);
cpueaxh_err cpueaxh_reg_read(cpueaxh_engine* engine, int regid, void* value);

cpueaxh_err cpueaxh_emu_start(cpueaxh_engine* engine, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
cpueaxh_err cpueaxh_emu_start_function(cpueaxh_engine* engine, uint64_t begin, uint64_t timeout, size_t count);
void cpueaxh_emu_stop(cpueaxh_engine* engine);

cpueaxh_err cpueaxh_host_call(cpueaxh_x86_context* context, cpueaxh_cb_host_bridge_t bridge);

cpueaxh_err cpueaxh_hook_add(cpueaxh_engine* engine, cpueaxh_hook* out_hook, uint32_t type, void* callback, void* user_data, uint64_t begin, uint64_t end);
cpueaxh_err cpueaxh_hook_add_address(cpueaxh_engine* engine, cpueaxh_hook* out_hook, uint32_t type, void* callback, void* user_data, uint64_t address);
cpueaxh_err cpueaxh_hook_del(cpueaxh_engine* engine, cpueaxh_hook hook);
cpueaxh_err cpueaxh_escape_add(cpueaxh_engine* engine, cpueaxh_escape_handle* out_hook, cpueaxh_escape_insn_id instruction_id, void* callback, void* user_data, uint64_t begin, uint64_t end);
cpueaxh_err cpueaxh_escape_del(cpueaxh_engine* engine, cpueaxh_escape_handle hook);

uint32_t cpueaxh_code_exception(const cpueaxh_engine* engine);
uint32_t cpueaxh_error_code_exception(const cpueaxh_engine* engine);
void cpueaxh_free(void* ptr);

#ifdef __cplusplus
}
#endif
