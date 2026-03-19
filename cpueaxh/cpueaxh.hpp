#pragma once

#if defined(CPUEAXH_PLATFORM_KERNEL) || defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_WDM_INCLUDED_) || defined(_NTIFS_)
#include <stddef.h>
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#include <stddef.h>
#endif

typedef int cpueaxh_err;
typedef struct cpueaxh_engine cpueaxh_engine;
typedef uint64_t cpueaxh_hook;
typedef uint64_t cpueaxh_mem_patch_handle;
typedef uint64_t cpueaxh_escape_handle;
typedef uint64_t cpueaxh_write_isolation_handle;
typedef uint32_t cpueaxh_escape_insn_id;
typedef cpueaxh_escape_insn_id cpueaxh_insn_id;
typedef void (*cpueaxh_cb_hookcode_t)(cpueaxh_engine* engine, uint64_t address, void* user_data);
typedef void (*cpueaxh_cb_hookmem_t)(cpueaxh_engine* engine, uint32_t type, uint64_t address, size_t size, uint64_t value, void* user_data);
typedef int (*cpueaxh_cb_hookmem_invalid_t)(cpueaxh_engine* engine, uint32_t type, uint64_t address, size_t size, uint64_t value, void* user_data);
typedef void (*cpueaxh_cb_host_bridge_t)(void);

typedef struct cpueaxh_x86_xmm {
	uint64_t low;
	uint64_t high;
} cpueaxh_x86_xmm;

typedef struct cpueaxh_x86_ymm {
	cpueaxh_x86_xmm lower;
	cpueaxh_x86_xmm upper;
} cpueaxh_x86_ymm;

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
	uint64_t control_regs[16];
	uint32_t processor_id;
	uint32_t reserved4;
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
#define CPUEAXH_HOOK_MEM_READ 3u
#define CPUEAXH_HOOK_MEM_WRITE 4u
#define CPUEAXH_HOOK_MEM_FETCH 5u
#define CPUEAXH_HOOK_MEM_READ_UNMAPPED 6u
#define CPUEAXH_HOOK_MEM_WRITE_UNMAPPED 7u
#define CPUEAXH_HOOK_MEM_FETCH_UNMAPPED 8u
#define CPUEAXH_HOOK_MEM_READ_PROT 9u
#define CPUEAXH_HOOK_MEM_WRITE_PROT 10u
#define CPUEAXH_HOOK_MEM_FETCH_PROT 11u

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
#define CPUEAXH_ESCAPE_INSN_WRITECRX 13u
#define CPUEAXH_ESCAPE_INSN_READCRX 14u
#define CPUEAXH_ESCAPE_INSN_RDSSPD 15u
#define CPUEAXH_ESCAPE_INSN_RDSSPQ 16u

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
#define CPUEAXH_X86_REG_CR0 21
#define CPUEAXH_X86_REG_CR2 22
#define CPUEAXH_X86_REG_CR3 23
#define CPUEAXH_X86_REG_CR4 24
#define CPUEAXH_X86_REG_CR8 25
#define CPUEAXH_X86_REG_XMM0 26
#define CPUEAXH_X86_REG_XMM1 27
#define CPUEAXH_X86_REG_XMM2 28
#define CPUEAXH_X86_REG_XMM3 29
#define CPUEAXH_X86_REG_XMM4 30
#define CPUEAXH_X86_REG_XMM5 31
#define CPUEAXH_X86_REG_XMM6 32
#define CPUEAXH_X86_REG_XMM7 33
#define CPUEAXH_X86_REG_XMM8 34
#define CPUEAXH_X86_REG_XMM9 35
#define CPUEAXH_X86_REG_XMM10 36
#define CPUEAXH_X86_REG_XMM11 37
#define CPUEAXH_X86_REG_XMM12 38
#define CPUEAXH_X86_REG_XMM13 39
#define CPUEAXH_X86_REG_XMM14 40
#define CPUEAXH_X86_REG_XMM15 41
#define CPUEAXH_X86_REG_YMM0 42
#define CPUEAXH_X86_REG_YMM1 43
#define CPUEAXH_X86_REG_YMM2 44
#define CPUEAXH_X86_REG_YMM3 45
#define CPUEAXH_X86_REG_YMM4 46
#define CPUEAXH_X86_REG_YMM5 47
#define CPUEAXH_X86_REG_YMM6 48
#define CPUEAXH_X86_REG_YMM7 49
#define CPUEAXH_X86_REG_YMM8 50
#define CPUEAXH_X86_REG_YMM9 51
#define CPUEAXH_X86_REG_YMM10 52
#define CPUEAXH_X86_REG_YMM11 53
#define CPUEAXH_X86_REG_YMM12 54
#define CPUEAXH_X86_REG_YMM13 55
#define CPUEAXH_X86_REG_YMM14 56
#define CPUEAXH_X86_REG_YMM15 57
#define CPUEAXH_X86_REG_MM0 58
#define CPUEAXH_X86_REG_MM1 59
#define CPUEAXH_X86_REG_MM2 60
#define CPUEAXH_X86_REG_MM3 61
#define CPUEAXH_X86_REG_MM4 62
#define CPUEAXH_X86_REG_MM5 63
#define CPUEAXH_X86_REG_MM6 64
#define CPUEAXH_X86_REG_MM7 65
#define CPUEAXH_X86_REG_MXCSR 66
#define CPUEAXH_X86_REG_ES_SELECTOR 67
#define CPUEAXH_X86_REG_CS_SELECTOR 68
#define CPUEAXH_X86_REG_SS_SELECTOR 69
#define CPUEAXH_X86_REG_DS_SELECTOR 70
#define CPUEAXH_X86_REG_FS_SELECTOR 71
#define CPUEAXH_X86_REG_ES_BASE 72
#define CPUEAXH_X86_REG_CS_BASE 73
#define CPUEAXH_X86_REG_SS_BASE 74
#define CPUEAXH_X86_REG_DS_BASE 75
#define CPUEAXH_X86_REG_FS_BASE 76
#define CPUEAXH_X86_REG_GDTR_BASE 77
#define CPUEAXH_X86_REG_GDTR_LIMIT 78
#define CPUEAXH_X86_REG_LDTR_BASE 79
#define CPUEAXH_X86_REG_LDTR_LIMIT 80
#define CPUEAXH_X86_REG_EXCEPTION_CODE 81
#define CPUEAXH_X86_REG_EXCEPTION_ERROR_CODE 82
#define CPUEAXH_X86_REG_CR1 83
#define CPUEAXH_X86_REG_CR5 84
#define CPUEAXH_X86_REG_CR6 85
#define CPUEAXH_X86_REG_CR7 86
#define CPUEAXH_X86_REG_CR9 87
#define CPUEAXH_X86_REG_CR10 88
#define CPUEAXH_X86_REG_CR11 89
#define CPUEAXH_X86_REG_CR12 90
#define CPUEAXH_X86_REG_CR13 91
#define CPUEAXH_X86_REG_CR14 92
#define CPUEAXH_X86_REG_CR15 93
#define CPUEAXH_X86_REG_PROCESSOR_ID 94
#define CPUEAXH_X86_REG_ES_LIMIT 95
#define CPUEAXH_X86_REG_ES_TYPE 96
#define CPUEAXH_X86_REG_ES_DPL 97
#define CPUEAXH_X86_REG_ES_PRESENT 98
#define CPUEAXH_X86_REG_ES_GRANULARITY 99
#define CPUEAXH_X86_REG_ES_DB 100
#define CPUEAXH_X86_REG_ES_LONG_MODE 101
#define CPUEAXH_X86_REG_CS_LIMIT 102
#define CPUEAXH_X86_REG_CS_TYPE 103
#define CPUEAXH_X86_REG_CS_DPL 104
#define CPUEAXH_X86_REG_CS_PRESENT 105
#define CPUEAXH_X86_REG_CS_GRANULARITY 106
#define CPUEAXH_X86_REG_CS_DB 107
#define CPUEAXH_X86_REG_CS_LONG_MODE 108
#define CPUEAXH_X86_REG_SS_LIMIT 109
#define CPUEAXH_X86_REG_SS_TYPE 110
#define CPUEAXH_X86_REG_SS_DPL 111
#define CPUEAXH_X86_REG_SS_PRESENT 112
#define CPUEAXH_X86_REG_SS_GRANULARITY 113
#define CPUEAXH_X86_REG_SS_DB 114
#define CPUEAXH_X86_REG_SS_LONG_MODE 115
#define CPUEAXH_X86_REG_DS_LIMIT 116
#define CPUEAXH_X86_REG_DS_TYPE 117
#define CPUEAXH_X86_REG_DS_DPL 118
#define CPUEAXH_X86_REG_DS_PRESENT 119
#define CPUEAXH_X86_REG_DS_GRANULARITY 120
#define CPUEAXH_X86_REG_DS_DB 121
#define CPUEAXH_X86_REG_DS_LONG_MODE 122
#define CPUEAXH_X86_REG_FS_LIMIT 123
#define CPUEAXH_X86_REG_FS_TYPE 124
#define CPUEAXH_X86_REG_FS_DPL 125
#define CPUEAXH_X86_REG_FS_PRESENT 126
#define CPUEAXH_X86_REG_FS_GRANULARITY 127
#define CPUEAXH_X86_REG_FS_DB 128
#define CPUEAXH_X86_REG_FS_LONG_MODE 129
#define CPUEAXH_X86_REG_GS_LIMIT 130
#define CPUEAXH_X86_REG_GS_TYPE 131
#define CPUEAXH_X86_REG_GS_DPL 132
#define CPUEAXH_X86_REG_GS_PRESENT 133
#define CPUEAXH_X86_REG_GS_GRANULARITY 134
#define CPUEAXH_X86_REG_GS_DB 135
#define CPUEAXH_X86_REG_GS_LONG_MODE 136

#ifdef __cplusplus
extern "C" {
#endif

cpueaxh_err cpueaxh_open(uint32_t arch, uint32_t mode, cpueaxh_engine** out_engine);
void cpueaxh_close(cpueaxh_engine* engine);

cpueaxh_err cpueaxh_set_memory_mode(cpueaxh_engine* engine, uint32_t memory_mode);
cpueaxh_err cpueaxh_host_write_isolation_set(cpueaxh_engine* engine, uint32_t enabled);
cpueaxh_err cpueaxh_host_write_isolation_group_create(cpueaxh_engine* engine, cpueaxh_write_isolation_handle* out_group);
cpueaxh_err cpueaxh_host_write_isolation_group_select(cpueaxh_engine* engine, cpueaxh_write_isolation_handle group);
cpueaxh_err cpueaxh_host_write_isolation_group_delete(cpueaxh_engine* engine, cpueaxh_write_isolation_handle group);
cpueaxh_err cpueaxh_host_write_isolation_exempt_add(cpueaxh_engine* engine, uint64_t address, size_t size);
cpueaxh_err cpueaxh_host_write_isolation_exempt_del(cpueaxh_engine* engine, uint64_t address, size_t size);

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
cpueaxh_err cpueaxh_context_write(cpueaxh_engine* engine, const cpueaxh_x86_context* context);
cpueaxh_err cpueaxh_context_read(const cpueaxh_engine* engine, cpueaxh_x86_context* context);
cpueaxh_err cpueaxh_set_processor_id(cpueaxh_engine* engine, uint32_t processor_id);

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
