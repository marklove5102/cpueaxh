#pragma once

extern "C" cpueaxh_err cpueaxh_host_call(cpueaxh_x86_context* context, cpueaxh_cb_host_bridge_t bridge);
extern "C" void __int2d();
extern "C" void __readcr0_rax();
extern "C" void __readcr2_rax();
extern "C" void __readcr3_rax();
extern "C" void __readcr4_rax();
extern "C" void __readcr8_rax();
extern "C" void __writecr0_rax();
extern "C" void __writecr2_rax();
extern "C" void __writecr3_rax();
extern "C" void __writecr4_rax();
extern "C" void __writecr8_rax();

static bool add_host_escape(cpueaxh_engine* engine, cpueaxh_escape_insn_id instruction_id, void* callback) {
	cpueaxh_escape_handle handle = 0;
	return cpueaxh_escape_add(engine, &handle, instruction_id, callback, nullptr, 0, 0) == CPUEAXH_ERR_OK;
}

static cpueaxh_err rdtsc_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	const unsigned __int64 tsc = __rdtsc();
	context->regs[CPUEAXH_X86_REG_RAX] = static_cast<uint32_t>(tsc);
	context->regs[CPUEAXH_X86_REG_RDX] = static_cast<uint32_t>(tsc >> 32);
	return CPUEAXH_ERR_OK;
}

static cpueaxh_err rdtscp_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	unsigned int aux = 0;
	const unsigned __int64 tsc = __rdtscp(&aux);
	context->regs[CPUEAXH_X86_REG_RAX] = static_cast<uint32_t>(tsc);
	context->regs[CPUEAXH_X86_REG_RDX] = static_cast<uint32_t>(tsc >> 32);
	context->regs[CPUEAXH_X86_REG_RCX] = aux;
	return CPUEAXH_ERR_OK;
}

static cpueaxh_err cpuid_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	int cpu_info[4] = {};
	__cpuidex(cpu_info, static_cast<int>(context->regs[CPUEAXH_X86_REG_RAX]), static_cast<int>(context->regs[CPUEAXH_X86_REG_RCX]));
	context->regs[CPUEAXH_X86_REG_RAX] = static_cast<uint32_t>(cpu_info[0]);
	context->regs[CPUEAXH_X86_REG_RBX] = static_cast<uint32_t>(cpu_info[1]);
	context->regs[CPUEAXH_X86_REG_RCX] = static_cast<uint32_t>(cpu_info[2]);
	context->regs[CPUEAXH_X86_REG_RDX] = static_cast<uint32_t>(cpu_info[3]);
	return CPUEAXH_ERR_OK;
}

static bool decode_mov_crx(const uint8_t* instruction, uint8_t expected_opcode, uint8_t* out_control_register, uint8_t* out_general_register) {
	if (!instruction || !out_control_register || !out_general_register) {
		return false;
	}

	uint8_t rex_prefix = 0;
	uint8_t prefix_length = 0;
	bool has_lock_prefix = false;
	while (prefix_length < 15) {
		const uint8_t byte = instruction[prefix_length];
		if (byte >= 0x40 && byte <= 0x4F) {
			rex_prefix = byte;
			prefix_length++;
			continue;
		}
		if (byte == 0xF0) {
			has_lock_prefix = true;
			prefix_length++;
			continue;
		}
		if (byte == 0x26 || byte == 0x2E || byte == 0x36 || byte == 0x3E ||
			byte == 0x64 || byte == 0x65 || byte == 0x66 || byte == 0x67 ||
			byte == 0xF2 || byte == 0xF3) {
			prefix_length++;
			continue;
		}
		break;
	}

	if (has_lock_prefix || instruction[prefix_length] != 0x0F || instruction[prefix_length + 1] != expected_opcode) {
		return false;
	}

	const uint8_t modrm = instruction[prefix_length + 2];
	const uint8_t rex_r = (rex_prefix & 0x04) != 0 ? 1 : 0;
	const uint8_t rex_b = (rex_prefix & 0x01) != 0 ? 1 : 0;
	const uint8_t control_register = (uint8_t)(((modrm >> 3) & 0x07) | (rex_r << 3));
	const uint8_t general_register = (uint8_t)((modrm & 0x07) | (rex_b << 3));

	if ((rex_r != 0 && control_register != 8) ||
		(control_register != 0 && control_register != 2 && control_register != 3 && control_register != 4 && control_register != 8)) {
		return false;
	}

	*out_control_register = control_register;
	*out_general_register = general_register;
	return true;
}

static cpueaxh_cb_host_bridge_t get_readcrx_bridge(uint8_t control_register) {
	switch (control_register) {
	case 0: return __readcr0_rax;
	case 2: return __readcr2_rax;
	case 3: return __readcr3_rax;
	case 4: return __readcr4_rax;
	case 8: return __readcr8_rax;
	default: return nullptr;
	}
}

static cpueaxh_cb_host_bridge_t get_writecrx_bridge(uint8_t control_register) {
	switch (control_register) {
	case 0: return __writecr0_rax;
	case 2: return __writecr2_rax;
	case 3: return __writecr3_rax;
	case 4: return __writecr4_rax;
	case 8: return __writecr8_rax;
	default: return nullptr;
	}
}

static cpueaxh_err readcrx_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	UNREFERENCED_PARAMETER(engine);
	UNREFERENCED_PARAMETER(user_data);

	if (!context || !instruction) {
		return CPUEAXH_ERR_ARG;
	}

	uint8_t control_register = 0;
	uint8_t destination_register = 0;
	if (!decode_mov_crx(instruction, 0x20, &control_register, &destination_register)) {
		context->code_exception = CPUEAXH_EXCEPTION_UD;
		context->error_code_exception = 0;
		return CPUEAXH_ERR_EXCEPTION;
	}

	cpueaxh_cb_host_bridge_t bridge = get_readcrx_bridge(control_register);
	if (!bridge) {
		context->code_exception = CPUEAXH_EXCEPTION_UD;
		context->error_code_exception = 0;
		return CPUEAXH_ERR_EXCEPTION;
	}

	const uint64_t saved_rax = context->regs[CPUEAXH_X86_REG_RAX];
	cpueaxh_err err = cpueaxh_host_call(context, bridge);
	if (err != CPUEAXH_ERR_OK) {
		return err;
	}

	const uint64_t value = context->regs[CPUEAXH_X86_REG_RAX];
	if (destination_register != CPUEAXH_X86_REG_RAX) {
		context->regs[destination_register] = value;
		context->regs[CPUEAXH_X86_REG_RAX] = saved_rax;
	}
	return CPUEAXH_ERR_OK;
}

static cpueaxh_err writecrx_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	UNREFERENCED_PARAMETER(engine);
	UNREFERENCED_PARAMETER(user_data);

	if (!context || !instruction) {
		return CPUEAXH_ERR_ARG;
	}

	uint8_t control_register = 0;
	uint8_t source_register = 0;
	if (!decode_mov_crx(instruction, 0x22, &control_register, &source_register)) {
		context->code_exception = CPUEAXH_EXCEPTION_UD;
		context->error_code_exception = 0;
		return CPUEAXH_ERR_EXCEPTION;
	}

	cpueaxh_cb_host_bridge_t bridge = get_writecrx_bridge(control_register);
	if (!bridge) {
		context->code_exception = CPUEAXH_EXCEPTION_UD;
		context->error_code_exception = 0;
		return CPUEAXH_ERR_EXCEPTION;
	}

	const uint64_t saved_rax = context->regs[CPUEAXH_X86_REG_RAX];
	if (source_register != CPUEAXH_X86_REG_RAX) {
		context->regs[CPUEAXH_X86_REG_RAX] = context->regs[source_register];
	}

	cpueaxh_err err = cpueaxh_host_call(context, bridge);
	if (source_register != CPUEAXH_X86_REG_RAX) {
		context->regs[CPUEAXH_X86_REG_RAX] = saved_rax;
	}
	return err;
}

static cpueaxh_err int_escape_callback(cpueaxh_engine* engine, cpueaxh_x86_context* context, const uint8_t* instruction, void* user_data) {
	UNREFERENCED_PARAMETER(engine);
	UNREFERENCED_PARAMETER(user_data);

	if (!context || !instruction) {
		return CPUEAXH_ERR_ARG;
	}

	if (instruction[0] != 0xCD || instruction[1] != 0x2D) {
		context->code_exception = CPUEAXH_EXCEPTION_UD;
		context->error_code_exception = 0;
		return CPUEAXH_ERR_EXCEPTION;
	}

	cpueaxh_err err = cpueaxh_host_call(context, __int2d);
	if (err != CPUEAXH_ERR_OK) {
		return err;
	}
	context->rip += 3;
	return CPUEAXH_ERR_OK;
}

static bool register_default_host_escapes(cpueaxh_engine* engine) {
	return add_host_escape(engine, CPUEAXH_ESCAPE_INSN_CPUID, (void*)cpuid_escape_callback)
		&& add_host_escape(engine, CPUEAXH_ESCAPE_INSN_RDTSC, (void*)rdtsc_escape_callback)
		&& add_host_escape(engine, CPUEAXH_ESCAPE_INSN_RDTSCP, (void*)rdtscp_escape_callback)
		&& add_host_escape(engine, CPUEAXH_ESCAPE_INSN_READCRX, (void*)readcrx_escape_callback)
		&& add_host_escape(engine, CPUEAXH_ESCAPE_INSN_WRITECRX, (void*)writecrx_escape_callback)
		&& add_host_escape(engine, CPUEAXH_ESCAPE_INSN_INT, (void*)int_escape_callback);
}
