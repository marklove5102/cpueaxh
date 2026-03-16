#pragma once

static void seed_host_control_registers(cpueaxh_engine* engine) {
	uint64_t value = __readcr0();
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_CR0, &value);
	value = __readcr2();
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_CR2, &value);
	value = __readcr3();
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_CR3, &value);
	value = __readcr4();
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_CR4, &value);
	value = __readcr8();
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_CR8, &value);
}

static bool setup_host_dbgprint_engine(cpueaxh_engine** out_engine, void** out_stack_base) {
	if (!out_engine || !out_stack_base) {
		return false;
	}

	static const char host_message[] = "cpueaxh host-mode DbgPrintEx";
	cpueaxh_engine* engine = nullptr;
	cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
	if (err != CPUEAXH_ERR_OK) {
		return false;
	}

	err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_HOST);
	if (err != CPUEAXH_ERR_OK || !register_default_host_escapes(engine)) {
		cpueaxh_close(engine);
		return false;
	}

	void* stack_base = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'haxE');
	if (!stack_base) {
		cpueaxh_close(engine);
		return false;
	}

	RtlZeroMemory(stack_base, 0x4000);
	uint64_t value = (uint64_t)stack_base + 0x4000 - 0x80 - sizeof(uint64_t);
	*(uint64_t*)value = 0;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RSP, &value);
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RBP, &value);
	value = __readmsr(0xC0000101);
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_GS_BASE, &value);
	seed_host_control_registers(engine);
	value = DPFLTR_IHVDRIVER_ID;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RCX, &value);
	value = DPFLTR_ERROR_LEVEL;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RDX, &value);
	value = (uint64_t)host_message;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R8, &value);
	value = 0;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R9, &value);
	value = (uint64_t)DbgPrintEx;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RIP, &value);
	value = 0x202ull;
	cpueaxh_reg_write(engine, CPUEAXH_X86_REG_EFLAGS, &value);

	*out_engine = engine;
	*out_stack_base = stack_base;
	return true;
}

static void cleanup_host_dbgprint_engine(cpueaxh_engine* engine, void* stack_base) {
	if (stack_base) {
		ExFreePoolWithTag(stack_base, 'haxE');
	}
	if (engine) {
		cpueaxh_close(engine);
	}
}

static cpueaxh_err run_host_dbgprint_demo_at_current_irql() {
	cpueaxh_engine* engine = nullptr;
	void* stack_base = nullptr;
	if (!setup_host_dbgprint_engine(&engine, &stack_base)) {
		return CPUEAXH_ERR_HOOK;
	}

	cpueaxh_err err = cpueaxh_emu_start_function(engine, 0, 0, 1000000);
	if (err == CPUEAXH_ERR_OK) {
		uint64_t result = 0;
		cpueaxh_reg_read(engine, CPUEAXH_X86_REG_RAX, &result);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"kexample: host-mode DbgPrintEx completed at IRQL=%lu, return=0x%llX\n",
			KeGetCurrentIrql(),
			result);
	}
	else {
		uint64_t rip = 0;
		cpueaxh_reg_read(engine, CPUEAXH_X86_REG_RIP, &rip);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"kexample: host-mode DbgPrintEx failed: %s (%d), RIP=0x%llX, exception=0x%08X, error=0x%08X\n",
			kexample_err_string(err),
			err,
			rip,
			cpueaxh_code_exception(engine),
			cpueaxh_error_code_exception(engine));
	}

	cleanup_host_dbgprint_engine(engine, stack_base);
	return err;
}
