bool add_host_escape(cpueaxh_engine* engine, cpueaxh_escape_insn_id instruction_id, void* callback, const char* name) {
    cpueaxh_escape_handle escape_handle = 0;
    cpueaxh_err err = cpueaxh_escape_add(engine, &escape_handle, instruction_id, callback, 0, 0, 0);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_escape_add(" << name << ") failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        return false;
    }
    return true;
}

bool register_default_host_escapes(cpueaxh_engine* engine) {
    return add_host_escape(engine, CPUEAXH_ESCAPE_INSN_SYSCALL, (void*)syscall_escape_callback, "syscall")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_SYSENTER, (void*)sysenter_escape_callback, "sysenter")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_INT, (void*)int_escape_callback, "int")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_INT3, (void*)int3_escape_callback, "int3")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_CPUID, (void*)cpuid_escape_callback, "cpuid")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_XGETBV, (void*)xgetbv_escape_callback, "xgetbv")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_RDTSC, (void*)rdtsc_escape_callback, "rdtsc")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_RDTSCP, (void*)rdtscp_escape_callback, "rdtscp")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_RDRAND, (void*)rdrand_escape_callback, "rdrand")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_HLT, (void*)hlt_escape_callback, "hlt")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_IN, (void*)in_escape_callback, "in")
        && add_host_escape(engine, CPUEAXH_ESCAPE_INSN_OUT, (void*)out_escape_callback, "out");
}

bool setup_host_message_box_engine(cpueaxh_engine** out_engine, void** out_stack_base, const char* text, const char* caption) {
    cpueaxh_engine* engine = 0;
    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_open failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        return false;
    }

    err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_HOST);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_set_memory_mode(host) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return false;
    }

    void* stack_base = VirtualAlloc(0, 0x400000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!stack_base) {
        std::cerr << "VirtualAlloc(stack) failed" << std::endl;
        cpueaxh_close(engine);
        return false;
    }

    uint64_t value = (uint64_t)stack_base + 0x400000 - 0x80 - sizeof(uint64_t);
    *(uint64_t*)value = 0;

    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RSP, &value);
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RBP, &value);

    CONTEXT context{};
    RtlCaptureContext(&context);

    value = (uint64_t)context.SegGs;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_GS_SELECTOR, &value);

    value = (uint64_t)NtCurrentTeb();
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_GS_BASE, &value);

    value = 0;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RCX, &value);

    value = (uint64_t)text;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RDX, &value);

    value = (uint64_t)caption;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R8, &value);

    value = MB_OK;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R9, &value);

    value = (uint64_t)MessageBoxA;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RIP, &value);

    *out_engine = engine;
    *out_stack_base = stack_base;
    return true;
}

void cleanup_host_message_box_engine(cpueaxh_engine* engine, void* stack_base) {
    if (stack_base) {
        VirtualFree(stack_base, 0, MEM_RELEASE);
    }
    if (engine) {
        cpueaxh_close(engine);
    }
}

void run_message_box_demo() {
    static const char text[] = "cpueaxh host mode text";
    static const char caption[] = "cpueaxh host mode caption";

    cpueaxh_engine* engine = 0;
    void* stack_base = 0;
    if (!setup_host_message_box_engine(&engine, &stack_base, text, caption)) {
        return;
    }
    if (!register_default_host_escapes(engine)) {
        cleanup_host_message_box_engine(engine, stack_base);
        return;
    }

    print_context(engine, "host mode before");

    // cpueaxh_emu_start_function presets a magic return address on the stack and treats execution reaching that address as a normal function return.
    cpueaxh_err err = cpueaxh_emu_start_function(engine, 0, 0, 100000000);
    std::cout << "host mode result: " << cpueaxh_err_string(err)
        << " (" << err << ")" << std::endl;

    print_context(engine, "host mode after");
    cleanup_host_message_box_engine(engine, stack_base);
}

void run_message_box_patch_demo() {
    static const char text[] = "cpueaxh host mode text";
    static const char caption[] = "cpueaxh host mode caption";
    static const char patched_text[] = "patched host text";
    static const char patched_caption[] = "patched caption";

    cpueaxh_engine* engine = 0;
    void* stack_base = 0;
    if (!setup_host_message_box_engine(&engine, &stack_base, text, caption)) {
        return;
    }
    if (!register_default_host_escapes(engine)) {
        cleanup_host_message_box_engine(engine, stack_base);
        return;
    }

    cpueaxh_mem_patch_handle text_patch = 0;
    cpueaxh_err err = cpueaxh_mem_patch_add(engine, &text_patch, (uint64_t)text, patched_text, sizeof(patched_text));
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_patch_add(text) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cleanup_host_message_box_engine(engine, stack_base);
        return;
    }

    cpueaxh_mem_patch_handle caption_patch = 0;
    err = cpueaxh_mem_patch_add(engine, &caption_patch, (uint64_t)caption, patched_caption, sizeof(patched_caption));
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_patch_add(caption) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_mem_patch_del(engine, text_patch);
        cleanup_host_message_box_engine(engine, stack_base);
        return;
    }

    std::cout << "Original host text: " << text << std::endl;
    std::cout << "Original host caption: " << caption << std::endl;
    std::cout << "Patched text shown to emulation: " << patched_text << std::endl;
    std::cout << "Patched caption shown to emulation: " << patched_caption << std::endl;

    print_context(engine, "host patch before");

    // cpueaxh_emu_start_function presets a magic return address on the stack and treats execution reaching that address as a normal function return.
    err = cpueaxh_emu_start_function(engine, 0, 0, 100000000);
    std::cout << "host patch result: " << cpueaxh_err_string(err)
        << " (" << err << ")" << std::endl;

    print_context(engine, "host patch after");

    cpueaxh_err patch_del_err = cpueaxh_mem_patch_del(engine, caption_patch);
    if (patch_del_err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_patch_del(caption) failed: " << cpueaxh_err_string(patch_del_err)
            << " (" << patch_del_err << ")" << std::endl;
    }

    patch_del_err = cpueaxh_mem_patch_del(engine, text_patch);
    if (patch_del_err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_patch_del(text) failed: " << cpueaxh_err_string(patch_del_err)
            << " (" << patch_del_err << ")" << std::endl;
    }

    std::cout << "Host memory after deleting patches still reads: " << text
        << " / " << caption << std::endl;

    cleanup_host_message_box_engine(engine, stack_base);
}