void run_simple_function_demo() {
    cpueaxh_engine* engine = 0;
    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_open failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        return;
    }

    err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_GUEST);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_set_memory_mode(guest) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    constexpr uint64_t code_base = 0x100000;
    constexpr uint64_t stack_base = 0x200000;
    constexpr uint64_t stack_size = 0x1000;
    constexpr uint8_t code[] = {
        0x48, 0x89, 0xC8,
        0x48, 0x01, 0xD0,
        0x48, 0x83, 0xE8, 0x05,
        0x49, 0x89, 0xC0,
        0x4D, 0x31, 0xC9,
        0x90,
    };

    err = cpueaxh_mem_map(engine, code_base, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_map(code) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    err = cpueaxh_mem_write(engine, code_base, code, sizeof(code));
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_write(code) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    err = cpueaxh_mem_map(engine, stack_base, stack_size, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_mem_map(stack) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    uint64_t value = stack_base + stack_size - 0x80;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RSP, &value);
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RBP, &value);

    value = 0x123456789ABCDEF0ull;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RCX, &value);

    value = 0x1111111111111111ull;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RDX, &value);

    value = 0x2222222222222222ull;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R8, &value);

    value = 0x3333333333333333ull;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_R9, &value);

    value = code_base;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RIP, &value);

    value = 0x202ull;
    cpueaxh_reg_write(engine, CPUEAXH_X86_REG_EFLAGS, &value);

    print_context(engine, "guest mode before");

    err = cpueaxh_emu_start(engine, code_base, code_base + sizeof(code), 0, 0);
    std::cout << "guest mode result: " << cpueaxh_err_string(err)
        << " (" << err << ")" << std::endl;

    print_context(engine, "guest mode after");

    cpueaxh_close(engine);
}