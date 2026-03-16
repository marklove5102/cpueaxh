void guest_code_trace_hook(cpueaxh_engine* engine, uint64_t address, void* user_data) {
    (void)user_data;

    uint8_t bytes[16] = {};
    cpueaxh_err err = cpueaxh_mem_read(engine, address, bytes, sizeof(bytes));

    std::cout << "hook @ 0x"
        << std::hex << std::setfill('0') << std::setw(16) << address
        << " : ";

    if (err != CPUEAXH_ERR_OK) {
        std::cout << "<read failed: " << cpueaxh_err_string(err)
            << " (" << err << ")>";
    }
    else {
        for (size_t index = 0; index < sizeof(bytes); ++index) {
            if (index != 0) {
                std::cout << ' ';
            }
            std::cout << std::setw(2) << (unsigned int)bytes[index];
        }
    }

    std::cout << std::dec << std::endl;
}

void run_guest_hook_pre_demo() {
    cpueaxh_engine* engine = 0;
    if (!setup_guest_hook_demo(&engine)) {
        return;
    }

    cpueaxh_hook hook_pre = 0;
    cpueaxh_err err = cpueaxh_hook_add(engine, &hook_pre, CPUEAXH_HOOK_CODE_PRE, (void*)guest_code_trace_hook, 0, GUEST_HOOK_CODE_BASE, GUEST_HOOK_CODE_BASE + sizeof(GUEST_HOOK_CODE) - 1);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_hook_add(code_pre) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    run_guest_hook_demo_common(engine, "guest hook pre before");
    cpueaxh_hook_del(engine, hook_pre);
    cpueaxh_close(engine);
}