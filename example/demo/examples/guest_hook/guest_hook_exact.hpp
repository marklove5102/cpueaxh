void guest_exact_address_hook(cpueaxh_engine* engine, uint64_t address, void* user_data) {
    (void)engine;
    (void)user_data;

    std::cout << "exact hook hit @ 0x"
        << std::hex << std::setfill('0') << std::setw(16) << address
        << std::dec << std::endl;
}

void run_guest_hook_exact_demo() {
    cpueaxh_engine* engine = 0;
    if (!setup_guest_hook_demo(&engine)) {
        return;
    }

    cpueaxh_hook exact_hook = 0;
    cpueaxh_err err = cpueaxh_hook_add_address(engine, &exact_hook, CPUEAXH_HOOK_CODE_PRE, (void*)guest_exact_address_hook, 0, GUEST_HOOK_EXACT_ADDRESS);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_hook_add_address(code_pre) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    run_guest_hook_demo_common(engine, "guest hook exact before");
    cpueaxh_hook_del(engine, exact_hook);
    cpueaxh_close(engine);
}