void guest_code_post_hook(cpueaxh_engine* engine, uint64_t address, void* user_data) {
    (void)user_data;

    uint64_t rip = 0;
    cpueaxh_err err = cpueaxh_reg_read(engine, CPUEAXH_X86_REG_RIP, &rip);

    std::cout << "post @ 0x"
        << std::hex << std::setfill('0') << std::setw(16) << address;

    if (err != CPUEAXH_ERR_OK) {
        std::cout << " -> <rip read failed: " << cpueaxh_err_string(err)
            << " (" << err << ")>";
    }
    else {
        std::cout << " -> rip=0x" << std::setw(16) << rip;
    }

    std::cout << std::dec << std::endl;
}

void run_guest_hook_post_demo() {
    cpueaxh_engine* engine = 0;
    if (!setup_guest_hook_demo(&engine)) {
        return;
    }

    cpueaxh_hook hook_post = 0;
    cpueaxh_err err = cpueaxh_hook_add(engine, &hook_post, CPUEAXH_HOOK_CODE_POST, (void*)guest_code_post_hook, 0, GUEST_HOOK_CODE_BASE, GUEST_HOOK_CODE_BASE + sizeof(GUEST_HOOK_CODE) - 1);
    if (err != CPUEAXH_ERR_OK) {
        std::cerr << "cpueaxh_hook_add(code_post) failed: " << cpueaxh_err_string(err)
            << " (" << err << ")" << std::endl;
        cpueaxh_close(engine);
        return;
    }

    run_guest_hook_demo_common(engine, "guest hook post before");
    cpueaxh_hook_del(engine, hook_post);
    cpueaxh_close(engine);
}