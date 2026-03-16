struct RegisterDescriptor {
    int id;
    const char* name;
};

constexpr RegisterDescriptor g_registers[] = {
    { CPUEAXH_X86_REG_RAX, "RAX" },
    { CPUEAXH_X86_REG_RBX, "RBX" },
    { CPUEAXH_X86_REG_RCX, "RCX" },
    { CPUEAXH_X86_REG_RDX, "RDX" },
    { CPUEAXH_X86_REG_RSI, "RSI" },
    { CPUEAXH_X86_REG_RDI, "RDI" },
    { CPUEAXH_X86_REG_RBP, "RBP" },
    { CPUEAXH_X86_REG_RSP, "RSP" },
    { CPUEAXH_X86_REG_R8, "R8 " },
    { CPUEAXH_X86_REG_R9, "R9 " },
    { CPUEAXH_X86_REG_R10, "R10" },
    { CPUEAXH_X86_REG_R11, "R11" },
    { CPUEAXH_X86_REG_R12, "R12" },
    { CPUEAXH_X86_REG_R13, "R13" },
    { CPUEAXH_X86_REG_R14, "R14" },
    { CPUEAXH_X86_REG_R15, "R15" },
    { CPUEAXH_X86_REG_RIP, "RIP" },
    { CPUEAXH_X86_REG_EFLAGS, "RFL" },
};

const char* cpueaxh_err_string(cpueaxh_err err) {
    switch (err) {
    case CPUEAXH_ERR_OK:
        return "CPUEAXH_ERR_OK";
    case CPUEAXH_ERR_NOMEM:
        return "CPUEAXH_ERR_NOMEM";
    case CPUEAXH_ERR_ARG:
        return "CPUEAXH_ERR_ARG";
    case CPUEAXH_ERR_ARCH:
        return "CPUEAXH_ERR_ARCH";
    case CPUEAXH_ERR_MODE:
        return "CPUEAXH_ERR_MODE";
    case CPUEAXH_ERR_MAP:
        return "CPUEAXH_ERR_MAP";
    case CPUEAXH_ERR_READ_UNMAPPED:
        return "CPUEAXH_ERR_READ_UNMAPPED";
    case CPUEAXH_ERR_WRITE_UNMAPPED:
        return "CPUEAXH_ERR_WRITE_UNMAPPED";
    case CPUEAXH_ERR_FETCH_UNMAPPED:
        return "CPUEAXH_ERR_FETCH_UNMAPPED";
    case CPUEAXH_ERR_EXCEPTION:
        return "CPUEAXH_ERR_EXCEPTION";
    case CPUEAXH_ERR_HOOK:
        return "CPUEAXH_ERR_HOOK";
    case CPUEAXH_ERR_READ_PROT:
        return "CPUEAXH_ERR_READ_PROT";
    case CPUEAXH_ERR_WRITE_PROT:
        return "CPUEAXH_ERR_WRITE_PROT";
    case CPUEAXH_ERR_FETCH_PROT:
        return "CPUEAXH_ERR_FETCH_PROT";
    case CPUEAXH_ERR_PATCH:
        return "CPUEAXH_ERR_PATCH";
    default:
        return "CPUEAXH_ERR_UNKNOWN";
    }
}

void print_context(cpueaxh_engine* engine, const char* title) {
    const size_t register_count = sizeof(g_registers) / sizeof(g_registers[0]);

    std::cout << "\n--- " << title << " ---" << std::endl;
    std::cout << std::hex << std::setfill('0');

    for (size_t index = 0; index < register_count; ++index) {
        uint64_t value = 0;
        cpueaxh_err err = cpueaxh_reg_read(engine, g_registers[index].id, &value);
        if (err != CPUEAXH_ERR_OK) {
            std::cerr << "cpueaxh_reg_read failed: " << cpueaxh_err_string(err)
                << " (" << err << ")" << std::endl;
            std::cout << std::dec;
            return;
        }

        std::cout << g_registers[index].name << "=0x"
            << std::setw(16) << value;

        if ((index % 3) == 2 || index + 1 == register_count) {
            std::cout << std::endl;
        }
        else {
            std::cout << "  ";
        }
    }

    std::cout << "EXC=0x" << std::setw(8) << cpueaxh_code_exception(engine)
        << "  ERR=0x" << std::setw(8) << cpueaxh_error_code_exception(engine)
        << std::endl;
    std::cout << std::dec;
}