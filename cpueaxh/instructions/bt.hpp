// instrusments/bt.hpp - BT/BTS/BTR/BTC instruction implementation

enum BitTestOperation {
    BIT_TEST_OP_BT,
    BIT_TEST_OP_BTS,
    BIT_TEST_OP_BTR,
    BIT_TEST_OP_BTC,
};

int decode_bt_rm_index(CPU_CONTEXT* ctx, uint8_t modrm) {
    int rm = modrm & 0x07;
    if (ctx->rex_b) {
        rm |= 0x08;
    }
    return rm;
}

int decode_bt_reg_index(CPU_CONTEXT* ctx, uint8_t modrm) {
    int reg = (modrm >> 3) & 0x07;
    if (ctx->rex_r) {
        reg |= 0x08;
    }
    return reg;
}

uint64_t get_bt_operand_mask(int operand_size) {
    switch (operand_size) {
    case 16: return 0xFFFFULL;
    case 32: return 0xFFFFFFFFULL;
    case 64: return 0xFFFFFFFFFFFFFFFFULL;
    default: raise_ud(); return 0;
    }
}

uint64_t read_bt_memory_value(CPU_CONTEXT* ctx, uint64_t address, int operand_size) {
    switch (operand_size) {
    case 16: return read_memory_word(ctx, address);
    case 32: return read_memory_dword(ctx, address);
    case 64: return read_memory_qword(ctx, address);
    default: raise_ud(); return 0;
    }
}

void write_bt_memory_value(CPU_CONTEXT* ctx, uint64_t address, int operand_size, uint64_t value) {
    switch (operand_size) {
    case 16:
        write_memory_word(ctx, address, (uint16_t)value);
        break;
    case 32:
        write_memory_dword(ctx, address, (uint32_t)value);
        break;
    case 64:
        write_memory_qword(ctx, address, value);
        break;
    default:
        raise_ud();
    }
}

uint64_t read_bt_rm_value(CPU_CONTEXT* ctx, uint8_t modrm, uint64_t mem_addr, int operand_size) {
    uint8_t mod = (modrm >> 6) & 0x03;
    if (mod == 3) {
        int rm = decode_bt_rm_index(ctx, modrm);
        switch (operand_size) {
        case 16: return get_reg16(ctx, rm);
        case 32: return get_reg32(ctx, rm);
        case 64: return get_reg64(ctx, rm);
        default: raise_ud(); return 0;
        }
    }

    return read_bt_memory_value(ctx, mem_addr, operand_size);
}

void write_bt_rm_value(CPU_CONTEXT* ctx, uint8_t modrm, uint64_t mem_addr, int operand_size, uint64_t value) {
    uint8_t mod = (modrm >> 6) & 0x03;
    if (mod == 3) {
        int rm = decode_bt_rm_index(ctx, modrm);
        switch (operand_size) {
        case 16:
            set_reg16(ctx, rm, (uint16_t)value);
            break;
        case 32:
            set_reg32(ctx, rm, (uint32_t)value);
            break;
        case 64:
            set_reg64(ctx, rm, value);
            break;
        default:
            raise_ud();
        }
        return;
    }

    write_bt_memory_value(ctx, mem_addr, operand_size, value);
}

int64_t sign_extend_bt_source(uint64_t value, int operand_size) {
    switch (operand_size) {
    case 16: return (int16_t)value;
    case 32: return (int32_t)value;
    case 64: return (int64_t)value;
    default: raise_ud(); return 0;
    }
}

int64_t floor_div_bt_index(int64_t value, int divisor) {
    if (value >= 0) {
        return value / divisor;
    }

    uint64_t magnitude = (uint64_t)(-(value + 1)) + 1ULL;
    return -(int64_t)((magnitude + (uint64_t)divisor - 1ULL) / (uint64_t)divisor);
}

uint64_t add_bt_signed_offset(uint64_t base, int64_t byte_offset) {
    if (byte_offset >= 0) {
        return base + (uint64_t)byte_offset;
    }
    return base - (uint64_t)(-byte_offset);
}

BitTestOperation decode_bt_operation(uint8_t opcode, uint8_t modrm) {
    switch (opcode) {
    case 0xA3:
        return BIT_TEST_OP_BT;
    case 0xAB:
        return BIT_TEST_OP_BTS;
    case 0xB3:
        return BIT_TEST_OP_BTR;
    case 0xBB:
        return BIT_TEST_OP_BTC;
    case 0xBA:
        switch ((modrm >> 3) & 0x07) {
        case 4: return BIT_TEST_OP_BT;
        case 5: return BIT_TEST_OP_BTS;
        case 6: return BIT_TEST_OP_BTR;
        case 7: return BIT_TEST_OP_BTC;
        default: raise_ud(); return BIT_TEST_OP_BT;
        }
    default:
        raise_ud();
        return BIT_TEST_OP_BT;
    }
}

bool bt_operation_allows_lock(BitTestOperation operation, uint8_t modrm) {
    if (operation == BIT_TEST_OP_BT) {
        return false;
    }
    return ((modrm >> 6) & 0x03) != 3;
}

uint64_t read_bt_source_register(CPU_CONTEXT* ctx, uint8_t modrm, int operand_size) {
    int reg = decode_bt_reg_index(ctx, modrm);
    switch (operand_size) {
    case 16: return get_reg16(ctx, reg);
    case 32: return get_reg32(ctx, reg);
    case 64: return get_reg64(ctx, reg);
    default: raise_ud(); return 0;
    }
}

bool execute_locked_bt_memory(CPU_CONTEXT* ctx, BitTestOperation operation, uint64_t address, int operand_size, unsigned int bit_index) {
    switch (operand_size) {
    case 16: {
        uint16_t old_value = read_memory_word(ctx, address);
        if (cpu_has_exception(ctx)) {
            return true;
        }

        bool carry = (old_value & (uint16_t)(1u << bit_index)) != 0;
        uint16_t new_value = old_value;

        switch (operation) {
        case BIT_TEST_OP_BT:
            set_flag(ctx, RFLAGS_CF, carry);
            return true;
        case BIT_TEST_OP_BTS:
            new_value = (uint16_t)(old_value | (uint16_t)(1u << bit_index));
            break;
        case BIT_TEST_OP_BTR:
            new_value = (uint16_t)(old_value & (uint16_t)~(1u << bit_index));
            break;
        case BIT_TEST_OP_BTC:
            new_value = (uint16_t)(old_value ^ (uint16_t)(1u << bit_index));
            break;
        }

        write_memory_word(ctx, address, new_value);
        set_flag(ctx, RFLAGS_CF, carry);
        return true;
    }
    case 32: {
        uint32_t old_value = read_memory_dword(ctx, address);
        if (cpu_has_exception(ctx)) {
            return true;
        }

        bool carry = ((old_value >> bit_index) & 1u) != 0;
        uint32_t new_value = old_value;

        switch (operation) {
        case BIT_TEST_OP_BT:
            set_flag(ctx, RFLAGS_CF, carry);
            return true;
        case BIT_TEST_OP_BTS:
            new_value = old_value | (1u << bit_index);
            break;
        case BIT_TEST_OP_BTR:
            new_value = old_value & ~(1u << bit_index);
            break;
        case BIT_TEST_OP_BTC:
            new_value = old_value ^ (1u << bit_index);
            break;
        }

        write_memory_dword(ctx, address, new_value);
        set_flag(ctx, RFLAGS_CF, carry);
        return true;
    }
    case 64: {
        uint64_t old_value = read_memory_qword(ctx, address);
        if (cpu_has_exception(ctx)) {
            return true;
        }

        bool carry = ((old_value >> bit_index) & 1ULL) != 0;
        uint64_t new_value = old_value;

        switch (operation) {
        case BIT_TEST_OP_BT:
            set_flag(ctx, RFLAGS_CF, carry);
            return true;
        case BIT_TEST_OP_BTS:
            new_value = old_value | (1ULL << bit_index);
            break;
        case BIT_TEST_OP_BTR:
            new_value = old_value & ~(1ULL << bit_index);
            break;
        case BIT_TEST_OP_BTC:
            new_value = old_value ^ (1ULL << bit_index);
            break;
        }

        write_memory_qword(ctx, address, new_value);
        set_flag(ctx, RFLAGS_CF, carry);
        return true;
    }
    default:
        raise_ud();
        return true;
    }

    raise_ud();
    return true;
}

void execute_bt_operation(CPU_CONTEXT* ctx, const DecodedInstruction* inst) {
    BitTestOperation operation = decode_bt_operation(inst->opcode, inst->modrm);
    uint8_t mod = (inst->modrm >> 6) & 0x03;
    int operand_bits = inst->operand_size;
    uint64_t operand_mask = get_bt_operand_mask(operand_bits);
    unsigned int bit_index = 0;
    uint64_t target_value = 0;
    uint64_t target_address = inst->mem_address;

    if (mod == 3) {
        uint64_t raw_index = (inst->opcode == 0xBA)
            ? (inst->immediate & 0xFFULL)
            : read_bt_source_register(ctx, inst->modrm, operand_bits);
        bit_index = (unsigned int)(raw_index & (uint64_t)(operand_bits - 1));
        target_value = read_bt_rm_value(ctx, inst->modrm, inst->mem_address, operand_bits) & operand_mask;
    }
    else {
        if (inst->opcode == 0xBA) {
            bit_index = (unsigned int)((inst->immediate & 0xFFULL) & (uint64_t)(operand_bits - 1));
        }
        else {
            int64_t source_index = sign_extend_bt_source(read_bt_source_register(ctx, inst->modrm, operand_bits), operand_bits);
            int64_t element_index = floor_div_bt_index(source_index, operand_bits);
            int64_t byte_offset = element_index * (operand_bits / 8);
            target_address = add_bt_signed_offset(inst->mem_address, byte_offset);
            bit_index = (unsigned int)((uint64_t)source_index & (uint64_t)(operand_bits - 1));
        }

        target_value = read_bt_memory_value(ctx, target_address, operand_bits) & operand_mask;
    }

    bool carry = ((target_value >> bit_index) & 0x1ULL) != 0;
    set_flag(ctx, RFLAGS_CF, carry);

    if (inst->has_lock_prefix && mod != 3) {
        execute_locked_bt_memory(ctx, operation, target_address, operand_bits, bit_index);
        return;
    }

    uint64_t bit_mask = 1ULL << bit_index;
    uint64_t result = target_value;
    switch (operation) {
    case BIT_TEST_OP_BT:
        return;
    case BIT_TEST_OP_BTS:
        result |= bit_mask;
        break;
    case BIT_TEST_OP_BTR:
        result &= ~bit_mask;
        break;
    case BIT_TEST_OP_BTC:
        result ^= bit_mask;
        break;
    default:
        raise_ud();
    }

    result &= operand_mask;
    if (mod == 3) {
        write_bt_rm_value(ctx, inst->modrm, inst->mem_address, operand_bits, result);
    }
    else {
        write_bt_memory_value(ctx, target_address, operand_bits, result);
    }
}

void decode_modrm_bt(CPU_CONTEXT* ctx, DecodedInstruction* inst, uint8_t* code, size_t code_size, size_t* offset) {
    if (*offset >= code_size) {
        raise_gp(0);
    }

    inst->has_modrm = true;
    inst->modrm = code[(*offset)++];

    uint8_t mod = (inst->modrm >> 6) & 0x03;
    uint8_t rm = inst->modrm & 0x07;

    if (mod != 3 && rm == 4 && inst->address_size != 16) {
        if (*offset >= code_size) {
            raise_gp(0);
        }
        inst->has_sib = true;
        inst->sib = code[(*offset)++];
    }

    if (mod == 0 && rm == 5) {
        inst->disp_size = (inst->address_size == 16) ? 2 : 4;
    }
    else if (mod == 0 && inst->has_sib && (inst->sib & 0x07) == 5) {
        inst->disp_size = 4;
    }
    else if (mod == 1) {
        inst->disp_size = 1;
    }
    else if (mod == 2) {
        inst->disp_size = (inst->address_size == 16) ? 2 : 4;
    }

    if (inst->disp_size > 0) {
        if (*offset + inst->disp_size > code_size) {
            raise_gp(0);
        }

        inst->displacement = 0;
        for (int i = 0; i < inst->disp_size; i++) {
            inst->displacement |= ((int32_t)code[(*offset)++]) << (i * 8);
        }

        if (inst->disp_size == 1) {
            inst->displacement = (int8_t)inst->displacement;
        }
        else if (inst->disp_size == 2) {
            inst->displacement = (int16_t)inst->displacement;
        }
    }

    if (mod != 3) {
        inst->mem_address = get_effective_address(ctx, inst->modrm, &inst->sib, &inst->displacement, inst->address_size);
    }
}

DecodedInstruction decode_bt_instruction(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
    DecodedInstruction inst = {};
    size_t offset = 0;
    bool has_lock_prefix = false;

    ctx->rex_present = false;
    ctx->rex_w = false;
    ctx->rex_r = false;
    ctx->rex_x = false;
    ctx->rex_b = false;
    ctx->operand_size_override = false;
    ctx->address_size_override = false;

    while (offset < code_size) {
        uint8_t prefix = code[offset];
        if (prefix == 0x66) {
            ctx->operand_size_override = true;
            offset++;
        }
        else if (prefix == 0x67) {
            ctx->address_size_override = true;
            offset++;
        }
        else if (prefix >= 0x40 && prefix <= 0x4F) {
            ctx->rex_present = true;
            ctx->rex_w = (prefix >> 3) & 1;
            ctx->rex_r = (prefix >> 2) & 1;
            ctx->rex_x = (prefix >> 1) & 1;
            ctx->rex_b = prefix & 1;
            offset++;
        }
        else if (prefix == 0xF0) {
            has_lock_prefix = true;
            offset++;
        }
        else if (prefix == 0x26 || prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
                 prefix == 0x64 || prefix == 0x65 || prefix == 0xF2 || prefix == 0xF3) {
            offset++;
        }
        else {
            break;
        }
    }

    if (offset >= code_size) {
        raise_gp(0);
    }

    inst.opcode = code[offset++];
    if (inst.opcode != 0x0F) {
        raise_ud();
    }

    if (offset >= code_size) {
        raise_gp(0);
    }

    inst.opcode = code[offset++];
    if (inst.opcode != 0xA3 && inst.opcode != 0xAB && inst.opcode != 0xB3 &&
        inst.opcode != 0xBB && inst.opcode != 0xBA) {
        raise_ud();
    }

    inst.operand_size = 32;
    if (ctx->rex_w) {
        inst.operand_size = 64;
    }
    else if (ctx->operand_size_override) {
        inst.operand_size = 16;
    }

    if (ctx->cs.descriptor.long_mode) {
        inst.address_size = ctx->address_size_override ? 32 : 64;
    }
    else {
        inst.address_size = ctx->address_size_override ? 16 : 32;
    }

    decode_modrm_bt(ctx, &inst, code, code_size, &offset);

    if (inst.opcode == 0xBA) {
        uint8_t extension = (inst.modrm >> 3) & 0x07;
        if (extension < 4 || extension > 7) {
            raise_ud();
        }

        inst.imm_size = 1;
        if (offset >= code_size) {
            raise_gp(0);
        }
        inst.immediate = code[offset++];
    }

    BitTestOperation operation = decode_bt_operation(inst.opcode, inst.modrm);
    if (has_lock_prefix && !bt_operation_allows_lock(operation, inst.modrm)) {
        raise_ud();
    }

    inst.has_lock_prefix = has_lock_prefix;

    inst.inst_size = (int)offset;
    finalize_rip_relative_address(ctx, &inst, (int)offset);
    ctx->last_inst_size = (int)offset;
    return inst;
}

void execute_bt(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
    DecodedInstruction inst = decode_bt_instruction(ctx, code, code_size);
    execute_bt_operation(ctx, &inst);
}
