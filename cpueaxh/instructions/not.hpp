// instrusments/not.hpp - NOT instruction implementation

// --- NOT internal helpers ---

int decode_not_rm_index(CPU_CONTEXT* ctx, uint8_t modrm) {
    int rm = modrm & 0x07;
    if (ctx->rex_b) {
        rm |= 0x08;
    }
    return rm;
}

uint64_t read_not_rm_operand(CPU_CONTEXT* ctx, uint8_t modrm, uint64_t mem_addr, int operand_size) {
    uint8_t mod = (modrm >> 6) & 0x03;
    int rm = decode_not_rm_index(ctx, modrm);

    if (mod == 3) {
        switch (operand_size) {
        case 8:  return get_reg8(ctx, rm);
        case 16: return get_reg16(ctx, rm);
        case 32: return get_reg32(ctx, rm);
        case 64: return get_reg64(ctx, rm);
        default: raise_ud(); return 0;
        }
    }

    switch (operand_size) {
    case 8:  return read_memory_byte(ctx, mem_addr);
    case 16: return read_memory_word(ctx, mem_addr);
    case 32: return read_memory_dword(ctx, mem_addr);
    case 64: return read_memory_qword(ctx, mem_addr);
    default: raise_ud(); return 0;
    }
}

void write_not_rm_operand(CPU_CONTEXT* ctx, uint8_t modrm, uint64_t mem_addr, int operand_size, uint64_t value) {
    uint8_t mod = (modrm >> 6) & 0x03;
    int rm = decode_not_rm_index(ctx, modrm);

    if (mod == 3) {
        switch (operand_size) {
        case 8:  set_reg8(ctx, rm, (uint8_t)value); break;
        case 16: set_reg16(ctx, rm, (uint16_t)value); break;
        case 32: set_reg32(ctx, rm, (uint32_t)value); break;
        case 64: set_reg64(ctx, rm, value); break;
        default: raise_ud();
        }
        return;
    }

    switch (operand_size) {
    case 8:  write_memory_byte(ctx, mem_addr, (uint8_t)value); break;
    case 16: write_memory_word(ctx, mem_addr, (uint16_t)value); break;
    case 32: write_memory_dword(ctx, mem_addr, (uint32_t)value); break;
    case 64: write_memory_qword(ctx, mem_addr, value); break;
    default: raise_ud();
    }
}

// --- NOT execution helpers ---

// F6 /2 - NOT r/m8
void not_rm8(CPU_CONTEXT* ctx, uint8_t modrm, uint8_t sib, int32_t disp, uint64_t mem_addr) {
    (void)sib;
    (void)disp;
    uint8_t result = (uint8_t)~read_not_rm_operand(ctx, modrm, mem_addr, 8);
    write_not_rm_operand(ctx, modrm, mem_addr, 8, result);
}

// F7 /2 - NOT r/m16
void not_rm16(CPU_CONTEXT* ctx, uint8_t modrm, uint8_t sib, int32_t disp, uint64_t mem_addr) {
    (void)sib;
    (void)disp;
    uint16_t result = (uint16_t)~read_not_rm_operand(ctx, modrm, mem_addr, 16);
    write_not_rm_operand(ctx, modrm, mem_addr, 16, result);
}

// F7 /2 - NOT r/m32
void not_rm32(CPU_CONTEXT* ctx, uint8_t modrm, uint8_t sib, int32_t disp, uint64_t mem_addr) {
    (void)sib;
    (void)disp;
    uint32_t result = (uint32_t)~read_not_rm_operand(ctx, modrm, mem_addr, 32);
    write_not_rm_operand(ctx, modrm, mem_addr, 32, result);
}

// REX.W + F7 /2 - NOT r/m64
void not_rm64(CPU_CONTEXT* ctx, uint8_t modrm, uint8_t sib, int32_t disp, uint64_t mem_addr) {
    (void)sib;
    (void)disp;
    uint64_t result = ~read_not_rm_operand(ctx, modrm, mem_addr, 64);
    write_not_rm_operand(ctx, modrm, mem_addr, 64, result);
}

// --- NOT decode helpers ---

void decode_modrm_not(CPU_CONTEXT* ctx, DecodedInstruction* inst, uint8_t* code, size_t code_size, size_t* offset, bool has_lock_prefix) {
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

    if (has_lock_prefix && mod == 3) {
        raise_ud();
    }
}

// --- NOT instruction decoder ---

DecodedInstruction decode_not_instruction(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
    DecodedInstruction inst = {};
    size_t offset = 0;

    ctx->rex_present = false;
    ctx->rex_w = false;
    ctx->rex_r = false;
    ctx->rex_x = false;
    ctx->rex_b = false;
    ctx->operand_size_override = false;
    ctx->address_size_override = false;

    bool has_lock_prefix = false;

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

    switch (inst.opcode) {
    // F6 /2 - NOT r/m8
    case 0xF6:
        inst.operand_size = 8;
        decode_modrm_not(ctx, &inst, code, code_size, &offset, has_lock_prefix);
        if (((inst.modrm >> 3) & 0x07) != 2) {
            raise_ud();
        }
        break;

    // F7 /2 - NOT r/m16 / NOT r/m32 / REX.W + NOT r/m64
    case 0xF7:
        decode_modrm_not(ctx, &inst, code, code_size, &offset, has_lock_prefix);
        if (((inst.modrm >> 3) & 0x07) != 2) {
            raise_ud();
        }
        break;

    default:
        raise_ud();
    }

    finalize_rip_relative_address(ctx, &inst, (int)offset);
    ctx->last_inst_size = (int)offset;
    return inst;
}

// --- NOT instruction executor ---

void execute_not(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
    DecodedInstruction inst = decode_not_instruction(ctx, code, code_size);

    switch (inst.opcode) {
    // F6 /2 - NOT r/m8
    case 0xF6:
        not_rm8(ctx, inst.modrm, inst.sib, inst.displacement, inst.mem_address);
        break;

    // F7 /2 - NOT r/m16 / NOT r/m32 / REX.W + NOT r/m64
    case 0xF7:
        if (ctx->rex_w) {
            not_rm64(ctx, inst.modrm, inst.sib, inst.displacement, inst.mem_address);
        }
        else if (ctx->operand_size_override) {
            not_rm16(ctx, inst.modrm, inst.sib, inst.displacement, inst.mem_address);
        }
        else {
            not_rm32(ctx, inst.modrm, inst.sib, inst.displacement, inst.mem_address);
        }
        break;
    }
}
