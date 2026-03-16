// instrusments/ret.hpp - RET far instruction implementation

int decode_ret_far_operand_size(CPU_CONTEXT* ctx) {
    if (ctx->cs.descriptor.long_mode) {
        return ctx->operand_size_override ? 16 : 64;
    }
    return ctx->operand_size_override ? 16 : 32;
}

void ret_far_adjust_stack(CPU_CONTEXT* ctx, uint16_t adjustment) {
    int stack_addr_size = get_stack_addr_size(ctx);
    if (stack_addr_size == 64) {
        ctx->regs[REG_RSP] += adjustment;
    }
    else if (stack_addr_size == 32) {
        uint32_t esp = (uint32_t)(ctx->regs[REG_RSP] & 0xFFFFFFFF);
        esp += adjustment;
        ctx->regs[REG_RSP] = (ctx->regs[REG_RSP] & ~0xFFFFFFFFULL) | esp;
    }
    else {
        uint16_t sp = (uint16_t)(ctx->regs[REG_RSP] & 0xFFFF);
        sp = (uint16_t)(sp + adjustment);
        ctx->regs[REG_RSP] = (ctx->regs[REG_RSP] & ~0xFFFFULL) | sp;
    }
}

void validate_ret_far_selector(CPU_CONTEXT* ctx, uint16_t selector, SegmentDescriptor* desc_out) {
    if (is_null_selector(selector)) {
        raise_gp(0);
    }

    SegmentDescriptor desc = load_descriptor_from_table(ctx, selector);
    if (!is_code_segment(desc.type)) {
        raise_gp(selector & 0xFFFC);
    }

    if (ctx->cs.descriptor.long_mode && desc.long_mode && desc.db) {
        raise_gp(selector & 0xFFFC);
    }

    uint8_t rpl = selector & 0x03;
    if (rpl != ctx->cpl) {
        raise_gp(selector & 0xFFFC);
    }

    if (is_conforming_code_segment(desc.type)) {
        if (desc.dpl > ctx->cpl) {
            raise_gp(selector & 0xFFFC);
        }
    }
    else if (desc.dpl != ctx->cpl) {
        raise_gp(selector & 0xFFFC);
    }

    if (!desc.present) {
        raise_np(selector & 0xFFFC);
    }

    *desc_out = desc;
}

DecodedInstruction decode_ret_instruction(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
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
    if (inst.opcode != 0xCA && inst.opcode != 0xCB) {
        raise_ud();
    }

    if (has_lock_prefix) {
        raise_ud();
    }

    inst.operand_size = decode_ret_far_operand_size(ctx);
    inst.address_size = get_stack_addr_size(ctx);

    if (inst.opcode == 0xCA) {
        if (offset + 2 > code_size) {
            raise_gp(0);
        }
        inst.immediate = (uint16_t)code[offset] | ((uint16_t)code[offset + 1] << 8);
        inst.imm_size = 2;
        offset += 2;
    }

    inst.inst_size = (int)offset;
    finalize_rip_relative_address(ctx, &inst, (int)offset);
    ctx->last_inst_size = (int)offset;
    return inst;
}

void execute_ret(CPU_CONTEXT* ctx, uint8_t* code, size_t code_size) {
    DecodedInstruction inst = decode_ret_instruction(ctx, code, code_size);

    uint64_t new_rip;
    uint16_t new_selector;
    if (inst.operand_size == 64) {
        new_rip = pop_value64(ctx);
        new_selector = (uint16_t)pop_value64(ctx);
    }
    else if (inst.operand_size == 32) {
        new_rip = pop_value32(ctx);
        new_selector = (uint16_t)pop_value32(ctx);
    }
    else {
        new_rip = pop_value16(ctx);
        new_selector = pop_value16(ctx);
    }

    SegmentDescriptor new_desc = {};
    validate_ret_far_selector(ctx, new_selector, &new_desc);

    ret_far_adjust_stack(ctx, (uint16_t)inst.immediate);

    ctx->cs.selector = (new_selector & 0xFFFC) | ctx->cpl;
    ctx->cs.descriptor = new_desc;

    if (inst.operand_size == 16) {
        ctx->rip = (uint16_t)new_rip;
    }
    else if (inst.operand_size == 32) {
        ctx->rip = (uint32_t)new_rip;
    }
    else {
        ctx->rip = new_rip;
    }
}
