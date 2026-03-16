// cpu/init.hpp - CPU initialization

void init_cpu_context(CPU_CONTEXT* ctx, MEMORY_MANAGER* mem_mgr) {
    CPUEAXH_MEMSET(ctx, 0, sizeof(CPU_CONTEXT));
    ctx->mem_mgr = mem_mgr;
    ctx->cpl = 0;
    ctx->mxcsr = 0x1F80;

    ctx->cs.selector = 0x08;
    ctx->cs.descriptor.base = 0;
    ctx->cs.descriptor.limit = 0xFFFFFFFF;
    ctx->cs.descriptor.type = 0x0B;
    ctx->cs.descriptor.dpl = 0;
    ctx->cs.descriptor.present = true;
    ctx->cs.descriptor.granularity = true;
    ctx->cs.descriptor.db = false;
    ctx->cs.descriptor.long_mode = true;

    ctx->ds.selector = 0x10;
    ctx->ds.descriptor.base = 0;
    ctx->ds.descriptor.limit = 0xFFFFFFFF;
    ctx->ds.descriptor.type = 0x03;
    ctx->ds.descriptor.dpl = 0;
    ctx->ds.descriptor.present = true;
    ctx->ds.descriptor.granularity = true;
    ctx->ds.descriptor.db = true;

    ctx->es = ctx->ds;
    ctx->fs = ctx->ds;
    ctx->gs = ctx->ds;
    ctx->ss = ctx->ds;
    ctx->ss.selector = 0x18;
}
