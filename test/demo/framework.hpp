#pragma once

#define NOMINMAX

#include <windows.h>
#include <intrin.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cpueaxh.hpp"
#include "cpu/def.h"
#include "memory/manager.hpp"

void init_cpu_context(CPU_CONTEXT* ctx, MEMORY_MANAGER* mem_mgr);
int cpu_step(CPU_CONTEXT* ctx);

constexpr int kCpuStepOk = 0;
constexpr int kCpuStepException = 4;

extern "C" int cpueaxh_test_run_native(cpueaxh_x86_context* context, void* code, void* bridge_block);

namespace cpueaxh_test {

constexpr std::uint64_t kFlagCF = 1ull << 0;
constexpr std::uint64_t kFlagPF = 1ull << 2;
constexpr std::uint64_t kFlagAF = 1ull << 4;
constexpr std::uint64_t kFlagZF = 1ull << 6;
constexpr std::uint64_t kFlagSF = 1ull << 7;
constexpr std::uint64_t kFlagDF = 1ull << 10;
constexpr std::uint64_t kFlagOF = 1ull << 11;
constexpr std::uint64_t kStatusMask = kFlagCF | kFlagPF | kFlagAF | kFlagZF | kFlagSF | kFlagOF;
constexpr std::uint64_t kLogicMask = kFlagCF | kFlagPF | kFlagZF | kFlagSF | kFlagOF;
constexpr std::uint64_t kPcmpstrMask = kFlagCF | kFlagZF | kFlagSF | kFlagOF;
constexpr std::uint64_t kIncDecMask = kFlagPF | kFlagAF | kFlagZF | kFlagSF | kFlagOF;
constexpr std::uint64_t kRotationMask = kFlagCF | kFlagOF;
constexpr std::uint64_t kBitTestMask = kFlagCF;
constexpr std::uint64_t kBitScanMask = kFlagZF;
constexpr std::uint64_t kSeedCount = 128;
constexpr std::uint64_t kExceptionSeedCount = 128;
constexpr std::uint64_t kHostIsolationSeedCount = 64;
constexpr std::uint64_t kHostIsolationGroupSeedCount = 32;
constexpr std::uint64_t kContextApiSeedCount = 128;
constexpr std::uint64_t kGuestCodeBase = 0x100000;
constexpr std::uint64_t kGuestStackBase = 0x200000;
constexpr std::size_t kCodePageSize = 0x1000;
constexpr std::size_t kStackSize = 0x4000;
constexpr std::size_t kSlotSize = 16;
constexpr std::size_t kBufferSize = 64;
constexpr std::size_t kDataSize = kSlotSize * 4 + kBufferSize * 2;
constexpr std::uint64_t kInitialMxcsr = 0x1F80;
constexpr std::uint64_t kInitialRspOffset = kStackSize - 0x200;

struct TestBridgeBlock {
    std::uint64_t host_rsp;
    std::uint64_t context_ptr;
    std::uint64_t guest_rsp;
    std::uint64_t saved_stack0;
    std::uint64_t saved_stack1;
    std::uint64_t saved_stack2;
    std::uint64_t guest_rax;
    std::uint64_t guest_r10;
};

inline std::uint64_t mix64(std::uint64_t value) {
    value += 0x9E3779B97F4A7C15ull;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
}

inline std::uint32_t narrow32(std::uint64_t value) {
    return static_cast<std::uint32_t>(value & 0xFFFFFFFFu);
}

inline std::uint8_t narrow8(std::uint64_t value) {
    return static_cast<std::uint8_t>(value & 0xFFu);
}

inline std::uint64_t seeded(std::uint64_t seed, std::uint64_t salt) {
    return mix64(seed + salt * 0x9E3779B97F4A7C15ull + 0xD1B54A32D192ED03ull);
}

inline std::string hex64(std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return stream.str();
}

inline std::string hex8(std::uint8_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value);
    return stream.str();
}

enum class Reg : std::uint8_t {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
};

enum class Family : std::uint8_t {
    BinaryRegReg,
    BinaryRegImm,
    UnaryReg,
    ShiftImm,
    ShiftCl,
    BitOps,
    FlagOps,
    MoveOps,
    MemoryOps,
    StackOps,
    StringOps,
    VectorOps,
    ControlFlow,
};

enum class BinaryOp : std::uint8_t {
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Cmp,
    Test,
};

enum class UnaryOp : std::uint8_t {
    Inc,
    Dec,
    Neg,
    Not,
};

enum class ShiftOp : std::uint8_t {
    Rol,
    Ror,
    Shl,
    Shr,
    Sar,
};

enum class BitOp : std::uint8_t {
    BtImm,
    BtReg,
    Bsf,
    Bswap,
    BsfAlt,
    BswapAlt,
};

enum class FlagProgram : std::uint8_t {
    Setcc,
    Cmovcc,
    Jcc,
};

enum class MoveProgram : std::uint8_t {
    MovA,
    MovB,
    MovzxByte,
    MovzxWord,
    MovsxByte,
    MovsxWord,
    Movsxd,
    Lea2,
    Lea4,
};

enum class MemoryProgram : std::uint8_t {
    MovRoundtrip,
    AddMem,
    SubMem,
    AndMem,
    OrMem,
    XorMem,
    XaddMem,
    CmpxchgMem,
};

enum class StackProgram : std::uint8_t {
    PushPopPair,
    PushPopFlags,
    EnterLeave,
    PushChain,
};

enum class StringProgram : std::uint8_t {
    Movsb,
    Movsw,
    Movsd,
    Movsq,
    RepMovsb,
    RepMovsw,
    Lodsb,
    Lodsq,
    Stosb,
    Stosq,
    Cmpsb,
    Scasb,
};

enum class VectorProgram : std::uint8_t {
    Paddq,
    Pxor,
    Pand,
    Por,
    Vinsertf128,
    MovdMmReg,
    MovqMmReg,
    MovdMmMem,
    MovqMmMem,
    MovdXmmReg,
    MovqXmmReg,
    MovdXmmMem,
    MovqXmmMem,
    Punpcklbw,
    Punpcklwd,
    Punpckldq,
    Punpcklqdq,
    Pcmpeqb,
    Pcmpeqw,
    Pcmpeqd,
    Pshufd,
    Pslldq,
    Psrldq,
    PaddqPxor,
    Movdqu,
    Pshufb,
    Aesenc,
    Aesenclast,
    Aeskeygenassist,
    Roundsd,
    Roundss,
    Pcmpestrm,
    Pcmpestri,
    Pcmpistrm,
};

enum class ControlProgram : std::uint8_t {
    JmpSkip,
    CallAdd,
    CallXor,
    CallLea,
};

struct PairSpec {
    Reg dst;
    Reg src;
    const char* name;
};

struct RegSpec {
    Reg reg;
    const char* name;
};

struct CondSpec {
    std::uint8_t code;
    const char* name;
};

struct ProgramSpec {
    Family family;
    std::uint32_t op;
    std::uint32_t variant;
    std::uint64_t flag_mask;
    std::string name;
};

struct BuiltCase {
    ProgramSpec spec;
    std::uint64_t seed;
    std::vector<std::uint8_t> image;
    std::uint32_t data_offset;
    cpueaxh_x86_context initial_context;
};

struct Failure {
    std::string case_name;
    std::string detail;
};

struct HostFeatures {
    bool avx = false;
    bool ssse3 = false;
    bool sse41 = false;
    bool sse42 = false;
    bool aes = false;
    bool rdpid = false;
};

inline constexpr std::array<std::uint8_t, 4> kAesKeygenAssistImmediates = {{ 0x01, 0x1B, 0x36, 0x80 }};
inline constexpr std::array<std::uint8_t, 6> kRoundImmediates = {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x08 }};
inline constexpr std::array<std::uint8_t, 8> kPshufdImmediates = {{ 0x00, 0x1B, 0x4E, 0x93, 0x39, 0xC6, 0xFF, 0x72 }};
inline constexpr std::array<std::uint8_t, 8> kPcmpestriImmediates = {{ 0x00, 0x08, 0x10, 0x18, 0x40, 0x48, 0x70, 0x78 }};
inline constexpr std::array<std::uint8_t, 4> kVinsertf128Immediates = {{ 0x00, 0x01, 0x40, 0x7F }};

inline constexpr std::array<PairSpec, 3> kBinaryPairs = {{
    { Reg::RAX, Reg::RBX, "rax_rbx" },
    { Reg::R8, Reg::R9, "r8_r9" },
    { Reg::R10, Reg::R11, "r10_r11" },
}};

inline constexpr std::array<RegSpec, 3> kCoreRegs = {{
    { Reg::RAX, "rax" },
    { Reg::R8, "r8" },
    { Reg::R10, "r10" },
}};

inline constexpr std::array<RegSpec, 4> kUnaryRegs = {{
    { Reg::RAX, "rax" },
    { Reg::R8, "r8" },
    { Reg::R10, "r10" },
    { Reg::R13, "r13" },
}};

inline constexpr std::array<CondSpec, 7> kConditions = {{
    { 0x0, "o" },
    { 0x2, "b" },
    { 0x4, "z" },
    { 0x8, "s" },
    { 0xA, "p" },
    { 0xC, "l" },
    { 0xE, "le" },
}};

inline const char* reg_name(Reg reg) {
    static constexpr const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    return names[static_cast<std::size_t>(reg)];
}

inline const char* binary_name(BinaryOp op) {
    switch (op) {
    case BinaryOp::Add: return "add";
    case BinaryOp::Adc: return "adc";
    case BinaryOp::Sub: return "sub";
    case BinaryOp::Sbb: return "sbb";
    case BinaryOp::And: return "and";
    case BinaryOp::Or: return "or";
    case BinaryOp::Xor: return "xor";
    case BinaryOp::Cmp: return "cmp";
    default: return "test";
    }
}

inline const char* unary_name(UnaryOp op) {
    switch (op) {
    case UnaryOp::Inc: return "inc";
    case UnaryOp::Dec: return "dec";
    case UnaryOp::Neg: return "neg";
    default: return "not";
    }
}

inline const char* shift_name(ShiftOp op) {
    switch (op) {
    case ShiftOp::Rol: return "rol";
    case ShiftOp::Ror: return "ror";
    case ShiftOp::Shl: return "shl";
    case ShiftOp::Shr: return "shr";
    default: return "sar";
    }
}

inline std::uint64_t binary_flag_mask(BinaryOp op) {
    switch (op) {
    case BinaryOp::And:
    case BinaryOp::Or:
    case BinaryOp::Xor:
    case BinaryOp::Test:
        return kLogicMask;
    default:
        return kStatusMask;
    }
}

inline std::uint64_t unary_flag_mask(UnaryOp op) {
    switch (op) {
    case UnaryOp::Inc:
    case UnaryOp::Dec:
        return kIncDecMask;
    case UnaryOp::Neg:
        return kStatusMask;
    default:
        return 0;
    }
}

inline std::uint64_t shift_flag_mask(ShiftOp op) {
    switch (op) {
    case ShiftOp::Rol:
    case ShiftOp::Ror:
        return kRotationMask;
    default:
        return kLogicMask;
    }
}

inline std::uint64_t make_initial_flags(std::uint64_t seed) {
    std::uint64_t flags = 0x202ull;
    std::uint64_t bits = seeded(seed, 0x55);
    if (bits & 0x01) flags |= kFlagCF;
    if (bits & 0x02) flags |= kFlagPF;
    if (bits & 0x04) flags |= kFlagAF;
    if (bits & 0x08) flags |= kFlagZF;
    if (bits & 0x10) flags |= kFlagSF;
    if (bits & 0x20) flags |= kFlagOF;
    return flags;
}

inline HostFeatures query_host_features() {
    HostFeatures features;
    int cpu_info[4] = {};
    __cpuid(cpu_info, 0);
    const int max_leaf = cpu_info[0];
    if (max_leaf >= 1) {
        __cpuidex(cpu_info, 1, 0);
        const bool has_xsave = (cpu_info[2] & (1 << 26)) != 0;
        const bool has_osxsave = (cpu_info[2] & (1 << 27)) != 0;
        const bool has_avx = (cpu_info[2] & (1 << 28)) != 0;
        if (has_xsave && has_osxsave && has_avx) {
            const unsigned __int64 xcr0 = _xgetbv(0);
            features.avx = (xcr0 & 0x6) == 0x6;
        }
        features.ssse3 = (cpu_info[2] & (1 << 9)) != 0;
        features.sse41 = (cpu_info[2] & (1 << 19)) != 0;
        features.sse42 = (cpu_info[2] & (1 << 20)) != 0;
        features.aes = (cpu_info[2] & (1 << 25)) != 0;
    }
    if (max_leaf >= 7) {
        __cpuidex(cpu_info, 7, 0);
        features.rdpid = (cpu_info[2] & (1 << 22)) != 0;
    }
    return features;
}

inline cpueaxh_x86_context make_initial_context(std::uint64_t seed) {
    cpueaxh_x86_context context{};
    for (std::size_t index = 0; index < 16; ++index) {
        context.regs[index] = seeded(seed, 0x100 + index);
    }
    context.rflags = make_initial_flags(seed);
    context.mxcsr = static_cast<std::uint32_t>(kInitialMxcsr);
    return context;
}

inline cpueaxh_x86_xmm make_seeded_xmm(std::uint64_t seed, std::uint64_t salt) {
    cpueaxh_x86_xmm value{};
    value.low = seeded(seed, salt);
    value.high = seeded(seed, salt + 1);
    return value;
}

inline cpueaxh_x86_ymm make_seeded_ymm(std::uint64_t seed, std::uint64_t salt) {
    cpueaxh_x86_ymm value{};
    value.lower = make_seeded_xmm(seed, salt);
    value.upper = make_seeded_xmm(seed, salt + 2);
    return value;
}

inline cpueaxh_x86_context make_extended_context(std::uint64_t seed) {
    cpueaxh_x86_context context = make_initial_context(seed);
    for (std::size_t index = 0; index < 16; ++index) {
        context.xmm[index] = make_seeded_xmm(seed, 0x500 + index * 8);
        context.ymm_upper[index] = make_seeded_xmm(seed, 0x580 + index * 8);
        context.control_regs[index] = seeded(seed, 0x900 + index);
    }
    for (std::size_t index = 0; index < 8; ++index) {
        context.mm[index] = seeded(seed, 0x700 + index);
    }
    context.mxcsr = static_cast<std::uint32_t>(0x1F80u | (seeded(seed, 0x800) & 0x1F3Fu));
    context.es.selector = static_cast<std::uint16_t>(seeded(seed, 0xA00) & 0xFFF8u);
    context.cs.selector = static_cast<std::uint16_t>(seeded(seed, 0xA01) & 0xFFF8u);
    context.ss.selector = static_cast<std::uint16_t>(seeded(seed, 0xA02) & 0xFFF8u);
    context.ds.selector = static_cast<std::uint16_t>(seeded(seed, 0xA03) & 0xFFF8u);
    context.fs.selector = static_cast<std::uint16_t>(seeded(seed, 0xA04) & 0xFFF8u);
    context.gs.selector = static_cast<std::uint16_t>(seeded(seed, 0xA05) & 0xFFF8u);
    context.es.descriptor.base = seeded(seed, 0xA10);
    context.cs.descriptor.base = seeded(seed, 0xA11);
    context.ss.descriptor.base = seeded(seed, 0xA12);
    context.ds.descriptor.base = seeded(seed, 0xA13);
    context.fs.descriptor.base = seeded(seed, 0xA14);
    context.gs.descriptor.base = seeded(seed, 0xA15);
    context.es.descriptor.limit = narrow32(seeded(seed, 0xA20));
    context.cs.descriptor.limit = narrow32(seeded(seed, 0xA21));
    context.ss.descriptor.limit = narrow32(seeded(seed, 0xA22));
    context.ds.descriptor.limit = narrow32(seeded(seed, 0xA23));
    context.fs.descriptor.limit = narrow32(seeded(seed, 0xA24));
    context.gs.descriptor.limit = narrow32(seeded(seed, 0xA25));
    context.es.descriptor.type = narrow8(seeded(seed, 0xA30)) & 0x1Fu;
    context.cs.descriptor.type = narrow8(seeded(seed, 0xA31)) & 0x1Fu;
    context.ss.descriptor.type = narrow8(seeded(seed, 0xA32)) & 0x1Fu;
    context.ds.descriptor.type = narrow8(seeded(seed, 0xA33)) & 0x1Fu;
    context.fs.descriptor.type = narrow8(seeded(seed, 0xA34)) & 0x1Fu;
    context.gs.descriptor.type = narrow8(seeded(seed, 0xA35)) & 0x1Fu;
    context.es.descriptor.dpl = narrow8(seeded(seed, 0xA40)) & 0x3u;
    context.cs.descriptor.dpl = narrow8(seeded(seed, 0xA41)) & 0x3u;
    context.ss.descriptor.dpl = narrow8(seeded(seed, 0xA42)) & 0x3u;
    context.ds.descriptor.dpl = narrow8(seeded(seed, 0xA43)) & 0x3u;
    context.fs.descriptor.dpl = narrow8(seeded(seed, 0xA44)) & 0x3u;
    context.gs.descriptor.dpl = narrow8(seeded(seed, 0xA45)) & 0x3u;
    context.es.descriptor.present = narrow8(seeded(seed, 0xA50)) & 1u;
    context.cs.descriptor.present = narrow8(seeded(seed, 0xA51)) & 1u;
    context.ss.descriptor.present = narrow8(seeded(seed, 0xA52)) & 1u;
    context.ds.descriptor.present = narrow8(seeded(seed, 0xA53)) & 1u;
    context.fs.descriptor.present = narrow8(seeded(seed, 0xA54)) & 1u;
    context.gs.descriptor.present = narrow8(seeded(seed, 0xA55)) & 1u;
    context.es.descriptor.granularity = narrow8(seeded(seed, 0xA60)) & 1u;
    context.cs.descriptor.granularity = narrow8(seeded(seed, 0xA61)) & 1u;
    context.ss.descriptor.granularity = narrow8(seeded(seed, 0xA62)) & 1u;
    context.ds.descriptor.granularity = narrow8(seeded(seed, 0xA63)) & 1u;
    context.fs.descriptor.granularity = narrow8(seeded(seed, 0xA64)) & 1u;
    context.gs.descriptor.granularity = narrow8(seeded(seed, 0xA65)) & 1u;
    context.es.descriptor.db = narrow8(seeded(seed, 0xA70)) & 1u;
    context.cs.descriptor.db = narrow8(seeded(seed, 0xA71)) & 1u;
    context.ss.descriptor.db = narrow8(seeded(seed, 0xA72)) & 1u;
    context.ds.descriptor.db = narrow8(seeded(seed, 0xA73)) & 1u;
    context.fs.descriptor.db = narrow8(seeded(seed, 0xA74)) & 1u;
    context.gs.descriptor.db = narrow8(seeded(seed, 0xA75)) & 1u;
    context.es.descriptor.long_mode = narrow8(seeded(seed, 0xA80)) & 1u;
    context.cs.descriptor.long_mode = narrow8(seeded(seed, 0xA81)) & 1u;
    context.ss.descriptor.long_mode = narrow8(seeded(seed, 0xA82)) & 1u;
    context.ds.descriptor.long_mode = narrow8(seeded(seed, 0xA83)) & 1u;
    context.fs.descriptor.long_mode = narrow8(seeded(seed, 0xA84)) & 1u;
    context.gs.descriptor.long_mode = narrow8(seeded(seed, 0xA85)) & 1u;
    context.gdtr_base = seeded(seed, 0xB00);
    context.gdtr_limit = static_cast<std::uint16_t>(seeded(seed, 0xB01) & 0xFFFFu);
    context.ldtr_base = seeded(seed, 0xB02);
    context.ldtr_limit = static_cast<std::uint16_t>(seeded(seed, 0xB03) & 0xFFFFu);
    context.cpl = static_cast<std::uint8_t>(seeded(seed, 0xB04) & 0x3u);
    context.code_exception = static_cast<std::uint32_t>(CPUEAXH_EXCEPTION_UD + ((seeded(seed, 0xB05) % 3u)));
    context.error_code_exception = narrow32(seeded(seed, 0xB06));
    context.processor_id = narrow32(seeded(seed, 0xB07));
    return context;
}

inline bool equal_xmm(const cpueaxh_x86_xmm& left, const cpueaxh_x86_xmm& right) {
    return left.low == right.low && left.high == right.high;
}

inline bool equal_segment_descriptor(const cpueaxh_x86_segment_descriptor& left, const cpueaxh_x86_segment_descriptor& right) {
    return left.base == right.base &&
        left.limit == right.limit &&
        left.type == right.type &&
        left.dpl == right.dpl &&
        left.present == right.present &&
        left.granularity == right.granularity &&
        left.db == right.db &&
        left.long_mode == right.long_mode;
}

inline bool equal_segment(const cpueaxh_x86_segment& left, const cpueaxh_x86_segment& right) {
    return left.selector == right.selector && equal_segment_descriptor(left.descriptor, right.descriptor);
}

inline bool equal_context(const cpueaxh_x86_context& left, const cpueaxh_x86_context& right) {
    for (std::size_t index = 0; index < 16; ++index) {
        if (left.regs[index] != right.regs[index]) {
            return false;
        }
        if (!equal_xmm(left.xmm[index], right.xmm[index])) {
            return false;
        }
        if (!equal_xmm(left.ymm_upper[index], right.ymm_upper[index])) {
            return false;
        }
        if (left.control_regs[index] != right.control_regs[index]) {
            return false;
        }
    }
    for (std::size_t index = 0; index < 8; ++index) {
        if (left.mm[index] != right.mm[index]) {
            return false;
        }
    }
    return left.rip == right.rip &&
        left.rflags == right.rflags &&
        left.mxcsr == right.mxcsr &&
        equal_segment(left.es, right.es) &&
        equal_segment(left.cs, right.cs) &&
        equal_segment(left.ss, right.ss) &&
        equal_segment(left.ds, right.ds) &&
        equal_segment(left.fs, right.fs) &&
        equal_segment(left.gs, right.gs) &&
        left.gdtr_base == right.gdtr_base &&
        left.gdtr_limit == right.gdtr_limit &&
        left.ldtr_base == right.ldtr_base &&
        left.ldtr_limit == right.ldtr_limit &&
        left.cpl == right.cpl &&
        left.code_exception == right.code_exception &&
        left.error_code_exception == right.error_code_exception &&
        left.processor_id == right.processor_id;
}

inline std::array<std::uint8_t, kDataSize> make_initial_data(std::uint64_t seed) {
    std::array<std::uint8_t, kDataSize> data{};
    for (std::size_t index = 0; index < data.size(); ++index) {
        data[index] = narrow8(seeded(seed, 0x400 + index));
    }
    for (std::size_t index = 0; index < 32; ++index) {
        data[kSlotSize * 4 + index] = narrow8(index + 1);
        data[kSlotSize * 4 + kBufferSize + index] = narrow8(0x80u + index);
    }
    return data;
}

class CodeBuilder {
public:
    struct Label {
        std::size_t id;
    };

    Label make_label() {
        labels_.push_back(static_cast<std::size_t>(-1));
        return Label{ labels_.size() - 1 };
    }

    void mark(Label label) {
        labels_[label.id] = bytes_.size();
    }

    std::size_t offset() const {
        return bytes_.size();
    }

    std::size_t label_offset(Label label) const {
        return labels_[label.id];
    }

    void align(std::size_t alignment) {
        while ((bytes_.size() % alignment) != 0) {
            emit8(0x90);
        }
    }

    void emit8(std::uint8_t value) {
        bytes_.push_back(value);
    }

    void emit16(std::uint16_t value) {
        emit8(static_cast<std::uint8_t>(value & 0xFFu));
        emit8(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    }

    void emit32(std::uint32_t value) {
        for (int shift = 0; shift < 32; shift += 8) {
            emit8(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
        }
    }

    void emit64(std::uint64_t value) {
        for (int shift = 0; shift < 64; shift += 8) {
            emit8(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
        }
    }

    void emit_bytes(const std::uint8_t* data, std::size_t size) {
        bytes_.insert(bytes_.end(), data, data + size);
    }

    void emit_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm) {
        emit8(static_cast<std::uint8_t>((mod << 6) | ((reg & 7u) << 3) | (rm & 7u)));
    }

    void emit_sib(std::uint8_t scale, std::uint8_t index, std::uint8_t base) {
        emit8(static_cast<std::uint8_t>((scale << 6) | ((index & 7u) << 3) | (base & 7u)));
    }

    void emit_rex(bool w, std::uint8_t reg, std::uint8_t index, std::uint8_t rm) {
        std::uint8_t rex = 0x40u;
        if (w) rex |= 0x08u;
        if ((reg & 8u) != 0) rex |= 0x04u;
        if ((index & 8u) != 0) rex |= 0x02u;
        if ((rm & 8u) != 0) rex |= 0x01u;
        if (rex != 0x40u) {
            emit8(rex);
        }
    }

    void emit_vex3(bool w, std::uint8_t map_select, std::uint8_t vvvv, bool l, std::uint8_t pp, std::uint8_t reg, std::uint8_t index, std::uint8_t rm) {
        emit8(0xC4);
        emit8(static_cast<std::uint8_t>(((reg & 8u) == 0 ? 0x80u : 0x00u) |
                                        ((index & 8u) == 0 ? 0x40u : 0x00u) |
                                        ((rm & 8u) == 0 ? 0x20u : 0x00u) |
                                        (map_select & 0x1Fu)));
        emit8(static_cast<std::uint8_t>((w ? 0x80u : 0x00u) |
                                        (((~vvvv) & 0x0Fu) << 3) |
                                        (l ? 0x04u : 0x00u) |
                                        (pp & 0x03u)));
    }

    void rip_rel32(Label label) {
        patches_.push_back(Patch{ label.id, bytes_.size(), 4, 0 });
        emit32(0);
    }

    void rip_rel32(Label label, std::size_t trailing_size) {
        patches_.push_back(Patch{ label.id, bytes_.size(), 4, trailing_size });
        emit32(0);
    }

    void rel32(Label label) {
        rip_rel32(label);
    }

    void rel8(Label label) {
        patches_.push_back(Patch{ label.id, bytes_.size(), 1, 0 });
        emit8(0);
    }

    void ret() {
        emit8(0xC3);
    }

    void jmp32(Label label) {
        emit8(0xE9);
        rel32(label);
    }

    void call32(Label label) {
        emit8(0xE8);
        rel32(label);
    }

    void jcc32(std::uint8_t cc, Label label) {
        emit8(0x0F);
        emit8(static_cast<std::uint8_t>(0x80u + cc));
        rel32(label);
    }

    void mov_reg_reg(Reg dst, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, static_cast<std::uint8_t>(dst));
        emit8(0x89);
        emit_modrm(3, static_cast<std::uint8_t>(src), static_cast<std::uint8_t>(dst));
    }

    void binary_reg_reg(BinaryOp op, Reg dst, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, static_cast<std::uint8_t>(dst));
        switch (op) {
        case BinaryOp::Add: emit8(0x01); break;
        case BinaryOp::Adc: emit8(0x11); break;
        case BinaryOp::Sub: emit8(0x29); break;
        case BinaryOp::Sbb: emit8(0x19); break;
        case BinaryOp::And: emit8(0x21); break;
        case BinaryOp::Or: emit8(0x09); break;
        case BinaryOp::Xor: emit8(0x31); break;
        case BinaryOp::Cmp: emit8(0x39); break;
        case BinaryOp::Test: emit8(0x85); break;
        }
        emit_modrm(3, static_cast<std::uint8_t>(src), static_cast<std::uint8_t>(dst));
    }

    void binary_reg_imm(BinaryOp op, Reg dst, std::uint32_t imm) {
        std::uint8_t reg_field = 0;
        std::uint8_t opcode = 0x81;
        if (op == BinaryOp::Test) {
            opcode = 0xF7;
            reg_field = 0;
        }
        else {
            switch (op) {
            case BinaryOp::Add: reg_field = 0; break;
            case BinaryOp::Or: reg_field = 1; break;
            case BinaryOp::Adc: reg_field = 2; break;
            case BinaryOp::Sbb: reg_field = 3; break;
            case BinaryOp::And: reg_field = 4; break;
            case BinaryOp::Sub: reg_field = 5; break;
            case BinaryOp::Xor: reg_field = 6; break;
            case BinaryOp::Cmp: reg_field = 7; break;
            case BinaryOp::Test: reg_field = 0; break;
            }
        }
        emit_rex(true, reg_field, 0, static_cast<std::uint8_t>(dst));
        emit8(opcode);
        emit_modrm(3, reg_field, static_cast<std::uint8_t>(dst));
        emit32(imm);
    }

    void unary_reg(UnaryOp op, Reg reg) {
        std::uint8_t reg_field = 0;
        std::uint8_t opcode = 0xFF;
        switch (op) {
        case UnaryOp::Inc: reg_field = 0; opcode = 0xFF; break;
        case UnaryOp::Dec: reg_field = 1; opcode = 0xFF; break;
        case UnaryOp::Not: reg_field = 2; opcode = 0xF7; break;
        case UnaryOp::Neg: reg_field = 3; opcode = 0xF7; break;
        }
        emit_rex(true, reg_field, 0, static_cast<std::uint8_t>(reg));
        emit8(opcode);
        emit_modrm(3, reg_field, static_cast<std::uint8_t>(reg));
    }

    void shift_imm(ShiftOp op, Reg reg, std::uint8_t amount) {
        std::uint8_t reg_field = 0;
        switch (op) {
        case ShiftOp::Rol: reg_field = 0; break;
        case ShiftOp::Ror: reg_field = 1; break;
        case ShiftOp::Shl: reg_field = 4; break;
        case ShiftOp::Shr: reg_field = 5; break;
        case ShiftOp::Sar: reg_field = 7; break;
        }
        emit_rex(true, reg_field, 0, static_cast<std::uint8_t>(reg));
        emit8(0xC1);
        emit_modrm(3, reg_field, static_cast<std::uint8_t>(reg));
        emit8(amount);
    }

    void shift_cl(ShiftOp op, Reg reg) {
        std::uint8_t reg_field = 0;
        switch (op) {
        case ShiftOp::Rol: reg_field = 0; break;
        case ShiftOp::Ror: reg_field = 1; break;
        case ShiftOp::Shl: reg_field = 4; break;
        case ShiftOp::Shr: reg_field = 5; break;
        case ShiftOp::Sar: reg_field = 7; break;
        }
        emit_rex(true, reg_field, 0, static_cast<std::uint8_t>(reg));
        emit8(0xD3);
        emit_modrm(3, reg_field, static_cast<std::uint8_t>(reg));
    }

    void bt_reg_imm(Reg reg, std::uint8_t bit) {
        emit_rex(true, 4, 0, static_cast<std::uint8_t>(reg));
        emit8(0x0F);
        emit8(0xBA);
        emit_modrm(3, 4, static_cast<std::uint8_t>(reg));
        emit8(bit);
    }

    void bt_reg_reg(Reg dst, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, static_cast<std::uint8_t>(dst));
        emit8(0x0F);
        emit8(0xA3);
        emit_modrm(3, static_cast<std::uint8_t>(src), static_cast<std::uint8_t>(dst));
    }

    void bsf(Reg dst, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(0xBC);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void bswap(Reg reg) {
        emit_rex(true, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(0x0F);
        emit8(static_cast<std::uint8_t>(0xC8u + (static_cast<std::uint8_t>(reg) & 7u)));
    }

    void setcc(std::uint8_t cc, Reg reg) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(0x0F);
        emit8(static_cast<std::uint8_t>(0x90u + cc));
        emit_modrm(3, 0, static_cast<std::uint8_t>(reg));
    }

    void cmovcc(std::uint8_t cc, Reg dst, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(static_cast<std::uint8_t>(0x40u + cc));
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movzx_byte(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0xB6);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movzx_word(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0xB7);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movsx_byte(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0xBE);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movsx_word(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0xBF);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movsxd_dword(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x63);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void lea_scaled(Reg dst, Reg base, Reg index, std::uint8_t scale, std::int8_t disp) {
        emit_rex(true, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(index), static_cast<std::uint8_t>(base));
        emit8(0x8D);
        emit_modrm(1, static_cast<std::uint8_t>(dst), 4);
        emit_sib(scale, static_cast<std::uint8_t>(index), static_cast<std::uint8_t>(base));
        emit8(static_cast<std::uint8_t>(disp));
    }

    void lea_rip(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x8D);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void mov_mem_reg(Label label, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x89);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void mov_reg_mem(Reg dst, Label label) {
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x8B);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void binary_mem_reg(BinaryOp op, Label label, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, 5);
        switch (op) {
        case BinaryOp::Add: emit8(0x01); break;
        case BinaryOp::Sub: emit8(0x29); break;
        case BinaryOp::And: emit8(0x21); break;
        case BinaryOp::Or: emit8(0x09); break;
        case BinaryOp::Xor: emit8(0x31); break;
        default: emit8(0x01); break;
        }
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void xadd_mem_reg(Label label, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x0F);
        emit8(0xC1);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void cmpxchg_mem_reg(Label label, Reg src) {
        emit_rex(true, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x0F);
        emit8(0xB1);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void push_reg(Reg reg) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(static_cast<std::uint8_t>(0x50u + (static_cast<std::uint8_t>(reg) & 7u)));
    }

    void pop_reg(Reg reg) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(static_cast<std::uint8_t>(0x58u + (static_cast<std::uint8_t>(reg) & 7u)));
    }

    void pushf() {
        emit8(0x9C);
    }

    void lahf() {
        emit8(0x9F);
    }

    void enter(std::uint16_t size) {
        emit8(0xC8);
        emit16(size);
        emit8(0x00);
    }

    void leave() {
        emit8(0xC9);
    }

    void mov_r32_imm(Reg reg, std::uint32_t imm) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(static_cast<std::uint8_t>(0xB8u + (static_cast<std::uint8_t>(reg) & 7u)));
        emit32(imm);
    }

    void mov_r8_imm(Reg reg, std::uint8_t imm) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(reg));
        emit8(static_cast<std::uint8_t>(0xB0u + (static_cast<std::uint8_t>(reg) & 7u)));
        emit8(imm);
    }

    void rep() {
        emit8(0xF3);
    }

    void movsb() { emit8(0xA4); }
    void movsw() { emit8(0x66); emit8(0xA5); }
    void movsd() { emit8(0xA5); }
    void movsq() { emit8(0x48); emit8(0xA5); }
    void lodsb() { emit8(0xAC); }
    void lodsq() { emit8(0x48); emit8(0xAD); }
    void stosb() { emit8(0xAA); }
    void stosq() { emit8(0x48); emit8(0xAB); }
    void cmpsb() { emit8(0xA6); }
    void scasb() { emit8(0xAE); }

    void movdqu_load(Reg dst, Label label) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0xF3);
        emit8(0x0F);
        emit8(0x6F);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movdqu_store(Label label, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0xF3);
        emit8(0x0F);
        emit8(0x7F);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void vmovups_ymm_load(Reg dst, Label label) {
        emit_vex3(false, 0x01, 0x00, true, 0x00, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x10);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void vmovups_ymm_store(Label label, Reg src) {
        emit_vex3(false, 0x01, 0x00, true, 0x00, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x11);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void vinsertf128(Reg dst, Reg src1, Reg src2, std::uint8_t imm) {
        emit_vex3(false, 0x03, static_cast<std::uint8_t>(src1), true, 0x01, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src2));
        emit8(0x18);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src2));
        emit8(imm);
    }

    void vinsertf128_mem(Reg dst, Reg src1, Label label, std::uint8_t imm) {
        emit_vex3(false, 0x03, static_cast<std::uint8_t>(src1), true, 0x01, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x18);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label, 1);
        emit8(imm);
    }

    void paddq(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0xD4);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pxor(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0xEF);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pand(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0xDB);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void por(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0xEB);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movd_mm_reg(Reg dst, Reg src) {
        emit_rex(false, 0, 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movq_mm_reg(Reg dst, Reg src) {
        emit_rex(true, 0, 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movd_mm_mem(Reg dst, Label label) {
        emit_rex(false, 0, 0, 5);
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movq_mm_mem(Reg dst, Label label) {
        emit_rex(true, 0, 0, 5);
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movd_mem_mm(Label label, Reg src) {
        emit_rex(false, 0, 0, 5);
        emit8(0x0F);
        emit8(0x7E);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void movq_mem_mm(Label label, Reg src) {
        emit_rex(true, 0, 0, 5);
        emit8(0x0F);
        emit8(0x7E);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void movd_xmm_reg(Reg dst, Reg src) {
        emit8(0x66);
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movq_xmm_reg(Reg dst, Reg src) {
        emit8(0x66);
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void movd_xmm_mem(Reg dst, Label label) {
        emit8(0x66);
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movq_xmm_mem(Reg dst, Label label) {
        emit8(0x66);
        emit_rex(true, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0x6E);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label);
    }

    void movd_mem_xmm(Label label, Reg src) {
        emit8(0x66);
        emit_rex(false, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x0F);
        emit8(0x7E);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void movq_mem_xmm(Label label, Reg src) {
        emit8(0x66);
        emit_rex(true, static_cast<std::uint8_t>(src), 0, 5);
        emit8(0x0F);
        emit8(0x7E);
        emit_modrm(0, static_cast<std::uint8_t>(src), 5);
        rip_rel32(label);
    }

    void punpcklbw(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x60);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void punpcklwd(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x61);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void punpckldq(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x62);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void punpcklqdq(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x6C);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pcmpeqb(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x74);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pcmpeqw(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x75);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pcmpeqd(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x76);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void pshufd(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x70);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void pshufd_mem(Reg dst, Label label, std::uint8_t imm) {
        emit8(0x66);
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, 5);
        emit8(0x0F);
        emit8(0x70);
        emit_modrm(0, static_cast<std::uint8_t>(dst), 5);
        rip_rel32(label, 1);
        emit8(imm);
    }

    void pslldq(Reg reg, std::uint8_t imm) {
        emit_rex(false, 7, 0, static_cast<std::uint8_t>(reg));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x73);
        emit_modrm(3, 7, static_cast<std::uint8_t>(reg));
        emit8(imm);
    }

    void psrldq(Reg reg, std::uint8_t imm) {
        emit_rex(false, 3, 0, static_cast<std::uint8_t>(reg));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x73);
        emit_modrm(3, 3, static_cast<std::uint8_t>(reg));
        emit8(imm);
    }

    void pshufb(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x38);
        emit8(0x00);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void aesenc(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x38);
        emit8(0xDC);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void aesenclast(Reg dst, Reg src) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x38);
        emit8(0xDD);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
    }

    void aeskeygenassist(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0xDF);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void roundsd(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0x0B);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void roundss(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0x0A);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void pcmpestri(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0x61);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void pcmpestrm(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0x60);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    void pcmpistrm(Reg dst, Reg src, std::uint8_t imm) {
        emit_rex(false, static_cast<std::uint8_t>(dst), 0, static_cast<std::uint8_t>(src));
        emit8(0x66);
        emit8(0x0F);
        emit8(0x3A);
        emit8(0x62);
        emit_modrm(3, static_cast<std::uint8_t>(dst), static_cast<std::uint8_t>(src));
        emit8(imm);
    }

    bool finalize() {
        for (const Patch& patch : patches_) {
            const std::size_t target = labels_[patch.label_id];
            if (target == static_cast<std::size_t>(-1)) {
                return false;
            }
            const std::int64_t next = static_cast<std::int64_t>(patch.offset + patch.size + patch.trailing_size);
            const std::int64_t disp = static_cast<std::int64_t>(target) - next;
            if (patch.size == 4) {
                const std::int32_t value = static_cast<std::int32_t>(disp);
                for (int shift = 0; shift < 32; shift += 8) {
                    bytes_[patch.offset + shift / 8] = static_cast<std::uint8_t>((value >> shift) & 0xFF);
                }
            }
            else {
                const std::int8_t value = static_cast<std::int8_t>(disp);
                bytes_[patch.offset] = static_cast<std::uint8_t>(value);
            }
        }
        return true;
    }

    const std::vector<std::uint8_t>& bytes() const {
        return bytes_;
    }

private:
    struct Patch {
        std::size_t label_id;
        std::size_t offset;
        std::size_t size;
        std::size_t trailing_size;
    };

    std::vector<std::uint8_t> bytes_;
    std::vector<std::size_t> labels_;
    std::vector<Patch> patches_;
};

inline std::vector<ProgramSpec> make_specs(const HostFeatures& features) {
    std::vector<ProgramSpec> specs;
    const BinaryOp binary_ops[] = {
        BinaryOp::Add, BinaryOp::Adc, BinaryOp::Sub, BinaryOp::Sbb,
        BinaryOp::And, BinaryOp::Or, BinaryOp::Xor, BinaryOp::Cmp, BinaryOp::Test
    };
    const BinaryOp imm_ops[] = {
        BinaryOp::Add, BinaryOp::Sub, BinaryOp::And, BinaryOp::Or,
        BinaryOp::Xor, BinaryOp::Cmp, BinaryOp::Test
    };
    const UnaryOp unary_ops[] = { UnaryOp::Inc, UnaryOp::Dec, UnaryOp::Neg, UnaryOp::Not };
    const ShiftOp shift_ops[] = { ShiftOp::Rol, ShiftOp::Ror, ShiftOp::Shl, ShiftOp::Shr, ShiftOp::Sar };
    for (const BinaryOp op : binary_ops) {
        for (std::size_t index = 0; index < kBinaryPairs.size(); ++index) {
            specs.push_back({ Family::BinaryRegReg, static_cast<std::uint32_t>(op), static_cast<std::uint32_t>(index), binary_flag_mask(op), std::string(binary_name(op)) + "_rr_" + kBinaryPairs[index].name });
        }
    }
    for (const BinaryOp op : imm_ops) {
        for (std::size_t index = 0; index < kCoreRegs.size(); ++index) {
            specs.push_back({ Family::BinaryRegImm, static_cast<std::uint32_t>(op), static_cast<std::uint32_t>(index), binary_flag_mask(op), std::string(binary_name(op)) + "_ri_" + kCoreRegs[index].name });
        }
    }
    for (const UnaryOp op : unary_ops) {
        for (std::size_t index = 0; index < kUnaryRegs.size(); ++index) {
            specs.push_back({ Family::UnaryReg, static_cast<std::uint32_t>(op), static_cast<std::uint32_t>(index), unary_flag_mask(op), std::string(unary_name(op)) + "_" + kUnaryRegs[index].name });
        }
    }
    for (const ShiftOp op : shift_ops) {
        for (std::size_t index = 0; index < kCoreRegs.size(); ++index) {
            const std::uint64_t mask = shift_flag_mask(op);
            specs.push_back({ Family::ShiftImm, static_cast<std::uint32_t>(op), static_cast<std::uint32_t>(index), mask, std::string(shift_name(op)) + "_imm_" + kCoreRegs[index].name });
            specs.push_back({ Family::ShiftCl, static_cast<std::uint32_t>(op), static_cast<std::uint32_t>(index), mask, std::string(shift_name(op)) + "_cl_" + kCoreRegs[index].name });
        }
    }
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::BtImm), 0, kBitTestMask, "bt_imm_rax" });
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::BtReg), 0, kBitTestMask, "bt_reg_r8_rcx" });
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::Bsf), 0, kBitScanMask, "bsf_rdx_rbx" });
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::Bswap), 0, kStatusMask, "bswap_r11" });
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::BsfAlt), 0, kBitScanMask, "bsf_r9_r10" });
    specs.push_back({ Family::BitOps, static_cast<std::uint32_t>(BitOp::BswapAlt), 0, kStatusMask, "bswap_rax" });
    for (const CondSpec& condition : kConditions) {
        specs.push_back({ Family::FlagOps, static_cast<std::uint32_t>(FlagProgram::Setcc), condition.code, kStatusMask, std::string("set") + condition.name });
        specs.push_back({ Family::FlagOps, static_cast<std::uint32_t>(FlagProgram::Cmovcc), condition.code, kStatusMask, std::string("cmov") + condition.name });
        specs.push_back({ Family::FlagOps, static_cast<std::uint32_t>(FlagProgram::Jcc), condition.code, kStatusMask, std::string("j") + condition.name });
    }
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovA), 0, 0, "mov_rax_r8" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovB), 0, 0, "mov_r9_rbx" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovzxByte), 0, 0, "movzx_byte" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovzxWord), 0, 0, "movzx_word" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovsxByte), 0, 0, "movsx_byte" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::MovsxWord), 0, 0, "movsx_word" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::Movsxd), 0, 0, "movsxd_dword" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::Lea2), 0, 0, "lea_scale2" });
    specs.push_back({ Family::MoveOps, static_cast<std::uint32_t>(MoveProgram::Lea4), 0, 0, "lea_scale4" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::MovRoundtrip), 0, 0, "mov_mem_roundtrip" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::AddMem), 0, kStatusMask, "add_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::SubMem), 0, kStatusMask, "sub_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::AndMem), 0, kLogicMask, "and_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::OrMem), 0, kLogicMask, "or_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::XorMem), 0, kLogicMask, "xor_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::XaddMem), 0, kStatusMask, "xadd_mem" });
    specs.push_back({ Family::MemoryOps, static_cast<std::uint32_t>(MemoryProgram::CmpxchgMem), 0, kStatusMask, "cmpxchg_mem" });
    specs.push_back({ Family::StackOps, static_cast<std::uint32_t>(StackProgram::PushPopPair), 0, 0, "push_pop_pair" });
    specs.push_back({ Family::StackOps, static_cast<std::uint32_t>(StackProgram::PushPopFlags), 0, 0, "pushf_pop_lahf" });
    specs.push_back({ Family::StackOps, static_cast<std::uint32_t>(StackProgram::EnterLeave), 0, 0, "enter_leave" });
    specs.push_back({ Family::StackOps, static_cast<std::uint32_t>(StackProgram::PushChain), 0, 0, "push_chain" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Movsb), 0, 0, "movsb" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Movsw), 0, 0, "movsw" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Movsd), 0, 0, "movsd" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Movsq), 0, 0, "movsq" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::RepMovsb), 0, 0, "rep_movsb" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::RepMovsw), 0, 0, "rep_movsw" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Lodsb), 0, 0, "lodsb" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Lodsq), 0, 0, "lodsq" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Stosb), 0, 0, "stosb" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Stosq), 0, 0, "stosq" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Cmpsb), 0, kStatusMask, "cmpsb" });
    specs.push_back({ Family::StringOps, static_cast<std::uint32_t>(StringProgram::Scasb), 0, kStatusMask, "scasb" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Paddq), 0, 0, "paddq" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pxor), 0, 0, "pxor" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pand), 0, 0, "pand" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Por), 0, 0, "por" });
    if (features.avx) {
        for (std::size_t index = 0; index < kVinsertf128Immediates.size(); ++index) {
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Vinsertf128), static_cast<std::uint32_t>(index), 0, "vinsertf128_reg_imm" + std::to_string(kVinsertf128Immediates[index]) });
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Vinsertf128), static_cast<std::uint32_t>(index + kVinsertf128Immediates.size()), 0, "vinsertf128_mem_imm" + std::to_string(kVinsertf128Immediates[index]) });
        }
    }
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovdMmReg), 0, 0, "movd_mm_reg" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovqMmReg), 0, 0, "movq_mm_reg" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovdMmMem), 0, 0, "movd_mm_mem" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovqMmMem), 0, 0, "movq_mm_mem" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovdXmmReg), 0, 0, "movd_xmm_reg" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovqXmmReg), 0, 0, "movq_xmm_reg" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovdXmmMem), 0, 0, "movd_xmm_mem" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::MovqXmmMem), 0, 0, "movq_xmm_mem" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Punpcklbw), 0, 0, "punpcklbw" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Punpcklwd), 0, 0, "punpcklwd" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Punpckldq), 0, 0, "punpckldq" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Punpcklqdq), 0, 0, "punpcklqdq" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpeqb), 0, 0, "pcmpeqb" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpeqw), 0, 0, "pcmpeqw" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpeqd), 0, 0, "pcmpeqd" });
    for (std::size_t index = 0; index < kPshufdImmediates.size(); ++index) {
        specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pshufd), static_cast<std::uint32_t>(index), 0, "pshufd_reg_imm" + std::to_string(kPshufdImmediates[index]) });
        specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pshufd), static_cast<std::uint32_t>(index + kPshufdImmediates.size()), 0, "pshufd_mem_imm" + std::to_string(kPshufdImmediates[index]) });
    }
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pslldq), 0, 0, "pslldq" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Psrldq), 0, 0, "psrldq" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::PaddqPxor), 0, 0, "paddq_pxor" });
    specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Movdqu), 0, 0, "movdqu_roundtrip" });
    if (features.ssse3) {
        specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pshufb), 0, 0, "pshufb" });
    }
    if (features.aes) {
        specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Aesenc), 0, 0, "aesenc" });
        specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Aesenclast), 0, 0, "aesenclast" });
        for (std::size_t index = 0; index < kAesKeygenAssistImmediates.size(); ++index) {
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Aeskeygenassist), static_cast<std::uint32_t>(index), 0, "aeskeygenassist_imm" + std::to_string(kAesKeygenAssistImmediates[index]) });
        }
    }
    if (features.sse41) {
        for (std::size_t index = 0; index < kRoundImmediates.size(); ++index) {
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Roundsd), static_cast<std::uint32_t>(index), 0, "roundsd_imm" + std::to_string(kRoundImmediates[index]) });
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Roundss), static_cast<std::uint32_t>(index), 0, "roundss_imm" + std::to_string(kRoundImmediates[index]) });
        }
    }
    if (features.sse42) {
        for (std::size_t index = 0; index < kPcmpestriImmediates.size(); ++index) {
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpestrm), static_cast<std::uint32_t>(index), kPcmpstrMask, "pcmpestrm_imm" + std::to_string(kPcmpestriImmediates[index]) });
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpestri), static_cast<std::uint32_t>(index), kPcmpstrMask, "pcmpestri_imm" + std::to_string(kPcmpestriImmediates[index]) });
            specs.push_back({ Family::VectorOps, static_cast<std::uint32_t>(VectorProgram::Pcmpistrm), static_cast<std::uint32_t>(index), kPcmpstrMask, "pcmpistrm_imm" + std::to_string(kPcmpestriImmediates[index]) });
        }
    }
    specs.push_back({ Family::ControlFlow, static_cast<std::uint32_t>(ControlProgram::JmpSkip), 0, kStatusMask, "jmp_skip" });
    specs.push_back({ Family::ControlFlow, static_cast<std::uint32_t>(ControlProgram::CallAdd), 0, kStatusMask, "call_add" });
    specs.push_back({ Family::ControlFlow, static_cast<std::uint32_t>(ControlProgram::CallXor), 0, kLogicMask, "call_xor" });
    specs.push_back({ Family::ControlFlow, static_cast<std::uint32_t>(ControlProgram::CallLea), 0, 0, "call_lea" });
    return specs;
}

inline BuiltCase build_case(const ProgramSpec& spec, std::uint64_t seed) {
    BuiltCase built{};
    built.spec = spec;
    built.seed = seed;
    built.initial_context = make_initial_context(seed);
    auto data = make_initial_data(seed);

    CodeBuilder code;
    const CodeBuilder::Label slot0 = code.make_label();
    const CodeBuilder::Label slot1 = code.make_label();
    const CodeBuilder::Label slot2 = code.make_label();
    const CodeBuilder::Label slot3 = code.make_label();
    const CodeBuilder::Label buffer0 = code.make_label();
    const CodeBuilder::Label buffer1 = code.make_label();
    const CodeBuilder::Label label_true = code.make_label();
    const CodeBuilder::Label label_false = code.make_label();
    const CodeBuilder::Label label_end = code.make_label();
    const CodeBuilder::Label helper = code.make_label();
    const CodeBuilder::Label after_helper = code.make_label();

    switch (spec.family) {
    case Family::BinaryRegReg: {
        const auto op = static_cast<BinaryOp>(spec.op);
        const PairSpec pair = kBinaryPairs[spec.variant % kBinaryPairs.size()];
        code.binary_reg_reg(op, pair.dst, pair.src);
        break;
    }
    case Family::BinaryRegImm: {
        const auto op = static_cast<BinaryOp>(spec.op);
        const Reg reg = kCoreRegs[spec.variant % kCoreRegs.size()].reg;
        std::uint32_t imm = narrow32(seeded(seed, 0x600));
        if (imm == 0) imm = 1;
        code.binary_reg_imm(op, reg, imm);
        break;
    }
    case Family::UnaryReg: {
        const auto op = static_cast<UnaryOp>(spec.op);
        const Reg reg = kUnaryRegs[spec.variant % kUnaryRegs.size()].reg;
        code.unary_reg(op, reg);
        break;
    }
    case Family::ShiftImm: {
        const auto op = static_cast<ShiftOp>(spec.op);
        const Reg reg = kCoreRegs[spec.variant % kCoreRegs.size()].reg;
        code.shift_imm(op, reg, 1);
        break;
    }
    case Family::ShiftCl: {
        const auto op = static_cast<ShiftOp>(spec.op);
        const Reg reg = kCoreRegs[spec.variant % kCoreRegs.size()].reg;
        built.initial_context.regs[static_cast<std::size_t>(Reg::RCX)] = 1;
        code.shift_cl(op, reg);
        break;
    }
    case Family::BitOps: {
        switch (static_cast<BitOp>(spec.op)) {
        case BitOp::BtImm:
            code.bt_reg_imm(Reg::RAX, static_cast<std::uint8_t>(seed % 63));
            break;
        case BitOp::BtReg:
            built.initial_context.regs[static_cast<std::size_t>(Reg::RCX)] = seed % 63;
            code.bt_reg_reg(Reg::R8, Reg::RCX);
            break;
        case BitOp::Bsf:
            built.initial_context.regs[static_cast<std::size_t>(Reg::RBX)] |= 1;
            code.bsf(Reg::RDX, Reg::RBX);
            break;
        case BitOp::Bswap:
            code.bswap(Reg::R11);
            break;
        case BitOp::BsfAlt:
            built.initial_context.regs[static_cast<std::size_t>(Reg::R10)] |= 1;
            code.bsf(Reg::R9, Reg::R10);
            break;
        case BitOp::BswapAlt:
            code.bswap(Reg::RAX);
            break;
        }
        break;
    }
    case Family::FlagOps: {
        const std::uint8_t cc = static_cast<std::uint8_t>(spec.variant);
        const auto program = static_cast<FlagProgram>(spec.op);
        code.binary_reg_reg(BinaryOp::Cmp, Reg::RAX, Reg::RBX);
        if (program == FlagProgram::Setcc) {
            code.setcc(cc, Reg::RAX);
        }
        else if (program == FlagProgram::Cmovcc) {
            code.cmovcc(cc, Reg::R10, Reg::R11);
        }
        else {
            code.jcc32(cc, label_true);
            code.mov_reg_reg(Reg::R12, Reg::R13);
            code.jmp32(label_end);
            code.mark(label_true);
            code.mov_reg_reg(Reg::R12, Reg::R14);
            code.mark(label_end);
        }
        break;
    }
    case Family::MoveOps: {
        switch (static_cast<MoveProgram>(spec.op)) {
        case MoveProgram::MovA:
            code.mov_reg_reg(Reg::RAX, Reg::R8);
            break;
        case MoveProgram::MovB:
            code.mov_reg_reg(Reg::R9, Reg::RBX);
            break;
        case MoveProgram::MovzxByte:
            code.movzx_byte(Reg::RAX, slot0);
            break;
        case MoveProgram::MovzxWord:
            code.movzx_word(Reg::R10, slot0);
            break;
        case MoveProgram::MovsxByte:
            data[0] |= 0x80u;
            code.movsx_byte(Reg::R11, slot0);
            break;
        case MoveProgram::MovsxWord:
            data[0] = 0x34u;
            data[1] = 0xF2u;
            code.movsx_word(Reg::R12, slot0);
            break;
        case MoveProgram::Movsxd:
            data[0] = 0x78u;
            data[1] = 0x56u;
            data[2] = 0x34u;
            data[3] = 0xF2u;
            code.movsxd_dword(Reg::R13, slot0);
            break;
        case MoveProgram::Lea2:
            code.lea_scaled(Reg::R14, Reg::RBX, Reg::RSI, 1, 0x24);
            break;
        case MoveProgram::Lea4:
            code.lea_scaled(Reg::R15, Reg::R8, Reg::R9, 2, 0x18);
            break;
        }
        break;
    }
    case Family::MemoryOps: {
        switch (static_cast<MemoryProgram>(spec.op)) {
        case MemoryProgram::MovRoundtrip:
            code.mov_mem_reg(buffer0, Reg::RAX);
            code.mov_reg_mem(Reg::RBX, buffer0);
            break;
        case MemoryProgram::AddMem:
            code.binary_mem_reg(BinaryOp::Add, buffer0, Reg::R8);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::SubMem:
            code.binary_mem_reg(BinaryOp::Sub, buffer0, Reg::R9);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::AndMem:
            code.binary_mem_reg(BinaryOp::And, buffer0, Reg::R10);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::OrMem:
            code.binary_mem_reg(BinaryOp::Or, buffer0, Reg::R11);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::XorMem:
            code.binary_mem_reg(BinaryOp::Xor, buffer0, Reg::R12);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::XaddMem:
            code.xadd_mem_reg(buffer0, Reg::R13);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        case MemoryProgram::CmpxchgMem:
            code.cmpxchg_mem_reg(buffer0, Reg::R14);
            code.mov_reg_mem(Reg::RDX, buffer0);
            break;
        }
        break;
    }
    case Family::StackOps: {
        switch (static_cast<StackProgram>(spec.op)) {
        case StackProgram::PushPopPair:
            code.push_reg(Reg::RAX);
            code.push_reg(Reg::RBX);
            code.pop_reg(Reg::R10);
            code.pop_reg(Reg::R11);
            break;
        case StackProgram::PushPopFlags:
            code.pushf();
            code.pop_reg(Reg::RAX);
            code.lahf();
            break;
        case StackProgram::EnterLeave:
            code.enter(0x20);
            code.mov_reg_reg(Reg::R12, Reg::RBP);
            code.leave();
            break;
        case StackProgram::PushChain:
            code.push_reg(Reg::R8);
            code.push_reg(Reg::R9);
            code.push_reg(Reg::R10);
            code.pop_reg(Reg::R11);
            code.pop_reg(Reg::R12);
            code.pop_reg(Reg::R13);
            break;
        }
        break;
    }
    case Family::StringOps: {
        const auto program = static_cast<StringProgram>(spec.op);
        code.lea_rip(Reg::RSI, buffer0);
        code.lea_rip(Reg::RDI, buffer1);
        code.mov_r32_imm(Reg::RCX, 4);
        switch (program) {
        case StringProgram::Movsb:
            code.movsb();
            break;
        case StringProgram::Movsw:
            code.movsw();
            break;
        case StringProgram::Movsd:
            code.movsd();
            break;
        case StringProgram::Movsq:
            code.movsq();
            break;
        case StringProgram::RepMovsb:
            code.mov_r32_imm(Reg::RCX, 12);
            code.rep();
            code.movsb();
            break;
        case StringProgram::RepMovsw:
            code.mov_r32_imm(Reg::RCX, 6);
            code.rep();
            code.movsw();
            break;
        case StringProgram::Lodsb:
            code.lodsb();
            break;
        case StringProgram::Lodsq:
            code.lodsq();
            break;
        case StringProgram::Stosb:
            code.mov_r8_imm(Reg::RAX, narrow8(seeded(seed, 0x700)));
            code.stosb();
            break;
        case StringProgram::Stosq:
            code.stosq();
            break;
        case StringProgram::Cmpsb:
            code.cmpsb();
            break;
        case StringProgram::Scasb:
            code.mov_r8_imm(Reg::RAX, data[kSlotSize * 4 + 5]);
            code.scasb();
            break;
        }
        break;
    }
    case Family::VectorOps: {
        const auto program = static_cast<VectorProgram>(spec.op);
        code.movdqu_load(Reg::RAX, slot0);
        code.movdqu_load(Reg::RCX, slot1);
        switch (program) {
        case VectorProgram::Paddq:
            code.paddq(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pxor:
            code.pxor(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pand:
            code.pand(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Por:
            code.por(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Vinsertf128: {
            const std::uint8_t imm8 = kVinsertf128Immediates[spec.variant % kVinsertf128Immediates.size()];
            code.vmovups_ymm_load(Reg::RAX, slot0);
            if (spec.variant < kVinsertf128Immediates.size()) {
                code.movdqu_load(Reg::RCX, slot2);
                code.vinsertf128(Reg::RDX, Reg::RAX, Reg::RCX, imm8);
            }
            else {
                code.vinsertf128_mem(Reg::RDX, Reg::RAX, slot2, imm8);
            }
            code.vmovups_ymm_store(buffer0, Reg::RDX);
            break;
        }
        case VectorProgram::MovdMmReg:
            code.movd_mm_reg(Reg::RAX, Reg::R8);
            code.movd_mem_mm(buffer0, Reg::RAX);
            break;
        case VectorProgram::MovqMmReg:
            code.movq_mm_reg(Reg::RAX, Reg::R9);
            code.movq_mem_mm(buffer0, Reg::RAX);
            break;
        case VectorProgram::MovdMmMem:
            code.movd_mm_mem(Reg::RAX, slot0);
            code.movd_mem_mm(buffer0, Reg::RAX);
            break;
        case VectorProgram::MovqMmMem:
            code.movq_mm_mem(Reg::RAX, slot0);
            code.movq_mem_mm(buffer0, Reg::RAX);
            break;
        case VectorProgram::MovdXmmReg:
            code.movd_xmm_reg(Reg::RAX, Reg::R10);
            code.movdqu_store(buffer0, Reg::RAX);
            code.movd_mem_xmm(buffer1, Reg::RAX);
            break;
        case VectorProgram::MovqXmmReg:
            code.movq_xmm_reg(Reg::RAX, Reg::R11);
            code.movdqu_store(buffer0, Reg::RAX);
            code.movq_mem_xmm(buffer1, Reg::RAX);
            break;
        case VectorProgram::MovdXmmMem:
            code.movd_xmm_mem(Reg::RAX, slot0);
            code.movdqu_store(buffer0, Reg::RAX);
            code.movd_mem_xmm(buffer1, Reg::RAX);
            break;
        case VectorProgram::MovqXmmMem:
            code.movq_xmm_mem(Reg::RAX, slot0);
            code.movdqu_store(buffer0, Reg::RAX);
            code.movq_mem_xmm(buffer1, Reg::RAX);
            break;
        case VectorProgram::Punpcklbw:
            code.punpcklbw(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Punpcklwd:
            code.punpcklwd(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Punpckldq:
            code.punpckldq(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Punpcklqdq:
            code.punpcklqdq(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pcmpeqb:
            code.pcmpeqb(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pcmpeqw:
            code.pcmpeqw(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pcmpeqd:
            code.pcmpeqd(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pshufd: {
            const std::size_t imm_index = spec.variant % kPshufdImmediates.size();
            const std::uint8_t imm8 = kPshufdImmediates[imm_index];
            if (spec.variant < kPshufdImmediates.size()) {
                code.pshufd(Reg::RAX, Reg::RAX, imm8);
            }
            else {
                code.pshufd_mem(Reg::RAX, slot1, imm8);
            }
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        }
        case VectorProgram::Pslldq:
            code.pslldq(Reg::RAX, 4);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Psrldq:
            code.psrldq(Reg::RAX, 5);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::PaddqPxor:
            code.paddq(Reg::RAX, Reg::RCX);
            code.pxor(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Movdqu:
            code.movdqu_store(buffer0, Reg::RAX);
            code.movdqu_load(Reg::RDX, buffer0);
            code.movdqu_store(buffer1, Reg::RDX);
            break;
        case VectorProgram::Pshufb:
            code.pshufb(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Aesenc:
            code.aesenc(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Aesenclast:
            code.aesenclast(Reg::RAX, Reg::RCX);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Aeskeygenassist:
            code.aeskeygenassist(Reg::RAX, Reg::RCX, kAesKeygenAssistImmediates[spec.variant % kAesKeygenAssistImmediates.size()]);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Roundsd:
            code.roundsd(Reg::RAX, Reg::RCX, kRoundImmediates[spec.variant % kRoundImmediates.size()]);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Roundss:
            code.roundss(Reg::RAX, Reg::RCX, kRoundImmediates[spec.variant % kRoundImmediates.size()]);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        case VectorProgram::Pcmpestrm: {
            const std::uint8_t imm8 = kPcmpestriImmediates[spec.variant % kPcmpestriImmediates.size()];
            const std::int32_t max_length = (imm8 & 0x01u) != 0 ? 8 : 16;
            const std::int32_t length_a = static_cast<std::int32_t>(seeded(seed, 0x820) % static_cast<std::uint64_t>(max_length * 4 + 1)) - max_length * 2;
            const std::int32_t length_b = static_cast<std::int32_t>(seeded(seed, 0x821) % static_cast<std::uint64_t>(max_length * 4 + 1)) - max_length * 2;
            built.initial_context.regs[static_cast<std::size_t>(Reg::RAX)] = static_cast<std::uint64_t>(static_cast<std::int64_t>(length_a));
            built.initial_context.regs[static_cast<std::size_t>(Reg::RDX)] = static_cast<std::uint64_t>(static_cast<std::int64_t>(length_b));
            code.pcmpestrm(Reg::RAX, Reg::RCX, imm8);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        }
        case VectorProgram::Pcmpestri: {
            const std::uint8_t imm8 = kPcmpestriImmediates[spec.variant % kPcmpestriImmediates.size()];
            const std::int32_t max_length = (imm8 & 0x01u) != 0 ? 8 : 16;
            const std::int32_t length_a = static_cast<std::int32_t>(seeded(seed, 0x830) % static_cast<std::uint64_t>(max_length * 4 + 1)) - max_length * 2;
            const std::int32_t length_b = static_cast<std::int32_t>(seeded(seed, 0x831) % static_cast<std::uint64_t>(max_length * 4 + 1)) - max_length * 2;
            built.initial_context.regs[static_cast<std::size_t>(Reg::RAX)] = static_cast<std::uint64_t>(static_cast<std::int64_t>(length_a));
            built.initial_context.regs[static_cast<std::size_t>(Reg::RDX)] = static_cast<std::uint64_t>(static_cast<std::int64_t>(length_b));
            code.pcmpestri(Reg::RAX, Reg::RCX, imm8);
            break;
        }
        case VectorProgram::Pcmpistrm: {
            const std::uint8_t imm8 = kPcmpestriImmediates[spec.variant % kPcmpestriImmediates.size()];
            code.pcmpistrm(Reg::RAX, Reg::RCX, imm8);
            code.movdqu_store(buffer0, Reg::RAX);
            break;
        }
        }
        break;
    }
    case Family::ControlFlow: {
        switch (static_cast<ControlProgram>(spec.op)) {
        case ControlProgram::JmpSkip:
            code.jmp32(label_end);
            code.mov_reg_reg(Reg::RAX, Reg::R15);
            code.mark(label_end);
            code.binary_reg_reg(BinaryOp::Add, Reg::RAX, Reg::RBX);
            break;
        case ControlProgram::CallAdd:
            code.call32(helper);
            code.mov_reg_reg(Reg::R8, Reg::RAX);
            code.jmp32(after_helper);
            code.mark(helper);
            code.binary_reg_reg(BinaryOp::Add, Reg::RAX, Reg::RBX);
            code.ret();
            code.mark(after_helper);
            break;
        case ControlProgram::CallXor:
            code.call32(helper);
            code.mov_reg_reg(Reg::R9, Reg::R10);
            code.jmp32(after_helper);
            code.mark(helper);
            code.binary_reg_reg(BinaryOp::Xor, Reg::R10, Reg::R11);
            code.ret();
            code.mark(after_helper);
            break;
        case ControlProgram::CallLea:
            code.call32(helper);
            code.mov_reg_reg(Reg::R12, Reg::R14);
            code.jmp32(after_helper);
            code.mark(helper);
            code.lea_scaled(Reg::R14, Reg::RAX, Reg::RBX, 1, 0x10);
            code.ret();
            code.mark(after_helper);
            break;
        }
        break;
    }
    }

    code.ret();
    code.align(16);
    built.data_offset = static_cast<std::uint32_t>(code.offset());
    code.mark(slot0);
    code.emit_bytes(data.data(), kSlotSize);
    code.mark(slot1);
    code.emit_bytes(data.data() + kSlotSize, kSlotSize);
    code.mark(slot2);
    code.emit_bytes(data.data() + kSlotSize * 2, kSlotSize);
    code.mark(slot3);
    code.emit_bytes(data.data() + kSlotSize * 3, kSlotSize);
    code.mark(buffer0);
    code.emit_bytes(data.data() + kSlotSize * 4, kBufferSize);
    code.mark(buffer1);
    code.emit_bytes(data.data() + kSlotSize * 4 + kBufferSize, kBufferSize);
    if (!code.finalize()) {
        built.image.clear();
        return built;
    }
    built.image = code.bytes();
    return built;
}

inline bool write_engine_reg(cpueaxh_engine* engine, int reg, std::uint64_t value) {
    return cpueaxh_reg_write(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool read_engine_reg(cpueaxh_engine* engine, int reg, std::uint64_t& value) {
    return cpueaxh_reg_read(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool write_engine_reg32(cpueaxh_engine* engine, int reg, std::uint32_t value) {
    return cpueaxh_reg_write(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool read_engine_reg32(cpueaxh_engine* engine, int reg, std::uint32_t& value) {
    return cpueaxh_reg_read(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool write_engine_reg16(cpueaxh_engine* engine, int reg, std::uint16_t value) {
    return cpueaxh_reg_write(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool read_engine_reg16(cpueaxh_engine* engine, int reg, std::uint16_t& value) {
    return cpueaxh_reg_read(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool write_engine_xmm(cpueaxh_engine* engine, int reg, const cpueaxh_x86_xmm& value) {
    return cpueaxh_reg_write(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool read_engine_xmm(cpueaxh_engine* engine, int reg, cpueaxh_x86_xmm& value) {
    return cpueaxh_reg_read(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool write_engine_ymm(cpueaxh_engine* engine, int reg, const cpueaxh_x86_ymm& value) {
    return cpueaxh_reg_write(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool read_engine_ymm(cpueaxh_engine* engine, int reg, cpueaxh_x86_ymm& value) {
    return cpueaxh_reg_read(engine, reg, &value) == CPUEAXH_ERR_OK;
}

inline bool run_context_api_case(const std::string& name, std::uint64_t seed, Failure& failure) {
    cpueaxh_engine* engine = nullptr;
    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_open failed";
        return false;
    }

    bool ok = false;
    do {
        cpueaxh_x86_context initial = make_extended_context(seed);
        initial.rip = seeded(seed, 0xC00);

        err = cpueaxh_context_write(engine, &initial);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_context_write failed";
            break;
        }

        cpueaxh_x86_context roundtrip{};
        err = cpueaxh_context_read(engine, &roundtrip);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_context_read failed";
            break;
        }
        if (!equal_context(initial, roundtrip)) {
            failure.case_name = name;
            failure.detail = "context roundtrip mismatch";
            break;
        }

        cpueaxh_x86_ymm ymm_written = make_seeded_ymm(seed, 0xC10);
        if (!write_engine_ymm(engine, CPUEAXH_X86_REG_YMM3, ymm_written)) {
            failure.case_name = name;
            failure.detail = "write ymm3 failed";
            break;
        }
        cpueaxh_x86_ymm ymm_read{};
        if (!read_engine_ymm(engine, CPUEAXH_X86_REG_YMM3, ymm_read) ||
            !equal_xmm(ymm_read.lower, ymm_written.lower) ||
            !equal_xmm(ymm_read.upper, ymm_written.upper)) {
            failure.case_name = name;
            failure.detail = "read ymm3 mismatch";
            break;
        }

        cpueaxh_x86_xmm xmm_written = make_seeded_xmm(seed, 0xC20);
        if (!write_engine_xmm(engine, CPUEAXH_X86_REG_XMM3, xmm_written)) {
            failure.case_name = name;
            failure.detail = "write xmm3 failed";
            break;
        }
        cpueaxh_x86_xmm xmm_read{};
        if (!read_engine_xmm(engine, CPUEAXH_X86_REG_XMM3, xmm_read) || !equal_xmm(xmm_read, xmm_written)) {
            failure.case_name = name;
            failure.detail = "read xmm3 mismatch";
            break;
        }
        if (!read_engine_ymm(engine, CPUEAXH_X86_REG_YMM3, ymm_read) ||
            !equal_xmm(ymm_read.lower, xmm_written) ||
            !equal_xmm(ymm_read.upper, ymm_written.upper)) {
            failure.case_name = name;
            failure.detail = "ymm3/xmm3 coupling mismatch";
            break;
        }

        const std::uint64_t mm0_written = seeded(seed, 0xC30);
        if (!write_engine_reg(engine, CPUEAXH_X86_REG_MM0, mm0_written)) {
            failure.case_name = name;
            failure.detail = "write mm0 failed";
            break;
        }
        std::uint64_t mm0_read = 0;
        if (!read_engine_reg(engine, CPUEAXH_X86_REG_MM0, mm0_read) || mm0_read != mm0_written) {
            failure.case_name = name;
            failure.detail = "read mm0 mismatch";
            break;
        }

        const std::uint32_t mxcsr_written = static_cast<std::uint32_t>(0x1F80u | (seeded(seed, 0xC31) & 0x1F3Fu));
        if (!write_engine_reg32(engine, CPUEAXH_X86_REG_MXCSR, mxcsr_written)) {
            failure.case_name = name;
            failure.detail = "write mxcsr failed";
            break;
        }
        std::uint32_t mxcsr_read = 0;
        if (!read_engine_reg32(engine, CPUEAXH_X86_REG_MXCSR, mxcsr_read) || mxcsr_read != mxcsr_written) {
            failure.case_name = name;
            failure.detail = "read mxcsr mismatch";
            break;
        }

        const std::uint16_t fs_selector = static_cast<std::uint16_t>(seeded(seed, 0xC40) & 0xFFF8u);
        const std::uint64_t fs_base = seeded(seed, 0xC41);
        const std::uint32_t fs_granularity = static_cast<std::uint32_t>(seeded(seed, 0xC44) & 1u);
        if (!write_engine_reg16(engine, CPUEAXH_X86_REG_FS_SELECTOR, fs_selector) ||
            !write_engine_reg(engine, CPUEAXH_X86_REG_FS_BASE, fs_base) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_FS_GRANULARITY, fs_granularity)) {
            failure.case_name = name;
            failure.detail = "write fs failed";
            break;
        }
        std::uint16_t fs_selector_read = 0;
        std::uint64_t fs_base_read = 0;
        std::uint32_t fs_granularity_read = 0;
        if (!read_engine_reg16(engine, CPUEAXH_X86_REG_FS_SELECTOR, fs_selector_read) ||
            !read_engine_reg(engine, CPUEAXH_X86_REG_FS_BASE, fs_base_read) ||
            !read_engine_reg32(engine, CPUEAXH_X86_REG_FS_GRANULARITY, fs_granularity_read) ||
            fs_selector_read != fs_selector ||
            fs_base_read != fs_base ||
            fs_granularity_read != fs_granularity) {
            failure.case_name = name;
            failure.detail = "read fs mismatch";
            break;
        }

        const std::uint16_t gs_selector = static_cast<std::uint16_t>(seeded(seed, 0xC42) & 0xFFF8u);
        const std::uint64_t gs_base = seeded(seed, 0xC43);
        const std::uint32_t gs_db = static_cast<std::uint32_t>(seeded(seed, 0xC45) & 1u);
        const std::uint32_t gs_long_mode = static_cast<std::uint32_t>(seeded(seed, 0xC46) & 1u);
        if (!write_engine_reg16(engine, CPUEAXH_X86_REG_GS_SELECTOR, gs_selector) ||
            !write_engine_reg(engine, CPUEAXH_X86_REG_GS_BASE, gs_base) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_GS_DB, gs_db) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_GS_LONG_MODE, gs_long_mode)) {
            failure.case_name = name;
            failure.detail = "write gs failed";
            break;
        }
        std::uint32_t gs_db_read = 0;
        std::uint32_t gs_long_mode_read = 0;
        if (!read_engine_reg32(engine, CPUEAXH_X86_REG_GS_DB, gs_db_read) ||
            !read_engine_reg32(engine, CPUEAXH_X86_REG_GS_LONG_MODE, gs_long_mode_read) ||
            gs_db_read != gs_db ||
            gs_long_mode_read != gs_long_mode) {
            failure.case_name = name;
            failure.detail = "read gs mismatch";
            break;
        }

        const std::uint32_t es_limit = narrow32(seeded(seed, 0xC47));
        const std::uint32_t cs_type = static_cast<std::uint32_t>(seeded(seed, 0xC48) & 0x1Fu);
        const std::uint32_t ss_dpl = static_cast<std::uint32_t>(seeded(seed, 0xC49) & 0x3u);
        const std::uint32_t ds_present = static_cast<std::uint32_t>(seeded(seed, 0xC4A) & 1u);
        if (!write_engine_reg32(engine, CPUEAXH_X86_REG_ES_LIMIT, es_limit) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_CS_TYPE, cs_type) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_SS_DPL, ss_dpl) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_DS_PRESENT, ds_present)) {
            failure.case_name = name;
            failure.detail = "write segment descriptor fields failed";
            break;
        }
        std::uint32_t es_limit_read = 0;
        std::uint32_t cs_type_read = 0;
        std::uint32_t ss_dpl_read = 0;
        std::uint32_t ds_present_read = 0;
        if (!read_engine_reg32(engine, CPUEAXH_X86_REG_ES_LIMIT, es_limit_read) ||
            !read_engine_reg32(engine, CPUEAXH_X86_REG_CS_TYPE, cs_type_read) ||
            !read_engine_reg32(engine, CPUEAXH_X86_REG_SS_DPL, ss_dpl_read) ||
            !read_engine_reg32(engine, CPUEAXH_X86_REG_DS_PRESENT, ds_present_read) ||
            es_limit_read != es_limit ||
            cs_type_read != cs_type ||
            ss_dpl_read != ss_dpl ||
            ds_present_read != ds_present) {
            failure.case_name = name;
            failure.detail = "read segment descriptor fields mismatch";
            break;
        }

        const std::uint64_t gdtr_base = seeded(seed, 0xC50);
        const std::uint16_t gdtr_limit = static_cast<std::uint16_t>(seeded(seed, 0xC51) & 0xFFFFu);
        const std::uint64_t ldtr_base = seeded(seed, 0xC52);
        const std::uint16_t ldtr_limit = static_cast<std::uint16_t>(seeded(seed, 0xC53) & 0xFFFFu);
        if (!write_engine_reg(engine, CPUEAXH_X86_REG_GDTR_BASE, gdtr_base) ||
            !write_engine_reg16(engine, CPUEAXH_X86_REG_GDTR_LIMIT, gdtr_limit) ||
            !write_engine_reg(engine, CPUEAXH_X86_REG_LDTR_BASE, ldtr_base) ||
            !write_engine_reg16(engine, CPUEAXH_X86_REG_LDTR_LIMIT, ldtr_limit)) {
            failure.case_name = name;
            failure.detail = "write descriptor tables failed";
            break;
        }

        const std::uint32_t exception_code = CPUEAXH_EXCEPTION_GP;
        const std::uint32_t exception_error = narrow32(seeded(seed, 0xC60));
        if (!write_engine_reg32(engine, CPUEAXH_X86_REG_EXCEPTION_CODE, exception_code) ||
            !write_engine_reg32(engine, CPUEAXH_X86_REG_EXCEPTION_ERROR_CODE, exception_error)) {
            failure.case_name = name;
            failure.detail = "write exception state failed";
            break;
        }

        const std::uint64_t cr1_written = seeded(seed, 0xC70);
        const std::uint64_t cr15_written = seeded(seed, 0xC71);
        if (!write_engine_reg(engine, CPUEAXH_X86_REG_CR1, cr1_written) ||
            !write_engine_reg(engine, CPUEAXH_X86_REG_CR15, cr15_written)) {
            failure.case_name = name;
            failure.detail = "write extra control regs failed";
            break;
        }
        std::uint64_t cr1_read = 0;
        std::uint64_t cr15_read = 0;
        if (!read_engine_reg(engine, CPUEAXH_X86_REG_CR1, cr1_read) ||
            !read_engine_reg(engine, CPUEAXH_X86_REG_CR15, cr15_read) ||
            cr1_read != cr1_written ||
            cr15_read != cr15_written) {
            failure.case_name = name;
            failure.detail = "read extra control regs mismatch";
            break;
        }

        const std::uint32_t processor_id = narrow32(seeded(seed, 0xC72));
        if (!write_engine_reg32(engine, CPUEAXH_X86_REG_PROCESSOR_ID, processor_id)) {
            failure.case_name = name;
            failure.detail = "write processor_id failed";
            break;
        }
        std::uint32_t processor_id_read = 0;
        if (!read_engine_reg32(engine, CPUEAXH_X86_REG_PROCESSOR_ID, processor_id_read) || processor_id_read != processor_id) {
            failure.case_name = name;
            failure.detail = "read processor_id mismatch";
            break;
        }

        cpueaxh_x86_context final_context{};
        err = cpueaxh_context_read(engine, &final_context);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "final context read failed";
            break;
        }
        if (!equal_xmm(final_context.xmm[3], xmm_written) ||
            !equal_xmm(final_context.ymm_upper[3], ymm_written.upper) ||
            final_context.mm[0] != mm0_written ||
            final_context.mxcsr != mxcsr_written ||
            final_context.es.descriptor.limit != es_limit ||
            final_context.cs.descriptor.type != cs_type ||
            final_context.ss.descriptor.dpl != ss_dpl ||
            final_context.ds.descriptor.present != ds_present ||
            final_context.fs.selector != fs_selector ||
            final_context.fs.descriptor.base != fs_base ||
            final_context.fs.descriptor.granularity != fs_granularity ||
            final_context.gs.selector != gs_selector ||
            final_context.gs.descriptor.base != gs_base ||
            final_context.gs.descriptor.db != gs_db ||
            final_context.gs.descriptor.long_mode != gs_long_mode ||
            final_context.gdtr_base != gdtr_base ||
            final_context.gdtr_limit != gdtr_limit ||
            final_context.ldtr_base != ldtr_base ||
            final_context.ldtr_limit != ldtr_limit ||
            final_context.control_regs[1] != cr1_written ||
            final_context.control_regs[15] != cr15_written ||
            final_context.code_exception != exception_code ||
            final_context.error_code_exception != exception_error ||
            final_context.processor_id != processor_id) {
            failure.case_name = name;
            failure.detail = "final context state mismatch";
            break;
        }

        ok = true;
    } while (false);

    cpueaxh_close(engine);
    return ok;
}

inline bool initialize_manual_engine(cpueaxh_engine* engine, const std::vector<std::uint8_t>& code, const cpueaxh_x86_context& initial, std::uint64_t guest_rsp, Failure& failure, const std::string& name) {
    cpueaxh_err err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_GUEST);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_set_memory_mode failed";
        return false;
    }
    err = cpueaxh_mem_map(engine, kGuestCodeBase, kCodePageSize, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_mem_map code failed";
        return false;
    }
    err = cpueaxh_mem_map(engine, kGuestStackBase, kStackSize, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_mem_map stack failed";
        return false;
    }
    err = cpueaxh_mem_write(engine, kGuestCodeBase, code.data(), code.size());
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_mem_write failed";
        return false;
    }

    if (!write_engine_reg(engine, CPUEAXH_X86_REG_RAX, initial.regs[0]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RCX, initial.regs[1]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RDX, initial.regs[2]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RBX, initial.regs[3]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RSP, guest_rsp) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RBP, initial.regs[5]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RSI, initial.regs[6]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RDI, initial.regs[7]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R8, initial.regs[8]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R9, initial.regs[9]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R10, initial.regs[10]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R11, initial.regs[11]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R12, initial.regs[12]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R13, initial.regs[13]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R14, initial.regs[14]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_R15, initial.regs[15]) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_RIP, kGuestCodeBase) ||
        !write_engine_reg(engine, CPUEAXH_X86_REG_EFLAGS, initial.rflags)) {
        failure.case_name = name;
        failure.detail = "register initialization failed";
        return false;
    }

    return true;
}

inline bool initialize_manual_cpu_context(CPU_CONTEXT& context, MEMORY_MANAGER& memory_manager, const std::vector<std::uint8_t>& code, const cpueaxh_x86_context& initial, std::uint64_t guest_rsp, Failure& failure, const std::string& name) {
    mm_init(&memory_manager);
    init_cpu_context(&context, &memory_manager);

    if (!mm_map_internal(&memory_manager, kGuestCodeBase, kCodePageSize, MM_PROT_READ | MM_PROT_WRITE | MM_PROT_EXEC)) {
        failure.case_name = name;
        failure.detail = "internal code map failed";
        return false;
    }
    if (!mm_map_internal(&memory_manager, kGuestStackBase, kStackSize, MM_PROT_READ | MM_PROT_WRITE)) {
        failure.case_name = name;
        failure.detail = "internal stack map failed";
        return false;
    }

    for (std::size_t index = 0; index < code.size(); ++index) {
        if (mm_write_byte_checked(&memory_manager, kGuestCodeBase + index, code[index]) != MM_ACCESS_OK) {
            failure.case_name = name;
            failure.detail = "internal code write failed";
            return false;
        }
    }

    for (std::size_t index = 0; index < 16; ++index) {
        context.regs[index] = initial.regs[index];
    }
    context.regs[REG_RSP] = guest_rsp;
    context.rip = kGuestCodeBase;
    context.rflags = initial.rflags;
    context.mxcsr = static_cast<std::uint32_t>(initial.mxcsr);
    return true;
}

inline bool run_manual_special_case(
    const std::string& name,
    const std::vector<std::uint8_t>& code,
    std::uint64_t seed,
    std::uint32_t processor_id,
    bool expect_rdpid,
    Failure& failure) {
    cpueaxh_engine* engine = nullptr;
    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_open failed";
        return false;
    }

    bool ok = false;
    do {
        cpueaxh_x86_context initial = make_initial_context(seed);
        const std::uint64_t guest_rsp = kGuestStackBase + kInitialRspOffset;
        if (!initialize_manual_engine(engine, code, initial, guest_rsp, failure, name)) {
            break;
        }

        cpueaxh_set_processor_id(engine, processor_id);

        err = cpueaxh_emu_start_function(engine, kGuestCodeBase, 0, 1000);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "execution failed";
            break;
        }
        if (cpueaxh_code_exception(engine) != CPUEAXH_EXCEPTION_NONE) {
            failure.case_name = name;
            failure.detail = "unexpected exception";
            break;
        }

        std::array<std::uint64_t, 16> regs{};
        for (std::size_t index = 0; index < regs.size(); ++index) {
            if (!read_engine_reg(engine, static_cast<int>(index), regs[index])) {
                failure.case_name = name;
                failure.detail = "register read failed";
                goto cleanup;
            }
        }
        std::uint64_t flags = 0;
        if (!read_engine_reg(engine, CPUEAXH_X86_REG_EFLAGS, flags)) {
            failure.case_name = name;
            failure.detail = "flags read failed";
            break;
        }

        for (std::size_t index = 1; index < regs.size(); ++index) {
            if (index == static_cast<std::size_t>(Reg::RSP)) {
                continue;
            }
            if (regs[index] != initial.regs[index]) {
                failure.case_name = name;
                failure.detail = std::string(reg_name(static_cast<Reg>(index))) + " changed unexpectedly";
                goto cleanup;
            }
        }
        if ((flags & kStatusMask) != (initial.rflags & kStatusMask)) {
            failure.case_name = name;
            failure.detail = "flags changed unexpectedly";
            break;
        }
        if (expect_rdpid) {
            if (regs[0] != processor_id) {
                failure.case_name = name;
                failure.detail = "rdpid result mismatch";
                break;
            }
        }
        else if (regs[0] != initial.regs[0]) {
            failure.case_name = name;
            failure.detail = "rax changed unexpectedly";
            break;
        }

        ok = true;
    } while (false);

cleanup:
    cpueaxh_close(engine);
    return ok;
}

inline bool run_manual_exception_case(
    const std::string& name,
    const std::vector<std::uint8_t>& code,
    std::uint64_t seed,
    std::uint32_t expected_exception,
    Failure& failure) {
    MEMORY_MANAGER memory_manager = {};
    CPU_CONTEXT context = {};
    bool ok = false;
    do {
        cpueaxh_x86_context initial = make_initial_context(seed);
        const std::uint64_t guest_rsp = kGuestStackBase + kInitialRspOffset;
        std::vector<std::uint8_t> image = code;
        image.push_back(0x90);
        image.push_back(0x90);
        if (!initialize_manual_cpu_context(context, memory_manager, image, initial, guest_rsp, failure, name)) {
            break;
        }

        const int status = cpu_step(&context);
        if (status != kCpuStepException) {
            failure.case_name = name;
            failure.detail = "expected CPU_STEP_EXCEPTION";
            break;
        }
        if (context.exception.code != expected_exception) {
            failure.case_name = name;
            failure.detail = "unexpected exception code";
            break;
        }

        if (context.regs[REG_RAX] != initial.regs[0]) {
            failure.case_name = name;
            failure.detail = "rax changed unexpectedly";
            break;
        }
        if ((context.rflags & kStatusMask) != (initial.rflags & kStatusMask)) {
            failure.case_name = name;
            failure.detail = "flags changed unexpectedly";
            break;
        }

        cpu_clear_exception(&context);
        context.rip = kGuestCodeBase + static_cast<std::uint64_t>(code.size());

        const int resume0 = cpu_step(&context);
        if (resume0 != kCpuStepOk || cpu_has_exception(&context)) {
            failure.case_name = name;
            failure.detail = "resume step 0 failed";
            break;
        }
        const std::uint64_t expected_rip_after_resume0 = kGuestCodeBase + static_cast<std::uint64_t>(code.size()) + 1;
        if (context.rip != expected_rip_after_resume0) {
            failure.case_name = name;
            failure.detail = "resume rip 0 mismatch";
            break;
        }

        const int resume1 = cpu_step(&context);
        if (resume1 != kCpuStepOk || cpu_has_exception(&context)) {
            failure.case_name = name;
            failure.detail = "resume step 1 failed";
            break;
        }
        const std::uint64_t expected_rip_after_resume1 = expected_rip_after_resume0 + 1;
        if (context.rip != expected_rip_after_resume1) {
            failure.case_name = name;
            failure.detail = "resume rip 1 mismatch";
            break;
        }
        ok = true;
    } while (false);

    mm_destroy(&memory_manager);
    return ok;
}

inline bool run_manual_exception_case_public(
    const std::string& name,
    const std::vector<std::uint8_t>& code,
    std::uint64_t seed,
    std::uint32_t expected_exception,
    Failure& failure) {
    cpueaxh_engine* engine = nullptr;
    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_open failed";
        return false;
    }

    bool ok = false;
    do {
        cpueaxh_x86_context initial = make_initial_context(seed);
        const std::uint64_t guest_rsp = kGuestStackBase + kInitialRspOffset;
        if (!initialize_manual_engine(engine, code, initial, guest_rsp, failure, name)) {
            break;
        }

        err = cpueaxh_emu_start(engine, kGuestCodeBase, 0, 0, 1);
        if (err != CPUEAXH_ERR_EXCEPTION) {
            failure.case_name = name;
            failure.detail = "expected CPUEAXH_ERR_EXCEPTION";
            break;
        }
        if (cpueaxh_code_exception(engine) != expected_exception) {
            failure.case_name = name;
            failure.detail = "unexpected exception code";
            break;
        }
        ok = true;
    } while (false);

    cpueaxh_close(engine);
    return ok;
}

inline bool emit_host_mov_reg_imm64(std::vector<std::uint8_t>& code, std::uint8_t reg_low3, std::uint64_t imm);
inline bool run_host_write_isolation_case(const std::string& name, std::uint64_t seed, Failure& failure);
inline bool run_host_write_isolation_groups_case(const std::string& name, std::uint64_t seed, Failure& failure);

inline std::uint64_t manual_special_case_count(const HostFeatures& features) {
    (void)features;
    return kSeedCount * 6ull + kExceptionSeedCount * 8ull + kHostIsolationSeedCount + kHostIsolationGroupSeedCount + kContextApiSeedCount;
}

inline bool run_manual_special_tests(const HostFeatures& features, std::uint64_t& executed, std::uint64_t total) {
    const std::vector<std::uint8_t> endbr64 = { 0xF3, 0x0F, 0x1E, 0xFA, 0xC3 };
    const std::vector<std::uint8_t> endbr32 = { 0xF3, 0x0F, 0x1E, 0xFB, 0xC3 };
    const std::vector<std::uint8_t> rdsspq = { 0xF3, 0x48, 0x0F, 0x1E, 0xC8, 0xC3 };
    const std::vector<std::uint8_t> rdsspd = { 0xF3, 0x0F, 0x1E, 0xC8, 0xC3 };
    const std::vector<std::uint8_t> rdpid64 = { 0xF3, 0x48, 0x0F, 0xC7, 0xF8, 0xC3 };
    const std::vector<std::uint8_t> rdpid32 = { 0xF3, 0x0F, 0xC7, 0xF8, 0xC3 };
    const std::vector<std::uint8_t> invalid_endbr_lock = { 0xF0, 0xF3, 0x0F, 0x1E, 0xFA };
    const std::vector<std::uint8_t> invalid_rdssp_lock = { 0xF0, 0xF3, 0x48, 0x0F, 0x1E, 0xC8 };
    const std::vector<std::uint8_t> invalid_rdpid_no_f3 = { 0x48, 0x0F, 0xC7, 0xF8 };
    const std::vector<std::uint8_t> invalid_rdpid_with_66 = { 0x66, 0xF3, 0x48, 0x0F, 0xC7, 0xF8 };

    auto tick = [&](bool result, const Failure& failure) -> bool {
        if (!result) {
            std::cerr << "FAIL " << failure.case_name << std::endl;
            std::cerr << failure.detail << std::endl;
            return false;
        }
        ++executed;
        if ((executed % 1024) == 0 || executed == total) {
            std::cout << "progress " << executed << "/" << total << std::endl;
        }
        return true;
    };

    for (std::uint64_t seed_index = 0; seed_index < kSeedCount; ++seed_index) {
        Failure failure;
        const std::uint64_t seed0 = seeded(seed_index, 0xE001);
        if (!tick(run_manual_special_case("endbr64:" + std::to_string(seed0), endbr64, seed0, 0, false, failure), failure)) return false;

        const std::uint64_t seed_endbr32 = seeded(seed_index, 0xE011);
        if (!tick(run_manual_special_case("endbr32:" + std::to_string(seed_endbr32), endbr32, seed_endbr32, 0, false, failure), failure)) return false;

        const std::uint64_t seed1 = seeded(seed_index, 0xE002);
        if (!tick(run_manual_special_case("rdsspq:" + std::to_string(seed1), rdsspq, seed1, 0, false, failure), failure)) return false;

        const std::uint64_t seed_rdsspd = seeded(seed_index, 0xE012);
        if (!tick(run_manual_special_case("rdsspd:" + std::to_string(seed_rdsspd), rdsspd, seed_rdsspd, 0, false, failure), failure)) return false;

        const std::uint64_t seed2 = seeded(seed_index, 0xE003);
        const std::uint32_t processor_id = static_cast<std::uint32_t>(seeded(seed2, 0x90));
        if (!tick(run_manual_special_case("rdpid64:" + std::to_string(seed2), rdpid64, seed2, processor_id, true, failure), failure)) return false;

        const std::uint64_t seed_rdpid32 = seeded(seed_index, 0xE013);
        const std::uint32_t processor_id32 = static_cast<std::uint32_t>(seeded(seed_rdpid32, 0x91));
        if (!tick(run_manual_special_case("rdpid32:" + std::to_string(seed_rdpid32), rdpid32, seed_rdpid32, processor_id32, true, failure), failure)) return false;
    }

    for (std::uint64_t seed_index = 0; seed_index < kExceptionSeedCount; ++seed_index) {
        Failure failure;
        const std::uint64_t seed3 = seeded(seed_index, 0xE004);
        if (!tick(run_manual_exception_case_public("public_endbr_lock_ud:" + std::to_string(seed3), invalid_endbr_lock, seed3, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;
        if (!tick(run_manual_exception_case("endbr_lock_ud:" + std::to_string(seed3), invalid_endbr_lock, seed3, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;

        const std::uint64_t seed4 = seeded(seed_index, 0xE005);
        if (!tick(run_manual_exception_case_public("public_rdssp_lock_ud:" + std::to_string(seed4), invalid_rdssp_lock, seed4, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;
        if (!tick(run_manual_exception_case("rdssp_lock_ud:" + std::to_string(seed4), invalid_rdssp_lock, seed4, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;

        const std::uint64_t seed5 = seeded(seed_index, 0xE006);
        if (!tick(run_manual_exception_case_public("public_rdpid_no_f3_ud:" + std::to_string(seed5), invalid_rdpid_no_f3, seed5, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;
        if (!tick(run_manual_exception_case("rdpid_no_f3_ud:" + std::to_string(seed5), invalid_rdpid_no_f3, seed5, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;

        const std::uint64_t seed6 = seeded(seed_index, 0xE007);
        if (!tick(run_manual_exception_case_public("public_rdpid_66_ud:" + std::to_string(seed6), invalid_rdpid_with_66, seed6, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;
        if (!tick(run_manual_exception_case("rdpid_66_ud:" + std::to_string(seed6), invalid_rdpid_with_66, seed6, CPUEAXH_EXCEPTION_UD, failure), failure)) return false;
    }

    for (std::uint64_t seed_index = 0; seed_index < kHostIsolationSeedCount; ++seed_index) {
        Failure failure;
        const std::uint64_t seed7 = seeded(seed_index, 0xE101);
        if (!tick(run_host_write_isolation_case("host_write_isolation:" + std::to_string(seed7), seed7, failure), failure)) return false;
    }

    for (std::uint64_t seed_index = 0; seed_index < kHostIsolationGroupSeedCount; ++seed_index) {
        Failure failure;
        const std::uint64_t seed8 = seeded(seed_index, 0xE201);
        if (!tick(run_host_write_isolation_groups_case("host_write_isolation_groups:" + std::to_string(seed8), seed8, failure), failure)) return false;
    }

    for (std::uint64_t seed_index = 0; seed_index < kContextApiSeedCount; ++seed_index) {
        Failure failure;
        const std::uint64_t seed9 = seeded(seed_index, 0xE301);
        if (!tick(run_context_api_case("context_api:" + std::to_string(seed9), seed9, failure), failure)) return false;
    }

    return true;
}

inline bool emit_host_mov_reg_imm64(std::vector<std::uint8_t>& code, std::uint8_t reg_low3, std::uint64_t imm) {
    if (reg_low3 > 7) {
        return false;
    }
    code.push_back(0x48);
    code.push_back(static_cast<std::uint8_t>(0xB8u + reg_low3));
    for (int shift = 0; shift < 64; shift += 8) {
        code.push_back(static_cast<std::uint8_t>((imm >> shift) & 0xFFu));
    }
    return true;
}

inline bool run_host_write_isolation_case(const std::string& name, std::uint64_t seed, Failure& failure) {
    cpueaxh_engine* engine = nullptr;
    std::uint8_t* code_page = nullptr;
    std::uint8_t* stack_page = nullptr;
    std::uint8_t* data_pages = nullptr;

    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_open failed";
        return false;
    }

    bool ok = false;
    do {
        code_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kCodePageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        stack_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        data_pages = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kCodePageSize * 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!code_page || !stack_page || !data_pages) {
            failure.case_name = name;
            failure.detail = "VirtualAlloc failed";
            break;
        }

        std::memset(code_page, 0xCC, kCodePageSize);
        std::memset(stack_page, 0, kStackSize);
        std::memset(data_pages, 0, kCodePageSize * 3);

        std::uint8_t* isolated_page = data_pages;
        std::uint8_t* exempt_page0 = data_pages + kCodePageSize;
        std::uint8_t* exempt_page1 = data_pages + kCodePageSize * 2;

        const std::uint8_t isolated_initial = narrow8(seeded(seed, 0xF001));
        const std::uint8_t exempt_initial0 = narrow8(seeded(seed, 0xF002));
        const std::uint8_t exempt_initial1 = narrow8(seeded(seed, 0xF003));
        const std::uint8_t isolated_write = narrow8(seeded(seed, 0xF101)) | 1u;
        const std::uint8_t exempt_write0 = narrow8(seeded(seed, 0xF102)) | 1u;
        const std::uint8_t exempt_write1 = narrow8(seeded(seed, 0xF103)) | 1u;

        isolated_page[0] = isolated_initial;
        exempt_page0[0] = exempt_initial0;
        exempt_page1[0] = exempt_initial1;

        std::vector<std::uint8_t> code;
        if (!emit_host_mov_reg_imm64(code, 3, reinterpret_cast<std::uint64_t>(isolated_page)) ||
            !emit_host_mov_reg_imm64(code, 1, reinterpret_cast<std::uint64_t>(exempt_page0)) ||
            !emit_host_mov_reg_imm64(code, 2, reinterpret_cast<std::uint64_t>(exempt_page1))) {
            failure.case_name = name;
            failure.detail = "code emit failed";
            break;
        }

        code.push_back(0xC6); code.push_back(0x03); code.push_back(isolated_write);
        code.push_back(0x31); code.push_back(0xC0);
        code.push_back(0x8A); code.push_back(0x03);
        code.push_back(0xC6); code.push_back(0x01); code.push_back(exempt_write0);
        code.push_back(0xC6); code.push_back(0x02); code.push_back(exempt_write1);
        code.push_back(0xC3);

        std::memcpy(code_page, code.data(), code.size());

        err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_HOST);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_set_memory_mode(host) failed";
            break;
        }
        err = cpueaxh_host_write_isolation_set(engine, 1);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_host_write_isolation_set failed";
            break;
        }
        err = cpueaxh_host_write_isolation_exempt_add(engine, reinterpret_cast<std::uint64_t>(exempt_page0), kCodePageSize);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_host_write_isolation_exempt_add 0 failed";
            break;
        }
        err = cpueaxh_host_write_isolation_exempt_add(engine, reinterpret_cast<std::uint64_t>(exempt_page1), kCodePageSize);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "cpueaxh_host_write_isolation_exempt_add 1 failed";
            break;
        }

        std::uint64_t rsp = reinterpret_cast<std::uint64_t>(stack_page) + kStackSize - 0x80 - sizeof(std::uint64_t);
        *reinterpret_cast<std::uint64_t*>(rsp) = 0;
        std::uint64_t rbp = rsp;
        std::uint64_t rip = reinterpret_cast<std::uint64_t>(code_page);
        std::uint64_t rax = 0;
        cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RSP, &rsp);
        cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RBP, &rbp);
        cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RIP, &rip);
        cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RAX, &rax);

        err = cpueaxh_emu_start_function(engine, 0, 0, 1024);
        if (err != CPUEAXH_ERR_OK || cpueaxh_code_exception(engine) != CPUEAXH_EXCEPTION_NONE) {
            failure.case_name = name;
            failure.detail = "host isolation execution failed";
            break;
        }

        if (isolated_page[0] != isolated_initial) {
            failure.case_name = name;
            failure.detail = "isolated host memory changed unexpectedly";
            break;
        }
        if (exempt_page0[0] != exempt_write0 || exempt_page1[0] != exempt_write1) {
            failure.case_name = name;
            failure.detail = "exempt host memory did not update";
            break;
        }

        std::uint8_t isolated_observed = 0;
        err = cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(isolated_page), &isolated_observed, sizeof(isolated_observed));
        if (err != CPUEAXH_ERR_OK || isolated_observed != isolated_write) {
            failure.case_name = name;
            failure.detail = "isolated readback mismatch";
            break;
        }

        std::uint8_t exempt_observed0 = 0;
        std::uint8_t exempt_observed1 = 0;
        err = cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(exempt_page0), &exempt_observed0, sizeof(exempt_observed0));
        if (err != CPUEAXH_ERR_OK || exempt_observed0 != exempt_write0) {
            failure.case_name = name;
            failure.detail = "exempt readback 0 mismatch";
            break;
        }
        err = cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(exempt_page1), &exempt_observed1, sizeof(exempt_observed1));
        if (err != CPUEAXH_ERR_OK || exempt_observed1 != exempt_write1) {
            failure.case_name = name;
            failure.detail = "exempt readback 1 mismatch";
            break;
        }

        std::uint64_t observed_rax = 0;
        if (!read_engine_reg(engine, CPUEAXH_X86_REG_RAX, observed_rax) || static_cast<std::uint8_t>(observed_rax & 0xFFu) != isolated_write) {
            failure.case_name = name;
            failure.detail = "write-after-read register mismatch";
            break;
        }

        ok = true;
    } while (false);

    if (data_pages) {
        ::VirtualFree(data_pages, 0, MEM_RELEASE);
    }
    if (stack_page) {
        ::VirtualFree(stack_page, 0, MEM_RELEASE);
    }
    if (code_page) {
        ::VirtualFree(code_page, 0, MEM_RELEASE);
    }
    if (engine) {
        cpueaxh_close(engine);
    }
    return ok;
}

inline bool run_host_write_isolation_groups_case(const std::string& name, std::uint64_t seed, Failure& failure) {
    cpueaxh_engine* engine = nullptr;
    std::uint8_t* code_page = nullptr;
    std::uint8_t* stack_page = nullptr;
    std::uint8_t* data_page = nullptr;

    auto run_program = [&](std::uint8_t write_value, std::uint8_t expected_value) -> bool {
        std::vector<std::uint8_t> code;
        if (!emit_host_mov_reg_imm64(code, 3, reinterpret_cast<std::uint64_t>(data_page))) {
            failure.case_name = name;
            failure.detail = "group code emit failed";
            return false;
        }
        code.push_back(0xC6); code.push_back(0x03); code.push_back(write_value);
        code.push_back(0x31); code.push_back(0xC0);
        code.push_back(0x8A); code.push_back(0x03);
        code.push_back(0xC3);
        std::memset(code_page, 0xCC, kCodePageSize);
        std::memcpy(code_page, code.data(), code.size());

        std::uint64_t rsp = reinterpret_cast<std::uint64_t>(stack_page) + kStackSize - 0x80 - sizeof(std::uint64_t);
        *reinterpret_cast<std::uint64_t*>(rsp) = 0;
        std::uint64_t rbp = rsp;
        std::uint64_t rip = reinterpret_cast<std::uint64_t>(code_page);
        std::uint64_t rax = 0;
        if (cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RSP, &rsp) != CPUEAXH_ERR_OK ||
            cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RBP, &rbp) != CPUEAXH_ERR_OK ||
            cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RIP, &rip) != CPUEAXH_ERR_OK ||
            cpueaxh_reg_write(engine, CPUEAXH_X86_REG_RAX, &rax) != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group register initialization failed";
            return false;
        }

        cpueaxh_err err = cpueaxh_emu_start_function(engine, 0, 0, 1024);
        if (err != CPUEAXH_ERR_OK || cpueaxh_code_exception(engine) != CPUEAXH_EXCEPTION_NONE) {
            failure.case_name = name;
            failure.detail = "group execution failed";
            return false;
        }

        std::uint64_t observed_rax = 0;
        if (!read_engine_reg(engine, CPUEAXH_X86_REG_RAX, observed_rax) || static_cast<std::uint8_t>(observed_rax & 0xFFu) != expected_value) {
            failure.case_name = name;
            failure.detail = "group register result mismatch";
            return false;
        }
        return true;
    };

    cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine);
    if (err != CPUEAXH_ERR_OK) {
        failure.case_name = name;
        failure.detail = "cpueaxh_open failed";
        return false;
    }

    bool ok = false;
    do {
        code_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kCodePageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        stack_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        data_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kCodePageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!code_page || !stack_page || !data_page) {
            failure.case_name = name;
            failure.detail = "group VirtualAlloc failed";
            break;
        }

        std::memset(code_page, 0xCC, kCodePageSize);
        std::memset(stack_page, 0, kStackSize);
        std::memset(data_page, 0, kCodePageSize);

        const std::uint8_t initial = narrow8(seeded(seed, 0x6201));
        const std::uint8_t value0 = narrow8(seeded(seed, 0x6202)) | 1u;
        const std::uint8_t value1 = narrow8(seeded(seed, 0x6203)) | 1u;
        data_page[0] = initial;

        err = cpueaxh_set_memory_mode(engine, CPUEAXH_MEMORY_MODE_HOST);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group set_memory_mode failed";
            break;
        }
        err = cpueaxh_host_write_isolation_set(engine, 1);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group isolation enable failed";
            break;
        }

        cpueaxh_write_isolation_handle group0 = 0;
        cpueaxh_write_isolation_handle group1 = 0;
        err = cpueaxh_host_write_isolation_group_create(engine, &group0);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group create 0 failed";
            break;
        }
        err = cpueaxh_host_write_isolation_group_create(engine, &group1);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group create 1 failed";
            break;
        }

        if (cpueaxh_host_write_isolation_group_select(engine, group0) != CPUEAXH_ERR_OK || !run_program(value0, value0)) {
            break;
        }

        if (data_page[0] != initial) {
            failure.case_name = name;
            failure.detail = "group 0 changed host memory unexpectedly";
            break;
        }

        std::uint8_t observed = 0;
        if (cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(data_page), &observed, sizeof(observed)) != CPUEAXH_ERR_OK || observed != value0) {
            failure.case_name = name;
            failure.detail = "group 0 readback mismatch";
            break;
        }

        if (cpueaxh_host_write_isolation_group_select(engine, group1) != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group select 1 failed";
            break;
        }
        if (cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(data_page), &observed, sizeof(observed)) != CPUEAXH_ERR_OK || observed != initial) {
            failure.case_name = name;
            failure.detail = "group 1 initial view mismatch";
            break;
        }
        if (!run_program(value1, value1)) {
            break;
        }
        if (cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(data_page), &observed, sizeof(observed)) != CPUEAXH_ERR_OK || observed != value1) {
            failure.case_name = name;
            failure.detail = "group 1 readback mismatch";
            break;
        }

        if (cpueaxh_host_write_isolation_group_select(engine, group0) != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group reselect 0 failed";
            break;
        }
        if (cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(data_page), &observed, sizeof(observed)) != CPUEAXH_ERR_OK || observed != value0) {
            failure.case_name = name;
            failure.detail = "group 0 persisted view mismatch";
            break;
        }

        if (cpueaxh_host_write_isolation_group_delete(engine, group0) != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group delete 0 failed";
            break;
        }
        if (cpueaxh_host_write_isolation_group_select(engine, group1) != CPUEAXH_ERR_OK) {
            failure.case_name = name;
            failure.detail = "group select surviving group failed";
            break;
        }
        if (cpueaxh_mem_read(engine, reinterpret_cast<std::uint64_t>(data_page), &observed, sizeof(observed)) != CPUEAXH_ERR_OK || observed != value1) {
            failure.case_name = name;
            failure.detail = "surviving group view mismatch";
            break;
        }
        if (data_page[0] != initial) {
            failure.case_name = name;
            failure.detail = "group delete changed host memory unexpectedly";
            break;
        }

        ok = true;
    } while (false);

    if (data_page) {
        ::VirtualFree(data_page, 0, MEM_RELEASE);
    }
    if (stack_page) {
        ::VirtualFree(stack_page, 0, MEM_RELEASE);
    }
    if (code_page) {
        ::VirtualFree(code_page, 0, MEM_RELEASE);
    }
    if (engine) {
        cpueaxh_close(engine);
    }
    return ok;
}

class Harness {
public:
    Harness() {
        native_code_ = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kCodePageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        native_stack_ = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, kStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        cpueaxh_err err = cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, &engine_);
        if (err != CPUEAXH_ERR_OK) {
            init_error_ = std::string("cpueaxh_open failed: ") + std::to_string(err);
            return;
        }
        err = cpueaxh_set_memory_mode(engine_, CPUEAXH_MEMORY_MODE_GUEST);
        if (err != CPUEAXH_ERR_OK) {
            init_error_ = std::string("cpueaxh_set_memory_mode failed: ") + std::to_string(err);
            return;
        }
        err = cpueaxh_mem_map(engine_, kGuestCodeBase, kCodePageSize, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC);
        if (err != CPUEAXH_ERR_OK) {
            init_error_ = std::string("cpueaxh_mem_map code failed: ") + std::to_string(err);
            return;
        }
        err = cpueaxh_mem_map(engine_, kGuestStackBase, kStackSize, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE);
        if (err != CPUEAXH_ERR_OK) {
            init_error_ = std::string("cpueaxh_mem_map stack failed: ") + std::to_string(err);
            return;
        }
        ready_ = native_code_ != nullptr && native_stack_ != nullptr;
        if (!ready_ && init_error_.empty()) {
            init_error_ = "memory allocation failed";
        }
    }

    ~Harness() {
        if (engine_) {
            cpueaxh_close(engine_);
        }
        if (native_code_) {
            ::VirtualFree(native_code_, 0, MEM_RELEASE);
        }
        if (native_stack_) {
            ::VirtualFree(native_stack_, 0, MEM_RELEASE);
        }
    }

    bool ready() const {
        return ready_;
    }

    const std::string& init_error() const {
        return init_error_;
    }

    bool run_case(const BuiltCase& built, Failure& failure) {
        if (built.image.empty() || built.image.size() > kCodePageSize) {
            failure.case_name = built.spec.name;
            failure.detail = "code generation failed";
            return false;
        }

        std::memset(native_code_, 0, kCodePageSize);
        std::memset(native_stack_, 0, kStackSize);
        std::memcpy(native_code_, built.image.data(), built.image.size());

        const std::uint64_t guest_rsp = kGuestStackBase + kInitialRspOffset;
        const std::uint64_t native_rsp = reinterpret_cast<std::uint64_t>(native_stack_) + kInitialRspOffset;

        cpueaxh_x86_context native_context = built.initial_context;
        native_context.regs[static_cast<std::size_t>(Reg::RSP)] = native_rsp;
        native_context.rip = reinterpret_cast<std::uint64_t>(native_code_);
        native_context.rflags = built.initial_context.rflags;
        native_context.mxcsr = static_cast<std::uint32_t>(kInitialMxcsr);

        TestBridgeBlock block{};
        if (cpueaxh_test_run_native(&native_context, native_code_, &block) != 0) {
            failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
            failure.detail = "native execution failed";
            return false;
        }

        static const std::vector<std::uint8_t> zero_code(kCodePageSize, 0);
        static const std::vector<std::uint8_t> zero_stack(kStackSize, 0);
        cpueaxh_err err = cpueaxh_mem_write(engine_, kGuestCodeBase, zero_code.data(), zero_code.size());
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = built.spec.name;
            failure.detail = "guest zero code failed";
            return false;
        }
        err = cpueaxh_mem_write(engine_, kGuestStackBase, zero_stack.data(), zero_stack.size());
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = built.spec.name;
            failure.detail = "guest zero stack failed";
            return false;
        }
        err = cpueaxh_mem_write(engine_, kGuestCodeBase, built.image.data(), built.image.size());
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = built.spec.name;
            failure.detail = "guest write code failed";
            return false;
        }

        if (!write_reg(CPUEAXH_X86_REG_RAX, built.initial_context.regs[0])) return fail_reg_write(failure, built, "rax");
        if (!write_reg(CPUEAXH_X86_REG_RCX, built.initial_context.regs[1])) return fail_reg_write(failure, built, "rcx");
        if (!write_reg(CPUEAXH_X86_REG_RDX, built.initial_context.regs[2])) return fail_reg_write(failure, built, "rdx");
        if (!write_reg(CPUEAXH_X86_REG_RBX, built.initial_context.regs[3])) return fail_reg_write(failure, built, "rbx");
        if (!write_reg(CPUEAXH_X86_REG_RSP, guest_rsp)) return fail_reg_write(failure, built, "rsp");
        if (!write_reg(CPUEAXH_X86_REG_RBP, built.initial_context.regs[5])) return fail_reg_write(failure, built, "rbp");
        if (!write_reg(CPUEAXH_X86_REG_RSI, built.initial_context.regs[6])) return fail_reg_write(failure, built, "rsi");
        if (!write_reg(CPUEAXH_X86_REG_RDI, built.initial_context.regs[7])) return fail_reg_write(failure, built, "rdi");
        if (!write_reg(CPUEAXH_X86_REG_R8, built.initial_context.regs[8])) return fail_reg_write(failure, built, "r8");
        if (!write_reg(CPUEAXH_X86_REG_R9, built.initial_context.regs[9])) return fail_reg_write(failure, built, "r9");
        if (!write_reg(CPUEAXH_X86_REG_R10, built.initial_context.regs[10])) return fail_reg_write(failure, built, "r10");
        if (!write_reg(CPUEAXH_X86_REG_R11, built.initial_context.regs[11])) return fail_reg_write(failure, built, "r11");
        if (!write_reg(CPUEAXH_X86_REG_R12, built.initial_context.regs[12])) return fail_reg_write(failure, built, "r12");
        if (!write_reg(CPUEAXH_X86_REG_R13, built.initial_context.regs[13])) return fail_reg_write(failure, built, "r13");
        if (!write_reg(CPUEAXH_X86_REG_R14, built.initial_context.regs[14])) return fail_reg_write(failure, built, "r14");
        if (!write_reg(CPUEAXH_X86_REG_R15, built.initial_context.regs[15])) return fail_reg_write(failure, built, "r15");
        if (!write_reg(CPUEAXH_X86_REG_RIP, kGuestCodeBase)) return fail_reg_write(failure, built, "rip");
        if (!write_reg(CPUEAXH_X86_REG_EFLAGS, built.initial_context.rflags)) return fail_reg_write(failure, built, "rflags");

        err = cpueaxh_emu_start_function(engine_, kGuestCodeBase, 0, 100000);
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
            failure.detail = std::string("guest execution failed: ") + std::to_string(err) + " exc=" + std::to_string(cpueaxh_code_exception(engine_));
            return false;
        }

        std::array<std::uint64_t, 16> guest_regs{};
        for (std::size_t index = 0; index < guest_regs.size(); ++index) {
            if (!read_reg(static_cast<int>(index), guest_regs[index])) {
                failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
                failure.detail = "guest read register failed";
                return false;
            }
        }
        std::uint64_t guest_flags = 0;
        if (!read_reg(CPUEAXH_X86_REG_EFLAGS, guest_flags)) {
            failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
            failure.detail = "guest read flags failed";
            return false;
        }

        std::vector<std::uint8_t> guest_data(kDataSize);
        err = cpueaxh_mem_read(engine_, kGuestCodeBase + built.data_offset, guest_data.data(), guest_data.size());
        if (err != CPUEAXH_ERR_OK) {
            failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
            failure.detail = "guest read data failed";
            return false;
        }

        const std::uint8_t* native_data = native_code_ + built.data_offset;
        for (std::size_t index = 0; index < 16; ++index) {
            const std::uint64_t guest_value = guest_regs[index];
            const std::uint64_t native_value = normalize_native_value(native_context.regs[index], built);
            if (guest_value != native_value) {
                failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
                failure.detail = std::string(reg_name(static_cast<Reg>(index))) + " guest=" + hex64(guest_value) + " native=" + hex64(native_value);
                return false;
            }
        }

        const std::uint64_t guest_masked = guest_flags & built.spec.flag_mask;
        const std::uint64_t native_masked = native_context.rflags & built.spec.flag_mask;
        if (guest_masked != native_masked) {
            failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
            failure.detail = std::string("flags guest=") + hex64(guest_masked) + " native=" + hex64(native_masked);
            return false;
        }

        for (std::size_t index = 0; index < guest_data.size(); ++index) {
            if (guest_data[index] != native_data[index]) {
                failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
                failure.detail = std::string("data[") + std::to_string(index) + "] guest=" + hex8(guest_data[index]) + " native=" + hex8(native_data[index]);
                return false;
            }
        }

        return true;
    }

private:
    std::uint64_t normalize_native_value(std::uint64_t value, const BuiltCase& built) const {
        const std::uint64_t native_code_begin = reinterpret_cast<std::uint64_t>(native_code_);
        const std::uint64_t native_code_end = native_code_begin + kCodePageSize;
        if (value >= native_code_begin && value < native_code_end) {
            return kGuestCodeBase + (value - native_code_begin);
        }

        const std::uint64_t native_stack_begin = reinterpret_cast<std::uint64_t>(native_stack_);
        const std::uint64_t native_stack_end = native_stack_begin + kStackSize;
        if (value >= native_stack_begin && value < native_stack_end) {
            return kGuestStackBase + (value - native_stack_begin);
        }

        (void)built;
        return value;
    }

    bool write_reg(int reg, std::uint64_t value) {
        return cpueaxh_reg_write(engine_, reg, &value) == CPUEAXH_ERR_OK;
    }

    bool read_reg(int reg, std::uint64_t& value) {
        return cpueaxh_reg_read(engine_, reg, &value) == CPUEAXH_ERR_OK;
    }

    bool fail_reg_write(Failure& failure, const BuiltCase& built, const char* name) {
        failure.case_name = built.spec.name + ":" + std::to_string(built.seed);
        failure.detail = std::string("guest write ") + name + " failed";
        return false;
    }

    cpueaxh_engine* engine_ = nullptr;
    std::uint8_t* native_code_ = nullptr;
    std::uint8_t* native_stack_ = nullptr;
    bool ready_ = false;
    std::string init_error_;
};

inline bool run_all_tests() {
    const HostFeatures features = query_host_features();
    const std::vector<ProgramSpec> specs = make_specs(features);
    const std::uint64_t total = static_cast<std::uint64_t>(specs.size()) * kSeedCount + manual_special_case_count(features);
    std::cout << "cpueaxh test cases: " << total << std::endl;

    Harness harness;
    if (!harness.ready()) {
        std::cerr << harness.init_error() << std::endl;
        return false;
    }

    std::uint64_t executed = 0;
    for (const ProgramSpec& spec : specs) {
        for (std::uint64_t seed_index = 0; seed_index < kSeedCount; ++seed_index) {
            const std::uint64_t seed = seeded(seed_index, static_cast<std::uint64_t>(spec.op) + (static_cast<std::uint64_t>(spec.family) << 8) + (static_cast<std::uint64_t>(spec.variant) << 16));
            BuiltCase built = build_case(spec, seed);
            Failure failure;
            if (!harness.run_case(built, failure)) {
                std::cerr << "FAIL " << failure.case_name << std::endl;
                std::cerr << failure.detail << std::endl;
                return false;
            }
            ++executed;
            if ((executed % 1024) == 0 || executed == total) {
                std::cout << "progress " << executed << "/" << total << std::endl;
            }
        }
    }

    if (!run_manual_special_tests(features, executed, total)) {
        return false;
    }

    std::cout << "PASS " << executed << "/" << total << std::endl;
    return true;
}

}