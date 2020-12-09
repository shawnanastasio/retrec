#pragma once

#include <util/util.h>
#include <util/magic.h>

#include <functional>
#include <memory>
#include <utility>
#include <variant>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <cassert>

namespace retrec {

/**
 * A stream of instructions emitted by an assembler. Each instruction object can be called to
 * emit the instruction to a provided buffer.
 *
 * Traits expected members:
 *   (Type) AssemblerT - Opaque type for assembler
 *   (Type) InsnT - Type for instruction (see below)
 *   constexpr size_t calculate_code_size(const InsnT *insn_buf, size_t count)
 *          - Function to calculate the total code size that will be emitted for a given instruction buffer.
 *
 * InsnT is the type of each entry in this instruction stream. Its expected members are:
 *   Public constructor that can be called through a perfect forwarding template
 *   Move constructor
 *   status_code operator()(assembler*) - Method to emit the instruction using the provided assembler
 *   void set_aux(...) - Method to construct an auxiliary data structure in-place to store with the instruction
 */
template <typename Traits>
class instruction_stream {
public:
    instruction_stream(typename Traits::AssemblerT &assembler_)
        : insns(), assembler(assembler_) {}
    DISABLE_COPY_AND_MOVE(instruction_stream)

    template <typename... Ts>
    auto &emplace_back(Ts&&... params) { return insns.emplace_back(std::forward<Ts>(params)...); }

    /**
     * Append auxiliary data to the last instruction emitted.
     */
    template <typename... Ts>
    void set_aux(Ts&&... args) {
        assert(insns.size());
        (*(insns.end() - 1)).set_aux(std::forward<Ts>(args)...);
    }

    /**
     * Emit all instructions in this stream to the provided code buffer.
     */
    status_code emit_all_to_buf(uint8_t *buf, size_t size) {
        out_buf = buf;
        buf_size = size;
        offset = 0;

        for (auto &insn : insns) {
            status_code res = insn(&assembler);
            if (res != status_code::SUCCESS)
                return res;
        }

        return status_code::SUCCESS;
    }

    // The total size the contained code will take once emitted
    size_t code_size() const { return Traits::calculate_code_size(&insns[0], insns.size()); }

    // Accessors for internal insn_data vec
    size_t size() const { return insns.size(); }
    typename Traits::InsnT &operator[](size_t i) { return insns[i]; }

    friend typename Traits::AssemblerT;

private:
    status_code write32(uint32_t x) {
        if (offset+4 > buf_size)
            return status_code::OVERFLOW;

        *(uint32_t *)(out_buf + offset) = x;
        offset += 4;

        return status_code::SUCCESS;
    };

    std::vector<typename Traits::InsnT> insns {};
    typename Traits::AssemblerT &assembler;

    uint8_t *out_buf { nullptr };
    size_t buf_size { 0 };
    size_t offset { 0 };
};

} // namespace retrec
