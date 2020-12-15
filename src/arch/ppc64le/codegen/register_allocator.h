#pragma once

#include <util/util.h>
#include <llir.h>

namespace retrec {
namespace ppc64le {

using gpr_t = uint8_t;
static constexpr gpr_t GPR_INVALID = (gpr_t)-1;

// RAII wrapper returned by GPR allocations
template <typename RegisterAllocatorT>
class allocated_gpr {
    gpr_t m_gpr;
    RegisterAllocatorT *m_allocator;

    allocated_gpr(gpr_t gpr, RegisterAllocatorT *allocator) : m_gpr(gpr), m_allocator(allocator) {}
public:
    allocated_gpr() : m_gpr(GPR_INVALID), m_allocator(nullptr) {}
    friend RegisterAllocatorT;

    gpr_t gpr() const { assert(m_allocator); return m_gpr; }
    explicit operator bool() { return !!m_allocator; }

    // Only allow moves
    ~allocated_gpr() { if (m_allocator) m_allocator->free_gpr(m_gpr); }
    allocated_gpr(const allocated_gpr &) = delete;
    allocated_gpr &operator= (allocated_gpr &) = delete;
    allocated_gpr(allocated_gpr &&other)
        : m_gpr(other.m_gpr), m_allocator(std::exchange(other.m_allocator, nullptr)) {}
    allocated_gpr &operator= (allocated_gpr &&other) {
        std::swap(m_gpr, other.m_gpr);
        std::swap(m_allocator, other.m_allocator);
        return *this;
    }
};

/**
 * Register allocator for X86_64 targets
 */
template <typename TargetTraits>
class register_allocator {
    // Allocation status of GPRs. True = reserved, false = free.
    struct RegisterInfo {
        enum class State {
            FREE,
            ALLOCATED,
            RESERVED
        } state;
    } gprs[32];

    // Statically allocated GPRs
    static struct static_allocation_set {
        static_allocation_set();
        using TargetRegisterT = typename TargetTraits::RegisterT;

        // Maps a given x86_64 register to a reserved ppc64le register, if available
        gpr_t allocations[(size_t)TargetRegisterT::MAXIMUM - 1];

        // allocations doesn't reserve space for the invalid register index 0, so subtract 1 to get index
        size_t reserved_index(const llir::Register &reg) { return (size_t)reg.x86_64 - 1; /* FIXME: not hardcoded to x86_64 */ }
        size_t reserved_index(TargetRegisterT reg) { return (size_t)reg - 1; }

        bool is_reserved(gpr_t gpr) {
            for (size_t i=0; i<ARRAY_SIZE(allocations); i++)
                if (allocations[i] == gpr)
                    return true;
            return false;
        }
    } static_allocations;

public:
    using AllocatedGprT = allocated_gpr<register_allocator<TargetTraits>>;
    friend AllocatedGprT;

    register_allocator();
    ~register_allocator();
    DISABLE_COPY_AND_MOVE(register_allocator)

    AllocatedGprT allocate_gpr();
    AllocatedGprT get_fixed_gpr(const llir::Register &reg);

private:
    void free_gpr(gpr_t gpr);
};

};
};
