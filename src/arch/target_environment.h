#pragma once

#include <util/util.h>
#include <arch/x86_64/target_environment.h>

#include <vector>
#include <string>

namespace retrec {

static inline void *initialize_target_stack(Architecture target, void *stack,
                                            const std::vector<std::string> &argv,
                                            const std::vector<std::string> &envp) {
    switch (target) {
        case Architecture::X86_64:
            return x86_64::initialize_target_stack(stack, argv, envp);
        default:
            TODO();
    }
}

};
