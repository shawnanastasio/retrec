/**
 * Definitions and helpers for the X86_64 target binary environment
 */
#pragma once

#include <vector>
#include <string>

namespace retrec {
namespace x86_64 {

/**
 * Initialize a stack with the given argv/envp.
 * Returns the decremented stack pointer that should be passed to translated runtime.
 */
void *initialize_target_stack(void *stack, const std::vector<std::string> &argv,
                              const std::vector<std::string> &envp);

}
}
