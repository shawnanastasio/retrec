#include <dynamic_recompiler.h>

#include <cstdio>
#include <cassert>

using namespace retrec;

std::vector<std::string> build_argv_vec(int argc, char **argv) {
    // Insert argument starting at argv[2]
    if (argc <= 2)
        return {};
    return {&argv[2], &argv[argc]};
}

std::vector<std::string> build_envp_vec(char **envp) {
    // Pass through host envp
    size_t len;
    for (len = 0; envp[len]; len++)
        ;
    return {&envp[0], &envp[len]};
}

int main(int argc, char **argv, char **envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    const char *binary_path = argv[1];

    // Map the user provided binary
    mapped_file binary(binary_path, true);
    if (binary.map() != status_code::SUCCESS) {
        pr_error("Failed to open binary: %s\n", binary_path);
        return 1;
    }

    // Initialize the dynamic recompiler and target environment
    target_environment env = {
        .binary = std::move(binary),
        .argv = build_argv_vec(argc, argv),
        .envp = build_envp_vec(envp)
    };
    dynamic_recompiler rec(Architecture::ppc64le, std::move(env));
    status_code res = rec.init();
    if (res != status_code::SUCCESS) {
        pr_error("Failed to init dynamic recompiler: %s\n", status_code_str(res));
        return 1;
    }

    rec.execute();

    return 0;
}
