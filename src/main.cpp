/**
 * Copyright 2020-2021 Shawn Anastasio.
 *
 * This file is part of retrec.
 *
 * retrec is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * retrec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <dynamic_recompiler.h>

#include <cstdio>
#include <cassert>

using namespace retrec;

std::vector<std::string> build_argv_vec(int start, int argc, char **argv) {
    // Insert arguments starting at argv[start]
    return {&argv[start], &argv[argc]};
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
        .argv = build_argv_vec(1, argc, argv),
        .envp = build_envp_vec(envp)
    };
    dynamic_recompiler rec(std::move(env));
    status_code res = rec.init();
    if (res != status_code::SUCCESS) {
        pr_error("Failed to init dynamic recompiler: %s\n", status_code_str(res));
        return 1;
    }

    rec.execute();

    return 0;
}
