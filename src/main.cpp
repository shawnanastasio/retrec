#include "dynamic_recompiler.h"

#include <cstdio>
#include <cassert>

using namespace retrec;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    const char *binary_path = argv[1];

    // Map the user provided binary
    mapped_file binary(binary_path, true);
    if (binary.map() != status_code::SUCCESS) {
        log(LOGL_ERROR, "Failed to open binary %s!\n", binary_path);
        return 1;
    }

    dynamic_recompiler rec(Architecture::ppc64le, std::move(binary));
    if (rec.init() != status_code::SUCCESS) {
        log(LOGL_ERROR, "Failed to init dynamic recompiler\n");
        return 1;
    }

    rec.execute();

    return 0;
}
