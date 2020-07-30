#pragma once

#include <cstdint>
#include <cassert>

#include <unistd.h>

#define log(level, fmt, ...) retrec::log_impl(level, __FILE__ + SOURCE_PATH_SIZE, __LINE__, fmt, ##__VA_ARGS__)

#define __weak __attribute__((weak))

namespace retrec {

//
// General definitions
//

enum class status_code {
    SUCCESS,
    BADARCH,
    BADELF,
    BADFILE,
    NOMEM,
    UNIMPL_INSN,
    OVERFLOW,
    BADALIGN,
    OVERLAP,

    // Code generation errors
    BADBRANCH,
};
const char *status_code_str(status_code code);

enum class Architecture {
    X86_64,
    ppc64le
};

//
// Misc. Helpers
//

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof(*(x)))

#define DISABLE_COPY_AND_MOVE(classname) \
    classname(const classname &other) = delete; \
    classname& operator=(const classname &other) = delete; \
    classname(const classname &&other) = delete; \
    classname& operator=(const classname &&other) = delete;

//
// Logging
//

enum log_level {
    LOGL_DEBUG,
    LOGL_INFO,
    LOGL_WARN,
    LOGL_ERROR,
};

void log_impl(log_level level, const char *file, int line, const char *fmt, ...);

#define TODO() do { \
    log(LOGL_ERROR, "Unimplemented code path hit!\n"); \
    assert(0); \
} while(0)

}
