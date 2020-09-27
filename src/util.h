#pragma once

#include <type_traits>
#include <cstdint>
#include <cassert>

#include <unistd.h>

#define log(level, fmt, ...) retrec::log_impl(level, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)

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

// C++ is a great language
#define DECLARE_SCOPED_ENUM_BINARY_OPERATOR(T, op) \
[[maybe_unused]] static inline T operator op (T a, T b) { \
    return static_cast<T>( \
            static_cast<std::underlying_type<T>::type>(a) op \
            static_cast<std::underlying_type<T>::type>(b)); \
}

#define DECLARE_SCOPED_ENUM_UNARY_OPERATOR(T, op) \
[[maybe_unused]] static inline T operator op (T a) { \
    return static_cast<T>(op static_cast<std::underlying_type<T>::type>(a)); \
}

#define DECLARE_SCOPED_ENUM_BITWISE_OPERATORS(T) \
    DECLARE_SCOPED_ENUM_BINARY_OPERATOR(T, |) \
    DECLARE_SCOPED_ENUM_BINARY_OPERATOR(T, &) \
    DECLARE_SCOPED_ENUM_BINARY_OPERATOR(T, ^) \
    DECLARE_SCOPED_ENUM_UNARY_OPERATOR(T, ~)

#define DISABLE_COPY_AND_MOVE(classname) \
    classname(const classname &other) = delete; \
    classname& operator=(const classname &other) = delete; \
    classname(const classname &&other) = delete; \
    classname& operator=(const classname &&other) = delete;

template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;

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
