#pragma once

#include <type_traits>
#include <cstdint>
#include <cassert>

#include <unistd.h>

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
#define _LOGL_DEBUG 0
    LOGL_DEBUG = _LOGL_DEBUG,
#define _LOGL_INFO 1
    LOGL_INFO = _LOGL_INFO,
#define _LOGL_WARN 2
    LOGL_WARN = _LOGL_WARN,
#define _LOGL_ERROR 3
    LOGL_ERROR = _LOGL_ERROR,
};

void log_impl(log_level level, const char *file, int line, const char *fmt, ...);
//#define log(level, fmt, ...) retrec::log_impl(level, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)

#define TODO() do { \
    pr_error("Unimplemented code path hit!\n"); \
    assert(0); \
} while(0)

} // namespace retrec

#ifndef RETREC_MINIMUM_LOG_LEVEL
#error "RETREC_MINIMUM_LOG_LEVEL not defined! Broken build system?"
#elif (RETREC_MINIMUM_LOG_LEVEL < _LOGL_DEBUG) || (RETREC_MINIMUM_LOG_LEVEL > _LOGL_ERROR)
#error "Invalid MINIMUM_LOG_LEVEL specified!"
#endif

/**
 * Only define logging macros if the minimum log level is <= to it.
 */
#if RETREC_MINIMUM_LOG_LEVEL <= _LOGL_DEBUG
#define pr_debug(fmt, ...) retrec::log_impl(LOGL_DEBUG, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)
#else
#define pr_debug(...)
#endif

#if RETREC_MINIMUM_LOG_LEVEL <= _LOGL_INFO
#define pr_info(fmt, ...) retrec::log_impl(LOGL_INFO, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)
#else
#define pr_info(...)
#endif

#if RETREC_MINIMUM_LOG_LEVEL <= _LOGL_WARN
#define pr_warn(fmt, ...) retrec::log_impl(LOGL_WARN, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)
#else
#define pr_warn(...)
#endif

// Always define PR_ERROR
#define pr_error(fmt, ...) retrec::log_impl(LOGL_ERROR, &__FILE__[SOURCE_PATH_SIZE], __LINE__, fmt, ##__VA_ARGS__)
