#pragma once

#include <type_traits>
#include <cstdint>
#include <cassert>
#include <cstdlib>

#include <unistd.h>

#define __weak __attribute__((weak))

namespace retrec {

//
// General definitions
//

enum class status_code {
    SUCCESS,
    BADACCESS,
    BADALIGN,
    BADARCH,
    BADBRANCH,
    BADELF,
    BADFILE,
    DEFER,
    HALT,
    NOMEM,
    OVERFLOW,
    OVERLAP,
    UNIMPL_INSN,
    UNTRANSLATED,
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

// Useful for declaring comma-separated lists with x-macros
#define X_LIST(x, ...) x,

// Template for creating dummy/sentinel types
template <size_t i>
class Sentinel {};

template <typename ValT, typename AlignT>
std::enable_if_t<(std::is_pointer_v<ValT> || std::is_integral_v<ValT>), ValT>
align_to(ValT val, AlignT alignment) {
    return (ValT)((uintptr_t)val & ~(alignment - 1));
}

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
    classname& operator=(classname &&other) = delete;

template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;

template <typename R, typename T>
constexpr std::remove_reference_t<R> ref_cast(T val) {
    return static_cast<std::remove_reference_t<R>>(val);
}

template <typename EnumT>
constexpr std::underlying_type_t<EnumT> enum_cast(EnumT val) {
    return static_cast<std::underlying_type_t<EnumT>>(val);
}

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

__attribute__((format (printf, 4, 5)))
void log_impl(log_level level, const char *file, int line, const char *fmt, ...);

} // namespace retrec

#define TODO() do { \
    pr_error("Unimplemented code path hit!\n"); \
    abort(); \
} while(0)

#define ASSERT_NOT_REACHED() do { \
    pr_error("Assert not reached!\n"); \
    abort(); \
} while (0)

#define ALLOW_IMPLICIT_INT_CONVERSION() do { \
    _Pragma("GCC diagnostic push"); \
    _Pragma("GCC diagnostic ignored \"-Wconversion\""); \
} while (0)

#define DISALLOW_IMPLICIT_INT_CONVERSION() do { \
    _Pragma("GCC diagnostic pop"); \
} while (0)

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
