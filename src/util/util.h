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

#pragma once

#include <algorithm>
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
    UNIMPL_SYSCALL,
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

template <typename ContainerT, typename ValT>
bool contains(const ContainerT &container, ValT val) {
    return std::find(container.cbegin(), container.cend(), val) != container.cend();
}

template <typename ContainerT, typename ValListT>
bool contains_any(const ContainerT &container, const ValListT &val_list) {
    for (auto &val : val_list) {
        if (contains(container, val))
            return true;
    }
    return false;
}

template <typename ContainerT, typename ValListT>
bool contains_all(const ContainerT &container, const ValListT &val_list) {
    for (auto &val : val_list) {
        if (!contains(container, val))
            return false;
    }
    return true;
}

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

#define DISABLE_COPY_AND_MOVE(classname) \
    classname(const classname &other) = delete; \
    classname& operator=(const classname &other) = delete; \
    classname(const classname &&other) = delete; \
    classname& operator=(classname &&other) = delete;

template <typename T>
uint32_t clz(T) {
    static_assert(!std::is_same_v<T, T>, "Unimplemented clz for this type");
    return 0;
}
template <>
inline uint32_t clz<unsigned short>(unsigned short val) { return __builtin_clz(val) - 16; }
template <>
inline uint32_t clz<unsigned int>(unsigned int val) { return __builtin_clz(val); }
template <>
inline uint32_t clz<unsigned long>(unsigned long val) { return __builtin_clzl(val); }

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

#define UNREACHABLE() __builtin_unreachable()

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
