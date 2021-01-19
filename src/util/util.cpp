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

#include <util/util.h>

#include <cstdio>
#include <cstdarg>

using namespace retrec;

const char *retrec::status_code_str(status_code code) {
    switch (code) {
        case status_code::SUCCESS:
            return "Success";
        case status_code::BADACCESS:
            return "Bad memory access";
        case status_code::BADALIGN:
            return "Bad alignment";
        case status_code::BADARCH:
            return "Bad architecture";
        case status_code::BADBRANCH:
            return "Unable to resolve branch target";
        case status_code::BADELF:
            return "Bad ELF file";
        case status_code::BADFILE:
            return "Bad file";
        case status_code::DEFER:
            return "Operation should be tried again later";
        case status_code::HALT:
            return "Translated code execution requested to halt";
        case status_code::NOMEM:
            return "No memory available";
        case status_code::OVERFLOW:
            return "Overflow";
        case status_code::OVERLAP:
            return "Operation would result in memory region overlap";
        case status_code::UNIMPL_INSN:
            return "Unimplemented instruction";
        case status_code::UNIMPL_SYSCALL:
            return "Unimplemented syscall";
        case status_code::UNTRANSLATED:
            return "Attempt to reference untranslated code";
    }
    UNREACHABLE();
}

const char *log_level_names[] = {
    "[DEBUG]",
    "[INFO]",
    "[WARN]",
    "[ERROR]"
};

void retrec::log_impl(log_level level, const char *file, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s %s:%d: ", log_level_names[level], file, line);
    vfprintf(stderr, fmt, args);

    va_end(args);
}
