#include <util/util.h>

#include <cstdio>
#include <cstdarg>

using namespace retrec;

const char *retrec::status_code_str(status_code code) {
    switch (code) {
        case status_code::SUCCESS:
            return "Success";
        case status_code::BADARCH:
            return "Bad architecture";
        case status_code::BADELF:
            return "Bad ELF file";
        case status_code::BADFILE:
            return "Bad file";
        case status_code::NOMEM:
            return "No memory available";
        case status_code::UNIMPL_INSN:
            return "Unimplemented instruction";
        case status_code::OVERFLOW:
            return "Overflow";
        case status_code::BADALIGN:
            return "Bad alignment";
        case status_code::OVERLAP:
            return "Operation would result in memory region overlap";
        case status_code::BADBRANCH:
            return "Unable to resolve branch target";
        case status_code::DEFER:
            return "Operation should be tried again later";
        default:
            TODO();
    }
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
