#pragma once

#include "util.h"

#include <string>
#include <utility>
#include <type_traits>

namespace retrec {

class mapped_file {
    std::string path;
    bool readonly;

    bool valid = false;
    void *data_region = nullptr;
    size_t data_length = 0;
public:
    mapped_file(std::string path_, bool readonly_): path(path_), readonly(readonly_) {}

    ~mapped_file();

    // Disable copy construction, allow move construction
    mapped_file(const mapped_file &) = delete;

    mapped_file &operator=(const mapped_file &) = delete;

    mapped_file(mapped_file &&other):
            path(std::move(other.path)),
            valid(std::exchange(other.valid, false)),
            data_region(other.data_region), data_length(other.data_length) {}

    mapped_file &operator=(mapped_file &&other) {
        std::swap(path, other.path);
        std::swap(valid, other.valid);
        std::swap(data_region, other.data_region);
        std::swap(data_length, other.data_length);
        return *this;
    }

    status_code map();

    template<typename T>
    T data() { static_assert(std::is_pointer_v<T>); return static_cast<T>(data_region); }

    size_t length() const { return data_length; };
};

}