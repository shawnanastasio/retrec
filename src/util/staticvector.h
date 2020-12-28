#pragma once

#include <util/util.h>

#include <array>
#include <cstddef>
#include <cassert>

namespace retrec {

/**
 * A simple vector class with fixed static storage
 */
template <typename T, size_t MAX_SIZE>
class StaticVector {
    std::array<T, MAX_SIZE> arr;
    size_t count { 0 };
    using UnderlyingArr = std::array<T, MAX_SIZE>;

public:
    constexpr StaticVector() : arr() {}
    constexpr StaticVector(const UnderlyingArr &other, size_t count_) : arr(other), count(count_) {}
    StaticVector(const StaticVector &other) :
        arr(other.arr), count(other.count) {}
    StaticVector &operator=(const StaticVector &other) {
        arr = other.arr;
        count = other.count;
        return *this;
    }

    const T &operator[](size_t i) const {
        assert(i < count);
        return arr[i];
    }

    bool operator==(const StaticVector &other) const {
        if (count != other.count)
            return false;
        return arr == other.arr;
    }

    void push_back(T val) {
        assert(count < MAX_SIZE);
        arr[count++] = val;
    }

    void remove(size_t i) {
        assert(i < count);
        // Shift all elements after i back one
        for (size_t j = i; i < count; i++) {
            arr[j] = std::move(arr[j + 1]);
        }
        count -= 1;
    }

    // Return new array of elements present in this and not other
    StaticVector difference(const StaticVector &other) const {
        std::array<T, MAX_SIZE> ret;
        size_t ret_size = 0;
        for (auto &elem : *this) {
            if (!contains(other, elem))
                ret[ret_size++] = elem;
        }
        return {ret, ret_size};
    }

    size_t size() const { return count; }
    const T *cbegin() const { return &arr[0]; }
    const T *cend()   const { return &arr[count]; }
    const T *begin()  const { return &arr[0]; }
    const T *end()    const { return &arr[count]; }
};

} // namespace retrec
