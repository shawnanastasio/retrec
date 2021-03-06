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

#include <util/util.h>

#include <array>
#include <cstddef>
#include <cassert>
#include <utility>

namespace retrec {

/**
 * A simple vector class with fixed static storage
 */
template <typename T, size_t MAX_SIZE>
class StaticVector {
    std::array<T, MAX_SIZE> arr;
    size_t count { 0 };
    using UnderlyingArr = std::array<T, MAX_SIZE>;

    template <typename ArrT, std::size_t... I>
    constexpr StaticVector(const ArrT &in_arr, size_t n, std::index_sequence<I...>)
            : arr({in_arr[I]...}), count(n) {}
public:
    // Construct from an array of Ts
    template <typename ArrT, size_t N>
    constexpr StaticVector(const ArrT (&in_arr)[N])
            : StaticVector(in_arr, N, std::make_index_sequence<N>{}) {
        static_assert(N <= MAX_SIZE);
    }

    // Construct from Ts
    template <typename... ElemTs, size_t N = sizeof...(ElemTs)>
    constexpr StaticVector(ElemTs... elements) : arr({elements...}), count(N) {
        static_assert(N <= MAX_SIZE);
    }

    constexpr StaticVector() : arr() {}
    constexpr StaticVector(const StaticVector &other) :
        arr(other.arr), count(other.count) {}
    constexpr StaticVector(StaticVector &&other) :
        arr(std::move(other.arr)), count(other.count) {}
    constexpr StaticVector &operator=(const StaticVector &other) {
        arr = other.arr;
        count = other.count;
        return *this;
    }
    constexpr StaticVector &operator=(StaticVector &&other) {
        arr = std::move(other.arr);
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

    void push_back(const T &val) {
        assert(count < MAX_SIZE);
        arr[count++] = val;
    }

    void push_back(T &&val) {
        assert(count < MAX_SIZE);
        arr[count++] = std::forward<T>(val);
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
        return ret;
    }

    size_t size() const { return count; }
    const T *cbegin() const { return &arr[0]; }
    const T *cend()   const { return &arr[count]; }
    const T *begin()  const { return &arr[0]; }
    const T *end()    const { return &arr[count]; }
};

} // namespace retrec
