#pragma once

#include <util.h>

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstdint>

#include <unistd.h>

namespace retrec {

class process_memory_map {
public:
    struct Mapping {
        uint64_t start;
        uint64_t end;

        enum class Type {
            SYSTEM, // Allocated by the system/runtime
            USER,   // Allocated by us
        } type;

        int prot;

        Mapping(uint64_t start_, uint64_t end_, Type type_)
            : start(start_), end(end_), type(type_) {}
        Mapping(uint64_t start_, uint64_t end_, Type type_, int prot_)
            : start(start_), end(end_), type(type_), prot(prot_) {}
    };

    explicit process_memory_map(pid_t pid_) : pid(pid_) {}

    status_code init();
    uint64_t allocate_high_vaddr(size_t size);
    uint64_t allocate_low_vaddr(size_t size);
    void mark_allocated(Mapping entry);
    [[nodiscard]] bool contains(uint64_t addr, uint64_t len) const;
    Mapping *find(uint64_t addr, uint64_t len);

private:
    pid_t pid;
    std::vector<Mapping> map;

    void sort();
};

}