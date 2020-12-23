#include <process_memory_map.h>

#include <algorithm>

using namespace retrec;


process_memory_map::process_memory_map(pid_t pid_) : pid(pid_), page_size(sysconf(_SC_PAGESIZE)) {}

status_code process_memory_map::init() {
    std::string path = std::string{"/proc/"} + std::to_string(pid) + "/maps";
    std::fstream maps(path, std::ios::in);
    if (!maps.is_open()) {
        pr_error("Failed to open %s!\n", path.c_str());
        return status_code::BADFILE;
    }

    std::string cur_line;
    while (std::getline(maps, cur_line)) {
        // Extract address range
        std::string range = cur_line.substr(0, cur_line.find(' '));
        std::string start_str = range.substr(0, range.find('-'));
        std::string end_str = range.substr(range.find('-') + 1, range.size());

        // Convert range to u64
        uint64_t start = std::stoull(start_str, 0, 16);
        uint64_t end = std::stoull(end_str, 0, 16);

        map.emplace_back(start, end, Mapping::Type::SYSTEM);
    }

    return status_code::SUCCESS;
}

uint64_t process_memory_map::allocate_vaddr_in_range(size_t size, Range range) {
    if (size % page_size != 0)
        return 0;
    if (range.low % page_size != 0)
        return 0;
    if (range.high - range.low < size)
        return 0;

    // Scan through address space at start of new account
    uint64_t cur_start = range.low;
    while (cur_start + size <= range.high) {
        // See if mapping already exists at this address
        auto mapping_opt = find(cur_start, size, nullptr, FindPolicy::CONTAINS);
        if (mapping_opt) {
            // It does - skip to the match's end
            cur_start = mapping_opt->end;
        } else {
            // It doesn't - we can use this region
            uint64_t cur_end = cur_start + size;
            map.emplace_back(cur_start, cur_end, Mapping::Type::USER);
            assert(cur_end % page_size == 0);
            sort();
            return cur_start;
        }
    }

    return 0;
}

void process_memory_map::sort() {
    std::sort(map.begin(), map.end(), [](auto &a, auto &b) {
        return a.start < b.start;
    });
}

void process_memory_map::mark_allocated(Mapping entry) {
    map.push_back(entry);
    sort();
}

std::optional<process_memory_map::Mapping> process_memory_map::find(uint64_t addr, uint64_t len, size_t *index_out,
                                                                    FindPolicy policy) {
    size_t i = 0;
    for (auto &cur : map) {
        switch (policy) {
            case FindPolicy::EXACT:
                if (cur.start == addr && cur.end == len + addr) {
                    if (index_out)
                        *index_out = i;
                    return cur;
                }
                break;

            case FindPolicy::CONTAINS:
                if (cur.start <= addr && (addr + len) <= cur.end) {
                    if (index_out)
                        *index_out = i;
                    return cur;
                }
                break;
        }

        ++i;
    }

    return std::nullopt;
}

void process_memory_map::free(uint64_t addr, uint64_t len) {
    size_t mapping_index;
    auto mapping = find(addr, len, &mapping_index);
    assert(mapping);

    map.erase(map.begin() + mapping_index);
}

