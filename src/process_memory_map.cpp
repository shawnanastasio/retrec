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

uint64_t process_memory_map::allocate_high_vaddr(size_t size) {
    if (size % getpagesize() != 0)
        return 0;

    // Current algorithm: go through process_memory_map and subtract size from
    // the first 0x7fff* mapping. This is pretty stupid but it's good enough for now.
    for (auto &mapping : map) {
        if (mapping.start >= 0x7fff00000000) {
            uint64_t new_start = mapping.start - size;
            map.emplace_back(new_start, new_start + size, Mapping::Type::USER);
            sort();
            return new_start;
        }
    }

    return 0;
}

uint64_t process_memory_map::allocate_low_vaddr(size_t size) {
    if (size % page_size != 0)
        return 0;

    // Same as allocate_high_vaddr, but pick the first region of the appropriate size
    for (size_t i=0; i<map.size() - 1; i++) {
        uint64_t new_start = map[i].end;
        if (new_start % page_size)
            new_start += page_size - (new_start % page_size);

        if (new_start + size <= map[i+1].start) {
            map.emplace_back(new_start, new_start + size, Mapping::Type::USER);
            sort();
            return new_start;
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

bool process_memory_map::contains(uint64_t addr, uint64_t len) const {
    for (const auto &cur : map) {
        // FIXME: This doesn't properly handle a conflict spread across multiple mappings
        if (cur.start <= addr && addr < cur.end)
            return true;
        else if (cur.start <= (addr+len) && (addr+len) < cur.end)
            return true;
    }

    return false;
}

std::optional<process_memory_map::Mapping> process_memory_map::find(uint64_t addr, uint64_t len, size_t *index_out) {
    size_t i = 0;
    for (auto &cur : map) {
        if (cur.start == addr && cur.end == len + addr) {
            if (index_out)
                *index_out = i;
            return cur;
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

