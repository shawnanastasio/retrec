#include <execution_context.h>

#include <sys/mman.h>
#include <algorithm>

using namespace retrec;

simple_execution_context::~simple_execution_context() {}

status_code simple_execution_context::init() {
    // Setup virtual address space allocator
    status_code ret = vaddr_map.init();
    if (ret != status_code::SUCCESS)
        return ret;

    // Allocate space for code
    uint64_t code_start = vaddr_map.allocate_high_vaddr(CODE_REGION_MAX_SIZE);
    if (!code_start)
        return status_code::NOMEM;

    // Map code space
    void *res = mmap((void *)code_start, CODE_REGION_MAX_SIZE,
                     PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                     -1, 0);
    if (res == (void *)-1)
        return status_code::NOMEM; // deallocate vaddr space?

    code_allocator.init((void *)code_start, CODE_REGION_MAX_SIZE);

    return status_code::SUCCESS;
}

status_code simple_execution_context::allocate_region(uint64_t start, size_t len, int prot, void **region_out) {
    if (start % getpagesize() != 0)
        return status_code::BADALIGN;

    if (vaddr_map.contains(start, len))
        return status_code::OVERLAP;

    pr_info("allocated region at 0x%zx\n", start);
    // Just try to map the region with mmap
    void *region = mmap((void *)start, len, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (region == (void *)-1)
        return status_code::NOMEM;

    if ((uint64_t)region != start) {
        pr_info("Kernel didn't map pages at requested address!\n");
        munmap(region, len);
        return status_code::NOMEM;
    }

    // Mark region as allocated
    vaddr_map.mark_allocated({start, start+len, process_memory_map::Mapping::Type::USER, prot});

    *region_out = region;
    return status_code::SUCCESS;
}

void *simple_execution_context::get_region_ptr(uint64_t ptr) {
    if (!vaddr_map.contains(ptr, sizeof(ptr)))
        return nullptr;

    return (void *)ptr;
}

status_code simple_execution_context::initialize_runtime_context(Architecture target_arch, translated_code_region *entry) {
    runtime_context = std::make_unique<retrec::runtime_context>();
    auto ret = runtime_context_init(runtime_context.get(), target_arch, entry);
    if (ret != status_code::SUCCESS)
        return ret;

    return status_code::SUCCESS;
}

void simple_execution_context::enter_translated_code() {
    assert(runtime_context);
    assert(runtime_context_execute(runtime_context.get()) == status_code::SUCCESS);
}

status_code simple_execution_context::protect_region(uint64_t start, uint64_t len, int prot) {
    auto *mapping = vaddr_map.find(start, len);
    if (!mapping)
        return status_code::NOMEM;

    mprotect((void *)start, len, prot);
    mapping->prot = prot;

    return status_code::SUCCESS;
}
