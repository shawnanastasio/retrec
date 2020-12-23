#include <execution_context.h>

#include <unistd.h>
#include <sys/mman.h>
#include <algorithm>

using namespace retrec;

execution_context::execution_context() : vaddr_map(getpid()),
                                         page_size(sysconf(_SC_PAGESIZE)) {}

execution_context::~execution_context() {}

status_code execution_context::init() {
    // Setup virtual address space allocator
    status_code res = vaddr_map.init();
    if (res != status_code::SUCCESS)
        return res;

    // Allocate code buffer
    void *code_start;
    res = allocate_and_map_vaddr(HIGH_MEM_RANGE, CODE_REGION_MAX_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, &code_start);
    if (res != status_code::SUCCESS)
        return res;

    code_allocator.init(code_start, CODE_REGION_MAX_SIZE);

    return status_code::SUCCESS;
}

status_code execution_context::allocate_and_map_vaddr(process_memory_map::Range range, size_t size, int prot, void **region_out) {
    uint64_t vaddr = vaddr_map.allocate_vaddr_in_range(size, range);
    if (!vaddr)
        return status_code::NOMEM;

    // Map the allocated address space
    void *mem = mmap((void *)vaddr, size, prot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (mem == (void *)-1) {
        pr_debug("mmap failed at %p: %m\n", (void *)vaddr);
        vaddr_map.free(vaddr, size);
        return status_code::NOMEM;
    }

    *region_out = mem;
    return status_code::SUCCESS;
}

status_code execution_context::allocate_new_stack(size_t size, void **stack_out) {
    // Determine the number of pages to allocate
    size_t allocation_size = align_to(size, page_size) + 1*page_size /* guard page */;
    assert(allocation_size >= 2);

    // Allocate at the end of the address space
    void *stack;
    auto res = allocate_and_map_vaddr(HIGH_MEM_RANGE, allocation_size, PROT_READ | PROT_WRITE, &stack);
    if (res != status_code::SUCCESS)
        return res;

    // Mark the guard page as !R, !W, !X
    mprotect((void *)stack, page_size, 0);

    *stack_out = (void *)((char *)stack + allocation_size);
    return status_code::SUCCESS;
}

status_code execution_context::allocate_region(uint64_t start, size_t len, int prot, void **region_out,
                                               process_memory_map::Mapping::Type type) {
    if (start % page_size != 0)
        return status_code::BADALIGN;

    if (vaddr_map.find(start, len, nullptr, process_memory_map::FindPolicy::CONTAINS))
        return status_code::OVERLAP;

    pr_info("allocated region at 0x%zx\n", start);
    // Just try to map the region with mmap
    void *region = mmap((void *)start, len, prot, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (region == (void *)-1)
        return status_code::NOMEM;

    if ((uint64_t)region != start) {
        pr_info("Kernel didn't map pages at requested address!\n");
        munmap(region, len);
        return status_code::NOMEM;
    }

    // Mark region as allocated
    vaddr_map.mark_allocated({start, start+len, type, prot});

    if (region_out)
        *region_out = region;
    return status_code::SUCCESS;
}

void *execution_context::get_region_ptr(uint64_t ptr) {
    if (!vaddr_map.find(ptr, sizeof(ptr), nullptr, process_memory_map::FindPolicy::CONTAINS))
        return nullptr;

    return (void *)ptr;
}

status_code execution_context::initialize_runtime_context(Architecture target_arch, void *entry, virtual_address_mapper *vam) {
    // Allocate an initial stack + guard page
    void *new_stack;
    auto res = allocate_new_stack(DEFAULT_STACK_SIZE, &new_stack);
    if (res != status_code::SUCCESS) {
        pr_error("Failed to allocate stack for translated code: %s\n", status_code_str(res));
        return res;
    }

    // Call architecture-specific function to populate the runtime context
    runtime_context = std::make_unique<retrec::runtime_context>();
    res = runtime_context->init(target_arch, entry, new_stack, vam);
    if (res != status_code::SUCCESS)
        return res;

    return status_code::SUCCESS;
}

status_code execution_context::enter_translated_code() {
    assert(runtime_context);
    return runtime_context->execute();
}

status_code execution_context::protect_region(uint64_t start, uint64_t len, int prot) {
    auto mapping = vaddr_map.find(start, len, nullptr);
    if (!mapping)
        return status_code::NOMEM;

    mprotect((void *)start, len, prot);
    mapping->prot = prot;

    return status_code::SUCCESS;
}
