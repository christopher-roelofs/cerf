#include "mem.h"

/* Auto-allocate on fault: if an access hits unmapped memory, allocate a page.
   Reject addresses that can't be identity-mapped on Windows (below 64KB or
   near 4GB boundary) — fallback allocations would crash if passed to native code. */
uint8_t* EmulatedMemory::AutoAlloc(uint32_t addr) {
    uint32_t page_base = addr & ~(PAGE_SIZE - 1);
    if (page_base < 0x10000 || page_base >= 0xF0000000) return nullptr;

    /* Check if a region already covers this page (avoids duplicate allocations
       that can result in different host addresses for the same emulated page). */
    for (auto& r : regions) {
        if (page_base >= r.base && page_base + PAGE_SIZE <= r.base + r.size)
            return r.host_ptr + (page_base - r.base);
    }

    return Alloc(page_base, PAGE_SIZE);
}

void EmulatedMemory::LogFault(const char* op, uint32_t addr) const {
    if (fault_count < 10) {
        fprintf(stderr, "[MEM] %s fault at 0x%08X\n", op, addr);
    } else if (fault_count == 10) {
        fprintf(stderr, "[MEM] ... suppressing further fault messages\n");
    }
    fault_count++;
}

uint32_t EmulatedMemory::AlignUp(uint32_t val, uint32_t align) {
    return (val + align - 1) & ~(align - 1);
}
