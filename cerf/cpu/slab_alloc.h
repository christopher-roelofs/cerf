#pragma once
/* SlabAllocator: free-list allocator for emulated memory regions.
   Manages blocks within committed EmulatedMemory pages using host-side
   metadata (ARM code never sees heap internals). Supports alloc, free,
   realloc with coalescing of adjacent free blocks.

   Matches WinCE heap semantics: 16-byte alignment, best-fit search,
   region-based growth. Used by HeapAlloc/LocalAlloc/malloc thunks. */

#include <cstdint>
#include <map>
#include <set>
#include <mutex>

class EmulatedMemory;

struct SlabAllocator {
    uint32_t region_base;     /* start of managed range */
    uint32_t region_size;     /* total reserved range */
    uint32_t bump_end;        /* high-water mark (next uncommitted addr) */
    EmulatedMemory* mem;

    static constexpr uint32_t ALIGN = 16;  /* WinCE ALIGNBYTES */
    static constexpr uint32_t MIN_SPLIT = 32; /* minimum free block worth keeping */

    struct BlockInfo {
        uint32_t alloc_size;  /* 16-byte aligned extent */
        uint32_t req_size;    /* original requested size */
        bool free;
    };

    /* Ordered by address for O(1) neighbor lookup during coalesce */
    std::map<uint32_t, BlockInfo> blocks;

    /* Free blocks indexed by size for best-fit search */
    std::map<uint32_t, std::set<uint32_t>> free_by_size;

    std::mutex mutex;

    SlabAllocator() = default;
    SlabAllocator(uint32_t base, uint32_t size, EmulatedMemory* m)
        : region_base(base), region_size(size), bump_end(base), mem(m) {}

    uint32_t Alloc(uint32_t size, bool zero = false);
    bool Free(uint32_t addr);
    uint32_t Realloc(uint32_t addr, uint32_t new_size);
    uint32_t ReallocInPlace(uint32_t addr, uint32_t new_size);
    uint32_t Size(uint32_t addr);
    bool Validate(uint32_t addr);
    void DestroyAll();

private:
    static uint32_t AlignUp(uint32_t sz) {
        return sz < ALIGN ? ALIGN : (sz + ALIGN - 1) & ~(ALIGN - 1);
    }
    void AddFree(uint32_t addr, uint32_t alloc_size);
    void RemoveFree(uint32_t addr, uint32_t alloc_size);
    void Coalesce(std::map<uint32_t, BlockInfo>::iterator it);
    void CommitRange(uint32_t addr, uint32_t size);
};
