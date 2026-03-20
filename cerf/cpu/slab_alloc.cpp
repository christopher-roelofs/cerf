/* SlabAllocator: free-list allocator for emulated WinCE heap.
   Host-side metadata with best-fit search and adjacent-block coalescing.
   See slab_alloc.h for design rationale. */
#define NOMINMAX
#include "slab_alloc.h"
#include "mem.h"
#include "../log.h"
#include <cstring>
#include <algorithm>

/* Commit emulated memory pages covering [addr, addr+size).
   Same logic as the old CommitPages — skips already-committed pages,
   uses HasCommittedRegion to avoid DLL alias confusion. */
void SlabAllocator::CommitRange(uint32_t addr, uint32_t size) {
    for (uint32_t p = addr & ~0xFFFu; p < addr + size; p += 0x1000) {
        if (!mem->HasCommittedRegion(p))
            mem->Alloc(p, 0x1000);
    }
}

void SlabAllocator::AddFree(uint32_t addr, uint32_t alloc_size) {
    free_by_size[alloc_size].insert(addr);
}

void SlabAllocator::RemoveFree(uint32_t addr, uint32_t alloc_size) {
    auto sit = free_by_size.find(alloc_size);
    if (sit != free_by_size.end()) {
        sit->second.erase(addr);
        if (sit->second.empty()) free_by_size.erase(sit);
    }
}

/* Merge a free block with adjacent free neighbors. */
void SlabAllocator::Coalesce(std::map<uint32_t, BlockInfo>::iterator it) {
    uint32_t addr = it->first;
    uint32_t size = it->second.alloc_size;

    /* Merge with next block */
    auto next = std::next(it);
    if (next != blocks.end() && next->second.free &&
        next->first == addr + size) {
        RemoveFree(next->first, next->second.alloc_size);
        size += next->second.alloc_size;
        blocks.erase(next);
    }

    /* Merge with previous block */
    if (it != blocks.begin()) {
        auto prev = std::prev(it);
        if (prev->second.free && prev->first + prev->second.alloc_size == addr) {
            RemoveFree(prev->first, prev->second.alloc_size);
            uint32_t new_addr = prev->first;
            size += prev->second.alloc_size;
            blocks.erase(it);
            prev->second.alloc_size = size;
            prev->second.req_size = 0;
            AddFree(new_addr, size);
            return;
        }
    }

    it->second.alloc_size = size;
    it->second.req_size = 0;
    AddFree(addr, size);
}

uint32_t SlabAllocator::Alloc(uint32_t size, bool zero) {
    std::lock_guard<std::mutex> lock(mutex);
    if (size > region_size) return 0; /* overflow guard */
    uint32_t aligned = AlignUp(size ? size : 1);

    /* Best-fit: find smallest free block >= aligned */
    auto fit = free_by_size.lower_bound(aligned);
    if (fit != free_by_size.end() && !fit->second.empty()) {
        uint32_t addr = *fit->second.begin();
        /* Remove from free list */
        fit->second.erase(fit->second.begin());
        if (fit->second.empty()) free_by_size.erase(fit);

        auto bit = blocks.find(addr);
        uint32_t blk_size = bit->second.alloc_size;
        bit->second.free = false;
        bit->second.req_size = size;

        /* Split if remainder is large enough */
        uint32_t remainder = blk_size - aligned;
        if (remainder >= MIN_SPLIT) {
            bit->second.alloc_size = aligned;
            uint32_t split_addr = addr + aligned;
            blocks[split_addr] = {remainder, 0, true};
            AddFree(split_addr, remainder);
        }

        if (zero) {
            uint8_t* p = mem->Translate(addr);
            if (p) memset(p, 0, bit->second.alloc_size);
        }
        return addr;
    }

    /* No free block — bump allocate from uncommitted region */
    uint32_t addr = bump_end;
    if (addr + aligned > region_base + region_size) {
        LOG(EMU, "[HEAP] SlabAllocator: out of address space "
            "(base=0x%08X, need 0x%X at 0x%08X)\n",
            region_base, aligned, addr);
        return 0;
    }
    CommitRange(addr, aligned);
    bump_end = addr + aligned;
    blocks[addr] = {aligned, size, false};

    if (zero) {
        uint8_t* p = mem->Translate(addr);
        if (p) memset(p, 0, aligned);
    }
    return addr;
}

bool SlabAllocator::Free(uint32_t addr) {
    if (!addr) return true; /* free(NULL) is valid */
    std::lock_guard<std::mutex> lock(mutex);
    auto it = blocks.find(addr);
    if (it == blocks.end() || it->second.free) return false;

    it->second.free = true;
    it->second.req_size = 0;
    Coalesce(it);
    return true;
}

uint32_t SlabAllocator::Realloc(uint32_t addr, uint32_t new_size) {
    if (!addr) return Alloc(new_size);
    if (!new_size) { Free(addr); return 0; }

    std::unique_lock<std::mutex> lock(mutex);
    auto it = blocks.find(addr);
    if (it == blocks.end() || it->second.free) return 0;

    uint32_t new_aligned = AlignUp(new_size);
    uint32_t old_alloc = it->second.alloc_size;

    /* Shrink in place */
    if (new_aligned <= old_alloc) {
        uint32_t remainder = old_alloc - new_aligned;
        if (remainder >= MIN_SPLIT) {
            it->second.alloc_size = new_aligned;
            uint32_t split_addr = addr + new_aligned;
            blocks[split_addr] = {remainder, 0, true};
            auto split_it = blocks.find(split_addr);
            Coalesce(split_it);
        }
        it->second.req_size = new_size;
        return addr;
    }

    /* Try to merge with next free block */
    auto next = std::next(it);
    if (next != blocks.end() && next->second.free &&
        next->first == addr + old_alloc) {
        uint32_t combined = old_alloc + next->second.alloc_size;
        if (combined >= new_aligned) {
            RemoveFree(next->first, next->second.alloc_size);
            blocks.erase(next);
            it->second.alloc_size = combined;
            /* Split excess */
            uint32_t remainder = combined - new_aligned;
            if (remainder >= MIN_SPLIT) {
                it->second.alloc_size = new_aligned;
                uint32_t split_addr = addr + new_aligned;
                blocks[split_addr] = {remainder, 0, true};
                AddFree(split_addr, remainder);
            }
            it->second.req_size = new_size;
            return addr;
        }
    }

    /* Can't extend — alloc new, copy, free old.
       Save state before releasing lock to avoid iterator invalidation.
       Copy alloc_size (not req_size) because HeapSize returns alloc_size
       and callers may have written up to that many bytes. */
    uint32_t old_copy = it->second.alloc_size;
    lock.unlock();
    uint32_t new_addr = Alloc(new_size);
    if (new_addr) {
        uint32_t copy_size = std::min(old_copy, new_size);
        uint8_t* src = mem->Translate(addr);
        uint8_t* dst = mem->Translate(new_addr);
        if (src && dst && copy_size > 0)
            memcpy(dst, src, copy_size);
        Free(addr);
    }
    return new_addr;
}

/* Realloc in-place only — returns addr on success, 0 on failure (won't move). */
uint32_t SlabAllocator::ReallocInPlace(uint32_t addr, uint32_t new_size) {
    if (!addr) return 0;
    if (!new_size) { Free(addr); return 0; }

    std::lock_guard<std::mutex> lock(mutex);
    auto it = blocks.find(addr);
    if (it == blocks.end() || it->second.free) return 0;

    uint32_t new_aligned = AlignUp(new_size);
    uint32_t old_alloc = it->second.alloc_size;

    /* Shrink: always possible in-place */
    if (new_aligned <= old_alloc) {
        uint32_t remainder = old_alloc - new_aligned;
        if (remainder >= MIN_SPLIT) {
            it->second.alloc_size = new_aligned;
            uint32_t split_addr = addr + new_aligned;
            blocks[split_addr] = {remainder, 0, true};
            auto split_it = blocks.find(split_addr);
            Coalesce(split_it);
        }
        it->second.req_size = new_size;
        return addr;
    }

    /* Grow: only if next block is free and large enough */
    auto next = std::next(it);
    if (next != blocks.end() && next->second.free &&
        next->first == addr + old_alloc) {
        uint32_t combined = old_alloc + next->second.alloc_size;
        if (combined >= new_aligned) {
            RemoveFree(next->first, next->second.alloc_size);
            blocks.erase(next);
            it->second.alloc_size = combined;
            uint32_t remainder = combined - new_aligned;
            if (remainder >= MIN_SPLIT) {
                it->second.alloc_size = new_aligned;
                uint32_t split_addr = addr + new_aligned;
                blocks[split_addr] = {remainder, 0, true};
                AddFree(split_addr, remainder);
            }
            it->second.req_size = new_size;
            return addr;
        }
    }
    return 0; /* can't grow in place */
}

uint32_t SlabAllocator::Size(uint32_t addr) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = blocks.find(addr);
    if (it == blocks.end() || it->second.free) return (uint32_t)-1;
    /* Return aligned usable size, matching real WinCE Int_HeapSize
       which returns pit->size - sizeof(item) (the full aligned extent). */
    return it->second.alloc_size;
}

bool SlabAllocator::Validate(uint32_t addr) {
    std::lock_guard<std::mutex> lock(mutex);
    if (!addr) {
        /* Validate entire heap — check all blocks are consistent */
        for (auto& [a, b] : blocks) {
            if (a < region_base || a + b.alloc_size > region_base + region_size)
                return false;
        }
        return true;
    }
    auto it = blocks.find(addr);
    return it != blocks.end() && !it->second.free;
}

void SlabAllocator::DestroyAll() {
    std::lock_guard<std::mutex> lock(mutex);
    blocks.clear();
    free_by_size.clear();
    bump_end = region_base;
}
