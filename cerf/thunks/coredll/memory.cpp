/* Memory allocation thunks: VirtualAlloc, Heap*, Local* — backed by SlabAllocator.
   Matches WinCE heap semantics: malloc → LocalAlloc → HeapAlloc chain,
   per-process isolation via ProcessSlot, kernel threads at 0x30000000+. */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../cpu/slab_alloc.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <mutex>
#include <map>

/* === Global heap instances === */

/* Main process heap: 0x00C00000-0x00EFFFFF (before stack) + 0x01000000-0x01BFFFFF (after) */
static SlabAllocator* g_main_heap = nullptr;

/* Kernel heap: 0x30000000+ (above slot-0, for driver threads like lpcd/dcomssd) */
static SlabAllocator* g_kernel_heap = nullptr;

/* Multiple heaps from HeapCreate: handle → allocator */
static std::map<uint32_t, SlabAllocator*> g_heap_map;
static std::mutex g_heap_map_mutex;
static std::atomic<uint32_t> g_next_heap_handle{0x00BF1000};

/* VirtualAlloc tracking: base → size (active allocations) */
static std::map<uint32_t, uint32_t> g_valloc_map;
/* VirtualFree'd ranges available for reuse: size → set of base addrs */
static std::map<uint32_t, std::set<uint32_t>> g_valloc_free;
static std::mutex g_valloc_mutex;

/* Fake process heap struct address (ARM code dereferences the handle) */
static constexpr uint32_t FAKE_PROCESS_HEAP = 0x00BF0000;

/* Get the correct SlabAllocator for the current thread context. */
SlabAllocator* GetSlab() {
    if (t_ctx && t_ctx->is_kernel_thread)
        return g_kernel_heap;
    auto* slot = EmulatedMemory::process_slot;
    if (slot && slot->has_own_allocators && slot->proc_slab)
        return slot->proc_slab;
    return g_main_heap;
}

/* Get slab for a specific heap handle (HeapAlloc's first arg). */
static SlabAllocator* GetSlabForHeap(uint32_t hHeap) {
    if (hHeap == FAKE_PROCESS_HEAP || hHeap == 0)
        return GetSlab();
    std::lock_guard<std::mutex> lock(g_heap_map_mutex);
    auto it = g_heap_map.find(hHeap);
    return (it != g_heap_map.end()) ? it->second : GetSlab();
}

void Win32Thunks::RegisterMemoryHandlers() {
    /* Reserve address ranges (unchanged from before) */
    mem.Reserve(0x00B00000, 0x00100000); /* VirtualAlloc: 1MB */
    mem.Reserve(0x00C00000, 0x00300000); /* Heap range A: 3MB (before stack) */
    mem.Reserve(0x01000000, 0x00C00000); /* Heap range B: 12MB (after stack) */
    mem.Reserve(0x01C00000, 0x00400000); /* VirtualAlloc overflow: 4MB */
    mem.Reserve(0x3F000000, 0x00010000); /* Marshaling scratch buffers */

    /* Initialize global heap allocators.
       Range A (0x00C00000-0x00EFFFFF) and B (0x01000000-0x01BFFFFF) are
       managed as one logical slab starting at A, overflowing into B.
       We use range A only; if it fills, range B starts as a second slab. */
    /* Range A: 0x00C00000-0x00EFFFFF (3MB, before stack gap at 0x00F00000)
       Range B: 0x01000000-0x01BFFFFF (12MB, after stack) — used for HeapCreate.
       Main slab covers range A only (3MB). With free+coalesce this handles
       typical WinCE apps. TODO: if 3MB proves tight for IE/mshtml, extend
       the main slab to also cover a portion of range B. */
    g_main_heap = new SlabAllocator(0x00C00000, 0x00300000, &mem);
    mem.Reserve(0x30000000, 0x04000000);
    g_kernel_heap = new SlabAllocator(0x30000000, 0x04000000, &mem);

    /* Register the process heap in the heap map */
    {
        std::lock_guard<std::mutex> lock(g_heap_map_mutex);
        g_heap_map[FAKE_PROCESS_HEAP] = g_main_heap;
    }

    /* -- VirtualAlloc / VirtualFree --
       Known differences from real WinCE (OK to skip for now):
       - MEM_RESERVE without MEM_COMMIT still commits pages (real WinCE only
         reserves address space; pages fault until committed)
       - MEM_DECOMMIT zeros pages but doesn't truly decommit (pages remain
         readable; real WinCE would fault on access to decommitted pages)
       - MEM_RELEASE doesn't enforce size==0 requirement
       - VirtualFree'd ranges are not coalesced with adjacent freed ranges
         (fragmentation possible under heavy VirtualAlloc/VirtualFree churn) */

    Thunk("VirtualAlloc", 524, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr_arg = regs[0], size = regs[1], type = regs[2];
        static std::atomic<uint32_t> next_valloc{0x00B00000};
        static constexpr uint32_t VALLOC_LIMIT = 0x00C00000; /* don't overflow into heap */
        uint32_t aligned = std::max((size + 0xFFF) & ~0xFFFu, 0x1000u);
        uint32_t base;
        /* MEM_COMMIT on existing reservation: just commit the pages */
        if (addr_arg && (type & 0x1000 /* MEM_COMMIT */) && !(type & 0x2000 /* MEM_RESERVE */)) {
            std::lock_guard<std::mutex> lock(g_valloc_mutex);
            if (g_valloc_map.count(addr_arg)) {
                mem.Alloc(addr_arg, size, regs[3]);
                regs[0] = addr_arg;
                LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X, COMMIT) -> 0x%08X\n",
                    addr_arg, size, regs[0]);
                return true;
            }
        }
        std::lock_guard<std::mutex> lock(g_valloc_mutex);
        if (addr_arg) {
            base = addr_arg;
        } else {
            /* Check free list for a reusable range (best-fit) */
            base = 0;
            auto fit = g_valloc_free.lower_bound(aligned);
            if (fit != g_valloc_free.end() && !fit->second.empty()) {
                base = *fit->second.begin();
                uint32_t free_size = fit->first;
                fit->second.erase(fit->second.begin());
                if (fit->second.empty()) g_valloc_free.erase(fit);
                /* Split excess back into free list */
                if (free_size > aligned) {
                    uint32_t remainder = free_size - aligned;
                    g_valloc_free[remainder].insert(base + aligned);
                }
            }
            if (!base) {
                base = next_valloc.fetch_add(aligned);
                if (base + aligned > VALLOC_LIMIT) {
                    /* Overflow: try VirtualAlloc overflow range */
                    static std::atomic<uint32_t> next_valloc2{0x01C00000};
                    base = next_valloc2.fetch_add(aligned);
                }
            }
        }
        uint8_t* ptr = mem.Alloc(base, size, regs[3]);
        regs[0] = ptr ? base : 0;
        if (regs[0]) g_valloc_map[regs[0]] = aligned;
        LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X, 0x%X) -> 0x%08X\n",
            addr_arg, size, type, regs[0]);
        return true;
    });
    Thunk("VirtualFree", 525, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], size = regs[1], type = regs[2];
        LOG(API, "[API] VirtualFree(0x%08X, 0x%X, 0x%X)\n", addr, size, type);
        std::lock_guard<std::mutex> lock(g_valloc_mutex);
        auto it = g_valloc_map.find(addr);
        if (it != g_valloc_map.end()) {
            uint8_t* p = mem.Translate(addr);
            if (p) memset(p, 0, it->second);
            if (type & 0x8000 /* MEM_RELEASE */) {
                g_valloc_free[it->second].insert(addr);
                g_valloc_map.erase(it);
            }
        }
        regs[0] = 1;
        return true;
    });

    /* -- GetProcessHeap / HeapCreate / HeapDestroy -- */

    Thunk("GetProcessHeap", 50, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Keep fake struct for ARM code that dereferences the handle */
        static bool initialized = false;
        if (!initialized) {
            mem.Alloc(FAKE_PROCESS_HEAP, 0x1000);
            mem.Write32(FAKE_PROCESS_HEAP, 0x50616548); /* "HeaP" signature */
            mem.Write32(FAKE_PROCESS_HEAP + 4, 0x00C00000);
            mem.Write32(FAKE_PROCESS_HEAP + 8, 0x00300000);
            initialized = true;
        }
        regs[0] = FAKE_PROCESS_HEAP;
        return true;
    });
    Thunk("HeapCreate", 44, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Each created heap gets its own sub-range within 0x01000000-0x01BFFFFF.
           Sub-ranges are 1MB each, supporting up to 12 custom heaps. */
        static std::atomic<uint32_t> next_heap_base{0x01000000};
        uint32_t heap_base = next_heap_base.fetch_add(0x00100000);
        if (heap_base >= 0x01C00000) {
            LOG(API, "[API] HeapCreate: out of heap address space\n");
            regs[0] = FAKE_PROCESS_HEAP; /* fallback to process heap */
            return true;
        }
        uint32_t handle = g_next_heap_handle.fetch_add(0x100);
        mem.Alloc(handle, 0x100);
        mem.Write32(handle, 0x50616548); /* "HeaP" signature */
        auto* slab = new SlabAllocator(heap_base, 0x00100000, &mem);
        {
            std::lock_guard<std::mutex> lock(g_heap_map_mutex);
            g_heap_map[handle] = slab;
        }
        LOG(API, "[API] HeapCreate(0x%X, 0x%X, 0x%X) -> 0x%08X\n",
            regs[0], regs[1], regs[2], handle);
        regs[0] = handle;
        return true;
    });
    Thunk("HeapDestroy", 45, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t handle = regs[0];
        LOG(API, "[API] HeapDestroy(0x%08X)\n", handle);
        std::lock_guard<std::mutex> lock(g_heap_map_mutex);
        auto it = g_heap_map.find(handle);
        if (it != g_heap_map.end() && it->second != g_main_heap) {
            it->second->DestroyAll();
            delete it->second;
            g_heap_map.erase(it);
        }
        regs[0] = 1;
        return true;
    });

    /* -- HeapAlloc / HeapFree / HeapReAlloc / HeapSize / HeapValidate -- */

    auto heapAllocImpl = [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hHeap = regs[0], flags = regs[1], size = regs[2];
        bool zero = (flags & 0x08u /* HEAP_ZERO_MEMORY */) != 0;
        SlabAllocator* slab = GetSlabForHeap(hHeap);
        regs[0] = slab ? slab->Alloc(size, zero) : 0;
        LOG(API, "[API] HeapAlloc(0x%08X, 0x%X, %u) -> 0x%08X\n",
            hHeap, flags, size, regs[0]);
        return true;
    };
    Thunk("HeapAlloc", 46, heapAllocImpl);
    Thunk("HeapAllocTrace", 20, heapAllocImpl);
    Thunk("HeapFree", 49, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hHeap = regs[0], addr = regs[2];
        SlabAllocator* slab = GetSlabForHeap(hHeap);
        regs[0] = (slab && slab->Free(addr)) ? 1 : 0;
        return true;
    });
    Thunk("HeapReAlloc", 47, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hHeap = regs[0], flags = regs[1], old_ptr = regs[2], new_size = regs[3];
        SlabAllocator* slab = GetSlabForHeap(hHeap);
        if (!slab) { regs[0] = 0; return true; }
        bool in_place_only = (flags & 0x10 /* HEAP_REALLOC_IN_PLACE_ONLY */) != 0;
        bool zero_growth = (flags & 0x08 /* HEAP_ZERO_MEMORY */) != 0;
        uint32_t old_size = slab->Size(old_ptr);
        uint32_t result;
        if (in_place_only) {
            result = slab->ReallocInPlace(old_ptr, new_size);
        } else {
            result = slab->Realloc(old_ptr, new_size);
        }
        if (zero_growth && result && new_size > old_size && old_size != (uint32_t)-1) {
            uint8_t* p = mem.Translate(result + old_size);
            if (p) memset(p, 0, new_size - old_size);
        }
        regs[0] = result;
        return true;
    });
    Thunk("HeapSize", 48, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hHeap = regs[0], addr = regs[2];
        SlabAllocator* slab = GetSlabForHeap(hHeap);
        regs[0] = slab ? slab->Size(addr) : (uint32_t)-1;
        return true;
    });
    Thunk("HeapValidate", 51, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hHeap = regs[0], addr = regs[2];
        SlabAllocator* slab = GetSlabForHeap(hHeap);
        regs[0] = (slab && slab->Validate(addr)) ? 1 : 0;
        return true;
    });

    /* -- LocalAlloc / LocalFree / LocalReAlloc / LocalSize -- */

    Thunk("LocalAlloc", 33, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t flags = regs[0], size = regs[1];
        bool zero = (flags & 0x0040u /* LMEM_ZEROINIT */) != 0;
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Alloc(size, zero) : 0;
        return true;
    });
    thunk_handlers["LocalAllocTrace"] = thunk_handlers["LocalAlloc"];
    /* TODO: LocalReAlloc should check LMEM_MOVEABLE flag — without it,
       real WinCE only allows in-place realloc (same as HEAP_REALLOC_IN_PLACE_ONLY).
       Currently we always allow moving. */
    Thunk("LocalReAlloc", 34, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t old_ptr = regs[0], new_size = regs[1];
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Realloc(old_ptr, new_size) : 0;
        return true;
    });
    Thunk("LocalFree", 36, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t hMem = regs[0];
        SlabAllocator* slab = GetSlab();
        bool ok = !hMem || (slab && slab->Free(hMem));
        regs[0] = ok ? 0 : hMem; /* NULL on success, handle on failure */
        return true;
    });
    Thunk("LocalSize", 35, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SlabAllocator* slab = GetSlab();
        uint32_t size = slab ? slab->Size(regs[0]) : (uint32_t)-1;
        regs[0] = (size == (uint32_t)-1) ? 0 : size;
        return true;
    });

    RegisterCrtMemoryHandlers();
}
