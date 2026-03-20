/* Memory allocation thunks: VirtualAlloc, Heap*, Local*, malloc/free */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>

/* Track allocation sizes so LocalSize/HeapSize/_msize return correct values
   and realloc variants copy the correct number of bytes. */
static std::mutex g_alloc_mutex;
static std::unordered_map<uint32_t, uint32_t> g_alloc_sizes;

void TrackAlloc(uint32_t addr, uint32_t size) {
    std::lock_guard<std::mutex> lk(g_alloc_mutex);
    g_alloc_sizes[addr] = size;
}
uint32_t GetAllocSize(uint32_t addr) {
    std::lock_guard<std::mutex> lk(g_alloc_mutex);
    auto it = g_alloc_sizes.find(addr);
    return (it != g_alloc_sizes.end()) ? it->second : 0;
}
void FreeAlloc(uint32_t addr) {
    std::lock_guard<std::mutex> lk(g_alloc_mutex);
    g_alloc_sizes.erase(addr);
}

/* All allocator bases MUST be below 0x02000000 (32MB slot boundary).
   WinCE ARM code applies slot masking (AND addr, #0x01FFFFFF) to pointers.
   Any address >= 0x02000000 gets corrupted to a different address.

   DLL slot-0 aliases (dll_addr & 0x01FFFFFF) can span up to 0x01FFFFFF.
   Late-loaded DLLs (e.g. webview.dll at 0x10C10000) alias into the heap
   range. CommitPages() uses HasCommittedRegion() to avoid confusing DLL
   alias pages with committed heap pages — once committed, the global
   region takes priority over the alias in Translate().

   Address space layout (allocator ranges — may shadow DLL aliases after commit):
     VirtualAlloc:  0x00B00000  (grows up, ~1MB for app VirtualAlloc calls)
     HeapAlloc:     0x00C00000  (grows up, ~3MB for heap blocks)
     Stack:         0x00F00000-0x01000000  (1MB, grows down from STACK_BASE)
     HeapReAlloc:   0x01000000  (grows up, ~1MB for heap realloc)
     malloc etc:    0x01100000  (grows up, ~3MB for malloc/calloc/realloc)
     LocalAlloc:    0x01400000  (grows up, ~4MB for small heap allocations)
     LocalReAlloc:  0x01800000  (grows up, ~4MB for reallocation buffers)
     VirtualAlloc2: 0x01C00000  (overflow, ~4MB additional VirtualAlloc space)
   Sub-page allocation: blocks <= 4032 bytes use 16-byte alignment within
   shared pages, giving ~50x address space savings for small allocations. */

/* Commit pages covering [addr, addr+size). Skips already-committed pages.
   Uses HasCommittedRegion() which checks actual committed regions only —
   NOT DLL slot-0 aliases. DLL aliases map (dll_base & 0x01FFFFFF) back to
   DLL .text/.data, so IsValid() returns true for heap addresses that shadow
   a DLL alias (e.g. heap 0x00C12000 aliased to webview.dll 0x10C12000).
   Without this, the allocator skips committing the page, and subsequent
   memset/Translate writes to the DLL's code pages instead of the heap. */
void CommitPages(EmulatedMemory& mem, uint32_t addr, uint32_t size) {
    for (uint32_t p = addr & ~0xFFFu; p < addr + size; p += 0x1000) {
        if (!mem.HasCommittedRegion(p))
            mem.Alloc(p, 0x1000);
    }
}

/* Get the appropriate allocator counter for the current process context.
   Child processes (with active ProcessSlot) use per-process counters to avoid
   address overlap with the parent's allocations. */
/* Kernel heap counters — used by driver threads (lpcd.dll, dcomssd.dll).
   Allocated above 0x02000000 (shared DLL space) so they don't conflict
   with user process ProcessSlot overlays on slot-0. On real WinCE,
   device.exe has its own slot — this is the equivalent. */
static std::atomic<uint32_t> g_kernel_heap{0x30000000};
static std::atomic<uint32_t> g_kernel_malloc{0x32000000};

std::atomic<uint32_t>& GetHeapCounter(std::atomic<uint32_t>& global_counter) {
    if (t_ctx && t_ctx->is_kernel_thread)
        return g_kernel_heap;
    auto* slot = EmulatedMemory::process_slot;
    if (slot && slot->has_own_allocators)
        return slot->proc_heap_counter;
    return global_counter;
}

std::atomic<uint32_t>& GetMallocCounter(std::atomic<uint32_t>& global_counter) {
    if (t_ctx && t_ctx->is_kernel_thread)
        return g_kernel_malloc;
    auto* slot = EmulatedMemory::process_slot;
    if (slot && slot->has_own_allocators)
        return slot->proc_malloc_counter;
    return global_counter;
}

/* Bump-allocate with sub-page packing for small allocations. */
uint32_t BumpAlloc(std::atomic<uint32_t>& counter, EmulatedMemory& mem,
                          uint32_t size) {
    uint32_t alloc_size = size > 0 ? size : 0x10;
    /* Small: 16-byte aligned (pack into shared pages). Large: page-aligned. */
    uint32_t step = (alloc_size <= 0xFC0)
        ? std::max((alloc_size + 0xFu) & ~0xFu, 0x10u)
        : std::max((alloc_size + 0xFFFu) & ~0xFFFu, 0x1000u);
    uint32_t addr = counter.fetch_add(step);
    CommitPages(mem, addr, step);
    return addr;
}

void Win32Thunks::RegisterMemoryHandlers() {
    /* Pre-reserve address ranges for each allocator so that page-by-page
       commits within these ranges succeed (Windows requires 64KB-aligned
       addresses for MEM_RESERVE, but MEM_COMMIT works within reservations). */
    mem.Reserve(0x00B00000, 0x00100000); /* VirtualAlloc: 0x00B00000-0x00BFFFFF (1MB) */
    mem.Reserve(0x00C00000, 0x00300000); /* HeapAlloc:    0x00C00000-0x00EFFFFF (3MB) */
    /* Stack at 0x00F00000-0x01000000 is reserved by AllocStack() */
    mem.Reserve(0x01000000, 0x00100000); /* HeapReAlloc:  0x01000000-0x010FFFFF (1MB) */
    mem.Reserve(0x01100000, 0x00300000); /* malloc etc:   0x01100000-0x013FFFFF (3MB) */
    mem.Reserve(0x01400000, 0x00400000); /* LocalAlloc:   0x01400000-0x017FFFFF (4MB) */
    mem.Reserve(0x01800000, 0x00400000); /* LocalReAlloc: 0x01800000-0x01BFFFFF (4MB) */
    mem.Reserve(0x01C00000, 0x00400000); /* VirtualAlloc overflow: 0x01C00000-0x01FFFFFF */
    mem.Reserve(0x3F000000, 0x00010000); /* Marshaling scratch buffers (callbacks/dlgproc) */

    Thunk("VirtualAlloc", 524, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr_arg = regs[0], size = regs[1];
        static std::atomic<uint32_t> next_valloc{0x00B00000};
        uint32_t aligned = std::max((size + 0xFFF) & ~0xFFF, 0x1000u);
        uint32_t base = addr_arg ? addr_arg : next_valloc.fetch_add(aligned);
        uint8_t* ptr = mem.Alloc(base, size, regs[3]);
        regs[0] = ptr ? base : 0;
        if (regs[0]) TrackAlloc(regs[0], size);
        LOG(API, "[API] VirtualAlloc(0x%08X, 0x%X) -> 0x%08X\n", addr_arg, size, regs[0]);
        return true;
    });
    Thunk("VirtualFree", 525, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[STUB] VirtualFree(0x%08X) -> 1 (leak)\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("LocalAlloc", 33, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        static std::atomic<uint32_t> next_local{0x01400000};
        uint32_t flags = regs[0], size = regs[1];
        uint32_t addr = BumpAlloc(next_local, mem, size);
        TrackAlloc(addr, size);
        if ((flags & 0x0040u /* LMEM_ZEROINIT */) && size > 0) {
            /* Zero page-by-page to handle non-contiguous host backing */
            for (uint32_t off = 0; off < size; ) {
                uint32_t page_rem = 0x1000 - ((addr + off) & 0xFFF);
                uint32_t chunk = std::min(page_rem, size - off);
                uint8_t* host = mem.Translate(addr + off);
                if (host) memset(host, 0, chunk);
                off += chunk;
            }
        }
        regs[0] = addr;
        return true;
    });
    thunk_handlers["LocalAllocTrace"] = thunk_handlers["LocalAlloc"];
    Thunk("LocalReAlloc", 34, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], new_size = regs[1];
        static std::atomic<uint32_t> next_lrealloc{0x01800000};
        uint32_t addr = BumpAlloc(next_lrealloc, mem, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) {
            uint32_t old_size = GetAllocSize(old_ptr);
            uint32_t copy_size = old_size ? std::min(old_size, new_size) : new_size;
            memcpy(new_host, old_host, copy_size);
        }
        TrackAlloc(addr, new_size);
        regs[0] = addr;
        return true;
    });
    Thunk("LocalFree", 36, [](uint32_t* regs, EmulatedMemory&) -> bool {
        FreeAlloc(regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("LocalSize", 35, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t size = GetAllocSize(regs[0]);
        if (!size) size = 0x1000; /* fallback for untracked allocations */
        regs[0] = size;
        return true;
    });
    Thunk("GetProcessHeap", 50, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Return a pointer to a fake heap structure in emulated memory.
           ARM code (mshtml, OLE) dereferences the heap handle to validate it.
           Returning a dummy value like 0xDEAD0001 causes HeapString allocation
           failures because the handle doesn't point to readable memory. */
        constexpr uint32_t FAKE_PROCESS_HEAP = 0x00BF0000;
        static bool initialized = false;
        if (!initialized) {
            mem.Alloc(FAKE_PROCESS_HEAP, 0x1000);
            mem.Write32(FAKE_PROCESS_HEAP, 0x48454150); /* "HEAP" signature */
            mem.Write32(FAKE_PROCESS_HEAP + 4, 0x00C00000); /* base addr */
            mem.Write32(FAKE_PROCESS_HEAP + 8, 0x00300000); /* max size */
            initialized = true;
        }
        regs[0] = FAKE_PROCESS_HEAP;
        return true;
    });
    auto heapAllocImpl = [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        static std::atomic<uint32_t> next_heap{0x00C00000};
        auto& heap_ctr = GetHeapCounter(next_heap);
        uint32_t hHeap = regs[0], flags = regs[1], size = regs[2];
        regs[0] = BumpAlloc(heap_ctr, mem, size);
        TrackAlloc(regs[0], size);
        if (flags & 0x08u /* HEAP_ZERO_MEMORY */) {
            /* Zero page-by-page to handle non-contiguous host backing */
            for (uint32_t off = 0; off < size; ) {
                uint32_t page_rem = 0x1000 - ((regs[0] + off) & 0xFFF);
                uint32_t chunk = std::min(page_rem, size - off);
                uint8_t* host = mem.Translate(regs[0] + off);
                if (host) memset(host, 0, chunk);
                off += chunk;
            }
        }
        LOG(API, "[API] HeapAlloc(heap=0x%08X, flags=0x%X, size=%u) -> 0x%08X\n",
            hHeap, flags, size, regs[0]);
        return true;
    };
    Thunk("HeapAlloc", 46, heapAllocImpl);
    Thunk("HeapAllocTrace", 20, heapAllocImpl);
    Thunk("HeapCreate", 44, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        constexpr uint32_t HEAP_STRUCT_BASE = 0x00BF1000;
        constexpr uint32_t HEAP_STRUCT_SIZE = 0x100;
        static std::atomic<uint32_t> next_offset{0};
        uint32_t offset = next_offset.fetch_add(HEAP_STRUCT_SIZE);
        uint32_t addr = HEAP_STRUCT_BASE + offset;
        mem.Alloc(addr, HEAP_STRUCT_SIZE);
        mem.Write32(addr, 0x48454150); /* "HEAP" signature */
        LOG(API, "[API] HeapCreate(0x%X, 0x%X, 0x%X) -> 0x%08X\n",
            regs[0], regs[1], regs[2], addr);
        regs[0] = addr;
        return true;
    });
    Thunk("HeapFree", 49, [](uint32_t* regs, EmulatedMemory&) -> bool {
        FreeAlloc(regs[2]); /* regs[2] = lpMem (after hHeap, dwFlags) */
        regs[0] = 1; return true;
    });
    Thunk("HeapDestroy", 45, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] HeapDestroy(0x%08X) -> 1 (stub)\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("HeapReAlloc", 47, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[2], new_size = regs[3];
        static std::atomic<uint32_t> next_hrealloc{0x01000000};
        uint32_t addr = BumpAlloc(next_hrealloc, mem, new_size);
        uint8_t* old_host = mem.Translate(old_ptr);
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) {
            uint32_t old_size = GetAllocSize(old_ptr);
            uint32_t copy_size = old_size ? std::min(old_size, new_size) : new_size;
            memcpy(new_host, old_host, copy_size);
        }
        TrackAlloc(addr, new_size);
        regs[0] = addr;
        return true;
    });
    Thunk("HeapSize", 48, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t size = GetAllocSize(regs[2]); /* regs[2] = lpMem */
        if (!size) size = 0x1000; /* fallback for untracked */
        regs[0] = size;
        return true;
    });
    Thunk("HeapValidate", 51, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    /* CRT allocators (malloc/calloc/realloc/new/free/delete/_msize)
       and memory validation — registered in memory_crt.cpp */
    RegisterCrtMemoryHandlers();
}
