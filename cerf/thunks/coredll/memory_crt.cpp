/* CRT memory allocators: malloc, calloc, realloc, new, free, delete, _msize,
   IsBadReadPtr, IsBadWritePtr — split from memory.cpp */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>

/* Allocation tracking — same globals as memory.cpp (shared via extern) */
extern void TrackAlloc(uint32_t addr, uint32_t size);
extern uint32_t GetAllocSize(uint32_t addr);
extern void FreeAlloc(uint32_t addr);
extern uint32_t BumpAlloc(std::atomic<uint32_t>& counter, EmulatedMemory& mem, uint32_t size);
extern std::atomic<uint32_t>& GetMallocCounter(std::atomic<uint32_t>& global_counter);

void Win32Thunks::RegisterCrtMemoryHandlers() {
    static std::atomic<uint32_t> next_malloc{0x01100000};
    Thunk("malloc", 1041, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0];
        auto& malloc_ctr = GetMallocCounter(next_malloc);
        regs[0] = BumpAlloc(malloc_ctr, mem, size);
        TrackAlloc(regs[0], size);
        if (size <= 0x20) LOG(API, "[API] malloc(%u) -> 0x%08X\n", size, regs[0]);
        return true;
    });
    Thunk("calloc", 1346, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t size = regs[0] * regs[1];
        auto& calloc_ctr = GetMallocCounter(next_malloc);
        regs[0] = BumpAlloc(calloc_ctr, mem, size);
        TrackAlloc(regs[0], size);
        /* calloc: zero-initialize using write path to avoid DLL alias corruption */
        for (uint32_t off = 0; off < size; ) {
            uint32_t page_rem = 0x1000 - ((regs[0] + off) & 0xFFF);
            uint32_t chunk = std::min(page_rem, size - off);
            uint8_t* host = mem.Translate(regs[0] + off);
            if (host) memset(host, 0, chunk);
            off += chunk;
        }
        return true;
    });
    Thunk("new", 1095, thunk_handlers["malloc"]);
    Thunk("realloc", 1054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t old_ptr = regs[0], size = regs[1];
        auto& realloc_ctr = GetMallocCounter(next_malloc);
        uint32_t addr = BumpAlloc(realloc_ctr, mem, size);
        uint8_t* old_host = old_ptr ? mem.Translate(old_ptr) : nullptr;
        uint8_t* new_host = mem.Translate(addr);
        if (old_host && new_host) {
            uint32_t old_size = GetAllocSize(old_ptr);
            uint32_t copy_size = old_size ? std::min(old_size, size) : size;
            memcpy(new_host, old_host, copy_size);
        }
        TrackAlloc(addr, size);
        regs[0] = addr;
        return true;
    });
    Thunk("free", 1018, [](uint32_t* regs, EmulatedMemory&) -> bool {
        FreeAlloc(regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("delete", 1094, thunk_handlers["free"]);
    /* operator new[] (??_U@YAPAXI@Z) and operator delete[] (??_V@YAXPAX@Z) */
    Thunk("new[]", 1456, thunk_handlers["malloc"]);
    Thunk("delete[]", 1457, thunk_handlers["free"]);
    Thunk("_msize", [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t size = GetAllocSize(regs[0]);
        if (!size) size = 0x1000; /* fallback for untracked */
        regs[0] = size;
        return true;
    });
    /* Memory validation — check EmulatedMemory regions.  Native IsBadReadPtr
       rejects WinCE kernel-mapped regions (0x20000000+) that don't exist
       natively, but always returning 0 crashes on garbage pointers.  Check
       the base address against our region table for correct behavior. */
    Thunk("IsBadReadPtr", 522, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = mem.IsValid(regs[0]) ? 0 : 1;
        return true;
    });
    Thunk("IsBadWritePtr", 523, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = mem.IsValid(regs[0]) ? 0 : 1;
        return true;
    });
}
