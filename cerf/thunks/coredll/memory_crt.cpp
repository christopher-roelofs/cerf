/* CRT memory allocators: malloc, calloc, realloc, new, free, delete, _msize,
   IsBadReadPtr, IsBadWritePtr — backed by SlabAllocator.
   On real WinCE: malloc → LocalAlloc → HeapAlloc(hProcessHeap). */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../cpu/slab_alloc.h"
#include "../../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

/* Defined in memory.cpp */
extern SlabAllocator* GetSlab();

void Win32Thunks::RegisterCrtMemoryHandlers() {
    Thunk("malloc", 1041, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Alloc(regs[0]) : 0;
        return true;
    });
    Thunk("calloc", 1346, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t total = (uint64_t)regs[0] * regs[1];
        if (total > 0xFFFFFFFF) { regs[0] = 0; return true; }
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Alloc((uint32_t)total, true) : 0;
        return true;
    });
    Thunk("new", 1095, thunk_handlers["malloc"]);
    Thunk("realloc", 1054, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Realloc(regs[0], regs[1]) : 0;
        return true;
    });
    Thunk("free", 1018, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SlabAllocator* slab = GetSlab();
        if (slab) slab->Free(regs[0]);
        regs[0] = 0;
        return true;
    });
    Thunk("delete", 1094, thunk_handlers["free"]);
    Thunk("new[]", 1456, thunk_handlers["malloc"]);
    Thunk("delete[]", 1457, thunk_handlers["free"]);
    Thunk("_msize", 1049, [](uint32_t* regs, EmulatedMemory&) -> bool {
        SlabAllocator* slab = GetSlab();
        regs[0] = slab ? slab->Size(regs[0]) : (uint32_t)-1;
        return true;
    });
    Thunk("IsBadReadPtr", 522, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = mem.IsValid(regs[0]) ? 0 : 1;
        return true;
    });
    Thunk("IsBadWritePtr", 523, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = mem.IsValid(regs[0]) ? 0 : 1;
        return true;
    });
}
