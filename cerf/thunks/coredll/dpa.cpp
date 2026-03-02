#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Dynamic Pointer Array (DPA) thunks — coredll re-exports from commctrl.
   Used internally by ListView, TreeView, and other common controls.

   IMPORTANT: The ARM commctrl code reads DPA struct fields directly from
   memory (hdpa->cp, hdpa->pp[i]), so the DPA must live in emulated memory.

   WinCE DPA struct layout (20 bytes):
     +0  cp       (int32)  — count of pointers
     +4  pp       (uint32) — pointer to array of uint32 pointers
     +8  hheap    (uint32) — heap handle (unused, set to 0)
     +12 cpAlloc  (int32)  — allocated capacity
     +16 cpGrow   (int32)  — grow increment
*/
#include "../win32_thunks.h"
#include "../../log.h"

static constexpr uint32_t DPA_STRUCT_SIZE = 20;

/* Simple bump allocator for DPA structs and arrays in emulated memory */
static uint32_t dpa_heap_base = 0xDA000000;
static uint32_t dpa_heap_cur  = 0xDA000000;
static constexpr uint32_t DPA_HEAP_SIZE = 0x00200000; /* 2 MB */

static uint32_t DpaAlloc(EmulatedMemory& mem, uint32_t size) {
    /* Align to 4 bytes */
    size = (size + 3) & ~3u;
    if (dpa_heap_cur + size > dpa_heap_base + DPA_HEAP_SIZE) {
        LOG_ERR("[DPA] Out of DPA heap space!\n");
        return 0;
    }
    uint32_t addr = dpa_heap_cur;
    if (!mem.IsValid(addr)) {
        /* Allocate in 64KB pages */
        uint32_t page_base = addr & ~0xFFFFu;
        mem.Alloc(page_base, 0x10000);
    }
    /* Ensure the end is also allocated */
    uint32_t end_page = (addr + size) & ~0xFFFFu;
    if (!mem.IsValid(end_page) && end_page < dpa_heap_base + DPA_HEAP_SIZE) {
        mem.Alloc(end_page, 0x10000);
    }
    dpa_heap_cur = addr + size;
    return addr;
}

/* Read DPA fields from emulated memory */
static int DpaGetCp(EmulatedMemory& mem, uint32_t hdpa) {
    return (int)mem.Read32(hdpa + 0);
}
static uint32_t DpaGetPp(EmulatedMemory& mem, uint32_t hdpa) {
    return mem.Read32(hdpa + 4);
}
static int DpaGetCpAlloc(EmulatedMemory& mem, uint32_t hdpa) {
    return (int)mem.Read32(hdpa + 12);
}
static int DpaGetCpGrow(EmulatedMemory& mem, uint32_t hdpa) {
    return (int)mem.Read32(hdpa + 16);
}

/* Write DPA fields */
static void DpaSetCp(EmulatedMemory& mem, uint32_t hdpa, int cp) {
    mem.Write32(hdpa + 0, (uint32_t)cp);
}
static void DpaSetPp(EmulatedMemory& mem, uint32_t hdpa, uint32_t pp) {
    mem.Write32(hdpa + 4, pp);
}
static void DpaSetCpAlloc(EmulatedMemory& mem, uint32_t hdpa, int cpAlloc) {
    mem.Write32(hdpa + 12, (uint32_t)cpAlloc);
}

/* Read/write pointer at index in the pp array */
static uint32_t DpaGetItem(EmulatedMemory& mem, uint32_t hdpa, int index) {
    uint32_t pp = DpaGetPp(mem, hdpa);
    return mem.Read32(pp + (uint32_t)index * 4);
}
static void DpaSetItem(EmulatedMemory& mem, uint32_t hdpa, int index, uint32_t val) {
    uint32_t pp = DpaGetPp(mem, hdpa);
    mem.Write32(pp + (uint32_t)index * 4, val);
}

/* Grow the pointer array if needed */
static bool DpaGrow(EmulatedMemory& mem, uint32_t hdpa, int needed) {
    int cpAlloc = DpaGetCpAlloc(mem, hdpa);
    if (needed <= cpAlloc) return true;

    int cpGrow = DpaGetCpGrow(mem, hdpa);
    if (cpGrow < 4) cpGrow = 4;
    int newAlloc = ((needed + cpGrow - 1) / cpGrow) * cpGrow;

    uint32_t newPp = DpaAlloc(mem, (uint32_t)newAlloc * 4);
    if (!newPp) return false;

    /* Copy existing pointers */
    uint32_t oldPp = DpaGetPp(mem, hdpa);
    int cp = DpaGetCp(mem, hdpa);
    for (int i = 0; i < cp; i++) {
        mem.Write32(newPp + (uint32_t)i * 4, mem.Read32(oldPp + (uint32_t)i * 4));
    }
    /* Zero new slots */
    for (int i = cp; i < newAlloc; i++) {
        mem.Write32(newPp + (uint32_t)i * 4, 0);
    }

    DpaSetPp(mem, hdpa, newPp);
    DpaSetCpAlloc(mem, hdpa, newAlloc);
    return true;
}

void Win32Thunks::RegisterDpaHandlers() {
    Thunk("DPA_Create", 1837, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cpGrow = (int)regs[0];
        if (cpGrow < 1) cpGrow = 4;
        uint32_t hdpa = DpaAlloc(mem, DPA_STRUCT_SIZE);
        if (!hdpa) { regs[0] = 0; return true; }
        DpaSetCp(mem, hdpa, 0);
        DpaSetPp(mem, hdpa, 0);
        mem.Write32(hdpa + 8, 0); /* hheap */
        DpaSetCpAlloc(mem, hdpa, 0);
        mem.Write32(hdpa + 16, (uint32_t)cpGrow);
        regs[0] = hdpa;
        return true;
    });
    Thunk("DPA_CreateEx", 1838, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cpGrow = (int)regs[0];
        if (cpGrow < 1) cpGrow = 4;
        uint32_t hdpa = DpaAlloc(mem, DPA_STRUCT_SIZE);
        if (!hdpa) { regs[0] = 0; return true; }
        DpaSetCp(mem, hdpa, 0);
        DpaSetPp(mem, hdpa, 0);
        mem.Write32(hdpa + 8, 0);
        DpaSetCpAlloc(mem, hdpa, 0);
        mem.Write32(hdpa + 16, (uint32_t)cpGrow);
        regs[0] = hdpa;
        return true;
    });
    Thunk("DPA_Clone", 1839, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t src = regs[0], dst = regs[1];
        if (!src) { regs[0] = 0; return true; }
        int cp = DpaGetCp(mem, src);
        if (!dst) {
            int cpGrow = DpaGetCpGrow(mem, src);
            dst = DpaAlloc(mem, DPA_STRUCT_SIZE);
            if (!dst) { regs[0] = 0; return true; }
            DpaSetCp(mem, dst, 0);
            DpaSetPp(mem, dst, 0);
            mem.Write32(dst + 8, 0);
            DpaSetCpAlloc(mem, dst, 0);
            mem.Write32(dst + 16, (uint32_t)cpGrow);
        }
        if (!DpaGrow(mem, dst, cp)) { regs[0] = 0; return true; }
        uint32_t srcPp = DpaGetPp(mem, src);
        uint32_t dstPp = DpaGetPp(mem, dst);
        for (int i = 0; i < cp; i++)
            mem.Write32(dstPp + (uint32_t)i * 4, mem.Read32(srcPp + (uint32_t)i * 4));
        DpaSetCp(mem, dst, cp);
        regs[0] = dst;
        return true;
    });
    Thunk("DPA_DeleteAllPtrs", 1840, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        if (!hdpa) { regs[0] = 0; return true; }
        DpaSetCp(mem, hdpa, 0);
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_DeletePtr", 1841, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        int index = (int)regs[1];
        if (!hdpa) { regs[0] = 0; return true; }
        int cp = DpaGetCp(mem, hdpa);
        if (index < 0 || index >= cp) { regs[0] = 0; return true; }
        uint32_t deleted = DpaGetItem(mem, hdpa, index);
        /* Shift remaining elements down */
        for (int i = index; i < cp - 1; i++)
            DpaSetItem(mem, hdpa, i, DpaGetItem(mem, hdpa, i + 1));
        DpaSetCp(mem, hdpa, cp - 1);
        regs[0] = deleted;
        return true;
    });
    Thunk("DPA_Destroy", 1842, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* We don't free emulated memory (bump allocator), just clear the struct */
        uint32_t hdpa = regs[0];
        if (hdpa) {
            DpaSetCp(mem, hdpa, 0);
            DpaSetPp(mem, hdpa, 0);
        }
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_DestroyCallback", 1843, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        /* Note: we don't call the ARM callback for each item.
           This is used for cleanup, and the items are in ARM memory
           that will be freed by the ARM code or at exit. */
        if (hdpa) {
            DpaSetCp(mem, hdpa, 0);
            DpaSetPp(mem, hdpa, 0);
        }
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_EnumCallback", 1844, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        uint32_t arm_callback = regs[1];
        uint32_t arm_data = regs[2];
        if (!hdpa || !arm_callback || !callback_executor) {
            regs[0] = 0;
            return true;
        }
        int cp = DpaGetCp(mem, hdpa);
        for (int i = 0; i < cp; i++) {
            uint32_t ptr = DpaGetItem(mem, hdpa, i);
            uint32_t args[2] = { ptr, arm_data };
            uint32_t ret = callback_executor(arm_callback, args, 2);
            if (!ret) break;
        }
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_GetPtr", 1845, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        int index = (int)regs[1];
        if (!hdpa) { regs[0] = 0; return true; }
        int cp = DpaGetCp(mem, hdpa);
        if (index < 0 || index >= cp) { regs[0] = 0; return true; }
        regs[0] = DpaGetItem(mem, hdpa, index);
        return true;
    });
    Thunk("DPA_GetPtrIndex", 1846, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        uint32_t ptr = regs[1];
        if (!hdpa) { regs[0] = (uint32_t)-1; return true; }
        int cp = DpaGetCp(mem, hdpa);
        for (int i = 0; i < cp; i++) {
            if (DpaGetItem(mem, hdpa, i) == ptr) {
                regs[0] = (uint32_t)i;
                return true;
            }
        }
        regs[0] = (uint32_t)-1;
        return true;
    });
    Thunk("DPA_Grow", 1847, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        int newAlloc = (int)regs[1];
        if (!hdpa) { regs[0] = 0; return true; }
        regs[0] = DpaGrow(mem, hdpa, newAlloc) ? 1 : 0;
        return true;
    });
    Thunk("DPA_InsertPtr", 1848, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        int index = (int)regs[1];
        uint32_t ptr = regs[2];
        if (!hdpa) { regs[0] = (uint32_t)-1; return true; }
        int cp = DpaGetCp(mem, hdpa);
        /* DA_LAST = 0x7FFFFFFF means append */
        if (index < 0 || index > cp) index = cp;
        if (!DpaGrow(mem, hdpa, cp + 1)) { regs[0] = (uint32_t)-1; return true; }
        /* Shift elements up */
        for (int i = cp; i > index; i--)
            DpaSetItem(mem, hdpa, i, DpaGetItem(mem, hdpa, i - 1));
        DpaSetItem(mem, hdpa, index, ptr);
        DpaSetCp(mem, hdpa, cp + 1);
        regs[0] = (uint32_t)index;
        return true;
    });
    Thunk("DPA_Search", 1849, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        uint32_t pFind = regs[1];
        int iStart = (int)regs[2];
        uint32_t arm_cmp = regs[3];
        uint32_t lParam = ReadStackArg(regs, mem, 0);
        uint32_t options = ReadStackArg(regs, mem, 1);
        if (!hdpa || !arm_cmp || !callback_executor) {
            regs[0] = (uint32_t)-1;
            return true;
        }
        int cp = DpaGetCp(mem, hdpa);
        /* Linear search (DPAS_SORTED binary search not implemented) */
        for (int i = iStart; i < cp; i++) {
            uint32_t ptr = DpaGetItem(mem, hdpa, i);
            uint32_t args[3] = { ptr, pFind, lParam };
            int cmp = (int)callback_executor(arm_cmp, args, 3);
            if (cmp == 0) {
                regs[0] = (uint32_t)i;
                return true;
            }
        }
        regs[0] = (uint32_t)-1;
        return true;
    });
    Thunk("DPA_SetPtr", 1850, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        int index = (int)regs[1];
        uint32_t ptr = regs[2];
        if (!hdpa) { regs[0] = 0; return true; }
        int cp = DpaGetCp(mem, hdpa);
        if (index < 0) { regs[0] = 0; return true; }
        /* SetPtr can extend the array */
        if (index >= cp) {
            if (!DpaGrow(mem, hdpa, index + 1)) { regs[0] = 0; return true; }
            /* Zero-fill gap */
            for (int i = cp; i < index; i++)
                DpaSetItem(mem, hdpa, i, 0);
            DpaSetCp(mem, hdpa, index + 1);
        }
        DpaSetItem(mem, hdpa, index, ptr);
        regs[0] = 1;
        return true;
    });
    Thunk("DPA_Sort", 1851, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hdpa = regs[0];
        uint32_t arm_cmp = regs[1];
        uint32_t lParam = regs[2];
        if (!hdpa || !arm_cmp || !callback_executor) {
            regs[0] = 1;
            return true;
        }
        int cp = DpaGetCp(mem, hdpa);
        if (cp <= 1) { regs[0] = 1; return true; }
        /* Simple insertion sort via ARM callback comparator */
        for (int i = 1; i < cp; i++) {
            uint32_t key = DpaGetItem(mem, hdpa, i);
            int j = i - 1;
            while (j >= 0) {
                uint32_t other = DpaGetItem(mem, hdpa, j);
                uint32_t args[3] = { other, key, lParam };
                int cmp = (int)callback_executor(arm_cmp, args, 3);
                if (cmp <= 0) break;
                DpaSetItem(mem, hdpa, j + 1, other);
                j--;
            }
            DpaSetItem(mem, hdpa, j + 1, key);
        }
        regs[0] = 1;
        return true;
    });
}
