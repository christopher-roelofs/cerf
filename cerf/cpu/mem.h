#pragma once
#include <windows.h>
#include <cstdint>
#include <map>
#include <vector>
#include <cstring>
#include <cstdio>
#include <mutex>
#include "process_slot.h"

/* Emulated memory manager for ARM address space.
   Uses VirtualAlloc on the host to back emulated memory regions. */

struct MemRegion {
    uint32_t base;
    uint32_t size;
    uint8_t* host_ptr;   /* Host-side allocation */
    DWORD    protect;
    bool     is_stack;
    bool     is_external = false; /* True for externally-owned buffers (don't free) */
};

class EmulatedMemory {
public:
    static const uint32_t PAGE_SIZE = 0x1000;
    static const uint32_t STACK_SIZE = 1024 * 1024; /* 1 MB stack */
    static const uint32_t STACK_BASE = 0x01000000;  /* Stack grows down from here (above 64KB boundary) */

    /* WinCE slot-0 DLL aliasing constants.
       In real WinCE, DLLs loaded at global addresses (0x04000000-0x42000000) are
       also accessible via slot 0 at (addr & SLOT_MASK).  ATL thunk code and other
       WinCE internals use this masking for function pointers.  We replicate it by
       redirecting slot-0 reads to the real DLL memory as a Translate() fallback. */
    static constexpr uint32_t WINCE_DLL_REGION_START = 0x04000000;
    static constexpr uint32_t WINCE_DLL_REGION_END   = 0x42000000;
    static constexpr uint32_t WINCE_SLOT_MASK        = 0x01FFFFFF; /* 25 bits = 32MB */

    /* Per-thread KData page redirect. When set, reads/writes to 0xFFFFC000-0xFFFFCFFF
       go to this buffer instead of shared memory. Each ARM thread sets this to its
       own ThreadContext::kdata[] before entering ARM execution. */
    static thread_local uint8_t* kdata_override;

    /* Per-thread process slot overlay. When set, addresses in [0, 0x02000000)
       resolve through this overlay instead of the global regions. This implements
       WinCE's per-process virtual address space (slot 0). */
    static thread_local ProcessSlot* process_slot;

    /* DLL slot-0 alias: maps (dll_base & SLOT_MASK) back to dll_base in Translate(). */
    struct DllAlias {
        uint32_t slot0_base;  /* dll_base & WINCE_SLOT_MASK */
        uint32_t dll_base;    /* actual load address */
        uint32_t size;        /* size_of_image */
    };
    std::vector<DllAlias> dll_aliases;

    /* Global registry of DLL writable sections for copy-on-write.
       Populated by LoadArmDll when DLLs are loaded. Used by ProcessSlot to
       determine which pages need private copies per-process. */
    std::vector<DllWritableSection> dll_writable_sections;

    /* Register a DLL's writable sections (called from LoadArmDll). */
    void RegisterDllWritableSections(uint32_t image_base,
                                     const std::vector<IMAGE_SECTION_HEADER>& sections) {
        constexpr DWORD WRITE_FLAG = IMAGE_SCN_MEM_WRITE;
        for (auto& sec : sections) {
            if (sec.Characteristics & WRITE_FLAG) {
                DllWritableSection ws;
                ws.start = image_base + sec.VirtualAddress;
                ws.size = sec.Misc.VirtualSize;
                if (ws.size == 0) ws.size = sec.SizeOfRawData;
                dll_writable_sections.push_back(ws);
            }
        }
    }

    /* Check if an address is in any DLL's writable section (global list).
       Used by TranslateForWrite to trigger copy-on-write for child processes. */
    bool IsDllWritableAddr(uint32_t addr) const {
        for (auto& s : dll_writable_sections)
            if (addr >= s.start && addr < s.start + s.size) return true;
        return false;
    }

    /* Register a DLL for slot-0 aliasing. Call after loading a DLL at base >= 0x04000000. */
    void AddDllAlias(uint32_t dll_base, uint32_t size_of_image) {
        if (dll_base < WINCE_DLL_REGION_START || dll_base >= WINCE_DLL_REGION_END) return;
        DllAlias alias;
        alias.slot0_base = dll_base & WINCE_SLOT_MASK;
        alias.dll_base   = dll_base;
        alias.size        = size_of_image;
        dll_aliases.push_back(alias);
    }

    std::vector<MemRegion> regions;
    std::mutex alloc_mutex;  /* Protects regions vector during Alloc/Reserve */

    ~EmulatedMemory() {
        for (auto& r : regions) {
            if (r.host_ptr && !r.is_external)
                VirtualFree(r.host_ptr, 0, MEM_RELEASE);
        }
    }

    /* Allocate a region in the emulated address space.
       Identity-maps ARM addresses to host addresses so ARM pointers are valid
       native pointers — needed when ARM code passes struct pointers to native
       Win32 controls (e.g. tab control messages via SendMessageW). */
    /* Pre-reserve a large address range for identity-mapped allocations.
       Subsequent Alloc() calls within this range will MEM_COMMIT pages
       without needing 64KB-aligned MEM_RESERVE (which fails for non-aligned pages). */
    bool Reserve(uint32_t base, uint32_t size) {
        std::lock_guard<std::mutex> lock(alloc_mutex);
        size = AlignUp(size, PAGE_SIZE);
        LPVOID rv = VirtualAlloc((LPVOID)(uintptr_t)base, size, MEM_RESERVE, PAGE_READWRITE);
        if (!rv) {
            fprintf(stderr, "[MEM] Reserve 0x%08X+0x%X failed (err=%lu)\n", base, size, GetLastError());
            return false;
        }
        return true;
    }

    uint8_t* Alloc(uint32_t base, uint32_t size, DWORD protect = PAGE_READWRITE, bool is_stack = false) {
        std::lock_guard<std::mutex> lock(alloc_mutex);
        size = AlignUp(size, PAGE_SIZE);
        /* If a process slot overlay is active and the address falls in slot 0,
           commit pages in the overlay instead of global memory. */
        if (process_slot && base < ProcessSlot::SLOT_SIZE) {
            /* Copy-on-write: commit pages individually and snapshot parent's
               global data so child process sees existing shared-page content
               (heap/COM data on pages shared with parent's allocators). */
            uint32_t pg_start = base & ~(PAGE_SIZE - 1);
            uint32_t pg_end = AlignUp(base + size, PAGE_SIZE);
            for (uint32_t pg = pg_start; pg < pg_end; pg += PAGE_SIZE) {
                if (process_slot->IsPageCommitted(pg)) continue;
                if (!process_slot->Commit(pg, PAGE_SIZE)) {
                    fprintf(stderr, "[MEM] ProcessSlot commit failed at 0x%08X\n", pg);
                    continue;
                }
                /* Copy existing global memory content into the slot page */
                uint8_t* dst = process_slot->Translate(pg);
                if (!dst) continue;
                for (auto& r : regions) {
                    if (pg >= r.base && pg < r.base + r.size) {
                        uint8_t* src = r.host_ptr + (pg - r.base);
                        if (src != dst) memcpy(dst, src, PAGE_SIZE);
                        break;
                    }
                }
            }
            return process_slot->Translate(base);
        }
        /* Try to allocate at the exact ARM address for identity mapping */
        uint8_t* ptr = nullptr;
        if (base >= 0x10000) { /* Addresses below 64KB can't be allocated on Windows */
            /* First try MEM_COMMIT only (works if address is within a pre-reserved range) */
            ptr = (uint8_t*)VirtualAlloc((LPVOID)(uintptr_t)base, size,
                                         MEM_COMMIT, PAGE_READWRITE);
            if (!ptr) {
                /* Not within a reservation — try full MEM_COMMIT | MEM_RESERVE
                   (only succeeds at 64KB-aligned addresses) */
                ptr = (uint8_t*)VirtualAlloc((LPVOID)(uintptr_t)base, size,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
        }
        if (!ptr) {
            /* Fall back to arbitrary address if identity mapping fails */
            ptr = (uint8_t*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (ptr)
                fprintf(stderr, "[MEM] Region 0x%08X+0x%X: fallback to host %p (NOT identity-mapped)\n", base, size, ptr);
        }
        if (!ptr) {
            fprintf(stderr, "[MEM] Failed to allocate 0x%X bytes for region 0x%08X\n", size, base);
            return nullptr;
        }
        /* Windows zeroes newly committed pages — no memset needed.
           Skipping memset also avoids zeroing already-committed pages
           when sub-page allocators commit shared pages. */
        regions.push_back({ base, size, ptr, protect, is_stack });
        return ptr;
    }

    /* Find the host pointer for an emulated address */
    uint8_t* Translate(uint32_t addr) const {
        /* Per-thread KData page: each thread has its own TLS slots and thread ID.
           Single branch, almost always not-taken (well-predicted). */
        if (kdata_override && (addr >> 12) == 0xFFFFC)
            return kdata_override + (addr & 0xFFF);
        /* Per-process slot overlay: committed pages in [0, 0x02000000) go to the
           thread's private process slot. Uncommitted pages fall through to global
           regions so shared DLL heap pointers (e.g. ole32 CDllCache) resolve correctly. */
        if (process_slot && addr < ProcessSlot::SLOT_SIZE) {
            uint8_t* sp = process_slot->Translate(addr);
            if (sp) return sp;
        }
        /* DLL copy-on-write: if a private copy exists for this DLL data page,
           return it instead of the shared global page. Read path only — writes
           go through Write8/16/32 which trigger CopyOnWrite(). */
        if (process_slot && addr >= ProcessSlot::SLOT_SIZE) {
            uint8_t* dp = process_slot->TranslateDllOverlay(addr);
            if (dp) return dp;
        }
        for (auto& r : regions) {
            if (addr >= r.base && addr < r.base + r.size) {
                return r.host_ptr + (addr - r.base);
            }
        }
        /* WinCE slot-0 DLL aliasing: DLLs loaded at global addresses (0x04000000+)
           are also accessible via slot 0 at (dll_base & 0x1FFFFFF). ARM code uses
           these aliases for instruction fetch and data access. Safe because
           allocator address ranges are above the DLL alias range, preventing
           heap/DLL data overlap. */
        if (addr <= WINCE_SLOT_MASK && !dll_aliases.empty()) {
            for (auto& alias : dll_aliases) {
                if (addr >= alias.slot0_base && addr < alias.slot0_base + alias.size) {
                    uint32_t real_addr = alias.dll_base + (addr - alias.slot0_base);
                    for (auto& r : regions) {
                        if (real_addr >= r.base && real_addr < r.base + r.size)
                            return r.host_ptr + (real_addr - r.base);
                    }
                }
            }
        }
        return nullptr;
    }

    bool IsValid(uint32_t addr) const {
        return Translate(addr) != nullptr;
    }

    uint8_t Read8(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) return p[addr & (PAGE_SIZE - 1)];
            LogFault("Read8", addr); return 0;
        }
        return *p;
    }

    uint16_t Read16(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) return *(uint16_t*)(p + (addr & (PAGE_SIZE - 1)));
            LogFault("Read16", addr); return 0;
        }
        return *(uint16_t*)p;
    }

    uint32_t Read32(uint32_t addr) const {
        uint8_t* p = Translate(addr);
        if (!p) {
            p = const_cast<EmulatedMemory*>(this)->AutoAlloc(addr);
            if (p) { p += (addr & (PAGE_SIZE - 1)); return *(volatile uint32_t*)p; }
            LogFault("Read32", addr); return 0;
        }
        return *(volatile uint32_t*)p;
    }

    /* Write-path methods (TranslateForWrite, Write8/16/32, WriteBytes,
       AddExternalRegion, RemoveExternalRegion) — split to mem_rw.h */
#include "mem_rw.h"


    /* Auto-allocate on fault: if an access hits unmapped memory, allocate a page.
       Reject addresses that can't be identity-mapped on Windows (below 64KB or
       near 4GB boundary) — fallback allocations would crash if passed to native code. */
    uint8_t* AutoAlloc(uint32_t addr);

private:
    mutable int fault_count = 0;

    void LogFault(const char* op, uint32_t addr) const;

    static uint32_t AlignUp(uint32_t val, uint32_t align);
};
