#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

/* Writable section range in a loaded DLL (for copy-on-write tracking) */
struct DllWritableSection {
    uint32_t start; /* absolute address in emulated memory */
    uint32_t size;
};

/* Per-process virtual address space overlay.

   WinCE slot 0 (0x00000000-0x01FFFFFF): private per process — each process gets
   its own copy of the EXE's code/data/heap in this range.

   DLL region (0x02000000+): code is shared, DATA pages are copy-on-write per
   process. When a child process writes to a DLL .data/.bss page, a private copy
   is created in the dll_overlay map. Reads check the overlay first; if no private
   copy exists, the shared (global) page is returned.

   IMPORTANT: Only pages explicitly committed via Commit() or copied via
   CopyOnWrite() are intercepted. Other addresses fall through to global memory. */
struct ProcessSlot {
    static const uint32_t SLOT_SIZE = 0x02000000; /* 32 MB */
    static const uint32_t IDENTITY_BASE = 0x00010000; /* WinCE EXE base */
    static const uint32_t PAGE_SIZE = 0x1000;
    static const uint32_t NUM_PAGES = SLOT_SIZE / PAGE_SIZE; /* 8192 pages */
    uint8_t* buffer = nullptr;    /* Host allocation backing the slot */
    uint32_t committed = 0;       /* Bytes actually committed (may be < SLOT_SIZE) */
    bool identity_mapped = false; /* True if ARM addresses == native addresses */
    uint32_t image_base = 0;     /* Start of loaded PE image */
    uint32_t image_end = 0;      /* End of loaded PE image (base + size_of_image) */
    uint8_t page_bitmap[NUM_PAGES / 8] = {}; /* 1 bit per page: committed or not */

    ProcessSlot() {
        /* Try identity-mapped allocation: reserve native addresses 0x00010000-0x01FFFFFF
           so ARM pointers passed to native controls (SysListView32 etc.) work as-is. */
        void* p = VirtualAlloc((void*)(uintptr_t)IDENTITY_BASE,
                               SLOT_SIZE - IDENTITY_BASE,
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p == (void*)(uintptr_t)IDENTITY_BASE) {
            buffer = (uint8_t*)p;
            identity_mapped = true;
        } else {
            if (p) VirtualFree(p, 0, MEM_RELEASE);
            buffer = (uint8_t*)VirtualAlloc(NULL, SLOT_SIZE,
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        }
        memset(page_bitmap, 0, sizeof(page_bitmap));
    }
    ~ProcessSlot() {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    }

    void MarkPages(uint32_t offset, uint32_t size) {
        uint32_t first = offset / PAGE_SIZE;
        uint32_t last = (offset + size - 1) / PAGE_SIZE;
        for (uint32_t p = first; p <= last && p < NUM_PAGES; p++)
            page_bitmap[p / 8] |= (1u << (p & 7));
    }

    bool IsPageCommitted(uint32_t addr) const {
        uint32_t p = addr / PAGE_SIZE;
        if (p >= NUM_PAGES) return false;
        return (page_bitmap[p / 8] & (1u << (p & 7))) != 0;
    }

    /* Commit pages within the slot (relative to slot base 0) */
    bool Commit(uint32_t offset, uint32_t size) {
        if (identity_mapped) {
            /* Identity: only addresses >= IDENTITY_BASE are backed */
            if (offset < IDENTITY_BASE) {
                if (offset + size <= IDENTITY_BASE) return true;
                size -= (IDENTITY_BASE - offset);
                offset = IDENTITY_BASE;
            }
            if (offset + size > SLOT_SIZE) return false;
            MarkPages(offset, size);
            return true;
        }
        if (!buffer || offset + size > SLOT_SIZE) return false;
        uint32_t page_off = offset & ~0xFFFu;
        uint32_t page_end = (offset + size + 0xFFF) & ~0xFFFu;
        void* p = VirtualAlloc(buffer + page_off, page_end - page_off,
                               MEM_COMMIT, PAGE_READWRITE);
        if (p) MarkPages(page_off, page_end - page_off);
        return p != nullptr;
    }

    /* Translate an ARM address within slot 0 range to host pointer.
       Only returns non-null for pages that were explicitly committed. */
    uint8_t* Translate(uint32_t addr) const {
        if (addr >= SLOT_SIZE) return nullptr;
        if (!IsPageCommitted(addr)) return nullptr;
        if (identity_mapped) {
            if (addr < IDENTITY_BASE) return nullptr;
            return (uint8_t*)(uintptr_t)addr;
        }
        if (!buffer) return nullptr;
        return buffer + addr;
    }

    /* --- DLL data copy-on-write (addresses >= 0x02000000) --- */

    /* Register a DLL's writable sections for copy-on-write tracking. */
    void RegisterWritableSections(const std::vector<DllWritableSection>& sections) {
        for (auto& s : sections)
            dll_writable_sections.push_back(s);
    }

    /* Check if an address falls within a DLL writable section. */
    bool IsDllWritableAddr(uint32_t addr) const {
        for (auto& s : dll_writable_sections)
            if (addr >= s.start && addr < s.start + s.size) return true;
        return false;
    }

    /* Get the private copy of a DLL data page (returns nullptr if not yet copied). */
    uint8_t* TranslateDllOverlay(uint32_t addr) const {
        uint32_t page = addr & ~(PAGE_SIZE - 1);
        auto it = dll_overlay.find(page);
        if (it == dll_overlay.end()) return nullptr;
        return it->second + (addr & (PAGE_SIZE - 1));
    }

    /* Copy-on-write: create a private copy of a DLL data page from global memory.
       `global_page_ptr` is the host pointer to the shared page content.
       Returns the host pointer to the new private copy. */
    uint8_t* CopyOnWrite(uint32_t addr, const uint8_t* global_page_ptr) {
        uint32_t page = addr & ~(PAGE_SIZE - 1);
        auto it = dll_overlay.find(page);
        if (it != dll_overlay.end())
            return it->second + (addr & (PAGE_SIZE - 1)); /* already copied */

        /* Allocate a new private page */
        uint8_t* priv = (uint8_t*)VirtualAlloc(NULL, PAGE_SIZE,
                                                 MEM_COMMIT, PAGE_READWRITE);
        if (!priv) return nullptr;

        /* Copy the shared content */
        memcpy(priv, global_page_ptr, PAGE_SIZE);
        dll_overlay[page] = priv;
        return priv + (addr & (PAGE_SIZE - 1));
    }

    /* Free all private DLL data pages (called on process exit). */
    void FreeDllOverlay() {
        for (auto& pair : dll_overlay)
            VirtualFree(pair.second, 0, MEM_RELEASE);
        dll_overlay.clear();
    }

    /* Registered writable sections across all DLLs */
    std::vector<DllWritableSection> dll_writable_sections;

    /* Per-process allocator state.
       Child processes get their own heap/malloc counters so allocations
       don't overlap with the parent's address space. */
    std::atomic<uint32_t> proc_heap_counter{0x00C00000};
    std::atomic<uint32_t> proc_malloc_counter{0x01100000};
    bool has_own_allocators = false;

private:
    /* Private copies of DLL data pages: page_addr → host buffer */
    std::unordered_map<uint32_t, uint8_t*> dll_overlay;
};
