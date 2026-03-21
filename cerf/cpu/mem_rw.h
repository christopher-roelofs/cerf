/* mem_rw.h — EmulatedMemory write-path methods.
   Included inside the EmulatedMemory class definition in mem.h.
   Split out to keep mem.h under the 300-line limit. */

    /* Write-path translation: same as Translate() but triggers copy-on-write
       for DLL data pages when a ProcessSlot is active. */
    uint8_t* TranslateForWrite(uint32_t addr) {
        if (kdata_override && (addr >> 12) == 0xFFFFC)
            return kdata_override + (addr & 0xFFF);
        if (process_slot && addr < ProcessSlot::SLOT_SIZE) {
            uint8_t* sp = process_slot->Translate(addr);
            if (sp) return sp;
            /* Copy-on-write for slot-0 heap: auto-commit the page with a snapshot
               of the parent's data. On real WinCE, each process has MMU-isolated
               slot-0 pages. Without this, child writes to parent's heap objects
               (e.g., zeroing vtable during operator delete in DLL_PROCESS_DETACH)
               would corrupt the parent's shared heap. */
            uint32_t page = addr & ~(PAGE_SIZE - 1);
            if (page >= 0x10000) { /* skip null page */
                uint8_t* global = nullptr;
                for (auto& r : regions) {
                    if (page >= r.base && page < r.base + r.size) {
                        global = r.host_ptr + (page - r.base);
                        break;
                    }
                }
                if (global && process_slot->Commit(page, PAGE_SIZE)) {
                    uint8_t* dst = process_slot->Translate(page);
                    if (dst) {
                        memcpy(dst, global, PAGE_SIZE);
                        fprintf(stderr, "[MEM] Slot-0 heap CoW: page 0x%08X for addr 0x%08X\n", page, addr);
                        return dst + (addr & (PAGE_SIZE - 1));
                    }
                }
            }
        }
        /* DLL copy-on-write: if writing to a DLL writable section, create a
           private page copy so the child process doesn't corrupt shared state.
           Check the GLOBAL writable section list (not the ProcessSlot's snapshot)
           because DLLs may be loaded on other threads during the child's lifetime. */
        if (process_slot && addr >= ProcessSlot::SLOT_SIZE
            && IsDllWritableAddr(addr)) {
            uint8_t* dp = process_slot->TranslateDllOverlay(addr);
            if (dp) return dp;
            uint8_t* global = nullptr;
            uint32_t page_addr = addr & ~(PAGE_SIZE - 1);
            for (auto& r : regions) {
                if (page_addr >= r.base && page_addr < r.base + r.size) {
                    global = r.host_ptr + (page_addr - r.base);
                    break;
                }
            }
            if (global) return process_slot->CopyOnWrite(addr, global);
        }
        /* Normal path: find the global region */
        for (auto& r : regions) {
            if (addr >= r.base && addr < r.base + r.size)
                return r.host_ptr + (addr - r.base);
        }
        /* DLL slot-0 alias fallback — same as Translate(). Safe because allocator
           address ranges are configured above the DLL alias range, so heap writes
           never overlap with DLL code/data pages. */
        {
            uint32_t alias_n = dll_alias_count.load(std::memory_order_acquire);
            if (addr <= WINCE_SLOT_MASK && alias_n > 0) {
                for (uint32_t ai = 0; ai < alias_n; ai++) {
                    auto& alias = dll_alias_array[ai];
                    if (addr >= alias.slot0_base && addr < alias.slot0_base + alias.size) {
                        uint32_t real_addr = alias.dll_base + (addr - alias.slot0_base);
                        for (auto& r : regions) {
                            if (real_addr >= r.base && real_addr < r.base + r.size)
                                return r.host_ptr + (real_addr - r.base);
                        }
                    }
                }
            }
        }
        return nullptr;
    }

    void Write8(uint32_t addr, uint8_t val) {
        uint8_t* p = TranslateForWrite(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { p[addr & (PAGE_SIZE - 1)] = val; return; }
            LogFault("Write8", addr); return;
        }
        *p = val;
    }

    void Write16(uint32_t addr, uint16_t val) {
        uint8_t* p = TranslateForWrite(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { *(uint16_t*)(p + (addr & (PAGE_SIZE - 1))) = val; return; }
            LogFault("Write16", addr); return;
        }
        *(uint16_t*)p = val;
    }

    void Write32(uint32_t addr, uint32_t val) {
        uint8_t* p = TranslateForWrite(addr);
        if (!p) {
            p = AutoAlloc(addr);
            if (p) { *(volatile uint32_t*)(p + (addr & (PAGE_SIZE - 1))) = val; return; }
            LogFault("Write32", addr); return;
        }
        *(volatile uint32_t*)p = val;
    }

    void WriteBytes(uint32_t addr, const void* src, uint32_t len) {
        uint8_t* p = Translate(addr);
        if (!p) { fprintf(stderr, "[MEM] WriteBytes fault at 0x%08X len=0x%X\n", addr, len); return; }
        memcpy(p, src, len);
    }

    /* Register an externally-owned buffer as an emulated region.
       The caller retains ownership; the buffer must outlive the mapping.
       Used for CreateDIBSection pvBits: maps native bitmap data into ARM space. */
    void AddExternalRegion(uint32_t base, uint32_t size, uint8_t* host_ptr) {
        MemRegion r = {};
        r.base = base; r.size = size; r.host_ptr = host_ptr;
        r.protect = PAGE_READWRITE; r.is_external = true;
        regions.push_back(r);
    }

    /* Remove a previously-added external region by its base address. */
    void RemoveExternalRegion(uint32_t base) {
        for (auto it = regions.begin(); it != regions.end(); ++it) {
            if (it->base == base) { regions.erase(it); return; }
        }
    }

    /* Allocate the stack region */
    uint32_t AllocStack() {
        uint32_t stack_bottom = STACK_BASE - STACK_SIZE;
        Alloc(stack_bottom, STACK_SIZE, PAGE_READWRITE, true);
        return STACK_BASE - 16; /* Return initial SP, slightly below top */
    }
