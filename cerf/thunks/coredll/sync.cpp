/* Sync thunks: critical sections, interlocked ops, events, mutexes, semaphores, TLS */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../handle_table.h"
#include "../../log.h"
#include <cstdio>
#include <atomic>

void Win32Thunks::RegisterSyncHandlers() {
    /* Critical sections — real critical sections now that we have real threads */
    Thunk("InitializeCriticalSection", 2, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        /* In a child process, skip re-initializing CS that already exists in the
           global map. On real WinCE, the child gets a fresh copy of DLL data (MMU),
           but our shared host-side CS objects must not be overwritten. */
        if (EmulatedMemory::process_slot) {
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            if (cs_map.count(addr)) return true; /* Already exists, don't replace */
        }
        CRITICAL_SECTION* cs = new CRITICAL_SECTION;
        InitializeCriticalSection(cs);
        std::lock_guard<std::mutex> lock(cs_map_mutex);
        cs_map[addr] = cs;
        return true;
    });
    Thunk("DeleteCriticalSection", 3, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        /* When running in a child process (ProcessSlot active), skip deleting from
           the global cs_map. On real WinCE, each process has its own copy of DLL
           data sections (hardware MMU), so a child's DeleteCriticalSection only
           affects its own copy. In our emulation, native CS objects are in a shared
           host-side map — deleting them would corrupt the parent process. */
        if (EmulatedMemory::process_slot) {
            LOG(API, "[API] DeleteCriticalSection(0x%08X) skipped (child process)\n", addr);
            return true;
        }
        std::lock_guard<std::mutex> lock(cs_map_mutex);
        auto it = cs_map.find(addr);
        if (it != cs_map.end()) {
            DeleteCriticalSection(it->second);
            delete it->second;
            cs_map.erase(it);
        }
        return true;
    });
    Thunk("EnterCriticalSection", 4, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        CRITICAL_SECTION* cs = nullptr;
        {
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            auto it = cs_map.find(addr);
            if (it != cs_map.end()) cs = it->second;
        }
        if (!cs) {
            /* Auto-create native CS for addresses not initialized via our thunk.
               ARM DLLs (e.g., ole32.dll) may initialize critical sections through
               internal code paths that bypass our InitializeCriticalSection thunk. */
            cs = new CRITICAL_SECTION;
            InitializeCriticalSection(cs);
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            cs_map[addr] = cs;
            LOG(API, "[API] EnterCriticalSection(0x%08X) auto-created\n", addr);
        }
        LOG(API, "[API] EnterCriticalSection(0x%08X) ...\n", addr);
        EnterCriticalSection(cs);
        LOG(API, "[API] EnterCriticalSection(0x%08X) acquired\n", addr);
        return true;
    });
    Thunk("LeaveCriticalSection", 5, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t addr = regs[0];
        CRITICAL_SECTION* cs = nullptr;
        {
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            auto it = cs_map.find(addr);
            if (it != cs_map.end()) cs = it->second;
        }
        if (!cs) {
            /* Leave for an unknown CS — create it first (matches Enter behavior).
               This can happen if the CS was initialized outside our thunk. */
            cs = new CRITICAL_SECTION;
            InitializeCriticalSection(cs);
            std::lock_guard<std::mutex> lock(cs_map_mutex);
            cs_map[addr] = cs;
        }
        LeaveCriticalSection(cs);
        LOG(API, "[API] LeaveCriticalSection(0x%08X)\n", addr);
        return true;
    });
    Thunk("InitLocale", 8, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 1; return true; });
    /* Interlocked operations — use real atomic ops for thread safety.
       Must go through mem.Translate() to resolve ProcessSlot overlays;
       raw ARM-address casts would hit the global page instead of the
       child process's private copy, corrupting COM refcounts etc. */
    Thunk("InterlockedIncrement", 10, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Use TranslateForWrite for all Interlocked ops — they modify memory.
           TranslateForWrite triggers copy-on-write for child process isolation. */
        volatile LONG* ptr = (volatile LONG*)mem.TranslateForWrite(regs[0]);
        if (!ptr) ptr = (volatile LONG*)(mem.AutoAlloc(regs[0]) + (regs[0] & (EmulatedMemory::PAGE_SIZE - 1)));
        regs[0] = ptr ? (uint32_t)InterlockedIncrement(ptr) : 0;
        return true;
    });
    ThunkOrdinal("InterlockedDecrement", 11);
    Thunk("InterlockedDecrement", [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        volatile LONG* ptr = (volatile LONG*)mem.TranslateForWrite(regs[0]);
        if (!ptr) ptr = (volatile LONG*)(mem.AutoAlloc(regs[0]) + (regs[0] & (EmulatedMemory::PAGE_SIZE - 1)));
        regs[0] = ptr ? (uint32_t)InterlockedDecrement(ptr) : 0;
        return true;
    });
    Thunk("InterlockedExchange", 12, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        volatile LONG* ptr = (volatile LONG*)mem.TranslateForWrite(regs[0]);
        if (!ptr) ptr = (volatile LONG*)(mem.AutoAlloc(regs[0]) + (regs[0] & (EmulatedMemory::PAGE_SIZE - 1)));
        regs[0] = ptr ? (uint32_t)InterlockedExchange(ptr, (LONG)regs[1]) : 0;
        return true;
    });
    Thunk("InterlockedCompareExchange", 1492, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        volatile LONG* ptr = (volatile LONG*)mem.TranslateForWrite(regs[0]);
        if (!ptr) ptr = (volatile LONG*)(mem.AutoAlloc(regs[0]) + (regs[0] & (EmulatedMemory::PAGE_SIZE - 1)));
        LONG original = ptr ? InterlockedCompareExchange(ptr, (LONG)regs[1], (LONG)regs[2]) : 0;
        regs[0] = (uint32_t)original;
        return true;
    });
    Thunk("CreateEventW", 495, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = CreateEventW(NULL, regs[1], regs[2], NULL);
        regs[0] = (uint32_t)(uintptr_t)h;
        LOG(API, "[API] CreateEventW(manual=%d, initial=%d) -> handle=%p (arm=0x%08X)\n",
            regs[1], regs[2], h, regs[0]);
        auto* ht = GetProcessHandleTable();
        if (ht) ht->Track(h);
        return true;
    });
    /* WaitForSingleObject — pump sent messages while waiting to prevent
       cross-thread deadlocks.  WinCE GWES delivers cross-thread messages
       at the kernel level; desktop Windows requires the target thread to
       call a message-retrieval function.  MsgWaitForMultipleObjects with
       QS_SENDMESSAGE + PeekMessage(PM_NOREMOVE) lets sent messages through
       without pulling posted messages out of order. */
    Thunk("WaitForSingleObject", 497, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HANDLE h = (HANDLE)(intptr_t)(int32_t)regs[0];
        DWORD timeout = regs[1];
        LOG(API, "[API] WaitForSingleObject(0x%08X, %u) ...\n", regs[0], timeout);
        DWORD start = GetTickCount();
        for (;;) {
            DWORD elapsed = GetTickCount() - start;
            DWORD remaining = (timeout == INFINITE) ? INFINITE
                : (elapsed >= timeout ? 0 : timeout - elapsed);
            DWORD r = MsgWaitForMultipleObjects(1, &h, FALSE,
                                                remaining, QS_SENDMESSAGE);
            if (r == WAIT_OBJECT_0 + 1) {
                MSG msg;
                PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);
                continue;
            }
            /* Memory fence: ensure all emulated memory writes from other threads
               are visible after waking from wait.  Critical for cross-thread data
               like CDwnStm EOF flags written by the UI thread. */
            std::atomic_thread_fence(std::memory_order_seq_cst);
            LOG(API, "[API] WaitForSingleObject(0x%08X) -> %u\n", regs[0], r);
            regs[0] = r;
            return true;
        }
    });
    Thunk("CloseHandle", 553, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Stream device driver handles — route to DeviceManager */
        if (device_mgr.IsDeviceHandle(regs[0])) {
            regs[0] = device_mgr.Close(regs[0]) ? 1 : 0;
            return true;
        }
        uint32_t fake = regs[0]; HANDLE h = UnwrapHandle(fake);
        auto* ht = GetProcessHandleTable();
        /* In a child process (ProcessSlot active), only close handles that the
           child owns. On real WinCE, each process has its own handle table —
           closing handle X in process B doesn't affect process A's handle X. */
        if (EmulatedMemory::process_slot && ht) {
            if (ht->IsTracked(h)) {
                ht->Untrack(h);
                regs[0] = CloseHandle(h); RemoveHandle(fake);
            } else {
                regs[0] = 1; /* belongs to parent — don't close */
            }
            return true;
        }
        /* Main process: close normally */
        if (ht) ht->Untrack(h);
        regs[0] = CloseHandle(h); RemoveHandle(fake); return true;
    });
    Thunk("CreateMutexW", 555, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HANDLE h = CreateMutexW(NULL, regs[1], NULL);
        regs[0] = (uint32_t)(uintptr_t)h;
        auto* ht = GetProcessHandleTable();
        if (ht) ht->Track(h);
        return true;
    });
    Thunk("ReleaseMutex", 556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseMutex((HANDLE)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("CreateSemaphoreW", 1238, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* CreateSemaphoreW(lpSA, lInitialCount, lMaximumCount, lpName) */
        HANDLE h = CreateSemaphoreW(NULL, (LONG)regs[1], (LONG)regs[2], NULL);
        LOG(API, "[API] CreateSemaphoreW(init=%d, max=%d) -> 0x%p\n",
            (int)regs[1], (int)regs[2], h);
        regs[0] = (uint32_t)(uintptr_t)h;
        auto* ht = GetProcessHandleTable();
        if (ht) ht->Track(h);
        return true;
    });
    Thunk("ReleaseSemaphore", 1239, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LONG prev = 0;
        BOOL ok = ReleaseSemaphore((HANDLE)(intptr_t)(int32_t)regs[0], (LONG)regs[1], &prev);
        LOG(API, "[API] ReleaseSemaphore(0x%08X, count=%d) -> %d (prev=%d)\n",
            regs[0], (int)regs[1], ok, prev);
        regs[0] = ok;
        return true;
    });
    /* TLS — emulated via the KData page at 0xFFFFC800.
       WinCE ARM code can access TLS directly through memory:
         lpvTls = *(DWORD*)0xFFFFC800   (pointer to TLS slot array)
         value  = lpvTls[slot_index]     (read slot)
       TLS slot array at 0xFFFFC01C, set up in Win32Thunks constructor.
       Slots 0-3 reserved by WinCE; TlsCall allocates from 4 onward.
       Next-free counter stored at 0xFFFFC880 (KData padding area). */
    Thunk("TlsGetValue", 15, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            regs[0] = mem.Read32(0xFFFFC01C + idx * 4);
        } else {
            regs[0] = 0;
        }
        SetLastError(ERROR_SUCCESS);
        LOG(API, "[API] TlsGetValue(%u) -> 0x%08X\n", idx, regs[0]);
        return true;
    });
    Thunk("TlsSetValue", 16, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t idx = regs[0];
        if (idx < 64) {
            mem.Write32(0xFFFFC01C + idx * 4, regs[1]);
            LOG(API, "[API] TlsSetValue(%u, 0x%08X) -> 1\n", idx, regs[1]);
            regs[0] = 1;
        } else {
            LOG(API, "[API] TlsSetValue(%u) -> 0 (out of range)\n", idx);
            regs[0] = 0;
        }
        return true;
    });
    /* TlsCall: allocates a TLS slot. Uses atomic counter shared across threads. */
    Thunk("TlsCall", 520, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        uint32_t slot = next_tls_slot.fetch_add(1);
        if (slot < 64) {
            LOG(API, "[API] TlsCall() -> slot %u\n", slot);
            regs[0] = slot;
        } else {
            LOG(API, "[API] TlsCall() -> 0 (out of slots)\n");
            regs[0] = 0;
        }
        return true;
    });

    Thunk("WaitForMultipleObjects", 498, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t nCount = regs[0];
        uint32_t lpHandles = regs[1];
        BOOL bWaitAll = regs[2];
        uint32_t dwMilliseconds = regs[3];
        if (nCount == 0 || nCount > 64 || !lpHandles) {
            LOG(API, "[API] WaitForMultipleObjects(n=%u) -> WAIT_FAILED (bad args)\n", nCount);
            regs[0] = WAIT_FAILED;
            return true;
        }
        HANDLE handles[64];
        for (uint32_t i = 0; i < nCount; i++) {
            uint32_t raw = mem.Read32(lpHandles + i * 4);
            handles[i] = (HANDLE)(intptr_t)(int32_t)raw;
            LOG(API, "[API]   WaitForMulti handle[%u]: raw=0x%08X -> native=%p\n",
                i, raw, handles[i]);
        }
        /* Pump sent messages while waiting to prevent cross-thread deadlocks */
        DWORD start = GetTickCount();
        DWORD result;
        for (;;) {
            DWORD elapsed = GetTickCount() - start;
            DWORD remaining = (dwMilliseconds == INFINITE) ? INFINITE
                : (elapsed >= dwMilliseconds ? 0 : dwMilliseconds - elapsed);
            result = MsgWaitForMultipleObjects(nCount, handles, FALSE,
                                               remaining, QS_SENDMESSAGE);
            if (result == WAIT_OBJECT_0 + nCount) {
                MSG msg;
                PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);
                continue;
            }
            if (bWaitAll && result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + nCount) {
                DWORD full = WaitForMultipleObjects(nCount, handles, TRUE, 0);
                if (full != WAIT_TIMEOUT) { result = full; break; }
                continue;
            }
            break;
        }
        if (result == WAIT_FAILED) {
            LOG(API, "[API] WaitForMultipleObjects(n=%u, waitAll=%d, ms=%u) -> WAIT_FAILED (err=%lu)\n",
                nCount, bWaitAll, dwMilliseconds, GetLastError());
        } else {
            LOG(API, "[API] WaitForMultipleObjects(n=%u, waitAll=%d, ms=%u) -> 0x%X\n",
                nCount, bWaitAll, dwMilliseconds, result);
        }
        regs[0] = result;
        return true;
    });
}
