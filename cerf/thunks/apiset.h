#pragma once
/* WinCE Kernel API Set System.

   On real WinCE, processes register API sets via CreateAPISet/RegisterAPISet.
   When any process calls a trap in the 0xF000xxxx range, the kernel:
   1. Decodes: api_set = index / 256, method = index % 256
   2. Finds which process registered that api_set ID
   3. Looks up vtable[method] in the registered function table
   4. Calls that function in the registering process's thread context
   5. Returns the result to the caller

   CERF implements this faithfully. The registering process's callback_executor
   is captured at RegisterAPISet time. When a trap fires for that set, we call
   vtable[method] using the registered executor — running ARM code in the
   correct process context. */

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <mutex>

class EmulatedMemory;
struct ProcessSlot;

/* API set IDs (from WinCE kfuncs.h) */
constexpr uint32_t WINCE_SH_WIN32    = 0;
constexpr uint32_t WINCE_SH_GDI      = 16;
constexpr uint32_t WINCE_SH_WMGR     = 17;
constexpr uint32_t WINCE_SH_FILESYS   = 20;
constexpr uint32_t WINCE_SH_SHELL    = 21;
constexpr uint32_t WINCE_SH_DEVMGR   = 22;

/* Trap address computation constants (from psyscall.h, ARM target) */
constexpr uint32_t WINCE_TRAP_FIRST_METHOD = 0xF0010000;
constexpr uint32_t WINCE_TRAP_SCALE        = 4;
constexpr uint32_t WINCE_TRAP_HANDLE_SHIFT = 8;

/* Registered API set */
struct ApiSetEntry {
    std::string name;               /* 4-char name: "SHEL", "WNET", etc. */
    uint32_t set_id;                /* SH_SHELL=21, etc. */
    uint32_t vtable_addr;           /* ARM address of PFNVOID array */
    uint32_t sigtable_addr;         /* ARM address of DWORD signature array */
    uint16_t num_methods;           /* Number of entries in vtable */

    /* The callback executor captured from the registering thread.
       Calls ARM code in the registering process's context. */
    std::function<uint32_t(uint32_t, uint32_t*, int)> executor;

    /* ProcessSlot of the registering process — used to switch context
       during cross-process API set dispatch (matches real WinCE kernel
       behavior of switching to the target process's address space). */
    ProcessSlot* process_slot = nullptr;
};

class ApiSetManager {
public:
    /* CreateAPISet: register a function table. Returns an opaque handle.
       Called by ARM code (explorer.exe calls this to register shell APIs). */
    uint32_t Create(const char name[4], uint16_t num_methods,
                    uint32_t vtable_addr, uint32_t sigtable_addr);

    /* RegisterAPISet: associate a created set with a system API set ID.
       Captures the current thread's callback_executor for future dispatch. */
    bool Register(uint32_t handle, uint32_t set_id,
                  std::function<uint32_t(uint32_t, uint32_t*, int)> executor);

    /* CloseHandle: unregister an API set. */
    void Close(uint32_t handle);

    /* Dispatch a trap call. Returns true if handled.
       Looks up the API set for the given set_id, finds vtable[method],
       and calls it using the registered executor. */
    bool Dispatch(uint32_t set_id, uint32_t method,
                  uint32_t* regs, EmulatedMemory& mem);

    /* Check if a set ID has a registered handler. */
    bool IsRegistered(uint32_t set_id) const;

private:
    std::unordered_map<uint32_t, ApiSetEntry> sets_by_handle_;
    std::unordered_map<uint32_t, uint32_t> sets_by_id_; /* set_id → handle */
    uint32_t next_handle_ = 0xAE000001; /* opaque handles in a unique range */
    mutable std::mutex mutex_;
};
