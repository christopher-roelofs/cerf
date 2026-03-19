#pragma once
/* Per-process handle table for WinCE process isolation.

   On real WinCE, each process has its own handle namespace. A file handle
   opened by process A is not valid in process B. Named sync objects (events,
   mutexes) ARE shared across processes when opened by name.

   In CERF, native Win32 handles ARE shared (same process), so file handles
   work across "processes" automatically. But for proper isolation, we track
   which handles belong to which process and close them on process exit.

   Future: full handle virtualization (process-local handle IDs). */

#include <windows.h>
#include <cstdint>
#include <set>
#include <mutex>

class ProcessHandleTable {
public:
    /* Track a handle as owned by this process */
    void Track(HANDLE h) {
        if (h && h != INVALID_HANDLE_VALUE) {
            std::lock_guard<std::mutex> lock(mutex_);
            handles_.insert(h);
        }
    }

    /* Stop tracking a handle (it was explicitly closed) */
    void Untrack(HANDLE h) {
        std::lock_guard<std::mutex> lock(mutex_);
        handles_.erase(h);
    }

    /* Close all tracked handles (process exit cleanup) */
    void CloseAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (HANDLE h : handles_) {
            if (h && h != INVALID_HANDLE_VALUE)
                ::CloseHandle(h);
        }
        handles_.clear();
    }

    size_t Count() const { return handles_.size(); }

private:
    std::set<HANDLE> handles_;
    std::mutex mutex_;
};

/* Get the current thread's process handle table (nullptr for main process).
   Defined in shell_exec_launch.cpp. */
ProcessHandleTable* GetProcessHandleTable();
