# Process Isolation

## Overview

CERF emulates WinCE's per-process virtual address space using `ProcessSlot` — a 32 MB overlay buffer that isolates slot 0 (0x00000000–0x01FFFFFF) per process. DLLs above 0x02000000 are shared with copy-on-write for writable sections.

Each child process runs on a real OS thread with its own ProcessSlot, ArmCpu, ThreadContext, and KData page.

## ProcessSlot (`process_slot.h`)

### Memory Layout

```
0x00000000 - 0x01FFFFFF   Slot 0 — per-process (EXE, heap, stack, DLL .data)
0x02000000+                Shared DLL code — global, copy-on-write for .data
```

### Key Fields

- `buffer` — 32 MB host allocation backing the slot
- `page_bitmap[8192]` — tracks which 4 KB pages are committed
- `dll_writable_sections` — registered DLL .data/.bss sections for CoW
- `dll_overlay` — `unordered_map<page_addr, host_buffer>` for private DLL data copies
- `fake_pid` — unique emulated PID (global atomic counter)
- `proc_slab` — per-process SlabAllocator for heap isolation
- `tls_low_used` / `tls_high_used` — per-process TLS slot bitmasks (64 slots, CAS-based)

## Copy-on-Write

### Slot-0 Pages

`TranslateForWrite()` in `mem_rw.h` auto-commits slot-0 pages on first write by snapshotting the parent's global page content.

### DLL Data Pages

At child startup (`shell_exec_launch.cpp`), all DLL writable sections are pre-copied into the ProcessSlot's `dll_overlay`. This snapshot is taken **after** `InstallThunks` patches IAT entries (so the child sees correct thunk addresses) but **before** `CallDllEntryPoints` runs DllMain.

The `dll_load_mutex` is held during the snapshot to prevent concurrent DLL loading (e.g., dcomssd's background thread) from invalidating the snapshot.

Runtime writes to DLL data pages trigger `CopyOnWrite()` via `TranslateForWrite()`, which allocates a private page copy and stores it in `dll_overlay`.

## Child Process Creation (`shell_exec_launch.cpp`)

1. Allocate `ProcessSlot` on the new thread's stack
2. Create per-process `SlabAllocator` (0x00C00000–0x00F00000, 3 MB)
3. `PELoader::LoadIntoSlot()` — load EXE into slot buffer
4. Populate fake WinCE PROCESS struct at `0x3E000000 + procnum * 0x100`:
   - `procnum`, `bTrustLevel`, `hProc` (fake_pid), `BasePtr`, `aky`, `lpszProcName`
   - `tlsLowUsed` (0x0F — slots 0–3 reserved), `tlsHighUsed` (0x00)
5. `InitThreadKData()` — set up per-thread KData page (lpvTls, thread ID, process ID, pCurPrc, pCurThd)
6. Snapshot DLL writable sections (under dll_load_mutex)
7. `InstallThunks()` + `CallDllEntryPoints()` for this child's imports
8. `DLL_PROCESS_ATTACH` for all pre-existing DLLs (with `RefreshDllOverlay()` for concurrent safety)
9. Set up ArmCpu, run WinMain

## Thread Creation (`process.cpp`)

Child threads inherit the parent's ProcessSlot (same overlay, same DLL data). Each thread gets:

- Its own ArmCpu, ThreadContext, and KData page
- Stack allocated at `0x01900000 + thread_idx * 0x100000`
- `DLL_THREAD_ATTACH` dispatch (filtered: skip `DisableThreadLibraryCalls` bases, skip device.exe DLLs for non-kernel threads)

## KData Page (per-thread)

```
0xFFFFC000 - 0xFFFFC01B   Pre-TLS DWORDs (7 words)
0xFFFFC01C - 0xFFFFC11B   TLS slot array (64 slots)
0xFFFFC800 + 0x000         lpvTls → 0xFFFFC01C
0xFFFFC800 + 0x004         ahSys[0] = thread_id
0xFFFFC800 + 0x008         ahSys[1] = thread_id
0xFFFFC800 + 0x00C         ahSys[2] = fake_pid
0xFFFFC800 + 0x090         pCurPrc → fake PROCESS struct
0xFFFFC800 + 0x094         pCurThd → fake Thread struct
```

Accessed via `EmulatedMemory::kdata_override` thread-local, which intercepts all reads/writes to the 0xFFFFC000 page.

## Process Exit

1. ARM entry point returns → `cpu.halted = true`
2. Message pump runs until `WM_QUIT` (GUI apps keep windows alive)
3. `DLL_PROCESS_DETACH` for all DLLs (reverse order)
4. `EraseProcessHandles()` — clean up per-process handle map entries
5. `FreeDllOverlay()` — release private DLL data pages
6. `ProcessSlot` destructor frees the 32 MB buffer

## Key Files

| File | Role |
|------|------|
| `cerf/cpu/process_slot.h` | ProcessSlot struct, CoW, TLS allocation |
| `cerf/cpu/mem.h` / `mem_rw.h` | Translate/TranslateForWrite with CoW hooks |
| `cerf/thunks/coredll/shell_exec_launch.cpp` | Child process launch |
| `cerf/thunks/coredll/process.cpp` | Thread creation with slot inheritance |
| `cerf/thunks/thread_context.cpp` | InitThreadKData, PopulateProcessStruct |
| `cerf/thunks/boot_services.cpp` | device.exe process (isolated ProcessSlot) |
