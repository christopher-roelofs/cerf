# Multi-Process Support

## Architecture

CERF runs each WinCE process as a real OS thread with its own:

- **ProcessSlot** — 32 MB per-process virtual address overlay (slot 0)
- **ArmCpu** — independent register file, CPSR, instruction counter
- **ThreadContext** — per-thread KData page, callback executor, marshal buffer
- **SlabAllocator** — isolated heap (malloc/HeapAlloc/LocalAlloc)

DLL code (0x02000000+) is shared across all processes. DLL writable sections (.data/.bss) use copy-on-write — each process gets private copies on first write.

## How It Works

`ShellExecuteEx` and `CreateProcessW` call `LaunchArmChildProcess()` which spawns a native Windows thread. The child thread:

1. Creates a ProcessSlot with its own heap allocator
2. Loads the EXE into the slot via `PELoader::LoadIntoSlot()`
3. Snapshots all DLL writable sections (copy-on-write baseline)
4. Calls `DLL_PROCESS_ATTACH` for all loaded DLLs in the child's context
5. Runs WinMain on the child's ArmCpu
6. Pumps messages after WinMain returns (GUI apps)
7. Calls `DLL_PROCESS_DETACH` and cleans up on exit

## What's Shared

- Emulated memory regions (read-only DLL code, shared memory at 0x20000000)
- Registry (single in-memory store, protected by mutex)
- Window handles (HWNDs are system-wide, any process can SendMessage)
- Thunk handlers (single Win32Thunks instance)

## What's Isolated

- Slot 0 address space (EXE, heap, stack) — per-ProcessSlot overlay
- DLL .data sections — copy-on-write private copies
- TLS slots — per-process bitmask allocation
- KData page (thread ID, process ID, pCurPrc) — per-thread override
- Heap allocators — per-process SlabAllocator prevents address conflicts

## device.exe

Boot services (lpcd, dcomssd) run in a dedicated ProcessSlot matching real WinCE's device.exe isolation. This prevents driver DLL state from corrupting user process state.

See [process_isolation.md](process_isolation.md) for implementation details.
