# Boot Sequence

## Overview

CERF emulates the full WinCE boot sequence: device drivers, registry initialization, HKLM\init process launches, and shell startup. A threaded boot screen provides visual feedback during initialization.

## Boot Screen (`boot_screen.h/cpp`)

A dedicated thread creates a `WS_POPUP` window matching the device screen dimensions (default 800x480) at position (0,0). It shows:

- **Icon** — cerf.ico (256x256 variant from executable resources), centered
- **Marquee progress bar** — native comctl32 `PBS_MARQUEE`, 30ms animation
- **Status text** — white, centered, updated per step via `PostMessage`

The boot screen thread has its own message pump. Updates are thread-safe via `PostMessage(BS_UPDATE)`.

### Lifecycle

1. `BootScreen::Create(w, h)` — spawns thread, blocks until window is created
2. `BootScreen::Step(text)` — updates status text and triggers repaint
3. `BootScreen::OnShellReady()` — posts `WM_QUIT` to the boot screen thread (called when explorer signals)
4. `BootScreen::ScheduleDestroy(ms)` — fallback timer (10s) if no SignalStarted arrives
5. `BootScreen::Destroy()` — posts quit and joins the thread

## Boot Sequence (main.cpp)

```
 1. Parse CLI arguments (--device, --no-init, --gdb-port, etc.)
 2. Create EmulatedMemory + Win32Thunks
 3. LoadIniConfig() — global cerf.ini → device cerf.ini → CLI overrides
 4. BootScreen::Create() ← boot screen appears
 5. InitVFS() — virtual filesystem paths
 6. InitWceSysFont() — WinCE system font from HKLM\System\GDI\SYSFNT
 7. InitWceTheme() — inline hook GetSysColor/GetSysColorBrush, load colors
 8. Set up shared memory, main thread context, callback executor
 9. LoadRegistry() — file-backed registry from device directory
10. StartBootServices() ← device.exe in isolated ProcessSlot
11. ProcessInitHive() ← HKLM\init entries
12. ScheduleDestroy(10000) — fallback boot screen timeout
13. Launch user EXE (if any)
```

## device.exe (`boot_services.cpp`)

Emulates WinCE's device.exe — the built-in device manager that loads hardware/software drivers.

### How It Works

1. Read `HKLM\Drivers\BuiltIn\*` and `HKLM\Services\*` from the emulated registry
2. Filter by `boot_services=` whitelist in cerf.ini (e.g., `lpcd.dll;dcomssd.dll`)
3. Sort by `Order` value
4. Spawn a real OS thread with its own ProcessSlot (isolated from explorer)
5. For each service DLL: `LoadArmDll()` → find entry point → call via `callback_executor`
6. Signal `ready_event` when all services are initialized
7. Main thread waits up to 10s for the ready signal before continuing

### Why Isolated

device.exe runs in its own ProcessSlot with a separate SlabAllocator. This prevents driver DLL globals (dcomssd, RPCRT4) from corrupting user process state. DLL writable sections are copy-on-write, matching real WinCE behavior where device.exe is a separate process.

## HKLM\init (`init_sequence.cpp`)

Processes the WinCE boot sequence from `HKLM\init`:

1. Enumerate `LaunchXX` entries (XX = order number)
2. Sort by order
3. For each entry:
   - Check `init_blacklist=` in cerf.ini — skip if blacklisted (signal dummy event so dependents don't block)
   - Wait for `DependXX` entries (named events `CerfInitDone_<order>`)
   - Resolve WinCE path to host path (bare filenames search `\Windows\`)
   - `LaunchArmChildProcess()` — new thread with ProcessSlot
   - Brief delay (100ms) between launches

### SignalStarted

When an ARM process calls `SignalStarted(order)` (coredll ordinal 639), CERF:

1. Sets the named event `CerfInitDone_<order>` (unblocks dependent init entries)
2. If the caller is explorer.exe, calls `BootScreen::OnShellReady()` to dismiss the boot screen

## Configuration

Per-device cerf.ini controls the boot sequence:

```ini
boot_services=lpcd.dll;dcomssd.dll
init_blacklist=shell.exe;device.exe;gwes.exe
```

- **boot_services** — which driver DLLs to load from `HKLM\Drivers\BuiltIn`
- **init_blacklist** — which `HKLM\init` Launch entries to skip (services provided by thunks)

## Key Files

| File | Role |
|------|------|
| `cerf/boot_screen.h/cpp` | Threaded boot splash window |
| `cerf/main.cpp` | Orchestrator: config → boot → init → launch |
| `cerf/thunks/boot_services.cpp` | device.exe emulation |
| `cerf/thunks/init_sequence.cpp` | HKLM\init processing |
| `cerf/thunks/coredll/com.cpp` | SignalStarted thunk |
