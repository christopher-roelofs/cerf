# CERF Architecture

## Overview

CERF runs Windows CE ARM executables on modern x64 desktop Windows. It has three major components:

```
 ┌──────────────────────────────────────────────────┐
 │              WinCE ARM Executable                 │
 │         (e.g. solitare.exe, calc.exe)            │
 └───────────┬──────────────────────┬───────────────┘
             │ ARM instructions     │ API calls (IAT)
             ▼                      ▼
 ┌───────────────────┐  ┌──────────────────────────┐
 │   ARM CPU Core    │  │    Thunk Dispatcher       │
 │  (arm_cpu + mem)  │  │  (0xFE000000+ addresses)  │
 │                   │  │                            │
 │  ARMv5TE interp.  │  │  coredll → native Win32   │
 │  ARM + Thumb mode │  │  Other DLLs → ARM code    │
 └───────────────────┘  └──────────────────────────┘
```

Only coredll is thunked. All other WinCE DLLs (commctrl, aygshell, ole32, etc.) run as real ARM code.

## Startup Flow

CERF boots as an orchestrator — it does not run ARM code directly on the main thread. All ARM execution happens in child threads via `LaunchArmChildProcess`.

```
 1. ParseCerfArgs() — CLI parsing
 2. EmulatedMemory + Win32Thunks — 32-bit address space + handler registration
 3. LoadIniConfig() — global cerf.ini → device cerf.ini → CLI overrides
 4. BootScreen::Create() — threaded splash with marquee progress bar
 5. InitVFS() — virtual filesystem paths
 6. InitWceSysFont() + InitWceTheme() — system font and color theming
 7. Main thread context setup (callback executor, marshal buffer)
 8. LoadRegistry() — file-backed registry from device directory
 9. StartBootServices() — device.exe in isolated ProcessSlot
10. ProcessInitHive() — HKLM\init Launch entries with dependency ordering
11. Launch user-specified EXE (if any)
```

See [boot.md](boot.md) for details.

## Memory Map

Slot 0 (0x00000000–0x01FFFFFF) is per-process via ProcessSlot overlay. DLLs above 0x02000000 are shared (copy-on-write for writable sections).

```
0x00010000 - 0x000FFFFF   Main EXE (typical WinCE image base)
0x00B00000 - 0x00BFFFFF   VirtualAlloc pool (1MB)
0x00C00000 - 0x00EFFFFF   Main heap — SlabAllocator (3MB, malloc/HeapAlloc/LocalAlloc)
0x00F00000 - 0x01000000   Stack (1MB, grows down)
0x01000000 - 0x01BFFFFF   HeapCreate sub-heaps (12MB)
0x01C00000 - 0x01FFFFFF   VirtualAlloc overflow (4MB)
0x04000000+                Loaded ARM DLLs (commctrl, ole32, etc.)
0x20000000 - 0x20FFFFFF   WinCE shared memory area (OLE32)
0x30000000 - 0x33FFFFFF   Kernel heap (device.exe drivers, 64MB)
0x3E000000 - 0x3E0FFFFF   Fake WinCE Process/Thread structs
0x3F000000 - 0x3F00FFFF   Marshaling scratch buffers (64KB)
0x60000000+                Command line buffers (per-process, 4KB each)
0xCAFEC000                 Callback sentinel page (BX LR instruction)
0xF0000000 - 0xF0010000   WinCE trap call range
0xFE000000 - 0xFEFFFFFF   Thunk stubs (4 bytes each)
0xFFFFC000 - 0xFFFFCFFF   KData page (per-thread: TLS, thread/process IDs)
```

## Configuration

Two-level config: `bundled/cerf.ini` selects the device profile, `devices/<device>/cerf.ini` has all settings. CLI flags override both.

| Key | Default | Description |
|-----|---------|-------------|
| `device` | `wince5` | Device profile (`wince5`, `wince6`, `wince7`) |
| `screen_width` / `screen_height` | 800 / 480 | Emulated screen dimensions |
| `enable_theming` | false | Apply WinCE system colors from registry |
| `disable_uxtheme` | false | Strip UxTheme for classic look |
| `boot_services` | *(empty)* | Semicolon-separated DLLs for `HKLM\Drivers\BuiltIn` |
| `init_blacklist` | *(empty)* | Semicolon-separated EXEs to skip in `HKLM\init` |
| `os_major` / `os_minor` / `os_build` | 5 / 0 / 1 | WinCE version reported to ARM apps |

### CLI Options

| Flag | Effect |
|------|--------|
| `--device=NAME` | Device profile |
| `--screen-width=N` / `--screen-height=N` | Override screen dimensions |
| `--no-init` | Skip HKLM\init boot sequence |
| `--gdb-port=PORT` | GDB remote stub |
| `--trace` | Instruction-level tracing |
| `--log=CATEGORIES` | Enable log categories (`API`, `PE`, `EMU`, `TRACE`, `CPU`, `REG`, `DBG`, `VFS`, `THEME`) |
| `--flush-outputs` | Flush logs after every write |
| `--quiet` | Disable all log output |

## Virtual Filesystem & Registry

See [vfs.md](vfs.md) for complete path translation rules, device directory structure, file operation handling, and registry integration.

## Directory Structure

```
cerf/
  main.cpp              — Orchestrator: config → boot → init → launch
  boot_screen.h/cpp     — Threaded boot splash
  cpu/
    arm_cpu.h/cpp       — ARM CPU emulator (ARM + Thumb)
    mem.h / mem_rw.h    — EmulatedMemory with copy-on-write
    process_slot.h      — Per-process 32 MB address overlay
    slab_alloc.h        — Per-process heap allocator
  loader/
    pe_loader.h/cpp     — PE parser/loader for ARM executables
  debugger/
    gdb_stub.h/cpp      — GDB remote stub
  thunks/
    win32_thunks.h      — Win32Thunks class and all state
    dispatch.cpp        — Thunk + trap call dispatch
    callbacks.cpp       — EmuWndProc, EmuDlgProc, callback bridging
    dll_loader.cpp      — ARM DLL loading, DllMain sequencing
    boot_services.cpp   — device.exe emulation
    init_sequence.cpp   — HKLM\init boot processing
    theme.cpp           — WinCE theming engine
    coredll/            — ~40 thunk files, one per functional group
bundled/
  cerf.ini              — Global config (device= selector)
  devices/              — Device profiles (wince5, wince6, wince7)
e2e_tests/
  run_all.py            — Test runner (all devices)
  cerf_test_utils.py    — Log-driven test framework
```
