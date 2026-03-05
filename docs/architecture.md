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

## Component Details

### 1. ARM CPU Emulator (`cpu/`)

An interpretive emulator for the ARMv5TE instruction set:

- **arm_cpu.h/cpp** — Main CPU loop (`Run`/`Step`), condition evaluation, barrel shifter, flag updates. Supports all 15 ARM condition codes, CPSR flags (N/Z/C/V), and ARM/Thumb interworking via BX and bit-0 of PC.
- **arm_insn.cpp** — All 32-bit ARM instruction handlers (data processing, multiply, multiply-long, single/halfword data transfer, block data transfer LDM/STM, branch, branch-exchange, swap, SWI, MRS/MSR, CLZ)
- **thumb_insn.cpp** — All 16-bit Thumb-1 instruction handlers
- **mem.h** — `EmulatedMemory` class providing a 32-bit address space with page-granularity allocation. Identity-maps ARM addresses to host virtual addresses where possible via `VirtualAlloc` at the exact address. Includes `AutoAlloc` for on-demand page allocation on faults.

The CPU runs in a tight loop. When PC hits a thunk address (0xFE000000+) or a WinCE trap address (0xF000xxxx), it calls the thunk dispatcher instead of interpreting an instruction.

### 2. PE Loader (`loader/`)

Loads WinCE ARM PE executables into emulated memory:

- Parses PE headers for ARM (0x01C0) and Thumb (0x01C2) machine types
- Allocates sections at their preferred virtual addresses
- Applies base relocations when loaded at a non-preferred base
- Resolves imports — for coredll, creates thunk stubs; for other DLLs, loads them as ARM code
- Exports resolution for ARM DLLs (used by GetProcAddress and inter-DLL imports)

### 3. Thunk Layer (`thunks/`)

Translates WinCE coredll API calls to native Win32 calls:

- **win32_thunks.h** — `Win32Thunks` class definition, thunked DLL registry, address range constants
- **win32_thunks.cpp** — Core infrastructure: thunk allocation, handle wrapping (64-bit ↔ 32-bit), ordinal resolution, WinCE KData/TLS page setup, "Menu" window class registration
- **dispatch.cpp** — `HandleThunk`/`ExecuteThunk` dispatch logic for IAT thunks and WinCE trap calls
- **callbacks.cpp** — Callback bridging: `EmuWndProc`, `EmuDlgProc`, `MenuBarWndProc`, `CaptionOkSubclassProc`, message marshaling (WM_CREATE, WM_NOTIFY, WM_DRAWITEM, WM_SETTEXT, etc.)
- **dll_loader.cpp** — ARM DLL loading, recursive import resolution, DllMain calling
- **resource_helpers.cpp** — PE resource directory walking, native module loading for resource access
- **registry_impl.cpp** — File-backed registry storage (`registry.txt`)
- **registry_import.cpp** — REGEDIT4 format import (`registry_to_import.reg`)
- **coredll/*.cpp** — One file per functional group (26 files, ~7000 lines total)

Only coredll is thunked. All other WinCE DLLs (commctrl, aygshell, ole32, etc.) run as real ARM code.

## Startup Flow

```
 1. Log::Init() + parse CLI args
 2. EmulatedMemory mem — construct 32-bit address space
 3. PELoader::Load(exe_path, mem) — load ARM PE into emulated memory
 4. Win32Thunks thunks(mem) — register all handlers, set up KData page, allocate thunk region
 5. thunks.InitVFS(device_override) — read cerf.ini, set device paths + screen resolution
 6. thunks.InstallThunks(pe_info) — patch IAT with thunk addresses / ARM DLL exports
 7. mem.AllocStack() — 1MB stack at 0x00F00000-0x01000000
 8. ArmCpu cpu — construct CPU, set initial registers:
      SP=0x01000000-16, PC=entry_point, R0=hInstance, R2=cmdline, R3=SW_SHOWNORMAL
 9. Install thunk_handler (CPU → thunks bridge) and callback_executor (thunks → CPU bridge)
10. thunks.CallDllEntryPoints() — call DllMain for loaded ARM DLLs
11. cpu.Run() — main emulation loop
```

## CLI Arguments

| Flag | Effect |
|------|--------|
| `--trace` | Enable instruction-level tracing |
| `--log=CATEGORIES` | Enable specific log categories (comma-separated) |
| `--no-log=CATEGORIES` | Disable specific categories |
| `--log-file=PATH` | Tee log output to file |
| `--device=NAME` | Override device profile (overrides cerf.ini) |
| `--flush-outputs` | Flush after every log write |
| `--quiet` | Disable all log output |

Log categories: `API`, `PE`, `EMU`, `TRACE`, `CPU`, `REG`, `DBG`, `VFS`, `ALL`, `NONE`

## Memory Map

All allocators live below `0x02000000` (WinCE slot boundary — ARM code applies `AND addr, #0x01FFFFFF`). `0x00400000` is unavailable on x64 Windows.

```
0x00010000 - 0x000FFFFF   Main EXE (typical WinCE image base)
0x00200000 - 0x007FFFFF   VirtualAlloc pool (6MB, pre-reserved)
0x00800000 - 0x009FFFFF   LocalAlloc pool (2MB)
0x00A00000 - 0x00BFFFFF   LocalReAlloc pool (2MB)
0x00C00000 - 0x00EFFFFF   HeapAlloc pool (3MB)
0x00F00000 - 0x01000000   Stack (1MB, grows down, initial SP at top-16)
0x01000000 - 0x010FFFFF   HeapReAlloc pool (1MB)
0x01100000 - 0x01FFFFFF   malloc/calloc/realloc/new pool (15MB)
0x04000000+                DIB section pixel data (grows up)
0x10000000 - 0x102FFFFF   Loaded ARM DLLs (commctrl, aygshell, ole32, etc.)
0x3F000000 - 0x3F00FFFF   Marshaling scratch buffers (64KB)
0x60000000                 Command line buffer (4KB)
0xCAFEC000                 Callback sentinel page (BX LR instruction)
0xF0000000 - 0xF0010000   WinCE trap call range
0xFE000000 - 0xFEFFFFFF   Thunk stubs (allocated sequentially, 4 bytes each)
0xFFFFC000 - 0xFFFFC800   WinCE KData page (TLS array, thread/process IDs)
```

## Callback Bridging

Native Win32 uses callbacks (WndProc, DlgProc, TimerProc). When Windows calls a callback, CERF's wrapper (`EmuWndProc`/`EmuDlgProc`):

1. Saves full CPU state (all 16 registers + CPSR)
2. Sets R0-R3 to callback arguments (extra args pushed to stack at SP-0x100)
3. Sets LR to sentinel address (0xCAFEC000)
4. Sets PC to the ARM callback function
5. Runs CPU until it hits the sentinel
6. Reads R0 as return value, restores CPU state

### Message Marshaling

Messages with native pointers that can't safely truncate to 32-bit are either:
- **Bypassed** to `DefWindowProcW`: `WM_GETMINMAXINFO`, `WM_NCCALCSIZE`, `WM_WINDOWPOSCHANGING/CHANGED`, `WM_NCPAINT`, UAH theme messages (0x90-0x95)
- **Marshaled** into scratch memory at 0x3F000000: `WM_CREATE`/`WM_NCCREATE` (CREATESTRUCT), `WM_DRAWITEM`/`WM_MEASUREITEM` (with writeback), `WM_SETTEXT`/`WM_GETTEXT`, `WM_NOTIFY`, `WM_STYLECHANGING/CHANGED`

### WS_EX_CAPTIONOKBTN

WinCE's OK button (`WS_EX_CAPTIONOKBTN`, style 0x80000000) is emulated via window subclassing. The subclass proc disables DWM non-client rendering, paints an "OK" button in the title bar, and converts clicks on it to `WM_COMMAND(IDOK)`.

### Menu Bar (WinCE "Menu" Class)

A custom `MenuBarWndProc` implements the WinCE menu bar system. It reads `MENUCONTROLINFO` from `lpCreateParams`, loads the HMENU from native module resources, draws menu text items in `WM_PAINT`, and dispatches `TrackPopupMenuEx` on clicks.

## Handle Wrapping

Native Win32 handles are 64-bit on x64 but ARM code stores 32-bit values. Two strategies:

1. **Sign extension** (most common): `(HWND)(intptr_t)(int32_t)regs[0]` — works when handles have bit 31 set
2. **Handle map** (`handle_map`): For handles where sign extension doesn't round-trip, a `fake_handle → real_handle` map is used. Fake handles start at `0x00100000`.

## Configuration (`cerf.ini`)

Located next to `cerf.exe`. Parsed during `InitVFS`.

```ini
device=wince5
screen_width=800
screen_height=600
```

| Key | Default | Description |
|-----|---------|-------------|
| `device` | *(required)* | Device profile name — selects `devices/<name>/` |
| `screen_width` | 800 | Emulated screen width reported to ARM apps |
| `screen_height` | 600 | Emulated screen height reported to ARM apps |

The screen resolution affects: `GetSystemMetrics(SM_CXSCREEN/SM_CYSCREEN)`, `GetDeviceCaps(HORZRES/VERTRES)`, `SystemParametersInfoW(SPI_GETWORKAREA)`, `SystemParametersInfoW(SPI_GETSIPINFO)`, `GetMonitorInfo`, and top-level window sizing.

## Virtual Filesystem (VFS)

The VFS translates WinCE paths to host filesystem paths with a two-layer design:

```
WinCE Path                    Host Path
──────────────────────────    ──────────────────────────────────────
\Windows\foo                  <cerf_dir>/devices/<device>/fs/Windows/foo
\My Documents\file.txt        <cerf_dir>/devices/<device>/fs/My Documents/file.txt
\Program Files\app            <cerf_dir>/devices/<device>/fs/Program Files/app
\anything                     <cerf_dir>/devices/<device>/fs/anything

\c\foo\bar                    C:\foo\bar    ← real host drive
\d\                           D:\           ← real host drive
C:\foo\bar                    C:\foo\bar    ← drive letter syntax, same result
```

**Key rules:**
- **Single-letter root directories** (`\c\`, `\d\`, etc.) are drive letter pass-throughs to real host drives. `\c\foo` maps to `C:\foo` on the host.
- **Multi-letter root directories** (`\Windows\`, `\My Documents\`, etc.) resolve under the device's virtual filesystem at `devices/<device>/fs/`.
- **Drive letter syntax** (`C:\foo`) is equivalent to `\c\foo` — both pass through to the real host drive.
- **Reverse mapping**: Host drive paths (`C:\foo`) become `\c\foo` in WinCE space. Paths under the device fs root become `\relative`.

`GetTempPathW` returns `\Temp\` and auto-creates the host directory.

## Registry System

File-backed registry at `<device_dir>/registry.txt`. Loaded lazily on first registry call, saved on `RegCloseKey`.

**Format:**
```
[HKLM\Software\App]
"ValueName"=dword:000000FF
"StringVal"=sz:some string value
"BinaryVal"=hex:DE,AD,BE,EF
```

On first load, if `registry.txt` doesn't exist, imports from `<device_dir>/registry_to_import.reg` (REGEDIT4 format). Pre-populates COM CLSIDs for ceshell.dll file dialog support.

The WinCE system font is read from `HKLM\System\GDI\SYSFNT` (default: Tahoma, -12pt) and used to remap "System" font requests.

## Directory Structure

```
cerf/
  main.cpp              — Entry point, CLI parsing, CPU setup
  log.h                 — Logging macros (LOG, LOG_ERR) with category bitmask
  cpu/
    arm_cpu.h/cpp       — ARM CPU emulator core
    arm_insn.cpp        — 32-bit ARM instruction handlers
    thumb_insn.cpp      — 16-bit Thumb instruction handlers
    mem.h               — EmulatedMemory (32-bit address space)
  loader/
    pe_loader.h/cpp     — PE parser/loader for ARM executables
  thunks/
    win32_thunks.h      — Win32Thunks class, constants, thunked DLL registry
    win32_thunks.cpp    — Thunk infrastructure, handle wrapping, KData setup
    dispatch.cpp        — HandleThunk/ExecuteThunk dispatch
    callbacks.cpp       — EmuWndProc, EmuDlgProc, message marshaling
    dll_loader.cpp      — ARM DLL loading + recursive import resolution
    resource_helpers.cpp — PE resource directory walking
    registry_impl.cpp   — File-backed registry storage
    registry_import.cpp — REGEDIT4 format import
    coredll/            — 26 thunk files (~7000 lines), one per functional group
bundled/
  cerf.ini              — Default configuration
  devices/              — Device profiles (copied to build output)
devices/
  wince5/
    fs/Windows/         — WinCE system files (.2bp bitmaps, etc.)
    registry_to_import.reg — Initial registry data
references/
  windows_ce_5_armv4_build/ — Reference WinCE binaries + map files
  Optional Programs/    — Test WinCE executables
```
