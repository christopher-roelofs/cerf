# CERF Architecture

## Overview

CERF runs Windows CE ARM executables on modern x64 desktop Windows. It has three major components:

```
 ┌──────────────────────────────────────────────────┐
 │              WinCE ARM Executable                 │
 │         (e.g. solitare.exe, chearts.exe)         │
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

- **arm_cpu.cpp** — Main CPU loop (`Run`/`Step`), condition evaluation, barrel shifter, flag updates
- **arm_insn.cpp** — All 32-bit ARM instruction handlers (data processing, multiply, load/store, branch, coprocessor)
- **thumb_insn.cpp** — All 16-bit Thumb instruction handlers
- **mem.h** — `EmulatedMemory` class providing a 32-bit address space with page-granularity allocation

The CPU runs in a tight loop. When PC hits a thunk address (0xFE000000+) or a WinCE trap address (0xF000xxxx), it calls the thunk dispatcher instead of interpreting an instruction.

### 2. PE Loader (`loader/`)

Loads WinCE ARM PE executables into emulated memory:

- Parses PE headers, allocates sections at their preferred virtual addresses
- Applies base relocations if needed
- Resolves imports — for coredll, creates thunk stubs; for other DLLs, loads them as ARM code
- Exports resolution for ARM DLLs (used by GetProcAddress and inter-DLL imports)

### 3. Thunk Layer (`thunks/`)

Translates WinCE coredll API calls to native Win32 calls:

- **win32_thunks.cpp** — Core infrastructure: thunk allocation, dispatch, ordinal resolution, callback bridging (EmuWndProc/EmuDlgProc), ARM DLL loader
- **coredll/*.cpp** — One file per functional group (memory, GDI, windowing, etc.)

Only coredll is thunked. All other WinCE DLLs run as real ARM code.

## Execution Flow

```
1. main.cpp loads the EXE via PELoader::Load()
2. InstallThunks() patches the IAT:
   - coredll imports → thunk addresses (0xFE000000+)
   - other DLL imports → resolved ARM export addresses
3. CPU starts at entry point (WinMain)
4. ARM code runs until it hits a thunk address
5. Thunk dispatcher maps address → handler, executes native Win32 call
6. Result goes into R0, CPU resumes ARM execution
7. For callbacks (WndProc etc.): native side calls callback_executor
   which saves CPU state, runs ARM code, restores state
```

## Memory Map

```
0x00010000 - 0x000FFFFF   Main EXE (typical WinCE image base)
0x000F0000 - 0x000FFFF0   Stack (grows down)
0x10000000 - 0x102FFFFF   Loaded ARM DLLs (aygshell, ole32, commctrl, etc.)
0x50000000+                Emulated heap allocations (VirtualAlloc, HeapAlloc)
0x60000000+                CoTaskMemAlloc, command line buffers
0xCAFEC000                 Callback sentinel address
0xF0000000 - 0xF0010000   WinCE trap call range
0xFE000000 - 0xFEFFFFFF   Thunk stubs (allocated sequentially)
```

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

This allows WinCE apps to access both the sandboxed device filesystem and real host drives. The device filesystem is configured via `cerf.ini` (`device=wince5`).
