# CERF - Windows CE Runtime Foundation

## Project Overview

CERF is an ARM CPU emulator + Win32 API compatibility layer that runs Windows CE ARM binaries on modern x64 desktop Windows. It interprets ARMv5TE instructions (ARM + Thumb modes), loads WinCE PE executables, and thunks COREDLL.DLL API calls to native Win32 APIs. Non-core WinCE DLLs (commctrl, commdlg, ole32, etc.) are loaded and executed as real ARM code — only coredll is thunked.

## Architecture

```
cerf/
  main.cpp                        - Entry point, CLI parsing, emulation loop setup
  log.h / log.cpp                 - Categorized logging (THUNK, PE, EMU, TRACE, CPU, REG, DBG)
  cpu/
    mem.h                          - EmulatedMemory class (32-bit address space, page-based)
    arm_cpu.h                      - ArmCpu class declaration (registers, flags, methods)
    arm_cpu.cpp                    - CPU core: condition checks, barrel shifter, Run/Step loop
    arm_insn.cpp                   - ARM mode instruction handlers
    thumb_insn.cpp                 - Thumb mode instruction handlers
  loader/
    pe_loader.h/.cpp               - WinCE PE loader (sections, imports, relocations, exports)
  thunks/
    win32_thunks.h                 - Win32Thunks class, ThunkEntry, ThunkedDllInfo table
    win32_thunks.cpp               - Core thunk infrastructure, dispatch, callbacks, ARM DLL loader
    coredll/                       - COREDLL.DLL thunks (one file per functional group)
      memory.cpp                   - VirtualAlloc, HeapAlloc, malloc, LocalAlloc, etc.
      string.cpp                   - wcslen, wcscpy, wsprintfW, MultiByteToWideChar, etc.
      crt.cpp                      - C runtime: atoi, qsort, time, rand, etc.
      arm_runtime.cpp              - ARM compiler runtime helpers (__rt_sdiv, __rt_udiv, etc.)
      gdi_dc.cpp                   - Device contexts, SelectObject, DeleteObject
      gdi_draw.cpp                 - BitBlt, drawing primitives, DIB sections
      gdi_text.cpp                 - Text output, font creation
      gdi_region.cpp               - Regions, clipping
      window.cpp                   - RegisterClass, CreateWindowEx, window management
      window_props.cpp             - Get/SetWindowLong, window properties
      dialog.cpp                   - DialogBox, CreateDialog, dialog procedures
      message.cpp                  - Message loop, SendMessage, PostMessage
      menu.cpp                     - Menu creation and management
      input.cpp                    - Keyboard, mouse, cursor, caret
      file.cpp                     - File I/O (CreateFile, ReadFile, etc.)
      registry.cpp                 - Registry operations
      system.cpp                   - GetSystemMetrics, time, sync, TLS, locale
      resource.cpp                 - LoadString, LoadBitmap, LoadIcon, etc.
      module.cpp                   - GetModuleHandle, LoadLibrary, GetProcAddress
      process.cpp                  - Process/thread management
      shell.cpp                    - Shell APIs (SH* functions, file dialogs)
      imagelist.cpp                - ImageList_* and InitCommonControls (coredll re-exports)
      misc.cpp                     - Debug, clipboard, sound, COM, IMM stubs
wince_sys/                         - Bundled WinCE ARM system DLLs (copied to windows/ at build)
```

## Key Concepts

- **Thunking**: ARM code calls COREDLL functions via the IAT. These point to magic addresses (0xFE000000+, `THUNK_BASE`) that the CPU intercepts, executing native Win32 equivalents.
- **Only coredll is thunked**: coredll.dll is the WinCE kernel/system bridge — the only DLL that talks to the OS. All other WinCE DLLs (commctrl, commdlg, ole32, ceshell, aygshell) are user-mode libraries that just use coredll APIs internally. They are loaded and executed as real ARM code in the emulator.
- **Bundled ARM DLLs**: The `wince_sys/` directory contains real ARM DLLs from a WinCE 5.0 build. At build time these are copied to `windows/` next to cerf.exe. At runtime, CERF auto-detects this directory and loads ARM DLLs from it when apps import them.
- **ARM DLL loading**: `LoadArmDll()` searches the exe directory then `windows/` for ARM DLLs, loads them via `PELoader::LoadDll()`, and recursively resolves their imports (which may load more ARM DLLs).
- **coredll re-exports**: coredll.def re-exports functions from other DLLs (e.g. ImageList_* from commctrl, GetOpenFileNameW from commdlg, SH* from ceshell/aygshell). These are thunked as native implementations in coredll so apps that import them by ordinal from coredll still work.
- **WinCE trap calls**: Some WinCE apps call APIs via hardcoded trap addresses in the `0xF000xxxx` range (descending from `0xF0010000`). The emulator decodes these as `api_index = (0xF0010000 - addr) / 4` and dispatches to the same thunk handlers.
- **Owner-draw marshaling**: `WM_DRAWITEM` and `WM_MEASUREITEM` carry native 64-bit struct pointers in lParam. `EmuWndProc`/`EmuDlgProc` marshal these into 32-bit ARM layout in emulated memory before forwarding to ARM callbacks.
- **64-bit handle safety**: Native Windows uses 64-bit pointers/handles. ARM code uses 32-bit. Handles are sign-extended via `(intptr_t)(int32_t)` when passing to native APIs, and truncated back to uint32_t for ARM registers.
- **Callback bridging**: Native callbacks (WndProc, DlgProc, TimerProc) invoke back into ARM code via `callback_executor`. Sentinel address 0xCAFEC000 signals callback return.
- **WinCE fullscreen**: WinCE apps run fullscreen by default. CERF sizes windows to the desktop work area and hides borders, preserving the app's original window style for correct rendering.

## Building

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/Release/x64/cerf.exe` with `build/Release/x64/windows/` containing bundled ARM DLLs.

## Testing

```
cerf.exe [options] <path-to-arm-wince-exe>
```

Options: `--trace`, `--log=CATEGORIES`, `--no-log=CATEGORIES`, `--log-file=PATH`, `--wince-sys=DIR`, `--quiet`

Test apps in `tmp/arm_test_apps/`: solitare.exe, chearts.exe, Zuma-arm.exe

## References

The `references/` directory (gitignored) holds local WinCE SDK materials including `coredll.def` (ordinal map) and ARM DLL builds. See `references/README.md` for setup.

## Conventions

- C++17, MSVC (Visual Studio 2022, v143 toolset)
- No external dependencies beyond Win32 SDK
- `LOG()` macro for categorized output: `LOG(THUNK, ...)`, `LOG(PE, ...)`, `LOG(EMU, ...)`, etc.
- Categories: THUNK, PE, EMU, TRACE, CPU, REG, DBG (defined in `log.h`)
- `LOG_ERR(...)` for errors (always prints to stderr), `LOG_RAW(...)` for uncategorized output
- Static linking (`/MT` runtime)
- Thunk functions return `true` when handled, setting `regs[0]` as the return value

## IMPORTANT: Thunk File Organization

**Each functional group within coredll MUST have its own `.cpp` file in `thunks/coredll/`.** No single thunks file should exceed 100-200 lines. When a file grows beyond that, split it into smaller focused files.

- Each file has its own `Register*Handlers()` method declared in `win32_thunks.h` and called from the constructor in `win32_thunks.cpp`.
- New files must be added to `cerf.vcxproj` under `<ClCompile>`.

**NEVER pile unrelated thunks into an existing file.** Create a new file proactively.

## IMPORTANT: Stub Functions Must Log

**Every stub function MUST print a console warning** so unimplemented calls are visible during testing. Use the format:
```cpp
LOG(THUNK, "[THUNK] FunctionName(...) -> stub\n");
```
Never create a silent stub that just returns a value without logging. This is critical for debugging which functions apps actually call.

## IMPORTANT: Capturing App Output

To capture the emulator's log output for analysis, **always redirect to a file** and then read that file:
```
cerf.exe [options] <app.exe> > log.txt 2>&1
```
Do NOT try to capture output via Bash tool timeout or other methods — the app runs a GUI message loop and won't exit on its own. Redirect to a file, let the user close the app, then read the log file.
