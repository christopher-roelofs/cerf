# CERF - Windows CE Runtime Foundation

## Project Overview

CERF is an ARM CPU emulator + Win32 API compatibility layer that runs Windows CE ARM binaries on modern x64 desktop Windows. It interprets ARMv5TE instructions (ARM + Thumb modes), loads WinCE PE executables, and thunks COREDLL.DLL API calls to native Win32 APIs.

## Architecture

```
cerf/
  main.cpp                        - Entry point, CLI parsing, emulation loop setup
  cpu/
    mem.h                          - EmulatedMemory class (32-bit address space, page-based)
    arm_cpu.h                      - ArmCpu class declaration (registers, flags, methods)
    arm_cpu.cpp                    - CPU core: condition checks, barrel shifter, Run/Step loop
    arm_insn.cpp                   - ARM mode instruction handlers
    thumb_insn.cpp                 - Thumb mode instruction handlers
  loader/
    pe_loader.h/.cpp               - WinCE PE loader (sections, imports, relocations)
  thunks/
    win32_thunks.h                 - Win32Thunks class, ThunkEntry struct
    win32_thunks.cpp               - Core thunk infrastructure, dispatch, callbacks
    coredll/                       - COREDLL.DLL thunks (one file per functional group)
      memory.cpp, string.cpp, crt.cpp, arm_runtime.cpp
      gdi_dc.cpp, gdi_draw.cpp, gdi_text.cpp, gdi_region.cpp
      window.cpp, window_props.cpp, dialog.cpp, message.cpp, menu.cpp, input.cpp
      file.cpp, registry.cpp, system.cpp, resource.cpp, module.cpp, process.cpp
      shell.cpp, misc.cpp
    aygshell/                      - AYGSHELL.DLL thunks (WinCE shell helpers)
    commctrl/                      - COMMCTRL.DLL thunks (common controls, ImageList)
    commdlg/                       - COMMDLG.DLL thunks (file dialogs)
```

## Key Concepts

- **Thunking**: ARM code calls COREDLL functions via the IAT. These point to magic addresses (0xFE000000+, `THUNK_BASE`) that the CPU intercepts, executing native Win32 equivalents.
- **WinCE trap calls**: Some WinCE apps call APIs via hardcoded trap addresses in the `0xF000xxxx` range (descending from `0xF0010000`). The emulator decodes these as `api_index = (0xF0010000 - addr) / 4` and dispatches to the same thunk handlers. `THUNK_BASE` was moved to `0xFE000000` to avoid colliding with this range.
- **Owner-draw marshaling**: `WM_DRAWITEM` and `WM_MEASUREITEM` carry native 64-bit struct pointers in lParam. `EmuWndProc`/`EmuDlgProc` marshal these into 32-bit ARM layout in emulated memory before forwarding to ARM callbacks.
- **64-bit handle safety**: Native Windows uses 64-bit pointers/handles. ARM code uses 32-bit. Handles are sign-extended via `(intptr_t)(int32_t)` when passing to native APIs, and truncated back to uint32_t for ARM registers.
- **Callback bridging**: Native callbacks (WndProc, DlgProc, TimerProc) invoke back into ARM code via `callback_executor`. Sentinel address 0xCAFEC000 signals callback return.
- **WinCE fullscreen**: WinCE apps run fullscreen by default. CERF sizes windows to the desktop work area and hides borders, preserving the app's original window style for correct rendering.

## Building

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/Release/x64/cerf.exe`

## Testing

```
cerf.exe <path-to-wince-arm-exe>
```

Primary test app: Solitaire (`tmp/arm_test_apps/solitare.exe`). The game should launch, display cards, handle clicks, and show the Options dialog.

## References

The `references/` directory (gitignored) holds local WinCE SDK materials. See `references/README.md` for setup.

## Conventions

- C++17, MSVC (Visual Studio 2022, v143 toolset)
- No external dependencies beyond Win32 SDK
- `LOG()` macro for categorized output: `LOG(THUNK, ...)`, `LOG(PE, ...)`, `LOG(EMU, ...)`, etc.
- Categories: THUNK, PE, EMU, TRACE, CPU, REG, DBG (defined in `log.h`)
- `LOG_ERR(...)` for errors (always prints to stderr), `LOG_RAW(...)` for uncategorized output
- Static linking (`/MT` runtime)
- Thunk functions return `true` when handled, setting `regs[0]` as the return value

## IMPORTANT: Thunk File Organization

**Each DLL and each functional group within a DLL MUST have its own `thunks_*.cpp` file.** No single thunks file should exceed 100-200 lines. When a file grows beyond that, split it into smaller focused files.

- For COREDLL groups: `thunks_memory.cpp`, `thunks_gdi_dc.cpp`, `thunks_gdi_draw.cpp`, `thunks_string.cpp`, etc.
- For external DLLs: `thunks_aygshell.cpp`, `thunks_ole.cpp`, etc. If a DLL has multiple functional groups (e.g. aygshell has SIP functions, menu bar functions, notification functions), split those into separate files too as they grow.
- Each file has its own `Register*Handlers()` method declared in `win32_thunks.h` and called from the constructor in `win32_thunks.cpp`.
- New files must be added to `cerf.vcxproj` under `<ClCompile>`.

**NEVER pile unrelated thunks into an existing file.** Create a new file proactively.

## IMPORTANT: Stub Functions Must Log

**Every stub function MUST print a console warning** so unimplemented calls are visible during testing. Use the format:
```cpp
LOG(THUNK, "[THUNK] FunctionName(...) -> stub\n");
```
Never create a silent stub that just returns a value without logging. This is critical for debugging which functions apps actually call.
