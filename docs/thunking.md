# Thunking in CERF

## What is Thunking?

WinCE ARM apps call OS APIs through coredll.dll. Since we're running ARM code on x64, we intercept these calls and execute equivalent native Win32 functions. This translation is called "thunking".

## How It Works

### Import Address Table (IAT) Patching

When a WinCE EXE is loaded, its import table lists the DLLs and functions it needs. For coredll imports, CERF writes a magic "thunk address" (0xFE000000+) into each IAT slot:

```
EXE import: coredll.dll!CreateWindowExW (ordinal 246)
  → IAT entry patched to 0xFE000048
  → When ARM code calls this address, CPU intercepts
  → Thunk handler reads ARM registers (R0-R3 + stack), calls native CreateWindowExW
  → Result written to R0, CPU resumes
```

### Ordinal Resolution

WinCE imports are almost always by ordinal (not by name). CERF maintains an ordinal map built from `references/coredll.def` that maps ordinal numbers to function names. The thunk dispatcher uses this to find the right handler.

### WinCE Trap Calls

Some WinCE apps use an alternative calling convention — direct trap addresses in the 0xF000xxxx range (descending from 0xF0010000). These encode the API index as `(0xF0010000 - addr) / 4`. CERF decodes these and dispatches to the same handlers.

## Thunk Handler Convention

Each handler is a lambda with signature:

```cpp
[](uint32_t* regs, EmulatedMemory& mem) -> bool
```

- `regs[0]`-`regs[3]` = R0-R3 (first 4 arguments, ARM calling convention)
- Additional arguments on the emulated stack via `ReadStackArg(regs, mem, N)`
- Set `regs[0]` to the return value
- Return `true` if handled

### 64-bit Handle Safety

Native Win32 handles are 64-bit on x64. ARM code uses 32-bit. The convention:

```cpp
// ARM → native: sign-extend
HWND hwnd = (HWND)(intptr_t)(int32_t)regs[0];

// Native → ARM: truncate
regs[0] = (uint32_t)(uintptr_t)native_handle;
```

## Callback Bridging

Native Win32 uses callbacks (WndProc, DlgProc, TimerProc). When Windows calls a callback, CERF's `EmuWndProc`/`EmuDlgProc` wrapper:

1. Saves full CPU state (all 16 registers + CPSR)
2. Sets R0-R3 to callback arguments
3. Sets LR to sentinel address (0xCAFEC000)
4. Sets PC to the ARM callback function
5. Runs CPU until it hits the sentinel
6. Reads R0 as return value
7. Restores CPU state

## Thunk File Organization

All thunks live in `thunks/coredll/`, one file per functional group:

| File | Scope |
|------|-------|
| memory.cpp | VirtualAlloc, HeapAlloc, malloc, LocalAlloc |
| string.cpp | wcslen, wcscpy, wsprintfW, MultiByteToWideChar |
| crt.cpp | atoi, qsort, time, rand |
| gdi_dc.cpp | Device contexts, SelectObject |
| gdi_draw.cpp | BitBlt, drawing, DIB sections |
| gdi_text.cpp | TextOut, fonts |
| gdi_region.cpp | Regions, clipping |
| window.cpp | CreateWindowEx, RegisterClass |
| dialog.cpp | DialogBox, CreateDialog |
| message.cpp | GetMessage, SendMessage, PostMessage |
| menu.cpp | CreateMenu, AppendMenu |
| input.cpp | Keyboard, mouse |
| file.cpp | CreateFile, ReadFile, WriteFile |
| registry.cpp | RegOpenKeyEx, RegQueryValueEx |
| system.cpp | GetSystemMetrics, time, TLS, locale |
| resource.cpp | LoadString, LoadBitmap, LoadIcon |
| module.cpp | LoadLibrary, GetProcAddress, GetModuleHandle |
| process.cpp | CreateProcess, threads |
| shell.cpp | SH* functions, file dialogs |
| imagelist.cpp | ImageList_*, InitCommonControls |
| misc.cpp | Debug, clipboard, COM, IMM |

Each file implements a `Register*Handlers()` method called from the Win32Thunks constructor.
