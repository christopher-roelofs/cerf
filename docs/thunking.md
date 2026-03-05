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

Per-DLL ordinal overrides are supported via `dll_ordinal_map` — for example, WinCE 7's aygshell.dll uses coredll ordinal 5403 for `SystemParametersInfoW`.

### WinCE Trap Calls

Some WinCE apps use an alternative calling convention — direct trap addresses in the 0xF000xxxx range (descending from 0xF0010000). These encode the API index as `(0xF0010000 - addr) / 4`. CERF decodes these and dispatches to the same handlers.

## Thunk Handler Convention

Each handler is a lambda with signature:

```cpp
[this](uint32_t* regs, EmulatedMemory& mem) -> bool
```

- `regs[0]`-`regs[3]` = R0-R3 (first 4 arguments, ARM calling convention)
- Additional arguments on the emulated stack via `ReadStackArg(regs, mem, N)`
- Set `regs[0]` to the return value
- Return `true` if handled
- Lambdas capture `this` when they need access to `Win32Thunks` state (screen resolution, VFS paths, callback executor, etc.)

### ARM Double Passing

ARM passes doubles in register pairs: r0:r1 for the first double arg, r2:r3 for the second. In varargs functions (printf-like), doubles occupy two consecutive 32-bit argument slots. The `wprintf_format` helper in `string.cpp` handles this.

### 64-bit Handle Safety

Native Win32 handles are 64-bit on x64. ARM code uses 32-bit. Two strategies:

```cpp
// Strategy 1: Sign-extend (most common, works for handles with bit 31 set)
HWND hwnd = (HWND)(intptr_t)(int32_t)regs[0];
regs[0] = (uint32_t)(uintptr_t)native_handle;

// Strategy 2: Handle map (for handles that don't round-trip via sign extension)
uint32_t fake = WrapHandle(real_handle);    // stores in handle_map
HANDLE real = UnwrapHandle(fake);            // looks up or sign-extends
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

For callbacks with more than 4 arguments, extra args are pushed to the emulated stack at SP-0x100.

### Message Marshaling

Many Windows messages carry native pointers in lParam/wParam that can't safely truncate to 32-bit. These are handled in three ways:

**Bypassed to DefWindowProcW** (not forwarded to ARM):
- `WM_GETMINMAXINFO`, `WM_NCCALCSIZE`, `WM_WINDOWPOSCHANGING/CHANGED`
- `WM_NCDESTROY`, `WM_SETICON/GETICON`, `WM_COPYDATA`, `WM_INPUT`
- `WM_NCPAINT`, UAH theme messages (0x90-0x95)
- `WM_ENTERMENULOOP/EXITMENULOOP`

**Marshaled into scratch memory** (0x3F000000 region):
- `WM_CREATE`/`WM_NCCREATE` — 32-bit CREATESTRUCT at 0x3F000000
- `WM_DRAWITEM` — 32-bit DRAWITEMSTRUCT at 0x3F002000 (0x3F001000 for dialogs)
- `WM_MEASUREITEM` — with writeback to native struct
- `WM_SETTEXT` — string copied to ARM buffer at 0x3F002400
- `WM_GETTEXT` — ARM buffer at 0x3F002800, copied back after
- `WM_STYLECHANGING/CHANGED` — STYLESTRUCT at 0x3F002200 with writeback
- `WM_NOTIFY` — passed through if pointer is in ARM range

**Translated:**
- `WM_SETTINGCHANGE` — desktop convention (lParam=string) converted to WinCE convention (lParam=SPI constant)

## Thunk File Organization

All thunks live in `thunks/coredll/`, one file per functional group:

| File | Scope |
|------|-------|
| arm_runtime.cpp | Soft-float, integer division, 64-bit shift helpers |
| crt.cpp | memcpy, memmove, memset, strlen, strcpy, atoi, atof, qsort, time, rand |
| dialog.cpp | CreateDialogIndirectParamW, DialogBoxIndirectParamW, EndDialog |
| dpa.cpp | DPA_Create, DPA_InsertPtr, DPA_GetPtr, DPA_DeletePtr, DPA_Sort |
| dsa.cpp | DSA_Create, DSA_InsertItem, DSA_GetItemPtr, DSA_DeleteItem |
| file.cpp | CreateFileW, ReadFile, WriteFile, SetFilePointer, FindFirstFileW |
| gdi_dc.cpp | GetDC, CreateCompatibleDC, GetDeviceCaps, GetStockObject |
| gdi_draw.cpp | BitBlt, StretchBlt, CreateDIBSection, CreateBitmap, PatBlt |
| gdi_region.cpp | CreateRectRgn, CombineRgn, SelectClipRgn |
| gdi_text.cpp | CreateFontW, TextOutW, GetTextExtentPoint32W, DrawTextW |
| imagelist.cpp | ImageList_Create, ImageList_Add, ImageList_Draw (coredll re-exports) |
| input.cpp | GetKeyState, GetAsyncKeyState, MapVirtualKeyW |
| memory.cpp | VirtualAlloc, HeapAlloc, malloc, LocalAlloc, free, realloc |
| menu.cpp | CreateMenu, InsertMenuItemW, SetMenu, TrackPopupMenu |
| message.cpp | SendMessageW, PostMessageW, GetMessageW, DispatchMessageW, SetTimer |
| misc.cpp | CommandBar_*, ClipCursor, Beep, CoTaskMemAlloc, COM stubs, IMM stubs, GetMonitorInfo |
| module.cpp | GetModuleHandleW, LoadLibraryW, GetModuleFileNameW, GetProcAddress |
| process.cpp | CreateProcessW, CreateThread (stub), file mapping, WaitForMultipleObjects |
| registry.cpp | RegOpenKeyExW, RegCreateKeyExW, RegQueryValueExW, RegSetValueExW |
| resource.cpp | FindResourceW, LoadStringW, LoadBitmapW, LoadIconW |
| shell.cpp | SHGetOpenFileName, SHGetFileInfo, SHLoadDIBitmap (.2bp reader) |
| stdio.cpp | wprintf, swprintf, sprintf, sscanf, wcsftime, file handle I/O |
| string.cpp | wsprintf, wcslen, wcscmp, WideCharToMultiByte, MultiByteToWideChar |
| system.cpp | GetSystemMetrics, GetSysColor, GetTickCount, Sleep, TLS, locale, SystemParametersInfoW |
| vfs.cpp | GetTempPathW, InitVFS, MapWinCEPath, MapHostToWinCE |
| window.cpp | CreateWindowExW, ShowWindow, SetWindowPos, GetClientRect, SetWindowLongW |
| window_props.cpp | GetPropW, SetPropW, RemovePropW |

Each file implements a `Register*Handlers()` method called from the `Win32Thunks` constructor.

## Screen Resolution Emulation

ARM apps see a configurable screen resolution (default 800x600, set in `cerf.ini`). The following APIs all return the emulated resolution:

- `GetSystemMetrics(SM_CXSCREEN / SM_CYSCREEN)`
- `GetDeviceCaps(HORZRES / VERTRES)`
- `SystemParametersInfoW(SPI_GETWORKAREA)` — returns `{0, 0, width, height}`
- `SystemParametersInfoW(0xE1 / SPI_GETSIPINFO)` — WinCE 7 SIP info, visible desktop = full area
- `GetMonitorInfo` — rcMonitor and rcWork both report `{0, 0, width, height}`
- `CreateWindowExW` — top-level windows are sized to the emulated resolution

## Adding a New Thunk

1. Find the correct file in `coredll/` for the functional group
2. Add a `Thunk("FunctionName", ordinal, [...](uint32_t* regs, EmulatedMemory& mem) -> bool { ... });`
3. Look up the ordinal in `references/coredll.def`
4. Read args from `regs[0-3]` and stack, call the native equivalent, set `regs[0]` to the return value
5. Add appropriate `LOG(API, ...)` for debugging
