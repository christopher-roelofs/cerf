# WinCE DLL Architecture & Bundled Libraries

## WinCE DLL Hierarchy

Windows CE has a layered DLL architecture. At the bottom is coredll.dll — the single system bridge that talks to the CE kernel. Everything else is a user-mode library:

```
┌─────────────────────────────────────────────────┐
│                 WinCE Application                │
├──────────┬──────────┬───────────┬───────────────┤
│ aygshell │ ceshell  │ commdlg   │ commctrl      │
│ (shell   │ (shell   │ (file     │ (common       │
│  helpers)│  funcs)  │  dialogs) │  controls)    │
├──────────┴──────┬───┴───────────┴───────────────┤
│                 │ ole32 (COM)                    │
│                 ├────────┬───────────────────────┤
│                 │ rpcrt4 │                       │
├─────────────────┴────────┴───────────────────────┤
│                    coredll.dll                    │
│            (kernel bridge — thunked by CERF)      │
├──────────────────────────────────────────────────┤
│                  WinCE Kernel                     │
└──────────────────────────────────────────────────┘
```

## Why Only coredll Is Thunked

coredll.dll is special — it's the only DLL that interfaces with the WinCE kernel. It provides:
- Memory management (VirtualAlloc, HeapAlloc)
- Window management (CreateWindowEx, RegisterClass)
- GDI (CreateDC, BitBlt, TextOut)
- File I/O, registry, processes, threads
- C runtime (malloc, printf, memcpy)

Every other DLL is implemented entirely in terms of coredll calls. For example, the decompiled source of commctrl.dll's `CommandBands_InsertBands` shows it just calls `CreateWindowExW("ToolbarWindow32")` and `SendMessage` — pure coredll APIs.

This means if we thunk coredll correctly, all the other DLLs can run as real ARM code in the emulator. This is far more accurate than trying to reimplement their behavior with native stubs.

## Bundled ARM DLLs

CERF ships with real ARM DLLs from a Windows CE 5.0 build in the `wince_sys/` source directory. At build time, these are copied to `windows/` next to cerf.exe:

```
build/Release/x64/
  cerf.exe
  windows/
    commctrl.dll    - Common controls (toolbar, listview, treeview, etc.)
    commdlg.dll     - Common dialogs (GetOpenFileName, GetSaveFileName)
    ole32.dll       - COM runtime (CoCreateInstance, etc.)
    ceshell.dll     - Shell functions (SHGetSpecialFolderPath, etc.)
    aygshell.dll    - Application shell helpers (SHInitDialog, menubar, SIP)
    rpcrt4.dll      - RPC runtime (used internally by ole32)
    shcore.dll      - Shell core (used internally by ceshell)
```

## Import Dependencies

Each DLL's imports (verified via PE analysis):

| DLL | Imports From |
|-----|-------------|
| commctrl.dll | COREDLL (321 functions) |
| commdlg.dll | COREDLL (136 functions) |
| ole32.dll | COREDLL (152) + RPCRT4 (68) |
| ceshell.dll | COREDLL (280) + ole32 (7) + commctrl (7) + shcore (21) |
| aygshell.dll | COREDLL (153) + ole32 (4) + commctrl (4) |

All roads lead to coredll. No DLL talks directly to kernel drivers or hardware.

## coredll Re-exports

coredll.def re-exports some functions from these DLLs under its own ordinals. Apps that import these by ordinal from coredll hit our native thunks:

- **ImageList_*** (ordinals 738-769) — from commctrl
- **GetOpenFileNameW** (488), **GetSaveFileNameW** (489) — from commdlg
- **SH*** functions (various ordinals) — from ceshell/aygshell
- **InitCommonControls/Ex** — from commctrl

These are implemented as native thunks in `coredll/imagelist.cpp` and `coredll/shell.cpp`.

## ARM DLL Loading

When an app calls `LoadLibraryW("commctrl.dll")` or has a static import from a non-coredll DLL, CERF's `LoadArmDll()`:

1. Searches the app's directory, then `windows/` next to cerf.exe
2. Loads the ARM PE via `PELoader::LoadDll()`
3. Recursively resolves imports (may load more ARM DLLs)
4. Calls `DllMain(DLL_PROCESS_ATTACH)` via the callback executor
5. Returns the base address as the module handle

## Custom WinCE System Directory

By default, CERF looks for `windows/` next to the executable. Override with:

```
cerf.exe --wince-sys=C:\path\to\wince\dlls myapp.exe
```
