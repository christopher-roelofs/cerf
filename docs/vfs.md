# Virtual Filesystem (VFS)

## Overview

The VFS translates WinCE paths to host filesystem paths. It provides each device profile with an isolated filesystem root while allowing pass-through access to real host drives.

## Path Translation Rules

### MapWinCEPath (WinCE → Host)

Rules are evaluated in order:

| WinCE Path | Host Path | Rule |
|------------|-----------|------|
| `C:\foo\bar` | `C:\foo\bar` | Drive letter syntax — pass-through |
| `\c\foo\bar` | `C:\foo\bar` | Single-letter root — drive letter pass-through (uppercased) |
| `\d\` | `D:\` | Single-letter root — drive letter pass-through |
| `\Windows\notepad.exe` | `<device_fs_root>\Windows\notepad.exe` | Multi-letter root — device VFS |
| `\My Documents\file.txt` | `<device_fs_root>\My Documents\file.txt` | Multi-letter root — device VFS |
| `\Temp\cache.dat` | `<device_fs_root>\Temp\cache.dat` | Multi-letter root — device VFS |
| `relative\path` | `<device_fs_root>\relative\path` | No leading separator — relative to VFS root |
| *(empty)* | *(empty)* | Empty path — returned as-is |

**`device_fs_root`** = `<cerf_dir>/devices/<device>/fs/`

### MapHostToWinCE (Host → WinCE)

Used by `GetModuleFileNameW` and other APIs that return paths to ARM code:

| Host Path | WinCE Path | Rule |
|-----------|------------|------|
| `C:\foo\bar` | `\c\foo\bar` | Drive letter — lowercase drive dir |
| `<device_fs_root>\Windows\foo` | `\Windows\foo` | Under VFS root — strip prefix |
| Other | Returned as-is | External paths |

## Root Directory Enumeration

When ARM code calls `FindFirstFileW("\\*")` (enumerate root), the VFS returns:

1. **Real entries** from the device_fs_root directory (`Windows`, `My Documents`, etc.)
2. **Synthetic drive letter directories** — one for each drive reported by `GetLogicalDrives()` (e.g., `c`, `d`, `e`)

WinCE never returns `.` or `..` entries — these are filtered out.

This mimics real WinCE behavior where `\` contains both filesystem directories and drive letters as subdirectories.

## Device Directory Structure

```
devices/<device>/
├── cerf.ini                    # Device-specific configuration
├── registry.reg                # Compiled registry (auto-generated on first boot)
├── fs/                         # Virtual filesystem root
│   ├── Windows/                # WinCE system directory
│   │   ├── Desktop/
│   │   ├── Start Menu/
│   │   ├── Programs/
│   │   ├── solitare.exe        # ARM executables
│   │   ├── commctrl.dll        # ARM system DLLs
│   │   └── ...
│   ├── My Documents/
│   ├── Application Data/
│   ├── Program Files/
│   └── Temp/                   # Created on-demand by GetTempPathW
└── import_registry/            # Registry .reg files (imported on first boot)
    ├── common.reg              # Basic system entries
    ├── ie.reg                  # IE MIME types, CLSIDs, protocol handlers
    ├── shell.reg               # Shell/explorer entries
    ├── dcom.reg                # DCOM/OXID resolver
    └── custom.reg              # Device-specific overrides (imported LAST)
```

## Initialization

1. **LoadIniConfig()** — reads global `cerf.ini` to get `device=` name, then reads `devices/<device>/cerf.ini` for all settings
2. **InitVFS()** — validates device directory exists, sets:
   - `cerf_dir` — path to cerf.exe directory
   - `device_name` — profile name (e.g., `wince5`)
   - `device_dir` — `<cerf_dir>/devices/<device>/`
   - `device_fs_root` — `<device_dir>/fs/`
   - `wince_sys_dir` — `<device_fs_root>/Windows/`

## File Operations

All file thunks in `coredll/file.cpp` call `MapWinCEPath()` before invoking native Win32 file APIs:

| Thunk | Behavior |
|-------|----------|
| CreateFileW | Routes stream devices (e.g., `LPC1:`, `COM1:`) via DeviceManager first, then MapWinCEPath |
| FindFirstFileW | MapWinCEPath + root enumeration special case |
| GetFileAttributesW | MapWinCEPath + strips NTFS-only attribute bits (SPARSE, REPARSE, ENCRYPTED) that collide with WinCE meanings |
| DeleteFileW, MoveFileW | MapWinCEPath |
| CreateDirectoryW | MapWinCEPath |
| GetTempPathW | Returns `\Temp\`, creates `<device_fs_root>\Temp\` on host if missing |

### File Sharing Compatibility

WinCE is more permissive than desktop Windows with file sharing. If `CreateFileW` fails with `ERROR_SHARING_VIOLATION` and no sharing flags were specified, CERF retries with `FILE_SHARE_READ | FILE_SHARE_WRITE`.

### GetFileAttributesW Attribute Filtering

NTFS attributes that have different meanings on WinCE are stripped:

| Bit | NTFS Meaning | WinCE Collision | Action |
|-----|-------------|-----------------|--------|
| 0x0200 | SPARSE_FILE | — | Strip |
| 0x0400 | REPARSE_POINT | — | Strip |
| 0x1000 | OFFLINE | FILE_ATTRIBUTE_ROMSTATICREF | Strip |
| 0x2000 | NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_ROMMODULE | Strip |
| 0x4000 | ENCRYPTED | — | Strip |

## Stream Device Routing

Before filesystem mapping, `CreateFileW` checks if the path matches a registered stream device (e.g., `LPC1:`, `COM1:`). These are routed to the DeviceManager's device driver emulation instead of the filesystem.

## Registry Integration

The registry is stored per-device:

- **First boot**: If no `registry.reg` exists in the device directory, CERF imports all `.reg` files from `import_registry/` in sorted order, with `custom.reg` processed last (highest priority)
- **Subsequent boots**: Loads from `registry.reg` directly
- **Save**: Atomic write to `.tmp` file, then rename (prevents corruption on crash/kill)

## DLL Search Path

When ARM code loads a DLL (LoadLibraryW or static import), CERF searches:

1. `wince_sys_dir` (`devices/<device>/fs/Windows/`) — canonical system DLLs
2. `exe_dir` — directory of the launching executable (app-bundled DLLs)
3. Raw path as given

## Key Files

| File | Role |
|------|------|
| `cerf/thunks/coredll/vfs.cpp` | MapWinCEPath, MapHostToWinCE, InitVFS, GetTempPathW |
| `cerf/thunks/coredll/file.cpp` | CreateFileW, FindFirstFileW, root enumeration |
| `cerf/thunks/win32_thunks.cpp` | LoadIniConfig, LoadDeviceConfig |
| `cerf/thunks/registry_impl.cpp` | Registry loading from device directory |
| `cerf/thunks/registry_import.cpp` | REGEDIT4 format .reg file parser |
