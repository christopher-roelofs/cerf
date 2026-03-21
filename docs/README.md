# CERF Documentation

## Architecture

- [architecture.md](architecture.md) — Overview, memory map, configuration, VFS, directory structure
- [boot.md](boot.md) — Boot sequence, boot screen, device.exe, HKLM\init

## Core Systems

- [process_isolation.md](process_isolation.md) — ProcessSlot, copy-on-write, per-process state
- [multi_process.md](multi_process.md) — Child process creation, thread model, what's shared vs isolated
- [seh.md](seh.md) — ARM structured exception handling, .pdata dispatch, RaiseException
- [windowing.md](windowing.md) — WS_POPUP translation, WinCE NC area, style tracking

## Implementation Details

- [vfs.md](vfs.md) — Virtual filesystem, path translation, device directory, registry integration
- [thunking.md](thunking.md) — IAT patching, ordinal resolution, callback bridging, message marshaling
- [wince-dlls.md](wince-dlls.md) — DLL hierarchy, bundled ARM DLLs, resource handling
