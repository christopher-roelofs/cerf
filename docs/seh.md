# ARM Structured Exception Handling (SEH)

## Overview

CERF implements ARM WinCE structured exception handling so that `RaiseException` transfers control to `__except` handlers instead of crashing. This is required for RPCRT4 (which calls `RpcRaiseException`) and any ARM code using `__try/__except`.

## How It Works

### .pdata — Exception Directory

Each ARM PE has a `.pdata` section (IMAGE_DIRECTORY_ENTRY_EXCEPTION) containing function table entries. CERF parses this at DLL load time and stores `pdata_rva`/`pdata_size` in `PEInfo`.

Each entry is `{BeginAddress, InfoWord}` (8 bytes). When `InfoWord` bit 31 = 1 (HasHandler), the exception handler address and scope table pointer are stored at `pFuncStart - 8`.

### Dispatch Pipeline (`seh_dispatch.cpp`)

When `RaiseException` fires:

1. **Find function** — binary search .pdata by current PC
2. **Decode prologue** — match ARM instructions (STMDB SP!, SUB SP, STR LR) to determine frame layout
3. **Walk scope table** — match exception PC against `[Begin, End)` ranges to find the `__except` block
4. **Execute filter** — run the filter expression via `callback_executor`
5. **Transfer control** — set PC to the scope's JumpTarget, restore SP from the unwound frame
6. **Cascade** — if no match, unwind to caller via saved LR/SP and repeat (max 32 frames)

### Fallback Chain

If .pdata dispatch doesn't find a handler:

1. **setjmp/longjmp** — tracks setjmp buffers on stack; longjmp to recovery point for NONCONTINUABLE exceptions (MFC pattern)
2. **Unwind boundary** — unwinds to the `callback_executor` boundary using `last_unhandled_sp`/`last_unhandled_pc`
3. **HRESULT return** — returns `0x80070000 | exception_code` to caller

### Registration

`SetExceptionHandler` (coredll ordinal 583) stores the CRT handler in `t_ctx->seh_handler` per-thread, called by the WinCE CRT at thread startup.

## Limitations

- **Thumb functions** — prologue decoding only handles 32-bit ARM instructions. Thumb function unwinding is not implemented and will fatal exit. WinCE 5 is predominantly ARM.
- **EXCEPTION_POINTERS** — not built in ARM memory. Filters that call `GetExceptionInformation()` won't get valid data.
- **Nested exceptions** — not supported.
- **__finally blocks** — handled by ARM CRT via EH_FINALLY scope entries, not by CERF directly.

## Key Files

| File | Role |
|------|------|
| `cerf/thunks/coredll/seh_dispatch.cpp` | Binary search, prologue unwinding, scope table walking |
| `cerf/thunks/coredll/system.cpp` | RaiseException thunk (dispatch entry point) |
| `cerf/thunks/thread_context.h` | `seh_handler` field in ThreadContext |
| `cerf/loader/pe_loader.cpp` | .pdata RVA/size parsing from PE header |
