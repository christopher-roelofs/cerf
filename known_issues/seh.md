# ARM SEH — Known Limitations

## Implementation: `cerf/thunks/coredll/seh_dispatch.cpp`

## Working
- .pdata parsing (compressed format, 8-byte entries)
- PDATA_EH at pFuncStart-8 (handler + scope table pointers)
- Binary search of .pdata by PC
- Scope table walking with {TryBegin, TryEnd, FilterAddr, JumpTarget}
- Filter expression called via ARM callback
- Prologue-based frame unwinding (STMDB, SUB SP imm, SUB SP R12, STR LR)
- Correct SP for handler frame (function's SP, not caller's)

## Not Implemented — FATAL on encounter

### Thumb (16-bit) function unwinding
**Impact:** Any exception raised inside a Thumb-mode function cannot be dispatched.
**Detection:** FATAL exit when .pdata entry has ThirtyTwoBits=0.
**Fix needed:** Implement ThumbVirtualUnwind. Thumb prologues use different
instruction encodings (PUSH {regs, LR}, SUB SP, #imm as 16-bit instructions).
Reference: WinCE kernel `ARM/unwind.c` → `ThumbVirtualUnwind()`.

### Complex exception filters (EXCEPTION_POINTERS)
**Impact:** Filters that call `GetExceptionInformation()` read garbage because
we don't build `EXCEPTION_POINTERS` → `{EXCEPTION_RECORD, CONTEXT}` in ARM memory.
**Detection:** FATAL exit when filter returns value other than 0, 1, or -1.
**Fix needed:** Before calling filter:
1. Build EXCEPTION_RECORD at known ARM address (code, flags, address, params)
2. Build ARM CONTEXT (R0-R15, CPSR)
3. Build EXCEPTION_POINTERS pointing to both
4. Store pointer where filter expects it (frame-relative offset or TLS)
The compiler generates filter code that reads from a fixed stack offset,
set by the `__C_specific_handler` in the establishing function.
