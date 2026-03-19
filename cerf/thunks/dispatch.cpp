#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "apiset.h"
#include "trap_table.h"
#include "../log.h"
#include <cstdio>

uint32_t Win32Thunks::AllocThunk(const std::string& dll, const std::string& func,
                                  uint16_t ordinal, bool by_ordinal) {
    uint32_t addr = next_thunk_addr;
    next_thunk_addr += THUNK_STRIDE;

    ThunkEntry entry;
    entry.dll_name = dll;
    entry.func_name = func;
    entry.ordinal = ordinal;
    entry.by_ordinal = by_ordinal;
    entry.thunk_addr = addr;

    thunks[addr] = entry;

    /* Write a recognizable pattern at the thunk address:
       We write a BX LR instruction (0xE12FFF1E in ARM) so if the
       CPU somehow reaches it, it returns. But normally the thunk
       handler intercepts before execution. */
    mem.Write32(addr, 0xE12FFF1E);

    return addr;
}

uint32_t Win32Thunks::ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index) {
    /* ARM calling convention: R0-R3 for first 4 args, then stack.
       index 0 = first stack arg (5th overall arg) */
    uint32_t sp = regs[13];
    return mem.Read32(sp + index * 4);
}

bool Win32Thunks::HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem) {
    if (t_ctx) ++t_ctx->thunk_call_count;
    /* Check if address is in thunk range */
    auto it = thunks.find(addr);
    if (it == thunks.end()) {
        /* Also check addr+1 for Thumb calls */
        it = thunks.find(addr & ~1u);
        if (it == thunks.end()) {
            /* Handle WinCE trap-based API calls (0xF000xxxx range).
               Trap index = (0xF0010000 - addr) / 4 = (api_set << 8) | method.
               api_set identifies the target (0=W32 kernel, 21=shell, etc).
               method identifies the function within the set.

               Dispatch order:
               1. Registered API sets (CreateAPISet/RegisterAPISet) → vtable dispatch
               2. W32 kernel traps (set 0) → trap_table.h method → thunk handler
               3. Coredll ordinal fallback (for high indices that match ordinals) */
            if (addr >= WINCE_TRAP_BASE && addr < WINCE_TRAP_TOP) {
                uint32_t api_index = (WINCE_TRAP_TOP - addr) / 4;
                uint32_t api_set = api_index >> WINCE_TRAP_HANDLE_SHIFT;
                uint32_t method = api_index & 0xFF;

                /* 1. Registered API set dispatch (e.g. SH_SHELL from explorer) */
                if (api_sets_ && api_sets_->IsRegistered(api_set)) {
                    LOG(API, "[API] WinCE trap 0x%08X -> APISet %u method %u R0=0x%08X R1=0x%08X LR=0x%08X\n",
                        addr, api_set, method, regs[0], regs[1], regs[14]);
                    bool handled = api_sets_->Dispatch(api_set, method, regs, mem);
                    if (handled) {
                        uint32_t lr = regs[14];
                        regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                        return true;
                    }
                }

                /* 2. W32 kernel traps (set 0): look up in trap table.
                   These map to thunk handlers by NAME, not by ordinal.
                   If the method is not in the table, FATAL — do NOT fall through
                   to coredll ordinal dispatch (they're different numbering systems). */
                std::string func_name;
                if (api_set == 0) {
                    auto& w32_table = GetW32TrapTable();
                    auto w32_it = w32_table.find(method);
                    if (w32_it != w32_table.end()) {
                        func_name = w32_it->second;
                    } else {
                        LOG(API, "\n[FATAL] Unhandled W32 kernel trap: set=0 method=%u addr=0x%08X LR=0x%08X\n",
                            method, addr, regs[14]);
                        LOG(API, "  Add this method to cerf/thunks/trap_table.h\n");
                        Log::Close();
                        ExitProcess(1);
                    }
                }

                /* 3. Coredll ordinal fallback for non-W32 traps.
                   Shell traps (set 21+) have high indices that match coredll
                   ordinal forwarding stubs. */
                if (func_name.empty()) {
                    auto name_it = ordinal_map.find((uint16_t)api_index);
                    if (name_it != ordinal_map.end())
                        func_name = name_it->second;
                }

                LOG(API, "[API] WinCE trap 0x%08X -> set=%u method=%u (%s) R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X LR=0x%08X\n",
                    addr, api_set, method,
                    func_name.empty() ? "unknown" : func_name.c_str(),
                    regs[0], regs[1], regs[2], regs[3], regs[14]);

                ThunkEntry trap_entry;
                trap_entry.dll_name = "COREDLL.dll";
                trap_entry.func_name = func_name;
                trap_entry.ordinal = (uint16_t)api_index;
                trap_entry.by_ordinal = func_name.empty();
                trap_entry.thunk_addr = addr;
                bool result = ExecuteThunk(trap_entry, regs, mem);
                if (result) {
                    uint32_t lr = regs[14];
                    regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                }
                return result;
            }

            /* Detect branches into thunk memory region at unregistered addresses */
            if (addr >= THUNK_BASE && addr < THUNK_BASE + 0x100000) {
                LOG(EMU, "[EMU] ERROR: Branch to unregistered thunk address 0x%08X (LR=0x%08X)\n",
                       addr, regs[14]);
                regs[0] = 0;
                uint32_t lr = regs[14];
                regs[15] = (lr & 1) ? (lr & ~1u) : (lr & ~3u);
                return true;
            }
            return false;
        }
    }

    bool result = ExecuteThunk(it->second, regs, mem);
    if (result) {
        /* Return to caller: set PC = LR */
        uint32_t lr = regs[14];
        if (lr & 1) {
            /* Return to Thumb mode */
            regs[15] = lr & ~1u;
            /* Keep Thumb flag - handled by caller */
        } else {
            regs[15] = lr & ~3u;
        }
    }
    return result;
}

bool Win32Thunks::ExecuteThunk(ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem) {
    if (entry.func_name.empty() && entry.by_ordinal) {
        entry.func_name = ResolveOrdinal(entry.ordinal);
        if (!entry.func_name.empty()) {
            LOG(API, "[API] Resolved ordinal %d -> %s\n", entry.ordinal, entry.func_name.c_str());
        }
    }
    const std::string& func = entry.func_name;

    /* Map-based dispatch: look up handler by function name */
    auto it = thunk_handlers.find(func);
    if (it != thunk_handlers.end()) return it->second(regs, mem);

    /* Unhandled function — crash immediately so we notice and fix it. */
    if (func.empty() && entry.by_ordinal) {
        LOG(API, "\n[FATAL] UNIMPLEMENTED: %s!@%d (no name mapping) LR=0x%08X\n",
               entry.dll_name.c_str(), entry.ordinal, regs[14]);
    } else {
        LOG(API, "\n[FATAL] UNIMPLEMENTED: %s!%s (ordinal=%d) LR=0x%08X\n",
               entry.dll_name.c_str(), func.c_str(), entry.ordinal, regs[14]);
    }
    Log::Close();
    ExitProcess(1);
}
