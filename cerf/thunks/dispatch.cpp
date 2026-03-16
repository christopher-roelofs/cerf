#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
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
               WinCE apps call some APIs via trap addresses descending from 0xF0010000.
               API index = (0xF0010000 - addr) / 4, which maps to COREDLL ordinals. */
            if (addr >= WINCE_TRAP_BASE && addr < WINCE_TRAP_TOP) {
                uint32_t api_index = (WINCE_TRAP_TOP - addr) / 4;
                auto name_it = ordinal_map.find((uint16_t)api_index);
                std::string func_name = (name_it != ordinal_map.end()) ? name_it->second : "";
                uint32_t api_set = api_index / 256;
                uint32_t method = api_index % 256;
                if (!func_name.empty()) {
                    LOG(API, "[API] WinCE trap 0x%08X -> API %u (set=%u method=%u) (%s) R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X LR=0x%08X\n",
                        addr, api_index, api_set, method, func_name.c_str(),
                        regs[0], regs[1], regs[2], regs[3], regs[14]);
                } else {
                    LOG(API, "[API] WinCE trap 0x%08X -> API %u (set=%u method=%u) (unknown) R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X LR=0x%08X\n",
                        addr, api_index, api_set, method,
                        regs[0], regs[1], regs[2], regs[3], regs[14]);
                }
                /* Create a temporary thunk entry and execute it */
                ThunkEntry trap_entry;
                trap_entry.dll_name = "COREDLL.dll";
                trap_entry.func_name = func_name;
                trap_entry.ordinal = (uint16_t)api_index;
                trap_entry.by_ordinal = true;
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
