/* ARM SEH (Structured Exception Handling) dispatch for WinCE.
   Implements the kernel's NKDispatchException + ArmVirtualUnwind logic.

   .pdata format (compressed, ARM WinCE 5):
   - Each entry: 8 bytes {pFuncStart:32, Info:32}
   - Info: PrologLen:8 | FuncLen:22 | ThirtyTwoBits:1 | ExceptionFlag:1
   - When ExceptionFlag=1, PDATA_EH at pFuncStart-8
   - SCOPE_TABLE: {Count, {TryBegin, TryEnd, FilterAddr, JumpTarget}[]}

   Prologue patterns handled (from WinCE kernel ARM/unwind.c):
   - STMDB SP!, {reglist}  — push registers (saves LR if bit 14 set)
   - SUB SP, SP, #imm      — allocate locals (immediate)
   - SUB SP, SP, R12        — allocate locals (register, after LDR R12, [PC, #N])
   - STR LR, [SP, #-N]!    — single-register push of LR

   Limitations (FATAL on encounter):
   - Thumb (16-bit) functions: need ThumbVirtualUnwind (different encoding)
   - Complex filters: filters that call GetExceptionInformation() need
     EXCEPTION_POINTERS built in ARM memory (not yet implemented) */

#include "../win32_thunks.h"
#include "../../log.h"

/* ARM instruction identification masks and values.
   Reference: ARM Architecture Reference Manual, WinCE kernel arminst.h */
constexpr uint32_t STMDB_SP_MASK   = 0xFFFF0000;
constexpr uint32_t STMDB_SP_INST   = 0xE92D0000; /* STMDB SP!, {reglist} */
constexpr uint32_t SUB_SP_IMM_MASK = 0xFFFFF000;
constexpr uint32_t SUB_SP_IMM_INST = 0xE24DD000; /* SUB SP, SP, #imm */
constexpr uint32_t SUB_SP_REG_MASK = 0xFFFFFFF0;
constexpr uint32_t SUB_SP_REG_INST = 0xE04DD000; /* SUB SP, SP, Rm */
constexpr uint32_t LDR_PC_MASK     = 0xFFFF0000;
constexpr uint32_t LDR_PC_INST     = 0xE59FC000; /* LDR R12, [PC, #imm] */
constexpr uint32_t STR_LR_PUSH_MASK = 0xFFFFFFFF;
constexpr uint32_t STR_LR_PUSH_INST = 0xE52DE004; /* STR LR, [SP, #-4]! */

static int PopCount16(uint32_t v) {
    int c = 0;
    for (int i = 0; i < 16; i++)
        if (v & (1u << i)) c++;
    return c;
}

/* Decode ARM data processing immediate: 8-bit value rotated right by 2*rot */
static uint32_t DecodeArmImm(uint32_t instr) {
    uint32_t imm = instr & 0xFF;
    uint32_t rot = (instr >> 8) & 0xF;
    if (rot == 0) return imm; /* no rotation — avoid UB from shift by 32 */
    uint32_t shift = rot * 2;
    return (imm >> shift) | (imm << (32 - shift));
}

/* Unwind one ARM (32-bit) stack frame by reversing prologue instructions.
   Returns caller PC (saved_LR - 4 for ARM prefetch), or 0 on failure. */
static uint32_t UnwindFrame(EmulatedMemory& mem, uint32_t func_start,
    uint32_t prolog_bytes, uint32_t sp, uint32_t& out_sp)
{
    constexpr int MAX_PROLOG_INSTR = 15; /* same limit as WinCE kernel */
    int n = (int)(prolog_bytes / 4);
    if (n <= 0) { out_sp = sp; return 0; }
    if (n > MAX_PROLOG_INSTR) n = MAX_PROLOG_INSTR;

    uint32_t saved_lr = 0;
    bool found_lr = false;
    uint32_t cur_sp = sp;

    /* Read prologue instructions */
    uint32_t prolog[MAX_PROLOG_INSTR];
    for (int i = 0; i < n; i++)
        prolog[i] = mem.Read32(func_start + i * 4);

    /* Walk backwards, reversing each instruction's effect */
    for (int i = n - 1; i >= 0; i--) {
        uint32_t instr = prolog[i];

        if ((instr & STMDB_SP_MASK) == STMDB_SP_INST) {
            uint32_t reglist = instr & 0xFFFF;
            int n_regs = PopCount16(reglist);
            if (reglist & (1u << 14)) {
                int lr_slot = PopCount16(reglist & 0x3FFF);
                saved_lr = mem.Read32(cur_sp + lr_slot * 4);
                found_lr = true;
            }
            cur_sp += n_regs * 4;

        } else if ((instr & SUB_SP_IMM_MASK) == SUB_SP_IMM_INST) {
            cur_sp += DecodeArmImm(instr);

        } else if ((instr & SUB_SP_REG_MASK) == SUB_SP_REG_INST) {
            uint32_t rm = instr & 0xF;
            if (rm == 12) {
                for (int j = i - 1; j >= 0; j--) {
                    if ((prolog[j] & LDR_PC_MASK) == LDR_PC_INST) {
                        uint32_t offset = prolog[j] & 0xFFF;
                        uint32_t ldr_pc = func_start + j * 4 + 8;
                        cur_sp += mem.Read32(ldr_pc + offset);
                        break;
                    }
                }
            }

        } else if (instr == STR_LR_PUSH_INST) {
            saved_lr = mem.Read32(cur_sp);
            found_lr = true;
            cur_sp += 4;
        }
    }

    out_sp = cur_sp;
    return found_lr ? ((saved_lr & ~1u) - 4) : 0;
}

bool Win32Thunks::SehDispatch(uint32_t* regs, EmulatedMemory& mem,
    uint32_t exc_code, uint32_t exc_flags)
{
    uint32_t pc = regs[14];
    uint32_t sp = regs[13];
    constexpr int MAX_FRAMES = 16;

    LOG(API, "[SEH] Dispatch: code=0x%08X flags=0x%X pc=0x%08X sp=0x%08X\n",
        exc_code, exc_flags, pc, sp);

    for (int frame = 0; frame < MAX_FRAMES; frame++) {
        /* Find DLL containing pc */
        const LoadedDll* dll = nullptr;
        int32_t delta = 0;
        for (auto& [n, d] : loaded_dlls) {
            if (pc >= d.base_addr && pc < d.base_addr + d.pe_info.size_of_image) {
                dll = &d;
                delta = (int32_t)(d.base_addr - d.pe_info.image_base);
                break;
            }
        }
        if (!dll || !dll->pe_info.pdata_rva) {
            LOG(API, "[SEH] frame %d: pc=0x%08X not in any DLL with .pdata\n", frame, pc);
            break;
        }

        /* Binary search .pdata */
        uint32_t pdata_va = dll->base_addr + dll->pe_info.pdata_rva;
        uint32_t n_entries = dll->pe_info.pdata_size / 8;
        uint32_t lo = 0, hi = n_entries;
        bool found = false;
        uint32_t func_start = 0, prolog_bytes = 0;
        bool is_32bit = false;
        bool has_handler = false;
        uint32_t exc_handler = 0, handler_data = 0;

        while (lo < hi) {
            uint32_t mid = (lo + hi) / 2;
            uint32_t ea = pdata_va + mid * 8;
            uint32_t rs = mem.Read32(ea);
            uint32_t info = mem.Read32(ea + 4);
            is_32bit = (info >> 30) & 1;
            uint32_t fw = (info >> 8) & 0x3FFFFF;
            uint32_t ws = is_32bit ? 4 : 2;
            uint32_t fs = rs + delta, fe = fs + fw * ws;

            if (pc < fs) hi = mid;
            else if (pc >= fe) lo = mid + 1;
            else {
                func_start = fs;
                prolog_bytes = (info & 0xFF) * ws;
                has_handler = (info >> 31) & 1;
                if (has_handler) {
                    uint32_t eh = fs - 8;
                    uint32_t rh = mem.Read32(eh), rd = mem.Read32(eh + 4);
                    uint32_t ib = dll->pe_info.image_base;
                    uint32_t ie = ib + dll->pe_info.size_of_image;
                    exc_handler = (rh >= ib && rh < ie) ? rh + delta : rh;
                    handler_data = (rd >= ib && rd < ie) ? rd + delta : rd;
                }
                found = true;
                break;
            }
        }

        if (!found) {
            LOG(API, "[SEH] frame %d: pc=0x%08X not in .pdata, can't unwind\n", frame, pc);
            break;
        }

        /* FATAL: Thumb function unwinding not implemented.
           Thumb uses 16-bit instructions with completely different encodings.
           Need ThumbVirtualUnwind (see WinCE kernel ARM/unwind.c). */
        if (!is_32bit) {
            LOG(API, "\n[FATAL] SEH: Thumb function at 0x%08X needs ThumbVirtualUnwind "
                "(not implemented). Exception 0x%08X cannot be dispatched.\n"
                "  Implement ThumbVirtualUnwind in seh_dispatch.cpp\n",
                func_start, exc_code);
            CerfFatalExit(1);
        }

        LOG(API, "[SEH] frame %d: pc=0x%08X func=0x%08X prolog=%u handler=%d\n",
            frame, pc, func_start, prolog_bytes, has_handler);

        /* Check scope table if function has exception handler */
        if (has_handler && handler_data) {
            uint32_t count = mem.Read32(handler_data);
            for (uint32_t i = 0; i < count && i < 100; i++) {
                uint32_t rec = handler_data + 4 + i * 16;
                uint32_t tb = mem.Read32(rec) + delta;
                uint32_t te = mem.Read32(rec + 4) + delta;
                uint32_t filt = mem.Read32(rec + 8);
                uint32_t jump = mem.Read32(rec + 12);
                if (pc < tb || pc >= te || jump == 0) continue;

                uint32_t filt_rt = filt ? filt + delta : 0;
                uint32_t jump_rt = jump + delta;

                /* Call filter expression via ARM callback */
                if (filt_rt && callback_executor) {
                    uint32_t args[1] = { exc_code };
                    int32_t disp = (int32_t)callback_executor(filt_rt, args, 1);
                    LOG(API, "[SEH] filter@0x%08X returned %d\n", filt_rt, disp);
                    if (disp == 0) continue;       /* EXCEPTION_CONTINUE_SEARCH */
                    if (disp == -1) return false;   /* EXCEPTION_CONTINUE_EXECUTION */

                    /* FATAL: filter returned unexpected value. A filter that
                       inspects exception details (GetExceptionInformation) may
                       return garbage because we don't build EXCEPTION_POINTERS
                       in ARM memory. */
                    if (disp != 1) {
                        LOG(API, "\n[FATAL] SEH: filter@0x%08X returned unexpected "
                            "disposition %d (expected 0, 1, or -1).\n"
                            "  This may indicate the filter needs EXCEPTION_POINTERS "
                            "(not yet implemented).\n", filt_rt, disp);
                        CerfFatalExit(1);
                    }
                }

                /* Handler matched. __except runs in THIS function's frame. */
                LOG(API, "[SEH] Exception 0x%08X handled: pc=0x%08X -> "
                    "jump=0x%08X sp=0x%08X (frame %d)\n",
                    exc_code, pc, jump_rt, sp, frame);
                regs[15] = jump_rt;
                regs[13] = sp;
                regs[0] = exc_code;
                return true;
            }
        }

        /* No handler in this frame — unwind to caller */
        uint32_t caller_sp;
        uint32_t next_pc = UnwindFrame(mem, func_start, prolog_bytes, sp, caller_sp);
        if (!next_pc) {
            LOG(API, "[SEH] frame %d: UnwindFrame failed (no saved LR), "
                "func=0x%08X prolog=%u\n", frame, func_start, prolog_bytes);
            break;
        }
        LOG(API, "[SEH] frame %d: unwound -> next_pc=0x%08X sp=0x%08X\n",
            frame, next_pc, caller_sp);
        pc = next_pc;
        sp = caller_sp;
    }

    LOG(API, "[SEH] Dispatch FAILED: no handler found for exception 0x%08X\n", exc_code);
    return false;
}
