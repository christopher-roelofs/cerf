/* ARM mode instruction implementations */
#include "arm_cpu.h"
#include "../log.h"
#include <cstdlib>

void ArmCpu::ExecuteArm(uint32_t insn) {
    uint32_t cond = (insn >> 28) & 0xF;

    if (!CheckCondition(cond)) return;

    uint32_t op = (insn >> 20) & 0xFF;
    uint32_t bits7_4 = (insn >> 4) & 0xF;

    /* Decode ARM instruction classes */

    /* Branch and Exchange (BX, BLX) */
    if ((insn & 0x0FFFFFF0) == 0x012FFF10) {
        ArmBranchExchange(insn);
        return;
    }

    /* BLX register (ARMv5) */
    if ((insn & 0x0FFFFFF0) == 0x012FFF30) {
        uint32_t rm = insn & 0xF;
        uint32_t target = r[rm];
        r[REG_LR] = r[REG_PC]; /* PC already advanced by 4 */

        /* Check for thunk */
        if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
            return;
        }

        if (target & 1) {
            cpsr |= PSR_T;
            r[REG_PC] = target & ~1u;
        } else {
            r[REG_PC] = target & ~3u;
        }
        return;
    }

    /* CLZ (ARMv5) */
    if ((insn & 0x0FFF0FF0) == 0x016F0F10) {
        ArmCLZ(insn);
        return;
    }

    /* Multiply */
    if ((insn & 0x0FC000F0) == 0x00000090) {
        ArmMultiply(insn);
        return;
    }

    /* Multiply Long */
    if ((insn & 0x0F8000F0) == 0x00800090) {
        ArmMultiplyLong(insn);
        return;
    }

    /* Swap */
    if ((insn & 0x0FB00FF0) == 0x01000090) {
        ArmSwap(insn);
        return;
    }

    /* Halfword / signed byte transfers */
    if (((insn & 0x0E000090) == 0x00000090) && ((bits7_4 & 0x9) == 0x9) && (bits7_4 != 0x9)) {
        ArmHalfwordTransfer(insn);
        return;
    }

    /* MRS */
    if ((insn & 0x0FBF0FFF) == 0x010F0000) {
        ArmMRS(insn);
        return;
    }

    /* MSR (register) */
    if ((insn & 0x0FB0FFF0) == 0x0120F000) {
        ArmMSR(insn);
        return;
    }

    /* MSR (immediate) */
    if ((insn & 0x0FB0F000) == 0x0320F000) {
        ArmMSR(insn);
        return;
    }

    /* Data processing */
    if ((insn & 0x0C000000) == 0x00000000) {
        ArmDataProcessing(insn);
        return;
    }

    /* Undefined instruction / SWBKPT (WinCE __debugbreak):
       bits [27:25] = 011 with bit [4] = 1 is architecturally undefined.
       WinCE uses 0xE6000010 (and similar) as a software breakpoint.
       Log a warning and treat as NOP — do NOT fall through to LDR/STR. */
    if ((insn & 0x0E000010) == 0x06000010) {
        LOG(CPU, "[ARM] Undefined instruction (SWBKPT) 0x%08X at PC=0x%08X — treating as NOP\n",
            insn, r[REG_PC] - 4);
        return;
    }

    /* Single data transfer (LDR/STR) */
    if ((insn & 0x0C000000) == 0x04000000) {
        ArmSingleDataTransfer(insn);
        return;
    }

    /* Block data transfer (LDM/STM) */
    if ((insn & 0x0E000000) == 0x08000000) {
        ArmBlockDataTransfer(insn);
        return;
    }

    /* Branch / Branch with Link */
    if ((insn & 0x0E000000) == 0x0A000000) {
        ArmBranch(insn);
        return;
    }

    /* Software Interrupt */
    if ((insn & 0x0F000000) == 0x0F000000) {
        ArmSoftwareInterrupt(insn);
        return;
    }

    /* Coprocessor / undefined */
    LOG_ERR("[ARM] Unhandled instruction: 0x%08X at PC=0x%08X\n", insn, r[REG_PC] - 4);
    LOG_ERR("[ARM]   R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X\n", r[0], r[1], r[2], r[3]);
    LOG_ERR("[ARM]   R4=0x%08X R5=0x%08X R12=0x%08X LR=0x%08X SP=0x%08X\n",
            r[4], r[5], r[12], r[REG_LR], r[REG_SP]);
    /* Dump memory at R0 (likely 'this' pointer for vtable crash) */
    if (r[0] && mem) {
        uint8_t* p = mem->Translate(r[0]);
        if (p) {
            uint32_t vtbl = *(uint32_t*)p;
            LOG_ERR("[ARM]   [R0]=0x%08X [R0+4]=0x%08X [R0+8]=0x%08X\n",
                    vtbl, mem->Read32(r[0]+4), mem->Read32(r[0]+8));
            if (vtbl) {
                uint8_t* vp = mem->Translate(vtbl);
                LOG_ERR("[ARM]   vtable at host %p (slot=%p)\n", vp, EmulatedMemory::process_slot);
                if (vp)
                    LOG_ERR("[ARM]   vtable[0]=0x%08X vtable[1]=0x%08X vtable[2]=0x%08X\n",
                            mem->Read32(vtbl), mem->Read32(vtbl+4), mem->Read32(vtbl+8));
            }
        }
    }
    halted = true;
    halt_code = 1;
}

void ArmCpu::ArmDataProcessing(uint32_t insn) {
    uint32_t opcode = (insn >> 21) & 0xF;
    bool S = (insn >> 20) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    bool I = (insn >> 25) & 1;

    uint32_t op2;
    bool shifter_carry = GetC();

    if (I) {
        /* Immediate operand */
        uint32_t imm = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        op2 = (imm >> rot) | (imm << (32 - rot));
        if (rot != 0) {
            shifter_carry = (op2 >> 31) & 1;
        }
    } else {
        /* Register operand with shift */
        uint32_t rm = insn & 0xF;
        uint32_t shift_type = (insn >> 5) & 3;
        uint32_t shift_amount;
        bool reg_shift = (insn >> 4) & 1;

        uint32_t rm_val = r[rm];
        if (rm == REG_PC) rm_val += 4; /* PC ahead in register shift */

        if (reg_shift) {
            uint32_t rs = (insn >> 8) & 0xF;
            shift_amount = r[rs] & 0xFF;
        } else {
            shift_amount = (insn >> 7) & 0x1F;
        }
        op2 = BarrelShift(rm_val, shift_type, shift_amount, shifter_carry, reg_shift);
    }

    uint32_t rn_val = r[rn];
    if (rn == REG_PC) rn_val += 4; /* PC is ahead */

    uint32_t result = 0;
    bool write_rd = true;
    bool logic_op = false;

    switch (opcode) {
    case 0x0: /* AND */
        result = rn_val & op2;
        logic_op = true;
        break;
    case 0x1: /* EOR */
        result = rn_val ^ op2;
        logic_op = true;
        break;
    case 0x2: /* SUB */
        result = rn_val - op2;
        break;
    case 0x3: /* RSB */
        result = op2 - rn_val;
        break;
    case 0x4: /* ADD */
        result = rn_val + op2;
        break;
    case 0x5: /* ADC */
        result = rn_val + op2 + (GetC() ? 1 : 0);
        break;
    case 0x6: /* SBC */
        result = rn_val - op2 - (GetC() ? 0 : 1);
        break;
    case 0x7: /* RSC */
        result = op2 - rn_val - (GetC() ? 0 : 1);
        break;
    case 0x8: /* TST */
        result = rn_val & op2;
        write_rd = false;
        logic_op = true;
        break;
    case 0x9: /* TEQ */
        result = rn_val ^ op2;
        write_rd = false;
        logic_op = true;
        break;
    case 0xA: /* CMP */
        result = rn_val - op2;
        write_rd = false;
        break;
    case 0xB: /* CMN */
        result = rn_val + op2;
        write_rd = false;
        break;
    case 0xC: /* ORR */
        result = rn_val | op2;
        logic_op = true;
        break;
    case 0xD: /* MOV */
        result = op2;
        logic_op = true;
        break;
    case 0xE: /* BIC */
        result = rn_val & ~op2;
        logic_op = true;
        break;
    case 0xF: /* MVN */
        result = ~op2;
        logic_op = true;
        break;
    }

    if (S) {
        if (rd == REG_PC) {
            /* MOVS PC, LR => exception return */
            cpsr = spsr;
        } else {
            SetN((result >> 31) & 1);
            SetZ(result == 0);

            if (logic_op) {
                SetC(shifter_carry);
            } else {
                /* Arithmetic flags */
                switch (opcode) {
                case 0x2: /* SUB */
                case 0xA: /* CMP */
                    SetC(rn_val >= op2);
                    SetV(((rn_val ^ op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x3: /* RSB */
                    SetC(op2 >= rn_val);
                    SetV(((op2 ^ rn_val) & (op2 ^ result)) >> 31);
                    break;
                case 0x4: /* ADD */
                case 0xB: /* CMN */
                    SetC(result < rn_val);
                    SetV(((rn_val ^ ~op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x5: /* ADC */ {
                    uint64_t full = (uint64_t)rn_val + op2 + (GetC() ? 1 : 0);
                    SetC(full > 0xFFFFFFFF);
                    SetV(((rn_val ^ ~op2) & (rn_val ^ result)) >> 31);
                    break;
                }
                case 0x6: /* SBC */
                    SetC((uint64_t)rn_val >= (uint64_t)op2 + (GetC() ? 0 : 1));
                    SetV(((rn_val ^ op2) & (rn_val ^ result)) >> 31);
                    break;
                case 0x7: /* RSC */
                    SetC((uint64_t)op2 >= (uint64_t)rn_val + (GetC() ? 0 : 1));
                    SetV(((op2 ^ rn_val) & (op2 ^ result)) >> 31);
                    break;
                }
            }
        }
    }

    if (write_rd) {
        r[rd] = result;
        if (rd == REG_PC) {
            /* Branch via data processing (e.g. MOV PC, Rm) - check thunk handler */
            uint32_t target = result;
            if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
                return;
            }
            /* Normal branch - check for Thumb interwork */
            if (target & 1) {
                cpsr |= PSR_T;
                r[REG_PC] = target & ~1u;
            } else {
                r[REG_PC] = target & ~3u;
            }
        }
    }
}

/* Remaining ARM instruction handlers (multiply, load/store, branch, control)
   are in arm_insn_ops.cpp */
