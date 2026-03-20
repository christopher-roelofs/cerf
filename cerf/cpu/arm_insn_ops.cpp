/* ARM mode instruction implementations — memory, branch, and control operations.
   Split from arm_insn.cpp which has ExecuteArm dispatch and ArmDataProcessing. */
#include "arm_cpu.h"
#include "../log.h"

void ArmCpu::ArmMultiply(uint32_t insn) {
    bool A = (insn >> 21) & 1;  /* Accumulate */
    bool S = (insn >> 20) & 1;
    uint32_t rd = (insn >> 16) & 0xF;
    uint32_t rn = (insn >> 12) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    uint32_t rm = insn & 0xF;

    uint32_t result = r[rm] * r[rs];
    if (A) result += r[rn];

    r[rd] = result;
    if (S) SetNZ(result);
}

void ArmCpu::ArmMultiplyLong(uint32_t insn) {
    bool U = (insn >> 22) & 1;  /* Unsigned (0) / Signed (1) */
    bool A = (insn >> 21) & 1;
    bool S = (insn >> 20) & 1;
    uint32_t rdhi = (insn >> 16) & 0xF;
    uint32_t rdlo = (insn >> 12) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    uint32_t rm = insn & 0xF;

    uint64_t result;
    if (U) {
        result = (int64_t)(int32_t)r[rm] * (int64_t)(int32_t)r[rs];
    } else {
        result = (uint64_t)r[rm] * (uint64_t)r[rs];
    }

    if (A) {
        result += ((uint64_t)r[rdhi] << 32) | r[rdlo];
    }

    r[rdhi] = (uint32_t)(result >> 32);
    r[rdlo] = (uint32_t)result;

    if (S) {
        SetN((result >> 63) & 1);
        SetZ(result == 0);
    }
}

void ArmCpu::ArmSingleDataTransfer(uint32_t insn) {
    bool I = (insn >> 25) & 1;  /* Immediate offset (0) / Register (1) */
    bool P = (insn >> 24) & 1;  /* Pre/Post indexing */
    bool U = (insn >> 23) & 1;  /* Up/Down */
    bool B = (insn >> 22) & 1;  /* Byte/Word */
    bool W = (insn >> 21) & 1;  /* Write-back */
    bool L = (insn >> 20) & 1;  /* Load/Store */
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;

    uint32_t offset;
    if (!I) {
        offset = insn & 0xFFF;
    } else {
        uint32_t rm = insn & 0xF;
        uint32_t shift_type = (insn >> 5) & 3;
        uint32_t shift_amount = (insn >> 7) & 0x1F;
        bool dummy;
        offset = BarrelShift(r[rm], shift_type, shift_amount, dummy, false);
    }

    uint32_t base = r[rn];
    if (rn == REG_PC) base += 4;

    uint32_t addr;
    if (P) {
        addr = U ? base + offset : base - offset;
    } else {
        addr = base;
    }

    /* Check for thunk addresses */
    if (L && thunk_handler) {
        uint32_t load_addr = addr;
        if (mem->IsValid(load_addr)) {
            /* Check what we're loading - might be a thunk pointer */
        }
    }

    if (L) {
        /* Load */
        if (B) {
            r[rd] = mem->Read8(addr);
        } else {
            uint32_t val = mem->Read32(addr & ~3u);
            /* Handle unaligned reads via rotation */
            uint32_t misalign = addr & 3;
            if (misalign) {
                val = (val >> (misalign * 8)) | (val << (32 - misalign * 8));
            }
            r[rd] = val;
        }
        if (rd == REG_PC) {
            /* Branch via load (e.g. LDR PC, [Rn]) - check thunk handler */
            uint32_t target = r[REG_PC];
            if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
                return;
            }
            if (target & 1) {
                cpsr |= PSR_T;
                r[REG_PC] = target & ~1u;
            } else {
                r[REG_PC] = target & ~3u;
            }
        }
    } else {
        /* Store */
        uint32_t val = r[rd];
        if (rd == REG_PC) val += 4;
        if (B) {
            mem->Write8(addr, (uint8_t)val);
        } else {
            mem->Write32(addr & ~3u, val);
        }
    }

    /* Write-back / post-index */
    if (!P) {
        uint32_t new_base = U ? base + offset : base - offset;
        r[rn] = new_base;
    } else if (W) {
        r[rn] = addr;
    }
}

void ArmCpu::ArmHalfwordTransfer(uint32_t insn) {
    bool P = (insn >> 24) & 1;
    bool U = (insn >> 23) & 1;
    bool I = (insn >> 22) & 1;
    bool W = (insn >> 21) & 1;
    bool L = (insn >> 20) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t sh = (insn >> 5) & 3;

    uint32_t offset;
    if (I) {
        offset = ((insn >> 4) & 0xF0) | (insn & 0xF);
    } else {
        offset = r[insn & 0xF];
    }

    uint32_t base = r[rn];
    if (rn == REG_PC) base += 4;

    uint32_t addr;
    if (P) {
        addr = U ? base + offset : base - offset;
    } else {
        addr = base;
    }

    if (L) {
        switch (sh) {
        case 1: /* LDRH */
            r[rd] = mem->Read16(addr);
            break;
        case 2: /* LDRSB */
            r[rd] = (int32_t)(int8_t)mem->Read8(addr);
            break;
        case 3: /* LDRSH */
            r[rd] = (int32_t)(int16_t)mem->Read16(addr);
            break;
        }
    } else {
        switch (sh) {
        case 1: /* STRH */
            mem->Write16(addr, (uint16_t)r[rd]);
            break;
        case 2: /* LDRD (ARMv5) - load doubleword */
            r[rd] = mem->Read32(addr);
            r[rd + 1] = mem->Read32(addr + 4);
            break;
        case 3: /* STRD (ARMv5) - store doubleword */
            mem->Write32(addr, r[rd]);
            mem->Write32(addr + 4, r[rd + 1]);
            break;
        }
    }

    if (!P) {
        r[rn] = U ? base + offset : base - offset;
    } else if (W) {
        r[rn] = addr;
    }
}

void ArmCpu::ArmBlockDataTransfer(uint32_t insn) {
    bool P = (insn >> 24) & 1;  /* Pre/Post */
    bool U = (insn >> 23) & 1;  /* Up/Down */
    bool S = (insn >> 22) & 1;  /* PSR / force user */
    bool W = (insn >> 21) & 1;  /* Write-back */
    bool L = (insn >> 20) & 1;  /* Load/Store */
    uint32_t rn = (insn >> 16) & 0xF;
    uint16_t reg_list = insn & 0xFFFF;

    uint32_t base = r[rn];
    int count = 0;
    for (int i = 0; i < 16; i++) {
        if (reg_list & (1 << i)) count++;
    }

    uint32_t addr;
    uint32_t writeback_val;

    if (U) {
        addr = P ? base + 4 : base;
        writeback_val = base + count * 4;
    } else {
        addr = P ? base - count * 4 : base - count * 4 + 4;
        writeback_val = base - count * 4;
    }

    for (int i = 0; i < 16; i++) {
        if (!(reg_list & (1 << i))) continue;

        if (L) {
            r[i] = mem->Read32(addr);
            if (i == REG_PC) {
                if (S) cpsr = spsr;  /* LDMFD with S bit = exception return */
                if (r[REG_PC] & 1) {
                    cpsr |= PSR_T;
                    r[REG_PC] &= ~1u;
                } else {
                    r[REG_PC] &= ~3u;
                }
            }
        } else {
            uint32_t val = r[i];
            if (i == REG_PC) val += 4;
            mem->Write32(addr, val);
        }
        addr += 4;
    }

    if (W) r[rn] = writeback_val;
}

void ArmCpu::ArmBranch(uint32_t insn) {
    bool link = (insn >> 24) & 1;
    int32_t offset = (int32_t)(insn << 8) >> 6; /* Sign-extend 24-bit offset, shift left 2 */

    if (link) {
        r[REG_LR] = r[REG_PC]; /* Return address (PC already advanced by 4) */
    }

    uint32_t target = r[REG_PC] + 4 + offset; /* +4 because ARM PC is 2 instructions ahead */

    /* Check for thunk */
    if (thunk_handler && thunk_handler(target, r, *mem)) {
        return;
    }

    r[REG_PC] = target;
}

void ArmCpu::ArmBranchExchange(uint32_t insn) {
    uint32_t rm = insn & 0xF;
    uint32_t target = r[rm];

    /* Check for thunk */
    if (thunk_handler && thunk_handler(target & ~1u, r, *mem)) {
        return;
    }

    if (target & 1) {
        cpsr |= PSR_T;
        r[REG_PC] = target & ~1u;
    } else {
        cpsr &= ~PSR_T;
        r[REG_PC] = target & ~3u;
    }
}

void ArmCpu::ArmSwap(uint32_t insn) {
    bool B = (insn >> 22) & 1;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t rm = insn & 0xF;

    uint32_t addr = r[rn];
    if (B) {
        uint8_t tmp = mem->Read8(addr);
        mem->Write8(addr, (uint8_t)r[rm]);
        r[rd] = tmp;
    } else {
        uint32_t tmp = mem->Read32(addr);
        mem->Write32(addr, r[rm]);
        r[rd] = tmp;
    }
}

void ArmCpu::ArmSoftwareInterrupt(uint32_t insn) {
    uint32_t swi_num = insn & 0x00FFFFFF;
    LOG(CPU, "[ARM] SWI #0x%X at PC=0x%08X\n", swi_num, r[REG_PC] - 4);

    /* Windows CE uses SWI for system calls - we handle these through thunks */
    if (thunk_handler) {
        /* Pass SWI number encoded as a special address */
        uint32_t swi_addr = 0xFFFF0000 | swi_num;
        if (thunk_handler(swi_addr, r, *mem)) return;
    }

    halted = true;
    halt_code = 2;
}

void ArmCpu::ArmMRS(uint32_t insn) {
    bool R = (insn >> 22) & 1; /* SPSR (1) or CPSR (0) */
    uint32_t rd = (insn >> 12) & 0xF;
    r[rd] = R ? spsr : cpsr;
}

void ArmCpu::ArmMSR(uint32_t insn) {
    bool R = (insn >> 22) & 1;
    bool I = (insn >> 25) & 1;

    uint32_t val;
    if (I) {
        uint32_t imm = insn & 0xFF;
        uint32_t rot = ((insn >> 8) & 0xF) * 2;
        val = (imm >> rot) | (imm << (32 - rot));
    } else {
        val = r[insn & 0xF];
    }

    /* Field mask */
    uint32_t mask = 0;
    if (insn & (1 << 16)) mask |= 0x000000FF; /* control */
    if (insn & (1 << 17)) mask |= 0x0000FF00; /* extension */
    if (insn & (1 << 18)) mask |= 0x00FF0000; /* status */
    if (insn & (1 << 19)) mask |= 0xFF000000; /* flags */

    if (R) {
        spsr = (spsr & ~mask) | (val & mask);
    } else {
        cpsr = (cpsr & ~mask) | (val & mask);
    }
}

void ArmCpu::ArmCLZ(uint32_t insn) {
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t rm = insn & 0xF;
    uint32_t val = r[rm];

    if (val == 0) {
        r[rd] = 32;
    } else {
        uint32_t count = 0;
        while (!(val & 0x80000000)) { val <<= 1; count++; }
        r[rd] = count;
    }
}
