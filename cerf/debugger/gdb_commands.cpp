/* GDB RSP command handlers — register, memory, breakpoint, control.
   Thread-aware: uses current_cpu (selected via Hg) for register access.
   Dispatched from GdbStub::Poll() when any CPU is stopped. */
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "gdb_stub.h"
#include "../cpu/arm_cpu.h"
#include "../cpu/mem.h"
#include "../log.h"

/* Maximum bytes per memory read packet */
constexpr uint32_t GDB_MAX_MEM_READ = 0x2000;

void GdbStub::HandlePacket(const std::string& pkt) {
    if (pkt.empty()) return;
    char cmd = pkt[0];
    std::string args = pkt.substr(1);

    switch (cmd) {
    case '?': SendStopReply(); break;
    case 'g': HandleReadRegisters(); break;
    case 'G': HandleWriteRegisters(args); break;
    case 'p': HandleReadRegister(args); break;
    case 'P': HandleWriteRegister(args); break;
    case 'm': HandleReadMemory(args); break;
    case 'M': HandleWriteMemory(args); break;
    case 'Z': HandleBreakpoint(args, true); break;
    case 'z': HandleBreakpoint(args, false); break;
    case 'c': HandleContinue(); break;
    case 's': HandleStep(); break;
    case 'H': HandleThreadSelect(args); break;
    case 'D':  /* Detach */
        SendPacket("OK");
        connected = false;
        ResumeAll();
        LOG(DBG, "[GDB] Client detached\n");
        break;
    case 'k':  /* Kill */
        connected = false;
        ResumeAll();
        LOG(DBG, "[GDB] Kill requested\n");
        CerfFatalExit(0);
        break;
    case 'q': HandleQuery(pkt); break;
    case 'v':
        if (pkt == "vCont?") {
            SendPacket("vCont;c;s");
        } else if (pkt.substr(0, 6) == "vCont;") {
            char action = pkt[6];
            if (action == 'c') HandleContinue();
            else if (action == 's') HandleStep();
            else SendPacket("");
        } else {
            SendPacket("");
        }
        break;
    default:
        SendPacket("");  /* Unsupported command */
        break;
    }
}

void GdbStub::HandleQuery(const std::string& pkt) {
    if (pkt.substr(0, 10) == "qSupported") {
        SendPacket("PacketSize=4000;QStartNoAckMode+;vContSupported+");
    } else if (pkt == "qAttached") {
        SendPacket("1");
    } else if (pkt == "qC") {
        /* Report current thread ID */
        uint32_t tid = 1;
        {
            std::lock_guard<std::mutex> lock(registry_mutex);
            for (auto& t : threads)
                if (t.cpu == current_cpu) { tid = t.tid; break; }
        }
        char buf[16];
        snprintf(buf, sizeof(buf), "QC%x", tid);
        SendPacket(buf);
    } else if (pkt == "qfThreadInfo") {
        /* First thread info query — return all thread IDs */
        std::string reply = "m";
        {
            std::lock_guard<std::mutex> lock(registry_mutex);
            for (size_t i = 0; i < threads.size(); i++) {
                if (i > 0) reply += ",";
                char buf[16];
                snprintf(buf, sizeof(buf), "%x", threads[i].tid);
                reply += buf;
            }
        }
        if (reply == "m") reply = "m1"; /* fallback if no threads registered */
        SendPacket(reply);
    } else if (pkt == "qsThreadInfo") {
        SendPacket("l");  /* end of thread list */
    } else if (pkt == "qTStatus") {
        SendPacket("");
    } else if (pkt == "QStartNoAckMode") {
        no_ack_mode = true;
        SendPacket("OK");
    } else if (pkt == "qOffsets") {
        SendPacket("Text=0;Data=0;Bss=0");
    } else {
        SendPacket("");
    }
}

/* ---- Thread selection ---- */

void GdbStub::HandleThreadSelect(const std::string& args) {
    /* H<op><thread-id>  where op='g' (register reads) or 'c' (continue/step)
       thread-id: hex, 0 = any, -1 = all */
    if (args.empty()) { SendPacket("OK"); return; }
    /* Skip the operation char ('g' or 'c') */
    std::string tid_str = args.substr(1);
    int32_t tid = (int32_t)HexToU32(tid_str);

    if (tid <= 0) {
        /* 0 = pick any, -1 = all threads — keep current */
        SendPacket("OK");
        return;
    }

    std::lock_guard<std::mutex> lock(registry_mutex);
    ArmCpu* found = FindCpuByTid((uint32_t)tid);
    if (found) {
        current_cpu = found;
        LOG(DBG, "[GDB] Thread selected: tid=%d, PC=0x%08X\n",
            tid, found->r[REG_PC]);
    }
    SendPacket("OK");
}

/* ---- Register access (uses current_cpu) ---- */

void GdbStub::HandleReadRegisters() {
    if (!current_cpu) { SendPacket("E01"); return; }
    /* ARM 'g' packet: r0-r15 then cpsr, each 4 bytes little-endian hex. */
    std::string hex;
    hex.reserve(GDB_ARM_NUM_REGS * 8);
    for (int i = 0; i < 16; i++)
        hex += U32ToHexLE(current_cpu->r[i]);
    hex += U32ToHexLE(current_cpu->cpsr);
    SendPacket(hex);
}

void GdbStub::HandleWriteRegisters(const std::string& data) {
    if (!current_cpu) { SendPacket("E01"); return; }
    constexpr size_t MIN_LEN = GDB_ARM_NUM_REGS * 8;
    if (data.size() < MIN_LEN) { SendPacket("E01"); return; }
    uint8_t bytes[4];
    for (int i = 0; i < 16; i++) {
        FromHex(data.substr(i * 8, 8), bytes, 4);
        current_cpu->r[i] = bytes[0] | (bytes[1] << 8) |
                    (bytes[2] << 16) | (bytes[3] << 24);
    }
    FromHex(data.substr(16 * 8, 8), bytes, 4);
    current_cpu->cpsr = bytes[0] | (bytes[1] << 8) |
                (bytes[2] << 16) | (bytes[3] << 24);
    SendPacket("OK");
}

void GdbStub::HandleReadRegister(const std::string& args) {
    if (!current_cpu) { SendPacket("E01"); return; }
    uint32_t reg = HexToU32(args);
    uint32_t val;
    if (reg < 16)
        val = current_cpu->r[reg];
    else if (reg == 25 || reg == 16)
        val = current_cpu->cpsr;
    else {
        SendPacket("E01");
        return;
    }
    SendPacket(U32ToHexLE(val));
}

void GdbStub::HandleWriteRegister(const std::string& args) {
    if (!current_cpu) { SendPacket("E01"); return; }
    size_t eq = args.find('=');
    if (eq == std::string::npos) { SendPacket("E01"); return; }
    uint32_t reg = HexToU32(args.substr(0, eq));
    uint8_t bytes[4];
    FromHex(args.substr(eq + 1), bytes, 4);
    uint32_t val = bytes[0] | (bytes[1] << 8) |
                   (bytes[2] << 16) | (bytes[3] << 24);
    if (reg < 16)
        current_cpu->r[reg] = val;
    else if (reg == 25 || reg == 16)
        current_cpu->cpsr = val;
    else {
        SendPacket("E01");
        return;
    }
    SendPacket("OK");
}

/* ---- Memory access ---- */

void GdbStub::HandleReadMemory(const std::string& args) {
    size_t comma = args.find(',');
    if (comma == std::string::npos) { SendPacket("E01"); return; }
    uint32_t addr = HexToU32(args.substr(0, comma));
    uint32_t len = HexToU32(args.substr(comma + 1));
    if (len > GDB_MAX_MEM_READ) len = GDB_MAX_MEM_READ;

    std::string hex;
    hex.reserve(len * 2);
    for (uint32_t i = 0; i < len; i++) {
        uint8_t* ptr = mem->Translate(addr + i);
        uint8_t byte = ptr ? *ptr : 0;
        hex += ToHex(&byte, 1);
    }
    SendPacket(hex);
}

void GdbStub::HandleWriteMemory(const std::string& args) {
    size_t comma = args.find(',');
    size_t colon = args.find(':');
    if (comma == std::string::npos || colon == std::string::npos) {
        SendPacket("E01");
        return;
    }
    uint32_t addr = HexToU32(args.substr(0, comma));
    uint32_t len = HexToU32(args.substr(comma + 1, colon - comma - 1));
    std::string hex_data = args.substr(colon + 1);
    for (uint32_t i = 0; i < len && (i * 2 + 1) < hex_data.size(); i++) {
        uint8_t byte;
        FromHex(hex_data.substr(i * 2, 2), &byte, 1);
        mem->Write8(addr + i, byte);
    }
    SendPacket("OK");
}

/* ---- Breakpoints ---- */

void GdbStub::HandleBreakpoint(const std::string& args, bool set) {
    /* Format: type,addr,kind */
    size_t c1 = args.find(',');
    if (c1 == std::string::npos) { SendPacket("E01"); return; }
    uint32_t type = HexToU32(args.substr(0, c1));
    size_t c2 = args.find(',', c1 + 1);
    std::string addr_str = (c2 != std::string::npos)
        ? args.substr(c1 + 1, c2 - c1 - 1)
        : args.substr(c1 + 1);
    uint32_t addr = HexToU32(addr_str);

    if (type != 0) {
        /* Only software breakpoints (type 0) for now */
        SendPacket("");
        return;
    }
    if (set) AddBreakpoint(addr);
    else RemoveBreakpoint(addr);
    SendPacket("OK");
}

/* ---- Execution control ---- */

void GdbStub::HandleContinue() {
    single_step_cpu.store(nullptr);
    ResumeAll();
    /* No reply now — stop reply sent when next breakpoint/step completes */
}

void GdbStub::HandleStep() {
    /* Single-step the current (selected) CPU only */
    single_step_cpu.store(current_cpu);
    ResumeAll();
}
