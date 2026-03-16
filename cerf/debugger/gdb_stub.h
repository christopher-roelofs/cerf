#pragma once
/* GDB Remote Serial Protocol stub for ARM debugging.
   Listens on a TCP port, pauses the CPU at breakpoints,
   and lets GDB/IDA clients inspect and control execution. */
#include <cstdint>
#include <set>
#include <string>
/* Avoid including winsock2.h here — it conflicts with windows.h inclusion
   order in other translation units.  SOCKET is UINT_PTR on Windows. */
typedef uintptr_t GdbSocket;
constexpr GdbSocket GDB_INVALID_SOCKET = (GdbSocket)(~0);

class ArmCpu;
class EmulatedMemory;

/* Stop reasons sent to the GDB client (GDB signal numbers) */
enum class GdbSignal : uint8_t {
    NONE      = 0,
    SIGINT    = 2,   /* Ctrl+C interrupt */
    SIGTRAP   = 5,   /* Breakpoint / single-step */
};

constexpr uint16_t GDB_DEFAULT_PORT = 1234;
constexpr int GDB_ARM_NUM_REGS = 17;  /* r0-r15 + cpsr */
/* Periodic Ctrl+C check interval (every 65536 instructions) */
constexpr uint64_t GDB_INTERRUPT_CHECK_MASK = 0xFFFF;

class GdbStub {
public:
    GdbStub(uint16_t port, ArmCpu* cpu, EmulatedMemory* mem);
    ~GdbStub();

    /* Start listening and wait for a client. Blocks until connected.
       Returns false on bind/listen failure. */
    bool Start();

    /* Called from ArmCpu::Step() before each instruction.
       Fast-path returns immediately when running with no breakpoints.
       Blocks in command loop when stopped at a breakpoint. */
    void Poll();

    /* Check if a specific address has a breakpoint */
    bool HasBreakpoint(uint32_t addr) const;
    void AddBreakpoint(uint32_t addr);
    void RemoveBreakpoint(uint32_t addr);

private:
    ArmCpu* cpu;
    EmulatedMemory* mem;
    uint16_t port;

    GdbSocket listen_sock = GDB_INVALID_SOCKET;
    GdbSocket client_sock = GDB_INVALID_SOCKET;
    bool connected = false;
    bool stopped = true;   /* Start stopped so client can set breakpoints */
    bool single_step = false;
    bool no_ack_mode = false;
    GdbSignal stop_signal = GdbSignal::SIGTRAP;

    std::set<uint32_t> breakpoints;

    /* TCP + RSP packet I/O */
    bool WaitForClient();
    std::string RecvPacket();
    void SendPacket(const std::string& data);
    void SendStopReply();
    bool HasPendingData();

    /* Command dispatch + handlers (in gdb_commands.cpp) */
    void HandlePacket(const std::string& pkt);
    void HandleQuery(const std::string& pkt);
    void HandleReadRegisters();
    void HandleWriteRegisters(const std::string& data);
    void HandleReadRegister(const std::string& args);
    void HandleWriteRegister(const std::string& args);
    void HandleReadMemory(const std::string& args);
    void HandleWriteMemory(const std::string& args);
    void HandleBreakpoint(const std::string& args, bool set);
    void HandleContinue();
    void HandleStep();

    /* Hex encoding helpers */
    static std::string ToHex(const uint8_t* data, size_t len);
    static bool FromHex(const std::string& hex, uint8_t* out, size_t max_len);
    static uint32_t HexToU32(const std::string& hex);
    static std::string U32ToHexLE(uint32_t val);
};
