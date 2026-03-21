#pragma once
/* GDB Remote Serial Protocol stub for ARM debugging.
   Supports multiple ArmCpus (threads/child processes).
   Listens on a TCP port, pauses CPUs at breakpoints,
   and lets GDB/IDA clients inspect and control execution.

   Interrupt handling: a dedicated watcher thread monitors the client
   socket for Ctrl+C (0x03) asynchronously, so interrupts work even
   when all CPUs are blocked inside native thunk calls. */
#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <thread>
/* Avoid including winsock2.h here — it conflicts with windows.h inclusion
   order in other translation units.  SOCKET is UINT_PTR on Windows. */
typedef uintptr_t GdbSocket;
constexpr GdbSocket GDB_INVALID_SOCKET = (GdbSocket)(~0);

class ArmCpu;
class EmulatedMemory;
struct ProcessSlot;

/* Stop reasons sent to the GDB client (GDB signal numbers) */
enum class GdbSignal : uint8_t {
    NONE      = 0,
    SIGINT    = 2,   /* Ctrl+C interrupt */
    SIGTRAP   = 5,   /* Breakpoint / single-step */
};

constexpr uint16_t GDB_DEFAULT_PORT = 1234;
constexpr int GDB_ARM_NUM_REGS = 17;  /* r0-r15 + cpsr */
/* Periodic breakpoint check uses instruction count mask */
constexpr uint64_t GDB_INTERRUPT_CHECK_MASK = 0xFFFF;

/* Registered CPU entry */
struct GdbThread {
    ArmCpu* cpu;
    uint32_t tid;         /* OS thread ID */
    ProcessSlot* slot;    /* Per-process address space (for memory reads) */
};

class GdbStub {
public:
    GdbStub(uint16_t port, EmulatedMemory* mem);
    ~GdbStub();

    /* Start listening and wait for a client. Blocks until connected.
       Returns false on bind/listen failure. */
    bool Start();

    /* Register/unregister CPUs for debugging.
       Thread-safe — called from any OS thread. */
    void RegisterCpu(ArmCpu* cpu, uint32_t tid);
    void UnregisterCpu(ArmCpu* cpu);

    /* Called from ArmCpu::Step() before each instruction.
       Fast-path returns immediately when running with no breakpoints.
       Blocks in command loop when stopped at a breakpoint.
       @param cpu  The calling CPU (determines which thread hit the BP). */
    void Poll(ArmCpu* cpu);

    /* Check if a specific address has a breakpoint */
    bool HasBreakpoint(uint32_t addr) const;
    void AddBreakpoint(uint32_t addr);
    void RemoveBreakpoint(uint32_t addr);

    /* Public stop flag — thunks can check this to break out of
       blocking calls when an interrupt is pending. */
    std::atomic<bool> stop_all{false};

private:
    EmulatedMemory* mem;
    uint16_t port;

    GdbSocket listen_sock = GDB_INVALID_SOCKET;
    GdbSocket client_sock = GDB_INVALID_SOCKET;
    bool connected = false;
    bool no_ack_mode = false;
    GdbSignal stop_signal = GdbSignal::SIGTRAP;

    /* Thread registry (protected by registry_mutex) */
    mutable std::mutex registry_mutex;
    std::vector<GdbThread> threads;

    /* Currently selected CPU for register/memory reads (Hg command).
       Protected by stop_mutex. */
    ArmCpu* current_cpu = nullptr;

    /* Multi-thread stop coordination.
       stop_mutex + stop_cv: coordinate the command loop (one CPU handles
       packets while others wait). */
    std::mutex stop_mutex;
    std::condition_variable stop_cv;
    int stopped_count = 0;
    bool in_command_loop = false;  /* true while one CPU is handling packets */

    /* Per-CPU single-step tracking (only the stepping CPU should stop) */
    std::atomic<ArmCpu*> single_step_cpu{nullptr};

    /* True when a run→stop transition occurred (breakpoint/step/interrupt).
       False on initial entry — client queries with '?' instead. */
    bool send_stop_reply = false;

    std::set<uint32_t> breakpoints;

    /* Async interrupt watcher thread — monitors client socket for Ctrl+C
       even when all CPUs are blocked in native calls. */
    std::thread interrupt_thread;
    std::atomic<bool> interrupt_thread_active{false};
    void InterruptWatcherLoop();
    void StartInterruptWatcher();
    void StopInterruptWatcher();
    /* Wake up CPUs blocked in native thunks (posts WM_NULL to all threads) */
    void WakeBlockedThreads();

    /* TCP + RSP packet I/O (in gdb_server.cpp) */
    bool WaitForClient();
    std::string RecvPacket();
    void SendPacket(const std::string& data);
    void SendStopReply();
    bool HasPendingData();
    bool CheckForNewClient(ArmCpu* cpu);

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
    void HandleThreadSelect(const std::string& args);

    /* Find CPU by thread ID. Returns nullptr if not found.
       Caller must hold registry_mutex. */
    ArmCpu* FindCpuByTid(uint32_t tid) const;

    /* Resume all stopped CPUs */
    void ResumeAll();

    /* Hex encoding helpers */
    static std::string ToHex(const uint8_t* data, size_t len);
    static bool FromHex(const std::string& hex, uint8_t* out, size_t max_len);
    static uint32_t HexToU32(const std::string& hex);
    static std::string U32ToHexLE(uint32_t val);
};

/* Global debugger pointer — set in main.cpp, read by child threads. */
extern GdbStub* g_debugger;
