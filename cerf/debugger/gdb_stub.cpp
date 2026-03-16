/* GDB Remote Serial Protocol stub — CPU registry, interrupt watcher,
   breakpoint management, and multi-thread poll loop.
   TCP server and packet I/O are in gdb_server.cpp.
   Command handlers are in gdb_commands.cpp. */
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "gdb_stub.h"
#include "../cpu/arm_cpu.h"
#include "../cpu/mem.h"
#include "../log.h"

/* Global debugger pointer */
GdbStub* g_debugger = nullptr;

/* ---- CPU Registry ---- */

void GdbStub::RegisterCpu(ArmCpu* cpu, uint32_t tid) {
    std::lock_guard<std::mutex> lock(registry_mutex);
    for (auto& t : threads)
        if (t.cpu == cpu) { t.tid = tid; return; }
    threads.push_back({cpu, tid});
    LOG(DBG, "[GDB] Registered CPU tid=%u (%zu total)\n", tid, threads.size());
    if (!current_cpu) current_cpu = cpu;
}

void GdbStub::UnregisterCpu(ArmCpu* cpu) {
    std::lock_guard<std::mutex> lock(registry_mutex);
    for (auto it = threads.begin(); it != threads.end(); ++it) {
        if (it->cpu == cpu) {
            LOG(DBG, "[GDB] Unregistered CPU tid=%u\n", it->tid);
            threads.erase(it);
            break;
        }
    }
    if (current_cpu == cpu)
        current_cpu = threads.empty() ? nullptr : threads[0].cpu;
}

ArmCpu* GdbStub::FindCpuByTid(uint32_t tid) const {
    for (auto& t : threads)
        if (t.tid == tid) return t.cpu;
    return nullptr;
}

/* ---- Async Interrupt Watcher ---- */

void GdbStub::StartInterruptWatcher() {
    if (interrupt_thread_active.load()) return;
    interrupt_thread_active.store(true);
    interrupt_thread = std::thread(&GdbStub::InterruptWatcherLoop, this);
}

void GdbStub::StopInterruptWatcher() {
    interrupt_thread_active.store(false);
    if (interrupt_thread.joinable()) interrupt_thread.join();
}

void GdbStub::InterruptWatcherLoop() {
    /* This thread monitors the client socket for Ctrl+C (0x03) while
       CPUs are running. When all CPUs are in the command loop (stop_all),
       we sleep and let the command loop handle socket I/O. */
    constexpr int POLL_MS = 50;
    SOCKET cs = (SOCKET)client_sock;
    while (interrupt_thread_active.load()) {
        /* Only check when CPUs are running (not in command loop) */
        if (stop_all.load() || !connected || client_sock == GDB_INVALID_SOCKET) {
            Sleep(POLL_MS);
            continue;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(cs, &fds);
        timeval tv = {0, POLL_MS * 1000};  /* microseconds */
        int sel = ::select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        /* Data available — peek to check for Ctrl+C without consuming
           packet data that the command loop should handle. */
        char ch = 0;
        int n = ::recv(cs, &ch, 1, MSG_PEEK);
        if (n < 0) {
            /* Socket error — client probably disconnected */
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                LOG(DBG, "[GDB] Watcher: socket error %d, marking disconnected\n", err);
                connected = false;
            }
            continue;
        }
        if (n == 0) {
            /* Graceful close */
            LOG(DBG, "[GDB] Watcher: client disconnected (graceful)\n");
            connected = false;
            continue;
        }
        if (ch == 0x03) {
            /* Consume the Ctrl+C byte */
            ::recv(cs, &ch, 1, 0);
            LOG(DBG, "[GDB] Async interrupt received (watcher thread)\n");
            stop_signal = GdbSignal::SIGINT;
            send_stop_reply = true;
            stop_all.store(true);
            /* Wake up CPUs blocked in native calls */
            WakeBlockedThreads();
        }
        /* Non-Ctrl+C data: leave in buffer for command loop. */
    }
}

void GdbStub::WakeBlockedThreads() {
    /* Post WM_NULL to all registered threads to unblock GetMessage/WaitMessage.
       This is harmless — WM_NULL is a no-op message. */
    std::lock_guard<std::mutex> lock(registry_mutex);
    for (auto& t : threads) {
        PostThreadMessage(t.tid, WM_NULL, 0, 0);
    }
}

/* ---- Multi-Thread Poll ---- */

void GdbStub::Poll(ArmCpu* cpu) {
    /* If no client, periodically check for a new connection (non-blocking). */
    if (!connected && listen_sock != GDB_INVALID_SOCKET) {
        if ((cpu->insn_count & GDB_INTERRUPT_CHECK_MASK) == 0)
            CheckForNewClient(cpu);
        if (!connected) return;
    }

    /* Fast path: not stopped, check breakpoints and single-step */
    if (!stop_all.load(std::memory_order_relaxed)) {
        /* Check single-step completion */
        if (single_step_cpu.load(std::memory_order_relaxed) == cpu) {
            single_step_cpu.store(nullptr);
            stop_all.store(true);
            stop_signal = GdbSignal::SIGTRAP;
            current_cpu = cpu;
            send_stop_reply = true;
        }
        /* Check breakpoints */
        else if (!breakpoints.empty()) {
            uint32_t pc = cpu->r[REG_PC];
            if (breakpoints.count(pc)) {
                stop_all.store(true);
                stop_signal = GdbSignal::SIGTRAP;
                current_cpu = cpu;
                send_stop_reply = true;
                LOG(DBG, "[GDB] Breakpoint hit at 0x%08X (tid=%u)\n",
                    pc, GetCurrentThreadId());
            }
        }
        /* Note: Ctrl+C is handled by the interrupt watcher thread,
           not polled here. This eliminates the socket-read race. */

        if (!stop_all.load(std::memory_order_relaxed))
            return; /* Fast path — running, no breakpoint */
    }

    /* --- Stopped path: this CPU needs to wait or handle commands --- */
    std::unique_lock<std::mutex> lock(stop_mutex);

    if (in_command_loop) {
        stopped_count++;
        stop_cv.wait(lock, [this]{ return !stop_all.load(); });
        stopped_count--;
        return;
    }

    /* This CPU becomes the command loop handler.
       Stop the interrupt watcher so we own the socket exclusively. */
    in_command_loop = true;
    stopped_count++;
    lock.unlock();
    StopInterruptWatcher();
    lock.lock();

    /* Send stop reply only on run->stop transitions */
    if (send_stop_reply) {
        send_stop_reply = false;
        SendStopReply();
    }

    /* Command loop — blocks until client sends continue or step */
    while (stop_all.load() && connected) {
        lock.unlock();
        std::string pkt = RecvPacket();
        lock.lock();
        if (pkt.empty()) continue;
        if (pkt == "\x03") { SendStopReply(); continue; }
        HandlePacket(pkt);
    }

    in_command_loop = false;
    stopped_count--;
    lock.unlock();

    /* Resume interrupt watcher and wake other CPUs */
    StartInterruptWatcher();
    stop_cv.notify_all();
}

/* ---- Breakpoint Management ---- */

void GdbStub::ResumeAll() {
    stop_all.store(false);
}

bool GdbStub::HasBreakpoint(uint32_t addr) const {
    return breakpoints.count(addr) > 0;
}

void GdbStub::AddBreakpoint(uint32_t addr) {
    breakpoints.insert(addr);
    LOG(DBG, "[GDB] Breakpoint set at 0x%08X (%zu total)\n",
        addr, breakpoints.size());
}

void GdbStub::RemoveBreakpoint(uint32_t addr) {
    breakpoints.erase(addr);
    LOG(DBG, "[GDB] Breakpoint removed at 0x%08X (%zu remaining)\n",
        addr, breakpoints.size());
}
