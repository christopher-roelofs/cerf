#include "../trace_manager.h"
#include "../../cpu/mem.h"
#include "../../log.h"

/* wininet.dll (WinCE 5.0 ARM build) — HTTP/socket async operations.
   IDA base: 0x10000000. */

void RegisterWininetTraces(TraceManager& tm) {
    const char* DLL = "wininet.dll";
    tm.SetIdaBase(DLL, 0x10000000);
    tm.SetCRC32(DLL, 0x850730C5);

    /* ICAsyncThread::SelectThreadWrapper — entry point for WININET's async socket thread.
       Crashes at PC=0x44 when I_socket function pointer is NULL. */
    tm.Add(DLL, 0x100C1D20, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] WININET SelectThreadWrapper: this=0x%08X\n", r[0]);
    });

    /* ICAsyncThread::SelectThread — main select loop */
    tm.Add(DLL, 0x100C1DCC, [](uint32_t, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] WININET SelectThread: this=0x%08X\n", r[0]);
    });

    /* ICAsyncThread::CreateSelectSocket — creates the loopback UDP socket.
       Calls I_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP).
       I_socket is a function pointer at IDA 0x10132094 (WININET .data). */
    tm.Add(DLL, 0x100C2D18, [](uint32_t pc, const uint32_t* r, EmulatedMemory* mem) {
        /* Read I_socket function pointer from WININET .data section.
           IDA addr 0x10132094. Runtime base = pc - (IDA_pc - IDA_base). */
        constexpr uint32_t IDA_BASE = 0x10000000;
        constexpr uint32_t I_SOCKET_IDA = 0x10132094;
        constexpr uint32_t CREATE_SELECT_IDA = 0x100C2D18;
        uint32_t runtime_base = pc - (CREATE_SELECT_IDA - IDA_BASE);
        uint32_t i_socket_addr = runtime_base + (I_SOCKET_IDA - IDA_BASE);
        uint32_t i_socket_val = mem->Read32(i_socket_addr);
        LOG(TRACE, "[TRACE] WININET CreateSelectSocket: this=0x%08X I_socket@0x%08X=0x%08X %s\n",
            r[0], i_socket_addr, i_socket_val,
            i_socket_val == 0 ? "*** NULL — will crash! ***" : "");
    });

    /* LoadWinsock — initializes socket function pointers from WS2.dll.
       After GetProcAddress loop, dump I_socket to verify it was stored. */
    tm.Add(DLL, 0x100E3F14, [](uint32_t pc, const uint32_t* r, EmulatedMemory* mem) {
        LOG(TRACE, "[TRACE] WININET LoadWinsock called\n");
        /* Read I_socket now (should be 0 before loading) */
        constexpr uint32_t IDA_BASE = 0x10000000;
        constexpr uint32_t LOADWINSOCK_IDA = 0x100E3F14;
        uint32_t rt_base = pc - (LOADWINSOCK_IDA - IDA_BASE);
        uint32_t i_socket = rt_base + (0x10132094 - IDA_BASE);
        uint32_t val = mem->Read32(i_socket);
        LOG(TRACE, "[TRACE]   I_socket@0x%08X = 0x%08X (before)\n", i_socket, val);
        /* Also dump the SocketsFunctions table entry for socket (entry 21) */
        uint32_t sf_table = rt_base + (0x10129FE0 - IDA_BASE);
        uint32_t entry_name = mem->Read32(sf_table + 21 * 8);
        uint32_t entry_target = mem->Read32(sf_table + 21 * 8 + 4);
        LOG(TRACE, "[TRACE]   SocketsFunctions[21]: name=0x%08X target=0x%08X\n",
            entry_name, entry_target);
    });
}
