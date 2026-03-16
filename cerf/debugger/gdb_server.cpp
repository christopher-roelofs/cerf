/* GDB Remote Serial Protocol — TCP server, RSP packet I/O, and hex helpers.
   The main poll loop and breakpoint logic are in gdb_stub.cpp.
   Command handlers are in gdb_commands.cpp. */
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "gdb_stub.h"
#include "../cpu/arm_cpu.h"
#include "../log.h"

/* Cast helpers between our header-safe GdbSocket and real SOCKET */
static inline SOCKET S(GdbSocket s) { return (SOCKET)s; }
static inline GdbSocket G(SOCKET s) { return (GdbSocket)s; }

GdbStub::GdbStub(uint16_t port, EmulatedMemory* mem)
    : port(port), mem(mem) {}

GdbStub::~GdbStub() {
    StopInterruptWatcher();
    if (client_sock != GDB_INVALID_SOCKET) closesocket(S(client_sock));
    if (listen_sock != GDB_INVALID_SOCKET) closesocket(S(listen_sock));
}

bool GdbStub::Start() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    listen_sock = G(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (listen_sock == GDB_INVALID_SOCKET) {
        LOG_ERR("[GDB] Failed to create listen socket\n");
        return false;
    }
    int opt = 1;
    setsockopt(S(listen_sock), SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (::bind(S(listen_sock), (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERR("[GDB] Failed to bind to port %d (err=%d)\n", port, WSAGetLastError());
        closesocket(S(listen_sock));
        listen_sock = GDB_INVALID_SOCKET;
        return false;
    }
    ::listen(S(listen_sock), 1);
    LOG_RAW("[GDB] Listening on port %d — connect your debugger now...\n", port);

    if (!WaitForClient()) return false;
    LOG_RAW("[GDB] Debugger connected. Stopped at entry point.\n");
    stop_all.store(true);
    return true;
}

bool GdbStub::WaitForClient() {
    if (client_sock != GDB_INVALID_SOCKET) {
        closesocket(S(client_sock));
        client_sock = GDB_INVALID_SOCKET;
    }
    client_sock = G(::accept(S(listen_sock), nullptr, nullptr));
    if (client_sock == GDB_INVALID_SOCKET) {
        LOG_ERR("[GDB] accept() failed (err=%d)\n", WSAGetLastError());
        return false;
    }
    int opt = 1;
    setsockopt(S(client_sock), IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt));
    connected = true;
    no_ack_mode = false;
    return true;
}

/* ---- RSP Packet I/O ---- */

std::string GdbStub::RecvPacket() {
    char ch;
    while (true) {
        int n = ::recv(S(client_sock), &ch, 1, 0);
        if (n <= 0) { connected = false; return ""; }
        if (ch == '$') break;
        if (ch == 0x03) {
            stop_all.store(true);
            stop_signal = GdbSignal::SIGINT;
            return "\x03";
        }
    }

    std::string data;
    uint8_t cksum_calc = 0;
    while (true) {
        int n = ::recv(S(client_sock), &ch, 1, 0);
        if (n <= 0) { connected = false; return ""; }
        if (ch == '#') break;
        data += ch;
        cksum_calc += (uint8_t)ch;
    }
    char ck[3] = {};
    if (::recv(S(client_sock), ck, 2, 0) != 2) { connected = false; return ""; }
    uint8_t cksum_recv = (uint8_t)HexToU32(std::string(ck, 2));

    if (cksum_calc != cksum_recv) {
        if (!no_ack_mode) ::send(S(client_sock), "-", 1, 0);
        LOG(DBG, "[GDB] Checksum mismatch: got %02x expected %02x\n",
            cksum_recv, cksum_calc);
        return "";
    }
    if (!no_ack_mode) ::send(S(client_sock), "+", 1, 0);
    return data;
}

void GdbStub::SendPacket(const std::string& data) {
    uint8_t cksum = 0;
    for (char c : data) cksum += (uint8_t)c;
    char trailer[8];
    snprintf(trailer, sizeof(trailer), "#%02x", cksum);
    std::string pkt = "$" + data + trailer;
    ::send(S(client_sock), pkt.c_str(), (int)pkt.size(), 0);

    if (!no_ack_mode) {
        char ack;
        ::recv(S(client_sock), &ack, 1, 0);
    }
}

void GdbStub::SendStopReply() {
    char buf[8];
    snprintf(buf, sizeof(buf), "S%02x", (uint8_t)stop_signal);
    SendPacket(buf);
}

bool GdbStub::HasPendingData() {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(S(client_sock), &fds);
    timeval tv = {0, 0};
    return ::select(0, &fds, nullptr, nullptr, &tv) > 0;
}

/* ---- Reconnection check (non-blocking accept on listen socket) ---- */

bool GdbStub::CheckForNewClient(ArmCpu* cpu) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(S(listen_sock), &fds);
    timeval tv = {0, 0};
    if (::select(0, &fds, nullptr, nullptr, &tv) > 0) {
        if (WaitForClient()) {
            stop_all.store(true);
            stop_signal = GdbSignal::SIGTRAP;
            current_cpu = cpu;
            send_stop_reply = false;
            LOG(DBG, "[GDB] New client connected at PC=0x%08X\n",
                cpu->r[15]);
            return true;
        }
    }
    return false;
}

/* ---- Hex encoding helpers ---- */

std::string GdbStub::ToHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0xF];
    }
    return result;
}

bool GdbStub::FromHex(const std::string& hex, uint8_t* out, size_t max_len) {
    size_t len = hex.size() / 2;
    if (len > max_len) len = max_len;
    for (size_t i = 0; i < len; i++) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
    }
    return true;
}

uint32_t GdbStub::HexToU32(const std::string& hex) {
    uint32_t val = 0;
    for (char c : hex) {
        val <<= 4;
        if (c >= '0' && c <= '9') val |= c - '0';
        else if (c >= 'a' && c <= 'f') val |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val |= c - 'A' + 10;
    }
    return val;
}

std::string GdbStub::U32ToHexLE(uint32_t val) {
    uint8_t bytes[4] = {
        (uint8_t)(val),
        (uint8_t)(val >> 8),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 24)
    };
    return ToHex(bytes, 4);
}
