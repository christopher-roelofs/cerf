/* WinCE kernel socket traps — AFDSelect and DNS resolution.
   Split from socket.cpp for file size management. */
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "../win32_thunks.h"
#include "../../log.h"

extern std::map<uint32_t, SOCKET> g_socks;
extern bool HasIPv6();

constexpr uint16_t WINCE_SH_COMM_DNS = 19;
static constexpr uint16_t TRAP_DNS(uint16_t set, uint16_t method) {
    return (uint16_t)((set << 8) | method);
}
static SOCKET GetSockD(uint32_t h) {
    auto it = g_socks.find(h); return it != g_socks.end() ? it->second : INVALID_SOCKET;
}
static void EmuReadD(EmulatedMemory& m, uint32_t a, void* d, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) ((uint8_t*)d)[i] = m.Read8(a + i);
}

/* SOCK_THREAD offsets (32-bit ARM layout) */
constexpr uint32_t ST_HOSTENT  = 20, ST_ALIASES = 36, ST_HOSTBUF = 100;
constexpr uint32_t ST_ADDRPTRS = 740, ST_HOSTADDR = 804;
constexpr uint32_t ADDR_SLOT_SZ = 20, MAX_ADDRS = 15;
constexpr uint32_t HE_NAME = 0, HE_ALIASES = 4;
constexpr uint32_t HE_ADDRTYPE = 8, HE_LENGTH = 10, HE_ADDRLIST = 12;
constexpr uint16_t DNS_T_A = 1, DNS_T_AAAA = 28;

void Win32Thunks::RegisterSocketDnsHandlers() {
    /* AFDSelect (SH_COMM method 10): real select() forwarding.
       R0=ReadCnt R1=ReadList R2=WriteCnt R3=WriteList
       stk0=ExcCnt stk1=ExcList stk2=pTimeout stk3=pDllCS */
    Thunk("AFDSelect", TRAP_DNS(WINCE_SH_COMM_DNS, 10),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        constexpr uint32_t SL_SIZE = 16, SL_HSOCK = 0, SL_EVMASK = 8;
        uint32_t rc = regs[0], rl = regs[1], wc = regs[2], wl = regs[3];
        uint32_t ec = ReadStackArg(regs, mem, 0), el = ReadStackArg(regs, mem, 1);
        uint32_t pt = ReadStackArg(regs, mem, 2);
        fd_set rset, wset, eset;
        FD_ZERO(&rset); FD_ZERO(&wset); FD_ZERO(&eset);
        auto build = [&](uint32_t cnt, uint32_t lst, fd_set& fs) {
            for (uint32_t i = 0; i < cnt && i < FD_SETSIZE; i++) {
                uint32_t h = mem.Read32(lst + i * SL_SIZE + SL_HSOCK);
                SOCKET s = GetSockD(h);
                if (s != INVALID_SOCKET) FD_SET(s, &fs);
                mem.Write32(lst + i * SL_SIZE + SL_EVMASK, 0);
            }
        };
        build(rc, rl, rset); build(wc, wl, wset); build(ec, el, eset);
        struct timeval tv = {}, *ptv = nullptr;
        if (pt) { tv.tv_sec = (long)mem.Read32(pt);
                   tv.tv_usec = (long)mem.Read32(pt + 4); ptv = &tv; }
        if (rc > 0) {
            uint32_t h0 = mem.Read32(rl + SL_HSOCK);
            SOCKET s0 = GetSockD(h0);
            LOG(API, "[API] AFDSelect(r=%d w=%d e=%d h=0x%X ns=%lld tv=%s)\n",
                rc, wc, ec, h0, (long long)s0,
                ptv ? (std::to_string(tv.tv_sec) + "." +
                       std::to_string(tv.tv_usec)).c_str() : "NULL");
        }
        int n = ::select(0, rc ? &rset : nullptr, wc ? &wset : nullptr,
                         ec ? &eset : nullptr, ptv);
        if (n <= 0) {
            int err = (n < 0) ? WSAGetLastError() : 0;
            LOG(API, "[API]  -> select=%d err=%d\n", n, err);
            regs[0] = (n == 0) ? 0 : (uint32_t)err;
            return true;
        }
        constexpr uint32_t EVT_READ = 0x01, EVT_WRITE = 0x02, EVT_OOB = 0x04;
        auto mark = [&](uint32_t cnt, uint32_t lst, fd_set& fs, uint32_t bit) {
            for (uint32_t i = 0; i < cnt; i++) {
                uint32_t h = mem.Read32(lst + i * SL_SIZE + SL_HSOCK);
                SOCKET s = GetSockD(h);
                if (s != INVALID_SOCKET && FD_ISSET(s, &fs))
                    mem.Write32(lst + i * SL_SIZE + SL_EVMASK, bit);
            }
        };
        mark(rc, rl, rset, EVT_READ); mark(wc, wl, wset, EVT_WRITE);
        mark(ec, el, eset, EVT_OOB);
        regs[0] = (uint32_t)n; return true;
    });

    /* AFDGetHostentByAttr (SH_COMM method 7): real DNS resolution.
       R0=pThread R1=Name R2=Address R3=pOptions */
    Thunk("AFDGetHostentByAttr", TRAP_DNS(WINCE_SH_COMM_DNS, 7),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t pThread = regs[0], pName = regs[1], pAddr = regs[2];
        uint16_t qtype = regs[3] ? mem.Read16(regs[3]) : DNS_T_A;
        int af = (qtype == DNS_T_AAAA) ? AF_INET6 : AF_INET;
        int addrLen = (af == AF_INET6) ? 16 : 4;
        std::string host;
        if (pName) { std::wstring w = ReadWStringFromEmu(mem, pName);
            for (wchar_t c : w) host += (char)c; }
        LOG(API, "[API] AFDGetHostentByAttr('%s' type=%d af=%d)\n", host.c_str(), qtype, af);
        if (host.empty() && !pAddr) {
            SetLastError(WSAHOST_NOT_FOUND); regs[0] = 0; return true; }
        if (af == AF_INET6 && !HasIPv6()) {
            LOG(API, "[API]  -> no IPv6, skipping AAAA\n");
            SetLastError(WSAHOST_NOT_FOUND); regs[0] = 0; return true; }
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = af; hints.ai_socktype = SOCK_STREAM;
        int err = ::getaddrinfo(host.empty() ? nullptr : host.c_str(),
                                nullptr, &hints, &res);
        if (err || !res) {
            LOG(API, "[API]  -> DNS FAILED (%d)\n", err);
            if (res) ::freeaddrinfo(res);
            SetLastError(WSAHOST_NOT_FOUND); regs[0] = 0; return true; }
        std::vector<std::vector<uint8_t>> addrs;
        for (auto* ai = res; ai && addrs.size() < MAX_ADDRS; ai = ai->ai_next) {
            if (ai->ai_family != af) continue;
            std::vector<uint8_t> a(addrLen);
            if (af == AF_INET) memcpy(a.data(), &((sockaddr_in*)ai->ai_addr)->sin_addr, 4);
            else memcpy(a.data(), &((sockaddr_in6*)ai->ai_addr)->sin6_addr, 16);
            addrs.push_back(a);
        }
        ::freeaddrinfo(res);
        if (addrs.empty()) { SetLastError(WSAHOST_NOT_FOUND); regs[0] = 0; return true; }
        uint32_t bufA = pThread + ST_HOSTBUF;
        for (uint32_t i = 0; i <= (uint32_t)host.size() && i < 639; i++)
            mem.Write8(bufA + i, i < host.size() ? host[i] : 0);
        uint32_t addrBase = pThread + ST_HOSTADDR;
        for (size_t i = 0; i < addrs.size(); i++)
            for (int j = 0; j < addrLen; j++)
                mem.Write8(addrBase + (uint32_t)(i * ADDR_SLOT_SZ) + j, addrs[i][j]);
        uint32_t ptrBase = pThread + ST_ADDRPTRS;
        for (size_t i = 0; i < addrs.size(); i++)
            mem.Write32(ptrBase + (uint32_t)(i * 4), addrBase + (uint32_t)(i * ADDR_SLOT_SZ));
        mem.Write32(ptrBase + (uint32_t)(addrs.size() * 4), 0);
        mem.Write32(pThread + ST_ALIASES, 0);
        uint32_t he = pThread + ST_HOSTENT;
        mem.Write32(he + HE_NAME, bufA);
        mem.Write32(he + HE_ALIASES, pThread + ST_ALIASES);
        mem.Write16(he + HE_ADDRTYPE, (uint16_t)af);
        mem.Write16(he + HE_LENGTH, (uint16_t)addrLen);
        mem.Write32(he + HE_ADDRLIST, ptrBase);
        LOG(API, "[API]  -> OK, %zu addrs, first=%d.%d.%d.%d\n", addrs.size(),
            addrs[0][0], addrs[0][1], addrs[0][2], addrLen >= 4 ? addrs[0][3] : 0);
        regs[0] = 1; return true;
    });
}
