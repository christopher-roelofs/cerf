/* WinCE kernel socket traps — per-socket I/O operations.
   Handle type HT_SOCKET (11): bind, connect, send, recv, etc.
   See socket.cpp for provider management (SH_COMM) traps. */
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../win32_thunks.h"
#include "../../log.h"
#include <algorithm>

constexpr uint16_t WINCE_HT_SOCKET_IO = 11;
constexpr uint16_t TRAP_IO(uint16_t set, uint16_t method) {
    return (uint16_t)((set << 8) | method);
}

/* Shared socket state — defined in socket.cpp */
extern std::map<uint32_t, SOCKET> g_socks;
extern bool HasIPv6();
static SOCKET GetSock(uint32_t h) {
    auto it = g_socks.find(h);
    return it != g_socks.end() ? it->second : INVALID_SOCKET;
}
static void EmuRead(EmulatedMemory& m, uint32_t a, void* d, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) ((uint8_t*)d)[i] = m.Read8(a + i);
}
static void EmuWrite(EmulatedMemory& m, uint32_t a, const void* s, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) m.Write8(a + i, ((const uint8_t*)s)[i]);
}

void Win32Thunks::RegisterSocketIOHandlers() {
    /* ---- HT_SOCKET (type 11) per-socket operations ---- */

    Thunk("AFDCloseSocket", TRAP_IO(WINCE_HT_SOCKET_IO, 0),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        SOCKET s = GetSock(regs[0]);
        LOG(API, "[API] AFDCloseSocket(0x%X)\n", regs[0]);
        if (s != INVALID_SOCKET) { ::closesocket(s); g_socks.erase(regs[0]); }
        regs[0] = 0; return true;
    });

    Thunk("AFDBind", TRAP_IO(WINCE_HT_SOCKET_IO, 3),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t alen = std::min(regs[2], 64u);
        char sa[64] = {}; EmuRead(mem, regs[1], sa, alen);
        int r = ::bind(s, (SOCKADDR*)sa, (int)alen);
        LOG(API, "[API] AFDBind(0x%X) -> %d\n", regs[0], r);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    Thunk("AFDConnect", TRAP_IO(WINCE_HT_SOCKET_IO, 4),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t alen = std::min(regs[2], 64u);
        char sa[64] = {}; EmuRead(mem, regs[1], sa, alen);
        auto* saddr = (SOCKADDR*)sa;
        if (saddr->sa_family == AF_INET) {
            auto* sin = (SOCKADDR_IN*)sa;
            LOG(API, "[API] AFDConnect(0x%X, %d.%d.%d.%d:%d)\n", regs[0],
                sin->sin_addr.S_un.S_un_b.s_b1, sin->sin_addr.S_un.S_un_b.s_b2,
                sin->sin_addr.S_un.S_un_b.s_b3, sin->sin_addr.S_un.S_un_b.s_b4,
                ntohs(sin->sin_port));
        } else if (saddr->sa_family == AF_INET6) {
            auto* sin6 = (SOCKADDR_IN6*)sa;
            auto* b = sin6->sin6_addr.u.Byte;
            LOG(API, "[API] AFDConnect(0x%X, [%02x%02x:%02x%02x:...:%02x%02x]:%d)\n",
                regs[0], b[0],b[1],b[2],b[3],b[14],b[15], ntohs(sin6->sin6_port));
            /* Fast-fail IPv6 when no connectivity */
            bool is_v4mapped = (memcmp(b, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0);
            if (!is_v4mapped && !HasIPv6()) {
                LOG(API, "[API]  -> FAIL (no IPv6, fast reject)\n");
                regs[0] = WSAENETUNREACH; return true;
            }
        } else {
            LOG(API, "[API] AFDConnect(0x%X, af=%d)\n", regs[0], saddr->sa_family);
        }
        int r = ::connect(s, (SOCKADDR*)sa, (int)alen);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0;
        LOG(API, "[API]  -> %s (%d)\n", regs[0] ? "FAIL" : "OK", regs[0]);
        return true;
    });

    Thunk("AFDListen", TRAP_IO(WINCE_HT_SOCKET_IO, 6),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        SOCKET s = GetSock(regs[0]);
        int r = ::listen(s, (int)regs[1]);
        LOG(API, "[API] AFDListen(0x%X, %d) -> %d\n", regs[0], regs[1], r);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    /* AFDSend (method 8): R0=Socket R1=pBufs R2=nBufs R3=pcSent
       stk: Flags pAddr cAddr pOv pComp pTid pCS */
    Thunk("AFDSend", TRAP_IO(WINCE_HT_SOCKET_IO, 8),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t ba = regs[1], nb = regs[2], sp = regs[3];
        uint32_t flags = ReadStackArg(regs, mem, 0);
        int total = 0;
        for (uint32_t i = 0; i < nb; i++) {
            uint32_t len = mem.Read32(ba + i * 8);
            uint32_t ptr = mem.Read32(ba + i * 8 + 4);
            std::vector<char> d(len); EmuRead(mem, ptr, d.data(), len);
            /* Replace Accept-Encoding: gzip,deflate with identity to
               avoid garbled HTML (WinCE may lack httpcomp.dll) */
            if (len > 16 && (memcmp(d.data(), "GET ", 4) == 0 ||
                             memcmp(d.data(), "POST", 4) == 0 ||
                             memcmp(d.data(), "HEAD", 4) == 0)) {
                std::string buf(d.begin(), d.end());
                auto p = buf.find("Accept-Encoding:");
                if (p != std::string::npos) {
                    auto eol = buf.find("\r\n", p);
                    if (eol != std::string::npos) {
                        std::string rep = "Accept-Encoding: identity";
                        size_t hdr_len = eol - p;
                        if (rep.size() <= hdr_len) {
                            rep.append(hdr_len - rep.size(), ' ');
                            buf.replace(p, hdr_len, rep);
                            d.assign(buf.begin(), buf.end());
                        }
                    }
                }
            }
            int n = ::send(s, d.data(), (int)len, (int)flags);
            if (n == SOCKET_ERROR) {
                if (sp) mem.Write32(sp, (uint32_t)total);
                regs[0] = (uint32_t)WSAGetLastError(); return true;
            }
            total += n;
        }
        if (sp) mem.Write32(sp, (uint32_t)total);
        if (nb > 0 && total > 0) {
            uint32_t l0 = mem.Read32(ba), p0 = mem.Read32(ba + 4);
            uint32_t show = std::min(l0, 200u);
            std::string peek; peek.reserve(show);
            for (uint32_t i = 0; i < show; i++) {
                char c = (char)mem.Read8(p0 + i);
                peek += (c >= 32 && c < 127) ? c : '.';
            }
            LOG(API, "[API] AFDSend(0x%X) -> %d bytes [%s]\n",
                regs[0], total, peek.c_str());
        } else {
            LOG(API, "[API] AFDSend(0x%X) -> %d bytes\n", regs[0], total);
        }
        regs[0] = 0; return true;
    });

    /* AFDRecvImpl (method 7): R0=Socket R1=pBufs R2=nBufs R3=pcRcvd
       stk: pCtl pFlags pAddr pcAddr pOv pComp pTid pCS */
    Thunk("AFDRecvImpl", TRAP_IO(WINCE_HT_SOCKET_IO, 7),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t ba = regs[1], nb = regs[2], rp = regs[3];
        uint32_t fp = ReadStackArg(regs, mem, 1);
        int flags = fp ? (int)mem.Read32(fp) : 0;
        int total = 0;
        for (uint32_t i = 0; i < nb; i++) {
            uint32_t len = mem.Read32(ba + i * 8);
            uint32_t ptr = mem.Read32(ba + i * 8 + 4);
            std::vector<char> d(len);
            int n = ::recv(s, d.data(), (int)len, flags);
            if (n == SOCKET_ERROR) {
                if (rp) mem.Write32(rp, 0);
                regs[0] = (uint32_t)WSAGetLastError(); return true;
            }
            if (n > 0) EmuWrite(mem, ptr, d.data(), (uint32_t)n);
            total += n;
            if (n < (int)len) break;
        }
        if (rp) mem.Write32(rp, (uint32_t)total);
        if (nb > 0 && total > 0) {
            uint32_t l0 = mem.Read32(ba), p0 = mem.Read32(ba + 4);
            uint32_t show = std::min((uint32_t)total, 300u);
            show = std::min(show, l0);
            std::string peek; peek.reserve(show);
            for (uint32_t i = 0; i < show; i++) {
                char c = (char)mem.Read8(p0 + i);
                peek += (c >= 32 && c < 127) ? c : '.';
            }
            LOG(API, "[API] AFDRecvImpl(0x%X) -> %d bytes [%s]\n",
                regs[0], total, peek.c_str());
        } else {
            LOG(API, "[API] AFDRecvImpl(0x%X) -> %d bytes\n", regs[0], total);
        }
        regs[0] = 0; return true;
    });

    Thunk("AFDShutdown", TRAP_IO(WINCE_HT_SOCKET_IO, 9),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        SOCKET s = GetSock(regs[0]);
        int r = ::shutdown(s, (int)regs[1]);
        LOG(API, "[API] AFDShutdown(0x%X, %d) -> %d\n", regs[0], regs[1], r);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    Thunk("AFDGetsockname", TRAP_IO(WINCE_HT_SOCKET_IO, 10),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        char sa[64] = {}; int len = regs[2] ? (int)mem.Read32(regs[2]) : 64;
        int r = ::getsockname(s, (SOCKADDR*)sa, &len);
        if (!r) { EmuWrite(mem, regs[1], sa, (uint32_t)len); mem.Write32(regs[2], len); }
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    Thunk("AFDGetpeername", TRAP_IO(WINCE_HT_SOCKET_IO, 11),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        char sa[64] = {}; int len = regs[2] ? (int)mem.Read32(regs[2]) : 64;
        int r = ::getpeername(s, (SOCKADDR*)sa, &len);
        if (!r) { EmuWrite(mem, regs[1], sa, (uint32_t)len); mem.Write32(regs[2], len); }
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    Thunk("AFDGetSockOpt", TRAP_IO(WINCE_HT_SOCKET_IO, 12),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t lp = ReadStackArg(regs, mem, 0);
        int len = lp ? (int)mem.Read32(lp) : 0;
        char v[256] = {};
        int r = ::getsockopt(s, (int)regs[1], (int)regs[2], v, &len);
        if (!r && regs[3]) EmuWrite(mem, regs[3], v, std::min((uint32_t)len, 256u));
        if (!r && lp) mem.Write32(lp, (uint32_t)len);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    Thunk("AFDSetSockOpt", TRAP_IO(WINCE_HT_SOCKET_IO, 13),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t bl = ReadStackArg(regs, mem, 0);
        char v[256] = {};
        if (regs[3] && bl) EmuRead(mem, regs[3], v, std::min(bl, 256u));
        int r = ::setsockopt(s, (int)regs[1], (int)regs[2], v, (int)bl);
        LOG(API, "[API] AFDSetSockOpt(0x%X, %d, 0x%X) -> %d\n",
            regs[0], regs[1], regs[2], r);
        regs[0] = r ? (uint32_t)WSAGetLastError() : 0; return true;
    });

    /* AFDIoctl (method 5) */
    Thunk("AFDIoctl", TRAP_IO(WINCE_HT_SOCKET_IO, 5),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        SOCKET s = GetSock(regs[0]);
        uint32_t code = regs[1];
        uint32_t inBuf = regs[2], inLen = regs[3];
        uint32_t outBuf = ReadStackArg(regs, mem, 0);
        uint32_t outLen = ReadStackArg(regs, mem, 1);
        uint32_t pRet = ReadStackArg(regs, mem, 2);
        constexpr uint32_t IOCTL_FIONBIO  = 0x8004667E;
        constexpr uint32_t IOCTL_FIONREAD = 0x4004667F;
        if (code == IOCTL_FIONBIO && inBuf && inLen >= 4) {
            u_long mode = mem.Read32(inBuf);
            LOG(API, "[API] AFDIoctl(0x%X, FIONBIO=%lu) -> 0 (not applied)\n",
                regs[0], mode);
            regs[0] = 0;
        } else if (code == IOCTL_FIONREAD && outBuf && outLen >= 4) {
            u_long avail = 0;
            int r = ::ioctlsocket(s, FIONREAD, &avail);
            if (!r) mem.Write32(outBuf, (uint32_t)avail);
            if (pRet) mem.Write32(pRet, 4);
            LOG(API, "[API] AFDIoctl(0x%X, FIONREAD) -> %lu\n", regs[0], avail);
            regs[0] = r ? (uint32_t)WSAGetLastError() : 0;
        } else {
            LOG(API, "[API] AFDIoctl(0x%X, code=0x%X) -> stub 0\n", regs[0], code);
            regs[0] = 0;
        }
        return true;
    });

    /* AFDEventSelect (16) + AFDEnumNetworkEvents (17): stubs */
    Thunk("AFDEventSelect", TRAP_IO(WINCE_HT_SOCKET_IO, 16),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] AFDEventSelect(0x%X) -> stub 0\n", regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("AFDEnumNetworkEvents", TRAP_IO(WINCE_HT_SOCKET_IO, 17),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] AFDEnumNetworkEvents(0x%X) -> stub 0\n", regs[0]);
        regs[0] = 0; return true;
    });
}
