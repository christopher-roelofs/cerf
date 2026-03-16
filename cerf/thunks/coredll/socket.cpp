/* WinCE kernel socket traps — forwards to native Windows Winsock.
   API set SH_COMM (19): provider discovery + AFDSocket creation.
   Handle type HT_SOCKET (11): per-socket I/O operations.
   ws2.dll and wspm.dll run as unmodified ARM code; we only provide the
   kernel boundary that they call via 0xF000xxxx trap addresses. */
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "../win32_thunks.h"
#include "../../log.h"
#include <algorithm>

/* Trap index = (api_set << 8) | method.  See psyscall.h IMPLICIT_CALL. */
constexpr uint16_t WINCE_SH_COMM = 19;
constexpr uint16_t WINCE_HT_SOCKET = 11;
constexpr uint16_t TRAP(uint16_t set, uint16_t method) {
    return (uint16_t)((set << 8) | method);
}

/* --- Native socket state (shared with socket_io.cpp) --- */
std::map<uint32_t, SOCKET> g_socks;
static uint32_t g_next_sh = 0x100;
static bool g_wsa_ok = false;

static int g_ipv6_avail = -1; /* -1=unknown, 0=no, 1=yes */
static void EnsureWSA() {
    if (!g_wsa_ok) { WSADATA d; WSAStartup(MAKEWORD(2,2), &d); g_wsa_ok = true; }
}
/* Probe IPv6 connectivity once: TCP connect with short timeout to a
   well-known IPv6 address. UDP probes give false positives on hosts with
   an IPv6 interface but no real end-to-end connectivity. */
bool HasIPv6() {
    EnsureWSA();
    if (g_ipv6_avail >= 0) return g_ipv6_avail != 0;
    SOCKET s = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { g_ipv6_avail = 0; return false; }
    u_long nb = 1; ::ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in6 sa6 = {}; sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons(80);
    /* 2600:1901:0:38d7:: (Google front-end, well-known IPv6) */
    static const uint8_t addr[] = {0x26,0x00,0x19,0x01,0,0,0x38,0xd7,0,0,0,0,0,0,0,0};
    memcpy(&sa6.sin6_addr, addr, 16);
    ::connect(s, (SOCKADDR*)&sa6, sizeof(sa6));
    /* Wait up to 3 seconds for the TCP handshake to complete */
    constexpr long IPV6_PROBE_TIMEOUT_SEC = 3;
    fd_set wset; FD_ZERO(&wset); FD_SET(s, &wset);
    struct timeval tv = { IPV6_PROBE_TIMEOUT_SEC, 0 };
    int n = ::select(0, nullptr, &wset, nullptr, &tv);
    ::closesocket(s);
    g_ipv6_avail = (n > 0) ? 1 : 0;
    LOG(API, "[API] IPv6 probe: %s\n", g_ipv6_avail ? "available" : "unavailable");
    return g_ipv6_avail != 0;
}
static uint32_t WrapSock(SOCKET s) {
    uint32_t h = g_next_sh++; g_socks[h] = s; return h;
}
static SOCKET GetSock(uint32_t h) {
    auto it = g_socks.find(h);
    return it != g_socks.end() ? it->second : INVALID_SOCKET;
}

/* Copy bytes between emulated memory and native buffers */
static void EmuRead(EmulatedMemory& m, uint32_t a, void* d, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) ((uint8_t*)d)[i] = m.Read8(a + i);
}
static void EmuWrite(EmulatedMemory& m, uint32_t a, const void* s, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) m.Write8(a + i, ((const uint8_t*)s)[i]);
}
static void EmuWriteWStr(EmulatedMemory& m, uint32_t a, const wchar_t* s) {
    for (int i = 0; s[i]; i++) m.Write16(a + i * 2, (uint16_t)s[i]);
    m.Write16(a + (uint32_t)wcslen(s) * 2, 0);
}

/* WSAPROTOCOL_INFOW field offsets (32-bit ARM layout, total 628 bytes) */
constexpr uint32_t PI_SVC1 = 0, PI_PFLAGS = 16, PI_GUID = 20, PI_CATID = 36;
constexpr uint32_t PI_CHAIN = 40, PI_VER = 72, PI_AF = 76;
constexpr uint32_t PI_MAXSA = 80, PI_MINSA = 84, PI_TYPE = 88, PI_PROTO = 92;
constexpr uint32_t PI_SZPROTO = 116, PI_SIZE = 628;

void Win32Thunks::RegisterSocketHandlers() {
    /* WSAStartup deferred to first actual socket use, not constructor time */

    /* ---- SH_COMM (set 19) provider management traps ---- */

    /* PMFindProvider (method 28): ws2.dll asks which provider DLL handles a
       given (af, type, protocol).  We fill WSAPROTOCOL_INFOW and return the
       path to the ARM wspm.dll that already lives in the VFS.
       Args: R0=af R1=type R2=proto R3=catId stk0=flags stk1=pInfo stk2=pPath */
    Thunk("PMFindProvider", TRAP(WINCE_SH_COMM, 28),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int af = (int)regs[0], type = (int)regs[1], proto = (int)regs[2];
        uint32_t pi = ReadStackArg(regs, mem, 1);
        uint32_t pp = ReadStackArg(regs, mem, 2);
        LOG(API, "[API] PMFindProvider(af=%d type=%d proto=%d)\n", af, type, proto);
        int maxsa = 16, minsa = 16;
        if (af == AF_INET6) { maxsa = 28; minsa = 28; }
        else if (af != AF_INET) {
            LOG(API, "[API]  -> WSAEAFNOSUPPORT\n");
            regs[0] = WSAEAFNOSUPPORT; return true;
        }
        if (type == 0) type = SOCK_DGRAM; /* wildcard: default to UDP */
        if (type != SOCK_STREAM && type != SOCK_DGRAM) {
            regs[0] = WSAESOCKTNOSUPPORT; return true;
        }
        if (proto == 0) proto = (type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
        for (uint32_t i = 0; i < PI_SIZE; i += 4) mem.Write32(pi + i, 0);
        uint32_t svc = (type == SOCK_STREAM) ? 0x00000726u : 0x00000609u;
        mem.Write32(pi + PI_SVC1, svc);
        mem.Write32(pi + PI_PFLAGS, 0x08); /* PFL_MATCHES_PROTOCOL_ZERO */
        mem.Write32(pi + PI_GUID, 0xCE5F0001);
        mem.Write16(pi + PI_GUID + 4, (uint16_t)af);
        mem.Write16(pi + PI_GUID + 6, (uint16_t)type);
        uint32_t cat = (uint32_t)(af * 10 + type);
        mem.Write32(pi + PI_CATID, cat);
        mem.Write32(pi + PI_CHAIN, 1);
        mem.Write32(pi + PI_CHAIN + 4, cat);
        mem.Write32(pi + PI_VER, 2);
        mem.Write32(pi + PI_AF, (uint32_t)af);
        mem.Write32(pi + PI_MAXSA, (uint32_t)maxsa);
        mem.Write32(pi + PI_MINSA, (uint32_t)minsa);
        mem.Write32(pi + PI_TYPE, (uint32_t)type);
        mem.Write32(pi + PI_PROTO, (uint32_t)proto);
        EmuWriteWStr(mem, pi + PI_SZPROTO,
                     type == SOCK_STREAM ? L"TCP/IP" : L"UDP/IP");
        EmuWriteWStr(mem, pp, L"\\Windows\\wspm.dll");
        LOG(API, "[API]  -> OK cat=%d path=\\Windows\\wspm.dll\n", cat);
        regs[0] = 0; return true;
    });

    /* PMFindNameSpaces (method 31): return DNS namespace provider.
       R0=pQuery R1=pBuf R2=pcBuf R3=pErr
       Returns count of entries (or SOCKET_ERROR on error). */
    Thunk("PMFindNameSpaces", TRAP(WINCE_SH_COMM, 31),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t pBuf = regs[1], pcBuf = regs[2], pErr = regs[3];
        /* NameSpaces struct: Flags(4)+WSANAMESPACE_INFOW(32)+LibPath[260](520)+szId[32](64)=620 */
        constexpr uint32_t NS_ENTRY_SIZE = 620;
        constexpr uint32_t NS_FLAGS_OFF = 0;
        constexpr uint32_t NS_GUID_OFF = 4;       /* Info.NSProviderId */
        constexpr uint32_t NS_DWNS_OFF = 20;      /* Info.dwNameSpace */
        constexpr uint32_t NS_ACTIVE_OFF = 24;     /* Info.fActive */
        constexpr uint32_t NS_VER_OFF = 28;        /* Info.dwVersion */
        constexpr uint32_t NS_IDENT_OFF = 32;      /* Info.lpszIdentifier */
        constexpr uint32_t NS_LIBPATH_OFF = 36;    /* LibPath[MAX_PATH] */
        constexpr uint32_t NS_SZID_OFF = 556;      /* szId[32] */
        constexpr uint32_t WINCE_NS_DNS = 12;
        uint32_t need = NS_ENTRY_SIZE;
        uint32_t have = pcBuf ? mem.Read32(pcBuf) : 0;
        if (have < need || !pBuf) {
            if (pcBuf) mem.Write32(pcBuf, need);
            if (pErr) mem.Write32(pErr, WSAEFAULT);
            LOG(API, "[API] PMFindNameSpaces -> WSAEFAULT (need %d have %d)\n", need, have);
            regs[0] = (uint32_t)SOCKET_ERROR; return true;
        }
        /* Zero the entry, then fill DNS namespace provider */
        for (uint32_t i = 0; i < NS_ENTRY_SIZE; i += 4) mem.Write32(pBuf + i, 0);
        /* GUID: {3c8441d3-b4f9-4ea0-8974-f4c349665191} */
        mem.Write32(pBuf + NS_GUID_OFF,      0x3c8441d3);
        mem.Write16(pBuf + NS_GUID_OFF + 4,  0xb4f9);
        mem.Write16(pBuf + NS_GUID_OFF + 6,  0x4ea0);
        static const uint8_t guid_tail[] = {0x89,0x74,0xf4,0xc3,0x49,0x66,0x51,0x91};
        for (int i = 0; i < 8; i++) mem.Write8(pBuf + NS_GUID_OFF + 8 + i, guid_tail[i]);
        mem.Write32(pBuf + NS_DWNS_OFF, WINCE_NS_DNS);
        mem.Write32(pBuf + NS_ACTIVE_OFF, 1);  /* fActive = TRUE */
        mem.Write32(pBuf + NS_VER_OFF, 0);
        mem.Write32(pBuf + NS_IDENT_OFF, pBuf + NS_SZID_OFF); /* ptr to szId */
        EmuWriteWStr(mem, pBuf + NS_LIBPATH_OFF, L"nspm.dll");
        EmuWriteWStr(mem, pBuf + NS_SZID_OFF, L"DNS");
        if (pcBuf) mem.Write32(pcBuf, NS_ENTRY_SIZE);
        if (pErr) mem.Write32(pErr, 0);
        LOG(API, "[API] PMFindNameSpaces -> 1 (DNS via nspm.dll)\n");
        regs[0] = 1; return true;
    });

    /* PMEnumProtocols (method 27) */
    Thunk("PMEnumProtocols", TRAP(WINCE_SH_COMM, 27),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] PMEnumProtocols -> 0\n");
        regs[0] = 0; return true;
    });

    /* PMAddrConvert (method 32): address string ↔ SOCKADDR conversion.
       R0=Op R1=AF R2=pSA R3=pcSA stk0=pPI stk1=pStr stk2=pcStr stk3=_ */
    Thunk("PMAddrConvert", TRAP(WINCE_SH_COMM, 32),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        EnsureWSA();
        uint32_t op = regs[0], af = regs[1];
        uint32_t pSA = regs[2], pcSA = regs[3];
        uint32_t pStr = ReadStackArg(regs, mem, 1);
        uint32_t pcStr = ReadStackArg(regs, mem, 2);
        LOG(API, "[API] PMAddrConvert(op=%d af=%d)\n", op, af);
        if (op == 1) { /* AddressToString */
            int saLen = pcSA ? (int)mem.Read32(pcSA) : (af == AF_INET6 ? 28 : 16);
            char sa[64] = {}; EmuRead(mem, pSA, sa, std::min((uint32_t)saLen, 64u));
            wchar_t buf[128] = {}; DWORD bLen = 128;
            int r = ::WSAAddressToStringW((SOCKADDR*)sa, saLen, nullptr, buf, &bLen);
            if (r) { regs[0] = (uint32_t)WSAGetLastError(); return true; }
            EmuWriteWStr(mem, pStr, buf);
            if (pcStr) mem.Write32(pcStr, bLen);
            LOG(API, "[API]  -> '%ls'\n", buf);
            regs[0] = 0;
        } else if (op == 2) { /* StringToAddress */
            std::wstring str = ReadWStringFromEmu(mem, pStr);
            int saLen = (af == AF_INET6) ? 28 : 16;
            char sa[64] = {};
            int r = ::WSAStringToAddressW((LPWSTR)str.c_str(), (INT)af,
                                          nullptr, (SOCKADDR*)sa, &saLen);
            if (r) { regs[0] = (uint32_t)WSAGetLastError(); return true; }
            EmuWrite(mem, pSA, sa, (uint32_t)saLen);
            if (pcSA) mem.Write32(pcSA, (uint32_t)saLen);
            LOG(API, "[API]  -> wrote %d bytes SA\n", saLen);
            regs[0] = 0;
        } else {
            regs[0] = WSAEINVAL;
        }
        return true;
    });

    /* AFDSocket (method 2): R0=af R1=type R2=proto R3=catId stk0=pProvId */
    Thunk("AFDSocket", TRAP(WINCE_SH_COMM, 2),
        [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        EnsureWSA();
        int af = (int)regs[0], type = (int)regs[1], proto = (int)regs[2];
        SOCKET s = ::socket(af, type, proto);
        if (s == INVALID_SOCKET) {
            int e = WSAGetLastError();
            LOG(API, "[API] AFDSocket(af=%d type=%d proto=%d) -> FAIL %d\n",
                af, type, proto, e);
            SetLastError(e); regs[0] = 0; return true;
        }
        uint32_t sh = WrapSock(s);
        LOG(API, "[API] AFDSocket(af=%d type=%d proto=%d) -> 0x%X\n",
            af, type, proto, sh);
        regs[0] = sh; return true;
    });

    /* AFDControl (method 3): diagnostic ioctl. Stub. */
    Thunk("AFDControl", TRAP(WINCE_SH_COMM, 3),
        [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] AFDControl(proto=%d act=%d) -> stub 0\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });

    RegisterSocketDnsHandlers();
    RegisterSocketIOHandlers();
}
