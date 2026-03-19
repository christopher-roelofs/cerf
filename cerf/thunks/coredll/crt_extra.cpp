/* CRT extra thunks: wcsspn, _wcsrev, strtol, fabs, labs, _ultow, _ultoa,
   vsprintf, StringCchCatNW — needed by mshtml.dll */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>

void Win32Thunks::RegisterCrtExtraHandlers() {
    /* wcsspn(str, accept) -> length of initial segment of str containing only accept chars */
    Thunk("wcsspn", 72, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring str = ReadWStringFromEmu(mem, regs[0]);
        std::wstring accept = ReadWStringFromEmu(mem, regs[1]);
        size_t result = wcsspn(str.c_str(), accept.c_str());
        regs[0] = (uint32_t)result;
        return true;
    });
    /* _wcsrev(str) -> reverses wide string in place, returns pointer to str */
    Thunk("_wcsrev", 70, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0];
        /* Find length */
        uint32_t len = 0;
        while (mem.Read16(addr + len * 2) != 0) len++;
        /* Reverse in place */
        for (uint32_t i = 0; i < len / 2; i++) {
            uint16_t a = mem.Read16(addr + i * 2);
            uint16_t b = mem.Read16(addr + (len - 1 - i) * 2);
            mem.Write16(addr + i * 2, b);
            mem.Write16(addr + (len - 1 - i) * 2, a);
        }
        regs[0] = addr;
        return true;
    });
    /* strtol(str, endptr, base) -> long */
    Thunk("strtol", 1404, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        const char* str = (const char*)mem.Translate(regs[0]);
        int base = (int)regs[2];
        char* end = nullptr;
        long result = str ? strtol(str, &end, base) : 0;
        if (regs[1] && str) {
            uint32_t consumed = end ? (uint32_t)(end - str) : 0;
            mem.Write32(regs[1], regs[0] + consumed);
        }
        regs[0] = (uint32_t)result;
        return true;
    });
    /* fabs(double) -> double — ARM: double in r0:r1 (lo:hi), result in r0:r1 */
    Thunk("fabs", 1010, [](uint32_t* regs, EmulatedMemory&) -> bool {
        uint64_t bits = ((uint64_t)regs[1] << 32) | regs[0];
        double d; memcpy(&d, &bits, 8);
        d = fabs(d);
        memcpy(&bits, &d, 8);
        regs[0] = (uint32_t)bits; regs[1] = (uint32_t)(bits >> 32);
        return true;
    });
    /* labs(long) -> long */
    Thunk("labs", 1030, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)labs((long)(int32_t)regs[0]);
        return true;
    });
    /* _ultow(value, str, radix) -> wchar_t* str */
    Thunk("_ultow", 1080, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        unsigned long val = regs[0];
        uint32_t dst = regs[1];
        int radix = (int)regs[2];
        wchar_t buf[36];
        _ultow(val, buf, radix);
        for (int i = 0; buf[i] || i == 0; i++) {
            mem.Write16(dst + i * 2, buf[i]);
            if (buf[i] == 0) break;
        }
        regs[0] = dst;
        return true;
    });
    /* _ultoa(value, str, radix) -> char* str */
    Thunk("_ultoa", 1079, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        unsigned long val = regs[0];
        uint32_t dst = regs[1];
        int radix = (int)regs[2];
        char buf[36];
        _ultoa(val, buf, radix);
        uint8_t* p = mem.Translate(dst);
        if (p) strcpy((char*)p, buf);
        regs[0] = dst;
        return true;
    });
    /* vsprintf(buf, format, va_list) -> int chars written
       On ARM, va_list is a pointer to args in emulated memory */
    Thunk("vsprintf", 1146, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::string fmt = ReadStringFromEmu(mem, regs[1]);
        uint32_t va_ptr = regs[2];
        /* Read args from va_list pointer */
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va_ptr + i * 4);
        /* Simple format processing — reuse sprintf-style approach */
        std::string result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == '%' && i + 1 < fmt.size()) {
                i++;
                if (fmt[i] == '%') { result += '%'; continue; }
                std::string spec_str = "%";
                while (i < fmt.size() && !isalpha(fmt[i]) && fmt[i] != '%')
                    { spec_str += fmt[i]; i++; }
                if (i >= fmt.size()) break;
                char spec = fmt[i]; spec_str += spec;
                if (arg_idx >= 10) { result += '?'; continue; }
                char buf[128];
                if (spec == 'd' || spec == 'i') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (int)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'u' || spec == 'x' || spec == 'X' || spec == 'o') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 's') {
                    std::string s = ReadStringFromEmu(mem, args[arg_idx++]);
                    result += s;
                } else if (spec == 'c') {
                    result += (char)args[arg_idx++];
                } else if (spec == 'p') {
                    snprintf(buf, sizeof(buf), "%08X", args[arg_idx++]);
                    result += buf;
                } else { result += '?'; arg_idx++; }
            } else result += fmt[i];
        }
        uint8_t* dst = mem.Translate(dst_addr);
        if (dst) memcpy(dst, result.c_str(), result.size() + 1);
        regs[0] = (uint32_t)result.size();
        return true;
    });
    /* _snprintf(buf, count, fmt, ...) — varargs C formatting with size limit.
       R0=buf, R1=count, R2=fmt, R3+stack=varargs.
       Uses same format parser as vsprintf above. */
    Thunk("_snprintf", 729, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        uint32_t max_count = regs[1];
        std::string fmt = ReadStringFromEmu(mem, regs[2]);
        /* Varargs: R3 is first vararg, then stack */
        uint32_t args[10] = { regs[3] };
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        /* Format string */
        std::string result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == '%' && i + 1 < fmt.size()) {
                i++;
                if (fmt[i] == '%') { result += '%'; continue; }
                std::string spec_str = "%";
                while (i < fmt.size() && !isalpha(fmt[i]) && fmt[i] != '%')
                    { spec_str += fmt[i]; i++; }
                if (i >= fmt.size()) break;
                char spec = fmt[i]; spec_str += spec;
                if (arg_idx >= 10) { result += '?'; continue; }
                char buf[128];
                if (spec == 'd' || spec == 'i') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (int)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'u' || spec == 'x' || spec == 'X' || spec == 'o') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 's') {
                    std::string s = ReadStringFromEmu(mem, args[arg_idx++]);
                    result += s;
                } else if (spec == 'c') {
                    result += (char)args[arg_idx++];
                } else if (spec == 'p') {
                    snprintf(buf, sizeof(buf), "%08X", args[arg_idx++]);
                    result += buf;
                } else { result += '?'; arg_idx++; }
            } else result += fmt[i];
        }
        /* Write to ARM buffer with size limit */
        uint8_t* dst = mem.Translate(dst_addr);
        if (dst && max_count > 0) {
            size_t copy = std::min((size_t)max_count - 1, result.size());
            memcpy(dst, result.c_str(), copy);
            dst[copy] = 0;
        }
        regs[0] = (uint32_t)result.size();
        return true;
    });
    /* StringCchCatNW(dst, cchDest, src, cchToAppend) -> HRESULT */
    Thunk("StringCchCatNW", 1744, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], cchToAppend = regs[3];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; } /* E_INVALIDARG */
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToAppend);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min(src_len, avail);
        for (uint32_t i = 0; i < copy_len; i++)
            mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        regs[0] = (src_len > avail) ? 0x8007007A : 0; /* STRSAFE_E_INSUFFICIENT_BUFFER or S_OK */
        return true;
    });
    /* wcscspn(str, charset) -> size_t — needed by webview.dll */
    Thunk("wcscspn", 62, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring str = ReadWStringFromEmu(mem, regs[0]);
        std::wstring charset = ReadWStringFromEmu(mem, regs[1]);
        regs[0] = (uint32_t)wcscspn(str.c_str(), charset.c_str());
        return true;
    });
    /* _wcsupr(str) -> str — needed by webview.dll */
    Thunk("_wcsupr", 232, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0];
        for (uint32_t i = 0; ; i++) {
            uint16_t c = mem.Read16(addr + i * 2);
            if (!c) break;
            if (c >= 'a' && c <= 'z') mem.Write16(addr + i * 2, c - 32);
        }
        /* regs[0] already = addr */
        return true;
    });
    /* GetTempFileNameW(pathName, prefixString, unique, tempFileName) -> UINT */
    Thunk("GetTempFileNameW", 1234, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetTempFileNameW() -> 1 (stub)\n");
        /* Write a fake temp filename */
        if (regs[3]) {
            const wchar_t* fake = L"\\Temp\\tmp00001.tmp";
            for (int i = 0; fake[i]; i++) mem.Write16(regs[3] + i * 2, fake[i]);
            mem.Write16(regs[3] + 18 * 2, 0);
        }
        regs[0] = 1;
        return true;
    });
    /* keybd_event(bVk, bScan, dwFlags, dwExtraInfo) -> void */
    Thunk("keybd_event", 833, [](uint32_t* regs, EmulatedMemory&) -> bool {
        keybd_event((BYTE)regs[0], (BYTE)regs[1], regs[2], regs[3]);
        return true;
    });
    /* RAS stubs — needed by webview.dll for connection status */
    Thunk("RasEnumConnections", 353, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RasEnumConnections -> ERROR_INVALID_SIZE (no connections)\n");
        regs[0] = 632; /* ERROR_INVALID_SIZE — no RAS connections */
        return true;
    });
    Thunk("RasGetConnectStatus", 354, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RasGetConnectStatus -> ERROR_INVALID_HANDLE\n");
        regs[0] = 6; /* ERROR_INVALID_HANDLE */
        return true;
    });
    /* C++ exception runtime — needed by webview.dll for try/catch */
    Thunk("_CxxThrowException", 1551, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] _CxxThrowException(obj=0x%08X, info=0x%08X) — C++ exception in ARM code!\n",
            regs[0], regs[1]);
        /* Cannot propagate — return to let ARM code continue (will likely crash) */
        return true;
    });
    /* std::exception constructors/destructor — no-ops for IAT resolution */
    Thunk("??0exception@std@@QAE@ABV01@@Z", 1572, [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* copy ctor — no-op */
    });
    Thunk("??0exception@std@@QAE@PBD@Z", 1571, [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* ctor(const char*) — no-op */
    });
    Thunk("??1exception@std@@UAE@XZ", 1574, [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* dtor — no-op */
    });
    /* type_info vtable — just needs a non-null IAT entry */
    Thunk("??_7type_info@@6B@", 1580, [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* vtable reference — no-op */
    });
    /* STL throw helpers */
    Thunk("?_Xran@std@@YAXXZ", 1659, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] std::_Xran — range error in ARM code!\n");
        return true;
    });
    Thunk("?_Xlen@std@@YAXXZ", 1658, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] std::_Xlen — length error in ARM code!\n");
        return true;
    });
}
