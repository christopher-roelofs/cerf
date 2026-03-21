/* Extended string safe thunks: ANSI variants, va_list variants, safe copy/cat
   functions added for WinCE 6/7 support — split from string_safe.cpp */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>
#include <algorithm>

void Win32Thunks::RegisterStringSafeExtHandlers() {
    /* StringCchCopyA(dst, cchDest, src) — ANSI version */
    Thunk("StringCchCopyA", 1705, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p, src.c_str(), copy_len); p[copy_len] = 0; }
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchVPrintfExW(dst, cchDest, ppEnd, pcchRemaining, dwFlags, pszFormat, va_list)
       Same as StringCchPrintfExW but args come from va_list pointer instead of varargs */
    Thunk("StringCchVPrintfExW", 1703, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], ppEnd = regs[2], pcchRemaining = regs[3];
        uint32_t dwFlags = ReadStackArg(regs, mem, 0);
        uint32_t fmtPtr = ReadStackArg(regs, mem, 1);
        uint32_t va = ReadStackArg(regs, mem, 2);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring fmt = ReadWStringFromEmu(mem, fmtPtr);
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va + i * 4);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0;
        (void)dwFlags;
        return true;
    });
    /* StringCchCopyExA(dst, cchDest, src, ppEnd, pcchRemaining, dwFlags) — ANSI */
    Thunk("StringCchCopyExA", 1707, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p, src.c_str(), copy_len); p[copy_len] = 0; }
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchVPrintfExA — ANSI va_list printf */
    Thunk("StringCchVPrintfExA", 1719, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] StringCchVPrintfExA -> stub\n");
        uint32_t dst = regs[0], cch = regs[1];
        if (dst && cch > 0) { uint8_t* p = mem.Translate(dst); if (p) p[0] = 0; }
        regs[0] = 0;
        return true;
    });
    /* StringCbCopyNW(dst, cbDest, src, cbToCopy) — byte-count version of StringCchCopyNW */
    Thunk("StringCbCopyNW", 1743, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2], cbToCopy = regs[3];
        uint32_t cch = cb / 2, cchToCopy = cbToCopy / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToCopy);
        uint32_t copy_len = std::min(src_len, cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src_len >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchCopyNExW(dst, cchDest, src, cchToCopy, ppEnd, pcchRemaining, dwFlags) */
    Thunk("StringCchCopyNExW", 1868, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], cchToCopy = regs[3];
        uint32_t ppEnd = ReadStackArg(regs, mem, 0);
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 1);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToCopy);
        uint32_t copy_len = std::min(src_len, cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (src_len >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchCatA(dst, cchDest, src) — ANSI concat */
    Thunk("StringCchCatA", 1709, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string existing = ReadStringFromEmu(mem, dst);
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p + cur_len, src.c_str(), copy_len); p[cur_len + copy_len] = 0; }
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchPrintfA(dst, cchDest, pszFormat, ...) — ANSI printf */
    Thunk("StringCchPrintfA", 1715, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::string fmt = ReadStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        char buf[2048] = {};
        snprintf(buf, sizeof(buf), fmt.c_str(),
                 args[0], args[1], args[2], args[3], args[4],
                 args[5], args[6], args[7], args[8], args[9]);
        uint32_t len = (uint32_t)strlen(buf);
        uint32_t copy_len = std::min(len, cch - 1);
        uint8_t* p = mem.Translate(dst);
        if (p && cch > 0) { memcpy(p, buf, copy_len); p[copy_len] = 0; }
        regs[0] = (len >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchCopyNA(dst, cchDest, src, cchToCopy) — ANSI */
    Thunk("StringCchCopyNA", 1750, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], cchToCopy = regs[3];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToCopy);
        uint32_t copy_len = std::min(src_len, cch - 1);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p, src.c_str(), copy_len); p[copy_len] = 0; }
        regs[0] = (src_len >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchLengthA(psz, cchMax, pcch) — ANSI */
    Thunk("StringCchLengthA", 1756, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t psz = regs[0], cchMax = regs[1], pcch_out = regs[2];
        if (!psz) { regs[0] = 0x80070057; return true; }
        uint32_t len = 0;
        for (; len < cchMax; len++) { if (mem.Read8(psz + len) == 0) break; }
        if (len >= cchMax) { if (pcch_out) mem.Write32(pcch_out, 0); regs[0] = 0x8007007A; return true; }
        if (pcch_out) mem.Write32(pcch_out, len);
        regs[0] = 0;
        return true;
    });
    /* StringCchCatExA(dst, cchDest, src, ppEnd, pcchRemaining, dwFlags) — ANSI cat ex */
    Thunk("StringCchCatExA", 1711, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        LOG(API, "[API] StringCchCatExA(dst=0x%08X, cch=%u, src=0x%08X)\n", dst, cch, src_ptr);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string existing = ReadStringFromEmu(mem, dst);
        std::string src = ReadStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p + cur_len, src.c_str(), copy_len); p[cur_len + copy_len] = 0; }
        if (ppEnd) mem.Write32(ppEnd, dst + cur_len + copy_len);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - cur_len - copy_len);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchPrintfExA(dst, cchDest, ppEnd, pcchRemaining, dwFlags, pszFormat, ...) */
    Thunk("StringCchPrintfExA", 1717, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], ppEnd = regs[2], pcchRemaining = regs[3];
        uint32_t dwFlags = ReadStackArg(regs, mem, 0);
        uint32_t fmtPtr = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] StringCchPrintfExA(dst=0x%08X, cch=%u, fmt=0x%08X)\n", dst, cch, fmtPtr);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::string fmt = ReadStringFromEmu(mem, fmtPtr);
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = ReadStackArg(regs, mem, 2 + i);
        char buf[2048] = {};
        snprintf(buf, sizeof(buf), fmt.c_str(), args[0], args[1], args[2], args[3], args[4],
                 args[5], args[6], args[7], args[8], args[9]);
        uint32_t len = (uint32_t)strlen(buf);
        uint32_t copy_len = std::min(len, cch - 1);
        uint8_t* p = mem.Translate(dst);
        if (p) { memcpy(p, buf, copy_len); p[copy_len] = 0; }
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (len >= cch) ? 0x8007007A : 0;
        (void)dwFlags;
        return true;
    });
    /* memcpy_s(dst, dstSize, src, count) */
    Thunk("memcpy_s", 2652, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] memcpy_s(dst=0x%08X, dstSz=%u, src=0x%08X, count=%u)\n", regs[0], regs[1], regs[2], regs[3]);
        uint8_t* dst = mem.Translate(regs[0]);
        uint8_t* src = mem.Translate(regs[2]);
        uint32_t count = regs[3];
        if (dst && src && count > 0 && count <= regs[1]) memcpy(dst, src, count);
        regs[0] = (dst && src && count <= regs[1]) ? 0 : 22; /* EINVAL */
        return true;
    });
    /* memmove_s(dst, dstSize, src, count) */
    Thunk("memmove_s", 2653, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] memmove_s(dst=0x%08X, dstSz=%u, src=0x%08X, count=%u)\n", regs[0], regs[1], regs[2], regs[3]);
        uint8_t* dst = mem.Translate(regs[0]);
        uint8_t* src = mem.Translate(regs[2]);
        uint32_t count = regs[3];
        if (dst && src && count > 0 && count <= regs[1]) memmove(dst, src, count);
        regs[0] = (dst && src && count <= regs[1]) ? 0 : 22;
        return true;
    });
    /* swprintf_s(dst, cch, fmt, ...) */
    Thunk("swprintf_s", 2665, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        LOG(API, "[API] swprintf_s(dst=0x%08X, cch=%u, fmt='%ls')\n", dst, cch, fmt.c_str());
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = (uint32_t)-1; return true; }
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = copy_len;
        return true;
    });
    /* _vsnwprintf_s(dst, cch, maxcount, fmt, va_list) */
    Thunk("_vsnwprintf_s", 2668, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t va = regs[3]; /* va_list pointer */
        LOG(API, "[API] _vsnwprintf_s(dst=0x%08X, cch=%u, fmt='%ls')\n", dst, cch, fmt.c_str());
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va + i * 4);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = (uint32_t)-1; return true; }
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = copy_len;
        return true;
    });
    /* wcsncpy_s(dst, destsz, src, count) — safe wide string copy with count */
    Thunk("wcsncpy_s", 2632, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], destsz = regs[1], src_ptr = regs[2], count = regs[3];
        if (!dst || destsz == 0) { regs[0] = 22; return true; } /* EINVAL */
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), count);
        if (copy_len >= destsz) { mem.Write16(dst, 0); regs[0] = 34; return true; } /* ERANGE */
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = 0;
        return true;
    });
}
