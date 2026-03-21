/* String safe thunks: sprintf, StringCch/StringCb safe string functions */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterStringSafeHandlers() {
    /* sprintf(char* buf, const char* fmt, ...) — narrow printf */
    Thunk("sprintf", 719, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst_addr = regs[0];
        std::string fmt = ReadStringFromEmu(mem, regs[1]);
        uint32_t args[10];
        args[0] = regs[2]; args[1] = regs[3];
        for (int i = 2; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 2);
        /* Process format string, assembling output */
        std::string result;
        int arg_idx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == '%' && i + 1 < fmt.size()) {
                i++;
                if (fmt[i] == '%') { result += '%'; continue; }
                /* Collect the full format specifier */
                std::string spec_str = "%";
                while (i < fmt.size() && !isalpha(fmt[i]) && fmt[i] != '%') { spec_str += fmt[i]; i++; }
                if (i >= fmt.size()) break;
                char spec = fmt[i]; spec_str += spec;
                if (arg_idx >= 10) { result += '?'; continue; }
                char buf[128];
                if (spec == 'd' || spec == 'i') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (int)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'u') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 'x' || spec == 'X' || spec == 'o') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), args[arg_idx++]);
                    result += buf;
                } else if (spec == 's') {
                    std::string s = ReadStringFromEmu(mem, args[arg_idx++]);
                    snprintf(buf, sizeof(buf), spec_str.c_str(), s.c_str());
                    result += buf;
                } else if (spec == 'S') {
                    /* %S = wide string in WinCE narrow printf */
                    std::wstring ws = ReadWStringFromEmu(mem, args[arg_idx++]);
                    std::string ns(ws.begin(), ws.end());
                    result += ns;
                } else if (spec == 'c') {
                    snprintf(buf, sizeof(buf), spec_str.c_str(), (char)args[arg_idx++]);
                    result += buf;
                } else if (spec == 'f' || spec == 'e' || spec == 'E' || spec == 'g' || spec == 'G') {
                    if (arg_idx + 1 < 10) {
                        uint64_t bits = ((uint64_t)args[arg_idx + 1] << 32) | args[arg_idx];
                        double val; memcpy(&val, &bits, 8); arg_idx += 2;
                        snprintf(buf, sizeof(buf), spec_str.c_str(), val);
                        result += buf;
                    } else { result += '?'; arg_idx = 10; }
                } else if (spec == 'p') {
                    snprintf(buf, sizeof(buf), "%08X", args[arg_idx++]);
                    result += buf;
                } else { result += '?'; arg_idx++; }
            } else result += fmt[i];
        }
        uint8_t* dst = mem.Translate(dst_addr);
        if (dst) { memcpy(dst, result.c_str(), result.size() + 1); }
        regs[0] = (uint32_t)result.size();
        return true;
    });
    /* StringCchPrintfW(pszDest, cchDest, pszFormat, ...) — safe wide printf */
    Thunk("StringCchPrintfW", 1699, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; } /* E_INVALIDARG */
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0; /* STRSAFE_E_INSUFFICIENT_BUFFER or S_OK */
        return true;
    });

    /* StringCbPrintfW(pszDest, cbDest, pszFormat, ...) — byte-count version */
    Thunk("StringCbPrintfW", 1700, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1];
        uint32_t cch = cb / 2;
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t args[10];
        args[0] = regs[3];
        for (int i = 1; i < 10; i++) args[i] = ReadStackArg(regs, mem, i - 1);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    Thunk("StringCchCopyW", 1689, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; } /* E_INVALIDARG */
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0; /* STRSAFE_E_INSUFFICIENT_BUFFER or S_OK */
        return true;
    });
    /* StringCchCopyExW(dst, cchDest, src, ppszDestEnd, pcchRemaining, dwFlags) */
    Thunk("StringCchCopyExW", 1691, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - copy_len);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbCopyExW(dst, cbDest, src, ppszDestEnd, pcbRemaining, dwFlags) */
    Thunk("StringCbCopyExW", 1692, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcbRemaining = ReadStackArg(regs, mem, 0);
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + copy_len * 2);
        if (pcbRemaining) mem.Write32(pcbRemaining, (cch - copy_len) * 2);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    Thunk("StringCchCatW", 1693, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });

    /* StringCbCopyW(dst, cbDest, src) — byte-count version of StringCchCopyW */
    Thunk("StringCbCopyW", 1690, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2];
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t copy_len = std::min((uint32_t)src.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbCatW(dst, cbDest, src) — byte-count version of StringCchCatW */
    Thunk("StringCbCatW", 1694, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2];
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchCatExW(dst, cchDest, src, ppszDestEnd, pcchRemaining, dwFlags) */
    Thunk("StringCchCatExW", 1695, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcchRemaining = ReadStackArg(regs, mem, 0);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + (cur_len + copy_len) * 2);
        if (pcchRemaining) mem.Write32(pcchRemaining, cch - cur_len - copy_len);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbCatExW(dst, cbDest, src, ppszDestEnd, pcbRemaining, dwFlags) */
    Thunk("StringCbCatExW", 1696, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cb = regs[1], src_ptr = regs[2], ppEnd = regs[3];
        uint32_t pcbRemaining = ReadStackArg(regs, mem, 0);
        uint32_t cch = cb / 2;
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t cur_len = (uint32_t)existing.size();
        uint32_t avail = (cur_len < cch) ? cch - cur_len - 1 : 0;
        uint32_t copy_len = std::min((uint32_t)src.size(), avail);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + (cur_len + i) * 2, src[i]);
        mem.Write16(dst + (cur_len + copy_len) * 2, 0);
        if (ppEnd) mem.Write32(ppEnd, dst + (cur_len + copy_len) * 2);
        if (pcbRemaining) mem.Write32(pcbRemaining, (cch - cur_len - copy_len) * 2);
        regs[0] = (src.size() > avail) ? 0x8007007A : 0;
        return true;
    });
    /* StringCchPrintfExW(dst, cchDest, ppszDestEnd, pcchRemaining, dwFlags, pszFormat, ...) */
    Thunk("StringCchPrintfExW", 1701, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], ppEnd = regs[2], pcchRemaining = regs[3];
        uint32_t dwFlags = ReadStackArg(regs, mem, 0);
        uint32_t fmtPtr = ReadStackArg(regs, mem, 1);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring fmt = ReadWStringFromEmu(mem, fmtPtr);
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = ReadStackArg(regs, mem, 2 + i);
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
    /* StringCchCopyNW(dst, cchDest, src, cchToCopy) */
    Thunk("StringCchCopyNW", 1742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1], src_ptr = regs[2], cchToCopy = regs[3];
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t src_len = std::min((uint32_t)src.size(), cchToCopy);
        uint32_t copy_len = std::min(src_len, cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, src[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (src_len >= cch) ? 0x8007007A : 0;
        return true;
    });
    Thunk("StringCchLengthW", 1748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t psz = regs[0], cchMax = regs[1], pcch_out = regs[2];
        if (!psz) { regs[0] = 0x80070057; return true; } /* STRSAFE_E_INVALID_PARAMETER */
        uint32_t len = 0;
        for (; len < cchMax; len++) { if (mem.Read16(psz + len * 2) == 0) break; }
        if (len >= cchMax) { if (pcch_out) mem.Write32(pcch_out, 0); regs[0] = 0x8007007A; return true; }
        if (pcch_out) mem.Write32(pcch_out, len);
        regs[0] = 0; /* S_OK */
        return true;
    });
    /* StringCchVPrintfW(dst, cchDest, pszFormat, argList) — va_list version.
       On ARM, va_list is a pointer into the stack where args were pushed. */
    Thunk("StringCchVPrintfW", 1697, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], cch = regs[1];
        std::wstring fmt = ReadWStringFromEmu(mem, regs[2]);
        uint32_t va = regs[3]; /* pointer to va_list args in emulated memory */
        uint32_t args[10];
        for (int i = 0; i < 10; i++) args[i] = mem.Read32(va + i * 4);
        std::wstring result = WprintfFormat(mem, fmt, args, 10);
        if (!dst || cch == 0) { regs[0] = 0x80070057; return true; }
        uint32_t copy_len = std::min((uint32_t)result.size(), cch - 1);
        for (uint32_t i = 0; i < copy_len; i++) mem.Write16(dst + i * 2, result[i]);
        mem.Write16(dst + copy_len * 2, 0);
        regs[0] = (result.size() >= cch) ? 0x8007007A : 0;
        return true;
    });
    /* StringCbLengthW(psz, cbMax, pcb) — byte-count version of StringCchLengthW */
    Thunk("StringCbLengthW", 1749, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t psz = regs[0], cbMax = regs[1], pcb_out = regs[2];
        if (!psz) { regs[0] = 0x80070057; return true; }
        uint32_t cchMax = cbMax / 2;
        uint32_t len = 0;
        for (; len < cchMax; len++) { if (mem.Read16(psz + len * 2) == 0) break; }
        if (len >= cchMax) { if (pcb_out) mem.Write32(pcb_out, 0); regs[0] = 0x8007007A; return true; }
        if (pcb_out) mem.Write32(pcb_out, len * 2);
        regs[0] = 0;
        return true;
    });
    /* wcscpy_s(dst, destsz, src) — safe wide string copy (C11) */
    Thunk("wcscpy_s", 2629, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], destsz = regs[1], src_ptr = regs[2];
        if (!dst || destsz == 0) { regs[0] = 22; return true; } /* EINVAL */
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        if (src.size() >= destsz) { mem.Write16(dst, 0); regs[0] = 34; return true; } /* ERANGE */
        for (uint32_t i = 0; i <= (uint32_t)src.size(); i++) mem.Write16(dst + i * 2, src[i]);
        regs[0] = 0;
        return true;
    });
    /* wcsncat_s(dst, destsz, src, count) — safe wide string concat */
    Thunk("wcsncat_s", 2631, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[0], destsz = regs[1], src_ptr = regs[2], count = regs[3];
        if (!dst || destsz == 0) { regs[0] = 22; return true; }
        std::wstring existing = ReadWStringFromEmu(mem, dst);
        std::wstring src = ReadWStringFromEmu(mem, src_ptr);
        uint32_t append_len = std::min((uint32_t)src.size(), count);
        if (existing.size() + append_len >= destsz) { mem.Write16(dst, 0); regs[0] = 34; return true; }
        for (uint32_t i = 0; i < append_len; i++)
            mem.Write16(dst + ((uint32_t)existing.size() + i) * 2, src[i]);
        mem.Write16(dst + ((uint32_t)existing.size() + append_len) * 2, 0);
        regs[0] = 0;
        return true;
    });
    /* ANSI/extended variants: StringCchCopyA, StringCchCatA, StringCchPrintfA,
       va_list versions, wcsncpy_s, etc. — in string_safe_ext.cpp */
    RegisterStringSafeExtHandlers();
}
