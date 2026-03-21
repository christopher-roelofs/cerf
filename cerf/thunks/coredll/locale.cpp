/* Locale thunks: locale info, code pages, date/time/number/currency formatting */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"

void Win32Thunks::RegisterLocaleHandlers() {
    Thunk("GetLocaleInfoW", 200, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        wchar_t buf[256] = {}; uint32_t maxlen = regs[3]; if (maxlen > 256) maxlen = 256;
        int ret = GetLocaleInfoW(regs[0], regs[1], buf, (int)maxlen);
        for (int i = 0; i < ret; i++) mem.Write16(regs[2] + i * 2, buf[i]);
        regs[0] = ret; return true;
    });
    Thunk("GetSystemDefaultLangID", 211, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetSystemDefaultLangID(); return true;
    });
    Thunk("GetUserDefaultLangID", 212, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetUserDefaultLangID(); return true;
    });
    Thunk("GetUserDefaultLCID", 215, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetUserDefaultLCID(); return true;
    });
    Thunk("IsValidLocale", 209, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = IsValidLocale((LCID)regs[0], regs[1]); return true;
    });
    Thunk("GetSystemDefaultLCID", 213, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetSystemDefaultLCID(); return true;
    });
    Thunk("ConvertDefaultLocale", 210, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ConvertDefaultLocale(regs[0]); return true;
    });
    Thunk("GetACP", 186, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetACP(); return true; });
    Thunk("GetOEMCP", 187, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetOEMCP(); return true; });
    Thunk("IsValidCodePage", 185, [](uint32_t* regs, EmulatedMemory&) -> bool {
        UINT cp = regs[0];
        regs[0] = IsValidCodePage(cp);
        LOG(API, "[API] IsValidCodePage(%u) -> %u\n", cp, regs[0]);
        return true;
    });
    Thunk("GetCPInfo", 188, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        UINT codePage = regs[0];
        uint32_t cpinfo_addr = regs[1];
        CPINFO cpi = {};
        BOOL ret = GetCPInfo(codePage, &cpi);
        if (ret && cpinfo_addr) {
            mem.Write32(cpinfo_addr, cpi.MaxCharSize);
            mem.Write8(cpinfo_addr + 4, cpi.DefaultChar[0]);
            mem.Write8(cpinfo_addr + 5, cpi.DefaultChar[1]);
            for (int i = 0; i < MAX_LEADBYTES && i < 12; i++)
                mem.Write8(cpinfo_addr + 6 + i, cpi.LeadByte[i]);
        }
        LOG(API, "[API] GetCPInfo(cp=%u) -> %d (MaxCharSize=%u)\n",
            codePage, ret, cpi.MaxCharSize);
        regs[0] = ret;
        return true;
    });
    Thunk("LCMapStringW", 199, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LCID locale = regs[0];
        DWORD flags = regs[1];
        std::wstring src = ReadWStringFromEmu(mem, regs[2]);
        int srcLen = (int)regs[3];
        uint32_t dst_addr = ReadStackArg(regs, mem, 0);
        int dstLen = (int)ReadStackArg(regs, mem, 1);
        if (srcLen == -1) srcLen = (int)src.length();
        if (dst_addr == 0 || dstLen == 0) {
            /* Query required size */
            regs[0] = LCMapStringW(locale, flags, src.c_str(), srcLen, NULL, 0);
        } else {
            std::vector<wchar_t> buf(dstLen + 1, 0);
            int ret = LCMapStringW(locale, flags, src.c_str(), srcLen, buf.data(), dstLen);
            for (int i = 0; i < ret && i < dstLen; i++)
                mem.Write16(dst_addr + i * 2, buf[i]);
            regs[0] = ret;
        }
        return true;
    });
    /* GetTimeFormatW(Locale, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime)
       r0=Locale, r1=dwFlags, r2=lpTime(ARM ptr to SYSTEMTIME), r3=lpFormat(ARM ptr),
       stack[0]=lpTimeStr(ARM ptr), stack[1]=cchTime */
    Thunk("GetTimeFormatW", 202, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LCID locale = regs[0];
        DWORD flags = regs[1];
        uint32_t lpTime_addr = regs[2];
        uint32_t lpFormat_addr = regs[3];
        uint32_t lpOut_addr = ReadStackArg(regs, mem, 0);
        int cch = (int)ReadStackArg(regs, mem, 1);
        SYSTEMTIME st = {}, *pst = NULL;
        if (lpTime_addr) {
            st.wYear = mem.Read16(lpTime_addr);
            st.wMonth = mem.Read16(lpTime_addr + 2);
            st.wDayOfWeek = mem.Read16(lpTime_addr + 4);
            st.wDay = mem.Read16(lpTime_addr + 6);
            st.wHour = mem.Read16(lpTime_addr + 8);
            st.wMinute = mem.Read16(lpTime_addr + 10);
            st.wSecond = mem.Read16(lpTime_addr + 12);
            st.wMilliseconds = mem.Read16(lpTime_addr + 14);
            pst = &st;
        }
        std::wstring fmt;
        LPCWSTR pFmt = NULL;
        if (lpFormat_addr) { fmt = ReadWStringFromEmu(mem, lpFormat_addr); pFmt = fmt.c_str(); }
        wchar_t buf[256] = {};
        int ret = GetTimeFormatW(locale, flags, pst, pFmt, buf, 256);
        if (ret > 0 && lpOut_addr && cch > 0) {
            int copy = (ret < cch) ? ret : cch;
            for (int i = 0; i < copy; i++) mem.Write16(lpOut_addr + i * 2, buf[i]);
        } else if (cch == 0) {
            /* Query mode: return required size */
        }
        LOG(API, "[API] GetTimeFormatW(locale=0x%X, flags=0x%X, fmt=%ls) -> %d '%ls'\n",
            locale, flags, pFmt ? pFmt : L"(null)", ret, buf);
        regs[0] = ret;
        return true;
    });
    /* GetDateFormatW — same signature as GetTimeFormatW */
    Thunk("GetDateFormatW", 203, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LCID locale = regs[0];
        DWORD flags = regs[1];
        uint32_t lpDate_addr = regs[2];
        uint32_t lpFormat_addr = regs[3];
        uint32_t lpOut_addr = ReadStackArg(regs, mem, 0);
        int cch = (int)ReadStackArg(regs, mem, 1);
        SYSTEMTIME st = {}, *pst = NULL;
        if (lpDate_addr) {
            st.wYear = mem.Read16(lpDate_addr);
            st.wMonth = mem.Read16(lpDate_addr + 2);
            st.wDayOfWeek = mem.Read16(lpDate_addr + 4);
            st.wDay = mem.Read16(lpDate_addr + 6);
            st.wHour = mem.Read16(lpDate_addr + 8);
            st.wMinute = mem.Read16(lpDate_addr + 10);
            st.wSecond = mem.Read16(lpDate_addr + 12);
            st.wMilliseconds = mem.Read16(lpDate_addr + 14);
            pst = &st;
        }
        std::wstring fmt;
        LPCWSTR pFmt = NULL;
        if (lpFormat_addr) { fmt = ReadWStringFromEmu(mem, lpFormat_addr); pFmt = fmt.c_str(); }
        wchar_t buf[256] = {};
        int ret = GetDateFormatW(locale, flags, pst, pFmt, buf, 256);
        if (ret > 0 && lpOut_addr && cch > 0) {
            int copy = (ret < cch) ? ret : cch;
            for (int i = 0; i < copy; i++) mem.Write16(lpOut_addr + i * 2, buf[i]);
        }
        LOG(API, "[API] GetDateFormatW(locale=0x%X, flags=0x%X) -> %d '%ls'\n",
            locale, flags, ret, buf);
        regs[0] = ret;
        return true;
    });
    Thunk("GetNumberFormatW", 204, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("GetCurrencyFormatW", 205, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* Language */
    Thunk("GetUserDefaultUILanguage", 1318, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x0409; /* US English */
        return true;
    });
    Thunk("GetSystemDefaultUILanguage", 1319, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x0409; /* US English */
        return true;
    });
    Thunk("CharLowerBuffW", 222, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], len = regs[1];
        for (uint32_t i = 0; i < len; i++) {
            uint16_t ch = mem.Read16(addr + i * 2);
            mem.Write16(addr + i * 2, (uint16_t)towlower(ch));
        }
        regs[0] = len; return true;
    });
    Thunk("CharUpperBuffW", 223, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t addr = regs[0], len = regs[1];
        for (uint32_t i = 0; i < len; i++) {
            uint16_t ch = mem.Read16(addr + i * 2);
            mem.Write16(addr + i * 2, (uint16_t)towupper(ch));
        }
        regs[0] = len; return true;
    });
    Thunk("_ltow", 1040, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        long value = (int32_t)regs[0];
        uint32_t buf_addr = regs[1];
        int radix = regs[2];
        wchar_t buf[34];
        _ltow(value, buf, radix);
        for (int i = 0; buf[i]; i++) mem.Write16(buf_addr + i * 2, buf[i]);
        mem.Write16(buf_addr + (uint32_t)wcslen(buf) * 2, 0);
        regs[0] = buf_addr;
        return true;
    });
    Thunk("_itow", 1026, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int value = (int32_t)regs[0];
        uint32_t buf_addr = regs[1];
        int radix = regs[2];
        wchar_t buf[34];
        _itow(value, buf, radix);
        for (int i = 0; buf[i]; i++) mem.Write16(buf_addr + i * 2, buf[i]);
        mem.Write16(buf_addr + (uint32_t)wcslen(buf) * 2, 0);
        regs[0] = buf_addr;
        return true;
    });
    Thunk("EnumCalendarInfoW", 206, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] EnumCalendarInfoW -> stub 0\n");
        regs[0] = 0; return true;
    });
}
