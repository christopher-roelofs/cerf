/* GDI thunks: font creation, enumeration, charset info */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

/* Read WinCE system font configuration from HKLM\System\GDI\SYSFNT registry.
   This is how real WinCE configures the System/default GUI font. */
void Win32Thunks::InitWceSysFont() {
    RegValue val;
    /* "Nm" = font name (REG_SZ) */
    if (RegGetValue(L"hklm\\system\\gdi\\sysfnt", L"nm", val) && val.type == REG_SZ && val.data.size() >= 2) {
        wce_sysfont_name.clear();
        const wchar_t* p = (const wchar_t*)val.data.data();
        size_t len = val.data.size() / 2;
        for (size_t i = 0; i < len && p[i]; i++) wce_sysfont_name += p[i];
    }
    /* "Ht" = height (REG_DWORD, negative = point size) */
    if (RegGetValue(L"hklm\\system\\gdi\\sysfnt", L"ht", val) && val.type == REG_DWORD && val.data.size() >= 4)
        wce_sysfont_height = *(LONG*)val.data.data();
    /* "Wt" = weight (REG_DWORD, 400=normal, 700=bold) */
    if (RegGetValue(L"hklm\\system\\gdi\\sysfnt", L"wt", val) && val.type == REG_DWORD && val.data.size() >= 4)
        wce_sysfont_weight = *(LONG*)val.data.data();
    LOG(API, "[API] WinCE system font: '%ls' height=%d weight=%d\n",
        wce_sysfont_name.c_str(), wce_sysfont_height, wce_sysfont_weight);
}

void Win32Thunks::RegisterGdiFontHandlers() {
    Thunk("CreateFontIndirectW", 895, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* LOGFONTW is 92 bytes, identical layout on 32-bit WinCE and 64-bit Windows */
        uint32_t p = regs[0];
        LOGFONTW lf = {};
        lf.lfHeight         = (LONG)mem.Read32(p);
        lf.lfWidth          = (LONG)mem.Read32(p + 4);
        lf.lfEscapement     = (LONG)mem.Read32(p + 8);
        lf.lfOrientation    = (LONG)mem.Read32(p + 12);
        lf.lfWeight         = (LONG)mem.Read32(p + 16);
        lf.lfItalic         = mem.Read8(p + 20);
        lf.lfUnderline      = mem.Read8(p + 21);
        lf.lfStrikeOut      = mem.Read8(p + 22);
        lf.lfCharSet        = mem.Read8(p + 23);
        lf.lfOutPrecision   = mem.Read8(p + 24);
        lf.lfClipPrecision  = mem.Read8(p + 25);
        lf.lfQuality        = mem.Read8(p + 26);
        lf.lfPitchAndFamily = mem.Read8(p + 27);
        for (int i = 0; i < 32; i++) {
            lf.lfFaceName[i] = mem.Read16(p + 28 + i * 2);
            if (!lf.lfFaceName[i]) break;
        }
        /* WinCE "System" font is configured via HKLM\System\GDI\SYSFNT registry.
           On desktop Windows, "System" is an old bitmap font that looks wrong.
           Remap to the device's configured system font (typically Tahoma). */
        if (_wcsicmp(lf.lfFaceName, L"System") == 0) {
            wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
        }
        LOG(API, "[API] CreateFontIndirectW('%ls', h=%d, w=%d, wt=%d)\n",
            lf.lfFaceName, lf.lfHeight, lf.lfWidth, lf.lfWeight);
        regs[0] = (uint32_t)(uintptr_t)CreateFontIndirectW(&lf);
        return true;
    });
    Thunk("EnumFontFamiliesW", 965, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_callback = regs[2];
        uint32_t arm_lparam = regs[3];
        LOG(API, "[API] EnumFontFamiliesW(hdc=0x%08X, proc=0x%08X)\n", regs[0], arm_callback);
        if (!callback_executor || !arm_callback) { regs[0] = 1; return true; }

        /* Scratch area for LOGFONT (92 bytes) + TEXTMETRIC (60 bytes) in ARM memory */
        static uint32_t scratch = 0x3F004000;
        if (!mem.IsValid(scratch)) mem.Alloc(scratch, 0x1000);
        uint32_t lf_addr = scratch;
        uint32_t tm_addr = scratch + 96;

        /* Provide a hardcoded Tahoma font — avoids native GDI calls that may
           fail in deeply nested callback context. WinCE apps just need to know
           at least one font exists. */
        static const wchar_t* font_names[] = { L"Tahoma", L"Arial", L"Courier New" };
        int result = 1;
        for (int f = 0; f < 3 && result != 0; f++) {
            /* Zero-fill both structures */
            for (uint32_t i = 0; i < 92; i++) mem.Write8(lf_addr + i, 0);
            for (uint32_t i = 0; i < 60; i++) mem.Write8(tm_addr + i, 0);
            /* LOGFONTW: height=-13, weight=400, charset=1(DEFAULT), face name */
            mem.Write32(lf_addr + 0, (uint32_t)-13);  /* lfHeight */
            mem.Write32(lf_addr + 16, 400);            /* lfWeight (FW_NORMAL) */
            mem.Write8(lf_addr + 23, 1);               /* lfCharSet (DEFAULT_CHARSET) */
            mem.Write8(lf_addr + 27, 0x22);            /* lfPitchAndFamily (VARIABLE_PITCH | FF_SWISS) */
            const wchar_t* name = font_names[f];
            for (int i = 0; name[i] && i < 31; i++) mem.Write16(lf_addr + 28 + i * 2, name[i]);
            /* TEXTMETRICW: reasonable defaults */
            mem.Write32(tm_addr + 0, 16);   /* tmHeight */
            mem.Write32(tm_addr + 4, 13);   /* tmAscent */
            mem.Write32(tm_addr + 8, 3);    /* tmDescent */
            mem.Write32(tm_addr + 20, 7);   /* tmAveCharWidth */
            mem.Write32(tm_addr + 24, 14);  /* tmMaxCharWidth */
            mem.Write32(tm_addr + 28, 400); /* tmWeight */
            mem.Write16(tm_addr + 44, 0x20); /* tmFirstChar */
            mem.Write16(tm_addr + 46, 0xFFFD); /* tmLastChar */
            mem.Write8(tm_addr + 55, 0x22); /* tmPitchAndFamily */
            mem.Write8(tm_addr + 56, 1);    /* tmCharSet (DEFAULT_CHARSET) */

            uint32_t args[4] = { lf_addr, tm_addr, 4 /* TRUETYPE_FONTTYPE */, arm_lparam };
            LOG(API, "[API] EnumFontFamiliesW: callback for '%ls'\n", name);
            result = (int)callback_executor(arm_callback, args, 4);
            LOG(API, "[API] EnumFontFamiliesW: callback returned %d\n", result);
        }
        regs[0] = (uint32_t)result;
        return true;
    });
    Thunk("GetTextFaceW", 967, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        int nCount = (int)regs[1];
        uint32_t buf_addr = regs[2];
        wchar_t face[256] = {};
        int ret = ::GetTextFaceW(hdc, 256, face);
        LOG(API, "[API] GetTextFaceW(hdc=0x%08X, nCount=%d) -> '%ls' (%d)\n",
               regs[0], nCount, face, ret);
        if (buf_addr && nCount > 0) {
            int copyLen = (ret < nCount) ? ret : nCount - 1;
            for (int i = 0; i < copyLen; i++)
                mem.Write16(buf_addr + i * 2, face[i]);
            mem.Write16(buf_addr + copyLen * 2, 0);
        }
        regs[0] = (uint32_t)ret;
        return true;
    });
    Thunk("AddFontResourceW", 893, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] AddFontResourceW -> 1\n");
        regs[0] = 1; return true;
    });
    /* TranslateCharsetInfo(lpSrc, lpcs, dwFlags)
       r0=lpSrc (value or pointer depending on dwFlags), r1=lpcs, r2=dwFlags
       dwFlags: TCI_SRCCHARSET(1)=lpSrc is charset value, TCI_SRCCODEPAGE(2)=codepage value,
                TCI_SRCFONTSIG(3)=lpSrc is pointer to FONTSIGNATURE.
       CHARSETINFO = { UINT ciCharset; UINT ciACP; FONTSIGNATURE fs; } = 32 bytes
       FONTSIGNATURE = { DWORD fsUsb[4]; DWORD fsCsb[2]; } = 24 bytes */
    Thunk("TranslateCharsetInfo", 1166, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        DWORD* lpSrc;
        FONTSIGNATURE fsSrc = {};
        uint32_t dwFlags = regs[2];
        if (dwFlags == 3 /* TCI_SRCFONTSIG */ && regs[0]) {
            /* lpSrc is a pointer to FONTSIGNATURE in emulated memory */
            for (int i = 0; i < 4; i++) fsSrc.fsUsb[i] = mem.Read32(regs[0] + i * 4);
            for (int i = 0; i < 2; i++) fsSrc.fsCsb[i] = mem.Read32(regs[0] + 16 + i * 4);
            lpSrc = (DWORD*)&fsSrc;
        } else {
            /* TCI_SRCCHARSET or TCI_SRCCODEPAGE: lpSrc is a value cast to pointer */
            lpSrc = (DWORD*)(uintptr_t)regs[0];
        }
        CHARSETINFO cs = {};
        BOOL ret = ::TranslateCharsetInfo(lpSrc, &cs, dwFlags);
        if (ret && regs[1]) {
            mem.Write32(regs[1] + 0, cs.ciCharset);
            mem.Write32(regs[1] + 4, cs.ciACP);
            /* FONTSIGNATURE at offset 8 */
            for (int i = 0; i < 4; i++) mem.Write32(regs[1] + 8 + i * 4, cs.fs.fsUsb[i]);
            for (int i = 0; i < 2; i++) mem.Write32(regs[1] + 24 + i * 4, cs.fs.fsCsb[i]);
        }
        LOG(API, "[API] TranslateCharsetInfo(src=0x%08X, flags=%u) -> %d charset=%u acp=%u\n",
            regs[0], dwFlags, ret, cs.ciCharset, cs.ciACP);
        regs[0] = ret;
        return true;
    });
    /* GetCharWidth32W(hdc, iFirstChar, iLastChar, lpBuffer)
       r0=hdc, r1=first, r2=last, r3=lpBuffer */
    Thunk("GetCharWidth32", 1664, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        UINT first = regs[1], last = regs[2];
        uint32_t buf_addr = regs[3];
        UINT count = last - first + 1;
        std::vector<INT> widths(count);
        BOOL ret = GetCharWidth32W(hdc, first, last, widths.data());
        if (ret && buf_addr) {
            for (UINT i = 0; i < count; i++)
                mem.Write32(buf_addr + i * 4, (uint32_t)widths[i]);
        }
        LOG(API, "[API] GetCharWidth32(hdc=0x%08X, first=%u, last=%u) -> %d\n",
            (uint32_t)(uintptr_t)hdc, first, last, ret);
        regs[0] = ret;
        return true;
    });
}
