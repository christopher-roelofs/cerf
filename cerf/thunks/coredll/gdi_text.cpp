/* GDI thunks: text metrics and text output (DrawText, ExtTextOut, etc.)
   Font creation/enumeration thunks are in gdi_font.cpp. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterGdiTextHandlers() {
    Thunk("GetTextMetricsW", 898, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        TEXTMETRICW tm; BOOL ret = GetTextMetricsW(hdc, &tm);
        if (ret && regs[1]) {
            mem.Write32(regs[1]+0, tm.tmHeight); mem.Write32(regs[1]+4, tm.tmAscent);
            mem.Write32(regs[1]+8, tm.tmDescent); mem.Write32(regs[1]+12, tm.tmInternalLeading);
            mem.Write32(regs[1]+16, tm.tmExternalLeading); mem.Write32(regs[1]+20, tm.tmAveCharWidth);
            mem.Write32(regs[1]+24, tm.tmMaxCharWidth); mem.Write32(regs[1]+28, tm.tmWeight);
            mem.Write32(regs[1]+32, tm.tmOverhang); mem.Write32(regs[1]+36, tm.tmDigitizedAspectX);
            mem.Write32(regs[1]+40, tm.tmDigitizedAspectY);
            mem.Write16(regs[1]+44, tm.tmFirstChar); mem.Write16(regs[1]+46, tm.tmLastChar);
            mem.Write16(regs[1]+48, tm.tmDefaultChar); mem.Write16(regs[1]+50, tm.tmBreakChar);
            mem.Write8(regs[1]+52, tm.tmItalic); mem.Write8(regs[1]+53, tm.tmUnderlined);
            mem.Write8(regs[1]+54, tm.tmStruckOut); mem.Write8(regs[1]+55, tm.tmPitchAndFamily);
            mem.Write8(regs[1]+56, tm.tmCharSet);
        }
        LOG(API, "[API] GetTextMetricsW(hdc=0x%08X) -> %d h=%d asc=%d desc=%d avgW=%d maxW=%d\n",
            (uint32_t)(uintptr_t)hdc, ret, tm.tmHeight, tm.tmAscent, tm.tmDescent,
            tm.tmAveCharWidth, tm.tmMaxCharWidth);
        regs[0] = ret; return true;
    });
    Thunk("DrawTextW", 945, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        int count = (int32_t)regs[2]; uint32_t rect_addr = regs[3];
        uint32_t format = ReadStackArg(regs, mem, 0);
        RECT rc; rc.left = (int32_t)mem.Read32(rect_addr); rc.top = (int32_t)mem.Read32(rect_addr+4);
        rc.right = (int32_t)mem.Read32(rect_addr+8); rc.bottom = (int32_t)mem.Read32(rect_addr+12);
        LOG(API, "[API] DrawTextW(hdc=%p, '%ls', count=%d, {%ld,%ld,%ld,%ld}, fmt=0x%X)\n",
            hdc, text.c_str(), count, rc.left, rc.top, rc.right, rc.bottom, format);
        int ret = ::DrawTextW(hdc, text.c_str(), count, &rc, format);
        mem.Write32(rect_addr, (uint32_t)rc.left); mem.Write32(rect_addr+4, (uint32_t)rc.top);
        mem.Write32(rect_addr+8, (uint32_t)rc.right); mem.Write32(rect_addr+12, (uint32_t)rc.bottom);
        regs[0] = (uint32_t)ret; return true;
    });
    Thunk("SetTextAlign", 1654, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetTextAlign(GDI_HDC(regs[0]), regs[1]); return true; });
    Thunk("GetTextAlign", 1655, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetTextAlign(GDI_HDC(regs[0])); return true; });
    /* ExtTextOutW(hdc, x, y, options, lprc, lpString, nCount, lpDx)
       r0=hdc, r1=x, r2=y, r3=options, stack[0]=lprc, stack[1]=lpString,
       stack[2]=nCount, stack[3]=lpDx */
    Thunk("ExtTextOutW", 896, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Log is deferred to after parameter extraction for full context */
        HDC hdc = GDI_HDC(regs[0]);
        int x = (int)regs[1], y = (int)regs[2];
        UINT options = regs[3];
        uint32_t lprc_addr = ReadStackArg(regs, mem, 0);
        uint32_t lpStr_addr = ReadStackArg(regs, mem, 1);
        UINT count = ReadStackArg(regs, mem, 2);
        uint32_t lpDx_addr = ReadStackArg(regs, mem, 3);
        RECT rc = {};
        RECT* prc = NULL;
        if (lprc_addr) {
            rc.left = (int32_t)mem.Read32(lprc_addr);
            rc.top = (int32_t)mem.Read32(lprc_addr + 4);
            rc.right = (int32_t)mem.Read32(lprc_addr + 8);
            rc.bottom = (int32_t)mem.Read32(lprc_addr + 12);
            prc = &rc;
        }
        std::wstring text;
        if (lpStr_addr && count > 0) {
            text.resize(count);
            for (UINT i = 0; i < count; i++)
                text[i] = (wchar_t)mem.Read16(lpStr_addr + i * 2);
        }
        std::vector<INT> dx;
        INT* pdx = NULL;
        if (lpDx_addr && count > 0) {
            dx.resize(count);
            for (UINT i = 0; i < count; i++)
                dx[i] = (INT)mem.Read32(lpDx_addr + i * 4);
            pdx = dx.data();
        }
        LOG(API, "[API] ExtTextOutW(hdc=%p, x=%d, y=%d, opts=0x%X, rc=%s, count=%d, str=0x%08X, text='%ls') -> ...\n",
            hdc, x, y, options,
            prc ? "yes" : "null", count, lpStr_addr,
            (count > 0 && count < 100) ? text.c_str() : L"(long/empty)");
        BOOL ret = ExtTextOutW(hdc, x, y, options, prc,
                               text.empty() ? NULL : text.c_str(), count, pdx);
        LOG(API, "[API] ExtTextOutW -> %d\n", ret);
        regs[0] = ret;
        return true;
    });
    /* GetTextExtentExPointW(hdc, lpszStr, cchString, nMaxExtent,
       lpnFit, alpDx, lpSize)
       r0=hdc, r1=lpszStr, r2=cchString, r3=nMaxExtent,
       stack[0]=lpnFit, stack[1]=alpDx, stack[2]=lpSize */
    Thunk("GetTextExtentExPointW", 897, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        uint32_t str_addr = regs[1];
        int cch = (int)regs[2];
        int maxExtent = (int)regs[3];
        uint32_t pnFit_addr = ReadStackArg(regs, mem, 0);
        uint32_t alpDx_addr = ReadStackArg(regs, mem, 1);
        uint32_t pSize_addr = ReadStackArg(regs, mem, 2);
        std::wstring text;
        if (str_addr && cch > 0) {
            text.resize(cch);
            for (int i = 0; i < cch; i++)
                text[i] = (wchar_t)mem.Read16(str_addr + i * 2);
        }
        int nFit = 0;
        std::vector<INT> dx(cch > 0 ? cch : 1);
        SIZE sz = {};
        BOOL ret = GetTextExtentExPointW(hdc, text.c_str(), cch, maxExtent,
                                          &nFit, dx.data(), &sz);
        if (ret) {
            if (pnFit_addr) mem.Write32(pnFit_addr, (uint32_t)nFit);
            if (alpDx_addr) {
                for (int i = 0; i < nFit; i++)
                    mem.Write32(alpDx_addr + i * 4, (uint32_t)dx[i]);
            }
            if (pSize_addr) {
                mem.Write32(pSize_addr, (uint32_t)sz.cx);
                mem.Write32(pSize_addr + 4, (uint32_t)sz.cy);
            }
        }
        LOG(API, "[API] GetTextExtentExPointW(hdc=0x%08X, cch=%d, maxExt=%d) -> %d fit=%d sz={%d,%d}\n",
            (uint32_t)(uintptr_t)hdc, cch, maxExtent, ret, nFit, (int)sz.cx, (int)sz.cy);
        regs[0] = ret;
        return true;
    });
}
