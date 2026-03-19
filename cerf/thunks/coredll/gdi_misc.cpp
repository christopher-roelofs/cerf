/* GDI misc thunks: DIB color tables, ABC widths, FillRgn, ScrollDC,
   palette queries, font enumeration, pattern brush — needed by mshtml.dll */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>

void Win32Thunks::RegisterGdiMiscHandlers() {
    /* GetCurrentPositionEx(hdc, lpPoint) -> BOOL */
    Thunk("GetCurrentPositionEx", 1653, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        POINT pt = {};
        BOOL ret = ::GetCurrentPositionEx(hdc, &pt);
        if (ret && regs[1]) {
            mem.Write32(regs[1], (uint32_t)pt.x);
            mem.Write32(regs[1] + 4, (uint32_t)pt.y);
        }
        LOG(API, "[API] GetCurrentPositionEx(hdc=0x%08X) -> %d (%d,%d)\n",
            (uint32_t)(uintptr_t)hdc, ret, (int)pt.x, (int)pt.y);
        regs[0] = ret;
        return true;
    });
    /* SetDIBColorTable(hdc, iStart, cEntries, prgbq) -> UINT entries set */
    Thunk("SetDIBColorTable", 1666, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        UINT iStart = regs[1], cEntries = regs[2];
        uint8_t* host = mem.Translate(regs[3]);
        UINT ret = 0;
        if (host) ret = ::SetDIBColorTable(hdc, iStart, cEntries, (const RGBQUAD*)host);
        LOG(API, "[API] SetDIBColorTable(hdc=0x%08X, start=%u, count=%u) -> %u\n",
            (uint32_t)(uintptr_t)hdc, iStart, cEntries, ret);
        regs[0] = ret;
        return true;
    });
    /* GetDIBColorTable(hdc, iStart, cEntries, prgbq) -> UINT entries retrieved */
    Thunk("GetDIBColorTable", 1665, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        UINT iStart = regs[1], cEntries = regs[2];
        uint32_t buf_addr = regs[3];
        std::vector<RGBQUAD> entries(cEntries);
        UINT ret = ::GetDIBColorTable(hdc, iStart, cEntries, entries.data());
        if (ret && buf_addr) {
            for (UINT i = 0; i < ret; i++) {
                mem.Write8(buf_addr + i * 4 + 0, entries[i].rgbBlue);
                mem.Write8(buf_addr + i * 4 + 1, entries[i].rgbGreen);
                mem.Write8(buf_addr + i * 4 + 2, entries[i].rgbRed);
                mem.Write8(buf_addr + i * 4 + 3, entries[i].rgbReserved);
            }
        }
        LOG(API, "[API] GetDIBColorTable(hdc=0x%08X, start=%u, count=%u) -> %u\n",
            (uint32_t)(uintptr_t)hdc, iStart, cEntries, ret);
        regs[0] = ret;
        return true;
    });
    /* GetCharABCWidths(hdc, uFirstChar, uLastChar, lpABC) -> BOOL
       ABC struct: { int abcA; UINT abcB; int abcC; } = 12 bytes per char */
    Thunk("GetCharABCWidths", 1779, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        UINT first = regs[1], last = regs[2];
        uint32_t buf_addr = regs[3];
        UINT count = last - first + 1;
        std::vector<ABC> abc(count);
        BOOL ret = ::GetCharABCWidthsW(hdc, first, last, abc.data());
        if (ret && buf_addr) {
            for (UINT i = 0; i < count; i++) {
                mem.Write32(buf_addr + i * 12 + 0, (uint32_t)abc[i].abcA);
                mem.Write32(buf_addr + i * 12 + 4, abc[i].abcB);
                mem.Write32(buf_addr + i * 12 + 8, (uint32_t)abc[i].abcC);
            }
        }
        LOG(API, "[API] GetCharABCWidths(hdc=0x%08X, %u-%u) -> %d\n",
            (uint32_t)(uintptr_t)hdc, first, last, ret);
        regs[0] = ret;
        return true;
    });
    /* FillRgn(hdc, hrgn, hbr) -> BOOL */
    Thunk("FillRgn", 927, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        HRGN hrgn = GDI_HRGN(regs[1]);
        HBRUSH hbr = GDI_HBRUSH(regs[2]);
        BOOL ret = ::FillRgn(hdc, hrgn, hbr);
        LOG(API, "[API] FillRgn(hdc=0x%08X, rgn=0x%08X, br=0x%08X) -> %d\n",
            regs[0], regs[1], regs[2], ret);
        regs[0] = ret;
        return true;
    });
    /* ScrollDC(hdc, dx, dy, lprcScroll, lprcClip, hrgnUpdate, lprcUpdate)
       r0=hdc, r1=dx, r2=dy, r3=lprcScroll, stack[0..2] */
    Thunk("ScrollDC", 985, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        int dx = (int)regs[1], dy = (int)regs[2];
        RECT rcScroll = {}, rcClip = {};
        RECT* pScroll = nullptr; RECT* pClip = nullptr;
        if (regs[3]) {
            rcScroll.left = (LONG)mem.Read32(regs[3]);
            rcScroll.top = (LONG)mem.Read32(regs[3] + 4);
            rcScroll.right = (LONG)mem.Read32(regs[3] + 8);
            rcScroll.bottom = (LONG)mem.Read32(regs[3] + 12);
            pScroll = &rcScroll;
        }
        uint32_t clipAddr = ReadStackArg(regs, mem, 0);
        if (clipAddr) {
            rcClip.left = (LONG)mem.Read32(clipAddr);
            rcClip.top = (LONG)mem.Read32(clipAddr + 4);
            rcClip.right = (LONG)mem.Read32(clipAddr + 8);
            rcClip.bottom = (LONG)mem.Read32(clipAddr + 12);
            pClip = &rcClip;
        }
        HRGN hrgn = GDI_HRGN(ReadStackArg(regs, mem, 1));
        uint32_t rcUpdateAddr = ReadStackArg(regs, mem, 2);
        RECT rcUpdate = {};
        BOOL ret = ::ScrollDC(hdc, dx, dy, pScroll, pClip, hrgn, &rcUpdate);
        if (ret && rcUpdateAddr) {
            mem.Write32(rcUpdateAddr, (uint32_t)rcUpdate.left);
            mem.Write32(rcUpdateAddr + 4, (uint32_t)rcUpdate.top);
            mem.Write32(rcUpdateAddr + 8, (uint32_t)rcUpdate.right);
            mem.Write32(rcUpdateAddr + 12, (uint32_t)rcUpdate.bottom);
        }
        LOG(API, "[API] ScrollDC(hdc=0x%08X, dx=%d, dy=%d) -> %d\n",
            (uint32_t)(uintptr_t)hdc, dx, dy, ret);
        regs[0] = ret;
        return true;
    });
    /* GetDCEx(hwnd, hrgnClip, flags) -> HDC */
    Thunk("GetDCEx", 1185, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        HRGN hrgn = GDI_HRGN(regs[1]);
        DWORD flags = regs[2];
        HDC hdc = ::GetDCEx(hw, hrgn, flags);
        LOG(API, "[API] GetDCEx(hwnd=0x%p, rgn=0x%08X, flags=0x%X) -> 0x%08X\n",
            hw, regs[1], flags, (uint32_t)(uintptr_t)hdc);
        regs[0] = (uint32_t)(uintptr_t)hdc;
        return true;
    });
    /* GetNearestPaletteIndex(hpal, crColor) -> UINT index */
    Thunk("GetNearestPaletteIndex", 948, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HPALETTE hp = GDI_HPAL(regs[0]);
        UINT ret = ::GetNearestPaletteIndex(hp, regs[1]);
        LOG(API, "[API] GetNearestPaletteIndex(0x%08X, 0x%08X) -> %u\n",
            regs[0], regs[1], ret);
        regs[0] = ret;
        return true;
    });
    /* GetSystemPaletteEntries(hdc, iStart, nEntries, lppe) -> UINT */
    Thunk("GetSystemPaletteEntries", 950, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        UINT iStart = regs[1], nEntries = regs[2];
        uint32_t pe_addr = regs[3];
        std::vector<PALETTEENTRY> entries(nEntries);
        UINT ret = ::GetSystemPaletteEntries(hdc, iStart, nEntries,
                                              pe_addr ? entries.data() : nullptr);
        if (ret && pe_addr) {
            for (UINT i = 0; i < ret; i++) {
                mem.Write8(pe_addr + i * 4 + 0, entries[i].peRed);
                mem.Write8(pe_addr + i * 4 + 1, entries[i].peGreen);
                mem.Write8(pe_addr + i * 4 + 2, entries[i].peBlue);
                mem.Write8(pe_addr + i * 4 + 3, entries[i].peFlags);
            }
        }
        LOG(API, "[API] GetSystemPaletteEntries(hdc=0x%08X, start=%u, count=%u) -> %u\n",
            (uint32_t)(uintptr_t)hdc, iStart, nEntries, ret);
        regs[0] = ret;
        return true;
    });
    /* EnumFontFamiliesExW(hdc, lpLogfont, lpProc, lParam, dwFlags)
       r0=hdc, r1=lpLogfont, r2=lpProc, r3=lParam, stack[0]=dwFlags */
    Thunk("EnumFontFamiliesExW", 1885, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_callback = regs[2];
        uint32_t arm_lparam = regs[3];
        LOG(API, "[API] EnumFontFamiliesExW(hdc=0x%08X, proc=0x%08X)\n", regs[0], arm_callback);
        if (!callback_executor || !arm_callback) { regs[0] = 1; return true; }
        /* Reuse the same approach as EnumFontFamiliesW */
        static uint32_t scratch = 0x3F004200;
        if (!mem.IsValid(scratch)) mem.Alloc(scratch, 0x1000);
        uint32_t lf_addr = scratch;
        constexpr uint32_t TM_OFFSET = 96;
        uint32_t tm_addr = scratch + TM_OFFSET;
        static const wchar_t* font_names[] = { L"Tahoma", L"Arial", L"Courier New" };
        int result = 1;
        for (int f = 0; f < 3 && result != 0; f++) {
            for (uint32_t i = 0; i < 92; i++) mem.Write8(lf_addr + i, 0);
            for (uint32_t i = 0; i < 60; i++) mem.Write8(tm_addr + i, 0);
            mem.Write32(lf_addr + 0, (uint32_t)-13);
            mem.Write32(lf_addr + 16, 400);
            mem.Write8(lf_addr + 23, 1);
            mem.Write8(lf_addr + 27, 0x22);
            const wchar_t* name = font_names[f];
            for (int i = 0; name[i] && i < 31; i++)
                mem.Write16(lf_addr + 28 + i * 2, name[i]);
            mem.Write32(tm_addr + 0, 16);
            mem.Write32(tm_addr + 4, 13);
            mem.Write32(tm_addr + 8, 3);
            mem.Write32(tm_addr + 20, 7);
            mem.Write32(tm_addr + 24, 14);
            mem.Write32(tm_addr + 28, 400);
            uint32_t args[4] = { lf_addr, tm_addr, 4, arm_lparam };
            result = (int)callback_executor(arm_callback, args, 4);
        }
        regs[0] = (uint32_t)result;
        return true;
    });
    /* CreatePatternBrush(hbm) -> HBRUSH */
    Thunk("CreatePatternBrush", 925, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HBITMAP hbm = GDI_HBMP(regs[0]);
        HBRUSH ret = ::CreatePatternBrush(hbm);
        LOG(API, "[API] CreatePatternBrush(hbm=0x%08X) -> 0x%08X\n",
            regs[0], (uint32_t)(uintptr_t)ret);
        regs[0] = (uint32_t)(uintptr_t)ret;
        return true;
    });
}
