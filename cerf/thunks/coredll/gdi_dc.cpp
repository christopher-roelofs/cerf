#define NOMINMAX
/* GDI thunks: DC management, object selection, device caps */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <vector>
#include <algorithm>

void Win32Thunks::RegisterGdiDcHandlers() {
    Thunk("CreateCompatibleDC", 910, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDC src = GDI_HDC(regs[0]);
        HDC result = CreateCompatibleDC(src);
        LOG(API, "[API] CreateCompatibleDC(0x%08X) -> 0x%08X\n",
            (uint32_t)(uintptr_t)src, (uint32_t)(uintptr_t)result);
        regs[0] = (uint32_t)(uintptr_t)result;
        return true;
    });
    Thunk("DeleteDC", 911, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteDC(GDI_HDC(regs[0])); return true;
    });
    Thunk("GetDC", 262, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        HDC hdc = GetDC(hw);
        LOG(API, "[API] GetDC(0x%p) -> 0x%08X\n", hw, (uint32_t)(uintptr_t)hdc);
        regs[0] = (uint32_t)(uintptr_t)hdc; return true;
    });
    Thunk("ReleaseDC", 263, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* With CS_OWNDC set on all ARM window classes, GetDC returns the
           window's own persistent DC.  ReleaseDC is a no-op for own-DC
           windows on desktop Windows (the DC stays valid), matching WinCE
           behavior.  Call the native ReleaseDC for correctness. */
        regs[0] = ReleaseDC((HWND)(intptr_t)(int32_t)regs[0], GDI_HDC(regs[1]));
        return true;
    });
    Thunk("GetWindowDC", 270, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetWindowDC((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("CreateDCW", 909, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring driver = ReadWStringFromEmu(mem, regs[0]);
        regs[0] = (uint32_t)(uintptr_t)CreateDCW(driver.c_str(), NULL, NULL, NULL); return true;
    });
    Thunk("SelectObject", 921, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        HGDIOBJ hobj = GDI_OBJ(regs[1]);
        HGDIOBJ prev = SelectObject(hdc, hobj);
        LOG(API, "[API] SelectObject(hdc=0x%08X, obj=0x%08X) -> prev=0x%08X\n",
            (uint32_t)(uintptr_t)hdc, (uint32_t)(uintptr_t)hobj, (uint32_t)(uintptr_t)prev);
        regs[0] = (uint32_t)(uintptr_t)prev; return true;
    });
    Thunk("DeleteObject", 912, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DeleteObject(GDI_OBJ(regs[0])); return true;
    });
    Thunk("GetStockObject", 919, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        /* DEFAULT_GUI_FONT (17) and SYSTEM_FONT (13): WinCE configures these
           via HKLM\System\GDI\SYSFNT registry (typically Tahoma).
           Desktop Windows returns Segoe UI / System bitmap font.
           Override to match the WinCE device's configured font. */
        if (regs[0] == DEFAULT_GUI_FONT || regs[0] == SYSTEM_FONT) {
            static HFONT s_wce_font = NULL;
            if (!s_wce_font) {
                LOGFONTW lf = {};
                lf.lfHeight = wce_sysfont_height;
                lf.lfWeight = wce_sysfont_weight;
                lf.lfCharSet = DEFAULT_CHARSET;
                lf.lfQuality = DEFAULT_QUALITY;
                lf.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
                wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
                s_wce_font = CreateFontIndirectW(&lf);
                LOG(API, "[API] GetStockObject(%d) -> created '%ls' h=%d wt=%d font %p\n",
                    regs[0], wce_sysfont_name.c_str(), wce_sysfont_height, wce_sysfont_weight, s_wce_font);
            }
            if (s_wce_font) {
                regs[0] = (uint32_t)(uintptr_t)s_wce_font;
                return true;
            }
        }
        regs[0] = (uint32_t)(uintptr_t)GetStockObject(regs[0]); return true;
    });
    Thunk("GetDeviceCaps", 916, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        int index = (int)regs[1];
        if (fake_screen_resolution && index == HORZRES) { regs[0] = screen_width; return true; }
        if (fake_screen_resolution && index == VERTRES) { regs[0] = screen_height; return true; }
        /* Pass through native BITSPIXEL (32 on desktop). Apps check
           BITSPIXEL*PLANES >= 15 for high-color — 32 satisfies that.
           Using native bpp avoids 16bpp→32bpp mismatch in SelectObject
           and gives full-quality icons/bitmaps. */
        regs[0] = GetDeviceCaps(GDI_HDC(regs[0]), index);
        return true;
    });
    Thunk("SaveDC", 908, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SaveDC(GDI_HDC(regs[0])); return true;
    });
    Thunk("RestoreDC", 907, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = RestoreDC(GDI_HDC(regs[0]), regs[1]); return true;
    });
    Thunk("GetObjectW", 918, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HGDIOBJ hobj = GDI_OBJ(regs[0]);
        int cb = (int)regs[1]; uint32_t buf_addr = regs[2];
        if (buf_addr && cb > 0) {
            if (cb == 24) {
                /* 32-bit BITMAP: {bmType, bmWidth, bmHeight, bmWidthBytes, bmPlanes(16), bmBitsPixel(16), bmBits} = 24 bytes */
                BITMAP bm = {}; int ret = GetObjectW(hobj, sizeof(BITMAP), &bm);
                if (ret > 0) {
                    /* Look up emulated pvBits for this HBITMAP */
                    uint32_t emu_bits = 0;
                    auto it = hbitmap_to_emu_pvbits.find((uint32_t)(uintptr_t)hobj);
                    if (it != hbitmap_to_emu_pvbits.end()) emu_bits = it->second;
                    mem.Write32(buf_addr+0, bm.bmType); mem.Write32(buf_addr+4, bm.bmWidth);
                    mem.Write32(buf_addr+8, bm.bmHeight); mem.Write32(buf_addr+12, bm.bmWidthBytes);
                    mem.Write16(buf_addr+16, bm.bmPlanes); mem.Write16(buf_addr+18, bm.bmBitsPixel);
                    mem.Write32(buf_addr+20, emu_bits); regs[0] = 24;
                    LOG(API, "[API] GetObjectW(hbm=0x%08X, BITMAP) -> %dx%d %dbpp bmBits=0x%08X\n",
                        (uint32_t)(uintptr_t)hobj, bm.bmWidth, bm.bmHeight, bm.bmBitsPixel, emu_bits);
                } else regs[0] = 0;
            } else {
                std::vector<uint8_t> buf(std::max(cb, 64), 0);
                int ret = GetObjectW(hobj, (int)buf.size(), buf.data());
                if (ret > 0) mem.WriteBytes(buf_addr, buf.data(), std::min(ret, cb));
                regs[0] = ret;
            }
        } else regs[0] = GetObjectW(hobj, 0, NULL);
        return true;
    });
    Thunk("SetStretchBltMode", 920, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetStretchBltMode(GDI_HDC(regs[0]), regs[1]); return true; });
    /* AlphaBlend(hdcDest, xDest, yDest, wDest, hDest,
                  hdcSrc, xSrc, ySrc, wSrc, hSrc, blendFunc)
       ARM: R0=hdcDest R1=xDest R2=yDest R3=wDest
            Stack[0]=hDest [1]=hdcSrc [2]=xSrc [3]=ySrc [4]=wSrc [5]=hSrc [6]=blendFunc */
    Thunk("AlphaBlend", 1883, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cyDest  = (int)ReadStackArg(regs, mem, 0);
        HDC hdcSrc  = GDI_HDC(ReadStackArg(regs, mem, 1));
        int xSrc    = (int)ReadStackArg(regs, mem, 2);
        int ySrc    = (int)ReadStackArg(regs, mem, 3);
        int cxSrc   = (int)ReadStackArg(regs, mem, 4);
        int cySrc   = (int)ReadStackArg(regs, mem, 5);
        BLENDFUNCTION bf;
        uint32_t bfVal = ReadStackArg(regs, mem, 6);
        memcpy(&bf, &bfVal, sizeof(bf));
        regs[0] = ::AlphaBlend(
            GDI_HDC(regs[0]), (int)regs[1], (int)regs[2], (int)regs[3], cyDest,
            hdcSrc, xSrc, ySrc, cxSrc, cySrc, bf);
        return true;
    });
    Thunk("GetCurrentObject", 915, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetCurrentObject(GDI_HDC(regs[0]), regs[1]); return true;
    });
    Thunk("SetROP2", 928, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetROP2(GDI_HDC(regs[0]), regs[1]); return true;
    });
    Thunk("SetViewportOrgEx", 983, [](uint32_t* regs, EmulatedMemory&) -> bool {
        int x = (int)regs[1], y = (int)regs[2];
        LOG(API, "[API] SetViewportOrgEx(hdc=0x%08X, x=%d, y=%d)\n", regs[0], x, y);
        regs[0] = SetViewportOrgEx(GDI_HDC(regs[0]), x, y, NULL); return true;
    });
    Thunk("GetObjectType", 917, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetObjectType(GDI_OBJ(regs[0])); return true;
    });
    Thunk("CreateDIBPatternBrushPt", 929, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* lpPackedDIB points to a BITMAPINFO + bits in emulated memory.
           Copy it to host memory and create the brush natively. */
        uint32_t dib_addr = regs[0], usage = regs[1];
        uint8_t* host = mem.Translate(dib_addr);
        if (host) {
            regs[0] = (uint32_t)(uintptr_t)CreateDIBPatternBrushPt(host, usage);
        } else {
            regs[0] = 0;
        }
        return true;
    });
    Thunk("DrawEdge", 932, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={mem.Read32(regs[1]),mem.Read32(regs[1]+4),mem.Read32(regs[1]+8),mem.Read32(regs[1]+12)};
        regs[0] = DrawEdge(GDI_HDC(regs[0]), &rc, regs[2], regs[3]);
        /* Write back modified rect when BF_ADJUST (0x2000) is set */
        if (regs[3]&0x2000) { mem.Write32(regs[1],rc.left); mem.Write32(regs[1]+4,rc.top); mem.Write32(regs[1]+8,rc.right); mem.Write32(regs[1]+12,rc.bottom); }
        return true;
    });
    Thunk("DrawFrameControl", 987, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc={(LONG)mem.Read32(regs[1]),(LONG)mem.Read32(regs[1]+4),(LONG)mem.Read32(regs[1]+8),(LONG)mem.Read32(regs[1]+12)};
        regs[0] = DrawFrameControl(GDI_HDC(regs[0]), &rc, regs[2], regs[3]);
        return true;
    });
    /* WinCE 6 GDI — SetStretchBltMode alias (ordinal 1825) */
    Thunk("SetStretchBltMode_ce6", 1825, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SetStretchBltMode(hdc=0x%08X, mode=%d) -> forwarding\n", regs[0], regs[1]);
        LONG hdc_ext = (LONG)(int32_t)regs[0];
        regs[0] = (uint32_t)SetStretchBltMode((HDC)(intptr_t)hdc_ext, (int)regs[1]);
        return true;
    });
    Thunk("GetViewportOrgEx", 1988, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetViewportOrgEx(hdc=0x%08X, pt=0x%08X)\n", regs[0], regs[1]);
        LONG hdc_ext = (LONG)(int32_t)regs[0];
        POINT pt = {};
        BOOL ret = GetViewportOrgEx((HDC)(intptr_t)hdc_ext, &pt);
        if (regs[1]) { mem.Write32(regs[1], (uint32_t)pt.x); mem.Write32(regs[1] + 4, (uint32_t)pt.y); }
        regs[0] = ret;
        return true;
    });
}
