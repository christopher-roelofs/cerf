/* GDI paint thunks: BeginPaint, EndPaint, Ellipse, clip rects — split from gdi_region.cpp */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterGdiPaintHandlers() {
    Thunk("BeginPaint", 260, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        /* ARM toolbar code sometimes passes GetClientRect's return value (TRUE=1)
           instead of the real hwnd due to register clobbering in nested callbacks.
           Detect and fix: IsWindow fails for small bogus values. */
        if (!IsWindow(hw) && tls_paint_hwnd && IsWindow(tls_paint_hwnd)) {
            LOG(API, "[API] BeginPaint: bad hwnd=0x%p, using tls_paint_hwnd=0x%p\n", hw, tls_paint_hwnd);
            hw = tls_paint_hwnd;
        } else if (!IsWindow(hw)) {
            LOG(API, "[API] BeginPaint: bad hwnd=0x%p, no fallback\n", hw);
            uint32_t ps_addr = regs[1];
            constexpr uint32_t WINCE_PAINTSTRUCT_SIZE = 64;
            for (uint32_t i = 0; i < WINCE_PAINTSTRUCT_SIZE / 4; i++)
                mem.Write32(ps_addr + i * 4, 0);
            regs[0] = 0; return true;
        }
        /* WinCE BeginPaint stores the update region HRGN in ps.rgbReserved[0..3]
           (offset 32 of PAINTSTRUCT).  ARM code (mshtml CDoc::OnPaint) reads it
           via *(HRGN*)(ps.rgbReserved) and uses it as the paint clip region.
           Desktop BeginPaint clears the update region, so capture it first.
           WinCE stores this region in SCREEN coordinates, but desktop
           GetUpdateRgn returns CLIENT coordinates — convert by offsetting
           to the window's screen position. */
        /* VL_RENDERINPROGRESS hack removed — ARM SEH dispatch now properly
           unwinds CLock destructors via SehDispatch in seh_dispatch.cpp. */
        /* CS_OWNDC windows retain the DC between paint calls. Reset the
           viewport origin to (0,0) before BeginPaint so that the system
           computes rcPaint correctly (in client coordinates, not shifted
           by a stale viewport from a previous paint cycle). */
        {
            HDC ownDC = GetDC(hw);
            if (ownDC) {
                SetViewportOrgEx(ownDC, 0, 0, NULL);
                ReleaseDC(hw, ownDC);
            }
        }
        HRGN hUpdateRgn = CreateRectRgn(0, 0, 0, 0);
        GetUpdateRgn(hw, hUpdateRgn, FALSE);
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hw, &ps);
        /* If GetUpdateRgn returned an empty/error region, fall back to rcPaint */
        RECT rgnBox;
        if (GetRgnBox(hUpdateRgn, &rgnBox) == NULLREGION || IsRectEmpty(&rgnBox)) {
            DeleteObject(hUpdateRgn);
            hUpdateRgn = CreateRectRgnIndirect(&ps.rcPaint);
        }
        /* Convert update region from client coords to screen coords (WinCE convention) */
        POINT clientOrigin = {0, 0};
        ClientToScreen(hw, &clientOrigin);
        OffsetRgn(hUpdateRgn, clientOrigin.x, clientOrigin.y);
        uint32_t ps_addr = regs[1];
        mem.Write32(ps_addr+0, (uint32_t)(uintptr_t)hdc);
        mem.Write32(ps_addr+4, ps.fErase);
        mem.Write32(ps_addr+8, ps.rcPaint.left);
        mem.Write32(ps_addr+12, ps.rcPaint.top);
        mem.Write32(ps_addr+16, ps.rcPaint.right);
        mem.Write32(ps_addr+20, ps.rcPaint.bottom);
        /* fRestore, fIncUpdate */
        mem.Write32(ps_addr+24, 0);
        mem.Write32(ps_addr+28, 0);
        /* rgbReserved[0..3] = HRGN of update region (WinCE extension) */
        constexpr uint32_t PS_RGBRESERVED_OFFSET = 32;
        mem.Write32(ps_addr + PS_RGBRESERVED_OFFSET,
                    (uint32_t)(uintptr_t)hUpdateRgn);
        /* Zero the rest of rgbReserved */
        for (uint32_t i = 1; i < 8; i++)
            mem.Write32(ps_addr + PS_RGBRESERVED_OFFSET + i * 4, 0);
        LOG(API, "[API] BeginPaint(0x%p) -> hdc=0x%08X, fErase=%d, rcPaint={%d,%d,%d,%d}, updateRgn=0x%08X\n",
            hw, (uint32_t)(uintptr_t)hdc, ps.fErase,
            ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right, ps.rcPaint.bottom,
            (uint32_t)(uintptr_t)hUpdateRgn);

        regs[0] = (uint32_t)(uintptr_t)hdc; return true;
    });
    Thunk("EndPaint", 261, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        PAINTSTRUCT ps = {}; ps.hdc = GDI_HDC(mem.Read32(regs[1]));
        LOG(API, "[API] EndPaint(0x%p, hdc=0x%08X)\n", hw, (uint32_t)(uintptr_t)ps.hdc);
        EndPaint(hw, &ps);
        /* Delete the update region HRGN stored in rgbReserved by BeginPaint */
        constexpr uint32_t PS_RGBRESERVED_OFFSET = 32;
        HRGN hRgn = GDI_HRGN(mem.Read32(regs[1] + PS_RGBRESERVED_OFFSET));
        if (hRgn) DeleteObject(hRgn);
        regs[0] = 1; return true;
    });
    Thunk("Ellipse", 934, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ::Ellipse(GDI_HDC(regs[0]),
            (int)regs[1], (int)regs[2], (int)regs[3], (int)ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("ExcludeClipRect", 970, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ExcludeClipRect(GDI_HDC(regs[0]),
            (int)regs[1], (int)regs[2], (int)regs[3], (int)ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("SetWindowRgn", 1398, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        HRGN rgn = GDI_HRGN(regs[1]);
        BOOL redraw = regs[2];
        regs[0] = SetWindowRgn(hw, rgn, redraw);
        return true;
    });
    Thunk("GetWindowRgn", 1399, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetWindowRgn((HWND)(intptr_t)(int32_t)regs[0], GDI_HRGN(regs[1]));
        return true;
    });
}
