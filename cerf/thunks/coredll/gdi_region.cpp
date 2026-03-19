/* GDI thunks: regions, clipping, palette, paint */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterGdiRegionHandlers() {
    Thunk("SelectPalette", 954, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SelectPalette(GDI_HDC(regs[0]), GDI_HPAL(regs[1]), regs[2]); return true;
    });
    Thunk("RealizePalette", 953, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = RealizePalette(GDI_HDC(regs[0])); return true;
    });
    Thunk("CreatePalette", 947, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* LOGPALETTE: WORD palVersion, WORD palNumEntries, PALETTEENTRY[] */
        uint8_t* host = mem.Translate(regs[0]);
        HPALETTE hp = host ? CreatePalette((const LOGPALETTE*)host) : NULL;
        regs[0] = (uint32_t)(uintptr_t)hp;
        return true;
    });
    Thunk("GetPaletteEntries", 949, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HPALETTE hp = GDI_HPAL(regs[0]);
        UINT start = regs[1], count = regs[2]; uint32_t pe_ptr = regs[3];
        std::vector<PALETTEENTRY> entries(count);
        UINT ret = ::GetPaletteEntries(hp, start, count, entries.data());
        if (ret && pe_ptr) {
            for (UINT i = 0; i < ret; i++) {
                mem.Write8(pe_ptr + i * 4 + 0, entries[i].peRed);
                mem.Write8(pe_ptr + i * 4 + 1, entries[i].peGreen);
                mem.Write8(pe_ptr + i * 4 + 2, entries[i].peBlue);
                mem.Write8(pe_ptr + i * 4 + 3, entries[i].peFlags);
            }
        }
        regs[0] = ret;
        return true;
    });
    Thunk("CreateRectRgn", 980, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)CreateRectRgn(regs[0], regs[1], regs[2], regs[3]); return true;
    });
    Thunk("CombineRgn", 968, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HRGN dest = GDI_HRGN(regs[0]);
        HRGN src1 = GDI_HRGN(regs[1]);
        HRGN src2 = GDI_HRGN(regs[2]);
        int mode = regs[3];
        int ret = CombineRgn(dest, src1, src2, mode);
        RECT box = {};
        if (ret != ERROR && ret != NULLREGION) GetRgnBox(dest, &box);
        LOG(API, "[API] CombineRgn(dst=0x%08X, s1=0x%08X, s2=0x%08X, mode=%d) -> %d box={%d,%d,%d,%d}\n",
            regs[0], regs[1], regs[2], mode, ret, box.left, box.top, box.right, box.bottom);
        regs[0] = ret; return true;
    });
    Thunk("SelectClipRgn", 979, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        HRGN hrgn = GDI_HRGN(regs[1]);
        RECT box = {};
        if (hrgn) GetRgnBox(hrgn, &box);
        int ret = SelectClipRgn(hdc, hrgn);
        LOG(API, "[API] SelectClipRgn(hdc=0x%08X, rgn=0x%08X{%d,%d,%d,%d}) -> %d\n",
            regs[0], regs[1], box.left, box.top, box.right, box.bottom, ret);
        regs[0] = ret; return true;
    });
    Thunk("IntersectClipRect", 975, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[0]);
        int l = (int)regs[1], t = (int)regs[2], r = (int)regs[3], b = (int)ReadStackArg(regs,mem,0);
        int ret = IntersectClipRect(hdc, l, t, r, b);
        LOG(API, "[API] IntersectClipRect(hdc=0x%08X, {%d,%d,%d,%d}) -> %d\n",
            regs[0], l, t, r, b, ret);
        regs[0] = ret; return true;
    });
    Thunk("GetClipBox", 971, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; int ret = GetClipBox(GDI_HDC(regs[0]), &rc);
        mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
        mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        LOG(API, "[API] GetClipBox(hdc=0x%08X) -> %d, rc={%d,%d,%d,%d}\n",
            regs[0], ret, rc.left, rc.top, rc.right, rc.bottom);
        regs[0] = ret; return true;
    });
    Thunk("GetClipRgn", 972, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetClipRgn(GDI_HDC(regs[0]), GDI_HRGN(regs[1]));
        return true;
    });
    Thunk("SetLayout", 1890, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = SetLayout(GDI_HDC(regs[0]), regs[1]); return true; });
    Thunk("GetLayout", 1891, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = GetLayout(GDI_HDC(regs[0])); return true; });
    Thunk("CreateRectRgnIndirect", 969, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc;
        rc.left = (LONG)mem.Read32(regs[0]);
        rc.top = (LONG)mem.Read32(regs[0] + 4);
        rc.right = (LONG)mem.Read32(regs[0] + 8);
        rc.bottom = (LONG)mem.Read32(regs[0] + 12);
        regs[0] = (uint32_t)(uintptr_t)CreateRectRgnIndirect(&rc);
        return true;
    });
    Thunk("EqualRgn", 91, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = EqualRgn(GDI_HRGN(regs[0]), GDI_HRGN(regs[1]));
        return true;
    });
    /* BeginPaint, EndPaint, Ellipse, clip rects, window regions — in gdi_paint.cpp */
    RegisterGdiPaintHandlers();

    Thunk("ExtCreateRegion", 1617, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* ExtCreateRegion(lpXform, nCount, lpRgnData) */
        uint32_t xform_addr = regs[0];
        DWORD count = regs[1];
        uint32_t data_addr = regs[2];
        XFORM xf = {};
        XFORM* pXf = nullptr;
        if (xform_addr) {
            /* XFORM: 6 floats (24 bytes) — same layout on 32-bit */
            memcpy(&xf, mem.Translate(xform_addr), sizeof(XFORM));
            pXf = &xf;
        }
        uint8_t* host_data = mem.Translate(data_addr);
        HRGN rgn = ExtCreateRegion(pXf, count, (const RGNDATA*)host_data);
        LOG(API, "[API] ExtCreateRegion(xform=%s, count=%u) -> 0x%08X\n",
            pXf ? "yes" : "null", count, (uint32_t)(uintptr_t)rgn);
        regs[0] = (uint32_t)(uintptr_t)rgn;
        return true;
    });
    Thunk("GetRgnBox", 974, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc;
        int ret = GetRgnBox(GDI_HRGN(regs[0]), &rc);
        if (regs[1]) {
            mem.Write32(regs[1], rc.left); mem.Write32(regs[1]+4, rc.top);
            mem.Write32(regs[1]+8, rc.right); mem.Write32(regs[1]+12, rc.bottom);
        }
        LOG(API, "[API] GetRgnBox(0x%08X) -> %d {%d,%d,%d,%d}\n",
            regs[0], ret, rc.left, rc.top, rc.right, rc.bottom);
        regs[0] = ret;
        return true;
    });
    Thunk("OffsetRgn", 976, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HRGN rgn = GDI_HRGN(regs[0]);
        int dx = (int)regs[1], dy = (int)regs[2];
        int ret = OffsetRgn(rgn, dx, dy);
        RECT box = {};
        if (ret != ERROR && ret != NULLREGION) GetRgnBox(rgn, &box);
        LOG(API, "[API] OffsetRgn(0x%08X, dx=%d, dy=%d) -> %d box={%d,%d,%d,%d}\n",
            regs[0], dx, dy, ret, box.left, box.top, box.right, box.bottom);
        regs[0] = ret; return true;
    });
    Thunk("PtInRegion", 977, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = PtInRegion(GDI_HRGN(regs[0]), (int)regs[1], (int)regs[2]);
        return true;
    });
    Thunk("RectInRegion", 978, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc;
        rc.left = (LONG)mem.Read32(regs[1]); rc.top = (LONG)mem.Read32(regs[1]+4);
        rc.right = (LONG)mem.Read32(regs[1]+8); rc.bottom = (LONG)mem.Read32(regs[1]+12);
        regs[0] = RectInRegion(GDI_HRGN(regs[0]), &rc);
        return true;
    });
    Thunk("GetRegionData", 973, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HRGN rgn = GDI_HRGN(regs[0]);
        DWORD count = regs[1];
        uint32_t buf_addr = regs[2];
        if (!buf_addr || !count) {
            DWORD sz = GetRegionData(rgn, 0, NULL);
            LOG(API, "[API] GetRegionData SIZE QUERY(rgn=0x%08X) -> %u\n", regs[0], sz);
            regs[0] = sz;
        } else {
            std::vector<uint8_t> buf(count);
            DWORD ret = GetRegionData(rgn, count, (RGNDATA*)buf.data());
            if (ret && buf_addr) {
                mem.WriteBytes(buf_addr, buf.data(), ret);
                auto* rd = (RGNDATA*)buf.data();
                auto* rc = (RECT*)rd->Buffer;
                LOG(API, "[API] GetRegionData(rgn=0x%08X) -> %u rects, bounds={%d,%d,%d,%d}",
                    regs[0], rd->rdh.nCount,
                    rd->rdh.rcBound.left, rd->rdh.rcBound.top,
                    rd->rdh.rcBound.right, rd->rdh.rcBound.bottom);
                for (DWORD i = 0; i < rd->rdh.nCount && i < 4; i++)
                    LOG(API, " r[%u]={%d,%d,%d,%d}", i, rc[i].left, rc[i].top, rc[i].right, rc[i].bottom);
                LOG(API, "\n");
            }
            regs[0] = ret;
        }
        return true;
    });
}
