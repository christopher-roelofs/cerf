/* IDirectDrawSurface5 method handlers and vtable construction.
   See ddraw_iface.cpp for the DirectDraw overview. */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <map>
#include <mutex>

/* Imported from ddraw_iface.cpp */
struct DDSurfaceState {
    HBITMAP hbm; HDC hdc; void* pvBits;
    int width, height, bpp;
    uint32_t emu_addr, emu_pvBits; int refcount;
};
extern std::mutex g_ddraw_mutex;
extern std::map<uint32_t, DDSurfaceState*> g_surfaces;
extern bool g_vtables_built;

constexpr uint32_t DD_OK = 0;
constexpr uint32_t DDRAW_VTABLE_BASE = 0xCAFED000;
constexpr uint32_t DD4_VTABLE_ADDR   = DDRAW_VTABLE_BASE;
constexpr uint32_t DDS5_VTABLE_ADDR  = DDRAW_VTABLE_BASE + 0x200;
constexpr int DD4_VTABLE_SLOTS  = 28;
constexpr int DDS5_VTABLE_SLOTS = 46;

/* {06675a80-3b9b-11d2-b92f-00609797ea5b} */
static const uint8_t IID_IDirectDrawSurface5[] = {
    0x80,0x5A,0x67,0x06, 0x9B,0x3B, 0xD2,0x11,
    0xB9,0x2F, 0x00,0x60,0x97,0x97,0xEA,0x5B };

static DDSurfaceState* FindSurface(uint32_t obj) {
    std::lock_guard<std::mutex> lk(g_ddraw_mutex);
    auto it = g_surfaces.find(obj);
    return it != g_surfaces.end() ? it->second : nullptr;
}

void Win32Thunks::RegisterDirectDrawSurfaceHandlers() {
    Thunk("ddraw_DDS5_QueryInterface", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        mem.Write32(regs[2], regs[0]); /* return self */
        regs[0] = 0; return true;
    });
    Thunk("ddraw_DDS5_AddRef", [](uint32_t* regs, EmulatedMemory&) -> bool {
        auto* s = FindSurface(regs[0]);
        regs[0] = s ? ++s->refcount : 1;
        return true;
    });
    Thunk("ddraw_DDS5_Release", [](uint32_t* regs, EmulatedMemory&) -> bool {
        auto* s = FindSurface(regs[0]);
        if (s) {
            int rc = --s->refcount;
            if (rc <= 0) {
                LOG(API, "[API] DDS5::Release(0x%08X) -> destroy\n", regs[0]);
                DeleteDC(s->hdc);
                DeleteObject(s->hbm);
                std::lock_guard<std::mutex> lk(g_ddraw_mutex);
                g_surfaces.erase(regs[0]);
                delete s;
            }
            regs[0] = rc > 0 ? (uint32_t)rc : 0;
        } else { regs[0] = 0; }
        return true;
    });
    /* GetDC — the key method: returns a real native GDI DC */
    Thunk("ddraw_DDS5_GetDC", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto* s = FindSurface(regs[0]);
        if (!s) { regs[0] = 0x80004005; return true; } /* E_FAIL */
        uint32_t phDC = regs[1];
        uint32_t hdc32 = (uint32_t)(uintptr_t)s->hdc;
        mem.Write32(phDC, hdc32);
        LOG(API, "[API] DDS5::GetDC(0x%08X) -> hdc=0x%08X\n", regs[0], hdc32);
        regs[0] = DD_OK; return true;
    });
    /* ReleaseDC — keep DC alive for surface lifetime */
    Thunk("ddraw_DDS5_ReleaseDC", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DDS5::ReleaseDC(0x%08X)\n", regs[0]);
        regs[0] = DD_OK; return true;
    });
    /* Lock — fill DDSURFACEDESC2 with surface info */
    Thunk("ddraw_DDS5_Lock", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto* s = FindSurface(regs[0]);
        if (!s) { regs[0] = 0x80004005; return true; }
        uint32_t descAddr = regs[2]; /* lpDDSurfaceDesc */
        if (descAddr) {
            constexpr uint32_t DDSD_SIZE = 124;
            uint32_t stride = ((s->width * s->bpp + 31) / 32) * 4;
            mem.Write32(descAddr + 0, DDSD_SIZE);  /* dwSize */
            mem.Write32(descAddr + 4, 0x100F);     /* dwFlags: all relevant */
            mem.Write32(descAddr + 8, (uint32_t)s->height);
            mem.Write32(descAddr + 12, (uint32_t)s->width);
            mem.Write32(descAddr + 16, stride);    /* lPitch */
            mem.Write32(descAddr + 24, s->emu_pvBits); /* lpSurface */
        }
        regs[0] = DD_OK; return true;
    });
    Thunk("ddraw_DDS5_Unlock", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DD_OK; return true;
    });
    /* GetSurfaceDesc */
    Thunk("ddraw_DDS5_GetSurfaceDesc", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        auto* s = FindSurface(regs[0]);
        if (!s) { regs[0] = 0x80004005; return true; }
        uint32_t descAddr = regs[1];
        uint32_t stride = ((s->width * s->bpp + 31) / 32) * 4;
        mem.Write32(descAddr + 0, 124);
        mem.Write32(descAddr + 4, 0x100F);
        mem.Write32(descAddr + 8, (uint32_t)s->height);
        mem.Write32(descAddr + 12, (uint32_t)s->width);
        mem.Write32(descAddr + 16, stride);
        regs[0] = DD_OK; return true;
    });
    /* Per-method stubs with logging */
    auto mkStub5 = [this](const char* name) {
        std::string sn(name);
        Thunk(name, [sn](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s(0x%08X, R1=0x%08X, R2=0x%08X)\n",
                sn.c_str(), regs[0], regs[1], regs[2]);
            regs[0] = DD_OK; return true;
        });
    };
    for (auto& n : {"ddraw_DDS5_AddAttachedSurface","ddraw_DDS5_AddOverlayDirtyRect",
        "ddraw_DDS5_Blt","ddraw_DDS5_BltBatch","ddraw_DDS5_BltFast",
        "ddraw_DDS5_DeleteAttachedSurface","ddraw_DDS5_EnumAttachedSurfaces",
        "ddraw_DDS5_EnumOverlayZOrders","ddraw_DDS5_Flip",
        "ddraw_DDS5_GetAttachedSurface","ddraw_DDS5_GetBltStatus",
        "ddraw_DDS5_GetCaps","ddraw_DDS5_GetClipper","ddraw_DDS5_GetColorKey",
        "ddraw_DDS5_GetFlipStatus","ddraw_DDS5_GetOverlayPosition",
        "ddraw_DDS5_GetPalette","ddraw_DDS5_GetPixelFormat",
        "ddraw_DDS5_Initialize","ddraw_DDS5_IsLost",
        "ddraw_DDS5_Restore","ddraw_DDS5_SetClipper","ddraw_DDS5_SetColorKey",
        "ddraw_DDS5_SetOverlayPosition","ddraw_DDS5_SetPalette",
        "ddraw_DDS5_UpdateOverlay","ddraw_DDS5_UpdateOverlayDisplay",
        "ddraw_DDS5_UpdateOverlayZOrder","ddraw_DDS5_GetDDInterface",
        "ddraw_DDS5_PageLock","ddraw_DDS5_PageUnlock",
        "ddraw_DDS5_SetSurfaceDesc","ddraw_DDS5_SetPrivateData",
        "ddraw_DDS5_GetPrivateData","ddraw_DDS5_FreePrivateData",
        "ddraw_DDS5_GetUniquenessValue","ddraw_DDS5_ChangeUniquenessValue",
        "ddraw_DDS5_AlphaBlt"})
        mkStub5(n);
}

/* Build vtables in emulated memory: DD4 and DDS5 */
void Win32Thunks::BuildDirectDrawVtables(EmulatedMemory& mem) {
    if (g_vtables_built) return;
    g_vtables_built = true;
    mem.Alloc(DDRAW_VTABLE_BASE, 0x1000);
    /* IDirectDraw4 vtable */
    const char* dd4Names[] = {
        "ddraw_DD4_QueryInterface","ddraw_DD4_AddRef","ddraw_DD4_Release",
        "ddraw_DD4_Compact","ddraw_DD4_CreateClipper","ddraw_DD4_CreatePalette",
        "ddraw_DD4_CreateSurface","ddraw_DD4_DuplicateSurface",
        "ddraw_DD4_EnumDisplayModes","ddraw_DD4_EnumSurfaces",
        "ddraw_DD4_FlipToGDISurface","ddraw_DD4_GetCaps",
        "ddraw_DD4_GetDisplayMode","ddraw_DD4_GetFourCCCodes",
        "ddraw_DD4_GetGDISurface","ddraw_DD4_GetMonitorFrequency",
        "ddraw_DD4_GetScanLine","ddraw_DD4_GetVerticalBlankStatus",
        "ddraw_DD4_Initialize","ddraw_DD4_RestoreDisplayMode",
        "ddraw_DD4_SetCooperativeLevel","ddraw_DD4_SetDisplayMode",
        "ddraw_DD4_WaitForVerticalBlank","ddraw_DD4_GetAvailableVidMem",
        "ddraw_DD4_GetSurfaceFromDC","ddraw_DD4_RestoreAllSurfaces",
        "ddraw_DD4_TestCooperativeLevel","ddraw_DD4_GetDeviceIdentifier"
    };
    for (int i = 0; i < DD4_VTABLE_SLOTS; i++) {
        uint32_t thunk = AllocThunk("ddraw.dll", dd4Names[i], 0, false);
        mem.Write32(DD4_VTABLE_ADDR + i * 4, thunk);
    }
    /* IDirectDrawSurface5 vtable */
    const char* dds5Names[] = {
        "ddraw_DDS5_QueryInterface","ddraw_DDS5_AddRef","ddraw_DDS5_Release",
        "ddraw_DDS5_AddAttachedSurface","ddraw_DDS5_AddOverlayDirtyRect",
        "ddraw_DDS5_Blt","ddraw_DDS5_BltBatch","ddraw_DDS5_BltFast",
        "ddraw_DDS5_DeleteAttachedSurface","ddraw_DDS5_EnumAttachedSurfaces",
        "ddraw_DDS5_EnumOverlayZOrders","ddraw_DDS5_Flip",
        "ddraw_DDS5_GetAttachedSurface","ddraw_DDS5_GetBltStatus",
        "ddraw_DDS5_GetCaps","ddraw_DDS5_GetClipper","ddraw_DDS5_GetColorKey",
        "ddraw_DDS5_GetDC","ddraw_DDS5_GetFlipStatus",
        "ddraw_DDS5_GetOverlayPosition","ddraw_DDS5_GetPalette",
        "ddraw_DDS5_GetPixelFormat","ddraw_DDS5_GetSurfaceDesc",
        "ddraw_DDS5_Initialize","ddraw_DDS5_IsLost","ddraw_DDS5_Lock",
        "ddraw_DDS5_ReleaseDC","ddraw_DDS5_Restore","ddraw_DDS5_SetClipper",
        "ddraw_DDS5_SetColorKey","ddraw_DDS5_SetOverlayPosition",
        "ddraw_DDS5_SetPalette","ddraw_DDS5_Unlock",
        "ddraw_DDS5_UpdateOverlay","ddraw_DDS5_UpdateOverlayDisplay",
        "ddraw_DDS5_UpdateOverlayZOrder","ddraw_DDS5_GetDDInterface",
        "ddraw_DDS5_PageLock","ddraw_DDS5_PageUnlock",
        "ddraw_DDS5_SetSurfaceDesc","ddraw_DDS5_SetPrivateData",
        "ddraw_DDS5_GetPrivateData","ddraw_DDS5_FreePrivateData",
        "ddraw_DDS5_GetUniquenessValue","ddraw_DDS5_ChangeUniquenessValue",
        "ddraw_DDS5_AlphaBlt"
    };
    for (int i = 0; i < DDS5_VTABLE_SLOTS; i++) {
        uint32_t thunk = AllocThunk("ddraw.dll", dds5Names[i], 0, false);
        mem.Write32(DDS5_VTABLE_ADDR + i * 4, thunk);
    }
    LOG(DBG, "[DDraw] Built vtables: DD4 at 0x%08X (%d slots), "
        "DDS5 at 0x%08X (%d slots)\n",
        DD4_VTABLE_ADDR, DD4_VTABLE_SLOTS, DDS5_VTABLE_ADDR, DDS5_VTABLE_SLOTS);
}

/* g_vtables_built defined in ddraw_iface.cpp */
