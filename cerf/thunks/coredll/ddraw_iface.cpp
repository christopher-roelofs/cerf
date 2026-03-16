/* DirectDraw COM interface implementation for mshtml rendering.
   Provides IDirectDraw4 and IDirectDrawSurface5 objects backed by native
   GDI DIB sections. mshtml calls DirectDrawCreate -> CreateSurface ->
   GetDC to obtain a DC for HTML rendering.

   The ARM ddraw.dll cannot function without a WinCE display driver (DDI).
   Instead, we intercept DirectDrawCreate at the GetProcAddress level and
   provide COM objects with vtables in emulated memory. Each vtable entry
   points to a thunk address that dispatches to native C++ handlers. */
#define NOMINMAX
#include "../win32_thunks.h"
#include "../../log.h"
#include <map>
#include <mutex>

/* ---- Address space layout for DirectDraw objects ---- */
constexpr uint32_t DDRAW_VTABLE_BASE  = 0xCAFED000;
constexpr uint32_t DD4_VTABLE_ADDR    = DDRAW_VTABLE_BASE;         /* 28 slots */
constexpr uint32_t DDS5_VTABLE_ADDR   = DDRAW_VTABLE_BASE + 0x200; /* 46 slots */
constexpr uint32_t DDRAW_OBJ_BASE     = 0xCAFEE000;
constexpr uint32_t DDRAW_OBJ_STRIDE   = 0x10;
constexpr int DD4_VTABLE_SLOTS  = 28;
constexpr int DDS5_VTABLE_SLOTS = 46;

/* DD_OK and common error codes */
constexpr uint32_t DD_OK = 0;
constexpr uint32_t DDERR_UNSUPPORTED = 0x80004001;

/* IID constants (stored as raw bytes, little-endian DWORD for Data1) */
/* {9c59509a-39bd-11d1-8c4a-00c04fd930c5} */
static const uint8_t IID_IDirectDraw4[] = {
    0x9A,0x50,0x59,0x9C, 0xBD,0x39, 0xD1,0x11,
    0x8C,0x4A, 0x00,0xC0,0x4F,0xD9,0x30,0xC5 };
/* {06675a80-3b9b-11d2-b92f-00609797ea5b} */
static const uint8_t IID_IDirectDrawSurface5[] = {
    0x80,0x5A,0x67,0x06, 0x9B,0x3B, 0xD2,0x11,
    0xB9,0x2F, 0x00,0x60,0x97,0x97,0xEA,0x5B };

/* ---- Native state tracking ---- */
struct DDSurfaceState {
    HBITMAP hbm;
    HDC     hdc;
    void*   pvBits;
    int     width, height, bpp;
    uint32_t emu_addr;     /* ARM-visible object address */
    uint32_t emu_pvBits;   /* ARM-visible pixel data address */
    int      refcount;
};

/* Shared globals (extern'd by ddraw_surface.cpp) */
std::mutex g_ddraw_mutex;
std::map<uint32_t, DDSurfaceState*> g_surfaces;
static std::atomic<uint32_t> g_next_obj{DDRAW_OBJ_BASE};
static std::atomic<uint32_t> g_next_dib{0x04100000};
bool g_vtables_built = false;

static uint32_t AllocObj(EmulatedMemory& mem, uint32_t vtable_addr) {
    uint32_t addr = g_next_obj.fetch_add(DDRAW_OBJ_STRIDE);
    mem.Alloc(addr, DDRAW_OBJ_STRIDE);
    mem.Write32(addr, vtable_addr); /* first DWORD = vtable pointer */
    return addr;
}

void Win32Thunks::RegisterDirectDrawHandlers() {
    /* --- DirectDrawCreate DDI handler ---
       The ARM ddraw.dll wraps DDI output in a PSL (Protected Server Library)
       proxy for cross-process COM. Our emulator doesn't support the WinCE PSL
       mechanism, so the proxy creation fails and produces a NULL interface pointer.
       When mshtml's InitSurface calls DirectDrawCreate and gets a broken proxy,
       it crashes on NULL->QueryInterface.

       Fix: return DDERR_UNSUPPORTED from the DDI. This tells ddraw.dll the
       display driver can't create DirectDraw. ddraw.dll propagates the error.
       mshtml's InitSurface caches the error in g_hrDirectDraw. Future calls
       to GetSurfaceFromDC skip the DirectDraw path and use GDI instead.
       GDI rendering works correctly with our CS_OWNDC and GDI handle fixes. */
    Thunk("ddraw_DirectDrawCreate", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] DirectDrawCreate(guid=0x%08X, out=0x%08X) -> DDERR_UNSUPPORTED (no DDI)\n",
            regs[0], regs[1]);
        regs[0] = DDERR_UNSUPPORTED;
        return true;
    });

    /* --- IDirectDraw4 methods --- */
    /* QueryInterface: return same object for IDirectDraw4 requests */
    Thunk("ddraw_DD4_QueryInterface", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t pThis = regs[0], riid = regs[1], ppv = regs[2];
        uint8_t iid[16];
        for (int i = 0; i < 16; i++) { uint8_t* p = mem.Translate(riid+i); iid[i] = p ? *p : 0; }
        if (memcmp(iid, IID_IDirectDraw4, 16) == 0) {
            mem.Write32(ppv, pThis); /* return same object */
            regs[0] = 0; return true;
        }
        LOG(API, "[API] DD4::QI unknown IID {%02X%02X%02X%02X-...}\n",
            iid[0],iid[1],iid[2],iid[3]);
        mem.Write32(ppv, pThis); /* return self for any QI */
        regs[0] = 0; return true;
    });
    Thunk("ddraw_DD4_AddRef", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 2; return true;
    });
    Thunk("ddraw_DD4_Release", [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 1; return true;
    });
    /* SetCooperativeLevel: always succeed */
    Thunk("ddraw_DD4_SetCooperativeLevel", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] DD4::SetCooperativeLevel(hwnd=0x%08X, flags=0x%X) -> OK\n",
            regs[1], regs[2]);
        regs[0] = DD_OK; return true;
    });
    /* CreateSurface: create a native DIB section */
    Thunk("ddraw_DD4_CreateSurface", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t pThis = regs[0], descAddr = regs[1];
        uint32_t ppSurf = regs[2], pUnk = regs[3];
        uint32_t height = mem.Read32(descAddr + 8);
        uint32_t width  = mem.Read32(descAddr + 12);
        if (width == 0 || height == 0) {
            width = screen_width;
            height = screen_height;
        }
        LOG(API, "[API] DD4::CreateSurface(%ux%u) ...\n", width, height);
        /* Create native DIB section */
        HDC screenDC = GetDC(NULL);
        int bpp = GetDeviceCaps(screenDC, BITSPIXEL);
        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = (LONG)width;
        bmi.bmiHeader.biHeight = -(LONG)height; /* top-down */
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = (WORD)bpp;
        bmi.bmiHeader.biCompression = BI_RGB;
        void* pvBits = nullptr;
        HBITMAP hbm = CreateDIBSection(screenDC, &bmi, DIB_RGB_COLORS, &pvBits, NULL, 0);
        ReleaseDC(NULL, screenDC);
        if (!hbm || !pvBits) {
            LOG(API, "[API]   CreateDIBSection FAILED\n");
            mem.Write32(ppSurf, 0);
            regs[0] = DDERR_UNSUPPORTED; return true;
        }
        HDC hdc = CreateCompatibleDC(NULL);
        SelectObject(hdc, hbm);
        /* Map pixel data into emulated memory */
        uint32_t stride = ((width * bpp + 31) / 32) * 4;
        uint32_t dataSize = stride * height;
        uint32_t emuPvBits = g_next_dib.fetch_add((dataSize + 0xFFF) & ~0xFFF);
        mem.AddExternalRegion(emuPvBits, dataSize, (uint8_t*)pvBits);
        /* Create surface COM object */
        uint32_t surfObj = AllocObj(mem, DDS5_VTABLE_ADDR);
        auto* state = new DDSurfaceState{hbm, hdc, pvBits, (int)width, (int)height,
                                          bpp, surfObj, emuPvBits, 1};
        { std::lock_guard<std::mutex> lk(g_ddraw_mutex);
          g_surfaces[surfObj] = state; }
        mem.Write32(ppSurf, surfObj);
        LOG(API, "[API]   -> surface 0x%08X (%ux%u %dbpp) hdc=%p pvBits=emu:0x%08X\n",
            surfObj, width, height, bpp, hdc, emuPvBits);
        regs[0] = DD_OK; return true;
    });
    /* Per-method stubs with individual logging */
    auto mkStub = [this](const char* name) {
        std::string sname(name);
        Thunk(name, [sname](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s(this=0x%08X, R1=0x%08X, R2=0x%08X)\n",
                sname.c_str(), regs[0], regs[1], regs[2]);
            regs[0] = DD_OK; return true;
        });
    };
    mkStub("ddraw_DD4_Compact"); mkStub("ddraw_DD4_CreateClipper");
    mkStub("ddraw_DD4_CreatePalette"); mkStub("ddraw_DD4_DuplicateSurface");
    mkStub("ddraw_DD4_EnumDisplayModes"); mkStub("ddraw_DD4_EnumSurfaces");
    mkStub("ddraw_DD4_FlipToGDISurface"); mkStub("ddraw_DD4_GetCaps");
    mkStub("ddraw_DD4_GetDisplayMode"); mkStub("ddraw_DD4_GetFourCCCodes");
    mkStub("ddraw_DD4_GetGDISurface"); mkStub("ddraw_DD4_GetMonitorFrequency");
    mkStub("ddraw_DD4_GetScanLine"); mkStub("ddraw_DD4_GetVerticalBlankStatus");
    mkStub("ddraw_DD4_Initialize"); mkStub("ddraw_DD4_RestoreDisplayMode");
    mkStub("ddraw_DD4_SetDisplayMode"); mkStub("ddraw_DD4_WaitForVerticalBlank");
    mkStub("ddraw_DD4_GetAvailableVidMem");
    /* GetSurfaceFromDC: wrap an existing DC in a DirectDraw surface */
    Thunk("ddraw_DD4_GetSurfaceFromDC", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = GDI_HDC(regs[1]);
        uint32_t ppSurf = regs[2];
        LOG(API, "[API] DD4::GetSurfaceFromDC(hdc=0x%08X, out=0x%08X)\n",
            regs[1], ppSurf);
        BITMAP bm = {};
        HBITMAP hbmCur = (HBITMAP)GetCurrentObject(hdc, OBJ_BITMAP);
        int w, h, bpp;
        if (hbmCur && GetObject(hbmCur, sizeof(bm), &bm)) {
            w = bm.bmWidth; h = bm.bmHeight; bpp = bm.bmBitsPixel;
        } else {
            /* No bitmap in DC — use configured WinCE screen dimensions */
            w = screen_width;
            h = screen_height;
            bpp = GetDeviceCaps(hdc, BITSPIXEL);
        }
        uint32_t surfObj = AllocObj(mem, DDS5_VTABLE_ADDR);
        auto* state = new DDSurfaceState{nullptr, hdc, nullptr,
                                          w, h, bpp, surfObj, 0, 1};
        { std::lock_guard<std::mutex> lk(g_ddraw_mutex);
          g_surfaces[surfObj] = state; }
        mem.Write32(ppSurf, surfObj);
        LOG(API, "[API]   -> surface 0x%08X wrapping DC %dx%d\n", surfObj, w, h);
        regs[0] = DD_OK;
        return true;
    });
    mkStub("ddraw_DD4_RestoreAllSurfaces"); mkStub("ddraw_DD4_TestCooperativeLevel");
    mkStub("ddraw_DD4_GetDeviceIdentifier");
    /* Build vtables in emulated memory */
    BuildDirectDrawVtables(mem);
}
