#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ImageList and common controls init — coredll re-exports from commctrl.
   When an app links against coredll (which re-exports these),
   we handle them natively. When an app loads the real ARM commctrl.dll,
   that DLL runs as ARM code and calls coredll itself. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <commctrl.h>

void Win32Thunks::RegisterImageListHandlers() {
    /* InitCommonControlsEx / InitCommonControls — forward to ARM commctrl.dll.
       The ARM DLL must run its own init (sets fControlInitalized, registers window
       classes with ARM WndProcs, initializes critical sections). We resolve the
       export and call into ARM code. If commctrl isn't loaded yet, we load it. */
    Thunk("InitCommonControlsEx", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(THUNK, "[THUNK] InitCommonControlsEx(icc=0x%08X)\n", regs[0]);
        LoadedDll* cc = LoadArmDll("commctrl.dll");
        if (cc && callback_executor) {
            uint32_t addr = PELoader::ResolveExportName(mem, cc->pe_info, "InitCommonControlsEx");
            if (addr) {
                uint32_t args[1] = { regs[0] };
                regs[0] = callback_executor(addr, args, 1);
                return true;
            }
        }
        LOG(THUNK, "[THUNK]   commctrl.dll not available, using native fallback\n");
        INITCOMMONCONTROLSEX icc = {};
        icc.dwSize = sizeof(icc);
        icc.dwICC = regs[0] ? mem.Read32(regs[0] + 4) : 0xFFFF;
        regs[0] = InitCommonControlsEx(&icc);
        return true;
    });
    Thunk("InitCommonControls", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(THUNK, "[THUNK] InitCommonControls()\n");
        LoadedDll* cc = LoadArmDll("commctrl.dll");
        if (cc && callback_executor) {
            uint32_t addr = PELoader::ResolveExportName(mem, cc->pe_info, "InitCommonControls");
            if (addr) {
                callback_executor(addr, nullptr, 0);
                regs[0] = 0;
                return true;
            }
        }
        InitCommonControls(); regs[0] = 0; return true;
    });
    Thunk("ImageList_Create", 742, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = (uint32_t)(uintptr_t)ImageList_Create(regs[0], regs[1], regs[2], regs[3], ReadStackArg(regs, mem, 0));
        return true;
    });
    Thunk("ImageList_Destroy", 743, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Destroy((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_Add", 738, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Add((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (HBITMAP)(intptr_t)(int32_t)regs[1], (HBITMAP)(intptr_t)(int32_t)regs[2]);
        return true;
    });
    Thunk("ImageList_Draw", 748, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_Draw((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3], ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1));
        return true;
    });
    Thunk("ImageList_DrawEx", 749, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        regs[0] = ImageList_DrawEx((HIMAGELIST)(intptr_t)(int32_t)regs[0], regs[1],
            (HDC)(intptr_t)(int32_t)regs[2], regs[3],
            ReadStackArg(regs, mem, 0), ReadStackArg(regs, mem, 1), ReadStackArg(regs, mem, 2),
            ReadStackArg(regs, mem, 3), ReadStackArg(regs, mem, 4), ReadStackArg(regs, mem, 5));
        return true;
    });
    Thunk("ImageList_GetImageCount", 756, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_GetImageCount((HIMAGELIST)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ImageList_LoadImage", 758, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], lpbmp = regs[1], cx = regs[2], cGrow = regs[3];
        COLORREF crMask = ReadStackArg(regs, mem, 0);
        UINT uType = ReadStackArg(regs, mem, 1);
        UINT uFlags = ReadStackArg(regs, mem, 2);
        LOG(THUNK, "[THUNK] ImageList_LoadImage(0x%08X, %d, cx=%d, cGrow=%d, crMask=0x%X, type=%d, flags=0x%X)\n",
               hmod, lpbmp, cx, cGrow, crMask, uType, uFlags);
        HMODULE native_mod = NULL;
        bool is_arm = (hmod == emu_hinstance);
        for (auto& pair : loaded_dlls) { if (pair.second.base_addr == hmod) { is_arm = true; break; } }
        if (is_arm) native_mod = GetNativeModuleForResources(hmod);
        else native_mod = (HMODULE)(intptr_t)(int32_t)hmod;
        HIMAGELIST h = native_mod ? ImageList_LoadImageW(native_mod, MAKEINTRESOURCEW(lpbmp), cx, cGrow, crMask, uType, uFlags) : NULL;
        regs[0] = (uint32_t)(uintptr_t)h;
        return true;
    });
    Thunk("ImageList_GetIconSize", 755, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int cx, cy; BOOL ret = ImageList_GetIconSize((HIMAGELIST)(intptr_t)(int32_t)regs[0], &cx, &cy);
        if (regs[1]) mem.Write32(regs[1], cx); if (regs[2]) mem.Write32(regs[2], cy);
        regs[0] = ret; return true;
    });
    Thunk("ImageList_AddMasked", 739, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_AddMasked((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (HBITMAP)(intptr_t)(int32_t)regs[1], (COLORREF)regs[2]);
        return true;
    });
    Thunk("ImageList_SetBkColor", 763, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_SetBkColor((HIMAGELIST)(intptr_t)(int32_t)regs[0], (COLORREF)regs[1]);
        return true;
    });
    Thunk("ImageList_Remove", 760, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_Remove((HIMAGELIST)(intptr_t)(int32_t)regs[0], (int)regs[1]);
        return true;
    });
    Thunk("ImageList_ReplaceIcon", 762, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_ReplaceIcon((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (int)regs[1], (HICON)(intptr_t)(int32_t)regs[2]);
        return true;
    });
    Thunk("ImageList_GetIcon", 754, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)ImageList_GetIcon(
            (HIMAGELIST)(intptr_t)(int32_t)regs[0], (int)regs[1], regs[2]);
        return true;
    });
    Thunk("ImageList_DrawIndirect", 750, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* IMAGELISTDRAWPARAMS is complex — forward to ARM commctrl if available, else stub */
        LOG(THUNK, "[THUNK] ImageList_DrawIndirect(0x%08X) -> stub returning FALSE\n", regs[0]);
        regs[0] = FALSE;
        return true;
    });
    Thunk("ImageList_SetOverlayImage", 766, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ImageList_SetOverlayImage((HIMAGELIST)(intptr_t)(int32_t)regs[0],
            (int)regs[1], (int)regs[2]);
        return true;
    });
}
