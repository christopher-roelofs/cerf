#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "callbacks_marshal.h"
#include "../log.h"
#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "comctl32")
#pragma comment(lib, "dwmapi")

/* Helpers split into callbacks_logging.cpp */
void EmuWndProc_LogMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                             uint32_t arm_wndproc, EmulatedMemory& emem);
void EmuWndProc_LogPostDispatch(HWND hwnd, UINT msg, uint32_t result, EmulatedMemory& emem);
bool EmuWndProc_HandleNcCalcSize(HWND hwnd, WPARAM wParam, LPARAM lParam, LRESULT& out);

/* Static member definitions for callback infrastructure */
std::map<HWND, uint32_t> Win32Thunks::hwnd_wndproc_map;
std::map<HWND, WNDPROC> Win32Thunks::hwnd_native_wndproc_map;
std::map<UINT_PTR, uint32_t> Win32Thunks::arm_timer_callbacks;
std::map<HWND, uint32_t> Win32Thunks::hwnd_dlgproc_map;
uint32_t Win32Thunks::pending_arm_dlgproc = 0;
std::map<HWND, uint32_t> Win32Thunks::hwnd_wce_style_map;
std::map<HWND, uint32_t> Win32Thunks::hwnd_wce_exstyle_map;
std::map<HWND, ProcessSlot*> Win32Thunks::hwnd_slot_map;
thread_local uint32_t Win32Thunks::tls_pending_wce_style = 0;
thread_local uint32_t Win32Thunks::tls_pending_wce_exstyle = 0;
INT_PTR Win32Thunks::modal_dlg_result = 0;
bool Win32Thunks::modal_dlg_ended = false;
Win32Thunks* Win32Thunks::s_instance = nullptr;
std::set<HWND> Win32Thunks::captionok_hwnds;
thread_local HWND Win32Thunks::tls_paint_hwnd = NULL;

LRESULT CALLBACK Win32Thunks::EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!s_instance) return DefWindowProcW(hwnd, msg, wParam, lParam);

    if (!t_ctx || !t_ctx->callback_executor) {
        /* Non-ARM thread: check if this window has an ARM WndProc.
           COM/OLE threads may own ARM-class windows (e.g. MS_WebcheckMonitor).
           Create a lazy ARM context so the WndProc can execute. */
        bool has_arm_proc = (hwnd_wndproc_map.count(hwnd) > 0);
        if (!has_arm_proc) {
            wchar_t cls_name[256] = {};
            GetClassNameW(hwnd, cls_name, 256);
            has_arm_proc = (s_instance->arm_wndprocs.count(cls_name) > 0
                            && !s_instance->arm_wndprocs[cls_name].empty());
        }
        if (has_arm_proc)
            EnsureLazyArmContext(s_instance->mem, s_instance);
        if (!t_ctx || !t_ctx->callback_executor)
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    auto it = hwnd_wndproc_map.find(hwnd);
    if (it == hwnd_wndproc_map.end()) {
        /* During CreateWindow, HWND is not yet in the map.
           Look up the ARM WndProc from the window class name and auto-register. */
        wchar_t cls_name[256] = {};
        GetClassNameW(hwnd, cls_name, 256);
        auto cls_it = s_instance->arm_wndprocs.find(cls_name);
        if (cls_it != s_instance->arm_wndprocs.end() && !cls_it->second.empty()) {
            /* Resolve WndProc: try window owner's slot, then current thread's slot */
            auto& slot_map = cls_it->second;
            ProcessSlot* owner = nullptr;
            auto slot_it2 = hwnd_slot_map.find(hwnd);
            if (slot_it2 != hwnd_slot_map.end()) owner = slot_it2->second;
            auto sit = slot_map.find(owner);
            if (sit == slot_map.end())
                sit = slot_map.find(EmulatedMemory::process_slot);
            uint32_t wp = (sit != slot_map.end()) ? sit->second : slot_map.begin()->second;
            hwnd_wndproc_map[hwnd] = wp;
            it = hwnd_wndproc_map.find(hwnd);
        } else {
            if (msg == WM_CREATE || msg == WM_NCCREATE) {
                LOG(API, "[API] EmuWndProc: MISS class='%ls' msg=0x%04X hwnd=0x%p -> DefWindowProc\n",
                    cls_name, msg, hwnd);
            }
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    /* One-time deferred arrange fix for SysListView32. */
    if (msg == WM_PAINT && !GetPropW(hwnd, L"CerfLVArr")) {
        wchar_t cls_chk[64] = {};
        GetClassNameW(hwnd, cls_chk, 64);
        if (wcsstr(cls_chk, L"SysListView32")) {
            int count = (int)::SendMessageW(hwnd, 0x1004 /* LVM_GETITEMCOUNT */, 0, 0);
            if (count > 0) {
                SetPropW(hwnd, L"CerfLVArr", (HANDLE)1);
                LOG(API, "[API] SysListView32 first WM_PAINT: %d items, sending LVM_ARRANGE\n", count);
                ::SendMessageW(hwnd, 0x1016 /* LVM_ARRANGE */, 0, 0);
            }
        }
    }

    /* Messages with native pointer lParams need marshaling.
       For messages we can't marshal, use DefWindowProcW. */
    LPARAM native_lParam = lParam;
    MarshalCallbackExecutor executor = s_instance->callback_executor;
    uint32_t arm_wndproc = it->second;
    LRESULT marshal_result = 0;

    /* WM_NCCALCSIZE: compute WinCE non-client area — helper in callbacks_logging.cpp */
    if (msg == WM_NCCALCSIZE) {
        LRESULT r;
        if (EmuWndProc_HandleNcCalcSize(hwnd, wParam, lParam, r))
            return r;
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
    /* WM_GETMINMAXINFO: constrain maximized windows to the WinCE work area.
       DefWindowProcW would use the native desktop work area instead. */
    case WM_GETMINMAXINFO: {
        RECT wa = s_instance->GetWorkArea();
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMaxPosition.x = wa.left;
        mmi->ptMaxPosition.y = wa.top;
        mmi->ptMaxSize.x = wa.right - wa.left;
        mmi->ptMaxSize.y = wa.bottom - wa.top;
        return 0;
    }
    /* WM_SYSCOMMAND SC_CLOSE: native DefWindowProcW sends WM_CLOSE back through
       the native message path, bypassing the ARM wndproc. The ARM BrowseWndProc
       needs WM_CLOSE to call ExplorerList_t::RemoveExplorerWnd and clean up.
       Translate SC_CLOSE into WM_CLOSE and dispatch to ARM directly. */
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_CLOSE) {
            LOG(API, "[API] EmuWndProc: SC_CLOSE → forwarding WM_CLOSE to ARM wndproc\n");
            /* Fall through to ARM dispatch with WM_CLOSE instead */
            msg = WM_CLOSE;
            wParam = 0;
            lParam = 0;
            break; /* fall through to ARM dispatch below */
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    /* WM_NCDESTROY: the window is being destroyed. If this is a top-level window
       with an ARM wndproc, send WM_CLOSE to the ARM code first so it can clean up
       (e.g. ExplorerList_t::RemoveExplorerWnd). The native X button bypasses
       EmuWndProc's WM_SYSCOMMAND handler on some window styles, so WM_CLOSE
       may never reach the ARM code unless we inject it here. */
    case WM_NCDESTROY: {
        HWND parent = GetParent(hwnd);
        if (!parent && arm_wndproc && executor) {
            uint32_t args[4] = { (uint32_t)(uintptr_t)hwnd, WM_CLOSE, 0, 0 };
            executor(arm_wndproc, args, 4);
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    /* Messages with native 64-bit pointers — route to DefWindowProcW */
    case WM_SETICON:
    case WM_GETICON:
    case WM_COPYDATA:
    case WM_DEVICECHANGE:
    case WM_POWERBROADCAST:
    case WM_INPUT:
    case WM_NCPAINT:
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    case WM_ENTERMENULOOP:
    case WM_EXITMENULOOP:
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    /* Edit control messages with native string pointers in lParam.
       These come from the native combobox/edit system and carry 64-bit
       string pointers that ARM code can't dereference. Marshal the string
       into ARM emulated memory so the ARM wndproc can read it. */

    case 0xB2 /* EM_REPLACESEL */: { /* lParam = LPCWSTR lpNewText */
        if (lParam && (lParam >> 32) != 0) {
            /* Native 64-bit pointer — marshal to ARM memory */
            const wchar_t* text = (const wchar_t*)lParam;
            size_t len = wcslen(text);
            constexpr uint32_t EM_MARSHAL_ADDR = 0x3F008000;
            s_instance->mem.Alloc(EM_MARSHAL_ADDR, 0x1000);
            for (size_t i = 0; i <= len && i < 0x7FE; i++)
                s_instance->mem.Write16(EM_MARSHAL_ADDR + (uint32_t)(i * 2), text[i]);
            s_instance->mem.Write16(EM_MARSHAL_ADDR + (uint32_t)(len * 2), 0);
            lParam = EM_MARSHAL_ADDR;
        }
        break; /* fall through to ARM dispatch with marshaled lParam */
    }

    case WM_NOTIFY: {
        if (MarshalNotify(hwnd, wParam, lParam, arm_wndproc,
                          s_instance->mem, executor, marshal_result))
            return marshal_result;
        break; /* ARM pointer — forward directly */
    }
    case WM_NCHITTEST:
    case WM_DISPLAYCHANGE:
        break;
    case WM_DELETEITEM:
    case WM_COMPAREITEM:
        if (lParam > 0 && (lParam >> 32) == 0) break;
        return DefWindowProcW(hwnd, msg, wParam, lParam);

    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalWindowPos(hwnd, msg, wParam, lParam, arm_wndproc,
                         s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_STYLECHANGING:
    case WM_STYLECHANGED:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalStyleChange(hwnd, msg, wParam, lParam, arm_wndproc,
                           s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_SETTEXT:
        if (!lParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalSetText(lParam, s_instance->mem, lParam);
        break;

    case WM_GETTEXT:
        if (!lParam || !wParam) return DefWindowProcW(hwnd, msg, wParam, lParam);
        MarshalGetText(hwnd, wParam, lParam, arm_wndproc,
                       s_instance->mem, executor, marshal_result);
        return marshal_result;

    case WM_GETTEXTLENGTH:
        break;

    case WM_CREATE:
    case WM_NCCREATE: {
        /* Populate WinCE style map during WM_NCCREATE (first message to a new window).
           tls_pending_wce_style is set by the CreateWindowExW thunk before calling
           the native ::CreateWindowExW. */
        if (msg == WM_NCCREATE && tls_pending_wce_style) {
            hwnd_wce_style_map[hwnd] = tls_pending_wce_style;
            hwnd_wce_exstyle_map[hwnd] = tls_pending_wce_exstyle;
            /* Clear immediately so child windows created during WM_CREATE
               don't inherit the parent's WCE style via stale TLS value. */
            tls_pending_wce_style = 0;
            tls_pending_wce_exstyle = 0;
        }
        MarshalCreateStruct(lParam, s_instance->mem,
                            s_instance->GetEmuHInstance(), lParam);
        /* Override style/exStyle in the marshaled CREATESTRUCT with original WinCE
           values so ARM code sees the styles it requested, not our WS_POPUP conversion.
           CREATESTRUCT layout: +32 = style, +44 = dwExStyle (matches CS_EMU_ADDR offsets
           in callbacks_marshal.cpp). */
        {
            constexpr uint32_t CS_STYLE_ADDR   = 0x3F000020; /* CS_EMU_ADDR + 32 */
            constexpr uint32_t CS_EXSTYLE_ADDR  = 0x3F00002C; /* CS_EMU_ADDR + 44 */
            auto sit = hwnd_wce_style_map.find(hwnd);
            if (sit != hwnd_wce_style_map.end())
                s_instance->mem.Write32(CS_STYLE_ADDR, sit->second);
            auto eit = hwnd_wce_exstyle_map.find(hwnd);
            if (eit != hwnd_wce_exstyle_map.end())
                s_instance->mem.Write32(CS_EXSTYLE_ADDR, eit->second & 0x0FFFFFFF);
        }
        break;
    }

    case WM_DRAWITEM:
        MarshalDrawItem(lParam, s_instance->mem, lParam);
        break;

    case WM_MEASUREITEM:
        MarshalMeasureItem(lParam, s_instance->mem, lParam);
        break;
    }

    /* WM_SETTINGCHANGE: Desktop sends wParam=SPI, lParam=native string ptr.
       WinCE convention: lParam = SPI constant (for SPI_SETSIPINFO=0xE0). */
    if (msg == WM_SETTINGCHANGE) {
        if (wParam == 0xE0 /* SPI_SETSIPINFO */)
            lParam = 0xE0;
        else
            lParam = 0;
    }

    /* Debug logging — implementations in callbacks_logging.cpp */
    EmuWndProc_LogMessages(hwnd, msg, wParam, lParam, arm_wndproc, s_instance->mem);

    uint32_t args[4] = {
        (uint32_t)(uintptr_t)hwnd,
        (uint32_t)msg,
        (uint32_t)wParam,
        (uint32_t)lParam
    };

    /* Switch to the window owner's ProcessSlot for cross-process dispatch.
       A window created by process A may receive messages on process B's thread
       (SendMessage). The ARM WndProc must see process A's slot-0 overlay. */
    ProcessSlot* saved_slot = EmulatedMemory::process_slot;
    auto slot_it = hwnd_slot_map.find(hwnd);
    if (slot_it != hwnd_slot_map.end() && slot_it->second != saved_slot)
        EmulatedMemory::process_slot = slot_it->second;

    uint32_t result = s_instance->callback_executor(arm_wndproc, args, 4);

    EmulatedMemory::process_slot = saved_slot;

    EmuWndProc_LogPostDispatch(hwnd, msg, result, s_instance->mem);

    /* Copy back results from WM_MEASUREITEM */
    if (msg == WM_MEASUREITEM && native_lParam) {
        MarshalMeasureItemWriteback(native_lParam, s_instance->mem);
    }

    /* Sign-extend the 32-bit result to 64-bit LRESULT. */
    return (LRESULT)(intptr_t)(int32_t)result;
}
