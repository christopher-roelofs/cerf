/* Class attribute thunks: GetClassLongW, SetClassLongW — split from window_props.cpp.
   All translations go through ClassBridge (see class_bridge.h). */
#include "../win32_thunks.h"
#include "../class_bridge.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterWindowClassHandlers() {
    Thunk("GetClassLongW", 879, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int nIndex = (int)regs[1];
        auto& bridge = GetClassBridge();
        switch (nIndex) {
        case WINCE_GCL_WNDPROC: /* GCL_WNDPROC */
            regs[0] = bridge.GetArmWndProc(hw);
            break;
        case WINCE_GCL_STYLE: /* GCL_STYLE */
            regs[0] = bridge.GetArmClassStyle(hw);
            break;
        case WINCE_GCL_HBRBACKGROUND: /* GCL_HBRBACKGROUND */
            regs[0] = bridge.GetArmBrush(hw);
            break;
        case WINCE_GCL_HCURSOR: { /* GCL_HCURSOR */
            auto* ci = bridge.GetClassInfoForHwnd(hw);
            regs[0] = ci ? ci->arm_cursor : 0;
            break;
        }
        case WINCE_GCL_HICON: { /* GCL_HICON */
            auto* ci = bridge.GetClassInfoForHwnd(hw);
            regs[0] = ci ? ci->arm_icon : 0;
            break;
        }
        default:
            regs[0] = (uint32_t)GetClassLongW(hw, nIndex);
            break;
        }
        LOG(API, "[API] GetClassLongW(0x%p, %d) -> 0x%08X\n", hw, nIndex, regs[0]);
        return true;
    });
    Thunk("SetClassLongW", 880, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        int nIndex = (int)regs[1];
        uint32_t newVal = regs[2];
        LOG(API, "[API] SetClassLongW(0x%p, %d, 0x%08X)\n", hw, nIndex, newVal);
        auto& bridge = GetClassBridge();
        switch (nIndex) {
        case WINCE_GCL_WNDPROC: { /* GCL_WNDPROC: block native write, return old ARM proc */
            uint32_t old = bridge.GetArmWndProc(hw);
            LOG(API, "[API]   -> GCL_WNDPROC: old ARM=0x%08X (native write blocked)\n", old);
            regs[0] = old;
            return true;
        }
        case WINCE_GCL_HBRBACKGROUND: { /* GCL_HBRBACKGROUND: translate brush */
            HBRUSH native = ClassBridge::TranslateBrushToNative(newVal);
            regs[0] = (uint32_t)(uintptr_t)SetClassLongPtrW(hw, GCLP_HBRBACKGROUND, (LONG_PTR)native);
            return true;
        }
        case WINCE_GCL_HCURSOR: /* GCL_HCURSOR: sign-extend handle */
        case WINCE_GCL_HICON: /* GCL_HICON: sign-extend handle */
            regs[0] = (uint32_t)SetClassLongPtrW(hw, nIndex, (LONG_PTR)(intptr_t)(int32_t)newVal);
            return true;
        case WINCE_GCL_STYLE: { /* GCL_STYLE: preserve CS_OWNDC */
            UINT native_style = ClassBridge::TranslateStyleToNative(newVal);
            regs[0] = (uint32_t)SetClassLongW(hw, nIndex, native_style);
            return true;
        }
        default:
            regs[0] = (uint32_t)SetClassLongW(hw, nIndex, (LONG)(int32_t)newVal);
            return true;
        }
    });
}
