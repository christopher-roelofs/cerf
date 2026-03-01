#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* AYGSHELL.DLL thunks - WinCE Shell Helper Library.
   Most functions deal with WinCE-specific UI (SIP, fullscreen PDA, menu bars)
   and can be safely stubbed since we run on a desktop. */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterAygshellHandlers() {
    Thunk("SHHandleWMSettingChange", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHHandleWMSettingChange(0x%08X, 0x%08X, 0x%08X) -> stub\n", regs[0], regs[1], regs[2]);
        regs[0] = 0; return true;
    });
    Thunk("SHHandleWMActivate", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHHandleWMActivate(0x%08X, 0x%08X, 0x%08X) -> stub\n", regs[0], regs[1], regs[2]);
        regs[0] = 0; return true;
    });
    Thunk("SHInitDialog", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHInitDialog(0x%08X) -> stub\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("SHFullScreen", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHFullScreen(hwnd=0x%08X, flags=0x%08X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("SHCreateMenuBar", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHCreateMenuBar(0x%08X) -> stub\n", regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("SHSipPreference", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHSipPreference(hwnd=0x%08X, st=%d) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("SHRecognizeGesture", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHRecognizeGesture(0x%08X) -> stub\n", regs[0]);
        regs[0] = 0; return true;
    });
    Thunk("SHSendBackToFocusWindow", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHSendBackToFocusWindow(0x%08X, 0x%08X, 0x%08X) -> stub\n", regs[0], regs[1], regs[2]);
        regs[0] = 0; return true;
    });
    Thunk("SHSetAppKeyWndAssoc", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHSetAppKeyWndAssoc(key=%d, hwnd=0x%08X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("SHDoneButton", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHDoneButton(hwnd=0x%08X, state=%d) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("SHSipInfo", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHSipInfo(action=%d, param=%d) -> stub\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("SHNotificationAdd", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHNotificationAdd(0x%08X) -> stub\n", regs[0]);
        regs[0] = 1; return true;
    });
    Thunk("SHNotificationRemove", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHNotificationRemove(0x%08X, 0x%08X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("SHNotificationUpdate", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHNotificationUpdate(0x%08X, 0x%08X) -> stub\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
}
