/* Input thunks: cursor, keyboard, timer, focus, capture */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterInputHandlers() {
    Thunk("SetTimer", 875, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        UINT_PTR nIDEvent = regs[1]; UINT uElapse = regs[2]; uint32_t arm_timerproc = regs[3];
        LOG(API, "[API] SetTimer(hwnd=0x%p, id=0x%X, elapse=%u, timerproc=0x%08X)\n",
            hw, (uint32_t)nIDEvent, uElapse, arm_timerproc);
        if (arm_timerproc != 0) arm_timer_callbacks[nIDEvent] = arm_timerproc;
        regs[0] = (uint32_t)(uintptr_t)SetTimer(hw, nIDEvent, uElapse, NULL);
        return true;
    });
    Thunk("KillTimer", 876, [](uint32_t* regs, EmulatedMemory&) -> bool {
        arm_timer_callbacks.erase(regs[1]);
        regs[0] = KillTimer((HWND)(intptr_t)(int32_t)regs[0], regs[1]);
        return true;
    });
    Thunk("GetKeyState", 860, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetKeyState(regs[0]); return true;
    });
    Thunk("GetAsyncKeyState", 826, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)GetAsyncKeyState(regs[0]); return true;
    });
    Thunk("GetDoubleClickTime", 888, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetDoubleClickTime(); return true;
    });
    Thunk("GetCursorPos", 734, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        POINT pt; GetCursorPos(&pt);
        mem.Write32(regs[0], pt.x); mem.Write32(regs[0]+4, pt.y);
        regs[0] = 1; return true;
    });
    Thunk("SetCursorPos", 736, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SetCursorPos(regs[0], regs[1]); return true;
    });
    Thunk("ShowCursor", 737, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ShowCursor(regs[0]); return true;
    });
    Thunk("SetFocus", 704, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] SetFocus(0x%p)\n", hw);
        regs[0] = (uint32_t)(uintptr_t)SetFocus(hw); return true;
    });
    Thunk("GetFocus", 705, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetFocus(); return true;
    });
    Thunk("GetForegroundWindow", 701, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetForegroundWindow(); return true;
    });
    Thunk("SetForegroundWindow", 702, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        /* On desktop Windows, SetForegroundWindow from a background thread is
           restricted (can't steal focus). WinCE has no such restriction — all
           windows share a single session. Force foreground by granting permission
           via the foreground thread's input queue. */
        DWORD fgThread = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
        DWORD myThread = GetCurrentThreadId();
        if (fgThread != myThread) {
            AttachThreadInput(myThread, fgThread, TRUE);
            SetForegroundWindow(hw);
            BringWindowToTop(hw);
            AttachThreadInput(myThread, fgThread, FALSE);
        } else {
            SetForegroundWindow(hw);
        }
        regs[0] = 1;
        return true;
    });
    Thunk("SetActiveWindow", 703, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetActiveWindow((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetActiveWindow", 706, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetActiveWindow(); return true;
    });
    Thunk("SetCapture", 708, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetCapture((HWND)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("ReleaseCapture", 709, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ReleaseCapture(); return true;
    });
    Thunk("GetCapture", 707, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetCapture(); return true;
    });
    Thunk("SetCursor", 682, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)SetCursor((HCURSOR)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("LoadCursorW", 683, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)LoadCursorW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    });
    Thunk("DrawIconEx", 726, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HDC hdc = (HDC)(intptr_t)(int32_t)regs[0];
        int xLeft = (int)regs[1], yTop = (int)regs[2];
        HICON hIcon = (HICON)(intptr_t)(int32_t)regs[3];
        int cxWidth = (int)ReadStackArg(regs, mem, 0);
        int cyWidth = (int)ReadStackArg(regs, mem, 1);
        UINT istepIfAniCur = ReadStackArg(regs, mem, 2);
        HBRUSH hbrFlicker = (HBRUSH)(intptr_t)(int32_t)ReadStackArg(regs, mem, 3);
        UINT diFlags = ReadStackArg(regs, mem, 4);
        regs[0] = DrawIconEx(hdc, xLeft, yTop, hIcon, cxWidth, cyWidth,
                              istepIfAniCur, hbrFlicker, diFlags);
        return true;
    });
    Thunk("LoadIconW", 728, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)LoadIconW((HINSTANCE)(intptr_t)(int32_t)regs[0], MAKEINTRESOURCEW(regs[1]));
        return true;
    });

    Thunk("ClipCursor", 731, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[0]) {
            RECT rc;
            rc.left = (int)mem.Read32(regs[0]);     rc.top = (int)mem.Read32(regs[0]+4);
            rc.right = (int)mem.Read32(regs[0]+8);  rc.bottom = (int)mem.Read32(regs[0]+12);
            regs[0] = ClipCursor(&rc);
        } else {
            regs[0] = ClipCursor(nullptr);
        }
        return true;
    });
    Thunk("GetCursor", 733, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = (uint32_t)(uintptr_t)GetCursor();
        return true;
    });
    Thunk("CreateCursor", 722, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HINSTANCE hInst = (HINSTANCE)(intptr_t)(int32_t)regs[0];
        int xHot = (int)regs[1], yHot = (int)regs[2];
        int w = (int)regs[3];
        int h = (int)ReadStackArg(regs, mem, 0);
        uint32_t pAND = ReadStackArg(regs, mem, 1);
        uint32_t pXOR = ReadStackArg(regs, mem, 2);
        int maskSize = ((w + 31) / 32) * 4 * h;
        std::vector<uint8_t> andBits(maskSize), xorBits(maskSize);
        for (int i = 0; i < maskSize; i++) andBits[i] = mem.Read8(pAND + i);
        for (int i = 0; i < maskSize; i++) xorBits[i] = mem.Read8(pXOR + i);
        regs[0] = (uint32_t)(uintptr_t)CreateCursor(
            hInst, xHot, yHot, w, h, andBits.data(), xorBits.data());
        return true;
    });
    Thunk("CreateIconIndirect", 723, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* 32-bit ICONINFO: fIcon(4), xHotspot(4), yHotspot(4), hbmMask(4), hbmColor(4) = 20 bytes */
        uint32_t addr = regs[0];
        ICONINFO ii = {};
        ii.fIcon    = mem.Read32(addr + 0);
        ii.xHotspot = mem.Read32(addr + 4);
        ii.yHotspot = mem.Read32(addr + 8);
        ii.hbmMask  = (HBITMAP)(intptr_t)(int32_t)mem.Read32(addr + 12);
        ii.hbmColor = (HBITMAP)(intptr_t)(int32_t)mem.Read32(addr + 16);
        regs[0] = (uint32_t)(uintptr_t)CreateIconIndirect(&ii);
        return true;
    });
    Thunk("DestroyCursor", 724, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DestroyCursor((HCURSOR)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("DestroyIcon", 725, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = DestroyIcon((HICON)(intptr_t)(int32_t)regs[0]); return true;
    });
    Thunk("GetClipCursor", 732, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc;
        BOOL ok = GetClipCursor(&rc);
        if (ok && regs[0]) {
            mem.Write32(regs[0], (uint32_t)rc.left);  mem.Write32(regs[0]+4, (uint32_t)rc.top);
            mem.Write32(regs[0]+8, (uint32_t)rc.right); mem.Write32(regs[0]+12, (uint32_t)rc.bottom);
        }
        regs[0] = ok;
        return true;
    });
    /* LoadAcceleratorsW: registered in resource.cpp (full implementation) */
    /* IMM stubs */
    Thunk("ImmAssociateContext", 770, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmAssociateContext -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetContext", 783, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetContext -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmReleaseContext", 803, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmReleaseContext -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetOpenStatus", 792, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetOpenStatus -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmNotifyIME", 800, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmNotifyIME -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmSetOpenStatus", 814, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmSetOpenStatus -> 0\n"); regs[0] = 0; return true;
    });
    /* Additional IMM stubs needed by RICHED20.DLL */
    Thunk("ImmEscapeW", 775, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmEscapeW -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetCandidateWindow", 779, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetCandidateWindow -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetCompositionStringW", 781, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ImmGetCompositionStringW(himc=0x%08X, dwIndex=0x%X) -> 0 (stub)\n", regs[0], regs[1]);
        regs[0] = 0; return true;
    });
    Thunk("ImmGetConversionStatus", 785, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetConversionStatus -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetProperty", 793, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetProperty -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmSetCandidateWindow", 807, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmSetCandidateWindow -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmSetCompositionFontW", 808, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmSetCompositionFontW -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmSetCompositionStringW", 809, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmSetCompositionStringW -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmSetCompositionWindow", 810, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmSetCompositionWindow -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("ImmGetVirtualKey", 1210, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] ImmGetVirtualKey -> 0\n"); regs[0] = 0; return true;
    });
    Thunk("PostKeybdMessage", 832, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] [STUB] PostKeybdMessage -> 0\n"); regs[0] = 0; return true;
    });
    /* Keyboard */
    Thunk("GetKeyboardLayout", 1229, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x04090409; /* US English */
        return true;
    });
    /* SIP (Soft Input Panel) stubs */
    Thunk("ImmSIPanelState", 804, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ImmSIPanelState -> stub 0\n");
        regs[0] = 0; return true;
    });
    Thunk("SipSetInfo", 1173, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SipSetInfo -> stub FALSE\n");
        regs[0] = 0; return true;
    });
    /* WinCE 6 IMM stubs */
    Thunk("ImmCreateContext", 1198, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ImmCreateContext -> stub 0\n");
        regs[0] = 0; return true;
    });
    Thunk("ImmDestroyContext", 1199, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ImmDestroyContext(0x%08X) -> stub TRUE\n", regs[0]);
        regs[0] = 1; return true;
    });
}
