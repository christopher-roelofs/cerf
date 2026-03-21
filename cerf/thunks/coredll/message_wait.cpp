/* Message wait/misc thunks: MsgWaitForMultipleObjectsEx, SendNotifyMessageW,
   GetMessagePos, TranslateAcceleratorW — split from message.cpp */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterMessageWaitHandlers() {
    Thunk("PostQuitMessage", 866, [](uint32_t* regs, EmulatedMemory&) -> bool {
        PostQuitMessage(regs[0]); return true;
    });
    Thunk("DefWindowProcW", 264, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0]; UINT umsg = regs[1];
        if ((umsg == WM_CREATE || umsg == WM_NCCREATE) && regs[3] != 0) {
            regs[0] = (umsg == WM_NCCREATE) ? 1 : 0;
        } else if ((umsg == WM_WINDOWPOSCHANGED || umsg == WM_WINDOWPOSCHANGING) && regs[3] != 0) {
            /* ARM lParam points to 32-bit WINDOWPOS in emulated memory.
               Marshal to native 64-bit WINDOWPOS for DefWindowProcW.
               ARM layout: hwnd(4) hwndInsertAfter(4) x(4) y(4) cx(4) cy(4) flags(4) */
            uint32_t a = regs[3];
            WINDOWPOS wp = {};
            wp.hwnd = (HWND)(intptr_t)(int32_t)mem.Read32(a + 0);
            wp.hwndInsertAfter = (HWND)(intptr_t)(int32_t)mem.Read32(a + 4);
            wp.x = (int)mem.Read32(a + 8);
            wp.y = (int)mem.Read32(a + 12);
            wp.cx = (int)mem.Read32(a + 16);
            wp.cy = (int)mem.Read32(a + 20);
            wp.flags = mem.Read32(a + 24);
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, regs[2], (LPARAM)&wp);
            /* Copy back for WM_WINDOWPOSCHANGING */
            if (umsg == WM_WINDOWPOSCHANGING) {
                mem.Write32(a + 8, wp.x);
                mem.Write32(a + 12, wp.y);
                mem.Write32(a + 16, wp.cx);
                mem.Write32(a + 20, wp.cy);
                mem.Write32(a + 24, wp.flags);
            }
        } else if (umsg == WM_SETTEXT && regs[3] != 0) {
            std::wstring text = ReadWStringFromEmu(mem, regs[3]);
            regs[0] = (uint32_t)DefWindowProcW(hw, WM_SETTEXT, 0, (LPARAM)text.c_str());
        } else {
            regs[0] = (uint32_t)DefWindowProcW(hw, umsg, regs[2], regs[3]);
        }
        return true;
    });
    Thunk("MsgWaitForMultipleObjectsEx", 871, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        DWORD nCount = regs[0];
        uint32_t pHandlesArm = regs[1];
        DWORD dwTimeout = regs[2];
        DWORD dwWakeMask = regs[3];
        DWORD dwFlags = ReadStackArg(regs, mem, 0);
        /* Clamp nCount to prevent stack overflow from corrupt values */
        if (nCount > 64) nCount = 0;
        /* Read ARM handle array and zero-extend 32-bit handles to native 64-bit */
        HANDLE handles[64] = {};
        for (DWORD i = 0; i < nCount; i++) {
            uint32_t h32 = pHandlesArm ? mem.Read32(pHandlesArm + i * 4) : 0;
            handles[i] = (HANDLE)(uintptr_t)h32;
        }
        LOG(API, "[API] MsgWaitForMultipleObjectsEx(nCount=%u, timeout=%u, wakeMask=0x%X, flags=0x%X)\n",
            nCount, dwTimeout, dwWakeMask, dwFlags);
        regs[0] = MsgWaitForMultipleObjectsEx(
            nCount, nCount ? handles : NULL,
            dwTimeout, dwWakeMask, dwFlags);
        LOG(API, "[API] MsgWaitForMultipleObjectsEx -> %u\n", regs[0]);
        return true;
    });
    Thunk("SendNotifyMessageW", 869, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = SendNotifyMessageW((HWND)(intptr_t)(int32_t)regs[0], regs[1], regs[2], regs[3]);
        return true;
    });
    Thunk("GetMessagePos", 862, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetMessagePos(); return true;
    });
    Thunk("TranslateAcceleratorW", 838, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    Thunk("MessageBoxW", 858, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring text = ReadWStringFromEmu(mem, regs[1]);
        std::wstring title = ReadWStringFromEmu(mem, regs[2]);
        LOG(API, "[API] MessageBoxW(hwnd=0x%08X, text='%ls', title='%ls', type=0x%X)\n",
            regs[0], text.c_str(), title.c_str(), regs[3]);
        regs[0] = MessageBoxW((HWND)(intptr_t)(int32_t)regs[0], text.c_str(), title.c_str(), regs[3]);
        return true;
    });
    Thunk("MessageBeep", 857, [](uint32_t* regs, EmulatedMemory&) -> bool {
        MessageBeep(regs[0]); regs[0] = 1; return true;
    });
    Thunk("InSendMessage", 1419, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0; /* FALSE — not inside a SendMessage call */
        return true;
    });
    Thunk("GetQueueStatus", 1420, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetQueueStatus(regs[0]);
        return true;
    });
    Thunk("GetMessageSource", 872, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] GetMessageSource -> stub 0\n");
        regs[0] = 0; return true;
    });
}
