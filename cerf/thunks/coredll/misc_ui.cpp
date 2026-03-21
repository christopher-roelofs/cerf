/* Clipboard, caret, and sound stubs — split from misc.cpp */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>

void Win32Thunks::RegisterMiscUiHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    auto stub1 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 1\n", name); regs[0] = 1; return true;
        };
    };
    /* Clipboard */
    Thunk("OpenClipboard", 668, stub1("OpenClipboard"));
    Thunk("CloseClipboard", 669, stub1("CloseClipboard"));
    Thunk("EmptyClipboard", 677, stub1("EmptyClipboard"));
    Thunk("GetClipboardData", 672, stub0("GetClipboardData"));
    Thunk("SetClipboardData", 671, stub0("SetClipboardData"));
    Thunk("IsClipboardFormatAvailable", 678, stub0("IsClipboardFormatAvailable"));
    Thunk("EnumClipboardFormats", 675, stub0("EnumClipboardFormats"));
    Thunk("GetClipboardFormatNameW", 676, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        UINT format = regs[0];
        int cchMax = (int)regs[2];
        if (cchMax > 256) cchMax = 256;
        wchar_t buf[256] = {};
        int ret = ::GetClipboardFormatNameW(format, buf, cchMax);
        if (ret > 0 && regs[1]) {
            for (int i = 0; i <= ret; i++) mem.Write16(regs[1] + i*2, buf[i]);
        }
        LOG(API, "[API] GetClipboardFormatNameW(%u) -> %d '%ls'\n", format, ret, buf);
        regs[0] = ret;
        return true;
    });
    /* Caret — real implementations needed by RichEdit for the blinking cursor */
    Thunk("CreateCaret", 658, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        HBITMAP hbm = (HBITMAP)(uintptr_t)regs[1];
        regs[0] = CreateCaret(hw, hbm, (int)regs[2], (int)regs[3]);
        return true;
    });
    Thunk("HideCaret", 660, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = HideCaret((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("ShowCaret", 661, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = ShowCaret((HWND)(intptr_t)(int32_t)regs[0]);
        return true;
    });
    Thunk("GetCaretBlinkTime", 664, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = GetCaretBlinkTime();
        return true;
    });
    /* Sound */
    Thunk("sndPlaySoundW", 377, stub1("sndPlaySoundW"));
    Thunk("PlaySoundW", 378, stub1("PlaySoundW"));
    Thunk("waveOutSetVolume", 382, stub0("waveOutSetVolume"));
    /* RAS — wininet.dll dynamically loads these via GetProcAddress */
    Thunk("RasDial", 342, stub0("RasDial"));
    Thunk("RasHangup", stub0("RasHangup"));
    thunk_handlers["RasHangUp"] = thunk_handlers["RasHangup"];
    Thunk("RasEnumEntries", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* (reserved, phonebook, entries, cb, count) — 5th arg on stack */
        uint32_t sp = regs[13];
        uint32_t count_ptr = mem.Read32(sp);
        if (count_ptr) mem.Write32(count_ptr, 0);
        if (regs[3]) mem.Write32(regs[3], 0); /* *lpcb = 0 */
        LOG(API, "[API] RasEnumEntries() -> 0 (no entries)\n");
        regs[0] = 0; return true;
    });
    Thunk("RasGetErrorString", stub0("RasGetErrorString"));
    Thunk("RasGetEntryProperties", stub0("RasGetEntryProperties"));
    /* Clipboard (additional) */
    Thunk("RegisterClipboardFormatW", 673, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring fmt = ReadWStringFromEmu(mem, regs[0]);
        LOG(API, "[API] RegisterClipboardFormatW('%ls')\n", fmt.c_str());
        UINT id = RegisterClipboardFormatW(fmt.c_str());
        regs[0] = id;
        return true;
    });
    Thunk("GetClipboardOwner", 670, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] GetClipboardOwner() -> NULL (stub)\n");
        regs[0] = 0;
        return true;
    });
    Thunk("GetClipboardDataAlloc", 681, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] GetClipboardDataAlloc(format=%u) -> stub 0\n", regs[0]);
        regs[0] = 0; return true;
    });
}
