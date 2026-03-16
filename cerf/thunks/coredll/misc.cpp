#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Misc small stubs: debug, clipboard, caret, sound, RAS, IMM, gestures,
   C runtime.
   AI NOTE: Do NOT dump random thunks here. If a function belongs to a
   specific subsystem (file I/O, GDI, shell, etc.), put it in the
   appropriate dedicated file. This file is ONLY for genuinely
   miscellaneous stubs that don't fit anywhere else. */
#include "../win32_thunks.h"
#include "../../log.h"
#include "../../loader/pe_loader.h"
#include <cstdio>
void Win32Thunks::RegisterMiscHandlers() {
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
    /* SIP (Software Input Panel) */
    Thunk("SipGetInfo", stub0("SipGetInfo"));
    Thunk("SipSetDefaultRect", stub0("SipSetDefaultRect"));
    Thunk("SipEnumIM", stub0("SipEnumIM"));
    Thunk("SipShowIM", 1171, stub0("SipShowIM"));
    /* Debug */
    Thunk("OutputDebugStringW", 541, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(DBG, "[DEBUG] %ls\n", ReadWStringFromEmu(mem, regs[0]).c_str()); return true;
    });
    Thunk("NKDbgPrintfW", 545, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring fmt = ReadWStringFromEmu(mem, regs[0]);
        /* Simple substitution for common format specifiers using R1-R3 */
        std::wstring out;
        uint32_t argRegs[] = { regs[1], regs[2], regs[3] };
        int argIdx = 0;
        for (size_t i = 0; i < fmt.size(); i++) {
            if (fmt[i] == L'%' && i + 1 < fmt.size()) {
                wchar_t spec = fmt[i + 1];
                if (spec == L's' && argIdx < 3) {
                    out += ReadWStringFromEmu(mem, argRegs[argIdx++]);
                    i++; continue;
                } else if (spec == L'S' && argIdx < 3) {
                    /* %S = narrow string in wide printf */
                    std::string narrow;
                    uint32_t addr = argRegs[argIdx++];
                    for (uint32_t c; addr && (c = mem.Read8(addr)); addr++) narrow += (char)c;
                    out += std::wstring(narrow.begin(), narrow.end());
                    i++; continue;
                } else if ((spec == L'd' || spec == L'u') && argIdx < 3) {
                    out += std::to_wstring(argRegs[argIdx++]);
                    i++; continue;
                } else if (spec == L'x' && argIdx < 3) {
                    wchar_t hex[16]; swprintf(hex, 16, L"%x", argRegs[argIdx++]);
                    out += hex; i++; continue;
                } else if (spec == L'X' && argIdx < 3) {
                    wchar_t hex[16]; swprintf(hex, 16, L"%X", argRegs[argIdx++]);
                    out += hex; i++; continue;
                }
            }
            out += fmt[i];
        }
        LOG(DBG, "[NKDbg] %ls\n", out.c_str());
        return true;
    });
    Thunk("RegisterDbgZones", 546, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] RegisterDbgZones(hMod=0x%08X, lpdbgZones=0x%08X) -> TRUE (stub)\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    /* Clipboard */
    Thunk("OpenClipboard", 668, stub1("OpenClipboard"));
    Thunk("CloseClipboard", 669, stub1("CloseClipboard"));
    Thunk("EmptyClipboard", 677, stub1("EmptyClipboard"));
    Thunk("GetClipboardData", 672, stub0("GetClipboardData"));
    Thunk("SetClipboardData", 671, stub0("SetClipboardData"));
    Thunk("IsClipboardFormatAvailable", 678, stub0("IsClipboardFormatAvailable"));
    Thunk("EnumClipboardFormats", 675, stub0("EnumClipboardFormats"));
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
    Thunk("RasEnumConnections", [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        if (regs[2]) mem.Write32(regs[2], 0); /* *lpcConnections = 0 */
        LOG(API, "[API] RasEnumConnections() -> 0 (none)\n");
        regs[0] = 0; return true;
    });
    Thunk("RasGetConnectStatus", stub0("RasGetConnectStatus"));
    Thunk("RasGetErrorString", stub0("RasGetErrorString"));
    Thunk("RasGetEntryProperties", stub0("RasGetEntryProperties"));
    /* C runtime misc */
    Thunk("_purecall", 1092, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] _purecall\n"); regs[0] = 0; return true;
    });
    Thunk("terminate", 1556, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] terminate\n"); ExitProcess(3); return true;
    });
    Thunk("__security_gen_cookie", 1875, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("__security_gen_cookie2", 2696, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0xBB40E64E; return true; });
    Thunk("CeGenRandom", 1601, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (uint32_t i = 0; i < regs[0]; i++) mem.Write8(regs[1] + i, (uint8_t)(rand() & 0xFF));
        regs[0] = 1; return true;
    });
    Thunk("MulDiv", 1877, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = MulDiv((int)regs[0], (int)regs[1], (int)regs[2]); return true;
    });
    Thunk("_except_handler4_common", 87, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0] = 0; return true; });
    /* setjmp/longjmp + RaiseException integration:
       Track setjmp buffers so RaiseException(NONCONTINUABLE) can longjmp to recovery point.
       MFC uses setjmp/longjmp for C++ exception handling on WinCE. */
    /* setjmp: save callee-saved registers (r4-r11), SP, LR into jmp_buf at r0.
       ARM WinCE jmp_buf layout: r4, r5, r6, r7, r8, r9, r10, r11, r13(SP), r14(LR) = 10 words */
    Thunk("setjmp", 2054, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[0];
        if (buf) {
            for (int i = 4; i <= 11; i++) mem.Write32(buf + (i - 4) * 4, regs[i]);
            mem.Write32(buf + 8 * 4, regs[13]); /* SP */
            mem.Write32(buf + 9 * 4, regs[14]); /* LR (return address) */
            setjmp_stack.push_back(buf);
        }
        LOG(API, "[API] setjmp(buf=0x%08X, LR=0x%08X) -> 0 (stack depth=%zu)\n",
            buf, regs[14], setjmp_stack.size());
        regs[0] = 0;
        return true;
    });
    Thunk("_setjmp3", thunk_handlers["setjmp"]);
    /* longjmp: restore registers from jmp_buf, return val (or 1 if val==0) */
    Thunk("longjmp", 1036, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t buf = regs[0];
        uint32_t val = regs[1];
        if (val == 0) val = 1;
        if (buf) {
            for (int i = 4; i <= 11; i++) regs[i] = mem.Read32(buf + (i - 4) * 4);
            regs[13] = mem.Read32(buf + 8 * 4); /* SP */
            regs[14] = mem.Read32(buf + 9 * 4); /* LR */
            /* Pop setjmp stack back to this buffer (or further) */
            while (!setjmp_stack.empty() && setjmp_stack.back() != buf)
                setjmp_stack.pop_back();
            if (!setjmp_stack.empty()) setjmp_stack.pop_back();
        }
        LOG(API, "[API] longjmp(buf=0x%08X, val=%u) -> LR=0x%08X (stack depth=%zu)\n",
            buf, val, regs[14], setjmp_stack.size());
        regs[0] = val;
        return true;
    });
    /* Misc kernel stubs */
    Thunk("FlushInstructionCache", 508, stub1("FlushInstructionCache"));
    Thunk("GetProcessIndexFromID", stub1("GetProcessIndexFromID"));
    Thunk("EventModify", 494, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* WinCE EventModify(HANDLE hEvent, DWORD func)
           func: 1=EVENT_PULSE, 2=EVENT_RESET, 3=EVENT_SET */
        HANDLE hEvent = (HANDLE)(intptr_t)(int32_t)regs[0];
        uint32_t func = regs[1];
        BOOL result = FALSE;
        switch (func) {
            case 3: result = SetEvent(hEvent); break;    /* EVENT_SET */
            case 2: result = ResetEvent(hEvent); break;  /* EVENT_RESET */
            case 1: result = PulseEvent(hEvent); break;  /* EVENT_PULSE */
            default:
                LOG(API, "[API] EventModify(0x%p, func=%d) -> unknown func\n", hEvent, func);
                break;
        }
        LOG(API, "[API] EventModify(0x%p, func=%d) -> %d\n", hEvent, func, result);
        regs[0] = result;
        return true;
    });
    Thunk("GlobalAddAtomW", 1519, stub1("GlobalAddAtomW"));
    Thunk("GetAPIAddress", 32, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* WinCE GetAPIAddress(apiSetId, methodIndex) — returns function pointer.
           ddraw.dll calls this during DllMain to populate its DDI vtable
           (display driver interface, methods 2-139).

           On real WinCE, these point to the display driver's DirectDraw
           acceleration entry points. We provide thunks for each method:
           - Method 132 (DirectDrawCreate): full implementation via our
             ddraw_DirectDrawCreate handler (creates IDirectDraw4 COM object)
           - Other methods: return S_OK (0) as no-op stubs. ddraw.dll checks
             the return value — S_OK means "supported, operation done." */
        constexpr int DDI_METHOD_DDCREATE = 132;
        int method = (int)regs[1];

        /* For DirectDrawCreate (method 132), return thunk to our handler */
        if (method == DDI_METHOD_DDCREATE) {
            uint32_t thunk = AllocThunk("ddraw.dll", "ddraw_DirectDrawCreate", 0, false);
            LOG(API, "[API] GetAPIAddress(set=%d, method=%d) -> 0x%08X (DirectDrawCreate)\n",
                regs[0], method, thunk);
            regs[0] = thunk;
            return true;
        }
        /* For all other DDI methods, return a stub that returns S_OK (0).
           This tells ddraw.dll the driver "handled" the call successfully. */
        constexpr uint32_t DDI_STUB_ADDR = 0xCAFEC100;
        static bool stub_installed = false;
        if (!stub_installed) {
            mem.Alloc(DDI_STUB_ADDR, 0x100);
            mem.Write32(DDI_STUB_ADDR + 0x00, 0xE3A00000); /* MOV R0, #0 (S_OK) */
            mem.Write32(DDI_STUB_ADDR + 0x04, 0xE12FFF1E); /* BX LR              */
            stub_installed = true;
        }
        LOG(API, "[API] GetAPIAddress(set=%d, method=%d) -> 0x%08X (ddi-stub)\n",
            regs[0], method, DDI_STUB_ADDR);
        regs[0] = DDI_STUB_ADDR;
        return true;
    });
    Thunk("WaitForAPIReady", 2562, stub0("WaitForAPIReady"));
    Thunk("__GetUserKData", 2528, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Return the standard PUserKData address (0xFFFFC800).
           The KData page is set up in the Win32Thunks constructor with:
             offset 0x000: lpvTls (pointer to emulated TLS slot array)
             offset 0x004: SH_CURTHREAD (current thread ID)
             offset 0x008: SH_CURPROC (current process ID) */
        regs[0] = 0xFFFFC800;
        return true;
    });
    /* Gesture stubs */
    Thunk("RegisterDefaultGestureHandler", 2928, stub0("RegisterDefaultGestureHandler"));
    Thunk("GetGestureInfo", 2925, stub0("GetGestureInfo"));
    Thunk("GetGestureExtraArguments", stub0("GetGestureExtraArguments"));
    Thunk("CloseGestureInfoHandle", 2924, stub0("CloseGestureInfoHandle"));
    /* Clipboard */
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
    Thunk("CryptProtectData", 1599, stub0("CryptProtectData"));
    Thunk("EnumFontsW", 966, stub0("EnumFontsW"));
    Thunk("GetGweApiSetTables", 1867, stub0("GetGweApiSetTables"));
    Thunk("GetSystemDefaultUILanguage", 1319, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 0x0409; /* US English */
        return true;
    });
    Thunk("CeZeroPointer", 1907, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Identity no-op — kernel buffer unmapping not needed in emulator */
        LOG(API, "[API] CeZeroPointer(0x%08X) -> 0x%08X (identity)\n", regs[0], regs[0]);
        return true;
    });
    Thunk("CeGetCallerTrust", 1395, [](uint32_t* regs, EmulatedMemory&) -> bool {
        regs[0] = 2; /* OEM_CERTIFY — full trust */
        return true;
    });
    /* PMFindProvider */
    Thunk("QueryAPISetID", 490, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* Read 4-char API set name */
        char name[5] = {};
        for (int i = 0; i < 4; i++) name[i] = (char)mem.Read8(regs[0] + i);
        LOG(API, "[API] QueryAPISetID('%s') -> -1 (not registered)\n", name);
        regs[0] = (uint32_t)-1;
        return true;
    });
}
