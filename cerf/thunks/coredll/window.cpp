/* Window thunks: RegisterClass, CreateWindowEx, Show/Move/Destroy */
#include "../win32_thunks.h"
#include "../class_bridge.h"
#include "../../log.h"
#include <cstdio>
#include <commctrl.h>

void Win32Thunks::RegisterWindowHandlers() {
    Thunk("RegisterClassW", 95, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t arm_wndproc = mem.Read32(regs[0] + 4);
        WNDCLASSW wc = {};
        /* WinCE gives each window its own persistent DC (equivalent to CS_OWNDC).
           mshtml and other WinCE code cache DC handles from GetDC/WM_ERASEBKGND
           and reuse them later, expecting the DC to remain valid.  Without CS_OWNDC,
           desktop Windows uses a shared DC cache where DCs become invalid after
           ReleaseDC or when the system reclaims them after message processing. */
        wc.style = ClassBridge::TranslateStyleToNative(mem.Read32(regs[0]));
        wc.lpfnWndProc = EmuWndProc;
        wc.cbClsExtra = mem.Read32(regs[0]+8); wc.cbWndExtra = mem.Read32(regs[0]+12);
        wc.hInstance = GetModuleHandleW(NULL);
        /* WinCE icon/cursor/brush handles are 32-bit values that don't map to
           native x64 GDI handles. Use safe native equivalents instead.
           The ARM WndProc handles all actual drawing via EmuWndProc dispatch. */
        uint32_t emu_cursor = mem.Read32(regs[0]+24);
        uint32_t emu_brush = mem.Read32(regs[0]+28);
        uint32_t emu_icon = 0; /* WinCE icons not preserved (always NULL) */
        wc.hIcon = NULL;
        wc.hCursor = emu_cursor ? LoadCursorW(NULL, IDC_ARROW) : NULL;
        /* Brush translation: via ClassBridge (single source of truth) */
        wc.hbrBackground = ClassBridge::TranslateBrushToNative(emu_brush);
        std::wstring className = ReadWStringFromEmu(mem, mem.Read32(regs[0]+36));
        wc.lpszClassName = className.c_str();
        arm_wndprocs[className][EmulatedMemory::process_slot] = arm_wndproc;
        /* Store original ARM class info in ClassBridge for Get/SetClassLongW */
        ArmClassInfo aci;
        aci.arm_wndproc = arm_wndproc;
        aci.arm_style = mem.Read32(regs[0]); /* original style WITHOUT CS_OWNDC */
        aci.arm_brush = emu_brush;
        aci.arm_cursor = emu_cursor;
        aci.arm_icon = emu_icon;
        GetClassBridge().RegisterClass(className, aci);
        LOG(API, "[API] RegisterClassW: '%ls' (ARM WndProc=0x%08X, brush=0x%08X->0x%08X)\n",
            className.c_str(), arm_wndproc, emu_brush, (uint32_t)(uintptr_t)wc.hbrBackground);
        ATOM atom = RegisterClassW(&wc);
        if (!atom && GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
            /* Check if we already registered this class ourselves (arm_wndprocs
               has an entry).  In WinCE each process has its own class namespace,
               so a second instance re-registering the same class succeeds.  In our
               emulation all instances share one Win32 namespace.  If we already
               own the class (EmuWndProc is the wndproc), just return success —
               the arm_wndprocs map was already updated above (line 41). */
            WNDCLASSW existing = {};
            if (GetClassInfoW(GetModuleHandleW(NULL), className.c_str(), &existing)
                && existing.lpfnWndProc == EmuWndProc) {
                LOG(API, "[API]   Class '%ls' already registered with EmuWndProc, returning success\n", className.c_str());
                atom = (ATOM)GetClassInfoW(GetModuleHandleW(NULL), className.c_str(), &existing);
            } else {
                /* Native DLL registered it — try to replace with our version. */
                LOG(API, "[API]   Class '%ls' already exists, replacing with ARM version\n", className.c_str());
                HMODULE mods[] = {
                    GetModuleHandleW(L"comctl32.dll"),
                    GetModuleHandleW(L"comctl32"),
                    GetModuleHandleW(NULL),
                    NULL
                };
                for (HMODULE mod : mods) {
                    if (mod && UnregisterClassW(className.c_str(), mod)) {
                        LOG(API, "[API]   Unregistered existing class from module %p\n", mod);
                        break;
                    }
                }
                atom = RegisterClassW(&wc);
            }
        }
        if (!atom) LOG(API, "[API]   RegisterClassW FAILED (error=%d)\n", GetLastError());
        regs[0] = (uint32_t)atom; return true;
    });
    Thunk("CreateWindowExW", 246, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t exStyle = regs[0];
        uint32_t class_raw = regs[1];
        bool class_is_atom = (class_raw != 0 && class_raw <= 0xFFFF);
        std::wstring className;
        LPCWSTR lpClassName;
        if (class_is_atom) {
            lpClassName = MAKEINTRESOURCEW(class_raw);
            wchar_t buf[32];
            swprintf(buf, 32, L"#ATOM:%u", class_raw);
            className = buf;
        } else {
            className = ReadWStringFromEmu(mem, class_raw);
            lpClassName = className.c_str();
        }
        std::wstring windowName = ReadWStringFromEmu(mem, regs[2]);
        uint32_t style = regs[3];
        int x=(int)ReadStackArg(regs,mem,0), y=(int)ReadStackArg(regs,mem,1);
        int w=(int)ReadStackArg(regs,mem,2), h=(int)ReadStackArg(regs,mem,3);
        HWND parent = (HWND)(intptr_t)(int32_t)ReadStackArg(regs,mem,4);
        HMENU menu_h = (HMENU)(intptr_t)(int32_t)ReadStackArg(regs,mem,5);
        uint32_t arm_lpParam = ReadStackArg(regs,mem,7);

        /* Save original WinCE styles before any modification */
        uint32_t wce_style = style;
        uint32_t wce_exstyle = exStyle;
        bool has_captionok = (exStyle & 0x80000000) != 0;
        exStyle &= 0x0FFFFFFF; /* strip WinCE-only high bits */

        /* WinCE COMBOBOX defaults to CBS_DROPDOWN when no CBS type bits are set */
        if (_wcsicmp(className.c_str(), L"COMBOBOX") == 0 && (style & 0x3) == 0)
            style |= CBS_DROPDOWN;
        /* WinCE allows WS_CHILD with NULL parent — desktop doesn't */
        if (parent == NULL && (style & WS_CHILD)) {
            style &= ~(uint32_t)WS_CHILD;
            style |= WS_POPUP;
        }

        bool is_child = (style & WS_CHILD) != 0;
        bool is_toplevel = (parent == NULL && !is_child);

        LOG(API, "[API] CWEx: class='%ls' wce_style=0x%08X exStyle=0x%08X toplevel=%d w=%d h=%d\n",
            className.c_str(), wce_style, wce_exstyle, is_toplevel, w, h);

        if (is_toplevel) {
            /* Convert all top-level WinCE windows to WS_POPUP on desktop.
               This eliminates the native thick frame entirely — no inflate/deflate.
               Our WM_NCCALCSIZE handler in EmuWndProc provides WinCE NC area. */
            style &= ~(uint32_t)(WS_OVERLAPPED | WS_THICKFRAME |
                                  WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CAPTION);
            style |= WS_POPUP;
            /* Only add WS_EX_APPWINDOW for windows with actual size.
               Zero-sized windows (e.g. URL Moniker Notification Window) are
               message-only and should not appear on the taskbar. */
            if (w != 0 || h != 0)
                exStyle |= WS_EX_APPWINDOW;

            /* CW_USEDEFAULT → fill the work area (screen minus taskbar/shell panels).
               On real WinCE the shell calls SPI_SETWORKAREA to reserve taskbar space;
               apps size themselves to the work area, not the full screen. */
            RECT wa = GetWorkArea();
            if (x == (int)0x80000000) x = (int)wa.left;
            if (y == (int)0x80000000) y = (int)wa.top;

            if (w == (int)0x80000000) {
                w = (int)(wa.right - wa.left);
                if (h == (int)0x80000000) h = (int)(wa.bottom - wa.top);
            }
            if (h == (int)0x80000000) {
                h = (int)(wa.bottom - wa.top);
            }
        } else if (!is_child) {
            /* Owned popup (has parent but not WS_CHILD) — convert to WS_POPUP
               just like top-level windows for consistent WinCE NC area handling. */
            style &= ~(uint32_t)(WS_OVERLAPPED | WS_THICKFRAME |
                                  WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CAPTION);
            style |= WS_POPUP;
            RECT wa = GetWorkArea();
            if (x == (int)0x80000000) x = (int)wa.left;
            if (y == (int)0x80000000) y = (int)wa.top;
            if (w == (int)0x80000000) w = (int)(wa.right - wa.left);
            if (h == (int)0x80000000) h = (int)(wa.bottom - wa.top);
        } else {
            /* Child window — pass through, minimal fixups */
            if (x == (int)0x80000000) x = 0;
            if (y == (int)0x80000000) y = 0;
            bool allow_zero_size = (className == L"Menu");
            if (!allow_zero_size) {
                if (w == (int)0x80000000 || w == 0) w = (int)screen_width;
                if (h == (int)0x80000000 || h == 0) h = (int)screen_height;
            } else {
                if (w == (int)0x80000000) w = 0;
                if (h == (int)0x80000000) h = 0;
            }
        }

        /* Per-class fixups */
        if (className == L"SysListView32")
            style |= 0x0100; /* LVS_AUTOARRANGE */
        if (className == L"Shell Embedding" || className == L"DefShellView")
            style |= WS_VISIBLE;

        LOG(API, "[API] CreateWindowExW: class='%ls' title='%ls' style=0x%08X exStyle=0x%08X parent=0x%p pos=(%d,%d) size=(%dx%d)\n",
            className.c_str(), windowName.c_str(), style, exStyle, parent, x, y, w, h);

        /* Stash original WinCE styles for EmuWndProc to pick up during WM_NCCREATE.
           Covers both true top-level and owned popup windows. */
        if (!is_child) {
            tls_pending_wce_style = wce_style;
            tls_pending_wce_exstyle = wce_exstyle;
        }

        HWND hwnd = CreateWindowExW(exStyle, lpClassName, windowName.c_str(),
            style, x, y, w, h, parent, menu_h,
            GetModuleHandleW(NULL), (LPVOID)(uintptr_t)arm_lpParam);

        tls_pending_wce_style = 0;
        tls_pending_wce_exstyle = 0;

        if (!hwnd) {
            DWORD err = GetLastError();
            LOG(API, "[API]   CreateWindowExW FAILED (error=%d)\n", err);
        }
        if (hwnd) {
            uint32_t arm_wndproc = 0;
            for (auto& [cls, slot_map] : arm_wndprocs) {
                if (_wcsicmp(cls.c_str(), className.c_str()) == 0) {
                    auto sit = slot_map.find(EmulatedMemory::process_slot);
                    if (sit != slot_map.end()) { arm_wndproc = sit->second; break; }
                }
            }
            if (arm_wndproc && hwnd_wndproc_map.find(hwnd) == hwnd_wndproc_map.end())
                hwnd_wndproc_map[hwnd] = arm_wndproc;
            hwnd_slot_map[hwnd] = EmulatedMemory::process_slot;

            if (is_toplevel) {
                if (!windowName.empty()) SetWindowTextW(hwnd, windowName.c_str());
                HICON hIcon = LoadIconW(NULL, IDI_APPLICATION);
                SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
                /* On real WinCE, window activation is managed by the GWE kernel
                   without cross-process SendMessage. Desktop Windows'
                   SetForegroundWindow sends WM_ACTIVATEAPP via SendMessage to the
                   previous foreground window — this deadlocks when that window's
                   thread is executing ARM code and can't pump messages.
                   Use SetWindowPos(HWND_TOP) which brings to front without the
                   cross-thread activation messaging. */
                SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            }
            ApplyWindowTheme(hwnd, !is_child);
            if (has_captionok) {
                captionok_hwnds.insert(hwnd);
                InstallCaptionOk(hwnd);
                LOG(API, "[API]   WS_EX_CAPTIONOKBTN tracked for HWND=0x%p\n", hwnd);
            }
            if (!is_toplevel) {
                static HFONT s_wce_default_font = NULL;
                if (!s_wce_default_font) {
                    LOGFONTW lf = {};
                    lf.lfHeight = wce_sysfont_height;
                    lf.lfWeight = wce_sysfont_weight;
                    lf.lfCharSet = DEFAULT_CHARSET;
                    lf.lfQuality = DEFAULT_QUALITY;
                    lf.lfPitchAndFamily = VARIABLE_PITCH | FF_SWISS;
                    wcscpy_s(lf.lfFaceName, wce_sysfont_name.c_str());
                    s_wce_default_font = CreateFontIndirectW(&lf);
                }
                if (s_wce_default_font)
                    ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)s_wce_default_font, FALSE);
            }
        }
        regs[0] = (uint32_t)(uintptr_t)hwnd; return true;
    });
    Thunk("ShowWindow", 266, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] ShowWindow(0x%p, %d)\n", hw, regs[1]);
        if (hw == NULL && regs[1] == 5) { regs[0] = 0; return true; }
        regs[0] = ShowWindow(hw, regs[1]);
        /* With real threading, normal message delivery works correctly. */
        return true;
    });
    Thunk("UpdateWindow", 267, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] UpdateWindow(0x%p)\n", hw);
        regs[0] = UpdateWindow(hw);
        return true;
    });
    Thunk("RedrawWindow", 1672, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        /* lprcUpdate (regs[1]) — WinCE RECT ptr in emulated memory */
        RECT rc, *prc = NULL;
        if (regs[1]) { rc = {(LONG)mem.Read32(regs[1]),(LONG)mem.Read32(regs[1]+4),(LONG)mem.Read32(regs[1]+8),(LONG)mem.Read32(regs[1]+12)}; prc = &rc; }
        /* hrgnUpdate (regs[2]) — pass through as handle */
        HRGN hrgn = (HRGN)(intptr_t)(int32_t)regs[2];
        UINT flags = regs[3];
        wchar_t cls[64] = {};
        GetClassNameW(hw, cls, 64);
        RECT rgnBox = {};
        if (hrgn) GetRgnBox(hrgn, &rgnBox);
        LOG(API, "[API] RedrawWindow(0x%p '%ls', rc=%s{%d,%d,%d,%d}, rgn=0x%p{%d,%d,%d,%d}, flags=0x%X)\n",
            hw, cls,
            prc ? "" : "NULL", prc ? prc->left : 0, prc ? prc->top : 0, prc ? prc->right : 0, prc ? prc->bottom : 0,
            hrgn, rgnBox.left, rgnBox.top, rgnBox.right, rgnBox.bottom, flags);
        regs[0] = RedrawWindow(hw, prc, hrgn, flags);
        return true;
    });
    Thunk("DestroyWindow", 265, [](uint32_t* regs, EmulatedMemory&) -> bool {
        HWND hw = (HWND)(intptr_t)(int32_t)regs[0];
        LOG(API, "[API] DestroyWindow(0x%p) IsWindow=%d\n", hw, IsWindow(hw));
        if (captionok_hwnds.erase(hw)) RemoveCaptionOk(hw);
        hwnd_dlgproc_map.erase(hw);
        BOOL ret = DestroyWindow(hw);
        LOG(API, "[API] DestroyWindow result=%d, error=%d\n", ret, GetLastError());
        hwnd_wndproc_map.erase(hw);
        hwnd_native_wndproc_map.erase(hw);
        hwnd_wce_style_map.erase(hw);
        hwnd_wce_exstyle_map.erase(hw);
        hwnd_slot_map.erase(hw);
        regs[0] = ret;
        return true;
    });
}
