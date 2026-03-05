/* WinCE Theme Engine
   Loads system colors from the WinCE registry (HKLM\SYSTEM\GWE\SysColor)
   and applies them per-process via window subclassing. Zero global side effects.

   Approach:
   - Every cerf window gets a theme subclass proc (via SetWindowSubclass)
   - The subclass intercepts WM_CTLCOLOR*, WM_ERASEBKGND, WM_NCPAINT
   - Returns themed brushes and colors for control/dialog backgrounds
   - Custom-paints the title bar (caption) for top-level windows
   - SetWindowTheme strips UxTheme per-window for classic WinCE look
   - No SetSysColors, no global changes, completely per-process */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <uxtheme.h>
#include <commctrl.h>
#pragma comment(lib, "uxtheme")
#pragma comment(lib, "comctl32")

/* Number of WinCE system color indices (COLOR_SCROLLBAR=0 through COLOR_STATICTEXT=26) */
#define WCE_NUM_SYSCOLORS 27

/* Global theme state */
static bool g_theme_active = false;
static COLORREF g_wce_colors[WCE_NUM_SYSCOLORS];
static HBRUSH g_wce_brushes[WCE_NUM_SYSCOLORS];

/* Default WinCE 5.0 "Windows Standard" system colors.
   COLORREF format: 0x00BBGGRR. */
static const COLORREF wce5_default_colors[WCE_NUM_SYSCOLORS] = {
    0x00C8D0D4, /* 0  COLOR_SCROLLBAR        RGB(212,208,200) silver */
    0x00A56E3A, /* 1  COLOR_BACKGROUND        RGB(58,110,165)  steel blue desktop */
    0x00800000, /* 2  COLOR_ACTIVECAPTION     RGB(0,0,128)     navy blue */
    0x00808080, /* 3  COLOR_INACTIVECAPTION   RGB(128,128,128) gray */
    0x00C8D0D4, /* 4  COLOR_MENU              RGB(212,208,200) silver */
    0x00FFFFFF, /* 5  COLOR_WINDOW            RGB(255,255,255) white */
    0x00000000, /* 6  COLOR_WINDOWFRAME       RGB(0,0,0)       black */
    0x00000000, /* 7  COLOR_MENUTEXT          RGB(0,0,0)       black */
    0x00000000, /* 8  COLOR_WINDOWTEXT        RGB(0,0,0)       black */
    0x00FFFFFF, /* 9  COLOR_CAPTIONTEXT       RGB(255,255,255) white */
    0x00C8D0D4, /* 10 COLOR_ACTIVEBORDER      RGB(212,208,200) silver */
    0x00C8D0D4, /* 11 COLOR_INACTIVEBORDER    RGB(212,208,200) silver */
    0x00808080, /* 12 COLOR_APPWORKSPACE      RGB(128,128,128) gray */
    0x00800000, /* 13 COLOR_HIGHLIGHT         RGB(0,0,128)     navy blue */
    0x00FFFFFF, /* 14 COLOR_HIGHLIGHTTEXT     RGB(255,255,255) white */
    0x00C8D0D4, /* 15 COLOR_BTNFACE           RGB(212,208,200) silver */
    0x00808080, /* 16 COLOR_BTNSHADOW         RGB(128,128,128) gray */
    0x00808080, /* 17 COLOR_GRAYTEXT          RGB(128,128,128) gray */
    0x00000000, /* 18 COLOR_BTNTEXT           RGB(0,0,0)       black */
    0x00C8D0D4, /* 19 COLOR_INACTIVECAPTIONTEXT RGB(212,208,200) silver */
    0x00FFFFFF, /* 20 COLOR_BTNHIGHLIGHT      RGB(255,255,255) white */
    0x00404040, /* 21 COLOR_3DDKSHADOW        RGB(64,64,64)    dark gray */
    0x00C8D0D4, /* 22 COLOR_3DLIGHT           RGB(212,208,200) silver */
    0x00000000, /* 23 COLOR_INFOTEXT          RGB(0,0,0)       black */
    0x00E1FFFF, /* 24 COLOR_INFOBK            RGB(255,255,225) light yellow */
    0x00C8D0D4, /* 25 COLOR_STATIC            RGB(212,208,200) silver */
    0x00000000, /* 26 COLOR_STATICTEXT        RGB(0,0,0)       black */
};

/* ======================================================================
   Themed Brush Helpers
   ====================================================================== */

static HBRUSH GetThemedBrush(int color_idx) {
    if (color_idx < 0 || color_idx >= WCE_NUM_SYSCOLORS) return NULL;
    if (!g_wce_brushes[color_idx])
        g_wce_brushes[color_idx] = CreateSolidBrush(g_wce_colors[color_idx]);
    return g_wce_brushes[color_idx];
}

static COLORREF GetThemedColor(int color_idx) {
    if (color_idx >= 0 && color_idx < WCE_NUM_SYSCOLORS)
        return g_wce_colors[color_idx];
    return GetSysColor(color_idx);
}

/* ======================================================================
   Theme Subclass Proc — handles painting messages for themed windows
   ====================================================================== */

#define THEME_SUBCLASS_ID 0xCE0F0002

/* refData: 1 = top-level window, 0 = child control */
static LRESULT CALLBACK ThemeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    bool is_toplevel = (refData != 0);

    switch (msg) {

    /* ---- WM_CTLCOLOR* messages: return themed brush for control backgrounds ---- */
    case WM_CTLCOLORDLG: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_3DFACE));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_3DFACE);
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_3DFACE));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_3DFACE);
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_3DFACE));
        return (LRESULT)GetThemedBrush(COLOR_3DFACE);
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_WINDOW));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_WINDOW);
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, GetThemedColor(COLOR_WINDOW));
        SetTextColor(hdc, GetThemedColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetThemedBrush(COLOR_WINDOW);
    }
    case WM_CTLCOLORSCROLLBAR: {
        return (LRESULT)GetThemedBrush(COLOR_SCROLLBAR);
    }

    /* ---- WM_ERASEBKGND: fill window background with themed color ---- */
    case WM_ERASEBKGND: {
        /* Determine background color from the window class brush */
        ULONG_PTR cls_brush = GetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND);
        int color_idx = COLOR_3DFACE; /* default for dialogs */
        if (cls_brush >= 1 && cls_brush <= 31) {
            color_idx = (int)cls_brush - 1;
            if (color_idx >= WCE_NUM_SYSCOLORS) color_idx = COLOR_3DFACE;
        } else if (cls_brush == 0) {
            /* No class brush — let DefWindowProc handle it */
            break;
        } else {
            /* Actual HBRUSH handle — not a color constant, don't override */
            break;
        }
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, GetThemedBrush(color_idx));
        return 1;
    }

    /* ---- WM_NCPAINT: custom title bar for top-level windows ---- */
    case WM_NCPAINT: {
        if (!is_toplevel) break;

        /* Let DefWindowProc draw borders and non-caption NC area first */
        DefSubclassProc(hwnd, msg, wParam, lParam);

        /* Now overdraw the caption bar with our themed color */
        HDC hdc = GetWindowDC(hwnd);
        if (!hdc) return 0;

        bool active = (GetForegroundWindow() == hwnd);
        COLORREF caption_color = GetThemedColor(active ? COLOR_ACTIVECAPTION : COLOR_INACTIVECAPTION);
        COLORREF text_color = GetThemedColor(active ? COLOR_CAPTIONTEXT : COLOR_INACTIVECAPTIONTEXT);

        /* Calculate caption rect in window coordinates */
        RECT wr;
        GetWindowRect(hwnd, &wr);
        int winW = wr.right - wr.left;
        int frame = GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        int captH = GetSystemMetrics(SM_CYCAPTION);
        int border_top = GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);

        RECT captRect;
        captRect.left = frame;
        captRect.top = border_top;
        captRect.right = winW - frame;
        captRect.bottom = border_top + captH;

        /* Fill caption bar */
        HBRUSH captBrush = CreateSolidBrush(caption_color);
        FillRect(hdc, &captRect, captBrush);
        DeleteObject(captBrush);

        /* Draw caption text */
        wchar_t title[256] = {};
        GetWindowTextW(hwnd, title, 256);
        if (title[0]) {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, text_color);

            /* Use the system caption font */
            NONCLIENTMETRICSW ncm = {};
            ncm.cbSize = sizeof(ncm);
            SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
            HFONT captFont = CreateFontIndirectW(&ncm.lfCaptionFont);
            HFONT oldFont = (HFONT)SelectObject(hdc, captFont);

            /* Get icon width to offset text */
            HICON hIcon = (HICON)SendMessageW(hwnd, WM_GETICON, ICON_SMALL, 0);
            int iconW = hIcon ? GetSystemMetrics(SM_CXSMICON) + 4 : 0;

            RECT textRect = captRect;
            textRect.left += 4 + iconW;
            textRect.right -= 4;
            DrawTextW(hdc, title, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

            SelectObject(hdc, oldFont);
            DeleteObject(captFont);
        }

        /* Draw the icon */
        HICON hIcon = (HICON)SendMessageW(hwnd, WM_GETICON, ICON_SMALL, 0);
        if (hIcon) {
            int iconSize = GetSystemMetrics(SM_CXSMICON);
            int iconY = captRect.top + (captH - iconSize) / 2;
            DrawIconEx(hdc, captRect.left + 2, iconY, hIcon, iconSize, iconSize, 0, NULL, DI_NORMAL);
        }

        /* Draw caption buttons (Close [X], Help [?], etc.) with themed colors.
           Use DrawFrameControl which draws classic-style buttons. */
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        int btnW = GetSystemMetrics(SM_CXSIZE) - 2;
        int btnH = captH - 4;
        int btnY = captRect.top + 2;
        int btnX = captRect.right - 2;

        /* Close button */
        if (style & WS_SYSMENU) {
            btnX -= btnW;
            RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
            /* Fill with themed face color */
            FillRect(hdc, &btnR, GetThemedBrush(COLOR_3DFACE));
            DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONCLOSE);
        }

        /* Help button [?] */
        if (exStyle & WS_EX_CONTEXTHELP) {
            btnX -= btnW;
            RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
            FillRect(hdc, &btnR, GetThemedBrush(COLOR_3DFACE));
            DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONHELP);
        }

        /* Max/Min buttons */
        if (style & WS_MAXIMIZEBOX) {
            btnX -= btnW;
            RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
            FillRect(hdc, &btnR, GetThemedBrush(COLOR_3DFACE));
            DrawFrameControl(hdc, &btnR, DFC_CAPTION,
                IsZoomed(hwnd) ? DFCS_CAPTIONRESTORE : DFCS_CAPTIONMAX);
        }
        if (style & WS_MINIMIZEBOX) {
            btnX -= btnW;
            RECT btnR = { btnX, btnY, btnX + btnW, btnY + btnH };
            FillRect(hdc, &btnR, GetThemedBrush(COLOR_3DFACE));
            DrawFrameControl(hdc, &btnR, DFC_CAPTION, DFCS_CAPTIONMIN);
        }

        ReleaseDC(hwnd, hdc);
        return 0;
    }

    case WM_NCACTIVATE: {
        if (!is_toplevel) break;
        /* Let default handle it, then repaint our caption */
        LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
        /* Trigger our WM_NCPAINT to redraw caption with active/inactive color */
        SendMessageW(hwnd, WM_NCPAINT, (WPARAM)1, 0);
        return r;
    }

    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID);
        break;
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

/* ---- Theme initialization ---- */

void Win32Thunks::InitWceTheme() {
    LOG(THEME, "[THEME] InitWceTheme: enable_theming=%d, disable_uxtheme=%d\n",
            enable_theming, disable_uxtheme);
    if (!enable_theming && !disable_uxtheme) return;

    if (enable_theming) {
        /* Ensure registry is loaded */
        LoadRegistry();

        /* Read HKLM\SYSTEM\GWE\SysColor from emulated registry.
           Format: 27 x 4-byte COLORREFs (R,G,B,0 per entry = 108 bytes total). */
        bool loaded_from_reg = false;
        std::wstring key = L"hklm\\system\\gwe";
        auto it = registry.find(key);
        if (it != registry.end()) {
            std::wstring valname = L"syscolor";
            auto vit = it->second.values.find(valname);
            if (vit != it->second.values.end() && vit->second.type == REG_BINARY) {
                const auto& data = vit->second.data;
                size_t count = data.size() / 4;
                if (count > WCE_NUM_SYSCOLORS) count = WCE_NUM_SYSCOLORS;
                for (size_t i = 0; i < count; i++) {
                    uint8_t r = data[i * 4 + 0];
                    uint8_t g = data[i * 4 + 1];
                    uint8_t b = data[i * 4 + 2];
                    g_wce_colors[i] = RGB(r, g, b);
                }
                loaded_from_reg = true;
                LOG(THEME, "[THEME] Loaded %zu system colors from registry\n", count);
            }
        }

        if (!loaded_from_reg) {
            memcpy(g_wce_colors, wce5_default_colors, sizeof(g_wce_colors));
            LOG(THEME, "[THEME] Using default WinCE 5.0 system colors\n");

            std::vector<uint8_t> blob(WCE_NUM_SYSCOLORS * 4);
            for (int i = 0; i < WCE_NUM_SYSCOLORS; i++) {
                blob[i * 4 + 0] = GetRValue(g_wce_colors[i]);
                blob[i * 4 + 1] = GetGValue(g_wce_colors[i]);
                blob[i * 4 + 2] = GetBValue(g_wce_colors[i]);
                blob[i * 4 + 3] = 0;
            }
            RegValue val;
            val.type = REG_BINARY;
            val.data = std::move(blob);
            registry[key].values[L"syscolor"] = val;
            EnsureParentKeys(key);
            SaveRegistry();
        }

        /* Initialize brush cache */
        memset(g_wce_brushes, 0, sizeof(g_wce_brushes));

        g_theme_active = true;
        LOG(THEME, "[THEME] WinCE theming active (subclass). Caption=0x%06X, BtnFace=0x%06X, Window=0x%06X\n",
            g_wce_colors[COLOR_ACTIVECAPTION],
            g_wce_colors[COLOR_BTNFACE],
            g_wce_colors[COLOR_WINDOW]);
    }
}

/* ---- Per-window theme application ---- */

void Win32Thunks::ApplyWindowTheme(HWND hwnd, bool is_toplevel) {
    if (!hwnd) return;

    /* Strip UxTheme visual styles for classic WinCE look */
    if (disable_uxtheme) {
        SetWindowTheme(hwnd, L"", L"");
    }

    /* Install theme subclass to intercept painting messages.
       refData = 1 for top-level (custom title bar), 0 for child controls. */
    if (enable_theming) {
        SetWindowSubclass(hwnd, ThemeSubclassProc, THEME_SUBCLASS_ID,
                          is_toplevel ? 1 : 0);
    }
}

/* ---- Update theme colors at runtime (called from SetSysColors thunk) ---- */

void Win32Thunks::UpdateWceThemeColor(int index, COLORREF color) {
    if (index < 0 || index >= WCE_NUM_SYSCOLORS) return;
    g_wce_colors[index] = color;
    if (g_wce_brushes[index]) {
        DeleteObject(g_wce_brushes[index]);
        g_wce_brushes[index] = nullptr;
    }
}

/* ---- Thunk-level color access (for ARM code calling GetSysColor) ---- */

COLORREF Win32Thunks::GetWceThemeColor(int index) {
    if (enable_theming && index >= 0 && index < WCE_NUM_SYSCOLORS)
        return g_wce_colors[index];
    return GetSysColor(index);
}

HBRUSH Win32Thunks::GetWceThemeBrush(int index) {
    if (enable_theming && index >= 0 && index < WCE_NUM_SYSCOLORS) {
        if (!g_wce_brushes[index])
            g_wce_brushes[index] = CreateSolidBrush(g_wce_colors[index]);
        return g_wce_brushes[index];
    }
    return GetSysColorBrush(index);
}
