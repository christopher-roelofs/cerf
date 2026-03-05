/* WinCE Theme Engine
   Loads system colors from the WinCE registry (HKLM\SYSTEM\GWE\SysColor)
   and applies them to the process using SetSysColors + per-window UxTheme stripping.

   SetSysColors updates the kernel-managed shared color table that ALL painting
   code reads from (title bars, button faces, dialog backgrounds, scrollbars, etc.).
   This is the only way to change these colors — inline/IAT hooking of GetSysColor
   doesn't work because internal user32 painting reads the table directly.

   To minimize impact on other applications:
   - Original colors are saved before modification
   - Colors are restored on process exit (atexit handler)
   - SetWindowTheme strips UxTheme per-window for classic look */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <uxtheme.h>
#pragma comment(lib, "uxtheme")

/* Number of WinCE system color indices (COLOR_SCROLLBAR=0 through COLOR_STATICTEXT=26) */
#define WCE_NUM_SYSCOLORS 27

/* Global theme state */
static bool g_theme_active = false;
static COLORREF g_wce_colors[WCE_NUM_SYSCOLORS];
static HBRUSH g_wce_brushes[WCE_NUM_SYSCOLORS];

/* Saved original system colors (for restoration on exit) */
static COLORREF g_original_colors[WCE_NUM_SYSCOLORS];
static bool g_colors_saved = false;

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

/* Color index array for SetSysColors (indices 0-26) */
static const INT g_color_indices[WCE_NUM_SYSCOLORS] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26
};

/* Restore original system colors (atexit handler) */
static void RestoreOriginalColors() {
    if (g_colors_saved) {
        SetSysColors(WCE_NUM_SYSCOLORS, g_color_indices, g_original_colors);
        LOG(THEME, "[THEME] Restored original system colors\n");
    }
}

/* Apply our WinCE colors to the system */
static void ApplyWceColors() {
    SetSysColors(WCE_NUM_SYSCOLORS, g_color_indices, g_wce_colors);
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

        /* Save original system colors before overwriting */
        for (int i = 0; i < WCE_NUM_SYSCOLORS; i++)
            g_original_colors[i] = GetSysColor(i);
        g_colors_saved = true;

        /* Register atexit handler to restore colors on process exit */
        atexit(RestoreOriginalColors);

        /* Apply WinCE colors to the system color table.
           This updates the kernel-shared color table that all painting
           code reads from — title bars, buttons, dialogs, everything. */
        ApplyWceColors();
        g_theme_active = true;

        LOG(THEME, "[THEME] WinCE theming active (SetSysColors). Caption=0x%06X, BtnFace=0x%06X, Window=0x%06X\n",
            g_wce_colors[COLOR_ACTIVECAPTION],
            g_wce_colors[COLOR_BTNFACE],
            g_wce_colors[COLOR_WINDOW]);
    }
}

/* ---- Per-window theme application ---- */

void Win32Thunks::ApplyWindowTheme(HWND hwnd, bool is_toplevel) {
    if (!hwnd) return;

    /* Strip UxTheme visual styles for classic WinCE look.
       With SetSysColors applied, the classic renderer uses our WinCE
       colors for everything — title bars, borders, buttons, dialogs. */
    if (disable_uxtheme) {
        SetWindowTheme(hwnd, L"", L"");
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
    /* Update the system color table too */
    INT idx = index;
    SetSysColors(1, &idx, &color);
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
