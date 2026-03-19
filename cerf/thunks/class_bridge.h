#pragma once
/* Centralized ARM↔Native window class attribute bridge.

   WinCE ARM code sees one set of class attributes; native Windows sees another.
   This module is the SINGLE source of truth for all translations:
   - WndProc: ARM address ↔ EmuWndProc
   - Style: WinCE style ↔ native (CS_OWNDC added, WS_POPUP for top-level)
   - Brush: WinCE COLOR_STATIC(26)/COLOR_STATICTEXT(27) ↔ desktop equivalents
   - Cursor/Icon: original ARM values preserved (native gets defaults)

   ALL class manipulation code (RegisterClassW, CreateWindowExW, Get/SetWindowLongW,
   Get/SetClassLongW, CreateDialog, GetClassInfoW) MUST go through this module. */

#include <windows.h>
#include <cstdint>
#include <string>
#include <map>

/* WinCE GCL_* index constants.  Desktop Windows deprecates these on 64-bit
   (replaced by GCLP_*), but WinCE ARM code still uses the 32-bit indices. */
constexpr int WINCE_GCL_WNDPROC       = -24;
constexpr int WINCE_GCL_STYLE         = -26;
constexpr int WINCE_GCL_CBWNDEXTRA    = -18;
constexpr int WINCE_GCL_CBCLSEXTRA    = -20;
constexpr int WINCE_GCL_HICON         = -14;
constexpr int WINCE_GCL_HCURSOR       = -12;
constexpr int WINCE_GCL_HBRBACKGROUND = -10;
constexpr int WINCE_GCL_MENUNAME      = -8;

/* WinCE-only COLOR_* constants (not present in desktop Windows headers) */
constexpr uint32_t WINCE_COLOR_STATIC     = 26;
constexpr uint32_t WINCE_COLOR_STATICTEXT = 27;

/* Per-class ARM state: what RegisterClassW received from ARM code */
struct ArmClassInfo {
    uint32_t arm_wndproc = 0;       /* original ARM WndProc address */
    uint32_t arm_style = 0;         /* original WinCE class style (before CS_OWNDC) */
    uint32_t arm_brush = 0;         /* original brush value (COLOR_xxx+1 or GDI handle) */
    uint32_t arm_cursor = 0;        /* original cursor handle */
    uint32_t arm_icon = 0;          /* original icon handle */
};

/* Per-HWND ARM state: what CreateWindowExW received */
struct ArmWindowInfo {
    uint32_t arm_wndproc = 0;       /* per-window ARM WndProc (may differ from class) */
    uint32_t wce_style = 0;         /* original WinCE window style */
    uint32_t wce_exstyle = 0;       /* original WinCE extended style */
    WNDPROC  saved_native_proc = nullptr; /* saved native proc for subclassing */
};

class ClassBridge {
public:
    /* --- Class registration --- */

    /* Store ARM class info during RegisterClassW. Called BEFORE native registration. */
    void RegisterClass(const std::wstring& className, const ArmClassInfo& info);

    /* Look up ARM class info by name. Returns nullptr if not found. */
    const ArmClassInfo* GetClassInfo(const std::wstring& className) const;

    /* Look up ARM class info by HWND (resolves class name internally). */
    const ArmClassInfo* GetClassInfoForHwnd(HWND hwnd) const;

    /* --- Per-window state --- */

    /* Store per-window ARM state during CreateWindowExW. */
    void SetWindowInfo(HWND hwnd, const ArmWindowInfo& info);

    /* Get per-window ARM state. Returns nullptr if not found. */
    ArmWindowInfo* GetWindowInfo(HWND hwnd);
    const ArmWindowInfo* GetWindowInfo(HWND hwnd) const;

    /* Remove window state on WM_NCDESTROY. */
    void RemoveWindow(HWND hwnd);

    /* --- Attribute translation: ARM → Native --- */

    /* Translate a WinCE brush value for native RegisterClassW/SetClassLongW.
       Handles COLOR_STATIC(26)→COLOR_3DFACE, COLOR_STATICTEXT(27)→COLOR_WINDOWTEXT,
       and sign-extension of 32-bit GDI handles. */
    static HBRUSH TranslateBrushToNative(uint32_t arm_brush);

    /* Translate a WinCE class style for native RegisterClassW.
       Adds CS_OWNDC (WinCE persistent DC behavior). */
    static UINT TranslateStyleToNative(uint32_t arm_style);

    /* --- Attribute translation: Native → ARM --- */

    /* Get the ARM WndProc for a window. Checks per-window first, then per-class. */
    uint32_t GetArmWndProc(HWND hwnd) const;

    /* Get the ARM class style for a window (without CS_OWNDC). */
    uint32_t GetArmClassStyle(HWND hwnd) const;

    /* Get the original ARM brush value for a window's class. */
    uint32_t GetArmBrush(HWND hwnd) const;

private:
    /* Per-class state, keyed by lowercase class name */
    std::map<std::wstring, ArmClassInfo> class_map_;

    /* Per-window state, keyed by HWND */
    std::map<HWND, ArmWindowInfo> window_map_;

    static std::wstring NormalizeName(const std::wstring& name);
};
