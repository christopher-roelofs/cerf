/* Debug logging helpers for EmuWndProc — split from callbacks.cpp.
   These functions log key messages for debugging the ARM/native dispatch. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"

/* Consolidated pre-dispatch logging for EmuWndProc */
void EmuWndProc_LogMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                             uint32_t arm_wndproc, EmulatedMemory& emem) {
    if (msg == WM_PAINT || msg == WM_ERASEBKGND) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls'\n",
            msg, msg == WM_PAINT ? "WM_PAINT" : "WM_ERASEBKGND", hwnd, cls);
    }
    if (msg == WM_CREATE || msg == WM_NCCREATE) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X (%s) hwnd=0x%p class='%ls' arm_wndproc=0x%08X lP=0x%X\n",
            msg, msg == WM_CREATE ? "WM_CREATE" : "WM_NCCREATE", hwnd, cls, arm_wndproc, (uint32_t)lParam);
    }
    if (msg == WM_CLOSE || msg == WM_SYSCOMMAND || msg == WM_DESTROY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc CLOSE-PATH: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_CHAR || msg == WM_KEYDOWN || msg == WM_SETTEXT ||
        msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_CAPTURECHANGED ||
        msg == WM_SETFOCUS || msg == WM_KILLFOCUS ||
        msg == WM_INITMENUPOPUP || msg == WM_MENUSELECT) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        LOG(API, "[API] EmuWndProc: msg=0x%04X hwnd=0x%p class='%ls' wP=0x%X lP=0x%X\n",
            msg, hwnd, cls, (uint32_t)wParam, (uint32_t)lParam);
    }
    if (msg == WM_NOTIFY) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        int32_t nmCode = 0;
        uint32_t lp32 = (uint32_t)lParam;
        if (lp32 && emem.IsValid(lp32 + 8))
            nmCode = (int32_t)emem.Read32(lp32 + 8);
        LOG(API, "[API] EmuWndProc WM_NOTIFY: hwnd=0x%p class='%ls' code=%d lP=0x%X\n",
            hwnd, cls, nmCode, lp32);
    }

    /* Log mshtml deferred method call message (0x8002) for debugging */
    constexpr UINT MSHTML_METHOD_CALL_MSG = 0x8002;
    if (msg == MSHTML_METHOD_CALL_MSG) {
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 64);
        /* Read TLS slot 12 (THREADSTATE) to check paryCalls */
        uint32_t threadstate = emem.Read32(0xFFFFC000 + 12 * 4);
        uint32_t pary = threadstate ? emem.Read32(threadstate + 32) : 0;
        uint32_t posted = threadstate ? emem.Read32(threadstate + 28) : 0;
        uint32_t ary_size = 0;
        if (pary) {
            /* CImplAry layout: +0=count, +4=capacity, +8=data_ptr */
            ary_size = emem.Read32(pary);
        }
        LOG(API, "[API] EmuWndProc 0x8002: hwnd=0x%p class='%ls' THREADSTATE=0x%08X paryCalls=0x%08X(size=%u) posted=%u\n",
            hwnd, cls, threadstate, pary, ary_size, posted);
    }
}

/* Consolidated post-dispatch logging */
void EmuWndProc_LogPostDispatch(HWND hwnd, UINT msg, uint32_t result, EmulatedMemory& emem) {
    constexpr UINT MSHTML_METHOD_CALL_MSG = 0x8002;
    if (msg == MSHTML_METHOD_CALL_MSG) {
        /* Check state AFTER the ARM code processed 0x8002 */
        uint32_t threadstate = emem.Read32(0xFFFFC000 + 12 * 4);
        uint32_t pary = threadstate ? emem.Read32(threadstate + 32) : 0;
        uint32_t ary_size = pary ? emem.Read32(pary) : 0;
        LOG(API, "[API] EmuWndProc 0x8002 AFTER: paryCalls size=%u result=0x%X\n",
            ary_size, result);
    }

    if (msg == WM_NOTIFY) {
        LOG(API, "[API] EmuWndProc WM_NOTIFY result=%u (0x%X)\n", result, result);
    }
}

/* WM_NCCALCSIZE handler: compute WinCE non-client area for captioned windows.
   Since we create top-level WinCE windows as WS_POPUP (no native frame),
   we must manually define the NC area to match WinCE metrics (1px border + caption).
   Returns true if handled (caller should return `out`), false to fall through. */
bool EmuWndProc_HandleNcCalcSize(HWND hwnd, WPARAM wParam, LPARAM lParam, LRESULT& out) {
    auto sit = Win32Thunks::hwnd_wce_style_map.find(hwnd);
    if (sit == Win32Thunks::hwnd_wce_style_map.end())
        return false;
    uint32_t ws = sit->second;
    bool has_caption = (ws & WS_CAPTION) == WS_CAPTION;
    bool has_border = (ws & WS_BORDER) != 0;
    if (!has_caption && !has_border)
        return false;
    int border = 1;
    int caption = has_caption ? GetSystemMetrics(SM_CYCAPTION) : 0;
    if (wParam) {
        NCCALCSIZE_PARAMS* ncp = (NCCALCSIZE_PARAMS*)lParam;
        ncp->rgrc[0].left += border;
        ncp->rgrc[0].top += border + caption;
        ncp->rgrc[0].right -= border;
        ncp->rgrc[0].bottom -= border;
    } else {
        RECT* rc = (RECT*)lParam;
        rc->left += border;
        rc->top += border + caption;
        rc->right -= border;
        rc->bottom -= border;
    }
    out = 0;
    return true;
}
