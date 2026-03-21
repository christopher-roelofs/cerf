#include "boot_screen.h"
#include <commctrl.h>
#include <cstdio>

#pragma comment(lib, "comctl32.lib")

#define BS_UPDATE        (WM_USER + 1)
#define BS_DESTROY       (WM_USER + 2)
#define BS_SCHEDULE      (WM_USER + 3)  /* WPARAM = timeout ms */
#define BS_TIMER_FALLBACK 1

static BootScreen* s_boot = nullptr;

LRESULT CALLBACK BootScreen::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        BootScreen* bs = s_boot;
        if (!bs) { EndPaint(hwnd, &ps); return 0; }

        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right, h = rc.bottom;

        /* Black background */
        HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(hdc, &rc, black);
        DeleteObject(black);

        /* Icon at exact center of screen */
        int draw_size = 128;
        int icon_x = (w - draw_size) / 2;
        int icon_y = (h - draw_size) / 2;
        if (bs->icon)
            DrawIconEx(hdc, icon_x, icon_y, bs->icon,
                       draw_size, draw_size, 0, NULL, DI_NORMAL);

        /* Status text: below progress bar (progress bar positioned in BS_UPDATE) */
        std::string text;
        {
            std::lock_guard<std::mutex> lock(bs->mu);
            text = bs->status_text;
        }
        if (!text.empty()) {
            int bar_bottom = icon_y + draw_size + 35 + 15; /* bar_y + bar_h */
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));
            HFONT old = (HFONT)SelectObject(hdc, bs->font);
            RECT text_rc = { 0, bar_bottom + 10, w, bar_bottom + 38 };
            std::wstring wtext(text.begin(), text.end());
            DrawTextW(hdc, wtext.c_str(), -1, &text_rc,
                      DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(hdc, old);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    if (msg == BS_UPDATE) {
        BootScreen* bs = s_boot;
        if (bs) {
            /* Update native progress bar */
            int cur, total;
            {
                std::lock_guard<std::mutex> lock(bs->mu);
                cur = bs->progress_current;
                total = bs->progress_total;
            }
            if (bs->progress_hwnd) {
                SendMessage(bs->progress_hwnd, PBM_SETRANGE32, 0, total);
                SendMessage(bs->progress_hwnd, PBM_SETPOS, cur, 0);
            }
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    if (msg == BS_DESTROY) {
        KillTimer(hwnd, BS_TIMER_FALLBACK);
        PostQuitMessage(0);
        return 0;
    }

    if (msg == BS_SCHEDULE) {
        SetTimer(hwnd, BS_TIMER_FALLBACK, (UINT)wp, NULL);
        return 0;
    }

    if (msg == WM_TIMER && wp == BS_TIMER_FALLBACK) {
        KillTimer(hwnd, BS_TIMER_FALLBACK);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wp, lp);
}

static DWORD WINAPI BootScreenThread(LPVOID param) {
    BootScreen* bs = (BootScreen*)param;
    s_boot = bs;

    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = BootScreen::WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"CerfBootScreen";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    /* Position at top-left (0,0) — same as cerf WinCE windows */
    bs->hwnd = CreateWindowExW(WS_EX_APPWINDOW, L"CerfBootScreen", L"CERF",
        WS_POPUP | WS_VISIBLE, 0, 0, bs->width, bs->height,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    /* Load 256x256 32bpp icon (true alpha channel) — DrawIconEx scales to 64x64.
       The 4bpp variants have white in their transparent areas which shows on black. */
    bs->icon = (HICON)LoadImageW(GetModuleHandle(NULL),
        MAKEINTRESOURCEW(1), IMAGE_ICON, 256, 256, 0);

    bs->font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    /* Create native progress bar control — below centered icon */
    int draw_size = 128;
    int icon_y = (bs->height - draw_size) / 2;
    int bar_w = 180;
    int bar_h = 15;
    int bar_x = (bs->width - bar_w) / 2;
    int bar_y = icon_y + draw_size + 35;
    bs->progress_hwnd = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
        WS_CHILD | WS_VISIBLE, bar_x, bar_y, bar_w, bar_h,
        bs->hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(bs->progress_hwnd, PBM_SETRANGE32, 0, 1);
    SendMessage(bs->progress_hwnd, PBM_SETPOS, 0, 0);

    SetEvent(bs->ready_event);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (bs->progress_hwnd) DestroyWindow(bs->progress_hwnd);
    DestroyWindow(bs->hwnd);
    bs->hwnd = nullptr;
    bs->progress_hwnd = nullptr;
    if (bs->icon) { DestroyIcon(bs->icon); bs->icon = nullptr; }
    /* font is stock object — don't delete */
    s_boot = nullptr;
    return 0;
}

void BootScreen::Create(int w, int h) {
    width = w;
    height = h;
    ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    thread = ::CreateThread(NULL, 0, BootScreenThread, this, 0, NULL);
    WaitForSingleObject(ready_event, 5000);
    CloseHandle(ready_event);
    ready_event = nullptr;
}

void BootScreen::SetTotal(int total) {
    std::lock_guard<std::mutex> lock(mu);
    progress_total = total > 0 ? total : 1;
    if (hwnd) PostMessage(hwnd, BS_UPDATE, 0, 0);
}

void BootScreen::Step(const char* text) {
    {
        std::lock_guard<std::mutex> lock(mu);
        progress_current++;
        if (text) status_text = text;
    }
    if (hwnd) PostMessage(hwnd, BS_UPDATE, 0, 0);
}

void BootScreen::OnShellReady() {
    if (hwnd) PostMessage(hwnd, BS_DESTROY, 0, 0);
}

void BootScreen::ScheduleDestroy(int ms) {
    if (hwnd) PostMessage(hwnd, BS_SCHEDULE, (WPARAM)ms, 0);
}

void BootScreen::Destroy() {
    if (hwnd) PostMessage(hwnd, BS_DESTROY, 0, 0);
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        thread = nullptr;
    }
}
