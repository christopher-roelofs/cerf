#include "boot_screen.h"
#include <commctrl.h>

#define BS_UPDATE        (WM_USER + 1)
#define BS_DESTROY       (WM_USER + 2)
#define BS_SCHEDULE      (WM_USER + 3)
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

        HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(hdc, &rc, black);
        DeleteObject(black);

        int draw_size = 128;
        int icon_x = (w - draw_size) / 2;
        int icon_y = (h - draw_size) / 2;
        if (bs->icon)
            DrawIconEx(hdc, icon_x, icon_y, bs->icon,
                       draw_size, draw_size, 0, NULL, DI_NORMAL);

        std::string text;
        { std::lock_guard<std::mutex> lock(bs->mu); text = bs->status_text; }
        if (!text.empty()) {
            int bar_y = icon_y + draw_size + 35;
            int bar_h = 15;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));
            HFONT old = (HFONT)SelectObject(hdc, bs->font);
            RECT text_rc = { 0, bar_y + bar_h + 10, w, bar_y + bar_h + 38 };
            std::wstring wtext(text.begin(), text.end());
            DrawTextW(hdc, wtext.c_str(), -1, &text_rc,
                      DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(hdc, old);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    if (msg == BS_UPDATE) {
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

    /* Activate comctl32 v6 for this thread — PBS_MARQUEE requires visual styles */
    ACTCTXW actx = { sizeof(actx) };
    actx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
    actx.hModule = GetModuleHandle(NULL);
    actx.lpResourceName = MAKEINTRESOURCEW(2); /* try resource ID 2 first */
    HANDLE hActCtx = CreateActCtxW(&actx);
    if (hActCtx == INVALID_HANDLE_VALUE) {
        /* No manifest in exe — create one inline */
        static const char manifest[] =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
            "<dependency><dependentAssembly>"
            "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" "
            "version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\"/>"
            "</dependentAssembly></dependency></assembly>";
        /* Write temp manifest file */
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        strcat_s(tmp, "cerf_cc6.manifest");
        FILE* mf = fopen(tmp, "w");
        if (mf) { fputs(manifest, mf); fclose(mf); }
        ACTCTXA actxa = { sizeof(actxa) };
        actxa.lpSource = tmp;
        hActCtx = CreateActCtxA(&actxa);
    }
    ULONG_PTR cookie = 0;
    if (hActCtx != INVALID_HANDLE_VALUE)
        ActivateActCtx(hActCtx, &cookie);

    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = BootScreen::WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"CerfBootScreen";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    bs->hwnd = CreateWindowExW(0, L"CerfBootScreen", L"CERF",
        WS_POPUP | WS_VISIBLE, 0, 0, bs->width, bs->height,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    bs->icon = (HICON)LoadImageW(GetModuleHandle(NULL),
        MAKEINTRESOURCEW(1), IMAGE_ICON, 256, 256, 0);
    bs->font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    /* Native marquee progress bar */
    int draw_size = 128;
    int icon_y = (bs->height - draw_size) / 2;
    int bar_w = 180, bar_h = 15;
    int bar_x = (bs->width - bar_w) / 2;
    int bar_y = icon_y + draw_size + 35;
    bs->progress_hwnd = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
        WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
        bar_x, bar_y, bar_w, bar_h,
        bs->hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(bs->progress_hwnd, PBM_SETMARQUEE, TRUE, 30);

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

void BootScreen::Step(const char* text) {
    if (text) {
        std::lock_guard<std::mutex> lock(mu);
        status_text = text;
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
