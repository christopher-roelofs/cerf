#pragma once
#include <windows.h>
#include <string>
#include <mutex>

/* Windows 2000-style boot splash shown during CERF initialization.
   Runs on a dedicated thread with its own message pump so the main
   thread can block freely during driver loading / init sequence. */
struct BootScreen {
    HWND hwnd = nullptr;
    HWND progress_hwnd = nullptr;   /* native progress bar control */
    HANDLE thread = nullptr;
    HANDLE ready_event = nullptr;   /* signaled when window is created */
    HICON icon = nullptr;
    HFONT font = nullptr;

    std::mutex mu;
    std::string status_text;
    int progress_current = 0;
    int progress_total = 1;
    int width = 800;
    int height = 480;

    void Create(int w, int h);          /* spawn thread, block until ready */
    void SetTotal(int total);            /* thread-safe */
    void Step(const char* text);         /* increment + set status */
    void OnShellReady();                 /* called from SignalStarted thunk */
    void ScheduleDestroy(int ms);        /* fallback timer for --no-init */
    void Destroy();                      /* join thread, clean up */

    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
};
