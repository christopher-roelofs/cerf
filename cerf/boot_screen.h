#pragma once
#include <windows.h>
#include <string>
#include <mutex>

/* Boot splash shown during CERF initialization.
   Runs on a dedicated thread with its own message pump.
   Step/OnShellReady are thread-safe (use PostMessage).
   Progress bar is indeterminate (animated marquee). */
struct BootScreen {
    HWND hwnd = nullptr;
    HANDLE thread = nullptr;
    HANDLE ready_event = nullptr;
    HICON icon = nullptr;
    HFONT font = nullptr;

    std::mutex mu;
    std::string status_text;
    int marquee_pos = 0;
    int width = 800;
    int height = 480;

    void Create(int w, int h);
    void Step(const char* text);
    void OnShellReady();
    void ScheduleDestroy(int ms);
    void Destroy();

    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
};
