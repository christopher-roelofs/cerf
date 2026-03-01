"""Inspect running cerf.exe process: check if alive, list all windows with titles/classes/visibility."""
import ctypes
import ctypes.wintypes as wt
import sys

u32 = ctypes.windll.user32
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

EnumWindows = u32.EnumWindows
EnumChildWindows = u32.EnumChildWindows
GetWindowThreadProcessId = u32.GetWindowThreadProcessId
GetWindowTextW = u32.GetWindowTextW
GetWindowTextLengthW = u32.GetWindowTextLengthW
GetClassNameW = u32.GetClassNameW
IsWindowVisible = u32.IsWindowVisible
GetWindowRect = u32.GetWindowRect
IsWindowEnabled = u32.IsWindowEnabled

WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

def find_cerf_pids():
    """Find all cerf.exe process IDs."""
    import subprocess
    result = subprocess.run(
        ['tasklist', '/fi', 'imagename eq cerf.exe', '/fo', 'csv', '/nh'],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if not line or 'No tasks' in line or 'INFO' in line:
            continue
        parts = line.split(',')
        if len(parts) >= 2:
            pid_str = parts[1].strip('"')
            try:
                pids.append(int(pid_str))
            except ValueError:
                pass
    return pids

def get_windows_for_pid(pid):
    """Enumerate all top-level windows belonging to a process."""
    windows = []

    def enum_cb(hwnd, _):
        wp = wt.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
        if wp.value == pid:
            title_len = GetWindowTextLengthW(hwnd)
            title_buf = ctypes.create_unicode_buffer(title_len + 1)
            GetWindowTextW(hwnd, title_buf, title_len + 1)

            cls_buf = ctypes.create_unicode_buffer(256)
            GetClassNameW(hwnd, cls_buf, 256)

            rect = wt.RECT()
            GetWindowRect(hwnd, ctypes.byref(rect))

            visible = bool(IsWindowVisible(hwnd))
            enabled = bool(IsWindowEnabled(hwnd))

            windows.append({
                'hwnd': hwnd,
                'title': title_buf.value,
                'class': cls_buf.value,
                'visible': visible,
                'enabled': enabled,
                'rect': (rect.left, rect.top, rect.right, rect.bottom),
                'size': (rect.right - rect.left, rect.bottom - rect.top),
            })
        return True

    EnumWindows(WNDENUMPROC(enum_cb), 0)
    return windows

def main():
    pids = find_cerf_pids()
    if not pids:
        print("STATUS: cerf.exe is NOT running")
        return 1

    for pid in pids:
        print(f"STATUS: cerf.exe running (PID={pid})")
        windows = get_windows_for_pid(pid)
        if not windows:
            print("  No windows found")
            continue

        visible_count = sum(1 for w in windows if w['visible'])
        print(f"  Windows: {len(windows)} total, {visible_count} visible\n")

        for w in windows:
            vis = "VISIBLE" if w['visible'] else "hidden"
            ena = "" if w['enabled'] else " DISABLED"
            title = w['title'] if w['title'] else "(no title)"
            x, y = w['rect'][0], w['rect'][1]
            sw, sh = w['size']
            print(f"  [{vis}{ena}] hwnd=0x{w['hwnd']:08X} class='{w['class']}' title='{title}' pos=({x},{y}) size={sw}x{sh}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
