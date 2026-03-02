"""Inspect running cerf.exe process: check if alive, list all windows with
titles/classes/visibility, and show full child window tree with positions."""
import ctypes
import ctypes.wintypes as wt
import sys

# Make this process per-monitor DPI-aware so we get physical pixel coordinates
# matching what DPI-aware processes like cerf.exe see.
try:
    ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
    except Exception:
        pass

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
GetClientRect = u32.GetClientRect
IsWindowEnabled = u32.IsWindowEnabled
GetParent = u32.GetParent
ScreenToClient = u32.ScreenToClient

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

def get_window_info(hwnd):
    """Get detailed info about a window."""
    title_buf = ctypes.create_unicode_buffer(256)
    GetWindowTextW(hwnd, title_buf, 256)
    cls_buf = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, cls_buf, 256)
    rect = wt.RECT()
    GetWindowRect(hwnd, ctypes.byref(rect))
    crect = wt.RECT()
    GetClientRect(hwnd, ctypes.byref(crect))
    style = u32.GetWindowLongW(hwnd, -16)   # GWL_STYLE
    exstyle = u32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
    visible = bool(style & 0x10000000)       # WS_VISIBLE
    enabled = not bool(style & 0x08000000)   # WS_DISABLED
    parent = GetParent(hwnd)

    # Get position relative to parent
    rel_x, rel_y = rect.left, rect.top
    if parent:
        pt = (ctypes.c_long * 2)(rect.left, rect.top)
        ScreenToClient(parent, pt)
        rel_x, rel_y = pt[0], pt[1]

    return {
        'hwnd': hwnd,
        'title': title_buf.value,
        'class': cls_buf.value,
        'visible': visible,
        'enabled': enabled,
        'rect': (rect.left, rect.top, rect.right, rect.bottom),
        'size': (rect.right - rect.left, rect.bottom - rect.top),
        'client': (crect.right, crect.bottom),
        'rel_pos': (rel_x, rel_y),
        'style': style,
        'exstyle': exstyle,
        'parent': parent,
    }

def get_windows_for_pid(pid):
    """Enumerate all top-level windows belonging to a process."""
    windows = []
    def enum_cb(hwnd, _):
        wp = wt.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
        if wp.value == pid:
            windows.append(get_window_info(hwnd))
        return True
    EnumWindows(WNDENUMPROC(enum_cb), 0)
    return windows

def get_direct_children(parent_hwnd):
    """Get only direct children of a window (not grandchildren)."""
    all_children = []
    def enum_cb(hwnd, _):
        all_children.append(hwnd)
        return True
    EnumChildWindows(parent_hwnd, WNDENUMPROC(enum_cb), 0)
    # Filter to direct children only
    return [h for h in all_children if GetParent(h) == parent_hwnd]

def print_window_tree(hwnd, indent=0):
    """Recursively print a window and its children."""
    info = get_window_info(hwnd)
    vis = 'V' if info['visible'] else 'H'
    ena = '' if info['enabled'] else ' DIS'
    title = f' "{info["title"]}"' if info['title'] else ''
    w, h = info['size']
    cx, cy = info['client']
    rx, ry = info['rel_pos']

    prefix = '  ' * indent
    style_flags = []
    s = info['style']
    if s & 0x40000000: style_flags.append('CHILD')
    if s & 0x80000000: style_flags.append('POPUP')
    if s & 0x00800000: style_flags.append('BORDER')
    if s & 0x00400000: style_flags.append('DLGFRAME')
    if s & 0x00C00000 == 0x00C00000: style_flags = [f for f in style_flags if f not in ('BORDER','DLGFRAME')]; style_flags.append('CAPTION')
    style_str = '|'.join(style_flags) if style_flags else ''

    print(f'{prefix}[{vis}{ena}] {info["class"]:<24}{title}')
    print(f'{prefix}      pos=({rx},{ry}) size={w}x{h} client={cx}x{cy} style=0x{info["style"]:08X} {style_str}')

    # Recurse into children
    children = get_direct_children(hwnd)
    for child in children:
        print_window_tree(child, indent + 1)

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
            if not w['visible']:
                vis = 'hidden'
                ena = '' if w['enabled'] else ' DISABLED'
                print(f"  [{vis}{ena}] hwnd=0x{w['hwnd']:08X} class='{w['class']}' size={w['size'][0]}x{w['size'][1]}")
                continue
            # For visible top-level windows, show full tree
            print(f"  --- Window Tree ---")
            print_window_tree(w['hwnd'], indent=1)
            print()

    return 0

if __name__ == '__main__':
    sys.exit(main())
