"""IDAPython startup script: wait for auto-analysis, save DB, start ida_server.
Used by open_ida.py with IDA's -A (autonomous) flag for unattended opening."""

import ctypes
import os
import ida_auto
import ida_loader
import idaapi

# Wait for auto-analysis to finish
ida_auto.auto_wait()

# Save database immediately (protect against crashes)
idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
if idb_path:
    ida_loader.save_database(idb_path, 0)

# Minimize IDA window — we only need the server
# Find this process's own window by PID, not GetForegroundWindow
import ctypes.wintypes as wt
_pid = os.getpid()
_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
def _minimize_own_windows(hwnd, _):
    pid = wt.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == _pid and ctypes.windll.user32.IsWindowVisible(hwnd):
        ctypes.windll.user32.ShowWindow(hwnd, 6)  # SW_MINIMIZE
    return True
ctypes.windll.user32.EnumWindows(_WNDENUMPROC(_minimize_own_windows), 0)

# Now start the HTTP API server
server_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ida_server.py")
with open(server_script) as f:
    exec(compile(f.read(), server_script, "exec"))
