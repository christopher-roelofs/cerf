"""run_env.py -- Launch IDA dev environment with crash recovery loop."""

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent  # Z:\

IDA_EXE = Path(r"C:\Program Files\IDA Professional 9.0\ida.exe")
IDA_SCRIPT = PROJECT_DIR / "tools" / "ida_server.py"
REGISTRY_DIR = Path.home() / ".ida-mcp" / "instances"

u32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

try:
    u32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass


def fail(msg: str):
    print(f"\n  ERROR: {msg}\n")
    input("Press Enter to exit...")
    sys.exit(1)


def find_ida_pids():
    pids = {}
    for name in ["ida.exe", "ida64.exe"]:
        result = subprocess.run(
            ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
            capture_output=True, text=True,
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line or "No tasks" in line or "INFO" in line:
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    pids[int(parts[1].strip('"'))] = name
                except ValueError:
                    pass
    return pids


def has_crash_dialogs():
    """Check if any IDA 'Please confirm' crash recovery dialogs exist."""
    pids = find_ida_pids()
    if not pids:
        return False
    found = []

    def enum_cb(hwnd, _lparam):
        pid = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids and u32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(512)
            u32.GetWindowTextW(hwnd, buf, 512)
            if buf.value and "Please confirm" in buf.value:
                found.append(hwnd)
        return True

    u32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    return len(found) > 0


def minimize_ida_windows():
    print("[ida] Minimizing IDA windows...")
    SW_MINIMIZE = 6

    def enum_cb(hwnd, _lparam):
        if u32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(512)
            u32.GetWindowTextW(hwnd, buf, 512)
            title = buf.value
            if title and ("IDA" in title or "idaq" in title.lower()):
                print(f"[ida] Minimizing: {title}")
                u32.ShowWindow(hwnd, SW_MINIMIZE)
        return True

    u32.EnumWindows(WNDENUMPROC(enum_cb), 0)


def launch_all_idas():
    """Clean stale registrations, launch all .i64 files with IDA."""
    if not IDA_EXE.exists():
        fail(f"IDA not found at: {IDA_EXE}")

    # Clean stale registry JSON files
    if REGISTRY_DIR.is_dir():
        for f in REGISTRY_DIR.glob("*.json"):
            print(f"[cleanup] Removing stale registry: {f.name}")
            f.unlink(missing_ok=True)

    # Open all .i64 files
    i64_files = list(PROJECT_DIR.glob("**/*.i64"))
    if not i64_files:
        print("[ida] WARNING: No .i64 files found under", PROJECT_DIR)
    for f in i64_files:
        print(f"[ida] Launching: {f}")
        subprocess.Popen([str(IDA_EXE), f"-S{IDA_SCRIPT}", str(f)])


def run_script(name):
    """Run a sibling script and return its exit code."""
    script = SCRIPT_DIR / name
    print(f"\n[run] Running {name}...")
    result = subprocess.run([sys.executable, str(script)])
    print(f"[run] {name} exited with code {result.returncode}")
    return result.returncode


def main():
    print("=" * 60)
    print("[run_env] Starting IDA environment...")
    print("=" * 60)

    # 1. Launch all IDAs
    launch_all_idas()

    # 2. Wait for them to start up
    print(f"\n[wait] Waiting 25 seconds for IDA startup...")
    time.sleep(25)

    # 3. Check for crash recovery dialogs
    print("[check] Looking for crash recovery dialogs...")
    if has_crash_dialogs():
        print("[check] Crash dialog(s) detected! Running recovery cycle...")

        # 3a. Fix crash dialogs (dismiss "Please confirm" / restore packed base)
        run_script("fix_ida_crash.py")

        # 3b. Exit all IDAs cleanly (save + pack)
        run_script("exit_ida.py")

        # 3c. Restart from the beginning
        print("\n[restart] Restarting environment...\n")
        os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve())])
        # execv does not return

    # 4. No crashes -- minimize and open cmd
    print("[check] No crash dialogs. Environment is clean.")
    minimize_ida_windows()

    print("\n[cmd] Opening command prompt at Z:\\")
    subprocess.Popen(["cmd", "/k", "cd /d Z:\\"], creationflags=subprocess.CREATE_NEW_CONSOLE)

    print("\n[done] Environment ready.")


if __name__ == "__main__":
    main()
