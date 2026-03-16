#!/usr/bin/env python3
"""Kill cerf, start fresh explorer, open IE, navigate to URL.
Usage: python3 tools/open_ie.py [url]
Default: http://google.com
"""
import subprocess, time, sys, os, re, ctypes

URL = sys.argv[1] if len(sys.argv) > 1 else "http://google.com"
LOG = "Z:/tmp/ie_log.txt"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/build/Release/x64/devices/wince5/fs/Windows/explorer.exe"
REG = "Z:/build/Release/x64/devices/wince5/registry.reg"

def interact(*args):
    subprocess.run(["python3", "Z:/tools/interact.py"] + list(args),
                   capture_output=True, text=True)

def find_ie_hwnd():
    r = subprocess.run(["python3", "Z:/tools/interact.py", "windows"],
                       capture_output=True, text=True)
    lines = r.stdout.splitlines()
    for i, line in enumerate(lines):
        if "Explore" in line and "DesktopExplorer" not in line and "[V]" in line:
            for j in range(i, min(i + 3, len(lines))):
                m = re.search(r'hwnd=(0x[0-9a-fA-F]+)', lines[j])
                if m:
                    return m.group(1)
    return None

def press_key(vk):
    ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
    ctypes.windll.user32.keybd_event(vk, 0, 2, 0)

# 1. Kill cerf
print("[1] Killing cerf...")
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# 2. Delete stale registry
if os.path.exists(REG):
    os.remove(REG)
    print("    Deleted stale registry.reg")

# 3. Start cerf + explorer
print("[2] Starting cerf + explorer.exe...")
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen([CERF, "--flush-outputs", EXPLORER],
                        stdout=log_f, stderr=log_f, cwd="Z:/")
print(f"    PID={proc.pid}")
time.sleep(4)

# 4. Open IE
print("[3] Opening IE...")
interact("dclick", "35", "333")
time.sleep(7)

hwnd = find_ie_hwnd()
if not hwnd:
    print("ERROR: IE did not open!")
    sys.exit(1)
print(f"    IE hwnd={hwnd}")

# 5. Navigate
interact("focus", hwnd)
time.sleep(0.3)
print(f"[4] Navigating to {URL}")
interact("click", "300", "37")
time.sleep(0.3)

# Clear address bar: End + 20 rapid Backspaces via ctypes
VK_END, VK_BACK = 0x23, 0x08
press_key(VK_END)
time.sleep(0.05)
for _ in range(20):
    press_key(VK_BACK)

# Type URL and press Enter
interact("type", URL)
time.sleep(0.05)
interact("key", "enter")

print(f"[5] Navigated. Waiting 15s...")
time.sleep(15)
if proc.poll() is None:
    print(f"[OK] cerf.exe still running (PID={proc.pid}). Log: {LOG}")
else:
    print(f"[CRASH] cerf.exe exited with code {proc.returncode}. Log: {LOG}")
