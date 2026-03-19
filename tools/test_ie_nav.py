#!/usr/bin/env python3
"""Test IE navigation: open IE, then navigate to test.htm via address bar."""
import subprocess, time, sys, os, ctypes, re

LOG = "Z:/tmp/ie_nav_test.log"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/references/wce5_sysgen_armv4/explorer.exe"

def interact(*a):
    return subprocess.run(["python3", "Z:/tools/interact.py"] + list(a),
                          capture_output=True, text=True)

def press_key(vk):
    ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
    time.sleep(0.02)
    ctypes.windll.user32.keybd_event(vk, 0, 2, 0)
    time.sleep(0.02)

def shot(label=""):
    interact("screenshot")
    if label: print(f"  [{label}] Screenshot saved")

# 1. Kill old
print("[1] Killing cerf...")
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# 2. Start fresh
print("[2] Starting cerf + explorer...")
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,EMU,TRACE", EXPLORER],
    stdout=log_f, stderr=log_f, cwd="Z:/")
print(f"    PID={proc.pid}")
time.sleep(8)

# 3. Open IE
print("[3] Opening IE...")
interact("dclick", "35", "333")  # IE icon - verify from screenshot
time.sleep(25)
shot("after IE open")

# 4. Verify IE rendered
r = interact("windows")
ie_found = False
for line in r.stdout.splitlines():
    if "[V] Explore" in line and "Desktop" not in line:
        ie_found = True
        print(f"    OK: {line.strip()}")
if not ie_found:
    print("    FAIL: IE window not found!")
    sys.exit(1)

# 5. Navigate via address bar
URL = "file:///windows/test.htm"
print(f"[4] Navigating to {URL}...")
interact("click", "400", "38")
time.sleep(0.5)

# Clear address bar: End then Backspace x80
VK_END, VK_BACK = 0x23, 0x08
press_key(VK_END)
time.sleep(0.1)
for _ in range(80):
    press_key(VK_BACK)
time.sleep(0.3)

# Type URL
interact("type", URL)
time.sleep(0.3)

# Press Enter
interact("key", "enter")
print("    Enter pressed. Waiting 15s...")
time.sleep(15)
shot("after navigation")

# 6. Check if page changed
print("[5] Checking log for navigation activity...")
nav_count = 0
render_count = 0
with open(LOG) as f:
    for line in open(LOG, encoding="utf-8", errors="replace"):
        if "test.htm" in line and ("CreateFile" in line or "ReadFile" in line):
            if nav_count < 3:
                print(f"    NAV: {line.rstrip()[:120]}")
            nav_count += 1
        if "TRACE" in line and ("Tokenize" in line or "InitializeParser" in line or "ParseContent" in line):
            if render_count < 3:
                print(f"    RENDER: {line.rstrip()[:120]}")
            render_count += 1

if nav_count > 0:
    print(f"    Total nav activity for test.htm: {nav_count} lines")
else:
    print("    NO navigation activity for test.htm!")

# 7. Check address bar content
print("[6] Checking address bar...")
with open(LOG) as f:
    for line in open(LOG, encoding="utf-8", errors="replace"):
        if "SelChange" in line or "SetCurrentLocation" in line or "UpdateUrlList" in line:
            if "TRACE" in line:
                print(f"    {line.rstrip()[:120]}")

if proc.poll() is None:
    print(f"\n[OK] cerf running (PID={proc.pid}). Log: {LOG}")
else:
    print(f"\n[CRASH] cerf exited ({proc.returncode})")
