#!/usr/bin/env python3
"""Test: open My Device, close it, reopen — check if Bug 9 is fixed."""
import subprocess, time, sys, os

LOG = "Z:/tmp/reopen_test.log"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/references/wce5_sysgen_armv4/explorer.exe"

def interact(*a):
    return subprocess.run(["python3", "Z:/tools/interact.py"] + list(a),
                          capture_output=True, text=True)

def shot():
    interact("screenshot")
    print("  Screenshot saved to tmp/screenshot.png")

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

# 3. Open My Device
print("[3] Opening My Device...")
interact("dclick", "35", "30")
time.sleep(5)
shot()

# 4. Check it opened
r = interact("windows")
if "My Device" in r.stdout:
    print("    OK My Device window found")
else:
    print("    FAIL My Device NOT found!")
    # Try checking visible windows
    for line in r.stdout.splitlines():
        if "Explore" in line or "My Device" in line:
            print(f"    {line.strip()}")

# 5. Close it
print("[4] Closing My Device...")
interact("click", "789", "11")
time.sleep(5)

# 6. Verify closed
r = interact("windows")
has_explore = False
for line in r.stdout.splitlines():
    if "[V] Explore" in line and "Desktop" not in line:
        has_explore = True
        print(f"    Window still open: {line.strip()}")
if not has_explore:
    print("    OK My Device closed")

# 7. Reopen
print("[5] Reopening My Device...")
interact("dclick", "35", "30")
time.sleep(5)
shot()

# 8. Check reopened
r = interact("windows")
found = False
for line in r.stdout.splitlines():
    if "[V] Explore" in line and "Desktop" not in line:
        found = True
        print(f"    OK Found: {line.strip()}")
if not found:
    print("    FAIL My Device did NOT reopen!")
    # Check log for clues
    print("[6] Checking log...")
    with open(LOG) as f:
        for line in f:
            for kw in ["FindExplorerWnd", "RemoveExplorerWnd", "SHCreateExplorer",
                        "THREAD_DETACH", "Close()", "CMainWnd::Close"]:
                if kw in line and "[TRACE]" in line:
                    print(f"    {line.rstrip()}")
                    break

if proc.poll() is None:
    print(f"\n[OK] cerf running (PID={proc.pid}). Log: {LOG}")
else:
    print(f"\n[CRASH] cerf exited ({proc.returncode})")
