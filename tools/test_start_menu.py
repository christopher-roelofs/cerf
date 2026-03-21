#!/usr/bin/env python3
"""Test Start menu navigation: Start -> Programs -> submenu."""
import subprocess, time, os, sys

CERF = "Z:/build/Release/x64/cerf.exe"
LOG = "Z:/tmp/ed.txt"

# Kill existing
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# Delete stale registry
reg = "Z:/build/Release/x64/devices/wince5/registry.reg"
if os.path.exists(reg):
    os.remove(reg)

# Start cerf
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,EMU"],
    stdout=log_f, stderr=log_f, cwd="Z:/")
print(f"Started cerf PID={proc.pid}")
time.sleep(5)

# Click Start
os.system("python3 Z:/tools/interact.py click 25 478")
time.sleep(4)

# Hover Programs
os.system("python3 Z:/tools/interact.py move 60 337")
time.sleep(4)

# Hover submenu (Communication or File Viewers)
target = sys.argv[1] if len(sys.argv) > 1 else "fileviewers"
if target == "communication":
    os.system("python3 Z:/tools/interact.py move 243 369")
else:
    os.system("python3 Z:/tools/interact.py move 243 385")
time.sleep(4)

# Screenshot
os.system("python3 Z:/tools/interact.py screenshot")
print(f"Log: {LOG}")
