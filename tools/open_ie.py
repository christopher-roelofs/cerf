#!/usr/bin/env python3
"""Kill cerf, start fresh boot sequence, open IE via address bar navigation.

Works across all WinCE versions (5/6/7) by opening My Device first,
then using the address bar to navigate to the requested URL.

Usage:
    python3 tools/open_ie.py                       Open default.htm (wince5)
    python3 tools/open_ie.py <url>                 Open URL (wince5)
    python3 tools/open_ie.py --device=wince6       Open default.htm (wince6)
    python3 tools/open_ie.py --device=wince6 <url> Open URL on wince6
    python3 tools/open_ie.py --repl                Interactive debug REPL
"""
import subprocess, time, sys, os, re, ctypes

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERF = os.path.join(REPO_ROOT, "build", "Release", "x64", "cerf.exe")
LOG = os.path.join(REPO_ROOT, "tmp", "ie_log.txt")
INTERACT = os.path.join(REPO_ROOT, "tools", "interact.py")

# Parse args
URL = None
DEVICE = "wince5"
MODE = "run"
for a in sys.argv[1:]:
    if a == "--repl":
        MODE = "repl"
    elif a.startswith("--device="):
        DEVICE = a.split("=", 1)[1]
    else:
        URL = a

DEFAULT_URL = r"\windows\default.htm"
REG = os.path.join(REPO_ROOT, "build", "Release", "x64", "devices", DEVICE, "registry.reg")


def interact_cmd(*a):
    return subprocess.run(["python3", INTERACT] + list(a),
                          capture_output=True, text=True)

def press_key(vk):
    ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
    ctypes.windll.user32.keybd_event(vk, 0, 2, 0)

def wait_for_log(pattern, timeout=30, regex=False):
    """Poll log file for pattern. Returns matching line or None."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(LOG, "r", errors="replace") as f:
                for line in f:
                    if regex:
                        if re.search(pattern, line): return line.strip()
                    else:
                        if pattern in line: return line.strip()
        except: pass
        time.sleep(0.3)
    return None


# 1. Kill cerf
print(f"[1] Killing cerf...")
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# 2. Delete stale registry
if os.path.exists(REG):
    os.remove(REG)

# 3. Start cerf
print(f"[2] Starting cerf ({DEVICE})...")
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,TRACE", f"--device={DEVICE}"],
    stdout=log_f, stderr=log_f, cwd=REPO_ROOT)
print(f"    PID={proc.pid}")

def check_alive(step=""):
    if proc.poll() is not None:
        print(f"[CRASH] cerf.exe died (code={proc.returncode}) {step}")
        print(f"  Check log: {LOG}")
        try:
            with open(LOG) as f:
                for l in f.readlines()[-5:]:
                    print(f"  {l.rstrip()}")
        except: pass
        sys.exit(1)

# 4. Wait for explorer
print("[3] Waiting for explorer...")
match = wait_for_log("DrawTextW.*'Start'", timeout=30, regex=True)
if not match:
    check_alive("waiting for explorer")
    print("ERROR: Explorer did not start")
    sys.exit(1)
time.sleep(5)
check_alive("after explorer ready")
print("    Explorer ready.")

# 5. Open My Device to get a browser window with address bar
print("[4] Opening My Device...")
interact_cmd("dclick", "22", "30")
time.sleep(8)
check_alive("after My Device open")

# 6. Navigate using address bar
target_url = URL if URL else DEFAULT_URL
print(f"[5] Navigating to: {target_url}")
# Click address bar (combo box at top of explorer window)
interact_cmd("click", "300", "27")
time.sleep(0.5)
# Select all text and replace
interact_cmd("combo", "ctrl+a")
time.sleep(0.2)
interact_cmd("type", target_url)
time.sleep(0.3)
interact_cmd("key", "enter")
print("    Navigation started. Waiting for load...")
time.sleep(15)
check_alive("after navigate")

# 7. Screenshot
print("[6] Taking screenshot...")
interact_cmd("screenshot")
print("    Saved to tmp/screenshot.png")

if MODE == "repl":
    print("[7] Entering debug REPL (type 'q' to quit)...")
    while True:
        try:
            cmd = input("ie> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd: continue
        if cmd in ("q", "quit", "exit"): break
        if cmd == "shot":
            interact_cmd("screenshot")
            print("Saved to tmp/screenshot.png")
        elif cmd.startswith("log "):
            term = cmd[4:].lower()
            with open(LOG, "r", errors="replace") as f:
                for line in f:
                    if term in line.lower():
                        print(f"  {line.rstrip()}")
        elif cmd == "alive":
            check_alive("repl check")
            print("cerf is alive")
        else:
            print(f"Unknown: {cmd}  (try: shot, log <term>, alive, q)")

if proc.poll() is None:
    print(f"[OK] cerf.exe running (PID={proc.pid}). Log: {LOG}")
else:
    print(f"[CRASH] cerf.exe exited ({proc.returncode}). Log: {LOG}")
