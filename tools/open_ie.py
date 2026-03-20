#!/usr/bin/env python3
"""Kill cerf, start fresh boot sequence, open IE.

Usage:
    python3 tools/open_ie.py              Open IE (loads default.htm)
    python3 tools/open_ie.py <url>        Open IE and navigate to url
    python3 tools/open_ie.py --repl       Interactive debug REPL
    python3 tools/open_ie.py --repl <url> REPL after navigating to url
"""
import subprocess, time, sys, os, re, ctypes

URL = None
MODE = "run"  # run, repl
args = sys.argv[1:]
for a in args:
    if a == "--repl": MODE = "repl"
    else: URL = a

GDB_PORT = 1234
LOG = "Z:/tmp/ie_log.txt"
CERF = "Z:/build/Release/x64/cerf.exe"

sys.path.insert(0, "Z:/tools")
from debug import GdbClient

def interact(*a):
    return subprocess.run(["python3", "Z:/tools/interact.py"] + list(a),
                          capture_output=True, text=True)

def press_key(vk):
    ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
    ctypes.windll.user32.keybd_event(vk, 0, 2, 0)

def find_ie_hwnd():
    r = interact("windows")
    for i, line in enumerate(r.stdout.splitlines()):
        if "Explore" in line and "DesktopExplorer" not in line and "[V]" in line:
            for j in range(i, min(i + 3, len(r.stdout.splitlines()))):
                m = re.search(r'hwnd=(0x[0-9a-fA-F]+)', r.stdout.splitlines()[j])
                if m: return m.group(1)
    return None

# 1. Kill cerf
print("[1] Killing cerf...")
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# 2. Delete stale registry
REG = "Z:/build/Release/x64/devices/wince5/registry.reg"
if os.path.exists(REG):
    os.remove(REG)

# 3. Start cerf (boot sequence launches explorer automatically)
print(f"[2] Starting cerf...")
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,TRACE"],
    stdout=log_f, stderr=log_f, cwd="Z:/")
print(f"    PID={proc.pid}")

def check_alive(step=""):
    """Check if cerf.exe is still running. Exit if dead."""
    if proc.poll() is not None:
        print(f"[CRASH] cerf.exe died (code={proc.returncode}) {step}")
        print(f"  Check log: {LOG}")
        # Show last few lines
        try:
            with open(LOG) as f:
                lines = f.readlines()
                for l in lines[-5:]:
                    print(f"  {l.rstrip()}")
        except: pass
        sys.exit(1)

time.sleep(7)
check_alive("after startup")

# 4. Open IE via double-click on desktop icon
print("[3] Opening IE...")
interact("dclick", "35", "333")
time.sleep(10)
check_alive("after IE open")

hwnd = find_ie_hwnd()
if not hwnd:
    check_alive("IE window search")
    print("ERROR: IE did not open (but cerf is alive)")
    sys.exit(1)
print(f"    IE hwnd={hwnd}")

# 5. Navigate to URL (only if explicitly given)
if URL:
    check_alive("before navigate")
    print(f"[4] Navigating to {URL}")
    interact("click", "300", "37")
    time.sleep(0.3)
    VK_END, VK_BACK = 0x23, 0x08
    press_key(VK_END)
    time.sleep(0.05)
    for _ in range(80):
        press_key(VK_BACK)
    interact("type", URL)
    time.sleep(0.05)
    interact("key", "enter")
    print("    Navigated. Waiting for load...")
    time.sleep(15)
    check_alive("after navigate")
else:
    print("[4] No URL given — IE shows default.htm")
    time.sleep(2)

# 6. Screenshot
print("[5] Taking screenshot...")
interact("screenshot")
print("    Saved to tmp/screenshot.png")

if MODE == "repl":
    print("[6] Entering debug REPL (type 'help' for commands)...")
    while True:
        try:
            cmd = input("gdb> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd: continue
        if cmd in ("q", "quit", "exit"): break
        if cmd == "help":
            print("  threads   - list all threads")
            print("  regs      - show current thread registers")
            print("  thread N  - select thread by tid")
            print("  break A   - set breakpoint at hex address")
            print("  del A     - remove breakpoint at hex address")
            print("  cont      - continue execution")
            print("  stop      - interrupt all CPUs")
            print("  step      - single-step")
            print("  mem A [N] - read N bytes at address A")
            print("  log STR   - grep log for string")
            print("  shot      - take screenshot")
            print("  q         - quit")
            continue
        parts = cmd.split()
        try:
            if parts[0] == "threads":
                gdb.interrupt()
                reply = gdb.wait_stop(timeout=5)
                tids = gdb.list_threads()
                for tid in tids:
                    gdb.select_thread(tid)
                    r = gdb.read_regs()
                    pc = r[15]
                    label = ""
                    if mshtml_base and mshtml_base <= pc < mshtml_base + 0x200000:
                        label = f" [mshtml+0x{pc - mshtml_base:X}]"
                    print(f"  tid={tid} PC=0x{pc:08X} SP=0x{r[13]:08X}{label}")
            elif parts[0] == "regs":
                r = gdb.read_regs()
                from debug import print_regs
                print_regs(r)
            elif parts[0] == "thread":
                gdb.select_thread(int(parts[1], 0))
                r = gdb.read_regs()
                from debug import print_regs
                print_regs(r)
            elif parts[0] == "break":
                addr = int(parts[1], 16)
                print(gdb.set_break(addr))
            elif parts[0] == "del":
                addr = int(parts[1], 16)
                print(gdb.remove_break(addr))
            elif parts[0] == "cont":
                gdb.cont()
                print("Continuing...")
            elif parts[0] == "stop":
                gdb.interrupt()
                reply = gdb.wait_stop(timeout=5)
                print(f"Stop: {reply}")
            elif parts[0] == "step":
                reply = gdb.step()
                print(f"Step: {reply}")
                r = gdb.read_regs()
                print(f"  PC=0x{r[15]:08X}")
            elif parts[0] == "mem":
                addr = int(parts[1], 16)
                n = int(parts[2], 0) if len(parts) > 2 else 64
                data = gdb.read_mem(addr, n)
                from debug import hex_dump
                hex_dump(data, addr)
            elif parts[0] == "log":
                term = " ".join(parts[1:]).lower()
                with open(LOG, "r") as f:
                    for line in f:
                        if term in line.lower():
                            print(f"  {line.rstrip()}")
            elif parts[0] == "shot":
                interact("screenshot")
                print("Saved to tmp/screenshot.png")
            else:
                print(f"Unknown: {cmd}")
        except Exception as e:
            print(f"Error: {e}")

if proc.poll() is None:
    print(f"[OK] cerf.exe running (PID={proc.pid}). Log: {LOG}")
else:
    print(f"[CRASH] cerf.exe exited ({proc.returncode}). Log: {LOG}")
