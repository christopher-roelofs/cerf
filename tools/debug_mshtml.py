#!/usr/bin/env python3
"""Debug mshtml.dll rendering pipeline.

Launches cerf+explorer, opens IE (loads default.htm), then uses GDB
to set breakpoints on key rendering functions and trigger a repaint.

mshtml rendering pipeline (from IDA):
  InitSurface    (0x1017F70C) - loads ddraw.dll, DirectDrawCreate
  CreateDDSurface(0x1017FA50) - creates DirectDraw surface
  GetDDSurface   (0x1017FE2C) - cache lookup, calls CreateDDSurface
  GetDDB         (0x101807BC) - GDI fallback (CreateDIBSection)
  CreateDDB      (0x101806B4) - GDI DIB creation
  GetDC (surf)   (0x1017EF2C) - get DC from surface for drawing
"""
import subprocess, time, sys, os, re, ctypes, struct

GDB_PORT = 1234
LOG = "Z:/tmp/ie_dbg_log.txt"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/references/wce5_sysgen_armv4/explorer.exe"

sys.path.insert(0, "Z:/tools")
from debug import GdbClient, print_regs, hex_dump

IDA_BASE = 0x10000000

# Key rendering functions (IDA addresses)
RENDER_FUNCS = {
    "InitSurface":     0x1017F70C,
    "CreateDDSurface": 0x1017FA50,
    "GetDDSurface":    0x1017FE2C,
    "GetDDB":          0x101807BC,
    "CreateDDB":       0x101806B4,
    "GetDC_surf":      0x1017EF2C,
}

def interact(*a):
    return subprocess.run(["python3", "Z:/tools/interact.py"] + list(a),
                          capture_output=True, text=True)

def find_ie_hwnd():
    r = interact("windows")
    for i, line in enumerate(r.stdout.splitlines()):
        if "Explore" in line and "DesktopExplorer" not in line and "[V]" in line:
            for j in range(i, min(i + 3, len(r.stdout.splitlines()))):
                m = re.search(r'hwnd=(0x[0-9a-fA-F]+)', r.stdout.splitlines()[j])
                if m: return m.group(1)
    return None

# 1. Kill + start
print("[1] Starting cerf + explorer...")
REG = "Z:/build/Release/x64/devices/wince5/registry.reg"
if os.path.exists(REG): os.remove(REG)
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,EMU,DBG",
     f"--gdb-port={GDB_PORT}", EXPLORER],
    stdout=log_f, stderr=log_f, cwd="Z:/")
time.sleep(2)

# 2. Connect + continue to let explorer start
gdb = GdbClient(port=GDB_PORT)
print("[2] Debugger connected. Continuing to let explorer start...")
gdb.cont()
time.sleep(5)

# 3. Open IE
print("[3] Opening IE...")
interact("dclick", "35", "333")
time.sleep(8)

hwnd = find_ie_hwnd()
if not hwnd:
    print("ERROR: IE did not open!")
    sys.exit(1)
print(f"    IE hwnd={hwnd}")

# 4. Find mshtml base
mshtml_base = None
with open(LOG, "r") as f:
    for line in f:
        m = re.search(r"Loaded ARM DLL 'mshtml\.dll' at (0x[0-9a-fA-F]+)", line)
        if m:
            mshtml_base = int(m.group(1), 16)
            break
if not mshtml_base:
    print("ERROR: mshtml.dll not loaded!")
    sys.exit(1)
rebase = mshtml_base - IDA_BASE
print(f"    mshtml.dll at 0x{mshtml_base:08X} (rebase +0x{rebase:08X})")

# 5. Interrupt and set breakpoints
print("[4] Interrupting to set breakpoints...")
gdb.interrupt()
reply = gdb.wait_stop(timeout=5)
if not reply:
    print("    WARNING: interrupt may have failed")

bp_addrs = {}
for name, ida_addr in RENDER_FUNCS.items():
    addr = ida_addr + rebase
    gdb.set_break(addr)
    bp_addrs[addr] = name
    print(f"    BP {name} @ 0x{addr:08X}")

# Also list threads to see state
tids = gdb.list_threads()
print(f"    {len(tids)} threads active")

# 6. Continue and trigger repaint by invalidating IE window
print("[5] Continuing and triggering repaint...")
gdb.cont()
time.sleep(1)

# Force IE to repaint by minimizing and restoring
interact("click", "300", "200")  # click in content area
time.sleep(2)

# 7. Check if any breakpoint was hit
print("[6] Interrupting to check state...")
gdb.interrupt()
reply = gdb.wait_stop(timeout=5)

tids = gdb.list_threads()
hit_any = False
for tid in tids:
    gdb.select_thread(tid)
    regs = gdb.read_regs()
    pc = regs[15]
    for addr, name in bp_addrs.items():
        if abs(pc - addr) < 4:
            print(f"    >>> tid={tid} HIT {name} at PC=0x{pc:08X}")
            print_regs(regs)
            hit_any = True
            break
    else:
        label = ""
        if mshtml_base <= pc < mshtml_base + 0x1000000:
            label = f" [mshtml+0x{pc - mshtml_base:X}]"
        # Don't print every thread, only interesting ones
        if label:
            print(f"    tid={tid} PC=0x{pc:08X}{label}")

if not hit_any:
    print("    No rendering breakpoints hit!")
    print("    mshtml never called InitSurface/CreateDDSurface/GetDDB")
    print()
    print("    Investigating: checking mshtml globals...")

    # Read g_pDirectDraw and g_hrDirectDraw to see if surface was ever created
    # These are at known offsets in mshtml (from IDA analysis)
    # Let's check the code around where WM_PAINT dispatches
    # First, let's look at what 0x8002 message handler does

    # Check what's happening with the deferred paint (msg 0x8002)
    # Read the last part of the log to see any rendering activity
    with open(LOG, "r") as f:
        lines = f.readlines()

    print()
    print("    Recent CreateCompatibleDC/BitBlt/DDraw calls:")
    for line in lines:
        lower = line.lower()
        if any(k in lower for k in ["compatibledc", "bitblt", "stretchblt",
                                     "directdraw", "ddraw", "createdibs",
                                     "getddb", "createddb", "initsurface"]):
            print(f"      {line.rstrip()}")

# 8. Enter REPL for manual investigation
print()
print("[7] Entering debug REPL. Breakpoints still set.")
print("    Type 'cont' to continue, 'threads' to list, 'help' for more")
while True:
    try:
        cmd = input("mshtml-dbg> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not cmd: continue
    if cmd in ("q", "quit", "exit"): break
    if cmd == "help":
        print("  threads    - list threads (interrupts first)")
        print("  regs       - show current thread regs")
        print("  thread N   - select thread N")
        print("  cont       - continue")
        print("  stop       - interrupt")
        print("  step [N]   - single-step N times (default 1)")
        print("  mem A [N]  - read memory")
        print("  break A    - set breakpoint")
        print("  del A      - remove breakpoint")
        print("  bps        - list breakpoints")
        print("  log STR    - grep log")
        print("  shot       - screenshot")
        print("  func NAME  - set BP on named mshtml func")
        continue
    parts = cmd.split()
    try:
        if parts[0] == "threads":
            gdb.interrupt()
            gdb.wait_stop(timeout=5)
            tids = gdb.list_threads()
            for tid in tids:
                gdb.select_thread(tid)
                r = gdb.read_regs()
                pc = r[15]
                label = ""
                if mshtml_base <= pc < mshtml_base + 0x1000000:
                    label = f" [mshtml+0x{pc - mshtml_base:X}]"
                for a, n in bp_addrs.items():
                    if abs(pc - a) < 4:
                        label = f" *** {n} ***"
                        break
                print(f"  tid={tid} PC=0x{pc:08X} LR=0x{r[14]:08X}{label}")
        elif parts[0] == "regs":
            r = gdb.read_regs()
            print_regs(r)
        elif parts[0] == "thread":
            gdb.select_thread(int(parts[1], 0))
            r = gdb.read_regs()
            print_regs(r)
        elif parts[0] == "cont":
            gdb.cont()
            print("Continuing...")
            if len(parts) > 1:
                t = float(parts[1])
                print(f"  Waiting {t}s...")
                reply = gdb.wait_stop(timeout=t)
                if reply:
                    print(f"  Stopped: {reply}")
                    r = gdb.read_regs()
                    pc = r[15]
                    for a, n in bp_addrs.items():
                        if abs(pc - a) < 4:
                            print(f"  >>> HIT {n}")
                            break
                    print_regs(r)
                else:
                    print("  (timeout, still running)")
        elif parts[0] == "stop":
            gdb.interrupt()
            reply = gdb.wait_stop(timeout=5)
            print(f"Stop: {reply}")
        elif parts[0] == "step":
            n = int(parts[1]) if len(parts) > 1 else 1
            for i in range(n):
                reply = gdb.step()
                r = gdb.read_regs()
                pc = r[15]
                label = ""
                if mshtml_base <= pc < mshtml_base + 0x1000000:
                    label = f" [mshtml+0x{pc - mshtml_base:X}]"
                print(f"  PC=0x{pc:08X}{label}")
        elif parts[0] == "mem":
            addr = int(parts[1], 16)
            n = int(parts[2], 0) if len(parts) > 2 else 64
            data = gdb.read_mem(addr, n)
            hex_dump(data, addr)
        elif parts[0] == "break":
            addr = int(parts[1], 16)
            gdb.set_break(addr)
            bp_addrs[addr] = f"0x{addr:08X}"
            print(f"OK: BP at 0x{addr:08X}")
        elif parts[0] == "del":
            addr = int(parts[1], 16)
            gdb.remove_break(addr)
            bp_addrs.pop(addr, None)
            print(f"OK: removed BP at 0x{addr:08X}")
        elif parts[0] == "bps":
            for a, n in bp_addrs.items():
                print(f"  0x{a:08X} {n}")
        elif parts[0] == "func":
            name = parts[1]
            if name in RENDER_FUNCS:
                addr = RENDER_FUNCS[name] + rebase
                gdb.set_break(addr)
                bp_addrs[addr] = name
                print(f"OK: BP {name} at 0x{addr:08X}")
            else:
                print(f"Unknown func. Available: {', '.join(RENDER_FUNCS.keys())}")
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

print("Detaching...")
try: gdb.detach()
except: pass
gdb.close()
