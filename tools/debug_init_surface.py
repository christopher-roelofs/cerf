#!/usr/bin/env python3
"""Debug mshtml InitSurface by setting breakpoints BEFORE IE opens.

Sets BP on InitSurface at ALL possible rebase offsets (mshtml loads at
different addresses each run). Uses a pre-mapped address range approach.
"""
import subprocess, time, sys, os, re, struct

GDB_PORT = 1234
LOG = "Z:/tmp/ie_init_log.txt"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/references/wce5_sysgen_armv4/explorer.exe"

sys.path.insert(0, "Z:/tools")
from debug import GdbClient, print_regs, hex_dump

IDA_BASE = 0x10000000

# Key functions
FUNCS = {
    "InitSurface":     0x1017F70C,
    "CreateDDSurface": 0x1017FA50,
    "GetDDSurface":    0x1017FE2C,
    "GetDDB":          0x101807BC,
    "CreateDDB":       0x101806B4,
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
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)
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

# 3. Set breakpoints BEFORE opening IE
# mshtml always loads at 0x10960000 (deterministic in cerf)
MSHTML_BASE = 0x10960000
rebase = MSHTML_BASE - IDA_BASE
print(f"[3] Pre-setting breakpoints (assuming mshtml at 0x{MSHTML_BASE:08X})...")

bp_map = {}
for name, ida_addr in FUNCS.items():
    addr = ida_addr + rebase
    gdb.interrupt()
    gdb.wait_stop(timeout=3)
    gdb.set_break(addr)
    bp_map[addr] = name
    print(f"    BP {name} @ 0x{addr:08X}")
gdb.cont()

# 4. Open IE
print("[4] Opening IE — breakpoints should catch InitSurface...")
interact("dclick", "35", "333")

# 5. Wait for breakpoint
print("[5] Waiting for breakpoint hit (30s timeout)...")
reply = gdb.wait_stop(timeout=30)
if not reply:
    print("    TIMEOUT — no breakpoint hit!")
    print("    Checking if mshtml loaded at different address...")
    gdb.interrupt()
    gdb.wait_stop(timeout=5)
    with open(LOG, "r") as f:
        for line in f:
            if "mshtml.dll" in line and "Loaded" in line:
                print(f"    {line.rstrip()}")
else:
    print(f"    Stop reply: {reply}")
    # Find which thread hit the BP
    tids = gdb.list_threads()
    for tid in tids:
        gdb.select_thread(tid)
        regs = gdb.read_regs()
        pc = regs[15]
        for addr, name in bp_map.items():
            if abs(pc - addr) < 4:
                print(f"\n    >>> HIT: {name} on tid={tid}")
                print_regs(regs)
                print(f"\n    Now stepping through {name}...")

                # Step through and watch what happens
                for i in range(200):
                    reply = gdb.step()
                    regs = gdb.read_regs()
                    pc = regs[15]

                    # Check if we hit a thunk/API call
                    if pc >= 0xFE000000 or pc >= 0xF0000000:
                        print(f"    Step {i}: THUNK PC=0x{pc:08X}")
                        # Read log to see what API
                        time.sleep(0.1)
                        with open(LOG, "r") as f:
                            lines = f.readlines()
                        for l in lines[-5:]:
                            if "T" + str(tid) in l and ("API" in l or "Resolved" in l):
                                print(f"      {l.rstrip()}")
                    elif pc < 0x1000:
                        print(f"    Step {i}: NULL PC=0x{pc:08X} *** CRASH ***")
                        print_regs(regs)
                        break
                    elif pc == 0xCAFEC000 or pc == 0xCAFEC100:
                        print(f"    Step {i}: SENTINEL/STUB PC=0x{pc:08X}")
                    elif i < 20 or i % 50 == 0:
                        label = ""
                        if MSHTML_BASE <= pc < MSHTML_BASE + 0x1000000:
                            label = f" [mshtml+0x{pc - MSHTML_BASE:X}]"
                        elif 0x10910000 <= pc < 0x10930000:
                            label = f" [ddraw+0x{pc - 0x10910000:X}]"
                        print(f"    Step {i}: PC=0x{pc:08X}{label} R0=0x{regs[0]:08X}")
                break
        else:
            continue
        break

# Enter REPL
print("\n[6] Debug REPL (q to quit, cont to continue, step to step)")
while True:
    try:
        cmd = input("dbg> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not cmd: continue
    if cmd in ("q", "quit"): break
    parts = cmd.split()
    try:
        if parts[0] == "cont":
            gdb.cont()
            n = float(parts[1]) if len(parts) > 1 else 0
            if n > 0:
                reply = gdb.wait_stop(timeout=n)
                if reply:
                    print(f"Stopped: {reply}")
                    regs = gdb.read_regs()
                    print_regs(regs)
                else:
                    print("(timeout)")
            else:
                print("Continuing...")
        elif parts[0] == "step":
            n = int(parts[1]) if len(parts) > 1 else 1
            for _ in range(n):
                gdb.step()
                regs = gdb.read_regs()
                pc = regs[15]
                label = ""
                if MSHTML_BASE <= pc < MSHTML_BASE + 0x1000000:
                    label = f" [mshtml+0x{pc - MSHTML_BASE:X}]"
                print(f"  PC=0x{pc:08X} R0=0x{regs[0]:08X}{label}")
        elif parts[0] == "regs":
            regs = gdb.read_regs()
            print_regs(regs)
        elif parts[0] == "mem":
            addr = int(parts[1], 16)
            n = int(parts[2], 0) if len(parts) > 2 else 64
            hex_dump(gdb.read_mem(addr, n), addr)
        elif parts[0] == "threads":
            tids = gdb.list_threads()
            for tid in tids:
                gdb.select_thread(tid)
                r = gdb.read_regs()
                print(f"  tid={tid} PC=0x{r[15]:08X}")
        elif parts[0] == "log":
            term = " ".join(parts[1:]).lower()
            with open(LOG, "r") as f:
                for line in f:
                    if term in line.lower():
                        print(f"  {line.rstrip()}")
        else:
            print(f"Unknown: {cmd}")
    except Exception as e:
        print(f"Error: {e}")

print("Detaching...")
try: gdb.detach()
except: pass
gdb.close()
