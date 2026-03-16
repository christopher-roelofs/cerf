#!/usr/bin/env python3
"""Debug script to check if CDispRoot::DrawRoot is called during paint.
Sets breakpoint at DrawRoot entry, triggers repaint, checks if hit."""
import subprocess, time, sys, os, re
sys.path.insert(0, "Z:/tools")
from debug import GdbClient

GDB_PORT = 1234
LOG = "Z:/tmp/ie_log.txt"
CERF = "Z:/build/Release/x64/cerf.exe"
EXPLORER = "Z:/references/wce5_sysgen_armv4/explorer.exe"

def interact(*a):
    return subprocess.run(["python3", "Z:/tools/interact.py"] + list(a),
                          capture_output=True, text=True)

# 1. Kill cerf
print("[1] Killing cerf...")
subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

# Delete stale registry
REG = "Z:/build/Release/x64/devices/wince5/registry.reg"
if os.path.exists(REG):
    os.remove(REG)

# 2. Start cerf + explorer with GDB stub
print("[2] Starting cerf + explorer...")
try: os.remove(LOG)
except: pass
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,EMU,DBG",
     f"--gdb-port={GDB_PORT}", EXPLORER],
    stdout=log_f, stderr=log_f, cwd="Z:/")
time.sleep(2)

# 3. Connect debugger and continue
gdb = GdbClient(port=GDB_PORT)
print("[3] Debugger connected. Continuing...")
gdb.cont()
time.sleep(5)

# 4. Open IE
print("[4] Opening IE...")
interact("dclick", "35", "333")
time.sleep(8)

# Find mshtml.dll base from log
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

IDA_BASE = 0x10000000
rebase = mshtml_base - IDA_BASE
print(f"    mshtml.dll at 0x{mshtml_base:08X} (rebase +0x{rebase:08X})")

# Key addresses (IDA base -> runtime)
DRAWROOT = 0x106E39F0 + rebase  # CDispRoot::DrawRoot
RENDERVIEW = 0x1031C2F8 + rebase  # CView::RenderView (full)
SET_RENDER_SURFACE = 0x103287FC + rebase  # CView::SetRenderSurface
ENSURE_VIEW = 0x10319424 + rebase  # CView::EnsureView
ON_PAINT_DOC = 0x103F370C + rebase  # CDoc::OnPaint

print(f"    DrawRoot   = 0x{DRAWROOT:08X}")
print(f"    RenderView = 0x{RENDERVIEW:08X}")
print(f"    OnPaint    = 0x{ON_PAINT_DOC:08X}")

# 5. Set breakpoints
print("[5] Setting breakpoints...")
gdb.interrupt()
gdb.wait_stop(timeout=5)

# Set breakpoint at DrawRoot entry
print(f"    break DrawRoot: {gdb.set_break(DRAWROOT)}")
print(f"    break RenderView: {gdb.set_break(RENDERVIEW)}")
print(f"    break CDoc::OnPaint: {gdb.set_break(ON_PAINT_DOC)}")

# 6. Continue and trigger repaint
print("[6] Continuing, will trigger repaint...")
gdb.cont()
time.sleep(1)

# Trigger repaint by clicking in content area
interact("click", "400", "250")
time.sleep(0.5)

# Check if any breakpoint was hit
print("[7] Checking for breakpoint hits...")
gdb.interrupt()
reply = gdb.wait_stop(timeout=5)
print(f"    Stop reply: {reply}")

# Read registers to see where we stopped
r = gdb.read_regs()
pc = r[15]
print(f"    PC = 0x{pc:08X}")

if pc == ON_PAINT_DOC:
    print("    >> HIT CDoc::OnPaint!")
    # r0 = this (CDoc*)
    print(f"    CDoc* this = 0x{r[0]:08X}")
elif pc == RENDERVIEW:
    print("    >> HIT CView::RenderView!")
    print(f"    CView* this = 0x{r[0]:08X}")
    print(f"    CFormDrawInfo* = 0x{r[1]:08X}")
elif pc == DRAWROOT:
    print("    >> HIT CDispRoot::DrawRoot!")
    print(f"    CDispRoot* this = 0x{r[0]:08X}")
    print(f"    pRenderSurface = 0x{r[1]:08X}")
else:
    print(f"    Stopped elsewhere (not at breakpoints)")
    # Check if we're in mshtml
    if mshtml_base <= pc < mshtml_base + 0x900000:
        print(f"    In mshtml at +0x{pc - mshtml_base:X}")

# Continue stepping to see which breakpoints hit
print("\n[8] Single-stepping through paint to find all hits...")
for bp_name, bp_addr in [("OnPaint", ON_PAINT_DOC), ("RenderView", RENDERVIEW), ("DrawRoot", DRAWROOT)]:
    gdb.remove_break(bp_addr)
gdb.cont()
time.sleep(1)

# Set only DrawRoot breakpoint and trigger another repaint
print("[9] Setting DrawRoot-only breakpoint, triggering another repaint...")
gdb.interrupt()
gdb.wait_stop(timeout=5)
gdb.set_break(DRAWROOT)
gdb.cont()
time.sleep(0.5)
interact("click", "400", "300")
time.sleep(2)

gdb.interrupt()
reply = gdb.wait_stop(timeout=5)
r = gdb.read_regs()
pc = r[15]
print(f"    PC = 0x{pc:08X}")
if pc == DRAWROOT:
    print("    >> DrawRoot WAS called!")
    # Check _pDispRoot (this pointer)
    disp_root = r[0]
    print(f"    CDispRoot* = 0x{disp_root:08X}")
    # Read some fields to check if tree is populated
    data = gdb.read_mem(disp_root, 64)
    print(f"    CDispRoot data:")
    for i in range(0, min(len(data), 64), 4):
        val = int.from_bytes(data[i:i+4], 'little')
        print(f"      +{i:02X}: 0x{val:08X}")
else:
    print(f"    DrawRoot NOT hit (stopped at 0x{pc:08X})")
    if mshtml_base <= pc < mshtml_base + 0x900000:
        print(f"    In mshtml at +0x{pc - mshtml_base:X}")

# Cleanup
print("\n[10] Cleaning up...")
gdb.remove_break(DRAWROOT)
gdb.cont()
time.sleep(0.5)
gdb.detach()
gdb.close()

if proc.poll() is None:
    print(f"[OK] cerf.exe running (PID={proc.pid})")
else:
    print(f"[CRASH] cerf.exe exited ({proc.returncode})")
