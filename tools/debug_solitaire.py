#!/usr/bin/env python3
"""Debug solitaire hang: launch via Run dialog, inspect stuck threads via GDB."""
import subprocess, time, os, sys
sys.path.insert(0, "Z:/tools")
from debug import GdbClient

CERF = r"Z:\build\Release\x64\cerf.exe"
LOG = "Z:/tmp/ed.txt"

subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
time.sleep(1)

reg = "Z:/build/Release/x64/devices/wince5/registry.reg"
if os.path.exists(reg):
    os.remove(reg)

# Start cerf with GDB — Start() blocks until GDB connects
log_f = open(LOG, "w")
proc = subprocess.Popen(
    [CERF, "--flush-outputs", "--log=API,PE,EMU", "--gdb-port=1234"],
    stdout=log_f, stderr=log_f, cwd="Z:/")
print(f"Started cerf PID={proc.pid}, connecting GDB...")
time.sleep(1)

# Connect GDB immediately so cerf can proceed
gdb = GdbClient("127.0.0.1", 1234)
print("GDB connected, continuing...")
gdb.cont()
time.sleep(6)
print("Explorer should be up")

# Launch solitaire via Run dialog
os.system("python3 Z:/tools/interact.py click 25 478")
time.sleep(3)
os.system("python3 Z:/tools/interact.py click 45 410")
time.sleep(2)
os.system("python3 Z:/tools/interact.py click 540 275")
time.sleep(0.5)
os.system(r'python3 Z:/tools/interact.py type \windows\solitare.exe')
time.sleep(0.5)
os.system("python3 Z:/tools/interact.py click 504 315")
print("Waiting 5s for solitaire to hang...")
time.sleep(5)

# Interrupt all CPUs
print("Interrupting...")
gdb.interrupt()
reply = gdb.wait_stop(timeout=5)
print(f"Stop: {reply}")

# List all threads
tids = gdb.list_threads()
print(f"\nThreads ({len(tids)}):")
for tid in tids:
    gdb.select_thread(tid)
    r = gdb.read_regs()
    pc, lr, sp = r[15], r[14], r[13]
    label = ""
    if 0x10000 <= pc < 0x80000:
        label = " [EXE code]"
    elif pc >= 0x10000000:
        label = " [DLL]"
    elif pc == 0xDEADDEAD:
        label = " [returned]"
    print(f"  tid={tid:5d}  PC=0x{pc:08X}  LR=0x{lr:08X}  SP=0x{sp:08X}{label}")

proc.kill()
print(f"\nLog: {LOG}")
