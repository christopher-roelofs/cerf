#!/usr/bin/env python3
"""Run all CERF e2e tests and report results.
Tests are grouped by device directory (e.g. wince5/, wince6/).
Usage:
    run_all.py              Run all devices
    run_all.py wince5       Run only wince5 tests
"""
import subprocess, sys, os, time, glob

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# Find device subdirectories containing tests
device_filter = sys.argv[1] if len(sys.argv) > 1 else None
device_dirs = sorted(d for d in os.listdir(TEST_DIR)
                     if os.path.isdir(os.path.join(TEST_DIR, d))
                     and not d.startswith("_") and not d.startswith("."))
if device_filter:
    device_dirs = [d for d in device_dirs if d == device_filter]
    if not device_dirs:
        print(f"No device directory '{device_filter}' found")
        sys.exit(1)

results = []
for device in device_dirs:
    device_path = os.path.join(TEST_DIR, device)
    tests = sorted(glob.glob(os.path.join(device_path, "test_*.py")) +
                   glob.glob(os.path.join(device_path, "solitare_*.py")))
    if not tests:
        continue
    print(f"\n{'='*60}")
    print(f"  DEVICE: {device} ({len(tests)} tests)")
    print(f"{'='*60}")
    for test in tests:
        name = f"{device}/{os.path.basename(test)}"
        print(f"\n  RUNNING: {name}")
        print(f"  {'-'*56}")
        start = time.time()
        r = subprocess.run([sys.executable, test], timeout=180)
        elapsed = time.time() - start
        status = "PASS" if r.returncode == 0 else "FAIL"
        results.append((name, status, elapsed))
        print(f"  {status} ({elapsed:.1f}s)")

print(f"\n{'='*60}")
print(f"  RESULTS")
print(f"{'='*60}")
passed = sum(1 for _, s, _ in results if s == "PASS")
total = len(results)
for name, status, elapsed in results:
    marker = "OK" if status == "PASS" else "XX"
    print(f"  [{marker}] {name} ({elapsed:.1f}s)")
print(f"\n  {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
