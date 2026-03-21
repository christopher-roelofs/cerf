#!/usr/bin/env python3
"""Run all CERF e2e tests and report results."""
import subprocess, sys, os, time, glob

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
tests = sorted(glob.glob(os.path.join(TEST_DIR, "test_*.py")) +
               glob.glob(os.path.join(TEST_DIR, "solitare_*.py")))

results = []
for test in tests:
    name = os.path.basename(test)
    print(f"\n{'='*60}")
    print(f"  RUNNING: {name}")
    print(f"{'='*60}")
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
