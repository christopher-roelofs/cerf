#!/usr/bin/env python3
"""E2E test: WinCE 6 My Device opens via API set dispatch, shows folders."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_wince6_mydevice.txt")
runner = CerfTestRunner(LOG, device="wince6")

try:
    step("Starting cerf (wince6)...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Double-click My Device icon
    runner.mark()
    step("Double-clicking My Device...")
    runner.dclick(22, 30)
    step("Waiting for SHCreateExplorerInstance dispatch...")
    runner.wait_for_log("SHCreateExplorerInstance", timeout=15)
    step("Waiting for My Device window to render...")
    runner.wait_for_log("DrawTextW.*'My Device'", regex=True, timeout=15)
    step("My Device window opened!")
    time.sleep(2)
    runner.screenshot()

    passed("WinCE 6 My Device opens via SHEL API set dispatch")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
