#!/usr/bin/env python3
"""E2E test: WinCE 7 Start menu opens with entries."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_wince7_start_menu.txt")
runner = CerfTestRunner(LOG, device="wince7")

try:
    step("Starting cerf (wince7)...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Open Start menu
    runner.mark()
    step("Clicking Start...")
    runner.click(25, 478)
    step("Waiting for Start menu...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Start menu opened.")
    time.sleep(1)

    # Verify Start menu has entries (Programs folder is read)
    step("Checking for Programs folder access...")
    runner.wait_for_log("GetFileAttributesW.*Programs", regex=True, timeout=5,
                        since_mark=False)
    step("Programs folder accessed.")
    runner.screenshot()

    passed("WinCE 7 Start menu opens with entries")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
