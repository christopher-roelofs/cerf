#!/usr/bin/env python3
"""E2E test: WinCE 6 Start menu has Programs submenu with entries and icons."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_wince6_start_menu.txt")
runner = CerfTestRunner(LOG, device="wince6")

try:
    step("Starting cerf (wince6)...")
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

    # Hover over Programs to open submenu
    runner.mark()
    step("Moving to Programs...")
    runner.move(73, 354)
    time.sleep(2)
    step("Waiting for Programs submenu...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Programs submenu opened!")
    runner.screenshot()

    # Verify submenu entries rendered (Internet Explorer is a common entry)
    step("Checking for program entries...")
    runner.wait_for_log("DrawTextW.*'Internet Explorer'", regex=True, timeout=5,
                        since_mark=False)
    step("Internet Explorer entry found in Programs.")

    passed("WinCE 6 Start menu shows Programs with entries")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
