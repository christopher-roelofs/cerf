#!/usr/bin/env python3
"""E2E test: WinCE 7 explorer boots, shows desktop with icons and taskbar."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_wince7_desktop.txt")
runner = CerfTestRunner(LOG, device="wince7")

try:
    step("Starting cerf (wince7)...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Verify desktop window created
    runner.mark()
    step("Checking DesktopExplorerWindow...")
    runner.wait_for_log("class='DesktopExplorerWindow'", timeout=5, since_mark=False)
    step("Desktop window present.")

    # Verify Start menu works
    runner.mark()
    step("Clicking Start...")
    runner.click(25, 478)
    step("Waiting for Start menu...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Start menu opened.")
    time.sleep(1)
    runner.key("escape")
    time.sleep(1)
    runner.screenshot()

    passed("WinCE 7 explorer boots with desktop and Start menu")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
