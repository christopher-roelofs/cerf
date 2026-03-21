#!/usr/bin/env python3
"""E2E test: Open My Device, navigate, close, reopen — no crash."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_mydevice.txt"
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Open My Device
    runner.mark()
    step("Double-clicking My Device (35, 33)...")
    runner.dclick(35, 33)
    step("Waiting for My Device window...")
    runner.wait_for_log("class='Explore'", timeout=15)
    step("My Device opened!")
    time.sleep(2)
    runner.screenshot()

    # Close My Device (click X at top-right: 790, 5)
    runner.mark()
    step("Closing My Device (790, 5)...")
    runner.click(790, 5)
    time.sleep(2)
    step("My Device closed.")

    # Reopen My Device
    runner.mark()
    step("Reopening My Device (35, 33)...")
    runner.dclick(35, 33)
    step("Waiting for My Device window again...")
    runner.wait_for_log("class='Explore'", timeout=15)
    step("My Device reopened!")
    runner.screenshot()

    # Verify taskbar still works
    runner.mark()
    step("Closing My Device again...")
    runner.click(790, 5)
    time.sleep(1)
    step("Clicking Start to verify no crash...")
    runner.click(25, 478)
    runner.wait_for_log("TrackPopupMenuEx", timeout=10)
    step("Taskbar responsive.")

    passed("My Device open/close/reopen works without crash")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
