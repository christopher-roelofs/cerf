#!/usr/bin/env python3
"""E2E test: Right-click desktop -> Properties -> Display Properties opens."""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_desktop_props.txt"
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Right-click on desktop (center area, away from icons)
    runner.mark()
    step("Right-clicking desktop at (400, 240)...")
    runner.rclick(400, 240)
    step("Waiting for context menu (TrackPopupMenuEx)...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Context menu opened.")
    time.sleep(1)
    runner.screenshot("Z:/tmp/e2e_desktop_context.png")

    # Click Properties — last item in context menu
    # From screenshot analysis: Properties is at approximately (280, 226)
    runner.mark()
    step("Clicking Properties (280, 226)...")
    runner.click(280, 226)
    step("Waiting for Display Properties window...")
    runner.wait_for_log("ctlpnl.*CreateWindowExW", regex=True, icase=True, timeout=15)
    step("Waiting for ctlpnl message loop...")
    runner.wait_for_log("ctlpnl.*GetMessageW", regex=True, icase=True, timeout=15)
    step("Display Properties dialog is running!")
    runner.screenshot()

    passed("Desktop right-click -> Properties works")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
