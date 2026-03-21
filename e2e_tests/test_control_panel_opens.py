#!/usr/bin/env python3
"""E2E test: Start -> Settings -> Control Panel opens with applets."""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_control_panel.txt"
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
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

    # Hover over Settings to open submenu
    # Settings is at approximately (45, 388) from screenshot
    step("Moving to Settings...")
    runner.move(45, 388)
    time.sleep(2)

    # Click Control Panel
    # From screenshot: Control Panel is at approximately (200, 388)
    runner.mark()
    step("Clicking Control Panel (200, 388)...")
    runner.click(200, 388)
    step("Waiting for Control Panel window creation...")
    runner.wait_for_log("control.*CreateWindowExW", regex=True, timeout=15)
    step("Waiting for Control Panel to enter message loop...")
    runner.wait_for_log("GetMessageW", timeout=10)
    step("Control Panel window is running!")
    runner.screenshot()

    passed("Control Panel opens from Start -> Settings")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
