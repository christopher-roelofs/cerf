#!/usr/bin/env python3
"""E2E test: Start -> Settings -> Control Panel opens with applets."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
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
    # Verified: Settings is 3rd item in Start menu at (0,330)-(146,455)
    step("Moving to Settings (73, 388)...")
    runner.move(73, 388)
    time.sleep(2)

    # Click Control Panel — first item in Settings submenu at (140,374)-(392,446)
    runner.mark()
    step("Clicking Control Panel (266, 386)...")
    runner.click(266, 386)
    step("Waiting for Control Panel window creation...")
    runner.wait_for_log("class='CONTROLEXE_MAIN'", timeout=15)
    step("Waiting for Control Panel to enter message loop...")
    runner.wait_for_log("control.*GetMessageW", regex=True, timeout=10)
    step("Control Panel window is running!")
    runner.screenshot()

    passed("Control Panel opens from Start -> Settings")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
