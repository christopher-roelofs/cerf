#!/usr/bin/env python3
"""E2E test: Start -> Settings -> Control Panel -> double-click System -> opens."""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_cpanel_system.txt"
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
    # Settings is 3rd item in Start menu at (0,330)-(146,455)
    step("Moving to Settings (73, 388)...")
    runner.move(73, 388)
    time.sleep(2)

    # Click Control Panel — first item in Settings submenu at (140,374)-(392,446)
    runner.mark()
    step("Clicking Control Panel (266, 386)...")
    runner.click(266, 386)
    step("Waiting for Control Panel window creation...")
    runner.wait_for_log("class='CONTROLEXE_MAIN'", timeout=15)
    step("Waiting for Control Panel message loop...")
    runner.wait_for_log("control.*GetMessageW", regex=True, timeout=10)
    step("Control Panel window is running!")
    time.sleep(2)

    # Double-click System icon in Control Panel
    # System is in row 2, 7th column at approximately (640, 125)
    runner.mark()
    step("Double-clicking System applet (640, 125)...")
    runner.dclick(640, 125)
    step("Waiting for System Properties (ctlpnl) process...")
    runner.wait_for_log("ctlpnl.*CreateWindowExW", regex=True, icase=True, timeout=15)
    step("Waiting for System Properties dialog message loop...")
    runner.wait_for_log("ctlpnl.*IsDialogMessageW", regex=True, icase=True, timeout=15)
    step("System Properties dialog running!")
    runner.screenshot()

    passed("Control Panel -> System Properties opens successfully")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
