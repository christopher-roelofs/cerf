#!/usr/bin/env python3
"""E2E test: Right-click My Device -> Properties -> System Properties opens."""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_mydevice_props.txt"
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Right-click My Device icon (top-left desktop icon)
    runner.mark()
    step("Right-clicking My Device (35, 33)...")
    runner.rclick(35, 33)
    step("Waiting for context menu...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Context menu opened.")
    time.sleep(1)

    # Click Properties — last item in context menu
    # Verified position: menu at (35,33)-(186,198), Properties at bottom ~y=185
    runner.mark()
    step("Clicking Properties (110, 185)...")
    runner.click(110, 185)
    step("Waiting for System Properties window...")
    runner.wait_for_log("ctlpnl.*CreateWindowExW", regex=True, icase=True, timeout=15)
    step("Waiting for ctlpnl message loop...")
    runner.wait_for_log("ctlpnl.*IsDialogMessageW", regex=True, icase=True, timeout=15)
    step("System Properties dialog running!")
    runner.screenshot()

    passed("My Device right-click -> Properties opens System Properties")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
