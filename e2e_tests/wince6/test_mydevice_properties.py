#!/usr/bin/env python3
"""E2E test: WinCE 6 My Device Properties -> System Properties opens."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_wince6_mydevice_props.txt")
runner = CerfTestRunner(LOG, device="wince6")

try:
    step("Starting cerf (wince6)...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Right-click My Device icon
    runner.mark()
    step("Right-clicking My Device...")
    runner.rclick(22, 30)
    step("Waiting for context menu...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Context menu opened.")
    time.sleep(1)

    # Click Properties (last item in context menu)
    runner.mark()
    step("Clicking Properties...")
    runner.click(110, 185)
    step("Waiting for ctlpnl.exe to launch...")
    runner.wait_for_log("ctlpnl.*CreateWindowExW", regex=True, icase=True, timeout=15)
    step("Waiting for ctlpnl message loop...")
    runner.wait_for_log("ctlpnl.*GetMessageW", regex=True, icase=True, timeout=15)
    step("System Properties dialog running!")
    runner.screenshot()

    passed("WinCE 6 My Device Properties opens ctlpnl.exe")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
