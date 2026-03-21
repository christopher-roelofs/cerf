#!/usr/bin/env python3
"""E2E test: Open IE via desktop icon -> default.htm renders."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_ie_default.txt")
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Double-click Internet Explorer icon on desktop
    # IE icon is in the desktop icon grid — need to find it
    # On WinCE desktop, icons are arranged in a grid
    # IE is typically at the third position or so
    runner.mark()
    step("Double-clicking IE desktop icon (35, 313)...")
    runner.dclick(35, 313)
    step("Waiting for IE window (Explore class)...")
    runner.wait_for_log("class='Explore'", timeout=20)
    step("IE window created!")

    # Wait for default.htm content to render via ExtTextOutW
    # mshtml needs time to load, parse HTML, and render
    step("Waiting for default page content (ExtTextOutW)...")
    runner.wait_for_log("ExtTextOutW.*Welcome.*Pocket", regex=True, icase=True, timeout=45)
    step("Default.htm rendered!")
    runner.screenshot()

    passed("IE opens and renders default.htm")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
