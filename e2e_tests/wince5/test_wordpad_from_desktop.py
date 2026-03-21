#!/usr/bin/env python3
"""E2E test: Double-click WordPad desktop icon -> opens -> close -> no crash."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed

LOG = "Z:/tmp/e2e_wordpad.txt"
runner = CerfTestRunner(LOG)

try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Double-click WordPad icon
    # From screenshot: Microsoft WordPad icon is at approximately (113, 33)
    runner.mark()
    step("Double-clicking WordPad icon (113, 33)...")
    runner.dclick(113, 33)
    step("Waiting for WordPad window...")
    runner.wait_for_log("class='WordPad'", timeout=15)
    step("WordPad window created!")

    # Verify it has the rich edit control
    step("Waiting for RichEdit control...")
    runner.wait_for_log("RichEdit20W", timeout=10)
    step("WordPad fully loaded with RichEdit.")
    runner.screenshot()

    # Verify Start menu still works (no hang)
    runner.mark()
    step("Clicking Start to verify no hang...")
    runner.click(25, 478)
    runner.wait_for_log("TrackPopupMenuEx", timeout=10)
    step("Taskbar responsive after WordPad launch.")

    passed("WordPad opens from desktop, taskbar stays responsive")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
