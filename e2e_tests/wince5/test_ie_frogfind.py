#!/usr/bin/env python3
"""E2E test: Open IE, navigate to frogfind.com, verify render."""
import sys, os, time, ctypes
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed

u32 = ctypes.windll.user32

LOG = "Z:/tmp/e2e_ie_frogfind.txt"
runner = CerfTestRunner(LOG)


def press_key(vk):
    """Send a single key press/release via keybd_event."""
    u32.keybd_event(vk, 0, 0, 0)
    u32.keybd_event(vk, 0, 2, 0)  # KEYEVENTF_KEYUP


try:
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # Open IE
    runner.mark()
    step("Double-clicking IE desktop icon (35, 313)...")
    runner.dclick(35, 313)
    step("Waiting for IE window...")
    runner.wait_for_log("class='Explore'", timeout=20)
    step("IE window created!")

    # Wait for default page to fully render before navigating
    step("Waiting for default page to load...")
    runner.wait_for_log("ExtTextOutW.*Welcome.*Pocket", regex=True, icase=True, timeout=30)
    step("Default page loaded, now navigating...")
    time.sleep(1)

    # Navigate to frogfind.com via address bar
    # Use the same approach as open_ie.py: click, End, 80x Backspace, type, Enter
    runner.mark()
    step("Clicking address bar (420, 38)...")
    runner.click(420, 38)
    time.sleep(0.3)
    step("Clearing address bar...")
    VK_END, VK_BACK = 0x23, 0x08
    press_key(VK_END)
    time.sleep(0.05)
    for _ in range(80):
        press_key(VK_BACK)
    step("Typing frogfind.com...")
    runner.type_text("frogfind.com")
    time.sleep(0.05)
    step("Pressing Enter...")
    runner.key("enter")

    # Wait for page load — look for FrogFind content rendered via ExtTextOutW
    # frogfind.com shows "The Search Engine for Vintage Computers"
    step("Waiting for frogfind.com to render...")
    runner.wait_for_log("ExtTextOutW.*Vintage", regex=True, icase=True, timeout=45)
    step("FrogFind rendered!")
    runner.screenshot()

    passed("IE navigates to frogfind.com and renders")

except TimeoutError as e:
    runner.screenshot()
    failed(str(e))
finally:
    runner.stop()
