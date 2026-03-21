#!/usr/bin/env python3
"""E2E test: Start -> Run -> solitaire -> verify launch -> verify taskbar alive.

Log-driven: waits for specific log patterns with timeouts instead of fixed delays.
Does NOT guess coordinates for buttons inside solitaire (Exit etc) —
only uses known coordinates for explorer UI elements.
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cerf_test_utils import CerfTestRunner, step, passed, failed, TMP_DIR

LOG = os.path.join(TMP_DIR, "e2e_solitaire.txt")
runner = CerfTestRunner(LOG)

try:
    # --- Step 1: Start cerf and wait for explorer ---
    step("Starting cerf...")
    runner.start()
    runner.mark()
    runner.wait_for_explorer()

    # --- Step 2: Open Start menu ---
    runner.mark()
    step("Clicking Start...")
    runner.click(25, 478)
    step("Waiting for Start menu (TrackPopupMenuEx)...")
    runner.wait_for_log("TrackPopupMenuEx")
    step("Start menu opened.")

    # --- Step 3: Click Run ---
    runner.mark()
    step("Clicking Run...")
    runner.click(45, 410)
    step("Waiting for Run dialog...")
    runner.wait_for_log("CreateDialogIndirectParamW")
    step("Run dialog opened.")

    # --- Step 4: Type solitaire path and click OK ---
    runner.mark()
    step("Typing solitaire path...")
    runner.click(540, 275)
    time.sleep(0.5)
    runner.type_text("\\windows\\solitare.exe")
    time.sleep(0.5)
    step("Clicking OK (362, 291)...")
    runner.click(362, 291)

    # --- Step 5: Wait for solitaire to create its window ---
    step("Waiting for solitaire window creation...")
    runner.wait_for_log("class='Solitaire'")
    step("Solitaire window created.")

    # --- Step 6: Wait for solitaire to reach message loop ---
    step("Waiting for solitaire SetTimer...")
    try:
        runner.wait_for_log("solitare.*SetTimer", timeout=15, regex=True)
        step("Solitaire reached SetTimer — fully initialized!")
    except TimeoutError:
        step("SetTimer not found — solitaire may be stuck in CreateWindowExW")
        runner.screenshot()
        failed("Solitaire didn't initialize (no SetTimer)")

    # --- Step 7: Verify taskbar thread is alive ---
    # Click Start again — if taskbar is hung, this won't produce TrackPopupMenuEx
    runner.mark()
    step("Clicking Start to verify taskbar is alive...")
    runner.click(25, 478)
    try:
        runner.wait_for_log("TrackPopupMenuEx", timeout=10)
        step("Taskbar thread is alive — Start menu opened!")
    except TimeoutError:
        runner.screenshot()
        failed("Taskbar thread is HUNG — Start menu didn't open")

    # --- Step 8: Take final screenshot ---
    runner.screenshot()
    passed("Solitaire launched via Run dialog, taskbar remains responsive")

finally:
    runner.stop()
