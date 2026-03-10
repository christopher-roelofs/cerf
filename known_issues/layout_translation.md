# WinCE -> Desktop Window Layout Translation — RESOLVED

## Status: Fully resolved by WS_POPUP rewrite

The problems described below were caused by the old inflate/deflate approach,
which maintained two coordinate systems (WinCE vs native) that constantly got
out of sync. The WS_POPUP rewrite eliminated this entire class of bugs.

See `docs/windowing.md` for the current windowing architecture.

## Historical Context

### The Old Problem

WinCE uses 1px borders everywhere while desktop Windows uses thick frames
(4-8px borders, large caption, padded borders). The old approach tried to:

1. **Inflate** WinCE-sized windows to desktop frame sizes in CreateWindowExW
2. **Deflate** native rects back to WinCE rects in GetWindowRect
3. **Re-inflate** in SetWindowPos/MoveWindow

This created cascading bugs: coordinates drifted, minimum width enforcement
added phantom whitespace to property sheets, and dialog layouts broke.

### The DLU Override Hack (removed)

To work around desktop's minimum captioned window width (which WinCE doesn't
enforce), a hack made GetWindowRect lie to ARM code during WM_INITDIALOG by
returning DLU-based dimensions instead of the inflated native dimensions.
This involved `pending_template_cx/cy` and `dlu_override_hwnd` fields.

### The Fix

All of this was replaced by the WS_POPUP approach: create all top-level WinCE
windows as WS_POPUP (no native frame), draw WinCE-style NC area via
ThemeSubclassProc, and pass coordinates through unchanged. No inflation,
no deflation, no DLU overrides needed.
