# WinCE → Desktop Window Layout Translation

## The Core Problem

WinCE and desktop Windows have fundamentally different window frame dimensions. WinCE uses 1px borders everywhere, while desktop Windows uses thick frames (4-8px borders, large caption, padded borders). ARM WinCE apps compute layouts based on WinCE dimensions, so without translation, everything is oversized on desktop.

## Frame Dimension Translation

### WinCE frame metrics (what ARM code expects)
- SM_CXBORDER = 1, SM_CYBORDER = 1
- SM_CXDLGFRAME = 1, SM_CYDLGFRAME = 1
- SM_CXFRAME = 1, SM_CYFRAME = 1
- SM_CXPADDEDBORDER = 0
- SM_CXEDGE = 1, SM_CYEDGE = 1

### Translation thunks (in `system.cpp`, `window.cpp`, `window_props.cpp`)

**GetSystemMetrics**: Returns WinCE values for frame-related metrics so ARM code computes correct layouts.

**CreateWindowExW / SetWindowPos / MoveWindow**: ARM code passes WinCE-style dimensions (client + 2px border). Thunks convert:
1. Extract client: `client_w = wince_w - 2`
2. Compute native frame: `AdjustWindowRectEx(client, native_style, ...)`
3. Call native API with native dimensions

**GetWindowRect**: Returns WinCE-equivalent rect for non-child WS_CAPTION windows:
1. Get native client rect via `GetClientRect`
2. Compute WinCE frame: `{client_tl.x - 1, client_tl.y - caption - 1, client_tl.x + client_w + 1, client_tl.y + client_h + 1}`

This applies to ALL non-child captioned windows, including owned popup dialogs (property sheets, etc.), not just top-level windows.

## The Desktop Minimum Width Problem — RESOLVED

### Symptom
Property sheet dialogs (Display Properties, ResInfo) had ~66px of extra whitespace on the right side between the tab control edge and the frame edge.

### Root Cause
Desktop Windows enforces a **minimum window width** for captioned windows (to fit caption buttons, system menu icon, etc.). This minimum doesn't exist on WinCE.

The property sheet frame dialog template (resource 1006 in commctrl.dll) specifies very small DLU dimensions: cx=34, cy=30. On WinCE, this creates a ~53px wide frame. On desktop, the minimum width enforcement inflates this to ~136px (120px client).

ARM commctrl's `InitPropSheetDlg` algorithm:
1. Gets initial frame size: `GetWindowRect(frame)` → sees inflated 122px WinCE width (from 120px client)
2. Gets tab control client: `GetClientRect(tab)` → ~54px
3. Computes max page size from page DLU templates → ~396px
4. Growth = max(page, tab_client) - tab_client = 396 - 54 = 342px
5. **Final frame = initial frame + growth = 122 + 342 = 464px**

On real WinCE: initial frame = 53px, final = 53 + 342 = 395px. The 69px difference (122 - 53) is the whitespace.

### Why Naive Fixes Failed

1. **Post-creation resize** (resize dialog after CreateDialogIndirectParamW returns): WM_INITDIALOG is sent DURING CreateDialogIndirectParamW. By the time the API returns, InitPropSheetDlg has already run and computed the final size. Resizing after that shrinks the already-sized dialog.

2. **Pre-INITDIALOG resize** (resize in EmuDlgProc before dispatching WM_INITDIALOG to ARM): Desktop Windows **silently ignores** SetWindowPos requests that would make a captioned window smaller than the minimum width. The window stays inflated.

### The Fix: GetWindowRect DLU Override

Since we can't change the native window's actual size below the minimum, we make the GetWindowRect thunk **lie** to ARM code during WM_INITDIALOG processing:

1. **dialog.cpp**: When `CreateDialogIndirectParamW` is called, extract template DLU dimensions (cx, cy) and store as `pending_template_cx/cy` (like `pending_arm_dlgproc`).

2. **dlgproc.cpp**: In `EmuDlgProc`, when handling WM_INITDIALOG:
   - Convert pending DLU dimensions to pixel client size via `MapDialogRect`
   - If DLU-based client is smaller than actual (desktop inflated it), store as override: `dlu_override_hwnd`, `dlu_override_client_w/h`
   - Dispatch WM_INITDIALOG to ARM code (override is active)
   - Clear override after ARM dispatch returns

3. **window_props.cpp**: In `GetWindowRect` thunk, if the queried HWND matches `dlu_override_hwnd`, use the stored DLU-based client dimensions instead of the actual inflated client. Clear the override after first use (only the initial GetWindowRect needs the fix; subsequent calls see the real resized dimensions).

Result: ARM InitPropSheetDlg sees `initial_frame_wince_width = 53` instead of `122`, computes `final = 53 + 342 = 395`, matching real WinCE behavior.

### Files Changed
- `thunks/win32_thunks.h` — Added `pending_template_cx/cy`, `dlu_override_hwnd/client_w/client_h`
- `thunks/callbacks.cpp` — Static variable definitions
- `thunks/coredll/dialog.cpp` — Store template DLU dimensions before CreateDialogIndirectParamW
- `thunks/dlgproc.cpp` — Set DLU override before WM_INITDIALOG dispatch to ARM
- `thunks/coredll/window_props.cpp` — Apply DLU override in GetWindowRect thunk

### Key Lesson
When desktop Windows enforces constraints that WinCE doesn't have (like minimum window width), you can't always fight the constraint directly. Instead, intercept the ARM code's **observation** of the constrained value and return what WinCE would have returned. The ARM code then computes correct results from correct inputs.
