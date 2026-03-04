# ResInfo.exe (WR-Tools ResInfo) - Known Issues

## 1. Property sheet never appeared — RESOLVED

**Description**: ResInfo.exe is a WinCE system info app that shows Battery, Memory, and Storage tabs in a property sheet. On startup it created a property sheet dialog but never entered the message loop — the window never appeared and the process exited immediately.

**Root cause**: `DWL_USER` / `DWLP_USER` offset mismatch between 32-bit WinCE and 64-bit Windows.

On WinCE (32-bit): `DWL_MSGRESULT=0, DWL_DLGPROC=4, DWL_USER=8`
On x64 Windows: `DWLP_MSGRESULT=0, DWLP_DLGPROC=8, DWLP_USER=16`

ARM commctrl's `PropSheetDlgProc` calls `SetWindowLongW(hDlg, 8, ppda)` intending to store the property sheet data pointer at `DWL_USER`. On x64, index 8 maps to `DWLP_DLGPROC`, so this **corrupted the native dialog procedure pointer** (EmuDlgProc). After corruption, the dialog couldn't process any messages, `PageChange` couldn't set `ppda->hwndCurPage`, and `_RealPropertySheet`'s message loop `while (ppda->hwndCurPage)` never ran.

**Fix**: Added DWL→DWLP index translation in `GetWindowLongW` and `SetWindowLongW` thunks for dialog windows (tracked via `hwnd_dlgproc_map`):
- Index 0 → `DWLP_MSGRESULT`
- Index 4 → returns/updates ARM dlgproc from `hwnd_dlgproc_map` (prevents corrupting native DLGPROC)
- Index 8 → `DWLP_USER`

**Supporting fixes** (from previous sessions):
- Added `pending_arm_dlgproc` mechanism so `EmuDlgProc` can dispatch `WM_INITDIALOG` during `CreateDialogIndirectParamW` before `hwnd_dlgproc_map` is populated
- Added thunks: `GetUserDefaultLangID` (212), `MapDialogRect` (699), `CreateIconIndirect` (723)
- Identity-mapped emulated memory so ARM struct pointers are valid native pointers

---

## 2. Control layout inside tab pages is broken — OPEN

**Description**: The property sheet tabs (Battery, Memory, Storage) appear and can be switched, but all child controls within each page are stacked at y=0 (top of the page area). Labels, progress bars, and buttons all overlap at the same vertical position instead of being laid out vertically.

**Expected**: Controls should be vertically distributed as shown in `on_real_device.png`.

**Status**: Open — needs investigation. Likely related to DLU-to-pixel conversion or dialog template font metrics for page child dialogs.

---

## 3. Window positioned off-screen at Y=32767 — OPEN

**Description**: The property sheet window is created at Y=32767 (0x7FFF), which is off-screen. This is the maximum positive signed 16-bit value, suggesting a WinCE coordinate system issue. WinCE uses 16-bit screen coordinates; the property sheet may use CW_USEDEFAULT or a WinCE-specific default that doesn't translate to desktop Windows.

**Status**: Open — cosmetic issue, can be worked around by moving the window.

---

## Screenshots

- Expected: `on_real_device.png`
- Current: `cerf_current.png`
