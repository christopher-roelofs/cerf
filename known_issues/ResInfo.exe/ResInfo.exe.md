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

## 2. Control layout inside tab pages is broken — RESOLVED

**Description**: The property sheet tabs (Battery, Memory, Storage) appear and can be switched, but all child controls within each page are stacked at y=0 (top of the page area). Labels, progress bars, and buttons all overlap at the same vertical position instead of being laid out vertically.

**Root cause**: Desktop Windows `CreateDialogIndirectParamW` positions child controls at y=0 when `WS_CHILD` is set in the dialog template style. ARM commctrl's `_CreatePageDialog` calls `GetPageDialogStyle()` which forces `WS_CHILD | DS_CONTROL | DS_3DLOOK` on page templates before calling `CreateDialogIndirectParamW`. The DLU-to-pixel conversion for x positions, widths, and heights works correctly, but y coordinates are always mapped to 0 for WS_CHILD templates — verified by testing with different fonts and even a trivial dialog proc.

**Fix**: Strip `WS_CHILD` from the template style before calling native `CreateDialogIndirectParamW` (so DLU→pixel conversion works correctly for all coordinates), then reparent the dialog as a child window with `SetParent` + `SetWindowLongPtrW(GWL_STYLE, ... | WS_CHILD)` afterwards.

---

## 3. Missing tab icons — OPEN

**Description**: On real WinCE devices, the property sheet tabs show small icons next to the tab labels (Battery, Memory, Storage). In cerf, the tab labels appear but without icons.

**Status**: Open — needs investigation. The icons may be loaded from ResInfo.exe resources or system shell resources.

---

## 4. Window positioned off-screen at Y=32767 — RESOLVED

**Description**: The property sheet window was created at Y=32767 (0x7FFF), off-screen.

**Root cause**: `SystemParametersInfoW` thunk passed NULL for `pvParam`, discarding the output pointer. When ARM commctrl's `SHInitDialog` called `SystemParametersInfoW(SPI_GETWORKAREA, 0, &rect, 0)`, the work area RECT was never written back to emulated memory. The ARM code read garbage values and computed y=84425 for `SetWindowPos`.

**Fix** (`system.cpp`): Marshal `SPI_GETWORKAREA` properly — allocate a native RECT, call the native API, and write the result back to emulated memory at the ARM pointer address.

Also added DLGTEMPLATEEX detection for dialog position clamping (DLGTEMPLATEEX has x/y at offsets 18/20 vs DLGTEMPLATE at 10/12).

---

## Screenshots

- Expected: `on_real_device.png`
- Current: `cerf_current.png`
