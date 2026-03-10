# WinCE Windowing System Translation

## The Core Problem

Windows CE and desktop Windows use fundamentally different windowing models:

| Aspect | Windows CE | Desktop Windows |
|--------|-----------|-----------------|
| Frame border | 1px solid border | 7-8px thick frame (SM_CXFRAME) |
| Caption height | ~20px thin bar | ~30px with padding (SM_CYCAPTION + SM_CXPADDEDBORDER) |
| SM_CXDLGFRAME | 1 | 4 |
| SM_CXEDGE | 2 | 2 |
| SM_CXFRAME | 1 | 4+ |
| WS_OVERLAPPEDWINDOW | Not used — WS_CAPTION only | Thick frame, min/max boxes |
| Fullscreen | Window rect = screen rect | Rare; thick frame extends beyond screen |

ARM code computes window sizes using `GetSystemMetrics`, `AdjustWindowRectEx`, and
hardcoded assumptions about 1px borders. If we create native desktop windows with
WS_CAPTION, the thick frame adds 16+ extra pixels on each axis, breaking layouts.

## Our Solution: WS_POPUP + Custom NC Area

**All top-level WinCE windows are created as WS_POPUP on desktop.**

This eliminates the native frame entirely. We then manually define the non-client
area using WinCE-compatible metrics through two mechanisms:

### 1. WM_NCCALCSIZE (EmuWndProc + ThemeSubclassProc)

Defines the client area insets based on the original WinCE style:

- **WS_CAPTION** (WS_BORDER | WS_DLGFRAME): 1px border + SM_CYCAPTION caption
- **WS_BORDER only**: 1px border, no caption
- **Neither**: no NC area (fullscreen/popup)

```
WM_NCCALCSIZE handler:
  has_caption = (wce_style & WS_CAPTION) == WS_CAPTION
  has_border  = (wce_style & WS_BORDER) != 0
  border = 1
  caption = has_caption ? SM_CYCAPTION : 0
  client rect shrinks by (border, border+caption, border, border)
```

This handler lives in both EmuWndProc (for ARM-class windows) and
ThemeSubclassProc (for dialog windows that use DefDlgProc).

### 2. PaintWinCENCArea (theme_subclass.cpp)

Draws the WinCE-style NC area during WM_NCPAINT:

- 1px black border (COLOR_WINDOWFRAME) via FrameRect
- Caption bar filled with COLOR_ACTIVECAPTION/COLOR_INACTIVECAPTION
- Caption buttons: Close (X), Help (?), OK — drawn right-to-left
- Caption text with system font

### 3. HitTestWinCECaption (theme_subclass.cpp)

Hit-tests the caption area during WM_NCHITTEST, returning HTCLOSE, HTHELP,
HT_CAPTIONOK, or HTCAPTION for drag support.

**Critical**: The custom hit-test runs BEFORE DefSubclassProc because
DefWindowProc returns HTNOWHERE for the NC area of borderless WS_POPUP
windows, so a post-DefSubclassProc check would never fire.

## Style Tracking

Since we convert styles to WS_POPUP, ARM code would see the wrong style via
GetWindowLongW(GWL_STYLE). We maintain parallel maps:

- `hwnd_wce_style_map[HWND]` → original WinCE style
- `hwnd_wce_exstyle_map[HWND]` → original WinCE extended style

These maps are populated:
- **Top-level windows**: via `tls_pending_wce_style` TLS variable set in the
  CreateWindowExW thunk, read in EmuWndProc's WM_NCCREATE handler
- **Dialog windows**: directly in CreateDialogIndirectParamW/DialogBoxIndirectParamW
  after the dialog HWND is created

GetWindowLongW/SetWindowLongW thunks use these maps to return/update the
original WinCE styles. SetWindowLongW(GWL_STYLE) triggers SWP_FRAMECHANGED
to recalculate the NC area when caption state changes.

## CREATESTRUCT Override

When ARM code receives WM_CREATE/WM_NCCREATE, the marshaled CREATESTRUCT
must show the original WinCE styles (not WS_POPUP). After MarshalCreateStruct
writes the 32-bit CREATESTRUCT to emulated memory, we overwrite the style
and exStyle fields from hwnd_wce_style_map/hwnd_wce_exstyle_map.

Layout: CS_EMU_ADDR + 32 = style, CS_EMU_ADDR + 44 = exStyle.

## CW_USEDEFAULT Handling

WinCE treats CW_USEDEFAULT as "fullscreen":

- **With WS_CAPTION**: window = (0, 0, screen_width+2, screen_height+2+SM_CYCAPTION)
  so that client area = screen_width x screen_height
- **Without WS_CAPTION**: window = (0, 0, screen_width, screen_height)

## Dialog Windows

Dialog templates are patched in `FixupDlgTemplate`:
1. Strip WS_EX_CAPTIONOKBTN (0x80000000) from exStyle
2. Convert style to WS_POPUP (strip WS_CAPTION, WS_THICKFRAME, etc.)
3. Patch font name to WinCE system font
4. Add DS_SETFONT if missing

After creation, dialog HWNDs are added to hwnd_wce_style_map with the
original WinCE styles so WM_NCCALCSIZE and PaintWinCENCArea work correctly.

## AdjustWindowRectEx

Returns WinCE-compatible frame dimensions:
- WS_CAPTION: expand by 1px border + SM_CYCAPTION
- No WS_CAPTION: no expansion

This ensures ARM code computing window sizes via AdjustWindowRectEx gets
values consistent with our custom NC area.

## Coordinate Pass-through

With the WS_POPUP approach, **no coordinate translation is needed**:

- `SetWindowPos` / `MoveWindow`: pass through directly
- `GetWindowRect`: pass through (native rect IS the WinCE rect)
- `GetClientRect`: pass through (native client = WinCE client)
- `MapWindowPoints` / `ClientToScreen` / `ScreenToClient`: pass through

The old inflate/deflate approach (removed in this rewrite) maintained dual
coordinate systems that constantly got out of sync. The WS_POPUP approach
eliminates this entire class of bugs.

## Per-class Fixups

- `SysListView32`: force LVS_AUTOARRANGE (0x0100) for correct icon layout
- `Shell Embedding` / `DefShellView`: force WS_VISIBLE (shdocvw activation issue)
- `COMBOBOX`: default to CBS_DROPDOWN when no CBS type bits set

## File Map

| File | Role |
|------|------|
| `coredll/window.cpp` | CreateWindowExW thunk (WS_POPUP conversion) |
| `callbacks.cpp` | EmuWndProc (WM_NCCALCSIZE for ARM-class windows) |
| `theme.cpp` | Colors, inline hooks, initialization, per-window theme apply |
| `theme_subclass.cpp` | PaintWinCENCArea, HitTestWinCECaption, ThemeSubclassProc |
| `theme_internal.h` | Shared declarations between theme.cpp and theme_subclass.cpp |
| `coredll/window_props.cpp` | GetWindowLongW/SetWindowLongW (style map lookups) |
| `coredll/window_layout.cpp` | SetWindowPos/MoveWindow (pass-through) |
| `coredll/system.cpp` | GetSystemMetrics (WinCE frame values) |
| `coredll/dialog.cpp` | Dialog handler thunks + style map population |
| `coredll/dialog_template.cpp` | ComputeDlgTemplateSize, CopyDlgTemplate, FixupDlgTemplate |
| `callbacks_marshal.cpp` | CREATESTRUCT marshaling |
