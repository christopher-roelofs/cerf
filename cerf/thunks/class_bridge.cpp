#include "class_bridge.h"
#include "../cpu/mem.h"
#include <algorithm>

std::wstring ClassBridge::NormalizeName(const std::wstring& name) {
    std::wstring s = name;
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

/* --- Class registration --- */

void ClassBridge::RegisterClass(const std::wstring& className, const ArmClassInfo& info) {
    class_map_[{NormalizeName(className), EmulatedMemory::process_slot}] = info;
}

const ArmClassInfo* ClassBridge::GetClassInfo(const std::wstring& className) const {
    return GetClassInfo(className, EmulatedMemory::process_slot);
}

const ArmClassInfo* ClassBridge::GetClassInfo(const std::wstring& className, ProcessSlot* slot) const {
    auto norm = NormalizeName(className);
    auto it = class_map_.find({norm, slot});
    if (it != class_map_.end()) return &it->second;
    return nullptr;
}

const ArmClassInfo* ClassBridge::GetClassInfoForHwnd(HWND hwnd) const {
    wchar_t cls[128] = {};
    GetClassNameW(hwnd, cls, 128);
    return GetClassInfo(cls);
}

const ArmClassInfo* ClassBridge::GetClassInfoForHwnd(HWND hwnd,
    const std::map<HWND, ProcessSlot*>& hwnd_slot_map) const
{
    wchar_t cls[128] = {};
    GetClassNameW(hwnd, cls, 128);
    /* Resolve owning slot from hwnd_slot_map */
    ProcessSlot* owner = EmulatedMemory::process_slot;
    auto sit = hwnd_slot_map.find(hwnd);
    if (sit != hwnd_slot_map.end()) owner = sit->second;
    return GetClassInfo(cls, owner);
}

/* --- Per-window state --- */

void ClassBridge::SetWindowInfo(HWND hwnd, const ArmWindowInfo& info) {
    window_map_[hwnd] = info;
}

ArmWindowInfo* ClassBridge::GetWindowInfo(HWND hwnd) {
    auto it = window_map_.find(hwnd);
    return it != window_map_.end() ? &it->second : nullptr;
}

const ArmWindowInfo* ClassBridge::GetWindowInfo(HWND hwnd) const {
    auto it = window_map_.find(hwnd);
    return it != window_map_.end() ? &it->second : nullptr;
}

void ClassBridge::RemoveWindow(HWND hwnd) {
    window_map_.erase(hwnd);
}

/* --- ARM → Native translations --- */

HBRUSH ClassBridge::TranslateBrushToNative(uint32_t arm_brush) {
    if (arm_brush == 0) return NULL;
    uint32_t brush_val = arm_brush & 0x3FFFFFFF; /* strip WinCE sys color flag */
    if (brush_val > 0 && brush_val <= 31) {
        /* COLOR_xxx+1 constants. Map WinCE-only values to desktop equivalents. */
        constexpr uint32_t WINCE_COLOR_STATIC = 26;
        constexpr uint32_t WINCE_COLOR_STATICTEXT = 27;
        if (brush_val == WINCE_COLOR_STATIC)
            brush_val = COLOR_3DFACE + 1;
        else if (brush_val == WINCE_COLOR_STATICTEXT)
            brush_val = COLOR_WINDOWTEXT + 1;
        return (HBRUSH)(uintptr_t)brush_val;
    }
    /* GDI handle: sign-extend 32-bit → 64-bit */
    return (HBRUSH)(intptr_t)(int32_t)arm_brush;
}

UINT ClassBridge::TranslateStyleToNative(uint32_t arm_style) {
    return arm_style | CS_OWNDC; /* WinCE persistent DC behavior */
}

/* --- Native → ARM translations --- */

uint32_t ClassBridge::GetArmWndProc(HWND hwnd) const {
    /* Per-window override first */
    auto* winfo = GetWindowInfo(hwnd);
    if (winfo && winfo->arm_wndproc) return winfo->arm_wndproc;
    /* Fall back to per-class */
    auto* cinfo = GetClassInfoForHwnd(hwnd);
    if (cinfo) return cinfo->arm_wndproc;
    return 0;
}

uint32_t ClassBridge::GetArmClassStyle(HWND hwnd) const {
    auto* cinfo = GetClassInfoForHwnd(hwnd);
    return cinfo ? cinfo->arm_style : (uint32_t)::GetClassLongW(hwnd, GCL_STYLE);
}

uint32_t ClassBridge::GetArmBrush(HWND hwnd) const {
    auto* cinfo = GetClassInfoForHwnd(hwnd);
    return cinfo ? cinfo->arm_brush : (uint32_t)(uintptr_t)::GetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND);
}
