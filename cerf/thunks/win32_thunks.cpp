#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "class_bridge.h"
#include "apiset.h"
#include "../log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <commctrl.h>
#include <shlobj.h>
#include <fstream>

/* Helper: parse key=value lines from an ini file */
static std::string IniGetVal(const std::string& line, const char* key) {
    size_t klen = strlen(key);
    if (line.size() > klen && line.substr(0, klen) == key) {
        std::string val = line.substr(klen);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
            val.pop_back();
        return val;
    }
    return "";
}
static bool IniIsTrue(const std::string& v) { return v == "true" || v == "1" || v == "yes"; }
static void IniParseDllList(const std::string& v, std::set<std::string>& out) {
    out.clear();
    size_t pos = 0;
    while (pos < v.size()) {
        size_t end = v.find(';', pos);
        if (end == std::string::npos) end = v.size();
        std::string dll = v.substr(pos, end - pos);
        while (!dll.empty() && dll.back() == ' ') dll.pop_back();
        while (!dll.empty() && dll.front() == ' ') dll.erase(dll.begin());
        if (!dll.empty()) {
            for (auto& c : dll) if (c >= 'A' && c <= 'Z') c += 32;
            out.insert(dll);
        }
        pos = end + 1;
    }
}

/* Load configuration — two-phase:
   1. Global cerf.ini next to cerf.exe — reads only device= selector
   2. devices/<device>/cerf.ini — reads all device-specific settings
   CLI overrides are applied in main.cpp after this returns. */
void Win32Thunks::LoadIniConfig(const char* device_override) {
    char cerf_path[MAX_PATH];
    ::GetModuleFileNameA(NULL, cerf_path, MAX_PATH);
    std::string cerf_str(cerf_path);
    size_t last_sep = cerf_str.find_last_of("\\/");
    cerf_dir = (last_sep != std::string::npos) ? cerf_str.substr(0, last_sep + 1) : "";

    /* Phase 1: global cerf.ini — only device= */
    std::string global_ini = cerf_dir + "cerf.ini";
    std::ifstream g(global_ini);
    if (g.is_open()) {
        std::string line;
        while (std::getline(g, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            std::string v = IniGetVal(line, "device=");
            if (!v.empty()) device_name = v;
        }
    }

    /* CLI --device= overrides global cerf.ini */
    if (device_override && device_override[0])
        device_name = device_override;

    /* Phase 2: device-specific config */
    LoadDeviceConfig();
}

/* Phase 2: load device-specific cerf.ini after device_name is finalized
   (CLI --device= override applied between LoadIniConfig and this call). */
void Win32Thunks::LoadDeviceConfig() {
    std::string device_ini = cerf_dir + "devices/" + device_name + "/cerf.ini";
    std::ifstream f(device_ini);
    if (!f.is_open()) {
        LOG(API, "[CFG] No device config: %s (using defaults)\n", device_ini.c_str());
        return;
    }
    LOG(API, "[CFG] Loading device config: %s\n", device_ini.c_str());

    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        std::string v;
        if (!(v = IniGetVal(line, "screen_width=")).empty()) { int n = atoi(v.c_str()); if (n > 0) screen_width = (uint32_t)n; }
        if (!(v = IniGetVal(line, "screen_height=")).empty()) { int n = atoi(v.c_str()); if (n > 0) screen_height = (uint32_t)n; }
        if (!(v = IniGetVal(line, "fake_screen_resolution=")).empty()) fake_screen_resolution = (v != "false" && v != "0" && v != "no");
        if (!(v = IniGetVal(line, "enable_theming=")).empty()) enable_theming = IniIsTrue(v);
        if (!(v = IniGetVal(line, "disable_uxtheme=")).empty()) disable_uxtheme = IniIsTrue(v);
        if (!(v = IniGetVal(line, "os_major=")).empty()) { int n = atoi(v.c_str()); if (n >= 0) os_major = (uint32_t)n; }
        if (!(v = IniGetVal(line, "os_minor=")).empty()) { int n = atoi(v.c_str()); if (n >= 0) os_minor = (uint32_t)n; }
        if (!(v = IniGetVal(line, "os_build=")).empty()) { int n = atoi(v.c_str()); if (n >= 0) os_build = (uint32_t)n; }
        if (!(v = IniGetVal(line, "os_build_date=")).empty()) os_build_date = v;
        if (!(v = IniGetVal(line, "fake_total_phys=")).empty()) { int n = atoi(v.c_str()); if (n > 0) fake_total_phys = (uint32_t)n; }
        if (!(v = IniGetVal(line, "boot_services=")).empty()) IniParseDllList(v, boot_service_dlls);
        if (!(v = IniGetVal(line, "init_blacklist=")).empty()) IniParseDllList(v, init_blacklist);
    }
}

/* On x64, Windows handles are 32-bit values sign-extended to 64-bit.
   When passing handles from ARM registers to native APIs, we must sign-extend
   (cast through int32_t -> intptr_t) rather than zero-extend (uintptr_t). */

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "imm32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")

std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return L"";
    std::wstring result;
    for (int i = 0; i < 4096; i++) {
        uint16_t ch = mem.Read16(addr + i * 2);
        if (ch == 0) break;
        result += (wchar_t)ch;
    }
    return result;
}

std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr) {
    if (addr == 0) return "";
    std::string result;
    for (int i = 0; i < 4096; i++) {
        uint8_t ch = mem.Read8(addr + i);
        if (ch == 0) break;
        result += (char)ch;
    }
    return result;
}

/* Wrap a native 64-bit HANDLE into a safe 32-bit value for ARM code.
   Uses per-process mapping tables so each process has isolated handles. */
uint32_t Win32Thunks::WrapHandle(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE) return (uint32_t)INVALID_HANDLE_VALUE;
    if (h == NULL) return 0;
    std::lock_guard<std::mutex> lock(handle_map_mutex_);
    ProcessSlot* slot = EmulatedMemory::process_slot;
    if (slot) {
        auto& state = per_process_handles_[slot];
        uint32_t fake = state.next_fake++;
        state.handle_map[fake] = h;
        return fake;
    }
    uint32_t fake = next_fake_handle++;
    handle_map[fake] = h;
    return fake;
}

HANDLE Win32Thunks::UnwrapHandle(uint32_t fake) {
    if (fake == (uint32_t)INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (fake == 0) return NULL;
    std::lock_guard<std::mutex> lock(handle_map_mutex_);
    ProcessSlot* slot = EmulatedMemory::process_slot;
    if (slot) {
        auto pit = per_process_handles_.find(slot);
        if (pit != per_process_handles_.end()) {
            auto it = pit->second.handle_map.find(fake);
            if (it != pit->second.handle_map.end()) return it->second;
        }
    }
    /* Check global map (orchestrator handles, or pre-process handles) */
    auto it = handle_map.find(fake);
    if (it != handle_map.end()) return it->second;
    /* Not in our map — fall back to sign-extension (for handles from other APIs) */
    return (HANDLE)(intptr_t)(int32_t)fake;
}

void Win32Thunks::RemoveHandle(uint32_t fake) {
    std::lock_guard<std::mutex> lock(handle_map_mutex_);
    ProcessSlot* slot = EmulatedMemory::process_slot;
    if (slot) {
        auto pit = per_process_handles_.find(slot);
        if (pit != per_process_handles_.end())
            pit->second.handle_map.erase(fake);
        return;
    }
    handle_map.erase(fake);
}

void Win32Thunks::EraseProcessHandles(ProcessSlot* slot) {
    std::lock_guard<std::mutex> lock(handle_map_mutex_);
    per_process_handles_.erase(slot);
}

/* ---- Thunk registration infrastructure ---- */

std::map<uint16_t, std::string> Win32Thunks::ordinal_map;

void Win32Thunks::Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler) {
    if (thunk_handlers.count(name))
        duplicate_thunks.push_back(name + " (ordinal " + std::to_string(ordinal) + ")");
    thunk_handlers[name] = std::move(handler);
    if (ordinal > 0)
        ordinal_map[ordinal] = name;
}

void Win32Thunks::Thunk(const std::string& name, ThunkHandler handler) {
    if (thunk_handlers.count(name))
        duplicate_thunks.push_back(name);
    thunk_handlers[name] = std::move(handler);
}

void Win32Thunks::CheckDuplicateThunks() {
    if (duplicate_thunks.empty()) return;
    LOG_ERR("\n");
    LOG_ERR("================================================================\n");
    LOG_ERR("  FATAL: %d DUPLICATE thunk registrations detected!\n", (int)duplicate_thunks.size());
    LOG_ERR("  The second registration silently overwrites the first.\n");
    LOG_ERR("  Fix each duplicate by removing one of the two Thunk() calls.\n");
    LOG_ERR("================================================================\n");
    for (auto& d : duplicate_thunks)
        LOG_ERR("  - %s\n", d.c_str());
    LOG_ERR("================================================================\n\n");
    CerfFatalExit(1);
}

void Win32Thunks::ThunkOrdinal(const std::string& name, uint16_t ordinal) {
    ordinal_map[ordinal] = name;
}

std::string Win32Thunks::ResolveOrdinal(uint16_t ordinal) {
    auto it = ordinal_map.find(ordinal);
    if (it != ordinal_map.end()) return it->second;
    char buf[32];
    sprintf(buf, "ordinal_%d", ordinal);
    return buf;
}

/* ---- Constructor ---- */

Win32Thunks::Win32Thunks(EmulatedMemory& mem)
    : mem(mem), next_thunk_addr(THUNK_BASE), emu_hinstance(0) {
    s_instance = this;
    class_bridge_ = new ClassBridge();
    api_sets_ = new ApiSetManager();
    /* Allocate a memory region for thunk return stubs */
    mem.Alloc(THUNK_BASE, 0x100000);
    /* Register all thunk handlers (map-based dispatch).
       All ordinals go into a single ordinal_map — coredll.dll is the only thunked DLL. */
    RegisterArmRuntimeHandlers();
    RegisterMemoryHandlers();
    RegisterCrtHandlers();
    RegisterStringHandlers();
    RegisterStringFormatHandlers();
    RegisterStringSafeHandlers();
    RegisterGdiDcHandlers();
    RegisterGdiDrawHandlers();
    RegisterGdiTextHandlers();
    RegisterGdiFontHandlers();
    /* InitWceSysFont() is deferred — it calls LoadRegistry() which needs
       device_dir, but that isn't set until InitVFS() runs after construction.
       It's called from InitVFS() instead. */
    RegisterGdiRegionHandlers();
    RegisterWindowHandlers();
    RegisterWindowLayoutHandlers();
    RegisterWindowPropsHandlers();
    RegisterWindowRectHandlers();
    RegisterDialogHandlers();
    RegisterMessageHandlers();
    RegisterMenuHandlers();
    RegisterInputHandlers();
    RegisterRegistryHandlers();
    RegisterFileHandlers();
    RegisterFileNotifyHandlers();
    RegisterSystemHandlers();
    RegisterSysInfoHandlers();
    RegisterLocaleHandlers();
    RegisterSyncHandlers();
    RegisterResourceHandlers();
    RegisterProcessHandlers();
    RegisterFileMappingHandlers();
    RegisterMiscHandlers();
    RegisterComHandlers();
    RegisterImageListHandlers();
    RegisterModuleHandlers();
    RegisterDpaHandlers();
    RegisterDsaHandlers();
    RegisterStdioHandlers();
    RegisterVfsHandlers();
    RegisterShellHandlers();
    RegisterShellExecHandler();
    RegisterWininetDepsHandlers();
    RegisterSocketHandlers();
    RegisterCrtExtraHandlers();
    RegisterGdiMiscHandlers();
    RegisterMiscMshtmlHandlers();
    RegisterDirectDrawHandlers();
    RegisterDirectDrawSurfaceHandlers();
    RegisterKernelApiHandlers();
    CheckDuplicateThunks();
    /* WinCE UserKData page at fixed address 0xFFFFC800.
       ARM code reads GetCurrentThreadId/GetCurrentProcessId directly from here
       (PUserKData[SH_CURTHREAD] at offset +4, PUserKData[SH_CURPROC] at offset +8).
       Without this, GetCurrentThreadId returns 0 → COMMCTRL g_CriticalSectionOwner
       assert fires on every entry (0 != 0 is false).

       KDataStruct layout (from nkarm.h):
         offset 0x000: lpvTls     — pointer to current thread's TLS slot array
         offset 0x004: ahSys[0]   — SH_WIN32
         offset 0x008: ahSys[1]   — SH_CURTHREAD (current thread handle)
         offset 0x00C: ahSys[2]   — SH_CURPROC (current process handle)

       TLS array layout: 7 pre-TLS DWORDs (negative indices) + 64 TLS slots.
       We place this at 0xFFFFC000 (start of the allocated page).
       lpvTls points to slot 0, which is at 0xFFFFC000 + 7*4 = 0xFFFFC01C. */
    mem.Alloc(0xFFFFC000, 0x1000);
    /* Zero out TLS array area (pre-TLS + 64 slots = 71 DWORDs = 284 bytes) */
    for (uint32_t i = 0; i < 71; i++)
        mem.Write32(0xFFFFC000 + i * 4, 0);
    /* lpvTls → slot 0 of the TLS array */
    uint32_t emu_tls_slots = 0xFFFFC000 + 7 * 4;  /* 0xFFFFC01C */
    mem.Write32(0xFFFFC800 + 0x000, emu_tls_slots);  /* lpvTls */
    mem.Write32(0xFFFFC800 + 0x004, GetCurrentThreadId());  /* ahSys[0] SH_WIN32 (compat) */
    mem.Write32(0xFFFFC800 + 0x008, GetCurrentThreadId());  /* ahSys[1] SH_CURTHREAD */
    mem.Write32(0xFFFFC800 + 0x00C, 1); /* ahSys[2] SH_CURPROC — orchestrator fake PID */
    LOG(EMU, "[EMU] KData TLS array at 0x%08X, lpvTls at 0xFFFFC800 -> 0x%08X\n",
        0xFFFFC000, emu_tls_slots);

    /* Register WinCE "Menu" system class — a horizontal menu bar inside CommandBar.
       On real WinCE this is provided by gwes.dll. We implement it with MenuBarWndProc.
       cbWndExtra = 3 pointers: HMENU at 0, hwndNotify at sizeof(LONG_PTR). */
    {
        WNDCLASSEXW wcx = {};
        wcx.cbSize = sizeof(wcx);
        wcx.style = CS_GLOBALCLASS;
        wcx.lpfnWndProc = MenuBarWndProc;
        wcx.hInstance = GetModuleHandleW(NULL);
        wcx.hCursor = LoadCursorW(NULL, IDC_ARROW);
        wcx.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
        wcx.cbWndExtra = 3 * sizeof(LONG_PTR);
        wcx.lpszClassName = L"Menu";
        ATOM a = RegisterClassExW(&wcx);
        LOG(API, "[API] Pre-register WinCE class 'Menu' -> atom=%d (err=%d)\n",
            a, a ? 0 : GetLastError());
    }
}

ClassBridge& Win32Thunks::GetClassBridge() { return *class_bridge_; }
ApiSetManager& Win32Thunks::GetApiSets() { return *api_sets_; }

Win32Thunks::CallbackExecutor Win32Thunks::GetCallbackExecutor() const {
    /* Per-thread executor takes priority — each ARM thread has its own CPU,
       stack, and register state. Using the wrong executor would corrupt state.
       Falls back to main thread executor if no thread context exists. */
    if (t_ctx && t_ctx->callback_executor)
        return t_ctx->callback_executor;
    return main_callback_executor;
}
