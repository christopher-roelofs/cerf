#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <atomic>
#include "../cpu/mem.h"
#include "../loader/pe_loader.h"
#include "thread_context.h"
#include "device_manager.h"

/* GDI handles are UNSIGNED 32-bit values that must be ZERO-extended to 64-bit.
   On 64-bit Windows, GDI handles regularly have bit 31 set (e.g., HDC 0xA9011628).
   Sign-extending these via (intptr_t)(int32_t) corrupts them to 0xFFFFFFFFxxxxxxxx
   instead of the correct 0x00000000xxxxxxxx, causing ERROR_INVALID_HANDLE (6).
   Window handles (HWND) rarely have bit 31 set and still use sign-extension. */
#define GDI_HDC(r)    ((HDC)(uintptr_t)(uint32_t)(r))
#define GDI_HRGN(r)   ((HRGN)(uintptr_t)(uint32_t)(r))
#define GDI_HBRUSH(r) ((HBRUSH)(uintptr_t)(uint32_t)(r))
#define GDI_HPEN(r)   ((HPEN)(uintptr_t)(uint32_t)(r))
#define GDI_HFONT(r)  ((HFONT)(uintptr_t)(uint32_t)(r))
#define GDI_HBMP(r)   ((HBITMAP)(uintptr_t)(uint32_t)(r))
#define GDI_HPAL(r)   ((HPALETTE)(uintptr_t)(uint32_t)(r))
#define GDI_OBJ(r)    ((HGDIOBJ)(uintptr_t)(uint32_t)(r))

/* Thunked DLL registry — add one entry here, then create Register*Handlers(). */
struct ThunkedDllInfo {
    const char* name;          /* lowercase key (e.g. "coredll") */
    uint32_t    fake_handle;   /* returned by GetModuleHandle/LoadLibrary */
};
extern const ThunkedDllInfo thunked_dlls[];
extern const size_t thunked_dlls_count;
const ThunkedDllInfo* FindThunkedDll(const std::string& dll_name);   /* case-insensitive substring */
const ThunkedDllInfo* FindThunkedDllW(const std::wstring& dll_name); /* wide version */

/* Thunk address range (0xF000xxxx reserved for WinCE kernel trap API calls) */
#define THUNK_BASE   0xFE000000
#define THUNK_STRIDE 4
#define WINCE_SCREEN_WIDTH_DEFAULT   800

/* explorer.exe ARM function address for SHCreateExplorerInstance.
   IDA address 0x0001A120, explorer loads at its natural base 0x00010000. */
constexpr uint32_t EXPLORER_SHCREATEEXPLORERINSTANCE = 0x0001A120;

/* Kernel IPC message for cross-thread SHBrowseToURL dispatch.
   Sent via SendMessage from a child process thread to the main explorer's
   desktop window. The main thread's EmuWndProc calls SHCreateExplorerInstance
   in its own ARM context. WPARAM = ARM address of URL string. */
/* (Removed: WM_CERF_KERNEL_BROWSE — API set dispatch handles this now) */
#define WINCE_SCREEN_HEIGHT_DEFAULT  480
/* WinCE trap-based API range: index = (0xF0010000 - addr) / 4 */
#define WINCE_TRAP_BASE  0xF0000000
#define WINCE_TRAP_TOP   0xF0010000

struct ThunkEntry {
    std::string dll_name;
    std::string func_name;
    uint16_t    ordinal;
    bool        by_ordinal;
    uint32_t    thunk_addr;
};

std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr);
std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr);
bool IsArmPE(const std::wstring& host_path); /* Check if file is ARM PE (WinCE) */

class Win32Thunks {
public:
    Win32Thunks(EmulatedMemory& mem);
    void InstallThunks(PEInfo& info, const char* module_name = "");  /* Replace IAT entries with thunk addresses */
    void CallDllEntryPoints();             /* Call DllMain for loaded ARM DLLs */
    bool HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem);

    void SetHInstance(uint32_t hinst) { emu_hinstance = hinst; }
    /* Get the effective hInstance for the current thread.
       Per-thread value (from child process) takes priority over global. */
    uint32_t GetEmuHInstance() const { return t_emu_hinstance ? t_emu_hinstance : emu_hinstance; }
    void SetExePath(const std::wstring& path) { exe_path = path; }
    void SetExeDir(const std::string& dir) { exe_dir = dir; }
    const std::string& GetDeviceName() const { return device_name; }

    /* Trace manager for ARM instruction-level tracing */
    void SetTraceManager(class TraceManager* tm) { trace_mgr_ = tm; }
    void ActivateTracesForLoadedDlls(class TraceManager& tm);
    void StartBootServices(EmulatedMemory& mem);
    void RunPerProcessDllInit();
    class TraceManager* GetTraceManager() const { return trace_mgr_; }

    void LoadIniConfig();
    void InitVFS(const std::string& device_override = "");

    /* Callback executor: executes ARM code from native context.
       Each thread has its own executor (own CPU/stack/registers).
       The main_callback_executor is set for the main thread during init.
       All call sites use callback_executor which auto-resolves to the
       current thread's executor, falling back to main if no thread context. */
    typedef std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)> CallbackExecutor;
    CallbackExecutor main_callback_executor; /* main thread only — set in main.cpp */

    /* Returns the correct executor for the CURRENT thread */
    CallbackExecutor GetCallbackExecutor() const;

    /* Legacy name — kept as a property-like accessor so existing code compiles.
       All 61+ call sites that use `callback_executor` now get the right executor. */
    __declspec(property(get=GetCallbackExecutor)) CallbackExecutor callback_executor;

    /* TLS slot allocation moved to ProcessSlot::AllocTlsSlot() (per-process bitmask) */
    std::map<uint32_t, CRITICAL_SECTION*> cs_map; /* ARM CS addr -> native CS* */
    std::mutex cs_map_mutex;

    std::map<std::wstring, std::map<ProcessSlot*, uint32_t>> arm_wndprocs; /* class name -> {slot -> ARM WndProc} */
    static std::map<HWND, uint32_t> hwnd_wndproc_map;          /* HWND -> ARM WndProc */
    static std::map<HWND, WNDPROC> hwnd_native_wndproc_map;   /* HWND -> saved native WndProc before EmuWndProc subclass */
    static std::map<UINT_PTR, uint32_t> arm_timer_callbacks;   /* timer ID -> ARM TIMERPROC */
    static std::map<HWND, uint32_t> hwnd_dlgproc_map;          /* HWND -> ARM DlgProc */
    static uint32_t pending_arm_dlgproc;   /* stashed for CreateDialogIndirectParamW */
    /* Original WinCE window styles — stored per-HWND because we convert top-level
       windows to WS_POPUP on desktop, but ARM code needs to see original styles. */
    static std::map<HWND, uint32_t> hwnd_wce_style_map;
    static std::map<HWND, uint32_t> hwnd_wce_exstyle_map;
    static std::map<HWND, ProcessSlot*> hwnd_slot_map; /* HWND -> owning ProcessSlot */
    /* Thread-local pending WinCE styles for CreateWindowExW → EmuWndProc handoff.
       Set before ::CreateWindowExW, consumed during WM_NCCREATE in EmuWndProc. */
    static thread_local uint32_t tls_pending_wce_style;
    static thread_local uint32_t tls_pending_wce_exstyle;
    static std::set<HWND> captionok_hwnds; /* WS_EX_CAPTIONOKBTN tracking */
    static INT_PTR modal_dlg_result;
    static bool modal_dlg_ended;
    static Win32Thunks* s_instance;
    static thread_local HWND tls_paint_hwnd; /* last WM_PAINT target per thread */
    std::vector<uint32_t> setjmp_stack;    /* RaiseException recovery */

    /* ARM SEH dispatch — walks .pdata with prologue-based unwinding.
       Implementation in seh_dispatch.cpp. Internal helpers use LoadedDll
       but are declared there, not here, to avoid forward-decl issues. */
    bool SehDispatch(uint32_t* regs, EmulatedMemory& mem,
        uint32_t exc_code, uint32_t exc_flags);
    /* Set by SehDispatch when no handler is found — the final unwound
       PC and SP from the stack walk. Used by RaiseException to unwind
       to the callback_executor boundary without scanning for magic values. */
    uint32_t last_unhandled_sp = 0;
    uint32_t last_unhandled_pc = 0;

    static LRESULT CALLBACK EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MenuBarWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static void InstallCaptionOk(HWND hwnd);
    static void RemoveCaptionOk(HWND hwnd);
private:
    static LRESULT CALLBACK CaptionOkSubclassProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

    EmulatedMemory& mem;
    std::map<uint32_t, ThunkEntry> thunks;   /* thunk_addr -> entry */
    std::recursive_mutex thunks_mutex; /* protects thunks map (AllocThunk/HandleThunk) */
    uint32_t next_thunk_addr;
    uint32_t emu_hinstance;
    std::wstring exe_path;
    /* Kernel API Set system (CreateAPISet/RegisterAPISet) */
    class ApiSetManager& GetApiSets();
private:
    class ApiSetManager* api_sets_ = nullptr;
public:
    std::string exe_dir;
    std::string wince_sys_dir;

    /* WinCE system font (from HKLM\System\GDI\SYSFNT) */
    std::wstring wce_sysfont_name = L"Tahoma";
    LONG wce_sysfont_height = -12;
    LONG wce_sysfont_weight = FW_NORMAL;
    void InitWceSysFont();

public:
    /* Emulated screen resolution (from cerf.ini) */
    bool fake_screen_resolution = true;
    uint32_t screen_width  = WINCE_SCREEN_WIDTH_DEFAULT;
    uint32_t screen_height = WINCE_SCREEN_HEIGHT_DEFAULT;
    /* Emulated work area — initially full screen, reduced by SPI_SETWORKAREA
       when the shell (taskbar) reserves space.  {0,0,0,0} = use full screen. */
    RECT work_area = {};
    RECT GetWorkArea() const {
        if (work_area.right > 0 || work_area.bottom > 0) return work_area;
        return {0, 0, (LONG)screen_width, (LONG)screen_height};
    }
    /* Emulated WinCE OS version */
    uint32_t os_major = 5;
    uint32_t os_minor = 0;
    uint32_t os_build = 1;
    std::string os_build_date = "Jan  1 2008";
    uint32_t fake_total_phys = 0;  /* fake memory; 0 = use real host memory */
    std::set<std::string> boot_service_dlls; /* from cerf.ini boot_services= */
    std::set<std::string> init_blacklist;   /* from cerf.ini init_blacklist= */
    DeviceManager device_mgr; /* stream device driver manager (RegisterDevice etc.) */
    /* WinCE theming */
    bool enable_theming = false;
    bool disable_uxtheme = false;
    void InitWceTheme();
    void ApplyWindowTheme(HWND hwnd, bool is_toplevel);
    void UpdateWceThemeColor(int index, COLORREF color);
    COLORREF GetWceThemeColor(int index);
    HBRUSH GetWceThemeBrush(int index);

private:
    /* Virtual filesystem device paths */
    std::string cerf_dir;
    std::string device_name;
    std::string device_fs_root;
    std::string device_dir;
    class TraceManager* trace_mgr_ = nullptr;

public:
    /* Centralized ARM↔Native class attribute bridge.
       ALL class/window attribute code MUST use this. See class_bridge.h. */
    class ClassBridge& GetClassBridge();
private:
    class ClassBridge* class_bridge_ = nullptr;

    /* DLL loader and resource types — in win32_dll_types.h */
#include "win32_dll_types.h"
public:
    LoadedDll* FindLoadedDll(const std::wstring& name_lower);
private:

    /* Ordinal to function name mapping */
    static std::map<uint16_t, std::string> ordinal_map;
    std::string ResolveOrdinal(uint16_t ordinal);

    uint32_t AllocThunk(const std::string& dll, const std::string& func, uint16_t ordinal, bool by_ordinal);
    bool ExecuteThunk(ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem);
    uint32_t ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index);
    HMODULE GetNativeModuleForResources(uint32_t emu_handle);

    /* Handle mapping + DIB tracking — declarations in win32_handles.h */
#include "win32_handles.h"

    std::wstring MapWinCEPath(const std::wstring& wce_path);
    std::wstring MapHostToWinCE(const std::wstring& host_path);

public:
    /* Emulated registry types and private members — in win32_registry_types.h */
#include "win32_registry_types.h"

    /* Map-based thunk dispatch */
    typedef std::function<bool(uint32_t* regs, EmulatedMemory& mem)> ThunkHandler;
    std::map<std::string, ThunkHandler> thunk_handlers;
    void Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler);
    void Thunk(const std::string& name, ThunkHandler handler);
    void ThunkOrdinal(const std::string& name, uint16_t ordinal);
    std::vector<std::string> duplicate_thunks;
    void CheckDuplicateThunks();

    /* Handler registration (each in its own .cpp file) */
    void RegisterArmRuntimeHandlers();
    void RegisterMemoryHandlers();
    void RegisterCrtHandlers();
    void RegisterCrtMemoryHandlers();
    void RegisterStringHandlers();
    void RegisterStringFormatHandlers();
    void RegisterStringSafeHandlers();
    std::wstring WprintfFormat(EmulatedMemory& mem, const std::wstring& fmt, uint32_t* args, int nargs);
    void RegisterGdiDcHandlers();
    void RegisterGdiDrawHandlers();
    void RegisterGdiTextHandlers();
    void RegisterGdiFontHandlers();
    void RegisterGdiRegionHandlers();
    void RegisterGdiPaintHandlers();
    void RegisterWindowHandlers();
    void RegisterWindowLayoutHandlers();
    void RegisterWindowPropsHandlers();
    void RegisterDialogHandlers();
    void RegisterMessageHandlers();
    void RegisterMessageWaitHandlers();
    void RegisterMenuHandlers();
    void RegisterInputHandlers();
    void RegisterRegistryHandlers();
    void RegisterFileHandlers();
    void RegisterFileTimeHandlers();
    void RegisterFileNotifyHandlers();
    void RegisterSystemHandlers();
    void RegisterSysInfoHandlers();
    void RegisterLocaleHandlers();
    void RegisterSyncHandlers();
    void RegisterResourceHandlers();
    void RegisterResourceExtractHandlers();
    void RegisterShellHandlers();
    void RegisterProcessHandlers();
    void RegisterChildProcessHandler();
    void RegisterFileMappingHandlers();
    void RegisterMiscHandlers();
    void RegisterComHandlers();
    void RegisterImageListHandlers();
    void RegisterModuleHandlers();
    void RegisterDpaHandlers();
    void RegisterDsaHandlers();
    void RegisterStdioHandlers();
    void RegisterDeviceIoHandlers();
    void RegisterKernelApiHandlers();
    void RegisterVfsHandlers();
    void RegisterShellExecHandler();
    void RegisterWininetDepsHandlers();
    void RegisterSocketHandlers();
    void RegisterSocketIOHandlers();
    void RegisterSocketDnsHandlers();
    void RegisterWindowRectHandlers();
    void RegisterWindowClassHandlers();
    void RegisterCrtExtraHandlers();
    void RegisterGdiMiscHandlers();
    void RegisterMiscUiHandlers();
    void RegisterMiscMshtmlHandlers();
public:
    void RegisterDirectDrawHandlers();
    void RegisterDirectDrawSurfaceHandlers();
    void BuildDirectDrawVtables(EmulatedMemory& mem);
    bool LaunchArmChildProcess(const std::wstring& mapped_file, const std::wstring& params,
                               uint32_t sei_addr, uint32_t* regs, EmulatedMemory& mem);
    void ProcessInitHive(EmulatedMemory& mem);
    std::wstring ResolveExePath(const std::string& input);
};
