/* CERF - Windows CE Runtime Foundation
 * Orchestrator: sets up global emulated memory and thunks, launches boot services,
 * processes HKLM\init, and runs user-specified executables as child processes.
 * All ARM execution happens in child threads via LaunchArmChildProcess.
 *
 * Usage:
 *   cerf.exe                     Boot from HKLM\init (full WinCE boot)
 *   cerf.exe explorer.exe        Launch specific app (with init sequence)
 *   cerf.exe --no-init app.exe   Launch app directly (skip HKLM\init) */

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

#include "log.h"
#include "cpu/mem.h"
#include "cpu/arm_cpu.h"
#include "debugger/gdb_stub.h"
#include "tracing/trace_manager.h"
#include "tracing/register_all.h"
#include "loader/pe_loader.h"
#include "thunks/win32_thunks.h"
#include "cli_helpers.h"
#include "main_config.h"
#include "patches.h"
#include "boot_screen.h"

int main(int argc, char* argv[]) {
    CerfConfig cfg;
    Log::Init();

    if (!ParseCerfArgs(argc, argv, cfg))
        return 0; /* --help was requested */

    LOG_RAW("=== CERF - Windows CE Runtime Foundation ===\n");
    if (cfg.exe_path)
        LOG_RAW("Target: %s\n\n", cfg.exe_path);
    else
        LOG_RAW("Booting from HKLM\\init\n\n");

    /* Initialize emulated memory (global, shared across all processes) */
    EmulatedMemory mem;

    /* Set up thunks (no EXE loaded yet — orchestrator mode) */
    Win32Thunks thunks(mem);

    /* Load config and apply CLI overrides — need screen dimensions for boot screen */
    thunks.LoadIniConfig();
    if (cfg.cli_fake_screen_resolution >= 0)
        thunks.fake_screen_resolution = (cfg.cli_fake_screen_resolution != 0);
    if (cfg.cli_screen_width > 0)
        thunks.screen_width = (uint32_t)cfg.cli_screen_width;
    if (cfg.cli_screen_height > 0)
        thunks.screen_height = (uint32_t)cfg.cli_screen_height;
    if (cfg.cli_os_major >= 0) thunks.os_major = (uint32_t)cfg.cli_os_major;
    if (cfg.cli_os_minor >= 0) thunks.os_minor = (uint32_t)cfg.cli_os_minor;
    if (cfg.cli_os_build >= 0) thunks.os_build = (uint32_t)cfg.cli_os_build;
    if (cfg.cli_os_build_date) thunks.os_build_date = cfg.cli_os_build_date;
    if (cfg.cli_fake_total_phys > 0) thunks.fake_total_phys = (uint32_t)cfg.cli_fake_total_phys;

    /* Boot screen — threaded, appears immediately after config */
    BootScreen boot;
    boot.Create((int)thunks.screen_width, (int)thunks.screen_height);
    thunks.boot_screen = &boot;
    boot.Step("Initializing...");

    /* Initialize virtual filesystem — device paths */
    boot.Step("Loading virtual filesystem...");
    thunks.InitVFS(cfg.device_override ? cfg.device_override : "");

    /* System font and theming (reads registry, patches GetSysColor) */
    boot.Step("Loading system fonts...");
    thunks.InitWceSysFont();
    thunks.InitWceTheme();

    /* Shared memory, thread context, ARM CPU, callback executors */
    boot.Step("Initializing emulator...");
    uint32_t cb_sentinel = 0xCAFEC000;
    mem.Alloc(cb_sentinel, 0x1000);
    mem.Write32(cb_sentinel, 0xE12FFF1E); /* BX LR — safety net */
    mem.Alloc(0x20000000, 0x01000000);    /* WinCE shared memory area (OLE32) */
    mem.Reserve(0x3E000000, 0x00100000);  /* fake Process/Thread structs for KData */
    mem.Reserve(0x3F000000, 0x00100000);  /* marshal buffer space, up to 16 threads */

    /* Orchestrator's fake PROCESS struct (procnum 0) at 0x3E000000 */
    mem.Alloc(0x3E000000, 0x100);
    PopulateProcessStruct(mem, 0x3E000000, 0, 1, 0, "cerf");

    /* Set up main thread context (needed for callback executor trampoline).
       The main thread does NOT run ARM code directly — it just orchestrates. */
    ThreadContext main_ctx;
    main_ctx.marshal_base = 0x3F000000;
    ArmCpu& cpu = main_ctx.cpu;
    cpu.mem = &mem;
    cpu.trace = cfg.trace;
    cpu.thunk_handler = [&thunks](uint32_t addr, uint32_t* regs,
                                   EmulatedMemory& m) -> bool {
        if (addr == 0xCAFEC000) { regs[15] = 0xCAFEC000; return true; }
        return thunks.HandleThunk(addr, regs, m);
    };

    /* ARM trace point system — per-DLL, auto-rebased, checksum-gated */
    TraceManager trace_mgr;
    RegisterTracesForDevice(thunks.GetDeviceName(), trace_mgr);
    cpu.traces = &trace_mgr;
    thunks.SetTraceManager(&trace_mgr);

    /* KData page for main thread */
    uint8_t* shared_kdata = mem.Translate(0xFFFFC000);
    if (shared_kdata) memcpy(main_ctx.kdata, shared_kdata, 0x1000);
    t_ctx = &main_ctx;
    EmulatedMemory::kdata_override = main_ctx.kdata;

    mem.Alloc(main_ctx.marshal_base, 0x10000);
    MakeCallbackExecutor(&main_ctx, mem, thunks, cb_sentinel);

    snprintf(main_ctx.process_name, sizeof(main_ctx.process_name), "cerf");
    Log::SetProcessName(main_ctx.process_name, GetCurrentThreadId());

    /* Trampoline: thunk handlers use callback_executor which delegates
       to the current thread's real executor via t_ctx. */
    thunks.main_callback_executor = [](uint32_t addr, uint32_t* args, int nargs) -> uint32_t {
        if (!t_ctx || !t_ctx->callback_executor) return 0;
        return t_ctx->callback_executor(addr, args, nargs);
    };

    /* Wire up device manager's callback executor */
    thunks.device_mgr.SetCallbackExecutor(
        [](uint32_t addr, uint32_t* args, int nargs) -> uint32_t {
            if (!t_ctx || !t_ctx->callback_executor) return 0;
            return t_ctx->callback_executor(addr, args, nargs);
        });

    /* Load registry before boot services (was inside StartBootServices) */
    boot.Step("Loading registry...");
    thunks.LoadRegistry();

    /* Start device.exe (boot services: lpcd, dcomssd, etc.) */
    boot.Step("Loading drivers data...");
    thunks.StartBootServices(mem);

    ApplyRuntimePatches(mem);

    /* GDB remote debugging */
    GdbStub* gdb = nullptr;
    if (cfg.gdb_port > 0) {
        gdb = new GdbStub((uint16_t)cfg.gdb_port, &mem);
        if (!gdb->Start()) {
            LOG_ERR("[GDB] Failed to start debug server on port %d\n", cfg.gdb_port);
            delete gdb;
            gdb = nullptr;
        } else {
            g_debugger = gdb;
        }
    }

    /* Process HKLM\init boot sequence (unless --no-init) */
    if (!cfg.no_init) {
        boot.Step("Loading init data...");
        thunks.ProcessInitHive(mem);
    }

    boot.ScheduleDestroy(10000);

    /* Launch user-specified exe (if any) */
    if (cfg.exe_path) {
        boot.Step("Launching user executable...");
        std::wstring resolved = thunks.ResolveExePath(cfg.exe_path);
        LOG(EMU, "[EMU] Launching: %ls\n", resolved.c_str());

        /* Set exe_dir for DLL search (app-bundled DLLs) */
        {
            std::string narrow;
            for (auto c : resolved) narrow += (char)c;
            size_t last_sep = narrow.find_last_of("\\/");
            if (last_sep != std::string::npos)
                thunks.SetExeDir(narrow.substr(0, last_sep + 1));
            thunks.SetExePath(resolved);
        }

        /* Build cmdline from args after exe_path */
        std::wstring cmdline;
        bool found_exe = false;
        for (int i = 1; i < argc; i++) {
            if (!found_exe && argv[i] == cfg.exe_path) {
                found_exe = true;
                continue;
            }
            if (!found_exe) continue;
            if (!cmdline.empty()) cmdline += L' ';
            for (const char* p = argv[i]; *p; p++)
                cmdline += (wchar_t)*p;
        }

        thunks.LaunchArmChildProcess(resolved, cmdline, 0, nullptr, mem);
    } else if (cfg.no_init) {
        LOG_ERR("No exe specified and --no-init set. Nothing to run.\n");
        PrintUsage(argv[0]);
        if (gdb) { g_debugger = nullptr; delete gdb; }
        Log::Close();
        return 1;
    }

    boot.Step("");

    /* Wait for all child processes with message pump */
    LOG(EMU, "[EMU] Orchestrator waiting for child processes...\n");
    WaitForChildThreads();

    /* Keep pumping messages for any remaining windows */
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    boot.Destroy();
    thunks.boot_screen = nullptr;

    if (gdb) {
        g_debugger = nullptr;
        delete gdb;
    }

    Log::Close();
    return 0;
}
