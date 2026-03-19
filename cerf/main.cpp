/* CERF - Windows CE Runtime Foundation
 * Loads WinCE ARM executables on x64 desktop via ARM interpretation + API thunking.
 * Usage: cerf.exe <path-to-arm-wince-exe> */

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

int main(int argc, char* argv[]) {
    CerfConfig cfg;
    Log::Init();

    if (!ParseCerfArgs(argc, argv, cfg))
        return 0; /* --help was requested */

    const char* exe_path = cfg.exe_path;
    if (!exe_path) {
        PrintUsage(argv[0]);
        return 1;
    }

    LOG_RAW("=== CERF - Windows CE Runtime Foundation ===\n");
    LOG_RAW("Loading: %s\n\n", exe_path);

    /* Initialize emulated memory */
    EmulatedMemory mem;

    /* Load the PE file */
    PEInfo pe_info = {};
    uint32_t entry_point = PELoader::Load(exe_path, mem, pe_info);
    if (entry_point == 0) {
        LOG_ERR("Failed to load PE file\n");
        LOG_ERR("WinCE apps are in references/ dir, not the build dir.\n");
        LOG_ERR("Usage: cd build/Release/x64 && ./cerf.exe ../../../references/<app.exe>\n");
        return 1;
    }

    /* Verify it's ARM */
    if (pe_info.machine != 0x01C0 && pe_info.machine != 0x01C2) {
        LOG_ERR("Not an ARM executable (machine=0x%04X)\n", pe_info.machine);
        return 1;
    }

    LOG(EMU, "\n[EMU] ARM %s detected (machine=0x%04X)\n",
           pe_info.machine == 0x01C2 ? "Thumb" : "32-bit",
           pe_info.machine);

    /* Set up thunks */
    Win32Thunks thunks(mem);
    thunks.SetHInstance(pe_info.image_base);

    /* Convert exe path to wide string */
    std::wstring wide_path;
    for (const char* p = exe_path; *p; p++) wide_path += (wchar_t)*p;
    thunks.SetExePath(wide_path);

    /* Extract directory from exe path */
    std::string exe_dir;
    {
        std::string path_str(exe_path);
        size_t last_sep = path_str.find_last_of("\\/");
        if (last_sep != std::string::npos)
            exe_dir = path_str.substr(0, last_sep + 1);
    }
    thunks.SetExeDir(exe_dir);

    /* Initialize virtual filesystem — reads cerf.ini, sets up device paths.
       This also sets wince_sys_dir for ARM DLL loading. */
    thunks.InitVFS(cfg.device_override ? cfg.device_override : "");

    /* CLI overrides take priority over cerf.ini */
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

    /* Install import thunks */
    thunks.InstallThunks(pe_info, exe_path);

    /* Allocate stack */
    uint32_t stack_top = mem.AllocStack();

    /* Initialize main thread context */
    ThreadContext main_ctx;
    main_ctx.marshal_base = 0x3F000000;
    ArmCpu& cpu = main_ctx.cpu;
    cpu.mem = &mem;
    cpu.trace = cfg.trace;

    /* ARM trace point system — per-DLL, auto-rebased, checksum-gated */
    TraceManager trace_mgr;
    RegisterTracesForDevice(thunks.GetDeviceName(), trace_mgr);
    cpu.traces = &trace_mgr;
    thunks.SetTraceManager(&trace_mgr);

    /* Activate traces for the main EXE (it's loaded by PELoader::Load, not LoadArmDll,
       so the OnDllLoad hook in dll_loader.cpp doesn't fire for it) */
    trace_mgr.OnDllLoad(exe_path, exe_path, pe_info.image_base);

    /* Set up initial register state */
    cpu.r[REG_SP] = stack_top;
    cpu.r[REG_LR] = 0xDEADDEAD; /* Sentinel return address */
    cpu.r[REG_PC] = entry_point;

    /* Set up entry point arguments (WinMain style):
       R0 = hInstance
       R1 = hPrevInstance (always NULL)
       R2 = lpCmdLine (empty string)
       R3 = nCmdShow (SW_SHOW = 5) */
    cpu.r[0] = pe_info.image_base;  /* hInstance */
    cpu.r[1] = 0;                    /* hPrevInstance */

    /* Build lpCmdLine from arguments after exe_path */
    uint32_t cmdline_addr = 0x60000000;
    mem.Alloc(cmdline_addr, 0x1000);
    {
        std::wstring cmdline_str;
        bool found_exe = false;
        for (int i = 1; i < argc; i++) {
            if (!found_exe && argv[i] == exe_path) {
                found_exe = true;
                continue;
            }
            if (!found_exe) continue; /* skip options before exe_path */
            if (!cmdline_str.empty()) cmdline_str += L' ';
            for (const char* p = argv[i]; *p; p++)
                cmdline_str += (wchar_t)*p;
        }
        /* Write wide string to emulated memory */
        for (size_t j = 0; j < cmdline_str.size() && j < 0x7FE; j++)
            mem.Write16(cmdline_addr + (uint32_t)(j * 2), (uint16_t)cmdline_str[j]);
        mem.Write16(cmdline_addr + (uint32_t)(cmdline_str.size() * 2), 0);
    }
    cpu.r[2] = cmdline_addr;
    cpu.r[3] = 1; /* SW_SHOWNORMAL */

    /* Determine initial mode (ARM or Thumb) based on entry point bit 0.
       Machine type 0x01C2 (IMAGE_FILE_MACHINE_THUMB) means the binary supports
       Thumb instructions, but the entry point itself may be ARM or Thumb —
       bit 0 of the address determines the mode (standard ARM interworking). */
    if (entry_point & 1) {
        cpu.cpsr |= PSR_T;
        cpu.r[REG_PC] = entry_point & ~1u;
    }

    cpu.thunk_handler = [&thunks](uint32_t addr, uint32_t* regs, EmulatedMemory& mem_ref) -> bool {
        if (addr == 0xDEADDEAD) {
            LOG(EMU, "\n[EMU] Program returned from entry point with code %d\n", regs[0]);
            CerfFatalExit(regs[0]);
            return true;
        }
        if (addr == 0xCAFEC000) { regs[15] = 0xCAFEC000; return true; }
        return thunks.HandleThunk(addr, regs, mem_ref);
    };

    uint32_t cb_sentinel = 0xCAFEC000;
    mem.Alloc(cb_sentinel, 0x1000);
    mem.Write32(cb_sentinel, 0xE12FFF1E); /* BX LR — safety net */

    mem.Alloc(0x20000000, 0x01000000);  /* WinCE shared memory area (OLE32) */
    mem.Reserve(0x3F000000, 0x00100000); /* marshal buffer space, up to 16 threads */
    MakeCallbackExecutor(&main_ctx, mem, thunks, cb_sentinel);
    /* Copy shared KData page into main thread's per-thread buffer */
    uint8_t* shared_kdata = mem.Translate(0xFFFFC000);
    if (shared_kdata) memcpy(main_ctx.kdata, shared_kdata, 0x1000);
    t_ctx = &main_ctx;
    EmulatedMemory::kdata_override = main_ctx.kdata;

    /* Set process name for log lines (extract filename from path) */
    {
        const char* fname = strrchr(exe_path, '/');
        if (!fname) fname = strrchr(exe_path, '\\');
        fname = fname ? fname + 1 : exe_path;
        snprintf(main_ctx.process_name, sizeof(main_ctx.process_name), "%s", fname);
        Log::SetProcessName(main_ctx.process_name, GetCurrentThreadId());
    }

    /* Set up the trampoline: thunk handlers use this->callback_executor which
       delegates to the current thread's real callback_executor via t_ctx. */
    thunks.main_callback_executor = [](uint32_t addr, uint32_t* args, int nargs) -> uint32_t {
        if (!t_ctx || !t_ctx->callback_executor) return 0;
        return t_ctx->callback_executor(addr, args, nargs);
    };

    /* Call DllMain for any loaded ARM DLLs (must happen after callback_executor is set up) */
    thunks.CallDllEntryPoints();

    ApplyRuntimePatches(mem);
    LOG(EMU, "\n[EMU] Starting at 0x%08X (%s), SP=0x%08X hInst=0x%08X\n",
           cpu.r[REG_PC], cpu.IsThumb() ? "Thumb" : "ARM", cpu.r[REG_SP], cpu.r[0]);

    /* GDB remote debugging — start stub before running if requested */
    GdbStub* gdb = nullptr;
    if (cfg.gdb_port > 0) {
        gdb = new GdbStub((uint16_t)cfg.gdb_port, &mem);
        gdb->RegisterCpu(&cpu, GetCurrentThreadId());
        if (!gdb->Start()) {
            LOG_ERR("[GDB] Failed to start debug server on port %d\n", cfg.gdb_port);
            delete gdb;
            gdb = nullptr;
        } else {
            cpu.debugger = gdb;
            g_debugger = gdb;  /* make available to child threads */
        }
    }

    /* Run the emulator */
    cpu.Run();

    HandlePostHalt(cpu);

    if (gdb) {
        cpu.debugger = nullptr;
        gdb->UnregisterCpu(&cpu);
        g_debugger = nullptr;
        delete gdb;
    }

    Log::Close();
    return cpu.halt_code;
}
