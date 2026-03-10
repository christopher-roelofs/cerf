#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ShellExecuteEx thunk — handles CLSID paths, .lnk shortcuts, directories,
   ARM PE in-process loading, ctlpnl.exe CPL applet hosting, native fallback */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>
#include <cpl.h>

/* Extract basename from a path (lowercase) */
static std::wstring GetLowerBasename(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    std::wstring name = (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
    for (auto& c : name) c = towlower(c);
    return name;
}

void Win32Thunks::RegisterShellExecHandler() {
    Thunk("ShellExecuteEx", 480, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t sei_addr = regs[0];
        if (!sei_addr) { regs[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return true; }
        /* WinCE SHELLEXECUTEINFO layout (all 32-bit pointers):
           0x00 cbSize, 0x04 fMask, 0x08 hwnd, 0x0C lpVerb, 0x10 lpFile,
           0x14 lpParameters, 0x18 lpDirectory, 0x1C nShow, 0x20 hInstApp */
        uint32_t fMask     = mem.Read32(sei_addr + 0x04);
        uint32_t hwnd_val  = mem.Read32(sei_addr + 0x08);
        uint32_t verb_ptr  = mem.Read32(sei_addr + 0x0C);
        uint32_t file_ptr  = mem.Read32(sei_addr + 0x10);
        uint32_t params_ptr= mem.Read32(sei_addr + 0x14);
        uint32_t dir_ptr   = mem.Read32(sei_addr + 0x18);
        int nShow          = (int)mem.Read32(sei_addr + 0x1C);
        std::wstring verb, file, params, dir;
        if (verb_ptr) verb = ReadWStringFromEmu(mem, verb_ptr);
        if (file_ptr) file = ReadWStringFromEmu(mem, file_ptr);
        if (params_ptr) params = ReadWStringFromEmu(mem, params_ptr);
        if (dir_ptr) dir = ReadWStringFromEmu(mem, dir_ptr);
        LOG(API, "[API] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);

        /* Helper: open a folder browser via SHCreateExplorerInstance in the ARM explorer */
        auto callSHCreateExplorerInstance = [&](const std::wstring& path) -> bool {
            const uint32_t shCreateExplorerInstance = 0x0001A120;
            uint32_t path_addr = 0x60002000;
            mem.Alloc(path_addr, 0x1000);
            for (size_t j = 0; j < path.size() && j < 0x7FE; j++)
                mem.Write16(path_addr + (uint32_t)(j * 2), (uint16_t)path[j]);
            mem.Write16(path_addr + (uint32_t)(path.size() * 2), 0);
            uint32_t args[2] = { path_addr, 0 };
            LOG(API, "[API]   -> calling SHCreateExplorerInstance('%ls')\n", path.c_str());
            uint32_t ret = callback_executor(shCreateExplorerInstance, args, 2);
            LOG(API, "[API]   -> SHCreateExplorerInstance returned %d\n", ret);
            mem.Write32(sei_addr + 0x20, 42);
            regs[0] = 1;
            return true;
        };

        /* Handle CLSID shell paths (::{guid}) */
        if (file.size() > 3 && file[0] == L':' && file[1] == L':' && file[2] == L'{') {
            LOG(API, "[API]   -> CLSID shell path '%ls'\n", file.c_str());
            std::wstring folder_path;
            if (file.find(L"000214A0") != std::wstring::npos ||
                file.find(L"000214a0") != std::wstring::npos)
                folder_path = L"\\";
            else if (file.find(L"00021400") != std::wstring::npos)
                folder_path = L"\\";
            if (!folder_path.empty() && callback_executor) {
                return callSHCreateExplorerInstance(folder_path);
            }
            LOG(API, "[API]   -> unknown CLSID, returning success (stub)\n");
            mem.Write32(sei_addr + 0x20, 42);
            regs[0] = 1;
            return true;
        }

        /* Resolve WinCE .lnk shortcut files */
        if (file.size() > 4) {
            std::wstring ext = file.substr(file.size() - 4);
            for (auto& c : ext) c = towlower(c);
            if (ext == L".lnk") {
                std::wstring lnk_host = MapWinCEPath(file);
                HANDLE hf = CreateFileW(lnk_host.c_str(), GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, 0, NULL);
                if (hf != INVALID_HANDLE_VALUE) {
                    char buf[1024] = {};
                    DWORD n = 0;
                    ReadFile(hf, buf, sizeof(buf) - 1, &n, NULL);
                    CloseHandle(hf);
                    buf[n] = 0;
                    if (n > 0 && buf[0] == '#') {
                        char* p = buf + 1;
                        char* end = p;
                        while (*end && *end != '\r' && *end != '\n') end++;
                        *end = 0;
                        std::wstring target;
                        for (char* c = p; *c; c++) target += (wchar_t)*c;
                        LOG(API, "[API]   -> .lnk resolved to '%ls'\n", target.c_str());
                        file = target;
                    }
                }
            }
        }

        std::wstring mapped_file = file.empty() ? L"" : MapWinCEPath(file);
        /* WinCE resolves bare filenames via \Windows\ search path */
        if (!mapped_file.empty() && GetFileAttributesW(mapped_file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::wstring win_path = L"\\Windows\\" + file;
            std::wstring win_mapped = MapWinCEPath(win_path);
            if (GetFileAttributesW(win_mapped.c_str()) != INVALID_FILE_ATTRIBUTES) {
                LOG(API, "[API]   -> resolved '%ls' via \\Windows\\\n", file.c_str());
                mapped_file = win_mapped;
            }
        }

        /* Directory → open folder browser */
        if (!mapped_file.empty() && callback_executor) {
            DWORD attr = GetFileAttributesW(mapped_file.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                LOG(API, "[API]   -> target is DIRECTORY\n");
                std::wstring wce_path = file;
                if (!wce_path.empty() && wce_path[0] != L'\\') wce_path = L"\\" + wce_path;
                return callSHCreateExplorerInstance(wce_path);
            }
        }

        /* Handle ctlpnl.exe natively: load .cpl as ARM DLL, call CPlApplet.
           ctlpnl.exe loads at 0x00010000 (same as explorer.exe) and has no .reloc,
           so running it in-process would overwrite explorer's code. Instead we
           implement the SHRunCpl logic directly: parse params, LoadLibrary the .cpl,
           and call CPlApplet(CPL_INIT/CPL_DBLCLK/CPL_STOP/CPL_EXIT). */
        std::wstring basename = GetLowerBasename(file);
        if (basename == L"ctlpnl.exe" && callback_executor && !params.empty()) {
            /* Parse "cplmain.cpl,7" → cpl_name, applet_index */
            std::wstring cpl_name;
            int applet_idx = 0, tab_idx = 0;
            size_t comma = params.find(L',');
            if (comma != std::wstring::npos) {
                cpl_name = params.substr(0, comma);
                std::wstring rest = params.substr(comma + 1);
                applet_idx = _wtoi(rest.c_str());
                size_t comma2 = rest.find(L',');
                if (comma2 != std::wstring::npos) tab_idx = _wtoi(rest.substr(comma2+1).c_str());
            } else {
                cpl_name = params;
            }
            LOG(API, "[API]   -> ctlpnl.exe: loading CPL '%ls' applet=%d tab=%d\n",
                cpl_name.c_str(), applet_idx, tab_idx);
            /* Convert to narrow for LoadArmDll */
            std::string narrow_cpl;
            for (auto c : cpl_name) narrow_cpl += (char)c;
            LoadedDll* cpl = LoadArmDll(narrow_cpl.c_str());
            if (cpl) {
                CallDllEntryPoints();
                uint32_t cplApplet = PELoader::ResolveExportName(mem, cpl->pe_info, "CPlApplet");
                if (cplApplet) {
                    uint32_t a1[4] = { 0, CPL_INIT, 0, 0 };
                    callback_executor(cplApplet, a1, 4);
                    uint32_t a2[4] = { 0, CPL_DBLCLK, (uint32_t)MAKELONG(applet_idx, tab_idx), 0 };
                    callback_executor(cplApplet, a2, 4);
                    uint32_t a3[4] = { 0, CPL_STOP, (uint32_t)applet_idx, 0 };
                    callback_executor(cplApplet, a3, 4);
                    uint32_t a4[4] = { 0, CPL_EXIT, 0, 0 };
                    callback_executor(cplApplet, a4, 4);
                    LOG(API, "[API]   -> CPlApplet sequence complete\n");
                    mem.Write32(sei_addr + 0x20, 42);
                    regs[0] = 1;
                    return true;
                }
            }
            LOG(API, "[API]   -> failed to load CPL '%ls'\n", cpl_name.c_str());
            mem.Write32(sei_addr + 0x20, 0);
            regs[0] = 0;
            return true;
        }

        /* ARM PE child process — own OS thread with ProcessSlot for isolation */
        if (!mapped_file.empty() && IsArmPE(mapped_file)) {
            LOG(API, "[API]   -> ARM PE detected, launching as child process\n");
            std::string narrow_path;
            for (auto c : mapped_file) narrow_path += (char)c;
            struct ChildProcInfo { std::string path; std::wstring cmdline;
                                   EmulatedMemory* mem; Win32Thunks* thunks; };
            auto* cpi = new ChildProcInfo{ narrow_path, params, &mem, this };
            DWORD realThreadId = 0;
            HANDLE hThread = ::CreateThread(NULL, 0,
                [](LPVOID param) -> DWORD {
                    auto* cpi = (ChildProcInfo*)param;
                    int thread_idx = g_next_thread_index.fetch_add(1);
                    ThreadContext ctx;
                    ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                    t_ctx = &ctx;
                    { const char* p = cpi->path.c_str();
                      const char* fname = strrchr(p, '/');
                      if (!fname) fname = strrchr(p, '\\');
                      fname = fname ? fname + 1 : p;
                      snprintf(ctx.process_name, sizeof(ctx.process_name), "%s", fname);
                      Log::SetProcessName(ctx.process_name, GetCurrentThreadId()); }
                    ProcessSlot slot;
                    if (!slot.buffer) {
                        LOG(API, "[API] ShellExecuteEx: ProcessSlot alloc failed\n");
                        delete cpi; t_ctx = nullptr; return 1;
                    }
                    EmulatedMemory::process_slot = &slot;
                    PEInfo child_pe = {};
                    uint32_t entry = PELoader::LoadIntoSlot(
                        cpi->path.c_str(), *cpi->mem, child_pe, slot);
                    if (!entry) {
                        LOG(API, "[API] ShellExecuteEx: LoadIntoSlot failed\n");
                        EmulatedMemory::process_slot = nullptr;
                        delete cpi; t_ctx = nullptr; return 1;
                    }
                    uint32_t stack_top = 0x00FFFFF0;
                    InitThreadKData(&ctx, *cpi->mem, GetCurrentThreadId());
                    EmulatedMemory::kdata_override = ctx.kdata;
                    ArmCpu& cpu = ctx.cpu;
                    cpu.mem = cpi->mem;
                    cpu.thunk_handler = [thunks = cpi->thunks](
                            uint32_t addr, uint32_t* r, EmulatedMemory& m) -> bool {
                        if (addr == 0xDEADDEAD) {
                            LOG(EMU, "[EMU] Child process returned with code %d\n", r[0]);
                            return true;
                        }
                        if (addr == 0xCAFEC000) { r[15] = 0xCAFEC000; return true; }
                        return thunks->HandleThunk(addr, r, m);
                    };
                    MakeCallbackExecutor(&ctx, *cpi->mem, *cpi->thunks, 0xCAFEC000);
                    cpi->mem->Alloc(ctx.marshal_base, 0x10000);
                    cpi->thunks->InstallThunks(child_pe);
                    cpi->thunks->CallDllEntryPoints();
                    uint32_t cmdline_addr = 0x60003000;
                    cpi->mem->Alloc(cmdline_addr, 0x1000);
                    for (size_t j = 0; j < cpi->cmdline.size() && j < 0x7FE; j++)
                        cpi->mem->Write16(cmdline_addr + (uint32_t)(j * 2),
                                          (uint16_t)cpi->cmdline[j]);
                    cpi->mem->Write16(cmdline_addr + (uint32_t)(cpi->cmdline.size() * 2), 0);
                    cpu.r[0] = child_pe.image_base; cpu.r[1] = 0;
                    cpu.r[2] = cmdline_addr; cpu.r[3] = 1;
                    cpu.r[REG_SP] = stack_top; cpu.r[REG_LR] = 0xDEADDEAD;
                    if (entry & 1) { cpu.cpsr |= PSR_T; cpu.r[REG_PC] = entry & ~1u; }
                    else { cpu.r[REG_PC] = entry; }
                    cpu.cpsr |= 0x13;
                    LOG(API, "[PROC] Child process started: PC=0x%08X SP=0x%08X '%s'\n",
                        cpu.r[REG_PC], stack_top, ctx.process_name);
                    delete cpi;
                    cpu.Run();
                    uint32_t exit_code = cpu.r[0];
                    LOG(API, "[PROC] Child process exited with code %u\n", exit_code);
                    EmulatedMemory::process_slot = nullptr;
                    EmulatedMemory::kdata_override = nullptr;
                    t_ctx = nullptr;
                    return exit_code;
                },
                cpi, 0, &realThreadId);
            if (!hThread) {
                LOG(API, "[API] ShellExecuteEx: CreateThread failed (err=%lu)\n", GetLastError());
                delete cpi;
                mem.Write32(sei_addr + 0x20, 0);
                regs[0] = 0;
                return true;
            }
            LOG(API, "[API]   -> child process thread=%u\n", realThreadId);
            mem.Write32(sei_addr + 0x20, 42);
            regs[0] = 1;
        } else {
            /* Not an ARM PE — try native ShellExecuteExW */
            SHELLEXECUTEINFOW native_sei = {};
            native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
            native_sei.fMask = fMask;
            native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
            std::wstring mapped_dir = dir.empty() ? L"" : MapWinCEPath(dir);
            native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
            native_sei.lpFile = mapped_file.empty() ? NULL : mapped_file.c_str();
            native_sei.lpParameters = params.empty() ? NULL : params.c_str();
            native_sei.lpDirectory = mapped_dir.empty() ? NULL : mapped_dir.c_str();
            native_sei.nShow = nShow;
            BOOL ret = ShellExecuteExW(&native_sei);
            mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
            if (fMask & SEE_MASK_NOCLOSEPROCESS)
                mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
            LOG(API, "[API]   -> %s\n", ret ? "OK" : "FAILED");
            regs[0] = ret;
        }
        return true;
    });
}
