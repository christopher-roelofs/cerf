#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* ARM PE child process launch for ShellExecuteEx — creates a new OS thread
   with its own ProcessSlot, ThreadContext, ArmCpu, and isolated address space. */
#include "../win32_thunks.h"
#include "../handle_table.h"
#include "../../log.h"
#include "../../debugger/gdb_stub.h"
#include <cstdio>
#include <set>

/* Per-thread process handle table (for child processes) */
static thread_local ProcessHandleTable* t_handle_table = nullptr;

/* Get the current thread's handle table (nullptr for main process) */
ProcessHandleTable* GetProcessHandleTable() { return t_handle_table; }


bool Win32Thunks::LaunchArmChildProcess(
    const std::wstring& mapped_file, const std::wstring& params,
    uint32_t sei_addr, uint32_t* regs, EmulatedMemory& mem)
{
    LOG(API, "[API]   -> ARM PE detected, launching as child process\n");
    std::string narrow_path;
    for (auto c : mapped_file) narrow_path += (char)c;

    struct ChildProcInfo {
        std::string path;
        std::wstring cmdline;
        EmulatedMemory* mem;
        Win32Thunks* thunks;
    };
    auto* cpi = new ChildProcInfo{ narrow_path, params, &mem, this };

    DWORD realThreadId = 0;
    HANDLE hThread = ::CreateThread(NULL, 0,
        [](LPVOID param) -> DWORD {
            auto* cpi = (ChildProcInfo*)param;
            int thread_idx = g_next_thread_index.fetch_add(1);

            ThreadContext ctx;
            ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
            t_ctx = &ctx;

            /* Set process name and exe path for log lines and resources */
            {
                const char* p = cpi->path.c_str();
                const char* fname = strrchr(p, '/');
                if (!fname) fname = strrchr(p, '\\');
                fname = fname ? fname + 1 : p;
                snprintf(ctx.process_name, sizeof(ctx.process_name), "%s", fname);
                snprintf(ctx.exe_path, sizeof(ctx.exe_path), "%s", cpi->path.c_str());
                Log::SetProcessName(ctx.process_name, GetCurrentThreadId());
            }

            /* Create per-process virtual address space */
            ProcessSlot slot;
            slot.has_own_allocators = true; /* Phase 4: per-process heap */
            if (!slot.buffer) {
                LOG(API, "[API] ShellExecuteEx: ProcessSlot alloc failed\n");
                delete cpi; t_ctx = nullptr; return 1;
            }
            /* Register DLL writable sections for copy-on-write.
               Child process writes to DLL .data pages get private copies. */
            slot.RegisterWritableSections(cpi->mem->dll_writable_sections);
            EmulatedMemory::process_slot = &slot;

            /* Per-process handle table for cleanup on exit */
            ProcessHandleTable handle_table;
            t_handle_table = &handle_table;

            /* Record DLLs that exist before child starts — only DLLs loaded
               DURING the child's lifetime should get DLL_PROCESS_DETACH. */
            std::set<uint32_t> pre_existing_dll_bases;
            for (auto& pair : cpi->thunks->loaded_dlls)
                pre_existing_dll_bases.insert(pair.second.base_addr);

            /* Load PE into the slot */
            PEInfo child_pe = {};
            uint32_t entry = PELoader::LoadIntoSlot(
                cpi->path.c_str(), *cpi->mem, child_pe, slot);
            if (!entry) {
                LOG(API, "[API] ShellExecuteEx: LoadIntoSlot failed\n");
                EmulatedMemory::process_slot = nullptr;
                delete cpi; t_ctx = nullptr; return 1;
            }

            /* Allocate per-thread stack */
            uint32_t stack_top = 0x00FFFFF0;

            /* Initialize per-thread KData */
            InitThreadKData(&ctx, *cpi->mem, GetCurrentThreadId());
            EmulatedMemory::kdata_override = ctx.kdata;

            /* Set up CPU — SP must be valid before InstallThunks/CallDllEntryPoints
               because DllMain callbacks run via callback_executor which uses the stack */
            ArmCpu& cpu = ctx.cpu;
            cpu.mem = cpi->mem;
            cpu.traces = cpi->thunks->GetTraceManager();
            cpu.r[REG_SP] = stack_top;
            cpu.cpsr |= 0x13;
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
            cpi->thunks->InstallThunks(child_pe, ctx.process_name);
            cpi->thunks->CallDllEntryPoints();

            /* Phase 2: Call DLL_PROCESS_ATTACH for ALL previously-loaded DLLs.
               On real WinCE, each process gets its own DllMain calls. With Phase 1
               copy-on-write, these writes go to private pages so they don't corrupt
               the parent process's DLL state.
               Note: CallDllEntryPoints above handles DLLs loaded by THIS child's
               imports. Here we handle DLLs loaded before the child started. */
            {
                constexpr uint32_t DLL_PROCESS_ATTACH_REASON = 1;
                for (auto& pair : cpi->thunks->loaded_dlls) {
                    auto& dll = pair.second;
                    if (dll.pe_info.entry_point_rva == 0) continue;
                    uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
                    /* Skip DLLs that were just loaded by InstallThunks above
                       (they already got DLL_PROCESS_ATTACH from CallDllEntryPoints) */
                    if (cpi->thunks->disable_thread_notify_bases.count(dll.base_addr))
                        continue;
                    LOG(API, "[PROC] DLL_PROCESS_ATTACH (child): 0x%08X (base=0x%08X)\n",
                        entry, dll.base_addr);
                    uint32_t args[3] = { dll.base_addr, DLL_PROCESS_ATTACH_REASON, 0 };
                    ctx.callback_executor(entry, args, 3);
                }
            }

            /* Build command line in shared memory */
            uint32_t cmdline_addr = 0x60003000;
            cpi->mem->Alloc(cmdline_addr, 0x1000);
            for (size_t j = 0; j < cpi->cmdline.size() && j < 0x7FE; j++)
                cpi->mem->Write16(cmdline_addr + (uint32_t)(j * 2),
                                  (uint16_t)cpi->cmdline[j]);
            cpi->mem->Write16(cmdline_addr + (uint32_t)(cpi->cmdline.size() * 2), 0);

            /* Set up WinMain args (SP/CPSR already initialized above) */
            cpu.r[0] = child_pe.image_base;
            cpu.r[1] = 0;
            cpu.r[2] = cmdline_addr;
            cpu.r[3] = 1; /* SW_SHOWNORMAL */
            cpu.r[REG_SP] = stack_top;
            cpu.r[REG_LR] = 0xDEADDEAD;
            if (entry & 1) {
                cpu.cpsr |= PSR_T;
                cpu.r[REG_PC] = entry & ~1u;
            } else {
                cpu.r[REG_PC] = entry;
            }

            /* Attach GDB debugger if one is active */
            if (g_debugger) {
                cpu.debugger = g_debugger;
                g_debugger->RegisterCpu(&cpu, GetCurrentThreadId());
            }

            LOG(API, "[PROC] Child process started: PC=0x%08X SP=0x%08X '%s'\n",
                cpu.r[REG_PC], stack_top, ctx.process_name);
            Win32Thunks* thunks_ptr = cpi->thunks; /* save before delete */
            delete cpi;
            cpu.Run();

            if (g_debugger) {
                cpu.debugger = nullptr;
                g_debugger->UnregisterCpu(&cpu);
            }

            uint32_t exit_code = cpu.r[0];
            LOG(API, "[PROC] Child process exited with code %u\n", exit_code);

            /* Phase 3: Close all handles owned by this child process */
            LOG(API, "[PROC] Closing %zu handles for child process\n", handle_table.Count());
            handle_table.CloseAll();
            t_handle_table = nullptr;

            /* Phase 2: DLL_PROCESS_DETACH only for DLLs loaded DURING this child's
               lifetime. Pre-existing DLLs (loaded by parent) must NOT get DETACH
               because their DllMain modifies SHARED global state. On real WinCE,
               each process has hardware-MMU-isolated DLL data copies, so DETACH
               only affects the exiting process. We lack that isolation. */
            {
                constexpr uint32_t DLL_PROCESS_DETACH_REASON = 0;
                auto& dlls = thunks_ptr->loaded_dlls;
                std::vector<std::pair<uint32_t, uint32_t>> detach_list;
                for (auto& pair : dlls) {
                    auto& dll = pair.second;
                    if (dll.pe_info.entry_point_rva == 0) continue;
                    /* Skip DLLs that existed before this child started */
                    if (pre_existing_dll_bases.count(dll.base_addr)) continue;
                    uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
                    detach_list.push_back({entry, dll.base_addr});
                }
                /* Reverse order: last loaded → first detached */
                for (auto it = detach_list.rbegin(); it != detach_list.rend(); ++it) {
                    LOG(API, "[PROC] DLL_PROCESS_DETACH: 0x%08X (base=0x%08X)\n",
                        it->first, it->second);
                    uint32_t args[3] = { it->second, DLL_PROCESS_DETACH_REASON, 0 };
                    ctx.callback_executor(it->first, args, 3);
                }
            }

            /* Free per-process DLL data page copies */
            slot.FreeDllOverlay();
            EmulatedMemory::process_slot = nullptr;
            EmulatedMemory::kdata_override = nullptr;
            t_ctx = nullptr;
            return exit_code;
        },
        cpi, 0, &realThreadId);

    if (!hThread) {
        LOG(API, "[API] ShellExecuteEx: CreateThread failed (err=%lu)\n", GetLastError());
        delete cpi;
        if (sei_addr) mem.Write32(sei_addr + 0x20, 0);
        if (regs) regs[0] = 0;
        return true;
    }
    LOG(API, "[API]   -> child process thread=%u\n", realThreadId);
    RegisterChildThread(hThread);

    /* The kernel's job is done: process created, command line passed.
       What the child process does with its args is its own business.
       On real WinCE, explorer.exe handles the URL if it's a second instance
       (finds existing desktop → SHBrowseToURL). If it's the first instance,
       it creates the desktop and ignores the URL — that's the app's behavior. */

    if (sei_addr) mem.Write32(sei_addr + 0x20, 42);
    if (regs) regs[0] = 1;
    return true;
}
