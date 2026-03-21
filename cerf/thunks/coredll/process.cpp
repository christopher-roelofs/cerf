#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Process/thread thunks: CreateProcessW, CreateThread stubs, file mapping */
#include "../win32_thunks.h"
#include "../../log.h"
#include "../../debugger/gdb_stub.h"
#include <cstdio>
#include <vector>


void Win32Thunks::RegisterProcessHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(API, "[API] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("CreateThread", 492, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        /* CreateThread(lpSA, stackSize, lpStartAddress, lpParameter, flags, lpThreadId)
           ARM calling convention: R0=lpSA, R1=stackSize, R2=lpStartAddress, R3=lpParameter
           Stack: [0]=flags, [1]=lpThreadId */
        uint32_t lpStartAddress = regs[2];
        uint32_t lpParameter = regs[3];
        uint32_t flags = ReadStackArg(regs, mem, 0);
        uint32_t lpThreadId = ReadStackArg(regs, mem, 1);
        LOG(API, "[API] CreateThread(startAddr=0x%08X, param=0x%08X, flags=0x%X)\n",
            lpStartAddress, lpParameter, flags);

        if (!lpStartAddress) {
            LOG(API, "[API]   CreateThread: null start address\n");
            regs[0] = 0; return true;
        }

        /* Capture everything the new thread needs */
        struct ThreadStartInfo {
            uint32_t start_addr;
            uint32_t parameter;
            EmulatedMemory* mem;
            Win32Thunks* thunks;
            uint32_t sentinel;
            char parent_process[32];
            char parent_exe_path[512];
            ProcessSlot* parent_slot;
            uint32_t parent_hinstance;
            bool parent_is_kernel;
        };
        auto* info = new ThreadStartInfo{
            lpStartAddress, lpParameter, &mem, this, 0xCAFEC000, {}, {},
            EmulatedMemory::process_slot,
            t_emu_hinstance,
            t_ctx ? t_ctx->is_kernel_thread : false
        };
        if (t_ctx) {
            snprintf(info->parent_process, 32, "%s", t_ctx->process_name);
            snprintf(info->parent_exe_path, 512, "%s", t_ctx->exe_path);
        }

        DWORD realThreadId = 0;
        HANDLE hThread = ::CreateThread(NULL, 0,
            [](LPVOID param) -> DWORD {
                auto* info = (ThreadStartInfo*)param;
                int thread_idx = g_next_thread_index.fetch_add(1);

                /* Create per-thread context */
                ThreadContext ctx;
                ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                t_ctx = &ctx;

                /* Inherit process name, exe path, and address space from parent */
                snprintf(ctx.process_name, sizeof(ctx.process_name), "%s",
                         info->parent_process);
                snprintf(ctx.exe_path, sizeof(ctx.exe_path), "%s",
                         info->parent_exe_path);
                Log::SetProcessName(ctx.process_name, GetCurrentThreadId());
                EmulatedMemory::process_slot = info->parent_slot;
                t_emu_hinstance = info->parent_hinstance;
                ctx.is_kernel_thread = info->parent_is_kernel;

                /* Allocate per-thread stack in emulated memory */
                uint32_t stack_size = 0x100000; /* 1MB */
                /* Thread stacks below 0x02000000 (WinCE 32MB slot boundary).
                   Range 0x01900000-0x01FFFFFF (7 thread slots). */
                uint32_t stack_bottom = 0x01900000 + thread_idx * stack_size;
                info->mem->Alloc(stack_bottom, stack_size);
                uint32_t stack_top = stack_bottom + stack_size - 16;

                /* Initialize per-thread KData */
                InitThreadKData(&ctx, *info->mem, GetCurrentThreadId());
                EmulatedMemory::kdata_override = ctx.kdata;

                /* Set up CPU */
                ArmCpu& cpu = ctx.cpu;
                cpu.mem = info->mem;
                /* Use the global TraceManager from Win32Thunks — it's read-only
                   after init and shared across all threads. */
                cpu.traces = info->thunks->GetTraceManager();
                cpu.thunk_handler = [thunks = info->thunks](
                        uint32_t addr, uint32_t* regs, EmulatedMemory& m) -> bool {
                    if (addr == 0xDEADDEAD) {
                        LOG(EMU, "[EMU] Thread returned with code %d\n", regs[0]);
                        return true; /* will cause halted check */
                    }
                    if (addr == 0xCAFEC000) {
                        regs[15] = 0xCAFEC000;
                        return true;
                    }
                    return thunks->HandleThunk(addr, regs, m);
                };

                /* Build callback_executor for this thread */
                MakeCallbackExecutor(&ctx, *info->mem, *info->thunks, info->sentinel);

                /* Allocate marshal buffer page */
                info->mem->Alloc(ctx.marshal_base, 0x10000);

                /* Set up initial registers */
                cpu.r[0] = info->parameter;
                cpu.r[REG_SP] = stack_top;
                cpu.r[REG_LR] = 0xDEADDEAD;
                if (info->start_addr & 1) {
                    cpu.cpsr |= PSR_T;
                    cpu.r[REG_PC] = info->start_addr & ~1u;
                } else {
                    cpu.r[REG_PC] = info->start_addr;
                }
                cpu.cpsr |= 0x13; /* SVC mode */

                /* Attach GDB debugger if one is active */
                if (g_debugger) {
                    cpu.debugger = g_debugger;
                    g_debugger->RegisterCpu(&cpu, GetCurrentThreadId());
                }

                LOG(API, "[THREAD] Started thread %d: PC=0x%08X SP=0x%08X param=0x%08X\n",
                    thread_idx, cpu.r[REG_PC], stack_top, info->parameter);

                /* Send DLL_THREAD_ATTACH to loaded ARM DLLs. On real WinCE, only
                   DLLs loaded in the SAME PROCESS get THREAD_ATTACH. DLLs loaded
                   by device.exe shouldn't fire on explorer's threads.
                   Skip if: DisableThreadLibraryCalls was called, or the DLL was
                   loaded by a different process (ProcessSlot not in dllmain set). */
                constexpr uint32_t DLL_THREAD_ATTACH_REASON = 2;
                auto* thunks = info->thunks;
                ProcessSlot* thread_slot = EmulatedMemory::process_slot;
                for (auto& pair : thunks->loaded_dlls) {
                    auto& dll = pair.second;
                    if (dll.pe_info.entry_point_rva == 0) continue;
                    if (thunks->disable_thread_notify_bases.count(dll.base_addr))
                        continue;
                    /* Skip DLLs loaded exclusively by device.exe. On real WinCE,
                       device.exe's DLLs don't fire DLL_THREAD_ATTACH on other processes. */
                    if (dll.loaded_by_device && !ctx.is_kernel_thread)
                        continue;
                    uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
                    LOG(API, "[THREAD] DLL_THREAD_ATTACH: 0x%08X (base=0x%08X)\n",
                        entry, dll.base_addr);
                    uint32_t dllargs[3] = { dll.base_addr, DLL_THREAD_ATTACH_REASON, 0 };
                    ctx.callback_executor(entry, dllargs, 3);
                }

                /* DEBUG: check if vtable page survived DLL_THREAD_ATTACH.
                   Only check after webview.dll is loaded (base >= 0x10C00000). */
                for (auto& [n, d] : thunks->loaded_dlls) {
                    if (d.base_addr >= 0x10C00000 && d.base_addr <= 0x10D00000 &&
                        d.pe_info.size_of_image > 0x12000) {
                        uint32_t vt_addr = d.base_addr + 0x28B4;
                        uint8_t* host = info->mem->Translate(vt_addr);
                        uint32_t native_val = *(uint32_t*)(uintptr_t)vt_addr;
                        uint32_t emu_val = host ? *(uint32_t*)host : 0xDEAD;
                        if (emu_val == 0 || native_val != emu_val) {
                            LOG_ERR("[THREAD] VTABLE ISSUE on thread %d! "
                                    "native@%p=0x%08X emu@%p=0x%08X\n",
                                    thread_idx, (void*)(uintptr_t)vt_addr, native_val,
                                    host, emu_val);
                        }
                        break;
                    }
                }

                delete info;

                cpu.Run();

                /* Send DLL_THREAD_DETACH to all loaded ARM DLLs.
                   On real WinCE, the kernel sends this before thread termination.
                   DLLs use it to release per-thread resources (locks, TLS, etc.).
                   Without this, commdlg.dll's per-thread mutex stays held forever,
                   blocking DLL_THREAD_ATTACH on the next thread. */
                constexpr uint32_t DLL_THREAD_DETACH_REASON = 3;
                for (auto& pair : thunks->loaded_dlls) {
                    auto& dll = pair.second;
                    if (dll.pe_info.entry_point_rva == 0) continue;
                    if (thunks->disable_thread_notify_bases.count(dll.base_addr))
                        continue;
                    /* Same process filter as THREAD_ATTACH */
                    if (dll.loaded_by_device && !ctx.is_kernel_thread)
                        continue;
                    uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
                    LOG(API, "[THREAD] DLL_THREAD_DETACH: 0x%08X (base=0x%08X)\n",
                        entry, dll.base_addr);
                    uint32_t detach_args[3] = { dll.base_addr, DLL_THREAD_DETACH_REASON, 0 };
                    ctx.callback_executor(entry, detach_args, 3);
                }

                /* Detach from debugger before thread context is destroyed */
                if (g_debugger) {
                    cpu.debugger = nullptr;
                    g_debugger->UnregisterCpu(&cpu);
                }

                LOG(API, "[THREAD] Thread %d exited with R0=0x%X\n",
                    thread_idx, cpu.r[0]);
                t_ctx = nullptr;
                EmulatedMemory::kdata_override = nullptr;
                return cpu.r[0];
            },
            info,
            (flags & CREATE_SUSPENDED) ? CREATE_SUSPENDED : 0,
            &realThreadId);

        if (!hThread) {
            LOG(API, "[API]   CreateThread FAILED (err=%lu)\n", GetLastError());
            delete info;
            regs[0] = 0;
            return true;
        }

        LOG(API, "[API]   CreateThread: real thread handle=0x%p tid=%u\n",
            hThread, realThreadId);
        if (lpThreadId) mem.Write32(lpThreadId, realThreadId);
        regs[0] = WrapHandle(hThread);
        return true;
    });
    RegisterChildProcessHandler();
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("ResumeThread", 500, stub0("ResumeThread"));
    Thunk("SetThreadPriority", 514, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SetThreadPriority(thread=0x%X, prio=%d) -> TRUE\n", regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    /* WinCE extended thread priority (0-255 scale, 0=highest).
       CeSetThreadPriority stores it, CeGetThreadPriority reads it back. */
    Thunk("CeSetThreadPriority", 621, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] CeSetThreadPriority(thread=0x%X, prio=%d) -> stub TRUE\n",
            regs[0], regs[1]);
        regs[0] = 1; return true;
    });
    Thunk("CeGetThreadPriority", 622, [](uint32_t* regs, EmulatedMemory&) -> bool {
        constexpr uint32_t WINCE_PRIORITY_NORMAL = 251;
        LOG(API, "[API] CeGetThreadPriority(thread=0x%X) -> %d\n",
            regs[0], WINCE_PRIORITY_NORMAL);
        regs[0] = WINCE_PRIORITY_NORMAL; return true;
    });
    /* WaitForMultipleObjects moved to sync.cpp */
    /* Fiber APIs — WinCE fiber support.  We forward to native Win32 fibers
       since each ARM thread is a real OS thread. */
    /* Fiber pointer wrapping — native fiber pointers are 64-bit, ARM code
       uses 32-bit.  Use WrapHandle/UnwrapHandle to map them safely. */
    Thunk("ConvertThreadToFiber", 1480, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LPVOID fiber = ConvertThreadToFiber((LPVOID)(uintptr_t)regs[0]);
        uint32_t wrapped = WrapHandle((HANDLE)fiber);
        LOG(API, "[API] ConvertThreadToFiber(0x%08X) -> 0x%08X (native=0x%p)\n",
            regs[0], wrapped, fiber);
        regs[0] = wrapped;
        return true;
    });
    Thunk("GetCurrentFiber", 1481, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LPVOID fiber = GetCurrentFiber();
        regs[0] = WrapHandle((HANDLE)fiber);
        return true;
    });
    Thunk("GetFiberData", 1482, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LPVOID data = GetFiberData();
        regs[0] = (uint32_t)(uintptr_t)data;
        return true;
    });
    Thunk("CreateFiber", 1483, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t stackSize = regs[0];
        uint32_t armStartAddr = regs[1];
        uint32_t armParam = regs[2];
        /* Create a native fiber whose callback enters ARM execution.
           Fibers share the same thread, so thread_local (t_ctx) works. */
        struct FiberCtx {
            uint32_t arm_addr;
            uint32_t arm_param;
            Win32Thunks* thunks;
        };
        auto* fc = new FiberCtx{armStartAddr, armParam, this};
        LPVOID fiber = ::CreateFiber(stackSize ? stackSize : 0,
            [](LPVOID p) {
                auto* ctx = (FiberCtx*)p;
                uint32_t args[4] = {ctx->arm_param, 0, 0, 0};
                ctx->thunks->callback_executor(ctx->arm_addr, args, 1);
                delete ctx;
            }, fc);
        uint32_t wrapped = WrapHandle((HANDLE)fiber);
        LOG(API, "[API] CreateFiber(stack=%u, start=0x%08X, param=0x%08X) -> 0x%08X\n",
            stackSize, armStartAddr, armParam, wrapped);
        regs[0] = wrapped;
        return true;
    });
    Thunk("DeleteFiber", 1484, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LPVOID fiber = (LPVOID)UnwrapHandle(regs[0]);
        LOG(API, "[API] DeleteFiber(0x%08X)\n", regs[0]);
        DeleteFiber(fiber);
        regs[0] = 0;
        return true;
    });
    Thunk("SwitchToFiber", 1485, [this](uint32_t* regs, EmulatedMemory&) -> bool {
        LPVOID fiber = (LPVOID)UnwrapHandle(regs[0]);
        LOG(API, "[API] SwitchToFiber(0x%08X -> native=0x%p)\n", regs[0], fiber);
        ::SwitchToFiber(fiber);
        return true;
    });
    Thunk("GetExitCodeThread", 518, [](uint32_t* regs, EmulatedMemory& mem) -> bool {
        LOG(API, "[API] GetExitCodeThread(hThread=0x%08X, lpExitCode=0x%08X) -> stub\n", regs[0], regs[1]);
        if (regs[1]) mem.Write32(regs[1], 0);
        regs[0] = 1;
        return true;
    });
    Thunk("IsProcessDying", 1213, [](uint32_t* regs, EmulatedMemory&) -> bool {
        /* Called during thread/COM cleanup to check if the process is terminating.
           Our emulator process is never "dying" — individual ARM threads exit but
           the host process stays alive. Return FALSE so cleanup proceeds normally
           instead of taking the "process dying" shortcut path. */
        regs[0] = 0; /* FALSE — process is NOT dying */
        return true;
    });
    /* ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead) */
    Thunk("ReadProcessMemory", 506, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t src = regs[1], dst = regs[2], size = regs[3];
        uint32_t pBytesRead = ReadStackArg(regs, mem, 0);
        LOG(API, "[API] ReadProcessMemory(src=0x%08X, dst=0x%08X, size=%u)\n", src, dst, size);
        uint8_t* s = mem.Translate(src);
        uint8_t* d = mem.Translate(dst);
        if (s && d && size > 0) memcpy(d, s, size);
        if (pBytesRead) mem.Write32(pBytesRead, (s && d) ? size : 0);
        regs[0] = (s && d) ? 1 : 0;
        return true;
    });
    /* WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) */
    Thunk("WriteProcessMemory", 507, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t dst = regs[1], src = regs[2], size = regs[3];
        uint32_t pBytesWritten = ReadStackArg(regs, mem, 0);
        LOG(API, "[API] WriteProcessMemory(dst=0x%08X, src=0x%08X, size=%u)\n", dst, src, size);
        uint8_t* d = mem.Translate(dst);
        uint8_t* s = mem.Translate(src);
        if (s && d && size > 0) memcpy(d, s, size);
        if (pBytesWritten) mem.Write32(pBytesWritten, (s && d) ? size : 0);
        regs[0] = (s && d) ? 1 : 0;
        return true;
    });
    /* SuspendThread — stub fail, don't actually suspend */
    Thunk("SuspendThread", 499, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] SuspendThread(hThread=0x%08X) -> stub -1\n", regs[0]);
        regs[0] = (uint32_t)-1; return true;
    });
    /* ThreadExceptionExit */
    Thunk("ThreadExceptionExit", 1474, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(API, "[API] ThreadExceptionExit -> stub\n");
        regs[0] = 0; return true;
    });
}
