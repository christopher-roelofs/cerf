#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Process/thread thunks: CreateProcessW, CreateThread stubs, file mapping */
#include "../win32_thunks.h"
#include "../../log.h"
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
        };
        auto* info = new ThreadStartInfo{
            lpStartAddress, lpParameter, &mem, this, 0xCAFEC000
        };

        DWORD realThreadId = 0;
        HANDLE hThread = ::CreateThread(NULL, 0,
            [](LPVOID param) -> DWORD {
                auto* info = (ThreadStartInfo*)param;
                int thread_idx = g_next_thread_index.fetch_add(1);

                /* Create per-thread context */
                ThreadContext ctx;
                ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                t_ctx = &ctx;

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

                LOG(API, "[THREAD] Started thread %d: PC=0x%08X SP=0x%08X param=0x%08X\n",
                    thread_idx, cpu.r[REG_PC], stack_top, info->parameter);
                delete info;

                cpu.Run();

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
    Thunk("CreateProcessW", 493, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t image_ptr = regs[0], cmdline_ptr = regs[1];
        uint32_t fdwCreate = ReadStackArg(regs, mem, 1);
        uint32_t curdir_ptr = ReadStackArg(regs, mem, 3);
        uint32_t procinfo_ptr = ReadStackArg(regs, mem, 5);
        std::wstring image, cmdline, curdir;
        if (image_ptr) image = ReadWStringFromEmu(mem, image_ptr);
        if (cmdline_ptr) cmdline = ReadWStringFromEmu(mem, cmdline_ptr);
        if (curdir_ptr) curdir = ReadWStringFromEmu(mem, curdir_ptr);
        LOG(API, "[API] CreateProcessW(image='%ls', cmdline='%ls', curdir='%ls', flags=0x%X)\n",
               image.c_str(), cmdline.c_str(), curdir.c_str(), fdwCreate);
        std::wstring mapped_image = image.empty() ? L"" : MapWinCEPath(image);
        /* If image is an ARM PE, run it in-process with per-process virtual address space */
        if (!mapped_image.empty() && IsArmPE(mapped_image)) {
            LOG(API, "[API]   -> ARM PE, launching with ProcessSlot\n");
            std::string narrow_path;
            for (auto c : mapped_image) narrow_path += (char)c;

            /* Capture what the child thread needs */
            struct ChildProcInfo {
                std::string path;
                std::wstring cmdline;
                EmulatedMemory* mem;
                Win32Thunks* thunks;
            };
            auto* cpi = new ChildProcInfo{ narrow_path, cmdline, &mem, this };

            DWORD realThreadId = 0;
            HANDLE hThread = ::CreateThread(NULL, 0,
                [](LPVOID param) -> DWORD {
                    auto* cpi = (ChildProcInfo*)param;
                    int thread_idx = g_next_thread_index.fetch_add(1);

                    /* Create per-thread context */
                    ThreadContext ctx;
                    ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
                    t_ctx = &ctx;

                    /* Create per-process virtual address space */
                    ProcessSlot slot;
                    if (!slot.buffer) {
                        LOG(API, "[API] CreateProcessW: ProcessSlot alloc failed\n");
                        delete cpi; t_ctx = nullptr; return 1;
                    }
                    EmulatedMemory::process_slot = &slot;

                    /* Load PE into the slot */
                    PEInfo child_pe = {};
                    uint32_t entry = PELoader::LoadIntoSlot(
                        cpi->path.c_str(), *cpi->mem, child_pe, slot);
                    if (!entry) {
                        LOG(API, "[API] CreateProcessW: LoadIntoSlot failed\n");
                        EmulatedMemory::process_slot = nullptr;
                        delete cpi; t_ctx = nullptr; return 1;
                    }

                    /* Allocate per-thread stack (in the slot) */
                    uint32_t stack_top = 0x00FFFFF0;

                    /* Initialize per-thread KData */
                    InitThreadKData(&ctx, *cpi->mem, GetCurrentThreadId());
                    EmulatedMemory::kdata_override = ctx.kdata;

                    /* Set up CPU */
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

                    /* Build command line in shared memory */
                    uint32_t cmdline_addr = 0x60003000;
                    cpi->mem->Alloc(cmdline_addr, 0x1000);
                    for (size_t j = 0; j < cpi->cmdline.size() && j < 0x7FE; j++)
                        cpi->mem->Write16(cmdline_addr + (uint32_t)(j * 2),
                                          (uint16_t)cpi->cmdline[j]);
                    cpi->mem->Write16(cmdline_addr + (uint32_t)(cpi->cmdline.size() * 2), 0);

                    /* Set up WinMain args */
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
                    cpu.cpsr |= 0x13;

                    LOG(API, "[PROC] Child process started: PC=0x%08X SP=0x%08X\n",
                        cpu.r[REG_PC], stack_top);
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
                LOG(API, "[API] CreateProcessW: CreateThread failed (err=%lu)\n", GetLastError());
                delete cpi;
                regs[0] = 0;
                return true;
            }
            if (procinfo_ptr) {
                mem.Write32(procinfo_ptr + 0x00, WrapHandle(hThread));
                mem.Write32(procinfo_ptr + 0x04, WrapHandle(hThread));
                mem.Write32(procinfo_ptr + 0x08, realThreadId);
                mem.Write32(procinfo_ptr + 0x0C, realThreadId);
            }
            LOG(API, "[API]   -> child process thread=%u\n", realThreadId);
            regs[0] = 1;
        } else {
            /* Not an ARM PE — try native CreateProcessW */
            STARTUPINFOW si = {}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
            cmdline_buf.push_back(0);
            std::wstring mapped_curdir = curdir.empty() ? L"" : MapWinCEPath(curdir);
            BOOL ret = CreateProcessW(
                mapped_image.empty() ? NULL : mapped_image.c_str(),
                cmdline_buf.data(),
                NULL, NULL, FALSE, fdwCreate, NULL,
                mapped_curdir.empty() ? NULL : mapped_curdir.c_str(),
                &si, &pi);
            if (ret && procinfo_ptr) {
                mem.Write32(procinfo_ptr + 0x00, (uint32_t)(uintptr_t)pi.hProcess);
                mem.Write32(procinfo_ptr + 0x04, (uint32_t)(uintptr_t)pi.hThread);
                mem.Write32(procinfo_ptr + 0x08, pi.dwProcessId);
                mem.Write32(procinfo_ptr + 0x0C, pi.dwThreadId);
            }
            LOG(API, "[API]   -> %s (pid=%d)\n", ret ? "OK" : "FAILED", ret ? pi.dwProcessId : 0);
            regs[0] = ret;
        }
        return true;
    });
    Thunk("TerminateThread", 491, stub0("TerminateThread"));
    Thunk("ResumeThread", 500, stub0("ResumeThread"));
    Thunk("SetThreadPriority", 514, stub0("SetThreadPriority"));
    Thunk("GetExitCodeProcess", 519, stub0("GetExitCodeProcess"));
    Thunk("OpenProcess", 509, stub0("OpenProcess"));
    /* WaitForMultipleObjects moved to sync.cpp */
}
