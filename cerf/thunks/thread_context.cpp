#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "thread_context.h"
#include "win32_thunks.h"
#include "../log.h"

thread_local ThreadContext* t_ctx = nullptr;
thread_local uint32_t t_emu_hinstance = 0;
thread_local uint8_t* EmulatedMemory::kdata_override = nullptr;
thread_local ProcessSlot* EmulatedMemory::process_slot = nullptr;
thread_local ProcessSlot* EmulatedMemory::apiset_caller_slot = nullptr;
std::atomic<int> g_next_thread_index{0};
std::atomic<uint32_t> g_cmdline_page{0x60000000};

/* Child process thread tracking */
static std::mutex g_child_mutex;
static std::vector<HANDLE> g_child_threads;

void RegisterChildThread(HANDLE hThread) {
    std::lock_guard<std::mutex> lock(g_child_mutex);
    g_child_threads.push_back(hThread);
}

bool HasChildThreads() {
    std::lock_guard<std::mutex> lock(g_child_mutex);
    return !g_child_threads.empty();
}

void WaitForChildThreads() {
    std::lock_guard<std::mutex> lock(g_child_mutex);
    if (g_child_threads.empty()) return;
    LOG(EMU, "[EMU] Waiting for %zu child thread(s)...\n",
        g_child_threads.size());
    /* Wait with message pump so native windows stay responsive */
    while (!g_child_threads.empty()) {
        DWORD count = (DWORD)g_child_threads.size();
        if (count > MAXIMUM_WAIT_OBJECTS) count = MAXIMUM_WAIT_OBJECTS;
        DWORD r = MsgWaitForMultipleObjects(
            count, g_child_threads.data(), FALSE, INFINITE, QS_ALLINPUT);
        if (r >= WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + count) {
            DWORD idx = r - WAIT_OBJECT_0;
            CloseHandle(g_child_threads[idx]);
            g_child_threads.erase(g_child_threads.begin() + idx);
        } else if (r == WAIT_OBJECT_0 + count) {
            /* Messages available — pump them */
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        } else {
            break; /* error */
        }
    }
}

void PopulateProcessStruct(EmulatedMemory& mem, uint32_t addr,
    uint32_t procnum, uint32_t fake_pid,
    uint32_t image_base, const char* proc_name)
{
    mem.Write8(addr + 0x00, (uint8_t)procnum);     /* procnum */
    mem.Write8(addr + 0x03, 2);                     /* bTrustLevel = OEM_CERTIFY_TRUST */
    mem.Write32(addr + 0x08, fake_pid);             /* hProc */
    mem.Write32(addr + 0x0C, 0);                    /* dwVMBase (0 in CERF) */
    mem.Write32(addr + 0x14, 1u << procnum);        /* aky */
    mem.Write32(addr + 0x18, image_base);           /* BasePtr */
    mem.Write32(addr + 0x24, 0x0F);                 /* tlsLowUsed */
    mem.Write32(addr + 0x28, 0x00);                 /* tlsHighUsed */
    /* lpszProcName: write name at offset 0x40 within the 0x100 block */
    if (proc_name && proc_name[0]) {
        uint32_t name_addr = addr + 0x40;
        for (int i = 0; proc_name[i] && i < 30; i++)
            mem.Write16(name_addr + i * 2, (uint16_t)proc_name[i]);
        mem.Write16(name_addr + (uint32_t)strlen(proc_name) * 2, 0);
        mem.Write32(addr + 0x20, name_addr);        /* lpszProcName ptr */
    }
}

void InitThreadKData(ThreadContext* ctx, EmulatedMemory& mem, uint32_t thread_id) {
    memset(ctx->kdata, 0, sizeof(ctx->kdata));
    /* KData layout (mapped at 0xFFFFC000-0xFFFFCFFF):
       TLS pre-TLS DWORDs at offset 0x000 (7 words)
       TLS slot array at offset 0x01C (64 slots)
       KDataStruct at offset 0x800:
         +0x000: lpvTls -> TLS slot 0 address
         +0x004: ahSys[0] SH_WIN32
         +0x008: ahSys[1] SH_CURTHREAD
         +0x00C: ahSys[2] SH_CURPROC */
    uint32_t tls_slot0 = 0xFFFFC000 + 7 * 4;  /* 0xFFFFC01C */
    /* Write lpvTls at KData+0 (offset 0x800 in the page) */
    *(uint32_t*)(ctx->kdata + 0x800) = tls_slot0;
    *(uint32_t*)(ctx->kdata + 0x804) = thread_id;
    *(uint32_t*)(ctx->kdata + 0x808) = thread_id;
    {
        uint32_t pid = 1; /* orchestrator default */
        ProcessSlot* slot = EmulatedMemory::process_slot;
        if (slot) pid = slot->fake_pid;
        *(uint32_t*)(ctx->kdata + 0x80C) = pid;
    }
    /* pCurPrc (KData+0x890) and pCurThd (KData+0x894): point to fake
       Process/Thread structs so ARM DLLs that read these directly work.
       SC_TlsCall reads pCurProc->tlsLowUsed (+0x24), DecRefCount reads
       pCurProc->procnum (+0x00). */
    {
        ProcessSlot* slot = EmulatedMemory::process_slot;
        uint32_t proc_addr = 0x3E000000; /* orchestrator default */
        if (slot && slot->proc_struct_addr)
            proc_addr = slot->proc_struct_addr;
        *(uint32_t*)(ctx->kdata + 0x890) = proc_addr;
        *(uint32_t*)(ctx->kdata + 0x894) = proc_addr + 0x80; /* fake Thread */
    }
    LOG(EMU, "[EMU] InitThreadKData: tid=%u, lpvTls=0x%08X\n", thread_id, tls_slot0);
}

static thread_local ThreadContext* s_lazy_arm_ctx = nullptr;

void EnsureLazyArmContext(EmulatedMemory& mem, Win32Thunks* thunks) {
    if (s_lazy_arm_ctx) {
        t_ctx = s_lazy_arm_ctx;
        EmulatedMemory::kdata_override = s_lazy_arm_ctx->kdata;
        return;
    }
    int thread_idx = g_next_thread_index.fetch_add(1);
    auto* ctx = new ThreadContext();
    ctx->marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
    snprintf(ctx->process_name, sizeof(ctx->process_name), "com_%u",
             GetCurrentThreadId());
    Log::SetProcessName(ctx->process_name, GetCurrentThreadId());
    uint32_t stack_size = 0x100000;
    uint32_t stack_bottom = 0x01900000 + thread_idx * stack_size;
    mem.Alloc(stack_bottom, stack_size);
    uint32_t stack_top = stack_bottom + stack_size - 16;
    InitThreadKData(ctx, mem, GetCurrentThreadId());
    EmulatedMemory::kdata_override = ctx->kdata;
    ArmCpu& cpu = ctx->cpu;
    cpu.mem = &mem;
    cpu.thunk_handler = [thunks](uint32_t addr, uint32_t* regs,
                                 EmulatedMemory& m) -> bool {
        if (addr == 0xCAFEC000) { regs[15] = 0xCAFEC000; return true; }
        return thunks->HandleThunk(addr, regs, m);
    };
    cpu.r[REG_SP] = stack_top;
    cpu.cpsr |= 0x13;
    mem.Alloc(ctx->marshal_base, 0x10000);
    MakeCallbackExecutor(ctx, mem, *thunks, 0xCAFEC000);
    t_ctx = ctx;
    s_lazy_arm_ctx = ctx;
    LOG(API, "[API] Created lazy ARM context for native thread %u "
        "(idx=%d, SP=0x%08X)\n", GetCurrentThreadId(), thread_idx, stack_top);
}

void MakeCallbackExecutor(ThreadContext* ctx, EmulatedMemory& mem,
                          Win32Thunks& thunks, uint32_t sentinel) {
    ctx->callback_executor = [ctx, &mem, &thunks, sentinel](
            uint32_t arm_addr, uint32_t* args, int nargs) -> uint32_t {
        static thread_local int cb_depth = 0;
        ArmCpu& cpu = ctx->cpu;
        cb_depth++;
        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor NESTED depth=%d addr=0x%08X "
                "args=[0x%X,0x%X,0x%X,0x%X]\n",
                cb_depth, arm_addr,
                nargs > 0 ? args[0] : 0, nargs > 1 ? args[1] : 0,
                nargs > 2 ? args[2] : 0, nargs > 3 ? args[3] : 0);
        }
        /* Save CPU state */
        uint32_t saved_regs[16];
        memcpy(saved_regs, cpu.r, sizeof(saved_regs));
        uint32_t saved_cpsr = cpu.cpsr;
        bool saved_halted = cpu.halted;
        cpu.halted = false;

        /* Set up callback arguments (R0-R3) */
        for (int i = 0; i < nargs && i < 4; i++)
            cpu.r[i] = args[i];
        /* Set LR to sentinel so we know when the callback returns */
        cpu.r[REG_LR] = sentinel;
        /* Set PC to ARM function address */
        if (arm_addr & 1) {
            cpu.cpsr |= PSR_T;
            cpu.r[REG_PC] = arm_addr & ~1u;
        } else {
            cpu.cpsr &= ~PSR_T;
            cpu.r[REG_PC] = arm_addr;
        }
        /* Allocate stack frame and push extra args */
        cpu.r[REG_SP] -= 0x100;
        for (int i = 4; i < nargs; i++)
            mem.Write32(cpu.r[REG_SP] + (uint32_t)(i - 4) * 4, args[i]);

        /* Run until callback returns (hits sentinel) */
        uint32_t step_count = 0;
        uint32_t last_thunk_step = 0;
        uint64_t last_thunk_count = ctx->thunk_call_count;
        uint64_t start_thunk_count = ctx->thunk_call_count;
        while (!cpu.halted) {
            uint32_t pc = cpu.r[REG_PC];
            if (pc == sentinel || pc == (sentinel & ~1u)) break;
            if (pc < 0x1000) {
                LOG(API, "[API] callback_executor: NULL function pointer "
                    "(PC=0x%08X) at depth=%d, aborting. "
                    "LR=0x%08X R0=0x%08X R1=0x%08X SP=0x%08X "
                    "steps=%u\n",
                    pc, cb_depth, cpu.r[REG_LR], cpu.r[0], cpu.r[1],
                    cpu.r[REG_SP], step_count);
                cpu.r[0] = 0;
                break;
            }
            ++step_count;
            if (ctx->thunk_call_count != last_thunk_count) {
                last_thunk_step = step_count;
                last_thunk_count = ctx->thunk_call_count;
            }
            if (step_count - last_thunk_step > 50000000) {
                LOG(API, "\n[FATAL] callback_executor: infinite loop (pure ARM) "
                    "at PC=0x%08X depth=%d steps=%u thunks=%llu\n",
                    pc, cb_depth, step_count,
                    ctx->thunk_call_count - start_thunk_count);
                LOG(API, "[FATAL] ARM state is corrupt — exiting.\n");
                LOG(API, "[FATAL] Fix the root cause before restarting.\n\n");
                CerfFatalExit(1);
            }
            cpu.Step();
        }
        if (cpu.halted && cb_depth > 1) {
            LOG(API, "[API] callback_executor HALTED at depth=%d "
                "PC=0x%08X R0=0x%X LR=0x%X\n",
                cb_depth, cpu.r[REG_PC], cpu.r[0], cpu.r[REG_LR]);
        }
        uint32_t result = cpu.r[0];
        /* Restore CPU state */
        memcpy(cpu.r, saved_regs, sizeof(saved_regs));
        cpu.cpsr = saved_cpsr;
        cpu.halted = saved_halted;
        if (cb_depth > 1) {
            LOG(API, "[API] callback_executor RETURN depth=%d result=0x%X\n",
                cb_depth, result);
        }
        cb_depth--;
        return result;
    };
}
