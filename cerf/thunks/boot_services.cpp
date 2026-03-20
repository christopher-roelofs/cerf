/* WinCE Built-In Device Manager — emulates device.exe.
   On real WinCE, device.exe is a separate process that reads
   HKLM\Drivers\BuiltIn\* and loads each driver DLL, calling its
   Entry function. device.exe has its own process slot, so DLL writable
   sections (.data) get per-process copy-on-write — driver modifications
   to RPCRT4/ole32/etc globals don't affect user processes.

   We emulate this by spawning a real thread with its own ProcessSlot,
   exactly like shell_exec_launch.cpp does for child processes.
   DLLs load inside this process context, DllMain runs per-process,
   and everything is naturally isolated. */

#include "win32_thunks.h"
#include "device_manager.h"
#include "../cpu/mem.h"
#include "../log.h"
#include "../loader/pe_loader.h"
#include "../tracing/trace_manager.h"
#include <algorithm>

/* Shared state between main thread and device.exe thread */
struct DeviceExeContext {
    Win32Thunks* thunks;
    EmulatedMemory* mem;
    HANDLE ready_event; /* signaled when device.exe init is complete */
};

void Win32Thunks::StartBootServices(EmulatedMemory& mem) {
    if (!callback_executor) return;

    LOG(API, "[BOOT] Starting device.exe (built-in device services)...\n");

    /* Read registry and collect services BEFORE spawning the thread,
       since registry access needs the main thread's context. */
    LoadRegistry();

    struct BootService {
        std::wstring name;
        std::string dll;
        std::string entry;
        uint32_t order;
    };
    std::vector<BootService> services;

    {
        std::lock_guard<std::recursive_mutex> lock(registry_mutex);
        std::wstring base_key = L"hklm\\drivers\\builtin";
        auto base_it = registry.find(base_key);
        if (base_it == registry.end()) {
            LOG(API, "[BOOT] No HKLM\\Drivers\\BuiltIn key found\n");
            return;
        }

        for (auto& subkey_name : base_it->second.subkeys) {
            std::wstring svc_key = base_key + L"\\" + subkey_name;
            auto svc_it = registry.find(svc_key);
            if (svc_it == registry.end()) continue;

            BootService svc;
            svc.name = subkey_name;
            svc.order = 0xFFFFFFFF;

            auto dll_it = svc_it->second.values.find(L"Dll");
            if (dll_it == svc_it->second.values.end())
                dll_it = svc_it->second.values.find(L"dll");
            if (dll_it != svc_it->second.values.end() && dll_it->second.type == REG_SZ) {
                std::wstring wdll((const wchar_t*)dll_it->second.data.data(),
                                  dll_it->second.data.size() / 2);
                if (!wdll.empty() && wdll.back() == L'\0') wdll.pop_back();
                for (auto c : wdll) svc.dll += (char)c;
            }
            if (svc.dll.empty()) continue;

            auto entry_it = svc_it->second.values.find(L"Entry");
            if (entry_it == svc_it->second.values.end())
                entry_it = svc_it->second.values.find(L"entry");
            if (entry_it != svc_it->second.values.end() && entry_it->second.type == REG_SZ) {
                std::wstring wentry((const wchar_t*)entry_it->second.data.data(),
                                    entry_it->second.data.size() / 2);
                if (!wentry.empty() && wentry.back() == L'\0') wentry.pop_back();
                for (auto c : wentry) svc.entry += (char)c;
            }

            auto order_it = svc_it->second.values.find(L"Order");
            if (order_it == svc_it->second.values.end())
                order_it = svc_it->second.values.find(L"order");
            if (order_it != svc_it->second.values.end() &&
                order_it->second.type == REG_DWORD && order_it->second.data.size() >= 4) {
                memcpy(&svc.order, order_it->second.data.data(), 4);
            }

            services.push_back(std::move(svc));
        }
    }

    /* Filter by cerf.ini boot_services= whitelist */
    if (boot_service_dlls.empty()) {
        LOG(API, "[BOOT] No boot_services= in cerf.ini, skipping all\n");
        return;
    }
    services.erase(
        std::remove_if(services.begin(), services.end(),
            [&](const BootService& s) {
                std::string lower_dll = s.dll;
                for (auto& c : lower_dll) if (c >= 'A' && c <= 'Z') c += 32;
                bool allowed = boot_service_dlls.count(lower_dll) > 0;
                if (!allowed)
                    LOG(API, "[BOOT] Skipping '%ls' (%s not in boot_services)\n",
                        s.name.c_str(), s.dll.c_str());
                return !allowed;
            }),
        services.end());

    std::sort(services.begin(), services.end(),
        [](const BootService& a, const BootService& b) { return a.order < b.order; });

    if (services.empty()) return;

    /* Spawn device.exe as a real process with its own ProcessSlot.
       This thread stays alive — driver background threads (dcomssd)
       inherit its ProcessSlot and kernel thread flag. */
    HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);

    struct DeviceThreadInfo {
        Win32Thunks* thunks;
        EmulatedMemory* mem;
        std::vector<BootService> services;
        HANDLE ready_event;
    };
    auto* info = new DeviceThreadInfo{ this, &mem, std::move(services), ready };

    HANDLE hThread = ::CreateThread(NULL, 0,
        [](LPVOID param) -> DWORD {
            auto* info = (DeviceThreadInfo*)param;
            int thread_idx = g_next_thread_index.fetch_add(1);

            /* Create per-thread context (like any WinCE process) */
            ThreadContext ctx;
            ctx.marshal_base = 0x3F000000 + (thread_idx + 1) * 0x10000;
            ctx.is_kernel_thread = true;
            t_ctx = &ctx;
            snprintf(ctx.process_name, sizeof(ctx.process_name), "device.exe");
            Log::SetProcessName(ctx.process_name, GetCurrentThreadId());

            /* Create device.exe's ProcessSlot — per-process DLL isolation */
            ProcessSlot slot;
            slot.RegisterWritableSections(info->mem->dll_writable_sections);
            EmulatedMemory::process_slot = &slot;

            /* Set up ARM CPU for this process — stack, thunk handler, executor.
               Same init as EnsureArmContext in thread_context.cpp. */
            uint32_t stack_size = 0x100000; /* 1MB */
            uint32_t stack_bottom = 0x01900000 + thread_idx * stack_size;
            info->mem->Alloc(stack_bottom, stack_size);
            ArmCpu& cpu = ctx.cpu;
            cpu.mem = info->mem;
            cpu.r[REG_SP] = stack_bottom + stack_size - 16;
            cpu.thunk_handler = [thunks = info->thunks](uint32_t addr, uint32_t* regs,
                                     EmulatedMemory& m) -> bool {
                if (addr == 0xCAFEC000) { regs[15] = 0xCAFEC000; return true; }
                return thunks->HandleThunk(addr, regs, m);
            };
            info->mem->Alloc(ctx.marshal_base, 0x10000);
            MakeCallbackExecutor(&ctx, *info->mem, *info->thunks, 0xCAFEC000);

            /* Copy shared KData page */
            uint8_t* shared_kdata = info->mem->Translate(0xFFFFC000);
            if (shared_kdata) memcpy(ctx.kdata, shared_kdata, 0x1000);
            EmulatedMemory::kdata_override = ctx.kdata;

            LOG(API, "[BOOT] device.exe process started (thread %u)\n",
                GetCurrentThreadId());

            /* Load and initialize each boot service */
            for (auto& svc : info->services) {
                LOG(API, "[BOOT] Loading service '%ls': dll='%s' entry='%s' order=%u\n",
                    svc.name.c_str(), svc.dll.c_str(), svc.entry.c_str(), svc.order);

                /* Track which DLLs are newly loaded by device.exe. On real WinCE,
                   device.exe's DLLs don't fire DLL_THREAD_ATTACH on other processes. */
                std::set<uint32_t> pre_bases;
                for (auto& [n, d] : info->thunks->loaded_dlls)
                    pre_bases.insert(d.base_addr);

                auto* dll = info->thunks->LoadArmDll(svc.dll);
                if (!dll) {
                    LOG(API, "[BOOT]   FAILED to load %s\n", svc.dll.c_str());
                    continue;
                }

                /* Mark ALL newly loaded DLLs as device.exe-exclusive.
                   On real WinCE, device.exe's DLLs (including transitive deps)
                   don't fire DLL_THREAD_ATTACH on other processes' threads. */
                for (auto& [n, d] : info->thunks->loaded_dlls) {
                    if (!pre_bases.count(d.base_addr)) {
                        d.loaded_by_device = true;
                        LOG(API, "[BOOT] Marked %ls (0x%08X) as device-only\n",
                            n.c_str(), d.base_addr);
                    }
                }

                if (info->thunks->GetTraceManager())
                    info->thunks->GetTraceManager()->OnDllLoad(
                        svc.dll, dll->path, dll->base_addr);

                if (!svc.entry.empty()) {
                    uint32_t init_addr = PELoader::ResolveExportName(
                        *info->mem, dll->pe_info, svc.entry);
                    if (init_addr) {
                        LOG(API, "[BOOT]   Calling %s at 0x%08X\n",
                            svc.entry.c_str(), init_addr);
                        uint32_t args[1] = { 0 };
                        uint32_t result = ctx.callback_executor(init_addr, args, 1);
                        LOG(API, "[BOOT]   %s returned %u\n",
                            svc.entry.c_str(), result);
                    } else {
                        LOG(API, "[BOOT]   Export '%s' not found in %s\n",
                            svc.entry.c_str(), svc.dll.c_str());
                    }
                }
            }

            LOG(API, "[BOOT] device.exe initialization complete\n");
            SetEvent(info->ready_event);

            /* Keep thread alive — driver background threads (dcomssd's
               OXID resolver) are children of this thread and need the
               ProcessSlot to stay valid. Sleep indefinitely. */
            ::Sleep(INFINITE);

            EmulatedMemory::process_slot = nullptr;
            t_ctx = nullptr;
            delete info;
            return 0;
        }, info, 0, NULL);

    if (!hThread) {
        LOG(API, "[BOOT] FAILED to create device.exe thread\n");
        CloseHandle(ready);
        delete info;
        return;
    }
    CloseHandle(hThread);

    /* Wait for device.exe to finish initialization before continuing.
       Driver background threads (dcomssd) continue running independently. */
    WaitForSingleObject(ready, 10000);
    CloseHandle(ready);

    LOG(API, "[BOOT] device.exe ready, continuing main init\n");
}
