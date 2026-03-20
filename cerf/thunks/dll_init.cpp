/* DLL initialization lifecycle: DllMain dispatch, per-process init, trace activation.
   Split from dll_loader.cpp — these run AFTER DLLs are loaded. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../tracing/trace_manager.h"
#include "../log.h"

void Win32Thunks::RunPerProcessDllInit() {
    /* On real WinCE, each process gets DLL_PROCESS_ATTACH for every loaded DLL.
       Re-run DllMain only for DLLs that were first loaded by a DIFFERENT PROCESS
       (different ProcessSlot). DLLs loaded by the main thread (ProcessSlot=nullptr)
       have their state in GLOBAL and are correct for all processes — re-running
       their DllMain would corrupt the global state via CoW. */
    ProcessSlot* cur_slot = EmulatedMemory::process_slot;
    if (!callback_executor || !cur_slot) return;

    for (auto& [name, dll] : loaded_dlls) {
        if (dll.pe_info.entry_point_rva == 0) continue;
        if (dll.dllmain_called_slots.count(cur_slot)) continue;
        /* Skip DLLs loaded by the main thread (slot=nullptr in their set).
           Their .data is in global and correct for all processes. */
        if (dll.dllmain_called_slots.count(nullptr)) continue;

        uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
        LOG(API, "[API] RunPerProcessDllInit: DllMain for %ls at 0x%08X (slot=%p)\n",
            name.c_str(), entry, cur_slot);
        uint32_t args[3] = { dll.base_addr, 1 /* DLL_PROCESS_ATTACH */, 0 };
        callback_executor(entry, args, 3);
        dll.dllmain_called_slots.insert(cur_slot);
    }
}

void Win32Thunks::CallDllEntryPoints() {
    if (!callback_executor || pending_dll_inits.empty()) return;

    for (auto& init : pending_dll_inits) {
        LOG(API, "[API] Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH)\n",
               init.entry_point, init.base_addr);
        uint32_t args[3] = { init.base_addr, 1, 0 };
        uint32_t result = callback_executor(init.entry_point, args, 3);
        /* Record which ProcessSlot ran DllMain for this DLL */
        for (auto& [name, dll] : loaded_dlls) {
            if (dll.base_addr == init.base_addr) {
                dll.dllmain_called_slots.insert(EmulatedMemory::process_slot);
                break;
            }
        }
        LOG(API, "[API] DllMain returned %d\n", result);
    }
    pending_dll_inits.clear();
}

/* Retroactively activate traces for DLLs loaded before TraceManager was set.
   Called once from main() after SetTraceManager + RegisterTracesForDevice. */
void Win32Thunks::ActivateTracesForLoadedDlls(TraceManager& tm) {
    for (auto& [name, dll] : loaded_dlls) {
        std::string narrow_name(name.begin(), name.end());
        tm.OnDllLoad(narrow_name, dll.path, dll.base_addr);
    }
}
