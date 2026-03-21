#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../tracing/trace_manager.h"
#include "../log.h"
#include <cstdio>
#include <algorithm>
#include <set>

/* Check if a DLL name refers to a system DLL that we thunk (not an ARM DLL) */
static bool IsThunkedDll(const std::string& dll_name) {
    return FindThunkedDll(dll_name) != nullptr;
}

/* Look up an already-loaded ARM DLL by lowercase wide name. */
Win32Thunks::LoadedDll* Win32Thunks::FindLoadedDll(const std::wstring& name_lower) {
    auto it = loaded_dlls.find(name_lower);
    return it != loaded_dlls.end() ? &it->second : nullptr;
}

/* Try to find and load an ARM DLL by name.
   Returns pointer to LoadedDll if found, or nullptr.
   Searches: loaded_dlls cache, exe_dir, wince_sys_dir.
   Thread-safe: dll_load_mutex protects loaded_dlls + PE loading.
   DllMain runs OUTSIDE the lock to prevent deadlocks from cross-thread calls. */
Win32Thunks::LoadedDll* Win32Thunks::LoadArmDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::wstring wlower(lower.begin(), lower.end());

    /* Deferred DllMain calls — flushed outside the lock at outermost level */
    struct DeferredDllMain { uint32_t entry; uint32_t base_addr; std::wstring key; };
    static thread_local std::vector<DeferredDllMain> s_deferred;
    static thread_local ProcessSlot* s_original_slot = nullptr;
    static thread_local int s_load_depth = 0;
    bool is_outermost = (s_load_depth == 0);

    /* Already loaded? Check under lock, defer DllMain outside if needed.
       Use s_original_slot (not process_slot) because inner calls set process_slot=nullptr. */
    {
        std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
        auto it = loaded_dlls.find(wlower);
        if (it != loaded_dlls.end()) {
            LoadedDll& dll = it->second;
            ProcessSlot* real_slot = is_outermost ? EmulatedMemory::process_slot : s_original_slot;
            if (dll.loaded_by_device && callback_executor &&
                dll.pe_info.entry_point_rva != 0 &&
                !dll.dllmain_called_slots.count(real_slot)) {
                uint32_t entry = dll.base_addr + dll.pe_info.entry_point_rva;
                LOG(API, "[API] LoadArmDll: Queueing DllMain for device-loaded '%s' "
                    "(base=0x%08X, slot=%p)\n",
                    dll_name.c_str(), dll.base_addr, real_slot);
                s_deferred.push_back({entry, dll.base_addr, wlower});
            } else {
                return &dll;
            }
        }
    }
    /* Flush any deferred per-process DllMain for already-loaded DLLs */
    if (!s_deferred.empty() && is_outermost && callback_executor) {
        while (!s_deferred.empty()) {
            auto dm = s_deferred.front();
            s_deferred.erase(s_deferred.begin());
            {
                std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
                if (loaded_dlls[dm.key].dllmain_called_slots.count(EmulatedMemory::process_slot))
                    continue;
            }
            uint32_t args[3] = { dm.base_addr, 1, 0 };
            callback_executor(dm.entry, args, 3);
            std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
            loaded_dlls[dm.key].dllmain_called_slots.insert(EmulatedMemory::process_slot);
        }
        std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
        auto it = loaded_dlls.find(wlower);
        if (it != loaded_dlls.end()) return &it->second;
    }

    /* Try to find the ARM DLL file.
       Search order: wince_sys_dir first (canonical system DLLs — guaranteed
       to be standard PE, not UPX-packed), then exe_dir (app-bundled DLLs). */
    std::string dll_path;
    FILE* f = nullptr;
    if (!wince_sys_dir.empty()) {
        dll_path = wince_sys_dir + dll_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) {
        dll_path = exe_dir + dll_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) {
        dll_path = dll_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) {
        std::string with_ext = dll_name;
        if (dll_name.find('.') == std::string::npos)
            with_ext += ".dll";
        else {
            LOG(API, "[API] LoadArmDll: '%s' not found (searched sys/exe dirs)\n", dll_name.c_str());
            return nullptr;
        }
        if (!wince_sys_dir.empty()) {
            dll_path = wince_sys_dir + with_ext;
            f = fopen(dll_path.c_str(), "rb");
        }
        if (!f) {
            dll_path = exe_dir + with_ext;
            f = fopen(dll_path.c_str(), "rb");
        }
        if (!f) {
            dll_path = with_ext;
            f = fopen(dll_path.c_str(), "rb");
        }
        if (!f) {
            LOG(API, "[API] LoadArmDll: '%s' not found (also tried '%s')\n",
                dll_name.c_str(), with_ext.c_str());
            return nullptr;
        }
        lower = with_ext;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        wlower = std::wstring(lower.begin(), lower.end());
        std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
        auto it2 = loaded_dlls.find(wlower);
        if (it2 != loaded_dlls.end()) { fclose(f); return &it2->second; }
    }
    fclose(f);

    /* Lock for PE loading, map insertion, and InstallThunks.
       DllMain calls are deferred to after the lock is released. */
    dll_load_mutex.lock();

    /* Double-check cache after acquiring lock (another thread may have loaded it) */
    {
        auto it = loaded_dlls.find(wlower);
        if (it != loaded_dlls.end()) {
            dll_load_mutex.unlock();
            return &it->second;
        }
    }

    if (is_outermost)
        s_original_slot = EmulatedMemory::process_slot;
    s_load_depth++;
    EmulatedMemory::process_slot = nullptr;

    PEInfo dll_info = {};
    uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
    if (entry == 0 && dll_info.image_base == 0) {
        s_load_depth--;
        if (is_outermost) EmulatedMemory::process_slot = s_original_slot;
        dll_load_mutex.unlock();
        LOG(API, "[API] LoadArmDll: Failed to load ARM DLL: %s\n", dll_path.c_str());
        return nullptr;
    }

    LOG(API, "[API] LoadArmDll: Loaded ARM DLL '%s' at 0x%08X (exports: RVA=0x%X size=0x%X)\n",
           dll_name.c_str(), dll_info.image_base, dll_info.export_rva, dll_info.export_size);

    if (trace_mgr_)
        trace_mgr_->OnDllLoad(dll_name, dll_path, dll_info.image_base);

    mem.AddDllAlias(dll_info.image_base, dll_info.size_of_image);
    mem.RegisterDllWritableSections(dll_info.image_base, dll_info.sections);

    LoadedDll loaded;
    loaded.path = dll_path;
    loaded.base_addr = dll_info.image_base;
    loaded.pe_info = dll_info;
    loaded.native_rsrc_handle = NULL;
    loaded_dlls[wlower] = loaded;

    InstallThunks(loaded_dlls[wlower].pe_info, dll_name.c_str());

    s_load_depth--;
    /* Only restore ProcessSlot at the outermost LoadArmDll level.
       Nested calls (dependency resolution) must keep process_slot = nullptr
       so InstallThunks writes IAT entries to GLOBAL memory, not per-process
       overlay. Without this, nested LoadArmDll restores the slot mid-way
       through the parent's InstallThunks, causing IAT writes to go to
       CopyOnWrite overlay instead of global. */
    if (s_load_depth == 0)
        EmulatedMemory::process_slot = s_original_slot;

    /* CopyRegions for runtime-loaded DLLs: if a child process loads a new DLL
       via LoadLibraryW, copy its R/W sections into the process's overlay NOW.
       Without this, reads of the DLL's .data would see the global (shared) copy
       which may contain state from another process's DllMain. */
    if (s_original_slot) {
        constexpr DWORD WRITE_FLAG = IMAGE_SCN_MEM_WRITE;
        for (auto& sec : dll_info.sections) {
            if (!(sec.Characteristics & WRITE_FLAG)) continue;
            uint32_t ws_start = dll_info.image_base + sec.VirtualAddress;
            uint32_t ws_size = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            uint32_t pg = ws_start & ~(ProcessSlot::PAGE_SIZE - 1);
            uint32_t pg_end = (ws_start + ws_size + ProcessSlot::PAGE_SIZE - 1)
                              & ~(ProcessSlot::PAGE_SIZE - 1);
            for (; pg < pg_end; pg += ProcessSlot::PAGE_SIZE) {
                uint8_t* g = mem.TranslateGlobal(pg);
                if (g) s_original_slot->CopyOnWrite(pg, g);
            }
        }
    }

    /* Queue DllMain instead of calling under lock */
    if (entry != 0 && dll_info.entry_point_rva != 0) {
        if (callback_executor) {
            s_deferred.push_back({entry, dll_info.image_base, wlower});
        } else {
            pending_dll_inits.push_back({entry, dll_info.image_base});
        }
    }

    dll_load_mutex.unlock();

    /* At outermost level, flush all deferred DllMains OUTSIDE the lock.
       Dependencies are queued before the DLL that imported them, giving
       correct initialization order (same as WinCE kernel loader). */
    if (is_outermost && callback_executor) {
        while (!s_deferred.empty()) {
            auto dm = s_deferred.front();
            s_deferred.erase(s_deferred.begin());
            /* Skip if already called by a previous deferred entry (dedup) */
            {
                std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
                if (loaded_dlls[dm.key].dllmain_called_slots.count(EmulatedMemory::process_slot))
                    continue;
            }
            LOG(API, "[API] LoadArmDll: Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH)\n",
                dm.entry, dm.base_addr);
            uint32_t args[3] = { dm.base_addr, 1, 0 };
            uint32_t result = callback_executor(dm.entry, args, 3);
            {
                std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
                loaded_dlls[dm.key].dllmain_called_slots.insert(EmulatedMemory::process_slot);
            }
            LOG(API, "[API] DllMain returned %d\n", result);
        }
    }

    std::lock_guard<std::recursive_mutex> lock(dll_load_mutex);
    return &loaded_dlls[wlower];
}

void Win32Thunks::InstallThunks(PEInfo& info, const char* module_name) {
    /* For each import, try to resolve from a loaded ARM DLL first,
       then fall back to creating a thunk stub. ARM DLLs are loaded
       on demand (cascading: their imports are resolved recursively). */
    struct UnresolvedImport {
        std::string dll_name;
        std::string display;   /* "FuncName" or "@ordinal" */
    };
    std::vector<UnresolvedImport> unresolved;
    std::set<std::string> warned_dlls;
    std::set<std::string> missing_dlls;

    for (auto& imp : info.imports) {
        /* Thunked system DLL (coredll) — always create a thunk */
        if (IsThunkedDll(imp.dll_name)) {
            uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);
            mem.Write32(imp.iat_addr, thunk_addr);
            if (imp.by_ordinal) {
                LOG(API, "[API] Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                       imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
            } else {
                LOG(API, "[API] Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                       imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
            }

            /* Check if this thunk actually has a handler registered */
            bool has_handler = false;
            if (imp.by_ordinal) {
                auto oit = ordinal_map.find(imp.ordinal);
                if (oit != ordinal_map.end())
                    has_handler = thunk_handlers.count(oit->second) > 0;
            } else {
                has_handler = thunk_handlers.count(imp.func_name) > 0;
            }
            if (!has_handler) {
                char buf[64];
                if (imp.by_ordinal) {
                    sprintf(buf, "@%d", imp.ordinal);
                    /* Also try to show the name if we know it */
                    auto oit = ordinal_map.find(imp.ordinal);
                    if (oit != ordinal_map.end())
                        unresolved.push_back({imp.dll_name, oit->second + " (" + buf + ")"});
                    else
                        unresolved.push_back({imp.dll_name, buf});
                } else {
                    unresolved.push_back({imp.dll_name, imp.func_name});
                }
            }
            continue;
        }

        /* Try to load/find the ARM DLL */
        LoadedDll* arm_dll = LoadArmDll(imp.dll_name);
        if (arm_dll) {
            /* Resolve the export from the ARM DLL */
            uint32_t arm_addr = 0;
            if (imp.by_ordinal) {
                arm_addr = PELoader::ResolveExportOrdinal(mem, arm_dll->pe_info, imp.ordinal);
            } else {
                arm_addr = PELoader::ResolveExportName(mem, arm_dll->pe_info, imp.func_name);
            }

            if (arm_addr != 0) {
                mem.Write32(imp.iat_addr, arm_addr);
                if (imp.by_ordinal) {
                    LOG(API, "[API] Resolved %s!@%d -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.ordinal, arm_addr, imp.iat_addr);
                } else {
                    LOG(API, "[API] Resolved %s!%s -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.func_name.c_str(), arm_addr, imp.iat_addr);
                }
                continue;
            }
            LOG(API, "[API] LoadArmDll: WARNING: Export not found in %s for %s@%d, using thunk stub\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), imp.ordinal);
            /* Track as unresolved */
            if (imp.by_ordinal) {
                char buf[64];
                sprintf(buf, "@%d", imp.ordinal);
                unresolved.push_back({imp.dll_name, buf});
            } else {
                unresolved.push_back({imp.dll_name, imp.func_name});
            }
        } else {
            missing_dlls.insert(imp.dll_name);
            if (warned_dlls.insert(imp.dll_name).second) {
                LOG_ERR("[API] LoadArmDll: ERROR: DLL not found: %s — imports will fail at runtime!\n", imp.dll_name.c_str());
            }
            /* Track as unresolved */
            if (imp.by_ordinal) {
                char buf[64];
                sprintf(buf, "@%d", imp.ordinal);
                unresolved.push_back({imp.dll_name, buf});
            } else {
                unresolved.push_back({imp.dll_name, imp.func_name});
            }
        }

        /* Unresolved — create a thunk stub that will log loudly if called */
        uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);
        mem.Write32(imp.iat_addr, thunk_addr);
        if (imp.by_ordinal) {
            LOG(API, "[API] LoadArmDll: Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
        } else {
            LOG(API, "[API] LoadArmDll: Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
        }
    }

    /* Print summary of unresolved imports */
    if (!unresolved.empty()) {
        std::string mod = (module_name && module_name[0]) ? module_name : "<unknown>";
        /* Extract just the filename from a path */
        {
            size_t pos = mod.find_last_of("\\/");
            if (pos != std::string::npos) mod = mod.substr(pos + 1);
        }

        /* Group unresolved imports by DLL */
        std::map<std::string, std::vector<std::string>> by_dll;
        for (auto& u : unresolved) by_dll[u.dll_name].push_back(u.display);

        LOG_ERR("\n");
        LOG_ERR("================================================================\n");
        LOG_ERR("  UNRESOLVED IMPORTS in %s (%d total)\n", mod.c_str(), (int)unresolved.size());
        LOG_ERR("  These must be implemented (or stubbed with correct return data) to avoid fatal.\n");
        LOG_ERR("================================================================\n");

        for (auto& pair : by_dll) {
            bool is_missing = missing_dlls.count(pair.first) > 0;
            if (is_missing)
                LOG_ERR("  %s  [DLL NOT FOUND]\n", pair.first.c_str());
            else
                LOG_ERR("  %s\n", pair.first.c_str());
            for (auto& name : pair.second) {
                LOG_ERR("    - %s\n", name.c_str());
            }
        }
        LOG_ERR("================================================================\n\n");
    }
}

/* RunPerProcessDllInit, CallDllEntryPoints, ActivateTracesForLoadedDlls
   moved to dll_init.cpp */
