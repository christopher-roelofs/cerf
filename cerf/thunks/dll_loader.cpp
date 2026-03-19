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

/* Try to find and load an ARM DLL by name.
   Returns pointer to LoadedDll if found, or nullptr.
   Searches: loaded_dlls cache, exe_dir, wince_sys_dir. */
Win32Thunks::LoadedDll* Win32Thunks::LoadArmDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::wstring wlower(lower.begin(), lower.end());

    /* Already loaded? */
    auto it = loaded_dlls.find(wlower);
    if (it != loaded_dlls.end()) return &it->second;

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
    /* If not found and name has no extension, try appending ".dll" (standard
       Windows behavior — LoadLibrary("iectl") should find "iectl.dll") */
    if (!f) {
        std::string with_ext = dll_name;
        if (dll_name.find('.') == std::string::npos)
            with_ext += ".dll";
        else {
            LOG(API, "[API] LoadArmDll: '%s' not found (searched sys/exe dirs)\n", dll_name.c_str());
            return nullptr; /* already had extension, genuinely not found */
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
        /* Update lower/wlower to include the extension for the cache key */
        lower = with_ext;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        wlower = std::wstring(lower.begin(), lower.end());
        /* Check cache again with the full name */
        auto it2 = loaded_dlls.find(wlower);
        if (it2 != loaded_dlls.end()) { fclose(f); return &it2->second; }
    }
    fclose(f);

    PEInfo dll_info = {};
    uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
    if (entry == 0 && dll_info.image_base == 0) {
        LOG(API, "[API] LoadArmDll: Failed to load ARM DLL: %s\n", dll_path.c_str());
        return nullptr;
    }

    LOG(API, "[API] LoadArmDll: Loaded ARM DLL '%s' at 0x%08X (exports: RVA=0x%X size=0x%X)\n",
           dll_name.c_str(), dll_info.image_base, dll_info.export_rva, dll_info.export_size);

    /* Activate ARM trace points for this DLL (auto-rebase, CRC32 verification) */
    if (trace_mgr_)
        trace_mgr_->OnDllLoad(dll_name, dll_path, dll_info.image_base);

    /* Register slot-0 alias so WinCE slot-masked addresses resolve to this DLL */
    mem.AddDllAlias(dll_info.image_base, dll_info.size_of_image);

    /* Register writable sections for per-process copy-on-write */
    mem.RegisterDllWritableSections(dll_info.image_base, dll_info.sections);

    LoadedDll loaded;
    loaded.path = dll_path;
    loaded.base_addr = dll_info.image_base;
    loaded.pe_info = dll_info;
    loaded.native_rsrc_handle = NULL;
    loaded_dlls[wlower] = loaded;

    /* Recursively install thunks for this DLL's own imports */
    InstallThunks(loaded_dlls[wlower].pe_info, dll_name.c_str());

    /* Call DLL entry point (DllMain) — immediately if callback_executor is
       available (runtime LoadLibrary), otherwise queue for deferred init
       (initial PE loading before the CPU is set up). */
    if (entry != 0 && dll_info.entry_point_rva != 0) {
        if (callback_executor) {
            LOG(API, "[API] LoadArmDll: Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH) immediately\n",
                   entry, dll_info.image_base);
            uint32_t args[3] = { dll_info.image_base, 1 /* DLL_PROCESS_ATTACH */, 0 };
            uint32_t result = callback_executor(entry, args, 3);
            LOG(API, "[API] DllMain returned %d\n", result);
        } else {
            LOG(API, "[API] LoadArmDll: DLL has entry point at 0x%08X - queued for init\n", entry);
            pending_dll_inits.push_back({entry, dll_info.image_base});
        }
    }

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

void Win32Thunks::CallDllEntryPoints() {
    if (!callback_executor || pending_dll_inits.empty()) return;

    for (auto& init : pending_dll_inits) {
        LOG(API, "[API] Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH)\n",
               init.entry_point, init.base_addr);
        /* DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpvReserved)
           R0 = hinstDLL (DLL base address)
           R1 = fdwReason = 1 (DLL_PROCESS_ATTACH)
           R2 = lpvReserved = 0 */
        uint32_t args[3] = { init.base_addr, 1, 0 };
        uint32_t result = callback_executor(init.entry_point, args, 3);
        LOG(API, "[API] DllMain returned %d\n", result);
    }
    pending_dll_inits.clear();
}
