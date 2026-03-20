#pragma once
/* DLL loader and resource types — split from win32_thunks.h.
   Included by win32_thunks.h; do not include directly. */

    struct LoadedDll {
        std::string path;
        uint32_t base_addr;
        PEInfo pe_info;
        HMODULE native_rsrc_handle;
        /* Tracks which ProcessSlots have received DLL_PROCESS_ATTACH. */
        std::set<ProcessSlot*> dllmain_called_slots;
        /* True if this DLL was first loaded by device.exe's boot services.
           Device.exe DLLs don't fire DLL_THREAD_ATTACH on other processes' threads. */
        bool loaded_by_device = false;
    };
    std::map<std::wstring, LoadedDll> loaded_dlls;
    LoadedDll* LoadArmDll(const std::string& dll_name);

    struct EmuRsrc { uint32_t data_rva; uint32_t data_size; uint32_t module_base; };
    std::map<uint32_t, EmuRsrc> rsrc_map;
    uint32_t next_rsrc_handle = 0xE0000000;
    uint32_t FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                              uint32_t type_id, uint32_t name_id,
                              uint32_t& out_data_rva, uint32_t& out_data_size);

    struct PendingDllInit { uint32_t entry_point; uint32_t base_addr; };
    std::vector<PendingDllInit> pending_dll_inits;

    /* DLLs that called DisableThreadLibraryCalls — skip DLL_THREAD_ATTACH */
    std::set<uint32_t> disable_thread_notify_bases;

    /* (LPC mock removed — replaced by real lpcd.dll via DeviceManager) */
