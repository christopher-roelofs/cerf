#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Resource extraction thunks: LoadAcceleratorsW, ExtractResource
   — split from resource.cpp */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <algorithm>
#ifndef RT_TYPELIB
#define RT_TYPELIB MAKEINTRESOURCEW(8)
#endif

void Win32Thunks::RegisterResourceExtractHandlers() {
    Thunk("LoadAcceleratorsW", 94, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t hmod = regs[0], name_id = regs[1];
        LOG(API, "[API] LoadAcceleratorsW(0x%08X, %d)\n", hmod, name_id);
        uint32_t rsrc_rva = 0, rsrc_sz = 0;
        bool is_arm = (hmod == emu_hinstance);
        if (is_arm) {
            uint32_t dos_lfanew = mem.Read32(hmod + 0x3C), nt_addr = hmod + dos_lfanew;
            uint32_t n = mem.Read32(nt_addr + 0x74);
            if (n > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                rsrc_rva = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8);
                rsrc_sz = mem.Read32(nt_addr + 0x78 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4);
            }
        }
        for (auto& pair : loaded_dlls) {
            if (pair.second.base_addr == hmod) {
                is_arm = true; rsrc_rva = pair.second.pe_info.rsrc_rva;
                rsrc_sz = pair.second.pe_info.rsrc_size; break;
            }
        }
        if (is_arm && rsrc_rva) {
            uint32_t data_rva = 0, data_size = 0;
            if (FindResourceInPE(hmod, rsrc_rva, rsrc_sz, 9, name_id, data_rva, data_size)) {
                uint8_t* data = mem.Translate(hmod + data_rva);
                if (data && data_size >= 8) {
                    int count = data_size / 8;
                    ACCEL* accels = new ACCEL[count];
                    for (int i = 0; i < count; i++) {
                        uint16_t* entry = (uint16_t*)(data + i * 8);
                        accels[i].fVirt = (BYTE)entry[0];
                        accels[i].key = entry[1];
                        accels[i].cmd = entry[2] | (entry[3] << 16);
                    }
                    HACCEL h = CreateAcceleratorTableW(accels, count);
                    delete[] accels;
                    regs[0] = (uint32_t)(uintptr_t)h;
                    LOG(API, "[API]   -> HACCEL 0x%08X (%d entries)\n", regs[0], count);
                    return true;
                }
            }
        }
        HMODULE native_mod = is_arm ? GetNativeModuleForResources(hmod) : (HMODULE)(intptr_t)(int32_t)hmod;
        regs[0] = native_mod ? (uint32_t)(uintptr_t)LoadAcceleratorsW(native_mod, MAKEINTRESOURCEW(name_id)) : 0;
        return true;
    });
    /* ExtractResource: WinCE function to extract a named resource from a PE file
       to a destination file. Used by oleaut32's LoadTypeLib to extract embedded
       type libraries (TYPELIB resources) for IDispatch support.
       Signature: BOOL ExtractResource(LPCWSTR lpszFile, LPCWSTR lpszResName, LPCWSTR lpszDestFile)
       - lpszFile: source DLL path (e.g., "webview.dll")
       - lpszResName: resource name/ID (e.g., MAKEINTRESOURCE(1))
       - lpszDestFile: destination file path for extracted resource */
    Thunk("ExtractResource", 573, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        std::wstring src = ReadWStringFromEmu(mem, regs[0]);
        bool name_is_int = IS_INTRESOURCE(regs[1]);
        uint32_t name_id = name_is_int ? regs[1] : 0;
        std::wstring dest = ReadWStringFromEmu(mem, regs[2]);

        LOG(API, "[API] ExtractResource('%ls', %s%u, '%ls')\n",
            src.c_str(), name_is_int ? "#" : "str:", name_is_int ? name_id : regs[1],
            dest.c_str());

        /* Find the source DLL's native resource handle by matching filename */
        HMODULE native_mod = nullptr;
        std::string src_narrow(src.begin(), src.end());
        for (auto& pair : loaded_dlls) {
            std::string dll_file = pair.second.path;
            size_t sep = dll_file.find_last_of("\\/");
            if (sep != std::string::npos) dll_file = dll_file.substr(sep + 1);
            std::string src_file = src_narrow;
            sep = src_file.find_last_of("\\/");
            if (sep != std::string::npos) src_file = src_file.substr(sep + 1);
            std::transform(dll_file.begin(), dll_file.end(), dll_file.begin(), ::tolower);
            std::transform(src_file.begin(), src_file.end(), src_file.begin(), ::tolower);
            if (dll_file == src_file) {
                native_mod = GetNativeModuleForResources(pair.second.base_addr);
                break;
            }
        }
        if (!native_mod) {
            LOG(API, "[API]   -> 0 (DLL not found)\n");
            regs[0] = 0;
            return true;
        }

        /* Find the TYPELIB resource (RT_TYPELIB = 8). The name is typically
           MAKEINTRESOURCE(1) for the first (and usually only) type library. */
        LPCWSTR res_name = name_is_int ? MAKEINTRESOURCEW(name_id) : (LPCWSTR)nullptr;
        HRSRC hRes = FindResourceW(native_mod, res_name, RT_TYPELIB);
        if (!hRes) {
            /* Also try with MAKEINTRESOURCE(1) if name was a string */
            hRes = FindResourceW(native_mod, MAKEINTRESOURCEW(1), RT_TYPELIB);
        }
        if (!hRes) {
            LOG(API, "[API]   -> 0 (TYPELIB resource not found)\n");
            regs[0] = 0;
            return true;
        }

        HGLOBAL hGlobal = LoadResource(native_mod, hRes);
        DWORD resSize = SizeofResource(native_mod, hRes);
        void* resData = hGlobal ? LockResource(hGlobal) : nullptr;
        if (!resData || !resSize) {
            LOG(API, "[API]   -> 0 (load failed)\n");
            regs[0] = 0;
            return true;
        }

        /* Write to destination file. Map through VFS if it's a WinCE path. */
        std::wstring mapped_dest = MapWinCEPath(dest);
        FILE* fout = _wfopen(mapped_dest.c_str(), L"wb");
        if (!fout) {
            /* Destination might be a bare filename — write to VFS Windows dir */
            mapped_dest = MapWinCEPath(L"\\Windows\\" + dest);
            fout = _wfopen(mapped_dest.c_str(), L"wb");
        }
        if (!fout) {
            LOG(API, "[API]   -> 0 (can't create '%ls')\n", mapped_dest.c_str());
            regs[0] = 0;
            return true;
        }
        fwrite(resData, 1, resSize, fout);
        fclose(fout);

        LOG(API, "[API]   -> 1 (%u bytes to '%ls')\n", resSize, mapped_dest.c_str());
        regs[0] = 1;
        return true;
    });
}
