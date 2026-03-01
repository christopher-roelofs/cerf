#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Common dialog thunks: GetOpenFileNameW, GetSaveFileNameW */
#include "win32_thunks.h"
#include <cstdio>
#include <commdlg.h>
#include <vector>

void Win32Thunks::RegisterCommdlgHandlers() {
    auto getFileNameImpl = [this](uint32_t* regs, EmulatedMemory& mem, bool isSave) -> bool {
        uint32_t ofn_addr = regs[0];
        if (!ofn_addr) { regs[0] = 0; return true; }
        uint32_t hwnd_val      = mem.Read32(ofn_addr + 0x04);
        uint32_t filter_ptr    = mem.Read32(ofn_addr + 0x0C);
        uint32_t filter_idx    = mem.Read32(ofn_addr + 0x18);
        uint32_t file_ptr      = mem.Read32(ofn_addr + 0x1C);
        uint32_t max_file      = mem.Read32(ofn_addr + 0x20);
        uint32_t init_dir_ptr  = mem.Read32(ofn_addr + 0x2C);
        uint32_t title_ptr     = mem.Read32(ofn_addr + 0x30);
        uint32_t flags         = mem.Read32(ofn_addr + 0x34);
        uint32_t def_ext_ptr   = mem.Read32(ofn_addr + 0x3C);
        std::wstring filter, file_buf, init_dir, title, def_ext;
        if (filter_ptr) {
            for (uint32_t i = 0; i < 4096; i++) {
                wchar_t c = (wchar_t)mem.Read16(filter_ptr + i * 2);
                filter += c;
                if (c == 0 && i > 0 && filter[filter.size() - 2] == 0) break;
            }
        }
        if (file_ptr && max_file > 0) {
            for (uint32_t i = 0; i < max_file; i++) {
                wchar_t c = (wchar_t)mem.Read16(file_ptr + i * 2);
                file_buf += c;
                if (c == 0) break;
            }
        }
        if (init_dir_ptr) init_dir = ReadWStringFromEmu(mem, init_dir_ptr);
        if (title_ptr) title = ReadWStringFromEmu(mem, title_ptr);
        if (def_ext_ptr) def_ext = ReadWStringFromEmu(mem, def_ext_ptr);
        printf("[THUNK] %s(filter='%ls', file='%ls', dir='%ls', flags=0x%X)\n",
               isSave ? "GetSaveFileNameW" : "GetOpenFileNameW",
               filter.empty() ? L"" : filter.c_str(), file_buf.c_str(),
               init_dir.empty() ? L"" : init_dir.c_str(), flags);
        if (max_file < 260) max_file = 260;
        std::vector<wchar_t> native_file(max_file, 0);
        if (!file_buf.empty()) wcscpy_s(native_file.data(), max_file, file_buf.c_str());
        OPENFILENAMEW ofn = {};
        ofn.lStructSize = sizeof(OPENFILENAMEW);
        ofn.hwndOwner = (HWND)(intptr_t)(int32_t)hwnd_val;
        ofn.lpstrFilter = filter.empty() ? L"All Files\0*.*\0" : filter.c_str();
        ofn.nFilterIndex = filter_idx;
        ofn.lpstrFile = native_file.data();
        ofn.nMaxFile = max_file;
        ofn.lpstrInitialDir = init_dir.empty() ? NULL : init_dir.c_str();
        ofn.lpstrTitle = title.empty() ? NULL : title.c_str();
        ofn.lpstrDefExt = def_ext.empty() ? NULL : def_ext.c_str();
        ofn.Flags = flags & (OFN_READONLY | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                    OFN_NOCHANGEDIR | OFN_NOVALIDATE | OFN_ALLOWMULTISELECT |
                    OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_CREATEPROMPT |
                    OFN_NOREADONLYRETURN | OFN_EXPLORER);
        ofn.Flags |= OFN_EXPLORER;
        BOOL result = isSave ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
        if (result) {
            uint32_t orig_max = mem.Read32(ofn_addr + 0x20);
            for (uint32_t i = 0; i < orig_max && i < max_file; i++) {
                mem.Write16(file_ptr + i * 2, native_file[i]);
                if (native_file[i] == 0) break;
            }
            mem.Write16(ofn_addr + 0x38, ofn.nFileOffset);
            mem.Write16(ofn_addr + 0x3A, ofn.nFileExtension);
            mem.Write32(ofn_addr + 0x18, ofn.nFilterIndex);
            printf("[THUNK]   -> selected: '%ls'\n", native_file.data());
        } else {
            printf("[THUNK]   -> cancelled\n");
        }
        regs[0] = result;
        return true;
    };
    Thunk("GetOpenFileNameW", 488, [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, false);
    });
    Thunk("GetSaveFileNameW", [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, true);
    });
}
