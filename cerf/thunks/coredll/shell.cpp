#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
/* Shell thunks: ShellExecuteEx, Shell_NotifyIcon, SHGetSpecialFolderPath,
   GetOpenFileNameW/GetSaveFileNameW (coredll re-exports from commdlg),
   SH* functions (coredll re-exports from ceshell/aygshell) */
#include "../win32_thunks.h"
#include "../../log.h"
#include <cstdio>
#include <shellapi.h>
#include <commdlg.h>
#include <vector>

void Win32Thunks::RegisterShellHandlers() {
    auto stub0 = [](const char* name) -> ThunkHandler {
        return [name](uint32_t* regs, EmulatedMemory&) -> bool {
            LOG(THUNK, "[THUNK] [STUB] %s -> 0\n", name); regs[0] = 0; return true;
        };
    };
    Thunk("SHGetSpecialFolderPath", 295, stub0("SHGetSpecialFolderPath"));
    Thunk("SHLoadDIBitmap", 487, stub0("SHLoadDIBitmap"));
    ThunkOrdinal("SHCreateShortcut", 484);
    Thunk("ShellExecuteEx", 480, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        uint32_t sei_addr = regs[0];
        if (!sei_addr) { regs[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return true; }
        /* WinCE SHELLEXECUTEINFO layout (all 32-bit pointers):
           0x00 cbSize, 0x04 fMask, 0x08 hwnd, 0x0C lpVerb, 0x10 lpFile,
           0x14 lpParameters, 0x18 lpDirectory, 0x1C nShow, 0x20 hInstApp */
        uint32_t fMask     = mem.Read32(sei_addr + 0x04);
        uint32_t hwnd_val  = mem.Read32(sei_addr + 0x08);
        uint32_t verb_ptr  = mem.Read32(sei_addr + 0x0C);
        uint32_t file_ptr  = mem.Read32(sei_addr + 0x10);
        uint32_t params_ptr= mem.Read32(sei_addr + 0x14);
        uint32_t dir_ptr   = mem.Read32(sei_addr + 0x18);
        int nShow          = (int)mem.Read32(sei_addr + 0x1C);
        std::wstring verb, file, params, dir;
        if (verb_ptr) verb = ReadWStringFromEmu(mem, verb_ptr);
        if (file_ptr) file = ReadWStringFromEmu(mem, file_ptr);
        if (params_ptr) params = ReadWStringFromEmu(mem, params_ptr);
        if (dir_ptr) dir = ReadWStringFromEmu(mem, dir_ptr);
        LOG(THUNK, "[THUNK] ShellExecuteEx(verb='%ls', file='%ls', params='%ls', dir='%ls', nShow=%d)\n",
               verb.c_str(), file.c_str(), params.c_str(), dir.c_str(), nShow);
        SHELLEXECUTEINFOW native_sei = {};
        native_sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        native_sei.fMask = fMask;
        native_sei.hwnd = (HWND)(intptr_t)(int32_t)hwnd_val;
        native_sei.lpVerb = verb.empty() ? NULL : verb.c_str();
        native_sei.lpFile = file.empty() ? NULL : file.c_str();
        native_sei.lpParameters = params.empty() ? NULL : params.c_str();
        native_sei.lpDirectory = dir.empty() ? NULL : dir.c_str();
        native_sei.nShow = nShow;
        BOOL ret = ShellExecuteExW(&native_sei);
        mem.Write32(sei_addr + 0x20, (uint32_t)(uintptr_t)native_sei.hInstApp);
        if (fMask & SEE_MASK_NOCLOSEPROCESS)
            mem.Write32(sei_addr + 0x38, (uint32_t)(uintptr_t)native_sei.hProcess);
        LOG(THUNK, "[THUNK]   -> %s\n", ret ? "OK" : "FAILED");
        regs[0] = ret;
        return true;
    });
    Thunk("Shell_NotifyIcon", 481, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        DWORD dwMessage = regs[0];
        uint32_t nid_addr = regs[1];
        if (!nid_addr) { regs[0] = 0; return true; }
        /* WinCE NOTIFYICONDATA (32-bit):
           0x00 cbSize, 0x04 hWnd, 0x08 uID, 0x0C uFlags,
           0x10 uCallbackMessage, 0x14 hIcon, 0x18 szTip[64] (128 bytes) */
        NOTIFYICONDATAW nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATAW);
        nid.hWnd = (HWND)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x04);
        nid.uID = mem.Read32(nid_addr + 0x08);
        nid.uFlags = mem.Read32(nid_addr + 0x0C);
        nid.uCallbackMessage = mem.Read32(nid_addr + 0x10);
        nid.hIcon = (HICON)(intptr_t)(int32_t)mem.Read32(nid_addr + 0x14);
        for (int i = 0; i < 63; i++) {
            wchar_t c = (wchar_t)mem.Read16(nid_addr + 0x18 + i * 2);
            nid.szTip[i] = c;
            if (c == 0) break;
        }
        nid.szTip[63] = 0;
        LOG(THUNK, "[THUNK] Shell_NotifyIcon(msg=%d, uID=%d, tip='%ls')\n",
               dwMessage, nid.uID, nid.szTip);
        BOOL ret = Shell_NotifyIconW(dwMessage, &nid);
        regs[0] = ret;
        return true;
    });
    Thunk("SHGetFileInfo", 482, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHGetFileInfo(pszPath=0x%08X, attrs=0x%X, psfi=0x%08X, cbFileInfo=%d) -> 0 (stub)\n",
               regs[0], regs[1], regs[2], regs[3]);
        regs[0] = 0;
        return true;
    });
    /* GetOpenFileNameW / GetSaveFileNameW — coredll re-exports from commdlg */
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
        LOG(THUNK, "[THUNK] %s(filter='%ls', file='%ls', dir='%ls', flags=0x%X)\n",
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
            LOG(THUNK, "[THUNK]   -> selected: '%ls'\n", native_file.data());
        } else {
            LOG(THUNK, "[THUNK]   -> cancelled\n");
        }
        regs[0] = result;
        return true;
    };
    Thunk("GetOpenFileNameW", 488, [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, false);
    });
    Thunk("GetSaveFileNameW", 489, [this, getFileNameImpl](uint32_t* regs, EmulatedMemory& mem) -> bool {
        return getFileNameImpl(regs, mem, true);
    });
    /* ceshell re-exports via coredll */
    Thunk("SHGetShortcutTarget", 485, stub0("SHGetShortcutTarget"));
    Thunk("SHAddToRecentDocs", 483, [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHAddToRecentDocs(uFlags=%d, pv=0x%08X) -> stub\n", regs[0], regs[1]);
        return true;
    });
    Thunk("SHGetSpecialFolderLocation", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHGetSpecialFolderLocation(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001; /* E_NOTIMPL */
        return true;
    });
    Thunk("SHGetMalloc", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHGetMalloc(...) -> E_NOTIMPL (stub)\n");
        regs[0] = 0x80004001;
        return true;
    });
    Thunk("SHGetPathFromIDList", stub0("SHGetPathFromIDList"));
    Thunk("SHBrowseForFolder", stub0("SHBrowseForFolder"));
    Thunk("SHFileOperation", [](uint32_t* regs, EmulatedMemory&) -> bool {
        LOG(THUNK, "[THUNK] SHFileOperation(...) -> ERROR (stub)\n");
        regs[0] = 1;
        return true;
    });
    Thunk("ExtractIconExW", stub0("ExtractIconExW"));
    Thunk("DragAcceptFiles", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    Thunk("SHFreeNameMappings", [](uint32_t* regs, EmulatedMemory&) -> bool {
        return true; /* void */
    });
    /* aygshell re-exports via coredll */
    Thunk("SHHandleWMSettingChange", stub0("SHHandleWMSettingChange"));
    Thunk("SHHandleWMActivate", stub0("SHHandleWMActivate"));
    ThunkOrdinal("SHInitDialog", 1791);
    ThunkOrdinal("SHFullScreen", 1790);
    Thunk("SHCreateMenuBar", stub0("SHCreateMenuBar"));
    ThunkOrdinal("SHSipPreference", 1786);
    Thunk("SHRecognizeGesture", stub0("SHRecognizeGesture"));
    Thunk("SHSendBackToFocusWindow", stub0("SHSendBackToFocusWindow"));
    ThunkOrdinal("SHSetAppKeyWndAssoc", 1784);
    ThunkOrdinal("SHDoneButton", 1782);
    Thunk("SHSipInfo", stub0("SHSipInfo"));
    ThunkOrdinal("SHNotificationAdd", 1806);
    ThunkOrdinal("SHNotificationRemove", 1808);
    ThunkOrdinal("SHNotificationUpdate", 1807);
}
